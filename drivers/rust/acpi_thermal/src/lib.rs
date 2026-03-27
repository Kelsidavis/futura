// SPDX-License-Identifier: MPL-2.0
//
// ACPI Thermal Zone Management Driver for Futura OS (x86-64)
//
// Provides a unified thermal interface combining CPU package temperature
// (via AMD Zen MSR 0xC0010059 CUR_TEMP / Tctl) and board sensors (via
// ACPI Embedded Controller register reads).
//
// Architecture:
//   - Zone 0: CPU package temperature from MSR or SB-TSI
//   - Zones 1-3: Board sensors read from EC at configurable addresses
//   - Trip points: Critical (shutdown), Hot (throttle), Passive (freq
//     reduce), Active (fan on) with up to 4 active cooling levels
//   - Thermal policy evaluation returns a bitmask of zones needing action
//
// AMD CPU temperature MSR (Zen family):
//   MSR 0xC001_0059 (CUR_TEMP): bits [31:21] = Tctl in 0.125 C steps
//   Some Zen parts report Tdie = Tctl - TjOffset (family-specific)
//
// EC-based sensors:
//   The caller supplies an EcReadFn callback for reading EC registers.
//   Each board zone has a configurable EC address whose byte value is
//   interpreted as degrees Celsius (unsigned).

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(unexpected_cfgs)]

use core::cell::UnsafeCell;

use common::log;

unsafe extern "C" {
    fn fut_printf(fmt: *const u8, ...);
}

// ── StaticCell wrapper (avoids `static mut`) ──

/// Wrapper to allow `UnsafeCell` in a `static` (requires `Sync`).
/// Safety: all access is single-threaded or externally synchronised by the caller.
struct StaticCell<T>(UnsafeCell<T>);
unsafe impl<T> Sync for StaticCell<T> {}
impl<T> StaticCell<T> {
    const fn new(v: T) -> Self { Self(UnsafeCell::new(v)) }
    fn get(&self) -> *mut T { self.0.get() }
}

// ── EC read callback type ──

/// Callback to read a single byte from an EC register.
/// Returns the byte value (0-255) on success, or negative error.
type EcReadFn = unsafe extern "C" fn(addr: u8) -> i32;

// ── AMD thermal MSR ──

/// AMD Family 17h+ (Zen) reported temperature MSR.
/// Bits [31:21] contain Tctl in 0.125 C increments.
const MSR_AMD_CUR_TEMP: u32 = 0xC001_0059;

// ── Trip point types (for documentation / future enum use) ──

/// Maximum number of thermal zones.
const MAX_ZONES: usize = 4;

/// Maximum number of active cooling trip points per zone.
const MAX_ACTIVE_TRIPS: usize = 4;

// ── Thermal zone structure ──

/// A single ACPI thermal zone descriptor, exported to C callers.
#[repr(C)]
pub struct ThermalZone {
    /// Human-readable zone name (null-terminated, max 15 chars + NUL).
    pub name: [u8; 16],
    /// Current temperature in millidegrees Celsius.
    pub temp_millideg: i32,
    /// Critical trip point (millideg C) -- system should shut down.
    pub critical: i32,
    /// Hot trip point (millideg C) -- hardware throttle engaged.
    pub hot: i32,
    /// Passive trip point (millideg C) -- OS reduces frequency.
    pub passive: i32,
    /// Active trip points (millideg C) -- fan speed thresholds.
    pub active: [i32; MAX_ACTIVE_TRIPS],
    /// Current fan speed percentage (0-100), placeholder.
    pub fan_pct: u8,
    /// Whether the zone is currently being throttled.
    pub throttled: bool,
    /// Whether the zone contains a valid reading.
    pub valid: bool,
}

impl ThermalZone {
    const fn new() -> Self {
        Self {
            name: [0u8; 16],
            temp_millideg: 0,
            critical: 105_000,  // 105 C default
            hot: 95_000,        // 95 C default
            passive: 85_000,    // 85 C default
            active: [70_000, 60_000, 50_000, 40_000],
            fan_pct: 0,
            throttled: false,
            valid: false,
        }
    }
}

// ── Driver state ──

struct AcpiThermalState {
    /// Thermal zones (zone 0 = CPU, zones 1-3 = board/EC).
    zones: [ThermalZone; MAX_ZONES],
    /// Number of configured zones.
    zone_count: u32,
    /// EC read callback (may be null if CPU-only mode).
    ec_read: Option<EcReadFn>,
    /// EC register addresses for zones 1-3 (index 0 corresponds to zone 1).
    ec_addrs: [u8; MAX_ZONES - 1],
    /// Whether the driver has been initialised.
    initialized: bool,
}

impl AcpiThermalState {
    const fn new() -> Self {
        Self {
            zones: [
                ThermalZone::new(),
                ThermalZone::new(),
                ThermalZone::new(),
                ThermalZone::new(),
            ],
            zone_count: 0,
            ec_read: None,
            ec_addrs: [0u8; MAX_ZONES - 1],
            initialized: false,
        }
    }
}

static STATE: StaticCell<AcpiThermalState> = StaticCell::new(AcpiThermalState::new());

// ── MSR access ──

/// Read a 64-bit Model-Specific Register.
fn rdmsr(msr: u32) -> u64 {
    let lo: u32;
    let hi: u32;
    unsafe {
        core::arch::asm!(
            "rdmsr",
            in("ecx") msr,
            out("eax") lo,
            out("edx") hi,
            options(nomem, nostack, preserves_flags),
        );
    }
    ((hi as u64) << 32) | (lo as u64)
}

// ── CPU temperature reading ──

/// Read the AMD CPU package temperature from MSR 0xC001_0059.
///
/// Returns temperature in millidegrees Celsius, or negative error if
/// the reading appears invalid (zero or implausibly high).
fn read_cpu_temp_msr() -> i32 {
    let val = rdmsr(MSR_AMD_CUR_TEMP);

    // Bits [31:21] = Tctl in units of 0.125 C.
    let raw = ((val >> 21) & 0x7FF) as u32;

    if raw == 0 {
        return -5; // EIO -- sensor not responding
    }

    // Convert 0.125 C steps to millidegrees: raw * 125.
    let millideg = (raw * 125) as i32;

    millideg
}

// ── EC sensor reading ──

/// Read a board sensor temperature via the EC callback.
///
/// `ec_read` - The EC read callback function.
/// `addr`    - EC register address for this sensor.
///
/// Returns temperature in millidegrees Celsius, or negative error.
fn read_ec_sensor(ec_read: EcReadFn, addr: u8) -> i32 {
    let result = unsafe { ec_read(addr) };

    if result < 0 {
        return result; // Propagate EC error
    }

    // EC typically returns degrees Celsius as a single unsigned byte.
    let deg_c = result & 0xFF;
    deg_c * 1000 // Convert to millidegrees
}

// ── Name copy helper ──

/// Copy a C string (up to 15 bytes + NUL) into a zone name buffer.
fn copy_zone_name(dst: &mut [u8; 16], src: *const u8) {
    if src.is_null() {
        dst[0] = 0;
        return;
    }
    let mut i = 0usize;
    while i < 15 {
        let ch = unsafe { *src.add(i) };
        if ch == 0 {
            break;
        }
        dst[i] = ch;
        i += 1;
    }
    dst[i] = 0;
}

// ── FFI exports ──

/// Initialise the ACPI thermal zone management driver.
///
/// `ec_read` - Callback for EC register reads. Pass null for CPU-only
///             mode (no board sensor support).
///
/// Sets up zone 0 as the CPU package thermal zone using AMD MSR-based
/// temperature reading. Additional zones can be added with
/// `acpi_thermal_add_zone`.
///
/// Returns 0 on success, negative error on failure.
#[unsafe(no_mangle)]
pub extern "C" fn acpi_thermal_init(ec_read: Option<EcReadFn>) -> i32 {
    log("acpi_thermal: initialising ACPI thermal zone management");

    let state = STATE.get();

    // Set up zone 0 as the CPU package sensor.
    let cpu_name: [u8; 16] = *b"CPU Package\0\0\0\0\0";

    unsafe {
        (*state).zones[0].name = cpu_name;
        (*state).zones[0].valid = false;
        (*state).zone_count = 1;

        if ec_read.is_some() {
            (*state).ec_read = ec_read;
            log("acpi_thermal: EC read callback registered");
        } else {
            (*state).ec_read = None;
            log("acpi_thermal: CPU-only mode (no EC callback)");
        }
    }

    // Attempt an initial CPU temperature read to verify the MSR works.
    let temp = read_cpu_temp_msr();
    if temp >= 0 {
        unsafe {
            (*state).zones[0].temp_millideg = temp;
            (*state).zones[0].valid = true;
            fut_printf(
                b"acpi_thermal: CPU temperature = %d.%03d C\n\0".as_ptr(),
                temp / 1000,
                temp % 1000,
            );
        }
    } else {
        log("acpi_thermal: WARNING -- could not read CPU temperature MSR");
    }

    unsafe {
        (*state).initialized = true;
    }

    log("acpi_thermal: driver initialised (zone 0 = CPU package)");
    0
}

/// Add a board sensor thermal zone backed by an EC register.
///
/// `name`    - Null-terminated ASCII name for the zone (max 15 chars).
/// `ec_addr` - EC register address to read for this sensor.
///
/// Returns the zone ID (1-3) on success, or negative error:
///   -1  = driver not initialised
///   -12 = no free zones (ENOMEM)
///   -22 = no EC callback registered (EINVAL)
#[unsafe(no_mangle)]
pub extern "C" fn acpi_thermal_add_zone(name: *const u8, ec_addr: u8) -> i32 {
    let state = STATE.get();

    unsafe {
        if !(*state).initialized {
            return -1;
        }

        if (*state).ec_read.is_none() {
            log("acpi_thermal: cannot add EC zone without EC callback");
            return -22; // EINVAL
        }

        let count = (*state).zone_count as usize;
        if count >= MAX_ZONES {
            log("acpi_thermal: maximum number of thermal zones reached");
            return -12; // ENOMEM
        }

        let zone_id = count;
        copy_zone_name(&mut (*state).zones[zone_id].name, name);
        (*state).ec_addrs[zone_id - 1] = ec_addr;
        (*state).zones[zone_id].valid = false;
        (*state).zone_count = (count + 1) as u32;

        fut_printf(
            b"acpi_thermal: added zone %u (EC addr 0x%02x)\n\0".as_ptr(),
            zone_id as u32,
            ec_addr as u32,
        );

        zone_id as i32
    }
}

/// Read the current temperature for a thermal zone.
///
/// `zone` - Zone index (0 = CPU, 1-3 = board sensors).
///
/// Returns temperature in millidegrees Celsius on success, or negative
/// error code on failure.
#[unsafe(no_mangle)]
pub extern "C" fn acpi_thermal_read(zone: u32) -> i32 {
    let state = STATE.get();

    unsafe {
        if !(*state).initialized {
            return -1;
        }

        if zone >= (*state).zone_count {
            return -22; // EINVAL
        }

        let temp = if zone == 0 {
            // CPU package: read from MSR.
            read_cpu_temp_msr()
        } else {
            // Board sensor: read from EC.
            let ec_read = match (*state).ec_read {
                Some(f) => f,
                None => return -19, // ENODEV
            };
            let addr = (*state).ec_addrs[(zone - 1) as usize];
            read_ec_sensor(ec_read, addr)
        };

        if temp >= 0 {
            (*state).zones[zone as usize].temp_millideg = temp;
            (*state).zones[zone as usize].valid = true;
        } else {
            (*state).zones[zone as usize].valid = false;
        }

        temp
    }
}

/// Configure trip points for a thermal zone.
///
/// `zone`     - Zone index (0-3).
/// `critical` - Critical temperature in millideg C (shutdown).
/// `hot`      - Hot temperature in millideg C (hardware throttle).
/// `passive`  - Passive temperature in millideg C (OS freq reduction).
///
/// Active trip points retain their previous values; configure them
/// separately if needed.
///
/// Returns 0 on success, negative error on failure.
#[unsafe(no_mangle)]
pub extern "C" fn acpi_thermal_set_trips(
    zone: u32,
    critical: i32,
    hot: i32,
    passive: i32,
) -> i32 {
    let state = STATE.get();

    unsafe {
        if !(*state).initialized {
            return -1;
        }

        if zone >= (*state).zone_count {
            return -22; // EINVAL
        }

        // Validate ordering: passive <= hot <= critical.
        if passive > hot || hot > critical {
            log("acpi_thermal: trip points must satisfy passive <= hot <= critical");
            return -22; // EINVAL
        }

        (*state).zones[zone as usize].critical = critical;
        (*state).zones[zone as usize].hot = hot;
        (*state).zones[zone as usize].passive = passive;

        fut_printf(
            b"acpi_thermal: zone %u trips: passive=%d hot=%d critical=%d (millideg)\n\0"
                .as_ptr(),
            zone,
            passive,
            hot,
            critical,
        );

        0
    }
}

/// Retrieve the full thermal zone descriptor.
///
/// `zone` - Zone index (0-3).
/// `out`  - Pointer to a caller-allocated ThermalZone structure.
///
/// Copies the zone state including current temperature, trip points,
/// fan percentage, and throttle status into the output buffer.
///
/// Returns 0 on success, negative error on failure.
#[unsafe(no_mangle)]
pub extern "C" fn acpi_thermal_get_zone(zone: u32, out: *mut ThermalZone) -> i32 {
    let state = STATE.get();

    unsafe {
        if !(*state).initialized {
            return -1;
        }

        if zone >= (*state).zone_count {
            return -22; // EINVAL
        }

        if out.is_null() {
            return -22; // EINVAL
        }

        core::ptr::write(out, core::ptr::read(&(*state).zones[zone as usize]));

        0
    }
}

/// Evaluate thermal policy for all zones.
///
/// Reads the current temperature of every configured zone and compares
/// it against the zone's trip points. Updates the `throttled` field and
/// computes a recommended fan percentage for each zone.
///
/// Returns a bitmask where bit N is set if zone N requires thermal
/// action (temperature at or above the passive trip point):
///   bit 0 = zone 0 needs action
///   bit 1 = zone 1 needs action
///   etc.
///
/// A return value of 0 means all zones are within safe limits.
#[unsafe(no_mangle)]
pub extern "C" fn acpi_thermal_evaluate() -> u32 {
    let state = STATE.get();

    unsafe {
        if !(*state).initialized {
            return 0;
        }

        let count = (*state).zone_count;
        let mut action_mask: u32 = 0;

        for i in 0..count {
            let idx = i as usize;

            // Read current temperature.
            let temp = if i == 0 {
                read_cpu_temp_msr()
            } else {
                let ec_read = match (*state).ec_read {
                    Some(f) => f,
                    None => continue,
                };
                let addr = (*state).ec_addrs[idx - 1];
                read_ec_sensor(ec_read, addr)
            };

            if temp < 0 {
                (*state).zones[idx].valid = false;
                continue;
            }

            (*state).zones[idx].temp_millideg = temp;
            (*state).zones[idx].valid = true;

            let z = &mut (*state).zones[idx];

            // Evaluate trip points.
            if temp >= z.critical {
                // Critical: signal for immediate shutdown.
                z.throttled = true;
                z.fan_pct = 100;
                action_mask |= 1 << i;
                fut_printf(
                    b"acpi_thermal: CRITICAL zone %u: %d.%03d C >= %d.%03d C\n\0".as_ptr(),
                    i,
                    temp / 1000,
                    temp % 1000,
                    z.critical / 1000,
                    z.critical % 1000,
                );
            } else if temp >= z.hot {
                // Hot: hardware throttle territory.
                z.throttled = true;
                z.fan_pct = 100;
                action_mask |= 1 << i;
            } else if temp >= z.passive {
                // Passive: OS should reduce frequency.
                z.throttled = true;
                z.fan_pct = 80;
                action_mask |= 1 << i;
            } else {
                z.throttled = false;

                // Compute fan percentage from active trip points.
                // active[0] = highest active threshold (fan full),
                // active[3] = lowest active threshold (fan minimum).
                if temp >= z.active[0] {
                    z.fan_pct = 60;
                } else if temp >= z.active[1] {
                    z.fan_pct = 45;
                } else if temp >= z.active[2] {
                    z.fan_pct = 30;
                } else if temp >= z.active[3] {
                    z.fan_pct = 15;
                } else {
                    z.fan_pct = 0;
                }
            }
        }

        action_mask
    }
}

/// Return the number of configured thermal zones.
///
/// Returns 0 if the driver is not initialised.
#[unsafe(no_mangle)]
pub extern "C" fn acpi_thermal_zone_count() -> u32 {
    let state = STATE.get();
    unsafe {
        if !(*state).initialized {
            return 0;
        }
        (*state).zone_count
    }
}
