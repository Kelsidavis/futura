// SPDX-License-Identifier: MPL-2.0
//
// Intel Thermal Management (DPTF/PECI) Driver for Futura OS
//
// Provides CPU and package thermal monitoring, PROCHOT/throttle status,
// and RAPL power limit management on Intel Gen 10+ (Ice Lake and later)
// platforms.
//
// Key MSRs:
//   0x19C  IA32_THERM_STATUS         per-core thermal status and digital readout
//   0x1A2  MSR_TEMPERATURE_TARGET    TjMax (thermal junction maximum)
//   0x1B1  IA32_PACKAGE_THERM_STATUS package-level thermal status
//   0x606  MSR_RAPL_POWER_UNIT       RAPL unit divisors (power, energy, time)
//   0x610  MSR_PKG_POWER_LIMIT       PL1/PL2 power limits
//   0x611  MSR_PKG_ENERGY_STATUS     cumulative package energy counter
//   0x639  MSR_PP0_ENERGY_STATUS     cumulative core energy counter
//   0x641  MSR_PP1_ENERGY_STATUS     cumulative GPU/uncore energy counter
//
// Temperature calculation:
//   cpu_temp = TjMax - digital_readout
//
// RAPL energy units:
//   energy_joules = raw_counter * (0.5 ^ energy_unit)
//   energy_microjoules = raw_counter * 1_000_000 / (1 << energy_unit)

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(unexpected_cfgs)]

use core::cell::UnsafeCell;

use common::log;

unsafe extern "C" {
    fn fut_printf(fmt: *const u8, ...);
}

// -- Static state wrapper --

/// Wrapper to allow `UnsafeCell` in a `static` (requires `Sync`).
/// Safety: all access is single-threaded or externally synchronised by the caller.
struct StaticCell<T>(UnsafeCell<T>);
unsafe impl<T> Sync for StaticCell<T> {}
impl<T> StaticCell<T> {
    const fn new(v: T) -> Self { Self(UnsafeCell::new(v)) }
    fn get(&self) -> *mut T { self.0.get() }
}

// -- MSR addresses --

/// IA32_THERM_STATUS: per-core thermal status.
/// bits[22:16] = Digital Readout (offset below TjMax).
/// bits[30:27] = Resolution in degrees C.
/// bit 0 = Thermal Status (DCC active).
/// bit 1 = Thermal Status Log.
/// bit 2 = PROCHOT# or FORCEPR# asserted.
/// bit 4 = Critical Temperature Status.
/// bit 6 = Thermal Threshold #1 Status.
/// bit 8 = Thermal Threshold #2 Status.
const MSR_IA32_THERM_STATUS: u32 = 0x19C;

/// MSR_TEMPERATURE_TARGET: bits[23:16] = TjMax in degrees C.
const MSR_TEMPERATURE_TARGET: u32 = 0x1A2;

/// IA32_PACKAGE_THERM_STATUS: package-level thermal status.
/// Same bit layout as IA32_THERM_STATUS.
const MSR_IA32_PKG_THERM_STATUS: u32 = 0x1B1;

/// MSR_RAPL_POWER_UNIT: unit divisors for RAPL domains.
/// bits[3:0]   = Power units (watts = 1 / 2^val).
/// bits[12:8]  = Energy units (joules = 1 / 2^val).
/// bits[19:16] = Time units (seconds = 1 / 2^val).
const MSR_RAPL_POWER_UNIT: u32 = 0x606;

/// MSR_PKG_POWER_LIMIT: PL1 and PL2 configuration.
/// bits[14:0]  = PL1 power limit (in RAPL power units).
/// bit 15      = PL1 enable.
/// bits[23:17] = PL1 time window (encoded).
/// bits[46:32] = PL2 power limit (in RAPL power units).
/// bit 47      = PL2 enable.
const MSR_PKG_POWER_LIMIT: u32 = 0x610;

/// MSR_PKG_ENERGY_STATUS: cumulative package energy consumed.
const MSR_PKG_ENERGY_STATUS: u32 = 0x611;

/// MSR_PP0_ENERGY_STATUS: cumulative core domain energy consumed.
#[allow(dead_code)]
const MSR_PP0_ENERGY_STATUS: u32 = 0x639;

/// MSR_PP1_ENERGY_STATUS: cumulative GPU/uncore domain energy consumed.
#[allow(dead_code)]
const MSR_PP1_ENERGY_STATUS: u32 = 0x641;

// -- Thermal status bit masks --

/// Bit 0: Thermal Status (DCC active).
const THERM_STATUS_DCC: u64 = 1 << 0;
/// Bit 2: PROCHOT# or FORCEPR# event.
const THERM_STATUS_PROCHOT: u64 = 1 << 2;
/// Bit 4: Critical Temperature Status.
#[allow(dead_code)]
const THERM_STATUS_CRITICAL: u64 = 1 << 4;
/// Bit 6: Thermal Threshold #1 Status.
#[allow(dead_code)]
const THERM_STATUS_THRESH1: u64 = 1 << 6;
/// Bit 8: Thermal Threshold #2 Status.
#[allow(dead_code)]
const THERM_STATUS_THRESH2: u64 = 1 << 8;

/// Digital Readout field: bits[22:16].
const THERM_DIGITAL_READOUT_SHIFT: u32 = 16;
const THERM_DIGITAL_READOUT_MASK: u64 = 0x7F << 16;

/// Resolution field: bits[30:27].
const THERM_RESOLUTION_SHIFT: u32 = 27;
const THERM_RESOLUTION_MASK: u64 = 0xF << 27;

// -- RAPL power limit bit masks --

/// PL1 power limit: bits[14:0].
const PL1_POWER_MASK: u64 = 0x7FFF;
/// PL1 enable: bit 15.
const PL1_ENABLE_BIT: u64 = 1 << 15;
/// PL1 time window: bits[23:17].
#[allow(dead_code)]
const PL1_TIME_SHIFT: u32 = 17;
const PL1_TIME_MASK: u64 = 0x7F << 17;

/// PL2 power limit: bits[46:32].
const PL2_POWER_SHIFT: u32 = 32;
const PL2_POWER_MASK: u64 = 0x7FFF_u64 << 32;
/// PL2 enable: bit 47.
const PL2_ENABLE_BIT: u64 = 1 << 47;

// -- CPUID thermal leaf --

const CPUID_THERMAL_POWER: u32 = 0x06;
/// CPUID 0x06 EAX bit 0: Digital Thermal Sensor supported.
const DTS_BIT: u32 = 1 << 0;
/// CPUID 0x06 EAX bit 6: Package Thermal Management supported.
const PTM_BIT: u32 = 1 << 6;

// -- ThermalInfo structure (exported to C) --

/// Comprehensive thermal status snapshot.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct ThermalInfo {
    pub cpu_temp_c: i32,
    pub pkg_temp_c: i32,
    pub tjmax_c: u32,
    pub pl1_watts: u32,
    pub pl2_watts: u32,
    pub pkg_energy_j: u64,
    pub prochot_active: bool,
    pub thermal_throttled: bool,
}

impl ThermalInfo {
    const fn zero() -> Self {
        Self {
            cpu_temp_c: 0,
            pkg_temp_c: 0,
            tjmax_c: 0,
            pl1_watts: 0,
            pl2_watts: 0,
            pkg_energy_j: 0,
            prochot_active: false,
            thermal_throttled: false,
        }
    }
}

// -- Inline assembly helpers --

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

/// Write a 64-bit Model-Specific Register.
fn wrmsr(msr: u32, val: u64) {
    let lo = val as u32;
    let hi = (val >> 32) as u32;
    unsafe {
        core::arch::asm!(
            "wrmsr",
            in("ecx") msr,
            in("eax") lo,
            in("edx") hi,
            options(nomem, nostack, preserves_flags),
        );
    }
}

/// Execute CPUID instruction and return (eax, ebx, ecx, edx).
fn cpuid(leaf: u32) -> (u32, u32, u32, u32) {
    let eax: u32;
    let ebx: u32;
    let ecx: u32;
    let edx: u32;
    unsafe {
        core::arch::asm!(
            "push rbx",
            "cpuid",
            "mov {ebx_out:e}, ebx",
            "pop rbx",
            inout("eax") leaf => eax,
            ebx_out = out(reg) ebx,
            inout("ecx") 0u32 => ecx,
            lateout("edx") edx,
            options(nomem, preserves_flags),
        );
    }
    (eax, ebx, ecx, edx)
}

// -- Driver state --

struct ThermalState {
    /// Whether the driver has been initialised.
    initialized: bool,
    /// TjMax in degrees C (read from MSR_TEMPERATURE_TARGET).
    tjmax_c: u32,
    /// RAPL power unit: watts = raw / (1 << power_unit).
    power_unit: u32,
    /// RAPL energy unit: joules = raw / (1 << energy_unit).
    energy_unit: u32,
    /// RAPL time unit: seconds = raw / (1 << time_unit).
    time_unit: u32,
    /// Digital Thermal Sensor capability (CPUID 0x06 EAX bit 0).
    has_dts: bool,
    /// Package Thermal Management capability (CPUID 0x06 EAX bit 6).
    has_ptm: bool,
}

impl ThermalState {
    const fn new() -> Self {
        Self {
            initialized: false,
            tjmax_c: 0,
            power_unit: 0,
            energy_unit: 0,
            time_unit: 0,
            has_dts: false,
            has_ptm: false,
        }
    }
}

static STATE: StaticCell<ThermalState> = StaticCell::new(ThermalState::new());

// -- Internal helpers --

/// Detect thermal features from CPUID leaf 0x06.
fn detect_thermal_features() -> (bool, bool) {
    let (eax, _ebx, _ecx, _edx) = cpuid(CPUID_THERMAL_POWER);
    let has_dts = (eax & DTS_BIT) != 0;
    let has_ptm = (eax & PTM_BIT) != 0;
    (has_dts, has_ptm)
}

/// Read TjMax from MSR_TEMPERATURE_TARGET bits[23:16].
fn read_tjmax() -> u32 {
    let val = rdmsr(MSR_TEMPERATURE_TARGET);
    ((val >> 16) & 0xFF) as u32
}

/// Read RAPL power units from MSR_RAPL_POWER_UNIT.
/// Returns (power_unit, energy_unit, time_unit) as shift values.
fn read_rapl_units() -> (u32, u32, u32) {
    let val = rdmsr(MSR_RAPL_POWER_UNIT);
    let power_unit = (val & 0xF) as u32;
    let energy_unit = ((val >> 8) & 0x1F) as u32;
    let time_unit = ((val >> 16) & 0xF) as u32;
    (power_unit, energy_unit, time_unit)
}

/// Read the digital readout from a thermal status MSR.
/// Returns the offset below TjMax (in degrees C).
fn read_digital_readout(msr: u32) -> u32 {
    let val = rdmsr(msr);
    ((val & THERM_DIGITAL_READOUT_MASK) >> THERM_DIGITAL_READOUT_SHIFT) as u32
}

/// Read the temperature resolution from a thermal status MSR.
/// Returns the resolution in degrees C.
fn read_resolution(msr: u32) -> u32 {
    let val = rdmsr(msr);
    ((val & THERM_RESOLUTION_MASK) >> THERM_RESOLUTION_SHIFT) as u32
}

/// Check if PROCHOT# is asserted from a thermal status MSR.
fn is_prochot(msr: u32) -> bool {
    let val = rdmsr(msr);
    (val & THERM_STATUS_PROCHOT) != 0
}

/// Check if thermal throttling (DCC) is active from a thermal status MSR.
fn is_throttled(msr: u32) -> bool {
    let val = rdmsr(msr);
    (val & THERM_STATUS_DCC) != 0
}

/// Read a power limit in watts from the raw RAPL value.
/// raw_power is in RAPL power units; power_unit is the shift value.
fn rapl_power_to_watts(raw_power: u64, power_unit: u32) -> u32 {
    if power_unit == 0 {
        return raw_power as u32;
    }
    (raw_power / (1u64 << power_unit)) as u32
}

/// Convert a watts value to raw RAPL power units.
fn watts_to_rapl_power(watts: u32, power_unit: u32) -> u64 {
    (watts as u64) * (1u64 << power_unit)
}

/// Convert a raw energy counter to microjoules.
fn rapl_energy_to_uj(raw_energy: u64, energy_unit: u32) -> u64 {
    // microjoules = raw * 1_000_000 / (1 << energy_unit)
    // To avoid overflow for large counters, split the multiplication.
    if energy_unit >= 20 {
        // 1_000_000 / (1 << 20) < 1, so shift differently
        raw_energy / ((1u64 << energy_unit) / 1_000_000)
    } else {
        (raw_energy * 1_000_000) >> energy_unit
    }
}

// -- FFI exports --

/// Initialise the Intel thermal management driver.
///
/// Detects thermal sensor and package thermal management support via
/// CPUID leaf 0x06, reads TjMax from MSR_TEMPERATURE_TARGET, and
/// decodes RAPL power units from MSR_RAPL_POWER_UNIT.
///
/// Returns 0 on success, negative on failure:
///   -95 (ENOTSUP) = Digital Thermal Sensor not supported.
#[unsafe(no_mangle)]
pub extern "C" fn intel_thermal_init() -> i32 {
    log("intel_thermal: initialising Intel thermal management driver");

    // Detect feature support.
    let (has_dts, has_ptm) = detect_thermal_features();
    if !has_dts {
        log("intel_thermal: Digital Thermal Sensor not supported (CPUID 0x06 EAX bit 0 clear)");
        return -95; // ENOTSUP
    }

    unsafe {
        fut_printf(
            b"intel_thermal: features: DTS=%u PTM=%u\n\0".as_ptr(),
            has_dts as u32,
            has_ptm as u32,
        );
    }

    // Read TjMax.
    let tjmax = read_tjmax();
    if tjmax == 0 {
        log("intel_thermal: WARNING: TjMax reads as 0, defaulting to 100C");
    }
    let tjmax = if tjmax == 0 { 100 } else { tjmax };

    unsafe {
        fut_printf(
            b"intel_thermal: TjMax = %u C\n\0".as_ptr(),
            tjmax,
        );
    }

    // Read RAPL power units.
    let (power_unit, energy_unit, time_unit) = read_rapl_units();
    unsafe {
        fut_printf(
            b"intel_thermal: RAPL units: power=%u energy=%u time=%u\n\0".as_ptr(),
            power_unit,
            energy_unit,
            time_unit,
        );
    }

    // Read initial temperatures.
    let cpu_readout = read_digital_readout(MSR_IA32_THERM_STATUS);
    let cpu_temp = tjmax as i32 - cpu_readout as i32;
    let resolution = read_resolution(MSR_IA32_THERM_STATUS);

    unsafe {
        fut_printf(
            b"intel_thermal: CPU temp = %d C (readout=%u, resolution=%u C)\n\0".as_ptr(),
            cpu_temp,
            cpu_readout,
            resolution,
        );
    }

    if has_ptm {
        let pkg_readout = read_digital_readout(MSR_IA32_PKG_THERM_STATUS);
        let pkg_temp = tjmax as i32 - pkg_readout as i32;
        unsafe {
            fut_printf(
                b"intel_thermal: Package temp = %d C (readout=%u)\n\0".as_ptr(),
                pkg_temp,
                pkg_readout,
            );
        }
    }

    // Read current power limits.
    let pwr_limit = rdmsr(MSR_PKG_POWER_LIMIT);
    let pl1_raw = pwr_limit & PL1_POWER_MASK;
    let pl1_enabled = (pwr_limit & PL1_ENABLE_BIT) != 0;
    let pl1_watts = rapl_power_to_watts(pl1_raw, power_unit);

    let pl2_raw = (pwr_limit & PL2_POWER_MASK) >> PL2_POWER_SHIFT;
    let pl2_enabled = (pwr_limit & PL2_ENABLE_BIT) != 0;
    let pl2_watts = rapl_power_to_watts(pl2_raw, power_unit);

    unsafe {
        fut_printf(
            b"intel_thermal: PL1=%u W (enabled=%u) PL2=%u W (enabled=%u)\n\0".as_ptr(),
            pl1_watts,
            pl1_enabled as u32,
            pl2_watts,
            pl2_enabled as u32,
        );
    }

    // Log PROCHOT / throttle status.
    let prochot = is_prochot(MSR_IA32_THERM_STATUS);
    let throttled = is_throttled(MSR_IA32_THERM_STATUS);
    if prochot {
        log("intel_thermal: WARNING: PROCHOT# is currently asserted");
    }
    if throttled {
        log("intel_thermal: WARNING: thermal throttling (DCC) is active");
    }

    // Read initial energy counters.
    let pkg_energy_raw = rdmsr(MSR_PKG_ENERGY_STATUS) & 0xFFFF_FFFF;
    let pkg_energy_uj = rapl_energy_to_uj(pkg_energy_raw, energy_unit);
    unsafe {
        fut_printf(
            b"intel_thermal: package energy counter = %llu uJ (raw=0x%08x)\n\0".as_ptr(),
            pkg_energy_uj,
            pkg_energy_raw as u32,
        );
    }

    // Store driver state.
    let state = ThermalState {
        initialized: true,
        tjmax_c: tjmax,
        power_unit,
        energy_unit,
        time_unit,
        has_dts,
        has_ptm,
    };

    unsafe {
        (*STATE.get()) = state;
    }

    log("intel_thermal: driver initialised successfully");
    0
}

/// Get the current CPU core temperature in degrees C.
///
/// Reads IA32_THERM_STATUS digital readout and subtracts from TjMax.
/// Returns 0 if the driver is not initialised.
#[unsafe(no_mangle)]
pub extern "C" fn intel_thermal_cpu_temp() -> i32 {
    let state = unsafe { &*STATE.get() };
    if !state.initialized {
        return 0;
    }

    let readout = read_digital_readout(MSR_IA32_THERM_STATUS);
    state.tjmax_c as i32 - readout as i32
}

/// Get the current package temperature in degrees C.
///
/// Reads IA32_PACKAGE_THERM_STATUS digital readout and subtracts from TjMax.
/// Returns 0 if the driver is not initialised or PTM is not supported.
#[unsafe(no_mangle)]
pub extern "C" fn intel_thermal_pkg_temp() -> i32 {
    let state = unsafe { &*STATE.get() };
    if !state.initialized || !state.has_ptm {
        return 0;
    }

    let readout = read_digital_readout(MSR_IA32_PKG_THERM_STATUS);
    state.tjmax_c as i32 - readout as i32
}

/// Get the TjMax (thermal junction maximum) in degrees C.
///
/// Returns 0 if the driver is not initialised.
#[unsafe(no_mangle)]
pub extern "C" fn intel_thermal_tjmax() -> u32 {
    let state = unsafe { &*STATE.get() };
    if !state.initialized {
        return 0;
    }
    state.tjmax_c
}

/// Fill a ThermalInfo structure with a comprehensive thermal status snapshot.
///
/// Returns 0 on success, negative on failure:
///   -19 (ENODEV) = driver not initialised.
///   -22 (EINVAL) = null pointer.
#[unsafe(no_mangle)]
pub extern "C" fn intel_thermal_get_info(info: *mut ThermalInfo) -> i32 {
    let state = unsafe { &*STATE.get() };
    if !state.initialized {
        return -19; // ENODEV
    }
    if info.is_null() {
        return -22; // EINVAL
    }

    let cpu_readout = read_digital_readout(MSR_IA32_THERM_STATUS);
    let cpu_temp = state.tjmax_c as i32 - cpu_readout as i32;

    let pkg_temp = if state.has_ptm {
        let pkg_readout = read_digital_readout(MSR_IA32_PKG_THERM_STATUS);
        state.tjmax_c as i32 - pkg_readout as i32
    } else {
        cpu_temp // fallback to CPU temp if PTM not available
    };

    // Read power limits.
    let pwr_limit = rdmsr(MSR_PKG_POWER_LIMIT);
    let pl1_raw = pwr_limit & PL1_POWER_MASK;
    let pl1_watts = rapl_power_to_watts(pl1_raw, state.power_unit);
    let pl2_raw = (pwr_limit & PL2_POWER_MASK) >> PL2_POWER_SHIFT;
    let pl2_watts = rapl_power_to_watts(pl2_raw, state.power_unit);

    // Read energy counter (convert to joules).
    let pkg_energy_raw = rdmsr(MSR_PKG_ENERGY_STATUS) & 0xFFFF_FFFF;
    let pkg_energy_j = if state.energy_unit > 0 {
        pkg_energy_raw / (1u64 << state.energy_unit)
    } else {
        pkg_energy_raw
    };

    // Read throttle/PROCHOT status.
    let prochot = is_prochot(MSR_IA32_THERM_STATUS);
    let throttled = is_throttled(MSR_IA32_THERM_STATUS);

    let result = ThermalInfo {
        cpu_temp_c: cpu_temp,
        pkg_temp_c: pkg_temp,
        tjmax_c: state.tjmax_c,
        pl1_watts,
        pl2_watts,
        pkg_energy_j,
        prochot_active: prochot,
        thermal_throttled: throttled,
    };

    unsafe {
        core::ptr::write(info, result);
    }

    0
}

/// Get the cumulative package energy consumed in microjoules.
///
/// Reads MSR_PKG_ENERGY_STATUS and converts using RAPL energy units.
/// Returns 0 if the driver is not initialised.
#[unsafe(no_mangle)]
pub extern "C" fn intel_thermal_pkg_energy_uj() -> u64 {
    let state = unsafe { &*STATE.get() };
    if !state.initialized {
        return 0;
    }

    let raw = rdmsr(MSR_PKG_ENERGY_STATUS) & 0xFFFF_FFFF;
    rapl_energy_to_uj(raw, state.energy_unit)
}

/// Set the PL1 (sustained) power limit in watts.
///
/// Modifies only the PL1 field and enable bit in MSR_PKG_POWER_LIMIT,
/// preserving PL2 and all other fields.
///
/// Returns 0 on success, negative on failure:
///   -19 (ENODEV) = driver not initialised.
///   -22 (EINVAL) = watts value exceeds representable range.
#[unsafe(no_mangle)]
pub extern "C" fn intel_thermal_set_pl1(watts: u32) -> i32 {
    let state = unsafe { &*STATE.get() };
    if !state.initialized {
        return -19; // ENODEV
    }

    let raw_power = watts_to_rapl_power(watts, state.power_unit);
    if raw_power > PL1_POWER_MASK as u64 {
        log("intel_thermal: PL1 value exceeds representable range");
        return -22; // EINVAL
    }

    // Read current value, clear PL1 fields, set new value with enable.
    let current = rdmsr(MSR_PKG_POWER_LIMIT);
    let cleared = current & !(PL1_POWER_MASK | PL1_ENABLE_BIT | PL1_TIME_MASK);
    // Preserve existing time window, set new power and enable.
    let time_window = current & PL1_TIME_MASK;
    let new_val = cleared | raw_power | PL1_ENABLE_BIT | time_window;
    wrmsr(MSR_PKG_POWER_LIMIT, new_val);

    unsafe {
        fut_printf(
            b"intel_thermal: set PL1 = %u W (raw=0x%04x)\n\0".as_ptr(),
            watts,
            raw_power as u32,
        );
    }

    0
}

/// Get the current PL1 (sustained) power limit in watts.
///
/// Returns 0 if the driver is not initialised.
#[unsafe(no_mangle)]
pub extern "C" fn intel_thermal_get_pl1() -> u32 {
    let state = unsafe { &*STATE.get() };
    if !state.initialized {
        return 0;
    }

    let pwr_limit = rdmsr(MSR_PKG_POWER_LIMIT);
    let pl1_raw = pwr_limit & PL1_POWER_MASK;
    rapl_power_to_watts(pl1_raw, state.power_unit)
}

/// Check whether the CPU is currently being thermally throttled.
///
/// Returns true if either PROCHOT# is asserted or DCC (duty cycle
/// clocking) is active, indicating thermal throttling is in effect.
///
/// Returns false if the driver is not initialised.
#[unsafe(no_mangle)]
pub extern "C" fn intel_thermal_is_throttled() -> bool {
    let state = unsafe { &*STATE.get() };
    if !state.initialized {
        return false;
    }

    let val = rdmsr(MSR_IA32_THERM_STATUS);
    let prochot = (val & THERM_STATUS_PROCHOT) != 0;
    let dcc = (val & THERM_STATUS_DCC) != 0;
    prochot || dcc
}
