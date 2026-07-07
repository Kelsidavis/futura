// SPDX-License-Identifier: MPL-2.0
//
// ACPI Battery Driver for Futura OS (x86-64)
//
// Reads battery status from the ACPI Embedded Controller via a caller-
// supplied EC read callback. Supports two common EC battery register
// layouts:
//
//   Layout A ("standard"): used by most Lenovo ThinkPads, Dell, HP
//     0x38: status byte  (bit 0 = discharging, bit 1 = charging,
//                         bit 2 = critical)
//     0x39: rate lo      (mA or mW, depending on power_unit)
//     0x3A: rate hi
//     0x3B: capacity lo  (mAh or mWh remaining)
//     0x3C: capacity hi
//     0x3D: voltage lo   (mV)
//     0x3E: voltage hi
//
//   Static info (read once at init, some vendors):
//     0x40: design cap lo (mAh/mWh)
//     0x41: design cap hi
//     0x42: full charge cap lo
//     0x43: full charge cap hi
//     0x44: design voltage lo (mV)
//     0x45: design voltage hi
//
//   Layout B ("compact"): some newer platforms
//     0x20: status + percentage in one byte (bits [6:0] = %)
//     0x21: rate lo/hi merged or absent
//
// The driver auto-detects by probing: if layout A returns sane values
// (voltage 2000–20000 mV, capacity > 0 when status != 0), it's used;
// otherwise falls back to layout B or reports unavailable.
//
// ACPI SBS (Smart Battery System) over SMBus is NOT handled here;
// that would need a separate SMBus battery driver.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(unexpected_cfgs)]
#![allow(dead_code)]

use core::cell::UnsafeCell;
use common::log;

unsafe extern "C" {
    fn fut_printf(fmt: *const u8, ...);
}

type EcReadFn = unsafe extern "C" fn(addr: u8) -> i32;

// ── EC register addresses (Layout A — ThinkPad/Dell/HP standard) ──

const EC_BAT0_STATUS: u8    = 0x38;
const EC_BAT0_RATE_LO: u8   = 0x39;
const EC_BAT0_RATE_HI: u8   = 0x3A;
const EC_BAT0_CAP_LO: u8    = 0x3B;
const EC_BAT0_CAP_HI: u8    = 0x3C;
const EC_BAT0_VOLT_LO: u8   = 0x3D;
const EC_BAT0_VOLT_HI: u8   = 0x3E;

const EC_BAT0_DCAP_LO: u8   = 0x40;
const EC_BAT0_DCAP_HI: u8   = 0x41;
const EC_BAT0_FCAP_LO: u8   = 0x42;
const EC_BAT0_FCAP_HI: u8   = 0x43;
const EC_BAT0_DVOLT_LO: u8  = 0x44;
const EC_BAT0_DVOLT_HI: u8  = 0x45;

// Status byte bits
const BAT_DISCHARGING: u8 = 1 << 0;
const BAT_CHARGING: u8    = 1 << 1;
const BAT_CRITICAL: u8    = 1 << 2;

// ── Battery state ──

#[derive(Clone, Copy, PartialEq)]
#[repr(u8)]
enum BatLayout {
    None = 0,
    Standard,  // Layout A: status/rate/cap/volt at 0x38-0x3E
    Compact,   // Layout B: percentage-only at 0x20
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct BatteryInfo {
    pub present: bool,
    pub charging: bool,
    pub discharging: bool,
    pub critical: bool,
    pub percentage: u8,
    pub voltage_mv: u16,
    pub current_ma: u16,
    pub remaining_mah: u16,
    pub full_charge_mah: u16,
    pub design_cap_mah: u16,
    pub design_volt_mv: u16,
    pub temperature_dk: u16, // deci-Kelvin (0 = unavailable)
}

impl BatteryInfo {
    const fn empty() -> Self {
        Self {
            present: false,
            charging: false,
            discharging: false,
            critical: false,
            percentage: 0,
            voltage_mv: 0,
            current_ma: 0,
            remaining_mah: 0,
            full_charge_mah: 0,
            design_cap_mah: 0,
            design_volt_mv: 0,
            temperature_dk: 0,
        }
    }
}

struct StaticCell<T>(UnsafeCell<T>);
unsafe impl<T> Sync for StaticCell<T> {}
impl<T> StaticCell<T> {
    const fn new(v: T) -> Self { Self(UnsafeCell::new(v)) }
    fn get(&self) -> *mut T { self.0.get() }
}

struct BatteryState {
    initialized: bool,
    ec_read: Option<EcReadFn>,
    layout: BatLayout,
    info: BatteryInfo,
}

static STATE: StaticCell<BatteryState> = StaticCell::new(BatteryState {
    initialized: false,
    ec_read: None,
    layout: BatLayout::None,
    info: BatteryInfo::empty(),
});

#[inline(always)]
fn state() -> &'static mut BatteryState {
    unsafe { &mut *STATE.get() }
}

fn ec_read(ec: EcReadFn, addr: u8) -> i32 {
    unsafe { ec(addr) }
}

fn ec_read_u16(ec: EcReadFn, lo_addr: u8, hi_addr: u8) -> Option<u16> {
    let lo = ec_read(ec, lo_addr);
    if lo < 0 { return None; }
    let hi = ec_read(ec, hi_addr);
    if hi < 0 { return None; }
    Some(((hi as u16) << 8) | (lo as u16))
}

// ── Layout detection ──

fn probe_layout_a(ec: EcReadFn) -> bool {
    let status = ec_read(ec, EC_BAT0_STATUS);
    if status < 0 || status > 0x07 {
        return false;
    }
    let voltage = match ec_read_u16(ec, EC_BAT0_VOLT_LO, EC_BAT0_VOLT_HI) {
        Some(v) => v,
        None => return false,
    };
    // Sane voltage range: 2.0V–20.0V (single cell to 5S pack)
    if voltage < 2000 || voltage > 20000 {
        return false;
    }
    let cap = match ec_read_u16(ec, EC_BAT0_CAP_LO, EC_BAT0_CAP_HI) {
        Some(c) => c,
        None => return false,
    };
    // At least one of status or capacity should be nonzero if a battery is present
    if status == 0 && cap == 0 {
        return false;
    }
    true
}

fn probe_layout_b(ec: EcReadFn) -> bool {
    let val = ec_read(ec, 0x20);
    if val < 0 {
        return false;
    }
    let pct = (val as u8) & 0x7F;
    pct <= 100
}

// ── Read battery data ──

fn read_standard(ec: EcReadFn, info: &mut BatteryInfo) {
    let status = ec_read(ec, EC_BAT0_STATUS);
    if status < 0 {
        info.present = false;
        return;
    }

    let s = status as u8;
    info.present = true;
    info.discharging = (s & BAT_DISCHARGING) != 0;
    info.charging = (s & BAT_CHARGING) != 0;
    info.critical = (s & BAT_CRITICAL) != 0;

    info.voltage_mv = ec_read_u16(ec, EC_BAT0_VOLT_LO, EC_BAT0_VOLT_HI).unwrap_or(0);
    info.current_ma = ec_read_u16(ec, EC_BAT0_RATE_LO, EC_BAT0_RATE_HI).unwrap_or(0);
    info.remaining_mah = ec_read_u16(ec, EC_BAT0_CAP_LO, EC_BAT0_CAP_HI).unwrap_or(0);
    info.full_charge_mah = ec_read_u16(ec, EC_BAT0_FCAP_LO, EC_BAT0_FCAP_HI).unwrap_or(0);
    info.design_cap_mah = ec_read_u16(ec, EC_BAT0_DCAP_LO, EC_BAT0_DCAP_HI).unwrap_or(0);
    info.design_volt_mv = ec_read_u16(ec, EC_BAT0_DVOLT_LO, EC_BAT0_DVOLT_HI).unwrap_or(0);

    if info.full_charge_mah > 0 {
        let pct = (info.remaining_mah as u32 * 100) / (info.full_charge_mah as u32);
        info.percentage = core::cmp::min(pct, 100) as u8;
    } else if info.design_cap_mah > 0 {
        let pct = (info.remaining_mah as u32 * 100) / (info.design_cap_mah as u32);
        info.percentage = core::cmp::min(pct, 100) as u8;
    } else {
        info.percentage = 0;
    }
}

fn read_compact(ec: EcReadFn, info: &mut BatteryInfo) {
    let val = ec_read(ec, 0x20);
    if val < 0 {
        info.present = false;
        return;
    }
    let raw = val as u8;
    info.present = true;
    info.percentage = raw & 0x7F;
    info.charging = (raw & 0x80) != 0;
    info.discharging = !info.charging && info.percentage < 100;
}

// ── Public C API ──

#[unsafe(no_mangle)]
pub extern "C" fn acpi_battery_init(ec_read_fn: Option<EcReadFn>) -> i32 {
    log("acpi-battery: initializing");

    let ec = match ec_read_fn {
        Some(f) => f,
        None => {
            log("acpi-battery: no EC read callback, skipping");
            return -19; // ENODEV
        }
    };

    let layout = if probe_layout_a(ec) {
        log("acpi-battery: detected standard EC layout (0x38-0x45)");
        BatLayout::Standard
    } else if probe_layout_b(ec) {
        log("acpi-battery: detected compact EC layout (0x20)");
        BatLayout::Compact
    } else {
        log("acpi-battery: no battery detected via EC");
        return -19;
    };

    let s = state();
    s.initialized = true;
    s.ec_read = Some(ec);
    s.layout = layout;

    // Initial read
    acpi_battery_poll();

    let info = &s.info;
    if info.present {
        if layout == BatLayout::Standard {
            unsafe {
                fut_printf(
                    b"acpi-battery: %u%% (%s), %u mV, %u mA, %u/%u mAh\n\0".as_ptr(),
                    info.percentage as u32,
                    if info.charging {
                        b"charging\0".as_ptr()
                    } else if info.discharging {
                        b"discharging\0".as_ptr()
                    } else {
                        b"idle\0".as_ptr()
                    },
                    info.voltage_mv as u32,
                    info.current_ma as u32,
                    info.remaining_mah as u32,
                    info.full_charge_mah as u32,
                );
            }
        } else {
            unsafe {
                fut_printf(
                    b"acpi-battery: %u%% (%s)\n\0".as_ptr(),
                    info.percentage as u32,
                    if info.charging {
                        b"charging\0".as_ptr()
                    } else {
                        b"discharging\0".as_ptr()
                    },
                );
            }
        }
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn acpi_battery_poll() {
    let s = state();
    if !s.initialized {
        return;
    }
    let ec = match s.ec_read {
        Some(f) => f,
        None => return,
    };

    match s.layout {
        BatLayout::Standard => read_standard(ec, &mut s.info),
        BatLayout::Compact => read_compact(ec, &mut s.info),
        BatLayout::None => {}
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn acpi_battery_get_info(out: *mut BatteryInfo) -> i32 {
    let s = state();
    if !s.initialized || out.is_null() {
        return -19;
    }
    acpi_battery_poll();
    unsafe {
        core::ptr::write(out, s.info);
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn acpi_battery_percentage() -> i32 {
    let s = state();
    if !s.initialized {
        return -1;
    }
    acpi_battery_poll();
    if s.info.present {
        s.info.percentage as i32
    } else {
        -1
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn acpi_battery_is_charging() -> bool {
    let s = state();
    if !s.initialized {
        return false;
    }
    s.info.charging
}

#[unsafe(no_mangle)]
pub extern "C" fn acpi_battery_voltage_mv() -> i32 {
    let s = state();
    if !s.initialized {
        return -1;
    }
    s.info.voltage_mv as i32
}

#[unsafe(no_mangle)]
pub extern "C" fn acpi_battery_is_present() -> bool {
    let s = state();
    s.initialized && s.info.present
}
