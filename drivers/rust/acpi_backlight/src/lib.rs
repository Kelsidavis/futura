// SPDX-License-Identifier: MPL-2.0
//
// ACPI / Intel GPU Backlight Driver for Futura OS (x86-64)
//
// Controls laptop panel backlight brightness via two methods:
//
//   Method A — Intel GPU BLC_PWM registers (Gen9+, e.g. Apollo Lake):
//     BLC_PWM_CTL2  (0xC8254): bit 31 = enable, bit 29 = pipe select
//     BLC_PWM_FREQ  (0xC8254): bits [15:0] = PWM frequency divider
//     BLC_PWM_DUTY  (0xC8250): bits [31:16] = max duty, [15:0] = duty
//     Writing duty = 0 → backlight off; duty = max → full brightness.
//
//   Method B — ACPI Embedded Controller:
//     Some vendors expose a brightness register at a fixed EC offset
//     (e.g. ThinkPad EC offset 0x31 = LCDB, range 0x00–0xFF).
//     The caller provides an EC read/write callback pair.
//
// The driver auto-selects: if an i915 MMIO base is provided, it uses
// the GPU registers (more reliable); otherwise falls back to EC.

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
type EcWriteFn = unsafe extern "C" fn(addr: u8, val: u8) -> i32;

// ── Intel GPU backlight registers (Gen9 / Gen11) ──

const BLC_PWM_DUTY: u32 = 0xC8250;
const BLC_PWM_CTL2: u32 = 0xC8254;

// Newer (Gen11+, Ice Lake and later) use the south display engine:
const SBLC_PWM_DUTY: u32 = 0xC8254;
const SBLC_PWM_CTL1: u32 = 0xC8250;
const SBLC_PWM_CTL2: u32 = 0xC8254;

// ── ThinkPad EC backlight register ──

const EC_LCDB: u8 = 0x31;        // LCD brightness (0x00 = off, 0xFF = max)
const EC_LCDB_MAX: u8 = 0xFF;

// ── Driver state ──

#[derive(Clone, Copy, PartialEq)]
#[repr(u8)]
enum BacklightMethod {
    None = 0,
    IntelGpu,
    AcpiEc,
}

struct StaticCell<T>(UnsafeCell<T>);
unsafe impl<T> Sync for StaticCell<T> {}
impl<T> StaticCell<T> {
    const fn new(v: T) -> Self { Self(UnsafeCell::new(v)) }
    fn get(&self) -> *mut T { self.0.get() }
}

struct BacklightState {
    initialized: bool,
    method: BacklightMethod,
    // Intel GPU path
    mmio_base: *mut u8,
    pwm_max: u32,
    // EC path
    ec_read: Option<EcReadFn>,
    ec_write: Option<EcWriteFn>,
    // Cached brightness (0–100)
    brightness: u8,
    max_brightness: u8,
}

unsafe impl Send for BacklightState {}
unsafe impl Sync for BacklightState {}

static STATE: StaticCell<BacklightState> = StaticCell::new(BacklightState {
    initialized: false,
    method: BacklightMethod::None,
    mmio_base: core::ptr::null_mut(),
    pwm_max: 0,
    ec_read: None,
    ec_write: None,
    brightness: 0,
    max_brightness: 100,
});

#[inline(always)]
fn state() -> &'static mut BacklightState {
    unsafe { &mut *STATE.get() }
}

#[inline(always)]
unsafe fn mmio_read32(base: *const u8, offset: u32) -> u32 {
    unsafe { core::ptr::read_volatile(base.add(offset as usize) as *const u32) }
}

#[inline(always)]
unsafe fn mmio_write32(base: *mut u8, offset: u32, val: u32) {
    unsafe { core::ptr::write_volatile(base.add(offset as usize) as *mut u32, val) }
}

// ── Intel GPU backlight ──

fn intel_gpu_read_brightness(mmio: *const u8) -> (u32, u32) {
    let duty_reg = unsafe { mmio_read32(mmio, BLC_PWM_DUTY) };
    let max_duty = (duty_reg >> 16) & 0xFFFF;
    let cur_duty = duty_reg & 0xFFFF;
    (cur_duty, max_duty)
}

fn intel_gpu_set_brightness(mmio: *mut u8, duty: u32, max_duty: u32) {
    let val = (max_duty << 16) | (duty & 0xFFFF);
    unsafe { mmio_write32(mmio, BLC_PWM_DUTY, val); }
}

// ── EC backlight ──

fn ec_read_brightness(ec_read: EcReadFn) -> u8 {
    let val = unsafe { ec_read(EC_LCDB) };
    if val < 0 { 0 } else { val as u8 }
}

fn ec_set_brightness(ec_write: EcWriteFn, level: u8) -> i32 {
    unsafe { ec_write(EC_LCDB, level) }
}

// ── Public C API ──

#[unsafe(no_mangle)]
pub extern "C" fn acpi_backlight_init(
    gpu_mmio: *mut u8,
    ec_read_fn: Option<EcReadFn>,
    ec_write_fn: Option<EcWriteFn>,
) -> i32 {
    log("acpi-backlight: initializing");

    let s = state();

    // Prefer Intel GPU if MMIO base is provided
    if !gpu_mmio.is_null() {
        let (cur, max) = intel_gpu_read_brightness(gpu_mmio);
        if max > 0 {
            s.method = BacklightMethod::IntelGpu;
            s.mmio_base = gpu_mmio;
            s.pwm_max = max;
            s.brightness = ((cur as u64 * 100) / (max as u64)) as u8;
            s.max_brightness = 100;
            s.initialized = true;
            unsafe {
                fut_printf(
                    b"acpi-backlight: Intel GPU PWM (duty=%u/%u, %u%%)\n\0".as_ptr(),
                    cur, max, s.brightness as u32,
                );
            }
            return 0;
        }
    }

    // Fallback to EC
    if let (Some(rd), Some(wr)) = (ec_read_fn, ec_write_fn) {
        let raw = ec_read_brightness(rd);
        s.method = BacklightMethod::AcpiEc;
        s.ec_read = Some(rd);
        s.ec_write = Some(wr);
        s.brightness = ((raw as u32 * 100) / EC_LCDB_MAX as u32) as u8;
        s.max_brightness = 100;
        s.initialized = true;
        unsafe {
            fut_printf(
                b"acpi-backlight: EC register (raw=%u, %u%%)\n\0".as_ptr(),
                raw as u32, s.brightness as u32,
            );
        }
        return 0;
    }

    log("acpi-backlight: no backlight control available");
    -19 // ENODEV
}

#[unsafe(no_mangle)]
pub extern "C" fn acpi_backlight_get() -> i32 {
    let s = state();
    if !s.initialized { return -1; }

    match s.method {
        BacklightMethod::IntelGpu => {
            let (cur, max) = intel_gpu_read_brightness(s.mmio_base);
            if max > 0 {
                ((cur as u64 * 100) / (max as u64)) as i32
            } else {
                s.brightness as i32
            }
        }
        BacklightMethod::AcpiEc => {
            if let Some(rd) = s.ec_read {
                let raw = ec_read_brightness(rd);
                ((raw as u32 * 100) / EC_LCDB_MAX as u32) as i32
            } else {
                -1
            }
        }
        BacklightMethod::None => -1,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn acpi_backlight_set(percent: u8) -> i32 {
    let s = state();
    if !s.initialized { return -19; }
    let pct = if percent > 100 { 100 } else { percent };

    match s.method {
        BacklightMethod::IntelGpu => {
            let duty = (pct as u32 * s.pwm_max) / 100;
            intel_gpu_set_brightness(s.mmio_base, duty, s.pwm_max);
            s.brightness = pct;
            0
        }
        BacklightMethod::AcpiEc => {
            if let Some(wr) = s.ec_write {
                let raw = (pct as u32 * EC_LCDB_MAX as u32) / 100;
                let rc = ec_set_brightness(wr, raw as u8);
                if rc >= 0 { s.brightness = pct; }
                rc
            } else {
                -19
            }
        }
        BacklightMethod::None => -19,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn acpi_backlight_max() -> i32 {
    let s = state();
    if !s.initialized { return -1; }
    s.max_brightness as i32
}

#[unsafe(no_mangle)]
pub extern "C" fn acpi_backlight_up() -> i32 {
    let cur = acpi_backlight_get();
    if cur < 0 { return cur; }
    let new = core::cmp::min(cur + 10, 100) as u8;
    acpi_backlight_set(new)
}

#[unsafe(no_mangle)]
pub extern "C" fn acpi_backlight_down() -> i32 {
    let cur = acpi_backlight_get();
    if cur < 0 { return cur; }
    let new = if cur > 10 { (cur - 10) as u8 } else { 0 };
    acpi_backlight_set(new)
}
