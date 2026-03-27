// SPDX-License-Identifier: MPL-2.0
//
// Raspberry Pi Hardware Watchdog Timer & Power Management
//
// The BCM2711/BCM2712 has a hardware watchdog timer (PM_WDOG) that can
// reset the system if not fed within the timeout period. Also provides
// system reset and power-off functionality.
//
// Watchdog base: peripheral_base + 0x100000
//
// The watchdog uses a password mechanism: writes must include 0x5A000000
// in the upper bits or they're ignored (prevents accidental resets).
//
// Also handles:
//   - System reboot (via watchdog with 0-tick timeout)
//   - System power-off (via mailbox or PM registers)

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(unexpected_cfgs)]
extern crate common;

use core::ptr::{read_volatile, write_volatile};

// PM (Power Management) register offsets from watchdog base
const PM_RSTC: usize = 0x1C;    // Reset Control
const PM_RSTS: usize = 0x20;    // Reset Status
const PM_WDOG: usize = 0x24;    // Watchdog Timer

// Password for PM register writes (must be in bits 31:24)
const PM_PASSWORD: u32 = 0x5A000000;

// RSTC bits
const PM_RSTC_WRCFG_FULL_RESET: u32 = 0x00000020;
const PM_RSTC_WRCFG_MASK: u32 = 0x00000030;
const PM_RSTC_RESET: u32 = 0x00000102;

// RSTS bits for power-off (partition 63 = halt)
const PM_RSTS_HADPOR: u32 = 0x00001000;
const PM_RSTS_PARTITION_MASK: u32 = 0x00000AAA;

// Watchdog tick rate: 65536 Hz (each tick = ~15.26 µs)
const WDOG_TICKS_PER_SEC: u32 = 65536;

static mut WDOG_BASE: usize = 0;

fn mmio_read(addr: usize) -> u32 {
    unsafe { read_volatile(addr as *const u32) }
}

fn mmio_write(addr: usize, val: u32) {
    unsafe { write_volatile(addr as *mut u32, val) }
}

// ── FFI exports ──

/// Initialize the watchdog timer
/// base_addr: MMIO base (peripheral_base + 0x100000)
#[unsafe(no_mangle)]
pub extern "C" fn rpi_watchdog_init(base_addr: u64) {
    unsafe { WDOG_BASE = base_addr as usize; }
}

/// Start the watchdog with a timeout in seconds
/// The system will reset if rpi_watchdog_feed() is not called within timeout.
/// timeout_secs: 1-15 seconds (hardware maximum ~16s)
#[unsafe(no_mangle)]
pub extern "C" fn rpi_watchdog_start(timeout_secs: u32) {
    let base = unsafe { WDOG_BASE };
    if base == 0 { return; }

    let secs = if timeout_secs > 15 { 15 } else if timeout_secs == 0 { 1 } else { timeout_secs };
    let ticks = secs * WDOG_TICKS_PER_SEC;

    // Set watchdog timer value
    mmio_write(base + PM_WDOG, PM_PASSWORD | (ticks & 0x000FFFFF));

    // Enable watchdog reset
    let rstc = mmio_read(base + PM_RSTC);
    mmio_write(base + PM_RSTC,
               PM_PASSWORD | (rstc & !PM_RSTC_WRCFG_MASK) | PM_RSTC_WRCFG_FULL_RESET);
}

/// Feed (pet) the watchdog to prevent reset
/// Must be called periodically within the timeout period
#[unsafe(no_mangle)]
pub extern "C" fn rpi_watchdog_feed(timeout_secs: u32) {
    let base = unsafe { WDOG_BASE };
    if base == 0 { return; }

    let secs = if timeout_secs > 15 { 15 } else if timeout_secs == 0 { 1 } else { timeout_secs };
    let ticks = secs * WDOG_TICKS_PER_SEC;
    mmio_write(base + PM_WDOG, PM_PASSWORD | (ticks & 0x000FFFFF));
}

/// Stop the watchdog timer
#[unsafe(no_mangle)]
pub extern "C" fn rpi_watchdog_stop() {
    let base = unsafe { WDOG_BASE };
    if base == 0 { return; }

    // Clear the watchdog reset configuration
    let rstc = mmio_read(base + PM_RSTC);
    mmio_write(base + PM_RSTC, PM_PASSWORD | (rstc & !PM_RSTC_WRCFG_MASK));
}

/// Get remaining watchdog time in ticks (~15µs each)
#[unsafe(no_mangle)]
pub extern "C" fn rpi_watchdog_remaining() -> u32 {
    let base = unsafe { WDOG_BASE };
    if base == 0 { return 0; }
    mmio_read(base + PM_WDOG) & 0x000FFFFF
}

/// Reboot the system immediately via watchdog
/// This triggers a full system reset
#[unsafe(no_mangle)]
pub extern "C" fn rpi_system_reboot() {
    let base = unsafe { WDOG_BASE };
    if base == 0 { return; }

    // Set watchdog to minimum timeout (instant reset)
    mmio_write(base + PM_WDOG, PM_PASSWORD | 10); // ~150µs

    // Enable full reset
    let rstc = mmio_read(base + PM_RSTC);
    mmio_write(base + PM_RSTC,
               PM_PASSWORD | (rstc & !PM_RSTC_WRCFG_MASK) | PM_RSTC_WRCFG_FULL_RESET);

    // Spin until reset occurs
    loop { unsafe { core::arch::asm!("wfe") }; }
}

/// Power off the system (halt)
/// Uses partition 63 in RSTS to signal power-off to firmware
#[unsafe(no_mangle)]
pub extern "C" fn rpi_system_poweroff() {
    let base = unsafe { WDOG_BASE };
    if base == 0 { return; }

    // Set RSTS to partition 63 (power-off signal)
    let rsts = mmio_read(base + PM_RSTS);
    mmio_write(base + PM_RSTS, PM_PASSWORD | (rsts & !PM_RSTS_PARTITION_MASK) | 0x00000555);

    // Trigger reset (firmware sees partition 63 and powers off instead of rebooting)
    mmio_write(base + PM_WDOG, PM_PASSWORD | 10);
    let rstc = mmio_read(base + PM_RSTC);
    mmio_write(base + PM_RSTC,
               PM_PASSWORD | (rstc & !PM_RSTC_WRCFG_MASK) | PM_RSTC_WRCFG_FULL_RESET);

    loop { unsafe { core::arch::asm!("wfe") }; }
}
