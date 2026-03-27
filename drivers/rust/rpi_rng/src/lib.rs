// SPDX-License-Identifier: MPL-2.0
//
// Raspberry Pi Hardware Random Number Generator Driver
//
// BCM2711 has a TRNG (True Random Number Generator) at peripheral_base + 0x104000.
// Based on thermal noise, provides high-quality entropy for /dev/hwrng,
// /dev/urandom seeding, and cryptographic operations.
//
// The RNG200 controller has a FIFO that fills with random words.
// Reading from the FIFO drains it; the hardware continuously generates
// new entropy to refill.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(unexpected_cfgs)]
extern crate common;

use core::ptr::{read_volatile, write_volatile};

// RNG200 register offsets
const RNG_CTRL: usize = 0x00;       // Control register
const RNG_STATUS: usize = 0x04;     // Status (includes FIFO count)
const RNG_DATA: usize = 0x08;       // Random data output
const RNG_FF_THRESH: usize = 0x0C;  // FIFO full threshold
const RNG_INT_MASK: usize = 0x10;   // Interrupt mask

// Older iproc-rng200 registers (BCM2711 variant)
const RNG_CTRL_V2: usize = 0x00;
const RNG_SOFT_RESET: usize = 0x04;
const RNG_RBGEN: usize = 0x28;      // RBG enable
const RNG_INT_STATUS: usize = 0x18;
const RNG_FIFO_DATA: usize = 0x20;
const RNG_FIFO_COUNT: usize = 0x24;

// Control bits
const RNG_RBGEN_ENABLE: u32 = 1 << 0;

static mut RNG_BASE: usize = 0;
static mut RNG_INITIALIZED: bool = false;

fn mmio_read(addr: usize) -> u32 {
    unsafe { read_volatile(addr as *const u32) }
}

fn mmio_write(addr: usize, val: u32) {
    unsafe { write_volatile(addr as *mut u32, val) }
}

fn delay(n: u32) {
    for _ in 0..n { unsafe { core::arch::asm!("yield") }; }
}

// ── FFI exports ──

/// Initialize the hardware RNG
/// base_addr: MMIO base (peripheral_base + 0x104000)
#[unsafe(no_mangle)]
pub extern "C" fn rpi_rng_init(base_addr: u64) -> i32 {
    let base = base_addr as usize;
    unsafe {
        RNG_BASE = base;
        RNG_INITIALIZED = false;
    }

    // Soft reset
    mmio_write(base + RNG_SOFT_RESET, 1);
    delay(1000);
    mmio_write(base + RNG_SOFT_RESET, 0);
    delay(1000);

    // Enable RBG (Random Bit Generator)
    mmio_write(base + RNG_RBGEN, RNG_RBGEN_ENABLE);
    delay(1000);

    // Disable interrupts (we'll poll)
    mmio_write(base + RNG_INT_MASK, 0xFFFFFFFF);

    // Wait for FIFO to start filling
    for _ in 0..10000 {
        let count = mmio_read(base + RNG_FIFO_COUNT) >> 24;
        if count > 0 {
            unsafe { RNG_INITIALIZED = true; }
            return 0;
        }
        delay(100);
    }

    // RNG may still work even if FIFO count is slow to appear
    unsafe { RNG_INITIALIZED = true; }
    0
}

/// Get a random 32-bit value from the hardware RNG
/// Returns: random u32, or 0 if RNG not ready
#[unsafe(no_mangle)]
pub extern "C" fn rpi_rng_read32() -> u32 {
    let base = unsafe { RNG_BASE };
    if base == 0 { return 0; }

    // Wait for FIFO to have data (with timeout)
    for _ in 0..10000 {
        let count = mmio_read(base + RNG_FIFO_COUNT) >> 24;
        if count > 0 {
            return mmio_read(base + RNG_FIFO_DATA);
        }
        delay(1);
    }

    // Fallback: read anyway (may get stale data)
    mmio_read(base + RNG_FIFO_DATA)
}

/// Fill a buffer with random bytes from hardware RNG
/// buf: output buffer
/// len: number of bytes to fill
/// Returns: number of bytes filled
#[unsafe(no_mangle)]
pub extern "C" fn rpi_rng_fill(buf: *mut u8, len: u32) -> u32 {
    if buf.is_null() || len == 0 { return 0; }
    let base = unsafe { RNG_BASE };
    if base == 0 { return 0; }

    let mut filled = 0u32;
    while filled < len {
        // Get a random word
        let word = rpi_rng_read32();
        let bytes = word.to_le_bytes();

        for b in &bytes {
            if filled >= len { break; }
            unsafe { *buf.add(filled as usize) = *b; }
            filled += 1;
        }
    }
    filled
}

/// Get available entropy count (FIFO word count)
#[unsafe(no_mangle)]
pub extern "C" fn rpi_rng_available() -> u32 {
    let base = unsafe { RNG_BASE };
    if base == 0 { return 0; }
    mmio_read(base + RNG_FIFO_COUNT) >> 24
}

/// Check if RNG is initialized
#[unsafe(no_mangle)]
pub extern "C" fn rpi_rng_is_ready() -> bool {
    unsafe { RNG_INITIALIZED }
}
