// SPDX-License-Identifier: MPL-2.0
//! Apple Silicon I2C controller driver for Futura OS
//!
//! Implements the Apple I2C/SPI hybrid ("AXI" I2C) controller found in
//! M1/M2/M3 SoCs.  Used for keyboard, trackpad, ambient-light sensor,
//! and other low-speed peripherals.
//!
//! The Apple I2C controller is broadly compatible with the Samsung S3C I2C
//! core, sharing the same basic register layout.  Apple extends it with an
//! IRQ-based FIFO and a dedicated TIMING register for SCL duty-cycle tuning.
//!
//! Register layout (relative to controller base)
//! ----------------------------------------------
//! 0x00  IICCON  Control register
//! 0x04  IICSTAT Status register
//! 0x08  IICADD  Address register (slave mode)
//! 0x0C  IICDS   Data shift register (TX/RX byte)
//! 0x10  IICLC   Line control (SDA/SCL override)
//! 0x14  IICTXD  TX FIFO data (Apple extension)
//! 0x18  IICSTO  Stop register (Apple extension)
//!
//! References
//! ----------
//! - Linux `drivers/i2c/busses/i2c-s3c2410.c`
//! - Asahi Linux `drivers/i2c/busses/i2c-pasemi-platform.c`
//! - m1n1 `proxyclient/m1n1/hw/i2c.py`
//! - Apple device tree node compatible: "apple,t8103-i2c", "apple,i2c"

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(dead_code)]

use core::ptr::{read_volatile, write_volatile};

// ---------------------------------------------------------------------------
// Register offsets
// ---------------------------------------------------------------------------

const IICCON:  usize = 0x00;  // Control
const IICSTAT: usize = 0x04;  // Status
const IICADD:  usize = 0x08;  // Address (slave mode)
const IICDS:   usize = 0x0C;  // Data shift register
const IICLC:   usize = 0x10;  // Line control
const IICTXD:  usize = 0x14;  // TX data (Apple FIFO extension)
const IICSTO:  usize = 0x18;  // Stop register (Apple extension)

// ---------------------------------------------------------------------------
// IICCON bits
// ---------------------------------------------------------------------------

/// Acknowledge enable
const IICCON_ACKGEN:     u32 = 1 << 7;
/// TX/RX clock source prescaler: 0=input/16, 1=input/512
const IICCON_PRESCALE:   u32 = 1 << 6;
/// IRQ enable
const IICCON_IRQ_EN:     u32 = 1 << 5;
/// IRQ pending flag (write 0 to clear)
const IICCON_IRQ_PEND:   u32 = 1 << 4;
/// Clock prescaler (bits [3:0])
const IICCON_CLK_MASK:   u32 = 0xF;

// ---------------------------------------------------------------------------
// IICSTAT bits
// ---------------------------------------------------------------------------

/// Mode[1:0]: 00=slave-Rx, 01=slave-Tx, 10=master-Rx, 11=master-Tx
const IICSTAT_MODE_MASK: u32 = 0x3 << 6;
const IICSTAT_MASTER_TX: u32 = 0x3 << 6;
const IICSTAT_MASTER_RX: u32 = 0x2 << 6;
/// Enable I2C serial output
const IICSTAT_BUSY:      u32 = 1 << 5;
/// Arbitration status (1=lost)
const IICSTAT_ARB_LOST:  u32 = 1 << 3;
/// Slave address match
const IICSTAT_ADDR_ZERO: u32 = 1 << 2;
/// Slave address match
const IICSTAT_ADDR_SLAVE:u32 = 1 << 1;
/// Last received/transmitted ack bit (0=ack, 1=nack)
const IICSTAT_LAST_NACK: u32 = 1 << 0;

// ---------------------------------------------------------------------------
// IICLC bits (line control / override)
// ---------------------------------------------------------------------------

/// SDA output override enable
const IICLC_SDA_OE:  u32 = 1 << 1;
/// SCL output override enable
const IICLC_SCL_OE:  u32 = 1 << 3;

// ---------------------------------------------------------------------------
// Timing constants
// ---------------------------------------------------------------------------

/// Default I2C clock: ~100 kHz at 24 MHz input clock.
/// IICCON prescaler: 0x4F (79 decimal) with input/16 → 24M/(16*(79+1)) = 18750 Hz
/// Actual 100 kHz operation uses Apple's TIMING register (not modelled here).
const DEFAULT_PRESCALER: u32 = 0x0F;

/// Maximum number of bytes to transfer in a single message.
const MAX_XFER: usize = 256;

/// Spin-loop timeout iterations (~1 ms at ~1 GHz with simple loops).
const TIMEOUT_LOOPS: u32 = 100_000;

// ---------------------------------------------------------------------------
// Transfer result
// ---------------------------------------------------------------------------

/// Result of a single-byte I2C operation.
#[must_use]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum I2cResult {
    /// Transfer completed successfully.
    Ok,
    /// Remote device NAK'd the address or data byte.
    Nack,
    /// Arbitration lost (bus busy, another master won).
    ArbLost,
    /// Hardware timeout (bus stuck, clock stretching exceeded).
    Timeout,
    /// Invalid parameter.
    Invalid,
}

// ---------------------------------------------------------------------------
// AppleI2c — driver state
// ---------------------------------------------------------------------------

/// Apple Silicon I2C controller.
pub struct AppleI2c {
    base: usize,
}

impl AppleI2c {
    // ---- MMIO helpers -------------------------------------------------------

    fn r32(&self, off: usize) -> u32 {
        unsafe { read_volatile((self.base + off) as *const u32) }
    }

    fn w32(&self, off: usize, val: u32) {
        unsafe { write_volatile((self.base + off) as *mut u32, val) }
    }

    // ---- Low-level helpers --------------------------------------------------

    /// Clear the IRQ-pending bit by writing 0 to it.
    fn clear_irq(&self) {
        let con = self.r32(IICCON);
        self.w32(IICCON, con & !IICCON_IRQ_PEND);
    }

    /// Wait for the IRQ-pending bit to be set (one byte transferred / START/STOP done).
    fn wait_irq(&self) -> I2cResult {
        for _ in 0..TIMEOUT_LOOPS {
            if self.r32(IICCON) & IICCON_IRQ_PEND != 0 {
                return I2cResult::Ok;
            }
            core::hint::spin_loop();
        }
        I2cResult::Timeout
    }

    /// Check for NACK or arbitration-lost after a transfer.
    fn check_errors(&self) -> I2cResult {
        let stat = self.r32(IICSTAT);
        if stat & IICSTAT_ARB_LOST != 0 { return I2cResult::ArbLost; }
        if stat & IICSTAT_LAST_NACK != 0 { return I2cResult::Nack; }
        I2cResult::Ok
    }

    // ---- Public API ---------------------------------------------------------

    /// Initialise the I2C controller with default 100 kHz settings.
    ///
    /// Must be called once before any transfer.
    pub fn init(&self) {
        // Prescaler: /16 clock source, DEFAULT_PRESCALER, IRQ enabled, ACK enable.
        self.w32(IICCON,
            IICCON_ACKGEN | IICCON_IRQ_EN | DEFAULT_PRESCALER);
        // Clear any pending interrupt.
        self.clear_irq();
    }

    /// Send a START condition and the address byte `addr_rw` (7-bit addr << 1 | R/W).
    fn start(&self, addr_rw: u8) -> I2cResult {
        // Load address into data shift register.
        self.w32(IICDS, addr_rw as u32);
        // Set mode: master-TX (or master-RX depending on R/W bit) + busy=1 → START.
        let mode = if addr_rw & 1 == 0 { IICSTAT_MASTER_TX } else { IICSTAT_MASTER_RX };
        self.w32(IICSTAT, mode | IICSTAT_BUSY);
        // Wait for address byte + START to complete.
        let r = self.wait_irq();
        if r != I2cResult::Ok { return r; }
        self.check_errors()
    }

    /// Send a STOP condition.
    fn stop(&self) {
        let stat = self.r32(IICSTAT);
        // Clear BUSY bit to generate STOP.
        self.w32(IICSTAT, stat & !IICSTAT_BUSY);
        self.clear_irq();
        // Give the bus a few cycles to settle.
        for _ in 0..100 {
            core::hint::spin_loop();
        }
    }

    /// Write one data byte.
    fn write_byte(&self, data: u8) -> I2cResult {
        self.w32(IICDS, data as u32);
        self.clear_irq();
        let r = self.wait_irq();
        if r != I2cResult::Ok { return r; }
        self.check_errors()
    }

    /// Read one data byte.  Pass `ack=false` for the final byte (NACK it to
    /// signal the slave to stop sending).
    fn read_byte(&self, ack: bool) -> (u8, I2cResult) {
        // Configure ACK/NACK for this byte.
        let con = self.r32(IICCON);
        if ack {
            self.w32(IICCON, con | IICCON_ACKGEN);
        } else {
            self.w32(IICCON, con & !IICCON_ACKGEN);
        }
        self.clear_irq();
        let r = self.wait_irq();
        if r != I2cResult::Ok { return (0, r); }
        let data = self.r32(IICDS) as u8;
        (data, I2cResult::Ok)
    }

    /// Write `buf` to I2C slave at 7-bit address `addr`.
    ///
    /// Returns `I2cResult::Ok` on success; the STOP is always issued.
    pub fn write(&self, addr: u8, buf: &[u8]) -> I2cResult {
        if buf.is_empty() { return I2cResult::Invalid; }
        let r = self.start((addr << 1) | 0);  // write
        if r != I2cResult::Ok { self.stop(); return r; }
        for &b in buf {
            let r = self.write_byte(b);
            if r != I2cResult::Ok { self.stop(); return r; }
        }
        self.stop();
        I2cResult::Ok
    }

    /// Read `buf.len()` bytes from I2C slave at 7-bit address `addr`.
    ///
    /// Returns `I2cResult::Ok` on success; the STOP is always issued.
    pub fn read(&self, addr: u8, buf: &mut [u8]) -> I2cResult {
        if buf.is_empty() { return I2cResult::Invalid; }
        let r = self.start((addr << 1) | 1);  // read
        if r != I2cResult::Ok { self.stop(); return r; }
        let last = buf.len() - 1;
        for (i, slot) in buf.iter_mut().enumerate() {
            let ack = i < last;  // NACK the last byte
            let (b, r) = self.read_byte(ack);
            if r != I2cResult::Ok { self.stop(); return r; }
            *slot = b;
        }
        self.stop();
        I2cResult::Ok
    }

    /// Write `tx_buf` then read `rx_buf` in a combined START-ADDR-TX-RS-ADDR-RX
    /// (repeated-start) transaction.
    ///
    /// Returns `I2cResult::Ok` on success.
    pub fn write_read(&self, addr: u8, tx_buf: &[u8], rx_buf: &mut [u8]) -> I2cResult {
        if tx_buf.is_empty() || rx_buf.is_empty() { return I2cResult::Invalid; }

        // Write phase
        let r = self.start((addr << 1) | 0);
        if r != I2cResult::Ok { self.stop(); return r; }
        for &b in tx_buf {
            let r = self.write_byte(b);
            if r != I2cResult::Ok { self.stop(); return r; }
        }

        // Repeated START into read phase
        let r = self.start((addr << 1) | 1);
        if r != I2cResult::Ok { self.stop(); return r; }
        let last = rx_buf.len() - 1;
        for (i, slot) in rx_buf.iter_mut().enumerate() {
            let (b, r) = self.read_byte(i < last);
            if r != I2cResult::Ok { self.stop(); return r; }
            *slot = b;
        }
        self.stop();
        I2cResult::Ok
    }

    /// Read the raw status register (for diagnostics).
    pub fn status(&self) -> u32 {
        self.r32(IICSTAT)
    }
}

// ---------------------------------------------------------------------------
// Heap allocation shim
// ---------------------------------------------------------------------------

unsafe extern "C" {
    fn fut_alloc(size: usize) -> *mut u8;
    fn fut_free(ptr: *mut u8);
}

// ---------------------------------------------------------------------------
// C FFI
// ---------------------------------------------------------------------------

/// Allocate and initialise an I2C controller at `base`.
///
/// Returns a non-null opaque pointer on success, null on failure.
#[unsafe(no_mangle)]
pub extern "C" fn rust_i2c_init(base: u64) -> *mut AppleI2c {
    if base == 0 {
        return core::ptr::null_mut();
    }
    let ptr = unsafe { fut_alloc(core::mem::size_of::<AppleI2c>()) } as *mut AppleI2c;
    if ptr.is_null() {
        return core::ptr::null_mut();
    }
    let i2c = unsafe { &mut *ptr };
    i2c.base = base as usize;
    i2c.init();
    ptr
}

/// Free an I2C controller returned by `rust_i2c_init`.
#[unsafe(no_mangle)]
pub extern "C" fn rust_i2c_free(i2c: *mut AppleI2c) {
    if !i2c.is_null() {
        unsafe { fut_free(i2c as *mut u8) };
    }
}

/// Write `len` bytes from `buf` to the I2C slave at 7-bit address `addr`.
///
/// Returns 0 on success, negative errno on failure:
///   -5  = I/O error (timeout, arbitration lost)
///   -19 = NACK (device not responding)
///   -22 = invalid argument
///
/// # Safety
/// `buf` must be valid for `len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_i2c_write(
    i2c:  *const AppleI2c,
    addr: u8,
    buf:  *const u8,
    len:  usize,
) -> i32 {
    if i2c.is_null() || buf.is_null() || len == 0 { return -22; }
    let data = unsafe { core::slice::from_raw_parts(buf, len) };
    match unsafe { (*i2c).write(addr, data) } {
        I2cResult::Ok      =>  0,
        I2cResult::Nack    => -19,
        I2cResult::Timeout => -5,
        I2cResult::ArbLost => -5,
        I2cResult::Invalid => -22,
    }
}

/// Read `len` bytes into `buf` from the I2C slave at 7-bit address `addr`.
///
/// Returns 0 on success, negative errno on failure.
///
/// # Safety
/// `buf` must be valid for `len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_i2c_read(
    i2c:  *const AppleI2c,
    addr: u8,
    buf:  *mut u8,
    len:  usize,
) -> i32 {
    if i2c.is_null() || buf.is_null() || len == 0 { return -22; }
    let data = unsafe { core::slice::from_raw_parts_mut(buf, len) };
    match unsafe { (*i2c).read(addr, data) } {
        I2cResult::Ok      =>  0,
        I2cResult::Nack    => -19,
        I2cResult::Timeout => -5,
        I2cResult::ArbLost => -5,
        I2cResult::Invalid => -22,
    }
}

/// Write `tx_len` bytes then read `rx_len` bytes in a combined transaction.
///
/// Returns 0 on success, negative errno on failure.
///
/// # Safety
/// `tx_buf` must be valid for `tx_len` bytes; `rx_buf` must be valid for `rx_len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_i2c_write_read(
    i2c:    *const AppleI2c,
    addr:   u8,
    tx_buf: *const u8,
    tx_len: usize,
    rx_buf: *mut u8,
    rx_len: usize,
) -> i32 {
    if i2c.is_null() || tx_buf.is_null() || rx_buf.is_null() { return -22; }
    if tx_len == 0 || rx_len == 0 { return -22; }
    let tx = unsafe { core::slice::from_raw_parts(tx_buf, tx_len) };
    let rx = unsafe { core::slice::from_raw_parts_mut(rx_buf, rx_len) };
    match unsafe { (*i2c).write_read(addr, tx, rx) } {
        I2cResult::Ok      =>  0,
        I2cResult::Nack    => -19,
        I2cResult::Timeout => -5,
        I2cResult::ArbLost => -5,
        I2cResult::Invalid => -22,
    }
}

/// Return the current status register value (for diagnostics).
#[unsafe(no_mangle)]
pub extern "C" fn rust_i2c_status(i2c: *const AppleI2c) -> u32 {
    if i2c.is_null() { return 0; }
    unsafe { (*i2c).status() }
}

// ---------------------------------------------------------------------------
// Panic handler
// ---------------------------------------------------------------------------

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
