// SPDX-License-Identifier: MPL-2.0
//! Apple Silicon S5L UART driver for Futura OS
//!
//! Implements the Samsung S5L-style UART used in Apple M1/M2/M3 SoCs.
//! Based on the Asahi Linux `tty/serial/samsung_tty.c` and Apple-specific
//! register documentation from m1n1 and Asahi Linux.
//!
//! Register layout (Samsung S5L compatible):
//!   ULCON   0x00 - Line control (word length, parity, stop bits)
//!   UCON    0x04 - Control (TX/RX mode, interrupts)
//!   UFCON   0x08 - FIFO control (enable, reset, trigger levels)
//!   UMCON   0x0C - Modem control
//!   UTRSTAT 0x10 - TX/RX status
//!   UERSTAT 0x14 - Error status
//!   UFSTAT  0x18 - FIFO status
//!   UMSTAT  0x1C - Modem status
//!   UTXH    0x20 - Transmit buffer
//!   URXH    0x24 - Receive buffer
//!   UBRDIV  0x28 - Baud rate integer divisor
//!   UFRACVAL 0x2C - Baud rate fractional value
//!   UINTP   0x30 - Interrupt pending (write 1 to clear)
//!   UINTS   0x34 - Interrupt source
//!   UINTM   0x38 - Interrupt mask

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::ptr::{read_volatile, write_volatile};

// ---------------------------------------------------------------------------
// Register offsets
// ---------------------------------------------------------------------------

const ULCON: usize    = 0x00;
const UCON: usize     = 0x04;
const UFCON: usize    = 0x08;
const UTRSTAT: usize  = 0x10;
const UTXH: usize     = 0x20;
const URXH: usize     = 0x24;
const UBRDIV: usize   = 0x28;
const UFRACVAL: usize = 0x2C;
const UINTP: usize    = 0x30;
const UINTM: usize    = 0x38;

// ---------------------------------------------------------------------------
// Bit definitions
// ---------------------------------------------------------------------------

// ULCON
const ULCON_WORD_LEN_8: u32  = 0x3;
const ULCON_PARITY_NONE: u32 = 0 << 3;

// UCON
const UCON_RX_MODE_INT: u32  = 1 << 0;
const UCON_TX_MODE_INT: u32  = 1 << 2;
const UCON_RX_TIMEOUT: u32   = 1 << 7;

// UFCON
const UFCON_FIFO_ENABLE: u32  = 1 << 0;
const UFCON_RX_FIFO_RST: u32  = 1 << 1;
const UFCON_TX_FIFO_RST: u32  = 1 << 2;
const UFCON_RX_TRIGGER_8: u32 = 1 << 4;
const UFCON_TX_TRIGGER_8: u32 = 1 << 6;

// UTRSTAT
const UTRSTAT_RX_READY: u32  = 1 << 0;
const UTRSTAT_TX_EMPTY: u32  = 1 << 1;

// Interrupt bits (UINTP / UINTM)
const UINT_RXD: u32  = 1 << 0;
const UINT_TXD: u32  = 1 << 2;

// UART clock (24 MHz, as supplied by Apple SoC)
const APPLE_UART_CLOCK: u32 = 24_000_000;

// ---------------------------------------------------------------------------
// AppleUart — the core driver struct
// ---------------------------------------------------------------------------

/// MMIO-mapped Apple S5L UART.
///
/// All methods take `&self` and perform volatile reads/writes through the
/// stored base pointer.  The struct itself is `!Send + !Sync` by default
/// (raw pointer); callers are responsible for ensuring exclusive access.
pub struct AppleUart {
    base: usize,
}

impl AppleUart {
    /// Construct from a physical/virtual base address already mapped into the
    /// kernel address space.
    ///
    /// # Safety
    /// `base` must be a valid, uniquely-owned MMIO region for an Apple S5L UART.
    pub const unsafe fn new(base: usize) -> Self {
        Self { base }
    }

    // --- raw register helpers ---

    unsafe fn read(&self, offset: usize) -> u32 {
        // SAFETY: delegated to caller of `new`
        unsafe { read_volatile((self.base + offset) as *const u32) }
    }

    unsafe fn write(&self, offset: usize, val: u32) {
        // SAFETY: delegated to caller of `new`
        unsafe { write_volatile((self.base + offset) as *mut u32, val) }
    }

    // --- public API ---

    /// Initialise the UART: configure 8N1, enable FIFO, set baud rate.
    ///
    /// # Safety
    /// Must be called with the UART MMIO region exclusively owned and mapped.
    pub unsafe fn init(&self, baudrate: u32) {
        if baudrate == 0 {
            return;
        }

        // Disable UART while configuring
        unsafe { self.write(UCON, 0) };

        // 8 data bits, no parity
        unsafe { self.write(ULCON, ULCON_WORD_LEN_8 | ULCON_PARITY_NONE) };

        // Enable FIFO, reset TX/RX FIFOs, set trigger levels
        unsafe {
            self.write(UFCON,
                UFCON_FIFO_ENABLE | UFCON_RX_FIFO_RST |
                UFCON_TX_FIFO_RST | UFCON_RX_TRIGGER_8 |
                UFCON_TX_TRIGGER_8)
        };

        // Baud rate = UART_CLOCK / (16 * baudrate)
        // Fractional part: UFRACVAL = (remainder * 16) / (16 * baudrate)
        let div = APPLE_UART_CLOCK / (16 * baudrate);
        let remainder = APPLE_UART_CLOCK % (16 * baudrate);
        let frac = (remainder * 16) / (16 * baudrate);

        unsafe {
            self.write(UBRDIV, div);
            self.write(UFRACVAL, frac);
        }

        // Clear all pending interrupts, then mask them (enable selectively later)
        unsafe {
            self.write(UINTP, 0xF);
            self.write(UINTM, 0xF);
        }

        // Enable UART: RX/TX interrupt mode + RX timeout
        unsafe {
            self.write(UCON, UCON_RX_MODE_INT | UCON_TX_MODE_INT | UCON_RX_TIMEOUT)
        };
    }

    /// Returns `true` when the TX FIFO can accept at least one more byte.
    #[inline]
    pub fn tx_ready(&self) -> bool {
        unsafe { self.read(UTRSTAT) & UTRSTAT_TX_EMPTY != 0 }
    }

    /// Returns `true` when the RX FIFO contains at least one byte.
    #[inline]
    pub fn rx_ready(&self) -> bool {
        unsafe { self.read(UTRSTAT) & UTRSTAT_RX_READY != 0 }
    }

    /// Blocking write: spin until TX FIFO has space, then write `ch`.
    /// Converts bare `\n` to `\r\n` for terminal compatibility.
    pub fn putc(&self, ch: u8) {
        while !self.tx_ready() {
            core::hint::spin_loop();
        }
        unsafe { self.write(UTXH, ch as u32) };

        if ch == b'\n' {
            while !self.tx_ready() {
                core::hint::spin_loop();
            }
            unsafe { self.write(UTXH, b'\r' as u32) };
        }
    }

    /// Non-blocking read.  Returns `Some(byte)` if data is available, `None`
    /// otherwise.
    pub fn getc(&self) -> Option<u8> {
        if self.rx_ready() {
            Some((unsafe { self.read(URXH) } & 0xFF) as u8)
        } else {
            None
        }
    }

    /// Write a byte slice (not NUL-terminated) to the UART.
    pub fn write_bytes(&self, bytes: &[u8]) {
        for &b in bytes {
            self.putc(b);
        }
    }

    /// Enable the RX-data interrupt (clear its mask bit).
    pub fn enable_rx_irq(&self) {
        let mask = unsafe { self.read(UINTM) } & !UINT_RXD;
        unsafe { self.write(UINTM, mask) };
    }

    /// Enable the TX-empty interrupt.
    pub fn enable_tx_irq(&self) {
        let mask = unsafe { self.read(UINTM) } & !UINT_TXD;
        unsafe { self.write(UINTM, mask) };
    }

    /// Disable the TX-empty interrupt.
    pub fn disable_tx_irq(&self) {
        let mask = unsafe { self.read(UINTM) } | UINT_TXD;
        unsafe { self.write(UINTM, mask) };
    }

    /// Return the current interrupt-pending register value.
    pub fn intp(&self) -> u32 {
        unsafe { self.read(UINTP) }
    }

    /// Clear interrupt flags by writing 1 to the corresponding bits.
    pub fn clear_interrupts(&self, mask: u32) {
        unsafe { self.write(UINTP, mask) };
    }
}

// ---------------------------------------------------------------------------
// C FFI — replaces platform/arm64/drivers/apple_uart.c
// ---------------------------------------------------------------------------
//
// These functions mirror the C API in apple_uart.h so that the kernel can
// call into the Rust driver without any changes to the call sites.  The
// `base` parameter replaces the global `uart_base` in the C driver, making
// the Rust version fully re-entrant.

/// Initialise an Apple S5L UART at `base` with the given `baudrate`.
/// Returns 1 on success, 0 if `base` is 0 or `baudrate` is 0.
#[unsafe(no_mangle)]
pub extern "C" fn rust_apple_uart_init(base: u64, baudrate: u32) -> i32 {
    if base == 0 || baudrate == 0 {
        return 0;
    }
    // SAFETY: the kernel guarantees `base` is a valid MMIO mapping.
    let uart = unsafe { AppleUart::new(base as usize) };
    unsafe { uart.init(baudrate) };
    1
}

/// Write one character.  `ch` is the ASCII byte; `\n` is expanded to `\r\n`.
#[unsafe(no_mangle)]
pub extern "C" fn rust_apple_uart_putc(base: u64, ch: u8) {
    if base == 0 {
        return;
    }
    let uart = unsafe { AppleUart::new(base as usize) };
    uart.putc(ch);
}

/// Non-blocking read.  Returns the byte as a non-negative value, or -1 if
/// no data is available.
#[unsafe(no_mangle)]
pub extern "C" fn rust_apple_uart_getc(base: u64) -> i32 {
    if base == 0 {
        return -1;
    }
    let uart = unsafe { AppleUart::new(base as usize) };
    match uart.getc() {
        Some(b) => b as i32,
        None    => -1,
    }
}

/// Write `len` bytes from `ptr`.  NUL bytes are passed through unchanged.
///
/// # Safety
/// `ptr` must be valid for `len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_apple_uart_write(base: u64, ptr: *const u8, len: usize) {
    if base == 0 || ptr.is_null() || len == 0 {
        return;
    }
    let uart = unsafe { AppleUart::new(base as usize) };
    let bytes = unsafe { core::slice::from_raw_parts(ptr, len) };
    uart.write_bytes(bytes);
}

/// Write a NUL-terminated C string.
///
/// # Safety
/// `s` must point to a valid NUL-terminated string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_apple_uart_puts(base: u64, s: *const u8) {
    if base == 0 || s.is_null() {
        return;
    }
    let uart = unsafe { AppleUart::new(base as usize) };
    let mut p = s;
    loop {
        let b = unsafe { *p };
        if b == 0 {
            break;
        }
        uart.putc(b);
        p = unsafe { p.add(1) };
    }
}

/// Returns 1 if the TX FIFO can accept data, 0 otherwise.
#[unsafe(no_mangle)]
pub extern "C" fn rust_apple_uart_tx_ready(base: u64) -> i32 {
    if base == 0 {
        return 0;
    }
    let uart = unsafe { AppleUart::new(base as usize) };
    uart.tx_ready() as i32
}

/// Returns 1 if the RX FIFO has data, 0 otherwise.
#[unsafe(no_mangle)]
pub extern "C" fn rust_apple_uart_rx_ready(base: u64) -> i32 {
    if base == 0 {
        return 0;
    }
    let uart = unsafe { AppleUart::new(base as usize) };
    uart.rx_ready() as i32
}

/// Enable the RX-data interrupt.
#[unsafe(no_mangle)]
pub extern "C" fn rust_apple_uart_enable_rx_irq(base: u64) {
    if base == 0 {
        return;
    }
    let uart = unsafe { AppleUart::new(base as usize) };
    uart.enable_rx_irq();
}

/// Enable the TX-empty interrupt.
#[unsafe(no_mangle)]
pub extern "C" fn rust_apple_uart_enable_tx_irq(base: u64) {
    if base == 0 {
        return;
    }
    let uart = unsafe { AppleUart::new(base as usize) };
    uart.enable_tx_irq();
}

/// Disable the TX-empty interrupt.
#[unsafe(no_mangle)]
pub extern "C" fn rust_apple_uart_disable_tx_irq(base: u64) {
    if base == 0 {
        return;
    }
    let uart = unsafe { AppleUart::new(base as usize) };
    uart.disable_tx_irq();
}

/// Return the interrupt-pending register value.
#[unsafe(no_mangle)]
pub extern "C" fn rust_apple_uart_intp(base: u64) -> u32 {
    if base == 0 {
        return 0;
    }
    let uart = unsafe { AppleUart::new(base as usize) };
    uart.intp()
}

/// Clear interrupt flags (`mask` has 1 bits for each interrupt to clear).
#[unsafe(no_mangle)]
pub extern "C" fn rust_apple_uart_clear_interrupts(base: u64, mask: u32) {
    if base == 0 {
        return;
    }
    let uart = unsafe { AppleUart::new(base as usize) };
    uart.clear_interrupts(mask);
}

// ---------------------------------------------------------------------------
// Panic handler (required for no_std staticlib)
// ---------------------------------------------------------------------------

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
