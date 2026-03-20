// SPDX-License-Identifier: MPL-2.0
//! Apple Silicon SPI controller driver for Futura OS
//!
//! Used for keyboard/trackpad (SPI HID) on MacBook Air/Pro M1/M2/M3.
//!
//! Architecture notes
//! ------------------
//! - Polled or interrupt-driven (FIFO thresholds + status IRQ)
//! - FIFO depth: 16 words TX and RX
//! - Supports CPOL/CPHA (modes 0-3), 8/16/32-bit word size
//! - Clock divider: SCLK = PCLK / (2 * (div + 1))
//! - Full-duplex: TX and RX run simultaneously
//! - CS (chip select) is asserted by writing the CS register
//!
//! Register map
//! ------------
//! 0x000  SPI_CTRL          — master enable, word size, mode select
//! 0x004  SPI_CFG           — CS polarity, clock phase/polarity, loopback
//! 0x008  SPI_CLK_DIV       — clock divider (SCLK = PCLK / (2*(div+1)))
//! 0x00C  SPI_FIFO_CTRL     — TX/RX FIFO threshold, flush
//! 0x010  SPI_FIFO_STAT     — TX/RX FIFO level and overflow/underflow flags
//! 0x014  SPI_TX_DATA       — write a word into TX FIFO
//! 0x018  SPI_RX_DATA       — read a word from RX FIFO
//! 0x01C  SPI_CS            — chip select assertion (bit per CS line)
//! 0x020  SPI_IRQ_STAT      — interrupt status (write-1-to-clear)
//! 0x024  SPI_IRQ_MASK      — interrupt mask (1 = enabled)
//! 0x028  SPI_STATUS        — transfer in-progress, error flags
//! 0x02C  SPI_TX_THRESHOLD  — TX FIFO interrupt threshold
//! 0x030  SPI_RX_THRESHOLD  — RX FIFO interrupt threshold
//!
//! Reference: Asahi Linux `drivers/spi/spi-apple.c` (Hector Martin)

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(dead_code)]

use core::ptr::{read_volatile, write_volatile};

// ---------------------------------------------------------------------------
// Register offsets
// ---------------------------------------------------------------------------

const SPI_CTRL:         usize = 0x000;
const SPI_CFG:          usize = 0x004;
const SPI_CLK_DIV:      usize = 0x008;
const SPI_FIFO_CTRL:    usize = 0x00C;
const SPI_FIFO_STAT:    usize = 0x010;
const SPI_TX_DATA:      usize = 0x014;
const SPI_RX_DATA:      usize = 0x018;
const SPI_CS:           usize = 0x01C;
const SPI_IRQ_STAT:     usize = 0x020;
const SPI_IRQ_MASK:     usize = 0x024;
const SPI_STATUS:       usize = 0x028;
const SPI_TX_THRESHOLD: usize = 0x02C;
const SPI_RX_THRESHOLD: usize = 0x030;

// ---------------------------------------------------------------------------
// Register bit definitions
// ---------------------------------------------------------------------------

// SPI_CTRL
const CTRL_ENABLE:       u32 = 1 << 0;  // Master mode enable
const CTRL_TX_ENABLE:    u32 = 1 << 1;  // TX path enable
const CTRL_RX_ENABLE:    u32 = 1 << 2;  // RX path enable
const CTRL_WORD_8BIT:    u32 = 0 << 4;  // 8-bit words
const CTRL_WORD_16BIT:   u32 = 1 << 4;  // 16-bit words
const CTRL_WORD_32BIT:   u32 = 2 << 4;  // 32-bit words
const CTRL_WORD_MASK:    u32 = 3 << 4;

// SPI_CFG
const CFG_CPOL:          u32 = 1 << 0;  // Clock polarity (1 = idle high)
const CFG_CPHA:          u32 = 1 << 1;  // Clock phase (1 = sample on 2nd edge)
const CFG_CS_ACTIVE_HIGH:u32 = 1 << 2;  // CS polarity (default: active low)
const CFG_LOOPBACK:      u32 = 1 << 3;  // Internal loopback mode
const CFG_LSB_FIRST:     u32 = 1 << 4;  // LSB-first bit order (default: MSB)

// SPI_FIFO_CTRL
const FIFO_CTRL_TX_FLUSH: u32 = 1 << 0;
const FIFO_CTRL_RX_FLUSH: u32 = 1 << 1;

// SPI_FIFO_STAT
const FIFO_STAT_TX_LEVEL_SHIFT: u32 = 0;
const FIFO_STAT_TX_LEVEL_MASK:  u32 = 0x1F;
const FIFO_STAT_RX_LEVEL_SHIFT: u32 = 8;
const FIFO_STAT_RX_LEVEL_MASK:  u32 = 0x1F << 8;
const FIFO_STAT_TX_FULL:        u32 = 1 << 16;
const FIFO_STAT_TX_EMPTY:       u32 = 1 << 17;
const FIFO_STAT_RX_FULL:        u32 = 1 << 18;
const FIFO_STAT_RX_EMPTY:       u32 = 1 << 19;
const FIFO_STAT_TX_OVERFLOW:    u32 = 1 << 20;
const FIFO_STAT_RX_UNDERFLOW:   u32 = 1 << 21;

// SPI_CS
const CS_ASSERT_MASK:    u32 = 0xFF;  // One bit per CS line (active level per CFG_CS_ACTIVE_HIGH)

// SPI_IRQ_STAT / SPI_IRQ_MASK
const IRQ_TX_EMPTY:      u32 = 1 << 0;
const IRQ_TX_THRESHOLD:  u32 = 1 << 1;
const IRQ_RX_THRESHOLD:  u32 = 1 << 2;
const IRQ_RX_FULL:       u32 = 1 << 3;
const IRQ_XFER_DONE:     u32 = 1 << 4;
const IRQ_CS_FALL:       u32 = 1 << 5;
const IRQ_CS_RISE:       u32 = 1 << 6;
const IRQ_ERROR:         u32 = 1 << 7;

// SPI_STATUS
const STATUS_BUSY:       u32 = 1 << 0;
const STATUS_TX_ERR:     u32 = 1 << 1;
const STATUS_RX_ERR:     u32 = 1 << 2;

// FIFO depth
const FIFO_DEPTH: usize = 16;

// ---------------------------------------------------------------------------
// SPI Mode (CPOL + CPHA)
// ---------------------------------------------------------------------------

#[derive(Copy, Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum SpiMode {
    Mode0 = 0,  // CPOL=0, CPHA=0 — idle low, sample on rising
    Mode1 = 1,  // CPOL=0, CPHA=1 — idle low, sample on falling
    Mode2 = 2,  // CPOL=1, CPHA=0 — idle high, sample on falling
    Mode3 = 3,  // CPOL=1, CPHA=1 — idle high, sample on rising
}

// ---------------------------------------------------------------------------
// Word size
// ---------------------------------------------------------------------------

#[derive(Copy, Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum WordSize {
    Bits8  = 0,
    Bits16 = 1,
    Bits32 = 2,
}

// ---------------------------------------------------------------------------
// Transfer result
// ---------------------------------------------------------------------------

#[derive(Copy, Clone, PartialEq, Eq)]
#[repr(i32)]
pub enum SpiResult {
    Ok        = 0,
    Timeout   = -5,   // EIO
    FifoError = -6,   // ENXIO — FIFO overflow/underflow
    Invalid   = -22,  // EINVAL
}

// ---------------------------------------------------------------------------
// AppleSpi — driver state
// ---------------------------------------------------------------------------

pub struct AppleSpi {
    base:      usize,
    /// Peripheral (bus) clock frequency in Hz — used to compute divider
    pclk_hz:   u32,
}

impl AppleSpi {
    // ---- MMIO helpers ----

    fn r32(&self, off: usize) -> u32 {
        unsafe { read_volatile((self.base + off) as *const u32) }
    }

    fn w32(&self, off: usize, v: u32) {
        unsafe { write_volatile((self.base + off) as *mut u32, v) }
    }

    fn rmw32(&self, off: usize, clear: u32, set: u32) {
        let old = self.r32(off);
        self.w32(off, (old & !clear) | set);
    }

    // ---- Initialization ----

    /// Initialize the SPI controller.
    /// `mode`    — SPI mode (CPOL/CPHA).
    /// `word_sz` — word size for transfers.
    /// `hz`      — desired SCLK frequency in Hz.
    pub fn init(&self, mode: SpiMode, word_sz: WordSize, hz: u32) {
        // Disable controller first
        self.w32(SPI_CTRL, 0);

        // Flush both FIFOs
        self.w32(SPI_FIFO_CTRL, FIFO_CTRL_TX_FLUSH | FIFO_CTRL_RX_FLUSH);
        self.w32(SPI_FIFO_CTRL, 0);

        // Configure clock divider: div = (pclk / (2 * hz)) - 1
        let div = if hz == 0 || hz > self.pclk_hz {
            0u32
        } else {
            (self.pclk_hz / (2 * hz)).saturating_sub(1)
        };
        self.w32(SPI_CLK_DIV, div);

        // Configure mode
        let cfg = match mode {
            SpiMode::Mode0 => 0,
            SpiMode::Mode1 => CFG_CPHA,
            SpiMode::Mode2 => CFG_CPOL,
            SpiMode::Mode3 => CFG_CPOL | CFG_CPHA,
        };
        self.w32(SPI_CFG, cfg);

        // Configure word size
        let word_bits = match word_sz {
            WordSize::Bits8  => CTRL_WORD_8BIT,
            WordSize::Bits16 => CTRL_WORD_16BIT,
            WordSize::Bits32 => CTRL_WORD_32BIT,
        };

        // Enable master with TX+RX
        self.w32(SPI_CTRL, CTRL_ENABLE | CTRL_TX_ENABLE | CTRL_RX_ENABLE | word_bits);

        // Mask all IRQs (polled mode by default)
        self.w32(SPI_IRQ_MASK, 0);
    }

    // ---- Chip select ----

    /// Assert chip select line `cs` (0-based).
    pub fn cs_assert(&self, cs: u8) {
        let cur = self.r32(SPI_CS);
        self.w32(SPI_CS, cur | (1u32 << (cs & 7)));
    }

    /// Deassert chip select line `cs`.
    pub fn cs_deassert(&self, cs: u8) {
        let cur = self.r32(SPI_CS);
        self.w32(SPI_CS, cur & !(1u32 << (cs & 7)));
    }

    // ---- FIFO helpers ----

    fn tx_level(&self) -> u32 {
        (self.r32(SPI_FIFO_STAT) >> FIFO_STAT_TX_LEVEL_SHIFT) & FIFO_STAT_TX_LEVEL_MASK
    }

    fn rx_level(&self) -> u32 {
        (self.r32(SPI_FIFO_STAT) >> FIFO_STAT_RX_LEVEL_SHIFT) & (FIFO_STAT_RX_LEVEL_MASK >> 8)
    }

    fn tx_full(&self) -> bool {
        self.r32(SPI_FIFO_STAT) & FIFO_STAT_TX_FULL != 0
    }

    fn rx_empty(&self) -> bool {
        self.r32(SPI_FIFO_STAT) & FIFO_STAT_RX_EMPTY != 0
    }

    fn fifo_error(&self) -> bool {
        let stat = self.r32(SPI_FIFO_STAT);
        stat & (FIFO_STAT_TX_OVERFLOW | FIFO_STAT_RX_UNDERFLOW) != 0
    }

    /// Wait until TX FIFO has room for one word (polled, with timeout).
    fn wait_tx_not_full(&self) -> bool {
        for _ in 0..100_000u32 {
            if !self.tx_full() {
                return true;
            }
        }
        false
    }

    /// Wait until RX FIFO has at least one word (polled, with timeout).
    fn wait_rx_not_empty(&self) -> bool {
        for _ in 0..100_000u32 {
            if !self.rx_empty() {
                return true;
            }
        }
        false
    }

    /// Wait until the SPI controller is not busy (transfer complete).
    fn wait_not_busy(&self) -> bool {
        for _ in 0..200_000u32 {
            if self.r32(SPI_STATUS) & STATUS_BUSY == 0 {
                return true;
            }
        }
        false
    }

    // ---- Full-duplex transfer ----

    /// Full-duplex SPI transfer.
    ///
    /// Sends `len` bytes from `tx_buf` (may be NULL → sends 0x00) and receives
    /// into `rx_buf` (may be NULL → discards incoming data).
    ///
    /// Does not manage CS; caller must call `cs_assert`/`cs_deassert`.
    pub fn transfer(&self, tx_buf: *const u8, rx_buf: *mut u8, len: usize) -> SpiResult {
        if len == 0 {
            return SpiResult::Ok;
        }

        let mut sent = 0usize;
        let mut recvd = 0usize;

        while sent < len || recvd < len {
            // Push words into TX FIFO
            while sent < len && !self.tx_full() {
                let byte = if tx_buf.is_null() {
                    0x00u8
                } else {
                    unsafe { *tx_buf.add(sent) }
                };
                self.w32(SPI_TX_DATA, byte as u32);
                sent += 1;
            }

            // Drain RX FIFO
            while recvd < sent && !self.rx_empty() {
                let word = self.r32(SPI_RX_DATA);
                if !rx_buf.is_null() && recvd < len {
                    unsafe { *rx_buf.add(recvd) = word as u8 };
                }
                recvd += 1;
            }

            if self.fifo_error() {
                return SpiResult::FifoError;
            }

            // If TX is stuck, break with timeout
            if sent < len {
                if !self.wait_tx_not_full() {
                    return SpiResult::Timeout;
                }
            }
            if recvd < sent {
                if !self.wait_rx_not_empty() {
                    return SpiResult::Timeout;
                }
            }
        }

        // Wait for shift register to drain
        if !self.wait_not_busy() {
            return SpiResult::Timeout;
        }

        SpiResult::Ok
    }

    // ---- Write-only convenience ----

    pub fn write(&self, buf: *const u8, len: usize) -> SpiResult {
        self.transfer(buf, core::ptr::null_mut(), len)
    }

    // ---- Read-only convenience (sends 0x00) ----

    pub fn read(&self, buf: *mut u8, len: usize) -> SpiResult {
        self.transfer(core::ptr::null(), buf, len)
    }

    // ---- IRQ mode helpers ----

    /// Enable specific IRQ sources.
    pub fn enable_irqs(&self, mask: u32) {
        let cur = self.r32(SPI_IRQ_MASK);
        self.w32(SPI_IRQ_MASK, cur | mask);
    }

    /// Disable all IRQ sources.
    pub fn disable_irqs(&self) {
        self.w32(SPI_IRQ_MASK, 0);
    }

    /// Read and clear pending IRQ status.
    pub fn read_clear_irq(&self) -> u32 {
        let stat = self.r32(SPI_IRQ_STAT);
        self.w32(SPI_IRQ_STAT, stat);
        stat
    }

    /// Set RX FIFO threshold (fire IRQ when RX level ≥ threshold).
    pub fn set_rx_threshold(&self, threshold: u32) {
        self.w32(SPI_RX_THRESHOLD, threshold & 0x1F);
    }

    /// Set TX FIFO threshold (fire IRQ when TX level ≤ threshold).
    pub fn set_tx_threshold(&self, threshold: u32) {
        self.w32(SPI_TX_THRESHOLD, threshold & 0x1F);
    }
}

// ---------------------------------------------------------------------------
// Static singleton
// ---------------------------------------------------------------------------

static mut G_SPI: AppleSpi = AppleSpi { base: 0, pclk_hz: 0 };

// ---------------------------------------------------------------------------
// C FFI
// ---------------------------------------------------------------------------

/// Initialize the Apple SPI controller.
///
/// `base`    — MMIO base address.
/// `pclk_hz` — peripheral clock frequency in Hz (e.g., 125_000_000 for 125 MHz).
/// `mode`    — SPI mode: 0=Mode0, 1=Mode1, 2=Mode2, 3=Mode3.
/// `hz`      — desired SCLK frequency in Hz.
///
/// Returns a non-null handle on success, NULL on failure.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_spi_init(
    base: u64,
    pclk_hz: u32,
    mode: u8,
    hz: u32,
) -> *mut AppleSpi {
    if base == 0 || pclk_hz == 0 {
        return core::ptr::null_mut();
    }

    let spi_mode = match mode {
        0 => SpiMode::Mode0,
        1 => SpiMode::Mode1,
        2 => SpiMode::Mode2,
        3 => SpiMode::Mode3,
        _ => return core::ptr::null_mut(),
    };

    let spi = unsafe { &mut *(&raw mut G_SPI) };
    spi.base    = base as usize;
    spi.pclk_hz = pclk_hz;
    spi.init(spi_mode, WordSize::Bits8, hz);
    spi as *mut AppleSpi
}

/// Release resources held by the SPI driver.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_spi_free(spi: *mut AppleSpi) {
    if spi.is_null() {
        return;
    }
    let s = unsafe { &mut *spi };
    // Disable controller
    s.w32(SPI_CTRL, 0);
    s.base = 0;
}

/// Assert chip select `cs` (0-based).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_spi_cs_assert(spi: *mut AppleSpi, cs: u8) {
    if spi.is_null() { return; }
    unsafe { (*spi).cs_assert(cs) }
}

/// Deassert chip select `cs`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_spi_cs_deassert(spi: *mut AppleSpi, cs: u8) {
    if spi.is_null() { return; }
    unsafe { (*spi).cs_deassert(cs) }
}

/// Full-duplex transfer: send `len` bytes from `tx_buf`, receive into `rx_buf`.
/// Either pointer may be NULL (sends zeros / discards received data respectively).
/// Returns 0 on success, negative errno on error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_spi_transfer(
    spi: *mut AppleSpi,
    tx_buf: *const u8,
    rx_buf: *mut u8,
    len: usize,
) -> i32 {
    if spi.is_null() {
        return -22; // EINVAL
    }
    unsafe { (*spi).transfer(tx_buf, rx_buf, len) as i32 }
}

/// Write `len` bytes from `buf` (full-duplex; received data discarded).
/// Returns 0 on success, negative errno on error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_spi_write(
    spi: *mut AppleSpi,
    buf: *const u8,
    len: usize,
) -> i32 {
    if spi.is_null() || buf.is_null() {
        return -22;
    }
    unsafe { (*spi).write(buf, len) as i32 }
}

/// Read `len` bytes into `buf` (sends 0x00 bytes).
/// Returns 0 on success, negative errno on error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_spi_read(
    spi: *mut AppleSpi,
    buf: *mut u8,
    len: usize,
) -> i32 {
    if spi.is_null() || buf.is_null() {
        return -22;
    }
    unsafe { (*spi).read(buf, len) as i32 }
}

/// Read and clear the IRQ status register. Returns the raw status bitmask.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_spi_handle_irq(spi: *mut AppleSpi) -> u32 {
    if spi.is_null() {
        return 0;
    }
    unsafe { (*spi).read_clear_irq() }
}

/// Set the RX FIFO threshold level (0–16).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_spi_set_rx_threshold(spi: *mut AppleSpi, threshold: u32) {
    if spi.is_null() { return; }
    unsafe { (*spi).set_rx_threshold(threshold) }
}

// ---------------------------------------------------------------------------
// Panic handler
// ---------------------------------------------------------------------------

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {
        unsafe { core::arch::asm!("wfe") };
    }
}
