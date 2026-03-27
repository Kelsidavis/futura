// SPDX-License-Identifier: MPL-2.0
//
// Raspberry Pi SPI Controller Driver
//
// BCM2711 SPI0: peripheral_base + 0x204000 (main SPI bus on GPIO7-11)
// Supports SPI modes 0-3, chip select 0/1, configurable clock speed.
//
// Used for: TFT/OLED displays, ADCs, DACs, flash storage, LoRa modules,
// CAN bus adapters, and other SPI peripherals.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(unexpected_cfgs)]
extern crate common;

use core::ptr::{read_volatile, write_volatile};

// SPI register offsets
const SPI_CS: usize = 0x00;     // Control and Status
const SPI_FIFO: usize = 0x04;   // TX/RX FIFO
const SPI_CLK: usize = 0x08;    // Clock Divider
const SPI_DLEN: usize = 0x0C;   // Data Length
const SPI_LTOH: usize = 0x10;   // LoSSI mode TOH
const SPI_DC: usize = 0x14;     // DMA DREQ Controls

// CS register bits
const CS_LEN_LONG: u32 = 1 << 25;
const CS_DMA_LEN: u32 = 1 << 24;
const CS_CSPOL2: u32 = 1 << 23;
const CS_CSPOL1: u32 = 1 << 22;
const CS_CSPOL0: u32 = 1 << 21;
const CS_RXF: u32 = 1 << 20;    // RX FIFO Full
const CS_RXR: u32 = 1 << 19;    // RX FIFO needs Reading
const CS_TXD: u32 = 1 << 18;    // TX FIFO can accept Data
const CS_RXD: u32 = 1 << 17;    // RX FIFO contains Data
const CS_DONE: u32 = 1 << 16;   // Transfer Done
const CS_TA: u32 = 1 << 7;      // Transfer Active
const CS_CSPOL: u32 = 1 << 6;   // Chip Select Polarity
const CS_CLEAR_RX: u32 = 1 << 5;
const CS_CLEAR_TX: u32 = 1 << 4;
const CS_CPOL: u32 = 1 << 3;    // Clock Polarity
const CS_CPHA: u32 = 1 << 2;    // Clock Phase
const CS_CS_MASK: u32 = 0x03;   // Chip Select (0 or 1)

// Default core clock: 250 MHz for SPI
const SPI_CORE_CLOCK: u32 = 250_000_000;

static mut SPI_BASE: usize = 0;

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

/// Initialize SPI controller
/// base_addr: MMIO base (peripheral_base + 0x204000)
/// speed_hz: SPI clock speed (e.g., 1000000 for 1 MHz)
/// mode: SPI mode 0-3 (CPOL/CPHA combination)
#[unsafe(no_mangle)]
pub extern "C" fn rpi_spi_init(base_addr: u64, speed_hz: u32, mode: u8) -> i32 {
    let base = base_addr as usize;
    unsafe { SPI_BASE = base; }

    // Set clock divider
    let speed = if speed_hz == 0 { 1_000_000 } else { speed_hz };
    let div = SPI_CORE_CLOCK / speed;
    let div = if div < 2 { 2 } else { div & !1 }; // Must be even, min 2
    mmio_write(base + SPI_CLK, div);

    // Configure mode and clear FIFOs
    let mut cs: u32 = CS_CLEAR_RX | CS_CLEAR_TX;
    match mode & 0x03 {
        0 => {},                                    // CPOL=0, CPHA=0
        1 => cs |= CS_CPHA,                        // CPOL=0, CPHA=1
        2 => cs |= CS_CPOL,                        // CPOL=1, CPHA=0
        3 => cs |= CS_CPOL | CS_CPHA,              // CPOL=1, CPHA=1
        _ => {},
    }
    mmio_write(base + SPI_CS, cs);

    0
}

/// Transfer data over SPI (full-duplex: simultaneous TX and RX)
/// cs: chip select (0 or 1)
/// tx: data to transmit (NULL for read-only)
/// rx: buffer for received data (NULL for write-only)
/// len: number of bytes to transfer
/// Returns: 0 on success, negative on error
#[unsafe(no_mangle)]
pub extern "C" fn rpi_spi_transfer(cs: u8, tx: *const u8, rx: *mut u8, len: u32) -> i32 {
    let base = unsafe { SPI_BASE };
    if base == 0 { return -1; }

    // Set chip select
    let mut ctrl = mmio_read(base + SPI_CS);
    ctrl &= !CS_CS_MASK;
    ctrl |= (cs & 1) as u32;
    // Clear FIFOs
    ctrl |= CS_CLEAR_RX | CS_CLEAR_TX;
    mmio_write(base + SPI_CS, ctrl);

    // Set transfer active
    ctrl = mmio_read(base + SPI_CS);
    ctrl |= CS_TA;
    mmio_write(base + SPI_CS, ctrl);

    let mut tx_idx: u32 = 0;
    let mut rx_idx: u32 = 0;

    while rx_idx < len {
        // Fill TX FIFO
        while tx_idx < len {
            let s = mmio_read(base + SPI_CS);
            if s & CS_TXD == 0 { break; } // TX FIFO full
            let byte = if !tx.is_null() {
                unsafe { *tx.add(tx_idx as usize) }
            } else { 0xFF }; // Send 0xFF for read-only
            mmio_write(base + SPI_FIFO, byte as u32);
            tx_idx += 1;
        }

        // Drain RX FIFO
        while rx_idx < len {
            let s = mmio_read(base + SPI_CS);
            if s & CS_RXD == 0 { break; } // RX FIFO empty
            let byte = (mmio_read(base + SPI_FIFO) & 0xFF) as u8;
            if !rx.is_null() {
                unsafe { *rx.add(rx_idx as usize) = byte; }
            }
            rx_idx += 1;
        }
    }

    // Wait for DONE
    for _ in 0..100000 {
        if mmio_read(base + SPI_CS) & CS_DONE != 0 { break; }
        delay(1);
    }

    // Deassert transfer active
    ctrl = mmio_read(base + SPI_CS);
    ctrl &= !CS_TA;
    mmio_write(base + SPI_CS, ctrl);

    0
}

/// Write-only SPI transfer
#[unsafe(no_mangle)]
pub extern "C" fn rpi_spi_write(cs: u8, data: *const u8, len: u32) -> i32 {
    rpi_spi_transfer(cs, data, core::ptr::null_mut(), len)
}

/// Read-only SPI transfer (sends 0xFF while reading)
#[unsafe(no_mangle)]
pub extern "C" fn rpi_spi_read(cs: u8, data: *mut u8, len: u32) -> i32 {
    rpi_spi_transfer(cs, core::ptr::null(), data, len)
}

/// Set SPI clock speed
#[unsafe(no_mangle)]
pub extern "C" fn rpi_spi_set_speed(speed_hz: u32) {
    let base = unsafe { SPI_BASE };
    if base == 0 { return; }
    let div = SPI_CORE_CLOCK / speed_hz;
    let div = if div < 2 { 2 } else { div & !1 };
    mmio_write(base + SPI_CLK, div);
}

/// Check if SPI is initialized
#[unsafe(no_mangle)]
pub extern "C" fn rpi_spi_is_ready() -> bool {
    unsafe { SPI_BASE != 0 }
}
