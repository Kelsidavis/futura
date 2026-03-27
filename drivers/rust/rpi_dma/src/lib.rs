// SPDX-License-Identifier: MPL-2.0
//
// Raspberry Pi BCM2711 DMA Controller Driver
//
// BCM2711 has 16 DMA channels (0-15), with channels 0-6 being "lite" DMA
// and channels 7-10 being full-featured with 2D stride support.
// DMA base: peripheral_base + 0x007000
//
// Each channel has independent control, source/dest address, transfer
// length, and stride registers. Uses control blocks (CBs) in memory.
//
// Used by: eMMC, Ethernet, audio, SPI, UART for efficient bulk transfers.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(unexpected_cfgs)]
extern crate common;

use core::ptr::{read_volatile, write_volatile};

// DMA channel register offsets (per channel, 0x100 spacing)
const DMA_CS: usize = 0x00;       // Control and Status
const DMA_CONBLK_AD: usize = 0x04; // Control Block Address
const DMA_TI: usize = 0x08;       // Transfer Information (from CB)
const DMA_SOURCE_AD: usize = 0x0C; // Source Address (from CB)
const DMA_DEST_AD: usize = 0x10;   // Destination Address (from CB)
const DMA_TXFR_LEN: usize = 0x14; // Transfer Length (from CB)
const DMA_STRIDE: usize = 0x18;   // 2D Stride (from CB)
const DMA_NEXTCONBK: usize = 0x1C;// Next CB Address (from CB)
const DMA_DEBUG: usize = 0x20;    // Debug

// DMA_CS bits
const CS_ACTIVE: u32 = 1 << 0;
const CS_END: u32 = 1 << 1;
const CS_INT: u32 = 1 << 2;
const CS_DREQ: u32 = 1 << 3;
const CS_ERROR: u32 = 1 << 8;
const CS_ABORT: u32 = 1 << 30;
const CS_RESET: u32 = 1 << 31;

// Transfer Information bits
const TI_INTEN: u32 = 1 << 0;     // Interrupt Enable
const TI_WAIT_RESP: u32 = 1 << 3; // Wait for Write Response
const TI_DEST_INC: u32 = 1 << 4;  // Dest Address Increment
const TI_DEST_WIDTH: u32 = 1 << 5;// Dest Transfer Width (1=128-bit)
const TI_DEST_DREQ: u32 = 1 << 6; // Dest DREQ control transfers
const TI_SRC_INC: u32 = 1 << 8;   // Source Address Increment
const TI_SRC_WIDTH: u32 = 1 << 9; // Source Transfer Width
const TI_SRC_DREQ: u32 = 1 << 10; // Source DREQ control transfers

// DMA Control Block (must be 32-byte aligned in memory)
#[repr(C, align(32))]
pub struct DmaControlBlock {
    pub ti: u32,           // Transfer Information
    pub source_ad: u32,    // Source Address (bus address)
    pub dest_ad: u32,      // Destination Address (bus address)
    pub txfr_len: u32,     // Transfer Length
    pub stride: u32,       // 2D Stride
    pub nextconbk: u32,    // Next CB Address (bus, 0 = last)
    pub reserved: [u32; 2],
}

const DMA_CHANNEL_STRIDE: usize = 0x100;
const MAX_DMA_CHANNELS: usize = 16;

// Global DMA enable register
const DMA_ENABLE: usize = 0xFF0;

static mut DMA_BASE: usize = 0;
static mut DMA_CHANNEL_BUSY: [bool; MAX_DMA_CHANNELS] = [false; MAX_DMA_CHANNELS];

fn mmio_read(addr: usize) -> u32 {
    unsafe { read_volatile(addr as *const u32) }
}

fn mmio_write(addr: usize, val: u32) {
    unsafe { write_volatile(addr as *mut u32, val) }
}

fn channel_base(ch: u32) -> usize {
    unsafe { DMA_BASE + (ch as usize) * DMA_CHANNEL_STRIDE }
}

// ── FFI exports ──

/// Initialize DMA controller
/// base_addr: MMIO base (peripheral_base + 0x007000)
#[unsafe(no_mangle)]
pub extern "C" fn rpi_dma_init(base_addr: u64) {
    let base = base_addr as usize;
    unsafe {
        DMA_BASE = base;
        DMA_CHANNEL_BUSY = [false; MAX_DMA_CHANNELS];
    }

    // Enable all DMA channels
    mmio_write(base + DMA_ENABLE, 0xFFFF);

    // Reset all channels
    for ch in 0..MAX_DMA_CHANNELS as u32 {
        let cb = channel_base(ch);
        mmio_write(cb + DMA_CS, CS_RESET);
    }
}

/// Allocate a free DMA channel
/// Returns: channel number (0-15), or -1 if none available
#[unsafe(no_mangle)]
pub extern "C" fn rpi_dma_alloc_channel() -> i32 {
    unsafe {
        // Prefer channels 7-10 (full-featured), then lite channels
        for ch in (7..=10).chain(0..=6).chain(11..16) {
            if !DMA_CHANNEL_BUSY[ch] {
                DMA_CHANNEL_BUSY[ch] = true;
                return ch as i32;
            }
        }
    }
    -1
}

/// Free a DMA channel
#[unsafe(no_mangle)]
pub extern "C" fn rpi_dma_free_channel(ch: u32) {
    if (ch as usize) < MAX_DMA_CHANNELS {
        unsafe { DMA_CHANNEL_BUSY[ch as usize] = false; }
    }
}

/// Start a memory-to-memory DMA transfer
/// ch: DMA channel
/// cb: pointer to DmaControlBlock (must be 32-byte aligned, bus address)
#[unsafe(no_mangle)]
pub extern "C" fn rpi_dma_start(ch: u32, cb_bus_addr: u32) {
    if (ch as usize) >= MAX_DMA_CHANNELS { return; }
    let base = channel_base(ch);

    // Clear status
    mmio_write(base + DMA_CS, CS_END | CS_INT | CS_ERROR);

    // Set control block address
    mmio_write(base + DMA_CONBLK_AD, cb_bus_addr);

    // Start transfer
    mmio_write(base + DMA_CS, CS_ACTIVE);
}

/// Check if a DMA transfer is complete
/// Returns: true if done, false if still active
#[unsafe(no_mangle)]
pub extern "C" fn rpi_dma_is_done(ch: u32) -> bool {
    if (ch as usize) >= MAX_DMA_CHANNELS { return true; }
    let base = channel_base(ch);
    let cs = mmio_read(base + DMA_CS);
    (cs & CS_ACTIVE) == 0 || (cs & CS_END) != 0
}

/// Wait for DMA transfer to complete (blocking)
/// Returns: 0 on success, -1 on error, -2 on timeout
#[unsafe(no_mangle)]
pub extern "C" fn rpi_dma_wait(ch: u32) -> i32 {
    if (ch as usize) >= MAX_DMA_CHANNELS { return -1; }
    let base = channel_base(ch);

    for _ in 0..1_000_000 {
        let cs = mmio_read(base + DMA_CS);
        if cs & CS_ERROR != 0 { return -1; }
        if (cs & CS_ACTIVE) == 0 || (cs & CS_END) != 0 {
            mmio_write(base + DMA_CS, CS_END | CS_INT);
            return 0;
        }
    }
    -2 // Timeout
}

/// Abort an active DMA transfer
#[unsafe(no_mangle)]
pub extern "C" fn rpi_dma_abort(ch: u32) {
    if (ch as usize) >= MAX_DMA_CHANNELS { return; }
    let base = channel_base(ch);
    mmio_write(base + DMA_CS, CS_ABORT);
    for _ in 0..10000 {
        if mmio_read(base + DMA_CS) & CS_ACTIVE == 0 { break; }
    }
    mmio_write(base + DMA_CS, CS_RESET);
}

/// Simple memory copy using DMA (for large transfers > 4KB)
/// Allocates a channel, performs transfer, frees channel.
/// src/dst must be bus addresses (physical).
#[unsafe(no_mangle)]
pub extern "C" fn rpi_dma_memcpy(dst_bus: u32, src_bus: u32, len: u32) -> i32 {
    let ch = rpi_dma_alloc_channel();
    if ch < 0 { return -1; }

    // Build control block on stack (must be 32-byte aligned)
    let mut cb = DmaControlBlock {
        ti: TI_SRC_INC | TI_DEST_INC | TI_WAIT_RESP,
        source_ad: src_bus,
        dest_ad: dst_bus,
        txfr_len: len,
        stride: 0,
        nextconbk: 0,
        reserved: [0; 2],
    };

    // Convert CB address to bus address
    let cb_addr = &cb as *const _ as u64;
    let cb_bus = if cb_addr >= 0xC0000000 {
        (cb_addr & 0x3FFFFFFF) as u32 // Convert to bus address
    } else {
        cb_addr as u32
    };

    rpi_dma_start(ch as u32, cb_bus);
    let rc = rpi_dma_wait(ch as u32);
    rpi_dma_free_channel(ch as u32);
    rc
}
