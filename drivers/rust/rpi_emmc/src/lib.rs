// SPDX-License-Identifier: MPL-2.0
//
// Raspberry Pi 4/5 eMMC2/SDHCI SD card driver
//
// Implements the SDHCI (SD Host Controller Interface) for the BCM2711
// eMMC2 controller on RPi4 and BCM2712 on RPi5.
//
// Supports:
//   - SD card detection and initialization (CMD0, CMD8, ACMD41, CMD2, CMD3)
//   - Single block read (CMD17) and write (CMD24)
//   - SDHC/SDXC high-capacity cards
//   - PIO (programmed I/O) data transfer

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(unexpected_cfgs)]
extern crate common;

use core::ptr::{read_volatile, write_volatile};

// SDHCI register offsets
const SDHCI_ARGUMENT: usize = 0x08;
const SDHCI_TRANSFER_MODE: usize = 0x0C;
const SDHCI_COMMAND: usize = 0x0E;
const SDHCI_RESPONSE0: usize = 0x10;
const SDHCI_BUFFER_DATA: usize = 0x20;
const SDHCI_PRESENT_STATE: usize = 0x24;
const SDHCI_HOST_CONTROL: usize = 0x28;
const SDHCI_POWER_CONTROL: usize = 0x29;
const SDHCI_CLOCK_CONTROL: usize = 0x2C;
const SDHCI_TIMEOUT_CTRL: usize = 0x2E;
const SDHCI_SOFTWARE_RESET: usize = 0x2F;
const SDHCI_INT_STATUS: usize = 0x30;
const SDHCI_INT_ENABLE: usize = 0x34;
const SDHCI_BLOCK_SIZE: usize = 0x04;
const SDHCI_BLOCK_COUNT: usize = 0x06;

// Present state bits
const CMD_INHIBIT: u32 = 1 << 0;
const CARD_INSERTED: u32 = 1 << 16;
const BUF_RD_READY: u32 = 1 << 11;
const BUF_WR_READY: u32 = 1 << 10;

// Interrupt bits
const INT_CMD_DONE: u32 = 1 << 0;
const INT_XFER_DONE: u32 = 1 << 1;
const INT_BUF_RD_RDY: u32 = 1 << 5;
const INT_BUF_WR_RDY: u32 = 1 << 4;
const INT_ERROR: u32 = 1 << 15;

// Reset bits
const RESET_ALL: u8 = 0x01;

// Clock bits
const CLK_INT_EN: u16 = 1 << 0;
const CLK_INT_STABLE: u16 = 1 << 1;
const CLK_SD_EN: u16 = 1 << 2;

// Response types
const RESP_NONE: u8 = 0;
const RESP_136: u8 = 1;
const RESP_48: u8 = 2;
const RESP_48_BUSY: u8 = 3;

/// RPi eMMC2/SDHCI driver state
struct EmmcDriver {
    base: usize,
    initialized: bool,
    is_sdhc: bool,
    rca: u32,
}

static mut EMMC: EmmcDriver = EmmcDriver {
    base: 0,
    initialized: false,
    is_sdhc: false,
    rca: 0,
};

// MMIO helpers
fn mmio_read32(base: usize, offset: usize) -> u32 {
    unsafe { read_volatile((base + offset) as *const u32) }
}

fn mmio_write32(base: usize, offset: usize, val: u32) {
    unsafe { write_volatile((base + offset) as *mut u32, val) }
}

fn mmio_read16(base: usize, offset: usize) -> u16 {
    let val = mmio_read32(base, offset & !3);
    if offset & 2 != 0 { (val >> 16) as u16 } else { val as u16 }
}

fn mmio_write16(base: usize, offset: usize, val: u16) {
    let reg = mmio_read32(base, offset & !3);
    let new = if offset & 2 != 0 {
        (reg & 0x0000FFFF) | ((val as u32) << 16)
    } else {
        (reg & 0xFFFF0000) | (val as u32)
    };
    mmio_write32(base, offset & !3, new);
}

fn mmio_write8(base: usize, offset: usize, val: u8) {
    let reg = mmio_read32(base, offset & !3);
    let shift = (offset & 3) * 8;
    let new = (reg & !(0xFF << shift)) | ((val as u32) << shift);
    mmio_write32(base, offset & !3, new);
}

fn delay(count: u32) {
    for _ in 0..count {
        unsafe { core::arch::asm!("yield") };
    }
}

/// Send an SD command and wait for response
fn send_cmd(base: usize, cmd: u32, arg: u32, resp_type: u8) -> (i32, [u32; 4]) {
    let mut resp = [0u32; 4];

    // Wait for CMD line free
    for _ in 0..100000 {
        if mmio_read32(base, SDHCI_PRESENT_STATE) & CMD_INHIBIT == 0 { break; }
        delay(1);
    }

    // Clear interrupts
    mmio_write32(base, SDHCI_INT_STATUS, 0xFFFFFFFF);

    // Set argument
    mmio_write32(base, SDHCI_ARGUMENT, arg);

    // Build command register
    let mut cmd_val: u16 = ((cmd & 0x3F) << 8) as u16;
    match resp_type {
        RESP_NONE => {},
        RESP_136 => cmd_val |= 0x01,
        RESP_48 => cmd_val |= 0x02,
        RESP_48_BUSY => cmd_val |= 0x03,
        _ => {},
    }
    if resp_type != RESP_NONE {
        cmd_val |= 1 << 4; // CRC check
    }

    mmio_write16(base, SDHCI_COMMAND, cmd_val);

    // Wait for completion
    for _ in 0..100000 {
        let status = mmio_read32(base, SDHCI_INT_STATUS);
        if status & INT_ERROR != 0 {
            mmio_write32(base, SDHCI_INT_STATUS, status);
            return (-2, resp);
        }
        if status & INT_CMD_DONE != 0 {
            mmio_write32(base, SDHCI_INT_STATUS, INT_CMD_DONE);
            break;
        }
        delay(1);
    }

    // Read response
    if resp_type != RESP_NONE {
        resp[0] = mmio_read32(base, SDHCI_RESPONSE0);
        if resp_type == RESP_136 {
            resp[1] = mmio_read32(base, SDHCI_RESPONSE0 + 4);
            resp[2] = mmio_read32(base, SDHCI_RESPONSE0 + 8);
            resp[3] = mmio_read32(base, SDHCI_RESPONSE0 + 12);
        }
    }

    (0, resp)
}

// ── FFI exports for C kernel ──

/// Initialize the eMMC2 SDHCI controller
/// base_addr: physical MMIO base address of eMMC2
/// Returns: 0 on success, negative on failure
#[unsafe(no_mangle)]
pub extern "C" fn rpi_emmc_init(base_addr: u64) -> i32 {
    let base = base_addr as usize;

    unsafe {
        EMMC.base = base;
        EMMC.initialized = false;
    }

    // Reset controller
    mmio_write8(base, SDHCI_SOFTWARE_RESET, RESET_ALL);
    for _ in 0..100000 {
        if mmio_read32(base, SDHCI_SOFTWARE_RESET) & (RESET_ALL as u32) == 0 { break; }
        delay(10);
    }

    // Check card presence
    if mmio_read32(base, SDHCI_PRESENT_STATE) & CARD_INSERTED == 0 {
        return -2; // No card
    }

    // Enable internal clock
    mmio_write16(base, SDHCI_CLOCK_CONTROL, CLK_INT_EN);
    for _ in 0..10000 {
        if mmio_read16(base, SDHCI_CLOCK_CONTROL) & CLK_INT_STABLE != 0 { break; }
        delay(10);
    }

    // Set 400 KHz init clock
    let clk = CLK_INT_EN | (0x80 << 8);
    mmio_write16(base, SDHCI_CLOCK_CONTROL, clk);
    delay(1000);
    mmio_write16(base, SDHCI_CLOCK_CONTROL, clk | CLK_SD_EN);

    // Power on (3.3V)
    mmio_write8(base, SDHCI_POWER_CONTROL, 0x0F);

    // Enable interrupts
    mmio_write32(base, SDHCI_INT_ENABLE, 0x0FFF00FF);
    mmio_write8(base, SDHCI_TIMEOUT_CTRL, 0x0E);

    // CMD0: GO_IDLE
    send_cmd(base, 0, 0, RESP_NONE);
    delay(5000);

    // CMD8: SEND_IF_COND
    let (rc, resp) = send_cmd(base, 8, 0x1AA, RESP_48);
    let sd_v2 = rc == 0 && (resp[0] & 0xFFF) == 0x1AA;

    // ACMD41: SD_SEND_OP_COND
    let mut acmd41_arg: u32 = 0x00FF8000;
    if sd_v2 { acmd41_arg |= 1 << 30; } // HCS

    let mut ocr = 0u32;
    for _ in 0..100 {
        send_cmd(base, 55, 0, RESP_48);
        let (_, r) = send_cmd(base, 41, acmd41_arg, RESP_48);
        if r[0] & (1 << 31) != 0 {
            ocr = r[0];
            break;
        }
        delay(10000);
    }

    let is_sdhc = ocr & (1 << 30) != 0;

    // CMD2: ALL_SEND_CID
    send_cmd(base, 2, 0, RESP_136);

    // CMD3: SEND_RELATIVE_ADDR
    let (_, r3) = send_cmd(base, 3, 0, RESP_48);
    let rca = r3[0] >> 16;

    // CMD7: SELECT_CARD
    send_cmd(base, 7, rca << 16, RESP_48_BUSY);

    // Switch to 25 MHz
    mmio_write16(base, SDHCI_CLOCK_CONTROL, CLK_INT_EN | (0x04 << 8));
    delay(1000);
    mmio_write16(base, SDHCI_CLOCK_CONTROL, CLK_INT_EN | CLK_SD_EN | (0x04 << 8));

    // Block size = 512
    mmio_write16(base, SDHCI_BLOCK_SIZE, 512);

    unsafe {
        EMMC.initialized = true;
        EMMC.is_sdhc = is_sdhc;
        EMMC.rca = rca;
    }

    0
}

/// Read a single 512-byte block from the SD card
/// lba: logical block address
/// buffer: pointer to 512-byte output buffer
#[unsafe(no_mangle)]
pub extern "C" fn rpi_emmc_read_block(lba: u32, buffer: *mut u8) -> i32 {
    let base = unsafe { EMMC.base };
    if base == 0 || buffer.is_null() { return -1; }
    let is_sdhc = unsafe { EMMC.is_sdhc };

    let addr = if is_sdhc { lba } else { lba * 512 };

    mmio_write16(base, SDHCI_BLOCK_SIZE, 512);
    mmio_write16(base, SDHCI_BLOCK_COUNT, 1);
    mmio_write16(base, SDHCI_TRANSFER_MODE, 1 << 4); // Read

    let (rc, _) = send_cmd(base, 17, addr, RESP_48);
    if rc != 0 { return rc; }

    // Wait for buffer ready
    for _ in 0..100000 {
        let status = mmio_read32(base, SDHCI_INT_STATUS);
        if status & INT_ERROR != 0 { return -2; }
        if status & INT_BUF_RD_RDY != 0 {
            mmio_write32(base, SDHCI_INT_STATUS, INT_BUF_RD_RDY);
            break;
        }
        delay(1);
    }

    // Read 512 bytes
    let dst = buffer as *mut u32;
    for i in 0..128 {
        let val = mmio_read32(base, SDHCI_BUFFER_DATA);
        unsafe { dst.add(i).write_volatile(val); }
    }

    // Wait for transfer complete
    for _ in 0..100000 {
        let status = mmio_read32(base, SDHCI_INT_STATUS);
        if status & INT_XFER_DONE != 0 {
            mmio_write32(base, SDHCI_INT_STATUS, INT_XFER_DONE);
            break;
        }
    }

    0
}

/// Write a single 512-byte block to the SD card
#[unsafe(no_mangle)]
pub extern "C" fn rpi_emmc_write_block(lba: u32, buffer: *const u8) -> i32 {
    let base = unsafe { EMMC.base };
    if base == 0 || buffer.is_null() { return -1; }
    let is_sdhc = unsafe { EMMC.is_sdhc };

    let addr = if is_sdhc { lba } else { lba * 512 };

    mmio_write16(base, SDHCI_BLOCK_SIZE, 512);
    mmio_write16(base, SDHCI_BLOCK_COUNT, 1);
    mmio_write16(base, SDHCI_TRANSFER_MODE, 0); // Write

    let (rc, _) = send_cmd(base, 24, addr, RESP_48);
    if rc != 0 { return rc; }

    // Wait for buffer ready
    for _ in 0..100000 {
        let status = mmio_read32(base, SDHCI_INT_STATUS);
        if status & INT_ERROR != 0 { return -2; }
        if status & INT_BUF_WR_RDY != 0 {
            mmio_write32(base, SDHCI_INT_STATUS, INT_BUF_WR_RDY);
            break;
        }
        delay(1);
    }

    // Write 512 bytes
    let src = buffer as *const u32;
    for i in 0..128 {
        let val = unsafe { src.add(i).read_volatile() };
        mmio_write32(base, SDHCI_BUFFER_DATA, val);
    }

    // Wait for transfer complete
    for _ in 0..100000 {
        let status = mmio_read32(base, SDHCI_INT_STATUS);
        if status & INT_XFER_DONE != 0 {
            mmio_write32(base, SDHCI_INT_STATUS, INT_XFER_DONE);
            break;
        }
    }

    0
}

/// Check if eMMC driver is initialized
#[unsafe(no_mangle)]
pub extern "C" fn rpi_emmc_is_ready() -> bool {
    unsafe { EMMC.initialized }
}
