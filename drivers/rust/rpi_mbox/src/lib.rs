// SPDX-License-Identifier: MPL-2.0
//
// Raspberry Pi VideoCore Mailbox Driver
//
// Communication channel between ARM cores and VideoCore GPU firmware.
// Used for clock/power management, framebuffer, board info, temperature.
//
// BCM2711 (Pi4): mailbox at peripheral_base + 0xB880
// BCM2712 (Pi5): mailbox at peripheral_base + 0x13880

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(unexpected_cfgs)]
extern crate common;

use core::ptr::{read_volatile, write_volatile};

// Mailbox registers
const MBOX_READ: usize = 0x00;
const MBOX_STATUS: usize = 0x18;
const MBOX_WRITE: usize = 0x20;

const MBOX_FULL: u32 = 0x80000000;
const MBOX_EMPTY: u32 = 0x40000000;
const MBOX_CHANNEL_PROP: u8 = 8;

// Property tags
const TAG_GET_BOARD_REV: u32 = 0x00010002;
const TAG_GET_BOARD_SERIAL: u32 = 0x00010004;
const TAG_GET_ARM_MEMORY: u32 = 0x00010005;
const TAG_GET_CLOCK_RATE: u32 = 0x00030002;
const TAG_SET_CLOCK_RATE: u32 = 0x00038002;
const TAG_SET_POWER_STATE: u32 = 0x00028001;
const TAG_GET_TEMPERATURE: u32 = 0x00030006;

// 16-byte aligned mailbox buffer
#[repr(C, align(16))]
struct MboxBuffer {
    data: [u32; 256],
}

static mut MBOX_BUF: MboxBuffer = MboxBuffer { data: [0; 256] };
static mut MBOX_BASE: usize = 0;

fn mmio_read(addr: usize) -> u32 {
    unsafe { read_volatile(addr as *const u32) }
}

fn mmio_write(addr: usize, val: u32) {
    unsafe { write_volatile(addr as *mut u32, val) }
}

fn mbox_call(channel: u8) -> bool {
    let base = unsafe { MBOX_BASE };
    if base == 0 { return false; }

    let buf_addr = unsafe { &raw const MBOX_BUF.data as *const _ as u64 };
    // Convert kernel VA to physical if needed
    let phys = if buf_addr >= 0xFFFFFF8000000000 {
        buf_addr - 0xFFFFFF8040000000 + 0x40000000
    } else {
        buf_addr
    };

    let msg = ((phys as u32) & 0xFFFFFFF0) | (channel & 0xF) as u32;

    // Wait for mailbox not full
    for _ in 0..1000000 {
        if mmio_read(base + MBOX_STATUS) & MBOX_FULL == 0 { break; }
    }

    // Write
    mmio_write(base + MBOX_WRITE, msg);

    // Wait for response
    for _ in 0..1000000 {
        for _ in 0..1000000 {
            if mmio_read(base + MBOX_STATUS) & MBOX_EMPTY == 0 { break; }
        }
        let response = mmio_read(base + MBOX_READ);
        if response & 0xF == channel as u32 {
            return unsafe { MBOX_BUF.data[1] == 0x80000000 };
        }
    }
    false
}

// ── FFI exports ──

#[unsafe(no_mangle)]
pub extern "C" fn rpi_mbox_init(periph_base: u64) {
    // Pi4: +0xB880, Pi5: +0x13880
    // For simplicity, use the standard offset; caller can adjust
    unsafe { MBOX_BASE = (periph_base + 0xB880) as usize; }
}

#[unsafe(no_mangle)]
pub extern "C" fn rpi_mbox_get_board_revision() -> u32 {
    unsafe {
        MBOX_BUF.data[0] = 7 * 4;
        MBOX_BUF.data[1] = 0;
        MBOX_BUF.data[2] = TAG_GET_BOARD_REV;
        MBOX_BUF.data[3] = 4;
        MBOX_BUF.data[4] = 0;
        MBOX_BUF.data[5] = 0;
        MBOX_BUF.data[6] = 0;
    }
    if mbox_call(MBOX_CHANNEL_PROP) {
        unsafe { MBOX_BUF.data[5] }
    } else { 0 }
}

#[unsafe(no_mangle)]
pub extern "C" fn rpi_mbox_get_board_serial() -> u64 {
    unsafe {
        MBOX_BUF.data[0] = 8 * 4;
        MBOX_BUF.data[1] = 0;
        MBOX_BUF.data[2] = TAG_GET_BOARD_SERIAL;
        MBOX_BUF.data[3] = 8;
        MBOX_BUF.data[4] = 0;
        MBOX_BUF.data[5] = 0;
        MBOX_BUF.data[6] = 0;
        MBOX_BUF.data[7] = 0;
    }
    if mbox_call(MBOX_CHANNEL_PROP) {
        unsafe { ((MBOX_BUF.data[6] as u64) << 32) | MBOX_BUF.data[5] as u64 }
    } else { 0 }
}

#[unsafe(no_mangle)]
pub extern "C" fn rpi_mbox_get_arm_memory(base: *mut u32, size: *mut u32) {
    unsafe {
        MBOX_BUF.data[0] = 8 * 4;
        MBOX_BUF.data[1] = 0;
        MBOX_BUF.data[2] = TAG_GET_ARM_MEMORY;
        MBOX_BUF.data[3] = 8;
        MBOX_BUF.data[4] = 0;
        MBOX_BUF.data[5] = 0;
        MBOX_BUF.data[6] = 0;
        MBOX_BUF.data[7] = 0;
    }
    if mbox_call(MBOX_CHANNEL_PROP) {
        unsafe {
            if !base.is_null() { *base = MBOX_BUF.data[5]; }
            if !size.is_null() { *size = MBOX_BUF.data[6]; }
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn rpi_mbox_get_clock_rate(clock_id: u32) -> u32 {
    unsafe {
        MBOX_BUF.data[0] = 8 * 4;
        MBOX_BUF.data[1] = 0;
        MBOX_BUF.data[2] = TAG_GET_CLOCK_RATE;
        MBOX_BUF.data[3] = 8;
        MBOX_BUF.data[4] = 0;
        MBOX_BUF.data[5] = clock_id;
        MBOX_BUF.data[6] = 0;
        MBOX_BUF.data[7] = 0;
    }
    if mbox_call(MBOX_CHANNEL_PROP) {
        unsafe { MBOX_BUF.data[6] }
    } else { 0 }
}

#[unsafe(no_mangle)]
pub extern "C" fn rpi_mbox_set_clock_rate(clock_id: u32, rate: u32) -> u32 {
    unsafe {
        MBOX_BUF.data[0] = 9 * 4;
        MBOX_BUF.data[1] = 0;
        MBOX_BUF.data[2] = TAG_SET_CLOCK_RATE;
        MBOX_BUF.data[3] = 12;
        MBOX_BUF.data[4] = 0;
        MBOX_BUF.data[5] = clock_id;
        MBOX_BUF.data[6] = rate;
        MBOX_BUF.data[7] = 0;  /* skip setting turbo */
        MBOX_BUF.data[8] = 0;
    }
    if mbox_call(MBOX_CHANNEL_PROP) {
        unsafe { MBOX_BUF.data[6] }
    } else { 0 }
}

#[unsafe(no_mangle)]
pub extern "C" fn rpi_mbox_set_power_state(device_id: u32, on: bool) -> bool {
    unsafe {
        MBOX_BUF.data[0] = 8 * 4;
        MBOX_BUF.data[1] = 0;
        MBOX_BUF.data[2] = TAG_SET_POWER_STATE;
        MBOX_BUF.data[3] = 8;
        MBOX_BUF.data[4] = 0;
        MBOX_BUF.data[5] = device_id;
        MBOX_BUF.data[6] = if on { 3 } else { 0 };
        MBOX_BUF.data[7] = 0;
    }
    mbox_call(MBOX_CHANNEL_PROP)
}

#[unsafe(no_mangle)]
pub extern "C" fn rpi_mbox_get_temperature() -> u32 {
    unsafe {
        MBOX_BUF.data[0] = 8 * 4;
        MBOX_BUF.data[1] = 0;
        MBOX_BUF.data[2] = TAG_GET_TEMPERATURE;
        MBOX_BUF.data[3] = 8;
        MBOX_BUF.data[4] = 0;
        MBOX_BUF.data[5] = 0;
        MBOX_BUF.data[6] = 0;
        MBOX_BUF.data[7] = 0;
    }
    if mbox_call(MBOX_CHANNEL_PROP) {
        unsafe { MBOX_BUF.data[6] }
    } else { 0 }
}
