// SPDX-License-Identifier: MPL-2.0
//
// Raspberry Pi BSC I2C Controller Driver
//
// The BCM2711 has multiple BSC (Broadcom Serial Controller) I2C masters:
//   BSC0 (I2C0): peripheral_base + 0x205000 — HAT ID EEPROM, camera
//   BSC1 (I2C1): peripheral_base + 0x804000 — user I2C (GPIO2/3)
//   BSC3-6: additional I2C buses on Pi4
//
// Standard I2C: 100 kHz (default), 400 kHz (fast mode)
// Supports 7-bit addressing, multi-byte read/write transfers.
//
// Used for: HAT detection, RTC chips, temperature sensors, OLED displays,
// ADCs, GPIO expanders, and other I2C peripherals.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(unexpected_cfgs)]

use core::ptr::{read_volatile, write_volatile};

// BSC I2C register offsets
const BSC_C: usize = 0x00;      // Control
const BSC_S: usize = 0x04;      // Status
const BSC_DLEN: usize = 0x08;   // Data Length
const BSC_A: usize = 0x0C;      // Slave Address
const BSC_FIFO: usize = 0x10;   // Data FIFO
const BSC_DIV: usize = 0x14;    // Clock Divider
const BSC_DEL: usize = 0x18;    // Data Delay
const BSC_CLKT: usize = 0x1C;   // Clock Stretch Timeout

// Control register bits
const C_I2CEN: u32 = 1 << 15;    // I2C Enable
const C_INTR: u32 = 1 << 10;     // Interrupt on RX
const C_INTT: u32 = 1 << 9;      // Interrupt on TX
const C_INTD: u32 = 1 << 8;      // Interrupt on Done
const C_ST: u32 = 1 << 7;        // Start Transfer
const C_CLEAR: u32 = 3 << 4;     // Clear FIFO (bits 5:4)
const C_READ: u32 = 1 << 0;      // Read Transfer

// Status register bits
const S_CLKT: u32 = 1 << 9;      // Clock Stretch Timeout
const S_ERR: u32 = 1 << 8;       // ACK Error
const S_RXF: u32 = 1 << 7;       // RX FIFO Full
const S_TXE: u32 = 1 << 6;       // TX FIFO Empty
const S_RXD: u32 = 1 << 5;       // RX FIFO has Data
const S_TXD: u32 = 1 << 4;       // TX FIFO can accept Data
const S_RXR: u32 = 1 << 3;       // RX FIFO needs Reading
const S_TXW: u32 = 1 << 2;       // TX FIFO needs Writing
const S_DONE: u32 = 1 << 1;      // Transfer Done
const S_TA: u32 = 1 << 0;        // Transfer Active

// Default core clock for Pi4: 150 MHz (used to calculate divider)
const DEFAULT_CORE_CLOCK: u32 = 150_000_000;

// Maximum number of I2C buses we track
const MAX_BUSES: usize = 4;

struct I2cBus {
    base: usize,
    active: bool,
    speed_hz: u32,
}

static mut BUSES: [I2cBus; MAX_BUSES] = [
    I2cBus { base: 0, active: false, speed_hz: 100_000 },
    I2cBus { base: 0, active: false, speed_hz: 100_000 },
    I2cBus { base: 0, active: false, speed_hz: 100_000 },
    I2cBus { base: 0, active: false, speed_hz: 100_000 },
];

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

/// Initialize an I2C bus
/// bus: bus number (0-3)
/// base_addr: MMIO base of BSC controller
/// speed_hz: clock speed (100000 for standard, 400000 for fast)
#[no_mangle]
pub extern "C" fn rpi_i2c_init(bus: u32, base_addr: u64, speed_hz: u32) -> i32 {
    if bus as usize >= MAX_BUSES { return -1; }
    let base = base_addr as usize;
    let speed = if speed_hz == 0 { 100_000 } else { speed_hz };

    unsafe {
        BUSES[bus as usize].base = base;
        BUSES[bus as usize].speed_hz = speed;
        BUSES[bus as usize].active = true;
    }

    // Set clock divider: DIV = core_clock / speed
    let div = DEFAULT_CORE_CLOCK / speed;
    mmio_write(base + BSC_DIV, div);

    // Set clock stretch timeout (generous)
    mmio_write(base + BSC_CLKT, 0x40);

    // Clear FIFO and status
    mmio_write(base + BSC_C, C_CLEAR);
    mmio_write(base + BSC_S, S_CLKT | S_ERR | S_DONE);

    0
}

/// Write data to an I2C device
/// bus: bus number
/// addr: 7-bit slave address
/// data: pointer to bytes to write
/// len: number of bytes
/// Returns: 0 on success, -1 on NACK, -2 on timeout
#[no_mangle]
pub extern "C" fn rpi_i2c_write(bus: u32, addr: u8, data: *const u8, len: u32) -> i32 {
    if bus as usize >= MAX_BUSES || data.is_null() { return -1; }
    let base = unsafe { BUSES[bus as usize].base };
    if base == 0 { return -1; }

    // Clear status
    mmio_write(base + BSC_S, S_CLKT | S_ERR | S_DONE);

    // Set slave address and data length
    mmio_write(base + BSC_A, addr as u32);
    mmio_write(base + BSC_DLEN, len);

    // Clear FIFO and start write transfer
    mmio_write(base + BSC_C, C_I2CEN | C_ST | C_CLEAR);

    // Fill TX FIFO
    let mut idx: u32 = 0;
    while idx < len {
        // Wait for FIFO space
        for _ in 0..10000 {
            if mmio_read(base + BSC_S) & S_TXD != 0 { break; }
            delay(1);
        }
        let byte = unsafe { *data.add(idx as usize) };
        mmio_write(base + BSC_FIFO, byte as u32);
        idx += 1;
    }

    // Wait for transfer done
    for _ in 0..100000 {
        let s = mmio_read(base + BSC_S);
        if s & S_DONE != 0 { break; }
        if s & S_ERR != 0 {
            mmio_write(base + BSC_S, S_ERR);
            return -1; // NACK
        }
        if s & S_CLKT != 0 {
            mmio_write(base + BSC_S, S_CLKT);
            return -2; // Timeout
        }
        delay(1);
    }

    // Clear done flag
    mmio_write(base + BSC_S, S_DONE);
    0
}

/// Read data from an I2C device
/// bus: bus number
/// addr: 7-bit slave address
/// data: pointer to buffer for received bytes
/// len: number of bytes to read
/// Returns: 0 on success, negative on error
#[no_mangle]
pub extern "C" fn rpi_i2c_read(bus: u32, addr: u8, data: *mut u8, len: u32) -> i32 {
    if bus as usize >= MAX_BUSES || data.is_null() { return -1; }
    let base = unsafe { BUSES[bus as usize].base };
    if base == 0 { return -1; }

    // Clear status
    mmio_write(base + BSC_S, S_CLKT | S_ERR | S_DONE);

    // Set slave address and data length
    mmio_write(base + BSC_A, addr as u32);
    mmio_write(base + BSC_DLEN, len);

    // Clear FIFO and start read transfer
    mmio_write(base + BSC_C, C_I2CEN | C_ST | C_CLEAR | C_READ);

    // Read RX FIFO
    let mut idx: u32 = 0;
    while idx < len {
        // Wait for data
        for _ in 0..10000 {
            let s = mmio_read(base + BSC_S);
            if s & S_RXD != 0 { break; }
            if s & S_ERR != 0 {
                mmio_write(base + BSC_S, S_ERR);
                return -1;
            }
            if s & S_CLKT != 0 {
                mmio_write(base + BSC_S, S_CLKT);
                return -2;
            }
            delay(1);
        }
        let byte = (mmio_read(base + BSC_FIFO) & 0xFF) as u8;
        unsafe { *data.add(idx as usize) = byte; }
        idx += 1;
    }

    // Wait for done
    for _ in 0..10000 {
        if mmio_read(base + BSC_S) & S_DONE != 0 { break; }
        delay(1);
    }
    mmio_write(base + BSC_S, S_DONE);
    0
}

/// Write then read (combined transaction) — common for register reads
/// Writes reg_addr byte(s), then reads len bytes back
#[no_mangle]
pub extern "C" fn rpi_i2c_write_read(bus: u32, addr: u8,
                                      write_data: *const u8, write_len: u32,
                                      read_data: *mut u8, read_len: u32) -> i32 {
    let rc = rpi_i2c_write(bus, addr, write_data, write_len);
    if rc != 0 { return rc; }
    rpi_i2c_read(bus, addr, read_data, read_len)
}

/// Scan for I2C devices on a bus (probe addresses 0x03-0x77)
/// found: output array for detected addresses (max 112 entries)
/// Returns: number of devices found
#[no_mangle]
pub extern "C" fn rpi_i2c_scan(bus: u32, found: *mut u8) -> i32 {
    if bus as usize >= MAX_BUSES { return -1; }
    let base = unsafe { BUSES[bus as usize].base };
    if base == 0 { return -1; }

    let mut count = 0i32;
    for addr in 0x03u8..=0x77 {
        // Try a zero-length write to detect ACK
        mmio_write(base + BSC_S, S_CLKT | S_ERR | S_DONE);
        mmio_write(base + BSC_A, addr as u32);
        mmio_write(base + BSC_DLEN, 0);
        mmio_write(base + BSC_C, C_I2CEN | C_ST | C_CLEAR);

        delay(1000);
        let s = mmio_read(base + BSC_S);
        mmio_write(base + BSC_S, S_CLKT | S_ERR | S_DONE);

        if s & S_ERR == 0 && s & S_DONE != 0 {
            if !found.is_null() && count < 112 {
                unsafe { *found.add(count as usize) = addr; }
            }
            count += 1;
        }
    }
    count
}
