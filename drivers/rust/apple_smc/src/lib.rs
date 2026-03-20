// SPDX-License-Identifier: MPL-2.0
//! Apple Silicon SMC (System Management Controller) driver for Futura OS
//!
//! The SMC is a co-processor embedded in Apple Silicon SoCs that manages:
//! - Thermal sensors (CPU/GPU die temperature, PCB temperature, etc.)
//! - Fan control (MacBook Pro) and active cooling requests
//! - Battery / power management (charge state, watt-hours, adapter ID)
//! - System power events (system sleep/wake, lid open/close)
//! - Hardware random number generator seeding
//!
//! On Apple Silicon (M1/M2/M3), the SMC is accessed via a mailbox interface
//! backed by RTKit, unlike the x86 Mac SMC which used LPC I/O port 0x300.
//! This driver implements the RTKit-mailbox protocol variant.
//!
//! Protocol summary
//! ----------------
//! Each SMC operation is a "key" read/write.  A key is a 4-byte ASCII
//! identifier (e.g., "TC0E" = CPU die temperature, "TA0P" = ambient temp,
//! "FNum" = fan count).  Keys have an associated data type tag (e.g., "fpe2"
//! for a 14.2 fixed-point number) and a maximum data length (1–32 bytes).
//!
//! Mailbox protocol:
//!   1. Write command word to MBOX_WRITE_DATA: [cmd(8) | key_hi(16) | seq(8)]
//!   2. Write argument to MBOX_WRITE_ARG: [key_lo(16) | type(32) | len(8)]
//!   3. Poll MBOX_STATUS until NOT_EMPTY
//!   4. Read MBOX_READ_DATA for result and data bytes
//!
//! Register map (RTKit mailbox)
//! ----------------------------
//! 0x00  MBOX_WRITE_DATA   — write command + key high bytes + sequence
//! 0x04  MBOX_WRITE_ARG    — write argument (key low bytes + type + length)
//! 0x08  MBOX_STATUS       — bit 0: write-full; bit 4: read-not-empty
//! 0x0C  MBOX_READ_DATA    — read response data
//! 0x10  MBOX_READ_ARG     — read response argument (data bytes 0–3)
//! 0x14  MBOX_READ_ARG2    — read response argument (data bytes 4–7)
//! 0x18  MBOX_INT_MASK     — interrupt mask (1 = unmask)
//! 0x1C  MBOX_INT_CLR      — write-1-to-clear interrupt
//!
//! Reference: Asahi Linux `drivers/platform/apple/smc_rtkit.c`,
//!            OpenBMC project SMC key tables.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(dead_code)]

use core::ptr::{read_volatile, write_volatile};

// ---------------------------------------------------------------------------
// Register offsets
// ---------------------------------------------------------------------------

const MBOX_WRITE_DATA: usize = 0x00;
const MBOX_WRITE_ARG:  usize = 0x04;
const MBOX_STATUS:     usize = 0x08;
const MBOX_READ_DATA:  usize = 0x0C;
const MBOX_READ_ARG:   usize = 0x10;
const MBOX_READ_ARG2:  usize = 0x14;
const MBOX_INT_MASK:   usize = 0x18;
const MBOX_INT_CLR:    usize = 0x1C;

// ---------------------------------------------------------------------------
// Register bits
// ---------------------------------------------------------------------------

const STATUS_WRITE_FULL:   u32 = 1 << 0;
const STATUS_READ_NOTEMPTY:u32 = 1 << 4;

// ---------------------------------------------------------------------------
// SMC command opcodes
// ---------------------------------------------------------------------------

const SMC_CMD_READ_KEY:      u8 = 0x10;
const SMC_CMD_WRITE_KEY:     u8 = 0x11;
const SMC_CMD_GET_KEY_COUNT: u8 = 0x12;
const SMC_CMD_GET_KEY_INFO:  u8 = 0x13;
const SMC_CMD_GET_KEY_BY_IDX:u8 = 0x14;

// ---------------------------------------------------------------------------
// SMC key data types (4-byte ASCII tags)
// ---------------------------------------------------------------------------

/// 8-bit unsigned integer
pub const SMC_TYPE_UI8:  u32 = u32::from_le_bytes(*b"ui8 ");
/// 16-bit unsigned integer (big-endian)
pub const SMC_TYPE_UI16: u32 = u32::from_le_bytes(*b"ui16");
/// 32-bit unsigned integer (big-endian)
pub const SMC_TYPE_UI32: u32 = u32::from_le_bytes(*b"ui32");
/// 8-bit signed integer
pub const SMC_TYPE_SI8:  u32 = u32::from_le_bytes(*b"si8 ");
/// 16-bit signed integer (big-endian)
pub const SMC_TYPE_SI16: u32 = u32::from_le_bytes(*b"si16");
/// 14.2 fixed-point (multiply by 1/4 to get value; divided by 4 by convention)
pub const SMC_TYPE_FPE2: u32 = u32::from_le_bytes(*b"fpe2");
/// 7.1 fixed-point (multiply by 1/2)
pub const SMC_TYPE_SP1E: u32 = u32::from_le_bytes(*b"sp1e");
/// 8-byte hexadecimal
pub const SMC_TYPE_HEX:  u32 = u32::from_le_bytes(*b"{hex");
/// Flag (boolean byte)
pub const SMC_TYPE_FLAG: u32 = u32::from_le_bytes(*b"flag");

// ---------------------------------------------------------------------------
// Well-known SMC key names
// ---------------------------------------------------------------------------

/// CPU die temperature (°C, fpe2 encoding: raw / 4)
pub const SMC_KEY_TC0E:  u32 = u32::from_le_bytes(*b"TC0E");
/// CPU efficiency cluster temperature
pub const SMC_KEY_TC0F:  u32 = u32::from_le_bytes(*b"TC0F");
/// GPU die temperature
pub const SMC_KEY_TG0P:  u32 = u32::from_le_bytes(*b"TG0P");
/// Ambient temperature (bottom of chassis)
pub const SMC_KEY_TA0P:  u32 = u32::from_le_bytes(*b"TA0P");
/// Number of fans present
pub const SMC_KEY_FNUM:  u32 = u32::from_le_bytes(*b"FNum");
/// Fan 0 actual speed (RPM, ui16)
pub const SMC_KEY_F0AC:  u32 = u32::from_le_bytes(*b"F0Ac");
/// Fan 0 target speed (RPM, ui16)
pub const SMC_KEY_F0TG:  u32 = u32::from_le_bytes(*b"F0Tg");
/// Battery charge remaining (mAh, ui16)
pub const SMC_KEY_BCHG:  u32 = u32::from_le_bytes(*b"BCHG");
/// Battery full charge capacity (mAh)
pub const SMC_KEY_BFCG:  u32 = u32::from_le_bytes(*b"BFCG");
/// AC adapter wattage present (flag)
pub const SMC_KEY_ACIN:  u32 = u32::from_le_bytes(*b"ACIN");
/// System sleep request (flag)
pub const SMC_KEY_PSOK:  u32 = u32::from_le_bytes(*b"PSOK");

// ---------------------------------------------------------------------------
// SMC result codes
// ---------------------------------------------------------------------------

#[derive(Copy, Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum SmcResult {
    Ok          = 0x00,
    KeyNotFound = 0x84,
    NotReadable = 0x85,
    NotWritable = 0x86,
    KeyTypeMismatch = 0x8D,
    Busy        = 0xFF,
}

impl SmcResult {
    fn from_byte(b: u8) -> Self {
        match b {
            0x00 => SmcResult::Ok,
            0x84 => SmcResult::KeyNotFound,
            0x85 => SmcResult::NotReadable,
            0x86 => SmcResult::NotWritable,
            0x8D => SmcResult::KeyTypeMismatch,
            _    => SmcResult::Busy,
        }
    }

    /// Map to a negative errno for C callers.
    pub fn to_errno(self) -> i32 {
        match self {
            SmcResult::Ok              =>  0,
            SmcResult::KeyNotFound     => -2,   // ENOENT
            SmcResult::NotReadable     => -13,  // EACCES
            SmcResult::NotWritable     => -13,  // EACCES
            SmcResult::KeyTypeMismatch => -22,  // EINVAL
            SmcResult::Busy            => -16,  // EBUSY
        }
    }
}

// ---------------------------------------------------------------------------
// Key info descriptor
// ---------------------------------------------------------------------------

#[repr(C)]
pub struct SmcKeyInfo {
    /// Size of the key's data (bytes)
    pub size:  u8,
    /// Data type tag (4-byte ASCII, little-endian u32)
    pub dtype: u32,
    /// Attribute flags (e.g., readable, writeable, notify)
    pub attr:  u8,
}

// ---------------------------------------------------------------------------
// AppleSmc — driver state
// ---------------------------------------------------------------------------

pub struct AppleSmc {
    base: usize,
    seq:  u8,  // Rolling sequence number (0–255)
}

impl AppleSmc {
    // ---- MMIO helpers ----

    fn r32(&self, off: usize) -> u32 {
        unsafe { read_volatile((self.base + off) as *const u32) }
    }

    fn w32(&self, off: usize, v: u32) {
        unsafe { write_volatile((self.base + off) as *mut u32, v) }
    }

    // ---- Low-level mailbox ----

    /// Wait until the write FIFO is not full (poll with timeout).
    fn wait_write_ready(&self) -> bool {
        for _ in 0..100_000u32 {
            if self.r32(MBOX_STATUS) & STATUS_WRITE_FULL == 0 {
                return true;
            }
        }
        false
    }

    /// Wait until the read FIFO has a response (poll with timeout).
    fn wait_read_ready(&self) -> bool {
        for _ in 0..200_000u32 {
            if self.r32(MBOX_STATUS) & STATUS_READ_NOTEMPTY != 0 {
                return true;
            }
        }
        false
    }

    /// Send a command and receive the response.
    ///
    /// `cmd`     — SMC opcode byte.
    /// `key`     — 4-byte key identifier (big-endian u32).
    /// `data_in` — bytes to write into the mailbox (for CMD_WRITE_KEY).
    /// `data_out`— buffer to receive response bytes.
    ///
    /// Returns (SmcResult, bytes_received).
    fn transact(
        &mut self,
        cmd:      u8,
        key:      u32,
        data_in:  &[u8],
        data_out: &mut [u8],
    ) -> (SmcResult, usize) {
        if !self.wait_write_ready() {
            return (SmcResult::Busy, 0);
        }

        let seq = self.seq;
        self.seq = self.seq.wrapping_add(1);

        let key_hi = (key >> 16) & 0xFFFF;
        let key_lo = key & 0xFFFF;
        let len = data_in.len().min(8) as u8;

        // Pack up to 4 bytes of data_in into arg words
        let mut arg0 = (key_lo as u32) << 16;
        if !data_in.is_empty() {
            for i in 0..data_in.len().min(4) {
                arg0 |= (data_in[i] as u32) << (i * 8);
            }
        }
        let mut arg1 = 0u32;
        if data_in.len() > 4 {
            for i in 4..data_in.len().min(8) {
                arg1 |= (data_in[i] as u32) << ((i - 4) * 8);
            }
        }

        // Write command word: [cmd | key_hi | seq]
        let cmd_word = ((cmd as u32) << 24) | (key_hi << 8) | (seq as u32);
        self.w32(MBOX_WRITE_DATA, cmd_word);
        // Write argument: [key_lo | data[0..4]]
        let arg_word = ((len as u32) << 28) | arg0;
        self.w32(MBOX_WRITE_ARG, arg_word);

        if data_in.len() > 4 {
            self.w32(MBOX_WRITE_ARG, arg1);
        }

        // Wait for response
        if !self.wait_read_ready() {
            return (SmcResult::Busy, 0);
        }

        let resp_data = self.r32(MBOX_READ_DATA);
        let resp_arg  = self.r32(MBOX_READ_ARG);
        let resp_arg2 = self.r32(MBOX_READ_ARG2);

        // Result code is in the low byte of resp_data
        let result_code = (resp_data & 0xFF) as u8;
        let result = SmcResult::from_byte(result_code);

        // Extract response data bytes from resp_arg / resp_arg2
        let mut n = 0usize;
        for i in 0..data_out.len().min(4) {
            data_out[n] = ((resp_arg >> (i * 8)) & 0xFF) as u8;
            n += 1;
        }
        for i in 0..data_out.len().saturating_sub(4).min(4) {
            data_out[n] = ((resp_arg2 >> (i * 8)) & 0xFF) as u8;
            n += 1;
        }

        (result, n)
    }

    // ---- Public API ----

    /// Read a SMC key into `buf`.
    /// Returns (SmcResult, bytes_read).
    pub fn read_key(&mut self, key: u32, buf: &mut [u8]) -> (SmcResult, usize) {
        self.transact(SMC_CMD_READ_KEY, key, &[], buf)
    }

    /// Write `data` to a SMC key.
    pub fn write_key(&mut self, key: u32, data: &[u8]) -> SmcResult {
        let mut dummy = [0u8; 8];
        let (r, _) = self.transact(SMC_CMD_WRITE_KEY, key, data, &mut dummy);
        r
    }

    /// Query total number of SMC keys.
    pub fn key_count(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        let (r, n) = self.transact(SMC_CMD_GET_KEY_COUNT, 0, &[], &mut buf);
        if r != SmcResult::Ok || n < 4 { return 0; }
        u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]])
    }

    /// Get key info (size, type tag, attributes) for `key`.
    pub fn key_info(&mut self, key: u32, info: &mut SmcKeyInfo) -> SmcResult {
        let mut buf = [0u8; 6];
        let (r, _) = self.transact(SMC_CMD_GET_KEY_INFO, key, &[], &mut buf);
        if r == SmcResult::Ok {
            info.size  = buf[0];
            info.dtype = u32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]]);
            info.attr  = buf[5];
        }
        r
    }

    // ---- Convenience helpers ----

    /// Read a temperature key and return millidegrees Celsius.
    /// Assumes fpe2 encoding (raw u16 big-endian / 4 = °C).
    pub fn read_temp_mc(&mut self, key: u32) -> i32 {
        let mut buf = [0u8; 2];
        let (r, n) = self.read_key(key, &mut buf);
        if r != SmcResult::Ok || n < 2 { return i32::MIN; }
        let raw = u16::from_be_bytes([buf[0], buf[1]]) as u32;
        // fpe2: 14 integer bits + 2 fractional bits → divide by 4, then × 1000
        ((raw * 1000) / 4) as i32
    }

    /// Read a fan speed key (ui16 big-endian) and return RPM.
    pub fn read_fan_rpm(&mut self, key: u32) -> u32 {
        let mut buf = [0u8; 2];
        let (r, n) = self.read_key(key, &mut buf);
        if r != SmcResult::Ok || n < 2 { return 0; }
        u16::from_be_bytes([buf[0], buf[1]]) as u32
    }

    /// Read a boolean flag key.
    pub fn read_flag(&mut self, key: u32) -> bool {
        let mut buf = [0u8; 1];
        let (r, n) = self.read_key(key, &mut buf);
        r == SmcResult::Ok && n > 0 && buf[0] != 0
    }
}

// ---------------------------------------------------------------------------
// Static singleton
// ---------------------------------------------------------------------------

static mut G_SMC: AppleSmc = AppleSmc { base: 0, seq: 0 };

// ---------------------------------------------------------------------------
// C FFI
// ---------------------------------------------------------------------------

/// Initialize the Apple SMC driver.
///
/// `base` — MMIO base address of the SMC mailbox registers.
///
/// Returns a non-null handle on success, NULL on failure.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_smc_init(base: u64) -> *mut AppleSmc {
    if base == 0 { return core::ptr::null_mut(); }
    let smc = unsafe { &mut *(&raw mut G_SMC) };
    smc.base = base as usize;
    smc.seq  = 0;
    smc as *mut AppleSmc
}

/// Release resources held by the SMC driver.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_smc_free(smc: *mut AppleSmc) {
    if smc.is_null() { return; }
    unsafe { (*smc).base = 0; }
}

/// Read raw bytes from SMC key `key` into `buf` (up to `len` bytes).
/// Returns number of bytes read on success, negative errno on failure.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_smc_read_key(
    smc: *mut AppleSmc,
    key: u32,
    buf: *mut u8,
    len: usize,
) -> i32 {
    if smc.is_null() || buf.is_null() || len == 0 { return -22; }
    let slice = unsafe { core::slice::from_raw_parts_mut(buf, len.min(8)) };
    let (r, n) = unsafe { (*smc).read_key(key, slice) };
    if r != SmcResult::Ok { return r.to_errno(); }
    n as i32
}

/// Write `len` bytes from `data` to SMC key `key`.
/// Returns 0 on success, negative errno on failure.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_smc_write_key(
    smc:  *mut AppleSmc,
    key:  u32,
    data: *const u8,
    len:  usize,
) -> i32 {
    if smc.is_null() || data.is_null() || len == 0 { return -22; }
    let slice = unsafe { core::slice::from_raw_parts(data, len.min(8)) };
    unsafe { (*smc).write_key(key, slice).to_errno() }
}

/// Return the CPU die temperature in millidegrees Celsius.
/// Returns INT_MIN on error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_smc_cpu_temp_mc(smc: *mut AppleSmc) -> i32 {
    if smc.is_null() { return i32::MIN; }
    unsafe { (*smc).read_temp_mc(SMC_KEY_TC0E) }
}

/// Return fan 0 speed in RPM, or 0 on error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_smc_fan0_rpm(smc: *mut AppleSmc) -> u32 {
    if smc.is_null() { return 0; }
    unsafe { (*smc).read_fan_rpm(SMC_KEY_F0AC) }
}

/// Return 1 if AC adapter is present, 0 otherwise.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_smc_ac_present(smc: *mut AppleSmc) -> i32 {
    if smc.is_null() { return 0; }
    unsafe { (*smc).read_flag(SMC_KEY_ACIN) as i32 }
}

/// Return total number of SMC keys reported by the firmware.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_smc_key_count(smc: *mut AppleSmc) -> u32 {
    if smc.is_null() { return 0; }
    unsafe { (*smc).key_count() }
}

/// Fill `info` with key metadata for `key`.
/// Returns 0 on success, negative errno on failure.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_smc_key_info(
    smc:  *mut AppleSmc,
    key:  u32,
    info: *mut SmcKeyInfo,
) -> i32 {
    if smc.is_null() || info.is_null() { return -22; }
    let info_ref = unsafe { &mut *info };
    unsafe { (*smc).key_info(key, info_ref).to_errno() }
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
