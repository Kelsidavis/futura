// SPDX-License-Identifier: MPL-2.0
//
// x86-64 Machine Check Exception (MCE) Handler for Futura OS
//
// Implements the AMD64 Machine Check Architecture (MCA) as described in
// AMD64 Architecture Programmer's Manual Volume 2, Chapter 9 (Machine
// Check Architecture). Targets AMD Ryzen AM4 (Zen/Zen2/Zen3) and AM5
// (Zen4/Zen5) platforms.
//
// Architecture:
//   - Machine Check Architecture uses MSRs for error reporting and control
//   - Global MSRs: MCG_CAP (0x179), MCG_STATUS (0x17A), MCG_CTL (0x17B)
//   - Per-bank MSRs at base 0x400 + 4*N: MCi_CTL, MCi_STATUS, MCi_ADDR,
//     MCi_MISC for each of N error-reporting banks
//   - Error classification: corrected (CE) vs uncorrected (UC), with
//     processor context corrupt (PCC) indicating fatal conditions
//   - Polling mode: read MCi_STATUS.VAL to detect logged errors
//   - AMD Scalable MCA (SMCA) on Zen+ uses extended bank MSRs at
//     0xC000_2000 + 0x10*N for finer-grained error classification
//
// MCG_CAP (MSR 0x179):
//   Bits [7:0]   = Count of MCA error-reporting banks
//   Bit  8       = MCG_CTL_P (MCG_CTL register present)
//   Bit  9       = MCG_EXT_P (extended MCG registers present)
//   Bit  24      = MCG_SER_P (software error recovery supported)
//
// MCG_STATUS (MSR 0x17A):
//   Bit  0       = RIPV (restart IP valid)
//   Bit  1       = EIPV (error IP valid)
//   Bit  2       = MCIP (machine check in progress)
//
// MCi_STATUS (MSR 0x401 + 4*N):
//   Bit  63      = VAL   (valid entry)
//   Bit  62      = OVER  (overflow -- previous error lost)
//   Bit  61      = UC    (uncorrected error)
//   Bit  60      = EN    (error reporting enabled)
//   Bit  59      = MISCV (MCi_MISC register valid)
//   Bit  58      = ADDRV (MCi_ADDR register valid)
//   Bit  57      = PCC   (processor context corrupt)
//   Bits [31:16] = Model-specific error code
//   Bits [15:0]  = MCA error code
//
// AMD MCA error code ranges:
//   0x0001-0x000F  TLB errors
//   0x0010-0x001F  Memory controller errors
//   0x0100-0x01FF  Bus / interconnect errors
//   0x0800-0x080F  L2 cache errors

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(unexpected_cfgs)]

use core::cell::UnsafeCell;

use common::log;

unsafe extern "C" {
    fn fut_printf(fmt: *const u8, ...);
}

// ── StaticCell for safe global mutable state ──

/// Wrapper to allow `UnsafeCell` in a `static` (requires `Sync`).
/// Safety: all access is single-threaded or externally synchronised by the caller.
struct StaticCell<T>(UnsafeCell<T>);
unsafe impl<T> Sync for StaticCell<T> {}
impl<T> StaticCell<T> {
    const fn new(v: T) -> Self { Self(UnsafeCell::new(v)) }
    fn get(&self) -> *mut T { self.0.get() }
}

// ── MSR addresses ──

/// MCG_CAP: bits[7:0] = bank count, bit 8 = MCG_CTL_P.
const MSR_MCG_CAP: u32 = 0x179;
/// MCG_STATUS: bit 0 = RIPV, bit 1 = EIPV, bit 2 = MCIP.
const MSR_MCG_STATUS: u32 = 0x17A;
/// MCG_CTL: global MCA enable (present when MCG_CTL_P = 1).
const MSR_MCG_CTL: u32 = 0x17B;

/// Per-bank MSR base addresses (bank N at base + 4*N).
const MSR_MCI_CTL_BASE: u32 = 0x400;
const MSR_MCI_STATUS_BASE: u32 = 0x401;
const MSR_MCI_ADDR_BASE: u32 = 0x402;
const MSR_MCI_MISC_BASE: u32 = 0x403;

// ── MCi_STATUS bit positions ──

const STATUS_VAL: u64 = 1 << 63;
const STATUS_OVER: u64 = 1 << 62;
const STATUS_UC: u64 = 1 << 61;
const STATUS_EN: u64 = 1 << 60;
const STATUS_MISCV: u64 = 1 << 59;
const STATUS_ADDRV: u64 = 1 << 58;
const STATUS_PCC: u64 = 1 << 57;

/// Maximum number of MCA banks we support.
const MAX_BANKS: usize = 32;

// ── CPUID constants ──

/// Standard CPUID leaf 1: EDX bit 7 = MCA support, bit 14 = MCA with MCG_CAP.
const CPUID_LEAF_FEATURES: u32 = 0x01;
/// EDX bit 7: Machine Check Architecture supported.
const CPUID_MCE_BIT: u32 = 1 << 7;
/// EDX bit 14: Machine Check Architecture (MCA) supported.
const CPUID_MCA_BIT: u32 = 1 << 14;

// ── Inline assembly helpers ──

/// Read a 64-bit Model-Specific Register.
#[inline]
fn rdmsr(msr: u32) -> u64 {
    let lo: u32;
    let hi: u32;
    unsafe {
        core::arch::asm!(
            "rdmsr",
            in("ecx") msr,
            out("eax") lo,
            out("edx") hi,
            options(nomem, nostack, preserves_flags),
        );
    }
    ((hi as u64) << 32) | (lo as u64)
}

/// Write a 64-bit Model-Specific Register.
#[inline]
fn wrmsr(msr: u32, val: u64) {
    let lo = val as u32;
    let hi = (val >> 32) as u32;
    unsafe {
        core::arch::asm!(
            "wrmsr",
            in("ecx") msr,
            in("eax") lo,
            in("edx") hi,
            options(nomem, nostack, preserves_flags),
        );
    }
}

/// Execute CPUID instruction and return (eax, ebx, ecx, edx).
#[inline]
fn cpuid(leaf: u32) -> (u32, u32, u32, u32) {
    let eax: u32;
    let ebx: u32;
    let ecx: u32;
    let edx: u32;
    unsafe {
        core::arch::asm!(
            "push rbx",
            "cpuid",
            "mov {ebx_out:e}, ebx",
            "pop rbx",
            inout("eax") leaf => eax,
            ebx_out = out(reg) ebx,
            inout("ecx") 0u32 => ecx,
            lateout("edx") edx,
            options(nomem, preserves_flags),
        );
    }
    (eax, ebx, ecx, edx)
}

// ── MCE record ──

/// A single Machine Check error record.
#[repr(C)]
pub struct MceRecord {
    /// MCA bank number that reported this error.
    pub bank: u32,
    /// Raw MCi_STATUS value.
    pub status: u64,
    /// Error address from MCi_ADDR (valid when ADDRV is set).
    pub addr: u64,
    /// Miscellaneous info from MCi_MISC (valid when MISCV is set).
    pub misc: u64,
    /// Whether this is an uncorrected error.
    pub uncorrected: bool,
    /// Whether a previous error was lost (overflow).
    pub overflow: bool,
    /// Whether processor context is corrupt (fatal).
    pub pcc: bool,
    /// MCA error code (bits [15:0] of MCi_STATUS).
    pub error_code: u16,
    /// Model-specific error code (bits [31:16] of MCi_STATUS).
    pub model_code: u16,
}

// ── Driver state ──

struct MceState {
    /// Whether the driver has been initialised.
    initialised: bool,
    /// Number of MCA banks reported by MCG_CAP.
    bank_count: u32,
    /// Whether MCG_CTL is present (MCG_CTL_P bit in MCG_CAP).
    mcg_ctl_present: bool,
    /// Running count of corrected errors observed.
    corrected_count: u64,
    /// Running count of uncorrected errors observed.
    uncorrected_count: u64,
}

static STATE: StaticCell<MceState> = StaticCell::new(MceState {
    initialised: false,
    bank_count: 0,
    mcg_ctl_present: false,
    corrected_count: 0,
    uncorrected_count: 0,
});

// ── Internal helpers ──

/// Check CPUID for MCA support.
fn detect_mca_support() -> bool {
    let (_eax, _ebx, _ecx, edx) = cpuid(CPUID_LEAF_FEATURES);
    (edx & CPUID_MCE_BIT != 0) && (edx & CPUID_MCA_BIT != 0)
}

/// Read MCG_CAP and return (bank_count, mcg_ctl_present).
fn read_mcg_cap() -> (u32, bool) {
    let cap = rdmsr(MSR_MCG_CAP);
    let count = (cap & 0xFF) as u32;
    let ctl_p = (cap >> 8) & 1 != 0;
    (count, ctl_p)
}

/// Enable error reporting for a single MCA bank by writing all-ones
/// to MCi_CTL.
fn enable_bank(bank: u32) {
    let msr = MSR_MCI_CTL_BASE + 4 * bank;
    wrmsr(msr, !0u64);
}

/// Read MCi_STATUS for a given bank.
fn read_bank_status(bank: u32) -> u64 {
    rdmsr(MSR_MCI_STATUS_BASE + 4 * bank)
}

/// Read MCi_ADDR for a given bank.
fn read_bank_addr(bank: u32) -> u64 {
    rdmsr(MSR_MCI_ADDR_BASE + 4 * bank)
}

/// Read MCi_MISC for a given bank.
fn read_bank_misc(bank: u32) -> u64 {
    rdmsr(MSR_MCI_MISC_BASE + 4 * bank)
}

/// Clear MCi_STATUS for a given bank by writing zero.
fn clear_bank_status(bank: u32) {
    wrmsr(MSR_MCI_STATUS_BASE + 4 * bank, 0);
}

/// Parse a raw MCi_STATUS value into an MceRecord.
fn parse_status(bank: u32, status: u64) -> MceRecord {
    let uncorrected = status & STATUS_UC != 0;
    let overflow = status & STATUS_OVER != 0;
    let pcc = status & STATUS_PCC != 0;
    let error_code = (status & 0xFFFF) as u16;
    let model_code = ((status >> 16) & 0xFFFF) as u16;

    let addr = if status & STATUS_ADDRV != 0 {
        read_bank_addr(bank)
    } else {
        0
    };

    let misc = if status & STATUS_MISCV != 0 {
        read_bank_misc(bank)
    } else {
        0
    };

    MceRecord {
        bank,
        status,
        addr,
        misc,
        uncorrected,
        overflow,
        pcc,
        error_code,
        model_code,
    }
}

/// Copy a byte string into a destination buffer, ensuring NUL termination.
/// Returns the number of bytes written (excluding the NUL terminator).
fn copy_str_to_buf(src: &[u8], dst: *mut u8, max_len: u32) -> usize {
    if dst.is_null() || max_len == 0 {
        return 0;
    }
    let cap = (max_len as usize).saturating_sub(1);
    let len = src.len().min(cap);
    for i in 0..len {
        unsafe { *dst.add(i) = src[i]; }
    }
    unsafe { *dst.add(len) = 0; }
    len
}

/// Classify an MCA error code into a human-readable byte string.
fn error_code_string(code: u16) -> &'static [u8] {
    match code {
        0x0000 => b"no error",
        0x0001..=0x000F => b"TLB error",
        0x0010..=0x001F => b"memory controller error",
        0x0020..=0x003F => b"memory controller error (extended)",
        0x0100..=0x01FF => b"bus/interconnect error",
        0x0400..=0x040F => b"internal timer error",
        0x0500..=0x050F => b"internal unclassified error",
        0x0800..=0x080F => b"L2 cache error",
        _ => b"unknown MCA error",
    }
}

// ── FFI exports ──

/// Initialise the x86 Machine Check Exception handler.
///
/// Detects MCA support via CPUID, reads MCG_CAP for the bank count,
/// enables MCG_CTL (if present), and enables error reporting on all
/// MCA banks.
///
/// Returns 0 on success, -1 if MCA is not supported.
#[unsafe(no_mangle)]
pub extern "C" fn x86_mce_init() -> i32 {
    log("x86_mce: initialising Machine Check Architecture driver");

    if !detect_mca_support() {
        log("x86_mce: MCA not supported by this CPU");
        return -1;
    }

    let (bank_count, mcg_ctl_present) = read_mcg_cap();

    if bank_count == 0 {
        log("x86_mce: MCG_CAP reports 0 banks");
        return -1;
    }

    // Cap bank count to our internal maximum.
    let capped = if bank_count > MAX_BANKS as u32 {
        MAX_BANKS as u32
    } else {
        bank_count
    };

    // Enable global MCA if MCG_CTL is present.
    if mcg_ctl_present {
        wrmsr(MSR_MCG_CTL, !0u64);
    }

    // Enable error reporting for each bank.
    for i in 0..capped {
        enable_bank(i);
    }

    // Store driver state.
    let st = STATE.get();
    unsafe {
        (*st).initialised = true;
        (*st).bank_count = capped;
        (*st).mcg_ctl_present = mcg_ctl_present;
        (*st).corrected_count = 0;
        (*st).uncorrected_count = 0;
    }

    unsafe {
        fut_printf(
            b"x86_mce: %u MCA banks detected, MCG_CTL %s\n\0".as_ptr(),
            capped,
            if mcg_ctl_present {
                b"present\0".as_ptr()
            } else {
                b"absent\0".as_ptr()
            },
        );
    }

    log("x86_mce: initialisation complete");
    0
}

/// Return the number of MCA banks detected at init time.
#[unsafe(no_mangle)]
pub extern "C" fn x86_mce_bank_count() -> u32 {
    let st = STATE.get();
    unsafe { (*st).bank_count }
}

/// Poll all MCA banks for errors and fill the provided record array.
///
/// Up to `max` records are written to `records`. Returns the number of
/// errors found. Each valid error is logged and its bank status is
/// cleared after reading.
#[unsafe(no_mangle)]
pub extern "C" fn x86_mce_poll(records: *mut MceRecord, max: u32) -> u32 {
    let st = STATE.get();
    let bank_count = unsafe { (*st).bank_count };

    if !unsafe { (*st).initialised } {
        return 0;
    }

    let mut found: u32 = 0;

    for bank in 0..bank_count {
        if found >= max {
            break;
        }

        let status = read_bank_status(bank);
        if status & STATUS_VAL == 0 {
            continue;
        }

        let record = parse_status(bank, status);

        // Update error counters.
        unsafe {
            if record.uncorrected {
                (*st).uncorrected_count += 1;
            } else {
                (*st).corrected_count += 1;
            }
        }

        // Log the error.
        let severity = if record.pcc {
            b"FATAL\0".as_ptr()
        } else if record.uncorrected {
            b"UNCORRECTED\0".as_ptr()
        } else {
            b"CORRECTED\0".as_ptr()
        };

        unsafe {
            fut_printf(
                b"x86_mce: bank %u: %s error code=0x%04x model=0x%04x addr=0x%llx\n\0"
                    .as_ptr(),
                bank,
                severity,
                record.error_code as u32,
                record.model_code as u32,
                record.addr,
            );
        }

        // Write the record to the output array.
        if !records.is_null() {
            unsafe {
                *records.add(found as usize) = record;
            }
        }

        // Clear the bank status after reading.
        clear_bank_status(bank);

        found += 1;
    }

    found
}

/// Clear the error status for a single MCA bank.
///
/// Returns 0 on success, -1 if the bank index is out of range.
#[unsafe(no_mangle)]
pub extern "C" fn x86_mce_clear_bank(bank: u32) -> i32 {
    let st = STATE.get();
    let bank_count = unsafe { (*st).bank_count };

    if bank >= bank_count {
        return -1;
    }

    clear_bank_status(bank);
    0
}

/// Clear the error status for all MCA banks.
///
/// Returns 0 on success, -1 if the driver is not initialised.
#[unsafe(no_mangle)]
pub extern "C" fn x86_mce_clear_all() -> i32 {
    let st = STATE.get();

    if !unsafe { (*st).initialised } {
        return -1;
    }

    let bank_count = unsafe { (*st).bank_count };
    for bank in 0..bank_count {
        clear_bank_status(bank);
    }

    0
}

/// Return the total count of corrected (CE) errors observed since init.
#[unsafe(no_mangle)]
pub extern "C" fn x86_mce_corrected_count() -> u64 {
    let st = STATE.get();
    unsafe { (*st).corrected_count }
}

/// Return the total count of uncorrected (UC) errors observed since init.
#[unsafe(no_mangle)]
pub extern "C" fn x86_mce_uncorrected_count() -> u64 {
    let st = STATE.get();
    unsafe { (*st).uncorrected_count }
}

/// Write a human-readable description of an MCA error code into the
/// provided buffer.
///
/// The output is a NUL-terminated ASCII string. Returns 0 on success,
/// -1 if the buffer pointer is null or max_len is 0.
#[unsafe(no_mangle)]
pub extern "C" fn x86_mce_error_string(code: u16, buf: *mut u8, max_len: u32) -> i32 {
    if buf.is_null() || max_len == 0 {
        return -1;
    }

    let desc = error_code_string(code);
    copy_str_to_buf(desc, buf, max_len);
    0
}
