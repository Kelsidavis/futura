// SPDX-License-Identifier: MPL-2.0
//
// AMD P-State / CPPC (Collaborative Processor Performance Control) Driver
// for Futura OS
//
// Targets AMD Ryzen AM4 (Zen/Zen2/Zen3) and AM5 (Zen4/Zen5) platforms.
//
// Architecture:
//   - CPPC v2 via MSRs (not MMIO) for AMD processors
//   - CPUID function 0x80000008 ECX bit 25 for CPPC capability detection
//   - P-State definitions via MSRs 0xC001_0064..0xC001_006B
//   - CPPC performance requests via MSR 0xC001_0294
//   - Energy Performance Preference (EPP) for power/performance bias
//
// P-State frequency calculation:
//   Frequency (MHz) = 200 * CpuFid / CpuDid
//
// EPP values:
//   0 = maximum performance, 255 = maximum power saving

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(unexpected_cfgs)]

use core::cell::UnsafeCell;

use common::log;

unsafe extern "C" {
    fn fut_printf(fmt: *const u8, ...);
}

// -- Static state wrapper --

/// Wrapper to allow `UnsafeCell` in a `static` (requires `Sync`).
/// Safety: all access is single-threaded or externally synchronised by the caller.
struct StaticCell<T>(UnsafeCell<T>);
unsafe impl<T> Sync for StaticCell<T> {}
impl<T> StaticCell<T> {
    const fn new(v: T) -> Self { Self(UnsafeCell::new(v)) }
    fn get(&self) -> *mut T { self.0.get() }
}

// -- MSR addresses --

/// P-State Current Limit: MaxPstate[6:4], CurPstateLimit[2:0].
const MSR_PSTATE_CUR_LIM: u32 = 0xC001_0061;
/// P-State Control: PstateCmd[2:0].
const MSR_PSTATE_CTL: u32 = 0xC001_0062;
/// P-State Status: CurPstate[2:0].
const MSR_PSTATE_STAT: u32 = 0xC001_0063;
/// P-State Definition base (PStateDef[0] through PStateDef[7]).
const MSR_PSTATE_DEF_BASE: u32 = 0xC001_0064;
/// CPPC Capabilities 1: HighestPerf[7:0], NominalPerf[15:8],
/// LowestNonlinearPerf[23:16], LowestPerf[31:24].
const MSR_CPPC_CAPS1: u32 = 0xC001_0293;
/// CPPC Request: DesiredPerf[7:0], MinPerf[15:8], MaxPerf[23:16], EPP[31:24].
const MSR_CPPC_REQ: u32 = 0xC001_0294;
/// CPPC Status: current performance level.
const MSR_CPPC_STATUS: u32 = 0xC001_0299;

// -- CPUID constants --

/// Extended CPUID function for address sizes and feature identifiers.
const CPUID_EXT_FEATURES: u32 = 0x8000_0008;
/// Bit 25 of ECX from CPUID 0x80000008 indicates CPPC capability.
const CPPC_CAP_BIT: u32 = 1 << 25;

// -- P-State Definition field extraction --

/// Maximum number of hardware P-states (MSRs 0xC001_0064..0xC001_006B).
const MAX_PSTATES: usize = 8;

// -- MSR access via inline assembly --

/// Read a 64-bit Model-Specific Register.
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

// -- P-State Definition parsing --

/// A decoded P-State definition from MSR PStateDef[n].
#[derive(Copy, Clone)]
struct PStateDef {
    /// Whether this P-state is enabled (bit 63 of the MSR).
    enabled: bool,
    /// CPU Frequency ID (bits [7:0]).
    fid: u8,
    /// CPU Divisor ID (bits [13:8]).
    did: u8,
    /// CPU Voltage ID (bits [21:14]).
    vid: u8,
    /// Calculated frequency in MHz: 200 * CpuFid / CpuDid.
    freq_mhz: u64,
}

impl PStateDef {
    /// Decode a P-State definition from the raw MSR value.
    fn from_msr(val: u64) -> Self {
        let enabled = (val >> 63) & 1 != 0;
        let fid = (val & 0xFF) as u8;
        let did = ((val >> 8) & 0x3F) as u8;
        let vid = ((val >> 14) & 0xFF) as u8;
        let freq_mhz = if enabled && did != 0 {
            200u64 * (fid as u64) / (did as u64)
        } else {
            0
        };
        PStateDef { enabled, fid, did, vid, freq_mhz }
    }
}

// -- Driver state --

struct AmdPState {
    /// Whether CPPC (Collaborative Processor Performance Control) is supported.
    cppc_supported: bool,
    /// Number of valid (enabled) P-states discovered.
    num_pstates: u32,
    /// Decoded P-state definitions (up to 8).
    pstates: [PStateDef; MAX_PSTATES],
    /// Hardware P-state limit: maximum P-state index allowed.
    max_pstate_limit: u8,
    /// Hardware P-state limit: current P-state limit.
    cur_pstate_limit: u8,
}

static STATE: StaticCell<Option<AmdPState>> = StaticCell::new(None);

// -- Capability detection --

/// Check whether the CPU supports AMD CPPC via CPUID.
fn detect_cppc_support() -> bool {
    let (_eax, _ebx, ecx, _edx) = cpuid(CPUID_EXT_FEATURES);
    ecx & CPPC_CAP_BIT != 0
}

/// Read P-State Current Limit MSR and return (max_pstate, cur_pstate_limit).
fn read_pstate_limits() -> (u8, u8) {
    let val = rdmsr(MSR_PSTATE_CUR_LIM);
    let cur_limit = (val & 0x07) as u8;        // bits [2:0]
    let max_pstate = ((val >> 4) & 0x07) as u8; // bits [6:4]
    (max_pstate, cur_limit)
}

/// Read the current P-state index from MSR_PSTATE_STAT.
fn read_current_pstate() -> u8 {
    let val = rdmsr(MSR_PSTATE_STAT);
    (val & 0x07) as u8
}

/// Read a P-State definition MSR by index (0..7).
fn read_pstate_def(idx: u32) -> PStateDef {
    let val = rdmsr(MSR_PSTATE_DEF_BASE + idx);
    PStateDef::from_msr(val)
}

// -- FFI exports --

/// Initialise the AMD P-State / CPPC driver.
///
/// Detects CPPC capability via CPUID, enumerates available P-states from
/// hardware MSRs, and reads CPPC capabilities if supported.
///
/// Returns 0 on success, negative error on failure.
#[unsafe(no_mangle)]
pub extern "C" fn amd_pstate_init() -> i32 {
    log("amd_pstate: initialising AMD P-State / CPPC driver");

    // Detect CPPC support via CPUID.
    let cppc_supported = detect_cppc_support();
    if cppc_supported {
        log("amd_pstate: CPPC v2 supported (CPUID 0x80000008 ECX bit 25)");
    } else {
        log("amd_pstate: CPPC not supported, using legacy P-state control only");
    }

    // Read P-state limits.
    let (max_pstate, cur_pstate_limit) = read_pstate_limits();
    unsafe {
        fut_printf(
            b"amd_pstate: P-state limits: max=%u cur_limit=%u\n\0".as_ptr(),
            max_pstate as u32,
            cur_pstate_limit as u32,
        );
    }

    // Enumerate P-state definitions.
    let mut pstates = [PStateDef { enabled: false, fid: 0, did: 0, vid: 0, freq_mhz: 0 }; MAX_PSTATES];
    let mut num_enabled: u32 = 0;

    for i in 0..MAX_PSTATES as u32 {
        let def = read_pstate_def(i);
        pstates[i as usize] = def;
        if def.enabled {
            num_enabled += 1;
            unsafe {
                fut_printf(
                    b"amd_pstate: P%u: FID=%u DID=%u VID=%u freq=%lu MHz\n\0".as_ptr(),
                    i,
                    def.fid as u32,
                    def.did as u32,
                    def.vid as u32,
                    def.freq_mhz,
                );
            }
        }
    }

    if num_enabled == 0 {
        log("amd_pstate: no enabled P-states found");
        return -1;
    }

    unsafe {
        fut_printf(
            b"amd_pstate: found %u enabled P-state(s)\n\0".as_ptr(),
            num_enabled,
        );
    }

    // Read current P-state.
    let cur_pstate = read_current_pstate();
    let cur_freq = pstates[cur_pstate as usize].freq_mhz;
    unsafe {
        fut_printf(
            b"amd_pstate: current P-state: P%u (%lu MHz)\n\0".as_ptr(),
            cur_pstate as u32,
            cur_freq,
        );
    }

    // If CPPC is supported, read and display capabilities.
    if cppc_supported {
        let caps = rdmsr(MSR_CPPC_CAPS1);
        let highest = (caps & 0xFF) as u8;
        let nominal = ((caps >> 8) & 0xFF) as u8;
        let lowest_nonlinear = ((caps >> 16) & 0xFF) as u8;
        let lowest = ((caps >> 24) & 0xFF) as u8;

        unsafe {
            fut_printf(
                b"amd_pstate: CPPC caps: highest=%u nominal=%u lowest_nonlinear=%u lowest=%u\n\0"
                    .as_ptr(),
                highest as u32,
                nominal as u32,
                lowest_nonlinear as u32,
                lowest as u32,
            );
        }

        // Read current CPPC status.
        let status = rdmsr(MSR_CPPC_STATUS);
        unsafe {
            fut_printf(
                b"amd_pstate: CPPC status: current_perf=%u\n\0".as_ptr(),
                (status & 0xFF) as u32,
            );
        }
    }

    // Store driver state.
    let state = AmdPState {
        cppc_supported,
        num_pstates: num_enabled,
        pstates,
        max_pstate_limit: max_pstate,
        cur_pstate_limit,
    };

    unsafe {
        (*STATE.get()) = Some(state);
    }

    log("amd_pstate: driver initialised successfully");
    0
}

/// Get the current CPU frequency in MHz.
///
/// Reads the current P-state from hardware and returns the corresponding
/// frequency calculated from the P-state definition MSR.
///
/// Returns 0 if the driver is not initialised or the P-state is invalid.
#[unsafe(no_mangle)]
pub extern "C" fn amd_pstate_get_frequency() -> u64 {
    let state = match unsafe { (*STATE.get()).as_ref() } {
        Some(s) => s,
        None => return 0,
    };

    let cur = read_current_pstate();
    if (cur as usize) < MAX_PSTATES && state.pstates[cur as usize].enabled {
        state.pstates[cur as usize].freq_mhz
    } else {
        // Fall back: read the P-state definition MSR directly.
        let def = read_pstate_def(cur as u32);
        def.freq_mhz
    }
}

/// Set the CPU to a specific P-state by index.
///
/// `idx` - P-state index (0 = highest performance, higher = lower performance).
///         Must not exceed the hardware P-state limit.
///
/// Returns 0 on success, negative error on failure.
#[unsafe(no_mangle)]
pub extern "C" fn amd_pstate_set_pstate(idx: u32) -> i32 {
    let state = match unsafe { (*STATE.get()).as_ref() } {
        Some(s) => s,
        None => return -19, // ENODEV
    };

    if idx >= MAX_PSTATES as u32 {
        log("amd_pstate: P-state index out of range");
        return -22; // EINVAL
    }

    if !state.pstates[idx as usize].enabled {
        unsafe {
            fut_printf(
                b"amd_pstate: P%u is not enabled\n\0".as_ptr(),
                idx,
            );
        }
        return -22; // EINVAL
    }

    // Check against the hardware current P-state limit.
    // Lower index = higher performance; the limit is the maximum index allowed.
    if idx > state.max_pstate_limit as u32 {
        unsafe {
            fut_printf(
                b"amd_pstate: P%u exceeds hardware limit (max P%u)\n\0".as_ptr(),
                idx,
                state.max_pstate_limit as u32,
            );
        }
        return -1;
    }

    // Write the requested P-state to the control MSR.
    let val = idx as u64 & 0x07;
    wrmsr(MSR_PSTATE_CTL, val);

    unsafe {
        fut_printf(
            b"amd_pstate: set P-state to P%u (%lu MHz)\n\0".as_ptr(),
            idx,
            state.pstates[idx as usize].freq_mhz,
        );
    }

    0
}

/// Get the number of enabled P-states.
///
/// Returns 0 if the driver is not initialised.
#[unsafe(no_mangle)]
pub extern "C" fn amd_pstate_count() -> u32 {
    match unsafe { (*STATE.get()).as_ref() } {
        Some(s) => s.num_pstates,
        None => 0,
    }
}

/// Get the frequency in MHz for a specific P-state by index.
///
/// `idx` - P-state index (0..7).
///
/// Returns the frequency in MHz, or 0 if invalid/disabled.
#[unsafe(no_mangle)]
pub extern "C" fn amd_pstate_get_pstate_freq(idx: u32) -> u64 {
    let state = match unsafe { (*STATE.get()).as_ref() } {
        Some(s) => s,
        None => return 0,
    };

    if idx >= MAX_PSTATES as u32 {
        return 0;
    }

    let def = &state.pstates[idx as usize];
    if def.enabled {
        def.freq_mhz
    } else {
        0
    }
}

/// Set CPPC performance request parameters.
///
/// Writes the desired performance, minimum performance, maximum performance,
/// and Energy Performance Preference (EPP) to MSR 0xC001_0294.
///
/// `desired` - Desired performance level (0-255, 0 = autonomous mode).
/// `min`     - Minimum performance level (0-255).
/// `max`     - Maximum performance level (0-255).
/// `epp`     - Energy Performance Preference (0 = max performance, 255 = max power saving).
///
/// Returns 0 on success, negative error on failure.
#[unsafe(no_mangle)]
pub extern "C" fn amd_pstate_cppc_set_perf(desired: u8, min: u8, max: u8, epp: u8) -> i32 {
    let state = match unsafe { (*STATE.get()).as_ref() } {
        Some(s) => s,
        None => return -19, // ENODEV
    };

    if !state.cppc_supported {
        log("amd_pstate: CPPC not supported on this CPU");
        return -95; // ENOTSUP
    }

    // Validate: min <= max, desired <= max (unless desired is 0 for autonomous).
    if min > max {
        log("amd_pstate: CPPC min > max");
        return -22; // EINVAL
    }
    if desired != 0 && desired > max {
        log("amd_pstate: CPPC desired > max");
        return -22; // EINVAL
    }

    // Build the CPPC_REQ MSR value:
    //   bits [7:0]   = DesiredPerf
    //   bits [15:8]  = MinPerf
    //   bits [23:16] = MaxPerf
    //   bits [31:24] = EPP
    let val: u64 = (desired as u64)
        | ((min as u64) << 8)
        | ((max as u64) << 16)
        | ((epp as u64) << 24);

    wrmsr(MSR_CPPC_REQ, val);

    unsafe {
        fut_printf(
            b"amd_pstate: CPPC request: desired=%u min=%u max=%u epp=%u\n\0".as_ptr(),
            desired as u32,
            min as u32,
            max as u32,
            epp as u32,
        );
    }

    0
}

/// Read CPPC capability levels from MSR 0xC001_0293.
///
/// Outputs the highest, nominal, and lowest performance levels the CPU supports.
///
/// `highest`  - Pointer to receive the highest performance level.
/// `nominal`  - Pointer to receive the nominal performance level.
/// `lowest`   - Pointer to receive the lowest performance level.
///
/// Returns 0 on success, negative error on failure.
#[unsafe(no_mangle)]
pub extern "C" fn amd_pstate_cppc_get_caps(
    highest: *mut u8,
    nominal: *mut u8,
    lowest: *mut u8,
) -> i32 {
    let state = match unsafe { (*STATE.get()).as_ref() } {
        Some(s) => s,
        None => return -19, // ENODEV
    };

    if !state.cppc_supported {
        log("amd_pstate: CPPC not supported on this CPU");
        return -95; // ENOTSUP
    }

    if highest.is_null() || nominal.is_null() || lowest.is_null() {
        return -22; // EINVAL
    }

    let caps = rdmsr(MSR_CPPC_CAPS1);
    let h = (caps & 0xFF) as u8;
    let n = ((caps >> 8) & 0xFF) as u8;
    // bits [23:16] = LowestNonlinearPerf (skipped in output, but available).
    let l = ((caps >> 24) & 0xFF) as u8;

    unsafe {
        core::ptr::write(highest, h);
        core::ptr::write(nominal, n);
        core::ptr::write(lowest, l);
    }

    0
}
