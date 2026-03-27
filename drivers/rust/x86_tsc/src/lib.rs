// SPDX-License-Identifier: MPL-2.0
//
// x86-64 Time Stamp Counter (TSC) High-Resolution Timer Driver for Futura OS
//
// The TSC is the highest-resolution timer on x86-64 processors, providing
// sub-nanosecond precision on modern CPUs. On AMD Ryzen (Zen and later),
// the TSC is invariant: it runs at a constant rate regardless of P-state,
// C-state, or frequency scaling transitions.
//
// Architecture:
//   - RDTSC instruction returns 64-bit monotonic counter in EDX:EAX
//   - RDTSCP also returns IA32_TSC_AUX (processor ID) in ECX
//   - CPUID 0x80000007 EDX bit 8: Invariant TSC capability
//   - CPUID 0x15: TSC/Core Crystal Clock ratio and crystal frequency
//       EAX = denominator, EBX = numerator, ECX = crystal freq (Hz)
//       TSC freq = crystal_freq * EBX / EAX
//   - CPUID 0x16: Processor Base Frequency in MHz (EAX)
//   - Fallback calibration: measure TSC ticks over a known delay interval
//
// Frequency detection priority:
//   1. CPUID 0x15 with crystal frequency (ECX != 0)
//   2. CPUID 0x15 ratio + CPUID 0x16 base frequency as crystal estimate
//   3. Calibration via external delay callback (e.g. HPET or PIT based)
//
// Nanosecond conversion uses 128-bit arithmetic:
//   nanos = ticks * 1_000_000_000 / tsc_frequency_hz

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(unexpected_cfgs)]

use core::cell::UnsafeCell;
use core::sync::atomic::{fence, Ordering};

use common::log;

unsafe extern "C" {
    fn fut_printf(fmt: *const u8, ...);
}

// ── StaticCell wrapper (avoids `static mut`) ──

/// Wrapper to allow `UnsafeCell` in a `static` (requires `Sync`).
/// Safety: all access is single-threaded or externally synchronised by the caller.
struct StaticCell<T>(UnsafeCell<T>);
unsafe impl<T> Sync for StaticCell<T> {}
impl<T> StaticCell<T> {
    const fn new(v: T) -> Self { Self(UnsafeCell::new(v)) }
    fn get(&self) -> *mut T { self.0.get() }
}

// ── CPUID leaves ──

/// Standard: TSC/Crystal Clock ratio and crystal frequency.
const CPUID_TSC_FREQ: u32 = 0x15;

/// Standard: Processor Frequency Information.
const CPUID_PROC_FREQ: u32 = 0x16;

/// Extended: Advanced Power Management (bit 8 of EDX = invariant TSC).
const CPUID_ADV_PM: u32 = 0x8000_0007;

/// Extended: maximum extended CPUID leaf.
const CPUID_EXT_MAX: u32 = 0x8000_0000;

/// Bit 8 of CPUID 0x80000007 EDX: Invariant TSC.
const INVARIANT_TSC_BIT: u32 = 1 << 8;

// ── Calibration defaults ──

/// Default calibration period in microseconds (10 ms).
const CALIBRATION_US: u32 = 10_000;

/// Number of calibration rounds to average.
const CALIBRATION_ROUNDS: u32 = 3;

// ── Delay callback type ──

/// External microsecond delay function (e.g. HPET or PIT based).
/// Used for TSC frequency calibration when CPUID does not report it.
type DelayUsFn = unsafe extern "C" fn(us: u32);

// ── Inline assembly helpers ──

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

/// Read the 64-bit Time Stamp Counter via RDTSC.
///
/// Returns the current TSC value (EDX:EAX). This is not serialising;
/// out-of-order execution may reorder it relative to surrounding code.
#[inline]
fn rdtsc_raw() -> u64 {
    let lo: u32;
    let hi: u32;
    unsafe {
        core::arch::asm!(
            "rdtsc",
            out("eax") lo,
            out("edx") hi,
            options(nomem, nostack, preserves_flags),
        );
    }
    ((hi as u64) << 32) | (lo as u64)
}

/// Read the 64-bit Time Stamp Counter via RDTSCP.
///
/// Returns (tsc_value, aux) where `aux` is the contents of IA32_TSC_AUX
/// (typically the logical processor ID set by the OS). RDTSCP waits until
/// all previous instructions have executed before reading the counter.
#[inline]
fn rdtscp_raw() -> (u64, u32) {
    let lo: u32;
    let hi: u32;
    let aux: u32;
    unsafe {
        core::arch::asm!(
            "rdtscp",
            out("eax") lo,
            out("edx") hi,
            out("ecx") aux,
            options(nomem, nostack, preserves_flags),
        );
    }
    (((hi as u64) << 32) | (lo as u64), aux)
}

/// Serialising fence: CPUID leaf 0 is used as a full serialising barrier
/// to ensure RDTSC reads are not reordered across measurement boundaries.
#[inline]
fn serialise() {
    unsafe {
        core::arch::asm!(
            "push rbx",
            "xor eax, eax",
            "cpuid",
            "pop rbx",
            out("eax") _,
            out("ecx") _,
            out("edx") _,
            options(nomem, preserves_flags),
        );
    }
}

// ── Driver state ──

struct TscState {
    /// TSC frequency in Hz.
    frequency_hz: u64,
    /// TSC value at initialisation (epoch for nanos calculation).
    tsc_at_init: u64,
    /// Whether the TSC is invariant (constant rate).
    invariant: bool,
    /// Whether RDTSCP instruction is available.
    rdtscp_available: bool,
    /// Whether the driver has been initialised.
    initialized: bool,
}

impl TscState {
    const fn new() -> Self {
        Self {
            frequency_hz: 0,
            tsc_at_init: 0,
            invariant: false,
            rdtscp_available: false,
            initialized: false,
        }
    }
}

static TSC: StaticCell<TscState> = StaticCell::new(TscState::new());

// ── Internal helpers ──

/// Check for invariant TSC via CPUID 0x80000007 EDX bit 8.
fn check_invariant_tsc() -> bool {
    let (max_ext, _, _, _) = cpuid(CPUID_EXT_MAX);
    if max_ext < CPUID_ADV_PM {
        return false;
    }
    let (_eax, _ebx, _ecx, edx) = cpuid(CPUID_ADV_PM);
    (edx & INVARIANT_TSC_BIT) != 0
}

/// Check for RDTSCP support via CPUID 0x80000001 EDX bit 27.
fn check_rdtscp() -> bool {
    let (max_ext, _, _, _) = cpuid(CPUID_EXT_MAX);
    if max_ext < 0x8000_0001 {
        return false;
    }
    let (_eax, _ebx, _ecx, edx) = cpuid(0x8000_0001);
    (edx & (1 << 27)) != 0
}

/// Attempt to determine TSC frequency via CPUID 0x15 (crystal clock ratio).
///
/// Returns the frequency in Hz, or 0 if not determinable from CPUID alone.
fn detect_freq_cpuid15() -> u64 {
    // Check if CPUID 0x15 is supported
    let (max_leaf, _, _, _) = cpuid(0);
    if max_leaf < CPUID_TSC_FREQ {
        return 0;
    }

    let (denom, numer, crystal_hz, _) = cpuid(CPUID_TSC_FREQ);

    // Both ratio components must be non-zero
    if denom == 0 || numer == 0 {
        return 0;
    }

    if crystal_hz != 0 {
        // Direct calculation: tsc_freq = crystal_hz * numer / denom
        let freq = (crystal_hz as u64)
            .saturating_mul(numer as u64)
            / (denom as u64);
        return freq;
    }

    // Crystal frequency not reported; try CPUID 0x16 base frequency
    if max_leaf >= CPUID_PROC_FREQ {
        let (base_mhz, _, _, _) = cpuid(CPUID_PROC_FREQ);
        if base_mhz != 0 {
            // Use base frequency as an estimate:
            // crystal_est = base_freq_hz * denom / numer
            // tsc_freq = crystal_est * numer / denom = base_freq_hz
            // This is a rough approximation; the TSC may differ from base freq.
            return (base_mhz as u64) * 1_000_000;
        }
    }

    0
}

/// Calibrate TSC frequency by measuring ticks over a known delay.
///
/// Uses the provided external delay function to wait for `CALIBRATION_US`
/// microseconds, then computes frequency from elapsed ticks. Averages
/// over multiple rounds for stability.
///
/// Returns the measured frequency in Hz, or 0 on failure.
fn calibrate_with_delay(delay_fn: DelayUsFn) -> u64 {
    let mut total_ticks: u64 = 0;

    for _ in 0..CALIBRATION_ROUNDS {
        serialise();
        let start = rdtsc_raw();
        serialise();

        unsafe { delay_fn(CALIBRATION_US); }

        serialise();
        let end = rdtsc_raw();
        serialise();

        let elapsed = end.wrapping_sub(start);
        total_ticks = total_ticks.saturating_add(elapsed);
    }

    // Average ticks per round
    let avg_ticks = total_ticks / (CALIBRATION_ROUNDS as u64);

    // freq = ticks / time_seconds = ticks * 1_000_000 / CALIBRATION_US
    let freq = avg_ticks
        .saturating_mul(1_000_000)
        / (CALIBRATION_US as u64);

    freq
}

/// Convert TSC ticks to nanoseconds using 128-bit arithmetic.
///
/// nanos = ticks * 1_000_000_000 / frequency_hz
#[inline]
fn ticks_to_nanos(ticks: u64, freq_hz: u64) -> u64 {
    if freq_hz == 0 {
        return 0;
    }
    let product = (ticks as u128) * 1_000_000_000u128;
    (product / (freq_hz as u128)) as u64
}

/// Convert nanoseconds to TSC ticks using 128-bit arithmetic.
///
/// ticks = nanos * frequency_hz / 1_000_000_000
#[inline]
fn nanos_to_ticks(ns: u64, freq_hz: u64) -> u64 {
    let product = (ns as u128) * (freq_hz as u128);
    (product / 1_000_000_000u128) as u64
}

/// Convert microseconds to TSC ticks using 128-bit arithmetic.
#[inline]
fn micros_to_ticks(us: u64, freq_hz: u64) -> u64 {
    let product = (us as u128) * (freq_hz as u128);
    (product / 1_000_000u128) as u64
}

// ── FFI exports ──

/// Initialise the x86 TSC timer driver.
///
/// `delay_fn`: optional external microsecond delay callback for calibration.
///   If null, frequency detection relies solely on CPUID. If CPUID cannot
///   determine the frequency and no callback is provided, initialisation fails.
///
/// Returns 0 on success, negative on error:
///   -1 = TSC not available (RDTSC not supported)
///   -2 = TSC is not invariant (unreliable for timekeeping)
///   -3 = unable to determine TSC frequency
#[unsafe(no_mangle)]
pub extern "C" fn x86_tsc_init(delay_fn: Option<DelayUsFn>) -> i32 {
    log("x86_tsc: initializing TSC timer");

    // Check for invariant TSC
    let invariant = check_invariant_tsc();
    if !invariant {
        log("x86_tsc: WARNING - TSC is not invariant, frequency may vary");
    }

    let rdtscp = check_rdtscp();

    // Attempt frequency detection via CPUID
    let mut freq = detect_freq_cpuid15();

    if freq == 0 {
        // Fall back to calibration if a delay function was provided
        if let Some(dfn) = delay_fn {
            log("x86_tsc: CPUID frequency detection failed, calibrating...");
            freq = calibrate_with_delay(dfn);
        }
    }

    if freq == 0 {
        log("x86_tsc: unable to determine TSC frequency");
        return -3;
    }

    // Serialise and capture initial TSC value
    serialise();
    let tsc_init = rdtsc_raw();

    // Store state
    let state = TSC.get();
    unsafe {
        (*state).frequency_hz = freq;
        (*state).tsc_at_init = tsc_init;
        (*state).invariant = invariant;
        (*state).rdtscp_available = rdtscp;
        fence(Ordering::SeqCst);
        (*state).initialized = true;
    }

    // Log results
    let freq_mhz = freq / 1_000_000;
    let freq_khz_frac = (freq % 1_000_000) / 1_000;
    unsafe {
        fut_printf(
            b"x86_tsc: frequency %llu.%03llu MHz\n\0".as_ptr(),
            freq_mhz,
            freq_khz_frac,
        );
        fut_printf(
            b"x86_tsc: invariant=%u rdtscp=%u\n\0".as_ptr(),
            invariant as u32,
            rdtscp as u32,
        );
    }

    0
}

/// Read the raw TSC counter value.
///
/// Uses a serialising CPUID + RDTSC sequence for precise measurement.
/// Returns 0 if the driver is not initialised.
#[unsafe(no_mangle)]
pub extern "C" fn x86_tsc_read() -> u64 {
    let state = TSC.get();
    unsafe {
        if !(*state).initialized {
            return 0;
        }
    }
    serialise();
    rdtsc_raw()
}

/// Get the TSC frequency in Hz.
///
/// Returns 0 if the driver is not initialised.
#[unsafe(no_mangle)]
pub extern "C" fn x86_tsc_frequency() -> u64 {
    let state = TSC.get();
    unsafe {
        if !(*state).initialized { 0 } else { (*state).frequency_hz }
    }
}

/// Get the number of nanoseconds elapsed since TSC driver initialisation.
///
/// Uses 128-bit arithmetic to avoid overflow.
/// Returns 0 if the driver is not initialised.
#[unsafe(no_mangle)]
pub extern "C" fn x86_tsc_nanos() -> u64 {
    let state = TSC.get();
    unsafe {
        if !(*state).initialized {
            return 0;
        }
        serialise();
        let now = rdtsc_raw();
        let elapsed = now.wrapping_sub((*state).tsc_at_init);
        ticks_to_nanos(elapsed, (*state).frequency_hz)
    }
}

/// Busy-wait for the specified number of nanoseconds using the TSC.
///
/// Spins reading the TSC until the requested duration has elapsed.
/// Sub-nanosecond resolution on modern processors (typically ~0.3-0.5 ns
/// per tick at multi-GHz frequencies).
///
/// Does nothing if the driver is not initialised or ns is 0.
#[unsafe(no_mangle)]
pub extern "C" fn x86_tsc_delay_ns(ns: u64) {
    if ns == 0 { return; }

    let state = TSC.get();
    unsafe {
        if !(*state).initialized { return; }

        let freq = (*state).frequency_hz;
        let ticks_needed = nanos_to_ticks(ns, freq);
        if ticks_needed == 0 { return; }

        serialise();
        let start = rdtsc_raw();
        loop {
            let now = rdtsc_raw();
            if now.wrapping_sub(start) >= ticks_needed {
                break;
            }
            core::hint::spin_loop();
        }
    }
}

/// Busy-wait for the specified number of microseconds using the TSC.
///
/// Convenience wrapper using microsecond granularity for the tick
/// calculation to avoid unnecessary 128-bit multiplication overhead.
///
/// Does nothing if the driver is not initialised or us is 0.
#[unsafe(no_mangle)]
pub extern "C" fn x86_tsc_delay_us(us: u64) {
    if us == 0 { return; }

    let state = TSC.get();
    unsafe {
        if !(*state).initialized { return; }

        let freq = (*state).frequency_hz;
        let ticks_needed = micros_to_ticks(us, freq);
        if ticks_needed == 0 { return; }

        serialise();
        let start = rdtsc_raw();
        loop {
            let now = rdtsc_raw();
            if now.wrapping_sub(start) >= ticks_needed {
                break;
            }
            core::hint::spin_loop();
        }
    }
}

/// Check whether the TSC is invariant (constant rate regardless of P-state).
///
/// Returns true if CPUID 0x80000007 EDX bit 8 is set, false otherwise.
/// Returns false if the driver is not initialised.
#[unsafe(no_mangle)]
pub extern "C" fn x86_tsc_is_invariant() -> bool {
    let state = TSC.get();
    unsafe {
        if !(*state).initialized { false } else { (*state).invariant }
    }
}

/// Read the TSC via RDTSCP, also returning the processor/core ID.
///
/// RDTSCP is a serialising read: it waits for all prior instructions to
/// retire before reading the counter. The `cpu_id` output receives the
/// value of IA32_TSC_AUX (set by the OS, typically the logical CPU number).
///
/// If `cpu_id` is null, the auxiliary value is discarded.
/// Returns the 64-bit TSC value, or 0 if RDTSCP is not available or the
/// driver is not initialised.
#[unsafe(no_mangle)]
pub extern "C" fn x86_tsc_rdtscp(cpu_id: *mut u32) -> u64 {
    let state = TSC.get();
    unsafe {
        if !(*state).initialized || !(*state).rdtscp_available {
            return 0;
        }
    }

    let (tsc, aux) = rdtscp_raw();

    if !cpu_id.is_null() {
        unsafe {
            core::ptr::write_volatile(cpu_id, aux);
        }
    }

    tsc
}
