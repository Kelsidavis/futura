// SPDX-License-Identifier: MPL-2.0
//
// Intel Hardware P-States (HWP) / Speed Shift Technology Driver for Futura OS
//
// Targets Intel Gen 10+ (Ice Lake / Comet Lake and later) platforms, though
// the underlying HWP mechanism has been available since Skylake (Gen 6).
//
// Architecture:
//   - Detection via CPUID leaf 0x06 EAX:
//       bit  7: HWP base support
//       bit  8: HWP Notification
//       bit  9: HWP Activity Window
//       bit 10: HWP Energy Performance Preference (EPP)
//       bit 11: HWP Package Level Request
//
//   - Key MSRs:
//       0x770  IA32_PM_ENABLE           bit 0 = enable HWP
//       0x771  IA32_HWP_CAPABILITIES    performance level bounds
//       0x772  IA32_HWP_REQUEST         per-core HWP request
//       0x773  IA32_HWP_INTERRUPT       interrupt configuration
//       0x774  IA32_HWP_REQUEST_PKG     package-level HWP request
//       0x777  IA32_HWP_STATUS          status / change notification
//       0x0CE  MSR_PLATFORM_INFO        max non-turbo and max efficiency ratios
//
// Frequency calculation:
//   frequency_mhz = ratio * 100  (bus clock = 100 MHz)
//
// EPP (Energy Performance Preference):
//   0 = maximum performance, 128 = balanced, 255 = maximum power saving

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

/// IA32_PM_ENABLE: bit 0 enables HWP.
const MSR_PM_ENABLE: u32 = 0x770;
/// IA32_HWP_CAPABILITIES: Highest[7:0], Guaranteed[15:8],
/// MostEfficient[23:16], Lowest[31:24].
const MSR_HWP_CAPABILITIES: u32 = 0x771;
/// IA32_HWP_REQUEST: Minimum[7:0], Maximum[15:8], Desired[23:16],
/// EPP[31:24], ActivityWindow[41:32], PackageControl[42].
const MSR_HWP_REQUEST: u32 = 0x772;
/// IA32_HWP_INTERRUPT: bit 0=GuaranteedPerfChange, bit 1=ExcursionMin.
const MSR_HWP_INTERRUPT: u32 = 0x773;
/// IA32_HWP_REQUEST_PKG: package-level HWP request (same layout as 0x772).
const MSR_HWP_REQUEST_PKG: u32 = 0x774;
/// IA32_HWP_STATUS: bit 0=GuaranteedPerfChange, bit 2=ExcursionToMin.
const MSR_HWP_STATUS: u32 = 0x777;
/// MSR_PLATFORM_INFO: bits[15:8]=MaxNonTurbo ratio,
/// bits[47:40]=MaxEfficiency ratio.
const MSR_PLATFORM_INFO: u32 = 0xCE;

// -- CPUID leaf 0x06 capability bits --

const CPUID_THERMAL_POWER: u32 = 0x06;

const HWP_BIT: u32 = 1 << 7;
const HWP_NOTIFICATION_BIT: u32 = 1 << 8;
const HWP_ACTIVITY_WINDOW_BIT: u32 = 1 << 9;
const HWP_EPP_BIT: u32 = 1 << 10;
const HWP_PACKAGE_BIT: u32 = 1 << 11;

// -- EPP preset values --

const EPP_PERFORMANCE: u8 = 0;
const EPP_BALANCED: u8 = 128;
const EPP_POWERSAVE: u8 = 255;

// -- Profile constants --

const PROFILE_PERFORMANCE: u32 = 0;
const PROFILE_BALANCED: u32 = 1;
const PROFILE_POWERSAVE: u32 = 2;

// -- Bus clock for frequency calculation --

const BUS_CLOCK_MHZ: u32 = 100;

// -- Capabilities structure (exported to C) --

/// HWP capability levels read from IA32_HWP_CAPABILITIES.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct HwpCaps {
    pub highest: u8,
    pub guaranteed: u8,
    pub most_efficient: u8,
    pub lowest: u8,
}

impl HwpCaps {
    const fn zero() -> Self {
        Self { highest: 0, guaranteed: 0, most_efficient: 0, lowest: 0 }
    }
}

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

// -- Driver state --

struct HwpFeatures {
    /// HWP base support (CPUID 0x06 EAX bit 7).
    hwp: bool,
    /// HWP Notification support (bit 8).
    notification: bool,
    /// HWP Activity Window support (bit 9).
    activity_window: bool,
    /// HWP Energy Performance Preference support (bit 10).
    epp: bool,
    /// HWP Package Level Request support (bit 11).
    package_level: bool,
}

impl HwpFeatures {
    const fn zero() -> Self {
        Self {
            hwp: false,
            notification: false,
            activity_window: false,
            epp: false,
            package_level: false,
        }
    }
}

struct IntelHwpState {
    /// Whether the driver has been initialised and HWP is enabled.
    enabled: bool,
    /// Detected feature flags from CPUID.
    features: HwpFeatures,
    /// Cached capability levels from IA32_HWP_CAPABILITIES.
    caps: HwpCaps,
    /// Max non-turbo ratio from MSR_PLATFORM_INFO bits[15:8].
    max_non_turbo_ratio: u8,
    /// Max efficiency ratio from MSR_PLATFORM_INFO bits[47:40].
    max_efficiency_ratio: u8,
}

impl IntelHwpState {
    const fn new() -> Self {
        Self {
            enabled: false,
            features: HwpFeatures::zero(),
            caps: HwpCaps::zero(),
            max_non_turbo_ratio: 0,
            max_efficiency_ratio: 0,
        }
    }
}

static STATE: StaticCell<IntelHwpState> = StaticCell::new(IntelHwpState::new());

// -- Internal helpers --

/// Detect HWP feature flags from CPUID leaf 0x06.
fn detect_hwp_features() -> HwpFeatures {
    let (eax, _ebx, _ecx, _edx) = cpuid(CPUID_THERMAL_POWER);
    HwpFeatures {
        hwp: eax & HWP_BIT != 0,
        notification: eax & HWP_NOTIFICATION_BIT != 0,
        activity_window: eax & HWP_ACTIVITY_WINDOW_BIT != 0,
        epp: eax & HWP_EPP_BIT != 0,
        package_level: eax & HWP_PACKAGE_BIT != 0,
    }
}

/// Read HWP capabilities from IA32_HWP_CAPABILITIES (MSR 0x771).
fn read_hwp_caps() -> HwpCaps {
    let val = rdmsr(MSR_HWP_CAPABILITIES);
    HwpCaps {
        highest: (val & 0xFF) as u8,
        guaranteed: ((val >> 8) & 0xFF) as u8,
        most_efficient: ((val >> 16) & 0xFF) as u8,
        lowest: ((val >> 24) & 0xFF) as u8,
    }
}

/// Read platform info ratios from MSR_PLATFORM_INFO (MSR 0xCE).
fn read_platform_info() -> (u8, u8) {
    let val = rdmsr(MSR_PLATFORM_INFO);
    let max_non_turbo = ((val >> 8) & 0xFF) as u8;
    let max_efficiency = ((val >> 40) & 0xFF) as u8;
    (max_non_turbo, max_efficiency)
}

/// Enable HWP by setting bit 0 of IA32_PM_ENABLE (MSR 0x770).
fn enable_hwp() {
    let val = rdmsr(MSR_PM_ENABLE);
    if val & 1 == 0 {
        wrmsr(MSR_PM_ENABLE, val | 1);
    }
}

/// Build a 64-bit IA32_HWP_REQUEST value from individual fields.
fn build_hwp_request(min: u8, max: u8, desired: u8, epp: u8) -> u64 {
    (min as u64)
        | ((max as u64) << 8)
        | ((desired as u64) << 16)
        | ((epp as u64) << 24)
}

// -- FFI exports --

/// Check whether the CPU supports Intel HWP (CPUID 0x06 EAX bit 7).
///
/// This function does not require prior initialisation.
#[unsafe(no_mangle)]
pub extern "C" fn intel_hwp_is_supported() -> bool {
    let (eax, _ebx, _ecx, _edx) = cpuid(CPUID_THERMAL_POWER);
    eax & HWP_BIT != 0
}

/// Initialise the Intel HWP / Speed Shift driver.
///
/// Detects HWP capability via CPUID leaf 0x06, reads platform info ratios,
/// enables HWP via MSR 0x770, and caches the initial capability levels.
///
/// Returns 0 on success, negative error on failure.
#[unsafe(no_mangle)]
pub extern "C" fn intel_hwp_init() -> i32 {
    log("intel_hwp: initialising Intel HWP / Speed Shift driver");

    // Detect feature support.
    let features = detect_hwp_features();
    if !features.hwp {
        log("intel_hwp: HWP not supported on this CPU (CPUID 0x06 EAX bit 7 clear)");
        return -95; // ENOTSUP
    }

    log("intel_hwp: HWP supported");

    unsafe {
        fut_printf(
            b"intel_hwp: features: notification=%u activity_window=%u epp=%u package=%u\n\0"
                .as_ptr(),
            features.notification as u32,
            features.activity_window as u32,
            features.epp as u32,
            features.package_level as u32,
        );
    }

    // Read platform info ratios.
    let (max_non_turbo, max_efficiency) = read_platform_info();
    unsafe {
        fut_printf(
            b"intel_hwp: platform info: max_non_turbo=%u (%u MHz) max_efficiency=%u (%u MHz)\n\0"
                .as_ptr(),
            max_non_turbo as u32,
            (max_non_turbo as u32) * BUS_CLOCK_MHZ,
            max_efficiency as u32,
            (max_efficiency as u32) * BUS_CLOCK_MHZ,
        );
    }

    // Enable HWP.
    enable_hwp();
    log("intel_hwp: HWP enabled (IA32_PM_ENABLE bit 0 set)");

    // Read initial capabilities.
    let caps = read_hwp_caps();
    unsafe {
        fut_printf(
            b"intel_hwp: capabilities: highest=%u guaranteed=%u most_efficient=%u lowest=%u\n\0"
                .as_ptr(),
            caps.highest as u32,
            caps.guaranteed as u32,
            caps.most_efficient as u32,
            caps.lowest as u32,
        );
        fut_printf(
            b"intel_hwp: frequency range: %u - %u MHz (guaranteed %u MHz)\n\0".as_ptr(),
            (caps.lowest as u32) * BUS_CLOCK_MHZ,
            (caps.highest as u32) * BUS_CLOCK_MHZ,
            (caps.guaranteed as u32) * BUS_CLOCK_MHZ,
        );
    }

    // Read and log current HWP request.
    let req = rdmsr(MSR_HWP_REQUEST);
    let cur_min = (req & 0xFF) as u8;
    let cur_max = ((req >> 8) & 0xFF) as u8;
    let cur_desired = ((req >> 16) & 0xFF) as u8;
    let cur_epp = ((req >> 24) & 0xFF) as u8;
    unsafe {
        fut_printf(
            b"intel_hwp: current request: min=%u max=%u desired=%u epp=%u\n\0".as_ptr(),
            cur_min as u32,
            cur_max as u32,
            cur_desired as u32,
            cur_epp as u32,
        );
    }

    // Store driver state.
    let state = IntelHwpState {
        enabled: true,
        features,
        caps,
        max_non_turbo_ratio: max_non_turbo,
        max_efficiency_ratio: max_efficiency,
    };

    unsafe {
        (*STATE.get()) = state;
    }

    log("intel_hwp: driver initialised successfully");
    0
}

/// Read HWP capability levels into a caller-provided structure.
///
/// Populates `caps` with the highest, guaranteed, most efficient, and lowest
/// performance levels from IA32_HWP_CAPABILITIES (MSR 0x771).
///
/// Returns 0 on success, negative error on failure.
#[unsafe(no_mangle)]
pub extern "C" fn intel_hwp_get_caps(caps: *mut HwpCaps) -> i32 {
    let state = unsafe { &*STATE.get() };
    if !state.enabled {
        return -19; // ENODEV
    }
    if caps.is_null() {
        return -22; // EINVAL
    }

    // Re-read from hardware for the most current values.
    let hw_caps = read_hwp_caps();
    unsafe {
        core::ptr::write(caps, hw_caps);
    }

    0
}

/// Set the HWP request parameters for the current core.
///
/// Writes the Minimum, Maximum, Desired performance levels and EPP to
/// IA32_HWP_REQUEST (MSR 0x772).
///
/// `min`     - Minimum performance level (0-255).
/// `max`     - Maximum performance level (0-255).
/// `desired` - Desired performance level (0 = autonomous/hardware-managed).
/// `epp`     - Energy Performance Preference (0 = max perf, 255 = max saving).
///
/// Returns 0 on success, negative error on failure.
#[unsafe(no_mangle)]
pub extern "C" fn intel_hwp_set_request(min: u8, max: u8, desired: u8, epp: u8) -> i32 {
    let state = unsafe { &*STATE.get() };
    if !state.enabled {
        return -19; // ENODEV
    }

    // Validate: min <= max.
    if min > max {
        log("intel_hwp: invalid request: min > max");
        return -22; // EINVAL
    }

    // Validate: desired must be 0 (autonomous) or within [min, max].
    if desired != 0 && (desired < min || desired > max) {
        log("intel_hwp: invalid request: desired outside [min, max]");
        return -22; // EINVAL
    }

    // Preserve activity window and package control bits from current request.
    let current = rdmsr(MSR_HWP_REQUEST);
    let preserved_bits = current & !0xFFFF_FFFF_u64; // bits [63:32]
    let new_val = preserved_bits | build_hwp_request(min, max, desired, epp);
    wrmsr(MSR_HWP_REQUEST, new_val);

    unsafe {
        fut_printf(
            b"intel_hwp: set request: min=%u max=%u desired=%u epp=%u\n\0".as_ptr(),
            min as u32,
            max as u32,
            desired as u32,
            epp as u32,
        );
    }

    0
}

/// Set only the Energy Performance Preference (EPP) field, preserving all
/// other fields of the current HWP request.
///
/// `epp` - 0 = max performance, 128 = balanced, 255 = max power saving.
///
/// Returns 0 on success, negative error on failure.
#[unsafe(no_mangle)]
pub extern "C" fn intel_hwp_set_epp(epp: u8) -> i32 {
    let state = unsafe { &*STATE.get() };
    if !state.enabled {
        return -19; // ENODEV
    }

    if !state.features.epp {
        log("intel_hwp: EPP not supported on this CPU");
        return -95; // ENOTSUP
    }

    // Read current request, clear EPP field (bits [31:24]), set new EPP.
    let current = rdmsr(MSR_HWP_REQUEST);
    let new_val = (current & !0xFF00_0000_u64) | ((epp as u64) << 24);
    wrmsr(MSR_HWP_REQUEST, new_val);

    unsafe {
        fut_printf(
            b"intel_hwp: set epp=%u\n\0".as_ptr(),
            epp as u32,
        );
    }

    0
}

/// Apply a named performance profile by setting appropriate HWP request
/// parameters and EPP value.
///
/// `profile` - 0 = performance, 1 = balanced, 2 = powersave.
///
/// Returns 0 on success, negative error on failure.
#[unsafe(no_mangle)]
pub extern "C" fn intel_hwp_set_profile(profile: u32) -> i32 {
    let state = unsafe { &*STATE.get() };
    if !state.enabled {
        return -19; // ENODEV
    }

    let caps = read_hwp_caps();

    let (min, max, desired, epp, name): (u8, u8, u8, u8, &[u8]) = match profile {
        PROFILE_PERFORMANCE => {
            // Performance: request the highest level, EPP = 0.
            (caps.guaranteed, caps.highest, 0, EPP_PERFORMANCE,
             b"performance\0")
        }
        PROFILE_BALANCED => {
            // Balanced: full range, autonomous desired, EPP = 128.
            (caps.most_efficient, caps.highest, 0, EPP_BALANCED,
             b"balanced\0")
        }
        PROFILE_POWERSAVE => {
            // Power save: constrain to efficient range, EPP = 255.
            (caps.lowest, caps.most_efficient, 0, EPP_POWERSAVE,
             b"powersave\0")
        }
        _ => {
            log("intel_hwp: unknown profile");
            return -22; // EINVAL
        }
    };

    // Preserve upper bits (activity window, package control).
    let current = rdmsr(MSR_HWP_REQUEST);
    let preserved_bits = current & !0xFFFF_FFFF_u64;
    let new_val = preserved_bits | build_hwp_request(min, max, desired, epp);
    wrmsr(MSR_HWP_REQUEST, new_val);

    unsafe {
        fut_printf(
            b"intel_hwp: applied profile %s: min=%u max=%u desired=%u epp=%u\n\0".as_ptr(),
            name.as_ptr(),
            min as u32,
            max as u32,
            desired as u32,
            epp as u32,
        );
    }

    0
}

/// Get the current guaranteed operating frequency in MHz.
///
/// Returns the guaranteed performance ratio (from IA32_HWP_CAPABILITIES)
/// multiplied by the bus clock (100 MHz).  Returns 0 if the driver is not
/// initialised.
#[unsafe(no_mangle)]
pub extern "C" fn intel_hwp_get_frequency() -> u32 {
    let state = unsafe { &*STATE.get() };
    if !state.enabled {
        return 0;
    }

    // Re-read capabilities for the most current guaranteed ratio.
    let caps = read_hwp_caps();
    (caps.guaranteed as u32) * BUS_CLOCK_MHZ
}

/// Get the maximum turbo frequency in MHz.
///
/// Returns the highest performance ratio (from IA32_HWP_CAPABILITIES)
/// multiplied by the bus clock (100 MHz).  Returns 0 if the driver is not
/// initialised.
#[unsafe(no_mangle)]
pub extern "C" fn intel_hwp_max_frequency() -> u32 {
    let state = unsafe { &*STATE.get() };
    if !state.enabled {
        return 0;
    }

    let caps = read_hwp_caps();
    (caps.highest as u32) * BUS_CLOCK_MHZ
}

/// Read the HWP status register (IA32_HWP_STATUS, MSR 0x777).
///
/// Returns the raw 32-bit status value:
///   bit 0: Guaranteed performance change occurred
///   bit 2: Excursion to minimum occurred
///
/// Returns 0 if the driver is not initialised.
#[unsafe(no_mangle)]
pub extern "C" fn intel_hwp_get_status() -> u32 {
    let state = unsafe { &*STATE.get() };
    if !state.enabled {
        return 0;
    }

    let val = rdmsr(MSR_HWP_STATUS);
    val as u32
}

/// Clear the HWP status register (write 0 to IA32_HWP_STATUS).
///
/// Returns 0 on success, negative error on failure.
#[unsafe(no_mangle)]
pub extern "C" fn intel_hwp_clear_status() -> i32 {
    let state = unsafe { &*STATE.get() };
    if !state.enabled {
        return -19; // ENODEV
    }

    wrmsr(MSR_HWP_STATUS, 0);
    0
}

/// Set the package-level HWP request (IA32_HWP_REQUEST_PKG, MSR 0x774).
///
/// This applies to all cores in the package when PackageControl is set.
///
/// `min`     - Minimum performance level.
/// `max`     - Maximum performance level.
/// `desired` - Desired performance level (0 = autonomous).
/// `epp`     - Energy Performance Preference.
///
/// Returns 0 on success, negative error on failure.
#[unsafe(no_mangle)]
pub extern "C" fn intel_hwp_set_package_request(
    min: u8,
    max: u8,
    desired: u8,
    epp: u8,
) -> i32 {
    let state = unsafe { &*STATE.get() };
    if !state.enabled {
        return -19; // ENODEV
    }

    if !state.features.package_level {
        log("intel_hwp: package-level HWP request not supported");
        return -95; // ENOTSUP
    }

    if min > max {
        log("intel_hwp: invalid package request: min > max");
        return -22; // EINVAL
    }

    if desired != 0 && (desired < min || desired > max) {
        log("intel_hwp: invalid package request: desired outside [min, max]");
        return -22; // EINVAL
    }

    let val = build_hwp_request(min, max, desired, epp);
    wrmsr(MSR_HWP_REQUEST_PKG, val);

    // Also set PackageControl bit (bit 42) on the per-core request so the
    // hardware uses the package-level values.
    let current = rdmsr(MSR_HWP_REQUEST);
    wrmsr(MSR_HWP_REQUEST, current | (1u64 << 42));

    unsafe {
        fut_printf(
            b"intel_hwp: set package request: min=%u max=%u desired=%u epp=%u\n\0".as_ptr(),
            min as u32,
            max as u32,
            desired as u32,
            epp as u32,
        );
    }

    0
}
