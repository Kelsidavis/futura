// SPDX-License-Identifier: MPL-2.0
//
// Intel Speed Select Technology (SST) Driver for Futura OS
//
// Targets Intel Gen 10+ (Ice Lake and later) platforms with SST support.
//
// SST sub-features:
//   - SST-PP (Performance Profile): pre-defined profiles with different
//     core counts and frequencies (up to 4 levels).
//   - SST-BF (Base Frequency): assign higher base frequency to select cores.
//   - SST-TF (Turbo Frequency): assign higher turbo ratios to select cores.
//   - SST-CP (Core Power): per-core power budgeting.
//
// Detection:
//   CPUID leaf 0x06 EAX bit 19: SST-PP capability indicator.
//
// Key MSRs:
//   0x64F  MSR_CONFIG_TDP_CONTROL     profile select and lock
//   0x648  MSR_CONFIG_TDP_NOMINAL     nominal TDP ratio for current profile
//   0x649  MSR_CONFIG_TDP_LEVEL_1     level 1 TDP info (power + ratio)
//   0x64A  MSR_CONFIG_TDP_LEVEL_2     level 2 TDP info (power + ratio)
//   0x64B  MSR_TURBO_ACTIVATION_RATIO turbo activation ratio
//   0x1AD  MSR_TURBO_RATIO_LIMIT      max turbo ratios for 1-8 active cores
//   0x1AE  MSR_TURBO_RATIO_LIMIT1     max turbo ratios for 9-16 active cores
//
// Frequency calculation:
//   frequency_mhz = ratio * 100  (bus clock = 100 MHz)

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

/// MSR_CONFIG_TDP_NOMINAL: bits[7:0] = TDP ratio for the nominal (base) profile.
const MSR_CONFIG_TDP_NOMINAL: u32 = 0x648;
/// MSR_CONFIG_TDP_LEVEL_1: bits[14:0] = PKG_TDP, bits[23:16] = TDP_RATIO.
const MSR_CONFIG_TDP_LEVEL_1: u32 = 0x649;
/// MSR_CONFIG_TDP_LEVEL_2: same layout as LEVEL_1.
const MSR_CONFIG_TDP_LEVEL_2: u32 = 0x64A;
/// MSR_TURBO_ACTIVATION_RATIO: turbo activation ratio for current profile.
const MSR_TURBO_ACTIVATION_RATIO: u32 = 0x64B;
/// MSR_CONFIG_TDP_CONTROL: bits[1:0] = CONFIG_TDP_LEVEL, bit 31 = LOCK.
const MSR_CONFIG_TDP_CONTROL: u32 = 0x64F;
/// MSR_TURBO_RATIO_LIMIT: max turbo ratios per active core count (1-8).
const MSR_TURBO_RATIO_LIMIT: u32 = 0x1AD;
/// MSR_TURBO_RATIO_LIMIT1: max turbo ratios per active core count (9-16).
const MSR_TURBO_RATIO_LIMIT1: u32 = 0x1AE;

// -- CPUID detection --

/// CPUID leaf 0x06 (Thermal and Power Management).
const CPUID_THERMAL_POWER: u32 = 0x06;

/// CPUID 0x06 EAX bit 19: SST-PP (Intel Thread Director / SST) support.
const SST_PP_BIT: u32 = 1 << 19;

// -- Constants --

/// Bus clock frequency in MHz (Intel standard).
const BUS_CLOCK_MHZ: u32 = 100;

/// Maximum number of SST performance profiles (levels 0-3).
const MAX_PROFILES: u32 = 4;

/// CONFIG_TDP_CONTROL lock bit (bit 31).
const CONFIG_TDP_LOCK_BIT: u64 = 1 << 31;

/// CONFIG_TDP_CONTROL level mask (bits [1:0]).
const CONFIG_TDP_LEVEL_MASK: u64 = 0x3;

// -- Profile structure (exported to C) --

/// SST performance profile information.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct SstProfile {
    /// Profile level (0-3).
    pub level: u32,
    /// Package TDP in watts (approximate, derived from power units).
    pub tdp_watts: u32,
    /// Base frequency ratio for this profile.
    pub base_ratio: u32,
    /// Maximum turbo ratio with 1 active core.
    pub max_turbo_1core: u32,
    /// Maximum turbo ratio with all cores active (byte 7 from turbo limit MSR).
    pub max_turbo_all: u32,
}

impl SstProfile {
    const fn zero() -> Self {
        Self {
            level: 0,
            tdp_watts: 0,
            base_ratio: 0,
            max_turbo_1core: 0,
            max_turbo_all: 0,
        }
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

struct IntelSstState {
    /// Whether the driver has been initialised and SST is available.
    initialised: bool,
    /// Whether SST-PP is supported (CPUID 0x06 EAX bit 19).
    supported: bool,
    /// Number of available profiles (1-4).
    profile_count: u32,
    /// Cached profile information for each level.
    profiles: [SstProfile; MAX_PROFILES as usize],
}

impl IntelSstState {
    const fn new() -> Self {
        Self {
            initialised: false,
            supported: false,
            profile_count: 0,
            profiles: [SstProfile::zero(); MAX_PROFILES as usize],
        }
    }
}

static STATE: StaticCell<IntelSstState> = StaticCell::new(IntelSstState::new());

// -- Internal helpers --

/// Check whether the CPU supports SST-PP via CPUID leaf 0x06.
fn detect_sst_support() -> bool {
    let (eax, _ebx, _ecx, _edx) = cpuid(CPUID_THERMAL_POWER);
    eax & SST_PP_BIT != 0
}

/// Read the current CONFIG_TDP_LEVEL from MSR_CONFIG_TDP_CONTROL.
fn read_current_level() -> u32 {
    let val = rdmsr(MSR_CONFIG_TDP_CONTROL);
    (val & CONFIG_TDP_LEVEL_MASK) as u32
}

/// Check whether the CONFIG_TDP_CONTROL register is locked.
fn read_lock_status() -> bool {
    let val = rdmsr(MSR_CONFIG_TDP_CONTROL);
    val & CONFIG_TDP_LOCK_BIT != 0
}

/// Read the nominal TDP ratio from MSR_CONFIG_TDP_NOMINAL.
fn read_nominal_ratio() -> u32 {
    let val = rdmsr(MSR_CONFIG_TDP_NOMINAL);
    (val & 0xFF) as u32
}

/// Read TDP info from a CONFIG_TDP_LEVEL MSR (0x649 or 0x64A).
/// Returns (pkg_tdp_raw, tdp_ratio).
fn read_tdp_level_info(msr: u32) -> (u32, u32) {
    let val = rdmsr(msr);
    let pkg_tdp = (val & 0x7FFF) as u32;
    let tdp_ratio = ((val >> 16) & 0xFF) as u32;
    (pkg_tdp, tdp_ratio)
}

/// Read the turbo ratio for a given number of active cores (1-based).
/// Cores 1-8 come from MSR_TURBO_RATIO_LIMIT, 9-16 from MSR_TURBO_RATIO_LIMIT1.
fn read_turbo_ratio(active_cores: u32) -> u32 {
    if active_cores == 0 || active_cores > 16 {
        return 0;
    }

    let (msr, index) = if active_cores <= 8 {
        (MSR_TURBO_RATIO_LIMIT, active_cores - 1)
    } else {
        (MSR_TURBO_RATIO_LIMIT1, active_cores - 9)
    };

    let val = rdmsr(msr);
    let shift = index * 8;
    ((val >> shift) & 0xFF) as u32
}

/// Enumerate available profiles and populate their info.
/// Returns the number of valid profiles found.
fn enumerate_profiles(profiles: &mut [SstProfile; MAX_PROFILES as usize]) -> u32 {
    // Level 0 is always the nominal profile.
    let nominal_ratio = read_nominal_ratio();
    let turbo_1 = read_turbo_ratio(1);
    // Use byte index 7 (8 active cores) as an approximation of "all cores" turbo.
    let turbo_all = read_turbo_ratio(8);

    profiles[0] = SstProfile {
        level: 0,
        tdp_watts: 0, // Nominal level does not expose TDP via the level MSRs.
        base_ratio: nominal_ratio,
        max_turbo_1core: turbo_1,
        max_turbo_all: turbo_all,
    };

    let mut count: u32 = 1;

    // Level 1.
    let (pkg_tdp_1, ratio_1) = read_tdp_level_info(MSR_CONFIG_TDP_LEVEL_1);
    if ratio_1 != 0 {
        profiles[1] = SstProfile {
            level: 1,
            tdp_watts: pkg_tdp_1,
            base_ratio: ratio_1,
            max_turbo_1core: turbo_1,
            max_turbo_all: turbo_all,
        };
        count = 2;

        // Level 2.
        let (pkg_tdp_2, ratio_2) = read_tdp_level_info(MSR_CONFIG_TDP_LEVEL_2);
        if ratio_2 != 0 {
            profiles[2] = SstProfile {
                level: 2,
                tdp_watts: pkg_tdp_2,
                base_ratio: ratio_2,
                max_turbo_1core: turbo_1,
                max_turbo_all: turbo_all,
            };
            count = 3;

            // Level 3: some platforms expose a third configurable level in the
            // turbo activation ratio MSR. If the activation ratio differs from
            // levels 0-2, treat it as a distinct profile.
            let act_val = rdmsr(MSR_TURBO_ACTIVATION_RATIO);
            let act_ratio = (act_val & 0xFF) as u32;
            if act_ratio != 0
                && act_ratio != nominal_ratio
                && act_ratio != ratio_1
                && act_ratio != ratio_2
            {
                profiles[3] = SstProfile {
                    level: 3,
                    tdp_watts: 0,
                    base_ratio: act_ratio,
                    max_turbo_1core: turbo_1,
                    max_turbo_all: turbo_all,
                };
                count = 4;
            }
        }
    }

    count
}

// -- FFI exports --

/// Check whether the CPU supports Intel SST (CPUID 0x06 EAX bit 19).
///
/// This function does not require prior initialisation.
#[unsafe(no_mangle)]
pub extern "C" fn intel_sst_is_supported() -> bool {
    detect_sst_support()
}

/// Initialise the Intel SST driver.
///
/// Detects SST capability via CPUID leaf 0x06, enumerates available
/// performance profiles, reads turbo ratio limits, and caches all state.
///
/// Returns 0 on success, negative error on failure.
#[unsafe(no_mangle)]
pub extern "C" fn intel_sst_init() -> i32 {
    log("intel_sst: initialising Intel Speed Select Technology driver");

    // Detect SST-PP support.
    let supported = detect_sst_support();
    if !supported {
        log("intel_sst: SST-PP not supported (CPUID 0x06 EAX bit 19 clear)");
        return -95; // ENOTSUP
    }

    log("intel_sst: SST-PP supported");

    // Read lock status.
    let locked = read_lock_status();
    unsafe {
        fut_printf(
            b"intel_sst: CONFIG_TDP_CONTROL locked=%u\n\0".as_ptr(),
            locked as u32,
        );
    }

    // Read current profile level.
    let current_level = read_current_level();
    unsafe {
        fut_printf(
            b"intel_sst: current profile level=%u\n\0".as_ptr(),
            current_level,
        );
    }

    // Read nominal TDP ratio.
    let nominal_ratio = read_nominal_ratio();
    unsafe {
        fut_printf(
            b"intel_sst: nominal TDP ratio=%u (%u MHz)\n\0".as_ptr(),
            nominal_ratio,
            nominal_ratio * BUS_CLOCK_MHZ,
        );
    }

    // Enumerate available profiles.
    let mut profiles = [SstProfile::zero(); MAX_PROFILES as usize];
    let profile_count = enumerate_profiles(&mut profiles);
    unsafe {
        fut_printf(
            b"intel_sst: found %u performance profile(s)\n\0".as_ptr(),
            profile_count,
        );
    }

    // Log each profile.
    for i in 0..profile_count as usize {
        let p = &profiles[i];
        unsafe {
            fut_printf(
                b"intel_sst: profile %u: base_ratio=%u (%u MHz) tdp=%u turbo_1=%u turbo_all=%u\n\0"
                    .as_ptr(),
                p.level,
                p.base_ratio,
                p.base_ratio * BUS_CLOCK_MHZ,
                p.tdp_watts,
                p.max_turbo_1core,
                p.max_turbo_all,
            );
        }
    }

    // Log turbo ratio limits for cores 1-8.
    for core in 1u32..=8 {
        let ratio = read_turbo_ratio(core);
        if ratio == 0 {
            break;
        }
        unsafe {
            fut_printf(
                b"intel_sst: turbo ratio: %u active core(s) -> ratio %u (%u MHz)\n\0".as_ptr(),
                core,
                ratio,
                ratio * BUS_CLOCK_MHZ,
            );
        }
    }

    // Store driver state.
    let state = IntelSstState {
        initialised: true,
        supported: true,
        profile_count,
        profiles,
    };

    unsafe {
        (*STATE.get()) = state;
    }

    log("intel_sst: driver initialised successfully");
    0
}

/// Return the current SST profile level (0-3).
///
/// Reads MSR_CONFIG_TDP_CONTROL bits[1:0] directly from hardware.
/// Returns 0 if the driver is not initialised (level 0 is also the default).
#[unsafe(no_mangle)]
pub extern "C" fn intel_sst_current_level() -> u32 {
    let state = unsafe { &*STATE.get() };
    if !state.initialised {
        return 0;
    }
    read_current_level()
}

/// Set the SST profile level (0-3).
///
/// Writes the CONFIG_TDP_LEVEL field in MSR_CONFIG_TDP_CONTROL.
/// Fails if the register is locked (bit 31 set) or the level is out of range.
///
/// Returns 0 on success, negative error on failure.
#[unsafe(no_mangle)]
pub extern "C" fn intel_sst_set_level(level: u32) -> i32 {
    let state = unsafe { &*STATE.get() };
    if !state.initialised {
        return -19; // ENODEV
    }

    if level >= state.profile_count {
        log("intel_sst: requested level exceeds available profiles");
        return -22; // EINVAL
    }

    // Check lock status.
    if read_lock_status() {
        log("intel_sst: CONFIG_TDP_CONTROL is locked, cannot change profile");
        return -1; // EPERM
    }

    // Read current value, preserve upper bits (including lock), set new level.
    let current = rdmsr(MSR_CONFIG_TDP_CONTROL);
    let new_val = (current & !CONFIG_TDP_LEVEL_MASK) | (level as u64 & CONFIG_TDP_LEVEL_MASK);
    wrmsr(MSR_CONFIG_TDP_CONTROL, new_val);

    unsafe {
        fut_printf(
            b"intel_sst: switched to profile level %u\n\0".as_ptr(),
            level,
        );
    }

    0
}

/// Read profile information for a given level into a caller-provided structure.
///
/// `level`   - Profile level (0-3).
/// `profile` - Pointer to an SstProfile structure to populate.
///
/// Returns 0 on success, negative error on failure.
#[unsafe(no_mangle)]
pub extern "C" fn intel_sst_get_profile(level: u32, profile: *mut SstProfile) -> i32 {
    let state = unsafe { &*STATE.get() };
    if !state.initialised {
        return -19; // ENODEV
    }

    if profile.is_null() {
        return -22; // EINVAL
    }

    if level >= state.profile_count {
        return -22; // EINVAL
    }

    unsafe {
        core::ptr::write(profile, state.profiles[level as usize]);
    }

    0
}

/// Get the maximum turbo ratio for a given number of active cores.
///
/// `active_cores` - Number of active cores (1-16).
///
/// Returns the turbo ratio (multiply by 100 for MHz), or 0 on error.
#[unsafe(no_mangle)]
pub extern "C" fn intel_sst_turbo_ratio(active_cores: u32) -> u32 {
    let state = unsafe { &*STATE.get() };
    if !state.initialised {
        return 0;
    }
    read_turbo_ratio(active_cores)
}

/// Check whether the CONFIG_TDP_CONTROL register is locked.
///
/// When locked (bit 31 set), profile switching is not possible until the
/// next platform reset.
///
/// Returns true if locked, false otherwise. Returns false if not initialised.
#[unsafe(no_mangle)]
pub extern "C" fn intel_sst_is_locked() -> bool {
    let state = unsafe { &*STATE.get() };
    if !state.initialised {
        return false;
    }
    read_lock_status()
}

/// Return the number of available SST performance profiles.
///
/// Returns 0 if the driver is not initialised.
#[unsafe(no_mangle)]
pub extern "C" fn intel_sst_profile_count() -> u32 {
    let state = unsafe { &*STATE.get() };
    if !state.initialised {
        return 0;
    }
    state.profile_count
}
