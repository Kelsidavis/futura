// SPDX-License-Identifier: MPL-2.0
//
// AMD Secure Encrypted Virtualization (SEV) Interface Driver for Futura OS
//
// Targets AMD Ryzen AM4 (Zen/Zen2/Zen3) and AM5 (Zen4/Zen5) platforms.
//
// Architecture:
//   - AMD SEV provides transparent memory encryption for virtual machines
//   - Each VM can be assigned a unique encryption key managed by the AMD
//     Secure Processor (PSP/ASP)
//   - Memory encryption uses an AES-128 engine in the memory controller
//   - The C-bit (encryption bit) in page table entries controls which
//     pages are encrypted
//
// CPUID detection (leaf 0x8000001F):
//   EAX bit 0  = SEV supported
//   EAX bit 1  = SEV-ES (Encrypted State) supported
//   EAX bit 2  = SEV-SNP (Secure Nested Paging) supported
//   EAX bit 3  = VTE (VM Permission Table Enforcement)
//   EBX [5:0]  = C-bit position in page table entries
//   ECX        = number of encrypted guests supported simultaneously
//   EDX        = minimum ASID value for SEV-enabled guests
//
// Key MSRs:
//   0xC001_0131 (SEV_STATUS): bit 0 = SEV enabled, bit 1 = SEV-ES,
//                              bit 2 = SEV-SNP
//   0xC001_0010 (SYSCFG):     memory configuration (MTRR/DRAM enables)
//
// SEV-ES uses the Guest-Hypervisor Communication Block (GHCB) at
// MSR 0xC000_0101+ for #VC exception handling when the guest register
// state is encrypted.
//
// Platform status is queried via the PSP mailbox interface when available,
// providing API version, build ID, guest count, and platform state.

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

// -- Inline assembly helpers --

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

// -- CPUID constants --

/// Extended CPUID leaf for SEV feature detection.
const CPUID_SEV_LEAF: u32 = 0x8000_001F;

/// Maximum extended CPUID leaf query.
const CPUID_EXT_MAX: u32 = 0x8000_0000;

/// EAX bit 0: SEV supported.
const SEV_BIT: u32 = 1 << 0;
/// EAX bit 1: SEV-ES (Encrypted State) supported.
const SEV_ES_BIT: u32 = 1 << 1;
/// EAX bit 2: SEV-SNP (Secure Nested Paging) supported.
const SEV_SNP_BIT: u32 = 1 << 2;
/// EAX bit 3: VTE (VM Permission Table Enforcement) supported.
const VTE_BIT: u32 = 1 << 3;

// -- MSR addresses --

/// SEV_STATUS MSR: reports active SEV state.
///   bit 0 = SEV enabled
///   bit 1 = SEV-ES active
///   bit 2 = SEV-SNP active
const MSR_SEV_STATUS: u32 = 0xC001_0131;

/// SYSCFG MSR: system configuration.
///   bit 21 = MtrrVarDramEn
///   bit 22 = MtrrFixDramModEn
///   bit 23 = MtrrFixDramEn
const MSR_SYSCFG: u32 = 0xC001_0010;

/// SEV_STATUS bit definitions.
const SEV_STATUS_SEV_ENABLED: u64 = 1 << 0;
const SEV_STATUS_SEV_ES_ENABLED: u64 = 1 << 1;
const SEV_STATUS_SEV_SNP_ENABLED: u64 = 1 << 2;

/// SYSCFG bit definitions.
const SYSCFG_MTRR_VAR_DRAM_EN: u64 = 1 << 21;
const SYSCFG_MTRR_FIX_DRAM_MOD_EN: u64 = 1 << 22;
const SYSCFG_MTRR_FIX_DRAM_EN: u64 = 1 << 23;

// -- SEV information structure --

/// Aggregated SEV capability and status information.
#[repr(C)]
pub struct SevInfo {
    /// Whether SEV is supported by the CPU (CPUID).
    pub sev_supported: bool,
    /// Whether SEV-ES is supported by the CPU (CPUID).
    pub sev_es_supported: bool,
    /// Whether SEV-SNP is supported by the CPU (CPUID).
    pub sev_snp_supported: bool,
    /// Whether SEV is currently enabled (MSR).
    pub sev_enabled: bool,
    /// C-bit position in page table entries (from CPUID EBX[5:0]).
    pub c_bit_position: u32,
    /// Maximum number of encrypted guests supported (from CPUID ECX).
    pub max_encrypted_guests: u32,
    /// Minimum ASID for SEV-enabled guests (from CPUID EDX).
    pub min_asid: u32,
    /// PSP-reported API major version (0 if unavailable).
    pub api_major: u8,
    /// PSP-reported API minor version (0 if unavailable).
    pub api_minor: u8,
}

// -- Platform state constants --

/// Platform states as reported by the PSP (when available).
const _PLAT_UNINIT: u8 = 0;
const _PLAT_INIT: u8 = 1;
const _PLAT_WORKING: u8 = 2;

// -- Driver state --

struct AmdSev {
    /// Whether the CPUID SEV leaf is available.
    leaf_available: bool,
    /// Raw EAX from CPUID 0x8000001F (feature bits).
    cpuid_eax: u32,
    /// C-bit position from CPUID EBX[5:0].
    c_bit_position: u32,
    /// Maximum encrypted guests from CPUID ECX.
    max_encrypted_guests: u32,
    /// Minimum ASID for SEV guests from CPUID EDX.
    min_asid: u32,
    /// Whether SEV is currently enabled in the SEV_STATUS MSR.
    sev_active: bool,
    /// Whether SEV-ES is currently active.
    sev_es_active: bool,
    /// Whether SEV-SNP is currently active.
    sev_snp_active: bool,
    /// PSP-reported API major version (0 if not queried or unavailable).
    api_major: u8,
    /// PSP-reported API minor version.
    api_minor: u8,
}

static STATE: StaticCell<Option<AmdSev>> = StaticCell::new(None);

// -- Internal helpers --

/// Check whether the CPUID SEV leaf (0x8000001F) is available.
fn sev_leaf_available() -> bool {
    let (max_ext, _, _, _) = cpuid(CPUID_EXT_MAX);
    max_ext >= CPUID_SEV_LEAF
}

/// Query CPUID 0x8000001F and return (eax, ebx, ecx, edx).
fn query_sev_cpuid() -> (u32, u32, u32, u32) {
    cpuid(CPUID_SEV_LEAF)
}

/// Read the SEV_STATUS MSR and return the raw value.
fn read_sev_status() -> u64 {
    rdmsr(MSR_SEV_STATUS)
}

/// Read the SYSCFG MSR for diagnostic reporting.
fn read_syscfg() -> u64 {
    rdmsr(MSR_SYSCFG)
}

/// Log SYSCFG MTRR-related bits for diagnostics.
fn log_syscfg_info() {
    let syscfg = read_syscfg();
    let var_dram = if syscfg & SYSCFG_MTRR_VAR_DRAM_EN != 0 { 1u32 } else { 0u32 };
    let fix_mod = if syscfg & SYSCFG_MTRR_FIX_DRAM_MOD_EN != 0 { 1u32 } else { 0u32 };
    let fix_en = if syscfg & SYSCFG_MTRR_FIX_DRAM_EN != 0 { 1u32 } else { 0u32 };

    unsafe {
        fut_printf(
            b"amd_sev: SYSCFG: MtrrVarDramEn=%u MtrrFixDramModEn=%u MtrrFixDramEn=%u\n\0"
                .as_ptr(),
            var_dram,
            fix_mod,
            fix_en,
        );
    }
}

// -- FFI exports --

/// Initialise the AMD SEV interface driver.
///
/// Detects SEV capability via CPUID 0x8000001F, reads the SEV_STATUS MSR
/// to determine active encryption state, and reports the C-bit position,
/// maximum encrypted guest count, and minimum SEV ASID.
///
/// Returns 0 on success, -1 if SEV is not supported by the CPU.
#[unsafe(no_mangle)]
pub extern "C" fn amd_sev_init() -> i32 {
    log("amd_sev: initialising AMD SEV interface driver");

    // Check that the extended CPUID leaf for SEV is available.
    if !sev_leaf_available() {
        log("amd_sev: CPUID leaf 0x8000001F not available (SEV not supported)");
        return -1;
    }

    // Query SEV capabilities from CPUID.
    let (eax, ebx, ecx, edx) = query_sev_cpuid();

    let sev_supported = eax & SEV_BIT != 0;
    let sev_es_supported = eax & SEV_ES_BIT != 0;
    let sev_snp_supported = eax & SEV_SNP_BIT != 0;
    let vte_supported = eax & VTE_BIT != 0;

    if !sev_supported {
        log("amd_sev: CPUID 0x8000001F present but SEV bit not set");
        return -1;
    }

    let c_bit_position = ebx & 0x3F;
    let max_encrypted_guests = ecx;
    let min_asid = edx;

    unsafe {
        fut_printf(
            b"amd_sev: CPUID capabilities: SEV=%u SEV-ES=%u SEV-SNP=%u VTE=%u\n\0".as_ptr(),
            sev_supported as u32,
            sev_es_supported as u32,
            sev_snp_supported as u32,
            vte_supported as u32,
        );
        fut_printf(
            b"amd_sev: C-bit position: %u\n\0".as_ptr(),
            c_bit_position,
        );
        fut_printf(
            b"amd_sev: max encrypted guests: %u\n\0".as_ptr(),
            max_encrypted_guests,
        );
        fut_printf(
            b"amd_sev: min ASID for SEV guests: %u\n\0".as_ptr(),
            min_asid,
        );
    }

    // Read the SEV_STATUS MSR to check if SEV is currently active.
    let sev_status = read_sev_status();
    let sev_active = sev_status & SEV_STATUS_SEV_ENABLED != 0;
    let sev_es_active = sev_status & SEV_STATUS_SEV_ES_ENABLED != 0;
    let sev_snp_active = sev_status & SEV_STATUS_SEV_SNP_ENABLED != 0;

    unsafe {
        fut_printf(
            b"amd_sev: SEV_STATUS MSR=0x%08lx: SEV=%u SEV-ES=%u SEV-SNP=%u\n\0".as_ptr(),
            sev_status,
            sev_active as u32,
            sev_es_active as u32,
            sev_snp_active as u32,
        );
    }

    if sev_active {
        log("amd_sev: SEV is currently ACTIVE on this platform");
    } else {
        log("amd_sev: SEV is supported but not currently active");
    }

    // Log SYSCFG for diagnostic purposes.
    log_syscfg_info();

    // Store driver state.
    let state = AmdSev {
        leaf_available: true,
        cpuid_eax: eax,
        c_bit_position,
        max_encrypted_guests,
        min_asid,
        sev_active,
        sev_es_active,
        sev_snp_active,
        api_major: 0,
        api_minor: 0,
    };

    unsafe {
        (*STATE.get()) = Some(state);
    }

    log("amd_sev: driver initialised successfully");
    0
}

/// Retrieve aggregated SEV information.
///
/// `out` - Pointer to a `SevInfo` struct to receive the result.
///
/// Returns 0 on success, -19 (ENODEV) if the driver is not initialised,
/// -22 (EINVAL) if the output pointer is null.
#[unsafe(no_mangle)]
pub extern "C" fn amd_sev_get_info(out: *mut SevInfo) -> i32 {
    if out.is_null() {
        return -22; // EINVAL
    }

    let state = match unsafe { (*STATE.get()).as_ref() } {
        Some(s) => s,
        None => return -19, // ENODEV
    };

    let info = SevInfo {
        sev_supported: state.cpuid_eax & SEV_BIT != 0,
        sev_es_supported: state.cpuid_eax & SEV_ES_BIT != 0,
        sev_snp_supported: state.cpuid_eax & SEV_SNP_BIT != 0,
        sev_enabled: state.sev_active,
        c_bit_position: state.c_bit_position,
        max_encrypted_guests: state.max_encrypted_guests,
        min_asid: state.min_asid,
        api_major: state.api_major,
        api_minor: state.api_minor,
    };

    unsafe {
        core::ptr::write(out, info);
    }

    0
}

/// Check whether SEV is supported by the CPU.
///
/// Returns true if the CPU advertises SEV support via CPUID 0x8000001F.
#[unsafe(no_mangle)]
pub extern "C" fn amd_sev_is_supported() -> bool {
    match unsafe { (*STATE.get()).as_ref() } {
        Some(s) => s.cpuid_eax & SEV_BIT != 0,
        None => false,
    }
}

/// Check whether SEV is currently active (enabled in the SEV_STATUS MSR).
///
/// Returns true if SEV encryption is active on this platform.
#[unsafe(no_mangle)]
pub extern "C" fn amd_sev_is_active() -> bool {
    match unsafe { (*STATE.get()).as_ref() } {
        Some(s) => s.sev_active,
        None => false,
    }
}

/// Return the C-bit position in page table entries.
///
/// The C-bit (encryption bit) position tells the page table walker which
/// bit in a physical address entry marks a page as encrypted. Typically
/// bit 47 or bit 51 depending on the CPU model.
///
/// Returns 0 if the driver is not initialised.
#[unsafe(no_mangle)]
pub extern "C" fn amd_sev_c_bit() -> u32 {
    match unsafe { (*STATE.get()).as_ref() } {
        Some(s) => s.c_bit_position,
        None => 0,
    }
}

/// Return the maximum number of encrypted guests supported simultaneously.
///
/// Returns 0 if the driver is not initialised.
#[unsafe(no_mangle)]
pub extern "C" fn amd_sev_max_guests() -> u32 {
    match unsafe { (*STATE.get()).as_ref() } {
        Some(s) => s.max_encrypted_guests,
        None => 0,
    }
}
