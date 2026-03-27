// SPDX-License-Identifier: MPL-2.0
//
// x86-64 CPUID Information and Feature Detection Driver for Futura OS
//
// Queries the processor via the CPUID instruction to enumerate vendor
// identification, processor family/model/stepping, instruction-set
// feature flags, cache topology, core/thread counts, address widths,
// and AMD-specific capabilities (SEV, SVM, invariant TSC).
//
// CPUID leaves queried:
//   0x0000_0000  Max standard leaf, vendor string
//   0x0000_0001  Family/model/stepping, base feature flags (ECX/EDX)
//   0x0000_0007  Structured extended features (EBX/ECX, sub-leaf 0)
//   0x0000_000D  XSAVE state component sizes (sub-leaf 0)
//   0x8000_0000  Max extended leaf
//   0x8000_0001  Extended feature flags (ECX/EDX)
//   0x8000_0002  Processor brand string (chars  0-15)
//   0x8000_0003  Processor brand string (chars 16-31)
//   0x8000_0004  Processor brand string (chars 32-47)
//   0x8000_0005  L1 cache / TLB identifiers (AMD)
//   0x8000_0006  L2/L3 cache identifiers (AMD)
//   0x8000_0007  Advanced Power Management (invariant TSC bit 8)
//   0x8000_0008  Virtual/physical address sizes, core count
//   0x8000_001E  Extended APIC topology (threads per compute unit)
//   0x8000_001F  AMD SEV capabilities
//
// AMD family/model decoding:
//   Family 17h (0x17) = Zen, Zen+, Zen 2   (AM4)
//   Family 19h (0x19) = Zen 3, Zen 3+      (AM4 / AM5)
//   Family 1Ah (0x1A) = Zen 4, Zen 5       (AM5)

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(unexpected_cfgs)]

use core::cell::UnsafeCell;

use common::log;

unsafe extern "C" {
    fn fut_printf(fmt: *const u8, ...);
}

// ── StaticCell wrapper (avoids `static mut`) ──

struct StaticCell<T>(UnsafeCell<T>);
unsafe impl<T> Sync for StaticCell<T> {}
impl<T> StaticCell<T> {
    const fn new(v: T) -> Self {
        Self(UnsafeCell::new(v))
    }
    fn get(&self) -> *mut T {
        self.0.get()
    }
}

// ── Feature index constants ──

const FEATURE_SSE3: u32 = 0;
const FEATURE_AVX: u32 = 1;
const FEATURE_AVX2: u32 = 2;
const FEATURE_AES: u32 = 3;
const FEATURE_SHA: u32 = 4;
const FEATURE_RDRAND: u32 = 5;
const FEATURE_RDSEED: u32 = 6;
const FEATURE_SEV: u32 = 7;
const FEATURE_SVM: u32 = 8;
const FEATURE_INVARIANT_TSC: u32 = 9;

// ── CpuInfo structure ──

/// Processor information gathered from CPUID leaves.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct CpuInfo {
    /// Vendor string, e.g. "AuthenticAMD" (null-terminated, 13 bytes).
    pub vendor: [u8; 13],
    /// Processor brand string (null-terminated, 49 bytes).
    pub brand: [u8; 49],
    /// Processor family (AMD extended-family decoded).
    pub family: u32,
    /// Processor model (AMD extended-model decoded).
    pub model: u32,
    /// Processor stepping.
    pub stepping: u32,
    /// Physical core count.
    pub cores: u32,
    /// Logical thread count.
    pub threads: u32,
    /// Physical address width in bits.
    pub phys_addr_bits: u8,
    /// Virtual address width in bits.
    pub virt_addr_bits: u8,
    /// SSE3 support.
    pub has_sse3: bool,
    /// AVX support.
    pub has_avx: bool,
    /// AVX2 support.
    pub has_avx2: bool,
    /// AES-NI support.
    pub has_aes: bool,
    /// SHA extensions support.
    pub has_sha: bool,
    /// RDRAND support.
    pub has_rdrand: bool,
    /// RDSEED support.
    pub has_rdseed: bool,
    /// AMD SEV support.
    pub has_sev: bool,
    /// AMD SEV-ES support.
    pub has_sev_es: bool,
    /// L1 data cache size in KiB.
    pub l1d_kb: u32,
    /// L1 instruction cache size in KiB.
    pub l1i_kb: u32,
    /// L2 cache size in KiB.
    pub l2_kb: u32,
    /// L3 cache size in KiB (reported in 512 KiB units by CPUID, converted).
    pub l3_kb: u32,
}

impl CpuInfo {
    const fn zero() -> Self {
        Self {
            vendor: [0u8; 13],
            brand: [0u8; 49],
            family: 0,
            model: 0,
            stepping: 0,
            cores: 0,
            threads: 0,
            phys_addr_bits: 0,
            virt_addr_bits: 0,
            has_sse3: false,
            has_avx: false,
            has_avx2: false,
            has_aes: false,
            has_sha: false,
            has_rdrand: false,
            has_rdseed: false,
            has_sev: false,
            has_sev_es: false,
            l1d_kb: 0,
            l1i_kb: 0,
            l2_kb: 0,
            l3_kb: 0,
        }
    }
}

// ── Driver state ──

struct DriverState {
    initialized: bool,
    info: CpuInfo,
    /// AMD SVM (Secure Virtual Machine) support from leaf 0x8000_0001 ECX bit 2.
    has_svm: bool,
    /// Invariant TSC from leaf 0x8000_0007 EDX bit 8.
    has_invariant_tsc: bool,
    /// Maximum standard CPUID leaf.
    max_std_leaf: u32,
    /// Maximum extended CPUID leaf.
    max_ext_leaf: u32,
}

impl DriverState {
    const fn new() -> Self {
        Self {
            initialized: false,
            info: CpuInfo::zero(),
            has_svm: false,
            has_invariant_tsc: false,
            max_std_leaf: 0,
            max_ext_leaf: 0,
        }
    }
}

static STATE: StaticCell<DriverState> = StaticCell::new(DriverState::new());

// ── CPUID instruction wrapper ──
//
// LLVM reserves RBX for its own use (PIC base register), so we must
// save and restore it manually around the `cpuid` instruction.

#[derive(Copy, Clone)]
struct CpuidResult {
    eax: u32,
    ebx: u32,
    ecx: u32,
    edx: u32,
}

/// Execute CPUID with leaf `eax` and sub-leaf `ecx`.
#[inline]
fn cpuid(leaf: u32, sub_leaf: u32) -> CpuidResult {
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
            inout("ecx") sub_leaf => ecx,
            out("edx") edx,
            options(nostack, preserves_flags),
        );
    }
    CpuidResult { eax, ebx, ecx, edx }
}

// ── Helper: copy bytes into a fixed buffer ──

fn copy_bytes(dst: &mut [u8], src: &[u8]) {
    let len = if src.len() < dst.len() {
        src.len()
    } else {
        dst.len()
    };
    let mut i = 0;
    while i < len {
        dst[i] = src[i];
        i += 1;
    }
}

/// Store a u32 as 4 little-endian bytes at `dst[offset..]`.
fn store_le32(dst: &mut [u8], offset: usize, val: u32) {
    let bytes = val.to_le_bytes();
    let mut i = 0;
    while i < 4 && offset + i < dst.len() {
        dst[offset + i] = bytes[i];
        i += 1;
    }
}

// ── Leaf parsers ──

/// Leaf 0x00: vendor string and max standard leaf.
fn parse_leaf_00(state: &mut DriverState) {
    let r = cpuid(0x0000_0000, 0);
    state.max_std_leaf = r.eax;

    // Vendor string is EBX + EDX + ECX (12 ASCII chars).
    store_le32(&mut state.info.vendor, 0, r.ebx);
    store_le32(&mut state.info.vendor, 4, r.edx);
    store_le32(&mut state.info.vendor, 8, r.ecx);
    state.info.vendor[12] = 0; // null terminator
}

/// Leaf 0x01: family/model/stepping and base feature flags.
fn parse_leaf_01(state: &mut DriverState) {
    if state.max_std_leaf < 1 {
        return;
    }
    let r = cpuid(0x0000_0001, 0);

    // EAX: signature
    //   [3:0]   stepping
    //   [7:4]   base model
    //   [11:8]  base family
    //   [19:16] extended model
    //   [27:20] extended family
    let stepping = r.eax & 0xF;
    let base_model = (r.eax >> 4) & 0xF;
    let base_family = (r.eax >> 8) & 0xF;
    let ext_model = (r.eax >> 16) & 0xF;
    let ext_family = (r.eax >> 20) & 0xFF;

    // AMD extended family/model decode:
    //   If base_family == 0xF: family = base_family + ext_family
    //                          model  = (ext_model << 4) | base_model
    //   Otherwise:             family = base_family, model = base_model
    if base_family == 0xF {
        state.info.family = base_family + ext_family;
        state.info.model = (ext_model << 4) | base_model;
    } else {
        state.info.family = base_family;
        state.info.model = base_model;
    }
    state.info.stepping = stepping;

    // ECX feature flags (leaf 0x01)
    let ecx = r.ecx;
    state.info.has_sse3 = ecx & (1 << 0) != 0;       // bit  0: SSE3
    state.info.has_aes = ecx & (1 << 25) != 0;        // bit 25: AES-NI
    state.info.has_avx = ecx & (1 << 28) != 0;        // bit 28: AVX
    state.info.has_rdrand = ecx & (1 << 30) != 0;     // bit 30: RDRAND
}

/// Leaf 0x07: structured extended features.
fn parse_leaf_07(state: &mut DriverState) {
    if state.max_std_leaf < 7 {
        return;
    }
    let r = cpuid(0x0000_0007, 0);

    // EBX feature flags (leaf 0x07, sub-leaf 0)
    let ebx = r.ebx;
    state.info.has_avx2 = ebx & (1 << 5) != 0;       // bit  5: AVX2
    state.info.has_sha = ebx & (1 << 29) != 0;        // bit 29: SHA
    state.info.has_rdseed = ebx & (1 << 18) != 0;     // bit 18: RDSEED
}

/// Leaf 0x80000000: max extended leaf.
fn parse_leaf_ext_max(state: &mut DriverState) {
    let r = cpuid(0x8000_0000, 0);
    state.max_ext_leaf = r.eax;
}

/// Leaf 0x80000001: extended feature flags (AMD).
fn parse_leaf_ext_features(state: &mut DriverState) {
    if state.max_ext_leaf < 0x8000_0001 {
        return;
    }
    let r = cpuid(0x8000_0001, 0);

    // ECX: AMD extended features
    let ecx = r.ecx;
    state.has_svm = ecx & (1 << 2) != 0; // bit 2: SVM (Secure Virtual Machine)

    // EDX: extended feature flags
    // bit 20: NX, bit 27: RDTSCP, bit 29: Long Mode, etc.
    // (stored implicitly; we only track SVM and a few others explicitly)
}

/// Leaves 0x80000002-0x80000004: processor brand string (48 chars).
fn parse_brand_string(state: &mut DriverState) {
    if state.max_ext_leaf < 0x8000_0004 {
        return;
    }

    let mut offset = 0usize;
    let mut leaf = 0x8000_0002u32;
    while leaf <= 0x8000_0004 {
        let r = cpuid(leaf, 0);
        store_le32(&mut state.info.brand, offset, r.eax);
        store_le32(&mut state.info.brand, offset + 4, r.ebx);
        store_le32(&mut state.info.brand, offset + 8, r.ecx);
        store_le32(&mut state.info.brand, offset + 12, r.edx);
        offset += 16;
        leaf += 1;
    }
    state.info.brand[48] = 0; // null terminator
}

/// Leaf 0x80000005: L1 cache information (AMD specific).
///
/// ECX = L1 data cache: bits [31:24] = size in KiB
/// EDX = L1 instruction cache: bits [31:24] = size in KiB
fn parse_l1_cache(state: &mut DriverState) {
    if state.max_ext_leaf < 0x8000_0005 {
        return;
    }
    let r = cpuid(0x8000_0005, 0);
    state.info.l1d_kb = (r.ecx >> 24) & 0xFF;
    state.info.l1i_kb = (r.edx >> 24) & 0xFF;
}

/// Leaf 0x80000006: L2/L3 cache information (AMD specific).
///
/// ECX = L2 cache: bits [31:16] = size in KiB
/// EDX = L3 cache: bits [31:18] = size in 512 KiB units
fn parse_l2_l3_cache(state: &mut DriverState) {
    if state.max_ext_leaf < 0x8000_0006 {
        return;
    }
    let r = cpuid(0x8000_0006, 0);
    state.info.l2_kb = (r.ecx >> 16) & 0xFFFF;

    // L3: bits [31:18] give size in 512 KiB increments.
    let l3_half_mb = (r.edx >> 18) & 0x3FFF;
    state.info.l3_kb = l3_half_mb * 512;
}

/// Leaf 0x80000007: Advanced Power Management.
///
/// EDX bit 8 = invariant TSC.
fn parse_apm(state: &mut DriverState) {
    if state.max_ext_leaf < 0x8000_0007 {
        return;
    }
    let r = cpuid(0x8000_0007, 0);
    state.has_invariant_tsc = r.edx & (1 << 8) != 0;
}

/// Leaf 0x80000008: virtual/physical address sizes and core count.
///
/// EAX[7:0]  = physical address bits
/// EAX[15:8] = virtual address bits
/// ECX[7:0]  = NC (number of cores minus one) — if SVM/CMP legacy mode
fn parse_addr_sizes(state: &mut DriverState) {
    if state.max_ext_leaf < 0x8000_0008 {
        return;
    }
    let r = cpuid(0x8000_0008, 0);
    state.info.phys_addr_bits = (r.eax & 0xFF) as u8;
    state.info.virt_addr_bits = ((r.eax >> 8) & 0xFF) as u8;

    // ECX[7:0] = NC (number of cores - 1). Use as fallback core count.
    let nc = (r.ecx & 0xFF) + 1;
    if state.info.cores == 0 {
        state.info.cores = nc;
    }
}

/// Leaf 0x8000001E: Extended APIC topology (AMD).
///
/// EBX[15:8] = threads per compute unit minus one.
fn parse_apic_topology(state: &mut DriverState) {
    if state.max_ext_leaf < 0x8000_001E {
        return;
    }
    let r = cpuid(0x8000_001E, 0);

    // EBX[15:8] = ThreadsPerComputeUnit - 1.
    let threads_per_cu = ((r.ebx >> 8) & 0xFF) + 1;

    // Total logical threads = cores * threads_per_compute_unit.
    if state.info.cores > 0 {
        state.info.threads = state.info.cores * threads_per_cu;
    }
}

/// Leaf 0x8000001F: AMD Secure Encrypted Virtualization (SEV) capabilities.
///
/// EAX bit 1 = SEV supported
/// EAX bit 3 = SEV-ES supported
fn parse_sev(state: &mut DriverState) {
    if state.max_ext_leaf < 0x8000_001F {
        return;
    }
    let r = cpuid(0x8000_001F, 0);
    state.info.has_sev = r.eax & (1 << 1) != 0;
    state.info.has_sev_es = r.eax & (1 << 3) != 0;
}

/// Derive initial core/thread count from leaf 0x01 EBX if no better source.
fn parse_initial_topology(state: &mut DriverState) {
    if state.max_std_leaf < 1 {
        return;
    }
    let r = cpuid(0x0000_0001, 0);

    // EBX[23:16] = maximum number of addressable logical processor IDs.
    let max_logical = (r.ebx >> 16) & 0xFF;
    if max_logical > 0 && state.info.threads == 0 {
        state.info.threads = max_logical;
    }
}

// ── Family name helper for logging ──

fn family_name(family: u32) -> &'static [u8] {
    match family {
        0x17 => b"Zen/Zen+/Zen2 (Family 17h)\0",
        0x19 => b"Zen3/Zen3+ (Family 19h)\0",
        0x1A => b"Zen4/Zen5 (Family 1Ah)\0",
        _ => b"Unknown\0",
    }
}

// ── Exported C API ──

/// Initialize the CPUID driver.  Queries all relevant CPUID leaves and
/// populates the internal CpuInfo structure.
///
/// Returns 0 on success.
#[unsafe(no_mangle)]
pub extern "C" fn x86_cpuid_init() -> i32 {
    log("x86_cpuid: initializing CPUID driver");

    let state = unsafe { &mut *STATE.get() };

    // Query leaves in dependency order.
    parse_leaf_00(state);
    parse_leaf_01(state);
    parse_leaf_07(state);
    parse_leaf_ext_max(state);
    parse_leaf_ext_features(state);
    parse_brand_string(state);
    parse_l1_cache(state);
    parse_l2_l3_cache(state);
    parse_apm(state);
    parse_addr_sizes(state);
    parse_apic_topology(state);
    parse_sev(state);
    parse_initial_topology(state);

    // Ensure threads >= cores.
    if state.info.threads < state.info.cores {
        state.info.threads = state.info.cores;
    }

    state.initialized = true;

    // Log summary.
    unsafe {
        fut_printf(
            b"x86_cpuid: vendor=%s\n\0".as_ptr(),
            state.info.vendor.as_ptr(),
        );
        fut_printf(
            b"x86_cpuid: brand=%s\n\0".as_ptr(),
            state.info.brand.as_ptr(),
        );
        fut_printf(
            b"x86_cpuid: family=0x%x (%s) model=0x%x stepping=%u\n\0".as_ptr(),
            state.info.family,
            family_name(state.info.family).as_ptr(),
            state.info.model,
            state.info.stepping,
        );
        fut_printf(
            b"x86_cpuid: cores=%u threads=%u\n\0".as_ptr(),
            state.info.cores,
            state.info.threads,
        );
        fut_printf(
            b"x86_cpuid: phys_addr=%u bits, virt_addr=%u bits\n\0".as_ptr(),
            state.info.phys_addr_bits as u32,
            state.info.virt_addr_bits as u32,
        );
        fut_printf(
            b"x86_cpuid: L1d=%u KiB, L1i=%u KiB, L2=%u KiB, L3=%u KiB\n\0".as_ptr(),
            state.info.l1d_kb,
            state.info.l1i_kb,
            state.info.l2_kb,
            state.info.l3_kb,
        );
        fut_printf(
            b"x86_cpuid: SSE3=%u AVX=%u AVX2=%u AES=%u SHA=%u RDRAND=%u RDSEED=%u\n\0".as_ptr(),
            state.info.has_sse3 as u32,
            state.info.has_avx as u32,
            state.info.has_avx2 as u32,
            state.info.has_aes as u32,
            state.info.has_sha as u32,
            state.info.has_rdrand as u32,
            state.info.has_rdseed as u32,
        );
        fut_printf(
            b"x86_cpuid: SVM=%u SEV=%u SEV-ES=%u invariant_TSC=%u\n\0".as_ptr(),
            state.has_svm as u32,
            state.info.has_sev as u32,
            state.info.has_sev_es as u32,
            state.has_invariant_tsc as u32,
        );
    }

    log("x86_cpuid: driver initialized");
    0
}

/// Copy the full CpuInfo structure to the caller-provided buffer.
///
/// Returns 0 on success, -1 on failure.
#[unsafe(no_mangle)]
pub extern "C" fn x86_cpuid_get_info(out: *mut CpuInfo) -> i32 {
    if out.is_null() {
        return -1;
    }
    let state = unsafe { &*STATE.get() };
    if !state.initialized {
        return -1;
    }
    unsafe {
        *out = state.info;
    }
    0
}

/// Copy the vendor string into `buf` (up to `max_len` bytes including NUL).
///
/// Returns the number of bytes written (excluding NUL), or -1 on error.
#[unsafe(no_mangle)]
pub extern "C" fn x86_cpuid_vendor(buf: *mut u8, max_len: u32) -> i32 {
    if buf.is_null() || max_len == 0 {
        return -1;
    }
    let state = unsafe { &*STATE.get() };
    if !state.initialized {
        return -1;
    }

    let vendor = &state.info.vendor;
    // Find length of vendor string (up to 12 chars).
    let mut len = 0usize;
    while len < 12 && vendor[len] != 0 {
        len += 1;
    }

    let copy_len = if len < (max_len as usize - 1) {
        len
    } else {
        (max_len as usize).saturating_sub(1)
    };

    let dst = unsafe { core::slice::from_raw_parts_mut(buf, max_len as usize) };
    let mut i = 0;
    while i < copy_len {
        dst[i] = vendor[i];
        i += 1;
    }
    dst[copy_len] = 0;

    copy_len as i32
}

/// Copy the brand string into `buf` (up to `max_len` bytes including NUL).
///
/// Returns the number of bytes written (excluding NUL), or -1 on error.
#[unsafe(no_mangle)]
pub extern "C" fn x86_cpuid_brand(buf: *mut u8, max_len: u32) -> i32 {
    if buf.is_null() || max_len == 0 {
        return -1;
    }
    let state = unsafe { &*STATE.get() };
    if !state.initialized {
        return -1;
    }

    let brand = &state.info.brand;
    // Find length of brand string (up to 48 chars).
    let mut len = 0usize;
    while len < 48 && brand[len] != 0 {
        len += 1;
    }

    let copy_len = if len < (max_len as usize - 1) {
        len
    } else {
        (max_len as usize).saturating_sub(1)
    };

    let dst = unsafe { core::slice::from_raw_parts_mut(buf, max_len as usize) };
    let mut i = 0;
    while i < copy_len {
        dst[i] = brand[i];
        i += 1;
    }
    dst[copy_len] = 0;

    copy_len as i32
}

/// Check whether a specific CPU feature is present.
///
/// Feature indices:
///   0 = SSE3, 1 = AVX, 2 = AVX2, 3 = AES, 4 = SHA,
///   5 = RDRAND, 6 = RDSEED, 7 = SEV, 8 = SVM, 9 = INVARIANT_TSC
///
/// Returns `true` if the feature is supported, `false` otherwise.
#[unsafe(no_mangle)]
pub extern "C" fn x86_cpuid_has_feature(feature: u32) -> bool {
    let state = unsafe { &*STATE.get() };
    if !state.initialized {
        return false;
    }

    match feature {
        FEATURE_SSE3 => state.info.has_sse3,
        FEATURE_AVX => state.info.has_avx,
        FEATURE_AVX2 => state.info.has_avx2,
        FEATURE_AES => state.info.has_aes,
        FEATURE_SHA => state.info.has_sha,
        FEATURE_RDRAND => state.info.has_rdrand,
        FEATURE_RDSEED => state.info.has_rdseed,
        FEATURE_SEV => state.info.has_sev,
        FEATURE_SVM => state.has_svm,
        FEATURE_INVARIANT_TSC => state.has_invariant_tsc,
        _ => false,
    }
}

/// Return the cache size for the given level in KiB.
///
///   level 1 = L1 data cache
///   level 2 = L2 cache
///   level 3 = L3 cache
///
/// Returns 0 for unknown levels or if the driver is not initialized.
#[unsafe(no_mangle)]
pub extern "C" fn x86_cpuid_cache_size(level: u32) -> u32 {
    let state = unsafe { &*STATE.get() };
    if !state.initialized {
        return 0;
    }

    match level {
        1 => state.info.l1d_kb,
        2 => state.info.l2_kb,
        3 => state.info.l3_kb,
        _ => 0,
    }
}

/// Return the number of physical CPU cores.
///
/// Returns 0 if the driver is not initialized.
#[unsafe(no_mangle)]
pub extern "C" fn x86_cpuid_core_count() -> u32 {
    let state = unsafe { &*STATE.get() };
    if !state.initialized {
        return 0;
    }
    state.info.cores
}

/// Return the number of logical threads.
///
/// Returns 0 if the driver is not initialized.
#[unsafe(no_mangle)]
pub extern "C" fn x86_cpuid_thread_count() -> u32 {
    let state = unsafe { &*STATE.get() };
    if !state.initialized {
        return 0;
    }
    state.info.threads
}
