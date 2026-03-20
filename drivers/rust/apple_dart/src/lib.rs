// SPDX-License-Identifier: MPL-2.0
//! Apple Silicon DART (DMA Address Remapping Table) IOMMU driver for Futura OS
//!
//! DART is the IOMMU found in Apple M1/M2/M3 SoCs.  It protects physical
//! memory from DMA by mapping device-visible IOVAs to physical addresses
//! for each peripheral device.
//!
//! Architecture notes
//! ------------------
//! - Up to 16 DMA streams per DART instance (one per device function)
//! - 3-level page table (L1→L2→L3) with 4KB pages
//! - Per-stream translation: each stream has its own TCR + TTBR registers
//! - Translation can be enabled, disabled, or bypassed per stream
//! - TLB invalidation is explicit: write to DART_TLB_OP, then poll BUSY
//! - Two DART variants: t8020 (M1/M2) and t8110 (M1 Pro/Max/Ultra)
//!   — differences are in the TCR bypass bit position; handled by `variant`
//!
//! Page table layout
//! -----------------
//! - L1 table: 1 entry per 1GB; each entry → L2 table (4KB, 512 entries)
//! - L2 table: 1 entry per 2MB; each entry → L3 table (4KB, 512 entries)
//! - L3 table: 1 entry per 4KB page; bits[47:12] = physical PFN
//! - PTE valid bit: bit 0; read-only: bit 1; no-execute: bit 5
//!
//! Register map
//! ------------
//! 0x0000  DART_PARAMS1      — revision, page-size field, stream count
//! 0x0004  DART_PARAMS2      — features: bypass capability, etc.
//! 0x0020  DART_TLB_OP       — TLB invalidation command (FLUSH_ALL=0x1)
//! 0x0028  DART_TLB_OP_BUSY  — bit 2: flush in progress
//! 0x0098  DART_SIDMASK      — stream-ID enable mask (1 = stream active)
//! Per-stream block at 0x0200 + stream * 0x20:
//!   +0x00  SID_TCR           — translation control (ENABLED/BYPASS bits)
//!   +0x04  SID_TTBR0         — L1 page table physical address (low 32)
//!   +0x08  SID_TTBR1         — L1 page table physical address (high 32)
//!   +0x10  SID_TTBR_VALID    — bit 0: TTBR valid (enable translation)
//!
//! Reference: Asahi Linux `drivers/iommu/apple-dart.c` (Sven Peter)

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(dead_code)]

use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicBool, Ordering};

// ---------------------------------------------------------------------------
// Register offsets
// ---------------------------------------------------------------------------

const DART_PARAMS1:     usize = 0x0000;
const DART_PARAMS2:     usize = 0x0004;
const DART_TLB_OP:      usize = 0x0020;
const DART_TLB_OP_BUSY: usize = 0x0028;
const DART_SIDMASK:     usize = 0x0098;

// Per-stream register block base and stride
const DART_SID_BASE:   usize = 0x0200;
const DART_SID_STRIDE: usize = 0x0020;

// Per-stream offsets (relative to SID block base)
const SID_TCR:          usize = 0x00;
const SID_TTBR0:        usize = 0x04;  // Low 32 bits of L1 table phys addr
const SID_TTBR1:        usize = 0x08;  // High 32 bits
const SID_TTBR_VALID:   usize = 0x10;

// ---------------------------------------------------------------------------
// Register bit definitions
// ---------------------------------------------------------------------------

// DART_TLB_OP commands
const TLB_OP_FLUSH_ALL: u32 = 1 << 0;

// DART_TLB_OP_BUSY bits
const TLB_BUSY: u32 = 1 << 2;

// SID_TCR bits (t8020 variant, used in M1/M2)
const TCR_TRANSLATE_ENABLE:   u32 = 1 << 7;   // Enable translation for this stream
const TCR_BYPASS_DART_8020:   u32 = 1 << 8;   // Bypass DART (passthrough) — t8020
const TCR_BYPASS_DART_8110:   u32 = 1 << 12;  // Bypass DART (passthrough) — t8110

// SID_TTBR_VALID
const TTBR_VALID: u32 = 1 << 0;

// ---------------------------------------------------------------------------
// Page table constants
// ---------------------------------------------------------------------------

const PAGE_SHIFT:  usize = 12;
const PAGE_SIZE:   usize = 1 << PAGE_SHIFT;
const L3_ENTRIES:  usize = 512;
const L2_ENTRIES:  usize = 512;
const L1_ENTRIES:  usize = 4;   // Cover up to 4GB IOVA space

// PTE flags
const PTE_VALID:   u64 = 1 << 0;
const PTE_RDONLY:  u64 = 1 << 1;
const PTE_NOEXEC:  u64 = 1 << 5;

// Protection flags exposed to callers
pub const DART_PROT_READ:  u32 = 1 << 0;
pub const DART_PROT_WRITE: u32 = 1 << 1;
pub const DART_PROT_EXEC:  u32 = 1 << 2;

// ---------------------------------------------------------------------------
// DART hardware variant
// ---------------------------------------------------------------------------

#[derive(Copy, Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum DartVariant {
    /// Apple T8020 (M1, M2 base) — bypass bit at TCR[8]
    T8020 = 0,
    /// Apple T8110 (M1 Pro/Max/Ultra, M2 Pro/Max) — bypass bit at TCR[12]
    T8110 = 1,
}

// ---------------------------------------------------------------------------
// Page table allocator
// ---------------------------------------------------------------------------
//
// We use a simple bump allocator backed by a static pool.  On real hardware
// the kernel would allocate physical frames; here we embed the page tables
// in the driver's BSS segment.

const PT_POOL_PAGES: usize = 64;  // 64 * 4KB = 256KB of page table space

// 64-byte-aligned 4KB pages; must be physically contiguous for DART.
#[repr(C, align(4096))]
struct PagePool {
    pages: [[u64; 512]; PT_POOL_PAGES],
}

static mut G_PT_POOL: PagePool = PagePool { pages: [[0u64; 512]; PT_POOL_PAGES] };
static mut G_PT_POOL_NEXT: usize = 0;

/// Allocate one 4KB page from the static pool; returns (virt_ptr, phys_addr).
/// Panics (loops forever) if pool is exhausted — acceptable for a bare-metal
/// driver that will never exhaust a modest, pre-sized pool.
fn alloc_page() -> (*mut u64, u64) {
    let idx = unsafe { G_PT_POOL_NEXT };
    if idx >= PT_POOL_PAGES {
        // Out of pool: spin (should never happen in practice)
        loop { unsafe { core::arch::asm!("nop") }; }
    }
    unsafe { G_PT_POOL_NEXT = idx + 1; }
    let ptr = unsafe { G_PT_POOL.pages[idx].as_mut_ptr() };
    // Physical address: for identity-mapped kernel BSS, virt == phys
    let phys = ptr as u64;
    // Zero-fill
    unsafe {
        for i in 0..512usize {
            write_volatile(ptr.add(i), 0u64);
        }
    }
    (ptr, phys)
}

// ---------------------------------------------------------------------------
// Per-stream state
// ---------------------------------------------------------------------------

#[derive(Copy, Clone)]
struct StreamState {
    enabled:   bool,
    bypass:    bool,
    /// Physical address of L1 page table (NULL = not allocated)
    l1_phys:   u64,
    /// Virtual pointer to L1 table (for page table walks)
    l1_virt:   *mut u64,
}

unsafe impl Send for StreamState {}
unsafe impl Sync for StreamState {}

impl StreamState {
    const fn empty() -> Self {
        Self {
            enabled: false,
            bypass:  false,
            l1_phys: 0,
            l1_virt: core::ptr::null_mut(),
        }
    }
}

// ---------------------------------------------------------------------------
// AppleDart — main driver state
// ---------------------------------------------------------------------------

const MAX_STREAMS: usize = 16;

pub struct AppleDart {
    base:       usize,
    num_streams: u32,
    variant:    DartVariant,
    ready:      AtomicBool,
    streams:    [StreamState; MAX_STREAMS],
}

impl AppleDart {
    // ---- MMIO helpers ----

    fn r32(&self, off: usize) -> u32 {
        unsafe { read_volatile((self.base + off) as *const u32) }
    }

    fn w32(&self, off: usize, v: u32) {
        unsafe { write_volatile((self.base + off) as *mut u32, v) }
    }

    fn sid_base(&self, sid: u32) -> usize {
        self.base + DART_SID_BASE + (sid as usize) * DART_SID_STRIDE
    }

    fn sid_r32(&self, sid: u32, off: usize) -> u32 {
        unsafe { read_volatile((self.sid_base(sid) + off) as *const u32) }
    }

    fn sid_w32(&self, sid: u32, off: usize, v: u32) {
        unsafe { write_volatile((self.sid_base(sid) + off) as *mut u32, v) }
    }

    // ---- Initialization ----

    pub fn init(&mut self) {
        // Bypass all streams initially (safe default — devices can DMA freely
        // until a driver explicitly enables translation for their stream)
        let bypass_bit = match self.variant {
            DartVariant::T8020 => TCR_BYPASS_DART_8020,
            DartVariant::T8110 => TCR_BYPASS_DART_8110,
        };

        for sid in 0..self.num_streams {
            self.sid_w32(sid, SID_TCR, bypass_bit);
            self.streams[sid as usize].bypass = true;
        }

        self.flush_tlb_all();
        self.ready.store(true, Ordering::Release);
    }

    // ---- TLB management ----

    /// Flush all TLB entries for all streams.
    pub fn flush_tlb_all(&self) {
        // DSB before TLB invalidation
        unsafe { core::arch::asm!("dsb sy", options(nostack, nomem)) };
        self.w32(DART_TLB_OP, TLB_OP_FLUSH_ALL);
        // Poll until flush completes
        for _ in 0..100_000u32 {
            if self.r32(DART_TLB_OP_BUSY) & TLB_BUSY == 0 {
                break;
            }
        }
        unsafe { core::arch::asm!("dsb sy", options(nostack, nomem)) };
    }

    /// Flush TLB entries for a specific stream.
    pub fn flush_tlb_stream(&self, _sid: u32) {
        // DART does not have per-stream flush on t8020/t8110 — flush all
        self.flush_tlb_all();
    }

    // ---- Stream enable/disable ----

    /// Enable IOVA translation for `sid` (sets TCR_TRANSLATE_ENABLE,
    /// clears bypass bit).  The stream must have a valid L1 page table.
    pub fn enable_stream(&mut self, sid: u32) -> i32 {
        if sid >= self.num_streams {
            return -22; // EINVAL
        }
        let l1_phys = self.streams[sid as usize].l1_phys;
        if l1_phys == 0 {
            return -12; // ENOMEM — no page table allocated
        }

        // Program TTBR
        let lo = (l1_phys & 0xFFFF_FFFF) as u32;
        let hi = (l1_phys >> 32) as u32;
        self.sid_w32(sid, SID_TTBR0, lo);
        self.sid_w32(sid, SID_TTBR1, hi);
        self.sid_w32(sid, SID_TTBR_VALID, TTBR_VALID);

        // Enable translation
        self.sid_w32(sid, SID_TCR, TCR_TRANSLATE_ENABLE);
        self.flush_tlb_stream(sid);

        self.streams[sid as usize].enabled = true;
        self.streams[sid as usize].bypass  = false;
        0
    }

    /// Disable translation for `sid` and set to bypass (passthrough).
    pub fn disable_stream(&mut self, sid: u32) -> i32 {
        if sid >= self.num_streams {
            return -22;
        }
        let bypass_bit = match self.variant {
            DartVariant::T8020 => TCR_BYPASS_DART_8020,
            DartVariant::T8110 => TCR_BYPASS_DART_8110,
        };
        self.sid_w32(sid, SID_TCR, bypass_bit);
        self.sid_w32(sid, SID_TTBR_VALID, 0);
        self.flush_tlb_stream(sid);

        self.streams[sid as usize].enabled = false;
        self.streams[sid as usize].bypass  = true;
        0
    }

    // ---- Page table management ----

    /// Ensure the L1 table for `sid` exists; allocate if not.
    fn ensure_l1(&mut self, sid: u32) -> bool {
        let st = &mut self.streams[sid as usize];
        if st.l1_phys != 0 {
            return true;
        }
        let (virt, phys) = alloc_page();
        st.l1_phys = phys;
        st.l1_virt = virt;
        true
    }

    /// Walk/build the page table for `iova`, allocating L2/L3 tables as
    /// needed.  Returns a mutable pointer to the L3 PTE for `iova`, or
    /// NULL on failure.
    fn get_or_create_pte(&mut self, sid: u32, iova: u64) -> *mut u64 {
        if !self.ensure_l1(sid) {
            return core::ptr::null_mut();
        }

        let l1_idx = (iova >> (PAGE_SHIFT + 9 + 9)) as usize & (L1_ENTRIES - 1);
        let l2_idx = (iova >> (PAGE_SHIFT + 9))     as usize & (L3_ENTRIES - 1);
        let l3_idx = (iova >> PAGE_SHIFT)            as usize & (L3_ENTRIES - 1);

        let l1_virt = self.streams[sid as usize].l1_virt;
        if l1_virt.is_null() {
            return core::ptr::null_mut();
        }

        // L1 → L2
        let l1_pte_ptr = unsafe { l1_virt.add(l1_idx) };
        let l1_pte = unsafe { read_volatile(l1_pte_ptr) };
        let l2_virt: *mut u64;
        if l1_pte & PTE_VALID == 0 {
            let (v, p) = alloc_page();
            let new_l1 = p | PTE_VALID;
            unsafe { write_volatile(l1_pte_ptr, new_l1) };
            l2_virt = v;
        } else {
            // Physical → virtual: for identity-mapped BSS, phys == virt
            l2_virt = (l1_pte & !0xFFF) as *mut u64;
        }

        // L2 → L3
        let l2_pte_ptr = unsafe { l2_virt.add(l2_idx) };
        let l2_pte = unsafe { read_volatile(l2_pte_ptr) };
        let l3_virt: *mut u64;
        if l2_pte & PTE_VALID == 0 {
            let (v, p) = alloc_page();
            let new_l2 = p | PTE_VALID;
            unsafe { write_volatile(l2_pte_ptr, new_l2) };
            l3_virt = v;
        } else {
            l3_virt = (l2_pte & !0xFFF) as *mut u64;
        }

        unsafe { l3_virt.add(l3_idx) }
    }

    // ---- DMA mapping ----

    /// Map `len` bytes at physical address `paddr` into the IOVA space of
    /// stream `sid` at address `iova`.
    ///
    /// `prot` is a bitmask of `DART_PROT_*` flags.
    pub fn map(&mut self, sid: u32, iova: u64, paddr: u64, len: u64, prot: u32) -> i32 {
        if sid >= self.num_streams {
            return -22;
        }
        if len == 0 || (iova & (PAGE_SIZE as u64 - 1)) != 0 || (paddr & (PAGE_SIZE as u64 - 1)) != 0 {
            return -22;
        }

        let mut flags = PTE_VALID;
        if prot & DART_PROT_WRITE == 0 {
            flags |= PTE_RDONLY;
        }
        if prot & DART_PROT_EXEC == 0 {
            flags |= PTE_NOEXEC;
        }

        let pages = (len + PAGE_SIZE as u64 - 1) / PAGE_SIZE as u64;
        for i in 0..pages {
            let cur_iova  = iova  + i * PAGE_SIZE as u64;
            let cur_paddr = paddr + i * PAGE_SIZE as u64;
            let pte_ptr = self.get_or_create_pte(sid, cur_iova);
            if pte_ptr.is_null() {
                return -12; // ENOMEM
            }
            let pte = (cur_paddr & !0xFFF) | flags;
            unsafe { write_volatile(pte_ptr, pte) };
        }

        self.flush_tlb_stream(sid);
        0
    }

    /// Unmap `len` bytes from the IOVA space of stream `sid` at `iova`.
    pub fn unmap(&mut self, sid: u32, iova: u64, len: u64) -> i32 {
        if sid >= self.num_streams {
            return -22;
        }
        if len == 0 {
            return 0;
        }

        let pages = (len + PAGE_SIZE as u64 - 1) / PAGE_SIZE as u64;
        for i in 0..pages {
            let cur_iova = iova + i * PAGE_SIZE as u64;
            let pte_ptr = self.get_or_create_pte(sid, cur_iova);
            if !pte_ptr.is_null() {
                unsafe { write_volatile(pte_ptr, 0u64) };
            }
        }

        self.flush_tlb_stream(sid);
        0
    }

    /// Translate IOVA to physical address for stream `sid`.
    /// Returns 0 if not mapped.
    pub fn iova_to_phys(&self, sid: u32, iova: u64) -> u64 {
        if sid >= self.num_streams {
            return 0;
        }
        let st = &self.streams[sid as usize];
        if st.l1_virt.is_null() {
            return 0;
        }

        let l1_idx = (iova >> (PAGE_SHIFT + 9 + 9)) as usize & (L1_ENTRIES - 1);
        let l2_idx = (iova >> (PAGE_SHIFT + 9))     as usize & (L3_ENTRIES - 1);
        let l3_idx = (iova >> PAGE_SHIFT)            as usize & (L3_ENTRIES - 1);

        let l1_pte = unsafe { read_volatile(st.l1_virt.add(l1_idx)) };
        if l1_pte & PTE_VALID == 0 {
            return 0;
        }
        let l2_virt = (l1_pte & !0xFFF) as *const u64;
        let l2_pte = unsafe { read_volatile(l2_virt.add(l2_idx)) };
        if l2_pte & PTE_VALID == 0 {
            return 0;
        }
        let l3_virt = (l2_pte & !0xFFF) as *const u64;
        let l3_pte = unsafe { read_volatile(l3_virt.add(l3_idx)) };
        if l3_pte & PTE_VALID == 0 {
            return 0;
        }

        (l3_pte & !0xFFF) | (iova & (PAGE_SIZE as u64 - 1))
    }
}

// ---------------------------------------------------------------------------
// Static singleton
// ---------------------------------------------------------------------------

static mut G_DART: AppleDart = AppleDart {
    base:        0,
    num_streams: 0,
    variant:     DartVariant::T8020,
    ready:       AtomicBool::new(false),
    streams:     [StreamState::empty(); MAX_STREAMS],
};

// ---------------------------------------------------------------------------
// C FFI
// ---------------------------------------------------------------------------

/// Initialize the Apple DART IOMMU.
///
/// `base`        — MMIO base address of the DART registers.
/// `num_streams` — number of DMA streams (1–16).
/// `variant`     — hardware variant: 0 = T8020 (M1/M2), 1 = T8110 (M1 Pro/Max).
///
/// Returns non-null handle on success, NULL on failure.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_dart_init(
    base: u64,
    num_streams: u32,
    variant: u32,
) -> *mut AppleDart {
    if base == 0 || num_streams == 0 || num_streams > MAX_STREAMS as u32 {
        return core::ptr::null_mut();
    }
    let hw_variant = if variant == 0 { DartVariant::T8020 } else { DartVariant::T8110 };

    let dart = unsafe { &mut *(&raw mut G_DART) };
    dart.base        = base as usize;
    dart.num_streams = num_streams;
    dart.variant     = hw_variant;
    dart.ready       = AtomicBool::new(false);
    for i in 0..MAX_STREAMS {
        dart.streams[i] = StreamState::empty();
    }

    dart.init();
    dart as *mut AppleDart
}

/// Release resources held by the DART driver.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_dart_free(dart: *mut AppleDart) {
    if dart.is_null() { return; }
    let d = unsafe { &mut *dart };
    // Disable all streams (restore bypass)
    for sid in 0..d.num_streams {
        d.disable_stream(sid);
    }
    d.ready.store(false, Ordering::Release);
    d.base = 0;
}

/// Enable IOVA translation for stream `sid`.
/// Returns 0 on success, negative errno on failure.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_dart_enable_stream(dart: *mut AppleDart, sid: u32) -> i32 {
    if dart.is_null() { return -22; }
    unsafe { (*dart).enable_stream(sid) }
}

/// Disable translation for stream `sid` (restore bypass/passthrough).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_dart_disable_stream(dart: *mut AppleDart, sid: u32) -> i32 {
    if dart.is_null() { return -22; }
    unsafe { (*dart).disable_stream(sid) }
}

/// Map physical address `paddr` + `len` bytes into stream `sid` at IOVA `iova`.
/// `prot` is DART_PROT_READ | DART_PROT_WRITE | DART_PROT_EXEC bitmask.
/// Returns 0 on success, negative errno on failure.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_dart_map(
    dart: *mut AppleDart,
    sid:  u32,
    iova: u64,
    paddr: u64,
    len:  u64,
    prot: u32,
) -> i32 {
    if dart.is_null() { return -22; }
    unsafe { (*dart).map(sid, iova, paddr, len, prot) }
}

/// Unmap `len` bytes at IOVA `iova` in stream `sid`.
/// Returns 0 on success, negative errno on failure.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_dart_unmap(
    dart: *mut AppleDart,
    sid:  u32,
    iova: u64,
    len:  u64,
) -> i32 {
    if dart.is_null() { return -22; }
    unsafe { (*dart).unmap(sid, iova, len) }
}

/// Translate IOVA to physical address for stream `sid`.
/// Returns the physical address, or 0 if not mapped.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_dart_iova_to_phys(
    dart: *const AppleDart,
    sid:  u32,
    iova: u64,
) -> u64 {
    if dart.is_null() { return 0; }
    unsafe { (*dart).iova_to_phys(sid, iova) }
}

/// Flush all TLB entries for all streams.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_dart_flush_tlb_all(dart: *const AppleDart) {
    if dart.is_null() { return; }
    unsafe { (*dart).flush_tlb_all() }
}

/// Flush TLB entries for stream `sid`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_dart_flush_tlb_stream(dart: *const AppleDart, sid: u32) {
    if dart.is_null() { return; }
    unsafe { (*dart).flush_tlb_stream(sid) }
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
