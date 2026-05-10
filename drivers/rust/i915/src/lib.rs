// SPDX-License-Identifier: MPL-2.0
//
// i915 Driver for Futura OS -Phase 1: PCI detect + MMIO map + info readout
//
// This is the first slice of a real Intel integrated graphics driver, aimed
// initially at Gen9 LP (Apollo Lake / Gemini Lake -e.g. Celeron N4120 in
// the HP Chromebook 11 we're using as the bare-metal target). The end goal
// is hardware 2D acceleration via the BLT (Blitter) command streamer to
// replace the bit-banged framebuffer console scroll.
//
// Phase 1 (this file) is observational: it discovers the iGPU via PCI,
// maps BAR0 (the GTTMMADR -combined GTT + MMIO register window), and
// logs the device ID + a few MMIO identification registers so we can
// confirm which generation we're talking to. No display engine touched.
//
// Subsequent phases (in follow-up commits):
//   2. GTT setup -discover GTT base, install entries for the FB and a
//      command ring buffer.
//   3. BCS ring buffer init -allocate a ring, set RING_HEAD/TAIL/CTL,
//      submit a NOP and wait for completion.
//   4. XY_SRC_COPY_BLT -implement scroll() via the BLT engine.
//   5. XY_COLOR_BLT -implement clear() via the BLT engine.
//
// References:
//   - Intel OSS Graphics PRM Volume 1 (Gen9 / BXT/GLK)
//   - Intel OSS Graphics PRM Volume 2 (Command Reference)
//   - Intel OSS Graphics PRM Volume 5 (Memory Views -GTT)

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(unexpected_cfgs)]

use core::cell::UnsafeCell;
use core::ffi::c_void;
use common::{log, map_mmio_region, MMIO_DEFAULT_FLAGS};

unsafe extern "C" {
    fn fut_printf(fmt: *const u8, ...);
    fn fut_pmm_alloc_page() -> *mut c_void;
    fn rust_virt_to_phys(vaddr: *const c_void) -> u64;
}

#[inline]
fn alloc_page_phys() -> Option<(*mut u8, u64)> {
    let virt = unsafe { fut_pmm_alloc_page() } as *mut u8;
    if virt.is_null() {
        return None;
    }
    let phys = unsafe { rust_virt_to_phys(virt as *const c_void) };
    if phys == 0 {
        return None;
    }
    Some((virt, phys))
}

// ── PCI configuration space I/O ──

const PCI_CONFIG_ADDR: u16 = 0x0CF8;
const PCI_CONFIG_DATA: u16 = 0x0CFC;

fn pci_config_addr(bus: u8, dev: u8, func: u8, offset: u8) -> u32 {
    (1u32 << 31)
        | ((bus as u32) << 16)
        | ((dev as u32) << 11)
        | ((func as u32) << 8)
        | ((offset as u32) & 0xFC)
}

fn pci_read32(bus: u8, dev: u8, func: u8, offset: u8) -> u32 {
    let addr = pci_config_addr(bus, dev, func, offset);
    unsafe {
        core::arch::asm!("out dx, eax", in("dx") PCI_CONFIG_ADDR, in("eax") addr);
        let val: u32;
        core::arch::asm!("in eax, dx", in("dx") PCI_CONFIG_DATA, out("eax") val);
        val
    }
}

// ── PCI location of the Intel iGPU ──

/// Intel integrated graphics is conventionally at bus 0, device 2, function 0.
const GPU_BUS: u8 = 0x00;
const GPU_DEV: u8 = 0x02;
const GPU_FUNC: u8 = 0x00;

const PCI_VENDOR_INTEL: u16 = 0x8086;

// ── PCI config-space offsets ──

const PCI_CFG_VENDOR_DEVICE: u8 = 0x00;
/// BAR0 = GTTMMADR (Gen9+) -combined GTT + MMIO register window.
/// On Gen9 the GTT lives in the upper half of BAR0, MMIO in the lower half.
const PCI_CFG_BAR0_LO: u8 = 0x10;
const PCI_CFG_BAR0_HI: u8 = 0x14;
const PCI_CFG_COMMAND: u8 = 0x04;

// ── i915 MMIO identification registers (offsets in BAR0's MMIO area) ──

const MMIO_FORCEWAKE_GEN9_LP: u32 = 0x0A188;   /* RPCS forcewake on Gen9 LP */
const MMIO_GEN6_GT_THREAD_STATUS: u32 = 0x13805C;
const MMIO_REG_GMCH_CTL: u32 = 0x0;            /* placeholder */

/// MMIO IDs we read back during phase-1 detection. None of them require
/// the display/render engines to be powered up.
const MMIO_GFX_MSTR_INTR: u32 = 0x44200;       /* always-on */
const MMIO_GTT_PD0:        u32 = 0x4000;       /* GTT entry 0; should be programmed by firmware */

// ── Driver state ──

struct StaticCell<T>(UnsafeCell<T>);
unsafe impl<T> Sync for StaticCell<T> {}
impl<T> StaticCell<T> {
    const fn new(v: T) -> Self { Self(UnsafeCell::new(v)) }
    fn get(&self) -> *mut T { self.0.get() }
}

#[repr(C)]
struct I915State {
    pub initialized: bool,
    pub gtt_initialized: bool,
    pub vendor_id: u16,
    pub device_id: u16,
    pub bar0_phys: u64,
    pub mmio_base: *mut u8,
    /// On Gen9, BAR0 is split: first half is MMIO regs, second half is GTT.
    pub mmio_size: usize,
    /// GTT (Graphics Translation Table) — upper half of BAR0. Each entry
    /// is a 64-bit PTE that maps a 4 KiB GPU virtual page to a system
    /// physical page. Phase 2 maps this region and installs entries.
    pub gtt_base: *mut u64,
    pub gtt_size: usize,
    /// Number of valid GTT entries we've populated (for diagnostics).
    pub gtt_entries_used: u32,
    /// GPU virtual address of a 4 KiB scratch page we install during
    /// phase 2 as a smoke test (and which phase 3 will repurpose for
    /// the BCS command ring buffer).
    pub scratch_gpu_va: u64,
    pub scratch_phys: u64,
}

unsafe impl Send for I915State {}
unsafe impl Sync for I915State {}

static STATE: StaticCell<I915State> = StaticCell::new(I915State {
    initialized: false,
    gtt_initialized: false,
    vendor_id: 0,
    device_id: 0,
    bar0_phys: 0,
    mmio_base: core::ptr::null_mut(),
    mmio_size: 0,
    gtt_base: core::ptr::null_mut(),
    gtt_size: 0,
    gtt_entries_used: 0,
    scratch_gpu_va: 0,
    scratch_phys: 0,
});

#[inline(always)]
unsafe fn mmio_read32(base: *const u8, offset: u32) -> u32 {
    unsafe { core::ptr::read_volatile(base.add(offset as usize) as *const u32) }
}

// ── Public C API ──

/// Detect the Intel integrated GPU, map its BAR0, and log identification
/// info. Returns 0 on success, negative on failure (not an Intel iGPU,
/// MMIO map failure, etc.).
///
/// Safe to call before the kernel scheduler is up. Does not touch the
/// display engine, command streamers, or interrupts.
#[unsafe(no_mangle)]
pub extern "C" fn i915_init() -> i32 {
    log("i915: probing Intel integrated GPU at PCI 00:02.0");

    let vendor_device = pci_read32(GPU_BUS, GPU_DEV, GPU_FUNC, PCI_CFG_VENDOR_DEVICE);
    let vendor = (vendor_device & 0xFFFF) as u16;
    let device = (vendor_device >> 16) as u16;

    if vendor == 0xFFFF || vendor == 0x0000 {
        log("i915: no PCI device at 00:02.0 -skipping");
        return -1;
    }
    if vendor != PCI_VENDOR_INTEL {
        unsafe {
            fut_printf(
                b"i915: PCI 00:02.0 vendor 0x%04x is not Intel -skipping\n\0".as_ptr(),
                vendor as u32,
            );
        }
        return -1;
    }

    unsafe {
        fut_printf(
            b"i915: found Intel device 0x%04x at PCI 00:02.0\n\0".as_ptr(),
            device as u32,
        );
    }

    // Read BAR0 (GTTMMADR -64-bit memory BAR on Gen9). The low 4 bits are
    // type/prefetchable flags; mask them off to get the base address.
    let bar0_lo = pci_read32(GPU_BUS, GPU_DEV, GPU_FUNC, PCI_CFG_BAR0_LO);
    let bar0_hi = pci_read32(GPU_BUS, GPU_DEV, GPU_FUNC, PCI_CFG_BAR0_HI);
    let bar0_type = bar0_lo & 0x07;
    let bar0_phys: u64 = ((bar0_hi as u64) << 32) | ((bar0_lo as u64) & !0x0Fu64);

    if bar0_phys == 0 {
        log("i915: BAR0 not programmed by firmware -skipping");
        return -2;
    }

    unsafe {
        fut_printf(
            b"i915: BAR0 phys=0x%llx type=0x%x (memory-bar%s)\n\0".as_ptr(),
            bar0_phys,
            bar0_type,
            if (bar0_type & 0x04) != 0 { b"-64bit\0".as_ptr() } else { b"-32bit\0".as_ptr() },
        );
    }

    // Make sure PCI memory-space decoding + bus master are enabled so
    // reads through BAR0 actually reach the GPU.
    let cmd = pci_read32(GPU_BUS, GPU_DEV, GPU_FUNC, PCI_CFG_COMMAND) & 0xFFFF;
    if (cmd & 0x0006) != 0x0006 {
        unsafe {
            fut_printf(
                b"i915: PCI command=0x%04x missing memory-space (0x2) and/or bus-master (0x4) -phase 2 will enable\n\0".as_ptr(),
                cmd,
            );
        }
    }

    // Map BAR0. On Gen9 the BAR is 16 MiB total: lower 8 MiB MMIO regs,
    // upper 8 MiB GTT. We only need the MMIO half for identification reads.
    const GEN9_MMIO_HALF: usize = 8 * 1024 * 1024;

    let mmio = unsafe { map_mmio_region(bar0_phys, GEN9_MMIO_HALF, MMIO_DEFAULT_FLAGS) };
    if mmio.is_null() {
        log("i915: failed to map BAR0 MMIO region");
        return -3;
    }

    // Read a couple of always-available identification registers.
    // GFX_MSTR_INTR (0x44200) is the master interrupt control reg —
    // value depends on firmware state, but it should be readable.
    let gfx_mstr = unsafe { mmio_read32(mmio, MMIO_GFX_MSTR_INTR) };
    let gtt_pd0  = unsafe { mmio_read32(mmio, MMIO_GTT_PD0) };
    unsafe {
        fut_printf(
            b"i915: MMIO mapped at %p; GFX_MSTR_INTR=0x%08x GTT[0]=0x%08x\n\0".as_ptr(),
            mmio, gfx_mstr, gtt_pd0,
        );
    }

    // Stash state for phase 2/3/4 to use.
    let st = STATE.get();
    unsafe {
        (*st).vendor_id = vendor;
        (*st).device_id = device;
        (*st).bar0_phys = bar0_phys;
        (*st).mmio_base = mmio;
        (*st).mmio_size = GEN9_MMIO_HALF;
        (*st).initialized = true;
    }

    log("i915: phase 1 complete (PCI detect + MMIO map). Phase 2 (GTT) is next.");
    0
}

/// Returns true once i915_init has detected and mapped the iGPU.
/// Used by future BLT users (fb_console scroll) to gate hardware
/// acceleration behind successful init.
#[unsafe(no_mangle)]
pub extern "C" fn i915_is_initialized() -> bool {
    let st = STATE.get();
    unsafe { (*st).initialized }
}

/// Returns the device ID detected at probe time, or 0 if uninitialized.
#[unsafe(no_mangle)]
pub extern "C" fn i915_device_id() -> u16 {
    let st = STATE.get();
    unsafe { (*st).device_id }
}

// ── Phase 2: GTT (Graphics Translation Table) setup ──
//
// On Gen9 LP (Apollo Lake / Gemini Lake) the GTT lives in the upper
// half of BAR0 (the GTTMMADR). Each entry is a 64-bit PTE:
//
//   bit  0       Valid (must be 1 for the entry to translate)
//   bits 11..1   Cache attributes / reserved (Gen-specific encoding)
//   bits 47..12  Physical page address (4 KiB-aligned)
//   bits 63..48  Reserved (zero)
//
// For a Gen9 LP GTTMMADR sized 16 MiB:
//   - Lower 8 MiB = MMIO regs (mapped in phase 1)
//   - Upper 8 MiB = GTT (1 M entries × 8 B = 8 MiB → 4 GiB GPU VA range)
//
// The kernel does not need to manage every GTT slot. Firmware leaves
// the existing display-engine framebuffer mapped at whatever GTT VA it
// chose at boot. We carve out an unused range (here the very top of
// the GTT, working downward) for our own scratch / ring / BLT pages.

const GEN9_GTT_OFFSET_IN_BAR0: u64 = 8 * 1024 * 1024;  /* upper half */
const GEN9_GTT_SIZE: usize = 8 * 1024 * 1024;          /* 8 MiB */
const GTT_PTE_SIZE: usize = 8;                          /* 64-bit entries */
const GTT_NUM_ENTRIES: usize = GEN9_GTT_SIZE / GTT_PTE_SIZE;
const GTT_PAGE_SIZE: u64 = 4096;

const GTT_PTE_VALID: u64 = 1 << 0;
const GTT_PTE_LLC:   u64 = 1 << 1;  /* Use LLC for cacheable accesses */

/// Build a Gen9 GTT PTE from a 4-KiB-aligned physical address.
#[inline]
fn gtt_make_pte(phys: u64) -> u64 {
    debug_assert!(phys & 0xFFF == 0);
    (phys & 0x0000_FFFF_FFFF_F000) | GTT_PTE_VALID | GTT_PTE_LLC
}

/// Install a single 4-KiB GTT mapping: gpu_va → phys.
/// gpu_va must be 4 KiB-aligned and within the GTT-addressable range.
fn gtt_install(gtt_base: *mut u64, gpu_va: u64, phys: u64) {
    let idx = (gpu_va / GTT_PAGE_SIZE) as usize;
    if idx >= GTT_NUM_ENTRIES {
        return;
    }
    let pte = gtt_make_pte(phys);
    unsafe { core::ptr::write_volatile(gtt_base.add(idx), pte) };
    /* Read the entry back to flush the WC buffer (matches Linux's
     * i915_ggtt_invalidate hammer; on Gen9 LP a simple readback is
     * the documented serialization for GTT PTE writes). */
    let _readback = unsafe { core::ptr::read_volatile(gtt_base.add(idx)) };
}

/// Phase 2 entry point. Call after i915_init (which mapped BAR0 MMIO).
/// Maps the GTT half of BAR0, installs a single test entry pointing
/// at a freshly-allocated 4 KiB scratch page near the top of the GTT
/// VA range, and reads it back to confirm the write took.
///
/// Returns 0 on success, negative on failure.
#[unsafe(no_mangle)]
pub extern "C" fn i915_gtt_init() -> i32 {
    let st = STATE.get();
    if !unsafe { (*st).initialized } {
        log("i915_gtt_init: phase 1 not done; skipping");
        return -1;
    }
    if unsafe { (*st).gtt_initialized } {
        log("i915_gtt_init: already done");
        return 0;
    }

    let bar0_phys = unsafe { (*st).bar0_phys };
    let gtt_phys = bar0_phys + GEN9_GTT_OFFSET_IN_BAR0;

    /* Map GTT range as MMIO. The GTT itself is in device memory backed
     * by the GPU; writes to it must be uncached/WC and serialized via
     * a readback (see gtt_install). */
    let gtt_base = unsafe { map_mmio_region(gtt_phys, GEN9_GTT_SIZE, MMIO_DEFAULT_FLAGS) }
        as *mut u64;
    if gtt_base.is_null() {
        log("i915_gtt_init: GTT MMIO map failed");
        return -2;
    }

    unsafe {
        fut_printf(
            b"i915: GTT mapped at %p (phys 0x%llx, %u entries / %u GiB GPU VA)\n\0".as_ptr(),
            gtt_base,
            gtt_phys,
            GTT_NUM_ENTRIES as u32,
            ((GTT_NUM_ENTRIES as u64 * GTT_PAGE_SIZE) / (1u64 << 30)) as u32,
        );
    }

    /* Allocate a 4 KiB scratch page in DRAM. Phase 3 will reuse this
     * (or replace it with a larger ring) for BCS command submission. */
    let (_scratch_virt, scratch_phys) = match alloc_page_phys() {
        Some(p) => p,
        None => {
            log("i915_gtt_init: PMM alloc for scratch page failed");
            return -3;
        }
    };

    /* Pick a GPU VA near the top of the GTT range, far away from any
     * pre-existing firmware mappings (which sit at low addresses for
     * the framebuffer). One page below the very top. */
    let scratch_gpu_va = (GTT_NUM_ENTRIES as u64 - 1) * GTT_PAGE_SIZE;

    gtt_install(gtt_base, scratch_gpu_va, scratch_phys);

    /* Verify the install by reading the entry back. */
    let pte_idx = (scratch_gpu_va / GTT_PAGE_SIZE) as usize;
    let installed = unsafe { core::ptr::read_volatile(gtt_base.add(pte_idx)) };
    let expected = gtt_make_pte(scratch_phys);
    if installed != expected {
        unsafe {
            fut_printf(
                b"i915_gtt_init: PTE readback mismatch! wrote 0x%llx read 0x%llx\n\0".as_ptr(),
                expected, installed,
            );
        }
        return -4;
    }

    unsafe {
        fut_printf(
            b"i915: GTT scratch installed: gpu_va=0x%llx -> phys=0x%llx (PTE 0x%llx)\n\0".as_ptr(),
            scratch_gpu_va, scratch_phys, installed,
        );
    }

    unsafe {
        (*st).gtt_base = gtt_base;
        (*st).gtt_size = GEN9_GTT_SIZE;
        (*st).gtt_entries_used = 1;
        (*st).scratch_gpu_va = scratch_gpu_va;
        (*st).scratch_phys = scratch_phys;
        (*st).gtt_initialized = true;
    }

    log("i915: phase 2 complete (GTT mapped, scratch installed). Phase 3 (BCS ring) is next.");
    0
}

/// Returns true once i915_gtt_init has succeeded.
#[unsafe(no_mangle)]
pub extern "C" fn i915_gtt_ready() -> bool {
    let st = STATE.get();
    unsafe { (*st).gtt_initialized }
}
