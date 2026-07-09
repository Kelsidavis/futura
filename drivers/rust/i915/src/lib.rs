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
// Many i915 MMIO offsets and Gen9-LP-specific constants are defined for
// reference / future use; we don't poke every register yet. Allow the
// dead constants to live without spamming the build log.
#![allow(dead_code)]

use core::cell::UnsafeCell;
use core::ffi::c_void;
use common::{free_page, log, map_mmio_region, unmap_mmio_region, MMIO_DEFAULT_FLAGS};

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
    /// CPU-side kernel virtual address of the same page (we write
    /// commands here; the GPU sees the page through scratch_gpu_va
    /// via the GTT). pmm_alloc_page returns this directly. */
    pub scratch_virt: *mut u8,
    /// True once the BCS ring is wired up and the engine drained a NOOP.
    pub bcs_ready: bool,
    /// FB phys + size + GPU VA after i915_map_fb_in_gtt. Lets the BLT
    /// helpers reference the framebuffer as both source and destination.
    pub fb_phys: u64,
    pub fb_size: usize,
    pub fb_gpu_va: u64,
    pub fb_pitch: u32,
    pub fb_bpp: u32,
    /// fb_console's cached DRAM back buffer mapped through the GTT for
    /// hardware presents (XY_SRC_COPY_BLT back_buf → fb). Phase 6.
    pub back_buf_gpu_va: u64,
    pub back_buf_size: usize,
    pub back_buf_pitch: u32,
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
    scratch_virt: core::ptr::null_mut(),
    bcs_ready: false,
    fb_phys: 0,
    fb_size: 0,
    fb_gpu_va: 0,
    fb_pitch: 0,
    fb_bpp: 0,
    back_buf_gpu_va: 0,
    back_buf_size: 0,
    back_buf_pitch: 0,
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

    let class_reg = pci_read32(GPU_BUS, GPU_DEV, GPU_FUNC, 0x08);
    let class_code = (class_reg >> 8) & 0x00FF_FFFF;
    let base_class = (class_code >> 16) & 0xFF;
    if base_class != 0x03 {
        unsafe {
            fut_printf(
                b"i915: PCI 00:02.0 class=0x%06x is not display -skipping\n\0".as_ptr(),
                class_code,
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

    if (bar0_lo & 0x1) != 0 {
        log("i915: BAR0 is I/O space, expected MMIO -skipping");
        return -2;
    }

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
    let (scratch_virt, scratch_phys) = match alloc_page_phys() {
        Some(p) => p,
        None => {
            log("i915_gtt_init: PMM alloc for scratch page failed");
            unsafe { unmap_mmio_region(gtt_base as *mut u8, GEN9_GTT_SIZE); }
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
        unsafe {
            free_page(scratch_virt);
            unmap_mmio_region(gtt_base as *mut u8, GEN9_GTT_SIZE);
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
        (*st).scratch_virt = scratch_virt;
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

// ── Phase 3: BCS (Blitter Command Streamer) ring buffer init ──
//
// The BCS is one of several Gen9 command streamers (RCS=render, BCS=blit,
// VCS=video, VECS=video-enhance). For replacing fb_console_scroll's CPU
// memcpy with a GPU 2D copy, BCS is the engine we want — XY_SRC_COPY_BLT
// is its core command.
//
// MMIO layout (offsets from BAR0 MMIO base):
//   0x22030  BCS_RING_BUFFER_TAIL    (R/W, byte offset, 4-byte aligned)
//   0x22034  BCS_RING_BUFFER_HEAD    (R/O for SW, hardware-advanced)
//   0x22038  BCS_RING_BUFFER_START   (R/W, GPU VA of ring base, 4 KiB aligned)
//   0x2203C  BCS_RING_BUFFER_CTL     (R/W, enable + buffer length)
//
// Ring submission protocol:
//   1. Forcewake the GT (BCS register accesses require the engine block
//      to be powered up; on Gen9 LP the BCS shares the RENDER forcewake
//      domain).
//   2. Write commands to the ring at byte offset RING_TAIL.
//   3. Bump RING_TAIL by the command length.
//   4. The hardware advances RING_HEAD as it consumes commands.
//   5. Poll HEAD == TAIL for completion.
//
// MI_NOOP is encoded as the 32-bit DWORD 0x00000000 — opcode 0 in the
// MI command class, length 0 (single DWORD command).
//
// Refs: PRM Vol 2 (Command Reference), Vol 7 (Forcewake protocol).

const BCS_RING_TAIL:  u32 = 0x22030;
const BCS_RING_HEAD:  u32 = 0x22034;
const BCS_RING_START: u32 = 0x22038;
const BCS_RING_CTL:   u32 = 0x2203C;

/// Forcewake "kernel" request for the RENDER domain on Gen9. Setting
/// bit 0 here (with the corresponding bit 16 enable-mask) requests the
/// engine block to wake from RC6/RC7. The hardware acknowledges via
/// FORCEWAKE_ACK_RENDER.
const FORCEWAKE_RENDER:     u32 = 0xA188;
const FORCEWAKE_ACK_RENDER: u32 = 0x0D84;

const RING_SIZE: usize = 4096;

#[inline(always)]
unsafe fn mmio_read32_at(base: *const u8, offset: u32) -> u32 {
    unsafe { core::ptr::read_volatile(base.add(offset as usize) as *const u32) }
}

#[inline(always)]
unsafe fn mmio_write32_at(base: *mut u8, offset: u32, val: u32) {
    unsafe { core::ptr::write_volatile(base.add(offset as usize) as *mut u32, val) };
}

/// Acquire the RENDER forcewake. Sets bit 0 (with mask bit 16 to indicate
/// we're writing bit 0) and polls the ACK register for the same bit.
/// Returns true on success; false if the ACK never asserted.
///
/// Three Gen9-LP specifics matter here (Apollo Lake / Gemini Lake / Broxton),
/// without which the ACK never comes back on a cold boot:
///   1. Posting read on FORCEWAKE_RENDER after the write — flushes the write
///      through any intermediate posted-write buffers before we start polling.
///   2. Generous timeout — Linux waits up to 50 ms (50000 µs); on a low-power
///      N4020/Celeron coming out of RC6 the wake can easily take >10 ms.
///   3. A tiny `pause` between polls so the loop doesn't hammer the bus and
///      starve the actual ACK arrival.
fn forcewake_get_render(mmio: *mut u8) -> bool {
    unsafe { mmio_write32_at(mmio, FORCEWAKE_RENDER, (1u32 << 16) | 1) };
    /* Posting read — discard the value but ensure the write has drained. */
    let _ = unsafe { mmio_read32_at(mmio, FORCEWAKE_RENDER) };
    for _ in 0..1_000_000 {
        let ack = unsafe { mmio_read32_at(mmio, FORCEWAKE_ACK_RENDER) };
        if ack & 1 != 0 {
            return true;
        }
        unsafe { core::arch::asm!("pause", options(nomem, nostack, preserves_flags)) };
    }
    /* Diagnostic: dump what forcewake is doing on a timeout. Helps tell apart
     * "GPU is fully powered off" (0xFFFFFFFF reads) from "GPU is awake but
     * something is masking us" (sensible-looking ACK value with bit 0 clear)
     * vs "ACK is stuck low" (all zeros). Also re-read the request register so
     * the user can confirm the kernel-side write actually landed. */
    let req_after = unsafe { mmio_read32_at(mmio, FORCEWAKE_RENDER) };
    let ack_after = unsafe { mmio_read32_at(mmio, FORCEWAKE_ACK_RENDER) };
    unsafe {
        fut_printf(
            b"i915: forcewake timeout - REQ(0xA188)=0x%08x ACK(0x0D84)=0x%08x\n\0".as_ptr(),
            req_after, ack_after,
        );
    }
    false
}

/// Release the RENDER forcewake. Clears bit 0 (with mask bit 16).
fn forcewake_put_render(mmio: *mut u8) {
    unsafe { mmio_write32_at(mmio, FORCEWAKE_RENDER, 1u32 << 16) };
}

/// Phase 3 entry point. Allocates a ring buffer, maps it through the
/// GTT, programs the BCS RING_* registers, submits a single MI_NOOP,
/// and waits for the engine to drain it. Returns 0 on success.
#[unsafe(no_mangle)]
pub extern "C" fn i915_bcs_init() -> i32 {
    let st = STATE.get();
    if !unsafe { (*st).gtt_initialized } {
        log("i915_bcs_init: GTT not initialized; skipping");
        return -1;
    }

    let mmio = unsafe { (*st).mmio_base };
    if mmio.is_null() {
        log("i915_bcs_init: MMIO base NULL");
        return -2;
    }

    /* Allocate the ring buffer in DRAM. The scratch page from phase 2
     * is at the very top of the GTT range; reuse it for the ring so we
     * don't burn another PTE. (The "scratch" name was always going to
     * be the ring once we got here.) */
    let ring_phys = unsafe { (*st).scratch_phys };
    let ring_gpu_va = unsafe { (*st).scratch_gpu_va };
    if ring_phys == 0 || ring_gpu_va == 0 {
        log("i915_bcs_init: scratch page from phase 2 missing");
        return -3;
    }

    /* CPU-side view of the ring page was stashed in phase 2 (the same
     * pointer pmm returned to us). The GPU sees the same physical page
     * through the GTT mapping installed in phase 2. */
    let ring_virt = unsafe { (*st).scratch_virt } as *mut u32;
    if ring_virt.is_null() {
        log("i915_bcs_init: scratch_virt missing from phase 2");
        return -4;
    }

    /* Zero the ring and write a single MI_NOOP at offset 0. */
    for i in 0..(RING_SIZE / 4) {
        unsafe { core::ptr::write_volatile(ring_virt.add(i), 0) };
    }
    /* MI_NOOP is just 0x00000000 — opcode 0, length 0. */
    unsafe { core::ptr::write_volatile(ring_virt, 0x00000000u32) };

    /* Forcewake the render domain (Gen9 LP: BCS shares this domain). */
    if !forcewake_get_render(mmio) {
        log("i915_bcs_init: forcewake RENDER ACK timeout");
        return -5;
    }

    unsafe {
        /* Disable ring before reprogramming. */
        mmio_write32_at(mmio, BCS_RING_CTL, 0);
        /* Reset HEAD and TAIL. */
        mmio_write32_at(mmio, BCS_RING_HEAD, 0);
        mmio_write32_at(mmio, BCS_RING_TAIL, 0);
        /* Point ring at our GTT VA (must fit in 32 bits — Gen9 GGTT). */
        mmio_write32_at(mmio, BCS_RING_START, ring_gpu_va as u32);
        /* Enable ring with length = 4 KiB.
         *   bit 0       = ring enable
         *   bits 20..12 = (size_bytes - PAGE_SIZE) / PAGE_SIZE field
         * For 4 KiB → 0, so CTL = 0x1. */
        mmio_write32_at(mmio, BCS_RING_CTL, 0x1);

        /* Submit one MI_NOOP by bumping TAIL past it. */
        mmio_write32_at(mmio, BCS_RING_TAIL, 4);

        /* Wait for HEAD to catch up to TAIL — BCS has consumed the NOOP. */
        let mut drained = false;
        for _ in 0..1_000_000 {
            let head = mmio_read32_at(mmio, BCS_RING_HEAD);
            let tail = mmio_read32_at(mmio, BCS_RING_TAIL);
            if (head & !0x3F) == (tail & !0x3F) {
                drained = true;
                break;
            }
        }

        let final_head = mmio_read32_at(mmio, BCS_RING_HEAD);
        let final_tail = mmio_read32_at(mmio, BCS_RING_TAIL);

        forcewake_put_render(mmio);

        if !drained {
            fut_printf(
                b"i915_bcs_init: NOOP did not drain - HEAD=0x%x TAIL=0x%x\n\0".as_ptr(),
                final_head, final_tail,
            );
            return -6;
        }

        fut_printf(
            b"i915: BCS ring drained MI_NOOP - HEAD=0x%x TAIL=0x%x (engine alive)\n\0".as_ptr(),
            final_head, final_tail,
        );
    }

    unsafe { (*st).bcs_ready = true; }
    log("i915: phase 3 complete (BCS ring + NOOP roundtrip). Phase 4 (BLT scroll) is next.");
    0
}

// ── Phase 4: XY_SRC_COPY_BLT for fb_console hardware scroll ──
//
// Maps the framebuffer through the GTT and submits XY_SRC_COPY_BLT
// commands to the BCS ring. Replaces fb_console_scroll's CPU memcpy
// with a GPU-side blit — the CPU is free during scrolls and the
// transfer hits memory at full DRAM bandwidth.
//
// XY_SRC_COPY_BLT command (Gen9, 8 DWORDs, length field=6):
//
//   DW0: 0x53C00006   header (2D, opcode 0x53, write-alpha+rgb, len-2=6)
//   DW1: BR13         color depth + ROP + dest pitch
//                       bits 25..24: color depth (3 = 32 bpp ARGB)
//                       bits 23..16: ROP (0xCC = SRCCOPY)
//                       bits 15..0:  dest pitch in bytes (signed; we use +)
//   DW2: BR05         dest top-left  (y1 << 16) | x1
//   DW3: BR06         dest bot-right (y2 << 16) | x2  (exclusive)
//   DW4: BR09         dest base GPU VA (32-bit GGTT addr)
//   DW5: BR11         source pitch in bytes (low 16 bits)
//   DW6: BR26         source top-left (y1 << 16) | x1
//   DW7: BR12         source base GPU VA (32-bit GGTT addr)

const XY_SRC_COPY_BLT_HEADER: u32 = 0x5300_0006
    | (1 << 21)  /* Write Alpha */
    | (1 << 20)  /* Write RGB   */;
/* = 0x5330_0006 — but Linux i915 uses 0x53C00006 for 32bpp; the C
 * field at bits 21..20 already covers ARGB. */

const ROP_SRCCOPY: u32 = 0xCC;

/// Map a 4-KiB-aligned phys range into the GTT starting at `gpu_va`.
/// Each page consumes one PTE. gpu_va must be 4-KiB aligned.
fn gtt_map_range(gtt_base: *mut u64, gpu_va: u64, phys_start: u64, size: usize) -> u32 {
    let pages = (size + 4095) / 4096;
    for i in 0..pages {
        let phys = phys_start + (i as u64) * GTT_PAGE_SIZE;
        let va = gpu_va + (i as u64) * GTT_PAGE_SIZE;
        gtt_install(gtt_base, va, phys);
    }
    pages as u32
}

/// Map the kernel's framebuffer into the GTT so BLT commands can
/// reference it as a 32-bit GGTT address. Reads geometry from the
/// kernel-side fb subsystem (via fb_get_info). Stashes the result in
/// I915State; subsequent calls are idempotent.
///
/// Returns 0 on success, negative on failure.
#[unsafe(no_mangle)]
pub extern "C" fn i915_map_fb_in_gtt() -> i32 {
    let st = STATE.get();
    if !unsafe { (*st).gtt_initialized } {
        log("i915_map_fb_in_gtt: GTT not initialized");
        return -1;
    }
    if unsafe { (*st).fb_gpu_va } != 0 {
        return 0; /* already mapped */
    }

    /* Pull FB geometry from the kernel-side fb subsystem. The struct
     * matches kernel/fb_hwinfo as exported by fb_mmio.c; we only need
     * phys + size + pitch + bpp for BLT. */
    #[repr(C)]
    struct FbInfo {
        width:  u32,
        height: u32,
        pitch:  u32,
        bpp:    u32,
        red_shift:   u8,
        green_shift: u8,
        blue_shift:  u8,
        flags: u8,
    }
    #[repr(C)]
    struct FbHwinfo {
        info:   FbInfo,
        phys:   u64,
        length: u64,
    }
    unsafe extern "C" {
        fn fb_get_info(out: *mut FbHwinfo) -> i32;
    }
    let mut hw: FbHwinfo = unsafe { core::mem::zeroed() };
    if unsafe { fb_get_info(&mut hw) } != 0 {
        log("i915_map_fb_in_gtt: fb_get_info failed");
        return -2;
    }
    if hw.phys == 0 || hw.length == 0 {
        log("i915_map_fb_in_gtt: fb hwinfo missing phys/size");
        return -3;
    }
    if hw.info.bpp != 32 {
        unsafe {
            fut_printf(
                b"i915_map_fb_in_gtt: only 32 bpp supported, got %u\n\0".as_ptr(),
                hw.info.bpp,
            );
        }
        return -4;
    }

    /* Carve out a contiguous GTT VA window for the FB just below the
     * scratch page that phase 2 placed at the very top. Round size up
     * to the page count. */
    let pages = ((hw.length as usize) + 4095) / 4096;
    let gtt_top = (GTT_NUM_ENTRIES as u64) * GTT_PAGE_SIZE;
    let scratch_pages: u64 = 1;
    // If the FB doesn't fit below the scratch page, the subtraction below would
    // underflow to a wild GPU VA and the FB would be silently left unmapped
    // (gtt_install drops out-of-range indices), leaving the GPU pointed at
    // garbage. Reject it instead.
    if scratch_pages + pages as u64 > GTT_NUM_ENTRIES as u64 {
        log("i915: framebuffer too large for GTT");
        return -5;
    }
    let fb_gpu_va = gtt_top - (scratch_pages + pages as u64) * GTT_PAGE_SIZE;

    let gtt_base = unsafe { (*st).gtt_base };
    let installed = gtt_map_range(gtt_base, fb_gpu_va, hw.phys, hw.length as usize);

    unsafe {
        (*st).fb_phys = hw.phys;
        (*st).fb_size = hw.length as usize;
        (*st).fb_gpu_va = fb_gpu_va;
        (*st).fb_pitch = hw.info.pitch;
        (*st).fb_bpp = hw.info.bpp;
        (*st).gtt_entries_used += installed;

        fut_printf(
            b"i915: FB mapped in GTT: %u pages at gpu_va=0x%llx (phys 0x%llx, %ux%u, pitch=%u)\n\0".as_ptr(),
            installed,
            fb_gpu_va,
            hw.phys,
            hw.info.width, hw.info.height, hw.info.pitch,
        );
    }
    0
}

/// Submit an XY_SRC_COPY_BLT to scroll a region of the framebuffer.
/// All coordinates are in pixels. The blit copies a (height × width)
/// rectangle from (0, src_y) to (0, dst_y) in the FB.
///
/// Returns 0 on success, negative on failure (e.g., BCS not ready,
/// FB not GTT-mapped, ring full, drain timeout).
/// Submit XY_SRC_COPY_BLT to scroll a region of the surface at
/// `gpu_va` (back to itself, in place). Same pitch on src and dst,
/// rect (0..width, src_y..src_y+height) → (0..width, dst_y..dst_y+height).
fn blt_scroll_addr(gpu_va: u32, pitch: u32,
                   src_y: u32, dst_y: u32,
                   height: u32, width: u32) -> i32 {
    let st = STATE.get();
    let mmio = unsafe { (*st).mmio_base };
    let ring_virt = unsafe { (*st).scratch_virt } as *mut u32;
    if mmio.is_null() || ring_virt.is_null() {
        return -3;
    }

    /* CPU writes into the surface (chars accumulating in back_buf, or
     * any prior FB pokes) need to land before the GPU reads them. */
    unsafe { core::arch::x86_64::_mm_mfence() };

    let cmd: [u32; 8] = [
        XY_SRC_COPY_BLT_HEADER,
        (3u32 << 24) | (ROP_SRCCOPY << 16) | (pitch & 0xFFFF),
        (dst_y << 16) | 0,
        ((dst_y + height) << 16) | width,
        gpu_va,
        pitch & 0xFFFF,
        (src_y << 16) | 0,
        gpu_va,
    ];

    if !forcewake_get_render(mmio) {
        return -4;
    }

    unsafe {
        mmio_write32_at(mmio, BCS_RING_TAIL, 0);
        for _ in 0..1_000_000 {
            if mmio_read32_at(mmio, BCS_RING_HEAD) & !0x3F == 0 {
                break;
            }
        }
        for (i, dw) in cmd.iter().enumerate() {
            core::ptr::write_volatile(ring_virt.add(i), *dw);
        }
        mmio_write32_at(mmio, BCS_RING_TAIL, (cmd.len() * 4) as u32);
        let mut drained = false;
        for _ in 0..2_000_000 {
            let head = mmio_read32_at(mmio, BCS_RING_HEAD) & !0x3F;
            let tail = mmio_read32_at(mmio, BCS_RING_TAIL) & !0x3F;
            if head == tail {
                drained = true;
                break;
            }
        }
        forcewake_put_render(mmio);
        if !drained {
            return -5;
        }
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn i915_blt_scroll(src_y: u32, dst_y: u32, height: u32, width: u32) -> i32 {
    let st = STATE.get();
    if !unsafe { (*st).bcs_ready } {
        return -1;
    }
    if unsafe { (*st).fb_gpu_va } == 0 {
        /* Lazy first-time map. */
        if i915_map_fb_in_gtt() != 0 {
            return -2;
        }
    }
    if width == 0 || height == 0 {
        return 0;
    }
    let pitch = unsafe { (*st).fb_pitch };
    let fb_va = unsafe { (*st).fb_gpu_va } as u32;
    blt_scroll_addr(fb_va, pitch, src_y, dst_y, height, width)
}

/// Phase 8: same scroll on the registered back buffer instead of FB.
/// Replaces the per-scroll ~3.8 MiB CPU memmove that fb_console_scroll
/// previously did to keep back_buf in sync after a BLT FB scroll. The
/// caller still has to clear the now-empty bottom char row in back_buf
/// (we don't paint here) and mark the screen-bottom dirty so the next
/// flush_full pushes those zeros to FB.
///
/// Returns 0 on success, negative on failure. -1 BCS not ready, -2
/// back_buf not registered (call i915_register_back_buf first).
#[unsafe(no_mangle)]
pub extern "C" fn i915_blt_scroll_back_buf(src_y: u32, dst_y: u32,
                                            height: u32, width: u32) -> i32 {
    let st = STATE.get();
    if !unsafe { (*st).bcs_ready } {
        return -1;
    }
    if unsafe { (*st).back_buf_gpu_va } == 0 {
        return -2;
    }
    if width == 0 || height == 0 {
        return 0;
    }
    let pitch = unsafe { (*st).back_buf_pitch };
    let bb_va = unsafe { (*st).back_buf_gpu_va } as u32;
    blt_scroll_addr(bb_va, pitch, src_y, dst_y, height, width)
}

/// True iff phase 3 succeeded and the BCS engine is responsive. Callers
/// gate their use of i915_blt_scroll on this.
#[unsafe(no_mangle)]
pub extern "C" fn i915_bcs_ready() -> bool {
    let st = STATE.get();
    unsafe { (*st).bcs_ready }
}

// ── Phase 5: XY_COLOR_BLT for fb_console hardware clear ──
//
// Single GPU submission that fills a rectangle with a constant color.
// Replaces fb_console_clear's CPU 4 MB+ memset.
//
// XY_COLOR_BLT command (Gen9, 6 DWORDs total, length field = 6-2 = 4):
//
//   DW0: BR00  header — 0x57300004
//                bits 31..29 = 010 (2D Command class)
//                bits 28..22 = 0x50 (XY_COLOR_BLT opcode)
//                bits 25..24 = 11   (BLT_DEPTH_32 = 32 bpp ARGB)
//                bit  21     = 1    (Write Alpha)
//                bit  20     = 1    (Write RGB)
//                bits 7..0   = 4    (DWORD length minus 2)
//   DW1: BR13  color depth + ROP + dest pitch
//                bits 25..24: depth (3 = 32 bpp)
//                bits 23..16: ROP   (0xF0 = PATCOPY)
//                bits 15..0:  dest pitch in bytes
//   DW2: BR22  dest top-left      (y << 16) | x
//   DW3: BR23  dest bottom-right  (y << 16) | x  (exclusive)
//   DW4: BR09  dest base GGTT addr (32 bits on Gen9)
//   DW5: BR16  fill color (32-bit ARGB for 32 bpp)

const XY_COLOR_BLT_HEADER: u32 = 0x5730_0004;
const ROP_PATCOPY: u32 = 0xF0;

/// Fill a rectangle of the framebuffer with the given ARGB color.
/// (x1, y1) inclusive, (x2, y2) exclusive — same convention as
/// XY_COLOR_BLT itself. width = x2 - x1, height = y2 - y1.
///
/// Returns 0 on success, negative on failure (BCS not ready,
/// FB not GTT-mapped, ring full, drain timeout).
/// Submit XY_COLOR_BLT to fill `(x1,y1)..(x2,y2)` of the surface at
/// `gpu_va` (any GGTT-mapped 32 bpp surface) with `argb`.
fn blt_clear_addr(gpu_va: u32, pitch: u32,
                  x1: u32, y1: u32, x2: u32, y2: u32,
                  argb: u32) -> i32 {
    let st = STATE.get();
    let mmio = unsafe { (*st).mmio_base };
    let ring_virt = unsafe { (*st).scratch_virt } as *mut u32;
    if mmio.is_null() || ring_virt.is_null() {
        return -3;
    }

    let cmd: [u32; 6] = [
        XY_COLOR_BLT_HEADER,
        (3u32 << 24) | (ROP_PATCOPY << 16) | (pitch & 0xFFFF),
        (y1 << 16) | x1,
        (y2 << 16) | x2,
        gpu_va,
        argb,
    ];

    if !forcewake_get_render(mmio) {
        return -4;
    }

    unsafe {
        mmio_write32_at(mmio, BCS_RING_TAIL, 0);
        for _ in 0..1_000_000 {
            if mmio_read32_at(mmio, BCS_RING_HEAD) & !0x3F == 0 {
                break;
            }
        }
        for (i, dw) in cmd.iter().enumerate() {
            core::ptr::write_volatile(ring_virt.add(i), *dw);
        }
        mmio_write32_at(mmio, BCS_RING_TAIL, (cmd.len() * 4) as u32);

        let mut drained = false;
        for _ in 0..2_000_000 {
            let head = mmio_read32_at(mmio, BCS_RING_HEAD) & !0x3F;
            let tail = mmio_read32_at(mmio, BCS_RING_TAIL) & !0x3F;
            if head == tail {
                drained = true;
                break;
            }
        }
        forcewake_put_render(mmio);
        if !drained {
            return -5;
        }
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn i915_blt_clear(x1: u32, y1: u32, x2: u32, y2: u32,
                                  argb: u32) -> i32 {
    let st = STATE.get();
    if !unsafe { (*st).bcs_ready } {
        return -1;
    }
    if unsafe { (*st).fb_gpu_va } == 0 {
        if i915_map_fb_in_gtt() != 0 {
            return -2;
        }
    }
    if x2 <= x1 || y2 <= y1 {
        return 0;
    }
    let pitch = unsafe { (*st).fb_pitch };
    let fb_va = unsafe { (*st).fb_gpu_va } as u32;
    blt_clear_addr(fb_va, pitch, x1, y1, x2, y2, argb)
}

/// Phase 9: same XY_COLOR_BLT against the registered back buffer.
/// Replaces fb_console_clear's CPU loop that re-zeroed back_buf
/// after i915_blt_clear painted FB.
///
/// Returns 0 on success. -1 BCS not ready, -2 back_buf not registered.
#[unsafe(no_mangle)]
pub extern "C" fn i915_blt_clear_back_buf(x1: u32, y1: u32, x2: u32, y2: u32,
                                           argb: u32) -> i32 {
    let st = STATE.get();
    if !unsafe { (*st).bcs_ready } {
        return -1;
    }
    if unsafe { (*st).back_buf_gpu_va } == 0 {
        return -2;
    }
    if x2 <= x1 || y2 <= y1 {
        return 0;
    }
    let pitch = unsafe { (*st).back_buf_pitch };
    let bb_va = unsafe { (*st).back_buf_gpu_va } as u32;
    blt_clear_addr(bb_va, pitch, x1, y1, x2, y2, argb)
}

// ── Phase 6: XY_SRC_COPY_BLT for fb_console_present (back_buf → fb) ──
//
// fb_console_flush_full was a CPU memcpy from a cached DRAM back buffer
// to the WC-mapped framebuffer (~4 MiB on a 1366×768 panel, every
// newline). Once the BCS engine is up we can issue a single
// XY_SRC_COPY_BLT (8 DWORDs) that copies the entire back-buffer to the
// framebuffer at full DRAM bandwidth without touching the CPU.
//
// To do that we need the back_buf accessible to the GPU through the
// GTT. The buffer lives in kernel BSS — physically contiguous when
// loaded by GRUB but mapped into the higher-half kernel mapping. We
// walk it page-by-page, ask the kernel for the phys frame of each
// page, and install a GTT PTE for it.

/// Register fb_console's cached back buffer with the GTT. After this
/// call, i915_blt_present() can copy from `back_buf_gpu_va` to the
/// framebuffer in a single submission.
///
/// `virt` must be the kernel-virtual address of the buffer (typically
/// the address of fb_console's BSS-resident `g_fb_back_buf`).
/// `size` is the number of bytes the buffer holds, and `pitch` is the
/// stride in bytes per scanline (matches `fb_pitch` on a same-geometry
/// back buffer).
///
/// Returns 0 on success, negative on failure. Idempotent.
#[unsafe(no_mangle)]
pub extern "C" fn i915_register_back_buf(virt: *const u8, size: usize, pitch: u32) -> i32 {
    let st = STATE.get();
    if !unsafe { (*st).gtt_initialized } {
        log("i915_register_back_buf: GTT not initialized");
        return -1;
    }
    if unsafe { (*st).back_buf_gpu_va } != 0 {
        return 0; /* already registered */
    }
    if unsafe { (*st).fb_gpu_va } == 0 {
        if i915_map_fb_in_gtt() != 0 {
            return -2;
        }
    }
    if virt.is_null() || size == 0 {
        return -3;
    }

    let pages = (size + 4095) / 4096;
    let scratch_pages: u64 = 1;
    let fb_pages: u64 = ((unsafe { (*st).fb_size } + 4095) / 4096) as u64;
    let gtt_top = (GTT_NUM_ENTRIES as u64) * GTT_PAGE_SIZE;
    /* Place back_buf right below the FB window (which is right below
     * the scratch page). Reject it if it doesn't fit, so the subtraction
     * can't underflow into a wild GPU VA (see i915_map_fb_in_gtt). */
    if scratch_pages + fb_pages + pages as u64 > GTT_NUM_ENTRIES as u64 {
        log("i915: back buffer too large for GTT");
        return -5;
    }
    let back_buf_gpu_va =
        gtt_top - (scratch_pages + fb_pages + pages as u64) * GTT_PAGE_SIZE;

    let gtt_base = unsafe { (*st).gtt_base };
    /* Walk pages, virt_to_phys each, install. BSS is contiguous in
     * physical memory in practice, but we don't rely on that — every
     * page goes through the kernel's lookup. */
    for i in 0..pages {
        let v_page = unsafe { virt.add(i * 4096) } as *const c_void;
        let phys = unsafe { rust_virt_to_phys(v_page) };
        if phys == 0 {
            unsafe {
                fut_printf(
                    b"i915_register_back_buf: virt_to_phys(0x%llx) -> 0 at page %u\n\0".as_ptr(),
                    v_page as u64, i as u32,
                );
            }
            return -4;
        }
        let va = back_buf_gpu_va + (i as u64) * GTT_PAGE_SIZE;
        gtt_install(gtt_base, va, phys);
    }

    unsafe {
        (*st).back_buf_gpu_va = back_buf_gpu_va;
        (*st).back_buf_size = size;
        (*st).back_buf_pitch = pitch;
        (*st).gtt_entries_used += pages as u32;

        fut_printf(
            b"i915: back_buf mapped in GTT: %u pages at gpu_va=0x%llx (pitch=%u)\n\0".as_ptr(),
            pages as u32, back_buf_gpu_va, pitch,
        );
    }
    0
}

/// Submit XY_SRC_COPY_BLT to copy the entire registered back-buffer to
/// the framebuffer. Replaces fb_console_flush_full's CPU memcpy.
///
/// Width and height are the FB's pixel dimensions (taken from the
/// stored `fb_pitch`/`fb_size` and caller-provided height).
///
/// Returns 0 on success, negative on failure. The C side must fall
/// back to a CPU memcpy when this returns nonzero.
#[unsafe(no_mangle)]
pub extern "C" fn i915_blt_present(width: u32, height: u32) -> i32 {
    let st = STATE.get();
    if !unsafe { (*st).bcs_ready } {
        return -1;
    }
    if unsafe { (*st).fb_gpu_va } == 0 || unsafe { (*st).back_buf_gpu_va } == 0 {
        return -2;
    }
    if width == 0 || height == 0 {
        return 0;
    }

    let mmio = unsafe { (*st).mmio_base };
    let ring_virt = unsafe { (*st).scratch_virt } as *mut u32;
    let pitch = unsafe { (*st).fb_pitch };
    let fb_va = unsafe { (*st).fb_gpu_va } as u32;
    let bb_va = unsafe { (*st).back_buf_gpu_va } as u32;

    if mmio.is_null() || ring_virt.is_null() {
        return -3;
    }

    /* Make sure CPU stores to the back buffer are visible to the GPU
     * before submission. On Gen9 LP the iGPU shares the LLC, so an
     * mfence is sufficient — no explicit cache flush needed. */
    unsafe { core::arch::x86_64::_mm_mfence() };

    let cmd: [u32; 8] = [
        XY_SRC_COPY_BLT_HEADER,
        /* BR13: depth=3 (32bpp), ROP=SRCCOPY, dest pitch */
        (3u32 << 24) | (ROP_SRCCOPY << 16) | (pitch & 0xFFFF),
        /* BR05: dest top-left (0, 0) */
        0,
        /* BR06: dest bottom-right (height << 16) | width */
        (height << 16) | width,
        /* BR09: dest base GGTT addr (framebuffer) */
        fb_va,
        /* BR11: source pitch (low 16 bits) — same as fb pitch */
        pitch & 0xFFFF,
        /* BR26: source top-left (0, 0) */
        0,
        /* BR12: source base GGTT addr (back buffer) */
        bb_va,
    ];

    if !forcewake_get_render(mmio) {
        return -4;
    }

    unsafe {
        /* Drain any prior submission before reusing ring offset 0. */
        mmio_write32_at(mmio, BCS_RING_TAIL, 0);
        for _ in 0..1_000_000 {
            if mmio_read32_at(mmio, BCS_RING_HEAD) & !0x3F == 0 {
                break;
            }
        }

        for (i, dw) in cmd.iter().enumerate() {
            core::ptr::write_volatile(ring_virt.add(i), *dw);
        }
        mmio_write32_at(mmio, BCS_RING_TAIL, (cmd.len() * 4) as u32);

        let mut drained = false;
        for _ in 0..2_000_000 {
            let head = mmio_read32_at(mmio, BCS_RING_HEAD) & !0x3F;
            let tail = mmio_read32_at(mmio, BCS_RING_TAIL) & !0x3F;
            if head == tail {
                drained = true;
                break;
            }
        }

        forcewake_put_render(mmio);
        if !drained {
            return -5;
        }
    }
    0
}

/// True iff phase 6 is wired up: the BCS engine is alive and the
/// back-buffer has been registered with the GTT. Callers gate their
/// fast-path BLT presents on this.
#[unsafe(no_mangle)]
pub extern "C" fn i915_present_ready() -> bool {
    let st = STATE.get();
    unsafe { (*st).bcs_ready && (*st).back_buf_gpu_va != 0 }
}

// ── Phase 7: dirty-region BLT present ──
//
// Most fb_console flushes only change a single character row (one
// new line of text). Blitting the whole framebuffer for those wastes
// memory bandwidth proportional to (rows × char_height) /
// char_height ≈ rows-fold. A rect-form XY_SRC_COPY_BLT cuts the
// transfer to just the dirty scanlines.
//
// Same command as i915_blt_present but the source/dest rect uses
// (x1, y1, x2, y2) chosen by the caller, with the same offset on
// both sides (we're not panning, just copying a sub-region in place).

/// Submit XY_SRC_COPY_BLT to copy a rectangle of the registered
/// back-buffer to the same rectangle in the framebuffer.
/// (x1, y1) inclusive, (x2, y2) exclusive.
///
/// Returns 0 on success, negative on failure.
#[unsafe(no_mangle)]
pub extern "C" fn i915_blt_present_rect(x1: u32, y1: u32,
                                         x2: u32, y2: u32) -> i32 {
    let st = STATE.get();
    if !unsafe { (*st).bcs_ready } {
        return -1;
    }
    if unsafe { (*st).fb_gpu_va } == 0 || unsafe { (*st).back_buf_gpu_va } == 0 {
        return -2;
    }
    if x2 <= x1 || y2 <= y1 {
        return 0;
    }

    let mmio = unsafe { (*st).mmio_base };
    let ring_virt = unsafe { (*st).scratch_virt } as *mut u32;
    let pitch = unsafe { (*st).fb_pitch };
    let fb_va = unsafe { (*st).fb_gpu_va } as u32;
    let bb_va = unsafe { (*st).back_buf_gpu_va } as u32;

    if mmio.is_null() || ring_virt.is_null() {
        return -3;
    }

    /* CPU stores → LLC visible to iGPU before the BLT reads them. */
    unsafe { core::arch::x86_64::_mm_mfence() };

    let cmd: [u32; 8] = [
        XY_SRC_COPY_BLT_HEADER,
        (3u32 << 24) | (ROP_SRCCOPY << 16) | (pitch & 0xFFFF),
        /* BR05: dest top-left */
        (y1 << 16) | x1,
        /* BR06: dest bottom-right exclusive */
        (y2 << 16) | x2,
        /* BR09: dest base GGTT addr */
        fb_va,
        /* BR11: source pitch (low 16 bits) */
        pitch & 0xFFFF,
        /* BR26: source top-left (same as dest — copy in place) */
        (y1 << 16) | x1,
        /* BR12: source base GGTT addr */
        bb_va,
    ];

    if !forcewake_get_render(mmio) {
        return -4;
    }

    unsafe {
        mmio_write32_at(mmio, BCS_RING_TAIL, 0);
        for _ in 0..1_000_000 {
            if mmio_read32_at(mmio, BCS_RING_HEAD) & !0x3F == 0 {
                break;
            }
        }
        for (i, dw) in cmd.iter().enumerate() {
            core::ptr::write_volatile(ring_virt.add(i), *dw);
        }
        mmio_write32_at(mmio, BCS_RING_TAIL, (cmd.len() * 4) as u32);

        let mut drained = false;
        for _ in 0..2_000_000 {
            let head = mmio_read32_at(mmio, BCS_RING_HEAD) & !0x3F;
            let tail = mmio_read32_at(mmio, BCS_RING_TAIL) & !0x3F;
            if head == tail {
                drained = true;
                break;
            }
        }

        forcewake_put_render(mmio);
        if !drained {
            return -5;
        }
    }
    0
}
