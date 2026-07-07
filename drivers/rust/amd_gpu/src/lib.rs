// SPDX-License-Identifier: MPL-2.0
//
// AMD GPU driver for Futura OS
//
// Supports RDNA 1/2/3 discrete and APU display controllers. Discovers the
// GPU via PCI bus scan (vendor 0x1002, class 0x03), maps BAR0 MMIO and
// BAR2 VRAM aperture, identifies the ASIC generation, reads memory config,
// and brings up the SDMA0 engine for hardware-accelerated 2D copy/fill.
//
// Register references:
//   - AMD Open-Source GPU Kernel Drivers (amd-gfx / mesa)
//   - GCN/RDNA register header files (gc_10_*.h, mmhub_2_*.h, sdma_5_*.h)

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(unexpected_cfgs)]
#![allow(dead_code)]

use core::cell::UnsafeCell;
use core::ffi::c_void;
use common::{log, map_mmio_region, MMIO_DEFAULT_FLAGS};

unsafe extern "C" {
    fn fut_printf(fmt: *const u8, ...);
    fn fut_pmm_alloc_page() -> *mut c_void;
    fn rust_virt_to_phys(vaddr: *const c_void) -> u64;
    fn fb_get_info(out: *mut FbHwInfo) -> i32;
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

fn pci_write32(bus: u8, dev: u8, func: u8, offset: u8, val: u32) {
    let addr = pci_config_addr(bus, dev, func, offset);
    unsafe {
        core::arch::asm!("out dx, eax", in("dx") PCI_CONFIG_ADDR, in("eax") addr);
        core::arch::asm!("out dx, eax", in("dx") PCI_CONFIG_DATA, in("eax") val);
    }
}

// ── PCI config offsets ──

const PCI_CFG_VENDOR_DEVICE: u8 = 0x00;
const PCI_CFG_COMMAND: u8 = 0x04;
const PCI_CFG_CLASS_REV: u8 = 0x08;
const PCI_CFG_BAR0_LO: u8 = 0x10;
const PCI_CFG_BAR0_HI: u8 = 0x14;
const PCI_CFG_BAR2_LO: u8 = 0x18;
const PCI_CFG_BAR2_HI: u8 = 0x1C;
const PCI_CFG_BAR4_LO: u8 = 0x20;
const PCI_CFG_BAR4_HI: u8 = 0x24;

const PCI_VENDOR_AMD: u16 = 0x1002;
const PCI_CLASS_VGA: u8 = 0x03;

const PCI_CMD_MEM_ENABLE: u16 = 0x0002;
const PCI_CMD_BUS_MASTER: u16 = 0x0004;

// ── Framebuffer info struct (matches kernel/fb.h) ──

#[repr(C)]
struct FbInfo {
    width: u32,
    height: u32,
    pitch: u32,
    bpp: u32,
    flags: u32,
}

#[repr(C)]
struct FbHwInfo {
    phys: u64,
    length: u64,
    virt: *mut u8,
    info: FbInfo,
}

// ── ASIC families ──

#[derive(Clone, Copy, PartialEq)]
#[repr(u8)]
enum AsicFamily {
    Unknown = 0,
    Polaris,       // GCN 4 — RX 470/480/570/580
    Vega10,        // GCN 5 — Vega 56/64
    Vega20,        // GCN 5.1 — Radeon VII
    Navi10,        // RDNA 1 — RX 5600/5700
    Navi14,        // RDNA 1 — RX 5500
    Navi21,        // RDNA 2 — RX 6800/6900
    Navi22,        // RDNA 2 — RX 6700
    Navi23,        // RDNA 2 — RX 6600
    Navi24,        // RDNA 2 — RX 6400/6500
    Navi31,        // RDNA 3 — RX 7900
    Navi32,        // RDNA 3 — RX 7800/7700
    Navi33,        // RDNA 3 — RX 7600
    Renoir,        // APU — Ryzen 4000 (Vega iGPU)
    Cezanne,       // APU — Ryzen 5000 (Vega iGPU)
    Rembrandt,     // APU — Ryzen 6000 (RDNA 2 iGPU)
    Raphael,       // APU — Ryzen 7000 (RDNA 2 iGPU)
    Phoenix,       // APU — Ryzen 7040 (RDNA 3 iGPU)
}

impl AsicFamily {
    fn name(self) -> &'static [u8] {
        match self {
            Self::Unknown   => b"Unknown\0",
            Self::Polaris   => b"Polaris (GCN 4)\0",
            Self::Vega10    => b"Vega 10 (GCN 5)\0",
            Self::Vega20    => b"Vega 20 (GCN 5.1)\0",
            Self::Navi10    => b"Navi 10 (RDNA 1)\0",
            Self::Navi14    => b"Navi 14 (RDNA 1)\0",
            Self::Navi21    => b"Navi 21 (RDNA 2)\0",
            Self::Navi22    => b"Navi 22 (RDNA 2)\0",
            Self::Navi23    => b"Navi 23 (RDNA 2)\0",
            Self::Navi24    => b"Navi 24 (RDNA 2)\0",
            Self::Navi31    => b"Navi 31 (RDNA 3)\0",
            Self::Navi32    => b"Navi 32 (RDNA 3)\0",
            Self::Navi33    => b"Navi 33 (RDNA 3)\0",
            Self::Renoir    => b"Renoir APU (Vega)\0",
            Self::Cezanne   => b"Cezanne APU (Vega)\0",
            Self::Rembrandt => b"Rembrandt APU (RDNA 2)\0",
            Self::Raphael   => b"Raphael APU (RDNA 2)\0",
            Self::Phoenix   => b"Phoenix APU (RDNA 3)\0",
        }
    }

    fn is_rdna(self) -> bool {
        matches!(self,
            Self::Navi10 | Self::Navi14 |
            Self::Navi21 | Self::Navi22 | Self::Navi23 | Self::Navi24 |
            Self::Navi31 | Self::Navi32 | Self::Navi33 |
            Self::Rembrandt | Self::Raphael | Self::Phoenix
        )
    }

    fn is_rdna2_plus(self) -> bool {
        matches!(self,
            Self::Navi21 | Self::Navi22 | Self::Navi23 | Self::Navi24 |
            Self::Navi31 | Self::Navi32 | Self::Navi33 |
            Self::Rembrandt | Self::Raphael | Self::Phoenix
        )
    }

    fn is_rdna3(self) -> bool {
        matches!(self,
            Self::Navi31 | Self::Navi32 | Self::Navi33 | Self::Phoenix
        )
    }

    fn sdma_ip_version(self) -> u8 {
        match self {
            Self::Polaris | Self::Vega10 => 4,
            Self::Vega20 => 4,
            Self::Navi10 | Self::Navi14 => 5,
            Self::Navi21 | Self::Navi22 | Self::Navi23 | Self::Navi24 |
            Self::Rembrandt | Self::Raphael => 5,
            Self::Navi31 | Self::Navi32 | Self::Navi33 | Self::Phoenix => 6,
            Self::Renoir | Self::Cezanne => 4,
            Self::Unknown => 0,
        }
    }
}

fn identify_asic(device_id: u16) -> AsicFamily {
    match device_id {
        // Polaris (RX 470/480/570/580)
        0x67DF | 0x67C4 | 0x67C7 | 0x67D0 | 0x67E0 | 0x67E3 | 0x67E8 |
        0x67EB | 0x67EF | 0x67FF | 0x6FDF => AsicFamily::Polaris,

        // Vega 10 (Vega 56/64)
        0x6860 | 0x6861 | 0x6862 | 0x6863 | 0x6864 | 0x6867 | 0x6868 |
        0x6869 | 0x686A | 0x686B | 0x686C | 0x686D | 0x686E | 0x687F => AsicFamily::Vega10,

        // Vega 20 (Radeon VII)
        0x66A0 | 0x66A1 | 0x66A2 | 0x66A3 | 0x66A7 | 0x66AF => AsicFamily::Vega20,

        // Navi 10 (RX 5600/5700)
        0x7310 | 0x7312 | 0x7318 | 0x7319 | 0x731A | 0x731B | 0x731E |
        0x731F | 0x7340 => AsicFamily::Navi10,

        // Navi 14 (RX 5500)
        0x7341 | 0x7347 | 0x734F => AsicFamily::Navi14,

        // Navi 21 (RX 6800/6900)
        0x73A0 | 0x73A1 | 0x73A2 | 0x73A3 | 0x73A5 | 0x73AB | 0x73AE |
        0x73AF | 0x73BF => AsicFamily::Navi21,

        // Navi 22 (RX 6700)
        0x73C0 | 0x73C1 | 0x73C3 | 0x73DA | 0x73DB | 0x73DC | 0x73DD |
        0x73DE | 0x73DF => AsicFamily::Navi22,

        // Navi 23 (RX 6600)
        0x73E0 | 0x73E1 | 0x73E3 | 0x73E8 | 0x73E9 | 0x73EF |
        0x73FF => AsicFamily::Navi23,

        // Navi 24 (RX 6400/6500)
        0x7421 | 0x7422 | 0x7423 | 0x7424 | 0x743F => AsicFamily::Navi24,

        // Navi 31 (RX 7900)
        0x7440 | 0x7441 | 0x7448 | 0x744C | 0x745E => AsicFamily::Navi31,

        // Navi 32 (RX 7800/7700)
        0x7470 | 0x7471 | 0x7478 | 0x747E => AsicFamily::Navi32,

        // Navi 33 (RX 7600)
        0x7480 | 0x7481 | 0x7483 | 0x7489 | 0x748E => AsicFamily::Navi33,

        // APU — Renoir / Lucienne (Ryzen 4000/5000 mobile Vega iGPU)
        0x1636 | 0x1637 | 0x1638 => AsicFamily::Renoir,

        // APU — Cezanne / Barcelo (Ryzen 5000 desktop/mobile Vega iGPU)
        0x1639 | 0x163F => AsicFamily::Cezanne,

        // APU — Rembrandt (Ryzen 6000, RDNA 2)
        0x1681 | 0x1682 => AsicFamily::Rembrandt,

        // APU — Raphael (Ryzen 7000 desktop, RDNA 2)
        0x164E | 0x164F => AsicFamily::Raphael,

        // APU — Phoenix (Ryzen 7040/8040, RDNA 3)
        0x15BF | 0x15C8 | 0x15D8 => AsicFamily::Phoenix,

        _ => AsicFamily::Unknown,
    }
}

// ── MMIO register offsets ──
// These are GPU internal register offsets within the BAR0 MMIO window.
// Stable across GCN/RDNA generations (indices differ but dword offsets
// are consistent in the mapped register space).

// Graphics block status
const mmGRBM_STATUS: u32          = 0x8010;
const mmGRBM_STATUS2: u32         = 0x8014;
const mmSRBM_STATUS: u32          = 0x0E50;

// Scratch registers — always accessible, useful for liveness testing
const mmSCRATCH_REG0: u32         = 0x8040;
const mmSCRATCH_REG1: u32         = 0x8044;
const mmSCRATCH_REG2: u32         = 0x8048;
const mmSCRATCH_REG3: u32         = 0x804C;

// SDMA0 engine registers (GCN/RDNA 1–2)
const mmSDMA0_STATUS_REG: u32     = 0xD034;
const mmSDMA0_GFX_RB_CNTL: u32   = 0xD000;
const mmSDMA0_GFX_RB_BASE: u32   = 0xD004;
const mmSDMA0_GFX_RB_BASE_HI: u32 = 0xD008;
const mmSDMA0_GFX_RB_RPTR: u32   = 0xD010;
const mmSDMA0_GFX_RB_WPTR: u32   = 0xD014;
const mmSDMA0_GFX_DOORBELL: u32   = 0xD01C;
const mmSDMA0_GFX_RB_WPTR_POLL_CNTL: u32 = 0xD020;

// MMHUB — VRAM location + size (RDNA)
const mmMC_VM_FB_LOCATION_BASE: u32 = 0x2068;
const mmMC_VM_FB_LOCATION_TOP: u32  = 0x206C;

// SDMA packet opcodes
const SDMA_OP_NOP: u32            = 0x00000000;
const SDMA_OP_COPY_LINEAR: u32    = 0x00000001;
const SDMA_OP_FILL: u32           = 0x0000000B;

// SDMA ring buffer config
const SDMA_RING_SIZE_LOG2: u32    = 12; // 4 KiB (1024 dwords)
const SDMA_RING_SIZE: usize       = 1 << SDMA_RING_SIZE_LOG2;

// ── Driver state ──

struct StaticCell<T>(UnsafeCell<T>);
unsafe impl<T> Sync for StaticCell<T> {}
impl<T> StaticCell<T> {
    const fn new(v: T) -> Self { Self(UnsafeCell::new(v)) }
    fn get(&self) -> *mut T { self.0.get() }
}

struct AmdGpuState {
    initialized: bool,
    pci_bus: u8,
    pci_dev: u8,
    pci_func: u8,
    vendor_id: u16,
    device_id: u16,
    revision: u8,
    asic: AsicFamily,

    bar0_phys: u64,
    bar0_size: u64,
    mmio_base: *mut u8,

    bar2_phys: u64,
    bar2_size: u64,
    vram_base: *mut u8,
    vram_mapped: bool,

    vram_size_mb: u32,

    sdma_ready: bool,
    sdma_ring_virt: *mut u8,
    sdma_ring_phys: u64,
    sdma_wptr: u32,

    fb_phys: u64,
    fb_size: u64,
    fb_width: u32,
    fb_height: u32,
    fb_pitch: u32,
    fb_bpp: u32,
}

unsafe impl Send for AmdGpuState {}
unsafe impl Sync for AmdGpuState {}

static STATE: StaticCell<AmdGpuState> = StaticCell::new(AmdGpuState {
    initialized: false,
    pci_bus: 0,
    pci_dev: 0,
    pci_func: 0,
    vendor_id: 0,
    device_id: 0,
    revision: 0,
    asic: AsicFamily::Unknown,
    bar0_phys: 0,
    bar0_size: 0,
    mmio_base: core::ptr::null_mut(),
    bar2_phys: 0,
    bar2_size: 0,
    vram_base: core::ptr::null_mut(),
    vram_mapped: false,
    vram_size_mb: 0,
    sdma_ready: false,
    sdma_ring_virt: core::ptr::null_mut(),
    sdma_ring_phys: 0,
    sdma_wptr: 0,
    fb_phys: 0,
    fb_size: 0,
    fb_width: 0,
    fb_height: 0,
    fb_pitch: 0,
    fb_bpp: 0,
});

#[inline(always)]
fn state() -> &'static mut AmdGpuState {
    unsafe { &mut *STATE.get() }
}

#[inline(always)]
unsafe fn mmio_read32(base: *const u8, offset: u32) -> u32 {
    unsafe { core::ptr::read_volatile(base.add(offset as usize) as *const u32) }
}

#[inline(always)]
unsafe fn mmio_write32(base: *mut u8, offset: u32, val: u32) {
    unsafe { core::ptr::write_volatile(base.add(offset as usize) as *mut u32, val) }
}

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

// ── PCI bus scan ──
// Scan bus 0 for AMD display controllers. APUs are typically at 00:08.0
// or similar low device numbers; discrete GPUs sit wherever the BIOS
// assigns them (often bus 0 or 1+). We scan bus 0 devices 0–31.

fn pci_scan_amd_gpu() -> Option<(u8, u8, u8, u16, u16, u8)> {
    for dev in 0..32u8 {
        for func in 0..8u8 {
            let vd = pci_read32(0, dev, func, PCI_CFG_VENDOR_DEVICE);
            if vd == 0xFFFFFFFF || vd == 0 {
                if func == 0 { break; }
                continue;
            }
            let vendor = (vd & 0xFFFF) as u16;
            if vendor != PCI_VENDOR_AMD {
                if func == 0 { break; }
                continue;
            }
            let class_rev = pci_read32(0, dev, func, PCI_CFG_CLASS_REV);
            let class = ((class_rev >> 24) & 0xFF) as u8;
            if class != PCI_CLASS_VGA {
                continue;
            }
            let device = (vd >> 16) as u16;
            let revision = (class_rev & 0xFF) as u8;
            return Some((0, dev, func, vendor, device, revision));
        }
    }
    None
}

fn read_bar64(bus: u8, dev: u8, func: u8, bar_lo_off: u8, bar_hi_off: u8) -> (u64, u64) {
    let lo_raw = pci_read32(bus, dev, func, bar_lo_off);
    let hi_raw = pci_read32(bus, dev, func, bar_hi_off);
    let is_64bit = (lo_raw & 0x06) == 0x04;
    let base = if is_64bit {
        ((hi_raw as u64) << 32) | ((lo_raw as u64) & !0xF)
    } else {
        (lo_raw as u64) & !0xF
    };

    // Size the BAR: write all-ones, read back, restore
    pci_write32(bus, dev, func, bar_lo_off, 0xFFFFFFFF);
    let size_lo = pci_read32(bus, dev, func, bar_lo_off);
    pci_write32(bus, dev, func, bar_lo_off, lo_raw);

    let size_mask = if is_64bit {
        pci_write32(bus, dev, func, bar_hi_off, 0xFFFFFFFF);
        let size_hi = pci_read32(bus, dev, func, bar_hi_off);
        pci_write32(bus, dev, func, bar_hi_off, hi_raw);
        ((size_hi as u64) << 32) | ((size_lo as u64) & !0xF)
    } else {
        (size_lo as u64) & !0xF
    };

    let size = if size_mask == 0 { 0 } else { (!size_mask).wrapping_add(1) };
    (base, size)
}

// ── Phase 1: PCI detect + MMIO map ──

#[unsafe(no_mangle)]
pub extern "C" fn amd_gpu_init() -> i32 {
    log("amd-gpu: scanning PCI bus for AMD display controller");

    let (bus, dev, func, vendor, device, revision) = match pci_scan_amd_gpu() {
        Some(r) => r,
        None => {
            log("amd-gpu: no AMD GPU found on PCI bus 0");
            return -19; // ENODEV
        }
    };

    let asic = identify_asic(device);
    unsafe {
        fut_printf(
            b"amd-gpu: found %s [%04x:%04x rev %02x] at PCI %02x:%02x.%x\n\0".as_ptr(),
            asic.name().as_ptr(),
            vendor as u32, device as u32, revision as u32,
            bus as u32, dev as u32, func as u32,
        );
    }

    // Enable memory space + bus master
    let cmd = pci_read32(bus, dev, func, PCI_CFG_COMMAND) as u16;
    if (cmd & (PCI_CMD_MEM_ENABLE | PCI_CMD_BUS_MASTER)) != (PCI_CMD_MEM_ENABLE | PCI_CMD_BUS_MASTER) {
        let new_cmd = cmd | PCI_CMD_MEM_ENABLE | PCI_CMD_BUS_MASTER;
        pci_write32(bus, dev, func, PCI_CFG_COMMAND, new_cmd as u32);
    }

    // BAR0 — MMIO register window
    let (bar0_phys, bar0_size) = read_bar64(bus, dev, func, PCI_CFG_BAR0_LO, PCI_CFG_BAR0_HI);
    if bar0_phys == 0 || bar0_size == 0 {
        log("amd-gpu: BAR0 not configured");
        return -5; // EIO
    }

    // Map a reasonable chunk — 16 MiB covers all register blocks
    let map_size = core::cmp::min(bar0_size, 16 * 1024 * 1024) as usize;
    let mmio = unsafe { map_mmio_region(bar0_phys, map_size, MMIO_DEFAULT_FLAGS) };
    if mmio.is_null() {
        log("amd-gpu: failed to map BAR0 MMIO");
        return -12; // ENOMEM
    }

    unsafe {
        fut_printf(
            b"amd-gpu: BAR0 MMIO at phys 0x%016llx, size %u MiB, mapped at %p\n\0".as_ptr(),
            bar0_phys, (bar0_size / (1024 * 1024)) as u32, mmio,
        );
    }

    // BAR2 — VRAM aperture (discrete GPUs; may be absent on APUs)
    let (bar2_phys, bar2_size) = read_bar64(bus, dev, func, PCI_CFG_BAR2_LO, PCI_CFG_BAR2_HI);

    let s = state();
    s.initialized = true;
    s.pci_bus = bus;
    s.pci_dev = dev;
    s.pci_func = func;
    s.vendor_id = vendor;
    s.device_id = device;
    s.revision = revision;
    s.asic = asic;
    s.bar0_phys = bar0_phys;
    s.bar0_size = bar0_size;
    s.mmio_base = mmio;
    s.bar2_phys = bar2_phys;
    s.bar2_size = bar2_size;

    // Test register access — write scratch register and read back
    let test_val: u32 = 0xDEAD_BEEF;
    unsafe {
        mmio_write32(mmio, mmSCRATCH_REG0, test_val);
        let readback = mmio_read32(mmio, mmSCRATCH_REG0);
        if readback == test_val {
            fut_printf(b"amd-gpu: MMIO scratch register test PASSED\n\0".as_ptr());
        } else {
            fut_printf(
                b"amd-gpu: MMIO scratch test FAILED (wrote 0x%08x, read 0x%08x)\n\0".as_ptr(),
                test_val, readback,
            );
        }

        // Read GPU engine status registers
        let grbm = mmio_read32(mmio, mmGRBM_STATUS);
        let grbm2 = mmio_read32(mmio, mmGRBM_STATUS2);
        let srbm = mmio_read32(mmio, mmSRBM_STATUS);
        fut_printf(
            b"amd-gpu: GRBM_STATUS=0x%08x GRBM_STATUS2=0x%08x SRBM_STATUS=0x%08x\n\0".as_ptr(),
            grbm, grbm2, srbm,
        );
    }

    // Detect VRAM size from MMHUB (RDNA) or BAR2 size (fallback)
    detect_vram_size();

    if bar2_phys != 0 && bar2_size != 0 {
        unsafe {
            fut_printf(
                b"amd-gpu: BAR2 VRAM aperture at phys 0x%016llx, size %u MiB\n\0".as_ptr(),
                bar2_phys, (bar2_size / (1024 * 1024)) as u32,
            );
        }
    }

    // Read the existing framebuffer geometry
    read_fb_info();

    0
}

fn detect_vram_size() {
    let s = state();
    let mmio = s.mmio_base;

    if s.asic.is_rdna() {
        let fb_base = unsafe { mmio_read32(mmio, mmMC_VM_FB_LOCATION_BASE) };
        let fb_top = unsafe { mmio_read32(mmio, mmMC_VM_FB_LOCATION_TOP) };
        // Each unit is 1 MiB
        if fb_top > fb_base {
            s.vram_size_mb = fb_top - fb_base;
        }
    }

    // Fallback: use BAR2 size as lower-bound estimate
    if s.vram_size_mb == 0 && s.bar2_size > 0 {
        s.vram_size_mb = (s.bar2_size / (1024 * 1024)) as u32;
    }

    if s.vram_size_mb > 0 {
        unsafe {
            fut_printf(
                b"amd-gpu: VRAM size: %u MiB\n\0".as_ptr(),
                s.vram_size_mb,
            );
        }
    }
}

fn read_fb_info() {
    let s = state();
    let mut hw: FbHwInfo = FbHwInfo {
        phys: 0,
        length: 0,
        virt: core::ptr::null_mut(),
        info: FbInfo { width: 0, height: 0, pitch: 0, bpp: 0, flags: 0 },
    };

    let rc = unsafe { fb_get_info(&mut hw as *mut FbHwInfo) };
    if rc == 0 && hw.info.width > 0 && hw.info.height > 0 {
        s.fb_phys = hw.phys;
        s.fb_size = hw.length;
        s.fb_width = hw.info.width;
        s.fb_height = hw.info.height;
        s.fb_pitch = hw.info.pitch;
        s.fb_bpp = hw.info.bpp;
        unsafe {
            fut_printf(
                b"amd-gpu: firmware FB: %ux%u, %u bpp, pitch %u, phys 0x%016llx\n\0".as_ptr(),
                s.fb_width, s.fb_height, s.fb_bpp, s.fb_pitch, s.fb_phys,
            );
        }
    }
}

// ── Phase 2: SDMA engine init ──

#[unsafe(no_mangle)]
pub extern "C" fn amd_gpu_sdma_init() -> i32 {
    let s = state();
    if !s.initialized {
        return -19;
    }
    if s.sdma_ready {
        return 0;
    }
    if s.asic == AsicFamily::Unknown {
        log("amd-gpu: SDMA init skipped (unknown ASIC)");
        return -95; // ENOTSUP
    }

    log("amd-gpu: initializing SDMA0 engine");

    let (ring_virt, ring_phys) = match alloc_page_phys() {
        Some(p) => p,
        None => {
            log("amd-gpu: failed to allocate SDMA ring page");
            return -12;
        }
    };

    // Zero the ring buffer
    unsafe {
        core::ptr::write_bytes(ring_virt, 0, SDMA_RING_SIZE);
    }

    let mmio = s.mmio_base;

    unsafe {
        // Halt the SDMA engine before programming
        mmio_write32(mmio, mmSDMA0_GFX_RB_CNTL, 0);

        // Set ring buffer base address (in 256-byte units for SDMA)
        let rb_base = ring_phys >> 8;
        mmio_write32(mmio, mmSDMA0_GFX_RB_BASE, rb_base as u32);
        mmio_write32(mmio, mmSDMA0_GFX_RB_BASE_HI, (rb_base >> 32) as u32);

        // Reset read/write pointers
        mmio_write32(mmio, mmSDMA0_GFX_RB_RPTR, 0);
        mmio_write32(mmio, mmSDMA0_GFX_RB_WPTR, 0);

        // Disable doorbell and WPTR poll (we use MMIO-based WPTR)
        mmio_write32(mmio, mmSDMA0_GFX_DOORBELL, 0);
        mmio_write32(mmio, mmSDMA0_GFX_RB_WPTR_POLL_CNTL, 0);

        // Enable the ring: set size (log2) and enable bit
        // RB_CNTL: bits [6:1] = log2(size_in_dwords) - 1, bit [0] = enable
        let rb_cntl = ((SDMA_RING_SIZE_LOG2 - 1) << 1) | 1;
        mmio_write32(mmio, mmSDMA0_GFX_RB_CNTL, rb_cntl);
    }

    s.sdma_ring_virt = ring_virt;
    s.sdma_ring_phys = ring_phys;
    s.sdma_wptr = 0;

    // Submit a NOP and verify the engine consumes it
    unsafe {
        let ring = ring_virt as *mut u32;
        ring.write_volatile(SDMA_OP_NOP);
        s.sdma_wptr = 4; // advance by 1 dword (4 bytes)
        mmio_write32(mmio, mmSDMA0_GFX_RB_WPTR, s.sdma_wptr);

        // Wait for RPTR to catch up (engine consumes the NOP)
        let mut timeout = 100_000u32;
        loop {
            let rptr = mmio_read32(mmio, mmSDMA0_GFX_RB_RPTR);
            if rptr >= s.sdma_wptr {
                break;
            }
            timeout -= 1;
            if timeout == 0 {
                log("amd-gpu: SDMA0 NOP timeout — engine not responding");
                return -62; // ETIME
            }
        }
    }

    s.sdma_ready = true;
    unsafe {
        fut_printf(
            b"amd-gpu: SDMA0 engine ready (ring at phys 0x%016llx)\n\0".as_ptr(),
            ring_phys,
        );
    }
    0
}

// ── SDMA copy operation ──

#[unsafe(no_mangle)]
pub extern "C" fn amd_gpu_sdma_copy(dst_phys: u64, src_phys: u64, byte_count: u32) -> i32 {
    let s = state();
    if !s.sdma_ready {
        return -19;
    }

    // SDMA LINEAR_COPY packet: 7 dwords
    //   DW0: opcode (1) | sub-opcode (0)
    //   DW1: byte count
    //   DW2: reserved (0)
    //   DW3: src addr lo
    //   DW4: src addr hi
    //   DW5: dst addr lo
    //   DW6: dst addr hi
    let ring = s.sdma_ring_virt;
    let ring_mask = (SDMA_RING_SIZE - 1) as u32;
    let wptr = s.sdma_wptr;

    unsafe {
        let base = ring as *mut u32;
        let w = |off: u32, val: u32| {
            let idx = ((wptr + off * 4) & ring_mask) / 4;
            base.add(idx as usize).write_volatile(val);
        };

        w(0, SDMA_OP_COPY_LINEAR);
        w(1, byte_count);
        w(2, 0);
        w(3, src_phys as u32);
        w(4, (src_phys >> 32) as u32);
        w(5, dst_phys as u32);
        w(6, (dst_phys >> 32) as u32);
    }

    s.sdma_wptr = (wptr + 7 * 4) & ring_mask;
    unsafe {
        mmio_write32(s.mmio_base, mmSDMA0_GFX_RB_WPTR, s.sdma_wptr);
    }

    // Wait for completion
    let mut timeout = 1_000_000u32;
    loop {
        let rptr = unsafe { mmio_read32(s.mmio_base, mmSDMA0_GFX_RB_RPTR) };
        if rptr >= s.sdma_wptr {
            break;
        }
        timeout -= 1;
        if timeout == 0 {
            return -62;
        }
    }
    0
}

// ── SDMA fill operation ──

#[unsafe(no_mangle)]
pub extern "C" fn amd_gpu_sdma_fill(dst_phys: u64, fill_value: u32, byte_count: u32) -> i32 {
    let s = state();
    if !s.sdma_ready {
        return -19;
    }

    // SDMA CONSTANT_FILL packet: 5 dwords
    //   DW0: opcode (11) | sub-opcode (0)
    //   DW1: dst addr lo
    //   DW2: dst addr hi
    //   DW3: fill value
    //   DW4: byte count
    let ring = s.sdma_ring_virt;
    let ring_mask = (SDMA_RING_SIZE - 1) as u32;
    let wptr = s.sdma_wptr;

    unsafe {
        let base = ring as *mut u32;
        let w = |off: u32, val: u32| {
            let idx = ((wptr + off * 4) & ring_mask) / 4;
            base.add(idx as usize).write_volatile(val);
        };

        w(0, SDMA_OP_FILL);
        w(1, dst_phys as u32);
        w(2, (dst_phys >> 32) as u32);
        w(3, fill_value);
        w(4, byte_count);
    }

    s.sdma_wptr = (wptr + 5 * 4) & ring_mask;
    unsafe {
        mmio_write32(s.mmio_base, mmSDMA0_GFX_RB_WPTR, s.sdma_wptr);
    }

    let mut timeout = 1_000_000u32;
    loop {
        let rptr = unsafe { mmio_read32(s.mmio_base, mmSDMA0_GFX_RB_RPTR) };
        if rptr >= s.sdma_wptr {
            break;
        }
        timeout -= 1;
        if timeout == 0 {
            return -62;
        }
    }
    0
}

// ── Query API ──

#[unsafe(no_mangle)]
pub extern "C" fn amd_gpu_is_initialized() -> bool {
    state().initialized
}

#[unsafe(no_mangle)]
pub extern "C" fn amd_gpu_device_id() -> u16 {
    state().device_id
}

#[unsafe(no_mangle)]
pub extern "C" fn amd_gpu_vram_size_mb() -> u32 {
    state().vram_size_mb
}

#[unsafe(no_mangle)]
pub extern "C" fn amd_gpu_sdma_ready() -> bool {
    state().sdma_ready
}
