// SPDX-License-Identifier: MPL-2.0
//
// intel_pinctrl.rs — phase 1 of the Intel SoC pin-controller driver.
//
// Target: Apollo Lake / Gemini Lake (Broxton-family) on-SoC GPIO,
// accessed via the P2SB (Primary-to-Sideband) bridge. P2SB lives at
// PCI 00:0d.0 and (per Intel's convention) is *hidden* by firmware
// after early boot. We have to write 0x00 to PCI config register
// 0xE0 of the bridge to unhide it before we can read BAR0.
//
// SBREG_BAR (BAR0 of P2SB) is a 16 MiB MMIO window. Communities are
// addressed by an 8-bit PortID, with each community's registers at
// SBREG_BAR + (PortID << 16). Per Linux's pinctrl-broxton.c:
//
//   Community         PortID  Comment
//   ---------         ------  -------
//   North              0xC4
//   NorthWest          0xC5
//   West               0xC7
//   SouthWest          0xC0
//
// Within a community, the per-pad config registers (DW0/DW1) start
// at offset 0x500 (Apollo Lake) or 0x600 (Gemini Lake), 8 bytes per
// pad. PAD_CFG_DW0 controls direction, output value, alt-function;
// PAD_CFG_DW1 controls pull / termination.
//
// Phase 1 scope:
//   - P2SB PCI detect (vendor 0x8086, device 0x5A92 / 0x319B).
//   - P2SB unhide (write 0 to PCI config 0xE0).
//   - Map SBREG_BAR (16 MiB).
//   - Dump the first N pad PAD_CFG_DW0 values for each known
//     community so we can identify which pad currently drives the
//     SD slot voltage rail.
//
// Phase 2 (next iter): actually toggle the identified pad to GPIO
// output high, drive SD_VDD_EN, and call sdhci_card_init from a
// fresh power-up state. For now we only OBSERVE.
//
// References:
//   - Linux drivers/pinctrl/intel/pinctrl-broxton.c
//   - Linux drivers/mfd/intel-p2sb.c (P2SB unhide quirk)
//   - Intel Apollo Lake EDS Volume 3 (Pad Configuration)

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(unexpected_cfgs)]

use core::cell::UnsafeCell;
use core::ffi::c_void;
use common::{log, map_mmio_region, MMIO_DEFAULT_FLAGS};

unsafe extern "C" {
    fn fut_printf(fmt: *const u8, ...);
}

// ── PCI I/O ──

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

fn pci_read8(bus: u8, dev: u8, func: u8, offset: u8) -> u8 {
    let dw = pci_read32(bus, dev, func, offset & 0xFC);
    ((dw >> ((offset & 0x3) * 8)) & 0xFF) as u8
}

fn pci_write8(bus: u8, dev: u8, func: u8, offset: u8, val: u8) {
    let aligned = offset & 0xFC;
    let shift = (offset & 0x3) * 8;
    let mask = 0xFFu32 << shift;
    let dw = pci_read32(bus, dev, func, aligned);
    let new = (dw & !mask) | ((val as u32) << shift);
    pci_write32(bus, dev, func, aligned, new);
}

// ── P2SB ──

const PCI_VENDOR_INTEL: u16 = 0x8086;

/// P2SB PCI device IDs we recognize.
///   0x5A92 — Apollo Lake
///   0x31BB — Gemini Lake (per Linux drivers/mfd/intel-p2sb.c)
///   0x3192 — Gemini Lake variant (observed on HP Chromebook 11 G7
///            after unhide; Linux's pci_ids table doesn't include
///            this stepping but it's clearly the same IP at the
///            conventional 00:0d.0 location and responds to the
///            unhide quirk identically).
///   0x0BD0 — Lakefield
///   0x1980 — Coffee Lake
///   0x9D20 — Sunrise Point-LP
const P2SB_DEVICE_IDS: &[u16] = &[0x5A92, 0x31BB, 0x3192, 0x0BD0, 0x1980, 0x9D20];

/// If the device at 00:0d.0 reports Intel vendor after unhide but
/// the device ID isn't in our known list, trust the location anyway.
/// 00:0d.0 is the conventional P2SB slot on Broxton-family SoCs and
/// nothing else lives there in firmware-default routing. Without
/// this fallback we'd be stuck adding device IDs forever.
const P2SB_TRUST_LOCATION: bool = true;

/// P2SB Hide register. The P2SB Configuration register is a 32-bit
/// field at config offset 0xE0; the HIDE control is bit 8 of that
/// dword, i.e. byte 0xE1. Clearing it reveals the device to PCI
/// config scans (firmware on Apollo/Gemini Lake leaves it set).
const P2SB_E0H_HIDE_BYTE: u8 = 0xE1;

const SBREG_BAR_SIZE: usize = 16 * 1024 * 1024;

// ── Communities ──
//
// Apollo Lake (BXT) and Gemini Lake (GLK) both use 4 communities but
// the PortIDs and the count/identity of communities differ.
//
//                     Apollo Lake     Gemini Lake
//   NORTH              0xC4            0xC5  (swapped)
//   NORTHWEST          0xC5            0xC4  (swapped)
//   WEST               0xC7            — (removed)
//   SOUTHWEST          0xC0            — (renamed to SCC)
//   AUDIO              —               0xC8  (new)
//   SCC (SD/eMMC pins) —               0xC0  (renamed from SOUTHWEST)
//
// iter-70 used the Apollo Lake set and saw NORTH/NORTHWEST come up
// (with all-zero pads) but WEST and SOUTHWEST returned all-0xff,
// confirming those PortIDs aren't valid on this Gemini Lake chip.

const COMMUNITY_GLK_NORTH:     u8 = 0xC5;
const COMMUNITY_GLK_NORTHWEST: u8 = 0xC4;
const COMMUNITY_GLK_AUDIO:     u8 = 0xC8;
const COMMUNITY_GLK_SCC:       u8 = 0xC0;

/// Per-community offset where the pad config block starts. Apollo
/// Lake uses 0x500; Gemini Lake uses 0x600. Pads are 8 bytes each
/// (DW0 + DW1).
const PAD_BASE_GLK: u32 = 0x600;

// ── Driver state ──

struct StaticCell<T>(UnsafeCell<T>);
unsafe impl<T> Sync for StaticCell<T> {}
impl<T> StaticCell<T> {
    const fn new(v: T) -> Self { Self(UnsafeCell::new(v)) }
    fn get(&self) -> *mut T { self.0.get() }
}

#[repr(C)]
struct PinctrlState {
    pub initialized: bool,
    pub bus: u8,
    pub dev: u8,
    pub func: u8,
    pub vendor: u16,
    pub device: u16,
    pub sbreg_phys: u64,
    pub sbreg_base: *mut u8,
}

unsafe impl Send for PinctrlState {}
unsafe impl Sync for PinctrlState {}

static STATE: StaticCell<PinctrlState> = StaticCell::new(PinctrlState {
    initialized: false,
    bus: 0,
    dev: 0,
    func: 0,
    vendor: 0,
    device: 0,
    sbreg_phys: 0,
    sbreg_base: core::ptr::null_mut(),
});

#[inline(always)]
unsafe fn r32(base: *const u8, offset: u32) -> u32 {
    unsafe { core::ptr::read_volatile(base.add(offset as usize) as *const u32) }
}

#[inline(always)]
#[allow(dead_code)]
unsafe fn w32(base: *mut u8, offset: u32, val: u32) {
    unsafe { core::ptr::write_volatile(base.add(offset as usize) as *mut u32, val) }
}

// ── PCI scan + unhide ──

fn find_p2sb() -> Option<(u8, u8, u8, u16, u16)> {
    /* P2SB is conventionally at 00:0d.0 on Broxton-family SoCs. Try
     * that first by reading directly. */
    let direct = pci_read32(0, 0x0d, 0, 0);
    let vendor = (direct & 0xFFFF) as u16;
    if vendor == PCI_VENDOR_INTEL {
        let device = (direct >> 16) as u16;
        if P2SB_DEVICE_IDS.contains(&device) {
            return Some((0, 0x0d, 0, vendor, device));
        }
    }
    unsafe {
        fut_printf(
            b"pinctrl: direct read 00:0d.0 returned vendor=0x%04x (not P2SB), attempting unhide\n\0".as_ptr(),
            vendor as u32,
        );
    }

    /* Unhide quirk: write 0 to config byte 0xE1 (bit 8 of the
     * 32-bit P2SBC register at 0xE0). The config write lands even
     * when the device reads as 0xFFFF. */
    pci_write8(0, 0x0d, 0, P2SB_E0H_HIDE_BYTE, 0);
    let after = pci_read32(0, 0x0d, 0, 0);
    let vendor = (after & 0xFFFF) as u16;
    let device = (after >> 16) as u16;
    unsafe {
        fut_printf(
            b"pinctrl: after unhide write, 00:0d.0 reads vendor=0x%04x device=0x%04x\n\0".as_ptr(),
            vendor as u32, device as u32,
        );
    }
    if vendor == PCI_VENDOR_INTEL && P2SB_DEVICE_IDS.contains(&device) {
        unsafe {
            fut_printf(b"pinctrl: unhid P2SB at 00:0d.0 (known device id)\n\0".as_ptr());
        }
        return Some((0, 0x0d, 0, vendor, device));
    }
    if vendor == PCI_VENDOR_INTEL && P2SB_TRUST_LOCATION {
        unsafe {
            fut_printf(
                b"pinctrl: unhid Intel device at 00:0d.0 (device=0x%04x not in known list, trusting location)\n\0".as_ptr(),
                device as u32,
            );
        }
        return Some((0, 0x0d, 0, vendor, device));
    }

    /* Fall back: scan bus 0 for any P2SB-family device. */
    for dev in 0u8..32 {
        for func in 0u8..8 {
            let dw = pci_read32(0, dev, func, 0);
            let v = (dw & 0xFFFF) as u16;
            if v != PCI_VENDOR_INTEL { continue; }
            let d = (dw >> 16) as u16;
            if P2SB_DEVICE_IDS.contains(&d) {
                return Some((0, dev, func, v, d));
            }
        }
    }

    /* Diagnostic: print every Intel device on bus 0 so the user can
     * spot a P2SB-like one we haven't listed. */
    unsafe { fut_printf(b"pinctrl: bus-0 Intel device inventory (no P2SB found):\n\0".as_ptr()); }
    for dev in 0u8..32 {
        for func in 0u8..8 {
            let dw = pci_read32(0, dev, func, 0);
            let v = (dw & 0xFFFF) as u16;
            if v != PCI_VENDOR_INTEL { continue; }
            let d = (dw >> 16) as u16;
            let class = pci_read32(0, dev, func, 0x08) >> 8;
            unsafe {
                fut_printf(
                    b"pinctrl:   00:%02x.%x device=0x%04x class=0x%06x\n\0".as_ptr(),
                    dev as u32, func as u32, d as u32, class,
                );
            }
            if func == 0 {
                let header = pci_read32(0, dev, func, 0x0C);
                let multi = ((header >> 16) & 0x80) != 0;
                if !multi { break; }
            }
        }
    }
    None
}

// ── Public C API ──

const PCI_CFG_BAR0_LO: u8 = 0x10;
const PCI_CFG_BAR0_HI: u8 = 0x14;
const PCI_CFG_COMMAND: u8 = 0x04;

/// Phase 1: detect the P2SB bridge, unhide it if firmware hid it,
/// map SBREG_BAR, and dump the first N pad config words of each
/// community so we can identify which pad drives the SD slot
/// voltage rail. Returns 0 on success, negative on failure.
#[unsafe(no_mangle)]
pub extern "C" fn intel_pinctrl_init() -> i32 {
    log("pinctrl: probing Intel P2SB bridge at 00:0d.0");

    let (bus, dev, func, vendor, device) = match find_p2sb() {
        Some(v) => v,
        None => {
            log("pinctrl: no P2SB bridge found — SoC GPIO unavailable");
            return -1;
        }
    };
    unsafe {
        fut_printf(
            b"pinctrl: P2SB at %02x:%02x.%x vendor=0x%04x device=0x%04x\n\0".as_ptr(),
            bus as u32, dev as u32, func as u32,
            vendor as u32, device as u32,
        );
    }

    /* Enable memory-space + bus-master in PCI command. */
    let mut cmd = pci_read32(bus, dev, func, PCI_CFG_COMMAND) & 0xFFFF;
    if (cmd & 0x0006) != 0x0006 {
        cmd |= 0x0006;
        pci_write32(bus, dev, func, PCI_CFG_COMMAND, cmd);
    }

    /* P2SB BAR0 is a 64-bit MMIO BAR. */
    let bar0_lo = pci_read32(bus, dev, func, PCI_CFG_BAR0_LO);
    let bar0_hi = pci_read32(bus, dev, func, PCI_CFG_BAR0_HI);
    let sbreg_phys: u64 = ((bar0_hi as u64) << 32) | ((bar0_lo as u64) & !0x0Fu64);
    if sbreg_phys == 0 {
        log("pinctrl: P2SB BAR0 not programmed by firmware");
        return -2;
    }
    unsafe {
        fut_printf(b"pinctrl: SBREG_BAR phys=0x%llx (16 MiB)\n\0".as_ptr(), sbreg_phys);
    }

    let sbreg = unsafe { map_mmio_region(sbreg_phys, SBREG_BAR_SIZE, MMIO_DEFAULT_FLAGS) };
    if sbreg.is_null() {
        log("pinctrl: failed to map SBREG_BAR");
        return -3;
    }

    let st = STATE.get();
    unsafe {
        (*st).bus = bus;
        (*st).dev = dev;
        (*st).func = func;
        (*st).vendor = vendor;
        (*st).device = device;
        (*st).sbreg_phys = sbreg_phys;
        (*st).sbreg_base = sbreg;
        (*st).initialized = true;
    }

    /* Broad PortID probe: read DW0 of pad 0 (at both candidate bases
     * 0x500 and 0x600) for every PortID 0xC0..0xCC. A community is
     * "live" if at least one read isn't all-0xff. Tells us which
     * communities actually exist on this chip without committing to
     * an APL-vs-GLK assumption. */
    unsafe { fut_printf(b"pinctrl: PortID liveness probe (DW0 of pad 0):\n\0".as_ptr()); }
    for port in 0xC0u32..=0xCCu32 {
        let community_off = port << 16;
        let at500 = unsafe { r32(sbreg, community_off + 0x500) };
        let at600 = unsafe { r32(sbreg, community_off + 0x600) };
        let live500 = at500 != 0xFFFF_FFFF;
        let live600 = at600 != 0xFFFF_FFFF;
        unsafe {
            fut_printf(
                b"pinctrl:   port=0x%02x dw0@0x500=0x%08x %s  dw0@0x600=0x%08x %s\n\0".as_ptr(),
                port,
                at500, if live500 { b"LIVE\0".as_ptr() } else { b"void\0".as_ptr() },
                at600, if live600 { b"LIVE\0".as_ptr() } else { b"void\0".as_ptr() },
            );
        }
    }

    /* Per iter-71 liveness probe, this stepping responds at PortIDs
     * 0xC4, 0xC5, 0xC6, 0xC8 (NOT 0xC0 as Linux's pinctrl-broxton.c
     * claims for SCC). So the SD/eMMC pad community is one of those.
     *
     * Walk all four. For each pad: skip if dw0 reads as 0xffffffff,
     * else decode pmode/rxdis/txdis/state. Most important flag: a
     * pad in GPIO output mode (pmode=0, txdis=0) — those are the
     * SD-VDD-enable candidates.
     *
     * PAD_CFG_DW0 layout:
     *   [31:24] PADRSTCFG / OWN
     *   [13:10] PMODE — 0 = GPIO, 1+ = native function
     *   [9]     GPIORXDIS — 1 = disable input
     *   [8]     GPIOTXDIS — 1 = disable output
     *   [1]     GPIORXSTATE — current input level
     *   [0]     GPIOTXSTATE — driven output level */
    for &port in &[0xC4u8, 0xC5u8, 0xC6u8, 0xC8u8] {
        let community_off: u32 = (port as u32) << 16;
        unsafe {
            fut_printf(
                b"pinctrl: community port=0x%02x detailed dump (PAD_BASE=0x600):\n\0".as_ptr(),
                port as u32,
            );
        }
        let mut gpio_out_count: u32 = 0;
        for pad_idx in 0u32..32 {
            let dw0_off = community_off + PAD_BASE_GLK + pad_idx * 8;
            let dw1_off = dw0_off + 4;
            let dw0 = unsafe { r32(sbreg, dw0_off) };
            let dw1 = unsafe { r32(sbreg, dw1_off) };
            if dw0 == 0xFFFF_FFFF { continue; }
            let pmode    = (dw0 >> 10) & 0xF;
            let gpio_rxd = (dw0 >> 9)  & 0x1;
            let gpio_txd = (dw0 >> 8)  & 0x1;
            let rxstate  = (dw0 >> 1)  & 0x1;
            let txstate  = dw0 & 0x1;
            let is_gpio_out = pmode == 0 && gpio_txd == 0;
            if is_gpio_out { gpio_out_count += 1; }
            let role = if pmode == 0 {
                if gpio_txd == 0 { b"*GPIO-OUT*\0".as_ptr() } else { b"GPIO-IN\0".as_ptr() }
            } else {
                b"native\0".as_ptr()
            };
            unsafe {
                fut_printf(
                    b"pinctrl:   c%02x[%2u] dw0=0x%08x dw1=0x%08x pm=%u rxd=%u txd=%u rx=%u tx=%u %s\n\0".as_ptr(),
                    port as u32, pad_idx, dw0, dw1, pmode, gpio_rxd, gpio_txd, rxstate, txstate, role,
                );
            }
        }
        unsafe {
            fut_printf(
                b"pinctrl:   port=0x%02x summary: %u GPIO-output pads (SD_VDD candidates)\n\0".as_ptr(),
                port as u32, gpio_out_count,
            );
        }
    }

    log("pinctrl: phase 1 complete (P2SB unhidden, SBREG mapped, pad dump emitted)");
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn intel_pinctrl_is_initialized() -> bool {
    let st = STATE.get();
    unsafe { (*st).initialized }
}

/// Phase 2 stub: configure a specific pad as GPIO output high. Will
/// be wired up once the user identifies the SD-VDD pin from the
/// phase-1 dump.
#[unsafe(no_mangle)]
pub extern "C" fn intel_pinctrl_set_gpio_out(port_id: u32, pad_idx: u32, value: u32) -> i32 {
    let st = STATE.get();
    if !unsafe { (*st).initialized } { return -1; }
    let base = unsafe { (*st).sbreg_base };
    if base.is_null() { return -2; }

    let community_off: u32 = port_id << 16;
    let dw0_off = community_off + PAD_BASE_GLK + pad_idx * 8;
    let mut dw0 = unsafe { r32(base, dw0_off) };

    // Force PMODE = 0 (GPIO).
    dw0 &= !(0xF << 10);
    // GPIORXDIS = 1 (disable input).
    dw0 |= 1 << 9;
    // GPIOTXDIS = 0 (enable output).
    dw0 &= !(1 << 8);
    // GPIOTXSTATE = value & 1.
    dw0 = (dw0 & !1) | (value & 1);
    unsafe { w32(base, dw0_off, dw0); }

    let readback = unsafe { r32(base, dw0_off) };
    unsafe {
        fut_printf(
            b"pinctrl: pad %u/%u <- 0x%08x (readback 0x%08x)\n\0".as_ptr(),
            port_id, pad_idx, dw0, readback,
        );
    }
    0
}
