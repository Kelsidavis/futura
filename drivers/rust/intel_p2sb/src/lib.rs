// SPDX-License-Identifier: MPL-2.0
//
// Intel P2SB (Primary to Sideband) Bridge Driver for Futura OS
//
// The P2SB bridge exposes the sideband MMIO aperture used by several
// Platform Controller Hub blocks such as GPIO, SPI, PMC, and SMBus.
// This driver performs PCI discovery, enables BAR0 decoding, maps the
// sideband register window, and provides simple read/write helpers.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(unexpected_cfgs)]

use core::cell::UnsafeCell;
use core::ptr::{read_volatile, write_volatile};

use common::{log, map_mmio_region, unmap_mmio_region, MMIO_DEFAULT_FLAGS};

unsafe extern "C" {
    fn fut_printf(fmt: *const u8, ...);
    fn pci_device_count() -> i32;
    fn pci_get_device(index: i32) -> *const PciDevice;
}

#[repr(C)]
struct PciDevice {
    bus: u8,
    dev: u8,
    func: u8,
    vendor_id: u16,
    device_id: u16,
    class_code: u8,
    subclass: u8,
    prog_if: u8,
    revision: u8,
    header_type: u8,
    subsys_vendor: u16,
    subsys_id: u16,
    irq_line: u8,
}

struct StaticCell<T>(UnsafeCell<T>);
unsafe impl<T> Sync for StaticCell<T> {}
impl<T> StaticCell<T> {
    const fn new(v: T) -> Self { Self(UnsafeCell::new(v)) }
    fn get(&self) -> *mut T { self.0.get() }
}

const PCI_CONFIG_ADDR: u16 = 0x0CF8;
const PCI_CONFIG_DATA: u16 = 0x0CFC;
const PCI_COMMAND: u8 = 0x04;
const PCI_BAR0: u8 = 0x10;

const PCI_CMD_MEM_SPACE: u16 = 1 << 1;
const PCI_CMD_BUS_MASTER: u16 = 1 << 2;

const INTEL_VENDOR_ID: u16 = 0x8086;
const P2SB_DEVICE_IDS: &[u16] = &[
    0xA308, // Cannon/Comet Lake
    0x9D21, // Sunrise Point-LP
    0xA0A1, // Tiger Lake
    0x51A1, // Alder/Raptor Lake
    0x7E22, // Meteor Lake
    0x3192, // Gemini Lake / Apollo Lake (HP Chromebook 11 G7)
    0x5A92, // Apollo Lake (older Atom)
    0x31BB, // Gemini Lake refresh
    0x0BD0, // Tremont (Jasper Lake derivatives)
    0x1980, // Elkhart Lake
    0x9D20, // Sunrise Point alt
];

// Hidden-bridge unhide: on Apollo/Gemini Lake the P2SB is hidden from
// PCI enumeration by default (Coreboot leaves it hidden post-boot to
// match Linux's expected init order). Writing 0 to config byte 0xE1 at
// 00:0D.0 clears the hide bit — the byte write lands even when the
// device reads as vendor=0xFFFF. After unhide, re-read the config
// header to get the real vendor/device ID. This mirrors the logic in
// intel_pinctrl which had to do the same trick to find the SBREG_BAR.
const P2SB_E0H_HIDE_BYTE: u8 = 0xE1;

const PCI_CLASS_BRIDGE: u8 = 0x06;
const PCI_SUBCLASS_OTHER_BRIDGE: u8 = 0x80;

const P2SB_MMIO_SIZE: usize = 0x0100_0000;
const BAR_MEM_MASK: u32 = 0xFFFF_FFF0;

struct P2sbState {
    base: *mut u8,
    phys_base: u64,
    bus: u8,
    dev: u8,
    func: u8,
    device_id: u16,
    initialized: bool,
}

impl P2sbState {
    const fn new() -> Self {
        Self {
            base: core::ptr::null_mut(),
            phys_base: 0,
            bus: 0,
            dev: 0,
            func: 0,
            device_id: 0,
            initialized: false,
        }
    }
}

static STATE: StaticCell<P2sbState> = StaticCell::new(P2sbState::new());

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

fn pci_read16(bus: u8, dev: u8, func: u8, offset: u8) -> u16 {
    let val32 = pci_read32(bus, dev, func, offset & 0xFC);
    ((val32 >> ((offset & 2) * 8)) & 0xFFFF) as u16
}

fn pci_write8(bus: u8, dev: u8, func: u8, offset: u8, val: u8) {
    let aligned = offset & 0xFC;
    let shift = (offset & 3) * 8;
    let mut val32 = pci_read32(bus, dev, func, aligned);
    val32 &= !(0xFF << shift);
    val32 |= (val as u32) << shift;
    pci_write32(bus, dev, func, aligned, val32);
}

fn pci_write16(bus: u8, dev: u8, func: u8, offset: u8, val: u16) {
    let aligned = offset & 0xFC;
    let shift = (offset & 2) * 8;
    let mut val32 = pci_read32(bus, dev, func, aligned);
    val32 &= !(0xFFFF << shift);
    val32 |= (val as u32) << shift;
    pci_write32(bus, dev, func, aligned, val32);
}

fn mmio_read32(base: *mut u8, offset: usize) -> u32 {
    unsafe { read_volatile(base.add(offset) as *const u32) }
}

fn mmio_write32(base: *mut u8, offset: usize, val: u32) {
    unsafe { write_volatile(base.add(offset) as *mut u32, val) }
}

fn find_p2sb() -> Option<PciDevice> {
    /* First try the normal PCI enumeration result. This works on PCH
     * generations where firmware leaves P2SB visible. */
    let count = unsafe { pci_device_count() };
    for i in 0..count {
        let dev = unsafe { pci_get_device(i) };
        if dev.is_null() {
            continue;
        }
        let dev = unsafe { &*dev };
        if dev.vendor_id != INTEL_VENDOR_ID {
            continue;
        }
        if dev.class_code != PCI_CLASS_BRIDGE || dev.subclass != PCI_SUBCLASS_OTHER_BRIDGE {
            continue;
        }
        if P2SB_DEVICE_IDS.contains(&dev.device_id) || (dev.bus == 0 && dev.dev == 0x1F && dev.func == 1) {
            return Some(PciDevice { ..*dev });
        }
    }

    /* Apollo/Gemini Lake hide the P2SB at 00:0D.0 by default — Coreboot
     * leaves it that way to match Linux's init order. Probe the canonical
     * location directly: read the config header, and if the device reads
     * as 0xFFFF (hidden) or a non-P2SB vendor, clear the hide bit by
     * writing 0 to config byte 0xE1, then re-read. The byte write lands
     * even when the device reads as 0xFFFF. */
    let direct = pci_read32(0, 0x0D, 0, 0);
    let mut vendor = (direct & 0xFFFF) as u16;
    let mut device = (direct >> 16) as u16;
    if vendor != INTEL_VENDOR_ID || !P2SB_DEVICE_IDS.contains(&device) {
        pci_write8(0, 0x0D, 0, P2SB_E0H_HIDE_BYTE, 0);
        let after = pci_read32(0, 0x0D, 0, 0);
        vendor = (after & 0xFFFF) as u16;
        device = (after >> 16) as u16;
    }
    if vendor == INTEL_VENDOR_ID && P2SB_DEVICE_IDS.contains(&device) {
        log("intel_p2sb: unhid P2SB at 00:0D.0");
        return Some(PciDevice {
            bus: 0,
            dev: 0x0D,
            func: 0,
            vendor_id: vendor,
            device_id: device,
            class_code: PCI_CLASS_BRIDGE,
            subclass: PCI_SUBCLASS_OTHER_BRIDGE,
            prog_if: 0,
            revision: 0,
            header_type: 0,
            subsys_vendor: 0,
            subsys_id: 0,
            irq_line: 0,
        });
    }
    None
}

#[unsafe(no_mangle)]
pub extern "C" fn intel_p2sb_init() -> i32 {
    let state = unsafe { &mut *STATE.get() };
    if state.initialized {
        log("intel_p2sb: already initialised");
        return 0;
    }

    let dev = match find_p2sb() {
        Some(dev) => dev,
        None => {
            log("intel_p2sb: no P2SB bridge found");
            return -1;
        }
    };

    let mut cmd = pci_read16(dev.bus, dev.dev, dev.func, PCI_COMMAND);
    cmd |= PCI_CMD_MEM_SPACE | PCI_CMD_BUS_MASTER;
    pci_write16(dev.bus, dev.dev, dev.func, PCI_COMMAND, cmd);

    let bar0 = pci_read32(dev.bus, dev.dev, dev.func, PCI_BAR0);
    let phys = (bar0 & BAR_MEM_MASK) as u64;
    if phys == 0 {
        log("intel_p2sb: BAR0 not configured");
        return -2;
    }

    let base = unsafe { map_mmio_region(phys, P2SB_MMIO_SIZE, MMIO_DEFAULT_FLAGS) };
    if base.is_null() {
        log("intel_p2sb: failed to map SBREG BAR");
        return -3;
    }

    state.base = base;
    state.phys_base = phys;
    state.bus = dev.bus;
    state.dev = dev.dev;
    state.func = dev.func;
    state.device_id = dev.device_id;
    state.initialized = true;

    unsafe {
        fut_printf(
            b"intel_p2sb: mapped %04x at %02x:%02x.%x SBREG=0x%llx\n\0".as_ptr(),
            dev.device_id as u32,
            dev.bus as u32,
            dev.dev as u32,
            dev.func as u32,
            phys,
        );
    }

    0
}

#[unsafe(no_mangle)]
pub extern "C" fn intel_p2sb_shutdown() {
    let state = unsafe { &mut *STATE.get() };
    if state.initialized && !state.base.is_null() {
        unsafe { unmap_mmio_region(state.base, P2SB_MMIO_SIZE) };
    }
    *state = P2sbState::new();
}

#[unsafe(no_mangle)]
pub extern "C" fn intel_p2sb_is_present() -> bool {
    unsafe { (*STATE.get()).initialized }
}

#[unsafe(no_mangle)]
pub extern "C" fn intel_p2sb_sbregbar() -> u64 {
    unsafe { (*STATE.get()).phys_base }
}

#[unsafe(no_mangle)]
pub extern "C" fn intel_p2sb_read32(offset: u32) -> u32 {
    let state = unsafe { &*STATE.get() };
    if !state.initialized || state.base.is_null() {
        return 0xFFFF_FFFF;
    }
    mmio_read32(state.base, offset as usize)
}

#[unsafe(no_mangle)]
pub extern "C" fn intel_p2sb_write32(offset: u32, val: u32) -> i32 {
    let state = unsafe { &*STATE.get() };
    if !state.initialized || state.base.is_null() {
        return -1;
    }
    mmio_write32(state.base, offset as usize, val);
    0
}
