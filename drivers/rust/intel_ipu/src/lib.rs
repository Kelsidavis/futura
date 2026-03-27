// SPDX-License-Identifier: MPL-2.0
//
// Intel IPU (Image Processing Unit) Driver for Futura OS
//
// Provides PCI discovery and MMIO-level bring-up for Intel IPU / IPU6
// imaging devices present on Gen 10+ client platforms. This driver keeps
// scope intentionally narrow: identify the hardware, enable BAR0, map the
// register window, and expose a few low-level status accessors.

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
const PCI_CLASS_MULTIMEDIA: u8 = 0x04;
const PCI_SUBCLASS_OTHER_MULTIMEDIA: u8 = 0x80;

const IPU_DEVICE_IDS: &[u16] = &[
    0x8A19, // Ice Lake IPU4/IPU6 family
    0x450D, // Tiger Lake
    0x465D, // Alder Lake
    0x7D19, // Raptor Lake
    0x7E4E, // Meteor Lake
];

const BAR_MEM_MASK: u32 = 0xFFFF_FFF0;
const IPU_MMIO_SIZE: usize = 0x0020_0000;

const IPU_REG_HW_VERSION: usize = 0x0000;
const IPU_REG_FW_STATUS: usize = 0x0004;
const IPU_REG_GP_CONTROL: usize = 0x0010;
const IPU_REG_GP_STATUS: usize = 0x0014;

const GP_CONTROL_RUNSTALL: u32 = 1 << 0;

struct IpuState {
    base: *mut u8,
    phys_base: u64,
    bus: u8,
    dev: u8,
    func: u8,
    device_id: u16,
    initialized: bool,
}

impl IpuState {
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

static STATE: StaticCell<IpuState> = StaticCell::new(IpuState::new());

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

fn find_ipu() -> Option<PciDevice> {
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
        if dev.class_code != PCI_CLASS_MULTIMEDIA || dev.subclass != PCI_SUBCLASS_OTHER_MULTIMEDIA {
            continue;
        }
        if IPU_DEVICE_IDS.contains(&dev.device_id) {
            return Some(PciDevice { ..*dev });
        }
    }
    None
}

#[unsafe(no_mangle)]
pub extern "C" fn intel_ipu_init() -> i32 {
    let state = unsafe { &mut *STATE.get() };
    if state.initialized {
        log("intel_ipu: already initialised");
        return 0;
    }

    let dev = match find_ipu() {
        Some(dev) => dev,
        None => {
            log("intel_ipu: no Intel IPU device found");
            return -1;
        }
    };

    let mut cmd = pci_read16(dev.bus, dev.dev, dev.func, PCI_COMMAND);
    cmd |= PCI_CMD_MEM_SPACE | PCI_CMD_BUS_MASTER;
    pci_write16(dev.bus, dev.dev, dev.func, PCI_COMMAND, cmd);

    let phys = (pci_read32(dev.bus, dev.dev, dev.func, PCI_BAR0) & BAR_MEM_MASK) as u64;
    if phys == 0 {
        log("intel_ipu: BAR0 not configured");
        return -2;
    }

    let base = unsafe { map_mmio_region(phys, IPU_MMIO_SIZE, MMIO_DEFAULT_FLAGS) };
    if base.is_null() {
        log("intel_ipu: failed to map BAR0");
        return -3;
    }

    state.base = base;
    state.phys_base = phys;
    state.bus = dev.bus;
    state.dev = dev.dev;
    state.func = dev.func;
    state.device_id = dev.device_id;
    state.initialized = true;

    let hw = mmio_read32(base, IPU_REG_HW_VERSION);
    let fw = mmio_read32(base, IPU_REG_FW_STATUS);
    unsafe {
        fut_printf(
            b"intel_ipu: found %04x at %02x:%02x.%x BAR0=0x%llx hw=0x%08x fw=0x%08x\n\0".as_ptr(),
            dev.device_id as u32,
            dev.bus as u32,
            dev.dev as u32,
            dev.func as u32,
            phys,
            hw,
            fw,
        );
    }

    0
}

#[unsafe(no_mangle)]
pub extern "C" fn intel_ipu_shutdown() {
    let state = unsafe { &mut *STATE.get() };
    if state.initialized && !state.base.is_null() {
        unsafe { unmap_mmio_region(state.base, IPU_MMIO_SIZE) };
    }
    *state = IpuState::new();
}

#[unsafe(no_mangle)]
pub extern "C" fn intel_ipu_is_present() -> bool {
    unsafe { (*STATE.get()).initialized }
}

#[unsafe(no_mangle)]
pub extern "C" fn intel_ipu_hw_version() -> u32 {
    let state = unsafe { &*STATE.get() };
    if !state.initialized || state.base.is_null() {
        return 0;
    }
    mmio_read32(state.base, IPU_REG_HW_VERSION)
}

#[unsafe(no_mangle)]
pub extern "C" fn intel_ipu_fw_status() -> u32 {
    let state = unsafe { &*STATE.get() };
    if !state.initialized || state.base.is_null() {
        return 0;
    }
    mmio_read32(state.base, IPU_REG_FW_STATUS)
}

#[unsafe(no_mangle)]
pub extern "C" fn intel_ipu_set_runstall(enable: bool) -> i32 {
    let state = unsafe { &*STATE.get() };
    if !state.initialized || state.base.is_null() {
        return -1;
    }

    let mut ctrl = mmio_read32(state.base, IPU_REG_GP_CONTROL);
    if enable {
        ctrl |= GP_CONTROL_RUNSTALL;
    } else {
        ctrl &= !GP_CONTROL_RUNSTALL;
    }
    mmio_write32(state.base, IPU_REG_GP_CONTROL, ctrl);
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn intel_ipu_gp_status() -> u32 {
    let state = unsafe { &*STATE.get() };
    if !state.initialized || state.base.is_null() {
        return 0;
    }
    mmio_read32(state.base, IPU_REG_GP_STATUS)
}
