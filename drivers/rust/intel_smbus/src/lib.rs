// SPDX-License-Identifier: MPL-2.0
//
// Intel PCH SMBus Controller Driver for Futura OS
//
// Implements basic SMBus byte and word transactions for the Intel SMBus
// host controller typically found at PCI 00:1F.4 on Gen 10+ platforms.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(unexpected_cfgs)]

use core::cell::UnsafeCell;

use common::{log, thread_yield};

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

const PCI_CMD_IO_SPACE: u16 = 1 << 0;
const PCI_CMD_BUS_MASTER: u16 = 1 << 2;

const INTEL_VENDOR_ID: u16 = 0x8086;
const PCI_CLASS_SERIAL_BUS: u8 = 0x0C;
const PCI_SUBCLASS_SMBUS: u8 = 0x05;

const SMBUS_DEVICE_IDS: &[u16] = &[
    0xA323, // Cannon/Comet Lake
    0xA3A3, // Ice Lake
    0x43A3, // Tiger Lake
    0x51A3, // Alder/Raptor Lake
    0x7E23, // Meteor Lake
];

const SMBHSTSTS: u16 = 0x00;
const SMBHSTCNT: u16 = 0x02;
const SMBHSTCMD: u16 = 0x03;
const SMBXMITADD: u16 = 0x04;
const SMBHSTDAT0: u16 = 0x05;
const SMBHSTDAT1: u16 = 0x06;

const HSTSTS_HOST_BUSY: u8 = 1 << 0;
const HSTSTS_INTR: u8 = 1 << 1;
const HSTSTS_DEV_ERR: u8 = 1 << 2;
const HSTSTS_BUS_ERR: u8 = 1 << 3;
const HSTSTS_FAILED: u8 = 1 << 4;
const HSTSTS_BYTE_DONE: u8 = 1 << 7;
const HSTSTS_CLEAR_MASK: u8 =
    HSTSTS_INTR | HSTSTS_DEV_ERR | HSTSTS_BUS_ERR | HSTSTS_FAILED | HSTSTS_BYTE_DONE;

const HSTCNT_START: u8 = 1 << 6;
const HSTCNT_BYTE_DATA: u8 = 0x02 << 2;
const HSTCNT_WORD_DATA: u8 = 0x03 << 2;

const BAR_IO_MASK: u32 = 0x0000_FFE0;
const POLL_TIMEOUT: u32 = 100_000;

struct IntelSmbusState {
    io_base: u16,
    bus: u8,
    dev: u8,
    func: u8,
    device_id: u16,
    initialized: bool,
}

impl IntelSmbusState {
    const fn new() -> Self {
        Self {
            io_base: 0,
            bus: 0,
            dev: 0,
            func: 0,
            device_id: 0,
            initialized: false,
        }
    }
}

static STATE: StaticCell<IntelSmbusState> = StaticCell::new(IntelSmbusState::new());

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

fn io_outb(port: u16, val: u8) {
    unsafe {
        core::arch::asm!("out dx, al", in("dx") port, in("al") val);
    }
}

fn io_inb(port: u16) -> u8 {
    let val: u8;
    unsafe {
        core::arch::asm!("in al, dx", in("dx") port, out("al") val);
    }
    val
}

fn find_smbus() -> Option<PciDevice> {
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
        if dev.class_code != PCI_CLASS_SERIAL_BUS || dev.subclass != PCI_SUBCLASS_SMBUS {
            continue;
        }
        if SMBUS_DEVICE_IDS.contains(&dev.device_id) || (dev.bus == 0 && dev.dev == 0x1F && dev.func == 4) {
            return Some(PciDevice { ..*dev });
        }
    }
    None
}

fn clear_status(io_base: u16) {
    io_outb(io_base + SMBHSTSTS, HSTSTS_CLEAR_MASK);
}

fn wait_until_idle(io_base: u16) -> i32 {
    for _ in 0..POLL_TIMEOUT {
        if io_inb(io_base + SMBHSTSTS) & HSTSTS_HOST_BUSY == 0 {
            return 0;
        }
        thread_yield();
    }
    -1
}

fn wait_for_completion(io_base: u16) -> i32 {
    for _ in 0..POLL_TIMEOUT {
        let st = io_inb(io_base + SMBHSTSTS);
        if st & HSTSTS_INTR != 0 {
            return 0;
        }
        if st & (HSTSTS_DEV_ERR | HSTSTS_BUS_ERR | HSTSTS_FAILED) != 0 {
            return -2;
        }
        thread_yield();
    }
    -1
}

#[unsafe(no_mangle)]
pub extern "C" fn intel_smbus_init() -> i32 {
    let state = unsafe { &mut *STATE.get() };
    if state.initialized {
        log("intel_smbus: already initialised");
        return 0;
    }

    let dev = match find_smbus() {
        Some(dev) => dev,
        None => {
            log("intel_smbus: no controller found");
            return -1;
        }
    };

    let mut cmd = pci_read16(dev.bus, dev.dev, dev.func, PCI_COMMAND);
    cmd |= PCI_CMD_IO_SPACE | PCI_CMD_BUS_MASTER;
    pci_write16(dev.bus, dev.dev, dev.func, PCI_COMMAND, cmd);

    let io_base = (pci_read32(dev.bus, dev.dev, dev.func, PCI_BAR0) & BAR_IO_MASK) as u16;
    if io_base == 0 {
        log("intel_smbus: I/O BAR not configured");
        return -2;
    }

    clear_status(io_base);

    state.io_base = io_base;
    state.bus = dev.bus;
    state.dev = dev.dev;
    state.func = dev.func;
    state.device_id = dev.device_id;
    state.initialized = true;

    unsafe {
        fut_printf(
            b"intel_smbus: found %04x at %02x:%02x.%x io=0x%x\n\0".as_ptr(),
            dev.device_id as u32,
            dev.bus as u32,
            dev.dev as u32,
            dev.func as u32,
            io_base as u32,
        );
    }

    0
}

#[unsafe(no_mangle)]
pub extern "C" fn intel_smbus_is_present() -> bool {
    unsafe { (*STATE.get()).initialized }
}

#[unsafe(no_mangle)]
pub extern "C" fn intel_smbus_io_base() -> u16 {
    unsafe { (*STATE.get()).io_base }
}

#[unsafe(no_mangle)]
pub extern "C" fn intel_smbus_read_byte(addr: u8, command: u8) -> i32 {
    let state = unsafe { &*STATE.get() };
    if !state.initialized {
        return -1;
    }

    if wait_until_idle(state.io_base) != 0 {
        log("intel_smbus: controller busy");
        return -2;
    }

    clear_status(state.io_base);
    io_outb(state.io_base + SMBHSTCMD, command);
    io_outb(state.io_base + SMBXMITADD, (addr << 1) | 1);
    io_outb(state.io_base + SMBHSTCNT, HSTCNT_BYTE_DATA | HSTCNT_START);

    if wait_for_completion(state.io_base) != 0 {
        log("intel_smbus: byte read failed");
        clear_status(state.io_base);
        return -3;
    }

    let value = io_inb(state.io_base + SMBHSTDAT0);
    clear_status(state.io_base);
    value as i32
}

#[unsafe(no_mangle)]
pub extern "C" fn intel_smbus_write_byte(addr: u8, command: u8, value: u8) -> i32 {
    let state = unsafe { &*STATE.get() };
    if !state.initialized {
        return -1;
    }

    if wait_until_idle(state.io_base) != 0 {
        log("intel_smbus: controller busy");
        return -2;
    }

    clear_status(state.io_base);
    io_outb(state.io_base + SMBHSTCMD, command);
    io_outb(state.io_base + SMBXMITADD, addr << 1);
    io_outb(state.io_base + SMBHSTDAT0, value);
    io_outb(state.io_base + SMBHSTCNT, HSTCNT_BYTE_DATA | HSTCNT_START);

    if wait_for_completion(state.io_base) != 0 {
        log("intel_smbus: byte write failed");
        clear_status(state.io_base);
        return -3;
    }

    clear_status(state.io_base);
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn intel_smbus_read_word(addr: u8, command: u8) -> i32 {
    let state = unsafe { &*STATE.get() };
    if !state.initialized {
        return -1;
    }

    if wait_until_idle(state.io_base) != 0 {
        return -2;
    }

    clear_status(state.io_base);
    io_outb(state.io_base + SMBHSTCMD, command);
    io_outb(state.io_base + SMBXMITADD, (addr << 1) | 1);
    io_outb(state.io_base + SMBHSTCNT, HSTCNT_WORD_DATA | HSTCNT_START);

    if wait_for_completion(state.io_base) != 0 {
        log("intel_smbus: word read failed");
        clear_status(state.io_base);
        return -3;
    }

    let lo = io_inb(state.io_base + SMBHSTDAT0) as u16;
    let hi = io_inb(state.io_base + SMBHSTDAT1) as u16;
    clear_status(state.io_base);
    ((hi << 8) | lo) as i32
}

