// SPDX-License-Identifier: MPL-2.0
//
// Realtek RTW89 Wi-Fi Driver for Futura OS — Phase 1: PCI Probe
//
// Discovers Realtek 802.11ax/be PCIe wireless adapters, identifies
// the chipset generation, maps the MMIO register space, and reads
// chip version and RF type registers.
//
// Supported chipsets:
//   - RTL8852AE (Wi-Fi 6, 2x2)
//   - RTL8852BE (Wi-Fi 6, 2x2)
//   - RTL8852CE (Wi-Fi 6E, 2x2)
//   - RTL8851BE (Wi-Fi 6, 1x1, budget)
//   - RTL8922AE (Wi-Fi 7, 2x2)
//
// Phase 1 is observational — no firmware loading, no 802.11 MAC.
// Future phases will add firmware loading (header + DMEM/IMEM
// sections via DMA), MAC/BB/RF init sequences, and the data path.
//
// References:
//   - Linux rtw89 driver (drivers/net/wireless/realtek/rtw89/)
//   - RTL8852AE/BE/CE register maps (rtw8852a_regs.h, etc.)

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(unexpected_cfgs)]
#![allow(dead_code)]

use core::cell::UnsafeCell;
use common::{log, map_mmio_region, MMIO_DEFAULT_FLAGS};

unsafe extern "C" {
    fn fut_printf(fmt: *const u8, ...);
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

// ── PCI constants ──

const PCI_CFG_VENDOR_DEVICE: u8 = 0x00;
const PCI_CFG_COMMAND: u8 = 0x04;
const PCI_CFG_CLASS_REV: u8 = 0x08;
const PCI_CFG_BAR0_LO: u8 = 0x10;
const PCI_CFG_BAR0_HI: u8 = 0x14;
const PCI_CFG_SUBSYSTEM: u8 = 0x2C;

const PCI_VENDOR_REALTEK: u16 = 0x10EC;
const PCI_CLASS_NETWORK: u8 = 0x02;

const PCI_CMD_MEM_ENABLE: u16 = 0x0002;
const PCI_CMD_BUS_MASTER: u16 = 0x0004;

// ── RTW89 MMIO registers ──

// Chip identification
const R_AX_SYS_CHIPINFO: u32    = 0x0000;
const R_AX_SYS_CFG1: u32        = 0x00F0;
const R_AX_CHIP_VERSION: u32    = 0x00F4;
const R_AX_PLATFORM_TYPE: u32   = 0x00F8;

// HCI control
const R_AX_SYS_FUNC_EN: u32     = 0x0002;
const R_AX_SYS_CLK_CTRL: u32    = 0x0008;
const R_AX_HCI_FC_CTRL: u32     = 0x1700;

// Power and clock
const R_AX_SYS_PW_CTRL: u32     = 0x0004;
const R_AX_RSV_CTRL: u32        = 0x001C;

// RF type (read from SYS_CFG1)
const B_AX_RF_TYPE_MSK: u32     = 0x000000F0;
const B_AX_RF_TYPE_SHF: u32     = 4;
const B_AX_CHIP_ID_MSK: u32     = 0xFF000000;
const B_AX_CHIP_ID_SHF: u32     = 24;
const B_AX_CV_MSK: u32          = 0x00F00000;
const B_AX_CV_SHF: u32          = 20;

// ── Chip families ──

#[derive(Clone, Copy, PartialEq)]
#[repr(u8)]
enum RtwChip {
    Unknown = 0,
    Rtl8852a,   // RTL8852AE — first-gen Wi-Fi 6, 2x2
    Rtl8852b,   // RTL8852BE — cost-optimized Wi-Fi 6, 2x2
    Rtl8852c,   // RTL8852CE — Wi-Fi 6E with 6 GHz, 2x2
    Rtl8851b,   // RTL8851BE — Wi-Fi 6, 1x1 budget
    Rtl8922a,   // RTL8922AE — Wi-Fi 7, 2x2
}

impl RtwChip {
    fn name(self) -> &'static [u8] {
        match self {
            Self::Unknown  => b"Unknown Realtek Wireless\0",
            Self::Rtl8852a => b"RTL8852AE (Wi-Fi 6, 2x2)\0",
            Self::Rtl8852b => b"RTL8852BE (Wi-Fi 6, 2x2)\0",
            Self::Rtl8852c => b"RTL8852CE (Wi-Fi 6E, 2x2)\0",
            Self::Rtl8851b => b"RTL8851BE (Wi-Fi 6, 1x1)\0",
            Self::Rtl8922a => b"RTL8922AE (Wi-Fi 7, 2x2)\0",
        }
    }

    fn firmware_name(self) -> &'static [u8] {
        match self {
            Self::Unknown  => b"unknown\0",
            Self::Rtl8852a => b"rtw89/rtw8852a_fw.bin\0",
            Self::Rtl8852b => b"rtw89/rtw8852b_fw.bin\0",
            Self::Rtl8852c => b"rtw89/rtw8852c_fw.bin\0",
            Self::Rtl8851b => b"rtw89/rtw8851b_fw.bin\0",
            Self::Rtl8922a => b"rtw89/rtw8922a_fw.bin\0",
        }
    }
}

fn identify_chip(device_id: u16) -> RtwChip {
    match device_id {
        // RTL8852AE
        0x8852 | 0xA852 => RtwChip::Rtl8852a,
        // RTL8852BE
        0xB852 | 0xB85B => RtwChip::Rtl8852b,
        // RTL8852CE
        0xC852 | 0xC85B => RtwChip::Rtl8852c,
        // RTL8851BE
        0xB851 => RtwChip::Rtl8851b,
        // RTL8922AE
        0x8922 | 0xA922 => RtwChip::Rtl8922a,
        _ => RtwChip::Unknown,
    }
}

// ── Driver state ──

struct StaticCell<T>(UnsafeCell<T>);
unsafe impl<T> Sync for StaticCell<T> {}
impl<T> StaticCell<T> {
    const fn new(v: T) -> Self { Self(UnsafeCell::new(v)) }
    fn get(&self) -> *mut T { self.0.get() }
}

struct RtwState {
    initialized: bool,
    pci_bus: u8,
    pci_dev: u8,
    pci_func: u8,
    device_id: u16,
    subsystem_id: u32,
    revision: u8,
    chip: RtwChip,
    bar0_phys: u64,
    bar0_size: u64,
    mmio_base: *mut u8,
    chip_id: u8,
    chip_version: u8,
    rf_type: u8,
}

unsafe impl Send for RtwState {}
unsafe impl Sync for RtwState {}

static STATE: StaticCell<RtwState> = StaticCell::new(RtwState {
    initialized: false,
    pci_bus: 0,
    pci_dev: 0,
    pci_func: 0,
    device_id: 0,
    subsystem_id: 0,
    revision: 0,
    chip: RtwChip::Unknown,
    bar0_phys: 0,
    bar0_size: 0,
    mmio_base: core::ptr::null_mut(),
    chip_id: 0,
    chip_version: 0,
    rf_type: 0,
});

#[inline(always)]
fn state() -> &'static mut RtwState {
    unsafe { &mut *STATE.get() }
}

#[inline(always)]
unsafe fn mmio_read32(base: *const u8, offset: u32) -> u32 {
    unsafe { core::ptr::read_volatile(base.add(offset as usize) as *const u32) }
}

// ── PCI scan ──

fn pci_scan_realtek_wifi() -> Option<(u8, u8, u8, u16, u8)> {
    for bus in 0..4u8 {
        for dev in 0..32u8 {
            for func in 0..8u8 {
                let vd = pci_read32(bus, dev, func, PCI_CFG_VENDOR_DEVICE);
                if vd == 0xFFFFFFFF || vd == 0 {
                    if func == 0 { break; }
                    continue;
                }
                let vendor = (vd & 0xFFFF) as u16;
                if vendor != PCI_VENDOR_REALTEK {
                    if func == 0 { break; }
                    continue;
                }
                let class_rev = pci_read32(bus, dev, func, PCI_CFG_CLASS_REV);
                let class = ((class_rev >> 24) & 0xFF) as u8;
                if class != PCI_CLASS_NETWORK {
                    continue;
                }
                let device = (vd >> 16) as u16;
                let chip = identify_chip(device);
                if chip != RtwChip::Unknown {
                    let revision = (class_rev & 0xFF) as u8;
                    return Some((bus, dev, func, device, revision));
                }
            }
        }
    }
    None
}

fn read_bar0(bus: u8, dev: u8, func: u8) -> (u64, u64) {
    let lo_raw = pci_read32(bus, dev, func, PCI_CFG_BAR0_LO);
    let hi_raw = pci_read32(bus, dev, func, PCI_CFG_BAR0_HI);
    let is_64bit = (lo_raw & 0x06) == 0x04;
    let base = if is_64bit {
        ((hi_raw as u64) << 32) | ((lo_raw as u64) & !0xF)
    } else {
        (lo_raw as u64) & !0xF
    };

    pci_write32(bus, dev, func, PCI_CFG_BAR0_LO, 0xFFFFFFFF);
    let size_lo = pci_read32(bus, dev, func, PCI_CFG_BAR0_LO);
    pci_write32(bus, dev, func, PCI_CFG_BAR0_LO, lo_raw);

    let size_mask = if is_64bit {
        pci_write32(bus, dev, func, PCI_CFG_BAR0_HI, 0xFFFFFFFF);
        let size_hi = pci_read32(bus, dev, func, PCI_CFG_BAR0_HI);
        pci_write32(bus, dev, func, PCI_CFG_BAR0_HI, hi_raw);
        ((size_hi as u64) << 32) | ((size_lo as u64) & !0xF)
    } else {
        (size_lo as u64) & !0xF
    };

    let size = if size_mask == 0 { 0 } else { (!size_mask).wrapping_add(1) };
    (base, size)
}

// ── Public C API ──

#[unsafe(no_mangle)]
pub extern "C" fn rtw89_init() -> i32 {
    log("rtw89: scanning PCI for Realtek Wireless adapter");

    let (bus, dev, func, device_id, revision) = match pci_scan_realtek_wifi() {
        Some(r) => r,
        None => {
            log("rtw89: no Realtek Wireless adapter found");
            return -19;
        }
    };

    let chip = identify_chip(device_id);
    let subsystem = pci_read32(bus, dev, func, PCI_CFG_SUBSYSTEM);

    unsafe {
        fut_printf(
            b"rtw89: found %s [10ec:%04x] at PCI %02x:%02x.%x (rev %02x, subsys %08x)\n\0".as_ptr(),
            chip.name().as_ptr(),
            device_id as u32, bus as u32, dev as u32, func as u32,
            revision as u32, subsystem,
        );
    }

    // Enable memory space + bus master
    let cmd = pci_read32(bus, dev, func, PCI_CFG_COMMAND) as u16;
    if (cmd & (PCI_CMD_MEM_ENABLE | PCI_CMD_BUS_MASTER)) != (PCI_CMD_MEM_ENABLE | PCI_CMD_BUS_MASTER) {
        let new_cmd = cmd | PCI_CMD_MEM_ENABLE | PCI_CMD_BUS_MASTER;
        pci_write32(bus, dev, func, PCI_CFG_COMMAND, new_cmd as u32);
    }

    // Map BAR0
    let (bar0_phys, bar0_size) = read_bar0(bus, dev, func);
    if bar0_phys == 0 || bar0_size == 0 {
        log("rtw89: BAR0 not configured");
        return -5;
    }

    let map_size = core::cmp::min(bar0_size, 2 * 1024 * 1024) as usize;
    let mmio = unsafe { map_mmio_region(bar0_phys, map_size, MMIO_DEFAULT_FLAGS) };
    if mmio.is_null() {
        log("rtw89: failed to map BAR0 MMIO");
        return -12;
    }

    // Read chip identification registers
    let sys_cfg1 = unsafe { mmio_read32(mmio, R_AX_SYS_CFG1) };
    let chip_id = ((sys_cfg1 & B_AX_CHIP_ID_MSK) >> B_AX_CHIP_ID_SHF) as u8;
    let chip_ver = ((sys_cfg1 & B_AX_CV_MSK) >> B_AX_CV_SHF) as u8;
    let rf_type = ((sys_cfg1 & B_AX_RF_TYPE_MSK) >> B_AX_RF_TYPE_SHF) as u8;

    let chipinfo = unsafe { mmio_read32(mmio, R_AX_SYS_CHIPINFO) };
    let sys_func = unsafe { mmio_read32(mmio, R_AX_SYS_FUNC_EN) };

    unsafe {
        fut_printf(
            b"rtw89: SYS_CFG1=0x%08x chip_id=0x%02x cv=%u rf_type=%u\n\0".as_ptr(),
            sys_cfg1, chip_id as u32, chip_ver as u32, rf_type as u32,
        );
        fut_printf(
            b"rtw89: CHIPINFO=0x%08x SYS_FUNC_EN=0x%08x\n\0".as_ptr(),
            chipinfo, sys_func,
        );
        fut_printf(
            b"rtw89: BAR0 at phys 0x%016llx, size %u KiB\n\0".as_ptr(),
            bar0_phys, (bar0_size / 1024) as u32,
        );
        fut_printf(
            b"rtw89: firmware needed: %s\n\0".as_ptr(),
            chip.firmware_name().as_ptr(),
        );
    }

    let s = state();
    s.initialized = true;
    s.pci_bus = bus;
    s.pci_dev = dev;
    s.pci_func = func;
    s.device_id = device_id;
    s.subsystem_id = subsystem;
    s.revision = revision;
    s.chip = chip;
    s.bar0_phys = bar0_phys;
    s.bar0_size = bar0_size;
    s.mmio_base = mmio;
    s.chip_id = chip_id;
    s.chip_version = chip_ver;
    s.rf_type = rf_type;

    0
}

#[unsafe(no_mangle)]
pub extern "C" fn rtw89_is_initialized() -> bool {
    state().initialized
}

#[unsafe(no_mangle)]
pub extern "C" fn rtw89_device_id() -> u16 {
    state().device_id
}
