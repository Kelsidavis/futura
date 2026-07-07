// SPDX-License-Identifier: MPL-2.0
//
// Intel Wi-Fi (iwlwifi) Driver for Futura OS — Phase 1: PCI Probe
//
// Discovers Intel Wireless adapters on the PCI bus, identifies the
// exact hardware generation, maps the MMIO register space, reads the
// hardware revision and RF ID registers, and reports which firmware
// image is required.
//
// Supported device families:
//   - Intel Wi-Fi 6 AX200/AX201 (Cyclone Peak / Ice Lake CNVi)
//   - Intel Wi-Fi 6E AX210/AX211 (Typhoon Peak / Alder Lake CNVi)
//   - Intel Wi-Fi 7 BE200 (Burrinjuck / Meteor Lake CNVi)
//   - Intel Wireless-AC 9260/9560 (Jefferson Peak / Cannon Lake CNVi)
//
// Phase 1 is observational — no firmware loading, no 802.11 MAC, no
// data path. Future phases will add:
//   2. Firmware loading (ucode sections into SRAM via DMA)
//   3. NIC initialization (alive handshake, PHY calibration)
//   4. Scanning (passive/active channel scan)
//   5. Association (802.11 authentication + 4-way handshake)
//   6. Data path (Tx/Rx queues, aggregation)
//
// References:
//   - Intel iwlwifi Linux kernel driver (drivers/net/wireless/intel/iwlwifi/)
//   - Intel Wireless Adapter Programming Manual (iwl-drv.c, iwl-trans-pcie.c)

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(unexpected_cfgs)]
#![allow(dead_code)]

use core::cell::UnsafeCell;
use core::ffi::c_void;
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

// ── PCI config offsets ──

const PCI_CFG_VENDOR_DEVICE: u8 = 0x00;
const PCI_CFG_COMMAND: u8 = 0x04;
const PCI_CFG_CLASS_REV: u8 = 0x08;
const PCI_CFG_BAR0_LO: u8 = 0x10;
const PCI_CFG_BAR0_HI: u8 = 0x14;
const PCI_CFG_SUBSYSTEM: u8 = 0x2C;

const PCI_VENDOR_INTEL: u16 = 0x8086;
const PCI_CLASS_NETWORK: u8 = 0x02; // Network controller

const PCI_CMD_MEM_ENABLE: u16 = 0x0002;
const PCI_CMD_BUS_MASTER: u16 = 0x0004;

// ── iwlwifi MMIO registers ──

const CSR_HW_REV: u32          = 0x028;
const CSR_HW_REV_TYPE_MSK: u32 = 0x000FFF0;
const CSR_HW_REV_STEP_MSK: u32 = 0x000000F;

const CSR_HW_RF_ID: u32        = 0x09C;
const CSR_GP_CNTRL: u32        = 0x024;
const CSR_EEPROM_GP: u32       = 0x030;
const CSR_OTP_GP_REG: u32      = 0x034;
const CSR_GIO_REG: u32         = 0x03C;
const CSR_GP_UCODE_REG: u32    = 0x048;
const CSR_UCODE_DRV_GP1: u32   = 0x054;
const CSR_FH_INT_STATUS: u32   = 0x010;

// GP_CNTRL bits
const CSR_GP_CNTRL_REG_FLAG_MAC_CLOCK_READY: u32 = 1 << 0;
const CSR_GP_CNTRL_REG_FLAG_INIT_DONE: u32 = 1 << 2;
const CSR_GP_CNTRL_REG_FLAG_MAC_ACCESS_REQ: u32 = 1 << 3;

// ── Device families ──

#[derive(Clone, Copy, PartialEq)]
#[repr(u8)]
enum IwlFamily {
    Unknown = 0,
    Wifi6Ax200,    // AX200 — Cyclone Peak (discrete)
    Wifi6Ax201,    // AX201 — Ice Lake CNVi
    Wifi6eAx210,   // AX210 — Typhoon Peak (discrete)
    Wifi6eAx211,   // AX211 — Alder Lake CNVi
    Wifi7Be200,    // BE200 — Burrinjuck (discrete)
    WifiAc9260,    // AC 9260 — Jefferson Peak (discrete)
    WifiAc9560,    // AC 9560 — Cannon Lake CNVi
    WifiAc8265,    // AC 8265 — Stone Peak
}

impl IwlFamily {
    fn name(self) -> &'static [u8] {
        match self {
            Self::Unknown     => b"Unknown Intel Wireless\0",
            Self::Wifi6Ax200  => b"Wi-Fi 6 AX200 (Cyclone Peak)\0",
            Self::Wifi6Ax201  => b"Wi-Fi 6 AX201 (CNVi)\0",
            Self::Wifi6eAx210 => b"Wi-Fi 6E AX210 (Typhoon Peak)\0",
            Self::Wifi6eAx211 => b"Wi-Fi 6E AX211 (CNVi)\0",
            Self::Wifi7Be200  => b"Wi-Fi 7 BE200\0",
            Self::WifiAc9260  => b"Wireless-AC 9260\0",
            Self::WifiAc9560  => b"Wireless-AC 9560 (CNVi)\0",
            Self::WifiAc8265  => b"Wireless-AC 8265\0",
        }
    }

    fn firmware_name(self) -> &'static [u8] {
        match self {
            Self::Unknown     => b"unknown\0",
            Self::Wifi6Ax200  => b"iwlwifi-cc-a0-77.ucode\0",
            Self::Wifi6Ax201  => b"iwlwifi-QuZ-a0-hr-b0-77.ucode\0",
            Self::Wifi6eAx210 => b"iwlwifi-ty-a0-gf-a0-77.ucode\0",
            Self::Wifi6eAx211 => b"iwlwifi-so-a0-gf-a0-77.ucode\0",
            Self::Wifi7Be200  => b"iwlwifi-gl-c0-fm-c0-77.ucode\0",
            Self::WifiAc9260  => b"iwlwifi-9260-th-b0-jf-b0-46.ucode\0",
            Self::WifiAc9560  => b"iwlwifi-9000-pu-b0-jf-b0-46.ucode\0",
            Self::WifiAc8265  => b"iwlwifi-8265-36.ucode\0",
        }
    }

    fn is_ax(self) -> bool {
        matches!(self,
            Self::Wifi6Ax200 | Self::Wifi6Ax201 |
            Self::Wifi6eAx210 | Self::Wifi6eAx211 |
            Self::Wifi7Be200
        )
    }
}

fn identify_device(device_id: u16) -> IwlFamily {
    match device_id {
        // AX200 — Cyclone Peak
        0x2723 => IwlFamily::Wifi6Ax200,
        // AX201 — CNVi (Ice Lake, Comet Lake)
        0x02F0 | 0x06F0 | 0xA0F0 | 0x34F0 | 0x3DF0 |
        0x4DF0 | 0x54F0 => IwlFamily::Wifi6Ax201,
        // AX210 — Typhoon Peak (discrete)
        0x2725 | 0x2726 => IwlFamily::Wifi6eAx210,
        // AX211 — CNVi (Alder Lake, Raptor Lake)
        0x51F0 | 0x51F1 | 0x54F0 | 0x7AF0 | 0xA840 |
        0x7A70 => IwlFamily::Wifi6eAx211,
        // BE200 — Burrinjuck
        0x272B => IwlFamily::Wifi7Be200,
        // AC 9260 — Jefferson Peak
        0x2526 => IwlFamily::WifiAc9260,
        // AC 9560 — CNVi
        0x9DF0 | 0xA370 | 0x31DC | 0x30DC |
        0x271C | 0x271B => IwlFamily::WifiAc9560,
        // AC 8265 — Stone Peak
        0x24FD => IwlFamily::WifiAc8265,
        _ => IwlFamily::Unknown,
    }
}

// ── Driver state ──

struct StaticCell<T>(UnsafeCell<T>);
unsafe impl<T> Sync for StaticCell<T> {}
impl<T> StaticCell<T> {
    const fn new(v: T) -> Self { Self(UnsafeCell::new(v)) }
    fn get(&self) -> *mut T { self.0.get() }
}

struct IwlState {
    initialized: bool,
    pci_bus: u8,
    pci_dev: u8,
    pci_func: u8,
    device_id: u16,
    subsystem_id: u32,
    revision: u8,
    family: IwlFamily,
    bar0_phys: u64,
    bar0_size: u64,
    mmio_base: *mut u8,
    hw_rev: u32,
    hw_rf_id: u32,
}

unsafe impl Send for IwlState {}
unsafe impl Sync for IwlState {}

static STATE: StaticCell<IwlState> = StaticCell::new(IwlState {
    initialized: false,
    pci_bus: 0,
    pci_dev: 0,
    pci_func: 0,
    device_id: 0,
    subsystem_id: 0,
    revision: 0,
    family: IwlFamily::Unknown,
    bar0_phys: 0,
    bar0_size: 0,
    mmio_base: core::ptr::null_mut(),
    hw_rev: 0,
    hw_rf_id: 0,
});

#[inline(always)]
fn state() -> &'static mut IwlState {
    unsafe { &mut *STATE.get() }
}

#[inline(always)]
unsafe fn mmio_read32(base: *const u8, offset: u32) -> u32 {
    unsafe { core::ptr::read_volatile(base.add(offset as usize) as *const u32) }
}

// ── PCI bus scan for Intel Wireless ──

fn pci_scan_intel_wifi() -> Option<(u8, u8, u8, u16, u8)> {
    for bus in 0..4u8 {
        for dev in 0..32u8 {
            for func in 0..8u8 {
                let vd = pci_read32(bus, dev, func, PCI_CFG_VENDOR_DEVICE);
                if vd == 0xFFFFFFFF || vd == 0 {
                    if func == 0 { break; }
                    continue;
                }
                let vendor = (vd & 0xFFFF) as u16;
                if vendor != PCI_VENDOR_INTEL {
                    if func == 0 { break; }
                    continue;
                }
                let class_rev = pci_read32(bus, dev, func, PCI_CFG_CLASS_REV);
                let class = ((class_rev >> 24) & 0xFF) as u8;
                if class != PCI_CLASS_NETWORK {
                    continue;
                }
                let device = (vd >> 16) as u16;
                let family = identify_device(device);
                if family != IwlFamily::Unknown {
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
pub extern "C" fn iwlwifi_init() -> i32 {
    log("iwlwifi: scanning PCI for Intel Wireless adapter");

    let (bus, dev, func, device_id, revision) = match pci_scan_intel_wifi() {
        Some(r) => r,
        None => {
            log("iwlwifi: no Intel Wireless adapter found");
            return -19;
        }
    };

    let family = identify_device(device_id);
    let subsystem = pci_read32(bus, dev, func, PCI_CFG_SUBSYSTEM);

    unsafe {
        fut_printf(
            b"iwlwifi: found %s [8086:%04x] at PCI %02x:%02x.%x (rev %02x, subsys %08x)\n\0".as_ptr(),
            family.name().as_ptr(),
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
        log("iwlwifi: BAR0 not configured");
        return -5;
    }

    let map_size = core::cmp::min(bar0_size, 8 * 1024 * 1024) as usize;
    let mmio = unsafe { map_mmio_region(bar0_phys, map_size, MMIO_DEFAULT_FLAGS) };
    if mmio.is_null() {
        log("iwlwifi: failed to map BAR0 MMIO");
        return -12;
    }

    // Read hardware revision and RF ID
    let hw_rev = unsafe { mmio_read32(mmio, CSR_HW_REV) };
    let hw_rf_id = unsafe { mmio_read32(mmio, CSR_HW_RF_ID) };
    let gp_cntrl = unsafe { mmio_read32(mmio, CSR_GP_CNTRL) };

    let hw_type = (hw_rev & CSR_HW_REV_TYPE_MSK) >> 4;
    let hw_step = hw_rev & CSR_HW_REV_STEP_MSK;

    unsafe {
        fut_printf(
            b"iwlwifi: HW rev 0x%08x (type=%03x step=%x), RF ID 0x%08x\n\0".as_ptr(),
            hw_rev, hw_type, hw_step, hw_rf_id,
        );
        fut_printf(
            b"iwlwifi: GP_CNTRL=0x%08x, MAC clock %s\n\0".as_ptr(),
            gp_cntrl,
            if (gp_cntrl & CSR_GP_CNTRL_REG_FLAG_MAC_CLOCK_READY) != 0 {
                b"ready\0".as_ptr()
            } else {
                b"not ready\0".as_ptr()
            },
        );
        fut_printf(
            b"iwlwifi: firmware needed: %s\n\0".as_ptr(),
            family.firmware_name().as_ptr(),
        );
        fut_printf(
            b"iwlwifi: BAR0 at phys 0x%016llx, size %u KiB\n\0".as_ptr(),
            bar0_phys, (bar0_size / 1024) as u32,
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
    s.family = family;
    s.bar0_phys = bar0_phys;
    s.bar0_size = bar0_size;
    s.mmio_base = mmio;
    s.hw_rev = hw_rev;
    s.hw_rf_id = hw_rf_id;

    0
}

#[unsafe(no_mangle)]
pub extern "C" fn iwlwifi_is_initialized() -> bool {
    state().initialized
}

#[unsafe(no_mangle)]
pub extern "C" fn iwlwifi_device_id() -> u16 {
    state().device_id
}

#[unsafe(no_mangle)]
pub extern "C" fn iwlwifi_hw_rev() -> u32 {
    state().hw_rev
}
