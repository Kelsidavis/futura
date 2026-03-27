// SPDX-License-Identifier: MPL-2.0
//
// Raspberry Pi 4/5 PCIe Root Complex Controller Driver
//
// Pi4 (BCM2711): Single-lane Gen2 PCIe (5 GT/s) at 0xFD500000
//   - Connected to VL805 USB 3.0 xHCI controller
//   - Outbound window at 0x600000000 (3 GB)
//
// Pi5 (BCM2712): Single-lane Gen3 PCIe (8 GT/s) at 0x1000120000
//   - Connected to RP1 south bridge (USB, Ethernet, GPIO)
//   - Additional M.2 slot for NVMe SSD
//
// The PCIe controller must be initialized before USB or NVMe can be used.
// This includes link training, BAR configuration, and memory window setup.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(unexpected_cfgs)]

use core::ptr::{read_volatile, write_volatile};

// BCM2711 PCIe registers (offsets from 0xFD500000)
const RC_CFG_VENDOR_ID: usize = 0x00;
const RC_CFG_PRIV1_ID_VAL3: usize = 0x043C;
const RC_CFG_PRIV1_LINK_CAP: usize = 0x04DC;
const RC_DL_MDIO_ADDR: usize = 0x1100;
const RC_DL_MDIO_WR_DATA: usize = 0x1104;
const RC_DL_MDIO_RD_DATA: usize = 0x1108;
const MISC_CTRL: usize = 0x4008;
const MISC_CPU_2_PCIE_MEM_WIN0_LO: usize = 0x400C;
const MISC_CPU_2_PCIE_MEM_WIN0_HI: usize = 0x4010;
const MISC_CPU_2_PCIE_MEM_WIN0_BASE_LIMIT: usize = 0x4070;
const MISC_CPU_2_PCIE_MEM_WIN0_BASE_HI: usize = 0x4080;
const MISC_CPU_2_PCIE_MEM_WIN0_LIMIT_HI: usize = 0x4084;
const MISC_HARD_DEBUG: usize = 0x4204;
const MISC_RC_BAR1_CONFIG_LO: usize = 0x402C;
const MISC_RC_BAR2_CONFIG_LO: usize = 0x4034;
const MISC_RC_BAR2_CONFIG_HI: usize = 0x4038;
const MISC_RC_BAR3_CONFIG_LO: usize = 0x403C;
const INTR2_CPU_BASE: usize = 0x4300;
const MSI_INTR2_BASE: usize = 0x4500;
const PCIE_RGR1_SW_INIT_1: usize = 0x9210;
const PCIE_STATUS: usize = 0x4068;

// MISC_CTRL bits
const SCB_ACCESS_EN: u32 = 1 << 12;
const CFG_READ_UR_MODE: u32 = 1 << 13;
const SCB_MAX_BURST_SIZE_128: u32 = 0 << 20;

// Status bits
const PCIE_PHYLINKUP: u32 = 1 << 4;
const PCIE_DL_ACTIVE: u32 = 1 << 5;

static mut PCIE_BASE: usize = 0;
static mut PCIE_INITIALIZED: bool = false;
static mut PCIE_LINK_UP: bool = false;

fn mmio_read(addr: usize) -> u32 {
    unsafe { read_volatile(addr as *const u32) }
}

fn mmio_write(addr: usize, val: u32) {
    unsafe { write_volatile(addr as *mut u32, val) }
}

fn delay(n: u32) {
    for _ in 0..n { unsafe { core::arch::asm!("yield") }; }
}

// ── FFI exports ──

/// Initialize the PCIe root complex controller
/// base_addr: MMIO base (0xFD500000 for Pi4, 0x1000120000 for Pi5)
/// Returns: 0 on success with link up, 1 if no link, negative on error
#[no_mangle]
pub extern "C" fn rpi_pcie_init(base_addr: u64) -> i32 {
    let base = base_addr as usize;
    unsafe {
        PCIE_BASE = base;
        PCIE_INITIALIZED = false;
        PCIE_LINK_UP = false;
    }

    // Assert bridge reset
    mmio_write(base + PCIE_RGR1_SW_INIT_1, 0x3);
    delay(10000);

    // Deassert bridge reset (keep PCIe in reset)
    mmio_write(base + PCIE_RGR1_SW_INIT_1, 0x2);
    delay(10000);

    // Set SCB max burst size and enable access
    let misc = SCB_ACCESS_EN | CFG_READ_UR_MODE | SCB_MAX_BURST_SIZE_128;
    mmio_write(base + MISC_CTRL, misc);

    // Configure RC BAR2 for inbound memory (4 GB window)
    mmio_write(base + MISC_RC_BAR2_CONFIG_LO, 0x00000011); // 4 GB, 64-bit, enabled
    mmio_write(base + MISC_RC_BAR2_CONFIG_HI, 0x00000000);

    // Set outbound memory window: CPU 0x600000000 → PCIe 0x00000000 (3 GB)
    // Pi4: maps to 0x600000000-0x6BFFFFFFF
    mmio_write(base + MISC_CPU_2_PCIE_MEM_WIN0_LO, 0x00000000);
    mmio_write(base + MISC_CPU_2_PCIE_MEM_WIN0_HI, 0x00000006);
    mmio_write(base + MISC_CPU_2_PCIE_MEM_WIN0_BASE_LIMIT, 0x00000000);
    mmio_write(base + MISC_CPU_2_PCIE_MEM_WIN0_BASE_HI, 0x00000006);
    mmio_write(base + MISC_CPU_2_PCIE_MEM_WIN0_LIMIT_HI, 0x00000006);

    // Deassert PCIe reset (start link training)
    mmio_write(base + PCIE_RGR1_SW_INIT_1, 0x0);
    delay(100000);

    // Wait for link up (up to 1 second)
    let mut link_up = false;
    for _ in 0..100 {
        let status = mmio_read(base + PCIE_STATUS);
        if (status & PCIE_PHYLINKUP) != 0 && (status & PCIE_DL_ACTIVE) != 0 {
            link_up = true;
            break;
        }
        delay(10000); // ~10ms
    }

    unsafe {
        PCIE_INITIALIZED = true;
        PCIE_LINK_UP = link_up;
    }

    if link_up { 0 } else { 1 }
}

/// Read PCIe configuration space (Type 0/1)
/// bdf: bus/device/function (bus<<8 | dev<<3 | func)
/// offset: register offset (0-4095)
#[no_mangle]
pub extern "C" fn rpi_pcie_cfg_read(bdf: u32, offset: u32) -> u32 {
    let base = unsafe { PCIE_BASE };
    if base == 0 || !unsafe { PCIE_LINK_UP } { return 0xFFFFFFFF; }

    // ECAM-style config access
    let addr = base + ((bdf as usize) << 12) + (offset as usize & 0xFFC);
    mmio_read(addr)
}

/// Write PCIe configuration space
#[no_mangle]
pub extern "C" fn rpi_pcie_cfg_write(bdf: u32, offset: u32, val: u32) {
    let base = unsafe { PCIE_BASE };
    if base == 0 || !unsafe { PCIE_LINK_UP } { return; }

    let addr = base + ((bdf as usize) << 12) + (offset as usize & 0xFFC);
    mmio_write(addr, val);
}

/// Check if PCIe link is up
#[no_mangle]
pub extern "C" fn rpi_pcie_link_up() -> bool {
    unsafe { PCIE_LINK_UP }
}

/// Get link speed (1=Gen1, 2=Gen2, 3=Gen3)
#[no_mangle]
pub extern "C" fn rpi_pcie_link_speed() -> u32 {
    let base = unsafe { PCIE_BASE };
    if base == 0 { return 0; }
    let cap = mmio_read(base + RC_CFG_PRIV1_LINK_CAP);
    cap & 0xF // Max link speed
}

/// Enumerate devices on bus 0 (root port only)
/// Returns vendor/device ID of first device, or 0 if none
#[no_mangle]
pub extern "C" fn rpi_pcie_enumerate_bus0() -> u32 {
    if !unsafe { PCIE_LINK_UP } { return 0; }

    // Read device 0 on bus 1 (first downstream device)
    let vid_did = rpi_pcie_cfg_read(1 << 3, 0); // Bus 1, Dev 0, Func 0
    if vid_did == 0xFFFFFFFF { return 0; }
    vid_did
}

/// Check if controller is initialized
#[no_mangle]
pub extern "C" fn rpi_pcie_is_ready() -> bool {
    unsafe { PCIE_INITIALIZED }
}
