// SPDX-License-Identifier: MPL-2.0
//
// AMD NBIO (NorthBridge I/O) Driver for Futura OS
//
// The NBIO block on AMD Ryzen (Zen-based) processors controls:
//   - PCIe root ports and ECAM configuration space routing
//   - IOMMU integration and address translation
//   - MMIO aperture routing (up to 8 programmable regions)
//   - System hub (SYSHUB) DMA priority and fabric interconnect
//   - IOAPIC base address configuration
//   - Top-of-DRAM registers (below and above 4 GB)
//
// Architecture:
//   - NBIO registers are accessed via the AMD SMN (System Management Network)
//     bus, which is reached through PCI device 00:00.0 registers 0x60/0x64
//   - Write target SMN address to PCI config offset 0x60 (SMN_ADDR)
//   - Read/write data at PCI config offset 0x64 (SMN_DATA)
//
// SMN address ranges for NBIO:
//   0x01300000 : NBIO config base (IOHC top-level)
//   0x01310000 : IOHC (I/O Hub Controller)
//   0x01314000 : NBIF (NorthBridge Interface)
//   0x01340000 : SYSHUB (System Hub)
//   0x13B10000 : IOHC PCIe core config
//
// Key NBIO registers via SMN:
//   IOHC::NB_TOP_OF_DRAM   (0x013000A0) : Top of DRAM below 4G
//   IOHC::NB_TOP_OF_DRAM2  (0x013000A8) : Top of DRAM above 4G
//   IOHC::IOAPIC_BASE      (0x013000F0) : IOAPIC MMIO base address
//   IOHC::PCIE_CFG_BASE    (0x01300118) : PCIe ECAM config base
//   IOHC::MMIO_BASE0-7     (0x01301000+): MMIO aperture base/limit pairs
//   SYSHUB::FABRIC_PRIORITY(0x01340000) : DMA priority config
//
// This driver is read-only; it does not modify NBIO configuration.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(unexpected_cfgs)]

use core::cell::UnsafeCell;

use common::log;

unsafe extern "C" {
    fn fut_printf(fmt: *const u8, ...);
}

// ── StaticCell for safe global mutable state ──

struct StaticCell<T>(UnsafeCell<T>);
unsafe impl<T> Sync for StaticCell<T> {}

impl<T> StaticCell<T> {
    const fn new(v: T) -> Self {
        Self(UnsafeCell::new(v))
    }

    fn get(&self) -> *mut T {
        self.0.get()
    }
}

// ── PCI device structure (mirrors kernel/pci.h) ──

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

fn pci_read16(bus: u8, dev: u8, func: u8, offset: u8) -> u16 {
    let val32 = pci_read32(bus, dev, func, offset & 0xFC);
    ((val32 >> ((offset & 2) * 8)) & 0xFFFF) as u16
}

// ── SMN (System Management Network) access ──
//
// AMD root complex is PCI 00:00.0.
// SMN address register = PCI config offset 0x60
// SMN data register    = PCI config offset 0x64

/// PCI bus/device/function for AMD root complex.
const RC_BUS: u8 = 0;
const RC_DEV: u8 = 0;
const RC_FUNC: u8 = 0;

/// SMN address port (PCI config offset on device 00:00.0).
const SMN_ADDR_REG: u8 = 0x60;
/// SMN data port (PCI config offset on device 00:00.0).
const SMN_DATA_REG: u8 = 0x64;

/// Read a 32-bit value from the AMD SMN bus.
fn smn_read32(addr: u32) -> u32 {
    pci_write32(RC_BUS, RC_DEV, RC_FUNC, SMN_ADDR_REG, addr);
    pci_read32(RC_BUS, RC_DEV, RC_FUNC, SMN_DATA_REG)
}

// ── AMD Root Complex PCI identification ──

/// AMD vendor ID.
const AMD_VENDOR_ID: u16 = 0x1022;

/// Known AMD Root Complex device IDs across Zen generations.
/// Zen 1 / Zen+ (Ryzen 1000/2000, AM4).
const AMD_RC_ZEN1: u16 = 0x1450;
/// Zen 2 (Ryzen 3000, AM4).
const AMD_RC_ZEN2: u16 = 0x1480;
/// Zen 3 (Ryzen 5000, AM4).
const AMD_RC_ZEN3: u16 = 0x1630;
/// Zen 4 (Ryzen 7000, AM5).
const AMD_RC_ZEN4: u16 = 0x14B5;
/// Zen 5 (Ryzen 9000, AM5).
const AMD_RC_ZEN5: u16 = 0x1730;

/// PCI class: Host Bridge.
const PCI_CLASS_BRIDGE: u8 = 0x06;
/// PCI subclass: Host Bridge.
const PCI_SUBCLASS_HOST: u8 = 0x00;

/// Check whether a device ID is a known AMD Root Complex.
fn is_amd_root_complex(device_id: u16) -> bool {
    matches!(
        device_id,
        AMD_RC_ZEN1 | AMD_RC_ZEN2 | AMD_RC_ZEN3 | AMD_RC_ZEN4 | AMD_RC_ZEN5
    )
}

/// Return a human-readable name for the Zen generation based on device ID.
fn zen_generation_name(device_id: u16) -> &'static [u8] {
    match device_id {
        AMD_RC_ZEN1 => b"Zen/Zen+ (AM4)\0",
        AMD_RC_ZEN2 => b"Zen 2 (AM4)\0",
        AMD_RC_ZEN3 => b"Zen 3 (AM4)\0",
        AMD_RC_ZEN4 => b"Zen 4 (AM5)\0",
        AMD_RC_ZEN5 => b"Zen 5 (AM5)\0",
        _ => b"Unknown\0",
    }
}

// ── NBIO SMN register addresses ──

// IOHC (I/O Hub Controller) registers — NBIO config base 0x01300000

/// Top of DRAM below 4 GB.
/// Bits [31:23] contain the top-of-DRAM address in 8 MB granularity.
/// Bit 0: enable.
const IOHC_NB_TOP_OF_DRAM: u32 = 0x0130_00A0;

/// Top of DRAM above 4 GB (high).
/// Bits [31:8] contain the upper address bits (above 4 GB).
/// Bit 0: enable.
const IOHC_NB_TOP_OF_DRAM2_LO: u32 = 0x0130_00A8;

/// Top of DRAM above 4 GB (upper 32 bits of the 64-bit register).
const IOHC_NB_TOP_OF_DRAM2_HI: u32 = 0x0130_00AC;

/// IOAPIC MMIO base address register.
/// Bits [31:8] contain the base address.
/// Bit 0: enable.
const IOHC_IOAPIC_BASE: u32 = 0x0130_00F0;

/// PCIe ECAM configuration space base address.
/// Bits [31:20] contain the ECAM base in 1 MB granularity.
const IOHC_PCIE_CFG_BASE: u32 = 0x0130_0118;

/// MMIO aperture base/limit register block.
/// Each aperture occupies 16 bytes:
///   +0x00: MMIO base low  (bits [31:0] of base, bit 0 = enable, bit 1 = lock)
///   +0x04: MMIO base high (bits [47:32] of base)
///   +0x08: MMIO limit low (bits [31:0] of limit)
///   +0x0C: MMIO limit high (bits [47:32] of limit)
const IOHC_MMIO_BASE0: u32 = 0x0130_1000;

/// Number of MMIO apertures supported by the IOHC.
const MAX_MMIO_APERTURES: u32 = 8;

/// Stride between MMIO aperture register sets (16 bytes each).
const MMIO_APERTURE_STRIDE: u32 = 0x10;

// SYSHUB (System Hub) registers

/// SYSHUB fabric priority configuration.
/// Controls DMA request priority on the data fabric interconnect.
const SYSHUB_FABRIC_PRIORITY: u32 = 0x0134_0000;

/// SYSHUB clock configuration.
const SYSHUB_CLK_CONFIG: u32 = 0x0134_0004;

/// SYSHUB miscellaneous control.
const SYSHUB_MISC_CTRL: u32 = 0x0134_0008;

// NBIF (NorthBridge Interface) registers

/// NBIF device control.
const NBIF_DEV_CTRL: u32 = 0x0131_4000;

// IOHC PCIe core configuration

/// IOHC PCIe link capability register.
const IOHC_PCIE_LINK_CAP: u32 = 0x13B1_0000;

// ── MMIO aperture state ──

/// Decoded MMIO aperture information.
#[derive(Copy, Clone)]
struct MmioAperture {
    /// Whether this aperture is enabled.
    enabled: bool,
    /// Base address in bytes.
    base: u64,
    /// Limit address in bytes (inclusive).
    limit: u64,
}

const EMPTY_APERTURE: MmioAperture = MmioAperture {
    enabled: false,
    base: 0,
    limit: 0,
};

// ── Driver state ──

struct AmdNbio {
    /// Root Complex device ID (identifies Zen generation).
    device_id: u16,
    /// Whether the driver has been initialised.
    initialized: bool,
    /// Top of DRAM below 4 GB, in bytes.
    top_of_dram: u64,
    /// Top of DRAM above 4 GB, in bytes.
    top_of_dram_hi: u64,
    /// PCIe ECAM configuration base address.
    pcie_cfg_base: u64,
    /// IOAPIC MMIO base address.
    ioapic_base: u64,
    /// Number of enabled MMIO apertures.
    mmio_count: u32,
    /// MMIO aperture configuration.
    mmio_apertures: [MmioAperture; MAX_MMIO_APERTURES as usize],
    /// SYSHUB fabric priority register value.
    syshub_fabric_priority: u32,
    /// SYSHUB clock config register value.
    syshub_clk_config: u32,
    /// SYSHUB misc control register value.
    syshub_misc_ctrl: u32,
}

impl AmdNbio {
    const fn new() -> Self {
        Self {
            device_id: 0,
            initialized: false,
            top_of_dram: 0,
            top_of_dram_hi: 0,
            pcie_cfg_base: 0,
            ioapic_base: 0,
            mmio_count: 0,
            mmio_apertures: [EMPTY_APERTURE; MAX_MMIO_APERTURES as usize],
            syshub_fabric_priority: 0,
            syshub_clk_config: 0,
            syshub_misc_ctrl: 0,
        }
    }
}

static STATE: StaticCell<AmdNbio> = StaticCell::new(AmdNbio::new());

// ── PCI discovery ──

/// Probe PCI 00:00.0 for the AMD Root Complex.
/// Returns the device ID if found, or None.
fn find_amd_root_complex() -> Option<u16> {
    let vendor = pci_read16(0, 0, 0, 0x00);
    if vendor != AMD_VENDOR_ID {
        return None;
    }

    let device_id = pci_read16(0, 0, 0, 0x02);
    if !is_amd_root_complex(device_id) {
        return None;
    }

    // Verify class: Host Bridge (06:00).
    let class = pci_read32(0, 0, 0, 0x08);
    let class_code = ((class >> 24) & 0xFF) as u8;
    let subclass = ((class >> 16) & 0xFF) as u8;

    if class_code != PCI_CLASS_BRIDGE || subclass != PCI_SUBCLASS_HOST {
        return None;
    }

    Some(device_id)
}

/// Verify SMN access by reading the NBIO config base region.
/// The IOHC_NB_TOP_OF_DRAM register should not return all-ones on a
/// functioning AMD system (bit 0 = enable, typically set).
fn verify_smn_access() -> bool {
    let val = smn_read32(IOHC_NB_TOP_OF_DRAM);
    val != 0xFFFF_FFFF
}

// ── NBIO register reading helpers ──

/// Read the Top of DRAM (below 4 GB) register.
///
/// IOHC::NB_TOP_OF_DRAM (0x013000A0):
///   Bit 0      : Enable
///   Bits [31:23]: Top-of-DRAM address in 8 MB granularity
///
/// Returns the top-of-DRAM address in bytes.
fn read_top_of_dram() -> u64 {
    let raw = smn_read32(IOHC_NB_TOP_OF_DRAM);
    let enabled = raw & 1 != 0;
    if !enabled {
        return 0;
    }
    // Bits [31:23] represent the address at 8 MB granularity.
    // The address is formed by taking bits [31:23] and shifting left to
    // get the actual byte address. Since bits [31:23] are already in
    // position, mask off the lower bits.
    (raw & 0xFF80_0000) as u64
}

/// Read the Top of DRAM above 4 GB.
///
/// IOHC::NB_TOP_OF_DRAM2 is a 64-bit register split across two SMN addresses:
///   LO (0x013000A8): Bit 0 = enable, bits [31:8] = address bits [39:8]
///   HI (0x013000AC): Bits [15:0] = address bits [55:40]
///
/// Returns the top-of-DRAM-above-4G address in bytes.
fn read_top_of_dram_hi() -> u64 {
    let lo = smn_read32(IOHC_NB_TOP_OF_DRAM2_LO);
    let hi = smn_read32(IOHC_NB_TOP_OF_DRAM2_HI);
    let enabled = lo & 1 != 0;
    if !enabled {
        return 0;
    }
    // Construct the 64-bit address from lo[31:8] and hi[15:0].
    let addr_lo = (lo & 0xFFFF_FF00) as u64;
    let addr_hi = ((hi & 0xFFFF) as u64) << 32;
    addr_hi | addr_lo
}

/// Read the PCIe ECAM configuration base address.
///
/// IOHC::PCIE_CFG_BASE (0x01300118):
///   Bits [31:20]: ECAM base address in 1 MB granularity
///
/// Returns the ECAM base address in bytes.
fn read_pcie_cfg_base() -> u64 {
    let raw = smn_read32(IOHC_PCIE_CFG_BASE);
    // Bits [31:20] contain the base at 1 MB granularity; lower bits are
    // control/status fields.
    (raw & 0xFFF0_0000) as u64
}

/// Read the IOAPIC MMIO base address.
///
/// IOHC::IOAPIC_BASE (0x013000F0):
///   Bit 0      : Enable
///   Bits [31:8]: Base address
///
/// Returns the IOAPIC base address in bytes, or 0 if disabled.
fn read_ioapic_base() -> u64 {
    let raw = smn_read32(IOHC_IOAPIC_BASE);
    let enabled = raw & 1 != 0;
    if !enabled {
        return 0;
    }
    (raw & 0xFFFF_FF00) as u64
}

/// Read a single MMIO aperture configuration.
///
/// Each aperture has 4 registers at a 16-byte stride from IOHC_MMIO_BASE0:
///   +0x00: base_lo  (bit 0 = enable, bit 1 = lock, bits [31:16] = base[31:16])
///   +0x04: base_hi  (bits [15:0] = base[47:32])
///   +0x08: limit_lo (bits [31:16] = limit[31:16])
///   +0x0C: limit_hi (bits [15:0] = limit[47:32])
fn read_mmio_aperture(idx: u32) -> MmioAperture {
    if idx >= MAX_MMIO_APERTURES {
        return EMPTY_APERTURE;
    }

    let reg_base = IOHC_MMIO_BASE0 + idx * MMIO_APERTURE_STRIDE;

    let base_lo = smn_read32(reg_base);
    let base_hi = smn_read32(reg_base + 0x04);
    let limit_lo = smn_read32(reg_base + 0x08);
    let limit_hi = smn_read32(reg_base + 0x0C);

    let enabled = base_lo & 1 != 0;
    if !enabled {
        return EMPTY_APERTURE;
    }

    // Base address: hi[15:0] << 32 | lo[31:16] << 16
    let base = (((base_hi & 0xFFFF) as u64) << 32) | ((base_lo & 0xFFFF_0000) as u64);

    // Limit address: hi[15:0] << 32 | lo[31:16] << 16 | 0xFFFF (inclusive)
    let limit = (((limit_hi & 0xFFFF) as u64) << 32)
        | ((limit_lo & 0xFFFF_0000) as u64)
        | 0xFFFF;

    MmioAperture {
        enabled,
        base,
        limit,
    }
}

// ── FFI exports ──

/// Initialise the AMD NBIO (NorthBridge I/O) driver.
///
/// Probes PCI 00:00.0 for the AMD Root Complex, verifies SMN access,
/// and reads NBIO configuration registers including top-of-DRAM,
/// PCIe ECAM base, IOAPIC base, MMIO apertures, and SYSHUB state.
///
/// Returns 0 on success, negative error on failure.
#[unsafe(no_mangle)]
pub extern "C" fn amd_nbio_init() -> i32 {
    log("amd_nbio: scanning for AMD Root Complex at PCI 00:00.0...");

    let device_id = match find_amd_root_complex() {
        Some(id) => id,
        None => {
            log("amd_nbio: no AMD Root Complex found at PCI 00:00.0");
            return -1;
        }
    };

    let gen_name = zen_generation_name(device_id);
    unsafe {
        fut_printf(
            b"amd_nbio: found AMD Root Complex (device %04x) - %s\n\0".as_ptr(),
            device_id as u32,
            gen_name.as_ptr(),
        );
    }

    // Verify that SMN access to the NBIO region is functional.
    if !verify_smn_access() {
        log("amd_nbio: SMN access verification failed (IOHC returned 0xFFFFFFFF)");
        return -2;
    }

    log("amd_nbio: SMN access to NBIO region verified");

    // Read Top of DRAM (below 4 GB).
    let top_of_dram = read_top_of_dram();
    unsafe {
        fut_printf(
            b"amd_nbio: top of DRAM (below 4G): 0x%08x (%lu MB)\n\0".as_ptr(),
            top_of_dram as u32,
            top_of_dram / (1024 * 1024),
        );
    }

    // Read Top of DRAM (above 4 GB).
    let top_of_dram_hi = read_top_of_dram_hi();
    if top_of_dram_hi > 0 {
        unsafe {
            fut_printf(
                b"amd_nbio: top of DRAM (above 4G): 0x%lx (%lu MB)\n\0".as_ptr(),
                top_of_dram_hi,
                top_of_dram_hi / (1024 * 1024),
            );
        }
    }

    // Read PCIe ECAM configuration base.
    let pcie_cfg_base = read_pcie_cfg_base();
    unsafe {
        fut_printf(
            b"amd_nbio: PCIe ECAM base: 0x%08x\n\0".as_ptr(),
            pcie_cfg_base as u32,
        );
    }

    // Read IOAPIC base address.
    let ioapic_base = read_ioapic_base();
    if ioapic_base > 0 {
        unsafe {
            fut_printf(
                b"amd_nbio: IOAPIC base: 0x%08x\n\0".as_ptr(),
                ioapic_base as u32,
            );
        }
    } else {
        log("amd_nbio: IOAPIC not enabled in IOHC");
    }

    // Enumerate MMIO apertures.
    let mut mmio_apertures = [EMPTY_APERTURE; MAX_MMIO_APERTURES as usize];
    let mut mmio_count: u32 = 0;

    for i in 0..MAX_MMIO_APERTURES {
        let aperture = read_mmio_aperture(i);
        mmio_apertures[i as usize] = aperture;

        if aperture.enabled {
            mmio_count += 1;
            unsafe {
                fut_printf(
                    b"amd_nbio: MMIO aperture %u: base=0x%lx limit=0x%lx\n\0".as_ptr(),
                    i,
                    aperture.base,
                    aperture.limit,
                );
            }
        }
    }

    unsafe {
        fut_printf(
            b"amd_nbio: %u MMIO aperture(s) enabled\n\0".as_ptr(),
            mmio_count,
        );
    }

    // Read SYSHUB configuration registers.
    let syshub_fabric_priority = smn_read32(SYSHUB_FABRIC_PRIORITY);
    let syshub_clk_config = smn_read32(SYSHUB_CLK_CONFIG);
    let syshub_misc_ctrl = smn_read32(SYSHUB_MISC_CTRL);

    unsafe {
        fut_printf(
            b"amd_nbio: SYSHUB fabric priority: 0x%08x\n\0".as_ptr(),
            syshub_fabric_priority,
        );
        fut_printf(
            b"amd_nbio: SYSHUB clock config: 0x%08x\n\0".as_ptr(),
            syshub_clk_config,
        );
        fut_printf(
            b"amd_nbio: SYSHUB misc control: 0x%08x\n\0".as_ptr(),
            syshub_misc_ctrl,
        );
    }

    // Read and log NBIF device control for diagnostics.
    let nbif_ctrl = smn_read32(NBIF_DEV_CTRL);
    unsafe {
        fut_printf(
            b"amd_nbio: NBIF device control: 0x%08x\n\0".as_ptr(),
            nbif_ctrl,
        );
    }

    // Read IOHC PCIe link capability for diagnostics.
    let pcie_link_cap = smn_read32(IOHC_PCIE_LINK_CAP);
    if pcie_link_cap != 0xFFFF_FFFF && pcie_link_cap != 0 {
        let max_speed = pcie_link_cap & 0x0F;
        let max_width = (pcie_link_cap >> 4) & 0x3F;
        let speed_str = match max_speed {
            1 => b"2.5 GT/s (Gen1)\0".as_ptr(),
            2 => b"5 GT/s (Gen2)\0".as_ptr(),
            3 => b"8 GT/s (Gen3)\0".as_ptr(),
            4 => b"16 GT/s (Gen4)\0".as_ptr(),
            5 => b"32 GT/s (Gen5)\0".as_ptr(),
            _ => b"unknown\0".as_ptr(),
        };
        unsafe {
            fut_printf(
                b"amd_nbio: PCIe link cap: max speed %s, max width x%u\n\0".as_ptr(),
                speed_str,
                max_width,
            );
        }
    }

    // Store driver state.
    let st = unsafe { &mut *STATE.get() };
    st.device_id = device_id;
    st.initialized = true;
    st.top_of_dram = top_of_dram;
    st.top_of_dram_hi = top_of_dram_hi;
    st.pcie_cfg_base = pcie_cfg_base;
    st.ioapic_base = ioapic_base;
    st.mmio_count = mmio_count;
    st.mmio_apertures = mmio_apertures;
    st.syshub_fabric_priority = syshub_fabric_priority;
    st.syshub_clk_config = syshub_clk_config;
    st.syshub_misc_ctrl = syshub_misc_ctrl;

    log("amd_nbio: driver initialised successfully");
    0
}

/// Return the top-of-DRAM address below 4 GB, in bytes.
///
/// Returns 0 if the driver is not initialised or the register is disabled.
#[unsafe(no_mangle)]
pub extern "C" fn amd_nbio_top_of_dram() -> u64 {
    let st = unsafe { &*STATE.get() };
    if !st.initialized {
        return 0;
    }
    st.top_of_dram
}

/// Return the top-of-DRAM address above 4 GB, in bytes.
///
/// Returns 0 if the driver is not initialised or the register is disabled.
#[unsafe(no_mangle)]
pub extern "C" fn amd_nbio_top_of_dram_hi() -> u64 {
    let st = unsafe { &*STATE.get() };
    if !st.initialized {
        return 0;
    }
    st.top_of_dram_hi
}

/// Return the PCIe ECAM configuration space base address.
///
/// Returns 0 if the driver is not initialised.
#[unsafe(no_mangle)]
pub extern "C" fn amd_nbio_pcie_cfg_base() -> u64 {
    let st = unsafe { &*STATE.get() };
    if !st.initialized {
        return 0;
    }
    st.pcie_cfg_base
}

/// Return the IOAPIC MMIO base address.
///
/// Returns 0 if the driver is not initialised or IOAPIC is disabled.
#[unsafe(no_mangle)]
pub extern "C" fn amd_nbio_ioapic_base() -> u64 {
    let st = unsafe { &*STATE.get() };
    if !st.initialized {
        return 0;
    }
    st.ioapic_base
}

/// Return the base address of MMIO aperture `idx` (0-7).
///
/// Returns 0 if the index is out of range, the aperture is disabled,
/// or the driver is not initialised.
#[unsafe(no_mangle)]
pub extern "C" fn amd_nbio_mmio_base(idx: u32) -> u64 {
    let st = unsafe { &*STATE.get() };
    if !st.initialized || idx >= MAX_MMIO_APERTURES {
        return 0;
    }
    let ap = &st.mmio_apertures[idx as usize];
    if !ap.enabled {
        return 0;
    }
    ap.base
}

/// Return the limit address of MMIO aperture `idx` (0-7).
///
/// Returns 0 if the index is out of range, the aperture is disabled,
/// or the driver is not initialised.
#[unsafe(no_mangle)]
pub extern "C" fn amd_nbio_mmio_limit(idx: u32) -> u64 {
    let st = unsafe { &*STATE.get() };
    if !st.initialized || idx >= MAX_MMIO_APERTURES {
        return 0;
    }
    let ap = &st.mmio_apertures[idx as usize];
    if !ap.enabled {
        return 0;
    }
    ap.limit
}

/// Return the number of enabled MMIO apertures.
///
/// Returns 0 if the driver is not initialised.
#[unsafe(no_mangle)]
pub extern "C" fn amd_nbio_mmio_count() -> u32 {
    let st = unsafe { &*STATE.get() };
    if !st.initialized {
        return 0;
    }
    st.mmio_count
}
