// SPDX-License-Identifier: MPL-2.0
//
// AMD Data Fabric (Infinity Fabric) Driver for Futura OS
//
// The Data Fabric manages inter-CCX/CCD/die communication, DRAM address
// mapping, and NUMA topology on AMD Ryzen (Zen-based) processors.
//
// Architecture:
//   - The Data Fabric is exposed via PCI functions on bus 0, device 18h:
//     Function 0: Node ID, system configuration, instance count
//     Function 1: DRAM base/limit address map registers
//     Function 3: NB capabilities (ECC, ChipKill)
//     Function 4: Infinity Fabric link/transport (clock divider)
//     Function 5: Extended memory configuration (DRAM hole, chip select)
//     Function 6: Extended NB configuration
//   - All registers are accessed through standard PCI configuration space
//     I/O ports 0xCF8/0xCFC
//
// Key registers:
//   F0x044: FabricBlockInstanceCount - number of fabric instances
//   F0x050: SystemCfg - die/CCD/CCX counts
//   F1x040-048: DRAMBaseAddress[0-7] - DRAM region base addresses
//   F1x044-04C: DRAMLimitAddress[0-7] - DRAM region limit addresses
//   F3x044: MCAPNbCfg - NB capabilities (ECC, ChipKill support)
//   F4x068: Infinity Fabric clock divider
//   F5x204-244: DRAM hole, chip select base/mask
//
// PCI identification: vendor 1022h (AMD), device 18h functions 0-7.
// Supported platforms: AM4 (Zen/Zen+/Zen2/Zen3), AM5 (Zen4/Zen5).

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

fn pci_read16(bus: u8, dev: u8, func: u8, offset: u8) -> u16 {
    let val32 = pci_read32(bus, dev, func, offset & 0xFC);
    ((val32 >> ((offset & 2) * 8)) & 0xFFFF) as u16
}

// ── AMD Data Fabric PCI constants ──

/// AMD vendor ID.
const AMD_VENDOR_ID: u16 = 0x1022;

/// Data Fabric is always on bus 0, device 0x18, functions 0-7.
const DF_BUS: u8 = 0;
const DF_DEV: u8 = 0x18;

/// Data Fabric function assignments.
const DF_FUNC_SYSCFG: u8 = 0;   // Node ID, system config, instance count
const DF_FUNC_DRAM: u8 = 1;     // DRAM base/limit address map
const DF_FUNC_NBCAP: u8 = 3;    // NB capabilities (ECC, ChipKill)
const DF_FUNC_LINK: u8 = 4;     // Infinity Fabric link/transport
const DF_FUNC_EXTMEM: u8 = 5;   // Extended memory configuration
const DF_FUNC_EXTNB: u8 = 6;    // Extended NB configuration

// ── Data Fabric register offsets ──

/// F0x044: FabricBlockInstanceCount - number of fabric block instances.
const F0_FABRIC_BLOCK_INSTANCE_COUNT: u8 = 0x44;

/// F0x050: SystemCfg - die, CCD, and CCX topology.
///   bits [3:0]   : number of dies minus 1
///   bits [7:4]   : number of CCDs minus 1
///   bits [11:8]  : number of CCXs per CCD minus 1
///   bits [15:12] : number of cores per CCX minus 1
const F0_SYSTEM_CFG: u8 = 0x50;

/// F1x040: DRAMBaseAddress registers start (8 pairs, stride 8).
///   bits [31:1]  : base address bits [39:9] (shifted left by 9 to get phys addr)
///   bit [0]      : read enable
const F1_DRAM_BASE_ADDR0: u8 = 0x40;

/// F1x044: DRAMLimitAddress registers start (8 pairs, stride 8).
///   bits [31:1]  : limit address bits [39:9]
///   bit [0]      : write enable (destination node routing)
const F1_DRAM_LIMIT_ADDR0: u8 = 0x44;

/// Stride between consecutive DRAM base/limit register pairs.
const DRAM_MAP_STRIDE: u8 = 0x08;

/// Maximum number of DRAM address map regions.
const MAX_DRAM_REGIONS: usize = 8;

/// F3x044: MCAPNbCfg - NB capabilities register.
///   bit [3]  : ECC capable
///   bit [4]  : ChipKill ECC capable
///   bit [25] : ECC enabled
const F3_MCAP_NB_CFG: u8 = 0x44;

/// F4x068: Infinity Fabric clock divider register.
///   bits [6:0]  : fabric clock divider value
///   bits [14:8] : fabric clock multiplier value
/// Fabric frequency = (reference_clock * multiplier) / divider
/// Typical reference clock is 100 MHz.
const F4_FABRIC_CLK_DIV: u8 = 0x68;

/// F5x204: DRAM hole base register.
///   bits [31:24] : hole base address bits [31:24] (in 16 MB units)
///   bit [0]      : DRAM hole valid
const F5_DRAM_HOLE_BASE: u8 = 0x04; // Offset within F5 space (accessed at 0x204 conceptually)

// ── Zen generation detection ──

/// Known Data Fabric device IDs (function 0) for various Zen generations.
/// These are the device IDs seen at PCI 00:18.0.
const DF_DEVID_ZEN1: u16 = 0x1460;     // Zen (Ryzen 1000)
const DF_DEVID_ZEN_PLUS: u16 = 0x1490; // Zen+ (Ryzen 2000)
const DF_DEVID_ZEN2: u16 = 0x1440;     // Zen 2 (Ryzen 3000)
const DF_DEVID_ZEN3: u16 = 0x1650;     // Zen 3 (Ryzen 5000)
const DF_DEVID_ZEN4: u16 = 0x14E0;     // Zen 4 (Ryzen 7000)
const DF_DEVID_ZEN5: u16 = 0x14F0;     // Zen 5 (Ryzen 9000)

/// Zen generation enumeration.
#[derive(Copy, Clone, PartialEq)]
enum ZenGen {
    Zen1,
    ZenPlus,
    Zen2,
    Zen3,
    Zen4,
    Zen5,
    Unknown,
}

impl ZenGen {
    fn name(self) -> &'static [u8] {
        match self {
            ZenGen::Zen1 => b"Zen (AM4)\0",
            ZenGen::ZenPlus => b"Zen+ (AM4)\0",
            ZenGen::Zen2 => b"Zen 2 (AM4)\0",
            ZenGen::Zen3 => b"Zen 3 (AM4)\0",
            ZenGen::Zen4 => b"Zen 4 (AM5)\0",
            ZenGen::Zen5 => b"Zen 5 (AM5)\0",
            ZenGen::Unknown => b"Unknown Zen\0",
        }
    }

    /// Reference clock for Infinity Fabric frequency calculation (MHz).
    /// All current Zen generations use 100 MHz as the base reference.
    fn ref_clock_mhz(self) -> u32 {
        100
    }
}

fn detect_zen_gen(device_id: u16) -> ZenGen {
    match device_id {
        DF_DEVID_ZEN1 => ZenGen::Zen1,
        DF_DEVID_ZEN_PLUS => ZenGen::ZenPlus,
        DF_DEVID_ZEN2 => ZenGen::Zen2,
        DF_DEVID_ZEN3 => ZenGen::Zen3,
        DF_DEVID_ZEN4 => ZenGen::Zen4,
        DF_DEVID_ZEN5 => ZenGen::Zen5,
        _ => ZenGen::Unknown,
    }
}

// ── DRAM region descriptor ──

/// Decoded DRAM address map region.
#[derive(Copy, Clone)]
struct DramRegion {
    /// Whether this region is enabled (read-enable bit set).
    enabled: bool,
    /// Physical base address in bytes.
    base: u64,
    /// Physical limit address in bytes (inclusive).
    limit: u64,
    /// Destination NUMA node ID (from limit register routing).
    dst_node: u8,
}

const EMPTY_DRAM_REGION: DramRegion = DramRegion {
    enabled: false,
    base: 0,
    limit: 0,
    dst_node: 0,
};

// ── Driver state ──

struct AmdDf {
    /// Whether the driver is initialised.
    initialized: bool,
    /// Detected Zen generation.
    zen_gen: ZenGen,
    /// Data Fabric device ID (from PCI 00:18.0).
    device_id: u16,
    /// Number of fabric block instances.
    fabric_instance_count: u32,
    /// Number of physical dies.
    die_count: u32,
    /// Number of CCDs (Core Complex Dies).
    ccd_count: u32,
    /// Number of CCXs per CCD.
    ccx_per_ccd: u32,
    /// Number of cores per CCX.
    cores_per_ccx: u32,
    /// Total CCX count (ccx_per_ccd * ccd_count).
    ccx_total: u32,
    /// DRAM address map regions.
    dram_regions: [DramRegion; MAX_DRAM_REGIONS],
    /// Number of enabled DRAM regions.
    dram_region_count: u32,
    /// Infinity Fabric frequency in MHz.
    fabric_freq_mhz: u32,
    /// Number of NUMA nodes detected.
    numa_node_count: u32,
    /// ECC capability present.
    ecc_capable: bool,
    /// ChipKill ECC capability present.
    chipkill_capable: bool,
    /// ECC currently enabled.
    ecc_enabled: bool,
    /// Raw SystemCfg register value.
    syscfg_raw: u32,
    /// Raw MCAPNbCfg register value.
    nbcap_raw: u32,
}

impl AmdDf {
    const fn new() -> Self {
        Self {
            initialized: false,
            zen_gen: ZenGen::Unknown,
            device_id: 0,
            fabric_instance_count: 0,
            die_count: 0,
            ccd_count: 0,
            ccx_per_ccd: 0,
            cores_per_ccx: 0,
            ccx_total: 0,
            dram_regions: [EMPTY_DRAM_REGION; MAX_DRAM_REGIONS],
            dram_region_count: 0,
            fabric_freq_mhz: 0,
            numa_node_count: 0,
            ecc_capable: false,
            chipkill_capable: false,
            ecc_enabled: false,
            syscfg_raw: 0,
            nbcap_raw: 0,
        }
    }
}

static STATE: StaticCell<AmdDf> = StaticCell::new(AmdDf::new());

// ── Data Fabric PCI access helpers ──

/// Read a 32-bit register from a specific Data Fabric function.
fn df_read32(func: u8, offset: u8) -> u32 {
    pci_read32(DF_BUS, DF_DEV, func, offset)
}

// ── Topology discovery ──

/// Detect the Data Fabric at PCI 00:18.0 and return the device ID.
fn detect_data_fabric() -> Option<u16> {
    let vendor = pci_read16(DF_BUS, DF_DEV, DF_FUNC_SYSCFG, 0x00);
    if vendor != AMD_VENDOR_ID {
        return None;
    }

    let device_id = pci_read16(DF_BUS, DF_DEV, DF_FUNC_SYSCFG, 0x02);
    // Sanity check: device ID should not be 0xFFFF (absent device).
    if device_id == 0xFFFF {
        return None;
    }

    Some(device_id)
}

/// Read the die/CCD/CCX topology from F0x050 (SystemCfg).
///
/// Returns (die_count, ccd_count, ccx_per_ccd, cores_per_ccx).
fn read_topology() -> (u32, u32, u32, u32) {
    let syscfg = df_read32(DF_FUNC_SYSCFG, F0_SYSTEM_CFG);

    // SystemCfg register bit fields:
    //   bits [3:0]   : number of dies minus 1
    //   bits [7:4]   : number of CCDs minus 1
    //   bits [11:8]  : number of CCXs per CCD minus 1
    //   bits [15:12] : number of cores per CCX minus 1
    let dies = (syscfg & 0x0F) + 1;
    let ccds = ((syscfg >> 4) & 0x0F) + 1;
    let ccx_per_ccd = ((syscfg >> 8) & 0x0F) + 1;
    let cores_per_ccx = ((syscfg >> 12) & 0x0F) + 1;

    (dies, ccds, ccx_per_ccd, cores_per_ccx)
}

/// Read FabricBlockInstanceCount from F0x044.
fn read_fabric_instance_count() -> u32 {
    let val = df_read32(DF_FUNC_SYSCFG, F0_FABRIC_BLOCK_INSTANCE_COUNT);
    // Bits [7:0] contain the instance count.
    val & 0xFF
}

// ── DRAM address map ──

/// Read and decode the DRAM base/limit address map from function 1.
/// Populates the provided array and returns the number of enabled regions.
fn read_dram_map(regions: &mut [DramRegion; MAX_DRAM_REGIONS]) -> u32 {
    let mut count = 0u32;

    for i in 0..MAX_DRAM_REGIONS {
        let base_offset = F1_DRAM_BASE_ADDR0.wrapping_add((i as u8) * DRAM_MAP_STRIDE);
        let limit_offset = F1_DRAM_LIMIT_ADDR0.wrapping_add((i as u8) * DRAM_MAP_STRIDE);

        let base_raw = df_read32(DF_FUNC_DRAM, base_offset);
        let limit_raw = df_read32(DF_FUNC_DRAM, limit_offset);

        // Base register:
        //   bit [0]     : read enable
        //   bits [31:1] : base address bits [39:9]
        let enabled = base_raw & 1 != 0;

        // Physical address reconstruction:
        //   base_addr = (base_raw & 0xFFFF_FFFE) << 8
        //   This gives bits [39:9] shifted to their correct position,
        //   with bits [8:0] implicitly zero (512-byte alignment).
        let base_addr = ((base_raw & 0xFFFF_FFFE) as u64) << 8;

        // Limit register:
        //   bits [31:1] : limit address bits [39:9]
        //   bit [0]     : destination node route (low bit of node ID)
        //   bits [2:0]  : destination node ID (some generations)
        let limit_addr = ((limit_raw & 0xFFFF_FFFE) as u64) << 8 | 0x1FF;
        let dst_node = (limit_raw & 0x07) as u8;

        regions[i] = DramRegion {
            enabled,
            base: base_addr,
            limit: limit_addr,
            dst_node,
        };

        if enabled {
            count += 1;
        }
    }

    count
}

// ── NB capabilities ──

/// Read NB capability register (F3x044) and extract ECC/ChipKill info.
///
/// Returns (ecc_capable, chipkill_capable, ecc_enabled).
fn read_nb_capabilities() -> (bool, bool, bool) {
    let nbcap = df_read32(DF_FUNC_NBCAP, F3_MCAP_NB_CFG);

    // MCAPNbCfg register:
    //   bit [3]  : ECC capable
    //   bit [4]  : ChipKill ECC capable
    //   bit [25] : ECC enabled
    let ecc_cap = nbcap & (1 << 3) != 0;
    let chipkill_cap = nbcap & (1 << 4) != 0;
    let ecc_en = nbcap & (1 << 25) != 0;

    (ecc_cap, chipkill_cap, ecc_en)
}

// ── Infinity Fabric frequency ──

/// Read the Infinity Fabric clock divider from F4x068 and compute frequency.
///
/// The register contains a multiplier and divider value relative to a
/// 100 MHz reference clock.
///
/// Returns the fabric frequency in MHz, or 0 if unreadable.
fn read_fabric_frequency(zen_gen: ZenGen) -> u32 {
    let clk_div = df_read32(DF_FUNC_LINK, F4_FABRIC_CLK_DIV);

    // F4x068 layout:
    //   bits [6:0]  : divider value
    //   bits [14:8] : multiplier value
    let divider = clk_div & 0x7F;
    let multiplier = (clk_div >> 8) & 0x7F;

    if divider == 0 || multiplier == 0 {
        // Invalid or unprogrammed register; return a safe default.
        // On Zen2+ the default fabric clock is typically 1600 MHz.
        return 0;
    }

    let ref_clk = zen_gen.ref_clock_mhz();

    // Fabric frequency = reference_clock * multiplier / divider
    (ref_clk * multiplier) / divider
}

// ── NUMA node discovery ──

/// Determine the number of NUMA nodes from the DRAM address map.
///
/// Each enabled DRAM region has a destination node ID in its limit register.
/// The number of unique node IDs gives us the NUMA node count.
fn count_numa_nodes(regions: &[DramRegion; MAX_DRAM_REGIONS]) -> u32 {
    let mut node_seen: [bool; 8] = [false; 8];
    let mut count = 0u32;

    for region in regions.iter() {
        if region.enabled {
            let node = region.dst_node as usize;
            if node < 8 && !node_seen[node] {
                node_seen[node] = true;
                count += 1;
            }
        }
    }

    // Always report at least 1 NUMA node if any DRAM region is enabled.
    if count == 0 {
        for region in regions.iter() {
            if region.enabled {
                return 1;
            }
        }
    }

    count
}

// ── FFI exports ──

/// Initialise the AMD Data Fabric (Infinity Fabric) driver.
///
/// Probes PCI 00:18.x for the AMD Data Fabric, reads die/CCD/CCX topology,
/// DRAM address map, Infinity Fabric frequency, and ECC capabilities.
///
/// Returns 0 on success, negative error on failure.
#[unsafe(no_mangle)]
pub extern "C" fn amd_df_init() -> i32 {
    log("amd_df: scanning for AMD Data Fabric at PCI 00:18.x...");

    // Step 1: Detect Data Fabric presence.
    let device_id = match detect_data_fabric() {
        Some(id) => id,
        None => {
            log("amd_df: no AMD Data Fabric found at PCI 00:18.0");
            return -1;
        }
    };

    let zen_gen = detect_zen_gen(device_id);

    unsafe {
        fut_printf(
            b"amd_df: found Data Fabric (device %04x) - %s\n\0".as_ptr(),
            device_id as u32,
            zen_gen.name().as_ptr(),
        );
    }

    // Step 2: Read fabric instance count.
    let instance_count = read_fabric_instance_count();
    unsafe {
        fut_printf(
            b"amd_df: fabric block instance count: %u\n\0".as_ptr(),
            instance_count,
        );
    }

    // Step 3: Read die/CCD/CCX topology.
    let (die_count, ccd_count, ccx_per_ccd, cores_per_ccx) = read_topology();
    let ccx_total = ccx_per_ccd * ccd_count;
    let syscfg_raw = df_read32(DF_FUNC_SYSCFG, F0_SYSTEM_CFG);

    unsafe {
        fut_printf(
            b"amd_df: topology: %u die(s), %u CCD(s), %u CCX/CCD, %u cores/CCX\n\0".as_ptr(),
            die_count,
            ccd_count,
            ccx_per_ccd,
            cores_per_ccx,
        );
        fut_printf(
            b"amd_df: total CCXs: %u, total cores: %u\n\0".as_ptr(),
            ccx_total,
            ccx_total * cores_per_ccx,
        );
    }

    // Step 4: Read DRAM address map.
    let mut dram_regions = [EMPTY_DRAM_REGION; MAX_DRAM_REGIONS];
    let dram_region_count = read_dram_map(&mut dram_regions);

    unsafe {
        fut_printf(
            b"amd_df: DRAM address map: %u enabled region(s)\n\0".as_ptr(),
            dram_region_count,
        );
    }

    for i in 0..MAX_DRAM_REGIONS {
        if dram_regions[i].enabled {
            unsafe {
                fut_printf(
                    b"amd_df:   region %u: base=0x%08x%08x limit=0x%08x%08x node=%u\n\0".as_ptr(),
                    i as u32,
                    (dram_regions[i].base >> 32) as u32,
                    dram_regions[i].base as u32,
                    (dram_regions[i].limit >> 32) as u32,
                    dram_regions[i].limit as u32,
                    dram_regions[i].dst_node as u32,
                );
            }
        }
    }

    // Step 5: Read NB capabilities (ECC, ChipKill).
    let (ecc_capable, chipkill_capable, ecc_enabled) = read_nb_capabilities();
    let nbcap_raw = df_read32(DF_FUNC_NBCAP, F3_MCAP_NB_CFG);

    unsafe {
        fut_printf(
            b"amd_df: NB capabilities: ECC=%s, ChipKill=%s, ECC enabled=%s\n\0".as_ptr(),
            if ecc_capable { b"yes\0".as_ptr() } else { b"no\0".as_ptr() },
            if chipkill_capable { b"yes\0".as_ptr() } else { b"no\0".as_ptr() },
            if ecc_enabled { b"yes\0".as_ptr() } else { b"no\0".as_ptr() },
        );
    }

    // Step 6: Read Infinity Fabric frequency.
    let fabric_freq_mhz = read_fabric_frequency(zen_gen);

    if fabric_freq_mhz > 0 {
        unsafe {
            fut_printf(
                b"amd_df: Infinity Fabric frequency: %u MHz\n\0".as_ptr(),
                fabric_freq_mhz,
            );
        }
    } else {
        log("amd_df: could not determine Infinity Fabric frequency");
    }

    // Step 7: Count NUMA nodes.
    let numa_node_count = count_numa_nodes(&dram_regions);

    unsafe {
        fut_printf(
            b"amd_df: NUMA nodes: %u\n\0".as_ptr(),
            numa_node_count,
        );
    }

    // Store driver state.
    let st = unsafe { &mut *STATE.get() };
    st.initialized = true;
    st.zen_gen = zen_gen;
    st.device_id = device_id;
    st.fabric_instance_count = instance_count;
    st.die_count = die_count;
    st.ccd_count = ccd_count;
    st.ccx_per_ccd = ccx_per_ccd;
    st.cores_per_ccx = cores_per_ccx;
    st.ccx_total = ccx_total;
    st.dram_regions = dram_regions;
    st.dram_region_count = dram_region_count;
    st.fabric_freq_mhz = fabric_freq_mhz;
    st.numa_node_count = numa_node_count;
    st.ecc_capable = ecc_capable;
    st.chipkill_capable = chipkill_capable;
    st.ecc_enabled = ecc_enabled;
    st.syscfg_raw = syscfg_raw;
    st.nbcap_raw = nbcap_raw;

    log("amd_df: driver initialised successfully");
    0
}

/// Return the number of physical dies.
///
/// Returns 0 if the driver is not initialised.
#[unsafe(no_mangle)]
pub extern "C" fn amd_df_die_count() -> u32 {
    let st = unsafe { &*STATE.get() };
    if !st.initialized {
        return 0;
    }
    st.die_count
}

/// Return the total number of CCXs (Core Complexes).
///
/// This is ccx_per_ccd * ccd_count.
/// Returns 0 if the driver is not initialised.
#[unsafe(no_mangle)]
pub extern "C" fn amd_df_ccx_count() -> u32 {
    let st = unsafe { &*STATE.get() };
    if !st.initialized {
        return 0;
    }
    st.ccx_total
}

/// Return the Infinity Fabric frequency in MHz.
///
/// Returns 0 if the driver is not initialised or the frequency could not
/// be determined.
#[unsafe(no_mangle)]
pub extern "C" fn amd_df_fabric_freq_mhz() -> u32 {
    let st = unsafe { &*STATE.get() };
    if !st.initialized {
        return 0;
    }
    st.fabric_freq_mhz
}

/// Return the physical base address of a DRAM region (in bytes).
///
/// `region` - DRAM region index (0-7).
///
/// Returns the base address, or 0 if the region is disabled or index invalid.
#[unsafe(no_mangle)]
pub extern "C" fn amd_df_dram_base(region: u32) -> u64 {
    let st = unsafe { &*STATE.get() };
    if !st.initialized || region >= MAX_DRAM_REGIONS as u32 {
        return 0;
    }
    let r = &st.dram_regions[region as usize];
    if !r.enabled {
        return 0;
    }
    r.base
}

/// Return the physical limit address of a DRAM region (in bytes, inclusive).
///
/// `region` - DRAM region index (0-7).
///
/// Returns the limit address, or 0 if the region is disabled or index invalid.
#[unsafe(no_mangle)]
pub extern "C" fn amd_df_dram_limit(region: u32) -> u64 {
    let st = unsafe { &*STATE.get() };
    if !st.initialized || region >= MAX_DRAM_REGIONS as u32 {
        return 0;
    }
    let r = &st.dram_regions[region as usize];
    if !r.enabled {
        return 0;
    }
    r.limit
}

/// Return the number of NUMA nodes detected.
///
/// Returns 0 if the driver is not initialised.
#[unsafe(no_mangle)]
pub extern "C" fn amd_df_numa_node_count() -> u32 {
    let st = unsafe { &*STATE.get() };
    if !st.initialized {
        return 0;
    }
    st.numa_node_count
}

/// Return whether the platform has ECC capability.
///
/// This checks both hardware capability (NB cap register) and whether
/// ECC is currently enabled. Returns true if ECC is at least capable
/// (it may or may not be enabled depending on BIOS settings and DIMM type).
///
/// Returns false if the driver is not initialised.
#[unsafe(no_mangle)]
pub extern "C" fn amd_df_has_ecc() -> bool {
    let st = unsafe { &*STATE.get() };
    if !st.initialized {
        return false;
    }
    st.ecc_capable
}
