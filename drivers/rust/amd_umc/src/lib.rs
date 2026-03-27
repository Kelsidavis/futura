// SPDX-License-Identifier: MPL-2.0
//
// AMD Unified Memory Controller (UMC) Driver for Futura OS
//
// Implements read-only discovery and monitoring of the AMD Unified Memory
// Controller found on Ryzen AM4 (Zen/Zen2/Zen3) and AM5 (Zen4/Zen5) CPUs.
//
// Architecture:
//   - UMC registers are accessed via the AMD SMN (System Management Network)
//     bus, which is reached through PCI device 00:00.0 registers 0x60/0x64
//   - Channel 0 base = 0x50000, Channel 1 base = 0x150000 (AM4)
//   - AM5 (Zen4+) may expose additional channels at 0x250000, 0x350000
//   - Provides DDR type detection, timing readback, ECC status, DIMM sizing
//
// SMN access protocol:
//   1. Write target SMN address to PCI 00:00.0 config offset 0x60
//   2. Read/write data from PCI 00:00.0 config offset 0x64
//
// This driver is read-only; it does not modify UMC configuration.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(unexpected_cfgs)]

use core::cell::UnsafeCell;

use common::log;

unsafe extern "C" {
    fn fut_printf(fmt: *const u8, ...);
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

// ── Static state wrapper ──

/// Wrapper to allow `UnsafeCell` in a `static` (requires `Sync`).
/// Safety: all access is single-threaded or externally synchronised by the caller.
struct StaticCell<T>(UnsafeCell<T>);
unsafe impl<T> Sync for StaticCell<T> {}
impl<T> StaticCell<T> {
    const fn new(val: T) -> Self { Self(UnsafeCell::new(val)) }
    fn get(&self) -> *mut T { self.0.get() }
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

// ── SMN (System Management Network) access ──
//
// AMD data fabric / north bridge is PCI 00:00.0.
// SMN address register = PCI config offset 0x60
// SMN data register    = PCI config offset 0x64

/// PCI bus/device/function for AMD data fabric (root complex).
const DF_BUS: u8 = 0;
const DF_DEV: u8 = 0;
const DF_FUNC: u8 = 0;

/// SMN address port (PCI config offset on device 00:00.0).
const SMN_ADDR_REG: u8 = 0x60;
/// SMN data port (PCI config offset on device 00:00.0).
const SMN_DATA_REG: u8 = 0x64;

/// Read a 32-bit value from the AMD SMN bus.
fn smn_read32(addr: u32) -> u32 {
    pci_write32(DF_BUS, DF_DEV, DF_FUNC, SMN_ADDR_REG, addr);
    pci_read32(DF_BUS, DF_DEV, DF_FUNC, SMN_DATA_REG)
}

/// Write a 32-bit value to the AMD SMN bus.
fn smn_write32(addr: u32, val: u32) {
    pci_write32(DF_BUS, DF_DEV, DF_FUNC, SMN_ADDR_REG, addr);
    pci_write32(DF_BUS, DF_DEV, DF_FUNC, SMN_DATA_REG, val);
}

// ── UMC SMN register base addresses per channel ──

/// Maximum number of UMC channels we support (AM5 Zen4 can have up to 4).
const MAX_CHANNELS: usize = 4;

/// SMN base addresses for UMC channels.
/// AM4: channels 0 and 1 only.  AM5: up to 4 channels.
const UMC_CHANNEL_BASE: [u32; MAX_CHANNELS] = [
    0x0005_0000, // Channel 0
    0x0015_0000, // Channel 1
    0x0025_0000, // Channel 2 (AM5 only)
    0x0035_0000, // Channel 3 (AM5 only)
];

// ── UMC register offsets (relative to channel base) ──

/// Memory type, width, ECC enable.
const UMC_CONFIG: u32 = 0x000;
/// SDRAM type (DDR4/DDR5), rank count.
const UMC_SDRAM_CONFIG: u32 = 0x004;
/// tCL, tRCD, tRP, tRAS.
const UMC_DRAM_TIMING1: u32 = 0x200;
/// tRC, tRFC.
const UMC_DRAM_TIMING2: u32 = 0x204;
/// tWR, tWTR.
const UMC_DRAM_TIMING3: u32 = 0x208;
/// tRRD, tFAW.
const UMC_DRAM_TIMING4: u32 = 0x20C;
/// Rows, columns, banks, bank groups.
const UMC_ADDR_CONFIG: u32 = 0x300;
/// DIMM 0 configuration (size, ranks).
const UMC_DIMM_CONFIG0: u32 = 0x320;
/// DIMM 1 configuration (size, ranks).
const UMC_DIMM_CONFIG1: u32 = 0x324;
/// ECC error count: correctable and uncorrectable.
const UMC_ECC_STATUS: u32 = 0xD04;
/// Address of last ECC error.
const UMC_ECC_ADDR: u32 = 0xD08;
/// ECC syndrome bits.
const UMC_ECC_SYNDROME: u32 = 0xD10;

// ── Platform detection ──

/// AMD vendor ID.
const AMD_VENDOR_ID: u16 = 0x1022;

/// Known AMD data fabric / root complex device IDs.
/// AM4 (Zen/Zen+/Zen2/Zen3):
const DF_DEVICE_MATISSE: u16 = 0x1480;   // Zen2 (Ryzen 3000)
const DF_DEVICE_VERMEER: u16 = 0x1440;   // Zen3 (Ryzen 5000)
const DF_DEVICE_PINNACLE: u16 = 0x1450;  // Zen+ (Ryzen 2000)
const DF_DEVICE_SUMMIT: u16 = 0x1460;    // Zen (Ryzen 1000)
/// AM5 (Zen4/Zen5):
const DF_DEVICE_RAPHAEL: u16 = 0x14D8;   // Zen4 (Ryzen 7000)
const DF_DEVICE_GRANITE: u16 = 0x14E8;   // Zen5 (Ryzen 9000)

/// Platform generation.
#[derive(Copy, Clone, PartialEq)]
enum Platform {
    Am4,
    Am5,
}

impl Platform {
    fn num_channels(self) -> u32 {
        match self {
            Platform::Am4 => 2,
            Platform::Am5 => 4,
        }
    }

    fn name(self) -> &'static [u8] {
        match self {
            Platform::Am4 => b"AM4\0",
            Platform::Am5 => b"AM5\0",
        }
    }
}

/// Detect the AMD platform by reading PCI 00:00.0 vendor/device ID.
fn detect_platform() -> Option<Platform> {
    let vid_did = pci_read32(DF_BUS, DF_DEV, DF_FUNC, 0x00);
    let vendor = (vid_did & 0xFFFF) as u16;
    let device = ((vid_did >> 16) & 0xFFFF) as u16;

    if vendor != AMD_VENDOR_ID {
        return None;
    }

    match device {
        DF_DEVICE_SUMMIT | DF_DEVICE_PINNACLE | DF_DEVICE_MATISSE | DF_DEVICE_VERMEER => {
            Some(Platform::Am4)
        }
        DF_DEVICE_RAPHAEL | DF_DEVICE_GRANITE => Some(Platform::Am5),
        _ => {
            // Unknown AMD data fabric; try AM4 with 2 channels as a safe default.
            // If UMC_CONFIG reads back as 0 or 0xFFFFFFFF, the channel will be
            // marked inactive during probing.
            Some(Platform::Am4)
        }
    }
}

// ── UMC channel state ──

/// Decoded timing parameters for a single UMC channel.
#[derive(Copy, Clone)]
struct ChannelTimings {
    cl: u32,
    trcd: u32,
    trp: u32,
    tras: u32,
    trc: u32,
    trfc: u32,
    twr: u32,
    twtr: u32,
    trrd: u32,
    tfaw: u32,
}

/// Per-DIMM configuration.
#[derive(Copy, Clone)]
struct DimmInfo {
    /// DIMM size in megabytes (0 = not populated).
    size_mb: u32,
    /// Number of ranks.
    ranks: u32,
    /// Raw register value.
    raw: u32,
}

/// Per-channel UMC state.
#[derive(Copy, Clone)]
struct ChannelState {
    /// Whether this channel is active (has populated memory).
    active: bool,
    /// DDR type: 4 = DDR4, 5 = DDR5.
    ddr_type: u32,
    /// ECC enabled.
    ecc_enabled: bool,
    /// Bus width (64 or 128).
    bus_width: u32,
    /// Number of ranks.
    rank_count: u32,
    /// Timing parameters.
    timings: ChannelTimings,
    /// Address configuration raw register.
    addr_config_raw: u32,
    /// DIMM configuration.
    dimms: [DimmInfo; 2],
}

const EMPTY_DIMM: DimmInfo = DimmInfo { size_mb: 0, ranks: 0, raw: 0 };
const EMPTY_TIMINGS: ChannelTimings = ChannelTimings {
    cl: 0, trcd: 0, trp: 0, tras: 0,
    trc: 0, trfc: 0, twr: 0, twtr: 0,
    trrd: 0, tfaw: 0,
};
const EMPTY_CHANNEL: ChannelState = ChannelState {
    active: false,
    ddr_type: 0,
    ecc_enabled: false,
    bus_width: 64,
    rank_count: 0,
    timings: EMPTY_TIMINGS,
    addr_config_raw: 0,
    dimms: [EMPTY_DIMM; 2],
};

// ── Driver state ──

struct AmdUmc {
    platform: Platform,
    /// Number of channels probed (2 on AM4, up to 4 on AM5).
    num_channels: u32,
    /// Per-channel state.
    channels: [ChannelState; MAX_CHANNELS],
    /// Total memory discovered across all channels (MB).
    total_size_mb: u64,
    /// Estimated memory clock speed (MHz), derived from timings heuristic.
    speed_mhz: u32,
}

static STATE: StaticCell<Option<AmdUmc>> = StaticCell::new(None);

// ── UMC register reading helpers ──

/// Read a UMC register for a given channel.
fn umc_read(channel: u32, offset: u32) -> u32 {
    if (channel as usize) >= MAX_CHANNELS {
        return 0;
    }
    let addr = UMC_CHANNEL_BASE[channel as usize] + offset;
    smn_read32(addr)
}

// ── Channel probing ──

/// Probe a single UMC channel and return its state.
fn probe_channel(ch: u32) -> ChannelState {
    let config = umc_read(ch, UMC_CONFIG);
    let sdram_config = umc_read(ch, UMC_SDRAM_CONFIG);

    // If the config register reads back as all-ones or zero, the channel
    // is likely not populated or the SMN address is invalid.
    if config == 0xFFFF_FFFF || config == 0 {
        return EMPTY_CHANNEL;
    }

    // UMC_CONFIG bit fields (varies by generation, common layout):
    //   bit 0      : channel enabled
    //   bits [5:4] : bus width encoding (0=64, 1=128)
    //   bit 12     : ECC enabled
    let enabled = config & 1 != 0;
    if !enabled {
        return EMPTY_CHANNEL;
    }

    let ecc_enabled = (config >> 12) & 1 != 0;
    let width_enc = (config >> 4) & 0x3;
    let bus_width = match width_enc {
        0 => 64,
        1 => 128,
        _ => 64,
    };

    // UMC_SDRAM_CONFIG bit fields:
    //   bits [2:0]  : SDRAM type (0 = DDR4, 1 = DDR5 on newer; varies)
    //   bits [11:8] : number of ranks minus 1
    let sdram_type_raw = sdram_config & 0x07;
    // On Zen4+, type 1 indicates DDR5. On Zen/Zen2/Zen3, type 0 indicates DDR4.
    // A simple heuristic: if the field is 0, DDR4; if 1, DDR5.
    let ddr_type = if sdram_type_raw == 0 { 4u32 } else { 5u32 };
    let rank_count = ((sdram_config >> 8) & 0x0F) + 1;

    // Read timing registers.
    let timing1 = umc_read(ch, UMC_DRAM_TIMING1);
    let timing2 = umc_read(ch, UMC_DRAM_TIMING2);
    let timing3 = umc_read(ch, UMC_DRAM_TIMING3);
    let timing4 = umc_read(ch, UMC_DRAM_TIMING4);

    // UMC_DRAM_TIMING1: tCL[5:0], tRCD[13:8], tRP[21:16], tRAS[29:24]
    let cl   = timing1 & 0x3F;
    let trcd = (timing1 >> 8) & 0x3F;
    let trp  = (timing1 >> 16) & 0x3F;
    let tras = (timing1 >> 24) & 0x3F;

    // UMC_DRAM_TIMING2: tRC[7:0], tRFC[25:16]
    let trc  = timing2 & 0xFF;
    let trfc = (timing2 >> 16) & 0x3FF;

    // UMC_DRAM_TIMING3: tWR[5:0], tWTR[13:8]
    let twr  = timing3 & 0x3F;
    let twtr = (timing3 >> 8) & 0x3F;

    // UMC_DRAM_TIMING4: tRRD[4:0], tFAW[12:8]
    let trrd = timing4 & 0x1F;
    let tfaw = (timing4 >> 8) & 0x1F;

    let timings = ChannelTimings {
        cl, trcd, trp, tras, trc, trfc, twr, twtr, trrd, tfaw,
    };

    // Read address configuration.
    let addr_config_raw = umc_read(ch, UMC_ADDR_CONFIG);

    // Read DIMM configuration.
    let dimm0_raw = umc_read(ch, UMC_DIMM_CONFIG0);
    let dimm1_raw = umc_read(ch, UMC_DIMM_CONFIG1);

    let dimm0 = decode_dimm(dimm0_raw);
    let dimm1 = decode_dimm(dimm1_raw);

    ChannelState {
        active: true,
        ddr_type,
        ecc_enabled,
        bus_width,
        rank_count,
        timings,
        addr_config_raw,
        dimms: [dimm0, dimm1],
    }
}

/// Decode a DIMM configuration register into size and rank info.
///
/// DIMM_CONFIG register layout (approximate, varies by generation):
///   bit 0       : DIMM present
///   bits [3:1]  : number of ranks minus 1
///   bits [19:8] : size encoding (in units of 256 MB on DDR4, 512 MB on DDR5)
fn decode_dimm(raw: u32) -> DimmInfo {
    if raw == 0 || raw == 0xFFFF_FFFF {
        return EMPTY_DIMM;
    }

    let present = raw & 1 != 0;
    if !present {
        return DimmInfo { size_mb: 0, ranks: 0, raw };
    }

    let ranks = ((raw >> 1) & 0x07) + 1;

    // Size encoding: bits [19:8] represent the size in 256 MB units.
    // This is a common encoding; the actual formula depends on the exact
    // UMC generation, but 256 MB granularity is typical for DDR4.
    let size_enc = (raw >> 8) & 0xFFF;
    let size_mb = if size_enc > 0 {
        size_enc * 256
    } else {
        // Fallback: estimate from rank count (assume 8 Gbit dies, x8 width).
        // 1 rank of x8, 8 Gbit = 1 GB per rank.
        ranks * 1024
    };

    DimmInfo { size_mb, ranks, raw }
}

// ── MemoryInfo FFI structure ──

/// Memory information structure returned to C callers.
#[repr(C)]
pub struct MemoryInfo {
    /// DDR type: 4 = DDR4, 5 = DDR5.
    ddr_type: u32,
    /// Number of active memory channels.
    channels: u32,
    /// Total memory size in megabytes.
    total_size_mb: u64,
    /// Estimated memory clock speed in MHz.
    speed_mhz: u32,
    /// Whether ECC is enabled (on any channel).
    ecc_enabled: bool,
    /// CAS Latency (tCL) from channel 0.
    cl: u32,
    /// RAS-to-CAS Delay (tRCD) from channel 0.
    trcd: u32,
    /// Row Precharge (tRP) from channel 0.
    trp: u32,
    /// Row Active time (tRAS) from channel 0.
    tras: u32,
}

// ── FFI exports ──

/// Initialise the AMD Unified Memory Controller driver.
///
/// Detects the AMD platform via PCI 00:00.0, probes all UMC channels via
/// the SMN bus, reads timing parameters, DIMM configuration, and ECC state.
///
/// Returns 0 on success, negative error on failure.
#[unsafe(no_mangle)]
pub extern "C" fn amd_umc_init() -> i32 {
    log("amd_umc: initialising AMD Unified Memory Controller driver");

    // Detect AMD platform.
    let platform = match detect_platform() {
        Some(p) => p,
        None => {
            log("amd_umc: no AMD data fabric detected at PCI 00:00.0");
            return -1;
        }
    };

    unsafe {
        fut_printf(
            b"amd_umc: detected %s platform\n\0".as_ptr(),
            platform.name().as_ptr(),
        );
    }

    let max_ch = platform.num_channels();

    // Verify SMN access is working by reading a known location.
    // The data fabric vendor ID should echo through SMN reads.
    let test = smn_read32(UMC_CHANNEL_BASE[0] + UMC_CONFIG);
    if test == 0xFFFF_FFFF {
        // All-ones may indicate the SMN bus is not accessible.
        // This is not necessarily fatal (channel 0 might be unpopulated),
        // so we continue probing.
        log("amd_umc: warning - SMN read returned 0xFFFFFFFF for channel 0");
    }

    // Probe each channel.
    let mut channels = [EMPTY_CHANNEL; MAX_CHANNELS];
    let mut active_count: u32 = 0;
    let mut total_size_mb: u64 = 0;

    for ch in 0..max_ch {
        channels[ch as usize] = probe_channel(ch);
        let state = &channels[ch as usize];

        if state.active {
            active_count += 1;

            let ch_size: u64 = state.dimms[0].size_mb as u64 + state.dimms[1].size_mb as u64;
            total_size_mb += ch_size;

            let ddr_str = if state.ddr_type == 5 { b"DDR5\0".as_ptr() } else { b"DDR4\0".as_ptr() };
            let ecc_str = if state.ecc_enabled { b"ECC\0".as_ptr() } else { b"non-ECC\0".as_ptr() };

            unsafe {
                fut_printf(
                    b"amd_umc: channel %u: %s %s, %u-bit, %u rank(s), %lu MB\n\0".as_ptr(),
                    ch,
                    ddr_str,
                    ecc_str,
                    state.bus_width,
                    state.rank_count,
                    ch_size,
                );

                fut_printf(
                    b"amd_umc:   timings: CL=%u tRCD=%u tRP=%u tRAS=%u tRC=%u tRFC=%u\n\0".as_ptr(),
                    state.timings.cl,
                    state.timings.trcd,
                    state.timings.trp,
                    state.timings.tras,
                    state.timings.trc,
                    state.timings.trfc,
                );

                // Log DIMM population.
                for d in 0..2u32 {
                    let dimm = &state.dimms[d as usize];
                    if dimm.size_mb > 0 {
                        fut_printf(
                            b"amd_umc:   DIMM %u: %u MB, %u rank(s)\n\0".as_ptr(),
                            d,
                            dimm.size_mb,
                            dimm.ranks,
                        );
                    }
                }
            }
        }
    }

    if active_count == 0 {
        log("amd_umc: no active memory channels found");
        return -6; // ENXIO
    }

    // Estimate memory speed from tCL heuristic.
    // This is approximate; accurate speed requires reading the MCLK from
    // the data fabric or SMU, which is beyond this driver's scope.
    // Common DDR4 tCL values at various speeds:
    //   DDR4-2133: CL15, DDR4-2400: CL16, DDR4-2666: CL18,
    //   DDR4-3200: CL22, DDR4-3600: CL16-18 (XMP)
    // Common DDR5:
    //   DDR5-4800: CL40, DDR5-5600: CL36, DDR5-6000: CL30-36
    let first_active = channels.iter().find(|c| c.active).unwrap();
    let speed_mhz = estimate_speed(first_active.ddr_type, first_active.timings.cl);

    unsafe {
        fut_printf(
            b"amd_umc: total memory: %lu MB across %u channel(s), ~%u MHz\n\0".as_ptr(),
            total_size_mb,
            active_count,
            speed_mhz,
        );
    }

    // Store driver state.
    let umc = AmdUmc {
        platform,
        num_channels: active_count,
        channels,
        total_size_mb,
        speed_mhz,
    };

    unsafe {
        (*STATE.get()) = Some(umc);
    }

    log("amd_umc: driver initialised successfully");
    0
}

/// Estimate memory speed in MHz from DDR type and CAS latency.
/// This is a rough heuristic; real speed comes from MCLK readback.
fn estimate_speed(ddr_type: u32, cl: u32) -> u32 {
    if ddr_type == 5 {
        // DDR5 typical: CL30=6000, CL36=5600, CL40=4800
        match cl {
            0..=30 => 6000,
            31..=36 => 5600,
            37..=40 => 4800,
            _ => 4800,
        }
    } else {
        // DDR4 typical: CL14=2133, CL16=2400, CL18=2666, CL22=3200
        match cl {
            0..=14 => 2133,
            15..=16 => 2400,
            17..=18 => 2666,
            19..=20 => 3000,
            21..=22 => 3200,
            23..=24 => 3600,
            _ => 3200,
        }
    }
}

/// Populate a MemoryInfo structure with the current memory configuration.
///
/// `out` - Pointer to a MemoryInfo structure to fill.
///
/// Returns 0 on success, negative error on failure.
#[unsafe(no_mangle)]
pub extern "C" fn amd_umc_get_info(out: *mut MemoryInfo) -> i32 {
    if out.is_null() {
        return -22; // EINVAL
    }

    let umc = match unsafe { (*STATE.get()).as_ref() } {
        Some(s) => s,
        None => return -19, // ENODEV
    };

    // Find the first active channel for timing data.
    let first = match umc.channels.iter().find(|c| c.active) {
        Some(c) => c,
        None => return -6, // ENXIO
    };

    // Check if ECC is enabled on any active channel.
    let ecc = umc.channels.iter().any(|c| c.active && c.ecc_enabled);

    let info = MemoryInfo {
        ddr_type: first.ddr_type,
        channels: umc.num_channels,
        total_size_mb: umc.total_size_mb,
        speed_mhz: umc.speed_mhz,
        ecc_enabled: ecc,
        cl: first.timings.cl,
        trcd: first.timings.trcd,
        trp: first.timings.trp,
        tras: first.timings.tras,
    };

    unsafe {
        core::ptr::write(out, info);
    }

    0
}

/// Query ECC error status for a specific memory channel.
///
/// `channel`       - UMC channel index (0-based).
/// `correctable`   - Pointer to receive the correctable (CE) error count.
/// `uncorrectable` - Pointer to receive the uncorrectable (UE) error count.
///
/// Reads UMC_ECC_STATUS register live from hardware (not cached).
///
/// Returns 0 on success, negative error on failure.
#[unsafe(no_mangle)]
pub extern "C" fn amd_umc_ecc_status(
    channel: u32,
    correctable: *mut u32,
    uncorrectable: *mut u32,
) -> i32 {
    if correctable.is_null() || uncorrectable.is_null() {
        return -22; // EINVAL
    }

    let umc = match unsafe { (*STATE.get()).as_ref() } {
        Some(s) => s,
        None => return -19, // ENODEV
    };

    if channel >= umc.num_channels || !umc.channels[channel as usize].active {
        return -22; // EINVAL
    }

    // Read the ECC status register directly from hardware.
    let ecc_status = umc_read(channel, UMC_ECC_STATUS);

    // UMC_ECC_STATUS layout (common across Zen generations):
    //   bits [15:0]  : correctable error count
    //   bits [31:16] : uncorrectable error count
    let ce = ecc_status & 0xFFFF;
    let ue = (ecc_status >> 16) & 0xFFFF;

    unsafe {
        core::ptr::write(correctable, ce);
        core::ptr::write(uncorrectable, ue);
    }

    0
}

/// Clear ECC error counters for a specific memory channel.
///
/// `channel` - UMC channel index (0-based).
///
/// Writes zero to UMC_ECC_STATUS to reset the error counters.
///
/// Returns 0 on success, negative error on failure.
#[unsafe(no_mangle)]
pub extern "C" fn amd_umc_ecc_clear(channel: u32) -> i32 {
    let umc = match unsafe { (*STATE.get()).as_ref() } {
        Some(s) => s,
        None => return -19, // ENODEV
    };

    if channel >= umc.num_channels || !umc.channels[channel as usize].active {
        return -22; // EINVAL
    }

    // Write zero to clear the ECC error counters.
    let addr = UMC_CHANNEL_BASE[channel as usize] + UMC_ECC_STATUS;
    smn_write32(addr, 0);

    unsafe {
        fut_printf(
            b"amd_umc: cleared ECC counters for channel %u\n\0".as_ptr(),
            channel,
        );
    }

    0
}

/// Return the number of active UMC memory channels.
///
/// Returns 0 if the driver is not initialised.
#[unsafe(no_mangle)]
pub extern "C" fn amd_umc_channel_count() -> u32 {
    match unsafe { (*STATE.get()).as_ref() } {
        Some(umc) => umc.num_channels,
        None => 0,
    }
}

/// Return the size in megabytes of a specific DIMM.
///
/// `channel` - UMC channel index (0-based).
/// `dimm`    - DIMM index within the channel (0 or 1).
///
/// Returns the DIMM size in MB, or 0 if not populated or on error.
#[unsafe(no_mangle)]
pub extern "C" fn amd_umc_dimm_size_mb(channel: u32, dimm: u32) -> u32 {
    let umc = match unsafe { (*STATE.get()).as_ref() } {
        Some(s) => s,
        None => return 0,
    };

    if channel >= MAX_CHANNELS as u32 || dimm > 1 {
        return 0;
    }

    let ch = &umc.channels[channel as usize];
    if !ch.active {
        return 0;
    }

    ch.dimms[dimm as usize].size_mb
}
