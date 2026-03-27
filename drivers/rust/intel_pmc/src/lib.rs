// SPDX-License-Identifier: MPL-2.0
//
// Intel PMC (Power Management Controller) Driver for Futura OS
//
// Provides access to the PCH-embedded Power Management Controller on
// Intel Gen 10+ (Ice Lake and later) platforms. The PMC is not exposed
// as a standard PCI function; instead its MMIO register block is
// discovered via the PWRMBASE register (offset 0x48) in the PCH
// LPC/eSPI bridge at PCI 00:1F.0.
//
// Capabilities:
//   - S-state transition status (S0ix / S3 / S4 / S5)
//   - SLP_S0 (Modern Standby) residency counter
//   - Package C-state residency counters via MSRs (C2-C10)
//   - PCH IP power gating status
//   - Low Power Mode (LPM) sub-state status
//   - Raw PMC MMIO register read access
//
// PMC MMIO register map (offsets from PWRMBASE):
//   0x0000  PM_CFG           PM Configuration
//   0x0004  PM_CFG2          PM Configuration 2
//   0x0018  PRSTS            Power and Reset Status
//   0x001C  PM_CFG3          PM Configuration 3
//   0x0020  PM_CFG4          PM Configuration 4
//   0x0024  S3_PWRGATE_POL   S3 Power Gating Policy
//   0x0028  S4_PWRGATE_POL   S4 Power Gating Policy
//   0x002C  S5_PWRGATE_POL   S5 Power Gating Policy
//   0x00A0  SLP_S0_RES       SLP_S0 Residency Counter (32-bit, 32us units)
//   0x0630  LPM_EN           Low Power Mode Enable
//   0x0640  LPM_PRI          LPM Priority
//   0x0660  LPM_STS          LPM Status
//   0x1048  PKC_STS          Package C-state Status
//   0x1050  MPHY_CORE_STS    MPHY Core Power Status
//   0x10A0  LTR_IGN          LTR Ignore
//   0x10D0  CORE_PWRGATE_STS Core Power Gate Status
//
// Package C-state MSRs:
//   0x3F8  PKG_C2_RESIDENCY
//   0x3F9  PKG_C3_RESIDENCY
//   0x3FA  PKG_C6_RESIDENCY
//   0x3FC  PKG_C7_RESIDENCY
//   0x630  PKG_C8_RESIDENCY
//   0x631  PKG_C9_RESIDENCY
//   0x632  PKG_C10_RESIDENCY

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(unexpected_cfgs)]

use core::cell::UnsafeCell;
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{fence, Ordering};

use common::{log, map_mmio_region, unmap_mmio_region, MMIO_DEFAULT_FLAGS};

// ── FFI imports ──

unsafe extern "C" {
    fn fut_printf(fmt: *const u8, ...);
    fn pci_device_count() -> i32;
    fn pci_get_device(index: i32) -> *const PciDevice;
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

// ── StaticCell wrapper (avoids `static mut`) ──

/// Wrapper to allow `UnsafeCell` in a `static` (requires `Sync`).
/// Safety: all access is single-threaded or externally synchronised by the caller.
struct StaticCell<T>(UnsafeCell<T>);
unsafe impl<T> Sync for StaticCell<T> {}
impl<T> StaticCell<T> {
    const fn new(v: T) -> Self { Self(UnsafeCell::new(v)) }
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

// ── LPC/eSPI bridge identification ──

/// PCI bus/device/function for the PCH LPC/eSPI bridge
const LPC_BUS: u8 = 0x00;
const LPC_DEV: u8 = 0x1F;
const LPC_FUNC: u8 = 0x00;

/// Config space offset of PWRMBASE (Power Management Base Address)
const PWRMBASE_OFFSET: u8 = 0x48;

/// PWRMBASE is a 32-bit BAR; bits [31:12] hold the base address
const PWRMBASE_MASK: u32 = 0xFFFF_F000;

/// Size of the PMC MMIO region to map (8 KiB covers all known registers)
const PMC_MMIO_SIZE: usize = 0x2000;

// ── PMC MMIO register offsets ──

/// PM Configuration
const PM_CFG: usize = 0x0000;
/// PM Configuration 2
const PM_CFG2: usize = 0x0004;
/// Power and Reset Status (SLP_S3/S4/S5 status bits)
const PRSTS: usize = 0x0018;
/// PM Configuration 3
const PM_CFG3: usize = 0x001C;
/// PM Configuration 4
const PM_CFG4: usize = 0x0020;
/// S3 Power Gating Policy
const S3_PWRGATE_POL: usize = 0x0024;
/// S4 Power Gating Policy
const S4_PWRGATE_POL: usize = 0x0028;
/// S5 Power Gating Policy
const S5_PWRGATE_POL: usize = 0x002C;
/// SLP_S0 Residency Counter (32-bit, units of 32 microseconds)
const SLP_S0_RES: usize = 0x00A0;
/// Low Power Mode Enable
const LPM_EN: usize = 0x0630;
/// LPM Priority
const LPM_PRI: usize = 0x0640;
/// LPM Status (which sub-states have been entered)
const LPM_STS: usize = 0x0660;
/// Package C-state Status
const PKC_STS: usize = 0x1048;
/// MPHY Core Power Status
const MPHY_CORE_STS: usize = 0x1050;
/// LTR Ignore
const LTR_IGN: usize = 0x10A0;
/// Core Power Gate Status
const CORE_PWRGATE_STS: usize = 0x10D0;

/// SLP_S0 residency counter resolution: each tick = 32 microseconds
const SLP_S0_RES_TICK_US: u64 = 32;

// ── PRSTS register bits ──

/// SLP_S3# assertion status
const PRSTS_SLP_S3_STS: u32 = 1 << 4;
/// SLP_S4# assertion status
const PRSTS_SLP_S4_STS: u32 = 1 << 5;
/// SLP_S5# assertion status (exact bit position varies; common is bit 6)
const PRSTS_SLP_S5_STS: u32 = 1 << 6;

// ── PM_CFG register bits for S0ix capability ──

/// S0ix enable bit in PM_CFG
const PM_CFG_SLP_S0_EN: u32 = 1 << 28;

// ── Package C-state residency MSRs ──

const MSR_PKG_C2_RESIDENCY: u32 = 0x3F8;
const MSR_PKG_C3_RESIDENCY: u32 = 0x3F9;
const MSR_PKG_C6_RESIDENCY: u32 = 0x3FA;
const MSR_PKG_C7_RESIDENCY: u32 = 0x3FC;
const MSR_PKG_C8_RESIDENCY: u32 = 0x630;
const MSR_PKG_C9_RESIDENCY: u32 = 0x631;
const MSR_PKG_C10_RESIDENCY: u32 = 0x632;

// ── Inline assembly helpers ──

/// Read a Model Specific Register (MSR) via RDMSR.
/// Returns the 64-bit value (EDX:EAX).
#[inline]
fn rdmsr(msr: u32) -> u64 {
    let lo: u32;
    let hi: u32;
    unsafe {
        core::arch::asm!(
            "rdmsr",
            in("ecx") msr,
            out("eax") lo,
            out("edx") hi,
            options(nomem, nostack, preserves_flags),
        );
    }
    ((hi as u64) << 32) | (lo as u64)
}

// ── MMIO helpers ──

#[inline]
fn mmio_read32(base: *mut u8, offset: usize) -> u32 {
    unsafe { read_volatile(base.add(offset) as *const u32) }
}

#[inline]
#[allow(dead_code)]
fn mmio_write32(base: *mut u8, offset: usize, val: u32) {
    unsafe { write_volatile(base.add(offset) as *mut u32, val) }
}

// ── Driver state ──

struct PmcState {
    /// Virtual address of the PMC MMIO register base
    base: *mut u8,
    /// Physical address of PWRMBASE
    phys_base: u64,
    /// Whether the driver has been initialized
    initialized: bool,
}

impl PmcState {
    const fn new() -> Self {
        Self {
            base: core::ptr::null_mut(),
            phys_base: 0,
            initialized: false,
        }
    }
}

static PMC: StaticCell<PmcState> = StaticCell::new(PmcState::new());

// ── Internal helpers ──

/// Locate the PCH LPC/eSPI bridge (00:1F.0) in the kernel PCI device list.
/// Returns true if found (confirming the bridge is enumerated).
fn find_lpc_bridge() -> bool {
    let count = unsafe { pci_device_count() };
    for i in 0..count {
        let dev = unsafe { pci_get_device(i) };
        if dev.is_null() {
            continue;
        }
        let d = unsafe { &*dev };
        if d.bus == LPC_BUS && d.dev == LPC_DEV && d.func == LPC_FUNC {
            return true;
        }
    }
    false
}

/// Read PWRMBASE from the LPC bridge PCI config space.
/// Returns the physical base address of the PMC MMIO region, or 0 on failure.
fn read_pwrmbase() -> u64 {
    let raw = pci_read32(LPC_BUS, LPC_DEV, LPC_FUNC, PWRMBASE_OFFSET);
    let base = raw & PWRMBASE_MASK;
    if base == 0 || base == PWRMBASE_MASK {
        return 0;
    }
    base as u64
}

/// Map the MSR C-state index (2, 3, 6, 7, 8, 9, 10) to the corresponding MSR address.
/// Returns 0 if the C-state index is not valid.
fn cstate_to_msr(cstate: u32) -> u32 {
    match cstate {
        2 => MSR_PKG_C2_RESIDENCY,
        3 => MSR_PKG_C3_RESIDENCY,
        6 => MSR_PKG_C6_RESIDENCY,
        7 => MSR_PKG_C7_RESIDENCY,
        8 => MSR_PKG_C8_RESIDENCY,
        9 => MSR_PKG_C9_RESIDENCY,
        10 => MSR_PKG_C10_RESIDENCY,
        _ => 0,
    }
}

// ── FFI exports ──

/// Initialize the Intel PMC driver.
///
/// Discovers PWRMBASE from the PCH LPC/eSPI bridge (00:1F.0) config space
/// and maps the PMC MMIO register block.
///
/// Returns 0 on success, negative on error:
///   -1 = LPC bridge not found in PCI device list
///   -2 = PWRMBASE register reads as zero or invalid
///   -3 = failed to map PMC MMIO region
#[unsafe(no_mangle)]
pub extern "C" fn intel_pmc_init() -> i32 {
    log("intel_pmc: initializing PMC driver");

    // Verify the LPC/eSPI bridge is enumerated
    if !find_lpc_bridge() {
        log("intel_pmc: LPC/eSPI bridge (00:1F.0) not found");
        return -1;
    }

    // Read PWRMBASE from LPC bridge config space offset 0x48
    let pwrmbase = read_pwrmbase();
    if pwrmbase == 0 {
        log("intel_pmc: PWRMBASE is zero or invalid");
        return -2;
    }

    unsafe {
        fut_printf(
            b"intel_pmc: PWRMBASE = 0x%08llx\n\0".as_ptr(),
            pwrmbase,
        );
    }

    // Map the PMC MMIO region
    let base = unsafe { map_mmio_region(pwrmbase, PMC_MMIO_SIZE, MMIO_DEFAULT_FLAGS) };
    if base.is_null() {
        log("intel_pmc: failed to map PMC MMIO region");
        return -3;
    }

    // Read initial register values for diagnostics
    let pm_cfg = mmio_read32(base, PM_CFG);
    let prsts = mmio_read32(base, PRSTS);
    let slp_s0_res = mmio_read32(base, SLP_S0_RES);
    let lpm_en = mmio_read32(base, LPM_EN);
    let lpm_sts = mmio_read32(base, LPM_STS);
    let pkc_sts = mmio_read32(base, PKC_STS);
    let s0ix_capable = (pm_cfg & PM_CFG_SLP_S0_EN) != 0;

    // Store state
    let state = PMC.get();
    unsafe {
        (*state).base = base;
        (*state).phys_base = pwrmbase;
        fence(Ordering::SeqCst);
        (*state).initialized = true;
    }

    // Log initial status
    unsafe {
        fut_printf(
            b"intel_pmc: PM_CFG=0x%08x PRSTS=0x%08x S0ix=%s\n\0".as_ptr(),
            pm_cfg,
            prsts,
            if s0ix_capable { b"enabled\0".as_ptr() } else { b"disabled\0".as_ptr() },
        );
        fut_printf(
            b"intel_pmc: SLP_S0_RES=%u (raw ticks, x32us) LPM_EN=0x%08x\n\0".as_ptr(),
            slp_s0_res,
            lpm_en,
        );
        fut_printf(
            b"intel_pmc: LPM_STS=0x%08x PKC_STS=0x%08x\n\0".as_ptr(),
            lpm_sts,
            pkc_sts,
        );
    }

    // Log sleep state assertions from PRSTS
    if prsts & PRSTS_SLP_S3_STS != 0 {
        log("intel_pmc: SLP_S3# previously asserted");
    }
    if prsts & PRSTS_SLP_S4_STS != 0 {
        log("intel_pmc: SLP_S4# previously asserted");
    }
    if prsts & PRSTS_SLP_S5_STS != 0 {
        log("intel_pmc: SLP_S5# previously asserted");
    }

    // Log package C-state residency counters
    unsafe {
        let c2 = rdmsr(MSR_PKG_C2_RESIDENCY);
        let c3 = rdmsr(MSR_PKG_C3_RESIDENCY);
        let c6 = rdmsr(MSR_PKG_C6_RESIDENCY);
        let c7 = rdmsr(MSR_PKG_C7_RESIDENCY);
        fut_printf(
            b"intel_pmc: PKG_C2=%llu PKG_C3=%llu PKG_C6=%llu PKG_C7=%llu\n\0".as_ptr(),
            c2, c3, c6, c7,
        );
        let c8 = rdmsr(MSR_PKG_C8_RESIDENCY);
        let c9 = rdmsr(MSR_PKG_C9_RESIDENCY);
        let c10 = rdmsr(MSR_PKG_C10_RESIDENCY);
        fut_printf(
            b"intel_pmc: PKG_C8=%llu PKG_C9=%llu PKG_C10=%llu\n\0".as_ptr(),
            c8, c9, c10,
        );
    }

    log("intel_pmc: driver initialized");
    0
}

/// Read the SLP_S0 (Modern Standby) residency counter.
///
/// The hardware counter increments in units of 32 microseconds. This
/// function returns the total residency converted to microseconds.
///
/// Returns 0 if the driver is not initialized.
#[unsafe(no_mangle)]
pub extern "C" fn intel_pmc_slp_s0_residency() -> u64 {
    let state = PMC.get();
    unsafe {
        if !(*state).initialized {
            return 0;
        }
        let raw = mmio_read32((*state).base, SLP_S0_RES) as u64;
        raw * SLP_S0_RES_TICK_US
    }
}

/// Read the package C-state residency counter for the specified C-state.
///
/// Valid `cstate` values: 2, 3, 6, 7, 8, 9, 10.
/// The returned value is in TSC ticks (platform-dependent units).
///
/// Returns 0 if the driver is not initialized or the C-state is invalid.
#[unsafe(no_mangle)]
pub extern "C" fn intel_pmc_pkg_cstate_residency(cstate: u32) -> u64 {
    let state = PMC.get();
    unsafe {
        if !(*state).initialized {
            return 0;
        }
    }
    let msr = cstate_to_msr(cstate);
    if msr == 0 {
        return 0;
    }
    rdmsr(msr)
}

/// Read the Power and Reset Status register (PRSTS).
///
/// Contains SLP_S3/S4/S5 assertion status and other power state
/// information. See PRSTS bit definitions for interpretation.
///
/// Returns 0 if the driver is not initialized.
#[unsafe(no_mangle)]
pub extern "C" fn intel_pmc_power_status() -> u32 {
    let state = PMC.get();
    unsafe {
        if !(*state).initialized {
            return 0;
        }
        mmio_read32((*state).base, PRSTS)
    }
}

/// Read the Low Power Mode Status register (LPM_STS).
///
/// Indicates which LPM sub-states (S0i1, S0i2, S0i3) have been entered.
///
/// Returns 0 if the driver is not initialized.
#[unsafe(no_mangle)]
pub extern "C" fn intel_pmc_lpm_status() -> u32 {
    let state = PMC.get();
    unsafe {
        if !(*state).initialized {
            return 0;
        }
        mmio_read32((*state).base, LPM_STS)
    }
}

/// Check whether the platform supports S0ix (Modern Standby).
///
/// Reads PM_CFG bit 28 (SLP_S0_EN) which indicates whether the PCH
/// has been configured for S0ix entry.
///
/// Returns false if the driver is not initialized.
#[unsafe(no_mangle)]
pub extern "C" fn intel_pmc_is_s0ix_capable() -> bool {
    let state = PMC.get();
    unsafe {
        if !(*state).initialized {
            return false;
        }
        let pm_cfg = mmio_read32((*state).base, PM_CFG);
        (pm_cfg & PM_CFG_SLP_S0_EN) != 0
    }
}

/// Read a raw 32-bit PMC MMIO register at the given offset from PWRMBASE.
///
/// The caller is responsible for ensuring the offset is valid and
/// within the mapped region. Offsets must be 4-byte aligned.
///
/// Returns 0 if the driver is not initialized or the offset exceeds
/// the mapped region.
#[unsafe(no_mangle)]
pub extern "C" fn intel_pmc_read_reg(offset: u32) -> u32 {
    let state = PMC.get();
    unsafe {
        if !(*state).initialized {
            return 0;
        }
        let off = offset as usize;
        if off + 4 > PMC_MMIO_SIZE {
            return 0;
        }
        mmio_read32((*state).base, off)
    }
}
