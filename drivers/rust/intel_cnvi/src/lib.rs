// SPDX-License-Identifier: MPL-2.0
//
// Intel CNVi (Connectivity Integration) WiFi Interface Driver
//
// Supports Intel CNVi-integrated WiFi controllers found in Gen 10+
// (Ice Lake and later) platforms.  CNVi integrates the WiFi/BT MAC
// into the PCH and pairs it with a companion RF module (CRF) on an
// M.2 CNVio or CNVio2 connector.  The WiFi controller appears as a
// standard PCIe device but the RF front-end is provided by the CRF.
//
// This driver handles hardware-level initialisation: PCI discovery,
// MMIO setup, NIC wake, MAC access gating, and hardware identification.
// Actual 802.11 protocol handling is in higher-layer software.
//
// PCI identification (vendor 8086h):
//   A370h  AX201 / WiFi 6 (Ice Lake)
//   2723h  AX200
//   2725h  AX210 / WiFi 6E
//   51F0h  AX211 (Alder Lake)
//   7AF0h  AX211 (Raptor Lake)
//   7E40h  BE200 / WiFi 7 (Meteor Lake)
//
// MMIO register map (BAR0, iwlwifi-compatible CSR):
//   0x000  HW_IF_CONFIG      Hardware Interface Configuration
//   0x004  INT_COALESCING     Interrupt Coalescing
//   0x008  INT_CAUSE          Interrupt Cause Register
//   0x00C  INT_MASK           Interrupt Mask
//   0x020  GP_CNTRL           General Purpose Control
//   0x024  HW_REV             Hardware Revision
//   0x028  HW_REV_STEP        Revision Stepping
//   0x03C  HW_RF_ID           RF Module Identifier
//   0x0A0  UCODE_DRV_GP1      Firmware / uCode status
//   0x100  FH_RSCSR_CHNL0     RX Status Channel 0
//
// GP_CNTRL bit layout:
//   [0]  MAC_ACCESS_REQ    Request NIC internal register access
//   [1]  MAC_CLOCK_READY   MAC clock is stable (read-only)
//   [2]  INIT_DONE         Initialisation complete
//   [5]  MAC_ACCESS_ENA    MAC access window is open (read-only)
//   [7]  NIC_SLEEP         NIC is in low-power sleep state
//
// NIC access protocol:
//   1. Set MAC_ACCESS_REQ in GP_CNTRL
//   2. Poll until MAC_CLOCK_READY is set
//   3. Perform internal/peripheral register accesses
//   4. Clear MAC_ACCESS_REQ when done
//
// Peripheral (PRPH) register access is performed indirectly through
// a pair of MMIO windows:
//   0x448  PRPH_WADDR   Peripheral Write Address
//   0x44C  PRPH_RADDR   Peripheral Read Address
//   0x450  PRPH_WDAT    Peripheral Write Data
//   0x454  PRPH_RDAT    Peripheral Read Data

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(unexpected_cfgs)]
#![allow(dead_code)]

use core::cell::UnsafeCell;
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{fence, Ordering};

use common::{log, map_mmio_region, unmap_mmio_region, MMIO_DEFAULT_FLAGS, thread_yield};

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

// ── PCI identification ──

const INTEL_VENDOR_ID: u16 = 0x8086;

/// Known CNVi WiFi device IDs
const CNVI_DEVICE_IDS: &[u16] = &[
    0xA370, // AX201 / WiFi 6 (Ice Lake)
    0x2723, // AX200
    0x2725, // AX210 / WiFi 6E
    0x51F0, // AX211 (Alder Lake)
    0x7AF0, // AX211 (Raptor Lake)
    0x7E40, // BE200 / WiFi 7 (Meteor Lake)
];

/// PCI class 02h = Network Controller, subclass 80h = Other
const CNVI_CLASS: u8 = 0x02;
const CNVI_SUBCLASS: u8 = 0x80;

// ── MMIO register offsets (iwlwifi-compatible CSR) ──

/// Hardware Interface Configuration
const CSR_HW_IF_CONFIG: usize = 0x000;
/// Interrupt Coalescing
const CSR_INT_COALESCING: usize = 0x004;
/// Interrupt Cause Register
const CSR_INT_CAUSE: usize = 0x008;
/// Interrupt Mask Register
const CSR_INT_MASK: usize = 0x00C;
/// General Purpose Control
const CSR_GP_CNTRL: usize = 0x020;
/// Hardware Revision
const CSR_HW_REV: usize = 0x024;
/// Hardware Revision Stepping
const CSR_HW_REV_STEP: usize = 0x028;
/// RF Module Identifier
const CSR_HW_RF_ID: usize = 0x03C;
/// Firmware / uCode driver GP1
const CSR_UCODE_DRV_GP1: usize = 0x0A0;
/// RX Status Channel 0
const CSR_FH_RSCSR_CHNL0: usize = 0x100;

// ── GP_CNTRL bit definitions ──

/// Request NIC internal register access
const GP_CNTRL_MAC_ACCESS_REQ: u32 = 1 << 0;
/// MAC clock is stable (read-only)
const GP_CNTRL_MAC_CLOCK_READY: u32 = 1 << 1;
/// Initialisation complete
const GP_CNTRL_INIT_DONE: u32 = 1 << 2;
/// MAC access window is open (read-only)
const GP_CNTRL_MAC_ACCESS_ENA: u32 = 1 << 5;
/// NIC is in low-power sleep state
const GP_CNTRL_NIC_SLEEP: u32 = 1 << 7;

// ── Peripheral register access window ──

/// Peripheral write address register
const CSR_PRPH_WADDR: usize = 0x448;
/// Peripheral read address register
const CSR_PRPH_RADDR: usize = 0x44C;
/// Peripheral write data register
const CSR_PRPH_WDAT: usize = 0x450;
/// Peripheral read data register
const CSR_PRPH_RDAT: usize = 0x454;

/// Peripheral address mask (DWORD-aligned, 20-bit address space)
const PRPH_ADDR_MASK: u32 = 0x000F_FFFC;

// ── MMIO size ──

/// CNVi MMIO region size to map (8 KiB covers CSR + FH + PRPH windows)
const CNVI_MMIO_SIZE: usize = 0x2000;

/// Timeout iteration count for polling loops
const CNVI_TIMEOUT_ITERS: u32 = 50_000;

// ── Status bits returned by intel_cnvi_status ──

/// Driver is initialised and ready
const STATUS_INITIALIZED: u32 = 1 << 0;
/// MAC clock is stable
const STATUS_CLOCK_READY: u32 = 1 << 1;
/// NIC is awake (not sleeping)
const STATUS_NIC_AWAKE: u32 = 1 << 2;
/// MAC access window is currently held
const STATUS_MAC_ACCESS: u32 = 1 << 3;
/// Init-done flag is set in GP_CNTRL
const STATUS_INIT_DONE: u32 = 1 << 4;

// ── MMIO helpers ──

#[inline]
fn mmio_read32(base: *mut u8, offset: usize) -> u32 {
    unsafe { read_volatile(base.add(offset) as *const u32) }
}

#[inline]
fn mmio_write32(base: *mut u8, offset: usize, val: u32) {
    unsafe { write_volatile(base.add(offset) as *mut u32, val) }
}

// ── Driver state ──

struct CnviState {
    /// Virtual address of MMIO register base
    base: *mut u8,
    /// Physical address of BAR0
    phys_base: u64,
    /// PCI bus/dev/func of the CNVi device
    bus: u8,
    dev: u8,
    func: u8,
    /// PCI device ID (identifies specific WiFi generation)
    device_id: u16,
    /// Hardware revision (from CSR_HW_REV)
    hw_rev: u32,
    /// RF module identifier (from CSR_HW_RF_ID)
    rf_id: u32,
    /// Whether MAC access is currently held
    mac_access_held: bool,
    /// Whether the driver is initialised
    initialized: bool,
}

impl CnviState {
    const fn new() -> Self {
        Self {
            base: core::ptr::null_mut(),
            phys_base: 0,
            bus: 0,
            dev: 0,
            func: 0,
            device_id: 0,
            hw_rev: 0,
            rf_id: 0,
            mac_access_held: false,
            initialized: false,
        }
    }
}

static CNVI: StaticCell<CnviState> = StaticCell::new(CnviState::new());

// ── Internal helpers ──

/// Scan the PCI device list for an Intel CNVi WiFi controller.
/// Returns (bus, dev, func, device_id) or None.
fn find_cnvi_device() -> Option<(u8, u8, u8, u16)> {
    let count = unsafe { pci_device_count() };
    for i in 0..count {
        let pdev = unsafe { pci_get_device(i) };
        if pdev.is_null() {
            continue;
        }
        let d = unsafe { &*pdev };
        if d.vendor_id == INTEL_VENDOR_ID {
            for &known_id in CNVI_DEVICE_IDS {
                if d.device_id == known_id {
                    return Some((d.bus, d.dev, d.func, d.device_id));
                }
            }
        }
    }
    None
}

/// Read BAR0 from PCI config space.
/// Returns the 64-bit physical base address, or 0 on failure.
fn read_bar0(bus: u8, dev: u8, func: u8) -> u64 {
    let bar0_lo = pci_read32(bus, dev, func, 0x10);

    // Verify this is an MMIO BAR (bit 0 = 0 means memory space)
    if bar0_lo & 0x01 != 0 {
        return 0;
    }

    let is_64bit = (bar0_lo & 0x06) == 0x04;
    let phys_lo = bar0_lo & !0xF;
    let phys_hi = if is_64bit {
        pci_read32(bus, dev, func, 0x14)
    } else {
        0
    };
    let phys = (phys_lo as u64) | ((phys_hi as u64) << 32);

    if phys == 0 {
        return 0;
    }
    phys
}

/// Wake the NIC from sleep by clearing NIC_SLEEP and setting
/// MAC_ACCESS_REQ, then waiting for MAC_CLOCK_READY.
/// Returns true on success, false on timeout.
fn nic_wake(base: *mut u8) -> bool {
    let gp = mmio_read32(base, CSR_GP_CNTRL);

    // If NIC is sleeping, we need to clear the sleep bit first
    if gp & GP_CNTRL_NIC_SLEEP != 0 {
        // Clear NIC_SLEEP by writing 1 to bit 7 (write-1-to-clear)
        mmio_write32(base, CSR_GP_CNTRL, gp | GP_CNTRL_NIC_SLEEP);
        fence(Ordering::SeqCst);
    }

    // Request MAC access
    let gp = mmio_read32(base, CSR_GP_CNTRL);
    mmio_write32(base, CSR_GP_CNTRL, gp | GP_CNTRL_MAC_ACCESS_REQ);
    fence(Ordering::SeqCst);

    // Poll for MAC_CLOCK_READY
    for _ in 0..CNVI_TIMEOUT_ITERS {
        let val = mmio_read32(base, CSR_GP_CNTRL);
        if val & GP_CNTRL_MAC_CLOCK_READY != 0 {
            return true;
        }
        thread_yield();
    }

    false
}

/// Disable all interrupts (we operate in polling mode).
fn disable_interrupts(base: *mut u8) {
    // Clear any pending interrupt causes
    mmio_write32(base, CSR_INT_CAUSE, 0xFFFF_FFFF);
    // Mask all interrupts
    mmio_write32(base, CSR_INT_MASK, 0x0000_0000);
    fence(Ordering::SeqCst);
}

/// Return the WiFi generation name for a given device ID.
fn device_name(device_id: u16) -> &'static [u8] {
    match device_id {
        0xA370 => b"AX201 (ICL WiFi6)\0",
        0x2723 => b"AX200\0",
        0x2725 => b"AX210 (WiFi6E)\0",
        0x51F0 => b"AX211 (ADL)\0",
        0x7AF0 => b"AX211 (RPL)\0",
        0x7E40 => b"BE200 (MTL WiFi7)\0",
        _      => b"unknown\0",
    }
}

// ── FFI exports ──

/// Initialise the Intel CNVi WiFi interface driver.
///
/// Scans PCI for an Intel CNVi WiFi controller, maps BAR0 MMIO,
/// wakes the NIC, reads hardware revision and RF module ID, and
/// disables interrupts (polling mode).
///
/// Returns 0 on success, negative on error:
///   -1 = CNVi device not found in PCI device list
///   -2 = BAR0 is I/O space, not MMIO
///   -3 = BAR0 not configured (zero physical address)
///   -4 = failed to map MMIO region
///   -5 = NIC wake timeout (MAC clock did not stabilise)
#[unsafe(no_mangle)]
pub extern "C" fn intel_cnvi_init() -> i32 {
    log("intel_cnvi: initializing CNVi WiFi driver");

    // Scan for Intel CNVi PCI device
    let (bus, dev, func, device_id) = match find_cnvi_device() {
        Some(info) => info,
        None => {
            log("intel_cnvi: no Intel CNVi WiFi device found");
            return -1;
        }
    };

    unsafe {
        fut_printf(
            b"intel_cnvi: found %s [%04x:%04x] at PCI %02x:%02x.%x\n\0".as_ptr(),
            device_name(device_id).as_ptr(),
            INTEL_VENDOR_ID as u32, device_id as u32,
            bus as u32, dev as u32, func as u32,
        );
    }

    // Enable bus-master and memory space access in PCI command register
    let pci_cmd = pci_read16(bus, dev, func, 0x04);
    pci_write16(bus, dev, func, 0x04, pci_cmd | 0x06); // Memory Space + Bus Master

    // Read BAR0
    let bar0_lo = pci_read32(bus, dev, func, 0x10);
    if bar0_lo & 0x01 != 0 {
        log("intel_cnvi: BAR0 is I/O space, expected MMIO");
        return -2;
    }

    let bar_phys = read_bar0(bus, dev, func);
    if bar_phys == 0 {
        log("intel_cnvi: BAR0 not configured");
        return -3;
    }

    unsafe {
        fut_printf(
            b"intel_cnvi: MMIO BAR0 at physical 0x%llx\n\0".as_ptr(),
            bar_phys,
        );
    }

    // Map CNVi MMIO region
    let mmio = unsafe { map_mmio_region(bar_phys, CNVI_MMIO_SIZE, MMIO_DEFAULT_FLAGS) };
    if mmio.is_null() {
        log("intel_cnvi: failed to map MMIO region");
        return -4;
    }

    // Disable interrupts before doing anything else
    disable_interrupts(mmio);

    // Wake NIC from sleep and establish MAC clock
    if !nic_wake(mmio) {
        log("intel_cnvi: NIC wake timeout - MAC clock not ready");
        unsafe { unmap_mmio_region(mmio, CNVI_MMIO_SIZE); }
        return -5;
    }
    log("intel_cnvi: NIC awake, MAC clock stable");

    // Read hardware identification registers
    let hw_rev = mmio_read32(mmio, CSR_HW_REV);
    let hw_step = mmio_read32(mmio, CSR_HW_REV_STEP);
    let rf_id = mmio_read32(mmio, CSR_HW_RF_ID);
    let hw_if_cfg = mmio_read32(mmio, CSR_HW_IF_CONFIG);

    unsafe {
        fut_printf(
            b"intel_cnvi: HW_REV=0x%08x STEP=0x%08x RF_ID=0x%08x HW_IF=0x%08x\n\0".as_ptr(),
            hw_rev, hw_step, rf_id, hw_if_cfg,
        );
    }

    // Read GP_CNTRL for initial diagnostics
    let gp = mmio_read32(mmio, CSR_GP_CNTRL);
    unsafe {
        fut_printf(
            b"intel_cnvi: GP_CNTRL=0x%08x\n\0".as_ptr(),
            gp,
        );
    }

    // Release MAC access after identification reads
    let gp_rel = mmio_read32(mmio, CSR_GP_CNTRL);
    mmio_write32(mmio, CSR_GP_CNTRL, gp_rel & !GP_CNTRL_MAC_ACCESS_REQ);
    fence(Ordering::SeqCst);

    // Signal init-done
    let gp_done = mmio_read32(mmio, CSR_GP_CNTRL);
    mmio_write32(mmio, CSR_GP_CNTRL, gp_done | GP_CNTRL_INIT_DONE);
    fence(Ordering::SeqCst);

    // Store driver state
    let state = CNVI.get();
    unsafe {
        (*state).base = mmio;
        (*state).phys_base = bar_phys;
        (*state).bus = bus;
        (*state).dev = dev;
        (*state).func = func;
        (*state).device_id = device_id;
        (*state).hw_rev = hw_rev;
        (*state).rf_id = rf_id;
        (*state).mac_access_held = false;
        fence(Ordering::SeqCst);
        (*state).initialized = true;
    }

    log("intel_cnvi: driver ready");
    0
}

/// Return the hardware revision register value.
/// Returns 0 if the driver is not initialised.
#[unsafe(no_mangle)]
pub extern "C" fn intel_cnvi_hw_rev() -> u32 {
    let state = CNVI.get();
    unsafe {
        if !(*state).initialized {
            return 0;
        }
        (*state).hw_rev
    }
}

/// Return the RF module identifier register value.
/// Returns 0 if the driver is not initialised.
#[unsafe(no_mangle)]
pub extern "C" fn intel_cnvi_rf_id() -> u32 {
    let state = CNVI.get();
    unsafe {
        if !(*state).initialized {
            return 0;
        }
        (*state).rf_id
    }
}

/// Return true if an Intel CNVi WiFi device was found and initialised.
#[unsafe(no_mangle)]
pub extern "C" fn intel_cnvi_is_present() -> bool {
    let state = CNVI.get();
    unsafe { (*state).initialized }
}

/// Acquire MAC access (NIC internal register access window).
///
/// Sets MAC_ACCESS_REQ and polls for MAC_CLOCK_READY.  Must be paired
/// with `intel_cnvi_mac_access_release()`.
///
/// Returns 0 on success, -1 if not initialised, -2 on timeout.
#[unsafe(no_mangle)]
pub extern "C" fn intel_cnvi_mac_access_acquire() -> i32 {
    let state = CNVI.get();
    let base = unsafe { (*state).base };
    if unsafe { !(*state).initialized } || base.is_null() {
        return -1;
    }

    // Request MAC access
    let gp = mmio_read32(base, CSR_GP_CNTRL);
    mmio_write32(base, CSR_GP_CNTRL, gp | GP_CNTRL_MAC_ACCESS_REQ);
    fence(Ordering::SeqCst);

    // Poll for MAC_CLOCK_READY
    for _ in 0..CNVI_TIMEOUT_ITERS {
        let val = mmio_read32(base, CSR_GP_CNTRL);
        if val & GP_CNTRL_MAC_CLOCK_READY != 0 {
            unsafe { (*state).mac_access_held = true; }
            return 0;
        }
        thread_yield();
    }

    // Timeout - clear the request
    let gp = mmio_read32(base, CSR_GP_CNTRL);
    mmio_write32(base, CSR_GP_CNTRL, gp & !GP_CNTRL_MAC_ACCESS_REQ);
    -2
}

/// Release MAC access (clear MAC_ACCESS_REQ in GP_CNTRL).
#[unsafe(no_mangle)]
pub extern "C" fn intel_cnvi_mac_access_release() {
    let state = CNVI.get();
    let base = unsafe { (*state).base };
    if unsafe { !(*state).initialized } || base.is_null() {
        return;
    }

    let gp = mmio_read32(base, CSR_GP_CNTRL);
    mmio_write32(base, CSR_GP_CNTRL, gp & !GP_CNTRL_MAC_ACCESS_REQ);
    fence(Ordering::SeqCst);

    unsafe { (*state).mac_access_held = false; }
}

/// Read a peripheral (PRPH) register via the indirect access window.
///
/// The caller must hold MAC access (via `intel_cnvi_mac_access_acquire`)
/// before calling this function.  The address is masked to a 20-bit
/// DWORD-aligned value.
///
/// Returns the register value, or 0xFFFFFFFF on error.
#[unsafe(no_mangle)]
pub extern "C" fn intel_cnvi_read_prph(addr: u32) -> u32 {
    let state = CNVI.get();
    let base = unsafe { (*state).base };
    if unsafe { !(*state).initialized } || base.is_null() {
        return 0xFFFF_FFFF;
    }

    // Set the peripheral read address (DWORD-aligned)
    let prph_addr = addr & PRPH_ADDR_MASK;
    mmio_write32(base, CSR_PRPH_RADDR, prph_addr);
    fence(Ordering::SeqCst);

    // Read the data register
    mmio_read32(base, CSR_PRPH_RDAT)
}

/// Return a status bitmask describing the current CNVi hardware state.
///
/// Bit 0: driver initialised
/// Bit 1: MAC clock ready
/// Bit 2: NIC awake (not sleeping)
/// Bit 3: MAC access currently held
/// Bit 4: init-done flag set
#[unsafe(no_mangle)]
pub extern "C" fn intel_cnvi_status() -> u32 {
    let state = CNVI.get();
    if unsafe { !(*state).initialized } {
        return 0;
    }

    let base = unsafe { (*state).base };
    if base.is_null() {
        return 0;
    }

    let gp = mmio_read32(base, CSR_GP_CNTRL);
    let mut status: u32 = STATUS_INITIALIZED;

    if gp & GP_CNTRL_MAC_CLOCK_READY != 0 {
        status |= STATUS_CLOCK_READY;
    }
    if gp & GP_CNTRL_NIC_SLEEP == 0 {
        status |= STATUS_NIC_AWAKE;
    }
    if unsafe { (*state).mac_access_held } {
        status |= STATUS_MAC_ACCESS;
    }
    if gp & GP_CNTRL_INIT_DONE != 0 {
        status |= STATUS_INIT_DONE;
    }

    status
}
