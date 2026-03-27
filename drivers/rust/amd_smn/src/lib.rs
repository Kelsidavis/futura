// SPDX-License-Identifier: MPL-2.0
//
// AMD SMN (System Management Network) Bus Driver for Futura OS
//
// The SMN is an internal interconnect on AMD Ryzen (Zen-based) processors
// used to access on-die registers for subsystems such as:
//   - UMC (Unified Memory Controller) channels
//   - Data Fabric (DF) registers
//   - NBIO (NorthBridge I/O) registers
//   - USB controller internal registers
//   - CCX (Core Complex) configuration
//
// Architecture:
//   - SMN is accessed indirectly through PCI device 00:00.0 (AMD Root Complex)
//   - Write target SMN address to PCI config offset 0x60 (SMN_ADDR)
//   - Read/write data at PCI config offset 0x64 (SMN_DATA)
//   - Multi-die/multi-socket systems use indexed access via different
//     PCI functions on the root complex (function = node index)
//
// Common SMN address ranges:
//   0x0005_0000 - 0x0005_0FFF : UMC channel 0
//   0x0015_0000 - 0x0015_0FFF : UMC channel 1
//   0x1800_0000+              : Data Fabric registers
//   0x13B1_0000+              : USB controller internal registers
//   0x0380_0000+              : NBIO (NorthBridge I/O)
//
// PCI identification: vendor 1022h (AMD), device 1480h/1630h/14B5h/1730h
// (varies by Zen generation), class 06h subclass 00h (Host Bridge).

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

// ── SMN register offsets in PCI config space ──

/// PCI config offset for the SMN target address register.
const SMN_ADDR_OFFSET: u8 = 0x60;
/// PCI config offset for the SMN data register.
const SMN_DATA_OFFSET: u8 = 0x64;

// ── Common SMN address ranges ──

/// UMC (Unified Memory Controller) channel 0 base.
const SMN_UMC_CH0_BASE: u32 = 0x0005_0000;
/// UMC channel 0 end (inclusive).
const SMN_UMC_CH0_END: u32 = 0x0005_0FFF;
/// UMC channel 1 base.
const SMN_UMC_CH1_BASE: u32 = 0x0015_0000;
/// UMC channel 1 end (inclusive).
const SMN_UMC_CH1_END: u32 = 0x0015_0FFF;
/// Data Fabric register base.
const SMN_DF_BASE: u32 = 0x1800_0000;
/// USB controller internal register base.
const SMN_USB_BASE: u32 = 0x13B1_0000;
/// NBIO (NorthBridge I/O) register base.
const SMN_NBIO_BASE: u32 = 0x0380_0000;

// ── Driver state ──

struct AmdSmn {
    /// PCI bus/device/function of the AMD Root Complex.
    bus: u8,
    dev: u8,
    func: u8,
    /// Root Complex device ID (identifies Zen generation).
    device_id: u16,
    /// Whether the driver is initialised.
    initialized: bool,
}

impl AmdSmn {
    const fn new() -> Self {
        Self {
            bus: 0,
            dev: 0,
            func: 0,
            device_id: 0,
            initialized: false,
        }
    }
}

static STATE: StaticCell<AmdSmn> = StaticCell::new(AmdSmn::new());

// ── SMN core access ──

/// Write an SMN address and read back the 32-bit data register.
///
/// This is the fundamental SMN read operation:
///   1. Write the target SMN address to PCI config offset 0x60
///   2. Read the result from PCI config offset 0x64
fn smn_read32_bdf(bus: u8, dev: u8, func: u8, addr: u32) -> u32 {
    pci_write32(bus, dev, func, SMN_ADDR_OFFSET, addr);
    pci_read32(bus, dev, func, SMN_DATA_OFFSET)
}

/// Write a 32-bit value to an SMN address.
///
///   1. Write the target SMN address to PCI config offset 0x60
///   2. Write the data to PCI config offset 0x64
fn smn_write32_bdf(bus: u8, dev: u8, func: u8, addr: u32, val: u32) {
    pci_write32(bus, dev, func, SMN_ADDR_OFFSET, addr);
    pci_write32(bus, dev, func, SMN_DATA_OFFSET, val);
}

// ── PCI discovery ──

/// Check whether a device ID is a known AMD Root Complex.
fn is_amd_root_complex(device_id: u16) -> bool {
    matches!(
        device_id,
        AMD_RC_ZEN1 | AMD_RC_ZEN2 | AMD_RC_ZEN3 | AMD_RC_ZEN4 | AMD_RC_ZEN5
    )
}

/// Probe PCI 00:00.0 for the AMD Root Complex.
/// The root complex is always at bus 0, device 0, function 0 on AMD platforms.
/// Returns (device_id) if found, or None.
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

/// Verify SMN access by reading a known register.
/// The Data Fabric instance count register at SMN 0x18000044 should return
/// a nonzero value on any Zen-based system.
fn verify_smn_access(bus: u8, dev: u8, func: u8) -> bool {
    // Read DF SystemCfg (SMN 0x18000200) — should not be 0xFFFFFFFF.
    let val = smn_read32_bdf(bus, dev, func, 0x1800_0200);
    val != 0xFFFF_FFFF && val != 0x0000_0000
}

// ── FFI exports ──

/// Initialise the AMD SMN bus driver.
///
/// Probes PCI 00:00.0 for the AMD Root Complex, verifies SMN access,
/// and stores driver state for subsequent read/write operations.
///
/// Returns 0 on success, negative error on failure.
#[unsafe(no_mangle)]
pub extern "C" fn amd_smn_init() -> i32 {
    log("amd_smn: scanning for AMD Root Complex at PCI 00:00.0...");

    let device_id = match find_amd_root_complex() {
        Some(id) => id,
        None => {
            log("amd_smn: no AMD Root Complex found at PCI 00:00.0");
            return -1;
        }
    };

    let gen_name = zen_generation_name(device_id);
    unsafe {
        fut_printf(
            b"amd_smn: found AMD Root Complex (device %04x) - %s\n\0".as_ptr(),
            device_id as u32,
            gen_name.as_ptr(),
        );
    }

    // The Root Complex is always at 00:00.0.
    let bus: u8 = 0;
    let dev: u8 = 0;
    let func: u8 = 0;

    // Verify that SMN access is functional by reading a known DF register.
    if !verify_smn_access(bus, dev, func) {
        log("amd_smn: SMN access verification failed (DF SystemCfg returned invalid value)");
        return -2;
    }

    log("amd_smn: SMN access verified via Data Fabric SystemCfg register");

    // Read and display some useful DF information.
    let df_syscfg = smn_read32_bdf(bus, dev, func, 0x1800_0200);
    unsafe {
        fut_printf(
            b"amd_smn: DF SystemCfg = 0x%08x\n\0".as_ptr(),
            df_syscfg,
        );
    }

    // Store driver state.
    let st = unsafe { &mut *STATE.get() };
    st.bus = bus;
    st.dev = dev;
    st.func = func;
    st.device_id = device_id;
    st.initialized = true;

    log("amd_smn: driver initialised successfully");
    0
}

/// Read a 32-bit value from an SMN address.
///
/// `addr` - SMN address to read (e.g. 0x00050000 for UMC channel 0).
///
/// Returns the 32-bit value at the given SMN address.
/// Returns 0xFFFFFFFF if the driver is not initialised.
#[unsafe(no_mangle)]
pub extern "C" fn amd_smn_read32(addr: u32) -> u32 {
    let st = unsafe { &*STATE.get() };
    if !st.initialized {
        return 0xFFFF_FFFF;
    }
    smn_read32_bdf(st.bus, st.dev, st.func, addr)
}

/// Write a 32-bit value to an SMN address.
///
/// `addr` - SMN address to write.
/// `val`  - 32-bit value to write.
///
/// Silently does nothing if the driver is not initialised.
#[unsafe(no_mangle)]
pub extern "C" fn amd_smn_write32(addr: u32, val: u32) {
    let st = unsafe { &*STATE.get() };
    if !st.initialized {
        return;
    }
    smn_write32_bdf(st.bus, st.dev, st.func, addr, val);
}

/// Read a 32-bit value from an SMN address on a specific die/node.
///
/// On multi-die systems (e.g., Threadripper, EPYC), each die has its own
/// Root Complex function. The node index selects the PCI function (00:00.N)
/// used to access that die's SMN space.
///
/// `node` - Die/node index (0-7). Maps to PCI function number.
/// `addr` - SMN address to read.
///
/// Returns the 32-bit value, or 0xFFFFFFFF if invalid.
#[unsafe(no_mangle)]
pub extern "C" fn amd_smn_read_indexed(node: u32, addr: u32) -> u32 {
    let st = unsafe { &*STATE.get() };
    if !st.initialized {
        return 0xFFFF_FFFF;
    }

    // Each die is accessed via function N of the root complex on bus 0 dev 0.
    if node > 7 {
        return 0xFFFF_FFFF;
    }

    // Verify the target function exists (vendor ID should be AMD).
    let vendor = pci_read16(st.bus, st.dev, node as u8, 0x00);
    if vendor != AMD_VENDOR_ID {
        return 0xFFFF_FFFF;
    }

    smn_read32_bdf(st.bus, st.dev, node as u8, addr)
}

/// Dump a range of SMN registers for diagnostic purposes.
///
/// Reads `count` consecutive 32-bit registers starting at `start` and
/// prints them via fut_printf. Each line shows the SMN address and value.
///
/// `start` - Starting SMN address (should be 4-byte aligned).
/// `count` - Number of 32-bit registers to read.
#[unsafe(no_mangle)]
pub extern "C" fn amd_smn_dump_range(start: u32, count: u32) {
    let st = unsafe { &*STATE.get() };
    if !st.initialized {
        log("amd_smn: driver not initialised");
        return;
    }

    // Clamp to a reasonable maximum to avoid flooding the log.
    let max_count = if count > 256 { 256 } else { count };

    unsafe {
        fut_printf(
            b"amd_smn: dumping %u registers starting at SMN 0x%08x\n\0".as_ptr(),
            max_count,
            start,
        );
    }

    let aligned_start = start & !0x03;

    for i in 0..max_count {
        let addr = aligned_start.wrapping_add(i * 4);
        let val = smn_read32_bdf(st.bus, st.dev, st.func, addr);

        // Print in groups of 4 registers per line for readability.
        if i % 4 == 0 {
            if i > 0 {
                unsafe {
                    fut_printf(b"\n\0".as_ptr());
                }
            }
            unsafe {
                fut_printf(b"  %08x:\0".as_ptr(), addr);
            }
        }
        unsafe {
            fut_printf(b" %08x\0".as_ptr(), val);
        }
    }

    if max_count > 0 {
        unsafe {
            fut_printf(b"\n\0".as_ptr());
        }
    }
}
