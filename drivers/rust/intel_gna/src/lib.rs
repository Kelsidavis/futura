// SPDX-License-Identifier: MPL-2.0
//
// Intel GNA (Gaussian & Neural Accelerator) Driver for Futura OS
//
// Low-power neural network inference engine found in Intel Gen 10+
// (Gemini Lake, Ice Lake, Tiger Lake, Alder Lake, Meteor Lake).
// The GNA offloads audio/speech processing workloads (keyword detection,
// noise suppression, speaker identification) using integer-only
// arithmetic (INT8/INT16) for minimal power consumption.
//
// Architecture:
//   - PCI device, vendor 8086h, class 08h/80h (Other system peripheral)
//   - MMIO register access via PCI BAR0
//   - Descriptor-based inference submission (physical addresses)
//   - Each descriptor (32 bytes) describes a neural network layer
//     (affine, CNN, RNN, copy) with input/output addresses and dimensions
//   - Polling-based completion detection
//
// GNA MMIO register map (offsets from BAR0):
//   0x00  GNA_CTRL       Control (start, abort, interrupt enable)
//   0x04  GNA_STS        Status (busy, done, error, error code)
//   0x08  GNA_CFG        Configuration (mode, precision settings)
//   0x10  GNA_DESC_BASE  Descriptor base address low (physical)
//   0x14  GNA_DESC_BASE_HI  Descriptor base address high
//   0x18  GNA_DESC_COUNT Number of descriptors
//   0x20  GNA_MMIO_SCRATCH  Scratch register (debugging)
//   0x80  GNA_VERSION    Hardware version
//   0x84  GNA_CAPS       Capabilities (max layers, precision support)
//
// Supported device IDs:
//   3190h  Gemini Lake (GLK)
//   8A11h  Ice Lake (ICL)
//   4511h  Tiger Lake (TGL)
//   464Fh  Alder Lake (ADL)
//   7E4Ch  Meteor Lake (MTL)

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

// ── Intel GNA constants ──

const INTEL_VENDOR_ID: u16 = 0x8086;

/// Supported GNA device IDs
const GNA_DEVICE_IDS: &[u16] = &[
    0x3190, // Gemini Lake (GLK)
    0x8A11, // Ice Lake (ICL)
    0x4511, // Tiger Lake (TGL)
    0x464F, // Alder Lake (ADL)
    0x7E4C, // Meteor Lake (MTL)
];

// ── GNA MMIO register offsets ──

/// Control register: bit 0 = start, bit 1 = abort, bit 2 = interrupt enable
const GNA_CTRL: usize = 0x00;
/// Status register: bit 0 = busy, bit 1 = done, bit 2 = error, bits[7:4] = error code
const GNA_STS: usize = 0x04;
/// Configuration register: mode and precision settings
const GNA_CFG: usize = 0x08;
/// Descriptor base address (low 32 bits, physical)
const GNA_DESC_BASE: usize = 0x10;
/// Descriptor base address (high 32 bits)
const GNA_DESC_BASE_HI: usize = 0x14;
/// Number of descriptors to process
const GNA_DESC_COUNT: usize = 0x18;
/// Scratch register for debugging
const GNA_MMIO_SCRATCH: usize = 0x20;
/// Hardware version register (read-only)
const GNA_VERSION: usize = 0x80;
/// Capabilities register (read-only): max layers, precision support
const GNA_CAPS: usize = 0x84;

// ── GNA_CTRL bits ──

/// Start inference processing
const CTRL_START: u32 = 1 << 0;
/// Abort current inference
const CTRL_ABORT: u32 = 1 << 1;
/// Enable interrupt on completion
const CTRL_IRQ_EN: u32 = 1 << 2;

// ── GNA_STS bits ──

/// Inference engine is busy
const STS_BUSY: u32 = 1 << 0;
/// Inference completed successfully
const STS_DONE: u32 = 1 << 1;
/// Error occurred during inference
const STS_ERROR: u32 = 1 << 2;
/// Error code field mask (bits [7:4])
const STS_ERR_CODE_MASK: u32 = 0xF0;
/// Error code field shift
const STS_ERR_CODE_SHIFT: u32 = 4;

// ── GNA MMIO region size ──

/// The GNA register space fits in a single 4 KiB page
const GNA_MMIO_SIZE: usize = 0x1000;

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

struct GnaState {
    /// Virtual address of the GNA MMIO register base
    base: *mut u8,
    /// Physical address of BAR0
    phys_base: u64,
    /// PCI bus/device/function
    bus: u8,
    dev: u8,
    func: u8,
    /// Device ID (to identify the specific GNA generation)
    device_id: u16,
    /// Whether the driver has been initialized
    initialized: bool,
}

impl GnaState {
    const fn new() -> Self {
        Self {
            base: core::ptr::null_mut(),
            phys_base: 0,
            bus: 0,
            dev: 0,
            func: 0,
            device_id: 0,
            initialized: false,
        }
    }
}

static GNA: StaticCell<GnaState> = StaticCell::new(GnaState::new());

// ── PCI discovery ──

/// Scan PCI bus for a supported Intel GNA device.
/// Returns (bus, dev, func, device_id, irq) or None.
fn find_gna_pci() -> Option<(u8, u8, u8, u16, u8)> {
    let count = unsafe { pci_device_count() };
    for i in 0..count {
        let dev = unsafe { pci_get_device(i) };
        if dev.is_null() {
            continue;
        }
        let d = unsafe { &*dev };
        if d.vendor_id == INTEL_VENDOR_ID {
            for &did in GNA_DEVICE_IDS {
                if d.device_id == did {
                    return Some((d.bus, d.dev, d.func, d.device_id, d.irq_line));
                }
            }
        }
    }
    None
}

/// Return a human-readable name for a GNA device ID.
fn gna_generation_name(device_id: u16) -> &'static [u8] {
    match device_id {
        0x3190 => b"Gemini Lake\0",
        0x8A11 => b"Ice Lake\0",
        0x4511 => b"Tiger Lake\0",
        0x464F => b"Alder Lake\0",
        0x7E4C => b"Meteor Lake\0",
        _ => b"Unknown\0",
    }
}

// ── Internal helpers ──

/// Clear completion/error status bits by writing 1 to them (W1C).
fn gna_clear_status(base: *mut u8) {
    mmio_write32(base, GNA_STS, STS_DONE | STS_ERROR);
    fence(Ordering::SeqCst);
}

// ── FFI exports ──

/// Initialize the Intel GNA driver.
///
/// Discovers a GNA device on the PCI bus, maps BAR0, reads version
/// and capability registers, and prepares the device for inference
/// submission.
///
/// Returns 0 on success, negative on error:
///   -1 = no supported GNA device found
///   -2 = BAR0 is I/O space (expected MMIO)
///   -3 = BAR0 not configured
///   -4 = failed to map MMIO region
#[unsafe(no_mangle)]
pub extern "C" fn intel_gna_init() -> i32 {
    log("intel_gna: scanning PCI for Intel GNA devices...");

    let (bus, dev, func, device_id, irq) = match find_gna_pci() {
        Some(info) => info,
        None => {
            log("intel_gna: no supported GNA device found");
            return -1;
        }
    };

    unsafe {
        fut_printf(
            b"intel_gna: found device %04x:%04x at PCI %02x:%02x.%x IRQ %d\n\0".as_ptr(),
            INTEL_VENDOR_ID as u32, device_id as u32,
            bus as u32, dev as u32, func as u32, irq as u32,
        );
        fut_printf(
            b"intel_gna: generation: %s\n\0".as_ptr(),
            gna_generation_name(device_id).as_ptr(),
        );
    }

    // Enable bus mastering and memory space access in PCI command register
    let pci_cmd = pci_read16(bus, dev, func, 0x04);
    pci_write16(bus, dev, func, 0x04, pci_cmd | 0x06); // Memory Space + Bus Master

    // Read BAR0 for MMIO
    let bar0_lo = pci_read32(bus, dev, func, 0x10);

    if bar0_lo & 0x01 != 0 {
        log("intel_gna: BAR0 is I/O space, expected MMIO");
        return -2;
    }

    // Determine if 64-bit BAR
    let is_64bit = (bar0_lo & 0x06) == 0x04;
    let bar_phys_lo = bar0_lo & !0xF;
    let bar_phys_hi = if is_64bit {
        pci_read32(bus, dev, func, 0x14)
    } else {
        0
    };
    let bar_phys = (bar_phys_lo as u64) | ((bar_phys_hi as u64) << 32);

    if bar_phys == 0 {
        log("intel_gna: BAR0 not configured");
        return -3;
    }

    unsafe {
        fut_printf(
            b"intel_gna: MMIO BAR0 at physical 0x%llx\n\0".as_ptr(),
            bar_phys,
        );
    }

    // Map the GNA MMIO region
    let base = unsafe { map_mmio_region(bar_phys, GNA_MMIO_SIZE, MMIO_DEFAULT_FLAGS) };
    if base.is_null() {
        log("intel_gna: failed to map MMIO region");
        return -4;
    }

    // Read hardware version and capabilities
    let version = mmio_read32(base, GNA_VERSION);
    let caps = mmio_read32(base, GNA_CAPS);
    let status = mmio_read32(base, GNA_STS);
    let cfg = mmio_read32(base, GNA_CFG);

    unsafe {
        fut_printf(
            b"intel_gna: VERSION=0x%08x CAPS=0x%08x\n\0".as_ptr(),
            version, caps,
        );
        fut_printf(
            b"intel_gna: STS=0x%08x CFG=0x%08x\n\0".as_ptr(),
            status, cfg,
        );
    }

    // Clear any stale status bits
    gna_clear_status(base);

    // Disable interrupts (polling mode) - clear interrupt enable in CTRL
    let ctrl = mmio_read32(base, GNA_CTRL);
    mmio_write32(base, GNA_CTRL, ctrl & !CTRL_IRQ_EN);
    fence(Ordering::SeqCst);

    // Store driver state
    let state = GNA.get();
    unsafe {
        (*state).base = base;
        (*state).phys_base = bar_phys;
        (*state).bus = bus;
        (*state).dev = dev;
        (*state).func = func;
        (*state).device_id = device_id;
        fence(Ordering::SeqCst);
        (*state).initialized = true;
    }

    log("intel_gna: driver initialized");
    0
}

/// Return the GNA hardware version register.
///
/// Returns 0 if the driver is not initialized.
#[unsafe(no_mangle)]
pub extern "C" fn intel_gna_version() -> u32 {
    let state = GNA.get();
    unsafe {
        if !(*state).initialized {
            return 0;
        }
        mmio_read32((*state).base, GNA_VERSION)
    }
}

/// Return the GNA capabilities register.
///
/// Encodes maximum supported layers and precision modes.
/// Returns 0 if the driver is not initialized.
#[unsafe(no_mangle)]
pub extern "C" fn intel_gna_caps() -> u32 {
    let state = GNA.get();
    unsafe {
        if !(*state).initialized {
            return 0;
        }
        mmio_read32((*state).base, GNA_CAPS)
    }
}

/// Submit a descriptor list for inference.
///
/// `desc_phys` is the physical address of the descriptor array.
/// `count` is the number of descriptors (layers) to process.
///
/// The caller must ensure the descriptor memory and all referenced
/// data buffers (weights, biases, inputs, outputs) are in physically
/// contiguous memory and will remain valid until inference completes.
///
/// Returns 0 on success, negative on error:
///   -1 = driver not initialized
///   -2 = device is busy (previous inference still running)
///   -3 = invalid parameters (count == 0)
#[unsafe(no_mangle)]
pub extern "C" fn intel_gna_submit(desc_phys: u64, count: u32) -> i32 {
    let state = GNA.get();
    unsafe {
        if !(*state).initialized {
            return -1;
        }
    }

    if count == 0 {
        return -3;
    }

    let base = unsafe { (*GNA.get()).base };

    // Check that the device is not currently busy
    let sts = mmio_read32(base, GNA_STS);
    if sts & STS_BUSY != 0 {
        log("intel_gna: submit failed, device is busy");
        return -2;
    }

    // Clear any previous completion/error status
    gna_clear_status(base);

    // Program descriptor base address (low and high 32 bits)
    let desc_lo = desc_phys as u32;
    let desc_hi = (desc_phys >> 32) as u32;
    mmio_write32(base, GNA_DESC_BASE, desc_lo);
    mmio_write32(base, GNA_DESC_BASE_HI, desc_hi);
    fence(Ordering::SeqCst);

    // Program descriptor count
    mmio_write32(base, GNA_DESC_COUNT, count);
    fence(Ordering::SeqCst);

    // Start inference
    let ctrl = mmio_read32(base, GNA_CTRL);
    mmio_write32(base, GNA_CTRL, (ctrl & !CTRL_ABORT) | CTRL_START);
    fence(Ordering::SeqCst);

    unsafe {
        fut_printf(
            b"intel_gna: submitted %u descriptors at phys 0x%llx\n\0".as_ptr(),
            count, desc_phys,
        );
    }

    0
}

/// Poll the GNA for inference completion.
///
/// Returns:
///    0 = inference completed successfully
///    1 = inference still in progress (busy)
///   -1 = driver not initialized
///   -2 = inference completed with error (use `intel_gna_error_code` for details)
#[unsafe(no_mangle)]
pub extern "C" fn intel_gna_poll() -> i32 {
    let state = GNA.get();
    unsafe {
        if !(*state).initialized {
            return -1;
        }
    }

    let base = unsafe { (*GNA.get()).base };
    let sts = mmio_read32(base, GNA_STS);

    if sts & STS_ERROR != 0 {
        let err_code = (sts & STS_ERR_CODE_MASK) >> STS_ERR_CODE_SHIFT;
        unsafe {
            fut_printf(
                b"intel_gna: inference error, STS=0x%08x code=%u\n\0".as_ptr(),
                sts, err_code,
            );
        }
        return -2;
    }

    if sts & STS_DONE != 0 {
        // Clear the done bit for next submission
        gna_clear_status(base);
        return 0;
    }

    if sts & STS_BUSY != 0 {
        return 1;
    }

    // Neither busy, done, nor error -- device is idle (no submission pending)
    0
}

/// Abort the current inference operation.
///
/// Returns 0 on success, -1 if the driver is not initialized.
#[unsafe(no_mangle)]
pub extern "C" fn intel_gna_abort() -> i32 {
    let state = GNA.get();
    unsafe {
        if !(*state).initialized {
            return -1;
        }
    }

    let base = unsafe { (*GNA.get()).base };

    // Issue abort
    let ctrl = mmio_read32(base, GNA_CTRL);
    mmio_write32(base, GNA_CTRL, (ctrl & !CTRL_START) | CTRL_ABORT);
    fence(Ordering::SeqCst);

    // Wait for busy to clear (with a timeout)
    for _ in 0..100_000u32 {
        let sts = mmio_read32(base, GNA_STS);
        if sts & STS_BUSY == 0 {
            // Clear status bits
            gna_clear_status(base);
            log("intel_gna: inference aborted");
            return 0;
        }
        core::hint::spin_loop();
    }

    log("intel_gna: abort timeout, device still busy");
    // Clear abort bit regardless
    let ctrl = mmio_read32(base, GNA_CTRL);
    mmio_write32(base, GNA_CTRL, ctrl & !CTRL_ABORT);
    0
}

/// Return the error code from the last failed inference.
///
/// The error code is extracted from GNA_STS bits [7:4].
/// Returns 0 if the driver is not initialized or no error is present.
#[unsafe(no_mangle)]
pub extern "C" fn intel_gna_error_code() -> u32 {
    let state = GNA.get();
    unsafe {
        if !(*state).initialized {
            return 0;
        }
    }

    let base = unsafe { (*GNA.get()).base };
    let sts = mmio_read32(base, GNA_STS);

    if sts & STS_ERROR != 0 {
        (sts & STS_ERR_CODE_MASK) >> STS_ERR_CODE_SHIFT
    } else {
        0
    }
}

/// Check whether a supported Intel GNA device is present on the PCI bus.
///
/// This can be called before `intel_gna_init` to determine if GNA
/// hardware exists in the system.
#[unsafe(no_mangle)]
pub extern "C" fn intel_gna_is_present() -> bool {
    find_gna_pci().is_some()
}
