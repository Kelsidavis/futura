// SPDX-License-Identifier: MPL-2.0
//
// Intel MEI (Management Engine Interface) / HECI Driver for Futura OS
//
// Provides communication with the Intel CSME (Converged Security and
// Management Engine) via the HECI (Host Embedded Controller Interface)
// on Gen 10+ (Comet Lake and later) platforms.
//
// The MEI is exposed as PCI device 00:16.0 (vendor 8086h, class 07:80)
// with device IDs varying by platform generation:
//   A3BAh  Comet Lake (CML)
//   A0E0h  Tiger Lake (TGL)
//   51E0h  Alder Lake (ADL)
//   7E70h  Meteor Lake (MTL)
//
// Communication uses a pair of circular buffers in MMIO space: a host-
// to-ME write buffer and an ME-to-host read buffer.  Each message is
// prefixed by a 4-byte header carrying client addresses and length.
//
// MEI MMIO register map (offsets from BAR0):
//   0x00  H_CB_WW       Host Circular Buffer Write Window
//   0x04  H_CSR         Host Control / Status Register
//   0x08  ME_CB_RW      ME Circular Buffer Read Window
//   0x0C  ME_CSR_HA     ME Control / Status (Host Access)
//   0x10  H_GS          Host General Status (FW Status 1)
//   0x40  H_GS2         Host General Status 2 (FW Status 2)
//
// H_CSR / ME_CSR_HA layout:
//   [0]     IE   - Interrupt Enable
//   [1]     IS   - Interrupt Status
//   [2]     IG   - Interrupt Generate
//   [3]     RDY  - Ready
//   [4]     RST  - Reset
//   [15:8]  CBRP - Circular Buffer Read Pointer
//   [23:16] CBWP - Circular Buffer Write Pointer
//   [31:24] CBD  - Circular Buffer Depth
//
// MEI message header (32 bits):
//   [7:0]   me_addr      ME client address
//   [15:8]  host_addr    Host client address
//   [24:16] length       Payload length in bytes (max 512)
//   [31]    msg_complete  1 = final fragment
//
// MEI clients (identified by GUID, addressed by numeric ID):
//   MKHI  (ME Kernel Host Interface) - general CSME commands
//   AMTHI - Intel AMT Host Interface
//
// MKHI command format: group_id (u8), command_id (u8), reserved (u16)
//   0x03:0x00  GET_FW_VERSION
//   0xFF:0x05  GEN_GET_ME_UNCFG_STATE

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(unexpected_cfgs)]

use core::cell::UnsafeCell;
use core::ptr::{read_volatile, write_volatile, copy_nonoverlapping};
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

// ── PCI identification constants ──

const INTEL_VENDOR_ID: u16 = 0x8086;

/// Known MEI (HECI) device IDs per platform generation
const MEI_DEVICE_IDS: &[u16] = &[
    0xA3BA, // Comet Lake (CML)
    0xA0E0, // Tiger Lake (TGL)
    0x51E0, // Alder Lake (ADL)
    0x7E70, // Meteor Lake (MTL)
];

/// PCI class 07h = Communication Controller, subclass 80h = Other
const MEI_CLASS: u8 = 0x07;
const MEI_SUBCLASS: u8 = 0x80;

// ── MEI MMIO register offsets ──

/// Host Circular Buffer Write Window
const H_CB_WW: usize = 0x00;
/// Host Control / Status Register
const H_CSR: usize = 0x04;
/// ME Circular Buffer Read Window
const ME_CB_RW: usize = 0x08;
/// ME Control / Status Register (Host Access)
const ME_CSR_HA: usize = 0x0C;
/// Host General Status (firmware status register 1)
const H_GS: usize = 0x10;
/// Host General Status 2 (firmware status register 2)
const H_GS2: usize = 0x40;

// ── H_CSR / ME_CSR_HA bit definitions ──

/// Interrupt Enable
const CSR_IE: u32 = 1 << 0;
/// Interrupt Status
const CSR_IS: u32 = 1 << 1;
/// Interrupt Generate
const CSR_IG: u32 = 1 << 2;
/// Host/ME Ready
const CSR_RDY: u32 = 1 << 3;
/// Host/ME Reset
const CSR_RST: u32 = 1 << 4;

/// Circular Buffer Read Pointer shift and mask
const CSR_CBRP_SHIFT: u32 = 8;
const CSR_CBRP_MASK: u32 = 0xFF << CSR_CBRP_SHIFT;
/// Circular Buffer Write Pointer shift and mask
const CSR_CBWP_SHIFT: u32 = 16;
const CSR_CBWP_MASK: u32 = 0xFF << CSR_CBWP_SHIFT;
/// Circular Buffer Depth shift and mask
const CSR_CBD_SHIFT: u32 = 24;
const CSR_CBD_MASK: u32 = 0xFF << CSR_CBD_SHIFT;

// ── MEI message header ──

/// Build a 32-bit MEI message header.
fn mei_msg_hdr(me_addr: u8, host_addr: u8, length: u16, complete: bool) -> u32 {
    (me_addr as u32)
        | ((host_addr as u32) << 8)
        | (((length as u32) & 0x1FF) << 16)
        | if complete { 1 << 31 } else { 0 }
}

/// Extract payload length from a MEI message header.
fn mei_hdr_length(hdr: u32) -> u16 {
    ((hdr >> 16) & 0x1FF) as u16
}

/// Extract msg_complete flag from a MEI message header.
fn mei_hdr_complete(hdr: u32) -> bool {
    (hdr & (1 << 31)) != 0
}

/// Extract ME client address from a MEI message header.
#[allow(dead_code)]
fn mei_hdr_me_addr(hdr: u32) -> u8 {
    (hdr & 0xFF) as u8
}

/// Extract host client address from a MEI message header.
#[allow(dead_code)]
fn mei_hdr_host_addr(hdr: u32) -> u8 {
    ((hdr >> 8) & 0xFF) as u8
}

// ── MKHI command definitions ──

/// MKHI client address (well-known fixed ID = 7 for MKHI on HECI-1)
const MKHI_ADDR: u8 = 0x07;

/// Host client address for MKHI communication
const MKHI_HOST_ADDR: u8 = 0x01;

/// MKHI group ID for firmware version query
const MKHI_GRP_GEN: u8 = 0x03;

/// MKHI command: GET_FW_VERSION
const MKHI_CMD_GET_FW_VERSION: u8 = 0x00;

/// Build a 32-bit MKHI command header: group_id[7:0], command_id[15:8], rsvd[31:16]
fn mkhi_hdr(group_id: u8, command_id: u8) -> u32 {
    (group_id as u32) | ((command_id as u32) << 8)
}

// ── MMIO size ──

/// MEI MMIO region size to map (4 KiB covers all registers including H_GS2 at 0x40)
const MEI_MMIO_SIZE: usize = 0x1000;

/// Maximum payload size per MEI message fragment (bytes)
const MEI_MAX_MSG_LEN: usize = 512;

/// Timeout iteration count for polling loops
const MEI_TIMEOUT_ITERS: u32 = 50_000;

// ── MMIO helpers ──

#[inline]
fn mmio_read32(base: *mut u8, offset: usize) -> u32 {
    unsafe { read_volatile(base.add(offset) as *const u32) }
}

#[inline]
fn mmio_write32(base: *mut u8, offset: usize, val: u32) {
    unsafe { write_volatile(base.add(offset) as *mut u32, val) }
}

// ── CSR field extraction helpers ──

#[inline]
fn csr_cbrp(csr: u32) -> u8 {
    ((csr & CSR_CBRP_MASK) >> CSR_CBRP_SHIFT) as u8
}

#[inline]
fn csr_cbwp(csr: u32) -> u8 {
    ((csr & CSR_CBWP_MASK) >> CSR_CBWP_SHIFT) as u8
}

#[inline]
fn csr_cbd(csr: u32) -> u8 {
    ((csr & CSR_CBD_MASK) >> CSR_CBD_SHIFT) as u8
}

// ── Driver state ──

struct MeiState {
    /// Virtual address of MEI MMIO register base
    base: *mut u8,
    /// Physical address of BAR0
    phys_base: u64,
    /// PCI bus/dev/func of the MEI device
    bus: u8,
    dev: u8,
    func: u8,
    /// Circular buffer depth (in DWORDs)
    cb_depth: u8,
    /// Whether the driver is initialized and ready
    initialized: bool,
}

impl MeiState {
    const fn new() -> Self {
        Self {
            base: core::ptr::null_mut(),
            phys_base: 0,
            bus: 0,
            dev: 0,
            func: 0,
            cb_depth: 0,
            initialized: false,
        }
    }
}

static MEI: StaticCell<MeiState> = StaticCell::new(MeiState::new());

/// Scratch buffer for receive operations (header + payload, max 520 bytes)
static RX_BUF: StaticCell<[u8; 4 + MEI_MAX_MSG_LEN]> = StaticCell::new([0u8; 4 + MEI_MAX_MSG_LEN]);

// ── Internal helpers ──

/// Scan the PCI device list for an Intel MEI/HECI controller.
/// Returns (bus, dev, func, device_id) or None.
fn find_mei_device() -> Option<(u8, u8, u8, u16)> {
    let count = unsafe { pci_device_count() };
    for i in 0..count {
        let pdev = unsafe { pci_get_device(i) };
        if pdev.is_null() {
            continue;
        }
        let d = unsafe { &*pdev };
        if d.vendor_id == INTEL_VENDOR_ID
            && d.class_code == MEI_CLASS
            && d.subclass == MEI_SUBCLASS
        {
            // Check if this is a known MEI device ID
            for &known_id in MEI_DEVICE_IDS {
                if d.device_id == known_id {
                    return Some((d.bus, d.dev, d.func, d.device_id));
                }
            }
        }
    }
    None
}

/// Read BAR0 from PCI config space of the MEI device.
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

/// Perform MEI host-initiated reset and wait for ME to become ready.
/// Returns true on success, false on timeout.
fn mei_reset(base: *mut u8) -> bool {
    // Assert host reset: set H_RST and H_IG, clear H_IE
    let csr = mmio_read32(base, H_CSR);
    let val = (csr & !(CSR_IE | CSR_IS)) | CSR_RST | CSR_IG;
    mmio_write32(base, H_CSR, val);
    fence(Ordering::SeqCst);

    // Wait for host reset to complete (H_RDY should deassert briefly then reassert)
    for _ in 0..MEI_TIMEOUT_ITERS {
        let hcsr = mmio_read32(base, H_CSR);
        if hcsr & CSR_RST == 0 {
            break;
        }
        thread_yield();
    }

    // Wait for ME to signal readiness (ME_RDY in ME_CSR_HA)
    for _ in 0..MEI_TIMEOUT_ITERS {
        let mecsr = mmio_read32(base, ME_CSR_HA);
        if mecsr & CSR_RDY != 0 {
            return true;
        }
        thread_yield();
    }

    false
}

/// Set host ready: assert H_RDY, enable interrupts, generate interrupt.
fn mei_host_set_ready(base: *mut u8) {
    let csr = mmio_read32(base, H_CSR);
    let val = (csr & !(CSR_IS | CSR_RST)) | CSR_RDY | CSR_IE | CSR_IG;
    mmio_write32(base, H_CSR, val);
    fence(Ordering::SeqCst);
}

/// Clear interrupt status on the host side.
fn mei_clear_interrupts(base: *mut u8) {
    let csr = mmio_read32(base, H_CSR);
    mmio_write32(base, H_CSR, csr | CSR_IS | CSR_IG);
}

/// Check how many empty slots are available in the host circular buffer.
fn mei_host_buf_free_slots(base: *mut u8) -> u8 {
    let csr = mmio_read32(base, H_CSR);
    let depth = csr_cbd(csr);
    let rp = csr_cbrp(csr);
    let wp = csr_cbwp(csr);
    // Number of filled slots
    let filled = wp.wrapping_sub(rp) & (depth.wrapping_mul(2).wrapping_sub(1));
    if filled > depth {
        return 0;
    }
    depth.wrapping_sub(filled)
}

/// Check how many slots the ME has written (pending reads for the host).
fn mei_me_buf_pending_slots(base: *mut u8) -> u8 {
    let csr = mmio_read32(base, ME_CSR_HA);
    let rp = csr_cbrp(csr);
    let wp = csr_cbwp(csr);
    wp.wrapping_sub(rp)
}

/// Write a complete message (header + payload) to the host circular buffer.
/// `data` is the raw payload, `me_addr` and `host_addr` identify the clients.
/// Returns 0 on success, negative on error.
fn mei_write_message(
    base: *mut u8,
    me_addr: u8,
    host_addr: u8,
    data: *const u8,
    len: u32,
) -> i32 {
    if len as usize > MEI_MAX_MSG_LEN {
        return -1;
    }

    // Total DWORDs needed: 1 (header) + ceil(len/4) (payload)
    let payload_dwords = (len as usize + 3) / 4;
    let total_dwords = 1 + payload_dwords;

    // Wait for sufficient space in the host circular buffer
    for _ in 0..MEI_TIMEOUT_ITERS {
        let free = mei_host_buf_free_slots(base) as usize;
        if free >= total_dwords {
            break;
        }
        thread_yield();
    }

    // Double check after the wait loop
    if (mei_host_buf_free_slots(base) as usize) < total_dwords {
        return -2; // Timeout waiting for buffer space
    }

    // Write MEI message header
    let hdr = mei_msg_hdr(me_addr, host_addr, len as u16, true);
    mmio_write32(base, H_CB_WW, hdr);

    // Write payload DWORDs (last one may contain padding bytes)
    for i in 0..payload_dwords {
        let mut dword: u32 = 0;
        let offset = i * 4;
        let remaining = (len as usize).saturating_sub(offset);
        let copy_len = if remaining >= 4 { 4 } else { remaining };
        unsafe {
            copy_nonoverlapping(
                data.add(offset),
                &mut dword as *mut u32 as *mut u8,
                copy_len,
            );
        }
        mmio_write32(base, H_CB_WW, dword);
    }

    // Set H_IG to notify the ME that data is available
    let csr = mmio_read32(base, H_CSR);
    mmio_write32(base, H_CSR, (csr & !(CSR_IS)) | CSR_IG);
    fence(Ordering::SeqCst);

    0
}

/// Read a complete message from the ME circular buffer.
/// Returns the number of payload bytes read on success, or negative on error.
/// The header is stored in `hdr_out` if non-null.
fn mei_read_message(
    base: *mut u8,
    buf: *mut u8,
    max_len: u32,
    hdr_out: *mut u32,
) -> i32 {
    // Wait for at least one DWORD (the header) to be available
    for _ in 0..MEI_TIMEOUT_ITERS {
        if mei_me_buf_pending_slots(base) >= 1 {
            break;
        }
        thread_yield();
    }

    if mei_me_buf_pending_slots(base) == 0 {
        return -1; // Timeout waiting for ME response
    }

    // Read the message header from ME_CB_RW
    let hdr = mmio_read32(base, ME_CB_RW);
    if !hdr_out.is_null() {
        unsafe { write_volatile(hdr_out, hdr); }
    }

    let msg_len = mei_hdr_length(hdr) as u32;
    let payload_dwords = ((msg_len as usize) + 3) / 4;

    // Wait for remaining payload DWORDs
    for _ in 0..MEI_TIMEOUT_ITERS {
        if mei_me_buf_pending_slots(base) >= payload_dwords as u8 {
            break;
        }
        thread_yield();
    }

    // Read payload DWORDs
    let copy_len = if msg_len > max_len { max_len } else { msg_len };
    let mut bytes_read: u32 = 0;
    for i in 0..payload_dwords {
        let dword = mmio_read32(base, ME_CB_RW);
        let offset = (i * 4) as u32;
        let remaining = copy_len.saturating_sub(offset);
        if remaining > 0 {
            let n = if remaining >= 4 { 4 } else { remaining };
            unsafe {
                copy_nonoverlapping(
                    &dword as *const u32 as *const u8,
                    buf.add(offset as usize),
                    n as usize,
                );
            }
            bytes_read += n;
        }
    }

    // Clear interrupt and notify ME that we consumed the data
    mei_clear_interrupts(base);

    bytes_read as i32
}

// ── FFI exports ──

/// Initialize the Intel MEI/HECI driver.
///
/// Scans PCI for an Intel MEI controller, maps BAR0 MMIO, performs
/// a host reset, and establishes the host-ready handshake with ME.
///
/// Returns 0 on success, negative on error:
///   -1 = MEI device not found in PCI device list
///   -2 = BAR0 is I/O space, not MMIO
///   -3 = BAR0 not configured (zero physical address)
///   -4 = failed to map MEI MMIO region
///   -5 = MEI reset timeout (ME did not become ready)
///   -6 = ME firmware not ready after host-ready handshake
#[unsafe(no_mangle)]
pub extern "C" fn intel_mei_init() -> i32 {
    log("intel_mei: initializing MEI/HECI driver");

    // Scan for Intel MEI PCI device
    let (bus, dev, func, device_id) = match find_mei_device() {
        Some(info) => info,
        None => {
            log("intel_mei: no Intel MEI/HECI device found");
            return -1;
        }
    };

    unsafe {
        fut_printf(
            b"intel_mei: found device %04x:%04x at PCI %02x:%02x.%x\n\0".as_ptr(),
            INTEL_VENDOR_ID as u32, device_id as u32,
            bus as u32, dev as u32, func as u32,
        );
    }

    // Enable memory space access in PCI command register
    let pci_cmd = pci_read16(bus, dev, func, 0x04);
    pci_write16(bus, dev, func, 0x04, pci_cmd | 0x02); // Memory Space Enable

    // Read BAR0
    let bar0_lo = pci_read32(bus, dev, func, 0x10);
    if bar0_lo & 0x01 != 0 {
        log("intel_mei: BAR0 is I/O space, expected MMIO");
        return -2;
    }

    let bar_phys = read_bar0(bus, dev, func);
    if bar_phys == 0 {
        log("intel_mei: BAR0 not configured");
        return -3;
    }

    unsafe {
        fut_printf(
            b"intel_mei: MMIO BAR0 at physical 0x%llx\n\0".as_ptr(),
            bar_phys,
        );
    }

    // Map MEI MMIO region
    let mmio = unsafe { map_mmio_region(bar_phys, MEI_MMIO_SIZE, MMIO_DEFAULT_FLAGS) };
    if mmio.is_null() {
        log("intel_mei: failed to map MMIO region");
        return -4;
    }

    // Read initial firmware status for diagnostics
    let fwsts1 = mmio_read32(mmio, H_GS);
    let fwsts2 = mmio_read32(mmio, H_GS2);
    unsafe {
        fut_printf(
            b"intel_mei: FWSTS1=0x%08x FWSTS2=0x%08x\n\0".as_ptr(),
            fwsts1, fwsts2,
        );
    }

    // Read H_CSR to determine circular buffer depth
    let hcsr = mmio_read32(mmio, H_CSR);
    let cbd = csr_cbd(hcsr);
    unsafe {
        fut_printf(
            b"intel_mei: H_CSR=0x%08x (CB depth=%u)\n\0".as_ptr(),
            hcsr, cbd as u32,
        );
    }

    // Perform host-initiated reset
    log("intel_mei: performing host reset");
    if !mei_reset(mmio) {
        log("intel_mei: reset timeout - ME did not become ready");
        unsafe { unmap_mmio_region(mmio, MEI_MMIO_SIZE); }
        return -5;
    }
    log("intel_mei: ME is ready after reset");

    // Set host ready and enable interrupts
    mei_host_set_ready(mmio);

    // Verify ME is still ready after handshake
    let mecsr = mmio_read32(mmio, ME_CSR_HA);
    if mecsr & CSR_RDY == 0 {
        log("intel_mei: ME not ready after handshake");
        unsafe { unmap_mmio_region(mmio, MEI_MMIO_SIZE); }
        return -6;
    }

    // Read final buffer depth (may change after reset)
    let hcsr_final = mmio_read32(mmio, H_CSR);
    let cb_depth = csr_cbd(hcsr_final);

    // Store driver state
    let state = MEI.get();
    unsafe {
        (*state).base = mmio;
        (*state).phys_base = bar_phys;
        (*state).bus = bus;
        (*state).dev = dev;
        (*state).func = func;
        (*state).cb_depth = cb_depth;
        fence(Ordering::SeqCst);
        (*state).initialized = true;
    }

    unsafe {
        fut_printf(
            b"intel_mei: initialized (CB depth=%u, ME_CSR=0x%08x)\n\0".as_ptr(),
            cb_depth as u32, mecsr,
        );
    }

    log("intel_mei: driver ready");
    0
}

/// Query CSME firmware version via MKHI GET_FW_VERSION command.
///
/// On success, writes the version components to the provided pointers
/// and returns 0. On failure, returns a negative error code:
///   -1 = driver not initialized
///   -2 = failed to send MKHI command
///   -3 = failed to receive response
///   -4 = response too short
///   -5 = unexpected MKHI response group/command
#[unsafe(no_mangle)]
pub extern "C" fn intel_mei_get_fw_version(
    major: *mut u16,
    minor: *mut u16,
    hotfix: *mut u16,
    build: *mut u16,
) -> i32 {
    let state = MEI.get();
    let base = unsafe { (*state).base };
    if unsafe { !(*state).initialized } || base.is_null() {
        return -1;
    }

    // Build MKHI GET_FW_VERSION command (4-byte MKHI header, no extra payload)
    let mkhi_cmd = mkhi_hdr(MKHI_GRP_GEN, MKHI_CMD_GET_FW_VERSION);
    let cmd_bytes = mkhi_cmd.to_le_bytes();

    // Send the command to the MKHI ME client
    let rc = mei_write_message(
        base,
        MKHI_ADDR,
        MKHI_HOST_ADDR,
        cmd_bytes.as_ptr(),
        4,
    );
    if rc < 0 {
        log("intel_mei: failed to send GET_FW_VERSION");
        return -2;
    }

    // Read response into scratch buffer
    let rx = RX_BUF.get();
    let rx_ptr = rx as *mut u8;
    let mut hdr: u32 = 0;
    let nread = mei_read_message(base, rx_ptr, MEI_MAX_MSG_LEN as u32, &mut hdr);
    if nread < 0 {
        log("intel_mei: failed to receive GET_FW_VERSION response");
        return -3;
    }

    // MKHI response: 4 bytes MKHI header + at least 8 bytes for code version
    // Code version: major(u16), minor(u16), hotfix(u16), build(u16) = 8 bytes
    if nread < 12 {
        unsafe {
            fut_printf(
                b"intel_mei: GET_FW_VERSION response too short (%d bytes)\n\0".as_ptr(),
                nread,
            );
        }
        return -4;
    }

    // Verify MKHI response header (group_id should match, command has bit 7 set)
    let resp_mkhi = unsafe {
        let mut v: u32 = 0;
        copy_nonoverlapping(rx_ptr, &mut v as *mut u32 as *mut u8, 4);
        v
    };
    let resp_group = (resp_mkhi & 0xFF) as u8;
    let resp_cmd = ((resp_mkhi >> 8) & 0xFF) as u8;
    if resp_group != MKHI_GRP_GEN || (resp_cmd & 0x7F) != MKHI_CMD_GET_FW_VERSION {
        unsafe {
            fut_printf(
                b"intel_mei: unexpected MKHI response group=0x%02x cmd=0x%02x\n\0".as_ptr(),
                resp_group as u32, resp_cmd as u32,
            );
        }
        return -5;
    }

    // Parse firmware version from offset 4 in the response payload
    // Layout: major(u16 LE), minor(u16 LE), hotfix(u16 LE), build(u16 LE)
    unsafe {
        let ver_base = rx_ptr.add(4);
        let mut ver_major: u16 = 0;
        let mut ver_minor: u16 = 0;
        let mut ver_hotfix: u16 = 0;
        let mut ver_build: u16 = 0;
        copy_nonoverlapping(ver_base, &mut ver_major as *mut u16 as *mut u8, 2);
        copy_nonoverlapping(ver_base.add(2), &mut ver_minor as *mut u16 as *mut u8, 2);
        copy_nonoverlapping(ver_base.add(4), &mut ver_hotfix as *mut u16 as *mut u8, 2);
        copy_nonoverlapping(ver_base.add(6), &mut ver_build as *mut u16 as *mut u8, 2);

        if !major.is_null() {
            *major = ver_major;
        }
        if !minor.is_null() {
            *minor = ver_minor;
        }
        if !hotfix.is_null() {
            *hotfix = ver_hotfix;
        }
        if !build.is_null() {
            *build = ver_build;
        }

        fut_printf(
            b"intel_mei: CSME FW version %u.%u.%u.%u\n\0".as_ptr(),
            ver_major as u32, ver_minor as u32,
            ver_hotfix as u32, ver_build as u32,
        );
    }

    0
}

/// Read the ME firmware status register 1 (FWSTS1 / H_GS at offset 0x10).
///
/// Returns the raw 32-bit firmware status value, or 0 if the driver is
/// not initialized.
#[unsafe(no_mangle)]
pub extern "C" fn intel_mei_fw_status() -> u32 {
    let state = MEI.get();
    let base = unsafe { (*state).base };
    if unsafe { !(*state).initialized } || base.is_null() {
        return 0;
    }
    mmio_read32(base, H_GS)
}

/// Check whether the MEI driver is initialized and the ME is ready.
#[unsafe(no_mangle)]
pub extern "C" fn intel_mei_is_ready() -> bool {
    let state = MEI.get();
    if unsafe { !(*state).initialized } {
        return false;
    }
    let base = unsafe { (*state).base };
    if base.is_null() {
        return false;
    }
    let mecsr = mmio_read32(base, ME_CSR_HA);
    (mecsr & CSR_RDY) != 0
}

/// Send a raw MEI message to the specified ME client address.
///
/// `client` is the ME client address (e.g., 0x07 for MKHI).
/// `data` points to the payload, `len` is its length in bytes.
///
/// Returns 0 on success, negative on error:
///   -1 = driver not initialized
///   -2 = null data pointer
///   -3 = write failed (timeout or buffer full)
#[unsafe(no_mangle)]
pub extern "C" fn intel_mei_send(client: u8, data: *const u8, len: u32) -> i32 {
    let state = MEI.get();
    let base = unsafe { (*state).base };
    if unsafe { !(*state).initialized } || base.is_null() {
        return -1;
    }
    if data.is_null() && len > 0 {
        return -2;
    }

    let rc = mei_write_message(base, client, MKHI_HOST_ADDR, data, len);
    if rc < 0 {
        return -3;
    }
    0
}

/// Receive a raw MEI message from the specified ME client address.
///
/// `client` is the expected ME client address (currently unused for
/// filtering -- the caller should verify the response header).
/// `buf` is the destination buffer, `max_len` is its capacity.
///
/// Returns the number of bytes read on success, negative on error:
///   -1 = driver not initialized
///   -2 = null buffer pointer
///   -3 = read failed (timeout)
#[unsafe(no_mangle)]
pub extern "C" fn intel_mei_recv(_client: u8, buf: *mut u8, max_len: u32) -> i32 {
    let state = MEI.get();
    let base = unsafe { (*state).base };
    if unsafe { !(*state).initialized } || base.is_null() {
        return -1;
    }
    if buf.is_null() && max_len > 0 {
        return -2;
    }

    let mut hdr: u32 = 0;
    let nread = mei_read_message(base, buf, max_len, &mut hdr);
    if nread < 0 {
        return -3;
    }
    nread
}
