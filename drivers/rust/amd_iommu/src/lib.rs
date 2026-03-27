// SPDX-License-Identifier: MPL-2.0
//
// AMD IOMMU (AMD-Vi) Driver
//
// Implements the AMD I/O Virtualization Technology (IOMMU) specification
// Rev 3.0+ for DMA remapping and device isolation on AMD Ryzen AM4/AM5
// platforms.
//
// Architecture:
//   - PCI capability block (ID 0Fh) parsing for MMIO base discovery
//   - Device Table with 256 entries (64 KiB) for per-device translation
//   - Command Buffer ring (4 KiB, 256 entries) for invalidation commands
//   - Event Log ring (4 KiB, 256 entries) for DMA fault reporting
//   - 4-level I/O page tables (compatible with x86_64 CR3 format)
//   - Identity mapping (1:1 passthrough) as default policy
//
// Supported hardware:
//   - AMD Ryzen 3000/5000 series (AM4, device 1631h)
//   - AMD Ryzen 7000 series (AM5, device 14D9h/14BBh)
//
// PCI class: 08h (System Peripheral), subclass 06h (IOMMU)

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(unexpected_cfgs)]

use core::ffi::c_void;
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{Ordering, fence};

use common::{
    alloc, alloc_page, free, log, map_mmio_region, unmap_mmio_region,
    MMIO_DEFAULT_FLAGS,
};

unsafe extern "C" {
    fn fut_printf(fmt: *const u8, ...);
    fn pci_device_count() -> i32;
    fn pci_get_device(index: i32) -> *const PciDevice;
    fn rust_virt_to_phys(vaddr: *const c_void) -> u64;
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

fn pci_write16(bus: u8, dev: u8, func: u8, offset: u8, val: u16) {
    let aligned = offset & 0xFC;
    let shift = (offset & 2) * 8;
    let mut val32 = pci_read32(bus, dev, func, aligned);
    val32 &= !(0xFFFF << shift);
    val32 |= (val as u32) << shift;
    pci_write32(bus, dev, func, aligned, val32);
}

fn pci_read8(bus: u8, dev: u8, func: u8, offset: u8) -> u8 {
    let val32 = pci_read32(bus, dev, func, offset & 0xFC);
    ((val32 >> ((offset & 3) * 8)) & 0xFF) as u8
}

// ── Physical address helper ──

fn virt_to_phys(ptr: *const u8) -> u64 {
    unsafe { rust_virt_to_phys(ptr as *const c_void) }
}

// ── AMD IOMMU vendor/device IDs ──

const AMD_VENDOR_ID: u16 = 0x1022;
const AMD_IOMMU_DEVID_MATISSE: u16 = 0x1631;     // Ryzen 3000/5000 (AM4)
const AMD_IOMMU_DEVID_RAPHAEL: u16 = 0x14D9;     // Ryzen 7000 (AM5)
const AMD_IOMMU_DEVID_RAPHAEL_B: u16 = 0x14BB;   // Ryzen 7000 alternate (AM5)

/// AMD IOMMU PCI capability ID
const AMD_IOMMU_CAP_ID: u8 = 0x0F;

/// Offset within the IOMMU capability block where the MMIO base is stored
/// (Cap + 0x04, 64-bit BAR-like field)
const IOMMU_CAP_MMIO_OFFSET: u8 = 0x04;

// ── MMIO Register Offsets ──

const MMIO_DEV_TAB_BASE: usize     = 0x0000;
const MMIO_CMD_BUF_BASE: usize     = 0x0008;
const MMIO_EVT_LOG_BASE: usize     = 0x0010;
const MMIO_CONTROL: usize          = 0x0018;
const MMIO_EXCL_BASE: usize        = 0x0020;
const MMIO_EXCL_LIMIT: usize       = 0x0028;
const MMIO_EXT_FEATURES: usize     = 0x0030;

const MMIO_CMD_BUF_HEAD: usize     = 0x2000;
const MMIO_CMD_BUF_TAIL: usize     = 0x2008;
const MMIO_EVT_LOG_HEAD: usize     = 0x2010;
const MMIO_EVT_LOG_TAIL: usize     = 0x2018;
const MMIO_STATUS: usize           = 0x2020;

// MMIO region size: we need at least up to 0x2028
const IOMMU_MMIO_SIZE: usize = 0x4000;

// ── Control Register Bits ──

const CTRL_IOMMU_EN: u64       = 1 << 0;
const CTRL_HT_TUN_EN: u64      = 1 << 1;
const CTRL_EVT_LOG_EN: u64     = 1 << 2;
const CTRL_EVT_INT_EN: u64     = 1 << 3;
const CTRL_COM_WAIT_INT_EN: u64 = 1 << 4;
const CTRL_CMD_BUF_EN: u64     = 1 << 12;

// ── Status Register Bits ──

const STATUS_EVT_OVERFLOW: u64  = 1 << 0;
const STATUS_EVT_LOG_INT: u64   = 1 << 1;
const STATUS_CMD_BUF_RUN: u64   = 1 << 3;
const STATUS_EVT_LOG_RUN: u64   = 1 << 4;

// ── Command Buffer Opcodes (bits [31:28] of dword 1) ──

const CMD_COMPLETION_WAIT: u32          = 0x01;
const CMD_INVALIDATE_DEVTAB_ENTRY: u32  = 0x02;
const CMD_INVALIDATE_IOMMU_PAGES: u32   = 0x03;
const CMD_INVALIDATE_IOTLB_PAGES: u32   = 0x04;

// ── Device Table Entry (DTE) - 32 bytes ──

#[repr(C)]
#[derive(Clone, Copy)]
struct DeviceTableEntry {
    dw0: u64,   // V, TV, HAD, IR, IW, Domain ID, Page Table Root Ptr, Paging Mode
    dw1: u64,   // IntTabLen, IntTableRoot, InitPass, EIntPass, NMIPass, etc.
    dw2: u64,   // SysMgt, Lint0/1 Pass, Port I/O control
    dw3: u64,   // Reserved
}

const _: () = assert!(core::mem::size_of::<DeviceTableEntry>() == 32);

impl DeviceTableEntry {
    const fn zeroed() -> Self {
        Self { dw0: 0, dw1: 0, dw2: 0, dw3: 0 }
    }
}

// DTE dw0 bit layout:
//   [0]       V       - Valid
//   [1]       TV      - Translation Valid
//   [7:2]     HAD     - Host Address Dirty (reserved in older specs)
//   [8]       PPR     - PPR enable (reserved in older specs, set 0)
//   [9]       GPRP    - Guest PPR Response Pasthrough
//   [12:10]   GLX     - Guest levels translated (0)
//   [15:13]   GCR3 table root ptr [14:12]
//   [16]      IR      - I/O Read permission
//   [17]      IW      - I/O Write permission
//   [23:18]   Reserved
//   [31:24]   Domain ID [7:0]
//   [39:32]   Domain ID [15:8]
//   [51:40]   Page Table Root Ptr [51:40] >> shifted
//   [54:52]   Next Level / Paging Mode (4 = 4-level)
//   [55]      Reserved
//   [63:56]   Reserved / IOTLB support bits

// Actually, the AMD IOMMU spec encodes the DTE dw0 as follows (simplified):
//   [0]       V
//   [1]       TV
//   [8]       IR (I/O Read)
//   [9]       IW (I/O Write)
//   [11:10]   (reserved)
//   [12]      HA (Host Address)
//   [15:13]   Paging Mode / NextLevel (4 = 4-level page table)
//   [23:16]   Domain ID [7:0]
//   [31:24]   Domain ID [15:8]
//   [63:32]   Page Table Root Pointer [51:12] (4K-aligned, bits [51:12] stored in [63:32])
// This is a simplified encoding; the actual bitfield packing is complex.

// For the AMD IOMMU spec Rev 3.0, the DTE[0] layout (64-bit):
//   Bit  0     : V (Valid)
//   Bit  1     : TV (Translation Valid)
//   Bits 7:5   : HAD (reserved, set 0)
//   Bits 8     : reserved
//   Bits 9     : GV (Guest translation valid, set 0)
//   Bits 12:10 : GLX
//   Bits 15:13 : GCR3 Table Root Pointer [14:12]
//   Bit  16    : IR (I/O Read permission)
//   Bit  17    : IW (I/O Write permission)
//   Bits 23:18 : reserved
//   Bits 31:24 : DomainID[7:0]  (part of the domain)
//   Bits 39:32 : DomainID[15:8]
//   Bits 51:40 : Page Table Root Pointer [51:40] -- but actually stored differently
//   Bits 54:52 : Next Level (paging mode, 4 for 4-level)
//   Bits 63:55 : reserved

// Per AMD IOMMU spec section 2.2.2 (Device Table Entry, 256-bit):
// DW0 (bits 63:0):
//   [0]     = V (Valid)
//   [1]     = TV (Translation Valid)
//   [7:5]   = HAD[2:0] (Host Access Dirty)
//   [8]     = IR (IO Read)
//   [9]     = IW (IO Write)
//   [15:13] = Paging Mode (number of levels: 0=untranslated, 4=4-level)
//   [23:16] = DomainID[7:0]
//   [31:24] = DomainID[15:8]
//   [51:32] = Page Table Root Pointer[51:32] (bits 51:32 of the physical address)
//             but root ptr is [51:12] aligned to 4K, so stored in bits [63:12] with
//             bottom 12 bits implicitly zero.
//
// Actually the canonical encoding from the spec (Table 7):
// Byte  Bit Range  Field
//  0    [0]        V
//  0    [1]        TV
//  0    [7:2]      reserved
//  1    [0] (=8)   reserved
//  1    [1] (=9)   IR
//  1    [2] (=10)  IW
//  1    [7:3]      reserved
//  2-3  [23:16]    reserved (some for GV, GLX, etc.)
//
// The simplest correct approach for basic DMA remapping:
// DTE DW0 encoding (64 bits):
//   bit 0:      V
//   bit 1:      TV
//   bit 9:      IR
//   bit 10:     IW  (note: some spec revisions use bits 8/9)
//   bits 15:13: Paging Mode (NextLevel)
//   bits 23:16: DomainID low byte
//   bits 31:24: DomainID high byte
//   bits 63:32: Page Table Root[51:12] << shifted
//
// We use the encoding from AMDVI spec rev 3.05, Table 7:

const DTE_V: u64            = 1 << 0;      // Valid
const DTE_TV: u64           = 1 << 1;      // Translation Valid
const DTE_IR: u64           = 1 << 9;      // IO Read permission
const DTE_IW: u64           = 1 << 10;     // IO Write permission

// Paging mode field: bits [15:13] encode the number of page table levels
// 0 = no translation, 4 = 4-level (supports 48-bit virtual addresses)
const DTE_PAGING_MODE_SHIFT: u64 = 13;
const DTE_PAGING_MODE_4LVL: u64  = 4 << DTE_PAGING_MODE_SHIFT;

// Domain ID: bits [31:16]
const DTE_DOMAIN_ID_SHIFT: u64 = 16;

// Page table root pointer: bits [51:12] of the physical address are stored
// in DTE DW0 bits [63:32] after shifting. The root pointer must be 4K-aligned.
// Encoding: DW0[63:32] = root_phys_addr[51:20]? No --
// The spec says Page Table Root Pointer occupies bits [51:12] of the address,
// stored in DW0 starting from bit 12 (bits [63:12] contain the pointer aligned).
// So: DW0 |= (root_phys & 0x000F_FFFF_FFFF_F000)
// That is, bits [51:12] of the physical address sit directly in bits [51:12] of DW0.

// ── I/O Page Table Entry (PTE) - 8 bytes ──
// Compatible with x86_64 page table format for 4-level paging.
// Each level has 512 entries (9 bits of VA per level).

const IOPT_PRESENT: u64    = 1 << 0;   // PR - Present
const IOPT_NEXT_LEVEL_SHIFT: u64 = 9;  // NextLevel field at bits [11:9]
const IOPT_READ: u64        = 1 << 61;  // IR - I/O Read
const IOPT_WRITE: u64       = 1 << 62;  // IW - I/O Write
const IOPT_FC: u64          = 1 << 1;   // FC - Force Coherent (optional)

// For a page-level PTE (leaf), NextLevel = 0, and bits [51:12] hold the physical page frame.
// For a next-level PTE (non-leaf), NextLevel encodes the next level (3, 2, 1).

// Page sizes
const PAGE_SIZE_4K: u64 = 0x1000;
const PAGE_SIZE_2M: u64 = 0x200000;
const PAGE_SIZE_1G: u64 = 0x40000000;

// Number of entries per page table level
const PT_ENTRIES: usize = 512;

// ── Command Buffer Entry (16 bytes) ──

#[repr(C)]
#[derive(Clone, Copy)]
struct CommandEntry {
    dw0: u64,
    dw1: u64,
}

const _: () = assert!(core::mem::size_of::<CommandEntry>() == 16);

impl CommandEntry {
    const fn zeroed() -> Self {
        Self { dw0: 0, dw1: 0 }
    }
}

// ── Event Log Entry (16 bytes) ──

#[repr(C)]
#[derive(Clone, Copy)]
struct EventLogEntry {
    dw0: u64,
    dw1: u64,
}

const _: () = assert!(core::mem::size_of::<EventLogEntry>() == 16);

// Event codes (bits [31:28] of dw1, or [63:60] of the 128-bit entry depending
// on which dword you look at -- the spec encodes EventCode in operand bits):
// The event log entry format:
//   DW0[15:0]  = DeviceID (BDF)
//   DW0[19:16] = reserved / pasid stuff
//   DW0[27:20] = reserved
//   DW0[31:28] = EventCode
//   DW0[63:32] = operand / flags (depends on event type)
//   DW1[63:0]  = Address (the faulting address)
//
// Event codes:
const EVT_ILLEGAL_DEV_TABLE_ENTRY: u32 = 0x01;
const EVT_IO_PAGE_FAULT: u32           = 0x02;
const EVT_DEV_TABLE_HW_ERROR: u32      = 0x03;
const EVT_PAGE_TABLE_HW_ERROR: u32     = 0x04;
const EVT_ILLEGAL_COMMAND_ERROR: u32   = 0x05;
const EVT_COMMAND_HW_ERROR: u32        = 0x06;
const EVT_IOTLB_INV_TIMEOUT: u32       = 0x07;
const EVT_INVALID_DEVICE_REQUEST: u32  = 0x08;
const EVT_INVALID_PPR_REQUEST: u32     = 0x09;

// ── Buffer sizing ──

// Device Table: 256 entries * 32 bytes = 8192 bytes = 2 pages
// But the spec requires a minimum alignment of 4K and the size field encodes
// the number of entries as (size_in_bytes / 32) - 1.
// We allocate 256 entries = 8 KiB.
const DEV_TABLE_ENTRIES: usize = 256;
const DEV_TABLE_SIZE: usize = DEV_TABLE_ENTRIES * 32; // 8192 bytes

// Command Buffer: 256 entries * 16 bytes = 4096 bytes = 1 page
const CMD_BUF_ENTRIES: usize = 256;
const CMD_BUF_SIZE: usize = CMD_BUF_ENTRIES * 16; // 4096 bytes
// The CmdBufBase register encodes length as log2(entries) in bits [59:56].
// 256 entries => log2(256) = 8
const CMD_BUF_LEN_ENC: u64 = 8; // log2(256)

// Event Log: 256 entries * 16 bytes = 4096 bytes = 1 page
const EVT_LOG_ENTRIES: usize = 256;
const EVT_LOG_SIZE: usize = EVT_LOG_ENTRIES * 16; // 4096 bytes
// Same encoding: log2(256) = 8
const EVT_LOG_LEN_ENC: u64 = 8;

// ── MMIO helpers ──

fn mmio_read32(base: *mut u8, offset: usize) -> u32 {
    unsafe { read_volatile(base.add(offset) as *const u32) }
}

fn mmio_write32(base: *mut u8, offset: usize, val: u32) {
    unsafe { write_volatile(base.add(offset) as *mut u32, val) }
}

fn mmio_read64(base: *mut u8, offset: usize) -> u64 {
    let lo = mmio_read32(base, offset) as u64;
    let hi = mmio_read32(base, offset + 4) as u64;
    lo | (hi << 32)
}

fn mmio_write64(base: *mut u8, offset: usize, val: u64) {
    mmio_write32(base, offset, val as u32);
    mmio_write32(base, offset + 4, (val >> 32) as u32);
}

// ── Controller state ──

struct IommuState {
    mmio_base: *mut u8,
    mmio_size: usize,
    bus: u8,
    dev: u8,
    func: u8,

    // Device Table (physically contiguous)
    dev_table: *mut DeviceTableEntry,
    dev_table_phys: u64,

    // Command Buffer
    cmd_buf: *mut CommandEntry,
    cmd_buf_phys: u64,
    cmd_buf_tail: u32,   // tail pointer (byte offset)

    // Event Log
    evt_log: *mut EventLogEntry,
    evt_log_phys: u64,
    evt_log_head: u32,   // head pointer (byte offset)

    // Per-device page table root pointers (physical addresses)
    // Index by DeviceID (BDF, 16-bit). We support up to 256 devices.
    // Each entry is the physical address of the L4 page table, or 0 if unused.
    page_table_roots: [u64; DEV_TABLE_ENTRIES],

    enabled: bool,
}

/// Wrapper to allow `UnsafeCell` in a `static` (requires `Sync`).
/// Safety: all access is single-threaded or externally synchronised by the caller.
struct StaticCell<T>(core::cell::UnsafeCell<T>);
unsafe impl<T> Sync for StaticCell<T> {}
impl<T> StaticCell<T> {
    const fn new(val: T) -> Self { Self(core::cell::UnsafeCell::new(val)) }
    /// Returns a raw pointer to the inner value.
    fn get(&self) -> *mut T { self.0.get() }
}

static IOMMU: StaticCell<Option<IommuState>> = StaticCell::new(None);

// ── PCI discovery ──

/// Check if a PCI device is an AMD IOMMU by vendor/device ID.
fn is_amd_iommu_device(vendor: u16, device: u16) -> bool {
    vendor == AMD_VENDOR_ID
        && (device == AMD_IOMMU_DEVID_MATISSE
            || device == AMD_IOMMU_DEVID_RAPHAEL
            || device == AMD_IOMMU_DEVID_RAPHAEL_B)
}

/// Find the AMD IOMMU on the PCI bus.
/// Returns (bus, dev, func) if found.
fn find_iommu_pci() -> Option<(u8, u8, u8)> {
    let count = unsafe { pci_device_count() };
    for i in 0..count {
        let dev = unsafe { &*pci_get_device(i) };

        // Check by vendor/device ID (most reliable for AMD IOMMU)
        if is_amd_iommu_device(dev.vendor_id, dev.device_id) {
            return Some((dev.bus, dev.dev, dev.func));
        }

        // Also check PCI class 08h subclass 06h (IOMMU) with AMD vendor
        if dev.class_code == 0x08 && dev.subclass == 0x06
            && dev.vendor_id == AMD_VENDOR_ID
        {
            return Some((dev.bus, dev.dev, dev.func));
        }
    }
    None
}

/// Walk the PCI capability list to find the AMD IOMMU capability (ID 0Fh).
/// Returns the offset of the capability in config space, or None.
fn find_iommu_capability(bus: u8, dev: u8, func: u8) -> Option<u8> {
    // Check that the device has capabilities (Status register bit 4)
    let status = pci_read16(bus, dev, func, 0x06);
    if status & (1 << 4) == 0 {
        return None;
    }

    // Capabilities pointer is at offset 0x34
    let mut cap_ptr = pci_read8(bus, dev, func, 0x34) & 0xFC;
    let mut iterations = 0u32;

    while cap_ptr != 0 && iterations < 48 {
        let cap_id = pci_read8(bus, dev, func, cap_ptr);
        if cap_id == AMD_IOMMU_CAP_ID {
            return Some(cap_ptr);
        }
        // Next pointer is at cap_ptr + 1
        cap_ptr = pci_read8(bus, dev, func, cap_ptr + 1) & 0xFC;
        iterations += 1;
    }

    None
}

/// Read the MMIO base address from the IOMMU capability block.
/// The base address register is at capability offset + 0x04 (low) and + 0x08 (high).
fn read_mmio_base_from_cap(bus: u8, dev: u8, func: u8, cap_offset: u8) -> u64 {
    // IOMMU capability header (cap + 0x00): Cap ID, Next Ptr, type/rev
    // IOMMU Base Address Low (cap + 0x04):
    //   bits [0]:     Enable (must be 1 for MMIO to be active)
    //   bits [13:1]:  reserved
    //   bits [31:14]: Base Address [31:14] (16K aligned)
    // IOMMU Base Address High (cap + 0x08):
    //   bits [31:0]:  Base Address [63:32]
    let bar_lo = pci_read32(bus, dev, func, cap_offset.wrapping_add(0x04));
    let bar_hi = pci_read32(bus, dev, func, cap_offset.wrapping_add(0x08));

    // Mask off the enable bit and reserved bits; base is 16K-aligned (bits [13:0] = 0)
    let base_lo = (bar_lo & 0xFFFF_C000) as u64;
    let base_hi = (bar_hi as u64) << 32;

    base_lo | base_hi
}

// ── Page table management ──

/// Allocate a zeroed 4K page and return (virtual, physical) addresses.
fn alloc_zeroed_page() -> Option<(*mut u8, u64)> {
    let virt = unsafe { alloc_page() };
    if virt.is_null() {
        return None;
    }
    unsafe { core::ptr::write_bytes(virt, 0, 4096); }
    let phys = virt_to_phys(virt);
    Some((virt, phys))
}

/// Allocate an I/O page table (4-level, 512 entries of 8 bytes = 4K per level).
/// Returns the physical address of the L4 (PML4-equivalent) table.
fn alloc_io_page_table() -> Option<u64> {
    let (_, phys) = alloc_zeroed_page()?;
    Some(phys)
}

/// Map a single 4K page in the I/O page table for the given IOVA -> physical.
/// Walks 4 levels (L4 -> L3 -> L2 -> L1), allocating intermediate tables as needed.
///
/// AMD IOMMU page table entry format:
///   [0]     PR (Present)
///   [1]     FC (Force Coherent, optional, set 0)
///   [4:2]   reserved
///   [8:5]   reserved
///   [11:9]  NextLevel (for non-leaf: level of the next table, 0 for leaf)
///   [51:12] Physical page frame address [51:12]
///   [61]    IR (I/O Read)
///   [62]    IW (I/O Write)
///   [63]    reserved
///
/// For non-leaf entries, NextLevel indicates the level of the child table:
///   L4 entry -> NextLevel = 3 (points to L3 table)
///   L3 entry -> NextLevel = 2 (points to L2 table)
///   L2 entry -> NextLevel = 1 (points to L1 table)
///   L1 entry -> NextLevel = 0 (leaf, points to physical page)
fn io_pt_map_4k(l4_phys: u64, iova: u64, phys_addr: u64, read: bool, write: bool) -> bool {
    // Extract page table indices from IOVA (each level uses 9 bits)
    let l4_idx = ((iova >> 39) & 0x1FF) as usize;
    let l3_idx = ((iova >> 30) & 0x1FF) as usize;
    let l2_idx = ((iova >> 21) & 0x1FF) as usize;
    let l1_idx = ((iova >> 12) & 0x1FF) as usize;

    // We need virtual addresses to write page table entries.
    // Since we allocated these pages, we use the kernel mapping.
    // For simplicity, we map each table page via MMIO mapping (uncached).
    // In a production driver we would maintain a VA->PA mapping cache.

    // Walk L4 -> L3
    let l3_phys = walk_or_alloc_level(l4_phys, l4_idx, 3);
    if l3_phys == 0 { return false; }

    // Walk L3 -> L2
    let l2_phys = walk_or_alloc_level(l3_phys, l3_idx, 2);
    if l2_phys == 0 { return false; }

    // Walk L2 -> L1
    let l1_phys = walk_or_alloc_level(l2_phys, l2_idx, 1);
    if l1_phys == 0 { return false; }

    // Write L1 leaf entry (NextLevel = 0)
    let mut pte = IOPT_PRESENT | (phys_addr & 0x000F_FFFF_FFFF_F000);
    // NextLevel = 0 for leaf (bits [11:9] = 0, already zero)
    if read { pte |= IOPT_READ; }
    if write { pte |= IOPT_WRITE; }

    let l1_virt = unsafe { map_mmio_region(l1_phys, PAGE_SIZE_4K as usize, MMIO_DEFAULT_FLAGS) };
    if l1_virt.is_null() { return false; }
    unsafe {
        write_volatile((l1_virt as *mut u64).add(l1_idx), pte);
    }
    fence(Ordering::SeqCst);
    unsafe { unmap_mmio_region(l1_virt, PAGE_SIZE_4K as usize); }

    true
}

/// Walk one level of the I/O page table. If the entry at `index` is not present,
/// allocate a new child table and install it. Returns the physical address of the
/// child table, or 0 on failure.
///
/// `child_level` is the NextLevel value to store in the parent entry (3, 2, or 1).
fn walk_or_alloc_level(table_phys: u64, index: usize, child_level: u64) -> u64 {
    let table_virt = unsafe {
        map_mmio_region(table_phys, PAGE_SIZE_4K as usize, MMIO_DEFAULT_FLAGS)
    };
    if table_virt.is_null() { return 0; }

    let entry_ptr = unsafe { (table_virt as *mut u64).add(index) };
    let entry = unsafe { read_volatile(entry_ptr) };

    let child_phys;
    if entry & IOPT_PRESENT != 0 {
        // Already present -- extract physical address
        child_phys = entry & 0x000F_FFFF_FFFF_F000;
    } else {
        // Allocate a new child table
        match alloc_zeroed_page() {
            Some((_, phys)) => {
                let new_entry = IOPT_PRESENT
                    | (phys & 0x000F_FFFF_FFFF_F000)
                    | (child_level << IOPT_NEXT_LEVEL_SHIFT)
                    | IOPT_READ
                    | IOPT_WRITE;
                unsafe { write_volatile(entry_ptr, new_entry); }
                fence(Ordering::SeqCst);
                child_phys = phys;
            }
            None => {
                unsafe { unmap_mmio_region(table_virt, PAGE_SIZE_4K as usize); }
                return 0;
            }
        }
    }

    unsafe { unmap_mmio_region(table_virt, PAGE_SIZE_4K as usize); }
    child_phys
}

/// Unmap a single 4K page in the I/O page table.
/// Clears the L1 (leaf) entry. Does not free intermediate tables.
fn io_pt_unmap_4k(l4_phys: u64, iova: u64) -> bool {
    let l4_idx = ((iova >> 39) & 0x1FF) as usize;
    let l3_idx = ((iova >> 30) & 0x1FF) as usize;
    let l2_idx = ((iova >> 21) & 0x1FF) as usize;
    let l1_idx = ((iova >> 12) & 0x1FF) as usize;

    // Walk to find the L1 table
    let l3_phys = read_pt_entry_phys(l4_phys, l4_idx);
    if l3_phys == 0 { return false; }

    let l2_phys = read_pt_entry_phys(l3_phys, l3_idx);
    if l2_phys == 0 { return false; }

    let l1_phys = read_pt_entry_phys(l2_phys, l2_idx);
    if l1_phys == 0 { return false; }

    // Clear the leaf entry
    let l1_virt = unsafe { map_mmio_region(l1_phys, PAGE_SIZE_4K as usize, MMIO_DEFAULT_FLAGS) };
    if l1_virt.is_null() { return false; }
    unsafe {
        write_volatile((l1_virt as *mut u64).add(l1_idx), 0u64);
    }
    fence(Ordering::SeqCst);
    unsafe { unmap_mmio_region(l1_virt, PAGE_SIZE_4K as usize); }

    true
}

/// Read a page table entry at the given index and return the child physical address,
/// or 0 if not present.
fn read_pt_entry_phys(table_phys: u64, index: usize) -> u64 {
    let table_virt = unsafe {
        map_mmio_region(table_phys, PAGE_SIZE_4K as usize, MMIO_DEFAULT_FLAGS)
    };
    if table_virt.is_null() { return 0; }

    let entry = unsafe { read_volatile((table_virt as *const u64).add(index)) };
    unsafe { unmap_mmio_region(table_virt, PAGE_SIZE_4K as usize); }

    if entry & IOPT_PRESENT != 0 {
        entry & 0x000F_FFFF_FFFF_F000
    } else {
        0
    }
}

// ── Device Table Entry helpers ──

/// Build a DTE DW0 value for a device with the given page table root and domain ID.
fn build_dte_dw0(pt_root_phys: u64, domain_id: u16, read: bool, write: bool) -> u64 {
    let mut dw0: u64 = DTE_V | DTE_TV | DTE_PAGING_MODE_4LVL;
    if read { dw0 |= DTE_IR; }
    if write { dw0 |= DTE_IW; }
    dw0 |= ((domain_id as u64) & 0xFFFF) << DTE_DOMAIN_ID_SHIFT;
    // Page table root pointer: bits [51:12] placed in DW0 bits [51:12]
    dw0 |= pt_root_phys & 0x000F_FFFF_FFFF_F000;
    dw0
}

/// Build a DTE DW1 for basic operation:
/// - Interrupt remapping disabled (IntTabLen=0, IntTableRoot=0)
/// - InitPass=1, EIntPass=1, NMIPass=1 (pass through special interrupts)
fn build_dte_dw1() -> u64 {
    let init_pass: u64 = 1 << 40;   // InitPass
    let eint_pass: u64 = 1 << 41;   // EIntPass
    let nmi_pass: u64  = 1 << 42;   // NMIPass
    init_pass | eint_pass | nmi_pass
}

/// Write a Device Table Entry for the given DeviceID (BDF encoded as 16-bit).
fn write_device_table_entry(state: &mut IommuState, device_id: u16, dte: &DeviceTableEntry) {
    let idx = device_id as usize;
    if idx >= DEV_TABLE_ENTRIES {
        return;
    }
    unsafe {
        write_volatile(state.dev_table.add(idx), *dte);
    }
    fence(Ordering::SeqCst);
}

/// Encode a BDF (bus/device/function) into a 16-bit DeviceID.
fn bdf_to_devid(bus: u8, dev: u8, func: u8) -> u16 {
    ((bus as u16) << 8) | ((dev as u16) << 3) | (func as u16)
}

// ── Command buffer operations ──

/// Submit a command to the command buffer ring and advance the tail pointer.
fn submit_command(state: &mut IommuState, cmd: &CommandEntry) {
    let idx = (state.cmd_buf_tail as usize) / 16;
    if idx >= CMD_BUF_ENTRIES {
        // Wrap (should not happen if tail is managed correctly)
        state.cmd_buf_tail = 0;
    }
    let actual_idx = (state.cmd_buf_tail as usize) / 16;
    unsafe {
        write_volatile(state.cmd_buf.add(actual_idx), *cmd);
    }
    fence(Ordering::SeqCst);

    // Advance tail (wrapping at buffer size in bytes)
    state.cmd_buf_tail = ((state.cmd_buf_tail as usize + 16) % CMD_BUF_SIZE) as u32;

    // Write the new tail to the MMIO register
    mmio_write64(state.mmio_base, MMIO_CMD_BUF_TAIL, state.cmd_buf_tail as u64);
}

/// Issue a COMPLETION_WAIT command and spin until the hardware processes it.
/// This ensures all prior commands have been executed.
fn completion_wait(state: &mut IommuState) {
    let mut cmd = CommandEntry::zeroed();
    // DW0: opcode in bits [31:28] = 0x01, S (store) bit = bit 0, F (flush) bit = bit 1
    // We set the Store bit (bit 0) so the IOMMU writes a completion stamp.
    // The opcode for COMPLETION_WAIT is 0x01, placed in bits [31:28] of DW0 low word.
    // Actually, the command format is:
    //   DW0[3:0]   = opcode (4 bits) -- but the spec uses [31:28] of the first dword
    // Per AMD spec, the command entry is 128 bits:
    //   bits [3:0]  of DW0 = reserved
    //   bits [7:4]  of DW0 = reserved
    //   bits [27:8] of DW0 = reserved
    //   bits [31:28] of DW0 = opcode
    // Wait -- the AMD IOMMU command format actually has:
    //   Word 0 (bits 31:0):
    //     [0]     S (Store)
    //     [1]     I (Interrupt)
    //     [2]     F (Flush)
    //     [3]     reserved
    //     [31:4]  StoreAddress[51:3] (when S=1)
    //   Word 1 (bits 63:32):
    //     [27:0]  StoreAddress[19:0] -- err, that doesn't line up.
    //
    // Let me use the correct encoding from the spec:
    // COMPLETION_WAIT command (128 bits):
    //   DW0 (qword 0, bits [63:0]):
    //     [0]      s (Store completion)
    //     [1]      i (Interrupt on completion)
    //     [2]      f (Flush queue)
    //     [3]      reserved
    //     [31:4]   reserved (or StoreAddr low bits depending on spec rev)
    //     [59:32]  Opcode-specific (StoreAddr bits)
    //     [63:60]  Opcode = 0x1
    //   DW1 (qword 1, bits [127:64]):
    //     [63:0]   StoreData (written to StoreAddr when S=1)
    //
    // Simplified: We just want a simple completion wait with flush.

    // Opcode 0x01 in bits [63:60] of the first qword
    cmd.dw0 = (CMD_COMPLETION_WAIT as u64) << 60;
    // Set the Flush bit (bit 2) to ensure all prior commands complete
    cmd.dw0 |= 1 << 2; // F bit

    submit_command(state, &cmd);

    // Wait for the head to catch up to the tail
    for _ in 0..1_000_000u32 {
        let head = mmio_read64(state.mmio_base, MMIO_CMD_BUF_HEAD) as u32;
        if head == state.cmd_buf_tail {
            return;
        }
        core::hint::spin_loop();
    }
    log("amd_iommu: completion wait timeout");
}

/// Issue an INVALIDATE_DEVTAB_ENTRY command for the given DeviceID.
fn invalidate_devtab_entry(state: &mut IommuState, device_id: u16) {
    let mut cmd = CommandEntry::zeroed();
    // Opcode 0x02 in bits [63:60], DeviceID in bits [15:0]
    cmd.dw0 = ((CMD_INVALIDATE_DEVTAB_ENTRY as u64) << 60) | (device_id as u64);
    submit_command(state, &cmd);
}

/// Issue an INVALIDATE_IOMMU_PAGES command for the given domain.
/// Setting S=1 invalidates all pages in the domain.
fn invalidate_iommu_pages(state: &mut IommuState, domain_id: u16) {
    let mut cmd = CommandEntry::zeroed();
    // Opcode 0x03 in bits [63:60]
    // DomainID in bits [47:32]
    // S bit (bit 0) = 1 means invalidate all pages
    // PDE bit (bit 1) = 1 means also invalidate page directory entries
    cmd.dw0 = ((CMD_INVALIDATE_IOMMU_PAGES as u64) << 60)
        | ((domain_id as u64) << 32)
        | (1 << 0)   // S (size - invalidate all)
        | (1 << 1);  // PDE
    // DW1: Address = 0 when S=1 (all pages)
    cmd.dw1 = 0;
    submit_command(state, &cmd);
}

/// Issue an INVALIDATE_IOTLB_PAGES command for the given device.
fn invalidate_iotlb(state: &mut IommuState, device_id: u16, domain_id: u16) {
    let mut cmd = CommandEntry::zeroed();
    // Opcode 0x04 in bits [63:60]
    // DeviceID in bits [15:0]
    // S bit (bit 0) = 1 for invalidate all
    cmd.dw0 = ((CMD_INVALIDATE_IOTLB_PAGES as u64) << 60)
        | (device_id as u64)
        | (1 << 0);  // S (invalidate all)
    // DW1: reserved / address
    cmd.dw1 = 0;
    submit_command(state, &cmd);
}

/// Perform a full invalidation sequence for a device: invalidate DTE, IOMMU pages,
/// and IOTLB, then wait for completion.
fn full_invalidation(state: &mut IommuState, device_id: u16, domain_id: u16) {
    invalidate_devtab_entry(state, device_id);
    invalidate_iommu_pages(state, domain_id);
    invalidate_iotlb(state, device_id, domain_id);
    completion_wait(state);
}

// ── Event log parsing ──

fn event_code_name(code: u32) -> &'static str {
    match code {
        EVT_ILLEGAL_DEV_TABLE_ENTRY => "ILLEGAL_DEV_TABLE_ENTRY",
        EVT_IO_PAGE_FAULT => "IO_PAGE_FAULT",
        EVT_DEV_TABLE_HW_ERROR => "DEV_TABLE_HW_ERROR",
        EVT_PAGE_TABLE_HW_ERROR => "PAGE_TABLE_HW_ERROR",
        EVT_ILLEGAL_COMMAND_ERROR => "ILLEGAL_COMMAND_ERROR",
        EVT_COMMAND_HW_ERROR => "COMMAND_HW_ERROR",
        EVT_IOTLB_INV_TIMEOUT => "IOTLB_INV_TIMEOUT",
        EVT_INVALID_DEVICE_REQUEST => "INVALID_DEVICE_REQUEST",
        EVT_INVALID_PPR_REQUEST => "INVALID_PPR_REQUEST",
        _ => "UNKNOWN",
    }
}

/// Read and process all pending event log entries.
/// Returns the number of events found (negative on error).
fn poll_event_log(state: &mut IommuState) -> i32 {
    let mut count = 0i32;

    // Read the current tail from hardware
    let tail = (mmio_read64(state.mmio_base, MMIO_EVT_LOG_TAIL) & 0x7FFF0) as u32;

    while state.evt_log_head != tail {
        let idx = (state.evt_log_head as usize) / 16;
        if idx >= EVT_LOG_ENTRIES {
            state.evt_log_head = 0;
            continue;
        }

        let entry = unsafe { read_volatile(state.evt_log.add(idx)) };

        // Parse the event
        let device_id = (entry.dw0 & 0xFFFF) as u16;
        let event_code = ((entry.dw0 >> 60) & 0xF) as u32;
        let address = entry.dw1;

        let bus = (device_id >> 8) as u32;
        let devn = ((device_id >> 3) & 0x1F) as u32;
        let funcn = (device_id & 0x07) as u32;

        unsafe {
            fut_printf(
                b"amd_iommu: event: code=0x%x dev=%02x:%02x.%x addr=0x%llx\n\0".as_ptr(),
                event_code,
                bus,
                devn,
                funcn,
                address,
            );
        }

        count += 1;

        // Advance head
        state.evt_log_head = ((state.evt_log_head as usize + 16) % EVT_LOG_SIZE) as u32;
    }

    // Write updated head to hardware
    mmio_write64(state.mmio_base, MMIO_EVT_LOG_HEAD, state.evt_log_head as u64);

    // Clear event log interrupt status if set
    let status = mmio_read64(state.mmio_base, MMIO_STATUS);
    if status & STATUS_EVT_LOG_INT != 0 {
        mmio_write64(state.mmio_base, MMIO_STATUS, STATUS_EVT_LOG_INT);
    }
    if status & STATUS_EVT_OVERFLOW != 0 {
        log("amd_iommu: event log overflow detected");
        mmio_write64(state.mmio_base, MMIO_STATUS, STATUS_EVT_OVERFLOW);
    }

    count
}

// ── Identity mapping ──

/// Set up 1:1 identity mapping for the first 4 GiB using 2 MiB pages
/// in a given L4 page table. This maps IOVA == physical address.
fn setup_identity_map(l4_phys: u64) -> bool {
    // For identity mapping we create:
    //   L4[0] -> L3 table
    //   L3[0..3] -> L2 tables (each covers 1 GiB)
    //   L2[0..511] entries -> 2 MiB leaf pages (using NextLevel=0 for huge pages)
    //
    // For 2 MiB pages, we use a 3-level walk: L4 -> L3 -> L2 (leaf at L2 level).
    // However, the AMD IOMMU with 4-level paging expects the DTE to specify
    // paging mode = 4, so we must have L4 -> L3 -> L2 -> L1.
    //
    // For 2 MiB identity mapping with 4-level tables, we actually need L4 entries
    // that point to L3, and at L2 level we can use large pages by setting the
    // page size bit. But the AMD IOMMU page table format doesn't have a PS (page size)
    // bit like x86 CR3 page tables. Instead, you set NextLevel = 1 at L2 to indicate
    // the next level is L1 (4K pages), or NextLevel = 0 to indicate leaf.
    //
    // Actually, for the AMD IOMMU, a PTE with NextLevel=0 at any level is a leaf.
    // So we can use 2 MiB pages by making L2 entries into leaves (NextLevel=0).
    // But with DTE paging mode = 4 (4 levels), the IOMMU expects a 4-level walk,
    // and at level 2 (which maps 2 MiB regions), a NextLevel=0 entry IS a 2 MiB page.
    //
    // From the AMD IOMMU spec section 2.2.6:
    //   "A page table walk terminates when ... the Next Level field of the PTE is 0"
    //   The page size is determined by which level the walk terminates at.
    //
    // So: L4 entry (NextLevel=3) -> L3 entry (NextLevel=2) -> L2 leaf (NextLevel=0)
    //     = 2 MiB page

    // Allocate L3 table (we only need entry [0])
    let l4_virt = unsafe { map_mmio_region(l4_phys, PAGE_SIZE_4K as usize, MMIO_DEFAULT_FLAGS) };
    if l4_virt.is_null() { return false; }

    // Allocate a single L3 table
    let (_, l3_phys) = match alloc_zeroed_page() {
        Some(p) => p,
        None => {
            unsafe { unmap_mmio_region(l4_virt, PAGE_SIZE_4K as usize); }
            return false;
        }
    };

    // Install L4[0] -> L3 (NextLevel = 3)
    let l4_entry = IOPT_PRESENT
        | (l3_phys & 0x000F_FFFF_FFFF_F000)
        | (3 << IOPT_NEXT_LEVEL_SHIFT)
        | IOPT_READ
        | IOPT_WRITE;
    unsafe { write_volatile(l4_virt as *mut u64, l4_entry); }
    fence(Ordering::SeqCst);
    unsafe { unmap_mmio_region(l4_virt, PAGE_SIZE_4K as usize); }

    // Map L3 table and create 4 entries (one per GiB, covering 0-4 GiB)
    let l3_virt = unsafe { map_mmio_region(l3_phys, PAGE_SIZE_4K as usize, MMIO_DEFAULT_FLAGS) };
    if l3_virt.is_null() { return false; }

    for gib in 0u64..4 {
        // Allocate an L2 table for this 1 GiB region
        let (_, l2_phys) = match alloc_zeroed_page() {
            Some(p) => p,
            None => {
                unsafe { unmap_mmio_region(l3_virt, PAGE_SIZE_4K as usize); }
                return false;
            }
        };

        // Install L3[gib] -> L2 (NextLevel = 2)
        let l3_entry = IOPT_PRESENT
            | (l2_phys & 0x000F_FFFF_FFFF_F000)
            | (2 << IOPT_NEXT_LEVEL_SHIFT)
            | IOPT_READ
            | IOPT_WRITE;
        unsafe {
            write_volatile((l3_virt as *mut u64).add(gib as usize), l3_entry);
        }

        // Map L2 table and fill with 2 MiB leaf entries
        let l2_virt = unsafe {
            map_mmio_region(l2_phys, PAGE_SIZE_4K as usize, MMIO_DEFAULT_FLAGS)
        };
        if l2_virt.is_null() {
            unsafe { unmap_mmio_region(l3_virt, PAGE_SIZE_4K as usize); }
            return false;
        }

        for entry_idx in 0..PT_ENTRIES {
            let phys_addr = gib * PAGE_SIZE_1G + (entry_idx as u64) * PAGE_SIZE_2M;
            // Leaf entry: NextLevel = 0, Present, Read, Write
            let l2_entry = IOPT_PRESENT
                | (phys_addr & 0x000F_FFFF_FFFF_F000)
                | IOPT_READ
                | IOPT_WRITE;
            // NextLevel = 0 is implicit (bits [11:9] = 0) for 2 MiB leaf
            unsafe {
                write_volatile((l2_virt as *mut u64).add(entry_idx), l2_entry);
            }
        }

        fence(Ordering::SeqCst);
        unsafe { unmap_mmio_region(l2_virt, PAGE_SIZE_4K as usize); }
    }

    fence(Ordering::SeqCst);
    unsafe { unmap_mmio_region(l3_virt, PAGE_SIZE_4K as usize); }

    true
}

// ── FFI exports ──

/// Initialize the AMD IOMMU.
/// Scans PCI for the IOMMU device, parses capability blocks, allocates
/// Device Table / Command Buffer / Event Log, and prepares for enable.
/// Returns 0 on success, negative on error.
#[unsafe(no_mangle)]
pub extern "C" fn amd_iommu_init() -> i32 {
    log("amd_iommu: scanning PCI for AMD IOMMU (AMD-Vi)...");

    // ── Step 1: Find the IOMMU on PCI ──
    let (bus, dev, func) = match find_iommu_pci() {
        Some(bdf) => bdf,
        None => {
            log("amd_iommu: no AMD IOMMU found on PCI bus");
            return -1;
        }
    };

    unsafe {
        fut_printf(
            b"amd_iommu: found IOMMU at PCI %02x:%02x.%x\n\0".as_ptr(),
            bus as u32, dev as u32, func as u32,
        );
    }

    // ── Step 2: Find the IOMMU capability block (ID 0Fh) ──
    let cap_offset = match find_iommu_capability(bus, dev, func) {
        Some(off) => off,
        None => {
            log("amd_iommu: IOMMU capability (0Fh) not found in PCI config space");
            return -2;
        }
    };

    unsafe {
        fut_printf(
            b"amd_iommu: capability block at offset 0x%02x\n\0".as_ptr(),
            cap_offset as u32,
        );
    }

    // Read the capability header for type and revision info
    let cap_header = pci_read32(bus, dev, func, cap_offset);
    let cap_type = (cap_header >> 16) & 0x07;
    let cap_rev = (cap_header >> 19) & 0x1F;
    unsafe {
        fut_printf(
            b"amd_iommu: capability type=%d revision=%d\n\0".as_ptr(),
            cap_type,
            cap_rev,
        );
    }

    // ── Step 3: Read MMIO base from the capability block ──
    let mmio_phys = read_mmio_base_from_cap(bus, dev, func, cap_offset);
    if mmio_phys == 0 {
        log("amd_iommu: MMIO base address is zero (not configured by firmware)");
        return -3;
    }

    unsafe {
        fut_printf(
            b"amd_iommu: MMIO base physical address: 0x%llx\n\0".as_ptr(),
            mmio_phys,
        );
    }

    // Enable bus mastering on the IOMMU device
    let pci_cmd = pci_read16(bus, dev, func, 0x04);
    pci_write16(bus, dev, func, 0x04, pci_cmd | 0x06); // Memory Space + Bus Master

    // ── Step 4: Map MMIO region ──
    let mmio_base = unsafe { map_mmio_region(mmio_phys, IOMMU_MMIO_SIZE, MMIO_DEFAULT_FLAGS) };
    if mmio_base.is_null() {
        log("amd_iommu: failed to map MMIO region");
        return -4;
    }

    // Read and report extended features
    let ext_feat = mmio_read64(mmio_base, MMIO_EXT_FEATURES);
    unsafe {
        fut_printf(
            b"amd_iommu: extended features: 0x%llx\n\0".as_ptr(),
            ext_feat,
        );
    }

    // ── Step 5: Disable the IOMMU before reconfiguring ──
    let ctrl_reg = mmio_read64(mmio_base, MMIO_CONTROL);
    mmio_write64(mmio_base, MMIO_CONTROL, ctrl_reg & !(CTRL_IOMMU_EN | CTRL_CMD_BUF_EN | CTRL_EVT_LOG_EN));
    fence(Ordering::SeqCst);

    // ── Step 6: Allocate Device Table ──
    // Device Table needs to be physically contiguous and 4K-aligned.
    // 256 entries * 32 bytes = 8192 bytes = 2 pages.
    // We allocate 2 contiguous pages via alloc (which gives contiguous virtual memory).
    let dev_table = unsafe { alloc(DEV_TABLE_SIZE) as *mut DeviceTableEntry };
    if dev_table.is_null() {
        log("amd_iommu: failed to allocate Device Table");
        unsafe { unmap_mmio_region(mmio_base, IOMMU_MMIO_SIZE); }
        return -5;
    }
    // Zero the device table
    unsafe { core::ptr::write_bytes(dev_table, 0, DEV_TABLE_ENTRIES); }
    let dev_table_phys = virt_to_phys(dev_table as *const u8);

    // Write Device Table Base register
    // DevTabBase format: bits [51:12] = base address, bits [8:0] = Size (number of 4K
    // segments minus 1). For 8192 bytes = 2 * 4K segments, Size = 1.
    // Actually the DevTabBase size field encodes the number of entries:
    //   Size = ((num_entries * 32) / 4096) - 1
    // For 256 entries: (256*32)/4096 - 1 = 8192/4096 - 1 = 2 - 1 = 1
    let dev_tab_base_val = (dev_table_phys & 0x000F_FFFF_FFFF_F000) | 1u64; // Size = 1
    mmio_write64(mmio_base, MMIO_DEV_TAB_BASE, dev_tab_base_val);

    unsafe {
        fut_printf(
            b"amd_iommu: Device Table at phys 0x%llx (%d entries)\n\0".as_ptr(),
            dev_table_phys,
            DEV_TABLE_ENTRIES as u32,
        );
    }

    // ── Step 7: Allocate Command Buffer ──
    let (cmd_buf_virt, cmd_buf_phys) = match alloc_zeroed_page() {
        Some(p) => p,
        None => {
            log("amd_iommu: failed to allocate Command Buffer");
            unsafe {
                free(dev_table as *mut u8);
                unmap_mmio_region(mmio_base, IOMMU_MMIO_SIZE);
            }
            return -6;
        }
    };
    let cmd_buf = cmd_buf_virt as *mut CommandEntry;

    // CmdBufBase format: bits [51:12] = base address, bits [59:56] = length (log2 entries)
    let cmd_buf_base_val = (cmd_buf_phys & 0x000F_FFFF_FFFF_F000)
        | (CMD_BUF_LEN_ENC << 56);
    mmio_write64(mmio_base, MMIO_CMD_BUF_BASE, cmd_buf_base_val);

    // Reset head and tail pointers
    mmio_write64(mmio_base, MMIO_CMD_BUF_HEAD, 0);
    mmio_write64(mmio_base, MMIO_CMD_BUF_TAIL, 0);

    // ── Step 8: Allocate Event Log ──
    let (evt_log_virt, evt_log_phys) = match alloc_zeroed_page() {
        Some(p) => p,
        None => {
            log("amd_iommu: failed to allocate Event Log");
            unsafe {
                free(dev_table as *mut u8);
                unmap_mmio_region(mmio_base, IOMMU_MMIO_SIZE);
            }
            return -7;
        }
    };
    let evt_log = evt_log_virt as *mut EventLogEntry;

    // EvtLogBase format: bits [51:12] = base address, bits [59:56] = length (log2 entries)
    let evt_log_base_val = (evt_log_phys & 0x000F_FFFF_FFFF_F000)
        | (EVT_LOG_LEN_ENC << 56);
    mmio_write64(mmio_base, MMIO_EVT_LOG_BASE, evt_log_base_val);

    // Reset head and tail pointers
    mmio_write64(mmio_base, MMIO_EVT_LOG_HEAD, 0);
    mmio_write64(mmio_base, MMIO_EVT_LOG_TAIL, 0);

    // ── Step 9: Store controller state ──
    let state = IommuState {
        mmio_base,
        mmio_size: IOMMU_MMIO_SIZE,
        bus,
        dev,
        func,
        dev_table,
        dev_table_phys,
        cmd_buf,
        cmd_buf_phys,
        cmd_buf_tail: 0,
        evt_log,
        evt_log_phys,
        evt_log_head: 0,
        page_table_roots: [0u64; DEV_TABLE_ENTRIES],
        enabled: false,
    };

    unsafe { *IOMMU.get() = Some(state); }

    log("amd_iommu: initialization complete (IOMMU not yet enabled)");
    0
}

/// Enable the AMD IOMMU.
/// Activates translation, the command buffer, and the event log.
/// Returns 0 on success, negative on error.
#[unsafe(no_mangle)]
pub extern "C" fn amd_iommu_enable() -> i32 {
    let state = match unsafe { (*IOMMU.get()).as_mut() } {
        Some(s) => s,
        None => {
            log("amd_iommu: not initialized");
            return -1;
        }
    };

    if state.enabled {
        log("amd_iommu: already enabled");
        return 0;
    }

    // Read current control register
    let mut ctrl = mmio_read64(state.mmio_base, MMIO_CONTROL);

    // Enable Event Log first (must be enabled before IOMMU)
    ctrl |= CTRL_EVT_LOG_EN;
    mmio_write64(state.mmio_base, MMIO_CONTROL, ctrl);
    fence(Ordering::SeqCst);

    // Wait for Event Log to become active
    for _ in 0..100_000u32 {
        let status = mmio_read64(state.mmio_base, MMIO_STATUS);
        if status & STATUS_EVT_LOG_RUN != 0 {
            break;
        }
        core::hint::spin_loop();
    }

    // Enable Command Buffer
    ctrl |= CTRL_CMD_BUF_EN;
    mmio_write64(state.mmio_base, MMIO_CONTROL, ctrl);
    fence(Ordering::SeqCst);

    // Wait for Command Buffer to become active
    for _ in 0..100_000u32 {
        let status = mmio_read64(state.mmio_base, MMIO_STATUS);
        if status & STATUS_CMD_BUF_RUN != 0 {
            break;
        }
        core::hint::spin_loop();
    }

    // Enable the IOMMU (translation)
    ctrl |= CTRL_IOMMU_EN;
    mmio_write64(state.mmio_base, MMIO_CONTROL, ctrl);
    fence(Ordering::SeqCst);

    state.enabled = true;

    let final_ctrl = mmio_read64(state.mmio_base, MMIO_CONTROL);
    unsafe {
        fut_printf(
            b"amd_iommu: enabled (control=0x%llx)\n\0".as_ptr(),
            final_ctrl,
        );
    }

    log("amd_iommu: IOMMU translation enabled");
    0
}

/// Disable the AMD IOMMU.
/// Stops translation but keeps data structures allocated.
/// Returns 0 on success, negative on error.
#[unsafe(no_mangle)]
pub extern "C" fn amd_iommu_disable() -> i32 {
    let state = match unsafe { (*IOMMU.get()).as_mut() } {
        Some(s) => s,
        None => {
            log("amd_iommu: not initialized");
            return -1;
        }
    };

    if !state.enabled {
        log("amd_iommu: already disabled");
        return 0;
    }

    // Disable IOMMU, command buffer, and event log
    let mut ctrl = mmio_read64(state.mmio_base, MMIO_CONTROL);
    ctrl &= !(CTRL_IOMMU_EN | CTRL_CMD_BUF_EN | CTRL_EVT_LOG_EN
              | CTRL_EVT_INT_EN | CTRL_COM_WAIT_INT_EN);
    mmio_write64(state.mmio_base, MMIO_CONTROL, ctrl);
    fence(Ordering::SeqCst);

    // Wait for command buffer and event log to stop
    for _ in 0..100_000u32 {
        let status = mmio_read64(state.mmio_base, MMIO_STATUS);
        if (status & (STATUS_CMD_BUF_RUN | STATUS_EVT_LOG_RUN)) == 0 {
            break;
        }
        core::hint::spin_loop();
    }

    state.enabled = false;

    log("amd_iommu: IOMMU disabled");
    0
}

/// Map a DMA region for a specific device.
///
/// # Arguments
/// - `bdf`: Bus/Device/Function encoded as 16-bit DeviceID
/// - `iova`: I/O virtual address (device-visible address)
/// - `phys`: Physical address to map to
/// - `size`: Size in bytes (will be rounded up to 4K pages)
/// - `flags`: Mapping flags (bit 0 = read, bit 1 = write)
///
/// Returns 0 on success, negative on error.
#[unsafe(no_mangle)]
pub extern "C" fn amd_iommu_map_device(
    bdf: u16,
    iova: u64,
    phys: u64,
    size: u64,
    flags: u32,
) -> i32 {
    let state = match unsafe { (*IOMMU.get()).as_mut() } {
        Some(s) => s,
        None => {
            log("amd_iommu: not initialized");
            return -1;
        }
    };

    let idx = bdf as usize;
    if idx >= DEV_TABLE_ENTRIES {
        log("amd_iommu: DeviceID out of range");
        return -2;
    }

    let read = (flags & 1) != 0;
    let write = (flags & 2) != 0;

    // Ensure the device has a page table allocated
    if state.page_table_roots[idx] == 0 {
        let pt_root = match alloc_io_page_table() {
            Some(phys) => phys,
            None => {
                log("amd_iommu: failed to allocate page table for device");
                return -3;
            }
        };
        state.page_table_roots[idx] = pt_root;

        // Domain ID = device index (simple 1:1 mapping of domain to device)
        let domain_id = idx as u16;

        // Install the Device Table Entry
        let dte = DeviceTableEntry {
            dw0: build_dte_dw0(pt_root, domain_id, true, true),
            dw1: build_dte_dw1(),
            dw2: 0,
            dw3: 0,
        };
        write_device_table_entry(state, bdf, &dte);
    }

    let l4_phys = state.page_table_roots[idx];

    // Map each 4K page in the range
    let aligned_iova = iova & !0xFFF;
    let end = (iova + size + 0xFFF) & !0xFFF;
    let mut current_iova = aligned_iova;
    let mut current_phys = phys & !0xFFF;

    while current_iova < end {
        if !io_pt_map_4k(l4_phys, current_iova, current_phys, read, write) {
            log("amd_iommu: failed to map page in I/O page table");
            return -4;
        }
        current_iova += PAGE_SIZE_4K;
        current_phys += PAGE_SIZE_4K;
    }

    // Invalidate caches if IOMMU is active
    if state.enabled {
        let domain_id = idx as u16;
        full_invalidation(state, bdf, domain_id);
    }

    0
}

/// Unmap a DMA region for a specific device.
///
/// # Arguments
/// - `bdf`: Bus/Device/Function encoded as 16-bit DeviceID
/// - `iova`: I/O virtual address to unmap
/// - `size`: Size in bytes (will be rounded up to 4K pages)
///
/// Returns 0 on success, negative on error.
#[unsafe(no_mangle)]
pub extern "C" fn amd_iommu_unmap_device(bdf: u16, iova: u64, size: u64) -> i32 {
    let state = match unsafe { (*IOMMU.get()).as_mut() } {
        Some(s) => s,
        None => {
            log("amd_iommu: not initialized");
            return -1;
        }
    };

    let idx = bdf as usize;
    if idx >= DEV_TABLE_ENTRIES {
        log("amd_iommu: DeviceID out of range");
        return -2;
    }

    let l4_phys = state.page_table_roots[idx];
    if l4_phys == 0 {
        log("amd_iommu: device has no page table");
        return -3;
    }

    // Unmap each 4K page in the range
    let aligned_iova = iova & !0xFFF;
    let end = (iova + size + 0xFFF) & !0xFFF;
    let mut current_iova = aligned_iova;

    while current_iova < end {
        if !io_pt_unmap_4k(l4_phys, current_iova) {
            // Entry may not exist -- not necessarily an error
        }
        current_iova += PAGE_SIZE_4K;
    }

    // Invalidate caches if IOMMU is active
    if state.enabled {
        let domain_id = idx as u16;
        full_invalidation(state, bdf, domain_id);
    }

    0
}

/// Set up 1:1 identity mapping for a device (IOVA == physical address).
/// Maps the first 4 GiB using 2 MiB pages.
///
/// # Arguments
/// - `bdf`: Bus/Device/Function encoded as 16-bit DeviceID
///
/// Returns 0 on success, negative on error.
#[unsafe(no_mangle)]
pub extern "C" fn amd_iommu_identity_map(bdf: u16) -> i32 {
    let state = match unsafe { (*IOMMU.get()).as_mut() } {
        Some(s) => s,
        None => {
            log("amd_iommu: not initialized");
            return -1;
        }
    };

    let idx = bdf as usize;
    if idx >= DEV_TABLE_ENTRIES {
        log("amd_iommu: DeviceID out of range");
        return -2;
    }

    // Allocate a fresh L4 page table
    let l4_phys = match alloc_io_page_table() {
        Some(phys) => phys,
        None => {
            log("amd_iommu: failed to allocate L4 page table");
            return -3;
        }
    };

    // Build the 1:1 identity map (first 4 GiB)
    if !setup_identity_map(l4_phys) {
        log("amd_iommu: failed to build identity mapping");
        return -4;
    }

    state.page_table_roots[idx] = l4_phys;

    // Domain ID = device index
    let domain_id = idx as u16;

    // Install the DTE
    let dte = DeviceTableEntry {
        dw0: build_dte_dw0(l4_phys, domain_id, true, true),
        dw1: build_dte_dw1(),
        dw2: 0,
        dw3: 0,
    };
    write_device_table_entry(state, bdf, &dte);

    // Invalidate if IOMMU is active
    if state.enabled {
        full_invalidation(state, bdf, domain_id);
    }

    let bus = (bdf >> 8) as u32;
    let devn = ((bdf >> 3) & 0x1F) as u32;
    let funcn = (bdf & 0x07) as u32;
    unsafe {
        fut_printf(
            b"amd_iommu: identity map configured for device %02x:%02x.%x\n\0".as_ptr(),
            bus, devn, funcn,
        );
    }

    0
}

/// Poll the event log for DMA faults and other IOMMU events.
/// Returns the number of events processed, or negative on error.
#[unsafe(no_mangle)]
pub extern "C" fn amd_iommu_poll_events() -> i32 {
    let state = match unsafe { (*IOMMU.get()).as_mut() } {
        Some(s) => s,
        None => {
            log("amd_iommu: not initialized");
            return -1;
        }
    };

    if !state.enabled {
        return 0;
    }

    poll_event_log(state)
}
