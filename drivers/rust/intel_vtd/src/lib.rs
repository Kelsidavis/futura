// SPDX-License-Identifier: MPL-2.0
//
// Intel VT-d (Virtualization Technology for Directed I/O) IOMMU Driver
//
// Implements the Intel VT-d specification for DMA remapping on Gen 10+
// platforms.  VT-d hardware is discovered via the ACPI DMAR table; the
// kernel passes the MMIO base address of a DMAR remapping unit to this
// driver's init function.
//
// Architecture:
//   - Root Table: 256 entries (one per PCI bus), each 128 bits
//   - Context Table: 256 entries per bus (32 devices x 8 functions), 128 bits
//   - 4-level I/O page tables (PML4 -> PDPT -> PD -> PT), same as x86_64
//   - IOTLB and context-cache invalidation via register-based interface
//   - Fault recording via the FRCD registers
//
// VT-d MMIO Register Map:
//   0x000  VER      Version (major[3:0], minor[7:4])
//   0x008  CAP      Capability (64-bit)
//   0x010  ECAP     Extended Capability (64-bit)
//   0x018  GCMD     Global Command (32-bit)
//   0x01C  GSTS     Global Status (32-bit)
//   0x020  RTADDR   Root Table Address (64-bit)
//   0x024  CCMD     Context Command (64-bit)
//   0x028  FSTS     Fault Status (32-bit)
//   0x02C  FECTL    Fault Event Control (32-bit)
//   0x034  FEADDR   Fault Event Address (32-bit)
//   0x038  FEUADDR  Fault Event Upper Address (32-bit)
//   0x03C  FEDATA   Fault Event Data (32-bit)
//   0x100  FRCD_REG Fault Recording (128-bit per entry)
//
// IOTLB registers (offset from ECAP.IRO):
//   +0x00  IOTLB_REG (64-bit)  invalidation command/status
//   +0x08  IVA_REG   (64-bit)  invalidation address

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(unexpected_cfgs)]
#![allow(dead_code)]

use core::ffi::c_void;
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{Ordering, fence};

use common::{
    alloc_page, log, map_mmio_region, unmap_mmio_region,
    MMIO_DEFAULT_FLAGS,
};

unsafe extern "C" {
    fn fut_printf(fmt: *const u8, ...);
    fn fut_virt_to_phys(vaddr: *const c_void) -> u64;
}

// ---------------------------------------------------------------------------
// Physical address helper
// ---------------------------------------------------------------------------

fn virt_to_phys(ptr: *const u8) -> u64 {
    unsafe { fut_virt_to_phys(ptr as *const c_void) }
}

// ---------------------------------------------------------------------------
// MMIO Register Offsets
// ---------------------------------------------------------------------------

const REG_VER: usize          = 0x000;  // Version
const REG_CAP: usize          = 0x008;  // Capability (64-bit)
const REG_ECAP: usize         = 0x010;  // Extended Capability (64-bit)
const REG_GCMD: usize         = 0x018;  // Global Command (32-bit)
const REG_GSTS: usize         = 0x01C;  // Global Status (32-bit)
const REG_RTADDR: usize       = 0x020;  // Root Table Address (64-bit)
const REG_CCMD: usize         = 0x028;  // Context Command (64-bit)
const REG_FSTS: usize         = 0x028 + 6; // 0x02E -- actually 0x034 in spec
const REG_FECTL: usize        = 0x038;  // Fault Event Control

// Fault recording registers (base at 0x100, each record is 128 bits = 16 bytes)
const REG_FRCD_BASE: usize    = 0x100;
const FRCD_SIZE: usize        = 16;     // 128-bit per fault record

// Corrected offsets per VT-d spec
const REG_FSTS_OFF: usize     = 0x034;  // Fault Status Register
const REG_FECTL_OFF: usize    = 0x038;  // Fault Event Control
const REG_FEADDR_OFF: usize   = 0x03C;  // Fault Event Address
const REG_FEUADDR_OFF: usize  = 0x040;  // Fault Event Upper Address
const REG_FEDATA_OFF: usize   = 0x044;  // Fault Event Data

// MMIO region size: we map up to 0x200 to cover FRCD entries
const VTD_MMIO_SIZE: usize = 0x1000;

// ---------------------------------------------------------------------------
// Global Command (GCMD) bits
// ---------------------------------------------------------------------------

const GCMD_TE: u32    = 1 << 31;  // Translation Enable
const GCMD_SRTP: u32  = 1 << 30;  // Set Root Table Pointer
const GCMD_SFL: u32   = 1 << 29;  // Set Fault Log
const GCMD_EAFL: u32  = 1 << 28;  // Enable Advanced Fault Logging
const GCMD_WBF: u32   = 1 << 27;  // Write Buffer Flush
const GCMD_QIE: u32   = 1 << 26;  // Queued Invalidation Enable
const GCMD_IRE: u32   = 1 << 25;  // Interrupt Remapping Enable

// ---------------------------------------------------------------------------
// Global Status (GSTS) bits (mirror GCMD)
// ---------------------------------------------------------------------------

const GSTS_TES: u32   = 1 << 31;  // Translation Enable Status
const GSTS_RTPS: u32  = 1 << 30;  // Root Table Pointer Status
const GSTS_FLS: u32   = 1 << 29;  // Fault Log Status
const GSTS_AFLS: u32  = 1 << 28;  // Advanced Fault Logging Status
const GSTS_WBFS: u32  = 1 << 27;  // Write Buffer Flush Status
const GSTS_QIES: u32  = 1 << 26;  // Queued Invalidation Enable Status
const GSTS_IRES: u32  = 1 << 25;  // Interrupt Remapping Enable Status

// ---------------------------------------------------------------------------
// Context Command Register (CCMD) bits
// ---------------------------------------------------------------------------

const CCMD_ICC: u64  = 1 << 63;   // Invalidate Context-Cache
// CIRG: Context Invalidation Request Granularity [62:61]
const CCMD_CIRG_GLOBAL: u64  = 1 << 61;  // Global invalidation
const CCMD_CIRG_DOMAIN: u64  = 2 << 61;  // Domain-selective
const CCMD_CIRG_DEVICE: u64  = 3 << 61;  // Device-selective

// ---------------------------------------------------------------------------
// Capability Register (CAP) fields
// ---------------------------------------------------------------------------

// CAP.SAGAW: Supported Adjusted Guest Address Widths [12:8]
// Bit 1 (in field) = 39-bit (3-level), Bit 2 = 48-bit (4-level)
const CAP_SAGAW_SHIFT: u64 = 8;
const CAP_SAGAW_MASK: u64  = 0x1F;

// CAP.MGAW: Maximum Guest Address Width [44:39] (value + 1 = max bits)
const CAP_MGAW_SHIFT: u64  = 39;
const CAP_MGAW_MASK: u64   = 0x3F;

// CAP.ND: Number of Domains [2:0]
const CAP_ND_SHIFT: u64    = 0;
const CAP_ND_MASK: u64     = 0x7;

// CAP.RWBF: Required Write-Buffer Flushing [4]
const CAP_RWBF: u64        = 1 << 4;

// CAP.AFL: Advanced Fault Logging [3]
const CAP_AFL: u64          = 1 << 3;

// CAP.NFR: Number of Fault-recording Registers [47:40] (value + 1 = count)
const CAP_NFR_SHIFT: u64   = 40;
const CAP_NFR_MASK: u64    = 0xFF;

// CAP.FRO: Fault-recording Register Offset [33:24] (in 16-byte units)
const CAP_FRO_SHIFT: u64   = 24;
const CAP_FRO_MASK: u64    = 0x3FF;

// ---------------------------------------------------------------------------
// Extended Capability Register (ECAP) fields
// ---------------------------------------------------------------------------

// ECAP.IRO: IOTLB Register Offset [17:8] (in 16-byte units)
const ECAP_IRO_SHIFT: u64  = 8;
const ECAP_IRO_MASK: u64   = 0x3FF;

// ECAP feature bits
const ECAP_QI: u64         = 1 << 1;   // Queued Invalidation support
const ECAP_DI: u64         = 1 << 2;   // Device-IOTLB support
const ECAP_IR: u64         = 1 << 3;   // Interrupt Remapping support
const ECAP_EIM: u64        = 1 << 4;   // Extended Interrupt Mode
const ECAP_PT: u64         = 1 << 6;   // Pass-Through support
const ECAP_SC: u64         = 1 << 7;   // Snoop Control

// ---------------------------------------------------------------------------
// IOTLB Register bits (at ECAP.IRO offset)
// ---------------------------------------------------------------------------

// IOTLB Invalidate Register (64-bit, at IRO_offset + 0x08)
const IOTLB_IVT: u64           = 1 << 63;  // Invalidate IOTLB
// IIRG: IOTLB Invalidation Request Granularity [61:60]
const IOTLB_IIRG_GLOBAL: u64   = 1 << 60;  // Global invalidation
const IOTLB_IIRG_DOMAIN: u64   = 2 << 60;  // Domain-selective
const IOTLB_IIRG_PAGE: u64     = 3 << 60;  // Page-selective
// DID: Domain ID [47:32]
const IOTLB_DID_SHIFT: u64     = 32;
// DR: Drain Reads [49]
const IOTLB_DR: u64            = 1 << 49;
// DW: Drain Writes [48]
const IOTLB_DW: u64            = 1 << 48;

// ---------------------------------------------------------------------------
// Fault Status Register (FSTS) bits
// ---------------------------------------------------------------------------

const FSTS_PPF: u32   = 1 << 1;   // Primary Pending Fault
const FSTS_PFO: u32   = 1 << 0;   // Primary Fault Overflow
const FSTS_IQE: u32   = 1 << 4;   // Invalidation Queue Error
const FSTS_ICE: u32   = 1 << 5;   // Invalidation Completion Error
const FSTS_ITE: u32   = 1 << 6;   // Invalidation Timeout Error
const FSTS_FRI_SHIFT: u32 = 8;    // Fault Record Index [15:8]
const FSTS_FRI_MASK: u32  = 0xFF;

// ---------------------------------------------------------------------------
// Fault Recording Register bits (128-bit, two 64-bit dwords)
// ---------------------------------------------------------------------------

// FRCD high (bits [127:64]):
//   [127] F    - Fault (1 = valid fault record)
//   [126] T    - Type (0 = write, 1 = read)
//   [125:124] AT - Address Type
//   [123:104] SID (Source ID = BDF)
//   [103:72] FR (Fault Reason)
//   [71:64]  PV (PASID value, if applicable)
// FRCD low (bits [63:0]):
//   [63:12]  FI  - Fault Info (faulting address bits [63:12])
//   [11:0]   reserved

const FRCD_HI_F: u64         = 1 << 63;      // Fault valid bit (bit 127 of record)
const FRCD_HI_T: u64         = 1 << 62;      // Type: 1=read, 0=write
const FRCD_HI_SID_SHIFT: u64 = 40;           // Source ID shift (bits [55:40] in hi qword)
const FRCD_HI_SID_MASK: u64  = 0xFFFF;
const FRCD_HI_FR_SHIFT: u64  = 32;           // Fault Reason shift
const FRCD_HI_FR_MASK: u64   = 0xFF;         // 8-bit fault reason

// ---------------------------------------------------------------------------
// Root Table Entry (128 bits = 16 bytes)
// ---------------------------------------------------------------------------
//
// Low 64 bits:
//   [0]     Present
//   [11:1]  Reserved
//   [63:12] Context Table Pointer (physical address, 4K-aligned)
// High 64 bits:
//   Reserved (used for extended root table mode, not implemented here)

const ROOT_ENTRY_SIZE: usize = 16;
const ROOT_TABLE_ENTRIES: usize = 256;  // One per PCI bus
const ROOT_TABLE_SIZE: usize = ROOT_TABLE_ENTRIES * ROOT_ENTRY_SIZE; // 4096 bytes

const ROOT_PRESENT: u64 = 1 << 0;

// ---------------------------------------------------------------------------
// Context Table Entry (128 bits = 16 bytes)
// ---------------------------------------------------------------------------
//
// Low 64 bits:
//   [0]     P    - Present
//   [1]     FPD  - Fault Processing Disable
//   [3:2]   T    - Translation Type (00=untranslated, 01=multi-level, 10=pass-through)
//   [11:4]  Reserved
//   [63:12] ASR  - Address Space Root (page table root, 4K-aligned)
// High 64 bits:
//   [2:0]   AW   - Address Width (0=30-bit, 1=39-bit, 2=48-bit, 3=57-bit)
//   [3]     Reserved
//   [7:4]   Reserved
//   [23:8]  DID  - Domain ID
//   [63:24] Reserved

const CTX_ENTRY_SIZE: usize = 16;
const CTX_TABLE_ENTRIES: usize = 256;  // 32 devices x 8 functions
const CTX_TABLE_SIZE: usize = CTX_TABLE_ENTRIES * CTX_ENTRY_SIZE; // 4096 bytes

const CTX_PRESENT: u64        = 1 << 0;
const CTX_FPD: u64            = 1 << 1;

// Translation Type field [3:2]
const CTX_TT_MULTI_LEVEL: u64 = 1 << 2;   // Multi-level page table translation
const CTX_TT_PASS_THROUGH: u64 = 2 << 2;  // Pass-through (identity, if ECAP.PT)

// Address Width in high 64 bits [2:0]
const CTX_AW_39BIT: u64       = 1;  // 3-level page table (39-bit IOVA)
const CTX_AW_48BIT: u64       = 2;  // 4-level page table (48-bit IOVA)

// Domain ID in high 64 bits [23:8]
const CTX_DID_SHIFT: u64      = 8;

// ---------------------------------------------------------------------------
// I/O Page Table constants (x86_64 compatible 4-level paging)
// ---------------------------------------------------------------------------

const PAGE_SIZE_4K: u64 = 0x1000;
const PAGE_SIZE_2M: u64 = 0x200000;
const PAGE_SIZE_1G: u64 = 0x40000000;

const PT_ENTRIES: usize = 512;

// VT-d I/O PTE format (similar to x86_64 but not identical):
//   [0]     R  - Read
//   [1]     W  - Write
//   [6:2]   Reserved
//   [7]     SP - Super Page (for large pages at PD/PDPT level)
//   [11:8]  Reserved
//   [51:12] Address (physical page frame)
//   [63:52] Reserved (some implementations use for AVAIL)
const IOPT_READ: u64   = 1 << 0;
const IOPT_WRITE: u64  = 1 << 1;
const IOPT_SP: u64     = 1 << 7;   // Super Page

// For intermediate (non-leaf) entries, R and W must both be set
const IOPT_PRESENT: u64 = IOPT_READ | IOPT_WRITE;

// Address mask for PTE entries: bits [51:12]
const IOPT_ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

// ---------------------------------------------------------------------------
// MMIO helpers
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Controller state
// ---------------------------------------------------------------------------

struct VtdState {
    mmio_base: *mut u8,
    mmio_size: usize,
    mmio_phys: u64,

    // Hardware capabilities
    cap: u64,
    ecap: u64,
    ver_major: u8,
    ver_minor: u8,
    sagaw: u8,           // Supported address widths bitmask
    mgaw: u8,            // Maximum guest address width
    num_domains: u32,    // Maximum number of domains
    num_fault_regs: u8,  // Number of fault recording registers
    fault_reg_offset: usize,  // Byte offset of FRCD registers
    iotlb_reg_offset: usize,  // Byte offset of IOTLB registers (from ECAP.IRO)
    rwbf_required: bool, // Write-buffer flushing required

    // Root Table (4K, 256 entries of 16 bytes)
    root_table: *mut u8,
    root_table_phys: u64,

    // Per-bus context tables: physical addresses (0 = not allocated)
    ctx_tables: [u64; ROOT_TABLE_ENTRIES],
    // Per-bus context table virtual pointers (for page table management)
    ctx_table_virts: [*mut u8; ROOT_TABLE_ENTRIES],

    // Per-device page table roots (indexed by BDF, max 256 entries
    // for the devices we track -- bus 0..255, dev/func encoded)
    // We use a flat array indexed by (bus << 8 | dev << 3 | func)
    // but limit to 256 tracked devices for memory reasons.
    // In practice, we allocate page tables on demand.
    pt_roots: [u64; 256],

    // Next domain ID to assign
    next_domain_id: u16,

    enabled: bool,
}

// Safety: all access is single-threaded or externally synchronised.
unsafe impl Send for VtdState {}

/// Wrapper to allow `UnsafeCell` in a `static` (requires `Sync`).
/// Safety: all access is single-threaded or externally synchronised by the caller.
struct StaticCell<T>(core::cell::UnsafeCell<T>);
unsafe impl<T> Sync for StaticCell<T> {}
impl<T> StaticCell<T> {
    const fn new(val: T) -> Self { Self(core::cell::UnsafeCell::new(val)) }
    fn get(&self) -> *mut T { self.0.get() }
}

static VTD: StaticCell<Option<VtdState>> = StaticCell::new(None);

// ---------------------------------------------------------------------------
// Page table management
// ---------------------------------------------------------------------------

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

/// Walk one level of the I/O page table.  If the entry at `index` is not
/// present, allocate a new child table and install it.  Returns the physical
/// address of the child table, or 0 on failure.
fn walk_or_alloc_level(table_phys: u64, index: usize) -> u64 {
    let table_virt = unsafe {
        map_mmio_region(table_phys, PAGE_SIZE_4K as usize, MMIO_DEFAULT_FLAGS)
    };
    if table_virt.is_null() { return 0; }

    let entry_ptr = unsafe { (table_virt as *mut u64).add(index) };
    let entry = unsafe { read_volatile(entry_ptr) };

    let child_phys;
    if entry & IOPT_READ != 0 {
        // Already present -- extract physical address
        child_phys = entry & IOPT_ADDR_MASK;
    } else {
        // Allocate a new child table
        match alloc_zeroed_page() {
            Some((_, phys)) => {
                // Non-leaf entry: set R+W and address
                let new_entry = IOPT_PRESENT | (phys & IOPT_ADDR_MASK);
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

/// Map a single 4K page in the VT-d I/O page table (4-level).
/// PML4 -> PDPT -> PD -> PT
///
/// VT-d page table entry format:
///   [0]     R (Read)
///   [1]     W (Write)
///   [7]     SP (Super Page, only for leaf at PD/PDPT level)
///   [51:12] Physical address
fn io_pt_map_4k(pml4_phys: u64, iova: u64, phys_addr: u64, read: bool, write: bool) -> bool {
    let pml4_idx = ((iova >> 39) & 0x1FF) as usize;
    let pdpt_idx = ((iova >> 30) & 0x1FF) as usize;
    let pd_idx   = ((iova >> 21) & 0x1FF) as usize;
    let pt_idx   = ((iova >> 12) & 0x1FF) as usize;

    // Walk PML4 -> PDPT
    let pdpt_phys = walk_or_alloc_level(pml4_phys, pml4_idx);
    if pdpt_phys == 0 { return false; }

    // Walk PDPT -> PD
    let pd_phys = walk_or_alloc_level(pdpt_phys, pdpt_idx);
    if pd_phys == 0 { return false; }

    // Walk PD -> PT
    let pt_phys = walk_or_alloc_level(pd_phys, pd_idx);
    if pt_phys == 0 { return false; }

    // Write the leaf PT entry
    let mut pte: u64 = phys_addr & IOPT_ADDR_MASK;
    if read  { pte |= IOPT_READ; }
    if write { pte |= IOPT_WRITE; }

    let pt_virt = unsafe { map_mmio_region(pt_phys, PAGE_SIZE_4K as usize, MMIO_DEFAULT_FLAGS) };
    if pt_virt.is_null() { return false; }
    unsafe {
        write_volatile((pt_virt as *mut u64).add(pt_idx), pte);
    }
    fence(Ordering::SeqCst);
    unsafe { unmap_mmio_region(pt_virt, PAGE_SIZE_4K as usize); }

    true
}

/// Read a page table entry at the given index and return the child physical
/// address, or 0 if not present.
fn read_pt_entry_phys(table_phys: u64, index: usize) -> u64 {
    let table_virt = unsafe {
        map_mmio_region(table_phys, PAGE_SIZE_4K as usize, MMIO_DEFAULT_FLAGS)
    };
    if table_virt.is_null() { return 0; }

    let entry = unsafe { read_volatile((table_virt as *const u64).add(index)) };
    unsafe { unmap_mmio_region(table_virt, PAGE_SIZE_4K as usize); }

    if entry & IOPT_READ != 0 {
        entry & IOPT_ADDR_MASK
    } else {
        0
    }
}

/// Unmap a single 4K page in the I/O page table.
fn io_pt_unmap_4k(pml4_phys: u64, iova: u64) -> bool {
    let pml4_idx = ((iova >> 39) & 0x1FF) as usize;
    let pdpt_idx = ((iova >> 30) & 0x1FF) as usize;
    let pd_idx   = ((iova >> 21) & 0x1FF) as usize;
    let pt_idx   = ((iova >> 12) & 0x1FF) as usize;

    let pdpt_phys = read_pt_entry_phys(pml4_phys, pml4_idx);
    if pdpt_phys == 0 { return false; }

    let pd_phys = read_pt_entry_phys(pdpt_phys, pdpt_idx);
    if pd_phys == 0 { return false; }

    let pt_phys = read_pt_entry_phys(pd_phys, pd_idx);
    if pt_phys == 0 { return false; }

    let pt_virt = unsafe { map_mmio_region(pt_phys, PAGE_SIZE_4K as usize, MMIO_DEFAULT_FLAGS) };
    if pt_virt.is_null() { return false; }
    unsafe {
        write_volatile((pt_virt as *mut u64).add(pt_idx), 0u64);
    }
    fence(Ordering::SeqCst);
    unsafe { unmap_mmio_region(pt_virt, PAGE_SIZE_4K as usize); }

    true
}

// ---------------------------------------------------------------------------
// Identity mapping (1:1 passthrough using 2 MiB super-pages)
// ---------------------------------------------------------------------------

/// Set up 1:1 identity mapping for the first 4 GiB using 2 MiB pages
/// in a 4-level VT-d page table.
///
/// Layout: PML4[0] -> PDPT with 4 entries -> 4 PD tables
/// Each PD entry is a 2 MiB super-page leaf (SP bit set, R+W).
fn setup_identity_map(pml4_phys: u64) -> bool {
    let pml4_virt = unsafe {
        map_mmio_region(pml4_phys, PAGE_SIZE_4K as usize, MMIO_DEFAULT_FLAGS)
    };
    if pml4_virt.is_null() { return false; }

    // Allocate a PDPT table
    let (_, pdpt_phys) = match alloc_zeroed_page() {
        Some(p) => p,
        None => {
            unsafe { unmap_mmio_region(pml4_virt, PAGE_SIZE_4K as usize); }
            return false;
        }
    };

    // Install PML4[0] -> PDPT
    let pml4_entry = IOPT_PRESENT | (pdpt_phys & IOPT_ADDR_MASK);
    unsafe { write_volatile(pml4_virt as *mut u64, pml4_entry); }
    fence(Ordering::SeqCst);
    unsafe { unmap_mmio_region(pml4_virt, PAGE_SIZE_4K as usize); }

    // Map PDPT and create 4 entries (one per GiB, covering 0-4 GiB)
    let pdpt_virt = unsafe {
        map_mmio_region(pdpt_phys, PAGE_SIZE_4K as usize, MMIO_DEFAULT_FLAGS)
    };
    if pdpt_virt.is_null() { return false; }

    for gib in 0u64..4 {
        // Allocate a PD table for this 1 GiB region
        let (_, pd_phys) = match alloc_zeroed_page() {
            Some(p) => p,
            None => {
                unsafe { unmap_mmio_region(pdpt_virt, PAGE_SIZE_4K as usize); }
                return false;
            }
        };

        // Install PDPT[gib] -> PD
        let pdpt_entry = IOPT_PRESENT | (pd_phys & IOPT_ADDR_MASK);
        unsafe {
            write_volatile((pdpt_virt as *mut u64).add(gib as usize), pdpt_entry);
        }

        // Map PD table and fill with 2 MiB super-page leaf entries
        let pd_virt = unsafe {
            map_mmio_region(pd_phys, PAGE_SIZE_4K as usize, MMIO_DEFAULT_FLAGS)
        };
        if pd_virt.is_null() {
            unsafe { unmap_mmio_region(pdpt_virt, PAGE_SIZE_4K as usize); }
            return false;
        }

        for entry_idx in 0..PT_ENTRIES {
            let phys_addr = gib * PAGE_SIZE_1G + (entry_idx as u64) * PAGE_SIZE_2M;
            // 2 MiB super-page leaf: R + W + SP + address
            let pd_entry = IOPT_READ | IOPT_WRITE | IOPT_SP
                | (phys_addr & IOPT_ADDR_MASK);
            unsafe {
                write_volatile((pd_virt as *mut u64).add(entry_idx), pd_entry);
            }
        }

        fence(Ordering::SeqCst);
        unsafe { unmap_mmio_region(pd_virt, PAGE_SIZE_4K as usize); }
    }

    fence(Ordering::SeqCst);
    unsafe { unmap_mmio_region(pdpt_virt, PAGE_SIZE_4K as usize); }

    true
}

// ---------------------------------------------------------------------------
// Root Table / Context Table management
// ---------------------------------------------------------------------------

/// Ensure a context table exists for the given bus.  Allocates one if needed
/// and installs it into the root table.
fn ensure_context_table(state: &mut VtdState, bus: u8) -> bool {
    let idx = bus as usize;
    if state.ctx_tables[idx] != 0 {
        return true;
    }

    // Allocate a context table (4K, 256 entries of 16 bytes)
    let (ctx_virt, ctx_phys) = match alloc_zeroed_page() {
        Some(p) => p,
        None => return false,
    };

    state.ctx_tables[idx] = ctx_phys;
    state.ctx_table_virts[idx] = ctx_virt;

    // Install into the root table: low 64 bits = Present | CTP
    let root_entry_offset = idx * ROOT_ENTRY_SIZE;
    let root_virt = state.root_table;
    let root_lo = ROOT_PRESENT | (ctx_phys & IOPT_ADDR_MASK);
    unsafe {
        write_volatile(
            root_virt.add(root_entry_offset) as *mut u64,
            root_lo,
        );
        // High 64 bits = 0 (reserved for extended root table)
        write_volatile(
            root_virt.add(root_entry_offset + 8) as *mut u64,
            0u64,
        );
    }
    fence(Ordering::SeqCst);

    true
}

/// Write a context table entry for a specific device (bus:dev.func).
///
/// `pt_root_phys`: physical address of the PML4 page table root
/// `domain_id`: domain ID for this device
/// `tt`: translation type (CTX_TT_MULTI_LEVEL or CTX_TT_PASS_THROUGH)
fn write_context_entry(
    state: &mut VtdState,
    bus: u8,
    dev: u8,
    func: u8,
    pt_root_phys: u64,
    domain_id: u16,
    tt: u64,
) -> bool {
    if !ensure_context_table(state, bus) {
        return false;
    }

    let ctx_virt = state.ctx_table_virts[bus as usize];
    if ctx_virt.is_null() {
        return false;
    }

    let entry_idx = ((dev as usize) << 3) | (func as usize);
    let entry_offset = entry_idx * CTX_ENTRY_SIZE;

    // Low 64 bits: Present | Translation Type | ASR (page table root)
    let ctx_lo = CTX_PRESENT | tt | (pt_root_phys & IOPT_ADDR_MASK);

    // High 64 bits: Address Width | Domain ID
    // Use 48-bit (4-level) if supported, else 39-bit (3-level)
    let aw = if state.sagaw & (1 << 2) != 0 {
        CTX_AW_48BIT
    } else {
        CTX_AW_39BIT
    };
    let ctx_hi = aw | ((domain_id as u64) << CTX_DID_SHIFT);

    unsafe {
        write_volatile(
            ctx_virt.add(entry_offset) as *mut u64,
            ctx_lo,
        );
        write_volatile(
            ctx_virt.add(entry_offset + 8) as *mut u64,
            ctx_hi,
        );
    }
    fence(Ordering::SeqCst);

    true
}

/// Allocate a domain ID for a new device mapping.
fn alloc_domain_id(state: &mut VtdState) -> u16 {
    let id = state.next_domain_id;
    state.next_domain_id = state.next_domain_id.wrapping_add(1);
    if state.next_domain_id == 0 {
        state.next_domain_id = 1;
    }
    id
}

/// Encode a BDF (bus/device/function) into an index for our pt_roots array.
/// We use a simple hash: bus XOR ((dev << 3) | func) to fit in 256 entries.
/// For a full implementation this would be a larger table.
fn bdf_to_index(bus: u8, dev: u8, func: u8) -> usize {
    let devfn = ((dev as usize) << 3) | (func as usize);
    // Simple modular index -- collisions are possible but acceptable for
    // a driver that manages a moderate number of devices
    (((bus as usize) << 4) ^ devfn) & 0xFF
}

// ---------------------------------------------------------------------------
// Hardware operations
// ---------------------------------------------------------------------------

/// Set the Root Table Pointer in hardware and wait for acknowledgement.
fn set_root_table_pointer(state: &VtdState) -> bool {
    // Write the root table physical address to RTADDR
    mmio_write64(state.mmio_base, REG_RTADDR, state.root_table_phys & IOPT_ADDR_MASK);
    fence(Ordering::SeqCst);

    // Issue GCMD.SRTP
    let gcmd = mmio_read32(state.mmio_base, REG_GCMD);
    mmio_write32(state.mmio_base, REG_GCMD, gcmd | GCMD_SRTP);

    // Wait for GSTS.RTPS
    for _ in 0..1_000_000u32 {
        let gsts = mmio_read32(state.mmio_base, REG_GSTS);
        if gsts & GSTS_RTPS != 0 {
            return true;
        }
        core::hint::spin_loop();
    }

    log("intel_vtd: timeout waiting for GSTS.RTPS");
    false
}

/// Perform a write-buffer flush if required by hardware (CAP.RWBF).
fn write_buffer_flush(state: &VtdState) {
    if !state.rwbf_required {
        return;
    }

    let gcmd = mmio_read32(state.mmio_base, REG_GCMD);
    mmio_write32(state.mmio_base, REG_GCMD, gcmd | GCMD_WBF);

    // Wait for GSTS.WBFS to clear (indicates flush complete)
    for _ in 0..1_000_000u32 {
        let gsts = mmio_read32(state.mmio_base, REG_GSTS);
        if gsts & GSTS_WBFS == 0 {
            return;
        }
        core::hint::spin_loop();
    }

    log("intel_vtd: timeout waiting for write-buffer flush");
}

/// Invalidate the global context cache.
fn invalidate_context_cache_global(state: &VtdState) {
    // Write CCMD: ICC | CIRG=Global
    let ccmd = CCMD_ICC | CCMD_CIRG_GLOBAL;
    mmio_write64(state.mmio_base, REG_CCMD, ccmd);

    // Wait for ICC to clear (hardware clears it when done)
    for _ in 0..1_000_000u32 {
        let val = mmio_read64(state.mmio_base, REG_CCMD);
        if val & CCMD_ICC == 0 {
            return;
        }
        core::hint::spin_loop();
    }

    log("intel_vtd: timeout waiting for context-cache invalidation");
}

/// Invalidate the global IOTLB.
fn invalidate_iotlb_global(state: &VtdState) {
    let iotlb_offset = state.iotlb_reg_offset;
    // The IOTLB register is at IRO + 0x08
    let iotlb_reg = iotlb_offset + 0x08;

    // Write IOTLB_REG: IVT | IIRG=Global | DR | DW
    let cmd = IOTLB_IVT | IOTLB_IIRG_GLOBAL | IOTLB_DR | IOTLB_DW;
    mmio_write64(state.mmio_base, iotlb_reg, cmd);

    // Wait for IVT to clear
    for _ in 0..1_000_000u32 {
        let val = mmio_read64(state.mmio_base, iotlb_reg);
        if val & IOTLB_IVT == 0 {
            return;
        }
        core::hint::spin_loop();
    }

    log("intel_vtd: timeout waiting for IOTLB invalidation");
}

/// Perform a full invalidation sequence: write-buffer flush, context cache,
/// then IOTLB.
fn full_invalidation(state: &VtdState) {
    write_buffer_flush(state);
    invalidate_context_cache_global(state);
    invalidate_iotlb_global(state);
}

// ---------------------------------------------------------------------------
// Fault handling
// ---------------------------------------------------------------------------

/// Read and clear all pending fault records.
/// Returns the number of faults processed.
fn read_and_clear_faults(state: &VtdState) -> i32 {
    let fsts = mmio_read32(state.mmio_base, REG_FSTS_OFF);

    // Check if there are any pending faults
    if fsts & FSTS_PPF == 0 && fsts & FSTS_PFO == 0 {
        return 0;
    }

    if fsts & FSTS_PFO != 0 {
        log("intel_vtd: fault recording overflow detected");
    }

    let mut count = 0i32;

    // Process each fault recording register
    for i in 0..state.num_fault_regs as usize {
        let frcd_offset = state.fault_reg_offset + i * FRCD_SIZE;

        // Read the high 64 bits first (contains the F bit)
        let frcd_hi = mmio_read64(state.mmio_base, frcd_offset + 8);

        if frcd_hi & FRCD_HI_F == 0 {
            continue;  // No valid fault in this register
        }

        // Read the low 64 bits (faulting address)
        let frcd_lo = mmio_read64(state.mmio_base, frcd_offset);

        let fault_addr = frcd_lo & IOPT_ADDR_MASK;
        let is_read = (frcd_hi & FRCD_HI_T) != 0;
        let source_id = ((frcd_hi >> FRCD_HI_SID_SHIFT) & FRCD_HI_SID_MASK) as u16;
        let fault_reason = ((frcd_hi >> FRCD_HI_FR_SHIFT) & FRCD_HI_FR_MASK) as u32;

        let bus = (source_id >> 8) as u32;
        let devn = ((source_id >> 3) & 0x1F) as u32;
        let funcn = (source_id & 0x07) as u32;

        unsafe {
            fut_printf(
                b"intel_vtd: fault: %s dev=%02x:%02x.%x addr=0x%llx reason=0x%x\n\0".as_ptr(),
                if is_read { b"READ\0".as_ptr() } else { b"WRITE\0".as_ptr() },
                bus,
                devn,
                funcn,
                fault_addr,
                fault_reason,
            );
        }

        // Clear the fault by writing 1 to the F bit (W1C)
        mmio_write64(state.mmio_base, frcd_offset + 8, FRCD_HI_F);
        fence(Ordering::SeqCst);

        count += 1;
    }

    // Clear fault status bits (W1C)
    if fsts & (FSTS_PPF | FSTS_PFO) != 0 {
        mmio_write32(state.mmio_base, REG_FSTS_OFF, fsts & (FSTS_PPF | FSTS_PFO));
    }

    count
}

// ---------------------------------------------------------------------------
// Capability parsing
// ---------------------------------------------------------------------------

/// Decode the number of domains from the CAP.ND field.
fn decode_num_domains(nd: u64) -> u32 {
    match nd {
        0 => 16,       // 2^4
        1 => 64,       // 2^6
        2 => 256,      // 2^8
        3 => 1024,     // 2^10
        4 => 65536,    // 2^16
        5 => 262144,   // 2^18  (reserved in some implementations)
        6 => 0,        // reserved
        7 => 0,        // reserved
        _ => 0,
    }
}

// ---------------------------------------------------------------------------
// FFI exports
// ---------------------------------------------------------------------------

/// Initialize the Intel VT-d IOMMU.
///
/// `mmio_base`: physical address of the DMAR unit's MMIO register set
///              (obtained from the ACPI DMAR table).
///
/// Reads version and capabilities, allocates root table and programs
/// RTADDR.  Does NOT enable translation -- call `intel_vtd_enable()` after
/// setting up device mappings.
///
/// Returns 0 on success, negative on error.
#[unsafe(no_mangle)]
pub extern "C" fn intel_vtd_init(mmio_base_phys: u64) -> i32 {
    if mmio_base_phys == 0 {
        log("intel_vtd: MMIO base address is zero");
        return -1;
    }

    unsafe {
        fut_printf(
            b"intel_vtd: initializing DMAR unit at phys 0x%llx\n\0".as_ptr(),
            mmio_base_phys,
        );
    }

    // ---- Step 1: Map the MMIO region ----
    let mmio_base = unsafe { map_mmio_region(mmio_base_phys, VTD_MMIO_SIZE, MMIO_DEFAULT_FLAGS) };
    if mmio_base.is_null() {
        log("intel_vtd: failed to map MMIO region");
        return -2;
    }

    // ---- Step 2: Read and validate version ----
    let ver = mmio_read32(mmio_base, REG_VER);
    let ver_major = (ver & 0x0F) as u8;
    let ver_minor = ((ver >> 4) & 0x0F) as u8;

    unsafe {
        fut_printf(
            b"intel_vtd: version %d.%d\n\0".as_ptr(),
            ver_major as u32,
            ver_minor as u32,
        );
    }

    // ---- Step 3: Read capabilities ----
    let cap = mmio_read64(mmio_base, REG_CAP);
    let ecap = mmio_read64(mmio_base, REG_ECAP);

    let sagaw = ((cap >> CAP_SAGAW_SHIFT) & CAP_SAGAW_MASK) as u8;
    let mgaw = ((cap >> CAP_MGAW_SHIFT) & CAP_MGAW_MASK) as u8;
    let nd_field = (cap >> CAP_ND_SHIFT) & CAP_ND_MASK;
    let num_domains = decode_num_domains(nd_field);
    let rwbf_required = (cap & CAP_RWBF) != 0;
    let num_fault_regs = (((cap >> CAP_NFR_SHIFT) & CAP_NFR_MASK) + 1) as u8;
    let fault_reg_offset = (((cap >> CAP_FRO_SHIFT) & CAP_FRO_MASK) as usize) * 16;
    let iotlb_reg_offset = (((ecap >> ECAP_IRO_SHIFT) & ECAP_IRO_MASK) as usize) * 16;

    unsafe {
        fut_printf(
            b"intel_vtd: CAP=0x%llx ECAP=0x%llx\n\0".as_ptr(),
            cap,
            ecap,
        );
        fut_printf(
            b"intel_vtd: SAGAW=0x%x MGAW=%d domains=%d NFR=%d FRO=0x%x IRO=0x%x\n\0".as_ptr(),
            sagaw as u32,
            (mgaw as u32) + 1,
            num_domains,
            num_fault_regs as u32,
            fault_reg_offset as u32,
            iotlb_reg_offset as u32,
        );
    }

    // Check that 4-level or 3-level paging is supported
    if sagaw & 0x06 == 0 {
        log("intel_vtd: no supported address width (need SAGAW bit 1 or 2)");
        unsafe { unmap_mmio_region(mmio_base, VTD_MMIO_SIZE); }
        return -3;
    }

    // Report ECAP features
    if ecap & ECAP_QI != 0 { log("intel_vtd: queued invalidation supported"); }
    if ecap & ECAP_IR != 0 { log("intel_vtd: interrupt remapping supported"); }
    if ecap & ECAP_PT != 0 { log("intel_vtd: pass-through supported"); }
    if ecap & ECAP_SC != 0 { log("intel_vtd: snoop control supported"); }

    // ---- Step 4: Disable translation before reconfiguring ----
    let gsts = mmio_read32(mmio_base, REG_GSTS);
    if gsts & GSTS_TES != 0 {
        log("intel_vtd: translation already enabled, disabling...");
        // To disable: write GCMD without TE bit.  The GCMD write must
        // preserve all status bits that we want to keep set.
        let gcmd = gsts & !GCMD_TE;
        mmio_write32(mmio_base, REG_GCMD, gcmd);
        // Wait for GSTS.TES to clear
        for _ in 0..1_000_000u32 {
            if mmio_read32(mmio_base, REG_GSTS) & GSTS_TES == 0 {
                break;
            }
            core::hint::spin_loop();
        }
    }

    // ---- Step 5: Allocate and program the Root Table ----
    let (root_virt, root_phys) = match alloc_zeroed_page() {
        Some(p) => p,
        None => {
            log("intel_vtd: failed to allocate Root Table");
            unsafe { unmap_mmio_region(mmio_base, VTD_MMIO_SIZE); }
            return -4;
        }
    };

    unsafe {
        fut_printf(
            b"intel_vtd: Root Table at phys 0x%llx\n\0".as_ptr(),
            root_phys,
        );
    }

    // ---- Step 6: Store controller state ----
    let state = VtdState {
        mmio_base,
        mmio_size: VTD_MMIO_SIZE,
        mmio_phys: mmio_base_phys,
        cap,
        ecap,
        ver_major,
        ver_minor,
        sagaw,
        mgaw,
        num_domains,
        num_fault_regs,
        fault_reg_offset,
        iotlb_reg_offset,
        rwbf_required,
        root_table: root_virt,
        root_table_phys: root_phys,
        ctx_tables: [0u64; ROOT_TABLE_ENTRIES],
        ctx_table_virts: [core::ptr::null_mut(); ROOT_TABLE_ENTRIES],
        pt_roots: [0u64; 256],
        next_domain_id: 1,
        enabled: false,
    };

    unsafe { *VTD.get() = Some(state); }

    // ---- Step 7: Program RTADDR and verify ----
    let st = match unsafe { (*VTD.get()).as_ref() } {
        Some(s) => s,
        None => {
            log("intel_vtd: internal error: state not stored");
            return -5;
        }
    };

    if !set_root_table_pointer(st) {
        log("intel_vtd: failed to set root table pointer");
        unsafe { *VTD.get() = None; }
        return -5;
    }

    // ---- Step 8: Flush write buffers and invalidate caches ----
    write_buffer_flush(st);
    invalidate_context_cache_global(st);
    invalidate_iotlb_global(st);

    log("intel_vtd: initialization complete (translation not yet enabled)");
    0
}

/// Enable VT-d translation.
///
/// Activates DMA remapping by setting GCMD.TE.  All devices without a
/// context entry will be blocked from DMA.  Ensure identity maps or
/// per-device maps are installed before calling this.
///
/// Returns 0 on success, negative on error.
#[unsafe(no_mangle)]
pub extern "C" fn intel_vtd_enable() -> i32 {
    let state = match unsafe { (*VTD.get()).as_mut() } {
        Some(s) => s,
        None => {
            log("intel_vtd: not initialized");
            return -1;
        }
    };

    if state.enabled {
        log("intel_vtd: already enabled");
        return 0;
    }

    // Flush before enabling
    full_invalidation(state);

    // Set GCMD.TE
    let gcmd = mmio_read32(state.mmio_base, REG_GSTS) | GCMD_TE;
    mmio_write32(state.mmio_base, REG_GCMD, gcmd);

    // Wait for GSTS.TES
    for _ in 0..1_000_000u32 {
        let gsts = mmio_read32(state.mmio_base, REG_GSTS);
        if gsts & GSTS_TES != 0 {
            state.enabled = true;
            let ctrl = mmio_read32(state.mmio_base, REG_GSTS);
            unsafe {
                fut_printf(
                    b"intel_vtd: translation enabled (GSTS=0x%08x)\n\0".as_ptr(),
                    ctrl,
                );
            }
            return 0;
        }
        core::hint::spin_loop();
    }

    log("intel_vtd: timeout waiting for translation enable");
    -2
}

/// Disable VT-d translation.
///
/// Clears GCMD.TE.  DMA from all devices will bypass the IOMMU.
///
/// Returns 0 on success, negative on error.
#[unsafe(no_mangle)]
pub extern "C" fn intel_vtd_disable() -> i32 {
    let state = match unsafe { (*VTD.get()).as_mut() } {
        Some(s) => s,
        None => {
            log("intel_vtd: not initialized");
            return -1;
        }
    };

    if !state.enabled {
        log("intel_vtd: already disabled");
        return 0;
    }

    // Clear GCMD.TE: write current GSTS with TE bit cleared
    let gcmd = mmio_read32(state.mmio_base, REG_GSTS) & !GCMD_TE;
    mmio_write32(state.mmio_base, REG_GCMD, gcmd);

    // Wait for GSTS.TES to clear
    for _ in 0..1_000_000u32 {
        let gsts = mmio_read32(state.mmio_base, REG_GSTS);
        if gsts & GSTS_TES == 0 {
            state.enabled = false;
            log("intel_vtd: translation disabled");
            return 0;
        }
        core::hint::spin_loop();
    }

    log("intel_vtd: timeout waiting for translation disable");
    -2
}

/// Set up 1:1 identity mapping for a device (IOVA == physical address).
///
/// Maps the first 4 GiB using 2 MiB super-pages in a 4-level VT-d page
/// table and installs a context table entry for the specified device.
///
/// Returns 0 on success, negative on error.
#[unsafe(no_mangle)]
pub extern "C" fn intel_vtd_identity_map(bus: u8, dev: u8, func: u8) -> i32 {
    let state = match unsafe { (*VTD.get()).as_mut() } {
        Some(s) => s,
        None => {
            log("intel_vtd: not initialized");
            return -1;
        }
    };

    // Allocate a PML4 page table
    let (_, pml4_phys) = match alloc_zeroed_page() {
        Some(p) => p,
        None => {
            log("intel_vtd: failed to allocate PML4 page table");
            return -2;
        }
    };

    // Build the 1:1 identity map (first 4 GiB)
    if !setup_identity_map(pml4_phys) {
        log("intel_vtd: failed to build identity mapping");
        return -3;
    }

    // Allocate a domain ID
    let domain_id = alloc_domain_id(state);

    // Store the page table root
    let idx = bdf_to_index(bus, dev, func);
    state.pt_roots[idx] = pml4_phys;

    // Install context table entry
    if !write_context_entry(state, bus, dev, func, pml4_phys, domain_id, CTX_TT_MULTI_LEVEL) {
        log("intel_vtd: failed to write context table entry");
        return -4;
    }

    // Invalidate caches if translation is active
    if state.enabled {
        full_invalidation(state);
    }

    unsafe {
        fut_printf(
            b"intel_vtd: identity map configured for %02x:%02x.%x (domain %d)\n\0".as_ptr(),
            bus as u32,
            dev as u32,
            func as u32,
            domain_id as u32,
        );
    }

    0
}

/// Map a DMA region for a specific device.
///
/// Creates a mapping from IOVA to physical address in the device's I/O page
/// table.  If the device does not yet have a page table or context entry,
/// they are allocated automatically.
///
/// `flags`: bit 0 = read, bit 1 = write
///
/// Returns 0 on success, negative on error.
#[unsafe(no_mangle)]
pub extern "C" fn intel_vtd_map_device(
    bus: u8,
    dev: u8,
    func: u8,
    iova: u64,
    phys: u64,
    size: u64,
    flags: u32,
) -> i32 {
    let state = match unsafe { (*VTD.get()).as_mut() } {
        Some(s) => s,
        None => {
            log("intel_vtd: not initialized");
            return -1;
        }
    };

    if size == 0 {
        return -2;
    }

    let read  = (flags & 1) != 0;
    let write = (flags & 2) != 0;

    let idx = bdf_to_index(bus, dev, func);

    // Ensure the device has a page table allocated
    if state.pt_roots[idx] == 0 {
        let (_, pml4_phys) = match alloc_zeroed_page() {
            Some(p) => p,
            None => {
                log("intel_vtd: failed to allocate PML4 for device");
                return -3;
            }
        };
        state.pt_roots[idx] = pml4_phys;

        // Allocate domain and install context entry
        let domain_id = alloc_domain_id(state);
        if !write_context_entry(state, bus, dev, func, pml4_phys, domain_id, CTX_TT_MULTI_LEVEL) {
            log("intel_vtd: failed to write context table entry");
            return -4;
        }
    }

    let pml4_phys = state.pt_roots[idx];

    // Map each 4K page in the range
    let aligned_iova = iova & !0xFFF;
    let end = (iova + size + 0xFFF) & !0xFFF;
    let mut current_iova = aligned_iova;
    let mut current_phys = phys & !0xFFF;

    while current_iova < end {
        if !io_pt_map_4k(pml4_phys, current_iova, current_phys, read, write) {
            log("intel_vtd: failed to map page in I/O page table");
            return -5;
        }
        current_iova += PAGE_SIZE_4K;
        current_phys += PAGE_SIZE_4K;
    }

    // Invalidate IOTLB if translation is active
    if state.enabled {
        write_buffer_flush(state);
        invalidate_iotlb_global(state);
    }

    0
}

/// Unmap a DMA region for a specific device.
///
/// Clears the leaf page table entries for the given IOVA range.
/// Does not free intermediate page table levels.
///
/// Returns 0 on success, negative on error.
#[unsafe(no_mangle)]
pub extern "C" fn intel_vtd_unmap_device(
    bus: u8,
    dev: u8,
    func: u8,
    iova: u64,
    size: u64,
) -> i32 {
    let state = match unsafe { (*VTD.get()).as_mut() } {
        Some(s) => s,
        None => {
            log("intel_vtd: not initialized");
            return -1;
        }
    };

    let idx = bdf_to_index(bus, dev, func);
    let pml4_phys = state.pt_roots[idx];
    if pml4_phys == 0 {
        log("intel_vtd: device has no page table");
        return -2;
    }

    if size == 0 {
        return 0;
    }

    // Unmap each 4K page in the range
    let aligned_iova = iova & !0xFFF;
    let end = (iova + size + 0xFFF) & !0xFFF;
    let mut current_iova = aligned_iova;

    while current_iova < end {
        // Entry may not exist -- not necessarily an error
        io_pt_unmap_4k(pml4_phys, current_iova);
        current_iova += PAGE_SIZE_4K;
    }

    // Invalidate IOTLB if translation is active
    if state.enabled {
        write_buffer_flush(state);
        invalidate_iotlb_global(state);
    }

    0
}

/// Flush the global IOTLB and context cache.
///
/// Performs a full invalidation sequence: write-buffer flush, context-cache
/// invalidation, and IOTLB invalidation.
///
/// Returns 0 on success, negative on error.
#[unsafe(no_mangle)]
pub extern "C" fn intel_vtd_flush_iotlb() -> i32 {
    let state = match unsafe { (*VTD.get()).as_ref() } {
        Some(s) => s,
        None => {
            log("intel_vtd: not initialized");
            return -1;
        }
    };

    full_invalidation(state);
    0
}

/// Poll for and report any pending DMA faults.
///
/// Reads all fault recording registers, logs each fault with the faulting
/// device BDF, address, and reason, then clears the records.
///
/// Returns the number of faults processed, or negative on error.
#[unsafe(no_mangle)]
pub extern "C" fn intel_vtd_poll_faults() -> i32 {
    let state = match unsafe { (*VTD.get()).as_ref() } {
        Some(s) => s,
        None => {
            log("intel_vtd: not initialized");
            return -1;
        }
    };

    read_and_clear_faults(state)
}
