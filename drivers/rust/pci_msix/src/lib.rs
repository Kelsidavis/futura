// SPDX-License-Identifier: MPL-2.0
//
// PCI MSI-X (Message Signaled Interrupts Extended) Infrastructure Driver
//
// Implements the MSI-X capability defined in PCI 3.0 / PCIe specifications,
// providing per-vector interrupt steering for PCIe devices on x86 platforms.
//
// Architecture:
//   - Walks PCI capability list to locate MSI-X capability (ID 0x11)
//   - Maps MSI-X table and PBA from the BAR indicated by the BIR field
//   - Configures individual vectors with LAPIC destination and vector number
//   - Supports per-vector and function-level masking
//
// Up to 8 devices tracked simultaneously in a static array (no heap for tracking).

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(unexpected_cfgs)]

use core::ffi::c_void;
use core::ptr::{read_volatile, write_volatile};

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

// ── StaticCell for safe global mutable state ──

struct StaticCell<T>(core::cell::UnsafeCell<T>);
unsafe impl<T> Sync for StaticCell<T> {}

impl<T> StaticCell<T> {
    const fn new(v: T) -> Self {
        Self(core::cell::UnsafeCell::new(v))
    }

    fn get(&self) -> *mut T {
        self.0.get()
    }
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

// ── MSI-X constants ──

/// MSI-X capability ID in PCI config space
const MSIX_CAP_ID: u8 = 0x11;

/// Offsets within the MSI-X capability structure
const MSIX_MSG_CTRL: u8 = 0x02;   // Message Control (16-bit)
const MSIX_TABLE_OFF: u8 = 0x04;  // Table Offset / BIR (32-bit)
const MSIX_PBA_OFF: u8 = 0x08;    // PBA Offset / BIR (32-bit)

/// Message Control register bits
const MSIX_CTRL_ENABLE: u16 = 1 << 15;
const MSIX_CTRL_FUNC_MASK: u16 = 1 << 14;
const MSIX_CTRL_TABLE_SIZE_MASK: u16 = 0x07FF; // bits [10:0]

/// MSI-X table entry offsets (each entry is 16 bytes)
const MSIX_ENTRY_SIZE: usize = 16;
const MSIX_ENTRY_ADDR_LO: usize = 0x00;
const MSIX_ENTRY_ADDR_HI: usize = 0x04;
const MSIX_ENTRY_DATA: usize = 0x08;
const MSIX_ENTRY_VECTOR_CTRL: usize = 0x0C;

/// Vector control mask bit
const MSIX_VECTOR_CTRL_MASK: u32 = 1 << 0;

/// x86 LAPIC MSI address base
const MSI_ADDR_BASE: u32 = 0xFEE0_0000;

/// PCI config offset for capabilities pointer (type 0 header)
const PCI_CAP_PTR: u8 = 0x34;

/// PCI Status register offset and capability-list bit
const PCI_STATUS: u8 = 0x06;
const PCI_STATUS_CAP_LIST: u16 = 1 << 4;

/// BAR0-BAR5 config space offsets
const PCI_BAR0: u8 = 0x10;

/// Maximum number of tracked MSI-X devices
const MAX_MSIX_DEVICES: usize = 8;

// ── Per-device MSI-X state ──

#[derive(Clone, Copy)]
struct MsixDeviceState {
    /// Device identification
    bus: u8,
    dev: u8,
    func: u8,
    /// Whether this slot is in use
    active: bool,
    /// Capability offset in PCI config space
    cap_offset: u8,
    /// Number of table entries (table_size field + 1)
    table_size: u16,
    /// Virtual address of the mapped MSI-X table
    table_vaddr: *mut u8,
    /// Physical address of the MSI-X table
    table_paddr: u64,
    /// Size in bytes of the mapped MSI-X table region
    table_map_size: usize,
    /// Virtual address of the mapped PBA
    pba_vaddr: *mut u8,
    /// Physical address of the PBA
    pba_paddr: u64,
    /// Size in bytes of the mapped PBA region
    pba_map_size: usize,
}

impl MsixDeviceState {
    const fn empty() -> Self {
        Self {
            bus: 0,
            dev: 0,
            func: 0,
            active: false,
            cap_offset: 0,
            table_size: 0,
            table_vaddr: core::ptr::null_mut(),
            table_paddr: 0,
            table_map_size: 0,
            pba_vaddr: core::ptr::null_mut(),
            pba_paddr: 0,
            pba_map_size: 0,
        }
    }
}

// ── Global device state ──

static DEVICES: StaticCell<[MsixDeviceState; MAX_MSIX_DEVICES]> =
    StaticCell::new([MsixDeviceState::empty(); MAX_MSIX_DEVICES]);

// ── Internal helpers ──

/// Walk the PCI capability list and return the config-space offset of the
/// MSI-X capability, or 0 if not found.
fn find_msix_cap(bus: u8, dev: u8, func: u8) -> u8 {
    // Check that the device supports a capability list
    let status = pci_read16(bus, dev, func, PCI_STATUS);
    if status & PCI_STATUS_CAP_LIST == 0 {
        return 0;
    }

    // Capabilities pointer is at offset 0x34 (low byte only, dword-aligned)
    let mut ptr = pci_read8(bus, dev, func, PCI_CAP_PTR) & 0xFC;
    let mut visited = 0u32;

    while ptr != 0 && visited < 48 {
        let cap_id = pci_read8(bus, dev, func, ptr);
        if cap_id == MSIX_CAP_ID {
            return ptr;
        }
        ptr = pci_read8(bus, dev, func, ptr + 1) & 0xFC;
        visited += 1;
    }

    0
}

/// Read a BAR value (32 or 64-bit) and return the physical base address.
fn read_bar_addr(bus: u8, dev: u8, func: u8, bar_index: u8) -> u64 {
    let bar_offset = PCI_BAR0 + bar_index * 4;
    let bar_lo = pci_read32(bus, dev, func, bar_offset);

    // Memory BAR (bit 0 = 0)
    if bar_lo & 1 != 0 {
        // I/O BAR — not valid for MSI-X table
        return 0;
    }

    let bar_type = (bar_lo >> 1) & 0x03;
    let addr_lo = (bar_lo & 0xFFFF_FFF0) as u64;

    if bar_type == 0x02 {
        // 64-bit BAR: next BAR register holds upper 32 bits
        let bar_hi = pci_read32(bus, dev, func, bar_offset + 4) as u64;
        addr_lo | (bar_hi << 32)
    } else {
        addr_lo
    }
}

/// Find or allocate a slot in the device array for the given BDF.
/// Returns a mutable reference index, or None if full and not found.
fn find_device_slot(bus: u8, dev: u8, func: u8) -> Option<usize> {
    let devs = unsafe { &mut *DEVICES.get() };
    let mut free_slot: Option<usize> = None;

    for i in 0..MAX_MSIX_DEVICES {
        if devs[i].active && devs[i].bus == bus && devs[i].dev == dev && devs[i].func == func {
            return Some(i);
        }
        if !devs[i].active && free_slot.is_none() {
            free_slot = Some(i);
        }
    }

    free_slot
}

/// Look up an active device by BDF. Returns index or None.
fn lookup_device(bus: u8, dev: u8, func: u8) -> Option<usize> {
    let devs = unsafe { &*DEVICES.get() };
    for i in 0..MAX_MSIX_DEVICES {
        if devs[i].active && devs[i].bus == bus && devs[i].dev == dev && devs[i].func == func {
            return Some(i);
        }
    }
    None
}

/// Round up to page boundary (4 KiB).
fn page_align(size: usize) -> usize {
    (size + 0xFFF) & !0xFFF
}

// ── Exported API ──

/// Find the MSI-X capability for a PCI device.
/// Returns the capability offset in config space (>0) on success, or -1 if
/// the device does not support MSI-X.
#[unsafe(no_mangle)]
pub extern "C" fn pci_msix_find(bus: u8, dev: u8, func: u8) -> i32 {
    let cap = find_msix_cap(bus, dev, func);
    if cap == 0 {
        -1
    } else {
        cap as i32
    }
}

/// Initialize MSI-X for a device: find the capability, map the table and PBA
/// MMIO regions, mask all vectors, and enable MSI-X.
/// Returns 0 on success, negative on error.
#[unsafe(no_mangle)]
pub extern "C" fn pci_msix_init(bus: u8, dev: u8, func: u8) -> i32 {
    let cap_off = find_msix_cap(bus, dev, func);
    if cap_off == 0 {
        log("pci_msix: no MSI-X capability found");
        return -1;
    }

    // Read Message Control
    let msg_ctrl = pci_read16(bus, dev, func, cap_off + MSIX_MSG_CTRL);
    let table_size = (msg_ctrl & MSIX_CTRL_TABLE_SIZE_MASK) + 1;

    // Read Table Offset/BIR
    let table_off_bir = pci_read32(bus, dev, func, cap_off + MSIX_TABLE_OFF);
    let table_bir = (table_off_bir & 0x07) as u8;
    let table_offset = (table_off_bir & !0x07) as u64;

    // Read PBA Offset/BIR
    let pba_off_bir = pci_read32(bus, dev, func, cap_off + MSIX_PBA_OFF);
    let pba_bir = (pba_off_bir & 0x07) as u8;
    let pba_offset = (pba_off_bir & !0x07) as u64;

    // Read BAR addresses
    let table_bar_base = read_bar_addr(bus, dev, func, table_bir);
    if table_bar_base == 0 {
        log("pci_msix: invalid table BAR");
        return -2;
    }

    let pba_bar_base = read_bar_addr(bus, dev, func, pba_bir);
    if pba_bar_base == 0 {
        log("pci_msix: invalid PBA BAR");
        return -3;
    }

    let table_phys = table_bar_base + table_offset;
    let pba_phys = pba_bar_base + pba_offset;

    // Calculate region sizes
    let table_bytes = (table_size as usize) * MSIX_ENTRY_SIZE;
    let table_map_size = page_align(table_bytes);

    // PBA: one bit per vector, rounded to 8 bytes (qword), then page-aligned
    let pba_bytes = (((table_size as usize) + 63) / 64) * 8;
    let pba_map_size = page_align(pba_bytes);

    // Map the MSI-X table
    let table_vaddr = unsafe { map_mmio_region(table_phys, table_map_size, MMIO_DEFAULT_FLAGS) };
    if table_vaddr.is_null() {
        log("pci_msix: failed to map MSI-X table");
        return -4;
    }

    // Map the PBA
    let pba_vaddr = unsafe { map_mmio_region(pba_phys, pba_map_size, MMIO_DEFAULT_FLAGS) };
    if pba_vaddr.is_null() {
        unsafe { unmap_mmio_region(table_vaddr, table_map_size) };
        log("pci_msix: failed to map PBA");
        return -5;
    }

    // Allocate a slot in our tracking array
    let slot = match find_device_slot(bus, dev, func) {
        Some(s) => s,
        None => {
            unsafe {
                unmap_mmio_region(table_vaddr, table_map_size);
                unmap_mmio_region(pba_vaddr, pba_map_size);
            }
            log("pci_msix: no free device slots");
            return -6;
        }
    };

    let devs = unsafe { &mut *DEVICES.get() };

    // If re-initializing, unmap previous mappings
    if devs[slot].active {
        if !devs[slot].table_vaddr.is_null() {
            unsafe { unmap_mmio_region(devs[slot].table_vaddr, devs[slot].table_map_size) };
        }
        if !devs[slot].pba_vaddr.is_null() {
            unsafe { unmap_mmio_region(devs[slot].pba_vaddr, devs[slot].pba_map_size) };
        }
    }

    devs[slot] = MsixDeviceState {
        bus,
        dev,
        func,
        active: true,
        cap_offset: cap_off,
        table_size,
        table_vaddr,
        table_paddr: table_phys,
        table_map_size,
        pba_vaddr,
        pba_paddr: pba_phys,
        pba_map_size,
    };

    // Mask all vectors before enabling
    for i in 0..table_size as usize {
        let entry = unsafe { table_vaddr.add(i * MSIX_ENTRY_SIZE + MSIX_ENTRY_VECTOR_CTRL) };
        unsafe { write_volatile(entry as *mut u32, MSIX_VECTOR_CTRL_MASK) };
    }

    // Enable MSI-X with function mask set (caller can unmask later)
    let ctrl = pci_read16(bus, dev, func, cap_off + MSIX_MSG_CTRL);
    pci_write16(
        bus, dev, func,
        cap_off + MSIX_MSG_CTRL,
        ctrl | MSIX_CTRL_ENABLE | MSIX_CTRL_FUNC_MASK,
    );

    unsafe {
        fut_printf(
            b"pci_msix: init %02x:%02x.%x - %u vectors, table @ 0x%lx, PBA @ 0x%lx\n\0".as_ptr(),
            bus as u32,
            dev as u32,
            func as u32,
            table_size as u32,
            table_phys,
            pba_phys,
        );
    }

    0
}

/// Enable MSI-X for a previously initialized device (clears function mask).
/// Returns 0 on success, -1 if the device is not initialized.
#[unsafe(no_mangle)]
pub extern "C" fn pci_msix_enable(bus: u8, dev: u8, func: u8) -> i32 {
    let slot = match lookup_device(bus, dev, func) {
        Some(s) => s,
        None => return -1,
    };

    let devs = unsafe { &*DEVICES.get() };
    let cap_off = devs[slot].cap_offset;

    let ctrl = pci_read16(bus, dev, func, cap_off + MSIX_MSG_CTRL);
    // Set Enable, clear Function Mask
    pci_write16(
        bus, dev, func,
        cap_off + MSIX_MSG_CTRL,
        (ctrl | MSIX_CTRL_ENABLE) & !MSIX_CTRL_FUNC_MASK,
    );

    0
}

/// Disable MSI-X for a previously initialized device.
/// Returns 0 on success, -1 if the device is not initialized.
#[unsafe(no_mangle)]
pub extern "C" fn pci_msix_disable(bus: u8, dev: u8, func: u8) -> i32 {
    let slot = match lookup_device(bus, dev, func) {
        Some(s) => s,
        None => return -1,
    };

    let devs = unsafe { &*DEVICES.get() };
    let cap_off = devs[slot].cap_offset;

    let ctrl = pci_read16(bus, dev, func, cap_off + MSIX_MSG_CTRL);
    pci_write16(
        bus, dev, func,
        cap_off + MSIX_MSG_CTRL,
        ctrl & !MSIX_CTRL_ENABLE,
    );

    0
}

/// Return the MSI-X table size (number of vectors) for a device.
/// Returns 0 if the device has no MSI-X capability. Does not require prior init.
#[unsafe(no_mangle)]
pub extern "C" fn pci_msix_table_size(bus: u8, dev: u8, func: u8) -> u32 {
    // First check if we have it tracked
    if let Some(slot) = lookup_device(bus, dev, func) {
        let devs = unsafe { &*DEVICES.get() };
        return devs[slot].table_size as u32;
    }

    // Otherwise read directly from config space
    let cap_off = find_msix_cap(bus, dev, func);
    if cap_off == 0 {
        return 0;
    }

    let msg_ctrl = pci_read16(bus, dev, func, cap_off + MSIX_MSG_CTRL);
    ((msg_ctrl & MSIX_CTRL_TABLE_SIZE_MASK) + 1) as u32
}

/// Configure an MSI-X table entry to deliver the given interrupt vector
/// to the specified LAPIC destination. The vector is left masked; use
/// `pci_msix_unmask_vector` to arm it.
/// Returns 0 on success, negative on error.
#[unsafe(no_mangle)]
pub extern "C" fn pci_msix_set_vector(
    bus: u8,
    dev: u8,
    func: u8,
    index: u32,
    vector: u8,
    dest_apic: u8,
) -> i32 {
    let slot = match lookup_device(bus, dev, func) {
        Some(s) => s,
        None => return -1,
    };

    let devs = unsafe { &*DEVICES.get() };
    let state = &devs[slot];

    if index >= state.table_size as u32 {
        return -2;
    }

    let entry_base = unsafe { state.table_vaddr.add(index as usize * MSIX_ENTRY_SIZE) };

    // Compute x86 LAPIC MSI address: 0xFEE00000 | (dest_apic_id << 12)
    let msg_addr = MSI_ADDR_BASE | ((dest_apic as u32) << 12);
    let msg_data = vector as u32;

    unsafe {
        // Mask the vector first (safe modification)
        write_volatile(
            entry_base.add(MSIX_ENTRY_VECTOR_CTRL) as *mut u32,
            MSIX_VECTOR_CTRL_MASK,
        );
        // Write address low
        write_volatile(entry_base.add(MSIX_ENTRY_ADDR_LO) as *mut u32, msg_addr);
        // Write address high (zero for sub-4 GiB LAPIC address)
        write_volatile(entry_base.add(MSIX_ENTRY_ADDR_HI) as *mut u32, 0);
        // Write data (vector number)
        write_volatile(entry_base.add(MSIX_ENTRY_DATA) as *mut u32, msg_data);
    }

    0
}

/// Mask a single MSI-X vector (set the per-vector mask bit).
/// Returns 0 on success, negative on error.
#[unsafe(no_mangle)]
pub extern "C" fn pci_msix_mask_vector(bus: u8, dev: u8, func: u8, index: u32) -> i32 {
    let slot = match lookup_device(bus, dev, func) {
        Some(s) => s,
        None => return -1,
    };

    let devs = unsafe { &*DEVICES.get() };
    let state = &devs[slot];

    if index >= state.table_size as u32 {
        return -2;
    }

    let ctrl_ptr = unsafe {
        state.table_vaddr.add(index as usize * MSIX_ENTRY_SIZE + MSIX_ENTRY_VECTOR_CTRL)
    } as *mut u32;

    unsafe {
        let ctrl = read_volatile(ctrl_ptr);
        write_volatile(ctrl_ptr, ctrl | MSIX_VECTOR_CTRL_MASK);
    }

    0
}

/// Unmask a single MSI-X vector (clear the per-vector mask bit).
/// Returns 0 on success, negative on error.
#[unsafe(no_mangle)]
pub extern "C" fn pci_msix_unmask_vector(bus: u8, dev: u8, func: u8, index: u32) -> i32 {
    let slot = match lookup_device(bus, dev, func) {
        Some(s) => s,
        None => return -1,
    };

    let devs = unsafe { &*DEVICES.get() };
    let state = &devs[slot];

    if index >= state.table_size as u32 {
        return -2;
    }

    let ctrl_ptr = unsafe {
        state.table_vaddr.add(index as usize * MSIX_ENTRY_SIZE + MSIX_ENTRY_VECTOR_CTRL)
    } as *mut u32;

    unsafe {
        let ctrl = read_volatile(ctrl_ptr);
        write_volatile(ctrl_ptr, ctrl & !MSIX_VECTOR_CTRL_MASK);
    }

    0
}

/// Check whether a vector has a pending interrupt (reads the PBA).
/// Returns 1 if pending, 0 if not, negative on error.
#[unsafe(no_mangle)]
pub extern "C" fn pci_msix_is_pending(bus: u8, dev: u8, func: u8, index: u32) -> i32 {
    let slot = match lookup_device(bus, dev, func) {
        Some(s) => s,
        None => return -1,
    };

    let devs = unsafe { &*DEVICES.get() };
    let state = &devs[slot];

    if index >= state.table_size as u32 {
        return -2;
    }

    // PBA is a bitfield: one bit per vector, stored as an array of 64-bit words
    let qword_index = (index / 64) as usize;
    let bit_index = index % 64;

    let pba_ptr = unsafe { state.pba_vaddr.add(qword_index * 8) } as *const u64;
    let pba_val = unsafe { read_volatile(pba_ptr) };

    if pba_val & (1u64 << bit_index) != 0 {
        1
    } else {
        0
    }
}

/// Set the function-level mask (mask all vectors at once via Message Control).
/// Returns 0 on success, -1 if the device is not initialized.
#[unsafe(no_mangle)]
pub extern "C" fn pci_msix_function_mask(bus: u8, dev: u8, func: u8) -> i32 {
    let slot = match lookup_device(bus, dev, func) {
        Some(s) => s,
        None => return -1,
    };

    let devs = unsafe { &*DEVICES.get() };
    let cap_off = devs[slot].cap_offset;

    let ctrl = pci_read16(bus, dev, func, cap_off + MSIX_MSG_CTRL);
    pci_write16(bus, dev, func, cap_off + MSIX_MSG_CTRL, ctrl | MSIX_CTRL_FUNC_MASK);

    0
}

/// Clear the function-level mask (unmask all vectors via Message Control).
/// Returns 0 on success, -1 if the device is not initialized.
#[unsafe(no_mangle)]
pub extern "C" fn pci_msix_function_unmask(bus: u8, dev: u8, func: u8) -> i32 {
    let slot = match lookup_device(bus, dev, func) {
        Some(s) => s,
        None => return -1,
    };

    let devs = unsafe { &*DEVICES.get() };
    let cap_off = devs[slot].cap_offset;

    let ctrl = pci_read16(bus, dev, func, cap_off + MSIX_MSG_CTRL);
    pci_write16(bus, dev, func, cap_off + MSIX_MSG_CTRL, ctrl & !MSIX_CTRL_FUNC_MASK);

    0
}
