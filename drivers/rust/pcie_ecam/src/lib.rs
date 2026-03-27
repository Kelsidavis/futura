// SPDX-License-Identifier: MPL-2.0
//
// PCIe ECAM (Enhanced Configuration Access Mechanism) Driver for Futura OS
//
// Provides MMIO-based access to the full 4 KiB PCIe configuration space
// per function, replacing legacy I/O port access (which is limited to 256
// bytes). The ECAM base address is typically discovered via the ACPI MCFG
// table and passed to pcie_ecam_init().
//
// Architecture (x86-64):
//   - ECAM maps each function's 4 KiB config space contiguously in MMIO
//   - Address: base + ((bus - start_bus) << 20) | (dev << 15) | (func << 12) | offset
//   - Supports full 4096-byte PCIe extended config space
//   - Recursive bridge scanning for complete bus enumeration
//   - PCIe capability parsing (link speed/width)
//   - Extended capability enumeration (AER, serial number, etc.)
//
// Typical ECAM base addresses:
//   - Intel: 0xE0000000
//   - AMD:   0xF0000000 (Ryzen AM4/AM5)

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(unexpected_cfgs)]

use core::cell::UnsafeCell;
use core::ptr::{read_volatile, write_volatile};

use common::{log, map_mmio_region, unmap_mmio_region, MMIO_DEFAULT_FLAGS};

// ── FFI imports ──

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

// ── PCIe configuration space offsets ──

const CFG_VENDOR_ID: u16 = 0x00;
const CFG_DEVICE_ID: u16 = 0x02;
const CFG_COMMAND: u16 = 0x04;
const CFG_STATUS: u16 = 0x06;
const CFG_REVISION: u16 = 0x08;
const CFG_PROG_IF: u16 = 0x09;
const CFG_SUBCLASS: u16 = 0x0A;
const CFG_CLASS_CODE: u16 = 0x0B;
const CFG_HEADER_TYPE: u16 = 0x0E;
const CFG_CAP_PTR: u16 = 0x34;

// PCI-to-PCI bridge (header type 1) registers
const CFG_PRIMARY_BUS: u16 = 0x18;
const CFG_SECONDARY_BUS: u16 = 0x19;
const CFG_SUBORDINATE_BUS: u16 = 0x1A;

// Status register bits
const STATUS_CAP_LIST: u16 = 1 << 4;

// Capability IDs
const CAP_ID_PCIE: u8 = 0x10;

// PCIe Capability register offsets (from capability base)
const PCIE_CAP_FLAGS: u16 = 0x02;
const PCIE_LINK_CAP: u16 = 0x0C;
const PCIE_LINK_STATUS: u16 = 0x12;

// Extended Capability IDs (beyond offset 0x100)
const ECAP_AER: u16 = 0x0001;
const ECAP_VC: u16 = 0x0002;
const ECAP_SERIAL_NUMBER: u16 = 0x0003;
const ECAP_ACS: u16 = 0x0010;
const ECAP_ARI: u16 = 0x0011;
const ECAP_L1PM: u16 = 0x001E;

// AER register offsets (from extended capability base)
const AER_UNCORRECTABLE_STATUS: u16 = 0x04;
const AER_UNCORRECTABLE_MASK: u16 = 0x08;
const AER_CORRECTABLE_STATUS: u16 = 0x10;
const AER_CORRECTABLE_MASK: u16 = 0x14;

// Device Serial Number register offsets (from extended capability base)
const DSN_LOWER: u16 = 0x04;
const DSN_UPPER: u16 = 0x08;

// Maximum devices we can track
const MAX_DEVICES: usize = 256;

// ── PCIe device descriptor ──

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PcieDevice {
    bus: u8,
    dev: u8,
    func: u8,
    vendor_id: u16,
    device_id: u16,
    class_code: u8,
    subclass: u8,
    prog_if: u8,
    header_type: u8,
    pcie_cap_offset: u16,
    link_speed: u8,
    link_width: u8,
    segment: u16,
}

impl PcieDevice {
    const fn empty() -> Self {
        Self {
            bus: 0,
            dev: 0,
            func: 0,
            vendor_id: 0,
            device_id: 0,
            class_code: 0,
            subclass: 0,
            prog_if: 0,
            header_type: 0,
            pcie_cap_offset: 0,
            link_speed: 0,
            link_width: 0,
            segment: 0,
        }
    }
}

// ── ECAM controller state ──

struct EcamState {
    /// Virtual base address of the mapped ECAM region
    vbase: *mut u8,
    /// Physical base address from MCFG
    pbase: u64,
    /// First bus number in this segment
    start_bus: u8,
    /// Last bus number in this segment
    end_bus: u8,
    /// Size of the mapped MMIO region in bytes
    map_size: usize,
    /// Whether the ECAM is initialized
    initialized: bool,
}

impl EcamState {
    const fn new() -> Self {
        Self {
            vbase: core::ptr::null_mut(),
            pbase: 0,
            start_bus: 0,
            end_bus: 0,
            map_size: 0,
            initialized: false,
        }
    }
}

// ── Global state ──

static STATE: StaticCell<EcamState> = StaticCell::new(EcamState::new());
static DEVICES: StaticCell<[PcieDevice; MAX_DEVICES]> =
    StaticCell::new([PcieDevice::empty(); MAX_DEVICES]);
static DEVICE_COUNT: StaticCell<u32> = StaticCell::new(0);

// ── Internal helpers ──

/// Calculate the virtual address for a config space register.
/// Returns null if the bus/dev/func/offset is out of range.
fn ecam_addr(bus: u8, dev: u8, func: u8, offset: u16) -> *mut u8 {
    let st = unsafe { &*STATE.get() };
    if !st.initialized || bus < st.start_bus || bus > st.end_bus {
        return core::ptr::null_mut();
    }
    if dev > 31 || func > 7 || offset > 0xFFF {
        return core::ptr::null_mut();
    }

    let bus_offset = (bus - st.start_bus) as usize;
    let addr = (bus_offset << 20)
        | ((dev as usize) << 15)
        | ((func as usize) << 12)
        | (offset as usize);

    if addr >= st.map_size {
        return core::ptr::null_mut();
    }

    unsafe { st.vbase.add(addr) }
}

/// Read 8 bits from ECAM config space.
fn ecam_read8_internal(bus: u8, dev: u8, func: u8, offset: u16) -> u8 {
    let ptr = ecam_addr(bus, dev, func, offset);
    if ptr.is_null() {
        return 0xFF;
    }
    unsafe { read_volatile(ptr) }
}

/// Read 16 bits from ECAM config space (offset must be 2-byte aligned).
fn ecam_read16_internal(bus: u8, dev: u8, func: u8, offset: u16) -> u16 {
    let ptr = ecam_addr(bus, dev, func, offset & 0xFFE);
    if ptr.is_null() {
        return 0xFFFF;
    }
    unsafe { read_volatile(ptr as *const u16) }
}

/// Read 32 bits from ECAM config space (offset must be 4-byte aligned).
fn ecam_read32_internal(bus: u8, dev: u8, func: u8, offset: u16) -> u32 {
    let ptr = ecam_addr(bus, dev, func, offset & 0xFFC);
    if ptr.is_null() {
        return 0xFFFF_FFFF;
    }
    unsafe { read_volatile(ptr as *const u32) }
}

/// Write 8 bits to ECAM config space.
fn ecam_write8_internal(bus: u8, dev: u8, func: u8, offset: u16, val: u8) {
    let ptr = ecam_addr(bus, dev, func, offset);
    if ptr.is_null() {
        return;
    }
    unsafe { write_volatile(ptr, val) };
}

/// Write 16 bits to ECAM config space (offset must be 2-byte aligned).
fn ecam_write16_internal(bus: u8, dev: u8, func: u8, offset: u16, val: u16) {
    let ptr = ecam_addr(bus, dev, func, offset & 0xFFE);
    if ptr.is_null() {
        return;
    }
    unsafe { write_volatile(ptr as *mut u16, val) };
}

/// Write 32 bits to ECAM config space (offset must be 4-byte aligned).
fn ecam_write32_internal(bus: u8, dev: u8, func: u8, offset: u16, val: u32) {
    let ptr = ecam_addr(bus, dev, func, offset & 0xFFC);
    if ptr.is_null() {
        return;
    }
    unsafe { write_volatile(ptr as *mut u32, val) };
}

/// Walk the PCI capability list and return the offset of the capability
/// with the given ID, or 0 if not found.
fn find_cap(bus: u8, dev: u8, func: u8, cap_id: u8) -> u16 {
    let status = ecam_read16_internal(bus, dev, func, CFG_STATUS);
    if status & STATUS_CAP_LIST == 0 {
        return 0;
    }

    let mut ptr = (ecam_read8_internal(bus, dev, func, CFG_CAP_PTR) & 0xFC) as u16;
    let mut visited = 0u32;

    while ptr != 0 && ptr >= 0x40 && visited < 48 {
        let id = ecam_read8_internal(bus, dev, func, ptr);
        if id == cap_id {
            return ptr;
        }
        ptr = (ecam_read8_internal(bus, dev, func, ptr + 1) & 0xFC) as u16;
        visited += 1;
    }

    0
}

/// Walk the PCIe extended capability list (starting at offset 0x100).
/// Returns the offset of the extended capability with the given ID, or 0.
fn find_ext_cap(bus: u8, dev: u8, func: u8, ext_cap_id: u16) -> u16 {
    let mut offset: u16 = 0x100;
    let mut visited = 0u32;

    while offset != 0 && offset >= 0x100 && offset < 0x1000 && visited < 96 {
        let header = ecam_read32_internal(bus, dev, func, offset);
        if header == 0 || header == 0xFFFF_FFFF {
            break;
        }

        let id = (header & 0xFFFF) as u16;
        let next = ((header >> 20) & 0xFFC) as u16;

        if id == ext_cap_id {
            return offset;
        }

        offset = next;
        visited += 1;
    }

    0
}

/// Parse PCIe link capabilities from the PCIe Capability structure.
/// Returns (link_speed, link_width) from the Link Status register.
fn parse_link_status(bus: u8, dev: u8, func: u8, pcie_cap: u16) -> (u8, u8) {
    if pcie_cap == 0 {
        return (0, 0);
    }

    let link_status = ecam_read16_internal(bus, dev, func, pcie_cap + PCIE_LINK_STATUS);
    let speed = (link_status & 0x0F) as u8;       // bits [3:0]: current link speed
    let width = ((link_status >> 4) & 0x3F) as u8; // bits [9:4]: negotiated link width

    (speed, width)
}

/// Read the PCIe Device Serial Number extended capability.
/// Returns (lower_dword, upper_dword) or (0, 0) if not present.
fn read_serial_number(bus: u8, dev: u8, func: u8) -> (u32, u32) {
    let offset = find_ext_cap(bus, dev, func, ECAP_SERIAL_NUMBER);
    if offset == 0 {
        return (0, 0);
    }

    let lower = ecam_read32_internal(bus, dev, func, offset + DSN_LOWER);
    let upper = ecam_read32_internal(bus, dev, func, offset + DSN_UPPER);
    (lower, upper)
}

/// Read AER uncorrectable and correctable error status registers.
/// Returns (uncorrectable_status, correctable_status) or (0, 0) if no AER.
fn read_aer_status(bus: u8, dev: u8, func: u8) -> (u32, u32) {
    let offset = find_ext_cap(bus, dev, func, ECAP_AER);
    if offset == 0 {
        return (0, 0);
    }

    let uncorr = ecam_read32_internal(bus, dev, func, offset + AER_UNCORRECTABLE_STATUS);
    let corr = ecam_read32_internal(bus, dev, func, offset + AER_CORRECTABLE_STATUS);
    (uncorr, corr)
}

/// Add a device to the device array. Returns true if added, false if full.
fn add_device(dev_info: PcieDevice) -> bool {
    let count = unsafe { &mut *DEVICE_COUNT.get() };
    if *count as usize >= MAX_DEVICES {
        return false;
    }
    let devs = unsafe { &mut *DEVICES.get() };
    devs[*count as usize] = dev_info;
    *count += 1;
    true
}

/// Probe a single function and add it to the device list if present.
/// Returns the header type if a device is found, or 0xFF if no device.
fn probe_function(bus: u8, dev: u8, func: u8) -> u8 {
    let vendor = ecam_read16_internal(bus, dev, func, CFG_VENDOR_ID);
    if vendor == 0xFFFF || vendor == 0x0000 {
        return 0xFF;
    }

    let device_id = ecam_read16_internal(bus, dev, func, CFG_DEVICE_ID);
    let class_code = ecam_read8_internal(bus, dev, func, CFG_CLASS_CODE);
    let subclass = ecam_read8_internal(bus, dev, func, CFG_SUBCLASS);
    let prog_if = ecam_read8_internal(bus, dev, func, CFG_PROG_IF);
    let header_type = ecam_read8_internal(bus, dev, func, CFG_HEADER_TYPE);

    // Find PCIe capability
    let pcie_cap = find_cap(bus, dev, func, CAP_ID_PCIE);
    let (link_speed, link_width) = parse_link_status(bus, dev, func, pcie_cap);

    let info = PcieDevice {
        bus,
        dev,
        func,
        vendor_id: vendor,
        device_id,
        class_code,
        subclass,
        prog_if,
        header_type: header_type & 0x7F, // mask multi-function bit
        pcie_cap_offset: pcie_cap,
        link_speed,
        link_width,
        segment: 0,
    };

    add_device(info);

    // Log discovery
    unsafe {
        if pcie_cap != 0 && link_speed > 0 {
            fut_printf(
                b"pcie_ecam: %02x:%02x.%x %04x:%04x class %02x:%02x Gen%u x%u\n\0".as_ptr(),
                bus as u32,
                dev as u32,
                func as u32,
                vendor as u32,
                device_id as u32,
                class_code as u32,
                subclass as u32,
                link_speed as u32,
                link_width as u32,
            );
        } else {
            fut_printf(
                b"pcie_ecam: %02x:%02x.%x %04x:%04x class %02x:%02x\n\0".as_ptr(),
                bus as u32,
                dev as u32,
                func as u32,
                vendor as u32,
                device_id as u32,
                class_code as u32,
                subclass as u32,
            );
        }
    }

    // Log serial number if present
    let (sn_lo, sn_hi) = read_serial_number(bus, dev, func);
    if sn_lo != 0 || sn_hi != 0 {
        unsafe {
            fut_printf(
                b"pcie_ecam:   serial number: %08x-%08x\n\0".as_ptr(),
                sn_hi,
                sn_lo,
            );
        }
    }

    // Log AER status if present and any errors are logged
    let (aer_uncorr, aer_corr) = read_aer_status(bus, dev, func);
    if aer_uncorr != 0 || aer_corr != 0 {
        unsafe {
            fut_printf(
                b"pcie_ecam:   AER uncorrectable=0x%08x correctable=0x%08x\n\0".as_ptr(),
                aer_uncorr,
                aer_corr,
            );
        }
    }

    header_type
}

/// Scan a single bus, recursing into bridges.
fn scan_bus(bus: u8) {
    let st = unsafe { &*STATE.get() };
    if bus < st.start_bus || bus > st.end_bus {
        return;
    }

    for dev in 0..32u8 {
        let header = probe_function(bus, dev, 0);
        if header == 0xFF {
            continue;
        }

        // Check for multi-function device (bit 7 of raw header type)
        let raw_header = ecam_read8_internal(bus, dev, 0, CFG_HEADER_TYPE);
        if raw_header & 0x80 != 0 {
            for func in 1..8u8 {
                let func_header = probe_function(bus, dev, func);
                if func_header != 0xFF && (func_header & 0x7F) == 0x01 {
                    // PCI-to-PCI bridge — recurse
                    let secondary = ecam_read8_internal(bus, dev, func, CFG_SECONDARY_BUS);
                    if secondary > bus && secondary <= st.end_bus {
                        scan_bus(secondary);
                    }
                }
            }
        }

        // If function 0 is a bridge, recurse into the secondary bus
        if (header & 0x7F) == 0x01 {
            let secondary = ecam_read8_internal(bus, dev, 0, CFG_SECONDARY_BUS);
            if secondary > bus && secondary <= unsafe { &*STATE.get() }.end_bus {
                scan_bus(secondary);
            }
        }
    }
}

/// Round up to page boundary (4 KiB).
fn page_align(size: usize) -> usize {
    (size + 0xFFF) & !0xFFF
}

// ── Exported API ──

/// Initialize the PCIe ECAM driver by mapping the MMIO region.
///
/// base_phys: Physical base address from ACPI MCFG table.
/// start_bus: First bus number covered by this ECAM segment.
/// end_bus:   Last bus number covered by this ECAM segment.
///
/// Returns 0 on success, negative on error.
#[unsafe(no_mangle)]
pub extern "C" fn pcie_ecam_init(base_phys: u64, start_bus: u8, end_bus: u8) -> i32 {
    if end_bus < start_bus {
        log("pcie_ecam: invalid bus range");
        return -1;
    }

    let st = unsafe { &mut *STATE.get() };

    // Unmap previous mapping if re-initializing
    if st.initialized && !st.vbase.is_null() {
        unsafe { unmap_mmio_region(st.vbase, st.map_size) };
        st.initialized = false;
        st.vbase = core::ptr::null_mut();
    }

    // Each bus covers 32 devices * 8 functions * 4 KiB = 1 MiB
    let bus_count = (end_bus as usize) - (start_bus as usize) + 1;
    let map_size = page_align(bus_count << 20);

    let vbase = unsafe { map_mmio_region(base_phys, map_size, MMIO_DEFAULT_FLAGS) };
    if vbase.is_null() {
        log("pcie_ecam: failed to map ECAM region");
        return -2;
    }

    st.vbase = vbase;
    st.pbase = base_phys;
    st.start_bus = start_bus;
    st.end_bus = end_bus;
    st.map_size = map_size;
    st.initialized = true;

    // Reset device list
    let count = unsafe { &mut *DEVICE_COUNT.get() };
    *count = 0;

    unsafe {
        fut_printf(
            b"pcie_ecam: mapped %u MiB at phys 0x%lx for buses %u-%u\n\0".as_ptr(),
            (map_size >> 20) as u32,
            base_phys,
            start_bus as u32,
            end_bus as u32,
        );
    }

    0
}

/// Read an 8-bit value from PCIe configuration space.
#[unsafe(no_mangle)]
pub extern "C" fn pcie_ecam_read8(bus: u8, dev: u8, func: u8, offset: u16) -> u8 {
    ecam_read8_internal(bus, dev, func, offset)
}

/// Read a 16-bit value from PCIe configuration space.
#[unsafe(no_mangle)]
pub extern "C" fn pcie_ecam_read16(bus: u8, dev: u8, func: u8, offset: u16) -> u16 {
    ecam_read16_internal(bus, dev, func, offset)
}

/// Read a 32-bit value from PCIe configuration space.
#[unsafe(no_mangle)]
pub extern "C" fn pcie_ecam_read32(bus: u8, dev: u8, func: u8, offset: u16) -> u32 {
    ecam_read32_internal(bus, dev, func, offset)
}

/// Write an 8-bit value to PCIe configuration space.
#[unsafe(no_mangle)]
pub extern "C" fn pcie_ecam_write8(bus: u8, dev: u8, func: u8, offset: u16, val: u8) {
    ecam_write8_internal(bus, dev, func, offset, val);
}

/// Write a 16-bit value to PCIe configuration space.
#[unsafe(no_mangle)]
pub extern "C" fn pcie_ecam_write16(bus: u8, dev: u8, func: u8, offset: u16, val: u16) {
    ecam_write16_internal(bus, dev, func, offset, val);
}

/// Write a 32-bit value to PCIe configuration space.
#[unsafe(no_mangle)]
pub extern "C" fn pcie_ecam_write32(bus: u8, dev: u8, func: u8, offset: u16, val: u32) {
    ecam_write32_internal(bus, dev, func, offset, val);
}

/// Enumerate all PCIe devices by scanning all buses in the configured range.
/// Must be called after pcie_ecam_init().
/// Returns the number of devices found, or negative on error.
#[unsafe(no_mangle)]
pub extern "C" fn pcie_ecam_enumerate() -> i32 {
    let st = unsafe { &*STATE.get() };
    if !st.initialized {
        log("pcie_ecam: not initialized");
        return -1;
    }

    // Reset device list
    let count = unsafe { &mut *DEVICE_COUNT.get() };
    *count = 0;

    // Scan from start_bus; bridges will recurse into secondary buses
    let start = st.start_bus;
    let end = st.end_bus;

    // Check if bus 0 has a multi-function host bridge (multiple root buses)
    if start == 0 {
        let raw_header = ecam_read8_internal(0, 0, 0, CFG_HEADER_TYPE);
        if raw_header & 0x80 != 0 {
            // Multi-function host bridge: each function may be a root for a bus
            for func in 0..8u8 {
                let vendor = ecam_read16_internal(0, 0, func, CFG_VENDOR_ID);
                if vendor == 0xFFFF || vendor == 0x0000 {
                    continue;
                }
                scan_bus(func);
            }
        } else {
            scan_bus(0);
        }
    } else {
        // Non-zero start bus: just scan the range linearly
        for bus in start..=end {
            scan_bus(bus);
        }
    }

    let final_count = unsafe { *DEVICE_COUNT.get() };

    unsafe {
        fut_printf(
            b"pcie_ecam: enumeration complete, %u devices found\n\0".as_ptr(),
            final_count,
        );
    }

    final_count as i32
}

/// Get a pointer to the device descriptor at the given index.
/// Returns null if the index is out of range.
#[unsafe(no_mangle)]
pub extern "C" fn pcie_ecam_get_device(index: u32) -> *const PcieDevice {
    let count = unsafe { *DEVICE_COUNT.get() };
    if index >= count {
        return core::ptr::null();
    }
    let devs = unsafe { &*DEVICES.get() };
    &devs[index as usize] as *const PcieDevice
}

/// Find a device by vendor and device ID.
/// Returns the index of the first match, or -1 if not found.
#[unsafe(no_mangle)]
pub extern "C" fn pcie_ecam_find_device(vendor: u16, device: u16) -> i32 {
    let count = unsafe { *DEVICE_COUNT.get() };
    let devs = unsafe { &*DEVICES.get() };

    for i in 0..count as usize {
        if devs[i].vendor_id == vendor && devs[i].device_id == device {
            return i as i32;
        }
    }

    -1
}

/// Return the number of discovered PCIe devices.
#[unsafe(no_mangle)]
pub extern "C" fn pcie_ecam_device_count() -> u32 {
    unsafe { *DEVICE_COUNT.get() }
}
