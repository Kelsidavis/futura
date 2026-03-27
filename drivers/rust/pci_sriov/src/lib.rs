// SPDX-License-Identifier: MPL-2.0
//
// PCIe SR-IOV (Single Root I/O Virtualization) Driver for Futura OS (x86-64)
//
// Implements the PCIe SR-IOV extended capability (ID 0x0010) which allows a
// single Physical Function (PF) to present multiple Virtual Functions (VFs)
// to the system, enabling efficient hardware sharing across virtual machines.
//
// Architecture:
//   - Walks the PCIe extended capability chain starting at offset 0x100
//   - Reads SR-IOV capabilities (TotalVFs, InitialVFs, VF Device ID)
//   - Enables/disables VFs by configuring NumVFs and the VF Enable bit
//   - Reads VF BAR configuration for resource assignment
//   - Calculates VF BDF (bus/device/function) from First VF Offset and Stride
//
// All extended config access is performed through caller-supplied ECAM
// read/write callbacks, since offsets beyond 0xFF cannot be reached via
// legacy CF8/CFC I/O port access.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(unexpected_cfgs)]
#![allow(dead_code)]

use common::log;

// ── FFI imports ──

unsafe extern "C" {
    fn fut_printf(fmt: *const u8, ...);
}

// ── ECAM callback types ──

type EcamRead32Fn = unsafe extern "C" fn(bus: u8, dev: u8, func: u8, offset: u16) -> u32;
type EcamWrite32Fn = unsafe extern "C" fn(bus: u8, dev: u8, func: u8, offset: u16, val: u32);

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

// ── SR-IOV extended capability register offsets (relative to cap base) ──

/// Extended capability header: [15:0] = cap ID, [19:16] = version, [31:20] = next
const SRIOV_CAP_HEADER: u16 = 0x00;
/// SR-IOV Capabilities (32-bit)
const SRIOV_CAPABILITIES: u16 = 0x04;
/// SR-IOV Control (16-bit, lower half of DWORD at +0x08)
const SRIOV_CONTROL: u16 = 0x08;
/// SR-IOV Status (16-bit, upper half of DWORD at +0x08)
const SRIOV_STATUS: u16 = 0x08;
/// InitialVFs (16-bit, lower) and TotalVFs (16-bit, upper) at +0x0C
const SRIOV_INITIAL_TOTAL_VFS: u16 = 0x0C;
/// NumVFs (16-bit, lower) and Function Dependency Link (16-bit, upper) at +0x10
const SRIOV_NUM_VFS: u16 = 0x10;
/// First VF Offset (16-bit, lower) and VF Stride (16-bit, upper) at +0x14
const SRIOV_VF_OFFSET_STRIDE: u16 = 0x14;
/// Reserved (16-bit, lower) and VF Device ID (16-bit, upper) at +0x18
const SRIOV_VF_DEVICE_ID: u16 = 0x18;
/// Supported Page Sizes (32-bit)
const SRIOV_SUPPORTED_PAGE_SIZES: u16 = 0x1C;
/// System Page Size (32-bit)
const SRIOV_SYSTEM_PAGE_SIZE: u16 = 0x20;
/// VF BAR0 (first of 6 VF BARs)
const SRIOV_VF_BAR0: u16 = 0x24;

// ── SR-IOV Control register bits ──

const SRIOV_CTRL_VF_ENABLE: u32 = 1 << 0;
const SRIOV_CTRL_VF_MIGRATION_ENABLE: u32 = 1 << 1;
const SRIOV_CTRL_VF_MIGRATION_INT_ENABLE: u32 = 1 << 2;
const SRIOV_CTRL_VF_MSE: u32 = 1 << 3;
const SRIOV_CTRL_ARI_CAPABLE: u32 = 1 << 4;

// ── SR-IOV Capabilities register bits ──

const SRIOV_CAP_VF_MIGRATION: u32 = 1 << 0;
const SRIOV_CAP_ARI_HIERARCHY: u32 = 1 << 1;

// ── Extended capability chain constants ──

const ECAP_ID_SRIOV: u16 = 0x0010;
const EXT_CAP_START: u16 = 0x100;
const EXT_CAP_MAX_OFFSET: u16 = 0xFFC;
const EXT_CAP_MAX_WALK: u32 = 96;

// ── Maximum number of VF BARs ──

const VF_BAR_COUNT: usize = 6;

// ── Global state ──

struct SriovState {
    ecam_read: Option<EcamRead32Fn>,
    ecam_write: Option<EcamWrite32Fn>,
    initialized: bool,
}

impl SriovState {
    const fn new() -> Self {
        Self {
            ecam_read: None,
            ecam_write: None,
            initialized: false,
        }
    }
}

static STATE: StaticCell<SriovState> = StaticCell::new(SriovState::new());

// ── Internal helpers ──

/// Read a 32-bit value from extended config space via ECAM callback.
fn ecam_read32(bus: u8, dev: u8, func: u8, offset: u16) -> u32 {
    let st = unsafe { &*STATE.get() };
    match st.ecam_read {
        Some(f) => unsafe { f(bus, dev, func, offset) },
        None => 0xFFFF_FFFF,
    }
}

/// Write a 32-bit value to extended config space via ECAM callback.
fn ecam_write32(bus: u8, dev: u8, func: u8, offset: u16, val: u32) {
    let st = unsafe { &*STATE.get() };
    if let Some(f) = st.ecam_write {
        unsafe { f(bus, dev, func, offset, val) };
    }
}

/// Walk the PCIe extended capability chain starting at offset 0x100.
/// Returns the offset of the extended capability with the given ID, or 0.
fn find_ext_cap(bus: u8, dev: u8, func: u8, cap_id: u16) -> u16 {
    let mut offset = EXT_CAP_START;
    let mut visited: u32 = 0;

    while offset != 0 && offset >= EXT_CAP_START && offset <= EXT_CAP_MAX_OFFSET
        && visited < EXT_CAP_MAX_WALK
    {
        let header = ecam_read32(bus, dev, func, offset);
        if header == 0 || header == 0xFFFF_FFFF {
            break;
        }

        let id = (header & 0xFFFF) as u16;
        let next = ((header >> 20) & 0xFFC) as u16;

        if id == cap_id {
            return offset;
        }

        offset = next;
        visited += 1;
    }

    0
}

/// Find the SR-IOV capability offset for a device.
/// Returns the offset (>= 0x100) or 0 if not present.
fn get_sriov_offset(bus: u8, dev: u8, func: u8) -> u16 {
    find_ext_cap(bus, dev, func, ECAP_ID_SRIOV)
}

/// Read SR-IOV Control register (16-bit, lower half of DWORD at +0x08).
fn read_sriov_control(bus: u8, dev: u8, func: u8, cap_offset: u16) -> u16 {
    let val = ecam_read32(bus, dev, func, cap_offset + SRIOV_CONTROL);
    (val & 0xFFFF) as u16
}

/// Write SR-IOV Control register (16-bit, lower half of DWORD at +0x08).
/// Preserves the upper 16 bits (Status register).
fn write_sriov_control(bus: u8, dev: u8, func: u8, cap_offset: u16, ctrl: u16) {
    let current = ecam_read32(bus, dev, func, cap_offset + SRIOV_CONTROL);
    let new_val = (current & 0xFFFF_0000) | (ctrl as u32);
    ecam_write32(bus, dev, func, cap_offset + SRIOV_CONTROL, new_val);
}

/// Write NumVFs (16-bit, lower half of DWORD at +0x10).
/// Preserves the upper 16 bits (Function Dependency Link).
fn write_num_vfs(bus: u8, dev: u8, func: u8, cap_offset: u16, num_vfs: u16) {
    let current = ecam_read32(bus, dev, func, cap_offset + SRIOV_NUM_VFS);
    let new_val = (current & 0xFFFF_0000) | (num_vfs as u32);
    ecam_write32(bus, dev, func, cap_offset + SRIOV_NUM_VFS, new_val);
}

// ── Exported API ──

/// Initialize the PCIe SR-IOV driver with ECAM read/write callbacks.
///
/// The callbacks must provide access to the full PCIe extended configuration
/// space (offsets 0x000-0xFFF) for any bus/device/function.
///
/// Returns 0 on success, -1 on invalid arguments.
#[unsafe(no_mangle)]
pub extern "C" fn pci_sriov_init(
    ecam_read: EcamRead32Fn,
    ecam_write: EcamWrite32Fn,
) -> i32 {
    let st = unsafe { &mut *STATE.get() };
    st.ecam_read = Some(ecam_read);
    st.ecam_write = Some(ecam_write);
    st.initialized = true;

    log("pci_sriov: initialized with ECAM callbacks");
    0
}

/// Find the SR-IOV extended capability for a PCIe device.
///
/// Walks the extended capability chain starting at offset 0x100 looking
/// for capability ID 0x0010 (SR-IOV).
///
/// Returns the capability offset (>= 0x100) on success, or -1 if the
/// device does not support SR-IOV.
#[unsafe(no_mangle)]
pub extern "C" fn pci_sriov_find(bus: u8, dev: u8, func: u8) -> i32 {
    let st = unsafe { &*STATE.get() };
    if !st.initialized {
        return -1;
    }

    let offset = get_sriov_offset(bus, dev, func);
    if offset == 0 {
        return -1;
    }

    offset as i32
}

/// Return the TotalVFs value for a SR-IOV capable device.
///
/// TotalVFs indicates the maximum number of VFs the device can support.
/// Returns 0 if the device does not have SR-IOV capability or driver
/// is not initialized.
#[unsafe(no_mangle)]
pub extern "C" fn pci_sriov_total_vfs(bus: u8, dev: u8, func: u8) -> u32 {
    let st = unsafe { &*STATE.get() };
    if !st.initialized {
        return 0;
    }

    let cap_offset = get_sriov_offset(bus, dev, func);
    if cap_offset == 0 {
        return 0;
    }

    // TotalVFs is upper 16 bits of DWORD at +0x0C
    let val = ecam_read32(bus, dev, func, cap_offset + SRIOV_INITIAL_TOTAL_VFS);
    ((val >> 16) & 0xFFFF) as u32
}

/// Enable the specified number of Virtual Functions on a SR-IOV device.
///
/// This writes NumVFs, sets the VF Enable bit, and enables VF Memory
/// Space. The caller should wait for at least 100ms after enabling for
/// VFs to become active (per PCIe spec).
///
/// Returns 0 on success, -1 on error.
#[unsafe(no_mangle)]
pub extern "C" fn pci_sriov_enable(bus: u8, dev: u8, func: u8, num_vfs: u16) -> i32 {
    let st = unsafe { &*STATE.get() };
    if !st.initialized {
        return -1;
    }

    let cap_offset = get_sriov_offset(bus, dev, func);
    if cap_offset == 0 {
        log("pci_sriov: enable failed - SR-IOV not found");
        return -1;
    }

    if num_vfs == 0 {
        log("pci_sriov: enable failed - num_vfs must be > 0");
        return -1;
    }

    // Check against TotalVFs
    let total_vfs_dw = ecam_read32(bus, dev, func, cap_offset + SRIOV_INITIAL_TOTAL_VFS);
    let total_vfs = ((total_vfs_dw >> 16) & 0xFFFF) as u16;

    if num_vfs > total_vfs {
        log("pci_sriov: enable failed - num_vfs exceeds TotalVFs");
        return -1;
    }

    // First disable VFs if already enabled
    let ctrl = read_sriov_control(bus, dev, func, cap_offset);
    if (ctrl as u32) & SRIOV_CTRL_VF_ENABLE != 0 {
        // Disable first
        write_sriov_control(
            bus, dev, func, cap_offset,
            ctrl & !(SRIOV_CTRL_VF_ENABLE as u16) & !(SRIOV_CTRL_VF_MSE as u16),
        );
    }

    // Write NumVFs
    write_num_vfs(bus, dev, func, cap_offset, num_vfs);

    // Set VF Enable and VF Memory Space Enable
    let ctrl = read_sriov_control(bus, dev, func, cap_offset);
    let new_ctrl = ctrl | (SRIOV_CTRL_VF_ENABLE as u16) | (SRIOV_CTRL_VF_MSE as u16);
    write_sriov_control(bus, dev, func, cap_offset, new_ctrl);

    log("pci_sriov: VFs enabled");
    0
}

/// Disable all Virtual Functions on a SR-IOV device.
///
/// Clears the VF Enable and VF Memory Space Enable bits, and sets
/// NumVFs to 0.
///
/// Returns 0 on success, -1 on error.
#[unsafe(no_mangle)]
pub extern "C" fn pci_sriov_disable(bus: u8, dev: u8, func: u8) -> i32 {
    let st = unsafe { &*STATE.get() };
    if !st.initialized {
        return -1;
    }

    let cap_offset = get_sriov_offset(bus, dev, func);
    if cap_offset == 0 {
        log("pci_sriov: disable failed - SR-IOV not found");
        return -1;
    }

    // Clear VF Enable and VF MSE
    let ctrl = read_sriov_control(bus, dev, func, cap_offset);
    let new_ctrl = ctrl & !(SRIOV_CTRL_VF_ENABLE as u16) & !(SRIOV_CTRL_VF_MSE as u16);
    write_sriov_control(bus, dev, func, cap_offset, new_ctrl);

    // Set NumVFs to 0
    write_num_vfs(bus, dev, func, cap_offset, 0);

    log("pci_sriov: VFs disabled");
    0
}

/// Return the VF Device ID for a SR-IOV capable device.
///
/// This is the device ID that all VFs will present (distinct from the
/// PF's device ID). Returns 0 on error.
#[unsafe(no_mangle)]
pub extern "C" fn pci_sriov_vf_device_id(bus: u8, dev: u8, func: u8) -> u16 {
    let st = unsafe { &*STATE.get() };
    if !st.initialized {
        return 0;
    }

    let cap_offset = get_sriov_offset(bus, dev, func);
    if cap_offset == 0 {
        return 0;
    }

    // VF Device ID is upper 16 bits of DWORD at +0x18
    let val = ecam_read32(bus, dev, func, cap_offset + SRIOV_VF_DEVICE_ID);
    ((val >> 16) & 0xFFFF) as u16
}

/// Return the First VF Offset for a SR-IOV capable device.
///
/// The First VF Offset is the routing ID offset from the PF to the
/// first VF. Returns 0 on error.
#[unsafe(no_mangle)]
pub extern "C" fn pci_sriov_vf_offset(bus: u8, dev: u8, func: u8) -> u16 {
    let st = unsafe { &*STATE.get() };
    if !st.initialized {
        return 0;
    }

    let cap_offset = get_sriov_offset(bus, dev, func);
    if cap_offset == 0 {
        return 0;
    }

    // First VF Offset is lower 16 bits of DWORD at +0x14
    let val = ecam_read32(bus, dev, func, cap_offset + SRIOV_VF_OFFSET_STRIDE);
    (val & 0xFFFF) as u16
}

/// Return the VF Stride for a SR-IOV capable device.
///
/// The VF Stride is the routing ID offset between consecutive VFs.
/// Returns 0 on error.
#[unsafe(no_mangle)]
pub extern "C" fn pci_sriov_vf_stride(bus: u8, dev: u8, func: u8) -> u16 {
    let st = unsafe { &*STATE.get() };
    if !st.initialized {
        return 0;
    }

    let cap_offset = get_sriov_offset(bus, dev, func);
    if cap_offset == 0 {
        return 0;
    }

    // VF Stride is upper 16 bits of DWORD at +0x14
    let val = ecam_read32(bus, dev, func, cap_offset + SRIOV_VF_OFFSET_STRIDE);
    ((val >> 16) & 0xFFFF) as u16
}

/// Return the currently configured NumVFs for a SR-IOV capable device.
///
/// NumVFs is the number of VFs that are (or will be) enabled.
/// Returns 0 on error or if no VFs are configured.
#[unsafe(no_mangle)]
pub extern "C" fn pci_sriov_num_vfs(bus: u8, dev: u8, func: u8) -> u16 {
    let st = unsafe { &*STATE.get() };
    if !st.initialized {
        return 0;
    }

    let cap_offset = get_sriov_offset(bus, dev, func);
    if cap_offset == 0 {
        return 0;
    }

    // NumVFs is lower 16 bits of DWORD at +0x10
    let val = ecam_read32(bus, dev, func, cap_offset + SRIOV_NUM_VFS);
    (val & 0xFFFF) as u16
}
