// SPDX-License-Identifier: MPL-2.0
//
// PCIe Advanced Error Reporting (AER) Driver for Futura OS (x86-64)
//
// Implements the PCIe AER extended capability (ID 0x0001) for error
// detection, logging, and clearing on PCIe devices. AER lives in the
// extended configuration space (offset >= 0x100), requiring ECAM
// (MMIO-based config access) rather than legacy I/O ports.
//
// Architecture:
//   - Walks the PCIe extended capability chain starting at offset 0x100
//   - Reads/clears uncorrectable and correctable error status (W1C)
//   - Manages error masks and severity configuration
//   - Captures TLP header log on uncorrectable errors
//   - Supports root port error command/status registers
//   - Tracks cumulative error statistics per device
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

// ── AER extended capability register offsets (relative to cap base) ──

/// Extended capability header: [15:0] = cap ID, [19:16] = version, [31:20] = next
const AER_CAP_HEADER: u16 = 0x00;
/// Uncorrectable Error Status (W1C)
const AER_UNCORR_STATUS: u16 = 0x04;
/// Uncorrectable Error Mask
const AER_UNCORR_MASK: u16 = 0x08;
/// Uncorrectable Error Severity (0 = non-fatal, 1 = fatal)
const AER_UNCORR_SEVERITY: u16 = 0x0C;
/// Correctable Error Status (W1C)
const AER_CORR_STATUS: u16 = 0x10;
/// Correctable Error Mask
const AER_CORR_MASK: u16 = 0x14;
/// Advanced Error Capabilities and Control
const AER_CAP_CONTROL: u16 = 0x18;
/// Header Log register 0 (first DWORD of captured TLP header)
const AER_HEADER_LOG0: u16 = 0x1C;
/// Header Log register 1
const AER_HEADER_LOG1: u16 = 0x20;
/// Header Log register 2
const AER_HEADER_LOG2: u16 = 0x24;
/// Header Log register 3
const AER_HEADER_LOG3: u16 = 0x28;
/// Root Error Command (root ports only)
const AER_ROOT_ERR_CMD: u16 = 0x2C;
/// Root Error Status (root ports only)
const AER_ROOT_ERR_STATUS: u16 = 0x30;

// ── Uncorrectable error bit definitions ──

const UNCORR_DLP: u32 = 1 << 4;
const UNCORR_POISONED_TLP: u32 = 1 << 12;
const UNCORR_FLOW_CTRL: u32 = 1 << 13;
const UNCORR_COMPLETION_TIMEOUT: u32 = 1 << 14;
const UNCORR_COMPLETER_ABORT: u32 = 1 << 15;
const UNCORR_UNEXPECTED_COMPLETION: u32 = 1 << 16;
const UNCORR_RECEIVER_OVERFLOW: u32 = 1 << 17;
const UNCORR_MALFORMED_TLP: u32 = 1 << 18;
const UNCORR_ECRC: u32 = 1 << 19;
const UNCORR_UNSUPPORTED_REQ: u32 = 1 << 20;

// ── Correctable error bit definitions ──

const CORR_RECEIVER_ERROR: u32 = 1 << 0;
const CORR_BAD_TLP: u32 = 1 << 6;
const CORR_BAD_DLLP: u32 = 1 << 7;
const CORR_REPLAY_NUM_ROLLOVER: u32 = 1 << 8;
const CORR_REPLAY_TIMER_TIMEOUT: u32 = 1 << 12;
const CORR_ADVISORY_NONFATAL: u32 = 1 << 13;

// ── Extended capability ID for AER ──

const ECAP_ID_AER: u16 = 0x0001;

// ── Extended capability chain constants ──

const EXT_CAP_START: u16 = 0x100;
const EXT_CAP_MAX_OFFSET: u16 = 0xFFC;
const EXT_CAP_MAX_WALK: u32 = 96;

// ── Error statistics tracking ──

const MAX_TRACKED_DEVICES: usize = 64;

#[derive(Clone, Copy)]
struct AerDeviceStats {
    bus: u8,
    dev: u8,
    func: u8,
    active: bool,
    /// Cached AER capability offset (0 = not found)
    aer_offset: u16,
    /// Cumulative uncorrectable error count
    uncorr_count: u32,
    /// Cumulative correctable error count
    corr_count: u32,
    /// Last observed uncorrectable status
    last_uncorr_status: u32,
    /// Last observed correctable status
    last_corr_status: u32,
}

impl AerDeviceStats {
    const fn empty() -> Self {
        Self {
            bus: 0,
            dev: 0,
            func: 0,
            active: false,
            aer_offset: 0,
            uncorr_count: 0,
            corr_count: 0,
            last_uncorr_status: 0,
            last_corr_status: 0,
        }
    }
}

// ── Global state ──

struct AerState {
    ecam_read: Option<EcamRead32Fn>,
    ecam_write: Option<EcamWrite32Fn>,
    initialized: bool,
}

impl AerState {
    const fn new() -> Self {
        Self {
            ecam_read: None,
            ecam_write: None,
            initialized: false,
        }
    }
}

static STATE: StaticCell<AerState> = StaticCell::new(AerState::new());
static DEVICES: StaticCell<[AerDeviceStats; MAX_TRACKED_DEVICES]> =
    StaticCell::new([AerDeviceStats::empty(); MAX_TRACKED_DEVICES]);
static DEVICE_COUNT: StaticCell<u32> = StaticCell::new(0);

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

/// Find or create a tracking slot for the given BDF.
/// Returns the slot index, or None if full and not already tracked.
fn find_or_alloc_slot(bus: u8, dev: u8, func: u8) -> Option<usize> {
    let devs = unsafe { &*DEVICES.get() };
    let count = unsafe { *DEVICE_COUNT.get() } as usize;
    let mut free_slot: Option<usize> = None;

    for i in 0..MAX_TRACKED_DEVICES {
        if devs[i].active && devs[i].bus == bus && devs[i].dev == dev && devs[i].func == func {
            return Some(i);
        }
        if !devs[i].active && free_slot.is_none() && i < count + 1 {
            free_slot = Some(i);
        }
    }

    // If no inactive slot found within count range, try extending
    if free_slot.is_none() && count < MAX_TRACKED_DEVICES {
        free_slot = Some(count);
    }

    free_slot
}

/// Look up an active tracked device. Returns slot index or None.
fn lookup_device(bus: u8, dev: u8, func: u8) -> Option<usize> {
    let devs = unsafe { &*DEVICES.get() };
    for i in 0..MAX_TRACKED_DEVICES {
        if devs[i].active && devs[i].bus == bus && devs[i].dev == dev && devs[i].func == func {
            return Some(i);
        }
    }
    None
}

/// Get the AER capability offset for a device, using cached value if tracked.
/// Returns the offset (>= 0x100) or 0 if AER is not present.
fn get_aer_offset(bus: u8, dev: u8, func: u8) -> u16 {
    // Check cache first
    if let Some(slot) = lookup_device(bus, dev, func) {
        let devs = unsafe { &*DEVICES.get() };
        if devs[slot].aer_offset != 0 {
            return devs[slot].aer_offset;
        }
    }

    // Walk extended capability chain
    find_ext_cap(bus, dev, func, ECAP_ID_AER)
}

/// Count the number of set bits in a u32.
fn popcount32(mut v: u32) -> u32 {
    let mut count = 0u32;
    while v != 0 {
        count += 1;
        v &= v - 1;
    }
    count
}

/// Copy a byte string into a buffer, returning the number of bytes written
/// (not counting the null terminator). The output is always null-terminated
/// if max_len > 0.
fn copy_str_to_buf(s: &[u8], buf: *mut u8, max_len: u32) -> i32 {
    if buf.is_null() || max_len == 0 {
        return -1;
    }

    let copy_len = if s.len() < max_len as usize {
        s.len()
    } else {
        (max_len - 1) as usize
    };

    for i in 0..copy_len {
        unsafe { *buf.add(i) = s[i] };
    }
    unsafe { *buf.add(copy_len) = 0 };

    copy_len as i32
}

// ── Exported API ──

/// Initialize the PCIe AER driver with ECAM read/write callbacks.
///
/// The callbacks must provide access to the full PCIe extended configuration
/// space (offsets 0x000-0xFFF) for any bus/device/function.
///
/// Returns 0 on success, -1 on invalid arguments.
#[unsafe(no_mangle)]
pub extern "C" fn pci_aer_init(
    ecam_read: EcamRead32Fn,
    ecam_write: EcamWrite32Fn,
) -> i32 {
    let st = unsafe { &mut *STATE.get() };
    st.ecam_read = Some(ecam_read);
    st.ecam_write = Some(ecam_write);
    st.initialized = true;

    // Reset device tracking
    let count = unsafe { &mut *DEVICE_COUNT.get() };
    *count = 0;
    let devs = unsafe { &mut *DEVICES.get() };
    for i in 0..MAX_TRACKED_DEVICES {
        devs[i] = AerDeviceStats::empty();
    }

    log("pci_aer: initialized with ECAM callbacks");
    0
}

/// Find the AER extended capability for a PCIe device.
///
/// Walks the extended capability chain starting at offset 0x100 looking
/// for capability ID 0x0001 (AER).
///
/// Returns the capability offset (>= 0x100) on success, or -1 if the
/// device does not support AER.
#[unsafe(no_mangle)]
pub extern "C" fn pci_aer_find(bus: u8, dev: u8, func: u8) -> i32 {
    let st = unsafe { &*STATE.get() };
    if !st.initialized {
        return -1;
    }

    let offset = find_ext_cap(bus, dev, func, ECAP_ID_AER);
    if offset == 0 {
        return -1;
    }

    // Cache in tracking array
    if let Some(slot) = find_or_alloc_slot(bus, dev, func) {
        let devs = unsafe { &mut *DEVICES.get() };
        if !devs[slot].active {
            devs[slot] = AerDeviceStats {
                bus,
                dev,
                func,
                active: true,
                aer_offset: offset,
                uncorr_count: 0,
                corr_count: 0,
                last_uncorr_status: 0,
                last_corr_status: 0,
            };
            let count = unsafe { &mut *DEVICE_COUNT.get() };
            if slot as u32 >= *count {
                *count = slot as u32 + 1;
            }
        } else {
            devs[slot].aer_offset = offset;
        }
    }

    unsafe {
        fut_printf(
            b"pci_aer: %02x:%02x.%x AER capability at offset 0x%03x\n\0".as_ptr(),
            bus as u32,
            dev as u32,
            func as u32,
            offset as u32,
        );
    }

    offset as i32
}

/// Read the uncorrectable error status register for a device.
///
/// Returns the raw 32-bit status value, or 0 if AER is not present.
/// Each set bit indicates a logged error (write-1-to-clear semantics).
#[unsafe(no_mangle)]
pub extern "C" fn pci_aer_uncorrectable_status(bus: u8, dev: u8, func: u8) -> u32 {
    let st = unsafe { &*STATE.get() };
    if !st.initialized {
        return 0;
    }

    let aer_off = get_aer_offset(bus, dev, func);
    if aer_off == 0 {
        return 0;
    }

    let status = ecam_read32(bus, dev, func, aer_off + AER_UNCORR_STATUS);

    // Update tracking statistics
    if let Some(slot) = lookup_device(bus, dev, func) {
        let devs = unsafe { &mut *DEVICES.get() };
        devs[slot].last_uncorr_status = status;
        if status != 0 {
            devs[slot].uncorr_count = devs[slot].uncorr_count.saturating_add(popcount32(status));
        }
    }

    status
}

/// Read the correctable error status register for a device.
///
/// Returns the raw 32-bit status value, or 0 if AER is not present.
#[unsafe(no_mangle)]
pub extern "C" fn pci_aer_correctable_status(bus: u8, dev: u8, func: u8) -> u32 {
    let st = unsafe { &*STATE.get() };
    if !st.initialized {
        return 0;
    }

    let aer_off = get_aer_offset(bus, dev, func);
    if aer_off == 0 {
        return 0;
    }

    let status = ecam_read32(bus, dev, func, aer_off + AER_CORR_STATUS);

    // Update tracking statistics
    if let Some(slot) = lookup_device(bus, dev, func) {
        let devs = unsafe { &mut *DEVICES.get() };
        devs[slot].last_corr_status = status;
        if status != 0 {
            devs[slot].corr_count = devs[slot].corr_count.saturating_add(popcount32(status));
        }
    }

    status
}

/// Clear all uncorrectable errors by writing the current status back (W1C).
///
/// Returns 0 on success, -1 if AER is not present or driver not initialized.
#[unsafe(no_mangle)]
pub extern "C" fn pci_aer_clear_uncorrectable(bus: u8, dev: u8, func: u8) -> i32 {
    let st = unsafe { &*STATE.get() };
    if !st.initialized {
        return -1;
    }

    let aer_off = get_aer_offset(bus, dev, func);
    if aer_off == 0 {
        return -1;
    }

    let status = ecam_read32(bus, dev, func, aer_off + AER_UNCORR_STATUS);
    if status != 0 {
        ecam_write32(bus, dev, func, aer_off + AER_UNCORR_STATUS, status);

        unsafe {
            fut_printf(
                b"pci_aer: %02x:%02x.%x cleared uncorrectable errors 0x%08x\n\0".as_ptr(),
                bus as u32,
                dev as u32,
                func as u32,
                status,
            );
        }
    }

    0
}

/// Clear all correctable errors by writing the current status back (W1C).
///
/// Returns 0 on success, -1 if AER is not present or driver not initialized.
#[unsafe(no_mangle)]
pub extern "C" fn pci_aer_clear_correctable(bus: u8, dev: u8, func: u8) -> i32 {
    let st = unsafe { &*STATE.get() };
    if !st.initialized {
        return -1;
    }

    let aer_off = get_aer_offset(bus, dev, func);
    if aer_off == 0 {
        return -1;
    }

    let status = ecam_read32(bus, dev, func, aer_off + AER_CORR_STATUS);
    if status != 0 {
        ecam_write32(bus, dev, func, aer_off + AER_CORR_STATUS, status);

        unsafe {
            fut_printf(
                b"pci_aer: %02x:%02x.%x cleared correctable errors 0x%08x\n\0".as_ptr(),
                bus as u32,
                dev as u32,
                func as u32,
                status,
            );
        }
    }

    0
}

/// Read the TLP header log (4 DWORDs) captured on the last uncorrectable error.
///
/// `log` must point to a buffer of at least 4 u32 values (16 bytes).
///
/// Returns 0 on success, -1 on error (null pointer, AER not present, etc.).
#[unsafe(no_mangle)]
pub extern "C" fn pci_aer_read_header_log(
    bus: u8,
    dev: u8,
    func: u8,
    hdr_log: *mut u32,
) -> i32 {
    if hdr_log.is_null() {
        return -1;
    }

    let st = unsafe { &*STATE.get() };
    if !st.initialized {
        return -1;
    }

    let aer_off = get_aer_offset(bus, dev, func);
    if aer_off == 0 {
        return -1;
    }

    unsafe {
        *hdr_log.add(0) = ecam_read32(bus, dev, func, aer_off + AER_HEADER_LOG0);
        *hdr_log.add(1) = ecam_read32(bus, dev, func, aer_off + AER_HEADER_LOG1);
        *hdr_log.add(2) = ecam_read32(bus, dev, func, aer_off + AER_HEADER_LOG2);
        *hdr_log.add(3) = ecam_read32(bus, dev, func, aer_off + AER_HEADER_LOG3);
    }

    0
}

/// Get a human-readable name for an AER error bit.
///
/// `bit` is the bit position (0-31). `uncorrectable` selects the error class.
/// The name is written into `buf` (null-terminated), up to `max_len` bytes.
///
/// Returns the number of bytes written (not counting null terminator),
/// or -1 on error.
#[unsafe(no_mangle)]
pub extern "C" fn pci_aer_error_name(
    bit: u32,
    uncorrectable: bool,
    buf: *mut u8,
    max_len: u32,
) -> i32 {
    if bit > 31 {
        return copy_str_to_buf(b"Unknown", buf, max_len);
    }

    let name: &[u8] = if uncorrectable {
        match bit {
            4 => b"Data Link Protocol Error",
            12 => b"Poisoned TLP",
            13 => b"Flow Control Protocol Error",
            14 => b"Completion Timeout",
            15 => b"Completer Abort",
            16 => b"Unexpected Completion",
            17 => b"Receiver Overflow",
            18 => b"Malformed TLP",
            19 => b"ECRC Error",
            20 => b"Unsupported Request",
            _ => b"Reserved",
        }
    } else {
        match bit {
            0 => b"Receiver Error",
            6 => b"Bad TLP",
            7 => b"Bad DLLP",
            8 => b"Replay Num Rollover",
            12 => b"Replay Timer Timeout",
            13 => b"Advisory Non-Fatal",
            _ => b"Reserved",
        }
    };

    copy_str_to_buf(name, buf, max_len)
}

/// Read the uncorrectable error mask register.
///
/// Masked bits (set to 1) prevent the corresponding error from being
/// reported in the uncorrectable error status register.
///
/// Returns the raw 32-bit mask, or 0xFFFFFFFF on error.
#[unsafe(no_mangle)]
pub extern "C" fn pci_aer_uncorrectable_mask(bus: u8, dev: u8, func: u8) -> u32 {
    let st = unsafe { &*STATE.get() };
    if !st.initialized {
        return 0xFFFF_FFFF;
    }

    let aer_off = get_aer_offset(bus, dev, func);
    if aer_off == 0 {
        return 0xFFFF_FFFF;
    }

    ecam_read32(bus, dev, func, aer_off + AER_UNCORR_MASK)
}

/// Write the uncorrectable error mask register.
///
/// Returns 0 on success, -1 on error.
#[unsafe(no_mangle)]
pub extern "C" fn pci_aer_set_uncorrectable_mask(
    bus: u8,
    dev: u8,
    func: u8,
    mask: u32,
) -> i32 {
    let st = unsafe { &*STATE.get() };
    if !st.initialized {
        return -1;
    }

    let aer_off = get_aer_offset(bus, dev, func);
    if aer_off == 0 {
        return -1;
    }

    ecam_write32(bus, dev, func, aer_off + AER_UNCORR_MASK, mask);
    0
}

/// Read the uncorrectable error severity register.
///
/// Bits set to 1 classify the corresponding error as fatal; bits set to 0
/// classify it as non-fatal.
///
/// Returns the raw 32-bit severity, or 0xFFFFFFFF on error.
#[unsafe(no_mangle)]
pub extern "C" fn pci_aer_uncorrectable_severity(bus: u8, dev: u8, func: u8) -> u32 {
    let st = unsafe { &*STATE.get() };
    if !st.initialized {
        return 0xFFFF_FFFF;
    }

    let aer_off = get_aer_offset(bus, dev, func);
    if aer_off == 0 {
        return 0xFFFF_FFFF;
    }

    ecam_read32(bus, dev, func, aer_off + AER_UNCORR_SEVERITY)
}

/// Write the uncorrectable error severity register.
///
/// Returns 0 on success, -1 on error.
#[unsafe(no_mangle)]
pub extern "C" fn pci_aer_set_uncorrectable_severity(
    bus: u8,
    dev: u8,
    func: u8,
    severity: u32,
) -> i32 {
    let st = unsafe { &*STATE.get() };
    if !st.initialized {
        return -1;
    }

    let aer_off = get_aer_offset(bus, dev, func);
    if aer_off == 0 {
        return -1;
    }

    ecam_write32(bus, dev, func, aer_off + AER_UNCORR_SEVERITY, severity);
    0
}

/// Read the correctable error mask register.
///
/// Returns the raw 32-bit mask, or 0xFFFFFFFF on error.
#[unsafe(no_mangle)]
pub extern "C" fn pci_aer_correctable_mask(bus: u8, dev: u8, func: u8) -> u32 {
    let st = unsafe { &*STATE.get() };
    if !st.initialized {
        return 0xFFFF_FFFF;
    }

    let aer_off = get_aer_offset(bus, dev, func);
    if aer_off == 0 {
        return 0xFFFF_FFFF;
    }

    ecam_read32(bus, dev, func, aer_off + AER_CORR_MASK)
}

/// Write the correctable error mask register.
///
/// Returns 0 on success, -1 on error.
#[unsafe(no_mangle)]
pub extern "C" fn pci_aer_set_correctable_mask(
    bus: u8,
    dev: u8,
    func: u8,
    mask: u32,
) -> i32 {
    let st = unsafe { &*STATE.get() };
    if !st.initialized {
        return -1;
    }

    let aer_off = get_aer_offset(bus, dev, func);
    if aer_off == 0 {
        return -1;
    }

    ecam_write32(bus, dev, func, aer_off + AER_CORR_MASK, mask);
    0
}

/// Read the Advanced Error Capabilities and Control register.
///
/// Contains fields like First Error Pointer, ECRC generation/check enable,
/// and multiple header recording capability.
///
/// Returns the raw 32-bit value, or 0xFFFFFFFF on error.
#[unsafe(no_mangle)]
pub extern "C" fn pci_aer_cap_control(bus: u8, dev: u8, func: u8) -> u32 {
    let st = unsafe { &*STATE.get() };
    if !st.initialized {
        return 0xFFFF_FFFF;
    }

    let aer_off = get_aer_offset(bus, dev, func);
    if aer_off == 0 {
        return 0xFFFF_FFFF;
    }

    ecam_read32(bus, dev, func, aer_off + AER_CAP_CONTROL)
}

/// Read the Root Error Command register (root ports only).
///
/// Controls whether correctable, non-fatal, and fatal errors generate
/// system error interrupts.
///
/// Returns the raw 32-bit value, or 0xFFFFFFFF on error.
#[unsafe(no_mangle)]
pub extern "C" fn pci_aer_root_error_command(bus: u8, dev: u8, func: u8) -> u32 {
    let st = unsafe { &*STATE.get() };
    if !st.initialized {
        return 0xFFFF_FFFF;
    }

    let aer_off = get_aer_offset(bus, dev, func);
    if aer_off == 0 {
        return 0xFFFF_FFFF;
    }

    ecam_read32(bus, dev, func, aer_off + AER_ROOT_ERR_CMD)
}

/// Write the Root Error Command register (root ports only).
///
/// Bit 0: Correctable Error Reporting Enable
/// Bit 1: Non-Fatal Error Reporting Enable
/// Bit 2: Fatal Error Reporting Enable
///
/// Returns 0 on success, -1 on error.
#[unsafe(no_mangle)]
pub extern "C" fn pci_aer_set_root_error_command(
    bus: u8,
    dev: u8,
    func: u8,
    cmd: u32,
) -> i32 {
    let st = unsafe { &*STATE.get() };
    if !st.initialized {
        return -1;
    }

    let aer_off = get_aer_offset(bus, dev, func);
    if aer_off == 0 {
        return -1;
    }

    ecam_write32(bus, dev, func, aer_off + AER_ROOT_ERR_CMD, cmd);
    0
}

/// Read the Root Error Status register (root ports only).
///
/// Reports which types of errors have been received. Write-1-to-clear.
///
/// Returns the raw 32-bit value, or 0xFFFFFFFF on error.
#[unsafe(no_mangle)]
pub extern "C" fn pci_aer_root_error_status(bus: u8, dev: u8, func: u8) -> u32 {
    let st = unsafe { &*STATE.get() };
    if !st.initialized {
        return 0xFFFF_FFFF;
    }

    let aer_off = get_aer_offset(bus, dev, func);
    if aer_off == 0 {
        return 0xFFFF_FFFF;
    }

    ecam_read32(bus, dev, func, aer_off + AER_ROOT_ERR_STATUS)
}

/// Clear the Root Error Status register (root ports only, W1C).
///
/// Returns 0 on success, -1 on error.
#[unsafe(no_mangle)]
pub extern "C" fn pci_aer_clear_root_error_status(bus: u8, dev: u8, func: u8) -> i32 {
    let st = unsafe { &*STATE.get() };
    if !st.initialized {
        return -1;
    }

    let aer_off = get_aer_offset(bus, dev, func);
    if aer_off == 0 {
        return -1;
    }

    let status = ecam_read32(bus, dev, func, aer_off + AER_ROOT_ERR_STATUS);
    if status != 0 {
        ecam_write32(bus, dev, func, aer_off + AER_ROOT_ERR_STATUS, status);
    }

    0
}

/// Get cumulative error statistics for a tracked device.
///
/// Returns the total number of errors (uncorrectable + correctable)
/// observed across all calls to the status functions, or -1 if the
/// device is not tracked.
#[unsafe(no_mangle)]
pub extern "C" fn pci_aer_error_count(bus: u8, dev: u8, func: u8) -> i32 {
    match lookup_device(bus, dev, func) {
        Some(slot) => {
            let devs = unsafe { &*DEVICES.get() };
            let total = devs[slot]
                .uncorr_count
                .saturating_add(devs[slot].corr_count);
            total as i32
        }
        None => -1,
    }
}

/// Dump a summary of AER status for a device to the kernel log.
///
/// Returns 0 on success, -1 if AER is not present or driver not initialized.
#[unsafe(no_mangle)]
pub extern "C" fn pci_aer_dump(bus: u8, dev: u8, func: u8) -> i32 {
    let st = unsafe { &*STATE.get() };
    if !st.initialized {
        return -1;
    }

    let aer_off = get_aer_offset(bus, dev, func);
    if aer_off == 0 {
        return -1;
    }

    let uncorr_status = ecam_read32(bus, dev, func, aer_off + AER_UNCORR_STATUS);
    let uncorr_mask = ecam_read32(bus, dev, func, aer_off + AER_UNCORR_MASK);
    let uncorr_sev = ecam_read32(bus, dev, func, aer_off + AER_UNCORR_SEVERITY);
    let corr_status = ecam_read32(bus, dev, func, aer_off + AER_CORR_STATUS);
    let corr_mask = ecam_read32(bus, dev, func, aer_off + AER_CORR_MASK);
    let cap_ctrl = ecam_read32(bus, dev, func, aer_off + AER_CAP_CONTROL);

    unsafe {
        fut_printf(
            b"pci_aer: %02x:%02x.%x AER dump:\n\0".as_ptr(),
            bus as u32,
            dev as u32,
            func as u32,
        );
        fut_printf(
            b"pci_aer:   uncorrectable status=0x%08x mask=0x%08x severity=0x%08x\n\0".as_ptr(),
            uncorr_status,
            uncorr_mask,
            uncorr_sev,
        );
        fut_printf(
            b"pci_aer:   correctable   status=0x%08x mask=0x%08x\n\0".as_ptr(),
            corr_status,
            corr_mask,
        );
        fut_printf(
            b"pci_aer:   cap/control=0x%08x\n\0".as_ptr(),
            cap_ctrl,
        );
    }

    // Log individual uncorrectable errors
    if uncorr_status != 0 {
        log_error_bits(bus, dev, func, uncorr_status, true);
    }

    // Log individual correctable errors
    if corr_status != 0 {
        log_error_bits(bus, dev, func, corr_status, false);
    }

    // Read and log header log if any uncorrectable error is present
    if uncorr_status != 0 {
        let h0 = ecam_read32(bus, dev, func, aer_off + AER_HEADER_LOG0);
        let h1 = ecam_read32(bus, dev, func, aer_off + AER_HEADER_LOG1);
        let h2 = ecam_read32(bus, dev, func, aer_off + AER_HEADER_LOG2);
        let h3 = ecam_read32(bus, dev, func, aer_off + AER_HEADER_LOG3);

        unsafe {
            fut_printf(
                b"pci_aer:   TLP header: %08x %08x %08x %08x\n\0".as_ptr(),
                h0,
                h1,
                h2,
                h3,
            );
        }
    }

    0
}

/// Log individual error bits for a status register value.
fn log_error_bits(bus: u8, dev: u8, func: u8, status: u32, uncorrectable: bool) {
    let label: *const u8 = if uncorrectable {
        b"uncorrectable\0".as_ptr()
    } else {
        b"correctable\0".as_ptr()
    };

    // Check each defined bit
    let bits: &[u32] = if uncorrectable {
        &[4, 12, 13, 14, 15, 16, 17, 18, 19, 20]
    } else {
        &[0, 6, 7, 8, 12, 13]
    };

    for &bit in bits {
        if status & (1 << bit) != 0 {
            let name: &[u8] = if uncorrectable {
                match bit {
                    4 => b"DLP\0",
                    12 => b"Poisoned TLP\0",
                    13 => b"Flow Control\0",
                    14 => b"Completion Timeout\0",
                    15 => b"Completer Abort\0",
                    16 => b"Unexpected Completion\0",
                    17 => b"Receiver Overflow\0",
                    18 => b"Malformed TLP\0",
                    19 => b"ECRC\0",
                    20 => b"Unsupported Request\0",
                    _ => b"Reserved\0",
                }
            } else {
                match bit {
                    0 => b"Receiver Error\0",
                    6 => b"Bad TLP\0",
                    7 => b"Bad DLLP\0",
                    8 => b"Replay Num Rollover\0",
                    12 => b"Replay Timer Timeout\0",
                    13 => b"Advisory Non-Fatal\0",
                    _ => b"Reserved\0",
                }
            };

            unsafe {
                fut_printf(
                    b"pci_aer:   %02x:%02x.%x %s bit %u: %s\n\0".as_ptr(),
                    bus as u32,
                    dev as u32,
                    func as u32,
                    label,
                    bit,
                    name.as_ptr(),
                );
            }
        }
    }
}
