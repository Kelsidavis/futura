// SPDX-License-Identifier: MPL-2.0
//
// PCI Power Management Driver (x86-64)
//
// Implements the PCI Power Management Capability (PCI PM spec 1.2),
// providing D-state control, PME signalling, and capability discovery
// for PCI/PCIe devices on x86 platforms.
//
// Architecture:
//   - Walks PCI capability list to locate PM capability (ID 0x01)
//   - Reads/writes PMCSR to transition devices between D0-D3hot
//   - Enforces spec-mandated recovery delays on state transitions
//   - Supports PME enable/disable/status for wake event management
//
// No heap allocation; all config access via legacy I/O port mechanism.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(unexpected_cfgs)]

use common::log;

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

// ── PM capability constants ──

/// PCI Power Management capability ID
const PM_CAP_ID: u8 = 0x01;

/// PCI config offset for capabilities pointer (type 0 header)
const PCI_CAP_PTR: u8 = 0x34;

/// PCI Status register offset and capability-list bit
const PCI_STATUS: u8 = 0x06;
const PCI_STATUS_CAP_LIST: u16 = 1 << 4;

/// Offsets within the PM capability structure (relative to cap base)
const PM_PMC: u8 = 0x02;   // Power Management Capabilities (16-bit)
const PM_PMCSR: u8 = 0x04; // PM Control/Status Register (16-bit)

/// PMC register bit fields
const PMC_D1_SUPPORT: u16 = 1 << 9;
const PMC_D2_SUPPORT: u16 = 1 << 10;

/// PMCSR register bit fields
const PMCSR_STATE_MASK: u16 = 0x0003;  // bits [1:0]: PowerState
const PMCSR_PME_EN: u16 = 1 << 8;     // bit 8: PME_En
const PMCSR_PME_STATUS: u16 = 1 << 15; // bit 15: PME_Status (write-1-to-clear)

/// D-state encoding in PMCSR PowerState field
const PM_D0: u8 = 0;
const PM_D1: u8 = 1;
const PM_D2: u8 = 2;
const PM_D3HOT: u8 = 3;

/// Spec-mandated recovery delays (milliseconds)
/// D3hot -> D0 requires at least 10 ms
const D3_TO_D0_DELAY_MS: u64 = 10;
/// D2 -> D0 requires at least 200 us (we round up to 1 ms for kernel timer granularity)
const D2_TO_D0_DELAY_MS: u64 = 1;
/// D1 -> D0 is unspecified but conventionally 0 (no mandatory delay)

// ── Software delay ──

/// Busy-wait loop for short microsecond-scale delays.
/// For longer waits we would use `common::thread_sleep` but the common crate
/// exposes it and we use it for the longer D3->D0 transition.
fn delay_ms(ms: u64) {
    if ms > 0 {
        common::thread_sleep(ms);
    }
}

// ── Internal helpers ──

/// Walk the PCI capability list and return the config-space offset of the
/// PM capability (ID 0x01), or 0 if not found.
fn find_pm_cap(bus: u8, dev: u8, func: u8) -> u8 {
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
        if cap_id == PM_CAP_ID {
            return ptr;
        }
        ptr = pci_read8(bus, dev, func, ptr + 1) & 0xFC;
        visited += 1;
    }

    0
}

/// Read the PMCSR register for a device given the PM capability offset.
fn read_pmcsr(bus: u8, dev: u8, func: u8, cap_off: u8) -> u16 {
    pci_read16(bus, dev, func, cap_off + PM_PMCSR)
}

/// Write the PMCSR register for a device given the PM capability offset.
fn write_pmcsr(bus: u8, dev: u8, func: u8, cap_off: u8, val: u16) {
    pci_write16(bus, dev, func, cap_off + PM_PMCSR, val);
}

/// Read the PMC (Power Management Capabilities) register.
fn read_pmc(bus: u8, dev: u8, func: u8, cap_off: u8) -> u16 {
    pci_read16(bus, dev, func, cap_off + PM_PMC)
}

// ── Exported API ──

/// Find the PCI PM capability for a device.
/// Returns the capability offset in config space (>0) on success, or -1 if
/// the device does not support PCI Power Management.
#[unsafe(no_mangle)]
pub extern "C" fn pci_pm_find_cap(bus: u8, dev: u8, func: u8) -> i32 {
    let cap = find_pm_cap(bus, dev, func);
    if cap == 0 {
        -1
    } else {
        cap as i32
    }
}

/// Get the current power state of a device.
/// Returns 0 (D0), 1 (D1), 2 (D2), or 3 (D3hot) on success, -1 on error.
#[unsafe(no_mangle)]
pub extern "C" fn pci_pm_get_state(bus: u8, dev: u8, func: u8) -> i32 {
    let cap_off = find_pm_cap(bus, dev, func);
    if cap_off == 0 {
        return -1;
    }

    let pmcsr = read_pmcsr(bus, dev, func, cap_off);
    (pmcsr & PMCSR_STATE_MASK) as i32
}

/// Set the power state of a device. Valid state values: 0 (D0), 1 (D1),
/// 2 (D2), 3 (D3hot). Enforces spec-mandated recovery delays on transitions
/// toward D0.
///
/// Returns 0 on success, -1 if no PM capability, -2 if invalid state,
/// -3 if the device does not support the requested D-state.
#[unsafe(no_mangle)]
pub extern "C" fn pci_pm_set_state(bus: u8, dev: u8, func: u8, state: u8) -> i32 {
    if state > PM_D3HOT {
        return -2;
    }

    let cap_off = find_pm_cap(bus, dev, func);
    if cap_off == 0 {
        return -1;
    }

    // Verify D1/D2 support if those states are requested
    if state == PM_D1 || state == PM_D2 {
        let pmc = read_pmc(bus, dev, func, cap_off);
        if state == PM_D1 && (pmc & PMC_D1_SUPPORT == 0) {
            return -3;
        }
        if state == PM_D2 && (pmc & PMC_D2_SUPPORT == 0) {
            return -3;
        }
    }

    // Read current state to determine required delay
    let pmcsr = read_pmcsr(bus, dev, func, cap_off);
    let current_state = (pmcsr & PMCSR_STATE_MASK) as u8;

    // Write the new power state, preserving other PMCSR bits.
    // PME_Status (bit 15) is write-1-to-clear, so we must avoid accidentally
    // clearing it by masking it out of the value we write back.
    let new_pmcsr = (pmcsr & !PMCSR_STATE_MASK & !PMCSR_PME_STATUS) | (state as u16);
    write_pmcsr(bus, dev, func, cap_off, new_pmcsr);

    // Apply spec-mandated recovery delays when transitioning toward D0
    if state < current_state {
        // We are waking up — delay depends on the state we came from
        match current_state {
            3 => delay_ms(D3_TO_D0_DELAY_MS),  // D3hot -> anything lower
            2 => delay_ms(D2_TO_D0_DELAY_MS),  // D2 -> D0 or D1
            _ => {}                              // D1 -> D0: no mandatory delay
        }
    }

    unsafe {
        fut_printf(
            b"pci_pm: %02x:%02x.%x D%u -> D%u\n\0".as_ptr(),
            bus as u32,
            dev as u32,
            func as u32,
            current_state as u32,
            state as u32,
        );
    }

    0
}

/// Check whether a device supports the D1 power state.
/// Returns true if D1 is supported, false otherwise (including if no PM cap).
#[unsafe(no_mangle)]
pub extern "C" fn pci_pm_supports_d1(bus: u8, dev: u8, func: u8) -> bool {
    let cap_off = find_pm_cap(bus, dev, func);
    if cap_off == 0 {
        return false;
    }

    let pmc = read_pmc(bus, dev, func, cap_off);
    pmc & PMC_D1_SUPPORT != 0
}

/// Check whether a device supports the D2 power state.
/// Returns true if D2 is supported, false otherwise (including if no PM cap).
#[unsafe(no_mangle)]
pub extern "C" fn pci_pm_supports_d2(bus: u8, dev: u8, func: u8) -> bool {
    let cap_off = find_pm_cap(bus, dev, func);
    if cap_off == 0 {
        return false;
    }

    let pmc = read_pmc(bus, dev, func, cap_off);
    pmc & PMC_D2_SUPPORT != 0
}

/// Enable PME (Power Management Event) generation for a device.
/// Sets PMCSR.PME_En to allow the device to assert PME#.
/// Returns 0 on success, -1 if no PM capability.
#[unsafe(no_mangle)]
pub extern "C" fn pci_pm_enable_pme(bus: u8, dev: u8, func: u8) -> i32 {
    let cap_off = find_pm_cap(bus, dev, func);
    if cap_off == 0 {
        return -1;
    }

    let pmcsr = read_pmcsr(bus, dev, func, cap_off);
    // Set PME_En, preserve other bits, avoid clearing PME_Status
    let new_pmcsr = (pmcsr & !PMCSR_PME_STATUS) | PMCSR_PME_EN;
    write_pmcsr(bus, dev, func, cap_off, new_pmcsr);

    0
}

/// Disable PME (Power Management Event) generation for a device.
/// Clears PMCSR.PME_En.
/// Returns 0 on success, -1 if no PM capability.
#[unsafe(no_mangle)]
pub extern "C" fn pci_pm_disable_pme(bus: u8, dev: u8, func: u8) -> i32 {
    let cap_off = find_pm_cap(bus, dev, func);
    if cap_off == 0 {
        return -1;
    }

    let pmcsr = read_pmcsr(bus, dev, func, cap_off);
    // Clear PME_En, preserve other bits, avoid clearing PME_Status
    let new_pmcsr = pmcsr & !PMCSR_PME_EN & !PMCSR_PME_STATUS;
    write_pmcsr(bus, dev, func, cap_off, new_pmcsr);

    0
}

/// Check whether a PME (Power Management Event) is pending.
/// Returns true if PMCSR.PME_Status is set, false otherwise.
#[unsafe(no_mangle)]
pub extern "C" fn pci_pm_check_pme(bus: u8, dev: u8, func: u8) -> bool {
    let cap_off = find_pm_cap(bus, dev, func);
    if cap_off == 0 {
        return false;
    }

    let pmcsr = read_pmcsr(bus, dev, func, cap_off);
    pmcsr & PMCSR_PME_STATUS != 0
}

/// Clear a pending PME by writing 1 to PMCSR.PME_Status (write-1-to-clear).
#[unsafe(no_mangle)]
pub extern "C" fn pci_pm_clear_pme(bus: u8, dev: u8, func: u8) {
    let cap_off = find_pm_cap(bus, dev, func);
    if cap_off == 0 {
        return;
    }

    let pmcsr = read_pmcsr(bus, dev, func, cap_off);
    // Write back with PME_Status bit set to clear it, preserve other fields
    write_pmcsr(bus, dev, func, cap_off, pmcsr | PMCSR_PME_STATUS);
}
