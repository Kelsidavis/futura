// SPDX-License-Identifier: MPL-2.0
//
// Intel Thunderbolt / USB4 Controller Driver for Futura OS
//
// Provides access to the Intel Thunderbolt (TBT) / USB4 controller via the
// Native Host Interface (NHI) on Gen 10+ (Ice Lake and later) platforms.
// The controller is discovered through PCI enumeration (vendor 8086h, serial
// bus class 0Ch/03h or dedicated TBT device IDs) and exposes its register
// set through a BAR0-mapped MMIO region.
//
// Supported controllers:
//   - Ice Lake (ICL):   8A17h, 8A0Dh
//   - Tiger Lake (TGL): 9A1Bh, 9A1Dh
//   - Alder Lake (ADL): 463Eh
//   - Meteor Lake (MTL): 7EC4h
//
// NHI (Native Host Interface) MMIO register map (offsets from BAR0):
//   0x00  NHI_CAPS         Capabilities register
//   0x04  NHI_CTRL         Control register (enable/disable controller)
//   0x08  NHI_STS          Status register
//   0x20  NHI_MAILBOX_CMD  Mailbox command register
//   0x24  NHI_MAILBOX_DATA Mailbox data register
//   0x28  NHI_MAILBOX_STS  Mailbox status register
//
// Per-port registers (base 0x100, stride 0x40 per port):
//   +0x00  PORT_CTRL        Port control
//   +0x04  PORT_STS         Port status (connected, speed, device type)
//   +0x08  PORT_SEC         Port security level
//
// Mailbox commands (written to NHI_MAILBOX_CMD):
//   0x01  CONNECT          Establish a tunnel connection
//   0x02  DISCONNECT       Tear down a tunnel connection
//   0x03  APPROVE_DEVICE   Approve a connected device (security)
//   0x04  GET_TOPOLOGY     Retrieve topology information
//
// Security levels:
//   0  SEC_NONE     No security (legacy)
//   1  SEC_USER     User approval required
//   2  SEC_SECURE   Secure connect
//   3  SEC_DP_ONLY  DisplayPort tunnels only

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(unexpected_cfgs)]

use core::cell::UnsafeCell;
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{fence, Ordering};

use common::{log, map_mmio_region, unmap_mmio_region, thread_yield, MMIO_DEFAULT_FLAGS};

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

// ── PCI constants ──

const INTEL_VENDOR_ID: u16 = 0x8086;

/// Known Intel Thunderbolt / USB4 NHI device IDs
const TBT_DEVICE_IDS: &[u16] = &[
    0x8A17, // Ice Lake TBT3
    0x8A0D, // Ice Lake TBT3
    0x9A1B, // Tiger Lake TBT4
    0x9A1D, // Tiger Lake TBT4
    0x463E, // Alder Lake TBT4
    0x7EC4, // Meteor Lake USB4
];

/// PCI class 0Ch (serial bus controller), subclass 03h (USB)
const PCI_CLASS_SERIAL_BUS: u8 = 0x0C;
const PCI_SUBCLASS_USB: u8 = 0x03;

/// PCI BAR0 offset in configuration space
const PCI_BAR0_OFFSET: u8 = 0x10;

/// PCI Command register offset
const PCI_CMD_OFFSET: u8 = 0x04;

/// PCI Command register bits
const PCI_CMD_MEMORY_SPACE: u32 = 1 << 1;
const PCI_CMD_BUS_MASTER: u32 = 1 << 2;

/// BAR0 mask for 32-bit memory BAR (bits [31:4] are the base address)
const BAR0_ADDR_MASK: u32 = 0xFFFF_FFF0;

// ── NHI MMIO register offsets ──

/// NHI Capabilities register
const NHI_CAPS: usize = 0x00;
/// NHI Control register (enable/disable)
const NHI_CTRL: usize = 0x04;
/// NHI Status register
const NHI_STS: usize = 0x08;
/// NHI Mailbox Command register
const NHI_MAILBOX_CMD: usize = 0x20;
/// NHI Mailbox Data register
const NHI_MAILBOX_DATA: usize = 0x24;
/// NHI Mailbox Status register
const NHI_MAILBOX_STS: usize = 0x28;

/// Size of the NHI MMIO region to map (16 KiB covers NHI regs + port regs)
const NHI_MMIO_SIZE: usize = 0x4000;

// ── NHI_CAPS register fields ──

/// Bits [3:0] encode the number of ports (0-based, add 1)
const NHI_CAPS_PORT_COUNT_MASK: u32 = 0x0F;
/// Bit 4: mailbox supported
const NHI_CAPS_MAILBOX: u32 = 1 << 4;

// ── NHI_CTRL register bits ──

/// Bit 0: controller enable
const NHI_CTRL_ENABLE: u32 = 1 << 0;
/// Bit 1: controller reset
const NHI_CTRL_RESET: u32 = 1 << 1;

// ── NHI_STS register bits ──

/// Bit 0: controller ready
const NHI_STS_READY: u32 = 1 << 0;
/// Bit 1: controller error
const NHI_STS_ERROR: u32 = 1 << 1;

// ── Mailbox status bits ──

/// Bit 0: mailbox busy (command in progress)
const MBOX_STS_BUSY: u32 = 1 << 0;
/// Bit 1: mailbox done (command completed)
const MBOX_STS_DONE: u32 = 1 << 1;
/// Bit 2: mailbox error
const MBOX_STS_ERROR: u32 = 1 << 2;

// ── Mailbox commands ──

const MBOX_CMD_CONNECT: u32 = 0x01;
const MBOX_CMD_DISCONNECT: u32 = 0x02;
const MBOX_CMD_APPROVE_DEVICE: u32 = 0x03;
const MBOX_CMD_GET_TOPOLOGY: u32 = 0x04;

// ── Per-port registers ──

/// Base offset for port 0 registers
const PORT_REG_BASE: usize = 0x100;
/// Stride between consecutive port register blocks
const PORT_REG_STRIDE: usize = 0x40;

/// Port control register (offset within port block)
const PORT_CTRL: usize = 0x00;
/// Port status register (offset within port block)
const PORT_STS: usize = 0x04;
/// Port security register (offset within port block)
const PORT_SEC: usize = 0x08;

// ── Port status register fields ──

/// Bit 0: port connected
const PORT_STS_CONNECTED: u32 = 1 << 0;
/// Bits [3:1]: speed encoding
const PORT_STS_SPEED_SHIFT: u32 = 1;
const PORT_STS_SPEED_MASK: u32 = 0x07;
/// Bits [5:4]: device type
const PORT_STS_DEV_TYPE_SHIFT: u32 = 4;
const PORT_STS_DEV_TYPE_MASK: u32 = 0x03;

// ── Speed encodings ──

/// Speed code to Gbps mapping
const SPEED_UNKNOWN: u32 = 0;
const SPEED_TBT3_20G: u32 = 1;  // 20 Gbps (TBT3 half-duplex)
const SPEED_TBT3_40G: u32 = 2;  // 40 Gbps (TBT3 full)
const SPEED_USB4_20G: u32 = 3;  // 20 Gbps (USB4 Gen 2)
const SPEED_USB4_40G: u32 = 4;  // 40 Gbps (USB4 Gen 3)

/// Convert a speed code from the port status register to Gbps
fn speed_code_to_gbps(code: u32) -> u32 {
    match code {
        SPEED_TBT3_20G | SPEED_USB4_20G => 20,
        SPEED_TBT3_40G | SPEED_USB4_40G => 40,
        _ => 0,
    }
}

// ── Security levels ──

const SEC_NONE: u32 = 0;
const SEC_USER: u32 = 1;
const SEC_SECURE: u32 = 2;
const SEC_DP_ONLY: u32 = 3;

/// Port security register mask for security level bits [1:0]
const PORT_SEC_LEVEL_MASK: u32 = 0x03;

// ── Timeout / polling constants ──

/// Maximum polling iterations waiting for controller ready
const READY_POLL_MAX: u32 = 1000;
/// Maximum polling iterations waiting for mailbox completion
const MBOX_POLL_MAX: u32 = 500;
/// Maximum number of ports the controller can expose
const MAX_PORTS: u32 = 8;

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

struct TbtState {
    /// Virtual address of the NHI MMIO register base
    base: *mut u8,
    /// Physical address of BAR0
    phys_base: u64,
    /// PCI bus/device/function of the TBT controller
    bus: u8,
    dev: u8,
    func: u8,
    /// Device ID of the discovered controller
    device_id: u16,
    /// Number of TBT/USB4 ports
    port_count: u32,
    /// Whether mailbox interface is supported
    mailbox_supported: bool,
    /// Whether the driver has been initialized
    initialized: bool,
}

impl TbtState {
    const fn new() -> Self {
        Self {
            base: core::ptr::null_mut(),
            phys_base: 0,
            bus: 0,
            dev: 0,
            func: 0,
            device_id: 0,
            port_count: 0,
            mailbox_supported: false,
            initialized: false,
        }
    }
}

static TBT: StaticCell<TbtState> = StaticCell::new(TbtState::new());

// ── Internal helpers ──

/// Check if a PCI device matches a known Intel TBT/USB4 controller.
fn is_tbt_device(pci: &PciDevice) -> bool {
    if pci.vendor_id != INTEL_VENDOR_ID {
        return false;
    }
    // Match by known device ID
    for &did in TBT_DEVICE_IDS {
        if pci.device_id == did {
            return true;
        }
    }
    // Match by PCI class: serial bus controller (0Ch) / USB (03h)
    // with an Intel vendor ID and a device ID in the TBT range
    if pci.class_code == PCI_CLASS_SERIAL_BUS && pci.subclass == PCI_SUBCLASS_USB {
        // Additional heuristic: TBT NHI controllers typically have prog_if 0x40
        if pci.prog_if == 0x40 {
            return true;
        }
    }
    false
}

/// Scan the kernel PCI device list for a TBT/USB4 controller.
/// Returns Some((bus, dev, func, device_id)) on success.
fn find_tbt_controller() -> Option<(u8, u8, u8, u16)> {
    let count = unsafe { pci_device_count() };
    for i in 0..count {
        let dev = unsafe { pci_get_device(i) };
        if dev.is_null() {
            continue;
        }
        let d = unsafe { &*dev };
        if is_tbt_device(d) {
            return Some((d.bus, d.dev, d.func, d.device_id));
        }
    }
    None
}

/// Read BAR0 from PCI configuration space and return the physical address.
fn read_bar0(bus: u8, dev: u8, func: u8) -> u64 {
    let raw = pci_read32(bus, dev, func, PCI_BAR0_OFFSET);
    let addr = raw & BAR0_ADDR_MASK;
    if addr == 0 || addr == BAR0_ADDR_MASK {
        return 0;
    }
    addr as u64
}

/// Enable memory-space access and bus mastering for the PCI device.
fn enable_pci_device(bus: u8, dev: u8, func: u8) {
    let cmd = pci_read32(bus, dev, func, PCI_CMD_OFFSET);
    let needed = PCI_CMD_MEMORY_SPACE | PCI_CMD_BUS_MASTER;
    if (cmd & needed) != needed {
        pci_write32(bus, dev, func, PCI_CMD_OFFSET, cmd | needed);
    }
}

/// Compute the MMIO offset for a per-port register.
fn port_reg_offset(port: u32, reg: usize) -> usize {
    PORT_REG_BASE + (port as usize) * PORT_REG_STRIDE + reg
}

/// Wait for the controller to report ready status.
/// Returns true if the controller is ready, false on timeout.
fn wait_controller_ready(base: *mut u8) -> bool {
    for _ in 0..READY_POLL_MAX {
        let sts = mmio_read32(base, NHI_STS);
        if sts & NHI_STS_READY != 0 {
            return true;
        }
        if sts & NHI_STS_ERROR != 0 {
            return false;
        }
        thread_yield();
    }
    false
}

/// Send a mailbox command and wait for completion.
/// Returns 0 on success, -1 on timeout, -2 on mailbox error.
fn mailbox_send(base: *mut u8, cmd: u32, data: u32) -> i32 {
    // Wait for any previous command to complete
    for _ in 0..MBOX_POLL_MAX {
        let sts = mmio_read32(base, NHI_MAILBOX_STS);
        if sts & MBOX_STS_BUSY == 0 {
            break;
        }
        thread_yield();
    }

    // Check if still busy after waiting
    let sts = mmio_read32(base, NHI_MAILBOX_STS);
    if sts & MBOX_STS_BUSY != 0 {
        return -1;
    }

    // Write data, then command (writing command triggers execution)
    mmio_write32(base, NHI_MAILBOX_DATA, data);
    fence(Ordering::SeqCst);
    mmio_write32(base, NHI_MAILBOX_CMD, cmd);
    fence(Ordering::SeqCst);

    // Poll for completion
    for _ in 0..MBOX_POLL_MAX {
        let sts = mmio_read32(base, NHI_MAILBOX_STS);
        if sts & MBOX_STS_DONE != 0 {
            if sts & MBOX_STS_ERROR != 0 {
                return -2;
            }
            return 0;
        }
        thread_yield();
    }

    -1 // timeout
}

/// Read the mailbox data register (after a successful command).
fn mailbox_read_data(base: *mut u8) -> u32 {
    mmio_read32(base, NHI_MAILBOX_DATA)
}

/// Return a human-readable name for a known device ID.
fn device_name(device_id: u16) -> &'static [u8] {
    match device_id {
        0x8A17 => b"ICL TBT3\0",
        0x8A0D => b"ICL TBT3\0",
        0x9A1B => b"TGL TBT4\0",
        0x9A1D => b"TGL TBT4\0",
        0x463E => b"ADL TBT4\0",
        0x7EC4 => b"MTL USB4\0",
        _ => b"Unknown\0",
    }
}

/// Return a human-readable name for a security level.
fn security_name(level: u32) -> &'static [u8] {
    match level {
        SEC_NONE => b"none\0",
        SEC_USER => b"user\0",
        SEC_SECURE => b"secure\0",
        SEC_DP_ONLY => b"dp_only\0",
        _ => b"unknown\0",
    }
}

// ── FFI exports ──

/// Initialize the Intel Thunderbolt / USB4 controller driver.
///
/// Scans for a TBT/USB4 NHI controller on the PCI bus, maps BAR0,
/// reads capabilities, and enables the controller.
///
/// Returns 0 on success, negative on error:
///   -1 = no TBT/USB4 controller found
///   -2 = BAR0 is zero or invalid
///   -3 = failed to map NHI MMIO region
///   -4 = controller failed to become ready
#[unsafe(no_mangle)]
pub extern "C" fn intel_tbt_init() -> i32 {
    log("intel_tbt: initializing Thunderbolt/USB4 driver");

    // Scan PCI bus for a TBT/USB4 controller
    let (bus, dev, func, device_id) = match find_tbt_controller() {
        Some(v) => v,
        None => {
            log("intel_tbt: no Thunderbolt/USB4 controller found");
            return -1;
        }
    };

    unsafe {
        fut_printf(
            b"intel_tbt: found %s controller [%04x:%04x] at %02x:%02x.%x\n\0".as_ptr(),
            device_name(device_id).as_ptr(),
            INTEL_VENDOR_ID as u32,
            device_id as u32,
            bus as u32,
            dev as u32,
            func as u32,
        );
    }

    // Enable memory-space access and bus mastering
    enable_pci_device(bus, dev, func);

    // Read BAR0 physical address
    let bar0_phys = read_bar0(bus, dev, func);
    if bar0_phys == 0 {
        log("intel_tbt: BAR0 is zero or invalid");
        return -2;
    }

    unsafe {
        fut_printf(
            b"intel_tbt: BAR0 = 0x%08llx\n\0".as_ptr(),
            bar0_phys,
        );
    }

    // Map the NHI MMIO region
    let base = unsafe { map_mmio_region(bar0_phys, NHI_MMIO_SIZE, MMIO_DEFAULT_FLAGS) };
    if base.is_null() {
        log("intel_tbt: failed to map NHI MMIO region");
        return -3;
    }

    // Read capabilities
    let caps = mmio_read32(base, NHI_CAPS);
    let port_count = (caps & NHI_CAPS_PORT_COUNT_MASK) + 1;
    let port_count = if port_count > MAX_PORTS { MAX_PORTS } else { port_count };
    let mailbox_supported = (caps & NHI_CAPS_MAILBOX) != 0;

    unsafe {
        fut_printf(
            b"intel_tbt: NHI_CAPS=0x%08x ports=%u mailbox=%s\n\0".as_ptr(),
            caps,
            port_count,
            if mailbox_supported { b"yes\0".as_ptr() } else { b"no\0".as_ptr() },
        );
    }

    // Enable the controller
    let ctrl = mmio_read32(base, NHI_CTRL);
    if ctrl & NHI_CTRL_ENABLE == 0 {
        mmio_write32(base, NHI_CTRL, ctrl | NHI_CTRL_ENABLE);
        fence(Ordering::SeqCst);
        log("intel_tbt: controller enabled");
    }

    // Wait for the controller to become ready
    if !wait_controller_ready(base) {
        log("intel_tbt: controller failed to become ready");
        unsafe { unmap_mmio_region(base, NHI_MMIO_SIZE) };
        return -4;
    }

    // Read initial status
    let sts = mmio_read32(base, NHI_STS);
    unsafe {
        fut_printf(
            b"intel_tbt: NHI_CTRL=0x%08x NHI_STS=0x%08x\n\0".as_ptr(),
            mmio_read32(base, NHI_CTRL),
            sts,
        );
    }

    // Store driver state
    let state = TBT.get();
    unsafe {
        (*state).base = base;
        (*state).phys_base = bar0_phys;
        (*state).bus = bus;
        (*state).dev = dev;
        (*state).func = func;
        (*state).device_id = device_id;
        (*state).port_count = port_count;
        (*state).mailbox_supported = mailbox_supported;
        fence(Ordering::SeqCst);
        (*state).initialized = true;
    }

    // Log per-port status
    for p in 0..port_count {
        let ps = mmio_read32(base, port_reg_offset(p, PORT_STS));
        let sec = mmio_read32(base, port_reg_offset(p, PORT_SEC));
        let connected = (ps & PORT_STS_CONNECTED) != 0;
        let speed_code = (ps >> PORT_STS_SPEED_SHIFT) & PORT_STS_SPEED_MASK;
        let dev_type = (ps >> PORT_STS_DEV_TYPE_SHIFT) & PORT_STS_DEV_TYPE_MASK;
        let sec_level = sec & PORT_SEC_LEVEL_MASK;

        unsafe {
            fut_printf(
                b"intel_tbt: port %u: connected=%s speed=%u Gbps type=%u sec=%s\n\0".as_ptr(),
                p,
                if connected { b"yes\0".as_ptr() } else { b"no\0".as_ptr() },
                speed_code_to_gbps(speed_code),
                dev_type,
                security_name(sec_level).as_ptr(),
            );
        }
    }

    log("intel_tbt: driver initialized");
    0
}

/// Return the number of Thunderbolt/USB4 ports on the controller.
///
/// Returns 0 if the driver is not initialized.
#[unsafe(no_mangle)]
pub extern "C" fn intel_tbt_port_count() -> u32 {
    let state = TBT.get();
    unsafe {
        if !(*state).initialized {
            return 0;
        }
        (*state).port_count
    }
}

/// Read the raw port status register for the given port.
///
/// Returns the PORT_STS register value, or 0 if the driver is not
/// initialized or the port index is out of range.
#[unsafe(no_mangle)]
pub extern "C" fn intel_tbt_port_status(port: u32) -> u32 {
    let state = TBT.get();
    unsafe {
        if !(*state).initialized {
            return 0;
        }
        if port >= (*state).port_count {
            return 0;
        }
        mmio_read32((*state).base, port_reg_offset(port, PORT_STS))
    }
}

/// Return the link speed in Gbps for the given port.
///
/// Returns 0 if the driver is not initialized, the port index is out of
/// range, or no device is connected.
#[unsafe(no_mangle)]
pub extern "C" fn intel_tbt_port_speed(port: u32) -> u32 {
    let state = TBT.get();
    unsafe {
        if !(*state).initialized {
            return 0;
        }
        if port >= (*state).port_count {
            return 0;
        }
        let ps = mmio_read32((*state).base, port_reg_offset(port, PORT_STS));
        if ps & PORT_STS_CONNECTED == 0 {
            return 0;
        }
        let speed_code = (ps >> PORT_STS_SPEED_SHIFT) & PORT_STS_SPEED_MASK;
        speed_code_to_gbps(speed_code)
    }
}

/// Check whether a device is connected to the given port.
///
/// Returns false if the driver is not initialized or the port index
/// is out of range.
#[unsafe(no_mangle)]
pub extern "C" fn intel_tbt_is_connected(port: u32) -> bool {
    let state = TBT.get();
    unsafe {
        if !(*state).initialized {
            return false;
        }
        if port >= (*state).port_count {
            return false;
        }
        let ps = mmio_read32((*state).base, port_reg_offset(port, PORT_STS));
        (ps & PORT_STS_CONNECTED) != 0
    }
}

/// Approve a device connected to the given port.
///
/// Sends an APPROVE_DEVICE mailbox command to the TBT controller
/// firmware, authorising the device for full tunnel access.
///
/// Returns 0 on success, negative on error:
///   -1 = driver not initialized
///   -2 = port index out of range
///   -3 = mailbox not supported
///   -4 = no device connected on this port
///   -5 = mailbox command timeout
///   -6 = mailbox command error
#[unsafe(no_mangle)]
pub extern "C" fn intel_tbt_approve_device(port: u32) -> i32 {
    let state = TBT.get();
    unsafe {
        if !(*state).initialized {
            return -1;
        }
        if port >= (*state).port_count {
            return -2;
        }
        if !(*state).mailbox_supported {
            return -3;
        }
        // Verify a device is actually connected
        let ps = mmio_read32((*state).base, port_reg_offset(port, PORT_STS));
        if ps & PORT_STS_CONNECTED == 0 {
            return -4;
        }

        fut_printf(
            b"intel_tbt: approving device on port %u\n\0".as_ptr(),
            port,
        );

        let result = mailbox_send((*state).base, MBOX_CMD_APPROVE_DEVICE, port);
        match result {
            0 => {
                log("intel_tbt: device approved");
                0
            }
            -1 => {
                log("intel_tbt: approve mailbox timeout");
                -5
            }
            _ => {
                log("intel_tbt: approve mailbox error");
                -6
            }
        }
    }
}

/// Return the overall controller status register (NHI_STS).
///
/// Bit 0: controller ready
/// Bit 1: controller error
///
/// Returns 0 if the driver is not initialized.
#[unsafe(no_mangle)]
pub extern "C" fn intel_tbt_controller_status() -> u32 {
    let state = TBT.get();
    unsafe {
        if !(*state).initialized {
            return 0;
        }
        mmio_read32((*state).base, NHI_STS)
    }
}

/// Check whether an Intel Thunderbolt/USB4 controller is present on
/// the PCI bus (does not require prior initialization).
///
/// Performs a lightweight scan of the kernel PCI device list.
#[unsafe(no_mangle)]
pub extern "C" fn intel_tbt_is_present() -> bool {
    find_tbt_controller().is_some()
}
