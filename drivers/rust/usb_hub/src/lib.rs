// SPDX-License-Identifier: MPL-2.0
//
// USB Hub Class Driver for Futura OS
//
// Implements the USB Hub device class (bDeviceClass=09h) for managing
// downstream port power, reset, enable/disable, speed detection, and
// connection-change handling.
//
// Architecture:
//   - Callback model: a ControlTransferFn is provided at attach time
//     for issuing USB control transfers to the hub device
//   - Up to MAX_HUBS (8) simultaneously tracked hub devices
//   - Hub descriptor parsing for USB 2.0 (type 0x29) and USB 3.0 (type 0x2A)
//   - Port power sequencing with configurable power-on delay
//   - Port reset with C_PORT_RESET polling
//   - Status change polling returns a bitmask of ports with pending changes
//
// Hub Class Requests (bmRequestType):
//   0x20 / 0xA0 — hub-targeted SET / GET requests
//   0x23 / 0xA3 — port-targeted SET / GET requests
//
// Hub class request codes:
//   GET_STATUS    = 0x00
//   CLEAR_FEATURE = 0x01
//   SET_FEATURE   = 0x03

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(unexpected_cfgs)]

use core::cell::UnsafeCell;

use common::log;

unsafe extern "C" {
    fn fut_printf(fmt: *const u8, ...);
}

// ── StaticCell wrapper (avoids `static mut`) ──

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

// ── Control transfer callback type ──

/// Function pointer for issuing USB control transfers to a hub device.
///
/// `dev`  -- host-controller device handle
/// `rt`   -- bmRequestType
/// `req`  -- bRequest
/// `val`  -- wValue
/// `idx`  -- wIndex
/// `data` -- data stage buffer (may be null for no-data transfers)
/// `len`  -- wLength (data stage length)
///
/// Returns number of bytes transferred on success, negative on error.
pub type ControlTransferFn =
    unsafe extern "C" fn(dev: u32, rt: u8, req: u8, val: u16, idx: u16, data: *mut u8, len: u16) -> i32;

// ── Constants ──

/// Maximum number of simultaneously tracked hub devices.
const MAX_HUBS: usize = 8;

/// Maximum number of downstream ports per hub.
const MAX_PORTS_PER_HUB: usize = 16;

/// Maximum hub descriptor length (variable-length bitmask fields).
const MAX_HUB_DESC_LEN: usize = 40;

/// Maximum number of polling retries for port reset completion.
const PORT_RESET_MAX_RETRIES: u32 = 20;

// ── Hub descriptor types ──

const HUB_DESC_TYPE_USB2: u8 = 0x29;
const HUB_DESC_TYPE_USB3: u8 = 0x2A;

// ── Hub device class ──

const HUB_DEVICE_CLASS: u8 = 0x09;

// ── Hub class request codes ──

const HUB_REQ_GET_STATUS: u8 = 0x00;
const HUB_REQ_CLEAR_FEATURE: u8 = 0x01;
const HUB_REQ_SET_FEATURE: u8 = 0x03;
const HUB_REQ_GET_DESCRIPTOR: u8 = 0x06;

// ── bmRequestType values ──

/// Host-to-device, class, hub recipient (SET requests to hub).
const RT_HUB_SET: u8 = 0x20;
/// Device-to-host, class, hub recipient (GET requests from hub).
const RT_HUB_GET: u8 = 0xA0;
/// Host-to-device, class, other (port) recipient (SET requests to port).
const RT_PORT_SET: u8 = 0x23;
/// Device-to-host, class, other (port) recipient (GET requests from port).
const RT_PORT_GET: u8 = 0xA3;

// ── Port feature selectors ──

const PORT_CONNECTION: u16 = 0;
const PORT_ENABLE: u16 = 1;
const PORT_SUSPEND: u16 = 2;
const PORT_OVER_CURRENT: u16 = 3;
const PORT_RESET: u16 = 4;
const PORT_POWER: u16 = 8;
const PORT_LOW_SPEED: u16 = 9;

/// Change-indicator feature selectors (for CLEAR_FEATURE).
const C_PORT_CONNECTION: u16 = 16;
const C_PORT_ENABLE: u16 = 17;
const C_PORT_SUSPEND: u16 = 18;
const C_PORT_OVER_CURRENT: u16 = 19;
const C_PORT_RESET: u16 = 20;

// ── Port status bits (wPortStatus) ──

const PORT_STATUS_CONNECTION: u16 = 1 << 0;
const PORT_STATUS_ENABLE: u16 = 1 << 1;
const PORT_STATUS_SUSPEND: u16 = 1 << 2;
const PORT_STATUS_OVER_CURRENT: u16 = 1 << 3;
const PORT_STATUS_RESET: u16 = 1 << 4;
const PORT_STATUS_POWER: u16 = 1 << 8;
const PORT_STATUS_LOW_SPEED: u16 = 1 << 9;
const PORT_STATUS_HIGH_SPEED: u16 = 1 << 10;
const PORT_STATUS_TEST: u16 = 1 << 11;
const PORT_STATUS_INDICATOR: u16 = 1 << 12;

// ── Port status change bits (wPortChange, upper 16 bits of GET_STATUS) ──

const PORT_CHANGE_CONNECTION: u16 = 1 << 0;
const PORT_CHANGE_ENABLE: u16 = 1 << 1;
const PORT_CHANGE_SUSPEND: u16 = 1 << 2;
const PORT_CHANGE_OVER_CURRENT: u16 = 1 << 3;
const PORT_CHANGE_RESET: u16 = 1 << 4;

// ── Device speed classification ──

/// Speed as detected from port status bits.
#[derive(Copy, Clone, PartialEq)]
#[repr(u8)]
enum UsbSpeed {
    /// Speed unknown or port not connected.
    Unknown = 0,
    /// Low-speed device (1.5 Mbit/s).
    Low = 1,
    /// Full-speed device (12 Mbit/s).
    Full = 2,
    /// High-speed device (480 Mbit/s).
    High = 3,
}

// ── Hub descriptor (parsed) ──

#[derive(Copy, Clone)]
struct HubDescriptor {
    /// Number of downstream ports.
    num_ports: u8,
    /// Hub characteristics (power switching mode, overcurrent, TT think time).
    characteristics: u16,
    /// Power-on to power-good time in 2 ms units.
    pwr_on_2_pwr_good: u8,
    /// Maximum current requirements of the hub controller in mA.
    hub_contr_current: u8,
    /// Descriptor type (0x29 for USB 2.0, 0x2A for USB 3.0).
    desc_type: u8,
}

impl HubDescriptor {
    const fn empty() -> Self {
        Self {
            num_ports: 0,
            characteristics: 0,
            pwr_on_2_pwr_good: 0,
            hub_contr_current: 0,
            desc_type: 0,
        }
    }
}

// ── Per-port cached state ──

#[derive(Copy, Clone)]
struct PortState {
    /// Cached wPortStatus from last GET_STATUS.
    status: u16,
    /// Cached wPortChange from last GET_STATUS.
    change: u16,
}

impl PortState {
    const fn empty() -> Self {
        Self {
            status: 0,
            change: 0,
        }
    }
}

// ── Per-hub device state ──

#[derive(Copy, Clone)]
struct HubDevice {
    /// Whether this slot is in use.
    attached: bool,
    /// Host-controller device handle.
    dev_id: u32,
    /// Control transfer callback for this hub.
    ctrl_fn: Option<ControlTransferFn>,
    /// Parsed hub descriptor.
    descriptor: HubDescriptor,
    /// Cached per-port state.
    ports: [PortState; MAX_PORTS_PER_HUB],
}

impl HubDevice {
    const fn empty() -> Self {
        Self {
            attached: false,
            dev_id: 0,
            ctrl_fn: None,
            descriptor: HubDescriptor::empty(),
            ports: [PortState::empty(); MAX_PORTS_PER_HUB],
        }
    }
}

// ── Global driver state ──

struct HubDriverState {
    initialised: bool,
    hubs: [HubDevice; MAX_HUBS],
}

impl HubDriverState {
    const fn new() -> Self {
        Self {
            initialised: false,
            hubs: [
                HubDevice::empty(),
                HubDevice::empty(),
                HubDevice::empty(),
                HubDevice::empty(),
                HubDevice::empty(),
                HubDevice::empty(),
                HubDevice::empty(),
                HubDevice::empty(),
            ],
        }
    }
}

static STATE: StaticCell<HubDriverState> = StaticCell::new(HubDriverState::new());

// ── Slot lookup helpers ──

/// Find the internal slot index for a given `dev_id`.
fn find_hub(state: &HubDriverState, dev_id: u32) -> Option<usize> {
    for i in 0..MAX_HUBS {
        if state.hubs[i].attached && state.hubs[i].dev_id == dev_id {
            return Some(i);
        }
    }
    None
}

/// Find a free hub slot, returning its index.
fn find_free_slot(state: &HubDriverState) -> Option<usize> {
    for i in 0..MAX_HUBS {
        if !state.hubs[i].attached {
            return Some(i);
        }
    }
    None
}

// ── Byte-level helpers ──

/// Read a little-endian u16 from `buf` at byte offset `off`.
fn get_le16(buf: &[u8], off: usize) -> u16 {
    (buf[off] as u16) | ((buf[off + 1] as u16) << 8)
}

// ── Control transfer wrappers ──

/// Issue a control transfer to a hub device.  Returns the raw transfer result.
fn hub_control(
    hub: &HubDevice,
    rt: u8,
    req: u8,
    val: u16,
    idx: u16,
    data: *mut u8,
    len: u16,
) -> i32 {
    let ctrl_fn = match hub.ctrl_fn {
        Some(f) => f,
        None => return -1,
    };
    unsafe { (ctrl_fn)(hub.dev_id, rt, req, val, idx, data, len) }
}

/// GET_STATUS for the hub itself (4 bytes: wHubStatus + wHubChange).
fn hub_get_hub_status(hub: &HubDevice, buf: &mut [u8; 4]) -> i32 {
    hub_control(hub, RT_HUB_GET, HUB_REQ_GET_STATUS, 0, 0, buf.as_mut_ptr(), 4)
}

/// GET_STATUS for a specific port (4 bytes: wPortStatus + wPortChange).
/// `port` is 1-based as per the USB specification.
fn hub_get_port_status(hub: &HubDevice, port: u16, buf: &mut [u8; 4]) -> i32 {
    hub_control(hub, RT_PORT_GET, HUB_REQ_GET_STATUS, 0, port, buf.as_mut_ptr(), 4)
}

/// SET_FEATURE on a specific port.
fn hub_set_port_feature(hub: &HubDevice, port: u16, feature: u16) -> i32 {
    hub_control(hub, RT_PORT_SET, HUB_REQ_SET_FEATURE, feature, port, core::ptr::null_mut(), 0)
}

/// CLEAR_FEATURE on a specific port.
fn hub_clear_port_feature(hub: &HubDevice, port: u16, feature: u16) -> i32 {
    hub_control(hub, RT_PORT_SET, HUB_REQ_CLEAR_FEATURE, feature, port, core::ptr::null_mut(), 0)
}

/// Read the hub descriptor via GET_DESCRIPTOR (class-specific).
fn hub_get_descriptor(hub: &HubDevice, buf: &mut [u8], len: u16) -> i32 {
    // wValue: descriptor type in high byte, index 0 in low byte.
    // Try USB 2.0 descriptor type first (0x29).
    let wvalue: u16 = (HUB_DESC_TYPE_USB2 as u16) << 8;
    let ret = hub_control(hub, RT_HUB_GET, HUB_REQ_GET_DESCRIPTOR, wvalue, 0, buf.as_mut_ptr(), len);
    if ret >= 0 {
        return ret;
    }
    // Retry with USB 3.0 descriptor type (0x2A).
    let wvalue3: u16 = (HUB_DESC_TYPE_USB3 as u16) << 8;
    hub_control(hub, RT_HUB_GET, HUB_REQ_GET_DESCRIPTOR, wvalue3, 0, buf.as_mut_ptr(), len)
}

// ── Hub descriptor parsing ──

/// Parse a raw hub descriptor buffer into a HubDescriptor struct.
/// Returns `None` if the descriptor is too short or has an unrecognised type.
fn parse_hub_descriptor(buf: &[u8], len: usize) -> Option<HubDescriptor> {
    // Minimum hub descriptor length: 7 bytes (fixed portion).
    if len < 7 {
        return None;
    }
    let desc_len = buf[0] as usize;
    if desc_len < 7 || desc_len > len {
        return None;
    }
    let desc_type = buf[1];
    if desc_type != HUB_DESC_TYPE_USB2 && desc_type != HUB_DESC_TYPE_USB3 {
        return None;
    }

    let num_ports = buf[2];
    let characteristics = get_le16(buf, 3);
    let pwr_on_2_pwr_good = buf[5];
    let hub_contr_current = buf[6];

    Some(HubDescriptor {
        num_ports,
        characteristics,
        pwr_on_2_pwr_good,
        hub_contr_current,
        desc_type,
    })
}

// ── Port status reading and caching ──

/// Read and cache the status of a specific port (1-based).
fn read_port_status(hub: &mut HubDevice, port: u8) -> i32 {
    if port == 0 || port as usize > hub.descriptor.num_ports as usize {
        return -1;
    }
    let mut buf = [0u8; 4];
    let ret = hub_get_port_status(
        hub,
        port as u16,
        &mut buf,
    );
    if ret < 0 {
        return ret;
    }
    let idx = (port - 1) as usize;
    hub.ports[idx].status = get_le16(&buf, 0);
    hub.ports[idx].change = get_le16(&buf, 2);
    0
}

/// Detect device speed from cached port status bits.
fn detect_speed(status: u16) -> UsbSpeed {
    if (status & PORT_STATUS_CONNECTION) == 0 {
        return UsbSpeed::Unknown;
    }
    if (status & PORT_STATUS_HIGH_SPEED) != 0 {
        return UsbSpeed::High;
    }
    if (status & PORT_STATUS_LOW_SPEED) != 0 {
        return UsbSpeed::Low;
    }
    // Default: full-speed.
    UsbSpeed::Full
}

// ── Port power-on sequence ──

/// Power on all ports of a hub, waiting the hub's specified power-good delay.
fn power_on_all_ports(hub: &mut HubDevice) -> i32 {
    let num_ports = hub.descriptor.num_ports;
    for port in 1..=num_ports {
        let ret = hub_set_port_feature(hub, port as u16, PORT_POWER);
        if ret < 0 {
            unsafe {
                fut_printf(
                    b"usb_hub: failed to power on port %u: %d\n\0".as_ptr(),
                    port as u32,
                    ret,
                );
            }
            return ret;
        }
    }

    // The hub needs bPwrOn2PwrGood * 2 ms before ports are powered.
    // We use common::thread_sleep for the delay.
    let delay_ms = (hub.descriptor.pwr_on_2_pwr_good as u64) * 2;
    if delay_ms > 0 {
        common::thread_sleep(delay_ms);
    }

    unsafe {
        fut_printf(
            b"usb_hub: powered on %u ports (delay %u ms)\n\0".as_ptr(),
            num_ports as u32,
            delay_ms as u32,
        );
    }

    0
}

// ── Port reset sequence ──

/// Perform a port reset: SET_FEATURE(PORT_RESET), then poll until
/// C_PORT_RESET is set (indicating reset complete).
///
/// Returns 0 on success, negative on error or timeout.
fn do_port_reset(hub: &mut HubDevice, port: u8) -> i32 {
    if port == 0 || port as usize > hub.descriptor.num_ports as usize {
        return -1;
    }

    // Issue SET_FEATURE PORT_RESET.
    let ret = hub_set_port_feature(hub, port as u16, PORT_RESET);
    if ret < 0 {
        unsafe {
            fut_printf(
                b"usb_hub: SET_FEATURE PORT_RESET failed on port %u: %d\n\0".as_ptr(),
                port as u32,
                ret,
            );
        }
        return ret;
    }

    // Poll for C_PORT_RESET (reset complete) in the port change bits.
    for _attempt in 0..PORT_RESET_MAX_RETRIES {
        // Small delay between polls (10 ms).
        common::thread_sleep(10);

        let ret = read_port_status(hub, port);
        if ret < 0 {
            return ret;
        }

        let idx = (port - 1) as usize;
        if (hub.ports[idx].change & PORT_CHANGE_RESET) != 0 {
            // Reset complete -- clear the change bit.
            hub_clear_port_feature(hub, port as u16, C_PORT_RESET);

            // Re-read status after clearing.
            let _ = read_port_status(hub, port);

            let speed = detect_speed(hub.ports[idx].status);
            unsafe {
                fut_printf(
                    b"usb_hub: port %u reset complete, speed=%u, status=0x%04x\n\0".as_ptr(),
                    port as u32,
                    speed as u32,
                    hub.ports[idx].status as u32,
                );
            }
            return 0;
        }
    }

    unsafe {
        fut_printf(
            b"usb_hub: port %u reset timed out\n\0".as_ptr(),
            port as u32,
        );
    }
    -2 // timeout
}

// ── Connection change handling ──

/// Acknowledge and clear all pending change bits on a port.
fn clear_port_changes(hub: &HubDevice, port: u8, change: u16) {
    let p = port as u16;
    if (change & PORT_CHANGE_CONNECTION) != 0 {
        hub_clear_port_feature(hub, p, C_PORT_CONNECTION);
    }
    if (change & PORT_CHANGE_ENABLE) != 0 {
        hub_clear_port_feature(hub, p, C_PORT_ENABLE);
    }
    if (change & PORT_CHANGE_SUSPEND) != 0 {
        hub_clear_port_feature(hub, p, C_PORT_SUSPEND);
    }
    if (change & PORT_CHANGE_OVER_CURRENT) != 0 {
        hub_clear_port_feature(hub, p, C_PORT_OVER_CURRENT);
    }
    if (change & PORT_CHANGE_RESET) != 0 {
        hub_clear_port_feature(hub, p, C_PORT_RESET);
    }
}

// ── FFI exports ──

/// Initialise the USB hub class driver.
/// Must be called once before any attach/detach calls.
/// Returns 0 on success.
#[unsafe(no_mangle)]
pub extern "C" fn usb_hub_init() -> i32 {
    let state = unsafe { &mut *STATE.get() };
    if state.initialised {
        log("usb_hub: already initialised");
        return 0;
    }

    for i in 0..MAX_HUBS {
        state.hubs[i] = HubDevice::empty();
    }

    state.initialised = true;
    log("usb_hub: driver initialised (max 8 hubs)");
    0
}

/// Attach a USB hub device.
///
/// `dev_id`  -- host-controller device identifier
/// `ctrl_fn` -- control transfer callback for this hub
///
/// Reads the hub descriptor, powers on all downstream ports, and caches
/// initial port status.
///
/// Returns 0 on success, negative on error.
#[unsafe(no_mangle)]
pub extern "C" fn usb_hub_attach(dev_id: u32, ctrl_fn: ControlTransferFn) -> i32 {
    let state = unsafe { &mut *STATE.get() };
    if !state.initialised {
        log("usb_hub: not initialised");
        return -1;
    }

    // Check for duplicate.
    if find_hub(state, dev_id).is_some() {
        unsafe {
            fut_printf(
                b"usb_hub: device %u already attached\n\0".as_ptr(),
                dev_id,
            );
        }
        return -2;
    }

    let slot = match find_free_slot(state) {
        Some(s) => s,
        None => {
            log("usb_hub: no free hub slots");
            return -3;
        }
    };

    unsafe {
        fut_printf(
            b"usb_hub: attaching hub device %u to slot %u\n\0".as_ptr(),
            dev_id,
            slot as u32,
        );
    }

    let hub = &mut state.hubs[slot];
    hub.attached = true;
    hub.dev_id = dev_id;
    hub.ctrl_fn = Some(ctrl_fn);

    // Step 1: Read hub descriptor.
    let mut desc_buf = [0u8; MAX_HUB_DESC_LEN];
    let ret = hub_get_descriptor(hub, &mut desc_buf, MAX_HUB_DESC_LEN as u16);
    if ret < 0 {
        unsafe {
            fut_printf(
                b"usb_hub: failed to read hub descriptor: %d\n\0".as_ptr(),
                ret,
            );
        }
        hub.attached = false;
        return -10;
    }

    let desc_len = ret as usize;
    let descriptor = match parse_hub_descriptor(&desc_buf, desc_len) {
        Some(d) => d,
        None => {
            log("usb_hub: invalid hub descriptor");
            hub.attached = false;
            return -11;
        }
    };

    // Clamp port count to our maximum.
    let mut desc = descriptor;
    if desc.num_ports as usize > MAX_PORTS_PER_HUB {
        unsafe {
            fut_printf(
                b"usb_hub: clamping port count from %u to %u\n\0".as_ptr(),
                desc.num_ports as u32,
                MAX_PORTS_PER_HUB as u32,
            );
        }
        desc.num_ports = MAX_PORTS_PER_HUB as u8;
    }

    hub.descriptor = desc;

    unsafe {
        fut_printf(
            b"usb_hub: hub has %u ports, characteristics=0x%04x, pwr_delay=%u ms\n\0".as_ptr(),
            desc.num_ports as u32,
            desc.characteristics as u32,
            (desc.pwr_on_2_pwr_good as u32) * 2,
        );
    }

    // Step 2: Power on all ports.
    let ret = power_on_all_ports(hub);
    if ret < 0 {
        hub.attached = false;
        return -12;
    }

    // Step 3: Read initial port status for all ports.
    for port in 1..=hub.descriptor.num_ports {
        let _ = read_port_status(hub, port);
    }

    unsafe {
        fut_printf(
            b"usb_hub: hub device %u attached successfully\n\0".as_ptr(),
            dev_id,
        );
    }

    0
}

/// Detach a USB hub device.
///
/// `dev_id` -- host-controller device identifier.
///
/// Returns 0 on success, negative if the device was not found.
#[unsafe(no_mangle)]
pub extern "C" fn usb_hub_detach(dev_id: u32) -> i32 {
    let state = unsafe { &mut *STATE.get() };
    let slot = match find_hub(state, dev_id) {
        Some(s) => s,
        None => {
            unsafe {
                fut_printf(
                    b"usb_hub: detach: device %u not found\n\0".as_ptr(),
                    dev_id,
                );
            }
            return -1;
        }
    };

    state.hubs[slot] = HubDevice::empty();

    unsafe {
        fut_printf(
            b"usb_hub: detached device %u from slot %u\n\0".as_ptr(),
            dev_id,
            slot as u32,
        );
    }

    0
}

/// Query the number of downstream ports on an attached hub.
///
/// Returns the port count, or 0 if the device is not found.
#[unsafe(no_mangle)]
pub extern "C" fn usb_hub_port_count(dev_id: u32) -> u32 {
    let state = unsafe { &*STATE.get() };
    let slot = match find_hub(state, dev_id) {
        Some(s) => s,
        None => return 0,
    };
    state.hubs[slot].descriptor.num_ports as u32
}

/// Read the current status of a specific port (1-based).
///
/// Returns the 16-bit wPortStatus as a u32, or 0 on error.
/// The caller can inspect individual bits (CONNECTION, ENABLE, etc.).
#[unsafe(no_mangle)]
pub extern "C" fn usb_hub_port_status(dev_id: u32, port: u32) -> u32 {
    let state = unsafe { &mut *STATE.get() };
    let slot = match find_hub(state, dev_id) {
        Some(s) => s,
        None => return 0,
    };
    let hub = &mut state.hubs[slot];
    if port == 0 || port > hub.descriptor.num_ports as u32 {
        return 0;
    }

    // Refresh cached status.
    let ret = read_port_status(hub, port as u8);
    if ret < 0 {
        return 0;
    }

    hub.ports[(port - 1) as usize].status as u32
}

/// Perform a port reset sequence on a specific port (1-based).
///
/// Issues SET_FEATURE(PORT_RESET) and polls until C_PORT_RESET is set.
/// Returns 0 on success, negative on error or timeout.
#[unsafe(no_mangle)]
pub extern "C" fn usb_hub_port_reset(dev_id: u32, port: u32) -> i32 {
    let state = unsafe { &mut *STATE.get() };
    let slot = match find_hub(state, dev_id) {
        Some(s) => s,
        None => return -1,
    };
    let hub = &mut state.hubs[slot];
    if port == 0 || port > hub.descriptor.num_ports as u32 {
        return -1;
    }

    do_port_reset(hub, port as u8)
}

/// Enable a specific port (1-based).
///
/// Note: USB hubs do not have a SET_FEATURE(PORT_ENABLE); ports are enabled
/// automatically after a successful reset.  This function performs a port
/// reset to achieve the enable effect, then verifies the ENABLE bit is set.
///
/// Returns 0 on success, negative on error.
#[unsafe(no_mangle)]
pub extern "C" fn usb_hub_port_enable(dev_id: u32, port: u32) -> i32 {
    let state = unsafe { &mut *STATE.get() };
    let slot = match find_hub(state, dev_id) {
        Some(s) => s,
        None => return -1,
    };
    let hub = &mut state.hubs[slot];
    if port == 0 || port > hub.descriptor.num_ports as u32 {
        return -1;
    }

    // A port is enabled as a side-effect of reset.
    let ret = do_port_reset(hub, port as u8);
    if ret < 0 {
        return ret;
    }

    // Verify the ENABLE bit is set.
    let idx = (port - 1) as usize;
    if (hub.ports[idx].status & PORT_STATUS_ENABLE) == 0 {
        unsafe {
            fut_printf(
                b"usb_hub: port %u not enabled after reset\n\0".as_ptr(),
                port,
            );
        }
        return -3;
    }

    0
}

/// Disable a specific port (1-based) using CLEAR_FEATURE(PORT_ENABLE).
///
/// Returns 0 on success, negative on error.
#[unsafe(no_mangle)]
pub extern "C" fn usb_hub_port_disable(dev_id: u32, port: u32) -> i32 {
    let state = unsafe { &mut *STATE.get() };
    let slot = match find_hub(state, dev_id) {
        Some(s) => s,
        None => return -1,
    };
    let hub = &mut state.hubs[slot];
    if port == 0 || port > hub.descriptor.num_ports as u32 {
        return -1;
    }

    let ret = hub_clear_port_feature(hub, port as u16, PORT_ENABLE);
    if ret < 0 {
        unsafe {
            fut_printf(
                b"usb_hub: failed to disable port %u: %d\n\0".as_ptr(),
                port,
                ret,
            );
        }
        return ret;
    }

    // Refresh cached status.
    let _ = read_port_status(hub, port as u8);

    0
}

/// Poll all ports for status changes and return a bitmask indicating
/// which ports (1-based) have pending changes.
///
/// Bit N in the returned value corresponds to port N (bit 0 is unused,
/// bit 1 = port 1, bit 2 = port 2, etc.).
///
/// Change bits are cleared after being reported.  Returns 0 if no changes
/// are pending or on error.
#[unsafe(no_mangle)]
pub extern "C" fn usb_hub_poll_changes(dev_id: u32) -> u32 {
    let state = unsafe { &mut *STATE.get() };
    let slot = match find_hub(state, dev_id) {
        Some(s) => s,
        None => return 0,
    };
    let hub = &mut state.hubs[slot];
    let num_ports = hub.descriptor.num_ports;

    let mut change_mask: u32 = 0;

    for port in 1..=num_ports {
        let ret = read_port_status(hub, port);
        if ret < 0 {
            continue;
        }

        let idx = (port - 1) as usize;
        let change = hub.ports[idx].change;

        if change != 0 {
            change_mask |= 1u32 << (port as u32);

            // Log connection changes specifically.
            if (change & PORT_CHANGE_CONNECTION) != 0 {
                let connected = (hub.ports[idx].status & PORT_STATUS_CONNECTION) != 0;
                if connected {
                    let speed = detect_speed(hub.ports[idx].status);
                    unsafe {
                        fut_printf(
                            b"usb_hub: port %u connect, speed=%u\n\0".as_ptr(),
                            port as u32,
                            speed as u32,
                        );
                    }
                } else {
                    unsafe {
                        fut_printf(
                            b"usb_hub: port %u disconnect\n\0".as_ptr(),
                            port as u32,
                        );
                    }
                }
            }

            if (change & PORT_CHANGE_OVER_CURRENT) != 0 {
                unsafe {
                    fut_printf(
                        b"usb_hub: port %u over-current change\n\0".as_ptr(),
                        port as u32,
                    );
                }
            }

            // Clear all change bits for this port.
            clear_port_changes(hub, port, change);
        }
    }

    change_mask
}
