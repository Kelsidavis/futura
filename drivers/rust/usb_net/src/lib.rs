// SPDX-License-Identifier: MPL-2.0
//
// USB CDC/ECM (Communication Device Class / Ethernet Control Model) Network Driver
//
// Implements the USB CDC ECM specification for USB Ethernet adapters, USB
// tethering, and virtual network interfaces.  Sits above the USB transport
// layer, accepting bulk and control transfer callbacks from the host
// controller driver.
//
// CDC ECM identification:
//   - Communication interface: class 02h, subclass 06h (Ethernet Networking)
//   - Data interface: class 0Ah (CDC Data)
//   - CS_INTERFACE descriptors (type 0x24) carry union functional and
//     ethernet networking functional descriptors
//
// Architecture:
//   - Callback-based USB bulk/control transfer model
//   - Up to 4 simultaneously attached CDC ECM devices
//   - MAC address retrieval from ethernet functional descriptor
//   - Packet filter configuration (directed + broadcast)
//   - Bulk OUT for transmit, bulk IN for receive
//   - Interrupt endpoint for link status notifications
//   - Received frames delivered to the network stack via fut_net_rx_packet

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(unexpected_cfgs)]

use core::cell::UnsafeCell;
use core::ffi::c_void;

use common::log;

unsafe extern "C" {
    fn fut_printf(fmt: *const u8, ...);
    fn fut_net_rx_packet(iface: *mut c_void, data: *const u8, len: u32);
}

// ── Static state wrapper ──

/// Wrapper to allow `UnsafeCell` in a `static` (requires `Sync`).
/// Safety: all access is single-threaded or externally synchronised by the caller.
struct StaticCell<T>(UnsafeCell<T>);
unsafe impl<T> Sync for StaticCell<T> {}
impl<T> StaticCell<T> {
    const fn new(v: T) -> Self { Self(UnsafeCell::new(v)) }
    fn get(&self) -> *mut T { self.0.get() }
}

// ── USB transfer callback types ──

/// Function pointer type for performing USB bulk transfers.
///
/// `dev`  -- host-controller device handle
/// `ep`   -- endpoint address (bit 7 = direction: 0=OUT, 1=IN)
/// `data` -- buffer pointer
/// `len`  -- transfer length in bytes
///
/// Returns number of bytes actually transferred, or negative on error.
pub type BulkTransferFn =
    unsafe extern "C" fn(dev: u32, ep: u8, data: *mut u8, len: u32) -> i32;

/// Function pointer type for performing USB control transfers.
///
/// `dev`  -- host-controller device handle
/// `rt`   -- bmRequestType
/// `req`  -- bRequest
/// `val`  -- wValue
/// `idx`  -- wIndex
/// `data` -- data stage buffer (may be null for no-data transfers)
/// `len`  -- wLength
///
/// Returns number of bytes actually transferred, or negative on error.
pub type ControlTransferFn =
    unsafe extern "C" fn(dev: u32, rt: u8, req: u8, val: u16, idx: u16,
                         data: *mut u8, len: u16) -> i32;

// ── Constants ──

const MAX_DEVICES: usize = 4;

/// Maximum Ethernet frame size (standard MTU 1500 + 14-byte header + 4-byte FCS).
const MAX_ETH_FRAME: usize = 1518;

/// Receive buffer size -- slightly oversized to accommodate any padding.
const RX_BUF_SIZE: usize = 2048;

// ── CDC class / subclass / descriptor constants ──

/// CDC Communication interface class.
const CDC_COMM_CLASS: u8 = 0x02;

/// CDC ECM subclass (Ethernet Networking Control Model).
const CDC_ECM_SUBCLASS: u8 = 0x06;

/// CDC Data interface class.
const CDC_DATA_CLASS: u8 = 0x0A;

/// Class-specific interface descriptor type.
const CS_INTERFACE: u8 = 0x24;

/// CDC functional descriptor subtypes.
const CDC_UNION_FUNC_DESC: u8 = 0x06;
const CDC_ETHERNET_FUNC_DESC: u8 = 0x0F;

// ── CDC ECM class-specific control requests ──

/// SET_ETHERNET_MULTICAST_FILTERS
const CDC_SET_ETH_MULTICAST_FILTERS: u8 = 0x40;
/// SET_ETHERNET_PM_PATTERN_FILTER
const CDC_SET_ETH_PM_PATTERN_FILTER: u8 = 0x41;
/// GET_ETHERNET_PM_PATTERN_FILTER
const CDC_GET_ETH_PM_PATTERN_FILTER: u8 = 0x42;
/// SET_ETHERNET_PACKET_FILTER
const CDC_SET_ETH_PACKET_FILTER: u8 = 0x43;
/// GET_ETHERNET_STATISTIC
const CDC_GET_ETH_STATISTIC: u8 = 0x44;

// ── Packet filter bits (wValue for SET_ETHERNET_PACKET_FILTER) ──

const PACKET_TYPE_PROMISCUOUS: u16 = 1 << 0;
const PACKET_TYPE_ALL_MULTICAST: u16 = 1 << 1;
const PACKET_TYPE_DIRECTED: u16 = 1 << 2;
const PACKET_TYPE_BROADCAST: u16 = 1 << 3;
const PACKET_TYPE_MULTICAST: u16 = 1 << 4;

// ── USB control request type fields ──

/// Host-to-device, class request, interface recipient.
const USB_RT_CLASS_IFACE_OUT: u8 = 0x21;
/// Device-to-host, class request, interface recipient.
const USB_RT_CLASS_IFACE_IN: u8 = 0xA1;

// ── CDC notification codes (from interrupt endpoint) ──

const CDC_NOTIFY_NETWORK_CONNECTION: u8 = 0x00;
const CDC_NOTIFY_RESPONSE_AVAILABLE: u8 = 0x01;
const CDC_NOTIFY_SPEED_CHANGE: u8 = 0x2A;

// ── Link state ──

#[derive(Copy, Clone, PartialEq)]
enum LinkState {
    Down,
    Up,
}

// ── Per-device state ──

struct UsbNetDevice {
    /// Whether this slot is in use.
    attached: bool,
    /// Host-controller device handle.
    dev_id: u32,
    /// Bulk-IN endpoint address (e.g. 0x81).
    bulk_in_ep: u8,
    /// Bulk-OUT endpoint address (e.g. 0x02).
    bulk_out_ep: u8,
    /// Interrupt endpoint address (e.g. 0x83).
    int_ep: u8,
    /// Communication interface index (for control requests).
    comm_iface: u16,
    /// Bulk transfer function pointer.
    bulk_fn: Option<BulkTransferFn>,
    /// Control transfer function pointer.
    ctrl_fn: Option<ControlTransferFn>,
    /// MAC address (6 bytes).
    mac: [u8; 6],
    /// Whether we have retrieved a valid MAC address.
    mac_valid: bool,
    /// Current link state.
    link: LinkState,
    /// Maximum segment size from ethernet functional descriptor.
    max_segment_size: u16,
    /// Receive buffer.
    rx_buf: [u8; RX_BUF_SIZE],
    /// Interface pointer for fut_net_rx_packet callback.
    iface: *mut c_void,
    /// Device name (e.g. "ecm0\0").
    name: [u8; 8],
}

impl UsbNetDevice {
    const fn empty() -> Self {
        Self {
            attached: false,
            dev_id: 0,
            bulk_in_ep: 0,
            bulk_out_ep: 0,
            int_ep: 0,
            comm_iface: 0,
            bulk_fn: None,
            ctrl_fn: None,
            mac: [0; 6],
            mac_valid: false,
            link: LinkState::Down,
            max_segment_size: MAX_ETH_FRAME as u16,
            rx_buf: [0; RX_BUF_SIZE],
            iface: core::ptr::null_mut(),
            name: [0; 8],
        }
    }
}

// ── Global state ──

struct UsbNetState {
    devices: [UsbNetDevice; MAX_DEVICES],
    initialised: bool,
}

impl UsbNetState {
    const fn new() -> Self {
        Self {
            devices: [
                UsbNetDevice::empty(),
                UsbNetDevice::empty(),
                UsbNetDevice::empty(),
                UsbNetDevice::empty(),
            ],
            initialised: false,
        }
    }
}

static STATE: StaticCell<UsbNetState> = StaticCell::new(UsbNetState::new());

// ── Byte-level helpers ──

/// Read a little-endian u16 from `buf` at byte offset `off`.
fn get_le16(buf: &[u8], off: usize) -> u16 {
    (buf[off] as u16) | ((buf[off + 1] as u16) << 8)
}

/// Read a little-endian u32 from `buf` at byte offset `off`.
fn get_le32(buf: &[u8], off: usize) -> u32 {
    (buf[off] as u32)
        | ((buf[off + 1] as u32) << 8)
        | ((buf[off + 2] as u32) << 16)
        | ((buf[off + 3] as u32) << 24)
}

/// Convert a single hex ASCII character to its 4-bit value.
/// Returns 0xFF on invalid input.
fn hex_nibble(ch: u8) -> u8 {
    match ch {
        b'0'..=b'9' => ch - b'0',
        b'a'..=b'f' => ch - b'a' + 10,
        b'A'..=b'F' => ch - b'A' + 10,
        _ => 0xFF,
    }
}

/// Parse a MAC address from a 12-character hex ASCII string into 6 bytes.
/// Returns true on success.
fn parse_mac_hex(hex: &[u8], mac: &mut [u8; 6]) -> bool {
    if hex.len() < 12 {
        return false;
    }
    for i in 0..6 {
        let hi = hex_nibble(hex[i * 2]);
        let lo = hex_nibble(hex[i * 2 + 1]);
        if hi == 0xFF || lo == 0xFF {
            return false;
        }
        mac[i] = (hi << 4) | lo;
    }
    true
}

// ── Device slot lookup ──

/// Find the internal slot index for a given `dev_id`.
fn find_slot(state: &UsbNetState, dev_id: u32) -> Option<usize> {
    for i in 0..MAX_DEVICES {
        if state.devices[i].attached && state.devices[i].dev_id == dev_id {
            return Some(i);
        }
    }
    None
}

/// Find a free slot, returning its index.
fn find_free_slot(state: &UsbNetState) -> Option<usize> {
    for i in 0..MAX_DEVICES {
        if !state.devices[i].attached {
            return Some(i);
        }
    }
    None
}

// ── Device name helper ──

/// Generate a device name "ecmN\0" for slot index `idx`.
fn make_dev_name(idx: usize) -> [u8; 8] {
    let mut name = [0u8; 8];
    name[0] = b'e';
    name[1] = b'c';
    name[2] = b'm';
    name[3] = b'0' + (idx as u8);
    name[4] = 0;
    name
}

// ── USB control transfer helpers ──

/// Send a CDC class-specific SET request (host-to-device).
fn cdc_set_request(
    dev: &UsbNetDevice,
    request: u8,
    value: u16,
    index: u16,
    data: *mut u8,
    len: u16,
) -> i32 {
    let ctrl_fn = match dev.ctrl_fn {
        Some(f) => f,
        None => return -1,
    };
    unsafe {
        (ctrl_fn)(dev.dev_id, USB_RT_CLASS_IFACE_OUT, request, value, index, data, len)
    }
}

/// Send a CDC class-specific GET request (device-to-host).
fn cdc_get_request(
    dev: &UsbNetDevice,
    request: u8,
    value: u16,
    index: u16,
    data: *mut u8,
    len: u16,
) -> i32 {
    let ctrl_fn = match dev.ctrl_fn {
        Some(f) => f,
        None => return -1,
    };
    unsafe {
        (ctrl_fn)(dev.dev_id, USB_RT_CLASS_IFACE_IN, request, value, index, data, len)
    }
}

/// Retrieve a USB string descriptor and decode the UTF-16LE content
/// into ASCII bytes.  Returns the number of ASCII characters written
/// to `out`, or negative on error.
///
/// USB string descriptors:
///   byte 0: bLength
///   byte 1: bDescriptorType (0x03)
///   bytes 2..: UTF-16LE characters
fn get_string_descriptor(
    dev: &UsbNetDevice,
    str_index: u8,
    out: &mut [u8],
) -> i32 {
    let ctrl_fn = match dev.ctrl_fn {
        Some(f) => f,
        None => return -1,
    };

    // GET_DESCRIPTOR: bmRequestType=0x80 (device-to-host, standard, device),
    // bRequest=0x06, wValue=descriptor_type<<8|index, wIndex=language
    let mut buf = [0u8; 256];
    let wvalue: u16 = (0x03u16 << 8) | (str_index as u16);
    let ret = unsafe {
        (ctrl_fn)(dev.dev_id, 0x80, 0x06, wvalue, 0x0409, buf.as_mut_ptr(), 256)
    };
    if ret < 4 {
        return -1;
    }

    let blen = buf[0] as usize;
    if blen < 2 || buf[1] != 0x03 {
        return -2;
    }

    // Decode UTF-16LE characters (bytes 2..blen) into ASCII
    let char_bytes = if blen <= (ret as usize) { blen } else { ret as usize };
    let num_chars = (char_bytes - 2) / 2;
    let limit = num_chars.min(out.len());
    for i in 0..limit {
        let lo = buf[2 + i * 2];
        let hi = buf[2 + i * 2 + 1];
        // If hi != 0 it is a non-ASCII character; replace with '?'
        out[i] = if hi == 0 { lo } else { b'?' };
    }

    limit as i32
}

// ── MAC address retrieval ──

/// Attempt to retrieve the MAC address from the device.
///
/// Strategy: use the ethernet networking functional descriptor's
/// iMACAddress string index (provided during attach via a prior
/// descriptor parse by the USB stack), falling back to a GET request.
///
/// `mac_str_index` — string descriptor index for the MAC address
///                   (0 means unknown / not available).
fn retrieve_mac(dev: &mut UsbNetDevice, mac_str_index: u8) -> bool {
    if mac_str_index != 0 {
        let mut hex = [0u8; 24];
        let n = get_string_descriptor(dev, mac_str_index, &mut hex);
        if n >= 12 {
            let slice = &hex[..n as usize];
            if parse_mac_hex(slice, &mut dev.mac) {
                dev.mac_valid = true;
                return true;
            }
        }
    }

    // Fallback: some devices expose the MAC through a vendor control request
    // or have it hard-coded.  As a last resort, generate a locally-administered
    // MAC from the device id so the device is still usable.
    dev.mac[0] = 0x02; // locally administered, unicast
    dev.mac[1] = 0x00;
    dev.mac[2] = 0xEC;
    dev.mac[3] = (dev.dev_id >> 16) as u8;
    dev.mac[4] = (dev.dev_id >> 8) as u8;
    dev.mac[5] = dev.dev_id as u8;
    dev.mac_valid = true;
    false
}

// ── Packet filter ──

/// Configure the device to accept directed (unicast) and broadcast frames.
fn set_packet_filter(dev: &UsbNetDevice) -> i32 {
    let filter = PACKET_TYPE_DIRECTED | PACKET_TYPE_BROADCAST;
    cdc_set_request(
        dev,
        CDC_SET_ETH_PACKET_FILTER,
        filter,
        dev.comm_iface,
        core::ptr::null_mut(),
        0,
    )
}

// ── Transmit ──

/// Send an Ethernet frame via the bulk OUT endpoint.
fn send_frame(dev: &UsbNetDevice, data: *const u8, len: u32) -> i32 {
    let bulk_fn = match dev.bulk_fn {
        Some(f) => f,
        None => return -1,
    };
    if data.is_null() || len == 0 || len > MAX_ETH_FRAME as u32 {
        return -1;
    }
    // CDC ECM sends raw Ethernet frames on the bulk OUT endpoint.
    // The bulk transfer function takes *mut u8; cast away const for OUT.
    let ret = unsafe {
        (bulk_fn)(dev.dev_id, dev.bulk_out_ep, data as *mut u8, len)
    };
    if ret < 0 {
        return ret;
    }
    0
}

// ── Receive ──

/// Poll the bulk IN endpoint for a received Ethernet frame.
/// If a frame is available, deliver it to the network stack via
/// fut_net_rx_packet.  Returns the number of frames received (0 or 1),
/// or negative on error.
fn recv_frame(dev: &mut UsbNetDevice) -> i32 {
    let bulk_fn = match dev.bulk_fn {
        Some(f) => f,
        None => return -1,
    };

    let ret = unsafe {
        (bulk_fn)(
            dev.dev_id,
            dev.bulk_in_ep,
            dev.rx_buf.as_mut_ptr(),
            RX_BUF_SIZE as u32,
        )
    };

    if ret < 0 {
        // No data or error -- not fatal for polling
        return 0;
    }
    if ret == 0 {
        return 0;
    }

    let frame_len = ret as u32;
    // Minimum Ethernet frame is 14 bytes (header only, no payload)
    if frame_len < 14 {
        return 0;
    }

    // Deliver to network stack
    if !dev.iface.is_null() {
        unsafe {
            fut_net_rx_packet(dev.iface, dev.rx_buf.as_ptr(), frame_len);
        }
    }

    1
}

// ── Interrupt endpoint: link status notification ──

/// CDC notification header (8 bytes):
///   byte 0: bmRequestType (0xA1)
///   byte 1: bNotification
///   bytes 2-3: wValue (LE)
///   bytes 4-5: wIndex (LE)
///   bytes 6-7: wLength (LE)
const CDC_NOTIFY_HDR_SIZE: usize = 8;

/// Poll the interrupt endpoint for CDC notifications and update
/// link state accordingly.  Returns 0 on success, negative on error.
fn poll_notifications(dev: &mut UsbNetDevice) -> i32 {
    let bulk_fn = match dev.bulk_fn {
        Some(f) => f,
        None => return -1,
    };

    if dev.int_ep == 0 {
        return 0;
    }

    // Interrupt transfers are polled the same way as bulk in this model.
    // The notification fits in a small buffer.
    let mut buf = [0u8; 32];
    let ret = unsafe {
        (bulk_fn)(dev.dev_id, dev.int_ep, buf.as_mut_ptr(), buf.len() as u32)
    };

    if ret < CDC_NOTIFY_HDR_SIZE as i32 {
        // No notification available or short read -- not an error
        return 0;
    }

    let notification = buf[1];
    let wvalue = get_le16(&buf, 2);

    match notification {
        CDC_NOTIFY_NETWORK_CONNECTION => {
            let new_state = if wvalue != 0 { LinkState::Up } else { LinkState::Down };
            if dev.link != new_state {
                dev.link = new_state;
                let state_str = if new_state == LinkState::Up {
                    b"up\0".as_ptr()
                } else {
                    b"down\0".as_ptr()
                };
                unsafe {
                    fut_printf(
                        b"usb_net: %s link %s\n\0".as_ptr(),
                        dev.name.as_ptr(),
                        state_str,
                    );
                }
            }
        }
        CDC_NOTIFY_SPEED_CHANGE => {
            // Connection Speed Change notification.
            // wLength should be 8, carrying downstream and upstream speeds.
            let wlength = get_le16(&buf, 6);
            if wlength >= 8 && ret >= (CDC_NOTIFY_HDR_SIZE + 8) as i32 {
                let downstream = get_le32(&buf, 8);
                let upstream = get_le32(&buf, 12);
                unsafe {
                    fut_printf(
                        b"usb_net: %s speed down=%u up=%u bps\n\0".as_ptr(),
                        dev.name.as_ptr(),
                        downstream,
                        upstream,
                    );
                }
            }
        }
        CDC_NOTIFY_RESPONSE_AVAILABLE => {
            // Response Available -- the host should issue a class GET request.
            // Currently we do not issue encapsulated commands, so ignore.
        }
        _ => {
            // Unknown notification -- ignore
        }
    }

    0
}

// ── FFI exports ──

/// Initialise the USB CDC/ECM network driver.
/// Must be called once before any attach/detach/send/poll calls.
/// Returns 0 on success.
#[unsafe(no_mangle)]
pub extern "C" fn usb_net_init() -> i32 {
    let state = unsafe { &mut *STATE.get() };
    if state.initialised {
        log("usb_net: already initialised");
        return 0;
    }

    for i in 0..MAX_DEVICES {
        state.devices[i] = UsbNetDevice::empty();
    }

    state.initialised = true;
    log("usb_net: CDC/ECM driver initialised (max 4 devices)");
    0
}

/// Attach a new USB CDC/ECM network device.
///
/// `dev_id`   -- host-controller device identifier
/// `bulk_in`  -- bulk-IN endpoint address (e.g. 0x81)
/// `bulk_out` -- bulk-OUT endpoint address (e.g. 0x02)
/// `int_ep`   -- interrupt endpoint address (e.g. 0x83, or 0 if none)
/// `bulk_fn`  -- bulk transfer callback
/// `ctrl_fn`  -- control transfer callback
///
/// The driver retrieves the MAC address, sets the packet filter, and
/// marks the device as ready for send/receive.
///
/// Returns 0 on success, negative on error.
#[unsafe(no_mangle)]
pub extern "C" fn usb_net_attach(
    dev_id: u32,
    bulk_in: u8,
    bulk_out: u8,
    int_ep: u8,
    bulk_fn: BulkTransferFn,
    ctrl_fn: ControlTransferFn,
) -> i32 {
    let state = unsafe { &mut *STATE.get() };
    if !state.initialised {
        log("usb_net: not initialised");
        return -1;
    }

    // Check for duplicate
    if find_slot(state, dev_id).is_some() {
        unsafe {
            fut_printf(
                b"usb_net: device %u already attached\n\0".as_ptr(),
                dev_id,
            );
        }
        return -2;
    }

    let slot = match find_free_slot(state) {
        Some(s) => s,
        None => {
            log("usb_net: no free device slots");
            return -3;
        }
    };

    unsafe {
        fut_printf(
            b"usb_net: attaching device %u (IN=0x%02x OUT=0x%02x INT=0x%02x) slot %u\n\0"
                .as_ptr(),
            dev_id,
            bulk_in as u32,
            bulk_out as u32,
            int_ep as u32,
            slot as u32,
        );
    }

    let dev = &mut state.devices[slot];
    dev.attached = true;
    dev.dev_id = dev_id;
    dev.bulk_in_ep = bulk_in;
    dev.bulk_out_ep = bulk_out;
    dev.int_ep = int_ep;
    dev.comm_iface = 0; // default; caller may set via descriptor parsing
    dev.bulk_fn = Some(bulk_fn);
    dev.ctrl_fn = Some(ctrl_fn);
    dev.link = LinkState::Down;
    dev.iface = core::ptr::null_mut();
    dev.name = make_dev_name(slot);

    // Attempt MAC retrieval (string index 0 = unknown, will use fallback)
    let got_real_mac = retrieve_mac(dev, 0);
    if got_real_mac {
        unsafe {
            fut_printf(
                b"usb_net: %s MAC %02x:%02x:%02x:%02x:%02x:%02x\n\0".as_ptr(),
                dev.name.as_ptr(),
                dev.mac[0] as u32, dev.mac[1] as u32, dev.mac[2] as u32,
                dev.mac[3] as u32, dev.mac[4] as u32, dev.mac[5] as u32,
            );
        }
    } else {
        unsafe {
            fut_printf(
                b"usb_net: %s using generated MAC %02x:%02x:%02x:%02x:%02x:%02x\n\0".as_ptr(),
                dev.name.as_ptr(),
                dev.mac[0] as u32, dev.mac[1] as u32, dev.mac[2] as u32,
                dev.mac[3] as u32, dev.mac[4] as u32, dev.mac[5] as u32,
            );
        }
    }

    // Set packet filter to accept directed + broadcast
    let ret = set_packet_filter(dev);
    if ret < 0 {
        unsafe {
            fut_printf(
                b"usb_net: %s SET_PACKET_FILTER failed: %d\n\0".as_ptr(),
                dev.name.as_ptr(),
                ret,
            );
        }
        // Non-fatal -- some devices accept frames without explicit filter
    }

    // Assume link is up until we hear otherwise from a notification
    dev.link = LinkState::Up;

    unsafe {
        fut_printf(
            b"usb_net: %s attached and ready\n\0".as_ptr(),
            dev.name.as_ptr(),
        );
    }

    0
}

/// Detach a USB CDC/ECM network device.
///
/// `dev_id` -- host-controller device identifier as passed to `usb_net_attach`.
///
/// Returns 0 on success, negative if the device was not found.
#[unsafe(no_mangle)]
pub extern "C" fn usb_net_detach(dev_id: u32) -> i32 {
    let state = unsafe { &mut *STATE.get() };
    let slot = match find_slot(state, dev_id) {
        Some(s) => s,
        None => {
            unsafe {
                fut_printf(
                    b"usb_net: detach: device %u not found\n\0".as_ptr(),
                    dev_id,
                );
            }
            return -1;
        }
    };

    let dev = &mut state.devices[slot];
    let name_ptr = dev.name.as_ptr();
    dev.attached = false;
    dev.bulk_fn = None;
    dev.ctrl_fn = None;
    dev.mac_valid = false;
    dev.link = LinkState::Down;
    dev.iface = core::ptr::null_mut();

    unsafe {
        fut_printf(
            b"usb_net: detached device %u from slot %u\n\0".as_ptr(),
            dev_id,
            slot as u32,
        );
    }

    0
}

/// Send an Ethernet frame through a USB CDC/ECM device.
///
/// `dev_id` -- device identifier
/// `data`   -- pointer to the Ethernet frame
/// `len`    -- frame length in bytes
///
/// Returns 0 on success, negative on error.
#[unsafe(no_mangle)]
pub extern "C" fn usb_net_send(dev_id: u32, data: *const u8, len: u32) -> i32 {
    let state = unsafe { &mut *STATE.get() };
    let slot = match find_slot(state, dev_id) {
        Some(s) => s,
        None => return -1,
    };

    let dev = &state.devices[slot];
    if dev.link == LinkState::Down {
        return -2; // link is down
    }

    send_frame(dev, data, len)
}

/// Poll a USB CDC/ECM device for received frames and link status
/// notifications.
///
/// `dev_id` -- device identifier
///
/// Received frames are delivered to the network stack via
/// `fut_net_rx_packet`.  Link status changes are logged and tracked
/// internally.
///
/// Returns the number of frames received (>= 0), or negative on error.
#[unsafe(no_mangle)]
pub extern "C" fn usb_net_poll(dev_id: u32) -> i32 {
    let state = unsafe { &mut *STATE.get() };
    let slot = match find_slot(state, dev_id) {
        Some(s) => s,
        None => return -1,
    };

    let dev = &mut state.devices[slot];

    // Check for CDC notifications (link up/down, speed change)
    poll_notifications(dev);

    // Receive frames
    let mut count = 0i32;
    // Poll up to 16 frames per call to avoid unbounded processing
    for _ in 0..16 {
        let ret = recv_frame(dev);
        if ret <= 0 {
            break;
        }
        count += ret;
    }

    count
}

/// Retrieve the MAC address of an attached USB CDC/ECM device.
///
/// `dev_id` -- device identifier
/// `out`    -- pointer to a 6-byte buffer to receive the MAC address
///
/// Returns 0 on success, negative on error.
#[unsafe(no_mangle)]
pub extern "C" fn usb_net_get_mac(dev_id: u32, out: *mut u8) -> i32 {
    if out.is_null() {
        return -1;
    }

    let state = unsafe { &*STATE.get() };
    let slot = match find_slot(state, dev_id) {
        Some(s) => s,
        None => return -1,
    };

    let dev = &state.devices[slot];
    if !dev.mac_valid {
        return -2;
    }

    unsafe {
        core::ptr::copy_nonoverlapping(dev.mac.as_ptr(), out, 6);
    }

    0
}
