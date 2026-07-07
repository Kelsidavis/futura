// SPDX-License-Identifier: MPL-2.0
//
// USB Video Class (UVC) Driver for Futura OS
//
// Implements the USB Video Class 1.1/1.5 specification for webcam and
// video capture devices. Discovers UVC interfaces during xHCI USB
// enumeration (class 0x0E, subclass 0x01 = Video Control), negotiates
// format/resolution, and provides a frame capture API.
//
// UVC Architecture:
//   - Video Control (VC) interface: class 0x0E, subclass 0x01
//     Houses the Unit/Terminal topology (camera terminal, processing
//     unit, selector unit, extension units). Configuration and control
//     requests go here via USB control transfers.
//   - Video Streaming (VS) interface: class 0x0E, subclass 0x02
//     Carries payload frames. Uses isochronous or bulk endpoints.
//     For simplicity, this driver uses bulk endpoints.
//
// Supported formats (initial):
//   - MJPEG (GUID: 4d4a5047-0000-0010-8000-00aa00389b71)
//   - Uncompressed YUY2 (GUID: 32595559-0000-0010-8000-00aa00389b71)
//
// References:
//   - USB Video Class 1.5 specification (usb.org)
//   - UVC 1.1 Class-Specific Requests

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(unexpected_cfgs)]
#![allow(dead_code)]

use core::cell::UnsafeCell;
use common::log;

unsafe extern "C" {
    fn fut_printf(fmt: *const u8, ...);

    fn xhci_control_transfer_ext(
        slot_id: u32,
        bm_request_type: u8,
        b_request: u8,
        w_value: u16,
        w_index: u16,
        data: *mut u8,
        data_len: u16,
    ) -> i32;
    fn xhci_bulk_transfer(
        slot_id: u32,
        ep_addr: u8,
        data: *mut u8,
        len: u32,
    ) -> i32;
}

// ── USB Video Class constants ──

const UVC_CLASS: u8 = 0x0E;
const UVC_SC_VIDEO_CONTROL: u8 = 0x01;
const UVC_SC_VIDEO_STREAMING: u8 = 0x02;

// Control request types
const UVC_SET_CUR: u8 = 0x01;
const UVC_GET_CUR: u8 = 0x81;
const UVC_GET_MIN: u8 = 0x82;
const UVC_GET_MAX: u8 = 0x83;
const UVC_GET_DEF: u8 = 0x87;

// bmRequestType for class-specific interface requests
const UVC_REQ_TYPE_SET: u8 = 0x21; // host-to-device, class, interface
const UVC_REQ_TYPE_GET: u8 = 0xA1; // device-to-host, class, interface

// Video Streaming interface control selectors
const VS_PROBE_CONTROL: u16 = 0x0100;
const VS_COMMIT_CONTROL: u16 = 0x0200;

// Format type GUIDs
const FORMAT_MJPEG: u8 = 0x01;
const FORMAT_UNCOMPRESSED: u8 = 0x02;

// Probe/Commit control structure size
const UVC_PROBE_SIZE: usize = 26;

const MAX_DEVICES: usize = 4;
const MAX_FRAME_SIZE: usize = 640 * 480 * 2; // YUY2 VGA worst case

// ── Probe/Commit control data ──

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct UvcProbeCommit {
    bm_hint: u16,
    format_index: u8,
    frame_index: u8,
    frame_interval: u32,    // 100ns units
    key_frame_rate: u16,
    p_frame_rate: u16,
    comp_quality: u16,
    comp_window_size: u16,
    delay: u16,
    max_video_frame_size: u32,
    max_payload_transfer_size: u32,
}

impl UvcProbeCommit {
    const fn empty() -> Self {
        Self {
            bm_hint: 0,
            format_index: 0,
            frame_index: 0,
            frame_interval: 0,
            key_frame_rate: 0,
            p_frame_rate: 0,
            comp_quality: 0,
            comp_window_size: 0,
            delay: 0,
            max_video_frame_size: 0,
            max_payload_transfer_size: 0,
        }
    }
}

// ── Per-device state ──

struct UvcDevice {
    active: bool,
    slot_id: u32,
    vc_iface: u8,        // Video Control interface number
    vs_iface: u8,        // Video Streaming interface number
    bulk_in_ep: u8,      // Bulk IN endpoint for frame data
    bulk_out_ep: u8,     // Bulk OUT (if any, rare for webcams)
    width: u16,
    height: u16,
    format: u8,          // FORMAT_MJPEG or FORMAT_UNCOMPRESSED
    streaming: bool,
    probe: UvcProbeCommit,
}

impl UvcDevice {
    const fn new() -> Self {
        Self {
            active: false,
            slot_id: 0,
            vc_iface: 0,
            vs_iface: 0,
            bulk_in_ep: 0,
            bulk_out_ep: 0,
            width: 0,
            height: 0,
            format: 0,
            streaming: false,
            probe: UvcProbeCommit::empty(),
        }
    }
}

struct StaticCell<T>(UnsafeCell<T>);
unsafe impl<T> Sync for StaticCell<T> {}
impl<T> StaticCell<T> {
    const fn new(v: T) -> Self { Self(UnsafeCell::new(v)) }
    fn get(&self) -> *mut T { self.0.get() }
}

static DEVICES: StaticCell<[UvcDevice; MAX_DEVICES]> = StaticCell::new(
    [const { UvcDevice::new() }; MAX_DEVICES]
);

fn devices() -> &'static mut [UvcDevice; MAX_DEVICES] {
    unsafe { &mut *DEVICES.get() }
}

// ── UVC control requests ──

fn uvc_get_cur(slot_id: u32, iface: u8, selector: u16, buf: &mut [u8]) -> i32 {
    unsafe {
        xhci_control_transfer_ext(
            slot_id,
            UVC_REQ_TYPE_GET,
            UVC_GET_CUR,
            selector,
            iface as u16,
            buf.as_mut_ptr(),
            buf.len() as u16,
        )
    }
}

fn uvc_set_cur(slot_id: u32, iface: u8, selector: u16, buf: &[u8]) -> i32 {
    unsafe {
        xhci_control_transfer_ext(
            slot_id,
            UVC_REQ_TYPE_SET,
            UVC_SET_CUR,
            selector,
            iface as u16,
            buf.as_ptr() as *mut u8,
            buf.len() as u16,
        )
    }
}

fn uvc_get_max(slot_id: u32, iface: u8, selector: u16, buf: &mut [u8]) -> i32 {
    unsafe {
        xhci_control_transfer_ext(
            slot_id,
            UVC_REQ_TYPE_GET,
            UVC_GET_MAX,
            selector,
            iface as u16,
            buf.as_mut_ptr(),
            buf.len() as u16,
        )
    }
}

// ── Probe/Commit negotiation ──

fn negotiate_format(dev: &mut UvcDevice) -> i32 {
    // Step 1: Probe with desired settings (MJPEG, 640x480, 30fps)
    let mut probe = [0u8; UVC_PROBE_SIZE];
    probe[2] = 1; // format_index = 1 (first format, usually MJPEG)
    probe[3] = 1; // frame_index = 1 (first frame size)
    // frame_interval = 333333 (30fps in 100ns units)
    let interval: u32 = 333333;
    probe[4] = (interval & 0xFF) as u8;
    probe[5] = ((interval >> 8) & 0xFF) as u8;
    probe[6] = ((interval >> 16) & 0xFF) as u8;
    probe[7] = ((interval >> 24) & 0xFF) as u8;

    // SET_CUR(PROBE)
    let rc = uvc_set_cur(dev.slot_id, dev.vs_iface, VS_PROBE_CONTROL, &probe);
    if rc < 0 {
        return rc;
    }

    // GET_CUR(PROBE) — device returns negotiated values
    let mut result = [0u8; UVC_PROBE_SIZE];
    let rc = uvc_get_cur(dev.slot_id, dev.vs_iface, VS_PROBE_CONTROL, &mut result);
    if rc < 0 {
        return rc;
    }

    dev.probe.format_index = result[2];
    dev.probe.frame_index = result[3];
    dev.probe.frame_interval = u32::from_le_bytes([result[4], result[5], result[6], result[7]]);
    dev.probe.max_video_frame_size = u32::from_le_bytes([result[18], result[19], result[20], result[21]]);
    dev.probe.max_payload_transfer_size = u32::from_le_bytes([result[22], result[23], result[24], result[25]]);

    // SET_CUR(COMMIT) — accept the negotiated parameters
    let rc = uvc_set_cur(dev.slot_id, dev.vs_iface, VS_COMMIT_CONTROL, &result);
    if rc < 0 {
        return rc;
    }

    dev.format = dev.probe.format_index;

    unsafe {
        fut_printf(
            b"usb-video: negotiated format %u frame %u, interval %u, max_frame %u\n\0".as_ptr(),
            dev.probe.format_index as u32,
            dev.probe.frame_index as u32,
            dev.probe.frame_interval,
            dev.probe.max_video_frame_size,
        );
    }

    0
}

// ── Attach entry point (called from xHCI enumeration) ──

#[unsafe(no_mangle)]
pub extern "C" fn usb_video_attach(
    slot_id: u32,
    vc_iface: u8,
    vs_iface: u8,
    bulk_in_ep: u8,
) {
    let devs = devices();
    let idx = match devs.iter().position(|d| !d.active) {
        Some(i) => i,
        None => {
            log("usb-video: no free device slots");
            return;
        }
    };

    let dev = &mut devs[idx];
    dev.active = true;
    dev.slot_id = slot_id;
    dev.vc_iface = vc_iface;
    dev.vs_iface = vs_iface;
    dev.bulk_in_ep = bulk_in_ep;
    dev.streaming = false;

    unsafe {
        fut_printf(
            b"usb-video: attached slot %u (VC iface %u, VS iface %u, bulk_in 0x%02x)\n\0".as_ptr(),
            slot_id, vc_iface as u32, vs_iface as u32, bulk_in_ep as u32,
        );
    }

    // Attempt format negotiation
    let rc = negotiate_format(dev);
    if rc < 0 {
        unsafe {
            fut_printf(
                b"usb-video: format negotiation failed (rc=%d), device still registered\n\0".as_ptr(),
                rc,
            );
        }
    }
}

// ── Frame capture ──

#[unsafe(no_mangle)]
pub extern "C" fn usb_video_capture_frame(
    dev_index: u32,
    buf: *mut u8,
    buf_len: u32,
) -> i32 {
    if buf.is_null() || buf_len == 0 {
        return -22; // EINVAL
    }
    let devs = devices();
    if dev_index as usize >= MAX_DEVICES {
        return -22;
    }
    let dev = &devs[dev_index as usize];
    if !dev.active {
        return -19; // ENODEV
    }
    if dev.bulk_in_ep == 0 {
        return -5; // EIO
    }

    // Read a frame payload via bulk IN
    // UVC bulk payloads have a 2-byte header: length + flags
    let rc = unsafe {
        xhci_bulk_transfer(
            dev.slot_id,
            dev.bulk_in_ep,
            buf,
            buf_len,
        )
    };
    rc
}

// ── Start/stop streaming ──

#[unsafe(no_mangle)]
pub extern "C" fn usb_video_start(dev_index: u32) -> i32 {
    let devs = devices();
    if dev_index as usize >= MAX_DEVICES {
        return -22;
    }
    let dev = &mut devs[dev_index as usize];
    if !dev.active {
        return -19;
    }
    if dev.streaming {
        return 0;
    }

    // Select alternate setting 1 on the VS interface to start streaming
    // SET_INTERFACE request: bmRequestType=0x01, bRequest=0x0B (SET_INTERFACE)
    let rc = unsafe {
        xhci_control_transfer_ext(
            dev.slot_id,
            0x01, // host-to-device, standard, interface
            0x0B, // SET_INTERFACE
            1,    // alternate setting 1
            dev.vs_iface as u16,
            core::ptr::null_mut(),
            0,
        )
    };
    if rc < 0 {
        return rc;
    }

    dev.streaming = true;
    log("usb-video: streaming started");
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn usb_video_stop(dev_index: u32) -> i32 {
    let devs = devices();
    if dev_index as usize >= MAX_DEVICES {
        return -22;
    }
    let dev = &mut devs[dev_index as usize];
    if !dev.active || !dev.streaming {
        return 0;
    }

    // Select alternate setting 0 to stop streaming
    let rc = unsafe {
        xhci_control_transfer_ext(
            dev.slot_id,
            0x01,
            0x0B,
            0,    // alternate setting 0 (zero bandwidth)
            dev.vs_iface as u16,
            core::ptr::null_mut(),
            0,
        )
    };

    dev.streaming = false;
    log("usb-video: streaming stopped");
    if rc < 0 { rc } else { 0 }
}

// ── Query ──

#[unsafe(no_mangle)]
pub extern "C" fn usb_video_device_count() -> u32 {
    devices().iter().filter(|d| d.active).count() as u32
}

#[unsafe(no_mangle)]
pub extern "C" fn usb_video_is_streaming(dev_index: u32) -> bool {
    let devs = devices();
    if dev_index as usize >= MAX_DEVICES {
        return false;
    }
    devs[dev_index as usize].active && devs[dev_index as usize].streaming
}
