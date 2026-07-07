// SPDX-License-Identifier: MPL-2.0
//
// USB Bluetooth HCI Transport Driver for Futura OS
//
// Implements Bluetooth Core Spec Vol 4, Part B — USB transport for HCI.
// Registers with the kernel HCI framework (fut_hci_register) so higher
// layers can send commands and receive events/ACL data.
//
// Endpoint mapping (BT HCI USB transport):
//   Control EP0 OUT  → HCI commands  (class request 0x20/0x00)
//   Interrupt IN     → HCI events
//   Bulk IN          → ACL data (from controller)
//   Bulk OUT         → ACL data (to controller)

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(unexpected_cfgs)]
#![allow(dead_code)]

use core::cell::UnsafeCell;
use common::log;

// ── FFI imports ──

unsafe extern "C" {
    fn fut_printf(fmt: *const u8, ...);

    fn fut_hci_register(
        name: *const u8,
        dev_type: u32,
        ops: *const HciOps,
        cookie: *mut u8,
    ) -> i32;
    fn fut_hci_dispatch_event(
        dev_index: i32,
        pkt_type: u8,
        pkt: *const u8,
        len: usize,
    ) -> i32;

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

// ── Constants ──

const FUT_HCI_TYPE_USB: u32 = 1;
const FUT_HCI_CMD_PKT: u8 = 0x01;
const FUT_HCI_ACL_PKT: u8 = 0x02;
const FUT_HCI_EVT_PKT: u8 = 0x04;

const MAX_EVT_BUF: usize = 258;
const MAX_ACL_BUF: usize = 1027;
const MAX_DEVICES: usize = 2;

// USB BT HCI class request for sending commands via control EP0
const USB_BT_REQUEST_TYPE: u8 = 0x20; // class, host-to-device, interface
const USB_BT_SEND_CMD: u8 = 0x00;

// ── HCI ops FFI struct ──

#[repr(C)]
struct HciOps {
    send_cmd: unsafe extern "C" fn(*mut u8, *const u8, usize) -> i32,
    send_acl: unsafe extern "C" fn(*mut u8, *const u8, usize) -> i32,
    open: unsafe extern "C" fn(*mut u8) -> i32,
    close: unsafe extern "C" fn(*mut u8),
}

// ── Per-device state ──

struct UsbBtDevice {
    active: bool,
    slot_id: u32,
    intr_in_ep: u8,
    bulk_in_ep: u8,
    bulk_out_ep: u8,
    hci_index: i32,
    opened: bool,
    evt_buf: [u8; MAX_EVT_BUF],
    acl_buf: [u8; MAX_ACL_BUF],
}

impl UsbBtDevice {
    const fn new() -> Self {
        Self {
            active: false,
            slot_id: 0,
            intr_in_ep: 0,
            bulk_in_ep: 0,
            bulk_out_ep: 0,
            hci_index: -1,
            opened: false,
            evt_buf: [0u8; MAX_EVT_BUF],
            acl_buf: [0u8; MAX_ACL_BUF],
        }
    }
}

// ── Static state ──

struct StaticCell<T>(UnsafeCell<T>);
unsafe impl<T> Sync for StaticCell<T> {}
impl<T> StaticCell<T> {
    const fn new(v: T) -> Self { Self(UnsafeCell::new(v)) }
    fn get(&self) -> *mut T { self.0.get() }
}

static DEVICES: StaticCell<[UsbBtDevice; MAX_DEVICES]> = StaticCell::new(
    [const { UsbBtDevice::new() }; MAX_DEVICES]
);

static HCI_OPS: HciOps = HciOps {
    send_cmd: hci_send_cmd,
    send_acl: hci_send_acl,
    open: hci_open,
    close: hci_close,
};

fn devices() -> &'static mut [UsbBtDevice; MAX_DEVICES] {
    unsafe { &mut *DEVICES.get() }
}

fn find_device_by_cookie(cookie: *mut u8) -> Option<&'static mut UsbBtDevice> {
    let idx = cookie as usize;
    if idx < MAX_DEVICES {
        let dev = &mut devices()[idx];
        if dev.active { return Some(dev); }
    }
    None
}

// ── HCI transport callbacks ──

unsafe extern "C" fn hci_send_cmd(cookie: *mut u8, pkt: *const u8, len: usize) -> i32 {
    let dev = match find_device_by_cookie(cookie) {
        Some(d) => d,
        None => return -19, // ENODEV
    };
    if pkt.is_null() || len < 3 || len > 258 {
        return -22; // EINVAL
    }
    // HCI command packet layout: opcode (2 bytes) + param_len (1 byte) + params
    // Send via USB control transfer to EP0
    unsafe {
        xhci_control_transfer_ext(
            dev.slot_id,
            USB_BT_REQUEST_TYPE,
            USB_BT_SEND_CMD,
            0, // wValue
            0, // wIndex = interface 0
            pkt as *mut u8,
            len as u16,
        )
    }
}

unsafe extern "C" fn hci_send_acl(cookie: *mut u8, pkt: *const u8, len: usize) -> i32 {
    let dev = match find_device_by_cookie(cookie) {
        Some(d) => d,
        None => return -19,
    };
    if pkt.is_null() || len < 4 || len > MAX_ACL_BUF {
        return -22;
    }
    unsafe {
        xhci_bulk_transfer(
            dev.slot_id,
            dev.bulk_out_ep,
            pkt as *mut u8,
            len as u32,
        )
    }
}

unsafe extern "C" fn hci_open(cookie: *mut u8) -> i32 {
    let dev = match find_device_by_cookie(cookie) {
        Some(d) => d,
        None => return -19,
    };
    if dev.opened {
        return 0;
    }

    // Send HCI Reset via control EP0
    let reset_cmd: [u8; 3] = [0x03, 0x0C, 0x00]; // opcode 0x0C03 (Reset), param_len 0
    let rc = unsafe {
        xhci_control_transfer_ext(
            dev.slot_id,
            USB_BT_REQUEST_TYPE,
            USB_BT_SEND_CMD,
            0,
            0,
            reset_cmd.as_ptr() as *mut u8,
            3,
        )
    };
    if rc < 0 {
        unsafe {
            fut_printf(
                b"usb-bt: HCI Reset failed on slot %u (rc=%d)\n\0".as_ptr(),
                dev.slot_id, rc,
            );
        }
        return rc;
    }

    // Poll for the Command Complete event for HCI Reset
    let n = unsafe {
        xhci_bulk_transfer(
            dev.slot_id,
            dev.intr_in_ep,
            dev.evt_buf.as_mut_ptr(),
            MAX_EVT_BUF as u32,
        )
    };
    if n > 0 {
        unsafe {
            fut_hci_dispatch_event(
                dev.hci_index,
                FUT_HCI_EVT_PKT,
                dev.evt_buf.as_ptr(),
                n as usize,
            );
        }
    }

    dev.opened = true;
    log("usb-bt: transport opened");
    0
}

unsafe extern "C" fn hci_close(cookie: *mut u8) {
    if let Some(dev) = find_device_by_cookie(cookie) {
        dev.opened = false;
        log("usb-bt: transport closed");
    }
}

// ── Attach entry point (called from xHCI enumeration) ──

#[unsafe(no_mangle)]
pub extern "C" fn usb_bluetooth_attach(
    slot_id: u32,
    intr_in_ep: u8,
    bulk_in_ep: u8,
    bulk_out_ep: u8,
) {
    let devs = devices();
    let idx = match devs.iter().position(|d| !d.active) {
        Some(i) => i,
        None => {
            log("usb-bt: no free device slots");
            return;
        }
    };

    let dev = &mut devs[idx];
    dev.active = true;
    dev.slot_id = slot_id;
    dev.intr_in_ep = intr_in_ep;
    dev.bulk_in_ep = bulk_in_ep;
    dev.bulk_out_ep = bulk_out_ep;
    dev.opened = false;

    // Build name: "usb-bt0", "usb-bt1", etc.
    let name: [u8; 8] = [
        b'u', b's', b'b', b'-', b'b', b't',
        b'0' + idx as u8,
        0,
    ];

    let hci_idx = unsafe {
        fut_hci_register(
            name.as_ptr(),
            FUT_HCI_TYPE_USB,
            &HCI_OPS as *const HciOps,
            idx as *mut u8,
        )
    };

    if hci_idx < 0 {
        unsafe {
            fut_printf(
                b"usb-bt: fut_hci_register failed (rc=%d)\n\0".as_ptr(),
                hci_idx,
            );
        }
        dev.active = false;
        return;
    }

    dev.hci_index = hci_idx;

    unsafe {
        fut_printf(
            b"usb-bt: attached slot %u as hci%d (intr=0x%02x bulk_in=0x%02x bulk_out=0x%02x)\n\0".as_ptr(),
            slot_id, hci_idx,
            intr_in_ep as u32, bulk_in_ep as u32, bulk_out_ep as u32,
        );
    }
}

// ── Poll for incoming events/ACL (called from kernel polling loop) ──

#[unsafe(no_mangle)]
pub extern "C" fn usb_bluetooth_poll() {
    let devs = devices();
    for dev in devs.iter_mut() {
        if !dev.active || !dev.opened {
            continue;
        }

        // Poll interrupt IN for HCI events
        let n = unsafe {
            xhci_bulk_transfer(
                dev.slot_id,
                dev.intr_in_ep,
                dev.evt_buf.as_mut_ptr(),
                MAX_EVT_BUF as u32,
            )
        };
        if n > 0 {
            unsafe {
                fut_hci_dispatch_event(
                    dev.hci_index,
                    FUT_HCI_EVT_PKT,
                    dev.evt_buf.as_ptr(),
                    n as usize,
                );
            }
        }

        // Poll bulk IN for ACL data
        let n = unsafe {
            xhci_bulk_transfer(
                dev.slot_id,
                dev.bulk_in_ep,
                dev.acl_buf.as_mut_ptr(),
                MAX_ACL_BUF as u32,
            )
        };
        if n > 0 {
            unsafe {
                fut_hci_dispatch_event(
                    dev.hci_index,
                    FUT_HCI_ACL_PKT,
                    dev.acl_buf.as_ptr(),
                    n as usize,
                );
            }
        }
    }
}
