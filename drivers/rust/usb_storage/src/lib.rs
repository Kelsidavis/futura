// SPDX-License-Identifier: MPL-2.0
//
// USB Mass Storage Class Driver (Bulk-Only Transport)
//
// Implements the USB Mass Storage Bulk-Only Transport (BBB) specification
// for SCSI transparent command set devices (class 08h, subclass 06h,
// protocol 50h).
//
// Architecture:
//   - Callback-based USB bulk transfer model (sits above host controller)
//   - Up to 4 simultaneously attached USB storage devices
//   - SCSI command set: INQUIRY, TEST UNIT READY, READ CAPACITY 10,
//     READ 10, WRITE 10, REQUEST SENSE
//   - CBW/CSW (Command Block Wrapper / Command Status Wrapper) framing
//   - Block device registration through blkcore as "usb0" .. "usb3"
//   - Polling-based (no interrupt transfer support yet)

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(unexpected_cfgs)]

use core::cell::UnsafeCell;
use core::ffi::{c_char, c_void};

use common::{
    alloc, alloc_page, free, log, register,
    FutBlkBackend, FutBlkDev, FutStatus,
    FUT_BLK_ADMIN, FUT_BLK_READ, FUT_BLK_WRITE,
};

unsafe extern "C" {
    fn fut_printf(fmt: *const u8, ...);
}

// ── Static state wrapper ──

/// Wrapper to allow `UnsafeCell` in a `static` (requires `Sync`).
/// Safety: all access is single-threaded or externally synchronised by the caller.
struct StaticCell<T>(UnsafeCell<T>);
unsafe impl<T> Sync for StaticCell<T> {}
impl<T> StaticCell<T> {
    const fn new(val: T) -> Self { Self(UnsafeCell::new(val)) }
    fn get(&self) -> *mut T { self.0.get() }
}

// ── USB Bulk transfer callback ──

/// Function pointer type for performing USB bulk transfers.
///
/// `dev`  — host-controller device handle
/// `ep`   — endpoint address (bit 7 = direction: 0=OUT, 1=IN)
/// `data` — buffer pointer
/// `len`  — transfer length in bytes
///
/// Returns number of bytes actually transferred, or negative on error.
pub type BulkTransferFn = unsafe extern "C" fn(dev: u32, ep: u8, data: *mut u8, len: u32) -> i32;

// ── Constants ──

const MAX_USB_STORAGE_DEVICES: usize = 4;

// CBW/CSW signatures
const CBW_SIGNATURE: u32 = 0x43425355; // "USBC"
const CSW_SIGNATURE: u32 = 0x53425355; // "USBS"

// CBW sizes
const CBW_SIZE: usize = 31;
const CSW_SIZE: usize = 13;

// CBW direction flags
const CBW_FLAG_DATA_IN: u8 = 0x80;
const CBW_FLAG_DATA_OUT: u8 = 0x00;

// CSW status codes
const CSW_STATUS_PASSED: u8 = 0x00;
const CSW_STATUS_FAILED: u8 = 0x01;
const CSW_STATUS_PHASE_ERROR: u8 = 0x02;

// SCSI opcodes
const SCSI_INQUIRY: u8 = 0x12;
const SCSI_TEST_UNIT_READY: u8 = 0x00;
const SCSI_READ_CAPACITY_10: u8 = 0x25;
const SCSI_READ_10: u8 = 0x28;
const SCSI_WRITE_10: u8 = 0x2A;
const SCSI_REQUEST_SENSE: u8 = 0x03;

// SCSI data lengths
const SCSI_INQUIRY_DATA_LEN: u32 = 36;
const SCSI_SENSE_DATA_LEN: u32 = 18;
const SCSI_READ_CAP_DATA_LEN: u32 = 8;

// ── Command Block Wrapper (CBW) — 31 bytes ──

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct Cbw {
    signature: u32,
    tag: u32,
    data_transfer_length: u32,
    flags: u8,
    lun: u8,
    cb_length: u8,
    cb: [u8; 16],
}

const _: () = assert!(core::mem::size_of::<Cbw>() == CBW_SIZE);

impl Cbw {
    const fn zeroed() -> Self {
        Self {
            signature: CBW_SIGNATURE,
            tag: 0,
            data_transfer_length: 0,
            flags: 0,
            lun: 0,
            cb_length: 0,
            cb: [0; 16],
        }
    }
}

// ── Command Status Wrapper (CSW) — 13 bytes ──

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct Csw {
    signature: u32,
    tag: u32,
    data_residue: u32,
    status: u8,
}

const _: () = assert!(core::mem::size_of::<Csw>() == CSW_SIZE);

// ── Per-device state ──

struct UsbStorageDevice {
    /// Whether this slot is in use
    attached: bool,
    /// Host-controller device handle
    dev_id: u32,
    /// Bulk-IN endpoint address
    bulk_in_ep: u8,
    /// Bulk-OUT endpoint address
    bulk_out_ep: u8,
    /// Bulk transfer function pointer
    bulk_fn: Option<BulkTransferFn>,
    /// Monotonically increasing command tag
    next_tag: u32,
    /// Device geometry: total block count
    block_count: u64,
    /// Device geometry: block size in bytes
    block_size: u32,
    /// SCSI inquiry vendor string (8 bytes + NUL)
    vendor: [u8; 9],
    /// SCSI inquiry product string (16 bytes + NUL)
    product: [u8; 17],
    /// Block device name ("usb0\0" .. "usb3\0")
    name: [u8; 8],
}

impl UsbStorageDevice {
    const fn empty() -> Self {
        Self {
            attached: false,
            dev_id: 0,
            bulk_in_ep: 0,
            bulk_out_ep: 0,
            bulk_fn: None,
            next_tag: 1,
            block_count: 0,
            block_size: 0,
            vendor: [0; 9],
            product: [0; 17],
            name: [0; 8],
        }
    }
}

// ── Global state ──

struct UsbStorageState {
    devices: [UsbStorageDevice; MAX_USB_STORAGE_DEVICES],
    initialised: bool,
}

impl UsbStorageState {
    const fn new() -> Self {
        Self {
            devices: [
                UsbStorageDevice::empty(),
                UsbStorageDevice::empty(),
                UsbStorageDevice::empty(),
                UsbStorageDevice::empty(),
            ],
            initialised: false,
        }
    }
}

static STATE: StaticCell<UsbStorageState> = StaticCell::new(UsbStorageState::new());

// ── Byte-level serialisation helpers ──

/// Write a little-endian u32 into `buf` at byte offset `off`.
fn put_le32(buf: &mut [u8], off: usize, val: u32) {
    buf[off]     = val as u8;
    buf[off + 1] = (val >> 8) as u8;
    buf[off + 2] = (val >> 16) as u8;
    buf[off + 3] = (val >> 24) as u8;
}

/// Read a little-endian u32 from `buf` at byte offset `off`.
fn get_le32(buf: &[u8], off: usize) -> u32 {
    (buf[off] as u32)
        | ((buf[off + 1] as u32) << 8)
        | ((buf[off + 2] as u32) << 16)
        | ((buf[off + 3] as u32) << 24)
}

/// Read a big-endian u32 from `buf` at byte offset `off`.
fn get_be32(buf: &[u8], off: usize) -> u32 {
    ((buf[off] as u32) << 24)
        | ((buf[off + 1] as u32) << 16)
        | ((buf[off + 2] as u32) << 8)
        | (buf[off + 3] as u32)
}

// ── Low-level CBW/CSW transport ──

/// Serialise a CBW into `buf` (31 bytes).
fn cbw_to_bytes(cbw: &Cbw, buf: &mut [u8; CBW_SIZE]) {
    put_le32(buf, 0, cbw.signature);
    put_le32(buf, 4, cbw.tag);
    put_le32(buf, 8, cbw.data_transfer_length);
    buf[12] = cbw.flags;
    buf[13] = cbw.lun & 0x0F;
    buf[14] = cbw.cb_length & 0x1F;
    buf[15..31].copy_from_slice(&cbw.cb);
}

/// Parse a CSW from `buf` (13 bytes). Returns `None` if the signature is invalid.
fn csw_from_bytes(buf: &[u8; CSW_SIZE]) -> Option<Csw> {
    let sig = get_le32(buf, 0);
    if sig != CSW_SIGNATURE {
        return None;
    }
    Some(Csw {
        signature: sig,
        tag: get_le32(buf, 4),
        data_residue: get_le32(buf, 8),
        status: buf[12],
    })
}

/// Send a CBW on the bulk-OUT endpoint.
fn send_cbw(dev: &mut UsbStorageDevice, cbw: &Cbw) -> i32 {
    let bulk_fn = match dev.bulk_fn {
        Some(f) => f,
        None => return -1,
    };
    let mut buf = [0u8; CBW_SIZE];
    cbw_to_bytes(cbw, &mut buf);
    unsafe {
        (bulk_fn)(dev.dev_id, dev.bulk_out_ep, buf.as_mut_ptr(), CBW_SIZE as u32)
    }
}

/// Receive a CSW from the bulk-IN endpoint.
fn recv_csw(dev: &mut UsbStorageDevice, expected_tag: u32) -> Result<Csw, i32> {
    let bulk_fn = match dev.bulk_fn {
        Some(f) => f,
        None => return Err(-1),
    };
    let mut buf = [0u8; CSW_SIZE];
    let ret = unsafe {
        (bulk_fn)(dev.dev_id, dev.bulk_in_ep, buf.as_mut_ptr(), CSW_SIZE as u32)
    };
    if ret < 0 {
        return Err(ret);
    }
    if (ret as usize) < CSW_SIZE {
        return Err(-2);
    }
    let csw = match csw_from_bytes(&buf) {
        Some(c) => c,
        None => return Err(-3),
    };
    if csw.tag != expected_tag {
        return Err(-4);
    }
    Ok(csw)
}

/// Perform bulk data-IN transfer (device to host).
fn bulk_in(dev: &mut UsbStorageDevice, buf: *mut u8, len: u32) -> i32 {
    let bulk_fn = match dev.bulk_fn {
        Some(f) => f,
        None => return -1,
    };
    unsafe { (bulk_fn)(dev.dev_id, dev.bulk_in_ep, buf, len) }
}

/// Perform bulk data-OUT transfer (host to device).
fn bulk_out(dev: &mut UsbStorageDevice, buf: *const u8, len: u32) -> i32 {
    let bulk_fn = match dev.bulk_fn {
        Some(f) => f,
        None => return -1,
    };
    // The bulk transfer function takes *mut u8; cast away const for OUT transfers.
    unsafe { (bulk_fn)(dev.dev_id, dev.bulk_out_ep, buf as *mut u8, len) }
}

// ── SCSI command builders ──

/// Build a CBW for a SCSI command. Allocates a new tag from the device state.
fn build_cbw(
    dev: &mut UsbStorageDevice,
    direction: u8,
    transfer_len: u32,
    lun: u8,
    scsi_cmd: &[u8],
) -> Cbw {
    let tag = dev.next_tag;
    dev.next_tag = dev.next_tag.wrapping_add(1);

    let mut cbw = Cbw::zeroed();
    cbw.tag = tag;
    cbw.data_transfer_length = transfer_len;
    cbw.flags = direction;
    cbw.lun = lun & 0x0F;
    let cmd_len = scsi_cmd.len().min(16);
    cbw.cb_length = cmd_len as u8;
    cbw.cb[..cmd_len].copy_from_slice(scsi_cmd);
    cbw
}

/// Execute a complete Bulk-Only Transport command: CBW -> optional data -> CSW.
/// For DATA-IN commands, pass `data_buf` pointing to a receive buffer.
/// For DATA-OUT commands, pass `data_buf` pointing to the send buffer.
/// For no-data commands, pass null `data_buf` with `transfer_len` = 0.
fn execute_transport(
    dev: &mut UsbStorageDevice,
    direction: u8,
    lun: u8,
    scsi_cmd: &[u8],
    data_buf: *mut u8,
    transfer_len: u32,
) -> Result<Csw, i32> {
    // 1. Build and send CBW
    let cbw = build_cbw(dev, direction, transfer_len, lun, scsi_cmd);
    let tag = cbw.tag;
    let ret = send_cbw(dev, &cbw);
    if ret < 0 {
        return Err(ret);
    }

    // 2. Data phase (if any)
    if transfer_len > 0 && !data_buf.is_null() {
        if direction == CBW_FLAG_DATA_IN {
            let ret = bulk_in(dev, data_buf, transfer_len);
            if ret < 0 {
                return Err(ret);
            }
        } else {
            let ret = bulk_out(dev, data_buf as *const u8, transfer_len);
            if ret < 0 {
                return Err(ret);
            }
        }
    }

    // 3. Receive CSW
    recv_csw(dev, tag)
}

// ── SCSI command implementations ──

/// SCSI INQUIRY — retrieve standard inquiry data (36 bytes).
fn scsi_inquiry(dev: &mut UsbStorageDevice) -> i32 {
    let mut scsi_cmd = [0u8; 6];
    scsi_cmd[0] = SCSI_INQUIRY;
    scsi_cmd[4] = SCSI_INQUIRY_DATA_LEN as u8; // allocation length

    let mut data = [0u8; 36];
    let csw = match execute_transport(
        dev,
        CBW_FLAG_DATA_IN,
        0,
        &scsi_cmd,
        data.as_mut_ptr(),
        SCSI_INQUIRY_DATA_LEN,
    ) {
        Ok(c) => c,
        Err(e) => return e,
    };

    if csw.status != CSW_STATUS_PASSED {
        return -10;
    }

    // Extract vendor (bytes 8-15) and product (bytes 16-31)
    for i in 0..8 {
        dev.vendor[i] = data[8 + i];
    }
    dev.vendor[8] = 0;

    for i in 0..16 {
        dev.product[i] = data[16 + i];
    }
    dev.product[16] = 0;

    0
}

/// SCSI TEST UNIT READY — check if media is present and ready.
fn scsi_test_unit_ready(dev: &mut UsbStorageDevice) -> i32 {
    let scsi_cmd = [SCSI_TEST_UNIT_READY, 0, 0, 0, 0, 0];
    let csw = match execute_transport(
        dev,
        CBW_FLAG_DATA_OUT,
        0,
        &scsi_cmd,
        core::ptr::null_mut(),
        0,
    ) {
        Ok(c) => c,
        Err(e) => return e,
    };

    if csw.status != CSW_STATUS_PASSED {
        return -1;
    }
    0
}

/// SCSI REQUEST SENSE — retrieve sense data after a failed command.
fn scsi_request_sense(dev: &mut UsbStorageDevice) -> (u8, u8, u8) {
    let mut scsi_cmd = [0u8; 6];
    scsi_cmd[0] = SCSI_REQUEST_SENSE;
    scsi_cmd[4] = SCSI_SENSE_DATA_LEN as u8;

    let mut data = [0u8; 18];
    let csw = match execute_transport(
        dev,
        CBW_FLAG_DATA_IN,
        0,
        &scsi_cmd,
        data.as_mut_ptr(),
        SCSI_SENSE_DATA_LEN,
    ) {
        Ok(c) => c,
        Err(_) => return (0xFF, 0xFF, 0xFF),
    };

    if csw.status != CSW_STATUS_PASSED {
        return (0xFF, 0xFF, 0xFF);
    }

    // Sense key (byte 2, bits 3:0), ASC (byte 12), ASCQ (byte 13)
    let sense_key = data[2] & 0x0F;
    let asc = data[12];
    let ascq = data[13];
    (sense_key, asc, ascq)
}

/// SCSI READ CAPACITY (10) — discover block count and block size.
fn scsi_read_capacity_10(dev: &mut UsbStorageDevice) -> i32 {
    let scsi_cmd = [SCSI_READ_CAPACITY_10, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    let mut data = [0u8; 8];
    let csw = match execute_transport(
        dev,
        CBW_FLAG_DATA_IN,
        0,
        &scsi_cmd,
        data.as_mut_ptr(),
        SCSI_READ_CAP_DATA_LEN,
    ) {
        Ok(c) => c,
        Err(e) => return e,
    };

    if csw.status != CSW_STATUS_PASSED {
        // Try REQUEST SENSE for diagnostics
        let (sk, asc, ascq) = scsi_request_sense(dev);
        unsafe {
            fut_printf(
                b"usb_storage: READ CAPACITY failed, sense=%02x/%02x/%02x\n\0".as_ptr(),
                sk as u32, asc as u32, ascq as u32,
            );
        }
        return -10;
    }

    // READ CAPACITY (10) returns big-endian:
    //   bytes 0-3: last logical block address
    //   bytes 4-7: block length in bytes
    let last_lba = get_be32(&data, 0) as u64;
    let blk_size = get_be32(&data, 4);

    dev.block_count = last_lba + 1;
    dev.block_size = blk_size;

    0
}

/// SCSI READ (10) — read `count` sectors starting at `lba` into `buf`.
fn scsi_read_10(
    dev: &mut UsbStorageDevice,
    lba: u64,
    count: u32,
    buf: *mut u8,
) -> i32 {
    if count == 0 || count > 0xFFFF {
        return -1;
    }
    let lba32 = lba as u32; // READ (10) uses 32-bit LBA

    let mut scsi_cmd = [0u8; 10];
    scsi_cmd[0] = SCSI_READ_10;
    // LBA (bytes 2-5, big-endian)
    scsi_cmd[2] = (lba32 >> 24) as u8;
    scsi_cmd[3] = (lba32 >> 16) as u8;
    scsi_cmd[4] = (lba32 >> 8) as u8;
    scsi_cmd[5] = lba32 as u8;
    // Transfer length in sectors (bytes 7-8, big-endian)
    scsi_cmd[7] = (count >> 8) as u8;
    scsi_cmd[8] = count as u8;

    let transfer_bytes = count * dev.block_size;
    let csw = match execute_transport(
        dev,
        CBW_FLAG_DATA_IN,
        0,
        &scsi_cmd,
        buf,
        transfer_bytes,
    ) {
        Ok(c) => c,
        Err(e) => return e,
    };

    if csw.status != CSW_STATUS_PASSED {
        return -10;
    }

    0
}

/// SCSI WRITE (10) — write `count` sectors starting at `lba` from `buf`.
fn scsi_write_10(
    dev: &mut UsbStorageDevice,
    lba: u64,
    count: u32,
    buf: *const u8,
) -> i32 {
    if count == 0 || count > 0xFFFF {
        return -1;
    }
    let lba32 = lba as u32;

    let mut scsi_cmd = [0u8; 10];
    scsi_cmd[0] = SCSI_WRITE_10;
    scsi_cmd[2] = (lba32 >> 24) as u8;
    scsi_cmd[3] = (lba32 >> 16) as u8;
    scsi_cmd[4] = (lba32 >> 8) as u8;
    scsi_cmd[5] = lba32 as u8;
    scsi_cmd[7] = (count >> 8) as u8;
    scsi_cmd[8] = count as u8;

    let transfer_bytes = count * dev.block_size;
    let csw = match execute_transport(
        dev,
        CBW_FLAG_DATA_OUT,
        0,
        &scsi_cmd,
        buf as *mut u8, // cast for transport fn (direction is OUT)
        transfer_bytes,
    ) {
        Ok(c) => c,
        Err(e) => return e,
    };

    if csw.status != CSW_STATUS_PASSED {
        return -10;
    }

    0
}

// ── Device slot lookup ──

/// Find the internal slot index for a given `dev_id`.
fn find_slot(state: &UsbStorageState, dev_id: u32) -> Option<usize> {
    for i in 0..MAX_USB_STORAGE_DEVICES {
        if state.devices[i].attached && state.devices[i].dev_id == dev_id {
            return Some(i);
        }
    }
    None
}

/// Find a free slot, returning its index.
fn find_free_slot(state: &UsbStorageState) -> Option<usize> {
    for i in 0..MAX_USB_STORAGE_DEVICES {
        if !state.devices[i].attached {
            return Some(i);
        }
    }
    None
}

// ── Block device backend callbacks ──

/// Read callback for blkcore.
unsafe extern "C" fn usb_blk_read(
    ctx: *mut c_void,
    lba: u64,
    nsectors: usize,
    buf: *mut c_void,
) -> FutStatus {
    let dev = unsafe { &mut *(ctx as *mut UsbStorageDevice) };
    if !dev.attached {
        return -1;
    }
    scsi_read_10(dev, lba, nsectors as u32, buf as *mut u8)
}

/// Write callback for blkcore.
unsafe extern "C" fn usb_blk_write(
    ctx: *mut c_void,
    lba: u64,
    nsectors: usize,
    buf: *const c_void,
) -> FutStatus {
    let dev = unsafe { &mut *(ctx as *mut UsbStorageDevice) };
    if !dev.attached {
        return -1;
    }
    scsi_write_10(dev, lba, nsectors as u32, buf as *const u8)
}

/// Flush callback for blkcore (no-op for USB mass storage).
unsafe extern "C" fn usb_blk_flush(_ctx: *mut c_void) -> FutStatus {
    0
}

static USB_STORAGE_BACKEND: FutBlkBackend = FutBlkBackend {
    read: Some(usb_blk_read),
    write: Some(usb_blk_write),
    flush: Some(usb_blk_flush),
};

// ── Device name helper ──

/// Generate a device name "usbN\0" for slot index `idx`.
fn make_dev_name(idx: usize) -> [u8; 8] {
    let mut name = [0u8; 8];
    name[0] = b'u';
    name[1] = b's';
    name[2] = b'b';
    name[3] = b'0' + (idx as u8);
    name[4] = 0;
    name
}

// ── Block device registration ──

/// Register a USB storage device as a block device with blkcore.
fn register_blkdev(state: &mut UsbStorageState, slot: usize) -> i32 {
    let dev = &mut state.devices[slot];
    let dev_ptr = dev as *mut UsbStorageDevice;

    let blkdev = unsafe { alloc(core::mem::size_of::<FutBlkDev>()) as *mut FutBlkDev };
    if blkdev.is_null() {
        log("usb_storage: failed to allocate FutBlkDev");
        return -1;
    }

    unsafe {
        (*blkdev).name = dev.name.as_ptr() as *const c_char;
        (*blkdev).block_size = dev.block_size;
        (*blkdev).block_count = dev.block_count;
        (*blkdev).allowed_rights = FUT_BLK_READ | FUT_BLK_WRITE | FUT_BLK_ADMIN;
        (*blkdev).backend = &USB_STORAGE_BACKEND;
        (*blkdev).backend_ctx = dev_ptr as *mut c_void;
        (*blkdev).core = core::ptr::null_mut();
    }

    let blkdev_ref = unsafe { &mut *blkdev };
    match register(blkdev_ref) {
        Ok(()) => {
            unsafe {
                fut_printf(
                    b"usb_storage: registered block device %s (%llu blocks x %u bytes)\n\0"
                        .as_ptr(),
                    dev.name.as_ptr(),
                    dev.block_count,
                    dev.block_size,
                );
            }
            0
        }
        Err(e) => {
            unsafe {
                fut_printf(b"usb_storage: blk_register failed: %d\n\0".as_ptr(), e);
                free(blkdev as *mut u8);
            }
            e
        }
    }
}

// ── FFI exports ──

/// Initialise the USB mass storage class driver.
/// Must be called once before any attach/detach/read/write calls.
/// Returns 0 on success.
#[unsafe(no_mangle)]
pub extern "C" fn usb_storage_init() -> i32 {
    let state = unsafe { &mut *STATE.get() };
    if state.initialised {
        log("usb_storage: already initialised");
        return 0;
    }

    for i in 0..MAX_USB_STORAGE_DEVICES {
        state.devices[i] = UsbStorageDevice::empty();
    }

    state.initialised = true;
    log("usb_storage: driver initialised (max 4 devices)");
    0
}

/// Attach a new USB mass storage device.
///
/// `dev_id`      — host-controller device identifier
/// `bulk_in_ep`  — bulk-IN endpoint address (e.g. 0x81)
/// `bulk_out_ep` — bulk-OUT endpoint address (e.g. 0x02)
/// `bulk_fn`     — bulk transfer callback
///
/// Performs INQUIRY, TEST UNIT READY, and READ CAPACITY to probe the device,
/// then registers it as a block device with blkcore.
///
/// Returns 0 on success, negative on error.
#[unsafe(no_mangle)]
pub extern "C" fn usb_storage_attach(
    dev_id: u32,
    bulk_in_ep: u8,
    bulk_out_ep: u8,
    bulk_fn: BulkTransferFn,
) -> i32 {
    let state = unsafe { &mut *STATE.get() };
    if !state.initialised {
        log("usb_storage: not initialised");
        return -1;
    }

    // Check for duplicate
    if find_slot(state, dev_id).is_some() {
        unsafe {
            fut_printf(
                b"usb_storage: device %u already attached\n\0".as_ptr(),
                dev_id,
            );
        }
        return -2;
    }

    let slot = match find_free_slot(state) {
        Some(s) => s,
        None => {
            log("usb_storage: no free device slots");
            return -3;
        }
    };

    unsafe {
        fut_printf(
            b"usb_storage: attaching device %u (IN=0x%02x, OUT=0x%02x) to slot %u\n\0".as_ptr(),
            dev_id, bulk_in_ep as u32, bulk_out_ep as u32, slot as u32,
        );
    }

    let dev = &mut state.devices[slot];
    dev.attached = true;
    dev.dev_id = dev_id;
    dev.bulk_in_ep = bulk_in_ep;
    dev.bulk_out_ep = bulk_out_ep;
    dev.bulk_fn = Some(bulk_fn);
    dev.next_tag = 1;
    dev.name = make_dev_name(slot);

    // Step 1: SCSI INQUIRY
    let ret = scsi_inquiry(dev);
    if ret < 0 {
        unsafe {
            fut_printf(b"usb_storage: INQUIRY failed: %d\n\0".as_ptr(), ret);
        }
        dev.attached = false;
        return -10;
    }
    unsafe {
        fut_printf(
            b"usb_storage: vendor='%s' product='%s'\n\0".as_ptr(),
            dev.vendor.as_ptr(),
            dev.product.as_ptr(),
        );
    }

    // Step 2: TEST UNIT READY (retry a few times for spin-up)
    let mut ready = false;
    for attempt in 0..5u32 {
        let ret = scsi_test_unit_ready(dev);
        if ret == 0 {
            ready = true;
            break;
        }
        // Get sense data for diagnostic
        let (sk, asc, ascq) = scsi_request_sense(dev);
        if attempt < 4 {
            unsafe {
                fut_printf(
                    b"usb_storage: not ready (sense=%02x/%02x/%02x), retry %u\n\0".as_ptr(),
                    sk as u32, asc as u32, ascq as u32, attempt + 1,
                );
            }
        }
    }
    if !ready {
        log("usb_storage: device not ready after retries");
        dev.attached = false;
        return -11;
    }

    // Step 3: READ CAPACITY (10)
    let ret = scsi_read_capacity_10(dev);
    if ret < 0 {
        unsafe {
            fut_printf(b"usb_storage: READ CAPACITY failed: %d\n\0".as_ptr(), ret);
        }
        dev.attached = false;
        return -12;
    }

    let size_mb = (dev.block_count * dev.block_size as u64) / (1024 * 1024);
    unsafe {
        fut_printf(
            b"usb_storage: capacity: %llu blocks x %u bytes (%llu MiB)\n\0".as_ptr(),
            dev.block_count,
            dev.block_size,
            size_mb,
        );
    }

    // Step 4: Register as block device
    // Drop dev borrow before passing state to register_blkdev
    drop(dev);
    let ret = register_blkdev(state, slot);
    if ret < 0 {
        state.devices[slot].attached = false;
        return -13;
    }

    0
}

/// Detach a USB mass storage device.
///
/// `dev_id` — host-controller device identifier as passed to `usb_storage_attach`.
///
/// Returns 0 on success, negative if the device was not found.
#[unsafe(no_mangle)]
pub extern "C" fn usb_storage_detach(dev_id: u32) -> i32 {
    let state = unsafe { &mut *STATE.get() };
    let slot = match find_slot(state, dev_id) {
        Some(s) => s,
        None => {
            unsafe {
                fut_printf(
                    b"usb_storage: detach: device %u not found\n\0".as_ptr(),
                    dev_id,
                );
            }
            return -1;
        }
    };

    let dev = &mut state.devices[slot];
    dev.attached = false;
    dev.bulk_fn = None;
    dev.block_count = 0;
    dev.block_size = 0;

    unsafe {
        fut_printf(
            b"usb_storage: detached device %u from slot %u\n\0".as_ptr(),
            dev_id, slot as u32,
        );
    }

    0
}

/// Read sectors from a USB mass storage device.
///
/// `dev_id` — device identifier
/// `lba`    — starting logical block address
/// `count`  — number of sectors to read
/// `buf`    — destination buffer (must be at least `count * block_size` bytes)
///
/// Returns 0 on success, negative on error.
#[unsafe(no_mangle)]
pub extern "C" fn usb_storage_read(
    dev_id: u32,
    lba: u64,
    count: u32,
    buf: *mut u8,
) -> i32 {
    let state = unsafe { &mut *STATE.get() };
    let slot = match find_slot(state, dev_id) {
        Some(s) => s,
        None => return -1,
    };
    let dev = &mut state.devices[slot];
    scsi_read_10(dev, lba, count, buf)
}

/// Write sectors to a USB mass storage device.
///
/// `dev_id` — device identifier
/// `lba`    — starting logical block address
/// `count`  — number of sectors to write
/// `buf`    — source buffer (must be at least `count * block_size` bytes)
///
/// Returns 0 on success, negative on error.
#[unsafe(no_mangle)]
pub extern "C" fn usb_storage_write(
    dev_id: u32,
    lba: u64,
    count: u32,
    buf: *const u8,
) -> i32 {
    let state = unsafe { &mut *STATE.get() };
    let slot = match find_slot(state, dev_id) {
        Some(s) => s,
        None => return -1,
    };
    let dev = &mut state.devices[slot];
    scsi_write_10(dev, lba, count, buf)
}

/// Query the capacity of an attached USB mass storage device.
///
/// `dev_id`     — device identifier
/// `blocks`     — out: total number of logical blocks
/// `block_size` — out: size of each block in bytes
///
/// Returns 0 on success, negative if the device is not found.
#[unsafe(no_mangle)]
pub extern "C" fn usb_storage_get_capacity(
    dev_id: u32,
    blocks: *mut u64,
    block_size: *mut u32,
) -> i32 {
    let state = unsafe { &*STATE.get() };
    let slot = match find_slot(state, dev_id) {
        Some(s) => s,
        None => return -1,
    };
    let dev = &state.devices[slot];
    if !blocks.is_null() {
        unsafe { core::ptr::write(blocks, dev.block_count); }
    }
    if !block_size.is_null() {
        unsafe { core::ptr::write(block_size, dev.block_size); }
    }
    0
}
