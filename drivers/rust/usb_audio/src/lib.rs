// SPDX-License-Identifier: MPL-2.0
//
// USB Audio Class (UAC) 1.0 Driver for Futura OS
//
// Implements the USB Audio Class 1.0 specification for USB headsets, speakers,
// and microphones.  Sits above the USB transport layer, accepting isochronous
// and control transfer callbacks from the host controller driver.
//
// UAC1 identification:
//   - Audio Control interface: class 01h, subclass 01h
//   - Audio Streaming interface: class 01h, subclass 02h
//   - Class-specific descriptors carry terminal, feature unit, and format
//     information
//
// Architecture:
//   - Callback-based USB isochronous/control transfer model
//   - Up to 2 simultaneously attached audio devices
//   - Audio Control descriptor parsing (terminals, feature units)
//   - Sample rate configuration via SET_CUR to endpoint
//   - Volume/mute control via Feature Unit requests
//   - PCM audio data write (isochronous OUT) and read (isochronous IN)
//
// UAC1 Class-Specific Requests:
//   SET_CUR (0x01), GET_CUR (0x81): current value
//   SET_MIN/MAX/RES (0x02/0x03/0x04): range parameters
//   GET_MIN/MAX/RES (0x82/0x83/0x84): range parameters
//
// Feature Unit Control Selectors (wValue high byte):
//   0x01 = Mute Control (1 byte: 0=unmuted, 1=muted)
//   0x02 = Volume Control (2 bytes, signed 16-bit, 1/256 dB units)

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(unexpected_cfgs)]
#![allow(dead_code)]

use core::cell::UnsafeCell;

use common::log;

unsafe extern "C" {
    fn fut_printf(fmt: *const u8, ...);
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

/// Isochronous transfer: `dev` device handle, `ep` endpoint address,
/// `data` buffer, `len` byte count.  Returns bytes transferred or negative error.
pub type IsocTransferFn = unsafe extern "C" fn(dev: u32, ep: u8, data: *mut u8, len: u32) -> i32;

/// Control transfer: `dev` device handle, `rt` request type, `req` bRequest,
/// `val` wValue, `idx` wIndex, `data` buffer, `len` wLength.
/// Returns bytes transferred or negative error.
pub type ControlTransferFn = unsafe extern "C" fn(
    dev: u32, rt: u8, req: u8, val: u16, idx: u16, data: *mut u8, len: u16,
) -> i32;

// ── Constants ──

const MAX_DEVICES: usize = 2;

// USB Audio Class codes
const AUDIO_CLASS: u8 = 0x01;
const AUDIO_SUBCLASS_CONTROL: u8 = 0x01;
const AUDIO_SUBCLASS_STREAMING: u8 = 0x02;

// UAC1 class-specific request codes
const SET_CUR: u8 = 0x01;
const GET_CUR: u8 = 0x81;
const SET_MIN: u8 = 0x02;
const GET_MIN: u8 = 0x82;
const SET_MAX: u8 = 0x03;
const GET_MAX: u8 = 0x83;
const SET_RES: u8 = 0x04;
const GET_RES: u8 = 0x84;

// Feature Unit control selectors (high byte of wValue)
const FU_MUTE_CONTROL: u8 = 0x01;
const FU_VOLUME_CONTROL: u8 = 0x02;

// Control request type fields
/// Host-to-device, class request, interface recipient
const RT_CLASS_IFACE_OUT: u8 = 0x21;
/// Device-to-host, class request, interface recipient
const RT_CLASS_IFACE_IN: u8 = 0xA1;
/// Host-to-device, class request, endpoint recipient
const RT_CLASS_EP_OUT: u8 = 0x22;

// Audio Control descriptor subtypes
const AC_HEADER: u8 = 0x01;
const AC_INPUT_TERMINAL: u8 = 0x02;
const AC_OUTPUT_TERMINAL: u8 = 0x03;
const AC_MIXER_UNIT: u8 = 0x04;
const AC_SELECTOR_UNIT: u8 = 0x05;
const AC_FEATURE_UNIT: u8 = 0x06;

// Terminal types (USB Audio Terminal Types)
const TT_USB_STREAMING: u16 = 0x0101;
const TT_SPEAKER: u16 = 0x0301;
const TT_HEADPHONES: u16 = 0x0302;
const TT_MICROPHONE: u16 = 0x0201;

// Default audio parameters
const DEFAULT_SAMPLE_RATE: u32 = 48000;
const DEFAULT_CHANNELS: u8 = 2;
const DEFAULT_BIT_DEPTH: u8 = 16;

// Volume range: UAC1 uses 1/256 dB units (signed 16-bit)
// 0x0000 = 0 dB, 0x8000 = -128 dB (silence), 0x7FFF = +127.996 dB
const VOLUME_SILENCE: i16 = -0x7FFF; // effectively mute
const VOLUME_0DB: i16 = 0;

// Maximum descriptor parse length
const MAX_DESC_LEN: usize = 512;

// ── Audio endpoint state ──

#[derive(Copy, Clone)]
struct AudioEndpoint {
    /// Endpoint address (bit 7 = direction: 0=OUT, 1=IN)
    ep_addr: u8,
    /// True if this endpoint is configured and active
    active: bool,
    /// Number of channels
    channels: u8,
    /// Bits per sample
    bit_depth: u8,
    /// Current sample rate in Hz
    sample_rate: u32,
    /// Maximum packet size for this endpoint
    max_packet_size: u16,
}

impl AudioEndpoint {
    const fn empty() -> Self {
        Self {
            ep_addr: 0,
            active: false,
            channels: DEFAULT_CHANNELS,
            bit_depth: DEFAULT_BIT_DEPTH,
            sample_rate: DEFAULT_SAMPLE_RATE,
            max_packet_size: 0,
        }
    }
}

// ── Feature Unit state ──

#[derive(Copy, Clone)]
struct FeatureUnit {
    /// Feature Unit ID (used in control requests)
    unit_id: u8,
    /// Audio Control interface number (used as wIndex low byte)
    iface_num: u8,
    /// True if the feature unit has mute control
    has_mute: bool,
    /// True if the feature unit has volume control
    has_volume: bool,
    /// Current mute state
    muted: bool,
    /// Current volume in 1/256 dB units
    volume_cur: i16,
    /// Minimum volume in 1/256 dB units
    volume_min: i16,
    /// Maximum volume in 1/256 dB units
    volume_max: i16,
    /// Volume resolution in 1/256 dB units
    volume_res: i16,
}

impl FeatureUnit {
    const fn empty() -> Self {
        Self {
            unit_id: 0,
            iface_num: 0,
            has_mute: false,
            has_volume: false,
            muted: false,
            volume_cur: VOLUME_0DB,
            volume_min: VOLUME_SILENCE,
            volume_max: VOLUME_0DB,
            volume_res: 1,
        }
    }
}

// ── Terminal info ──

#[derive(Copy, Clone)]
struct TerminalInfo {
    /// Terminal ID
    terminal_id: u8,
    /// Terminal type (TT_SPEAKER, TT_MICROPHONE, etc.)
    terminal_type: u16,
    /// Associated terminal ID (0 if none)
    assoc_terminal: u8,
    /// Number of channels
    num_channels: u8,
}

impl TerminalInfo {
    const fn empty() -> Self {
        Self {
            terminal_id: 0,
            terminal_type: 0,
            assoc_terminal: 0,
            num_channels: 0,
        }
    }
}

// ── Per-device state ──

const MAX_TERMINALS: usize = 4;
const MAX_FEATURE_UNITS: usize = 2;

struct AudioDevice {
    /// Whether this slot is in use
    attached: bool,
    /// Host-controller device handle
    dev_id: u32,
    /// Isochronous transfer callback
    isoc_fn: Option<IsocTransferFn>,
    /// Control transfer callback
    ctrl_fn: Option<ControlTransferFn>,
    /// Audio Control interface number
    ac_iface: u8,
    /// Output (playback) endpoint — isochronous OUT to speaker/headphone
    out_ep: AudioEndpoint,
    /// Input (capture) endpoint — isochronous IN from microphone
    in_ep: AudioEndpoint,
    /// Discovered input/output terminals
    terminals: [TerminalInfo; MAX_TERMINALS],
    num_terminals: usize,
    /// Feature units for volume/mute control
    feature_units: [FeatureUnit; MAX_FEATURE_UNITS],
    num_feature_units: usize,
}

impl AudioDevice {
    const fn empty() -> Self {
        Self {
            attached: false,
            dev_id: 0,
            isoc_fn: None,
            ctrl_fn: None,
            ac_iface: 0,
            out_ep: AudioEndpoint::empty(),
            in_ep: AudioEndpoint::empty(),
            terminals: [TerminalInfo::empty(); MAX_TERMINALS],
            num_terminals: 0,
            feature_units: [FeatureUnit::empty(); MAX_FEATURE_UNITS],
            num_feature_units: 0,
        }
    }
}

// ── Global state ──

struct DriverState {
    devices: [AudioDevice; MAX_DEVICES],
    initialised: bool,
}

impl DriverState {
    const fn new() -> Self {
        Self {
            devices: [AudioDevice::empty(), AudioDevice::empty()],
            initialised: false,
        }
    }
}

static STATE: StaticCell<DriverState> = StaticCell::new(DriverState::new());

// ── Byte-level helpers ──

fn get_le16(buf: &[u8], off: usize) -> u16 {
    (buf[off] as u16) | ((buf[off + 1] as u16) << 8)
}

fn put_le16(buf: &mut [u8], off: usize, val: u16) {
    buf[off] = val as u8;
    buf[off + 1] = (val >> 8) as u8;
}

fn put_le24(buf: &mut [u8], off: usize, val: u32) {
    buf[off] = val as u8;
    buf[off + 1] = (val >> 8) as u8;
    buf[off + 2] = (val >> 16) as u8;
}

// ── Device slot lookup ──

fn find_slot(state: &DriverState, dev_id: u32) -> Option<usize> {
    for i in 0..MAX_DEVICES {
        if state.devices[i].attached && state.devices[i].dev_id == dev_id {
            return Some(i);
        }
    }
    None
}

fn find_free_slot(state: &DriverState) -> Option<usize> {
    for i in 0..MAX_DEVICES {
        if !state.devices[i].attached {
            return Some(i);
        }
    }
    None
}

// ── Audio Control descriptor parsing ──

/// Parse Audio Control class-specific interface descriptors from raw
/// descriptor data.  Populates the device's terminal and feature unit lists.
///
/// UAC1 AC descriptors are CS_INTERFACE (type 0x24) with subtypes:
///   0x01 = HEADER
///   0x02 = INPUT_TERMINAL
///   0x03 = OUTPUT_TERMINAL
///   0x06 = FEATURE_UNIT
fn parse_ac_descriptors(dev: &mut AudioDevice, desc: &[u8]) {
    let len = desc.len();
    let mut off = 0;

    while off + 2 <= len {
        let blen = desc[off] as usize;
        if blen < 2 || off + blen > len {
            break;
        }

        let btype = desc[off + 1];

        // CS_INTERFACE descriptor type
        if btype == 0x24 && blen >= 3 {
            let subtype = desc[off + 2];

            match subtype {
                AC_INPUT_TERMINAL if blen >= 12 => {
                    if dev.num_terminals < MAX_TERMINALS {
                        let idx = dev.num_terminals;
                        dev.terminals[idx].terminal_id = desc[off + 3];
                        dev.terminals[idx].terminal_type = get_le16(desc, off + 4);
                        dev.terminals[idx].assoc_terminal = desc[off + 6];
                        dev.terminals[idx].num_channels = desc[off + 7];
                        dev.num_terminals += 1;

                        unsafe {
                            fut_printf(
                                b"usb_audio: input terminal id=%u type=0x%04x ch=%u\n\0".as_ptr(),
                                desc[off + 3] as u32,
                                get_le16(desc, off + 4) as u32,
                                desc[off + 7] as u32,
                            );
                        }
                    }
                }
                AC_OUTPUT_TERMINAL if blen >= 9 => {
                    if dev.num_terminals < MAX_TERMINALS {
                        let idx = dev.num_terminals;
                        dev.terminals[idx].terminal_id = desc[off + 3];
                        dev.terminals[idx].terminal_type = get_le16(desc, off + 4);
                        dev.terminals[idx].assoc_terminal = desc[off + 6];
                        dev.terminals[idx].num_channels = 0; // output terminal has no channel count
                        dev.num_terminals += 1;

                        unsafe {
                            fut_printf(
                                b"usb_audio: output terminal id=%u type=0x%04x\n\0".as_ptr(),
                                desc[off + 3] as u32,
                                get_le16(desc, off + 4) as u32,
                            );
                        }
                    }
                }
                AC_FEATURE_UNIT if blen >= 7 => {
                    if dev.num_feature_units < MAX_FEATURE_UNITS {
                        let idx = dev.num_feature_units;
                        dev.feature_units[idx].unit_id = desc[off + 3];
                        dev.feature_units[idx].iface_num = dev.ac_iface;

                        // Feature unit controls are in bmaControls starting at
                        // offset 6, each `bControlSize` bytes wide.  For UAC1,
                        // bControlSize is at offset 5.
                        let ctrl_size = desc[off + 5] as usize;
                        if ctrl_size > 0 && off + 6 + ctrl_size <= off + blen {
                            // Master channel controls are at offset 6
                            let ctrl0 = desc[off + 6];
                            dev.feature_units[idx].has_mute = (ctrl0 & 0x01) != 0;
                            dev.feature_units[idx].has_volume = (ctrl0 & 0x02) != 0;
                        }

                        dev.num_feature_units += 1;

                        unsafe {
                            fut_printf(
                                b"usb_audio: feature unit id=%u mute=%u vol=%u\n\0".as_ptr(),
                                desc[off + 3] as u32,
                                dev.feature_units[idx].has_mute as u32,
                                dev.feature_units[idx].has_volume as u32,
                            );
                        }
                    }
                }
                _ => {}
            }
        }

        off += blen;
    }
}

// ── Control request helpers ──

/// Send a SET_CUR control request to a Feature Unit.
/// `cs` is the control selector (FU_MUTE_CONTROL, FU_VOLUME_CONTROL).
/// `channel` is the channel number (0 = master).
fn feature_unit_set_cur(
    dev: &AudioDevice,
    fu: &FeatureUnit,
    cs: u8,
    channel: u8,
    data: &mut [u8],
) -> i32 {
    let ctrl_fn = match dev.ctrl_fn {
        Some(f) => f,
        None => return -1,
    };

    // wValue: control selector (high byte) | channel number (low byte)
    let w_value = ((cs as u16) << 8) | (channel as u16);
    // wIndex: feature unit ID (high byte) | interface number (low byte)
    let w_index = ((fu.unit_id as u16) << 8) | (fu.iface_num as u16);

    unsafe {
        (ctrl_fn)(
            dev.dev_id,
            RT_CLASS_IFACE_OUT,
            SET_CUR,
            w_value,
            w_index,
            data.as_mut_ptr(),
            data.len() as u16,
        )
    }
}

/// Send a GET_CUR control request to a Feature Unit.
fn feature_unit_get_cur(
    dev: &AudioDevice,
    fu: &FeatureUnit,
    cs: u8,
    channel: u8,
    data: &mut [u8],
) -> i32 {
    let ctrl_fn = match dev.ctrl_fn {
        Some(f) => f,
        None => return -1,
    };

    let w_value = ((cs as u16) << 8) | (channel as u16);
    let w_index = ((fu.unit_id as u16) << 8) | (fu.iface_num as u16);

    unsafe {
        (ctrl_fn)(
            dev.dev_id,
            RT_CLASS_IFACE_IN,
            GET_CUR,
            w_value,
            w_index,
            data.as_mut_ptr(),
            data.len() as u16,
        )
    }
}

/// Send a GET request (GET_MIN, GET_MAX, GET_RES) to a Feature Unit.
fn feature_unit_get(
    dev: &AudioDevice,
    fu: &FeatureUnit,
    req: u8,
    cs: u8,
    channel: u8,
    data: &mut [u8],
) -> i32 {
    let ctrl_fn = match dev.ctrl_fn {
        Some(f) => f,
        None => return -1,
    };

    let w_value = ((cs as u16) << 8) | (channel as u16);
    let w_index = ((fu.unit_id as u16) << 8) | (fu.iface_num as u16);

    unsafe {
        (ctrl_fn)(
            dev.dev_id,
            RT_CLASS_IFACE_IN,
            req,
            w_value,
            w_index,
            data.as_mut_ptr(),
            data.len() as u16,
        )
    }
}

// ── Sample rate configuration ──

/// Set the sample rate on an audio streaming endpoint via SET_CUR.
/// UAC1 sample rate is a 3-byte LE value sent to the endpoint with
/// bRequest=SET_CUR, wValue=0x0100 (sampling freq control), wIndex=ep_addr.
fn set_endpoint_sample_rate(dev: &AudioDevice, ep_addr: u8, rate: u32) -> i32 {
    let ctrl_fn = match dev.ctrl_fn {
        Some(f) => f,
        None => return -1,
    };

    // Sampling frequency control selector = 0x01, channel = 0x00
    let w_value: u16 = 0x0100;
    let w_index: u16 = ep_addr as u16;

    let mut buf = [0u8; 3];
    put_le24(&mut buf, 0, rate);

    unsafe {
        (ctrl_fn)(
            dev.dev_id,
            RT_CLASS_EP_OUT,
            SET_CUR,
            w_value,
            w_index,
            buf.as_mut_ptr(),
            3,
        )
    }
}

// ── Volume control helpers ──

/// Query the volume range (min, max, resolution) from a feature unit and
/// cache the results in the FeatureUnit struct.
fn query_volume_range(dev: &AudioDevice, fu: &mut FeatureUnit) -> i32 {
    if !fu.has_volume {
        return -1;
    }

    let mut buf = [0u8; 2];

    // GET_MIN
    let ret = feature_unit_get(dev, fu, GET_MIN, FU_VOLUME_CONTROL, 0, &mut buf);
    if ret >= 0 {
        fu.volume_min = get_le16(&buf, 0) as i16;
    }

    // GET_MAX
    let ret = feature_unit_get(dev, fu, GET_MAX, FU_VOLUME_CONTROL, 0, &mut buf);
    if ret >= 0 {
        fu.volume_max = get_le16(&buf, 0) as i16;
    }

    // GET_RES
    let ret = feature_unit_get(dev, fu, GET_RES, FU_VOLUME_CONTROL, 0, &mut buf);
    if ret >= 0 {
        fu.volume_res = get_le16(&buf, 0) as i16;
        if fu.volume_res == 0 {
            fu.volume_res = 1;
        }
    }

    // GET_CUR
    let ret = feature_unit_get_cur(dev, fu, FU_VOLUME_CONTROL, 0, &mut buf);
    if ret >= 0 {
        fu.volume_cur = get_le16(&buf, 0) as i16;
    }

    unsafe {
        fut_printf(
            b"usb_audio: volume range min=%d max=%d res=%d cur=%d (1/256 dB)\n\0".as_ptr(),
            fu.volume_min as i32,
            fu.volume_max as i32,
            fu.volume_res as i32,
            fu.volume_cur as i32,
        );
    }

    0
}

/// Convert a percentage (0-100) to a UAC1 volume value in 1/256 dB units,
/// linearly interpolating between the feature unit's min and max.
fn pct_to_volume(fu: &FeatureUnit, pct: u32) -> i16 {
    let pct = if pct > 100 { 100 } else { pct };
    if pct == 0 {
        return fu.volume_min;
    }
    if pct == 100 {
        return fu.volume_max;
    }

    let range = (fu.volume_max as i32) - (fu.volume_min as i32);
    let val = (fu.volume_min as i32) + (range * pct as i32) / 100;

    // Snap to resolution grid
    let res = fu.volume_res as i32;
    if res > 0 {
        let offset = val - (fu.volume_min as i32);
        let snapped = (offset / res) * res + (fu.volume_min as i32);
        snapped as i16
    } else {
        val as i16
    }
}

// ── FFI exports ──

/// Initialise the USB Audio Class driver.
/// Must be called once before any attach/detach/control calls.
/// Returns 0 on success.
#[unsafe(no_mangle)]
pub extern "C" fn usb_audio_init() -> i32 {
    let state = unsafe { &mut *STATE.get() };
    if state.initialised {
        log("usb_audio: already initialised");
        return 0;
    }

    state.devices[0] = AudioDevice::empty();
    state.devices[1] = AudioDevice::empty();
    state.initialised = true;

    log("usb_audio: driver initialised (UAC1, max 2 devices)");
    0
}

/// Attach a USB audio device.
///
/// `dev_id`  -- host-controller device identifier
/// `isoc_fn` -- isochronous transfer callback
/// `ctrl_fn` -- control transfer callback
///
/// After attachment the caller should provide Audio Control descriptors via
/// `usb_audio_parse_ac_desc` and configure endpoints via
/// `usb_audio_set_out_ep` / `usb_audio_set_in_ep`.
///
/// Returns 0 on success, negative on error.
#[unsafe(no_mangle)]
pub extern "C" fn usb_audio_attach(
    dev_id: u32,
    isoc_fn: IsocTransferFn,
    ctrl_fn: ControlTransferFn,
) -> i32 {
    let state = unsafe { &mut *STATE.get() };
    if !state.initialised {
        log("usb_audio: not initialised");
        return -1;
    }

    if find_slot(state, dev_id).is_some() {
        unsafe {
            fut_printf(
                b"usb_audio: device %u already attached\n\0".as_ptr(),
                dev_id,
            );
        }
        return -2;
    }

    let slot = match find_free_slot(state) {
        Some(s) => s,
        None => {
            log("usb_audio: no free device slots");
            return -3;
        }
    };

    let dev = &mut state.devices[slot];
    *dev = AudioDevice::empty();
    dev.attached = true;
    dev.dev_id = dev_id;
    dev.isoc_fn = Some(isoc_fn);
    dev.ctrl_fn = Some(ctrl_fn);

    unsafe {
        fut_printf(
            b"usb_audio: attached device %u to slot %u\n\0".as_ptr(),
            dev_id,
            slot as u32,
        );
    }

    0
}

/// Detach a USB audio device.
///
/// `dev_id` -- host-controller device identifier as passed to `usb_audio_attach`.
///
/// Returns 0 on success, negative if the device was not found.
#[unsafe(no_mangle)]
pub extern "C" fn usb_audio_detach(dev_id: u32) -> i32 {
    let state = unsafe { &mut *STATE.get() };
    let slot = match find_slot(state, dev_id) {
        Some(s) => s,
        None => {
            unsafe {
                fut_printf(
                    b"usb_audio: detach: device %u not found\n\0".as_ptr(),
                    dev_id,
                );
            }
            return -1;
        }
    };

    state.devices[slot] = AudioDevice::empty();

    unsafe {
        fut_printf(
            b"usb_audio: detached device %u from slot %u\n\0".as_ptr(),
            dev_id,
            slot as u32,
        );
    }

    0
}

/// Provide Audio Control class-specific descriptors for parsing.
///
/// `dev_id`   -- device identifier
/// `desc`     -- pointer to raw descriptor bytes
/// `desc_len` -- length of descriptor data
/// `ac_iface` -- Audio Control interface number
///
/// Returns 0 on success, negative on error.
#[unsafe(no_mangle)]
pub extern "C" fn usb_audio_parse_ac_desc(
    dev_id: u32,
    desc: *const u8,
    desc_len: u32,
    ac_iface: u8,
) -> i32 {
    if desc.is_null() || desc_len == 0 {
        return -1;
    }

    let state = unsafe { &mut *STATE.get() };
    let slot = match find_slot(state, dev_id) {
        Some(s) => s,
        None => return -1,
    };

    let dev = &mut state.devices[slot];
    dev.ac_iface = ac_iface;

    let len = (desc_len as usize).min(MAX_DESC_LEN);
    let desc_slice = unsafe { core::slice::from_raw_parts(desc, len) };
    parse_ac_descriptors(dev, desc_slice);

    // Query volume range from first feature unit that supports it
    for i in 0..dev.num_feature_units {
        if dev.feature_units[i].has_volume {
            // Need to copy out, query, then copy back due to borrowing
            let mut fu = dev.feature_units[i];
            let _ = query_volume_range(dev, &mut fu);
            dev.feature_units[i] = fu;
        }
    }

    0
}

/// Configure the playback (output) isochronous endpoint.
///
/// `dev_id`         -- device identifier
/// `ep_addr`        -- endpoint address (e.g. 0x01 for OUT)
/// `channels`       -- number of audio channels (1=mono, 2=stereo)
/// `bit_depth`      -- bits per sample (typically 16)
/// `max_packet_size` -- maximum packet size reported by the endpoint descriptor
///
/// Returns 0 on success, negative on error.
#[unsafe(no_mangle)]
pub extern "C" fn usb_audio_set_out_ep(
    dev_id: u32,
    ep_addr: u8,
    channels: u8,
    bit_depth: u8,
    max_packet_size: u16,
) -> i32 {
    let state = unsafe { &mut *STATE.get() };
    let slot = match find_slot(state, dev_id) {
        Some(s) => s,
        None => return -1,
    };

    let dev = &mut state.devices[slot];
    dev.out_ep.ep_addr = ep_addr & 0x0F; // ensure OUT direction (bit 7 = 0)
    dev.out_ep.active = true;
    dev.out_ep.channels = channels;
    dev.out_ep.bit_depth = bit_depth;
    dev.out_ep.max_packet_size = max_packet_size;

    unsafe {
        fut_printf(
            b"usb_audio: out ep=0x%02x ch=%u bits=%u maxpkt=%u\n\0".as_ptr(),
            dev.out_ep.ep_addr as u32,
            channels as u32,
            bit_depth as u32,
            max_packet_size as u32,
        );
    }

    0
}

/// Configure the capture (input) isochronous endpoint.
///
/// `dev_id`         -- device identifier
/// `ep_addr`        -- endpoint address (e.g. 0x82 for IN)
/// `channels`       -- number of audio channels
/// `bit_depth`      -- bits per sample
/// `max_packet_size` -- maximum packet size reported by the endpoint descriptor
///
/// Returns 0 on success, negative on error.
#[unsafe(no_mangle)]
pub extern "C" fn usb_audio_set_in_ep(
    dev_id: u32,
    ep_addr: u8,
    channels: u8,
    bit_depth: u8,
    max_packet_size: u16,
) -> i32 {
    let state = unsafe { &mut *STATE.get() };
    let slot = match find_slot(state, dev_id) {
        Some(s) => s,
        None => return -1,
    };

    let dev = &mut state.devices[slot];
    dev.in_ep.ep_addr = ep_addr | 0x80; // ensure IN direction (bit 7 = 1)
    dev.in_ep.active = true;
    dev.in_ep.channels = channels;
    dev.in_ep.bit_depth = bit_depth;
    dev.in_ep.max_packet_size = max_packet_size;

    unsafe {
        fut_printf(
            b"usb_audio: in ep=0x%02x ch=%u bits=%u maxpkt=%u\n\0".as_ptr(),
            dev.in_ep.ep_addr as u32,
            channels as u32,
            bit_depth as u32,
            max_packet_size as u32,
        );
    }

    0
}

/// Set the sample rate for the audio device.
///
/// Configures both the playback and capture endpoints (if active) to the
/// requested sample rate via SET_CUR to the endpoint.
///
/// `dev_id` -- device identifier
/// `rate`   -- sample rate in Hz (e.g. 44100, 48000)
///
/// Returns 0 on success, negative on error.
#[unsafe(no_mangle)]
pub extern "C" fn usb_audio_set_sample_rate(dev_id: u32, rate: u32) -> i32 {
    let state = unsafe { &mut *STATE.get() };
    let slot = match find_slot(state, dev_id) {
        Some(s) => s,
        None => return -1,
    };

    let dev = &mut state.devices[slot];

    if dev.out_ep.active {
        let ret = set_endpoint_sample_rate(dev, dev.out_ep.ep_addr, rate);
        if ret < 0 {
            unsafe {
                fut_printf(
                    b"usb_audio: failed to set OUT ep sample rate: %d\n\0".as_ptr(),
                    ret,
                );
            }
            return ret;
        }
        dev.out_ep.sample_rate = rate;
    }

    if dev.in_ep.active {
        let ret = set_endpoint_sample_rate(dev, dev.in_ep.ep_addr, rate);
        if ret < 0 {
            unsafe {
                fut_printf(
                    b"usb_audio: failed to set IN ep sample rate: %d\n\0".as_ptr(),
                    ret,
                );
            }
            return ret;
        }
        dev.in_ep.sample_rate = rate;
    }

    unsafe {
        fut_printf(
            b"usb_audio: sample rate set to %u Hz\n\0".as_ptr(),
            rate,
        );
    }

    0
}

/// Set the playback volume as a percentage (0-100).
///
/// The percentage is linearly mapped to the device's reported volume range
/// (GET_MIN..GET_MAX) in 1/256 dB units.
///
/// `dev_id` -- device identifier
/// `pct`    -- volume percentage (0 = minimum/silence, 100 = maximum)
///
/// Returns 0 on success, negative on error.
#[unsafe(no_mangle)]
pub extern "C" fn usb_audio_set_volume(dev_id: u32, pct: u32) -> i32 {
    let state = unsafe { &mut *STATE.get() };
    let slot = match find_slot(state, dev_id) {
        Some(s) => s,
        None => return -1,
    };

    let dev = &mut state.devices[slot];

    // Find first feature unit with volume control
    let fu_idx = {
        let mut found = None;
        for i in 0..dev.num_feature_units {
            if dev.feature_units[i].has_volume {
                found = Some(i);
                break;
            }
        }
        match found {
            Some(i) => i,
            None => {
                log("usb_audio: no feature unit with volume control");
                return -1;
            }
        }
    };

    let vol = pct_to_volume(&dev.feature_units[fu_idx], pct);

    let mut buf = [0u8; 2];
    put_le16(&mut buf, 0, vol as u16);

    let fu = dev.feature_units[fu_idx];
    let ret = feature_unit_set_cur(dev, &fu, FU_VOLUME_CONTROL, 0, &mut buf);
    if ret < 0 {
        unsafe {
            fut_printf(
                b"usb_audio: SET_CUR volume failed: %d\n\0".as_ptr(),
                ret,
            );
        }
        return ret;
    }

    dev.feature_units[fu_idx].volume_cur = vol;

    unsafe {
        fut_printf(
            b"usb_audio: volume set to %u%% (%d/256 dB)\n\0".as_ptr(),
            pct,
            vol as i32,
        );
    }

    0
}

/// Set the mute state for the audio device.
///
/// `dev_id` -- device identifier
/// `muted`  -- true to mute, false to unmute
///
/// Returns 0 on success, negative on error.
#[unsafe(no_mangle)]
pub extern "C" fn usb_audio_set_mute(dev_id: u32, muted: bool) -> i32 {
    let state = unsafe { &mut *STATE.get() };
    let slot = match find_slot(state, dev_id) {
        Some(s) => s,
        None => return -1,
    };

    let dev = &mut state.devices[slot];

    // Find first feature unit with mute control
    let fu_idx = {
        let mut found = None;
        for i in 0..dev.num_feature_units {
            if dev.feature_units[i].has_mute {
                found = Some(i);
                break;
            }
        }
        match found {
            Some(i) => i,
            None => {
                log("usb_audio: no feature unit with mute control");
                return -1;
            }
        }
    };

    let mut buf = [if muted { 1u8 } else { 0u8 }];

    let fu = dev.feature_units[fu_idx];
    let ret = feature_unit_set_cur(dev, &fu, FU_MUTE_CONTROL, 0, &mut buf);
    if ret < 0 {
        unsafe {
            fut_printf(
                b"usb_audio: SET_CUR mute failed: %d\n\0".as_ptr(),
                ret,
            );
        }
        return ret;
    }

    dev.feature_units[fu_idx].muted = muted;

    unsafe {
        fut_printf(
            b"usb_audio: mute %s\n\0".as_ptr(),
            if muted { b"on\0".as_ptr() } else { b"off\0".as_ptr() },
        );
    }

    0
}

/// Write PCM audio samples to the playback (OUT) isochronous endpoint.
///
/// `dev_id` -- device identifier
/// `data`   -- pointer to PCM sample data (interleaved, little-endian)
/// `len`    -- number of bytes to write
///
/// Data is sent in chunks no larger than the endpoint's maximum packet size.
/// Returns total bytes written on success, negative on error.
#[unsafe(no_mangle)]
pub extern "C" fn usb_audio_write_samples(dev_id: u32, data: *const u8, len: u32) -> i32 {
    if data.is_null() || len == 0 {
        return -1;
    }

    let state = unsafe { &mut *STATE.get() };
    let slot = match find_slot(state, dev_id) {
        Some(s) => s,
        None => return -1,
    };

    let dev = &mut state.devices[slot];

    if !dev.out_ep.active {
        log("usb_audio: playback endpoint not configured");
        return -1;
    }

    let isoc_fn = match dev.isoc_fn {
        Some(f) => f,
        None => return -1,
    };

    let ep = dev.out_ep.ep_addr;
    let max_pkt = if dev.out_ep.max_packet_size > 0 {
        dev.out_ep.max_packet_size as u32
    } else {
        // Default: one millisecond of audio at current format
        let bytes_per_sample = (dev.out_ep.bit_depth as u32 / 8) * dev.out_ep.channels as u32;
        let frames_per_ms = dev.out_ep.sample_rate / 1000;
        frames_per_ms * bytes_per_sample
    };

    if max_pkt == 0 {
        return -1;
    }

    let mut offset: u32 = 0;
    let mut total_sent: i32 = 0;

    while offset < len {
        let chunk = if len - offset > max_pkt { max_pkt } else { len - offset };

        // Isochronous transfers use the data pointer directly; cast away const
        // since the callback type uses *mut u8 (common for both IN and OUT).
        let buf_ptr = unsafe { (data as *mut u8).add(offset as usize) };

        let ret = unsafe { (isoc_fn)(dev.dev_id, ep, buf_ptr, chunk) };
        if ret < 0 {
            if total_sent > 0 {
                return total_sent;
            }
            return ret;
        }

        offset += chunk;
        total_sent += ret;
    }

    total_sent
}

/// Read PCM audio samples from the capture (IN) isochronous endpoint.
///
/// `dev_id`  -- device identifier
/// `buf`     -- pointer to receive buffer
/// `max_len` -- maximum number of bytes to read
///
/// Returns number of bytes read on success, negative on error.
/// May return fewer bytes than `max_len` if less data is available.
#[unsafe(no_mangle)]
pub extern "C" fn usb_audio_read_samples(dev_id: u32, buf: *mut u8, max_len: u32) -> i32 {
    if buf.is_null() || max_len == 0 {
        return -1;
    }

    let state = unsafe { &mut *STATE.get() };
    let slot = match find_slot(state, dev_id) {
        Some(s) => s,
        None => return -1,
    };

    let dev = &mut state.devices[slot];

    if !dev.in_ep.active {
        log("usb_audio: capture endpoint not configured");
        return -1;
    }

    let isoc_fn = match dev.isoc_fn {
        Some(f) => f,
        None => return -1,
    };

    let ep = dev.in_ep.ep_addr;
    let max_pkt = if dev.in_ep.max_packet_size > 0 {
        dev.in_ep.max_packet_size as u32
    } else {
        let bytes_per_sample = (dev.in_ep.bit_depth as u32 / 8) * dev.in_ep.channels as u32;
        let frames_per_ms = dev.in_ep.sample_rate / 1000;
        frames_per_ms * bytes_per_sample
    };

    if max_pkt == 0 {
        return -1;
    }

    let mut offset: u32 = 0;
    let mut total_read: i32 = 0;

    while offset < max_len {
        let chunk = if max_len - offset > max_pkt {
            max_pkt
        } else {
            max_len - offset
        };

        let buf_ptr = unsafe { buf.add(offset as usize) };

        let ret = unsafe { (isoc_fn)(dev.dev_id, ep, buf_ptr, chunk) };
        if ret < 0 {
            if total_read > 0 {
                return total_read;
            }
            return ret;
        }
        if ret == 0 {
            // No more data available
            break;
        }

        offset += ret as u32;
        total_read += ret;
    }

    total_read
}
