// SPDX-License-Identifier: MPL-2.0
//
// Intel HDMI/DisplayPort Audio Codec Driver for HDA
//
// Codec-level driver that works with the HDA controller driver to program
// Intel HDMI/DisplayPort audio codecs found on Intel integrated graphics.
//
// Supported codecs (vendor 0x8086):
//   - 0x2805  (KBL)
//   - 0x280B  (ICL)
//   - 0x2812  (TGL/ADL)
//   - 0x2816  (RPL)
//   - 0x8020  (Gen generic)
//
// Architecture:
//   - Communicates with the HDA controller via a verb callback function
//   - Discovers HDMI/DP pin widgets and digital converter widgets
//   - Reads ELD (EDID-Like Data) from connected monitors
//   - Programs Audio InfoFrames for HDMI/DP output
//   - Manages digital converter enable and stream assignment
//   - Supports hot-plug detect via pin sense polling

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(unexpected_cfgs)]

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
    const fn new(val: T) -> Self { Self(UnsafeCell::new(val)) }
    fn get(&self) -> *mut T { self.0.get() }
}

// ── HDA verb callback type ──

/// Verb function provided by the HDA controller driver.
/// Sends a verb to a codec and returns the 32-bit response.
///   codec: codec address (0-14)
///   nid:   node ID (0-127)
///   verb:  20-bit verb + payload
type HdaVerbFn = unsafe extern "C" fn(codec: u8, nid: u16, verb: u32) -> u32;

// ── HDA Codec Verbs (Intel HDA Spec Rev 1.0a, Section 7) ──

// GET verbs (12-bit verb ID)
const VERB_GET_PARAMETER: u32         = 0xF0000;
const VERB_GET_CONN_SELECT: u32       = 0xF0100;
const VERB_GET_CONN_LIST: u32         = 0xF0200;
const VERB_GET_PIN_WIDGET_CTL: u32    = 0xF0700;
const VERB_GET_PIN_SENSE: u32         = 0xF0900;
const VERB_GET_CONFIG_DEFAULT: u32    = 0xF1C00;
const VERB_GET_POWER_STATE: u32       = 0xF0500;
const VERB_GET_DIGI_CONVERT: u32      = 0xF0D00;

// SET verbs (4-bit verb ID, 8-bit or 16-bit payload)
const VERB_SET_PIN_WIDGET_CTL: u32    = 0x70700;
const VERB_SET_CONN_SELECT: u32       = 0x70100;
const VERB_SET_POWER_STATE: u32       = 0x70500;
const VERB_SET_CHANNEL_STREAM_ID: u32 = 0x70600;
const VERB_SET_DIGI_CONVERT_1: u32    = 0x70D00;
const VERB_SET_DIGI_CONVERT_2: u32    = 0x70E00;
const VERB_SET_CONVERTER_FORMAT: u32  = 0x20000;

// HDMI-specific verbs
const VERB_GET_HDMI_DIP_SIZE: u32     = 0xF1300;
const VERB_SET_HDMI_DIP_INDEX: u32    = 0x73000;
const VERB_SET_HDMI_DIP_DATA: u32     = 0x73100;
const VERB_SET_HDMI_DIP_XMIT: u32    = 0x73200;

// ELD verbs
const VERB_GET_HDMI_ELD_DATA: u32     = 0xF2E00;

// Parameter IDs (used with GET_PARAMETER)
const PARAM_VENDOR_ID: u32            = 0x00;
const PARAM_REVISION_ID: u32          = 0x02;
const PARAM_SUB_NODE_COUNT: u32       = 0x04;
const PARAM_FUNC_GROUP_TYPE: u32      = 0x05;
const PARAM_AUDIO_WIDGET_CAP: u32     = 0x09;
const PARAM_PIN_CAPS: u32             = 0x0C;
const PARAM_CONN_LIST_LEN: u32        = 0x0E;

// Widget types (from Audio Widget Capabilities parameter, bits 23:20)
const WIDGET_TYPE_AUDIO_OUTPUT: u8    = 0x0;
const WIDGET_TYPE_PIN_COMPLEX: u8     = 0x4;

// Pin widget control bits
const PIN_CTL_OUT_EN: u8              = 1 << 6;

// Pin sense bits
const PIN_SENSE_PRESENCE: u32         = 1 << 31;
const PIN_SENSE_ELD_VALID: u32        = 1 << 30;

// Pin capabilities bits
const PIN_CAP_HDMI: u32              = 1 << 7;  // HDMI capable
const PIN_CAP_DP: u32                = 1 << 24;  // DisplayPort capable

// Digital converter control bits (SET_DIGI_CONVERT_1)
const DIGI_ENABLE: u8                = 1 << 0;   // Digital enable
const DIGI_VALIDITY: u8              = 1 << 1;   // Validity flag
const DIGI_DIGEN: u8                 = 1 << 4;   // Digital out enable

// HDMI DIP transmit control
const DIP_XMIT_DISABLE: u8          = 0x00;
const DIP_XMIT_ONCE: u8             = 0x01;
const DIP_XMIT_BEST: u8             = 0x02;

// Audio InfoFrame constants (CEA-861)
const AUDIO_INFOFRAME_TYPE: u8       = 0x84;
const AUDIO_INFOFRAME_VER: u8        = 0x01;
const AUDIO_INFOFRAME_LEN: u8        = 0x0A;

// Pin configuration default: default device field (bits 23:20)
const PIN_DEV_DIGITAL_OTHER: u8      = 0x03;
const PIN_DEV_HDMI: u8               = 0x08;

// ── Intel vendor/device IDs ──

const INTEL_VENDOR_ID: u16           = 0x8086;

const INTEL_HDMI_ICL: u16            = 0x280B;
const INTEL_HDMI_GEN: u16            = 0x8020;
const INTEL_HDMI_TGL: u16            = 0x2812;
const INTEL_HDMI_RPL: u16            = 0x2816;
const INTEL_HDMI_KBL: u16            = 0x2805;

// ── Data structures ──

const MAX_PINS: usize     = 8;
const MAX_CVTS: usize     = 8;
const MAX_CONN: usize     = 8;
const MAX_ELD: usize      = 128;

/// An HDMI/DP pin widget.
#[derive(Clone, Copy)]
struct HdmiPin {
    nid: u16,
    pin_caps: u32,
    config_default: u32,
    /// Assigned converter NID (0 = none).
    cvt_nid: u16,
    /// Connection list: converter NIDs this pin can be connected to.
    conn_list_len: u8,
    conn_list: [u16; MAX_CONN],
    /// Cached ELD data.
    eld: [u8; MAX_ELD],
    eld_len: u8,
    /// True if HDMI (vs. DisplayPort).
    is_hdmi: bool,
}

impl HdmiPin {
    const fn zeroed() -> Self {
        Self {
            nid: 0,
            pin_caps: 0,
            config_default: 0,
            cvt_nid: 0,
            conn_list_len: 0,
            conn_list: [0; MAX_CONN],
            eld: [0; MAX_ELD],
            eld_len: 0,
            is_hdmi: false,
        }
    }
}

/// A digital audio converter widget.
#[derive(Clone, Copy)]
struct HdmiCvt {
    nid: u16,
    caps: u32,
}

impl HdmiCvt {
    const fn zeroed() -> Self {
        Self { nid: 0, caps: 0 }
    }
}

/// Per-codec driver state.
struct IntelHdmiCodec {
    initialised: bool,
    verb_fn: Option<HdaVerbFn>,
    codec_addr: u8,

    // Identification
    vendor_id: u16,
    device_id: u16,
    revision: u32,

    // Audio function group
    afg_nid: u16,

    // HDMI/DP pins
    pins: [HdmiPin; MAX_PINS],
    num_pins: usize,

    // Digital converters
    cvts: [HdmiCvt; MAX_CVTS],
    num_cvts: usize,
}

impl IntelHdmiCodec {
    const fn new() -> Self {
        Self {
            initialised: false,
            verb_fn: None,
            codec_addr: 0,
            vendor_id: 0,
            device_id: 0,
            revision: 0,
            afg_nid: 0,
            pins: [HdmiPin::zeroed(); MAX_PINS],
            num_pins: 0,
            cvts: [HdmiCvt::zeroed(); MAX_CVTS],
            num_cvts: 0,
        }
    }
}

static STATE: StaticCell<IntelHdmiCodec> = StaticCell::new(IntelHdmiCodec::new());

// ── Helper: send verb through callback ──

fn send_verb(codec: &IntelHdmiCodec, nid: u16, verb: u32) -> u32 {
    match codec.verb_fn {
        Some(f) => unsafe { f(codec.codec_addr, nid, verb) },
        None => 0xFFFFFFFF,
    }
}

fn get_param(codec: &IntelHdmiCodec, nid: u16, param: u32) -> u32 {
    send_verb(codec, nid, VERB_GET_PARAMETER | (param & 0xFF))
}

// ── Pin config parsing helpers ──

fn pin_connectivity(cfg: u32) -> u8 {
    ((cfg >> 30) & 0x03) as u8
}

fn pin_default_device(cfg: u32) -> u8 {
    ((cfg >> 20) & 0x0F) as u8
}

/// Returns true if this pin's default device is HDMI or digital-other.
fn pin_is_digital_out(cfg: u32) -> bool {
    let dev = pin_default_device(cfg);
    dev == PIN_DEV_HDMI || dev == PIN_DEV_DIGITAL_OTHER
}

// ── Codec detection ──

fn detect_codec(codec: &mut IntelHdmiCodec) -> bool {
    let vendor_device = get_param(codec, 0, PARAM_VENDOR_ID);
    if vendor_device == 0 || vendor_device == 0xFFFFFFFF {
        log("intel_hda_hdmi: no response from codec");
        return false;
    }

    codec.vendor_id = ((vendor_device >> 16) & 0xFFFF) as u16;
    codec.device_id = (vendor_device & 0xFFFF) as u16;
    codec.revision = get_param(codec, 0, PARAM_REVISION_ID);

    if codec.vendor_id != INTEL_VENDOR_ID {
        unsafe {
            fut_printf(
                b"intel_hda_hdmi: not an Intel codec (vendor=0x%04x)\n\0".as_ptr(),
                codec.vendor_id as u32,
            );
        }
        return false;
    }

    let name = codec_name(codec.device_id);
    unsafe {
        fut_printf(
            b"intel_hda_hdmi: detected %s (0x%04x) rev 0x%08x\n\0".as_ptr(),
            name.as_ptr(),
            codec.device_id as u32,
            codec.revision,
        );
    }

    true
}

/// Return a static C-string name for known Intel HDMI/DP codec models.
fn codec_name(device_id: u16) -> &'static [u8] {
    match device_id {
        INTEL_HDMI_KBL => b"Intel Kaby Lake HDMI\0",
        INTEL_HDMI_ICL => b"Intel Ice Lake HDMI\0",
        INTEL_HDMI_GEN => b"Intel Generic HDMI\0",
        INTEL_HDMI_TGL => b"Intel Tiger Lake HDMI\0",
        INTEL_HDMI_RPL => b"Intel Raptor Lake HDMI\0",
        _              => b"Intel HDMI/DP\0",
    }
}

// ── Widget enumeration ──

fn enumerate_widgets(codec: &mut IntelHdmiCodec) {
    // Find Audio Function Group from root node
    let sub = get_param(codec, 0, PARAM_SUB_NODE_COUNT);
    let start_nid = ((sub >> 16) & 0xFF) as u16;
    let num_nodes = (sub & 0xFF) as u16;

    codec.afg_nid = 0;
    for i in 0..num_nodes {
        let nid = start_nid + i;
        let ftype = get_param(codec, nid, PARAM_FUNC_GROUP_TYPE);
        if (ftype & 0xFF) == 0x01 {
            codec.afg_nid = nid;
            // Power on the AFG (D0)
            send_verb(codec, nid, VERB_SET_POWER_STATE | 0x00);
            break;
        }
    }

    if codec.afg_nid == 0 {
        log("intel_hda_hdmi: no Audio Function Group found");
        return;
    }

    unsafe {
        fut_printf(
            b"intel_hda_hdmi: AFG at NID 0x%02x\n\0".as_ptr(),
            codec.afg_nid as u32,
        );
    }

    // Enumerate subordinate widgets under AFG
    let afg_sub = get_param(codec, codec.afg_nid, PARAM_SUB_NODE_COUNT);
    let w_start = ((afg_sub >> 16) & 0xFF) as u16;
    let w_count = (afg_sub & 0xFF) as u16;

    codec.num_pins = 0;
    codec.num_cvts = 0;

    for i in 0..w_count {
        let nid = w_start + i;
        let caps = get_param(codec, nid, PARAM_AUDIO_WIDGET_CAP);
        let wtype = ((caps >> 20) & 0x0F) as u8;

        // Power on each widget (D0)
        send_verb(codec, nid, VERB_SET_POWER_STATE | 0x00);

        match wtype {
            WIDGET_TYPE_PIN_COMPLEX => {
                if codec.num_pins >= MAX_PINS {
                    continue;
                }

                let pin_caps = get_param(codec, nid, PARAM_PIN_CAPS);
                let config_default = send_verb(codec, nid, VERB_GET_CONFIG_DEFAULT);

                // Accept pins that are HDMI/DP capable or configured as digital out
                let is_hdmi_cap = (pin_caps & PIN_CAP_HDMI) != 0;
                let is_dp_cap = (pin_caps & PIN_CAP_DP) != 0;
                let is_digital = pin_is_digital_out(config_default);

                if !is_hdmi_cap && !is_dp_cap && !is_digital {
                    continue;
                }

                let mut pin = HdmiPin::zeroed();
                pin.nid = nid;
                pin.pin_caps = pin_caps;
                pin.config_default = config_default;
                pin.is_hdmi = is_hdmi_cap && !is_dp_cap;

                // Read connection list
                let conn_len_raw = get_param(codec, nid, PARAM_CONN_LIST_LEN);
                let long_form = (conn_len_raw >> 7) & 1 != 0;
                let conn_len = (conn_len_raw & 0x7F) as u8;
                pin.conn_list_len = if (conn_len as usize) > MAX_CONN {
                    MAX_CONN as u8
                } else {
                    conn_len
                };

                if pin.conn_list_len > 0 {
                    if long_form {
                        let mut idx = 0u8;
                        while idx < pin.conn_list_len {
                            let offset = idx as u32;
                            let resp = send_verb(codec, nid, VERB_GET_CONN_LIST | offset);
                            pin.conn_list[idx as usize] = (resp & 0xFFFF) as u16;
                            idx += 1;
                            if idx < pin.conn_list_len {
                                pin.conn_list[idx as usize] = ((resp >> 16) & 0xFFFF) as u16;
                                idx += 1;
                            }
                        }
                    } else {
                        let mut idx = 0u8;
                        while idx < pin.conn_list_len {
                            let offset = idx as u32 & !3;
                            let resp = send_verb(codec, nid, VERB_GET_CONN_LIST | offset);
                            let sub_idx = (idx & 3) as u32;
                            pin.conn_list[idx as usize] =
                                ((resp >> (sub_idx * 8)) & 0xFF) as u16;
                            idx += 1;
                        }
                    }
                }

                unsafe {
                    fut_printf(
                        b"intel_hda_hdmi: pin NID 0x%02x caps=0x%08x cfg=0x%08x %s\n\0".as_ptr(),
                        nid as u32,
                        pin_caps,
                        config_default,
                        if pin.is_hdmi { b"HDMI\0".as_ptr() } else { b"DP\0".as_ptr() },
                    );
                }

                codec.pins[codec.num_pins] = pin;
                codec.num_pins += 1;
            }
            WIDGET_TYPE_AUDIO_OUTPUT => {
                if codec.num_cvts >= MAX_CVTS {
                    continue;
                }

                // Check for digital capability (bit 9 of widget caps = Digital)
                let is_digital = (caps >> 9) & 1 != 0;
                if !is_digital {
                    continue;
                }

                let mut cvt = HdmiCvt::zeroed();
                cvt.nid = nid;
                cvt.caps = caps;

                unsafe {
                    fut_printf(
                        b"intel_hda_hdmi: converter NID 0x%02x caps=0x%08x\n\0".as_ptr(),
                        nid as u32,
                        caps,
                    );
                }

                codec.cvts[codec.num_cvts] = cvt;
                codec.num_cvts += 1;
            }
            _ => {}
        }
    }

    unsafe {
        fut_printf(
            b"intel_hda_hdmi: found %d pins, %d converters\n\0".as_ptr(),
            codec.num_pins as u32,
            codec.num_cvts as u32,
        );
    }
}

// ── Auto-assign converters to pins ──

/// Assign each pin a default converter from its connection list.
fn assign_converters(codec: &mut IntelHdmiCodec) {
    // Track which converters are already assigned
    let mut used: [bool; MAX_CVTS] = [false; MAX_CVTS];

    for p in 0..codec.num_pins {
        let pin_nid = codec.pins[p].nid;
        let conn_len = codec.pins[p].conn_list_len as usize;
        let conn_list = codec.pins[p].conn_list;
        let mut assigned = false;

        // Walk the pin's connection list and find an unused converter
        for ci in 0..conn_len {
            let conn_nid = conn_list[ci];
            for c in 0..codec.num_cvts {
                if codec.cvts[c].nid == conn_nid && !used[c] {
                    used[c] = true;
                    codec.pins[p].cvt_nid = conn_nid;
                    // Set the connection select on the pin
                    send_verb(codec, pin_nid, VERB_SET_CONN_SELECT | ci as u32);
                    assigned = true;
                    break;
                }
            }
            if assigned {
                break;
            }
        }

        if !assigned && conn_len > 0 {
            // Fallback: just use the first connection
            codec.pins[p].cvt_nid = conn_list[0];
            send_verb(codec, pin_nid, VERB_SET_CONN_SELECT | 0);
        }
    }
}

// ── Presence detect ──

/// Check if a monitor/sink is connected to the given pin.
fn pin_is_present(codec: &IntelHdmiCodec, pin_idx: usize) -> bool {
    if pin_idx >= codec.num_pins {
        return false;
    }
    let sense = send_verb(codec, codec.pins[pin_idx].nid, VERB_GET_PIN_SENSE);
    (sense & PIN_SENSE_PRESENCE) != 0
}

/// Check if ELD data is valid for the given pin.
fn pin_eld_valid(codec: &IntelHdmiCodec, pin_idx: usize) -> bool {
    if pin_idx >= codec.num_pins {
        return false;
    }
    let sense = send_verb(codec, codec.pins[pin_idx].nid, VERB_GET_PIN_SENSE);
    (sense & PIN_SENSE_ELD_VALID) != 0
}

// ── ELD (EDID-Like Data) ──

/// Read ELD from a connected monitor into the pin's ELD buffer.
fn read_eld(codec: &mut IntelHdmiCodec, pin_idx: usize) -> i32 {
    if pin_idx >= codec.num_pins {
        return -1;
    }

    if !pin_eld_valid(codec, pin_idx) {
        codec.pins[pin_idx].eld_len = 0;
        return 0;
    }

    let nid = codec.pins[pin_idx].nid;

    // Read ELD size from offset 0 (size is in the lower byte)
    let size_resp = send_verb(codec, nid, VERB_GET_HDMI_ELD_DATA | 0x00);
    let eld_size = (size_resp >> 0) & 0xFF;

    if eld_size == 0 || eld_size as usize > MAX_ELD {
        codec.pins[pin_idx].eld_len = 0;
        return 0;
    }

    // Read ELD data byte-by-byte
    for offset in 0..eld_size {
        let resp = send_verb(codec, nid, VERB_GET_HDMI_ELD_DATA | (offset & 0xFF));
        codec.pins[pin_idx].eld[offset as usize] = (resp & 0xFF) as u8;
    }

    codec.pins[pin_idx].eld_len = eld_size as u8;

    unsafe {
        fut_printf(
            b"intel_hda_hdmi: pin 0x%02x ELD %d bytes\n\0".as_ptr(),
            nid as u32,
            eld_size,
        );
    }

    eld_size as i32
}

// ── Audio InfoFrame ──

/// Write an Audio InfoFrame to the pin's DIP buffer.
/// channel_count: number of audio channels (1-8)
/// speaker_alloc: CEA-861 speaker allocation byte
fn write_audio_infoframe(
    codec: &IntelHdmiCodec,
    pin_idx: usize,
    channel_count: u8,
    speaker_alloc: u8,
) {
    if pin_idx >= codec.num_pins {
        return;
    }

    let nid = codec.pins[pin_idx].nid;

    // Disable DIP transmission before writing
    send_verb(codec, nid, VERB_SET_HDMI_DIP_XMIT | DIP_XMIT_DISABLE as u32);

    // Build the Audio InfoFrame (13 bytes: 3-byte header + 10-byte payload)
    let cc = if channel_count > 0 { channel_count - 1 } else { 0 };

    let mut frame: [u8; 13] = [0; 13];
    frame[0] = AUDIO_INFOFRAME_TYPE;  // Type
    frame[1] = AUDIO_INFOFRAME_VER;   // Version
    frame[2] = AUDIO_INFOFRAME_LEN;   // Length

    // Checksum: sum of header + data must be 0 (mod 256)
    // frame[3] = checksum (computed below)
    frame[4] = cc & 0x07;             // CT=0 (refer to stream), CC
    frame[5] = 0x00;                  // SF=0 (refer to stream), SS=0 (refer to stream)
    frame[6] = 0x00;                  // format / DM_INH=0
    frame[7] = speaker_alloc;         // CA (channel/speaker allocation)
    frame[8] = 0x00;                  // LFEPBL=0, LSV=0, DM_INH=0
    // frame[9..12] = reserved (0)

    // Compute checksum: sum of all bytes = 0 mod 256
    let mut sum: u8 = 0;
    for i in 0..13 {
        if i != 3 {
            sum = sum.wrapping_add(frame[i]);
        }
    }
    frame[3] = 0u8.wrapping_sub(sum);

    // Set DIP buffer index to 0
    send_verb(codec, nid, VERB_SET_HDMI_DIP_INDEX | 0x00);

    // Write each byte of the InfoFrame
    for i in 0..13 {
        send_verb(codec, nid, VERB_SET_HDMI_DIP_DATA | frame[i] as u32);
    }

    // Pad remaining DIP buffer bytes with zeros (typical DIP size is 32 bytes)
    let dip_size_resp = send_verb(codec, nid, VERB_GET_HDMI_DIP_SIZE | AUDIO_INFOFRAME_TYPE as u32);
    let dip_size = dip_size_resp & 0xFF;
    if dip_size > 13 {
        for _ in 13..dip_size {
            send_verb(codec, nid, VERB_SET_HDMI_DIP_DATA | 0x00);
        }
    }

    // Enable DIP transmission (best-effort repeat)
    send_verb(codec, nid, VERB_SET_HDMI_DIP_XMIT | DIP_XMIT_BEST as u32);
}

// ── Digital converter control ──

/// Enable the digital converter for a given converter NID.
fn enable_digital_converter(codec: &IntelHdmiCodec, cvt_nid: u16) {
    // Set Digital Enable + Validity + DIGEN
    let ctrl = DIGI_ENABLE | DIGI_VALIDITY | DIGI_DIGEN;
    send_verb(codec, cvt_nid, VERB_SET_DIGI_CONVERT_1 | ctrl as u32);
    // Category code 0 (general)
    send_verb(codec, cvt_nid, VERB_SET_DIGI_CONVERT_2 | 0x00);
}

/// Disable the digital converter for a given converter NID.
fn disable_digital_converter(codec: &IntelHdmiCodec, cvt_nid: u16) {
    send_verb(codec, cvt_nid, VERB_SET_DIGI_CONVERT_1 | 0x00);
}

// ── Stream assignment ──

/// Assign a stream tag and channel to a converter, and set the converter format.
fn assign_stream(codec: &IntelHdmiCodec, cvt_nid: u16, stream_tag: u8, format: u16) {
    // Stream tag in bits 7:4, channel in bits 3:0 (channel 0)
    let stream_chan = ((stream_tag as u32 & 0x0F) << 4) | 0;
    send_verb(codec, cvt_nid, VERB_SET_CHANNEL_STREAM_ID | stream_chan);

    // Set converter format (16-bit payload)
    send_verb(codec, cvt_nid, VERB_SET_CONVERTER_FORMAT | (format as u32 & 0xFFFF));
}

/// Unassign stream from a converter.
fn unassign_stream(codec: &IntelHdmiCodec, cvt_nid: u16) {
    send_verb(codec, cvt_nid, VERB_SET_CHANNEL_STREAM_ID | 0x00);
}

// ── Pin enable/disable ──

/// Enable the pin widget for output.
fn enable_pin(codec: &IntelHdmiCodec, pin_idx: usize) {
    if pin_idx >= codec.num_pins {
        return;
    }
    send_verb(
        codec,
        codec.pins[pin_idx].nid,
        VERB_SET_PIN_WIDGET_CTL | PIN_CTL_OUT_EN as u32,
    );
}

/// Disable the pin widget.
fn disable_pin(codec: &IntelHdmiCodec, pin_idx: usize) {
    if pin_idx >= codec.num_pins {
        return;
    }
    send_verb(codec, codec.pins[pin_idx].nid, VERB_SET_PIN_WIDGET_CTL | 0x00);
}

// ── Exported API ──

/// Initialise the Intel HDMI/DP audio codec.
///
/// Returns 0 on success, negative on error.
#[unsafe(no_mangle)]
pub extern "C" fn intel_hda_hdmi_init(verb_fn: HdaVerbFn, codec_addr: u8) -> i32 {
    let codec = unsafe { &mut *STATE.get() };

    codec.verb_fn = Some(verb_fn);
    codec.codec_addr = codec_addr;

    // Detect the codec
    if !detect_codec(codec) {
        return -1;
    }

    // Enumerate widgets (pins and converters)
    enumerate_widgets(codec);

    if codec.num_pins == 0 {
        log("intel_hda_hdmi: no HDMI/DP pins found");
        return -2;
    }

    if codec.num_cvts == 0 {
        log("intel_hda_hdmi: no digital converters found");
        return -3;
    }

    // Auto-assign converters to pins
    assign_converters(codec);

    // Read ELD for any connected monitors
    for i in 0..codec.num_pins {
        if pin_is_present(codec, i) {
            read_eld(codec, i);
        }
    }

    codec.initialised = true;

    unsafe {
        fut_printf(
            b"intel_hda_hdmi: initialised (%d pins, %d converters)\n\0".as_ptr(),
            codec.num_pins as u32,
            codec.num_cvts as u32,
        );
    }

    0
}

/// Return the number of HDMI/DP pins discovered.
#[unsafe(no_mangle)]
pub extern "C" fn intel_hda_hdmi_pin_count() -> u32 {
    let codec = unsafe { &*STATE.get() };
    if !codec.initialised {
        return 0;
    }
    codec.num_pins as u32
}

/// Check if a monitor/sink is connected to pin at the given index.
#[unsafe(no_mangle)]
pub extern "C" fn intel_hda_hdmi_is_connected(pin: u32) -> bool {
    let codec = unsafe { &*STATE.get() };
    if !codec.initialised {
        return false;
    }
    pin_is_present(codec, pin as usize)
}

/// Set up HDMI/DP audio output on the given pin.
///
/// Enables the digital converter, assigns the stream, writes an Audio InfoFrame,
/// and enables the pin for output.
///
/// stream_tag: HDA stream tag (1-15)
/// format: HDA stream format register value (sample rate, bits, channels encoded)
///
/// Returns 0 on success, negative on error.
#[unsafe(no_mangle)]
pub extern "C" fn intel_hda_hdmi_setup_output(
    pin: u32,
    stream_tag: u8,
    format: u16,
) -> i32 {
    let codec = unsafe { &mut *STATE.get() };

    if !codec.initialised {
        log("intel_hda_hdmi: not initialised");
        return -1;
    }

    let pin_idx = pin as usize;
    if pin_idx >= codec.num_pins {
        return -2;
    }

    let cvt_nid = codec.pins[pin_idx].cvt_nid;
    if cvt_nid == 0 {
        unsafe {
            fut_printf(
                b"intel_hda_hdmi: pin %d has no converter assigned\n\0".as_ptr(),
                pin,
            );
        }
        return -3;
    }

    // Check if a sink is connected
    if !pin_is_present(codec, pin_idx) {
        unsafe {
            fut_printf(
                b"intel_hda_hdmi: pin %d no sink detected\n\0".as_ptr(),
                pin,
            );
        }
        return -4;
    }

    // Refresh ELD
    read_eld(codec, pin_idx);

    // Enable digital converter
    enable_digital_converter(codec, cvt_nid);

    // Assign stream to converter
    assign_stream(codec, cvt_nid, stream_tag, format);

    // Decode channel count from format register (bits 3:0 = channels - 1)
    let channels = ((format & 0x0F) + 1) as u8;

    // Determine speaker allocation from channel count
    let speaker_alloc = match channels {
        1 | 2 => 0x00, // FL/FR (stereo or mono)
        4     => 0x03, // FL/FR/RL/RR
        6     => 0x0B, // FL/FR/LFE/FC/RL/RR (5.1)
        8     => 0x13, // FL/FR/LFE/FC/RL/RR/RLC/RRC (7.1)
        _     => 0x00,
    };

    // Write Audio InfoFrame
    write_audio_infoframe(codec, pin_idx, channels, speaker_alloc);

    // Enable the pin for output
    enable_pin(codec, pin_idx);

    unsafe {
        fut_printf(
            b"intel_hda_hdmi: output on pin %d cvt=0x%02x stream=%d ch=%d\n\0".as_ptr(),
            pin,
            cvt_nid as u32,
            stream_tag as u32,
            channels as u32,
        );
    }

    0
}

/// Disable HDMI/DP audio output on the given pin.
///
/// Returns 0 on success, negative on error.
#[unsafe(no_mangle)]
pub extern "C" fn intel_hda_hdmi_disable_output(pin: u32) -> i32 {
    let codec = unsafe { &mut *STATE.get() };

    if !codec.initialised {
        return -1;
    }

    let pin_idx = pin as usize;
    if pin_idx >= codec.num_pins {
        return -2;
    }

    let cvt_nid = codec.pins[pin_idx].cvt_nid;

    // Disable DIP transmission
    send_verb(
        codec,
        codec.pins[pin_idx].nid,
        VERB_SET_HDMI_DIP_XMIT | DIP_XMIT_DISABLE as u32,
    );

    // Disable pin output
    disable_pin(codec, pin_idx);

    // Unassign stream and disable digital converter
    if cvt_nid != 0 {
        unassign_stream(codec, cvt_nid);
        disable_digital_converter(codec, cvt_nid);
    }

    unsafe {
        fut_printf(
            b"intel_hda_hdmi: disabled output on pin %d\n\0".as_ptr(),
            pin,
        );
    }

    0
}

/// Read ELD (EDID-Like Data) from a connected monitor on the given pin.
///
/// Copies up to max_len bytes of ELD data into buf.
/// Returns the number of bytes copied on success, 0 if no ELD available,
/// or negative on error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn intel_hda_hdmi_read_eld(
    pin: u32,
    buf: *mut u8,
    max_len: u32,
) -> i32 {
    let codec = unsafe { &mut *STATE.get() };

    if buf.is_null() || max_len == 0 {
        return -1;
    }

    if !codec.initialised {
        return -2;
    }

    let pin_idx = pin as usize;
    if pin_idx >= codec.num_pins {
        return -3;
    }

    // Refresh ELD
    read_eld(codec, pin_idx);

    let eld_len = codec.pins[pin_idx].eld_len as usize;
    if eld_len == 0 {
        return 0;
    }

    let copy_len = if eld_len < max_len as usize {
        eld_len
    } else {
        max_len as usize
    };

    unsafe {
        core::ptr::copy_nonoverlapping(
            codec.pins[pin_idx].eld.as_ptr(),
            buf,
            copy_len,
        );
    }

    copy_len as i32
}

/// Get the codec name string.
///
/// Copies a NUL-terminated name into buf (up to max_len bytes including NUL).
/// Returns the number of bytes copied (excluding NUL) on success, negative on error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn intel_hda_hdmi_get_codec_name(
    buf: *mut u8,
    max_len: u32,
) -> i32 {
    let codec = unsafe { &*STATE.get() };

    if buf.is_null() || max_len == 0 {
        return -1;
    }

    if !codec.initialised {
        unsafe {
            *buf = 0;
        }
        return -2;
    }

    let name = codec_name(codec.device_id);
    // name includes trailing \0; copy up to max_len-1 bytes + terminator
    let name_len = name.len().saturating_sub(1); // exclude trailing \0
    let copy_len = if name_len < max_len as usize {
        name_len
    } else {
        (max_len as usize).saturating_sub(1)
    };

    unsafe {
        core::ptr::copy_nonoverlapping(name.as_ptr(), buf, copy_len);
        *buf.add(copy_len) = 0;
    }

    copy_len as i32
}
