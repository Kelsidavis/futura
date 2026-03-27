// SPDX-License-Identifier: MPL-2.0
//
// Realtek HDA Codec Driver for AM4/AM5 Boards
//
// Codec-level driver that works with the HDA controller driver to program
// Realtek audio codecs commonly found on AMD Ryzen motherboards.
//
// Supported codecs:
//   - ALC887  (0x10EC0887) -- AM4 mainstream
//   - ALC892  (0x10EC0892) -- AM4 mid-range
//   - ALC1150 (0x10EC0900) -- AM4 high-end
//   - ALC1220 (0x10EC1168) -- AM4 enthusiast
//   - ALC4080 (0x10EC4080) -- AM5 platforms
//
// Architecture:
//   - Communicates with the HDA controller via a verb callback function
//   - Walks the codec widget tree to discover DACs, ADCs, mixers, and pins
//   - Builds output path: Pin -> Mixer -> DAC with connection select
//   - Builds input path: Mic Pin -> ADC
//   - Programs Realtek-specific coefficient registers for known models
//   - Supports headphone jack detection (pin sense polling)
//   - Volume and mute control via amplifier gain/mute verbs

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
const VERB_GET_PARAMETER: u32      = 0xF0000;
const VERB_GET_CONN_SELECT: u32    = 0xF0100;
const VERB_GET_CONN_LIST: u32      = 0xF0200;
const VERB_GET_AMP_GAIN_MUTE: u32  = 0xB0000;
const VERB_GET_PIN_WIDGET_CTL: u32 = 0xF0700;
const VERB_GET_PIN_SENSE: u32      = 0xF0900;
const VERB_GET_CONFIG_DEFAULT: u32 = 0xF1C00;
const VERB_GET_EAPD_BTLENABLE: u32 = 0xF0C00;
const VERB_GET_POWER_STATE: u32    = 0xF0500;

// SET verbs (4-bit verb ID, 8-bit or 16-bit payload)
const VERB_SET_AMP_GAIN_MUTE: u32   = 0x30000;
const VERB_SET_PIN_WIDGET_CTL: u32  = 0x70700;
const VERB_SET_CONN_SELECT: u32     = 0x70100;
const VERB_SET_EAPD_BTLENABLE: u32  = 0x70C00;
const VERB_SET_POWER_STATE: u32     = 0x70500;
const VERB_SET_CHANNEL_STREAM_ID: u32 = 0x70600;

// Realtek-specific coefficient verbs (NID 0x20)
const VERB_COEF_INDEX_SET: u32 = 0x50000; // Set COEF index (write index)
const VERB_COEF_INDEX_GET: u32 = 0xD0000; // Get COEF index (read index)
const VERB_COEF_DATA_SET: u32  = 0x40000; // Set COEF data  (write data)
const VERB_COEF_DATA_GET: u32  = 0xC0000; // Get COEF data  (read data)

// Parameter IDs (used with GET_PARAMETER)
const PARAM_VENDOR_ID: u32        = 0x00;
const PARAM_REVISION_ID: u32      = 0x02;
const PARAM_SUB_NODE_COUNT: u32   = 0x04;
const PARAM_FUNC_GROUP_TYPE: u32  = 0x05;
const PARAM_AUDIO_WIDGET_CAP: u32 = 0x09;
const PARAM_PIN_CAPS: u32         = 0x0C;
const PARAM_IN_AMP_CAP: u32       = 0x0D;
const PARAM_OUT_AMP_CAP: u32      = 0x12;
const PARAM_CONN_LIST_LEN: u32    = 0x0E;

// Widget types (from Audio Widget Capabilities parameter, bits 23:20)
const WIDGET_TYPE_AUDIO_OUTPUT: u8   = 0x0;
const WIDGET_TYPE_AUDIO_INPUT: u8    = 0x1;
const WIDGET_TYPE_AUDIO_MIXER: u8    = 0x2;
const WIDGET_TYPE_AUDIO_SELECTOR: u8 = 0x3;
const WIDGET_TYPE_PIN_COMPLEX: u8    = 0x4;

// Pin configuration default register fields
// Bits [31:30] = Port Connectivity
const PIN_CONN_JACK: u8  = 0x0;
const PIN_CONN_NONE: u8  = 0x1;
const PIN_CONN_FIXED: u8 = 0x2;
const PIN_CONN_BOTH: u8  = 0x3;

// Default device types (bits 23:20)
const PIN_DEV_LINE_OUT: u8 = 0x0;
const PIN_DEV_SPEAKER: u8  = 0x1;
const PIN_DEV_HP_OUT: u8   = 0x2;
const PIN_DEV_MIC_IN: u8   = 0xA;
const PIN_DEV_LINE_IN: u8  = 0x8;

// Pin widget control bits
const PIN_CTL_OUT_EN: u8 = 1 << 6;
const PIN_CTL_IN_EN: u8  = 1 << 5;
const PIN_CTL_HP_EN: u8  = 1 << 7;

// AMP gain/mute verb payload bits
const AMP_SET_OUTPUT: u32     = 1 << 15;
const AMP_SET_INPUT: u32      = 1 << 14;
const AMP_SET_LEFT: u32       = 1 << 13;
const AMP_SET_RIGHT: u32      = 1 << 12;
const AMP_MUTE: u32           = 1 << 7;

// EAPD/BTL Enable bits
const EAPD_BTL_ENABLE_EAPD: u32 = 1 << 1;

// Pin sense bits
const PIN_SENSE_PRESENCE: u32 = 1 << 31;

// ── Realtek vendor/device IDs ──

const REALTEK_VENDOR_ID: u16 = 0x10EC;

const ALC887_DEVICE_ID: u16  = 0x0887;
const ALC892_DEVICE_ID: u16  = 0x0892;
const ALC1150_DEVICE_ID: u16 = 0x0900;
const ALC1220_DEVICE_ID: u16 = 0x1168;
const ALC4080_DEVICE_ID: u16 = 0x4080;

// ── Realtek COEF node ──

const REALTEK_COEF_NID: u16 = 0x20;

// ── Data structures ──

const MAX_WIDGETS: usize    = 128;
const MAX_CONN_LIST: usize  = 16;
const MAX_OUTPUT_PATHS: usize = 4;

#[derive(Clone, Copy)]
struct Widget {
    nid: u16,
    wtype: u8,
    caps: u32,
    pin_cfg: u32,
    pin_caps: u32,
    amp_out_cap: u32,
    amp_in_cap: u32,
    conn_list_len: u8,
    conn_list: [u16; MAX_CONN_LIST],
}

impl Widget {
    const fn zeroed() -> Self {
        Self {
            nid: 0,
            wtype: 0,
            caps: 0,
            pin_cfg: 0,
            pin_caps: 0,
            amp_out_cap: 0,
            amp_in_cap: 0,
            conn_list_len: 0,
            conn_list: [0; MAX_CONN_LIST],
        }
    }
}

/// An output or input audio path through the codec widget tree.
#[derive(Clone, Copy)]
struct AudioPath {
    pin_nid: u16,        // Pin widget (speaker, HP, line-out, mic)
    mixer_nid: u16,      // Optional mixer/selector in the path (0 = none)
    dac_nid: u16,        // DAC for output paths
    adc_nid: u16,        // ADC for input paths
    conn_idx: u8,        // Connection select index at the mixer/selector
    is_hp: bool,         // True if headphone output
    active: bool,        // Path is configured and usable
}

impl AudioPath {
    const fn zeroed() -> Self {
        Self {
            pin_nid: 0,
            mixer_nid: 0,
            dac_nid: 0,
            adc_nid: 0,
            conn_idx: 0,
            is_hp: false,
            active: false,
        }
    }
}

/// Per-codec driver state.
struct RealtekCodec {
    initialised: bool,
    verb_fn: Option<HdaVerbFn>,
    codec_addr: u8,

    // Identification
    vendor_id: u16,
    device_id: u16,
    revision: u32,

    // Widget tree
    afg_nid: u16,
    widgets: [Widget; MAX_WIDGETS],
    num_widgets: usize,

    // Output paths (speaker, headphone, line-out, etc.)
    output_paths: [AudioPath; MAX_OUTPUT_PATHS],
    num_output_paths: usize,
    primary_output: usize, // Index into output_paths for the main speaker/line-out

    // Input path (microphone)
    input_path: AudioPath,

    // Volume state
    volume_pct: u32,
    muted: bool,
}

impl RealtekCodec {
    const fn new() -> Self {
        Self {
            initialised: false,
            verb_fn: None,
            codec_addr: 0,
            vendor_id: 0,
            device_id: 0,
            revision: 0,
            afg_nid: 0,
            widgets: [Widget::zeroed(); MAX_WIDGETS],
            num_widgets: 0,
            output_paths: [AudioPath::zeroed(); MAX_OUTPUT_PATHS],
            num_output_paths: 0,
            primary_output: 0,
            input_path: AudioPath::zeroed(),
            volume_pct: 100,
            muted: false,
        }
    }
}

static STATE: StaticCell<RealtekCodec> = StaticCell::new(RealtekCodec::new());

// ── Helper: send verb through callback ──

fn send_verb(codec: &RealtekCodec, nid: u16, verb: u32) -> u32 {
    match codec.verb_fn {
        Some(f) => unsafe { f(codec.codec_addr, nid, verb) },
        None => 0xFFFFFFFF,
    }
}

fn get_param(codec: &RealtekCodec, nid: u16, param: u32) -> u32 {
    send_verb(codec, nid, VERB_GET_PARAMETER | (param & 0xFF))
}

// ── Realtek COEF read/write ──

fn coef_read(codec: &RealtekCodec, index: u16) -> u16 {
    send_verb(codec, REALTEK_COEF_NID, VERB_COEF_INDEX_SET | (index as u32 & 0xFFFF));
    (send_verb(codec, REALTEK_COEF_NID, VERB_COEF_DATA_GET) & 0xFFFF) as u16
}

fn coef_write(codec: &RealtekCodec, index: u16, data: u16) {
    send_verb(codec, REALTEK_COEF_NID, VERB_COEF_INDEX_SET | (index as u32 & 0xFFFF));
    send_verb(codec, REALTEK_COEF_NID, VERB_COEF_DATA_SET | (data as u32 & 0xFFFF));
}

fn coef_update(codec: &RealtekCodec, index: u16, mask: u16, bits: u16) {
    let val = coef_read(codec, index);
    coef_write(codec, index, (val & !mask) | (bits & mask));
}

// ── Pin config parsing helpers ──

fn pin_connectivity(cfg: u32) -> u8 {
    ((cfg >> 30) & 0x03) as u8
}

fn pin_default_device(cfg: u32) -> u8 {
    ((cfg >> 20) & 0x0F) as u8
}

fn pin_location_gross(cfg: u32) -> u8 {
    ((cfg >> 28) & 0x03) as u8
}

fn pin_default_assoc(cfg: u32) -> u8 {
    ((cfg >> 4) & 0x0F) as u8
}

fn pin_sequence(cfg: u32) -> u8 {
    (cfg & 0x0F) as u8
}

/// Returns true if this pin is connected (not "no connection").
fn pin_is_connected(cfg: u32) -> bool {
    pin_connectivity(cfg) != PIN_CONN_NONE
}

/// Returns true if this pin is an output device (line-out, speaker, HP).
fn pin_is_output(cfg: u32) -> bool {
    let dev = pin_default_device(cfg);
    dev == PIN_DEV_LINE_OUT || dev == PIN_DEV_SPEAKER || dev == PIN_DEV_HP_OUT
}

/// Returns true if this pin is an input device (mic, line-in).
fn pin_is_input(cfg: u32) -> bool {
    let dev = pin_default_device(cfg);
    dev == PIN_DEV_MIC_IN || dev == PIN_DEV_LINE_IN
}

// ── Amp capability parsing ──

/// Extract number of steps from amp caps (bits 14:8).
fn amp_cap_num_steps(cap: u32) -> u32 {
    (cap >> 8) & 0x7F
}

/// Extract step size from amp caps (bits 22:16).
fn amp_cap_step_size(cap: u32) -> u32 {
    (cap >> 16) & 0x7F
}

/// Extract offset (0dB point) from amp caps (bits 6:0).
fn amp_cap_offset(cap: u32) -> u32 {
    cap & 0x7F
}

// ── Codec detection ──

fn detect_codec(codec: &mut RealtekCodec) -> bool {
    let vendor_device = get_param(codec, 0, PARAM_VENDOR_ID);
    if vendor_device == 0 || vendor_device == 0xFFFFFFFF {
        log("hda_realtek: no response from codec");
        return false;
    }

    codec.vendor_id = ((vendor_device >> 16) & 0xFFFF) as u16;
    codec.device_id = (vendor_device & 0xFFFF) as u16;
    codec.revision = get_param(codec, 0, PARAM_REVISION_ID);

    if codec.vendor_id != REALTEK_VENDOR_ID {
        unsafe {
            fut_printf(
                b"hda_realtek: not a Realtek codec (vendor=0x%04x)\n\0".as_ptr(),
                codec.vendor_id as u32,
            );
        }
        return false;
    }

    let name = codec_name(codec.device_id);
    unsafe {
        fut_printf(
            b"hda_realtek: detected %s (0x%04x) rev 0x%08x\n\0".as_ptr(),
            name.as_ptr(),
            codec.device_id as u32,
            codec.revision,
        );
    }

    true
}

/// Return a static C-string name for known Realtek codec models.
fn codec_name(device_id: u16) -> &'static [u8] {
    match device_id {
        ALC887_DEVICE_ID  => b"ALC887\0",
        ALC892_DEVICE_ID  => b"ALC892\0",
        ALC1150_DEVICE_ID => b"ALC1150\0",
        ALC1220_DEVICE_ID => b"ALC1220\0",
        ALC4080_DEVICE_ID => b"ALC4080\0",
        _ => b"Unknown Realtek\0",
    }
}

// ── Widget enumeration ──

fn enumerate_widgets(codec: &mut RealtekCodec) {
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
        log("hda_realtek: no Audio Function Group found");
        return;
    }

    unsafe {
        fut_printf(
            b"hda_realtek: AFG at NID 0x%02x\n\0".as_ptr(),
            codec.afg_nid as u32,
        );
    }

    // Enumerate subordinate widgets under AFG
    let afg_sub = get_param(codec, codec.afg_nid, PARAM_SUB_NODE_COUNT);
    let w_start = ((afg_sub >> 16) & 0xFF) as u16;
    let w_count = (afg_sub & 0xFF) as u16;

    codec.num_widgets = 0;

    for i in 0..w_count {
        if codec.num_widgets >= MAX_WIDGETS {
            break;
        }

        let nid = w_start + i;
        let caps = get_param(codec, nid, PARAM_AUDIO_WIDGET_CAP);
        let wtype = ((caps >> 20) & 0x0F) as u8;

        let mut w = Widget::zeroed();
        w.nid = nid;
        w.wtype = wtype;
        w.caps = caps;

        // Read connection list
        let conn_len_raw = get_param(codec, nid, PARAM_CONN_LIST_LEN);
        let long_form = (conn_len_raw >> 7) & 1 != 0;
        let conn_len = (conn_len_raw & 0x7F) as u8;
        w.conn_list_len = if conn_len as usize > MAX_CONN_LIST {
            MAX_CONN_LIST as u8
        } else {
            conn_len
        };

        // Read connection list entries
        if w.conn_list_len > 0 {
            if long_form {
                // Long form: 2 entries per 32-bit response (16-bit each)
                let mut idx = 0u8;
                while idx < w.conn_list_len {
                    let offset = idx as u32;
                    let resp = send_verb(codec, nid, VERB_GET_CONN_LIST | offset);
                    w.conn_list[idx as usize] = (resp & 0xFFFF) as u16;
                    idx += 1;
                    if idx < w.conn_list_len {
                        w.conn_list[idx as usize] = ((resp >> 16) & 0xFFFF) as u16;
                        idx += 1;
                    }
                }
            } else {
                // Short form: 4 entries per 32-bit response (8-bit each)
                let mut idx = 0u8;
                while idx < w.conn_list_len {
                    let offset = idx as u32 & !3;
                    let resp = send_verb(codec, nid, VERB_GET_CONN_LIST | offset);
                    let sub_idx = (idx & 3) as u32;
                    w.conn_list[idx as usize] = ((resp >> (sub_idx * 8)) & 0xFF) as u16;
                    idx += 1;
                }
            }
        }

        // Read amp capabilities (if widget has amps)
        let has_out_amp = (caps >> 2) & 1 != 0;
        let has_in_amp = (caps >> 1) & 1 != 0;
        let amp_override = (caps >> 3) & 1 != 0;

        if has_out_amp {
            w.amp_out_cap = if amp_override {
                get_param(codec, nid, PARAM_OUT_AMP_CAP)
            } else {
                get_param(codec, codec.afg_nid, PARAM_OUT_AMP_CAP)
            };
        }

        if has_in_amp {
            w.amp_in_cap = if amp_override {
                get_param(codec, nid, PARAM_IN_AMP_CAP)
            } else {
                get_param(codec, codec.afg_nid, PARAM_IN_AMP_CAP)
            };
        }

        // Read pin-specific data
        if wtype == WIDGET_TYPE_PIN_COMPLEX {
            w.pin_cfg = send_verb(codec, nid, VERB_GET_CONFIG_DEFAULT);
            w.pin_caps = get_param(codec, nid, PARAM_PIN_CAPS);
        }

        codec.widgets[codec.num_widgets] = w;
        codec.num_widgets += 1;
    }

    unsafe {
        fut_printf(
            b"hda_realtek: enumerated %d widgets\n\0".as_ptr(),
            codec.num_widgets as u32,
        );
    }
}

// ── Widget lookup helpers ──

fn find_widget(codec: &RealtekCodec, nid: u16) -> Option<usize> {
    for i in 0..codec.num_widgets {
        if codec.widgets[i].nid == nid {
            return Some(i);
        }
    }
    None
}

fn find_widget_by_type(codec: &RealtekCodec, wtype: u8) -> Option<usize> {
    for i in 0..codec.num_widgets {
        if codec.widgets[i].wtype == wtype {
            return Some(i);
        }
    }
    None
}

/// Find the first connected output pin of a given default device type.
fn find_output_pin(codec: &RealtekCodec, dev_type: u8) -> Option<usize> {
    for i in 0..codec.num_widgets {
        let w = &codec.widgets[i];
        if w.wtype == WIDGET_TYPE_PIN_COMPLEX
            && pin_is_connected(w.pin_cfg)
            && pin_default_device(w.pin_cfg) == dev_type
        {
            return Some(i);
        }
    }
    None
}

/// Find an input pin (mic or line-in).
fn find_input_pin(codec: &RealtekCodec) -> Option<usize> {
    // Prefer external mic first
    for i in 0..codec.num_widgets {
        let w = &codec.widgets[i];
        if w.wtype == WIDGET_TYPE_PIN_COMPLEX
            && pin_is_connected(w.pin_cfg)
            && pin_default_device(w.pin_cfg) == PIN_DEV_MIC_IN
            && pin_connectivity(w.pin_cfg) == PIN_CONN_JACK
        {
            return Some(i);
        }
    }
    // Fall back to any mic
    for i in 0..codec.num_widgets {
        let w = &codec.widgets[i];
        if w.wtype == WIDGET_TYPE_PIN_COMPLEX
            && pin_is_connected(w.pin_cfg)
            && pin_is_input(w.pin_cfg)
        {
            return Some(i);
        }
    }
    None
}

/// Walk back from a pin widget through mixers/selectors to find a DAC.
/// Returns (mixer_nid, dac_nid, conn_idx) or None.
fn trace_output_path(codec: &RealtekCodec, pin_idx: usize) -> Option<(u16, u16, u8)> {
    let pin = &codec.widgets[pin_idx];

    // Direct connection: pin -> DAC
    for ci in 0..pin.conn_list_len as usize {
        let target_nid = pin.conn_list[ci];
        if let Some(ti) = find_widget(codec, target_nid) {
            if codec.widgets[ti].wtype == WIDGET_TYPE_AUDIO_OUTPUT {
                return Some((0, target_nid, ci as u8));
            }
        }
    }

    // One-hop: pin -> mixer/selector -> DAC
    for ci in 0..pin.conn_list_len as usize {
        let mid_nid = pin.conn_list[ci];
        if let Some(mi) = find_widget(codec, mid_nid) {
            let mw = &codec.widgets[mi];
            if mw.wtype == WIDGET_TYPE_AUDIO_MIXER
                || mw.wtype == WIDGET_TYPE_AUDIO_SELECTOR
            {
                for di in 0..mw.conn_list_len as usize {
                    let dac_nid = mw.conn_list[di];
                    if let Some(daci) = find_widget(codec, dac_nid) {
                        if codec.widgets[daci].wtype == WIDGET_TYPE_AUDIO_OUTPUT {
                            return Some((mid_nid, dac_nid, ci as u8));
                        }
                    }
                }
            }
        }
    }

    None
}

/// Walk from an input pin to find an ADC.
/// Searches ADC widgets whose connection list references this pin (or a
/// mixer/selector connected to this pin).
fn trace_input_path(codec: &RealtekCodec, pin_idx: usize) -> Option<(u16, u16)> {
    let pin_nid = codec.widgets[pin_idx].nid;

    // Direct: ADC connected to pin
    for i in 0..codec.num_widgets {
        let w = &codec.widgets[i];
        if w.wtype == WIDGET_TYPE_AUDIO_INPUT {
            for ci in 0..w.conn_list_len as usize {
                if w.conn_list[ci] == pin_nid {
                    return Some((w.nid, 0));
                }
            }
        }
    }

    // One-hop: ADC -> selector/mixer -> pin
    for i in 0..codec.num_widgets {
        let w = &codec.widgets[i];
        if w.wtype == WIDGET_TYPE_AUDIO_INPUT {
            for ci in 0..w.conn_list_len as usize {
                let mid_nid = w.conn_list[ci];
                if let Some(mi) = find_widget(codec, mid_nid) {
                    let mw = &codec.widgets[mi];
                    if mw.wtype == WIDGET_TYPE_AUDIO_MIXER
                        || mw.wtype == WIDGET_TYPE_AUDIO_SELECTOR
                    {
                        for si in 0..mw.conn_list_len as usize {
                            if mw.conn_list[si] == pin_nid {
                                return Some((w.nid, mid_nid));
                            }
                        }
                    }
                }
            }
        }
    }

    None
}

// ── Realtek-specific COEF programming ──

fn apply_realtek_quirks(codec: &RealtekCodec) {
    match codec.device_id {
        ALC1220_DEVICE_ID | ALC4080_DEVICE_ID => {
            // Enable headphone amplifier via COEF 0x67 bit 14
            coef_update(codec, 0x67, 1 << 14, 1 << 14);

            unsafe {
                fut_printf(
                    b"hda_realtek: enabled HP amp (COEF 0x67)\n\0".as_ptr(),
                );
            }

            // ALC1220: reduce pop noise via COEF 0x36
            if codec.device_id == ALC1220_DEVICE_ID {
                coef_update(codec, 0x36, 0x000C, 0x000C);
            }

            // ALC4080 (AM5): additional init for improved SNR
            if codec.device_id == ALC4080_DEVICE_ID {
                coef_update(codec, 0x10, 0x0020, 0x0020);
            }
        }
        ALC1150_DEVICE_ID => {
            // ALC1150: enable headphone amp via COEF 0x67 bit 14
            coef_update(codec, 0x67, 1 << 14, 1 << 14);
        }
        ALC892_DEVICE_ID => {
            // ALC892: set analog reference voltage for better mic sensitivity
            coef_update(codec, 0x0B, 0x0008, 0x0008);
        }
        ALC887_DEVICE_ID => {
            // ALC887: basic init -- enable analog loopback avoidance
            coef_update(codec, 0x0B, 0x0004, 0x0004);
        }
        _ => {}
    }
}

// ── Output path setup ──

fn setup_output_path(codec: &mut RealtekCodec, path_idx: usize) -> bool {
    if path_idx >= codec.num_output_paths {
        return false;
    }

    let path = codec.output_paths[path_idx];
    if !path.active {
        return false;
    }

    // Power on DAC
    send_verb(codec, path.dac_nid, VERB_SET_POWER_STATE | 0x00);

    // Configure pin widget
    let pin_ctl = if path.is_hp {
        PIN_CTL_OUT_EN | PIN_CTL_HP_EN
    } else {
        PIN_CTL_OUT_EN
    };
    send_verb(codec, path.pin_nid, VERB_SET_PIN_WIDGET_CTL | pin_ctl as u32);

    // Enable EAPD on the pin (if supported)
    if let Some(pi) = find_widget(codec, path.pin_nid) {
        let pin_caps = codec.widgets[pi].pin_caps;
        if pin_caps & (1 << 16) != 0 {
            // EAPD capable
            let eapd = send_verb(codec, path.pin_nid, VERB_GET_EAPD_BTLENABLE);
            send_verb(
                codec,
                path.pin_nid,
                VERB_SET_EAPD_BTLENABLE | (eapd & 0xFF) | EAPD_BTL_ENABLE_EAPD,
            );
        }
    }

    // Set connection select at the pin to route through our chosen path
    if path.mixer_nid != 0 {
        send_verb(codec, path.pin_nid, VERB_SET_CONN_SELECT | path.conn_idx as u32);
    }

    // Unmute and set gain on DAC output amp
    if let Some(di) = find_widget(codec, path.dac_nid) {
        let amp_cap = codec.widgets[di].amp_out_cap;
        if amp_cap != 0 {
            let offset = amp_cap_offset(amp_cap);
            send_verb(
                codec,
                path.dac_nid,
                VERB_SET_AMP_GAIN_MUTE | AMP_SET_OUTPUT | AMP_SET_LEFT | AMP_SET_RIGHT | offset,
            );
        }
    }

    // Unmute mixer input amp (if mixer exists)
    if path.mixer_nid != 0 {
        if let Some(mi) = find_widget(codec, path.mixer_nid) {
            let amp_cap = codec.widgets[mi].amp_in_cap;
            if amp_cap != 0 {
                let offset = amp_cap_offset(amp_cap);
                // Unmute all inputs on the mixer
                for idx in 0..codec.widgets[mi].conn_list_len {
                    send_verb(
                        codec,
                        path.mixer_nid,
                        VERB_SET_AMP_GAIN_MUTE
                            | AMP_SET_INPUT
                            | AMP_SET_LEFT
                            | AMP_SET_RIGHT
                            | ((idx as u32) << 8)
                            | offset,
                    );
                }
            }
        }
    }

    // Unmute pin output amp
    if let Some(pi) = find_widget(codec, path.pin_nid) {
        let amp_cap = codec.widgets[pi].amp_out_cap;
        if amp_cap != 0 {
            let offset = amp_cap_offset(amp_cap);
            send_verb(
                codec,
                path.pin_nid,
                VERB_SET_AMP_GAIN_MUTE | AMP_SET_OUTPUT | AMP_SET_LEFT | AMP_SET_RIGHT | offset,
            );
        }
    }

    unsafe {
        fut_printf(
            b"hda_realtek: output path: pin 0x%02x -> mixer 0x%02x -> DAC 0x%02x\n\0".as_ptr(),
            path.pin_nid as u32,
            path.mixer_nid as u32,
            path.dac_nid as u32,
        );
    }

    true
}

// ── Input path setup ──

fn setup_input(codec: &mut RealtekCodec) -> bool {
    let path = &codec.input_path;
    if !path.active {
        log("hda_realtek: no input path found");
        return false;
    }

    let pin_nid = path.pin_nid;
    let adc_nid = path.adc_nid;

    // Enable input on pin
    send_verb(codec, pin_nid, VERB_SET_PIN_WIDGET_CTL | PIN_CTL_IN_EN as u32);

    // Power on ADC
    send_verb(codec, adc_nid, VERB_SET_POWER_STATE | 0x00);

    // Set ADC input amp gain
    if let Some(ai) = find_widget(codec, adc_nid) {
        let amp_cap = codec.widgets[ai].amp_in_cap;
        if amp_cap != 0 {
            let offset = amp_cap_offset(amp_cap);
            send_verb(
                codec,
                adc_nid,
                VERB_SET_AMP_GAIN_MUTE
                    | AMP_SET_INPUT
                    | AMP_SET_LEFT
                    | AMP_SET_RIGHT
                    | offset,
            );
        }
    }

    // If there is a selector between ADC and pin, select the correct input
    if path.mixer_nid != 0 {
        if let Some(mi) = find_widget(codec, path.mixer_nid) {
            let mw = &codec.widgets[mi];
            for ci in 0..mw.conn_list_len as usize {
                if mw.conn_list[ci] == pin_nid {
                    send_verb(codec, path.mixer_nid, VERB_SET_CONN_SELECT | ci as u32);
                    break;
                }
            }
        }
    }

    unsafe {
        fut_printf(
            b"hda_realtek: input path: pin 0x%02x -> ADC 0x%02x\n\0".as_ptr(),
            pin_nid as u32,
            adc_nid as u32,
        );
    }

    true
}

// ── Volume control ──

/// Convert a percentage (0-100) to a gain step value.
fn pct_to_gain(pct: u32, num_steps: u32) -> u32 {
    if pct >= 100 {
        num_steps
    } else if num_steps == 0 {
        0
    } else {
        (pct * num_steps + 50) / 100
    }
}

/// Set output amplifier gain on all active output paths.
fn apply_volume(codec: &RealtekCodec) {
    let gain_pct = if codec.muted { 0 } else { codec.volume_pct };

    for i in 0..codec.num_output_paths {
        let path = &codec.output_paths[i];
        if !path.active {
            continue;
        }

        // Set DAC output amp
        if let Some(di) = find_widget(codec, path.dac_nid) {
            let amp_cap = codec.widgets[di].amp_out_cap;
            if amp_cap != 0 {
                let num_steps = amp_cap_num_steps(amp_cap);
                let gain = pct_to_gain(gain_pct, num_steps);
                let mute_bit = if gain_pct == 0 { AMP_MUTE } else { 0 };
                send_verb(
                    codec,
                    path.dac_nid,
                    VERB_SET_AMP_GAIN_MUTE
                        | AMP_SET_OUTPUT
                        | AMP_SET_LEFT
                        | AMP_SET_RIGHT
                        | mute_bit
                        | (gain & 0x7F),
                );
            }
        }
    }
}

// ── Path discovery ──

/// Discover output paths (speaker, headphone, line-out) from the widget tree.
fn discover_output_paths(codec: &mut RealtekCodec) {
    codec.num_output_paths = 0;

    // Priority order: speaker, then headphone, then line-out
    let dev_types = [PIN_DEV_SPEAKER, PIN_DEV_HP_OUT, PIN_DEV_LINE_OUT];

    for &dev_type in &dev_types {
        if codec.num_output_paths >= MAX_OUTPUT_PATHS {
            break;
        }

        if let Some(pin_idx) = find_output_pin(codec, dev_type) {
            if let Some((mixer_nid, dac_nid, conn_idx)) = trace_output_path(codec, pin_idx) {
                let pin_nid = codec.widgets[pin_idx].nid;
                let is_hp = dev_type == PIN_DEV_HP_OUT;

                // Check we have not already used this DAC
                let mut dac_used = false;
                for j in 0..codec.num_output_paths {
                    if codec.output_paths[j].dac_nid == dac_nid {
                        dac_used = true;
                        break;
                    }
                }

                if !dac_used {
                    let idx = codec.num_output_paths;
                    codec.output_paths[idx] = AudioPath {
                        pin_nid,
                        mixer_nid,
                        dac_nid,
                        adc_nid: 0,
                        conn_idx,
                        is_hp,
                        active: true,
                    };
                    codec.num_output_paths += 1;

                    // First non-HP output is the primary
                    if !is_hp && codec.primary_output == 0 && idx > 0 {
                        codec.primary_output = idx;
                    }
                }
            }
        }
    }

    if codec.num_output_paths == 0 {
        log("hda_realtek: no output paths found");
    } else {
        unsafe {
            fut_printf(
                b"hda_realtek: discovered %d output path(s)\n\0".as_ptr(),
                codec.num_output_paths as u32,
            );
        }
    }
}

/// Discover the input path (microphone).
fn discover_input_path(codec: &mut RealtekCodec) {
    codec.input_path = AudioPath::zeroed();

    if let Some(pin_idx) = find_input_pin(codec) {
        let pin_nid = codec.widgets[pin_idx].nid;

        if let Some((adc_nid, mixer_nid)) = trace_input_path(codec, pin_idx) {
            codec.input_path = AudioPath {
                pin_nid,
                mixer_nid,
                dac_nid: 0,
                adc_nid,
                conn_idx: 0,
                is_hp: false,
                active: true,
            };

            unsafe {
                fut_printf(
                    b"hda_realtek: input: mic pin 0x%02x -> ADC 0x%02x\n\0".as_ptr(),
                    pin_nid as u32,
                    adc_nid as u32,
                );
            }
        }
    }
}

// ── FFI exports ──

/// Initialize the Realtek codec driver.
/// `verb_fn`: callback to send HDA verbs via the controller.
/// `codec_addr`: codec address on the HDA link (0-14).
/// Returns 0 on success, negative on error.
#[unsafe(no_mangle)]
pub extern "C" fn hda_realtek_init(verb_fn: HdaVerbFn, codec_addr: u8) -> i32 {
    let codec = unsafe { &mut *STATE.get() };

    codec.verb_fn = Some(verb_fn);
    codec.codec_addr = codec_addr;
    codec.initialised = false;
    codec.volume_pct = 100;
    codec.muted = false;

    log("hda_realtek: initialising Realtek HDA codec driver");

    // Step 1: detect and identify the codec
    if !detect_codec(codec) {
        return -1;
    }

    // Step 2: enumerate widget tree
    enumerate_widgets(codec);

    if codec.num_widgets == 0 {
        log("hda_realtek: no widgets found");
        return -2;
    }

    // Step 3: apply Realtek-specific coefficient programming
    apply_realtek_quirks(codec);

    // Step 4: discover output and input paths
    discover_output_paths(codec);
    discover_input_path(codec);

    codec.initialised = true;
    log("hda_realtek: initialisation complete");
    0
}

/// Configure and enable output paths (speaker/headphone/line-out).
/// Must be called after hda_realtek_init().
/// Returns 0 on success, negative on error.
#[unsafe(no_mangle)]
pub extern "C" fn hda_realtek_setup_output() -> i32 {
    let codec = unsafe { &mut *STATE.get() };

    if !codec.initialised {
        log("hda_realtek: not initialised");
        return -1;
    }

    if codec.num_output_paths == 0 {
        log("hda_realtek: no output paths discovered");
        return -2;
    }

    let mut ok = false;
    for i in 0..codec.num_output_paths {
        if setup_output_path(codec, i) {
            ok = true;
        }
    }

    if !ok {
        log("hda_realtek: failed to set up any output path");
        return -3;
    }

    // Apply initial volume
    apply_volume(codec);

    log("hda_realtek: output configured");
    0
}

/// Configure and enable the input path (microphone).
/// Must be called after hda_realtek_init().
/// Returns 0 on success, negative on error.
#[unsafe(no_mangle)]
pub extern "C" fn hda_realtek_setup_input() -> i32 {
    let codec = unsafe { &mut *STATE.get() };

    if !codec.initialised {
        log("hda_realtek: not initialised");
        return -1;
    }

    if !setup_input(codec) {
        return -2;
    }

    log("hda_realtek: input configured");
    0
}

/// Set the output volume (0-100 percent).
/// Returns 0 on success, negative on error.
#[unsafe(no_mangle)]
pub extern "C" fn hda_realtek_set_volume(pct: u32) -> i32 {
    let codec = unsafe { &mut *STATE.get() };

    if !codec.initialised {
        return -1;
    }

    codec.volume_pct = if pct > 100 { 100 } else { pct };
    apply_volume(codec);

    unsafe {
        fut_printf(
            b"hda_realtek: volume set to %d%%\n\0".as_ptr(),
            codec.volume_pct,
        );
    }
    0
}

/// Set mute state for all output paths.
/// Returns 0 on success, negative on error.
#[unsafe(no_mangle)]
pub extern "C" fn hda_realtek_set_mute(muted: bool) -> i32 {
    let codec = unsafe { &mut *STATE.get() };

    if !codec.initialised {
        return -1;
    }

    codec.muted = muted;
    apply_volume(codec);

    if muted {
        log("hda_realtek: muted");
    } else {
        log("hda_realtek: unmuted");
    }
    0
}

/// Detect headphone jack presence by polling pin sense.
/// Returns true if headphones are plugged in.
#[unsafe(no_mangle)]
pub extern "C" fn hda_realtek_headphone_detect() -> bool {
    let codec = unsafe { &*STATE.get() };

    if !codec.initialised {
        return false;
    }

    // Find headphone output path
    for i in 0..codec.num_output_paths {
        let path = &codec.output_paths[i];
        if path.active && path.is_hp {
            // Execute Pin Sense verb -- bit 31 indicates presence
            let sense = send_verb(codec, path.pin_nid, VERB_GET_PIN_SENSE);
            return (sense & PIN_SENSE_PRESENCE) != 0;
        }
    }

    false
}

/// Copy the codec name into the provided buffer.
/// Returns the number of bytes written (excluding null terminator),
/// or negative on error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hda_realtek_get_codec_name(buf: *mut u8, max_len: u32) -> i32 {
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
