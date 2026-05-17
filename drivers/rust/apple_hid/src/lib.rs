// SPDX-License-Identifier: MPL-2.0
//! Apple Silicon HID input protocol parser for Futura OS.
//!
//! What this crate does
//! --------------------
//! Decodes the keyboard / trackpad framing that Apple's MacBook
//! controllers push over the SPI HID transport (and the I2C trackpad
//! variant on some models).  The actual SPI / I2C bus transfers stay
//! in `apple_spi` / `apple_i2c` — this crate is a pure parser that
//! consumes received bytes and fires registered callbacks plus
//! maintains a small char ring buffer for `getchar`-style consumers.
//!
//! Reference: Asahi Linux `drivers/hid/hid-apple.c` and the spi-hid
//! framing documented in `drivers/hid/spi-hid/`.
//!
//! Compatibility note
//! ------------------
//! No MMIO at all — purely byte-level logic.  Safe to compile into
//! any ARM64 build; the consumer (apple_hid.c) only feeds packets to
//! this parser after the DTB has identified an Apple platform.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(dead_code)]

use core::ffi::c_void;

// ---------------------------------------------------------------------------
// HID report types in the spi-hid framing header
// ---------------------------------------------------------------------------

const HID_REPORT_KEYBOARD: u8 = 0x01;
const HID_REPORT_TOUCHPAD: u8 = 0x02;

// HID modifier bits (USB HID spec)
const HID_MOD_LCTRL:  u8 = 0x01;
const HID_MOD_LSHIFT: u8 = 0x02;
const HID_MOD_LALT:   u8 = 0x04;
const HID_MOD_LGUI:   u8 = 0x08;
const HID_MOD_RCTRL:  u8 = 0x10;
const HID_MOD_RSHIFT: u8 = 0x20;
const HID_MOD_RALT:   u8 = 0x40;
const HID_MOD_RGUI:   u8 = 0x80;

// Header on every SPI HID packet: 1 byte type + 1 byte reserved + u16 LE length.
#[repr(C, packed)]
struct HidMsgHeader {
    msg_type: u8,
    _reserved: u8,
    length:   u16,
}

const HEADER_SIZE: usize = core::mem::size_of::<HidMsgHeader>();

// Boot keyboard report (USB HID 1.11 §B.1): modifiers + reserved + up to 6 keys.
const KEYBOARD_REPORT_MIN_LEN: usize = 8;
const MAX_PRESSED:             usize = 6;

// ---------------------------------------------------------------------------
// US-layout HID scancode → ASCII tables
// ---------------------------------------------------------------------------

const fn us_unshifted() -> [u8; 128] {
    let mut t = [0u8; 128];
    let mut i = 0u8;
    // a-z
    while i < 26 {
        t[(0x04 + i) as usize] = b'a' + i;
        i += 1;
    }
    // 1-9, 0
    let nums = [b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'0'];
    let mut j = 0;
    while j < 10 {
        t[0x1E + j] = nums[j];
        j += 1;
    }
    t[0x28] = b'\n';
    t[0x29] = 0x1B; // Escape
    t[0x2A] = 0x08; // Backspace
    t[0x2B] = b'\t';
    t[0x2C] = b' ';
    t[0x2D] = b'-';
    t[0x2E] = b'=';
    t[0x2F] = b'[';
    t[0x30] = b']';
    t[0x31] = b'\\';
    t[0x33] = b';';
    t[0x34] = b'\'';
    t[0x35] = b'`';
    t[0x36] = b',';
    t[0x37] = b'.';
    t[0x38] = b'/';
    t
}

const fn us_shifted() -> [u8; 128] {
    let mut t = [0u8; 128];
    let mut i = 0u8;
    while i < 26 {
        t[(0x04 + i) as usize] = b'A' + i;
        i += 1;
    }
    let syms = [b'!', b'@', b'#', b'$', b'%', b'^', b'&', b'*', b'(', b')'];
    let mut j = 0;
    while j < 10 {
        t[0x1E + j] = syms[j];
        j += 1;
    }
    t[0x28] = b'\n';
    t[0x29] = 0x1B;
    t[0x2A] = 0x08;
    t[0x2B] = b'\t';
    t[0x2C] = b' ';
    t[0x2D] = b'_';
    t[0x2E] = b'+';
    t[0x2F] = b'{';
    t[0x30] = b'}';
    t[0x31] = b'|';
    t[0x33] = b':';
    t[0x34] = b'"';
    t[0x35] = b'~';
    t[0x36] = b'<';
    t[0x37] = b'>';
    t[0x38] = b'?';
    t
}

const US_UNSHIFTED: [u8; 128] = us_unshifted();
const US_SHIFTED:   [u8; 128] = us_shifted();

#[inline]
fn scancode_to_ascii(scancode: u8, modifiers: u8) -> u8 {
    if scancode as usize >= 128 {
        return 0;
    }
    let shift = (modifiers & (HID_MOD_LSHIFT | HID_MOD_RSHIFT)) != 0;
    if shift {
        US_SHIFTED[scancode as usize]
    } else {
        US_UNSHIFTED[scancode as usize]
    }
}

// ---------------------------------------------------------------------------
// Parser state
// ---------------------------------------------------------------------------

const KEY_RING_LEN: usize = 64;

/// Key event callback: scancode, modifier byte, pressed.
pub type KeyCb   = unsafe extern "C" fn(scancode: u8, modifiers: u8, pressed: bool);
/// Touchpad callback: pointer to the raw report bytes.  The shape is
/// model-specific; the consumer is expected to know how to decode it.
pub type TouchCb = unsafe extern "C" fn(report: *const u8, len: usize);

#[repr(C)]
pub struct AppleHidParser {
    /// Up to six keys held in the previous report.  Used to derive
    /// press vs release edges on each new report.
    last_keys: [u8; MAX_PRESSED],
    last_modifiers: u8,
    /// Small ASCII ring buffer for getchar-style consumers.
    ring: [u8; KEY_RING_LEN],
    head: u16,
    tail: u16,
    key_cb:   Option<KeyCb>,
    touch_cb: Option<TouchCb>,
}

impl AppleHidParser {
    pub const fn new() -> Self {
        Self {
            last_keys: [0u8; MAX_PRESSED],
            last_modifiers: 0,
            ring: [0u8; KEY_RING_LEN],
            head: 0,
            tail: 0,
            key_cb: None,
            touch_cb: None,
        }
    }

    fn ring_push(&mut self, c: u8) {
        let next = ((self.head as usize + 1) % KEY_RING_LEN) as u16;
        if next == self.tail {
            return; // ring full — drop oldest? we drop newest, mirrors C version
        }
        self.ring[self.head as usize] = c;
        self.head = next;
    }

    fn ring_pop(&mut self) -> i32 {
        if self.head == self.tail {
            return -1;
        }
        let c = self.ring[self.tail as usize];
        self.tail = ((self.tail as usize + 1) % KEY_RING_LEN) as u16;
        c as i32
    }

    /// Decode a 6-key boot-protocol keyboard report and fire edges.
    pub fn feed_keyboard(&mut self, data: &[u8]) {
        if data.len() < KEYBOARD_REPORT_MIN_LEN {
            return;
        }
        let modifiers = data[0];
        let keycodes = [data[2], data[3], data[4], data[5], data[6], data[7]];

        // Press edges: keys present now but not in last_keys.
        for &kc in &keycodes {
            if kc == 0 { continue; }
            if !self.last_keys.contains(&kc) {
                if let Some(cb) = self.key_cb {
                    // SAFETY: handler signature matches; no Rust-side state aliased.
                    unsafe { cb(kc, modifiers, true) };
                }
                let ascii = scancode_to_ascii(kc, modifiers);
                if ascii != 0 {
                    self.ring_push(ascii);
                }
            }
        }
        // Release edges: keys in last_keys but no longer present.
        for &kc in &self.last_keys {
            if kc == 0 { continue; }
            if !keycodes.contains(&kc) {
                if let Some(cb) = self.key_cb {
                    unsafe { cb(kc, modifiers, false) };
                }
            }
        }
        self.last_keys      = keycodes;
        self.last_modifiers = modifiers;
    }

    /// Pass-through touchpad report — geometry decoding is up to the
    /// consumer because Apple changes the byte layout per model.
    pub fn feed_touchpad(&mut self, data: &[u8]) {
        if let Some(cb) = self.touch_cb {
            unsafe { cb(data.as_ptr(), data.len()) };
        }
    }

    /// Top-level SPI HID dispatch: peel the 4-byte header off the
    /// front, length-check the payload, route to the per-type parser.
    pub fn feed_spi_packet(&mut self, pkt: &[u8]) {
        if pkt.len() < HEADER_SIZE { return; }
        let msg_type = pkt[0];
        // u16 length little-endian at offset 2.
        let length = u16::from_le_bytes([pkt[2], pkt[3]]) as usize;
        let payload_end = HEADER_SIZE + length;
        if payload_end > pkt.len() { return; }
        let payload = &pkt[HEADER_SIZE..payload_end];
        match msg_type {
            HID_REPORT_KEYBOARD => self.feed_keyboard(payload),
            HID_REPORT_TOUCHPAD => self.feed_touchpad(payload),
            _ => {}
        }
    }
}

// ---------------------------------------------------------------------------
// Heap shim — kernel-side allocator
// ---------------------------------------------------------------------------

unsafe extern "C" {
    fn fut_alloc(size: usize) -> *mut c_void;
    fn fut_free(ptr: *mut c_void);
}

// ---------------------------------------------------------------------------
// C FFI
// ---------------------------------------------------------------------------

/// Allocate a fresh parser.  Returns null on OOM.
#[unsafe(no_mangle)]
pub extern "C" fn rust_apple_hid_new() -> *mut AppleHidParser {
    let ptr = unsafe { fut_alloc(core::mem::size_of::<AppleHidParser>()) }
        as *mut AppleHidParser;
    if ptr.is_null() { return ptr; }
    unsafe { ptr.write(AppleHidParser::new()) };
    ptr
}

/// Free a parser allocated by `rust_apple_hid_new`.
#[unsafe(no_mangle)]
pub extern "C" fn rust_apple_hid_free(p: *mut AppleHidParser) {
    if p.is_null() { return; }
    unsafe { fut_free(p as *mut c_void) };
}

/// Feed an SPI HID packet (header + payload).
///
/// # Safety
/// `ptr` must be valid for `len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_apple_hid_feed_spi_packet(
    p: *mut AppleHidParser,
    ptr: *const u8,
    len: usize,
) {
    if p.is_null() || ptr.is_null() || len == 0 { return; }
    let slice = unsafe { core::slice::from_raw_parts(ptr, len) };
    unsafe { (*p).feed_spi_packet(slice) };
}

/// Feed a raw keyboard report (no SPI header — used by I2C trackpads
/// that include the keyboard slate in a separate channel).
///
/// # Safety
/// `ptr` must be valid for `len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_apple_hid_feed_keyboard(
    p: *mut AppleHidParser,
    ptr: *const u8,
    len: usize,
) {
    if p.is_null() || ptr.is_null() || len == 0 { return; }
    let slice = unsafe { core::slice::from_raw_parts(ptr, len) };
    unsafe { (*p).feed_keyboard(slice) };
}

/// Feed a raw touchpad report.
///
/// # Safety
/// `ptr` must be valid for `len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_apple_hid_feed_touchpad(
    p: *mut AppleHidParser,
    ptr: *const u8,
    len: usize,
) {
    if p.is_null() || ptr.is_null() || len == 0 { return; }
    let slice = unsafe { core::slice::from_raw_parts(ptr, len) };
    unsafe { (*p).feed_touchpad(slice) };
}

/// Pop one buffered ASCII character.  Returns the byte as i32, or -1
/// if the ring is empty.
#[unsafe(no_mangle)]
pub extern "C" fn rust_apple_hid_getchar(p: *mut AppleHidParser) -> i32 {
    if p.is_null() { return -1; }
    unsafe { (*p).ring_pop() }
}

/// Returns 1 if there is at least one buffered char, 0 otherwise.
#[unsafe(no_mangle)]
pub extern "C" fn rust_apple_hid_has_key(p: *const AppleHidParser) -> i32 {
    if p.is_null() { return 0; }
    let r = unsafe { &*p };
    if r.head != r.tail { 1 } else { 0 }
}

/// Install (or clear, with `None`) the key edge-event callback.
///
/// # Safety
/// `cb` must remain valid for the lifetime of the parser.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_apple_hid_set_key_cb(
    p: *mut AppleHidParser,
    cb: Option<KeyCb>,
) {
    if p.is_null() { return; }
    unsafe { (*p).key_cb = cb };
}

/// Install (or clear, with `None`) the touchpad callback.
///
/// # Safety
/// `cb` must remain valid for the lifetime of the parser.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_apple_hid_set_touch_cb(
    p: *mut AppleHidParser,
    cb: Option<TouchCb>,
) {
    if p.is_null() { return; }
    unsafe { (*p).touch_cb = cb };
}

// ---------------------------------------------------------------------------
// Panic handler — required for #![no_std] staticlib
// ---------------------------------------------------------------------------

#[cfg(not(test))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop { core::hint::spin_loop(); }
}

// ---------------------------------------------------------------------------
// Tests — pure logic, no I/O
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_ring_returns_minus_one() {
        let mut p = AppleHidParser::new();
        assert_eq!(p.ring_pop(), -1);
    }

    #[test]
    fn single_key_press_buffers_ascii() {
        let mut p = AppleHidParser::new();
        // Modifiers=0, reserved=0, keycode 'a' = 0x04, rest zero.
        let report = [0, 0, 0x04, 0, 0, 0, 0, 0];
        p.feed_keyboard(&report);
        assert_eq!(p.ring_pop(), b'a' as i32);
        assert_eq!(p.ring_pop(), -1);
    }

    #[test]
    fn shift_modifier_produces_uppercase() {
        let mut p = AppleHidParser::new();
        let report = [HID_MOD_LSHIFT, 0, 0x04, 0, 0, 0, 0, 0];
        p.feed_keyboard(&report);
        assert_eq!(p.ring_pop(), b'A' as i32);
    }

    #[test]
    fn key_held_does_not_re_emit() {
        let mut p = AppleHidParser::new();
        let report = [0, 0, 0x04, 0, 0, 0, 0, 0];
        p.feed_keyboard(&report);
        p.feed_keyboard(&report); // same report — no new press edge
        assert_eq!(p.ring_pop(), b'a' as i32);
        assert_eq!(p.ring_pop(), -1);
    }

    #[test]
    fn spi_header_routes_to_keyboard_parser() {
        let mut p = AppleHidParser::new();
        let mut pkt = [0u8; HEADER_SIZE + 8];
        pkt[0] = HID_REPORT_KEYBOARD;
        // length = 8 (LE)
        pkt[2] = 8;
        // payload: modifiers=0, reserved=0, 'b' (0x05)
        pkt[HEADER_SIZE + 2] = 0x05;
        p.feed_spi_packet(&pkt);
        assert_eq!(p.ring_pop(), b'b' as i32);
    }
}
