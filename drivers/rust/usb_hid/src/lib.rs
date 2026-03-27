// SPDX-License-Identifier: MPL-2.0
//
// USB HID (Human Interface Device) Class Driver for Futura OS
//
// Implements boot-protocol keyboard and mouse support on top of any USB
// host controller (xHCI, EHCI, etc.).  Full HID descriptor parsing is
// not required for boot-protocol devices — the report formats are fixed
// by the USB HID specification.
//
// Architecture:
//   - Class code 03h (HID), subclass 01h (Boot Interface)
//   - Protocol 01h = Keyboard, 02h = Mouse
//   - Up to MAX_DEVICES (4) simultaneously tracked HID devices
//   - Callback / polling model: the host controller hands interrupt
//     endpoint data to usb_hid_process_{keyboard,mouse}_report()
//   - A 64-entry ring buffer accumulates translated ASCII key presses
//   - Mouse state is accumulated (deltas summed) between reads
//
// HID class requests (via control endpoint, not used here directly but
// documented for completeness):
//   GET_REPORT   bRequest=0x01  wValue=report_type<<8|report_id
//   SET_REPORT   bRequest=0x09
//   GET_IDLE     bRequest=0x02
//   SET_IDLE     bRequest=0x0A
//   GET_PROTOCOL bRequest=0x03
//   SET_PROTOCOL bRequest=0x0B  (0=boot, 1=report)

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

// ── Constants ──

/// Maximum number of simultaneously tracked HID devices.
const MAX_DEVICES: usize = 4;

/// Maximum simultaneous key presses in a boot keyboard report.
const MAX_BOOT_KEYS: usize = 6;

/// Keyboard ring buffer size (must be power of two).
const KEY_BUF_SIZE: usize = 64;
const KEY_BUF_MASK: usize = KEY_BUF_SIZE - 1;

// ── HID class codes ──

const HID_CLASS: u8 = 0x03;
const HID_SUBCLASS_BOOT: u8 = 0x01;
const HID_PROTOCOL_KEYBOARD: u8 = 0x01;
const HID_PROTOCOL_MOUSE: u8 = 0x02;

// ── HID class request codes ──

const HID_REQ_GET_REPORT: u8 = 0x01;
const HID_REQ_GET_IDLE: u8 = 0x02;
const HID_REQ_GET_PROTOCOL: u8 = 0x03;
const HID_REQ_SET_REPORT: u8 = 0x09;
const HID_REQ_SET_IDLE: u8 = 0x0A;
const HID_REQ_SET_PROTOCOL: u8 = 0x0B;

// ── Boot keyboard report modifier bits ──

const MOD_LCTRL: u8 = 1 << 0;
const MOD_LSHIFT: u8 = 1 << 1;
const MOD_LALT: u8 = 1 << 2;
const MOD_LGUI: u8 = 1 << 3;
const MOD_RCTRL: u8 = 1 << 4;
const MOD_RSHIFT: u8 = 1 << 5;
const MOD_RALT: u8 = 1 << 6;
const MOD_RGUI: u8 = 1 << 7;

// ── Keyboard LED bits (output report byte 0) ──

const LED_NUM_LOCK: u8 = 1 << 0;
const LED_CAPS_LOCK: u8 = 1 << 1;
const LED_SCROLL_LOCK: u8 = 1 << 2;

// ── Boot mouse button bits ──

const MOUSE_BTN_LEFT: u8 = 1 << 0;
const MOUSE_BTN_RIGHT: u8 = 1 << 1;
const MOUSE_BTN_MIDDLE: u8 = 1 << 2;

// ── Device type tag ──

#[derive(Copy, Clone, PartialEq)]
enum HidDeviceType {
    None,
    Keyboard,
    Mouse,
}

// ── Per-device state ──

#[derive(Copy, Clone)]
struct HidDevice {
    dev_type: HidDeviceType,
    dev_id: u32,
    /// Keyboard: last set of scancodes (for detecting press/release).
    prev_keys: [u8; MAX_BOOT_KEYS],
    /// Keyboard: current modifier byte.
    modifiers: u8,
}

impl HidDevice {
    const fn new() -> Self {
        Self {
            dev_type: HidDeviceType::None,
            dev_id: 0,
            prev_keys: [0; MAX_BOOT_KEYS],
            modifiers: 0,
        }
    }
}

// ── Mouse accumulated state ──

#[derive(Copy, Clone)]
struct MouseState {
    buttons: u8,
    dx: i16,
    dy: i16,
    wheel: i8,
}

impl MouseState {
    const fn new() -> Self {
        Self {
            buttons: 0,
            dx: 0,
            dy: 0,
            wheel: 0,
        }
    }
}

// ── Keyboard ring buffer ──

struct KeyRingBuf {
    buf: [u8; KEY_BUF_SIZE],
    head: usize,
    tail: usize,
}

impl KeyRingBuf {
    const fn new() -> Self {
        Self {
            buf: [0; KEY_BUF_SIZE],
            head: 0,
            tail: 0,
        }
    }

    fn push(&mut self, ch: u8) {
        let next = (self.head + 1) & KEY_BUF_MASK;
        if next == self.tail {
            // Buffer full — drop oldest
            self.tail = (self.tail + 1) & KEY_BUF_MASK;
        }
        self.buf[self.head] = ch;
        self.head = next;
    }

    fn pop(&mut self) -> Option<u8> {
        if self.head == self.tail {
            None
        } else {
            let ch = self.buf[self.tail];
            self.tail = (self.tail + 1) & KEY_BUF_MASK;
            Some(ch)
        }
    }
}

// ── Global driver state ──

struct DriverState {
    initialized: bool,
    devices: [HidDevice; MAX_DEVICES],
    mouse: MouseState,
    key_buf: KeyRingBuf,
    /// Toggle-lock states: caps, num, scroll.
    led_state: u8,
    /// Currently pressed scancodes (for all keyboards combined).
    pressed_keys: [u8; MAX_BOOT_KEYS],
}

impl DriverState {
    const fn new() -> Self {
        Self {
            initialized: false,
            devices: [
                HidDevice::new(),
                HidDevice::new(),
                HidDevice::new(),
                HidDevice::new(),
            ],
            mouse: MouseState::new(),
            key_buf: KeyRingBuf::new(),
            led_state: 0,
            pressed_keys: [0; MAX_BOOT_KEYS],
        }
    }
}

static STATE: StaticCell<DriverState> = StaticCell::new(DriverState::new());

// ── Scancode to ASCII conversion tables (USB HID Usage Table page 0x07) ──

/// Unshifted ASCII values for USB HID scancodes 0x00..0x65.
/// Index = scancode, value = ASCII char (0 = no mapping).
static SCANCODE_TO_ASCII: [u8; 102] = [
    0,   0,   0,   0,   // 0x00-0x03: reserved / error
    b'a', b'b', b'c', b'd', b'e', b'f', b'g', b'h',  // 0x04-0x0B
    b'i', b'j', b'k', b'l', b'm', b'n', b'o', b'p',  // 0x0C-0x13
    b'q', b'r', b's', b't', b'u', b'v', b'w', b'x',  // 0x14-0x1B
    b'y', b'z',                                        // 0x1C-0x1D
    b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8',  // 0x1E-0x25
    b'9', b'0',                                        // 0x26-0x27
    b'\r', // 0x28: Enter
    0x1B,  // 0x29: Escape
    0x08,  // 0x2A: Backspace
    b'\t', // 0x2B: Tab
    b' ',  // 0x2C: Space
    b'-',  // 0x2D: minus
    b'=',  // 0x2E: equals
    b'[',  // 0x2F: left bracket
    b']',  // 0x30: right bracket
    b'\\', // 0x31: backslash
    0,     // 0x32: non-US #
    b';',  // 0x33: semicolon
    b'\'', // 0x34: apostrophe
    b'`',  // 0x35: grave accent
    b',',  // 0x36: comma
    b'.',  // 0x37: period
    b'/',  // 0x38: slash
    0,     // 0x39: Caps Lock (handled as toggle)
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 0x3A-0x45: F1-F12
    0,     // 0x46: Print Screen
    0,     // 0x47: Scroll Lock (handled as toggle)
    0,     // 0x48: Pause
    0,     // 0x49: Insert
    0,     // 0x4A: Home
    0,     // 0x4B: Page Up
    0x7F,  // 0x4C: Delete
    0,     // 0x4D: End
    0,     // 0x4E: Page Down
    0,     // 0x4F: Right Arrow
    0,     // 0x50: Left Arrow
    0,     // 0x51: Down Arrow
    0,     // 0x52: Up Arrow
    0,     // 0x53: Num Lock (handled as toggle)
    b'/',  // 0x54: Keypad /
    b'*',  // 0x55: Keypad *
    b'-',  // 0x56: Keypad -
    b'+',  // 0x57: Keypad +
    b'\r', // 0x58: Keypad Enter
    b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'0', // 0x59-0x62
    b'.',  // 0x63: Keypad .
    0,     // 0x64: non-US backslash
    0,     // 0x65: Application
];

/// Shifted ASCII values for USB HID scancodes 0x00..0x65.
static SCANCODE_TO_ASCII_SHIFT: [u8; 102] = [
    0,   0,   0,   0,   // 0x00-0x03
    b'A', b'B', b'C', b'D', b'E', b'F', b'G', b'H',  // 0x04-0x0B
    b'I', b'J', b'K', b'L', b'M', b'N', b'O', b'P',  // 0x0C-0x13
    b'Q', b'R', b'S', b'T', b'U', b'V', b'W', b'X',  // 0x14-0x1B
    b'Y', b'Z',                                        // 0x1C-0x1D
    b'!', b'@', b'#', b'$', b'%', b'^', b'&', b'*',  // 0x1E-0x25
    b'(', b')',                                        // 0x26-0x27
    b'\r', // 0x28: Enter
    0x1B,  // 0x29: Escape
    0x08,  // 0x2A: Backspace
    b'\t', // 0x2B: Tab
    b' ',  // 0x2C: Space
    b'_',  // 0x2D: underscore (shifted minus)
    b'+',  // 0x2E: plus (shifted equals)
    b'{',  // 0x2F: left brace
    b'}',  // 0x30: right brace
    b'|',  // 0x31: pipe (shifted backslash)
    0,     // 0x32: non-US ~
    b':',  // 0x33: colon
    b'"',  // 0x34: double-quote
    b'~',  // 0x35: tilde
    b'<',  // 0x36: less-than
    b'>',  // 0x37: greater-than
    b'?',  // 0x38: question mark
    0,     // 0x39: Caps Lock
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 0x3A-0x45: F1-F12
    0,     // 0x46: Print Screen
    0,     // 0x47: Scroll Lock
    0,     // 0x48: Pause
    0,     // 0x49: Insert
    0,     // 0x4A: Home
    0,     // 0x4B: Page Up
    0x7F,  // 0x4C: Delete
    0,     // 0x4D: End
    0,     // 0x4E: Page Down
    0,     // 0x4F: Right Arrow
    0,     // 0x50: Left Arrow
    0,     // 0x51: Down Arrow
    0,     // 0x52: Up Arrow
    0,     // 0x53: Num Lock
    b'/',  // 0x54: Keypad /
    b'*',  // 0x55: Keypad *
    b'-',  // 0x56: Keypad -
    b'+',  // 0x57: Keypad +
    b'\r', // 0x58: Keypad Enter
    b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'0', // 0x59-0x62
    b'.',  // 0x63: Keypad .
    0,     // 0x64: non-US backslash
    0,     // 0x65: Application
];

// ── Toggle-key scancode constants ──

const SC_CAPS_LOCK: u8 = 0x39;
const SC_NUM_LOCK: u8 = 0x53;
const SC_SCROLL_LOCK: u8 = 0x47;

// ── Helper: find device slot by dev_id ──

fn find_device(st: &DriverState, dev_id: u32) -> Option<usize> {
    for i in 0..MAX_DEVICES {
        if st.devices[i].dev_type != HidDeviceType::None && st.devices[i].dev_id == dev_id {
            return Some(i);
        }
    }
    None
}

/// Find a free device slot.
fn find_free_slot(st: &DriverState) -> Option<usize> {
    for i in 0..MAX_DEVICES {
        if st.devices[i].dev_type == HidDeviceType::None {
            return Some(i);
        }
    }
    None
}

/// Determine if shift is active based on modifier byte and caps lock state.
fn is_shifted(modifiers: u8, led_state: u8, scancode: u8) -> bool {
    let shift_held = (modifiers & (MOD_LSHIFT | MOD_RSHIFT)) != 0;
    let caps_on = (led_state & LED_CAPS_LOCK) != 0;
    // Caps lock only affects alphabetic keys (scancodes 0x04..=0x1D)
    if (0x04..=0x1D).contains(&scancode) {
        shift_held ^ caps_on
    } else {
        shift_held
    }
}

/// Convert a scancode to ASCII, considering modifiers and lock state.
fn scancode_to_ascii(scancode: u8, modifiers: u8, led_state: u8) -> u8 {
    if (scancode as usize) >= SCANCODE_TO_ASCII.len() {
        return 0;
    }
    if is_shifted(modifiers, led_state, scancode) {
        SCANCODE_TO_ASCII_SHIFT[scancode as usize]
    } else {
        SCANCODE_TO_ASCII[scancode as usize]
    }
}

/// Check if a scancode was present in the previous report.
fn was_pressed(prev: &[u8; MAX_BOOT_KEYS], sc: u8) -> bool {
    for &k in prev.iter() {
        if k == sc {
            return true;
        }
    }
    false
}

// ── FFI exports ──

/// Initialize the USB HID class driver.
/// Returns 0 on success.
#[unsafe(no_mangle)]
pub extern "C" fn usb_hid_init() -> i32 {
    let st = unsafe { &mut *STATE.get() };
    *st = DriverState::new();
    st.initialized = true;
    log("usb_hid: driver initialized");
    0
}

/// Register a keyboard device.
/// dev_id: unique identifier assigned by the USB host controller.
/// Returns 0 on success, -1 if no free slot or already registered.
#[unsafe(no_mangle)]
pub extern "C" fn usb_hid_register_keyboard(dev_id: u32) -> i32 {
    let st = unsafe { &mut *STATE.get() };
    if !st.initialized {
        return -1;
    }
    if find_device(st, dev_id).is_some() {
        return -1; // already registered
    }
    let slot = match find_free_slot(st) {
        Some(s) => s,
        None => return -1,
    };
    st.devices[slot] = HidDevice {
        dev_type: HidDeviceType::Keyboard,
        dev_id,
        prev_keys: [0; MAX_BOOT_KEYS],
        modifiers: 0,
    };
    log("usb_hid: keyboard registered");
    0
}

/// Register a mouse device.
/// dev_id: unique identifier assigned by the USB host controller.
/// Returns 0 on success, -1 if no free slot or already registered.
#[unsafe(no_mangle)]
pub extern "C" fn usb_hid_register_mouse(dev_id: u32) -> i32 {
    let st = unsafe { &mut *STATE.get() };
    if !st.initialized {
        return -1;
    }
    if find_device(st, dev_id).is_some() {
        return -1;
    }
    let slot = match find_free_slot(st) {
        Some(s) => s,
        None => return -1,
    };
    st.devices[slot] = HidDevice {
        dev_type: HidDeviceType::Mouse,
        dev_id,
        prev_keys: [0; MAX_BOOT_KEYS],
        modifiers: 0,
    };
    log("usb_hid: mouse registered");
    0
}

/// Process an 8-byte boot keyboard report from the interrupt endpoint.
///
/// Boot keyboard report format:
///   byte 0: modifier keys bitmask
///   byte 1: reserved (0x00)
///   bytes 2-7: up to 6 key scancodes (0 = no key)
///
/// Newly pressed keys are converted to ASCII and pushed into the ring buffer.
/// Toggle keys (Caps/Num/Scroll Lock) update LED state on key-down.
///
/// Returns 0 on success, -1 on error.
#[unsafe(no_mangle)]
pub extern "C" fn usb_hid_process_keyboard_report(
    dev_id: u32,
    report: *const u8,
    len: u32,
) -> i32 {
    if report.is_null() || len < 8 {
        return -1;
    }
    let st = unsafe { &mut *STATE.get() };
    if !st.initialized {
        return -1;
    }
    let idx = match find_device(st, dev_id) {
        Some(i) => i,
        None => return -1,
    };
    if st.devices[idx].dev_type != HidDeviceType::Keyboard {
        return -1;
    }

    let data = unsafe { core::slice::from_raw_parts(report, 8) };
    let modifiers = data[0];
    // data[1] is reserved
    let keys = &data[2..8];

    // Detect newly pressed keys (present now, absent in previous report)
    let prev = st.devices[idx].prev_keys;
    for &sc in keys.iter() {
        if sc == 0 || sc == 1 {
            // 0 = no key, 1 = error rollover
            continue;
        }
        if !was_pressed(&prev, sc) {
            // Handle toggle keys
            match sc {
                SC_CAPS_LOCK => {
                    st.led_state ^= LED_CAPS_LOCK;
                }
                SC_NUM_LOCK => {
                    st.led_state ^= LED_NUM_LOCK;
                }
                SC_SCROLL_LOCK => {
                    st.led_state ^= LED_SCROLL_LOCK;
                }
                _ => {
                    let ascii = scancode_to_ascii(sc, modifiers, st.led_state);
                    if ascii != 0 {
                        st.key_buf.push(ascii);
                    }
                }
            }
        }
    }

    // Update per-device state
    let mut new_keys = [0u8; MAX_BOOT_KEYS];
    for i in 0..MAX_BOOT_KEYS {
        new_keys[i] = keys[i];
    }
    st.devices[idx].prev_keys = new_keys;
    st.devices[idx].modifiers = modifiers;

    // Update global pressed keys snapshot
    st.pressed_keys = new_keys;

    0
}

/// Process a 3-4 byte boot mouse report from the interrupt endpoint.
///
/// Boot mouse report format:
///   byte 0: button bits (bit0=left, bit1=right, bit2=middle)
///   byte 1: X displacement (signed i8)
///   byte 2: Y displacement (signed i8)
///   byte 3: wheel scroll (signed i8, optional)
///
/// Deltas are accumulated until usb_hid_get_mouse_state() reads them.
///
/// Returns 0 on success, -1 on error.
#[unsafe(no_mangle)]
pub extern "C" fn usb_hid_process_mouse_report(
    dev_id: u32,
    report: *const u8,
    len: u32,
) -> i32 {
    if report.is_null() || len < 3 {
        return -1;
    }
    let st = unsafe { &mut *STATE.get() };
    if !st.initialized {
        return -1;
    }
    let idx = match find_device(st, dev_id) {
        Some(i) => i,
        None => return -1,
    };
    if st.devices[idx].dev_type != HidDeviceType::Mouse {
        return -1;
    }

    let data = unsafe { core::slice::from_raw_parts(report, len as usize) };

    st.mouse.buttons = data[0];

    // X and Y are signed 8-bit displacements; accumulate as i16 to
    // avoid losing data between reads.
    let dx = data[1] as i8;
    let dy = data[2] as i8;
    st.mouse.dx = st.mouse.dx.saturating_add(dx as i16);
    st.mouse.dy = st.mouse.dy.saturating_add(dy as i16);

    if len >= 4 {
        let w = data[3] as i8;
        st.mouse.wheel = st.mouse.wheel.saturating_add(w);
    }

    0
}

/// Retrieve the next ASCII key from the ring buffer.
/// Returns the character as a positive i32, or -1 if the buffer is empty.
#[unsafe(no_mangle)]
pub extern "C" fn usb_hid_get_key() -> i32 {
    let st = unsafe { &mut *STATE.get() };
    match st.key_buf.pop() {
        Some(ch) => ch as i32,
        None => -1,
    }
}

/// Read accumulated mouse state and reset deltas.
///
/// The caller provides pointers to receive:
///   buttons — current button bitmask
///   dx, dy  — accumulated X/Y displacement since last call
///   wheel   — accumulated wheel scroll since last call
///
/// Returns 0 on success, -1 if any pointer is null.
#[unsafe(no_mangle)]
pub extern "C" fn usb_hid_get_mouse_state(
    buttons: *mut u8,
    dx: *mut i16,
    dy: *mut i16,
    wheel: *mut i8,
) -> i32 {
    if buttons.is_null() || dx.is_null() || dy.is_null() || wheel.is_null() {
        return -1;
    }
    let st = unsafe { &mut *STATE.get() };

    unsafe {
        core::ptr::write(buttons, st.mouse.buttons);
        core::ptr::write(dx, st.mouse.dx);
        core::ptr::write(dy, st.mouse.dy);
        core::ptr::write(wheel, st.mouse.wheel);
    }

    // Reset accumulated deltas (buttons are level-triggered, not cleared)
    st.mouse.dx = 0;
    st.mouse.dy = 0;
    st.mouse.wheel = 0;

    0
}

/// Return current keyboard LED state as a bitmask:
///   bit 0 = Num Lock
///   bit 1 = Caps Lock
///   bit 2 = Scroll Lock
#[unsafe(no_mangle)]
pub extern "C" fn usb_hid_keyboard_led_state() -> u8 {
    let st = unsafe { &*STATE.get() };
    st.led_state
}
