// SPDX-License-Identifier: MPL-2.0
//
// i8042 PS/2 Controller Driver for Futura OS (x86-64)
//
// Implements the standard i8042 PS/2 keyboard/mouse controller found on
// all IBM PC-compatible systems.
//
// Features:
//   - Controller self-test and dual-port detection
//   - Keyboard initialisation with Scancode Set 1 mapping
//   - PS/2 mouse initialisation and 3-byte packet parsing
//   - 64-entry key event ring buffer
//   - Mouse state accumulator (buttons, delta X/Y)
//   - LED control (ScrollLock, NumLock, CapsLock)

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

// ── I/O ports ──

/// Data port: read received data, write device commands.
const DATA_PORT: u16 = 0x60;
/// Status register (read) / Command register (write).
const STATUS_CMD_PORT: u16 = 0x64;

// ── Status register bits (port 0x64, read) ──

/// Output buffer status: 1 = data available to read from port 0x60.
const STATUS_OBF: u8 = 1 << 0;
/// Input buffer status: 1 = controller busy, do not write.
const STATUS_IBF: u8 = 1 << 1;
/// Auxiliary output buffer: 1 = data is from the mouse (second port).
const STATUS_AUX: u8 = 1 << 5;
/// Timeout error.
const STATUS_TIMEOUT: u8 = 1 << 6;
/// Parity error.
const STATUS_PARITY: u8 = 1 << 7;

// ── Controller commands (write to port 0x64) ──

const CMD_READ_CONFIG: u8 = 0x20;
const CMD_WRITE_CONFIG: u8 = 0x60;
const CMD_DISABLE_PORT2: u8 = 0xA7;
const CMD_ENABLE_PORT2: u8 = 0xA8;
const CMD_TEST_PORT2: u8 = 0xA9;
const CMD_SELF_TEST: u8 = 0xAA;
const CMD_TEST_PORT1: u8 = 0xAB;
const CMD_DISABLE_PORT1: u8 = 0xAD;
const CMD_ENABLE_PORT1: u8 = 0xAE;
const CMD_WRITE_PORT2: u8 = 0xD4;

// ── Controller self-test / port-test results ──

const SELF_TEST_PASS: u8 = 0x55;
const PORT_TEST_PASS: u8 = 0x00;

// ── Configuration byte bits ──

const CONFIG_PORT1_IRQ: u8 = 1 << 0;
const CONFIG_PORT2_IRQ: u8 = 1 << 1;
const CONFIG_PORT1_CLK_DIS: u8 = 1 << 4;
const CONFIG_PORT2_CLK_DIS: u8 = 1 << 5;
const CONFIG_PORT1_XLAT: u8 = 1 << 6;

// ── PS/2 device commands / responses ──

const DEV_CMD_SET_LEDS: u8 = 0xED;
const _DEV_CMD_SCANCODE_SET: u8 = 0xF0;
const DEV_CMD_ENABLE_SCAN: u8 = 0xF4;
const _DEV_CMD_DISABLE_SCAN: u8 = 0xF5;
const DEV_CMD_RESET: u8 = 0xFF;
const DEV_CMD_SET_DEFAULTS: u8 = 0xF6;

const DEV_ACK: u8 = 0xFA;
const DEV_SELF_TEST_PASS: u8 = 0xAA;

// ── Scancode constants ──

/// Extended scancode prefix byte (Scancode Set 1).
const SC1_EXTENDED: u8 = 0xE0;
/// Break-code bit in Scancode Set 1.
const SC1_BREAK_BIT: u8 = 0x80;

// ── Key event ring buffer size ──

const KEY_RING_SIZE: usize = 64;

// ── Key event ──

#[derive(Copy, Clone)]
struct KeyEvent {
    /// Scancode (make code, without break bit).
    scancode: u8,
    /// `true` = key pressed, `false` = key released.
    pressed: bool,
}

impl KeyEvent {
    const fn zero() -> Self {
        Self {
            scancode: 0,
            pressed: false,
        }
    }
}

// ── Mouse state ──

#[derive(Copy, Clone)]
struct MouseState {
    /// Button state: bit 0 = left, bit 1 = right, bit 2 = middle.
    buttons: u8,
    /// Accumulated X movement since last query.
    dx: i16,
    /// Accumulated Y movement since last query.
    dy: i16,
    /// Packet assembly buffer (3 bytes for standard PS/2).
    packet: [u8; 3],
    /// Number of bytes received towards the current packet.
    packet_idx: u8,
}

impl MouseState {
    const fn new() -> Self {
        Self {
            buttons: 0,
            dx: 0,
            dy: 0,
            packet: [0; 3],
            packet_idx: 0,
        }
    }
}

// ── Driver state ──

struct DriverState {
    initialized: bool,
    has_keyboard: bool,
    has_mouse: bool,
    dual_channel: bool,
    /// Key event ring buffer.
    key_ring: [KeyEvent; KEY_RING_SIZE],
    /// Write index into key_ring (wraps modulo KEY_RING_SIZE).
    key_head: usize,
    /// Read index into key_ring (wraps modulo KEY_RING_SIZE).
    key_tail: usize,
    /// Number of events in the ring buffer.
    key_count: usize,
    /// Mouse accumulator state.
    mouse: MouseState,
    /// Extended scancode prefix pending.
    sc_extended: bool,
}

impl DriverState {
    const fn new() -> Self {
        Self {
            initialized: false,
            has_keyboard: false,
            has_mouse: false,
            dual_channel: false,
            key_ring: [KeyEvent::zero(); KEY_RING_SIZE],
            key_head: 0,
            key_tail: 0,
            key_count: 0,
            mouse: MouseState::new(),
            sc_extended: false,
        }
    }
}

static STATE: StaticCell<DriverState> = StaticCell::new(DriverState::new());

// ── x86 I/O port helpers ──

fn io_outb(port: u16, val: u8) {
    unsafe {
        core::arch::asm!("out dx, al", in("dx") port, in("al") val);
    }
}

fn io_inb(port: u16) -> u8 {
    let val: u8;
    unsafe {
        core::arch::asm!("in al, dx", in("dx") port, out("al") val);
    }
    val
}

/// Small I/O delay (standard x86 technique: dummy read of port 0x80).
fn io_delay() {
    io_inb(0x80);
}

// ── Controller I/O helpers ──

/// Wait until the input buffer is empty (controller ready to accept a write).
/// Returns `true` on success, `false` on timeout.
fn wait_input_ready() -> bool {
    for _ in 0..100_000u32 {
        if io_inb(STATUS_CMD_PORT) & STATUS_IBF == 0 {
            return true;
        }
        io_delay();
    }
    false
}

/// Wait until the output buffer is full (data available to read).
/// Returns `true` on success, `false` on timeout.
fn wait_output_ready() -> bool {
    for _ in 0..100_000u32 {
        if io_inb(STATUS_CMD_PORT) & STATUS_OBF != 0 {
            return true;
        }
        io_delay();
    }
    false
}

/// Send a command byte to the controller (port 0x64).
fn ctrl_cmd(cmd: u8) -> bool {
    if !wait_input_ready() {
        return false;
    }
    io_outb(STATUS_CMD_PORT, cmd);
    true
}

/// Write a data byte to the data port (port 0x60).
fn data_write(val: u8) -> bool {
    if !wait_input_ready() {
        return false;
    }
    io_outb(DATA_PORT, val);
    true
}

/// Read a data byte from the data port (port 0x60), with timeout.
fn data_read() -> Option<u8> {
    if wait_output_ready() {
        Some(io_inb(DATA_PORT))
    } else {
        None
    }
}

/// Flush any pending data in the output buffer.
fn flush_output_buffer() {
    for _ in 0..64u32 {
        if io_inb(STATUS_CMD_PORT) & STATUS_OBF == 0 {
            break;
        }
        let _ = io_inb(DATA_PORT);
        io_delay();
    }
}

/// Send a command to a PS/2 device on port 1 (keyboard) and wait for ACK.
fn device_cmd_port1(cmd: u8) -> bool {
    if !data_write(cmd) {
        return false;
    }
    match data_read() {
        Some(DEV_ACK) => true,
        _ => false,
    }
}

/// Send a command to a PS/2 device on port 2 (mouse) and wait for ACK.
fn device_cmd_port2(cmd: u8) -> bool {
    if !ctrl_cmd(CMD_WRITE_PORT2) {
        return false;
    }
    if !data_write(cmd) {
        return false;
    }
    match data_read() {
        Some(DEV_ACK) => true,
        _ => false,
    }
}

// ── Ring buffer helpers ──

fn ring_push(s: &mut DriverState, ev: KeyEvent) {
    s.key_ring[s.key_head] = ev;
    s.key_head = (s.key_head + 1) % KEY_RING_SIZE;
    if s.key_count < KEY_RING_SIZE {
        s.key_count += 1;
    } else {
        // Overwrite oldest: advance tail.
        s.key_tail = (s.key_tail + 1) % KEY_RING_SIZE;
    }
}

fn ring_pop(s: &mut DriverState) -> Option<KeyEvent> {
    if s.key_count == 0 {
        return None;
    }
    let ev = s.key_ring[s.key_tail];
    s.key_tail = (s.key_tail + 1) % KEY_RING_SIZE;
    s.key_count -= 1;
    Some(ev)
}

// ── Scancode Set 1 make-code to ASCII/keycode mapping ──
//
// Index = make code (0x00..0x58). Value = printable ASCII character or
// a symbolic constant. 0 = unmapped.
//
// This table handles the basic US keyboard layout for the low scancodes.
// Extended scancodes (0xE0 prefixed) are stored with bit 7 in a separate
// logical space.

static SC1_MAP: [u8; 89] = [
    0,    // 0x00 - (none)
    0x1B, // 0x01 - Escape
    b'1', // 0x02
    b'2', // 0x03
    b'3', // 0x04
    b'4', // 0x05
    b'5', // 0x06
    b'6', // 0x07
    b'7', // 0x08
    b'8', // 0x09
    b'9', // 0x0A
    b'0', // 0x0B
    b'-', // 0x0C
    b'=', // 0x0D
    0x08, // 0x0E - Backspace
    0x09, // 0x0F - Tab
    b'q', // 0x10
    b'w', // 0x11
    b'e', // 0x12
    b'r', // 0x13
    b't', // 0x14
    b'y', // 0x15
    b'u', // 0x16
    b'i', // 0x17
    b'o', // 0x18
    b'p', // 0x19
    b'[', // 0x1A
    b']', // 0x1B
    0x0A, // 0x1C - Enter
    0,    // 0x1D - Left Ctrl (modifier, no printable)
    b'a', // 0x1E
    b's', // 0x1F
    b'd', // 0x20
    b'f', // 0x21
    b'g', // 0x22
    b'h', // 0x23
    b'j', // 0x24
    b'k', // 0x25
    b'l', // 0x26
    b';', // 0x27
    b'\'',// 0x28
    b'`', // 0x29
    0,    // 0x2A - Left Shift (modifier)
    b'\\',// 0x2B
    b'z', // 0x2C
    b'x', // 0x2D
    b'c', // 0x2E
    b'v', // 0x2F
    b'b', // 0x30
    b'n', // 0x31
    b'm', // 0x32
    b',', // 0x33
    b'.', // 0x34
    b'/', // 0x35
    0,    // 0x36 - Right Shift (modifier)
    b'*', // 0x37 - Keypad *
    0,    // 0x38 - Left Alt (modifier)
    b' ', // 0x39 - Space
    0,    // 0x3A - CapsLock
    0,    // 0x3B - F1
    0,    // 0x3C - F2
    0,    // 0x3D - F3
    0,    // 0x3E - F4
    0,    // 0x3F - F5
    0,    // 0x40 - F6
    0,    // 0x41 - F7
    0,    // 0x42 - F8
    0,    // 0x43 - F9
    0,    // 0x44 - F10
    0,    // 0x45 - NumLock
    0,    // 0x46 - ScrollLock
    b'7', // 0x47 - Keypad 7 / Home
    b'8', // 0x48 - Keypad 8 / Up
    b'9', // 0x49 - Keypad 9 / PgUp
    b'-', // 0x4A - Keypad -
    b'4', // 0x4B - Keypad 4 / Left
    b'5', // 0x4C - Keypad 5
    b'6', // 0x4D - Keypad 6 / Right
    b'+', // 0x4E - Keypad +
    b'1', // 0x4F - Keypad 1 / End
    b'2', // 0x50 - Keypad 2 / Down
    b'3', // 0x51 - Keypad 3 / PgDn
    b'0', // 0x52 - Keypad 0 / Ins
    b'.', // 0x53 - Keypad . / Del
    0,    // 0x54
    0,    // 0x55
    0,    // 0x56
    0,    // 0x57 - F11
    0,    // 0x58 - F12
];

// ── Mouse packet parsing ──

fn parse_mouse_packet(mouse: &mut MouseState) {
    let b0 = mouse.packet[0];
    let b1 = mouse.packet[1];
    let b2 = mouse.packet[2];

    // Buttons: bits [2:0] of byte 0.
    mouse.buttons = b0 & 0x07;

    // X movement: 9-bit signed, sign in bit 4 of byte 0.
    let mut dx = b1 as i16;
    if b0 & (1 << 4) != 0 {
        // Sign-extend: the upper byte is all 1s.
        dx |= !0xFF_i16;
    }

    // Y movement: 9-bit signed, sign in bit 5 of byte 0.
    let mut dy = b2 as i16;
    if b0 & (1 << 5) != 0 {
        dy |= !0xFF_i16;
    }

    // Check for overflow and discard if so.
    if b0 & (1 << 6) != 0 || b0 & (1 << 7) != 0 {
        // Overflow in X or Y -- discard movement, keep buttons.
        return;
    }

    mouse.dx = mouse.dx.saturating_add(dx);
    mouse.dy = mouse.dy.saturating_add(dy);
}

// ── Exported functions ──

/// Initialise the i8042 PS/2 controller.
///
/// Performs a controller self-test, detects available ports (keyboard/mouse),
/// and configures the controller for interrupt-driven operation.
///
/// Returns 0 on success, -1 on self-test failure.
#[unsafe(no_mangle)]
pub extern "C" fn i8042_init() -> i32 {
    log("i8042: initializing PS/2 controller");

    // Step 1: Disable both ports during setup.
    ctrl_cmd(CMD_DISABLE_PORT1);
    ctrl_cmd(CMD_DISABLE_PORT2);

    // Flush any stale data.
    flush_output_buffer();

    // Step 2: Read configuration byte and disable IRQs + translation.
    if !ctrl_cmd(CMD_READ_CONFIG) {
        log("i8042: failed to read configuration byte");
        return -1;
    }
    let config = match data_read() {
        Some(v) => v,
        None => {
            log("i8042: timeout reading configuration byte");
            return -1;
        }
    };

    // Disable IRQs for both ports and translation during init.
    let init_config = config & !(CONFIG_PORT1_IRQ | CONFIG_PORT2_IRQ | CONFIG_PORT1_XLAT);
    if !ctrl_cmd(CMD_WRITE_CONFIG) || !data_write(init_config) {
        log("i8042: failed to write configuration byte");
        return -1;
    }

    // Step 3: Controller self-test.
    if !ctrl_cmd(CMD_SELF_TEST) {
        log("i8042: failed to send self-test command");
        return -1;
    }
    let result = match data_read() {
        Some(v) => v,
        None => {
            log("i8042: self-test timeout");
            return -1;
        }
    };
    if result != SELF_TEST_PASS {
        unsafe {
            fut_printf(
                b"i8042: self-test failed (0x%02x, expected 0x55)\n\0".as_ptr(),
                result as u32,
            );
        }
        return -1;
    }

    // The self-test may reset the controller, so re-write config.
    if !ctrl_cmd(CMD_WRITE_CONFIG) || !data_write(init_config) {
        log("i8042: failed to re-write configuration after self-test");
        return -1;
    }

    // Step 4: Detect dual-channel controller.
    // If bit 5 (port 2 clock disable) was set in the original config,
    // the controller might be dual-channel. Enable port 2 and re-read.
    let mut dual_channel = false;
    ctrl_cmd(CMD_ENABLE_PORT2);
    if ctrl_cmd(CMD_READ_CONFIG) {
        if let Some(cfg2) = data_read() {
            if cfg2 & CONFIG_PORT2_CLK_DIS == 0 {
                // Port 2 clock is now enabled -- controller is dual-channel.
                dual_channel = true;
            }
        }
    }
    // Disable port 2 again for testing.
    if dual_channel {
        ctrl_cmd(CMD_DISABLE_PORT2);
    }

    // Step 5: Test port 1 (keyboard).
    let mut port1_ok = false;
    if ctrl_cmd(CMD_TEST_PORT1) {
        if let Some(r) = data_read() {
            if r == PORT_TEST_PASS {
                port1_ok = true;
            } else {
                unsafe {
                    fut_printf(
                        b"i8042: port 1 test failed (0x%02x)\n\0".as_ptr(),
                        r as u32,
                    );
                }
            }
        }
    }

    // Step 6: Test port 2 (mouse) if dual-channel.
    let mut port2_ok = false;
    if dual_channel {
        if ctrl_cmd(CMD_TEST_PORT2) {
            if let Some(r) = data_read() {
                if r == PORT_TEST_PASS {
                    port2_ok = true;
                } else {
                    unsafe {
                        fut_printf(
                            b"i8042: port 2 test failed (0x%02x)\n\0".as_ptr(),
                            r as u32,
                        );
                    }
                }
            }
        }
    }

    // Step 7: Enable working ports.
    if port1_ok {
        ctrl_cmd(CMD_ENABLE_PORT1);
    }
    if port2_ok {
        ctrl_cmd(CMD_ENABLE_PORT2);
    }

    // Step 8: Set up configuration: enable IRQs for working ports,
    // enable translation (scancode set 1) for keyboard.
    let mut final_config = init_config;
    if port1_ok {
        final_config |= CONFIG_PORT1_IRQ | CONFIG_PORT1_XLAT;
        // Ensure port 1 clock is not disabled.
        final_config &= !CONFIG_PORT1_CLK_DIS;
    }
    if port2_ok {
        final_config |= CONFIG_PORT2_IRQ;
        final_config &= !CONFIG_PORT2_CLK_DIS;
    }
    if !ctrl_cmd(CMD_WRITE_CONFIG) || !data_write(final_config) {
        log("i8042: failed to write final configuration");
        return -1;
    }

    // Store state.
    let s = unsafe { &mut *STATE.get() };
    s.has_keyboard = port1_ok;
    s.has_mouse = port2_ok;
    s.dual_channel = dual_channel;
    s.initialized = true;

    unsafe {
        fut_printf(
            b"i8042: controller ready - keyboard=%s, mouse=%s\n\0".as_ptr(),
            if port1_ok {
                b"yes\0".as_ptr()
            } else {
                b"no\0".as_ptr()
            },
            if port2_ok {
                b"yes\0".as_ptr()
            } else {
                b"no\0".as_ptr()
            },
        );
    }

    0
}

/// Enable and initialise the PS/2 keyboard on port 1.
///
/// Resets the keyboard device, waits for self-test pass, and enables
/// scanning.  The keyboard must have been detected by `i8042_init`.
///
/// Returns 0 on success, -1 on error.
#[unsafe(no_mangle)]
pub extern "C" fn i8042_keyboard_enable() -> i32 {
    let s = unsafe { &mut *STATE.get() };
    if !s.initialized || !s.has_keyboard {
        return -1;
    }

    // Reset keyboard.
    flush_output_buffer();
    if !device_cmd_port1(DEV_CMD_RESET) {
        log("i8042: keyboard reset failed (no ACK)");
        return -1;
    }

    // Wait for self-test pass (0xAA).
    match data_read() {
        Some(DEV_SELF_TEST_PASS) => {}
        Some(other) => {
            unsafe {
                fut_printf(
                    b"i8042: keyboard self-test returned 0x%02x\n\0".as_ptr(),
                    other as u32,
                );
            }
            return -1;
        }
        None => {
            log("i8042: keyboard self-test timeout");
            return -1;
        }
    }

    // Enable scanning.
    if !device_cmd_port1(DEV_CMD_ENABLE_SCAN) {
        log("i8042: keyboard enable scanning failed");
        return -1;
    }

    log("i8042: keyboard enabled");
    0
}

/// Enable and initialise the PS/2 mouse on port 2.
///
/// Resets the mouse, sets defaults, and enables data reporting.
/// The mouse must have been detected by `i8042_init`.
///
/// Returns 0 on success, -1 on error.
#[unsafe(no_mangle)]
pub extern "C" fn i8042_mouse_enable() -> i32 {
    let s = unsafe { &mut *STATE.get() };
    if !s.initialized || !s.has_mouse {
        return -1;
    }

    // Reset mouse.
    flush_output_buffer();
    if !device_cmd_port2(DEV_CMD_RESET) {
        log("i8042: mouse reset failed (no ACK)");
        return -1;
    }

    // Wait for self-test pass (0xAA) followed by device ID (0x00).
    match data_read() {
        Some(DEV_SELF_TEST_PASS) => {}
        Some(other) => {
            unsafe {
                fut_printf(
                    b"i8042: mouse self-test returned 0x%02x\n\0".as_ptr(),
                    other as u32,
                );
            }
            return -1;
        }
        None => {
            log("i8042: mouse self-test timeout");
            return -1;
        }
    }
    // Read and discard device ID byte.
    let _ = data_read();

    // Set defaults.
    if !device_cmd_port2(DEV_CMD_SET_DEFAULTS) {
        log("i8042: mouse set-defaults failed");
        return -1;
    }

    // Enable data reporting.
    if !device_cmd_port2(DEV_CMD_ENABLE_SCAN) {
        log("i8042: mouse enable reporting failed");
        return -1;
    }

    // Reset packet assembly state.
    s.mouse = MouseState::new();

    log("i8042: mouse enabled");
    0
}

/// Read a raw scancode from the keyboard data port.
///
/// Checks the status register for available data from port 1 (keyboard)
/// and returns the byte.  Returns -1 if no keyboard data is available.
#[unsafe(no_mangle)]
pub extern "C" fn i8042_read_scancode() -> i32 {
    let s = unsafe { &*STATE.get() };
    if !s.initialized {
        return -1;
    }

    let status = io_inb(STATUS_CMD_PORT);
    if status & STATUS_OBF == 0 {
        return -1;
    }
    // Only return keyboard data (not mouse data).
    if status & STATUS_AUX != 0 {
        return -1;
    }
    io_inb(DATA_PORT) as i32
}

/// Process all pending keyboard scancodes and enqueue key events.
///
/// Reads all available keyboard bytes from the controller, translates
/// Scancode Set 1 make/break codes, handles the 0xE0 extended prefix,
/// and pushes events into the ring buffer.
///
/// Returns the number of key events enqueued during this call.
#[unsafe(no_mangle)]
pub extern "C" fn i8042_process_keyboard() -> i32 {
    let s = unsafe { &mut *STATE.get() };
    if !s.initialized || !s.has_keyboard {
        return 0;
    }

    let mut count: i32 = 0;

    // Process up to 64 bytes per call to avoid infinite loops.
    for _ in 0..64u32 {
        let status = io_inb(STATUS_CMD_PORT);
        if status & STATUS_OBF == 0 {
            break;
        }
        // Skip mouse data.
        if status & STATUS_AUX != 0 {
            break;
        }

        let byte = io_inb(DATA_PORT);

        // Handle extended prefix.
        if byte == SC1_EXTENDED {
            s.sc_extended = true;
            continue;
        }

        let pressed = (byte & SC1_BREAK_BIT) == 0;
        let make_code = byte & !SC1_BREAK_BIT;

        // For extended scancodes, store with bit 7 set in the scancode
        // field to distinguish from base scancodes. We use the make code
        // ORed with 0x80 as the identifier.
        let scancode = if s.sc_extended {
            s.sc_extended = false;
            make_code | 0x80
        } else {
            make_code
        };

        ring_push(s, KeyEvent { scancode, pressed });
        count += 1;
    }

    count
}

/// Process pending mouse data and assemble a complete packet.
///
/// Reads mouse bytes from the controller and assembles them into
/// 3-byte standard PS/2 packets.  When a complete packet is assembled
/// it is parsed into the mouse state accumulator.
///
/// Returns 1 if a complete packet was parsed, 0 otherwise.
#[unsafe(no_mangle)]
pub extern "C" fn i8042_process_mouse() -> i32 {
    let s = unsafe { &mut *STATE.get() };
    if !s.initialized || !s.has_mouse {
        return 0;
    }

    let mut parsed = 0i32;

    // Process up to 16 bytes per call.
    for _ in 0..16u32 {
        let status = io_inb(STATUS_CMD_PORT);
        if status & STATUS_OBF == 0 {
            break;
        }
        // Only process mouse data.
        if status & STATUS_AUX == 0 {
            break;
        }

        let byte = io_inb(DATA_PORT);
        let idx = s.mouse.packet_idx as usize;

        // Byte 0 synchronisation: bit 3 must always be set in a valid
        // PS/2 mouse first byte.
        if idx == 0 && (byte & 0x08) == 0 {
            // Out of sync -- discard and try next byte.
            continue;
        }

        s.mouse.packet[idx] = byte;
        s.mouse.packet_idx += 1;

        if s.mouse.packet_idx >= 3 {
            parse_mouse_packet(&mut s.mouse);
            s.mouse.packet_idx = 0;
            parsed = 1;
        }
    }

    parsed
}

/// Dequeue a key event from the ring buffer.
///
/// On success, writes the scancode and pressed state through the
/// provided pointers and returns 0.  Returns -1 if the ring buffer
/// is empty or if null pointers are provided.
#[unsafe(no_mangle)]
pub extern "C" fn i8042_get_key_event(scancode: *mut u8, pressed: *mut bool) -> i32 {
    if scancode.is_null() || pressed.is_null() {
        return -1;
    }

    let s = unsafe { &mut *STATE.get() };
    match ring_pop(s) {
        Some(ev) => {
            unsafe {
                *scancode = ev.scancode;
                *pressed = ev.pressed;
            }
            0
        }
        None => -1,
    }
}

/// Retrieve the accumulated mouse state and reset the deltas.
///
/// Writes the current button state and accumulated X/Y movement
/// through the provided pointers, then resets the deltas to zero.
///
/// Returns 0 on success, -1 on null pointers or uninitialised driver.
#[unsafe(no_mangle)]
pub extern "C" fn i8042_get_mouse_state(buttons: *mut u8, dx: *mut i16, dy: *mut i16) -> i32 {
    if buttons.is_null() || dx.is_null() || dy.is_null() {
        return -1;
    }

    let s = unsafe { &mut *STATE.get() };
    if !s.initialized {
        return -1;
    }

    unsafe {
        *buttons = s.mouse.buttons;
        *dx = s.mouse.dx;
        *dy = s.mouse.dy;
    }

    // Reset accumulated deltas.
    s.mouse.dx = 0;
    s.mouse.dy = 0;

    0
}

/// Set the keyboard indicator LEDs.
///
/// `leds`: bit 0 = ScrollLock, bit 1 = NumLock, bit 2 = CapsLock.
///
/// Returns 0 on success, -1 on error.
#[unsafe(no_mangle)]
pub extern "C" fn i8042_set_keyboard_leds(leds: u8) -> i32 {
    let s = unsafe { &*STATE.get() };
    if !s.initialized || !s.has_keyboard {
        return -1;
    }

    // Send the "Set LEDs" command.
    if !device_cmd_port1(DEV_CMD_SET_LEDS) {
        log("i8042: set LEDs command failed");
        return -1;
    }

    // Send the LED state byte (only lower 3 bits are meaningful).
    if !device_cmd_port1(leds & 0x07) {
        log("i8042: set LEDs data byte failed");
        return -1;
    }

    0
}

/// Check whether a keyboard was detected on port 1.
#[unsafe(no_mangle)]
pub extern "C" fn i8042_has_keyboard() -> bool {
    let s = unsafe { &*STATE.get() };
    s.initialized && s.has_keyboard
}

/// Check whether a mouse was detected on port 2.
#[unsafe(no_mangle)]
pub extern "C" fn i8042_has_mouse() -> bool {
    let s = unsafe { &*STATE.get() };
    s.initialized && s.has_mouse
}
