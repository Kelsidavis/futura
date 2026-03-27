// SPDX-License-Identifier: MPL-2.0
//
// ACPI Button Driver for Futura OS (x86-64)
//
// Handles ACPI power button, sleep button, and lid switch events via
// PM1 Status/Enable registers and a callback/polling model.
//
// Architecture:
//   - Power Button: PM1_STS bit 8 (PWRBTN_STS), PM1_EN bit 8 (PWRBTN_EN)
//   - Sleep Button: PM1_STS bit 9 (SLPBTN_STS), PM1_EN bit 9 (SLPBTN_EN)
//   - Lid Switch:   platform-specific (GPE or EC), tracked via software
//
// PM register access uses the same I/O port bases as the acpi_pm driver:
//   PM1a_EVT_BLK + 0x00  PM1_STS  (16-bit, R/WC)
//   PM1a_EVT_BLK + 0x02  PM1_EN   (16-bit, RW)
//
// Button event model:
//   - Polling: events are stored in a 16-entry ring buffer
//   - Callback: an optional function is invoked immediately on detection
//   - Press counts are tracked per button type

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(unexpected_cfgs)]

use core::cell::UnsafeCell;
use core::sync::atomic::{fence, Ordering};

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

// ── Button type constants ──

/// Power button.
const BUTTON_POWER: u32 = 0;

/// Sleep button.
const BUTTON_SLEEP: u32 = 1;

/// Lid switch.
const BUTTON_LID: u32 = 2;

/// Number of distinct button types.
const BUTTON_TYPE_COUNT: usize = 3;

// ── PM1 Status Register bits (PM1_STS, 16-bit at PM1a_EVT_BLK + 0x00) ──

/// Power button pressed.
const PM1_STS_PWRBTN: u16 = 1 << 8;

/// Sleep button pressed.
const PM1_STS_SLPBTN: u16 = 1 << 9;

// ── PM1 Enable Register bits (PM1_EN, 16-bit at PM1a_EVT_BLK + 0x02) ──

/// Power button enable.
const PM1_EN_PWRBTN: u16 = 1 << 8;

/// Sleep button enable.
const PM1_EN_SLPBTN: u16 = 1 << 9;

// ── Event ring buffer ──

/// Maximum number of events in the ring buffer.
const EVENT_RING_SIZE: usize = 16;

/// A button event record.
#[derive(Clone, Copy)]
struct ButtonEvent {
    /// Button type: 0=Power, 1=Sleep, 2=Lid.
    button_type: u32,
    /// Whether the button is pressed (true) or released (false).
    pressed: bool,
    /// Timestamp (opaque, incremented monotonically from a software counter).
    timestamp: u64,
}

impl ButtonEvent {
    const fn empty() -> Self {
        Self {
            button_type: 0,
            pressed: false,
            timestamp: 0,
        }
    }
}

// ── Callback type ──

/// Callback function signature for immediate button event notification.
/// Parameters: button_type (0=Power, 1=Sleep, 2=Lid), pressed (true/false).
type ButtonCallbackFn = unsafe extern "C" fn(button_type: u32, pressed: bool);

// ── Driver state ──

struct AcpiButtonState {
    /// I/O port base for PM1 status register (PM1_STS at +0).
    pm1a_evt: u16,
    /// I/O port for PM1 enable register (PM1_EN at pm1a_evt + 2, but
    /// we accept it separately for flexibility).
    pm1a_en: u16,
    /// Per-button enable flags.
    enabled: [bool; BUTTON_TYPE_COUNT],
    /// Per-button press counts.
    press_count: [u32; BUTTON_TYPE_COUNT],
    /// Event ring buffer.
    ring: [ButtonEvent; EVENT_RING_SIZE],
    /// Ring write index (next slot to write).
    ring_head: usize,
    /// Ring read index (next slot to read).
    ring_tail: usize,
    /// Number of events currently in the ring.
    ring_count: usize,
    /// Software timestamp counter (incremented per event).
    timestamp_counter: u64,
    /// Optional callback for immediate notification.
    callback: Option<ButtonCallbackFn>,
    /// Whether the driver has been initialized.
    initialized: bool,
}

impl AcpiButtonState {
    const fn new() -> Self {
        Self {
            pm1a_evt: 0,
            pm1a_en: 0,
            enabled: [false; BUTTON_TYPE_COUNT],
            press_count: [0; BUTTON_TYPE_COUNT],
            ring: [ButtonEvent::empty(); EVENT_RING_SIZE],
            ring_head: 0,
            ring_tail: 0,
            ring_count: 0,
            timestamp_counter: 0,
            callback: None,
            initialized: false,
        }
    }
}

static STATE: StaticCell<AcpiButtonState> = StaticCell::new(AcpiButtonState::new());

// ── x86 I/O port helpers ──

fn io_outw(port: u16, val: u16) {
    unsafe {
        core::arch::asm!("out dx, ax", in("dx") port, in("ax") val);
    }
}

fn io_inw(port: u16) -> u16 {
    let val: u16;
    unsafe {
        core::arch::asm!("in ax, dx", in("dx") port, out("ax") val);
    }
    val
}

// ── Internal register access helpers ──

/// Read PM1 Status register (16-bit at PM1a_EVT_BLK + 0x00).
#[inline]
fn pm1_sts_read(base: u16) -> u16 {
    io_inw(base)
}

/// Write PM1 Status register (write-1-to-clear semantics).
#[inline]
fn pm1_sts_write(base: u16, val: u16) {
    io_outw(base, val);
}

/// Read PM1 Enable register (16-bit at PM1a_EN port).
#[inline]
fn pm1_en_read(port: u16) -> u16 {
    io_inw(port)
}

/// Write PM1 Enable register.
#[inline]
fn pm1_en_write(port: u16, val: u16) {
    io_outw(port, val);
}

// ── Internal helpers ──

/// Push an event into the ring buffer. If the buffer is full, the oldest
/// event is overwritten.
fn ring_push(state: &mut AcpiButtonState, event: ButtonEvent) {
    state.ring[state.ring_head] = event;
    state.ring_head = (state.ring_head + 1) % EVENT_RING_SIZE;
    if state.ring_count < EVENT_RING_SIZE {
        state.ring_count += 1;
    } else {
        // Overwrite oldest: advance tail.
        state.ring_tail = (state.ring_tail + 1) % EVENT_RING_SIZE;
    }
}

/// Pop the oldest event from the ring buffer, if any.
fn ring_pop(state: &mut AcpiButtonState) -> Option<ButtonEvent> {
    if state.ring_count == 0 {
        return None;
    }
    let event = state.ring[state.ring_tail];
    state.ring_tail = (state.ring_tail + 1) % EVENT_RING_SIZE;
    state.ring_count -= 1;
    Some(event)
}

/// Record a button press: increment count, push event, invoke callback.
fn record_button_press(state: &mut AcpiButtonState, button_type: u32) {
    if (button_type as usize) < BUTTON_TYPE_COUNT {
        state.press_count[button_type as usize] =
            state.press_count[button_type as usize].wrapping_add(1);
    }

    state.timestamp_counter += 1;
    let event = ButtonEvent {
        button_type,
        pressed: true,
        timestamp: state.timestamp_counter,
    };

    ring_push(state, event);

    // Invoke callback if registered.
    if let Some(cb) = state.callback {
        unsafe {
            cb(button_type, true);
        }
    }
}

/// Map a button type constant to (PM1_STS bit, PM1_EN bit). Returns None
/// for lid (not directly mapped to PM1 registers).
fn button_pm1_bits(button_type: u32) -> Option<(u16, u16)> {
    match button_type {
        BUTTON_POWER => Some((PM1_STS_PWRBTN, PM1_EN_PWRBTN)),
        BUTTON_SLEEP => Some((PM1_STS_SLPBTN, PM1_EN_SLPBTN)),
        _ => None,
    }
}

// ── FFI exports ──

/// Initialize the ACPI button driver.
///
/// Parameters (I/O port addresses from ACPI FADT):
///   `pm1a_evt`: PM1a Event Block base (PM1_STS at +0x00)
///   `pm1a_en`:  PM1 Enable register port (typically PM1a_EVT + 0x02)
///
/// Returns 0 on success, negative on error:
///   -1 = invalid port configuration (pm1a_evt or pm1a_en is 0)
#[unsafe(no_mangle)]
pub extern "C" fn acpi_button_init(pm1a_evt: u16, pm1a_en: u16) -> i32 {
    log("acpi_button: initializing ACPI button driver");

    if pm1a_evt == 0 || pm1a_en == 0 {
        log("acpi_button: invalid PM1 port configuration");
        return -1;
    }

    // Read and log current PM1 status.
    let sts = pm1_sts_read(pm1a_evt);
    let en = pm1_en_read(pm1a_en);

    unsafe {
        fut_printf(
            b"acpi_button: PM1a_EVT=0x%04x PM1a_EN=0x%04x\n\0".as_ptr(),
            pm1a_evt as u32,
            pm1a_en as u32,
        );
        fut_printf(
            b"acpi_button: PM1_STS=0x%04x PM1_EN=0x%04x\n\0".as_ptr(),
            sts as u32,
            en as u32,
        );
    }

    // Clear any pending button status bits.
    pm1_sts_write(pm1a_evt, PM1_STS_PWRBTN | PM1_STS_SLPBTN);

    // Store driver state.
    let state = STATE.get();
    unsafe {
        let s = &mut *state;
        s.pm1a_evt = pm1a_evt;
        s.pm1a_en = pm1a_en;
        s.enabled = [false; BUTTON_TYPE_COUNT];
        s.press_count = [0; BUTTON_TYPE_COUNT];
        s.ring_head = 0;
        s.ring_tail = 0;
        s.ring_count = 0;
        s.timestamp_counter = 0;
        s.callback = None;
        fence(Ordering::SeqCst);
        s.initialized = true;
    }

    log("acpi_button: driver initialized");
    0
}

/// Enable events for a specific button type.
///
/// `button_type`: 0=Power, 1=Sleep, 2=Lid.
///
/// For power and sleep buttons, this sets the corresponding PM1_EN bit.
/// For lid, this only sets the software enable flag (hardware signaling
/// is platform-specific via GPE/EC).
///
/// Returns 0 on success, -1 if not initialized, -2 if invalid button type.
#[unsafe(no_mangle)]
pub extern "C" fn acpi_button_enable(button_type: u32) -> i32 {
    let state = STATE.get();
    unsafe {
        let s = &mut *state;
        if !s.initialized {
            return -1;
        }
        if (button_type as usize) >= BUTTON_TYPE_COUNT {
            return -2;
        }

        s.enabled[button_type as usize] = true;

        // Set hardware enable bit for power/sleep buttons.
        if let Some((_sts_bit, en_bit)) = button_pm1_bits(button_type) {
            let en = pm1_en_read(s.pm1a_en);
            pm1_en_write(s.pm1a_en, en | en_bit);
        }

        match button_type {
            BUTTON_POWER => log("acpi_button: power button enabled"),
            BUTTON_SLEEP => log("acpi_button: sleep button enabled"),
            BUTTON_LID => log("acpi_button: lid switch enabled (software only)"),
            _ => {}
        }

        0
    }
}

/// Disable events for a specific button type.
///
/// `button_type`: 0=Power, 1=Sleep, 2=Lid.
///
/// For power and sleep buttons, this clears the corresponding PM1_EN bit.
///
/// Returns 0 on success, -1 if not initialized, -2 if invalid button type.
#[unsafe(no_mangle)]
pub extern "C" fn acpi_button_disable(button_type: u32) -> i32 {
    let state = STATE.get();
    unsafe {
        let s = &mut *state;
        if !s.initialized {
            return -1;
        }
        if (button_type as usize) >= BUTTON_TYPE_COUNT {
            return -2;
        }

        s.enabled[button_type as usize] = false;

        // Clear hardware enable bit for power/sleep buttons.
        if let Some((_sts_bit, en_bit)) = button_pm1_bits(button_type) {
            let en = pm1_en_read(s.pm1a_en);
            pm1_en_write(s.pm1a_en, en & !en_bit);
        }

        match button_type {
            BUTTON_POWER => log("acpi_button: power button disabled"),
            BUTTON_SLEEP => log("acpi_button: sleep button disabled"),
            BUTTON_LID => log("acpi_button: lid switch disabled"),
            _ => {}
        }

        0
    }
}

/// Poll for button events.
///
/// Checks PM1_STS for power and sleep button presses, clears the status
/// bits (W1C), records events, and returns the button type of the oldest
/// pending event from the ring buffer.
///
/// Returns:
///   >= 0: button type of the dequeued event (0=Power, 1=Sleep, 2=Lid)
///   -1:   no pending events
///   -2:   driver not initialized
#[unsafe(no_mangle)]
pub extern "C" fn acpi_button_poll() -> i32 {
    let state = STATE.get();
    unsafe {
        let s = &mut *state;
        if !s.initialized {
            return -2;
        }

        // Read PM1 status to detect hardware button presses.
        let sts = pm1_sts_read(s.pm1a_evt);
        let mut clear_mask: u16 = 0;

        // Check power button.
        if s.enabled[BUTTON_POWER as usize] && (sts & PM1_STS_PWRBTN) != 0 {
            clear_mask |= PM1_STS_PWRBTN;
            record_button_press(s, BUTTON_POWER);
        }

        // Check sleep button.
        if s.enabled[BUTTON_SLEEP as usize] && (sts & PM1_STS_SLPBTN) != 0 {
            clear_mask |= PM1_STS_SLPBTN;
            record_button_press(s, BUTTON_SLEEP);
        }

        // Clear any detected status bits (write-1-to-clear).
        if clear_mask != 0 {
            pm1_sts_write(s.pm1a_evt, clear_mask);
        }

        // Dequeue the oldest event from the ring buffer.
        match ring_pop(s) {
            Some(event) => event.button_type as i32,
            None => -1,
        }
    }
}

/// Register a callback function for immediate button event notification.
///
/// The callback is invoked from within `acpi_button_poll()` when a new
/// event is detected, before the event is returned to the caller.
///
/// Pass a valid function pointer to register, or the behavior is undefined
/// if the pointer is invalid.
///
/// Returns 0 on success, -1 if not initialized.
#[unsafe(no_mangle)]
pub extern "C" fn acpi_button_register_callback(cb: ButtonCallbackFn) -> i32 {
    let state = STATE.get();
    unsafe {
        let s = &mut *state;
        if !s.initialized {
            return -1;
        }
        s.callback = Some(cb);
        log("acpi_button: callback registered");
        0
    }
}

/// Get the total press count for a specific button type.
///
/// `button_type`: 0=Power, 1=Sleep, 2=Lid.
///
/// Returns the number of presses detected since initialization (or last
/// clear). Returns 0 for invalid button types or if not initialized.
#[unsafe(no_mangle)]
pub extern "C" fn acpi_button_pressed_count(button_type: u32) -> u32 {
    let state = STATE.get();
    unsafe {
        let s = &*state;
        if !s.initialized {
            return 0;
        }
        if (button_type as usize) >= BUTTON_TYPE_COUNT {
            return 0;
        }
        s.press_count[button_type as usize]
    }
}

/// Clear the press count and any pending events for a specific button type.
///
/// `button_type`: 0=Power, 1=Sleep, 2=Lid.
///
/// Resets the press counter to zero and removes all matching events from
/// the ring buffer. Also clears the corresponding PM1_STS bit if applicable.
///
/// Returns 0 on success, -1 if not initialized, -2 if invalid button type.
#[unsafe(no_mangle)]
pub extern "C" fn acpi_button_clear(button_type: u32) -> i32 {
    let state = STATE.get();
    unsafe {
        let s = &mut *state;
        if !s.initialized {
            return -1;
        }
        if (button_type as usize) >= BUTTON_TYPE_COUNT {
            return -2;
        }

        // Reset press count.
        s.press_count[button_type as usize] = 0;

        // Remove matching events from the ring buffer by rebuilding it.
        // Copy non-matching events into a temporary buffer, then restore.
        let mut kept: [ButtonEvent; EVENT_RING_SIZE] = [ButtonEvent::empty(); EVENT_RING_SIZE];
        let mut kept_count: usize = 0;
        let mut idx = s.ring_tail;
        let mut remaining = s.ring_count;
        while remaining > 0 {
            let event = s.ring[idx];
            if event.button_type != button_type {
                kept[kept_count] = event;
                kept_count += 1;
            }
            idx = (idx + 1) % EVENT_RING_SIZE;
            remaining -= 1;
        }

        // Rebuild ring from kept events.
        let mut i = 0;
        while i < kept_count {
            s.ring[i] = kept[i];
            i += 1;
        }
        s.ring_tail = 0;
        s.ring_head = kept_count % EVENT_RING_SIZE;
        s.ring_count = kept_count;

        // Clear hardware status bit if applicable (W1C).
        if let Some((sts_bit, _en_bit)) = button_pm1_bits(button_type) {
            pm1_sts_write(s.pm1a_evt, sts_bit);
        }

        match button_type {
            BUTTON_POWER => log("acpi_button: power button state cleared"),
            BUTTON_SLEEP => log("acpi_button: sleep button state cleared"),
            BUTTON_LID => log("acpi_button: lid switch state cleared"),
            _ => {}
        }

        0
    }
}
