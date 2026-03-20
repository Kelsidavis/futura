// SPDX-License-Identifier: MPL-2.0
//! Apple Silicon GPIO / pinctrl driver for Futura OS
//!
//! Implements the Apple-specific GPIO controller found in M1/M2/M3 SoCs.
//! The controller uses a simple flat register map: one 32-bit word per GPIO
//! pin, encoding data, direction, pull, and interrupt configuration.
//!
//! Register layout (per pin, offset = `base + pin * 4`)
//! ----------------------------------------------------
//! Bits [0]     OUT      Output value (0=low, 1=high)
//! Bits [1]     OE       Output enable (1=output, 0=input)
//! Bits [3:2]   PULL     Pull config: 0=none, 1=pull-down, 2=pull-up, 3=rsvd
//! Bits [4]     IN       Input value (read-only)
//! Bits [9]     IRQ_EN   Interrupt enable
//! Bits [11:10] IRQ_MODE 0=level-low, 1=level-high, 2=edge-rise, 3=edge-fall
//! Bits [12]    IRQ_STS  Interrupt status (write 1 to clear)
//! Bits [15]    DRIVE    Drive strength select (0=4mA, 1=8mA)
//!
//! References
//! ----------
//! - Asahi Linux `drivers/pinctrl/pinctrl-apple-gpio.c` (Mark Kettenis)
//! - Apple device tree "simple-mfd-pinctrl" compatible
//! - m1n1 `proxyclient/m1n1/hw/gpio.py`

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(dead_code)]

use core::ptr::{read_volatile, write_volatile};

// ---------------------------------------------------------------------------
// Pin configuration register bit fields
// ---------------------------------------------------------------------------

/// Output value bit
const GPIO_OUT:          u32 = 1 << 0;
/// Output-enable bit (1 = output mode)
const GPIO_OE:           u32 = 1 << 1;
/// Pull configuration field mask
const GPIO_PULL_MASK:    u32 = 0x3 << 2;
/// Pull-down
const GPIO_PULL_DOWN:    u32 = 0x1 << 2;
/// Pull-up
const GPIO_PULL_UP:      u32 = 0x2 << 2;
/// Input value bit (read-only)
const GPIO_IN:           u32 = 1 << 4;
/// Interrupt enable
const GPIO_IRQ_EN:       u32 = 1 << 9;
/// Interrupt mode field mask
const GPIO_IRQ_MODE_MASK:u32 = 0x3 << 10;
/// Interrupt mode: level-low
const GPIO_IRQ_LEVEL_LO: u32 = 0x0 << 10;
/// Interrupt mode: level-high
const GPIO_IRQ_LEVEL_HI: u32 = 0x1 << 10;
/// Interrupt mode: rising edge
const GPIO_IRQ_EDGE_RISE:u32 = 0x2 << 10;
/// Interrupt mode: falling edge
const GPIO_IRQ_EDGE_FALL:u32 = 0x3 << 10;
/// Interrupt status bit (write 1 to clear)
const GPIO_IRQ_STS:      u32 = 1 << 12;
/// Drive strength (0=4 mA, 1=8 mA)
const GPIO_DRIVE:        u32 = 1 << 15;

/// Maximum GPIO pins per bank supported by this driver.
const GPIO_MAX_PINS: usize = 256;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// GPIO pin direction.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Direction {
    /// Pin is a digital input (high-impedance by default).
    Input,
    /// Pin drives the output value.
    Output,
}

/// GPIO pin pull configuration.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Pull {
    /// No pull resistor.
    None,
    /// Internal pull-down resistor.
    Down,
    /// Internal pull-up resistor.
    Up,
}

/// Interrupt trigger mode.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum IrqMode {
    /// Interrupt when pin is driven low.
    LevelLow,
    /// Interrupt when pin is driven high.
    LevelHigh,
    /// Interrupt on rising edge (low→high transition).
    EdgeRising,
    /// Interrupt on falling edge (high→low transition).
    EdgeFalling,
}

// ---------------------------------------------------------------------------
// C-callable IRQ handler type
// ---------------------------------------------------------------------------

/// C-callable IRQ handler: `fn(pin, cookie)`.
type GpioIrqFn = unsafe extern "C" fn(pin: u32, cookie: *mut ());

#[derive(Copy, Clone)]
struct IrqSlot {
    handler: Option<GpioIrqFn>,
    cookie:  *mut (),
}

// SAFETY: handlers are registered before use and accessed only under the
// single-hart GPIO IRQ serialisation.
unsafe impl Send for IrqSlot {}
unsafe impl Sync for IrqSlot {}

impl IrqSlot {
    const fn empty() -> Self {
        Self { handler: None, cookie: core::ptr::null_mut() }
    }
}

// ---------------------------------------------------------------------------
// AppleGpio — driver state
// ---------------------------------------------------------------------------

/// Apple Silicon GPIO controller.
///
/// Each instance represents one GPIO bank.  Multiple banks may exist on a
/// single SoC (M1: 3 banks, M2: 3+ banks), each with its own MMIO base and
/// pin count.
pub struct AppleGpio {
    base:     usize,
    npins:    u32,
    handlers: [IrqSlot; GPIO_MAX_PINS],
}

impl AppleGpio {
    // ---- MMIO helpers -------------------------------------------------------

    /// Read the configuration word for `pin`.
    fn read_cfg(&self, pin: u32) -> u32 {
        // SAFETY: pin is bounds-checked by callers; base is a valid MMIO mapping.
        unsafe { read_volatile((self.base + (pin as usize) * 4) as *const u32) }
    }

    /// Write the configuration word for `pin`.
    fn write_cfg(&self, pin: u32, val: u32) {
        // SAFETY: pin is bounds-checked by callers; base is a valid MMIO mapping.
        unsafe { write_volatile((self.base + (pin as usize) * 4) as *mut u32, val) }
    }

    /// Perform a read-modify-write on the configuration word for `pin`.
    fn rmw_cfg(&self, pin: u32, clear: u32, set: u32) {
        let old = self.read_cfg(pin);
        self.write_cfg(pin, (old & !clear) | set);
    }

    // ---- Bounds check -------------------------------------------------------

    #[inline]
    fn valid(&self, pin: u32) -> bool {
        pin < self.npins && (pin as usize) < GPIO_MAX_PINS
    }

    // ---- Public API ---------------------------------------------------------

    /// Initialise the GPIO controller.
    ///
    /// Leaves all pins in their power-on state (input, no pull, no IRQ).
    pub fn init(&mut self) -> bool {
        if self.base == 0 || self.npins == 0 {
            return false;
        }
        // Disable interrupts on all pins to start in a clean state.
        for pin in 0..self.npins {
            self.rmw_cfg(pin, GPIO_IRQ_EN | GPIO_IRQ_STS, 0);
        }
        true
    }

    /// Set the direction of `pin`.
    pub fn set_direction(&self, pin: u32, dir: Direction) {
        if !self.valid(pin) { return; }
        match dir {
            Direction::Output => self.rmw_cfg(pin, 0, GPIO_OE),
            Direction::Input  => self.rmw_cfg(pin, GPIO_OE, 0),
        }
    }

    /// Read the current direction of `pin`.
    pub fn direction(&self, pin: u32) -> Direction {
        if !self.valid(pin) { return Direction::Input; }
        if self.read_cfg(pin) & GPIO_OE != 0 { Direction::Output } else { Direction::Input }
    }

    /// Set the output value of `pin` (only meaningful in output mode).
    pub fn set_output(&self, pin: u32, high: bool) {
        if !self.valid(pin) { return; }
        if high {
            self.rmw_cfg(pin, 0, GPIO_OUT);
        } else {
            self.rmw_cfg(pin, GPIO_OUT, 0);
        }
    }

    /// Toggle the output value of `pin`.
    pub fn toggle(&self, pin: u32) {
        if !self.valid(pin) { return; }
        let old = self.read_cfg(pin);
        self.write_cfg(pin, old ^ GPIO_OUT);
    }

    /// Read the current (debounced) input value of `pin`.
    pub fn get_input(&self, pin: u32) -> bool {
        if !self.valid(pin) { return false; }
        self.read_cfg(pin) & GPIO_IN != 0
    }

    /// Configure the pull resistor for `pin`.
    pub fn set_pull(&self, pin: u32, pull: Pull) {
        if !self.valid(pin) { return; }
        let bits = match pull {
            Pull::None => 0,
            Pull::Down => GPIO_PULL_DOWN,
            Pull::Up   => GPIO_PULL_UP,
        };
        self.rmw_cfg(pin, GPIO_PULL_MASK, bits);
    }

    /// Read the current pull configuration of `pin`.
    pub fn pull(&self, pin: u32) -> Pull {
        if !self.valid(pin) { return Pull::None; }
        match self.read_cfg(pin) & GPIO_PULL_MASK {
            GPIO_PULL_DOWN => Pull::Down,
            GPIO_PULL_UP   => Pull::Up,
            _              => Pull::None,
        }
    }

    /// Configure `pin` for interrupt delivery with the given trigger mode.
    ///
    /// Clears any pending status before enabling.  The interrupt is only
    /// actually delivered after `enable_irq` is called.
    pub fn configure_irq(&self, pin: u32, mode: IrqMode) {
        if !self.valid(pin) { return; }
        let mode_bits = match mode {
            IrqMode::LevelLow    => GPIO_IRQ_LEVEL_LO,
            IrqMode::LevelHigh   => GPIO_IRQ_LEVEL_HI,
            IrqMode::EdgeRising  => GPIO_IRQ_EDGE_RISE,
            IrqMode::EdgeFalling => GPIO_IRQ_EDGE_FALL,
        };
        // Clear status, set mode, leave enable bit unchanged.
        self.rmw_cfg(pin, GPIO_IRQ_MODE_MASK | GPIO_IRQ_STS, mode_bits);
    }

    /// Enable the interrupt for `pin`.
    pub fn enable_irq(&self, pin: u32) {
        if !self.valid(pin) { return; }
        self.rmw_cfg(pin, 0, GPIO_IRQ_EN);
    }

    /// Disable the interrupt for `pin`.
    pub fn disable_irq(&self, pin: u32) {
        if !self.valid(pin) { return; }
        self.rmw_cfg(pin, GPIO_IRQ_EN, 0);
    }

    /// Clear the interrupt-pending flag for `pin` (write-1-to-clear).
    pub fn clear_irq(&self, pin: u32) {
        if !self.valid(pin) { return; }
        self.rmw_cfg(pin, 0, GPIO_IRQ_STS);
    }

    /// Return `true` if `pin` has a pending interrupt.
    pub fn irq_pending(&self, pin: u32) -> bool {
        if !self.valid(pin) { return false; }
        self.read_cfg(pin) & GPIO_IRQ_STS != 0
    }

    /// Register a C-callable handler for `pin`'s interrupt.
    pub fn register_irq_handler(
        &mut self,
        pin:     u32,
        handler: GpioIrqFn,
        cookie:  *mut (),
    ) {
        if !self.valid(pin) { return; }
        self.handlers[pin as usize] = IrqSlot { handler: Some(handler), cookie };
    }

    /// Unregister the interrupt handler for `pin`.
    pub fn unregister_irq_handler(&mut self, pin: u32) {
        if !self.valid(pin) { return; }
        self.handlers[pin as usize] = IrqSlot::empty();
    }

    /// Set the drive strength for `pin` (false=4 mA, true=8 mA).
    pub fn set_drive(&self, pin: u32, high: bool) {
        if !self.valid(pin) { return; }
        if high {
            self.rmw_cfg(pin, 0, GPIO_DRIVE);
        } else {
            self.rmw_cfg(pin, GPIO_DRIVE, 0);
        }
    }

    /// Top-level IRQ dispatch — call from the AIC IRQ handler for the GPIO IRQ.
    ///
    /// Scans all pins for pending interrupts, invokes handlers, and clears
    /// the pending bit.  Processes all pending pins in one call.
    pub fn handle_irq(&mut self) {
        for pin in 0..self.npins {
            if !self.irq_pending(pin) {
                continue;
            }
            // Clear before dispatching to avoid re-entry on level-triggered IRQs.
            self.clear_irq(pin);
            let slot = self.handlers[pin as usize];
            if let Some(h) = slot.handler {
                // SAFETY: handler registered with correct cookie type.
                unsafe { h(pin, slot.cookie) };
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Heap allocation shim
// ---------------------------------------------------------------------------

unsafe extern "C" {
    fn fut_alloc(size: usize) -> *mut u8;
    fn fut_free(ptr: *mut u8);
}

// ---------------------------------------------------------------------------
// C FFI
// ---------------------------------------------------------------------------

/// Allocate and initialise a GPIO controller at `base` with `npins` pins.
///
/// Returns a non-null opaque pointer on success, null on failure.
/// The caller is responsible for freeing the returned pointer with
/// `rust_gpio_free` when the driver is no longer needed.
#[unsafe(no_mangle)]
pub extern "C" fn rust_gpio_init(base: u64, npins: u32) -> *mut AppleGpio {
    if base == 0 || npins == 0 || npins as usize > GPIO_MAX_PINS {
        return core::ptr::null_mut();
    }
    let ptr = unsafe { fut_alloc(core::mem::size_of::<AppleGpio>()) } as *mut AppleGpio;
    if ptr.is_null() {
        return core::ptr::null_mut();
    }
    let gpio = unsafe { &mut *ptr };
    gpio.base     = base as usize;
    gpio.npins    = npins;
    gpio.handlers = [IrqSlot::empty(); GPIO_MAX_PINS];

    if !gpio.init() {
        unsafe { fut_free(ptr as *mut u8) };
        return core::ptr::null_mut();
    }
    ptr
}

/// Free a GPIO controller returned by `rust_gpio_init`.
#[unsafe(no_mangle)]
pub extern "C" fn rust_gpio_free(gpio: *mut AppleGpio) {
    if !gpio.is_null() {
        unsafe { fut_free(gpio as *mut u8) };
    }
}

/// Set the direction of `pin`: 0=input, 1=output.
#[unsafe(no_mangle)]
pub extern "C" fn rust_gpio_set_direction(gpio: *mut AppleGpio, pin: u32, output: i32) {
    if gpio.is_null() { return; }
    let dir = if output != 0 { Direction::Output } else { Direction::Input };
    unsafe { (*gpio).set_direction(pin, dir) };
}

/// Return the direction of `pin`: 0=input, 1=output.
#[unsafe(no_mangle)]
pub extern "C" fn rust_gpio_get_direction(gpio: *const AppleGpio, pin: u32) -> i32 {
    if gpio.is_null() { return 0; }
    match unsafe { (*gpio).direction(pin) } {
        Direction::Output => 1,
        Direction::Input  => 0,
    }
}

/// Set the output value of `pin`: 0=low, 1=high.
#[unsafe(no_mangle)]
pub extern "C" fn rust_gpio_set_output(gpio: *const AppleGpio, pin: u32, high: i32) {
    if gpio.is_null() { return; }
    unsafe { (*gpio).set_output(pin, high != 0) };
}

/// Toggle the output value of `pin`.
#[unsafe(no_mangle)]
pub extern "C" fn rust_gpio_toggle(gpio: *const AppleGpio, pin: u32) {
    if gpio.is_null() { return; }
    unsafe { (*gpio).toggle(pin) };
}

/// Read the current input value of `pin`: 0=low, 1=high.
#[unsafe(no_mangle)]
pub extern "C" fn rust_gpio_get_input(gpio: *const AppleGpio, pin: u32) -> i32 {
    if gpio.is_null() { return 0; }
    unsafe { (*gpio).get_input(pin) as i32 }
}

/// Configure the pull resistor: 0=none, 1=pull-down, 2=pull-up.
#[unsafe(no_mangle)]
pub extern "C" fn rust_gpio_set_pull(gpio: *const AppleGpio, pin: u32, pull: u32) {
    if gpio.is_null() { return; }
    let p = match pull {
        1 => Pull::Down,
        2 => Pull::Up,
        _ => Pull::None,
    };
    unsafe { (*gpio).set_pull(pin, p) };
}

/// Read the current pull configuration: 0=none, 1=pull-down, 2=pull-up.
#[unsafe(no_mangle)]
pub extern "C" fn rust_gpio_get_pull(gpio: *const AppleGpio, pin: u32) -> u32 {
    if gpio.is_null() { return 0; }
    match unsafe { (*gpio).pull(pin) } {
        Pull::Down => 1,
        Pull::Up   => 2,
        Pull::None => 0,
    }
}

/// Configure the interrupt trigger mode for `pin`.
///
/// `mode`: 0=level-low, 1=level-high, 2=edge-rising, 3=edge-falling.
#[unsafe(no_mangle)]
pub extern "C" fn rust_gpio_configure_irq(gpio: *const AppleGpio, pin: u32, mode: u32) {
    if gpio.is_null() { return; }
    let m = match mode {
        1 => IrqMode::LevelHigh,
        2 => IrqMode::EdgeRising,
        3 => IrqMode::EdgeFalling,
        _ => IrqMode::LevelLow,
    };
    unsafe { (*gpio).configure_irq(pin, m) };
}

/// Enable the interrupt for `pin`.
#[unsafe(no_mangle)]
pub extern "C" fn rust_gpio_enable_irq(gpio: *const AppleGpio, pin: u32) {
    if gpio.is_null() { return; }
    unsafe { (*gpio).enable_irq(pin) };
}

/// Disable the interrupt for `pin`.
#[unsafe(no_mangle)]
pub extern "C" fn rust_gpio_disable_irq(gpio: *const AppleGpio, pin: u32) {
    if gpio.is_null() { return; }
    unsafe { (*gpio).disable_irq(pin) };
}

/// Clear any pending interrupt for `pin`.
#[unsafe(no_mangle)]
pub extern "C" fn rust_gpio_clear_irq(gpio: *const AppleGpio, pin: u32) {
    if gpio.is_null() { return; }
    unsafe { (*gpio).clear_irq(pin) };
}

/// Return 1 if `pin` has a pending interrupt, 0 otherwise.
#[unsafe(no_mangle)]
pub extern "C" fn rust_gpio_irq_pending(gpio: *const AppleGpio, pin: u32) -> i32 {
    if gpio.is_null() { return 0; }
    unsafe { (*gpio).irq_pending(pin) as i32 }
}

/// Register a C handler for `pin`'s interrupt.
///
/// # Safety
/// `handler` must be a valid function pointer; `cookie` must remain live
/// until the handler is unregistered.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_gpio_register_irq_handler(
    gpio:    *mut AppleGpio,
    pin:     u32,
    handler: Option<unsafe extern "C" fn(pin: u32, cookie: *mut ())>,
    cookie:  *mut (),
) {
    if gpio.is_null() { return; }
    if let Some(h) = handler {
        unsafe { (*gpio).register_irq_handler(pin, h, cookie) };
    }
}

/// Unregister the interrupt handler for `pin`.
#[unsafe(no_mangle)]
pub extern "C" fn rust_gpio_unregister_irq_handler(gpio: *mut AppleGpio, pin: u32) {
    if gpio.is_null() { return; }
    unsafe { (*gpio).unregister_irq_handler(pin) };
}

/// Set the drive strength: 0=4 mA, 1=8 mA.
#[unsafe(no_mangle)]
pub extern "C" fn rust_gpio_set_drive(gpio: *const AppleGpio, pin: u32, high: i32) {
    if gpio.is_null() { return; }
    unsafe { (*gpio).set_drive(pin, high != 0) };
}

/// Read the raw configuration register for `pin` (for diagnostics).
#[unsafe(no_mangle)]
pub extern "C" fn rust_gpio_read_cfg(gpio: *const AppleGpio, pin: u32) -> u32 {
    if gpio.is_null() { return 0; }
    unsafe { (*gpio).read_cfg(pin) }
}

/// Write the raw configuration register for `pin` (for advanced use).
#[unsafe(no_mangle)]
pub extern "C" fn rust_gpio_write_cfg(gpio: *const AppleGpio, pin: u32, val: u32) {
    if gpio.is_null() { return; }
    unsafe { (*gpio).write_cfg(pin, val) };
}

/// Top-level IRQ dispatch — call from the AIC handler for the GPIO IRQ line.
/// Processes all pins with pending interrupts in a single call.
#[unsafe(no_mangle)]
pub extern "C" fn rust_gpio_handle_irq(gpio: *mut AppleGpio) {
    if gpio.is_null() { return; }
    unsafe { (*gpio).handle_irq() };
}

/// Return the number of pins managed by this controller.
#[unsafe(no_mangle)]
pub extern "C" fn rust_gpio_npins(gpio: *const AppleGpio) -> u32 {
    if gpio.is_null() { return 0; }
    unsafe { (*gpio).npins }
}

// ---------------------------------------------------------------------------
// Panic handler (required for no_std staticlib)
// ---------------------------------------------------------------------------

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
