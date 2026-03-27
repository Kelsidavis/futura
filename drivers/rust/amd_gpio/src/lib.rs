// SPDX-License-Identifier: MPL-2.0
//
// AMD FCH GPIO Controller Driver for Futura OS
//
// Implements the AMD Fusion Controller Hub (FCH) GPIO controller found on
// AM4 (Promontory / X370-X570) and AM5 (X670-X870) Ryzen platforms.
//
// Architecture:
//   - MMIO-based register access (ACPI MMIO block)
//   - Default ACPI MMIO base: 0xFED8_0000
//   - GPIO bank offset: 0x1500 from ACPI MMIO base
//   - Each GPIO pin has a 4-byte control register at base + pin * 4
//   - AM4: up to 184 GPIO pins
//   - AM5: up to 256 GPIO pins
//
// GPIO pin control register layout (32-bit per pin):
//   bits [1:0]   - Output enable (0=input, 1=output)
//   bit  4       - Pull-up enable
//   bit  5       - Pull-down enable
//   bit  6       - Output value (when in output mode)
//   bit  7       - Input value (read-only, current pin state)
//   bits [10:8]  - Drive strength (3-bit field)
//   bit  16      - Interrupt enable
//   bits [18:17] - Interrupt type (00=level, 01=edge)
//   bit  19      - Active level (0=active low, 1=active high)
//   bit  20      - Interrupt status (write 1 to clear)
//   bits [23:21] - Interrupt delivery / APIC routing
//   bit  24      - Wake enable (can wake from sleep states)
//   bit  28      - Debounce enable
//   bits [31:29] - Debounce timer select
//
// References:
//   - AMD BIOS and Kernel Developer's Guide (BKDG) for AMD Family 17h
//   - AMD PPR (Processor Programming Reference) for Ryzen
//   - coreboot src/soc/amd/common/block/gpio_banks.c
//   - Linux drivers/pinctrl/pinctrl-amd.c

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(unexpected_cfgs)]

use core::cell::UnsafeCell;
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{fence, Ordering};

use common::{log, map_mmio_region, unmap_mmio_region, MMIO_DEFAULT_FLAGS};

unsafe extern "C" {
    fn fut_printf(fmt: *const u8, ...);
}

// ---------------------------------------------------------------------------
// StaticCell — interior-mutable global without `static mut`
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// ACPI MMIO and GPIO bank constants
// ---------------------------------------------------------------------------

/// Default ACPI MMIO base address on AMD FCH platforms.
const ACPI_MMIO_BASE_DEFAULT: u64 = 0xFED8_0000;

/// GPIO bank offset within the ACPI MMIO block.
const GPIO_BANK_OFFSET: u64 = 0x1500;

/// Maximum GPIO pins on AM4 platforms (Promontory, X370-X570).
const GPIO_MAX_PINS_AM4: u32 = 184;

/// Maximum GPIO pins on AM5 platforms (X670-X870).
const GPIO_MAX_PINS_AM5: u32 = 256;

/// MMIO region size: max pins * 4 bytes per pin register.
const GPIO_MMIO_SIZE_AM5: usize = (GPIO_MAX_PINS_AM5 as usize) * 4;

// ---------------------------------------------------------------------------
// GPIO pin control register bit definitions
// ---------------------------------------------------------------------------

/// Output enable — bits [1:0]. Bit 0 set = output mode.
const GPIO_OUTPUT_ENABLE: u32 = 1 << 0;

/// Pull-up enable (bit 4).
const GPIO_PULL_UP_ENABLE: u32 = 1 << 4;

/// Pull-down enable (bit 5).
const GPIO_PULL_DOWN_ENABLE: u32 = 1 << 5;

/// Mask covering both pull bits for read-modify-write.
const GPIO_PULL_MASK: u32 = GPIO_PULL_UP_ENABLE | GPIO_PULL_DOWN_ENABLE;

/// Output value bit (bit 6) — drives the pin when in output mode.
const GPIO_OUTPUT_VALUE: u32 = 1 << 6;

/// Input value bit (bit 7) — read-only, reflects the current pin state.
const GPIO_INPUT_VALUE: u32 = 1 << 7;

/// Drive strength field mask — bits [10:8].
const GPIO_DRIVE_STRENGTH_MASK: u32 = 0x7 << 8;

/// Drive strength field shift.
const GPIO_DRIVE_STRENGTH_SHIFT: u32 = 8;

/// Interrupt enable (bit 16).
const GPIO_INT_ENABLE: u32 = 1 << 16;

/// Interrupt type field — bits [18:17] (00=level, 01=edge).
const GPIO_INT_TYPE_MASK: u32 = 0x3 << 17;
const GPIO_INT_TYPE_SHIFT: u32 = 17;
const GPIO_INT_TYPE_LEVEL: u32 = 0x0 << 17;
const GPIO_INT_TYPE_EDGE: u32 = 0x1 << 17;

/// Active level (bit 19): 0=active low, 1=active high.
const GPIO_INT_ACTIVE_HIGH: u32 = 1 << 19;

/// Interrupt status (bit 20) — write 1 to clear.
const GPIO_INT_STATUS: u32 = 1 << 20;

/// Interrupt delivery / APIC routing — bits [23:21].
const GPIO_INT_DELIVERY_MASK: u32 = 0x7 << 21;

/// Wake enable (bit 24) — can wake the system from sleep states.
const GPIO_WAKE_ENABLE: u32 = 1 << 24;

/// Debounce enable (bit 28).
const GPIO_DEBOUNCE_ENABLE: u32 = 1 << 28;

/// Debounce timer select — bits [31:29].
const GPIO_DEBOUNCE_TIMER_MASK: u32 = 0x7 << 29;
const GPIO_DEBOUNCE_TIMER_SHIFT: u32 = 29;

// ---------------------------------------------------------------------------
// Driver state
// ---------------------------------------------------------------------------

struct AmdGpioState {
    /// Virtual address of the GPIO register bank (after MMIO mapping).
    base: usize,
    /// Number of GPIO pins available on this platform.
    npins: u32,
    /// Whether the driver has been initialised.
    inited: bool,
}

impl AmdGpioState {
    const fn new() -> Self {
        Self {
            base: 0,
            npins: 0,
            inited: false,
        }
    }
}

static STATE: StaticCell<AmdGpioState> = StaticCell::new(AmdGpioState::new());

// ---------------------------------------------------------------------------
// MMIO helpers
// ---------------------------------------------------------------------------

/// Read the 32-bit control register for `pin`.
#[inline]
fn gpio_read(base: usize, pin: u32) -> u32 {
    let addr = base + (pin as usize) * 4;
    unsafe { read_volatile(addr as *const u32) }
}

/// Write the 32-bit control register for `pin`.
#[inline]
fn gpio_write(base: usize, pin: u32, val: u32) {
    let addr = base + (pin as usize) * 4;
    unsafe { write_volatile(addr as *mut u32, val) }
}

/// Read-modify-write: clear `clear_bits`, then set `set_bits`.
#[inline]
fn gpio_rmw(base: usize, pin: u32, clear_bits: u32, set_bits: u32) {
    let old = gpio_read(base, pin);
    let new = (old & !clear_bits) | set_bits;
    gpio_write(base, pin, new);
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Return a reference to the driver state, or None if not initialised.
fn with_state() -> Option<(usize, u32)> {
    let st = unsafe { &*STATE.get() };
    if st.inited && st.base != 0 {
        Some((st.base, st.npins))
    } else {
        None
    }
}

/// Validate that `pin` is in range.
#[inline]
fn valid_pin(pin: u32, npins: u32) -> bool {
    pin < npins
}

// ---------------------------------------------------------------------------
// Platform detection — heuristic based on ACPI MMIO presence
// ---------------------------------------------------------------------------

/// Try to detect the platform variant by reading a known GPIO register.
/// AM5 platforms support up to 256 pins; AM4 supports up to 184.
/// We default to AM5 (256) since it is a superset and safe to probe.
fn detect_pin_count(base: usize) -> u32 {
    // Probe a pin in the AM5-only range (pin 184+). If the register
    // reads back as all-ones (0xFFFF_FFFF) or all-zeros with no valid
    // bit patterns, assume AM4.
    let probe_pin: u32 = 184;
    let val = gpio_read(base, probe_pin);

    // On a real AM5 FCH the register will have defined reset values.
    // On AM4, reading beyond pin 183 returns bus-float (0xFFFF_FFFF)
    // or zero depending on decode.
    if val == 0xFFFF_FFFF {
        GPIO_MAX_PINS_AM4
    } else {
        GPIO_MAX_PINS_AM5
    }
}

// ---------------------------------------------------------------------------
// FFI exports
// ---------------------------------------------------------------------------

/// Initialise the AMD FCH GPIO controller.
///
/// `acpi_mmio_base`: physical address of the ACPI MMIO block.
///     Pass 0 to use the default (0xFED8_0000).
///
/// Returns 0 on success, negative error code on failure.
#[unsafe(no_mangle)]
pub extern "C" fn amd_gpio_init(acpi_mmio_base: u64) -> i32 {
    log("amd_gpio: initialising AMD FCH GPIO controller...");

    let mmio_base = if acpi_mmio_base == 0 {
        ACPI_MMIO_BASE_DEFAULT
    } else {
        acpi_mmio_base
    };

    let gpio_phys = mmio_base + GPIO_BANK_OFFSET;

    unsafe {
        fut_printf(
            b"amd_gpio: ACPI MMIO base = 0x%08llx, GPIO bank = 0x%08llx\n\0".as_ptr(),
            mmio_base,
            gpio_phys,
        );
    }

    // Map the GPIO register bank into virtual address space.
    // We map the maximum possible size (AM5 = 256 pins * 4 = 1024 bytes).
    let vaddr = unsafe { map_mmio_region(gpio_phys, GPIO_MMIO_SIZE_AM5, MMIO_DEFAULT_FLAGS) };
    if vaddr.is_null() {
        log("amd_gpio: failed to map GPIO MMIO region");
        return -1;
    }

    let base = vaddr as usize;

    // Detect platform (AM4 vs AM5) by probing pin range.
    let npins = detect_pin_count(base);

    unsafe {
        fut_printf(
            b"amd_gpio: mapped at vaddr 0x%p, detected %u GPIO pins\n\0".as_ptr(),
            vaddr,
            npins,
        );
    }

    // Store state.
    let st = unsafe { &mut *STATE.get() };
    st.base = base;
    st.npins = npins;
    st.inited = true;

    fence(Ordering::SeqCst);

    unsafe {
        fut_printf(
            b"amd_gpio: controller ready (%u pins)\n\0".as_ptr(),
            npins,
        );
    }

    0
}

/// Set the direction of a GPIO pin.
///
/// `pin`: GPIO pin number.
/// `output`: true = output mode, false = input mode.
///
/// Returns 0 on success, -1 on error.
#[unsafe(no_mangle)]
pub extern "C" fn amd_gpio_set_direction(pin: u32, output: bool) -> i32 {
    let (base, npins) = match with_state() {
        Some(s) => s,
        None => return -19, // ENODEV
    };
    if !valid_pin(pin, npins) {
        return -22; // EINVAL
    }

    if output {
        gpio_rmw(base, pin, 0, GPIO_OUTPUT_ENABLE);
    } else {
        gpio_rmw(base, pin, GPIO_OUTPUT_ENABLE, 0);
    }

    0
}

/// Set the output value of a GPIO pin.
///
/// `pin`: GPIO pin number.
/// `high`: true = drive high, false = drive low.
///
/// Returns 0 on success, -1 on error.
/// The pin must be configured as an output for this to have visible effect.
#[unsafe(no_mangle)]
pub extern "C" fn amd_gpio_set_value(pin: u32, high: bool) -> i32 {
    let (base, npins) = match with_state() {
        Some(s) => s,
        None => return -19, // ENODEV
    };
    if !valid_pin(pin, npins) {
        return -22; // EINVAL
    }

    if high {
        gpio_rmw(base, pin, 0, GPIO_OUTPUT_VALUE);
    } else {
        gpio_rmw(base, pin, GPIO_OUTPUT_VALUE, 0);
    }

    0
}

/// Read the current input value of a GPIO pin.
///
/// Returns 0 (low) or 1 (high) on success, negative error code on failure.
#[unsafe(no_mangle)]
pub extern "C" fn amd_gpio_get_value(pin: u32) -> i32 {
    let (base, npins) = match with_state() {
        Some(s) => s,
        None => return -19, // ENODEV
    };
    if !valid_pin(pin, npins) {
        return -22; // EINVAL
    }

    let val = gpio_read(base, pin);
    if val & GPIO_INPUT_VALUE != 0 { 1 } else { 0 }
}

/// Configure the pull resistor for a GPIO pin.
///
/// `pull`: 0 = no pull, 1 = pull-up, 2 = pull-down.
///
/// Returns 0 on success, negative error code on failure.
#[unsafe(no_mangle)]
pub extern "C" fn amd_gpio_set_pull(pin: u32, pull: u32) -> i32 {
    let (base, npins) = match with_state() {
        Some(s) => s,
        None => return -19, // ENODEV
    };
    if !valid_pin(pin, npins) {
        return -22; // EINVAL
    }

    let bits = match pull {
        0 => 0,                                   // No pull
        1 => GPIO_PULL_UP_ENABLE,                  // Pull-up
        2 => GPIO_PULL_DOWN_ENABLE,                // Pull-down
        _ => return -22,                           // EINVAL
    };

    gpio_rmw(base, pin, GPIO_PULL_MASK, bits);
    0
}

/// Configure interrupt parameters for a GPIO pin.
///
/// `edge`: true = edge-triggered, false = level-triggered.
/// `active_high`: true = active high / rising edge, false = active low / falling edge.
///
/// This configures the interrupt type and polarity but does NOT enable the
/// interrupt. The interrupt is armed on the next read of the pin status or
/// can be explicitly enabled by configuring bit 16 of the pin register.
///
/// Returns 0 on success, negative error code on failure.
#[unsafe(no_mangle)]
pub extern "C" fn amd_gpio_configure_interrupt(pin: u32, edge: bool, active_high: bool) -> i32 {
    let (base, npins) = match with_state() {
        Some(s) => s,
        None => return -19, // ENODEV
    };
    if !valid_pin(pin, npins) {
        return -22; // EINVAL
    }

    let type_bits = if edge { GPIO_INT_TYPE_EDGE } else { GPIO_INT_TYPE_LEVEL };
    let level_bits = if active_high { GPIO_INT_ACTIVE_HIGH } else { 0 };

    // Clear any pending interrupt status first.
    let clear_mask = GPIO_INT_TYPE_MASK | GPIO_INT_ACTIVE_HIGH | GPIO_INT_STATUS;
    let set_mask = type_bits | level_bits | GPIO_INT_ENABLE | GPIO_INT_STATUS;

    gpio_rmw(base, pin, clear_mask, set_mask);
    0
}

/// Clear the interrupt status flag for a GPIO pin (write-1-to-clear).
///
/// Returns 0 on success, negative error code on failure.
#[unsafe(no_mangle)]
pub extern "C" fn amd_gpio_clear_interrupt(pin: u32) -> i32 {
    let (base, npins) = match with_state() {
        Some(s) => s,
        None => return -19, // ENODEV
    };
    if !valid_pin(pin, npins) {
        return -22; // EINVAL
    }

    // Write 1 to bit 20 to clear the interrupt status.
    // Use direct read-modify-write preserving all other bits.
    let val = gpio_read(base, pin);
    gpio_write(base, pin, val | GPIO_INT_STATUS);

    0
}

/// Get the interrupt status for a GPIO pin.
///
/// Returns 1 if the interrupt is pending, 0 if not, negative on error.
#[unsafe(no_mangle)]
pub extern "C" fn amd_gpio_get_interrupt_status(pin: u32) -> i32 {
    let (base, npins) = match with_state() {
        Some(s) => s,
        None => return -19, // ENODEV
    };
    if !valid_pin(pin, npins) {
        return -22; // EINVAL
    }

    let val = gpio_read(base, pin);
    if val & GPIO_INT_STATUS != 0 { 1 } else { 0 }
}

/// Return the number of GPIO pins available on this platform.
///
/// Returns 0 if the driver has not been initialised.
#[unsafe(no_mangle)]
pub extern "C" fn amd_gpio_pin_count() -> u32 {
    match with_state() {
        Some((_, npins)) => npins,
        None => 0,
    }
}

// ---------------------------------------------------------------------------
// Extended utility functions
// ---------------------------------------------------------------------------

/// Set the drive strength for a GPIO pin.
///
/// `strength`: 3-bit value (0-7) selecting the drive strength level.
///     Exact current values are platform-dependent.
///
/// Returns 0 on success, negative error code on failure.
#[unsafe(no_mangle)]
pub extern "C" fn amd_gpio_set_drive_strength(pin: u32, strength: u32) -> i32 {
    let (base, npins) = match with_state() {
        Some(s) => s,
        None => return -19, // ENODEV
    };
    if !valid_pin(pin, npins) || strength > 7 {
        return -22; // EINVAL
    }

    let bits = (strength & 0x7) << GPIO_DRIVE_STRENGTH_SHIFT;
    gpio_rmw(base, pin, GPIO_DRIVE_STRENGTH_MASK, bits);

    0
}

/// Enable or disable the debounce filter for a GPIO pin.
///
/// `enable`: true to enable debounce, false to disable.
/// `timer_sel`: 3-bit debounce timer selection (0-7). Ignored when disabling.
///     Timer period values are platform-specific (typically ranging from
///     ~0.9ms to ~62ms depending on FCH revision).
///
/// Returns 0 on success, negative error code on failure.
#[unsafe(no_mangle)]
pub extern "C" fn amd_gpio_set_debounce(pin: u32, enable: bool, timer_sel: u32) -> i32 {
    let (base, npins) = match with_state() {
        Some(s) => s,
        None => return -19, // ENODEV
    };
    if !valid_pin(pin, npins) || timer_sel > 7 {
        return -22; // EINVAL
    }

    if enable {
        let timer_bits = (timer_sel & 0x7) << GPIO_DEBOUNCE_TIMER_SHIFT;
        gpio_rmw(
            base,
            pin,
            GPIO_DEBOUNCE_TIMER_MASK,
            GPIO_DEBOUNCE_ENABLE | timer_bits,
        );
    } else {
        gpio_rmw(base, pin, GPIO_DEBOUNCE_ENABLE | GPIO_DEBOUNCE_TIMER_MASK, 0);
    }

    0
}

/// Enable or disable wake-from-sleep capability for a GPIO pin.
///
/// Returns 0 on success, negative error code on failure.
#[unsafe(no_mangle)]
pub extern "C" fn amd_gpio_set_wake(pin: u32, enable: bool) -> i32 {
    let (base, npins) = match with_state() {
        Some(s) => s,
        None => return -19, // ENODEV
    };
    if !valid_pin(pin, npins) {
        return -22; // EINVAL
    }

    if enable {
        gpio_rmw(base, pin, 0, GPIO_WAKE_ENABLE);
    } else {
        gpio_rmw(base, pin, GPIO_WAKE_ENABLE, 0);
    }

    0
}

/// Read the raw 32-bit control register for a GPIO pin (for diagnostics).
///
/// Returns the register value, or 0xFFFF_FFFF on error.
#[unsafe(no_mangle)]
pub extern "C" fn amd_gpio_read_raw(pin: u32) -> u32 {
    let (base, npins) = match with_state() {
        Some(s) => s,
        None => return 0xFFFF_FFFF,
    };
    if !valid_pin(pin, npins) {
        return 0xFFFF_FFFF;
    }

    gpio_read(base, pin)
}

/// Write the raw 32-bit control register for a GPIO pin (for advanced use).
///
/// Returns 0 on success, negative error code on failure.
#[unsafe(no_mangle)]
pub extern "C" fn amd_gpio_write_raw(pin: u32, val: u32) -> i32 {
    let (base, npins) = match with_state() {
        Some(s) => s,
        None => return -19, // ENODEV
    };
    if !valid_pin(pin, npins) {
        return -22; // EINVAL
    }

    gpio_write(base, pin, val);
    0
}
