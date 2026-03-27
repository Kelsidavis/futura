// SPDX-License-Identifier: MPL-2.0
//
// Raspberry Pi BCM2711/BCM2712 GPIO Controller Driver
//
// Manages the 58 GPIO pins on BCM2711 (Pi4) and BCM2712 (Pi5).
// Supports pin function selection (input/output/alt0-5), pull-up/down,
// and basic read/write operations.
//
// BCM2711 GPIO base: peripheral_base + 0x200000
// BCM2712 GPIO base: peripheral_base + 0xD0000
//
// Key uses:
//   - UART TX/RX pin muxing (GPIO14=TXD0, GPIO15=RXD0 via ALT0)
//   - Activity LED (GPIO42 on Pi4, GPIO none on Pi5 — use mailbox)
//   - I2C/SPI pin configuration
//   - User GPIO for hardware projects

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(unexpected_cfgs)]
extern crate common;

use core::ptr::{read_volatile, write_volatile};

/// GPIO function select values (3 bits per pin)
#[repr(u32)]
#[derive(Clone, Copy)]
pub enum GpioFunc {
    Input  = 0b000,
    Output = 0b001,
    Alt0   = 0b100,  // UART0 TX/RX, I2C0 SDA/SCL, SPI0
    Alt1   = 0b101,  // Secondary functions
    Alt2   = 0b110,  // Tertiary functions
    Alt3   = 0b111,
    Alt4   = 0b011,
    Alt5   = 0b010,
}

/// GPIO pull-up/pull-down configuration
#[repr(u32)]
#[derive(Clone, Copy)]
pub enum GpioPull {
    None = 0,
    Up   = 1,
    Down = 2,
}

// BCM2711 GPIO registers (offsets from GPIO base)
const GPFSEL0: usize = 0x00;    // Function select 0 (GPIO 0-9)
// GPFSEL1-5 at +0x04 increments (GPIO 10-57)
const GPSET0: usize = 0x1C;     // Pin output set 0 (GPIO 0-31)
const GPSET1: usize = 0x20;     // Pin output set 1 (GPIO 32-57)
const GPCLR0: usize = 0x28;     // Pin output clear 0
const GPCLR1: usize = 0x2C;     // Pin output clear 1
const GPLEV0: usize = 0x34;     // Pin level 0 (read current state)
const GPLEV1: usize = 0x38;     // Pin level 1

// BCM2711 pull-up/down registers (new style — not the old GPPUD/GPPUDCLK)
const GPIO_PUP_PDN_CNTRL0: usize = 0xE4;  // Pull-up/down for GPIO 0-15
// +0x04 increments for GPIO 16-57

// Maximum GPIO pin number
const GPIO_MAX_PIN: u32 = 57;

static mut GPIO_BASE: usize = 0;

fn mmio_read(addr: usize) -> u32 {
    unsafe { read_volatile(addr as *const u32) }
}

fn mmio_write(addr: usize, val: u32) {
    unsafe { write_volatile(addr as *mut u32, val) }
}

// ── FFI exports ──

/// Initialize GPIO controller
/// base_addr: physical/virtual base of GPIO registers
#[unsafe(no_mangle)]
pub extern "C" fn rpi_gpio_init(base_addr: u64) {
    unsafe { GPIO_BASE = base_addr as usize; }
}

/// Set the function of a GPIO pin
/// pin: GPIO number (0-57)
/// func: GpioFunc value (0=input, 1=output, 4=alt0, etc.)
#[unsafe(no_mangle)]
pub extern "C" fn rpi_gpio_set_func(pin: u32, func: u32) {
    let base = unsafe { GPIO_BASE };
    if base == 0 || pin > GPIO_MAX_PIN { return; }

    let reg_offset = GPFSEL0 + ((pin / 10) * 4) as usize;
    let bit_offset = (pin % 10) * 3;

    let mut val = mmio_read(base + reg_offset);
    val &= !(0x7 << bit_offset);       // Clear 3-bit field
    val |= (func & 0x7) << bit_offset; // Set new function
    mmio_write(base + reg_offset, val);
}

/// Set a GPIO pin high (output)
#[unsafe(no_mangle)]
pub extern "C" fn rpi_gpio_set(pin: u32) {
    let base = unsafe { GPIO_BASE };
    if base == 0 || pin > GPIO_MAX_PIN { return; }

    let reg = if pin < 32 { GPSET0 } else { GPSET1 };
    let bit = pin % 32;
    mmio_write(base + reg, 1 << bit);
}

/// Set a GPIO pin low (output)
#[unsafe(no_mangle)]
pub extern "C" fn rpi_gpio_clear(pin: u32) {
    let base = unsafe { GPIO_BASE };
    if base == 0 || pin > GPIO_MAX_PIN { return; }

    let reg = if pin < 32 { GPCLR0 } else { GPCLR1 };
    let bit = pin % 32;
    mmio_write(base + reg, 1 << bit);
}

/// Read the current level of a GPIO pin
/// Returns: 1 if high, 0 if low
#[unsafe(no_mangle)]
pub extern "C" fn rpi_gpio_read(pin: u32) -> u32 {
    let base = unsafe { GPIO_BASE };
    if base == 0 || pin > GPIO_MAX_PIN { return 0; }

    let reg = if pin < 32 { GPLEV0 } else { GPLEV1 };
    let bit = pin % 32;
    (mmio_read(base + reg) >> bit) & 1
}

/// Configure pull-up/pull-down for a GPIO pin (BCM2711 style)
/// pin: GPIO number (0-57)
/// pull: 0=none, 1=up, 2=down
#[unsafe(no_mangle)]
pub extern "C" fn rpi_gpio_set_pull(pin: u32, pull: u32) {
    let base = unsafe { GPIO_BASE };
    if base == 0 || pin > GPIO_MAX_PIN { return; }

    let reg_offset = GPIO_PUP_PDN_CNTRL0 + ((pin / 16) * 4) as usize;
    let bit_offset = (pin % 16) * 2;

    let mut val = mmio_read(base + reg_offset);
    val &= !(0x3 << bit_offset);
    val |= (pull & 0x3) << bit_offset;
    mmio_write(base + reg_offset, val);
}

/// Configure GPIO14/15 for UART0 (ALT0 function)
/// This is the standard serial console on Pi4/Pi5 header pins 8/10
#[unsafe(no_mangle)]
pub extern "C" fn rpi_gpio_setup_uart() {
    // GPIO14 = TXD0 (ALT0)
    rpi_gpio_set_func(14, GpioFunc::Alt0 as u32);
    // GPIO15 = RXD0 (ALT0)
    rpi_gpio_set_func(15, GpioFunc::Alt0 as u32);
    // No pull on TX, pull-up on RX
    rpi_gpio_set_pull(14, GpioPull::None as u32);
    rpi_gpio_set_pull(15, GpioPull::Up as u32);
}

/// Configure GPIO2/3 for I2C1 (ALT0 function)
#[unsafe(no_mangle)]
pub extern "C" fn rpi_gpio_setup_i2c1() {
    rpi_gpio_set_func(2, GpioFunc::Alt0 as u32);  // SDA1
    rpi_gpio_set_func(3, GpioFunc::Alt0 as u32);  // SCL1
    rpi_gpio_set_pull(2, GpioPull::Up as u32);
    rpi_gpio_set_pull(3, GpioPull::Up as u32);
}

/// Configure GPIO8-11 for SPI0 (ALT0 function)
#[unsafe(no_mangle)]
pub extern "C" fn rpi_gpio_setup_spi0() {
    rpi_gpio_set_func(8, GpioFunc::Alt0 as u32);   // CE0
    rpi_gpio_set_func(9, GpioFunc::Alt0 as u32);   // MISO
    rpi_gpio_set_func(10, GpioFunc::Alt0 as u32);  // MOSI
    rpi_gpio_set_func(11, GpioFunc::Alt0 as u32);  // SCLK
}

/// Set activity LED state (Pi4: GPIO42)
#[unsafe(no_mangle)]
pub extern "C" fn rpi_gpio_set_activity_led(on: bool) {
    rpi_gpio_set_func(42, GpioFunc::Output as u32);
    if on {
        rpi_gpio_set(42);
    } else {
        rpi_gpio_clear(42);
    }
}
