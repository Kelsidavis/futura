//! GPIO Driver for Raspberry Pi ARM64 platforms
//!
//! This module implements a type-safe Rust driver for the Raspberry Pi GPIO controller.
//! Supports GPIO input/output operations for all RPi variants (3, 4, 5).

use core::ptr;

/// GPIO register map for Raspberry Pi
#[repr(C)]
pub struct GpioRegisters {
    /// 0x00-0x14: GPIO Function Select (6 registers, 3 bits per pin)
    pub gpfsel: [u32; 6],
    /// 0x18-0x1C: GPIO Pin Output Set (2 registers, bits 0-31 and 32-53)
    pub gpset: [u32; 2],
    /// 0x20-0x24: GPIO Pin Output Clear (2 registers, bits 0-31 and 32-53)
    pub gpclr: [u32; 2],
    /// 0x28-0x2C: GPIO Pin Level (2 registers, bits 0-31 and 32-53)
    pub gplev: [u32; 2],
    /// 0x30-0x34: GPIO Event Detect Status (2 registers)
    pub gpeds: [u32; 2],
    /// 0x38-0x3C: GPIO Rising Edge Detect Enable (2 registers)
    pub gpren: [u32; 2],
    /// 0x40-0x44: GPIO Falling Edge Detect Enable (2 registers)
    pub gpfen: [u32; 2],
    /// 0x48-0x4C: GPIO High Detect Enable (2 registers)
    pub gphen: [u32; 2],
    /// 0x50-0x54: GPIO Low Detect Enable (2 registers)
    pub gplen: [u32; 2],
    /// 0x58-0x5C: GPIO Async Rising Edge Detect (2 registers)
    pub gparen: [u32; 2],
    /// 0x60-0x64: GPIO Async Falling Edge Detect (2 registers)
    pub gpafen: [u32; 2],
    /// 0x68-0x6C: GPIO Pull-up/down Enable (2 registers)
    pub gppud: u32,
    /// 0x70-0x74: GPIO Pull-up/down Enable Clock (2 registers)
    pub gppudclk: [u32; 2],
}

/// GPIO pin function modes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpioMode {
    /// Input mode
    Input = 0,
    /// Output mode
    Output = 1,
    /// Alternate function 0
    Alt0 = 4,
    /// Alternate function 1
    Alt1 = 5,
    /// Alternate function 2
    Alt2 = 6,
    /// Alternate function 3
    Alt3 = 7,
    /// Alternate function 4
    Alt4 = 3,
    /// Alternate function 5
    Alt5 = 2,
}

/// GPIO pull-up/down configuration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PullMode {
    /// No pull-up/down
    Disabled = 0,
    /// Pull down
    Down = 1,
    /// Pull up
    Up = 2,
}

/// GPIO driver for Raspberry Pi
pub struct GpioController {
    regs: *mut GpioRegisters,
}

impl GpioController {
    /// Initialize GPIO driver from a base address
    ///
    /// # Safety
    /// The caller must ensure:
    /// - The base address points to a valid GPIO controller
    /// - The address is properly aligned and accessible
    /// - No other code accesses the same GPIO controller
    pub unsafe fn new(base_addr: u64) -> Self {
        let regs = base_addr as *mut GpioRegisters;
        GpioController { regs }
    }

    /// Set a GPIO pin's function mode
    ///
    /// # Arguments
    /// * `pin` - GPIO pin number (0-53)
    /// * `mode` - GPIO mode (input, output, or alternate function)
    pub fn set_mode(&self, pin: u32, mode: GpioMode) {
        if pin >= 54 {
            return; // Invalid pin
        }

        unsafe {
            let reg_idx = (pin / 10) as usize;
            let bit_offset = ((pin % 10) * 3) as usize;

            let current = ptr::read_volatile(&(*self.regs).gpfsel[reg_idx]);
            let mask = 0b111 << bit_offset;
            let new_value = (current & !mask) | ((mode as u32) << bit_offset);

            ptr::write_volatile(&mut (*self.regs).gpfsel[reg_idx], new_value);
        }
    }

    /// Set a GPIO pin to output high
    ///
    /// # Arguments
    /// * `pin` - GPIO pin number (0-53)
    pub fn set(&self, pin: u32) {
        if pin >= 54 {
            return; // Invalid pin
        }

        unsafe {
            let reg_idx = (pin / 32) as usize;
            let bit = pin % 32;

            if reg_idx < 2 {
                ptr::write_volatile(&mut (*self.regs).gpset[reg_idx], 1u32 << bit);
            }
        }
    }

    /// Set a GPIO pin to output low
    ///
    /// # Arguments
    /// * `pin` - GPIO pin number (0-53)
    pub fn clear(&self, pin: u32) {
        if pin >= 54 {
            return; // Invalid pin
        }

        unsafe {
            let reg_idx = (pin / 32) as usize;
            let bit = pin % 32;

            if reg_idx < 2 {
                ptr::write_volatile(&mut (*self.regs).gpclr[reg_idx], 1u32 << bit);
            }
        }
    }

    /// Write a GPIO pin to a specific level
    ///
    /// # Arguments
    /// * `pin` - GPIO pin number (0-53)
    /// * `level` - 0 for low, non-zero for high
    pub fn write(&self, pin: u32, level: u32) {
        if level != 0 {
            self.set(pin);
        } else {
            self.clear(pin);
        }
    }

    /// Read the current level of a GPIO pin
    ///
    /// # Arguments
    /// * `pin` - GPIO pin number (0-53)
    /// # Returns
    /// 0 if pin is low, 1 if pin is high
    pub fn read(&self, pin: u32) -> u32 {
        if pin >= 54 {
            return 0; // Invalid pin
        }

        unsafe {
            let reg_idx = (pin / 32) as usize;
            let bit = pin % 32;

            if reg_idx < 2 {
                let level = ptr::read_volatile(&(*self.regs).gplev[reg_idx]);
                (level >> bit) & 1
            } else {
                0
            }
        }
    }

    /// Configure pull-up/down for a GPIO pin
    ///
    /// # Arguments
    /// * `pin` - GPIO pin number (0-53)
    /// * `mode` - Pull-up/down mode
    ///
    /// # Safety
    /// This operation modifies the pull-up/down configuration which may affect
    /// the electrical characteristics of the GPIO pin. Care should be taken
    /// to ensure the pin is not actively driven when changing this setting.
    pub unsafe fn set_pull(&self, pin: u32, mode: PullMode) {
        if pin >= 54 {
            return; // Invalid pin
        }

        let reg_idx = (pin / 32) as usize;
        let bit = pin % 32;

        // Set GPPUD for pull mode
        ptr::write_volatile(&mut (*self.regs).gppud, mode as u32);

        // Wait at least 150 cycles (polling busy wait)
        for _ in 0..150 {
            core::hint::spin_loop();
        }

        // Clock the pull mode into the pin
        if reg_idx < 2 {
            ptr::write_volatile(&mut (*self.regs).gppudclk[reg_idx], 1u32 << bit);
        }

        // Wait at least 150 cycles again
        for _ in 0..150 {
            core::hint::spin_loop();
        }

        // Remove the clock signal
        if reg_idx < 2 {
            ptr::write_volatile(&mut (*self.regs).gppudclk[reg_idx], 0);
        }

        // Clear GPPUD
        ptr::write_volatile(&mut (*self.regs).gppud, 0);
    }

    /// Toggle a GPIO pin output (if in output mode)
    ///
    /// # Arguments
    /// * `pin` - GPIO pin number (0-53)
    pub fn toggle(&self, pin: u32) {
        let current = self.read(pin);
        self.write(pin, 1 - current);
    }

    /// Check if a GPIO pin is configured as output
    ///
    /// # Arguments
    /// * `pin` - GPIO pin number (0-53)
    /// # Returns
    /// true if pin is in output mode, false otherwise
    pub fn is_output(&self, pin: u32) -> bool {
        if pin >= 54 {
            return false;
        }

        unsafe {
            let reg_idx = (pin / 10) as usize;
            let bit_offset = ((pin % 10) * 3) as usize;

            let fsel = ptr::read_volatile(&(*self.regs).gpfsel[reg_idx]);
            let mode = (fsel >> bit_offset) & 0b111;

            mode == (GpioMode::Output as u32)
        }
    }

    /// Check if a GPIO pin is configured as input
    ///
    /// # Arguments
    /// * `pin` - GPIO pin number (0-53)
    /// # Returns
    /// true if pin is in input mode, false otherwise
    pub fn is_input(&self, pin: u32) -> bool {
        if pin >= 54 {
            return false;
        }

        unsafe {
            let reg_idx = (pin / 10) as usize;
            let bit_offset = ((pin % 10) * 3) as usize;

            let fsel = ptr::read_volatile(&(*self.regs).gpfsel[reg_idx]);
            let mode = (fsel >> bit_offset) & 0b111;

            mode == (GpioMode::Input as u32)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gpio_mode_values() {
        assert_eq!(GpioMode::Input as u32, 0);
        assert_eq!(GpioMode::Output as u32, 1);
        assert_eq!(GpioMode::Alt0 as u32, 4);
    }

    #[test]
    fn test_pull_mode_values() {
        assert_eq!(PullMode::Disabled as u32, 0);
        assert_eq!(PullMode::Down as u32, 1);
        assert_eq!(PullMode::Up as u32, 2);
    }
}
