//! PL011 UART Driver for Raspberry Pi ARM64 platforms
//!
//! This module implements a type-safe, embedded Rust driver for the ARM PL011
//! UART controller used in Raspberry Pi 3, 4, and 5.
//!
//! The PL011 is a standard ARM UART controller with:
//! - FIFO buffering (16 bytes typical)
//! - Programmable baud rate via IBRD/FBRD registers
//! - Hardware flow control support
//! - Interrupt capability

use core::fmt;
use core::ptr;

/// PL011 UART register map
#[repr(C)]
pub struct Pl011Registers {
    /// 0x00: Data Register - Transmit/Receive data
    pub dr: u32,
    /// 0x04: Receive Status/Error Clear Register
    pub rsrecr: u32,
    _reserved1: [u32; 4],
    /// 0x18: Flag Register
    pub fr: u32,
    _reserved2: [u32; 1],
    /// 0x20: IrDA Low-Power Counter Register
    pub ilpr: u32,
    /// 0x24: Integer Baud Rate Divisor
    pub ibrd: u32,
    /// 0x28: Fractional Baud Rate Divisor
    pub fbrd: u32,
    /// 0x2C: Line Control Register (High byte)
    pub lcrh: u32,
    /// 0x30: Control Register
    pub cr: u32,
    /// 0x34: Interrupt FIFO Level Select
    pub ifls: u32,
    /// 0x38: Interrupt Mask Set/Clear
    pub imsc: u32,
    /// 0x3C: Raw Interrupt Status
    pub ris: u32,
    /// 0x40: Masked Interrupt Status
    pub mis: u32,
    /// 0x44: Interrupt Clear Register
    pub icr: u32,
    /// 0x48: DMA Control Register
    pub dmacr: u32,
}

// Flag Register (FR) bits
/// Transmit FIFO full
const FR_TXFF: u32 = 1 << 5;
/// Receive FIFO empty
const FR_RXFE: u32 = 1 << 4;
/// UART busy
const FR_BUSY: u32 = 1 << 3;
/// Transmit FIFO empty
const FR_TXFE: u32 = 1 << 7;

// Control Register (CR) bits
/// UART enable
const CR_UARTEN: u32 = 1 << 0;
/// Transmit enable
const CR_TXE: u32 = 1 << 8;
/// Receive enable
const CR_RXE: u32 = 1 << 9;

// Line Control Register (LCRH) bits
/// Word length: 8 bits
const LCRH_WLEN_8: u32 = 3 << 5;
/// FIFO enable
const LCRH_FEN: u32 = 1 << 4;

/// Configuration for PL011 UART
#[derive(Debug, Clone, Copy)]
pub struct UartConfig {
    /// Baud rate in bits per second
    pub baudrate: u32,
    /// UART clock frequency in Hz (typically 3,000,000 Hz for RPi)
    pub clock_hz: u32,
    /// Enable FIFO buffering
    pub use_fifo: bool,
    /// Enable hardware flow control
    pub flow_control: bool,
}

impl Default for UartConfig {
    fn default() -> Self {
        UartConfig {
            baudrate: 115200,
            clock_hz: 3_000_000, // RPi standard UART clock
            use_fifo: true,
            flow_control: false,
        }
    }
}

/// PL011 UART driver
///
/// Provides safe access to the PL011 UART controller with proper
/// register abstractions and state management.
pub struct Pl011Uart {
    regs: *mut Pl011Registers,
    config: UartConfig,
}

impl Pl011Uart {
    /// Initialize a new UART driver from a base address
    ///
    /// # Safety
    /// The caller must ensure:
    /// - The base address points to a valid PL011 UART controller
    /// - The address is properly aligned and accessible
    /// - No other code accesses the same UART controller
    pub unsafe fn new(base_addr: u64, config: UartConfig) -> Self {
        let regs = base_addr as *mut Pl011Registers;
        let mut uart = Pl011Uart { regs, config };
        uart.init();
        uart
    }

    /// Initialize UART with the configured settings
    fn init(&mut self) {
        unsafe {
            // Disable UART during configuration
            ptr::write_volatile(&mut (*self.regs).cr, 0);

            // Calculate and set baud rate divisors
            let (ibrd, fbrd) = self.calculate_divisors();
            ptr::write_volatile(&mut (*self.regs).ibrd, ibrd);
            ptr::write_volatile(&mut (*self.regs).fbrd, fbrd);

            // Set line control: 8 bits, no parity, 1 stop bit
            let mut lcrh = LCRH_WLEN_8;
            if self.config.use_fifo {
                lcrh |= LCRH_FEN;
            }
            ptr::write_volatile(&mut (*self.regs).lcrh, lcrh);

            // Enable UART: transmit, receive, and UART itself
            let cr = CR_UARTEN | CR_TXE | CR_RXE;
            // Note: flow control bits could be added here if needed
            // cr |= CR_CTSEN | CR_RTSEN;
            ptr::write_volatile(&mut (*self.regs).cr, cr);
        }
    }

    /// Calculate baud rate divisors (IBRD and FBRD)
    ///
    /// Formula from PL011 datasheet:
    /// IBRD = UART_CLK / (16 * BAUD)
    /// FBRD = (UART_CLK % (16 * BAUD)) * 64 / (16 * BAUD)
    fn calculate_divisors(&self) -> (u32, u32) {
        let divisor = self.config.clock_hz / (16 * self.config.baudrate);
        let remainder = self.config.clock_hz % (16 * self.config.baudrate);

        let ibrd = divisor;
        let fbrd = ((remainder * 64) + (8 * self.config.baudrate)) / (16 * self.config.baudrate);

        (ibrd, fbrd & 0x3F) // FBRD is only 6 bits
    }

    /// Write a single byte to the UART
    ///
    /// This function blocks until the transmit FIFO has space.
    pub fn write_byte(&self, byte: u8) {
        unsafe {
            // Wait for transmit FIFO to have space
            while ptr::read_volatile(&(*self.regs).fr) & FR_TXFF != 0 {
                // Busy wait
            }

            // Send the byte
            ptr::write_volatile(&mut (*self.regs).dr, byte as u32);
        }
    }

    /// Read a single byte from the UART
    ///
    /// This function blocks until data is available.
    pub fn read_byte(&self) -> u8 {
        unsafe {
            // Wait for receive FIFO to have data
            while ptr::read_volatile(&(*self.regs).fr) & FR_RXFE != 0 {
                // Busy wait
            }

            // Read the byte
            (ptr::read_volatile(&(*self.regs).dr) & 0xFF) as u8
        }
    }

    /// Try to read a byte without blocking
    ///
    /// Returns `Some(byte)` if data is available, `None` if FIFO is empty.
    pub fn try_read_byte(&self) -> Option<u8> {
        unsafe {
            let fr = ptr::read_volatile(&(*self.regs).fr);
            if fr & FR_RXFE != 0 {
                None
            } else {
                Some((ptr::read_volatile(&(*self.regs).dr) & 0xFF) as u8)
            }
        }
    }

    /// Check if the transmit FIFO is empty
    pub fn is_tx_empty(&self) -> bool {
        unsafe { ptr::read_volatile(&(*self.regs).fr) & FR_TXFE != 0 }
    }

    /// Check if the receive FIFO is empty
    pub fn is_rx_empty(&self) -> bool {
        unsafe { ptr::read_volatile(&(*self.regs).fr) & FR_RXFE != 0 }
    }

    /// Check if the UART is busy (transmitting or receiving)
    pub fn is_busy(&self) -> bool {
        unsafe { ptr::read_volatile(&(*self.regs).fr) & FR_BUSY != 0 }
    }

    /// Flush any pending data in the transmit FIFO
    pub fn flush(&self) {
        // Wait for transmit FIFO to be empty
        while !self.is_tx_empty() {
            // Busy wait
        }
        // Wait for UART to finish transmitting
        while self.is_busy() {
            // Busy wait
        }
    }

    /// Write a string to the UART
    ///
    /// Characters are sent as-is. For newlines, this function also sends
    /// a carriage return before the newline for proper terminal formatting.
    pub fn write_str(&self, s: &str) {
        for byte in s.bytes() {
            if byte == b'\n' {
                self.write_byte(b'\r');
            }
            self.write_byte(byte);
        }
    }

    /// Disable the UART
    pub fn disable(&self) {
        unsafe {
            ptr::write_volatile(&mut (*self.regs).cr, 0);
        }
    }

    /// Get the current configuration
    pub fn config(&self) -> UartConfig {
        self.config
    }
}

impl fmt::Write for Pl011Uart {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        // Use the write_str method from Pl011Uart (non-mutable version)
        // by calling it on a reference
        (self as &Pl011Uart).write_str(s);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_divisor_calculation() {
        let config = UartConfig {
            baudrate: 115200,
            clock_hz: 3_000_000,
            use_fifo: true,
            flow_control: false,
        };

        // Create a dummy UART (we won't actually use it for hardware access)
        // This is just to test the divisor calculation logic
        let uart = Pl011Uart {
            regs: core::ptr::null_mut(),
            config,
        };

        let (ibrd, fbrd) = uart.calculate_divisors();
        assert_eq!(ibrd, 1); // 3MHz / (16 * 115200) ≈ 1
        assert!(fbrd < 64); // FBRD must be 6 bits
    }
}
