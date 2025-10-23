//! Broadcom Mailbox Protocol Driver for Raspberry Pi GPU Communication
//!
//! This module implements the mailbox interface used to communicate with the
//! VideoCore GPU firmware on Raspberry Pi platforms.
//!
//! The mailbox protocol enables:
//! - Device configuration (clock rates, power states)
//! - Framebuffer allocation and setup
//! - GPU memory management
//! - Temperature and voltage monitoring
//!
//! References:
//! - https://github.com/raspberrypi/firmware/wiki/Mailboxes
//! - https://github.com/raspberrypi/firmware/wiki/Mailbox-property-interface

use core::ptr;
use core::sync::atomic::{AtomicBool, Ordering};

/// Read register offset for mailbox
const MBOX_READ: usize = 0x00;
/// Write register offset for mailbox
const MBOX_WRITE: usize = 0x04;
/// Peek register offset for mailbox
#[allow(dead_code)]
const MBOX_PEEK: usize = 0x10;
/// Sender register offset for mailbox
#[allow(dead_code)]
const MBOX_SENDER: usize = 0x14;
/// Status register offset for mailbox
const MBOX_STATUS: usize = 0x18;
/// Config register offset for mailbox
#[allow(dead_code)]
const MBOX_CONFIG: usize = 0x1C;

/// Status register bit: mailbox empty
const MBOX_STATUS_EMPTY: u32 = 0x40000000;
/// Status register bit: mailbox full
const MBOX_STATUS_FULL: u32 = 0x80000000;

/// Mailbox channel: Power management
pub const MBOX_CHANNEL_POWER: u32 = 0;
/// Mailbox channel: Framebuffer interface
pub const MBOX_CHANNEL_FB: u32 = 1;
/// Mailbox channel: VCHIQ interface
pub const MBOX_CHANNEL_VCHIQ: u32 = 3;
/// Mailbox channel: Property tag interface
pub const MBOX_CHANNEL_PROPERTY: u32 = 8;
/// Mailbox channel: GPU memory access
pub const MBOX_CHANNEL_GPU_MEM: u32 = 8;

/// Request code for mailbox messages
pub const MBOX_REQUEST_CODE: u32 = 0x00000000;
/// Response code for mailbox messages
pub const MBOX_RESPONSE_CODE: u32 = 0x80000000;
/// End tag marker for property buffers
pub const MBOX_TAG_END: u32 = 0x00000000;

/// Property tag: Get board revision
pub const MBOX_TAG_GET_BOARD_REVISION: u32 = 0x00010002;
/// Property tag: Get ARM memory information
pub const MBOX_TAG_GET_ARM_MEMORY: u32 = 0x00010005;
/// Property tag: Get VideoCore memory information
pub const MBOX_TAG_GET_VC_MEMORY: u32 = 0x00010006;
/// Property tag: Get clock rate
pub const MBOX_TAG_GET_CLOCK_RATE: u32 = 0x00030002;
/// Property tag: Set clock rate
pub const MBOX_TAG_SET_CLOCK_RATE: u32 = 0x00038002;
/// Property tag: Get temperature
pub const MBOX_TAG_GET_TEMPERATURE: u32 = 0x00030006;
/// Property tag: Allocate framebuffer
pub const MBOX_TAG_ALLOCATE_FRAMEBUFFER: u32 = 0x00040001;
/// Property tag: Release framebuffer
pub const MBOX_TAG_RELEASE_FRAMEBUFFER: u32 = 0x00048001;
/// Property tag: Set physical framebuffer size
pub const MBOX_TAG_SET_PHYSICAL_SIZE: u32 = 0x00048003;
/// Property tag: Set virtual framebuffer size
pub const MBOX_TAG_SET_VIRTUAL_SIZE: u32 = 0x00048004;
/// Property tag: Set framebuffer color depth
pub const MBOX_TAG_SET_DEPTH: u32 = 0x00048005;
/// Property tag: Set pixel order (BGR/RGB)
pub const MBOX_TAG_SET_PIXEL_ORDER: u32 = 0x00048006;
/// Property tag: Get framebuffer pitch
pub const MBOX_TAG_GET_PITCH: u32 = 0x00040008;

/// Clock ID: Core clock
pub const MBOX_CLOCK_CORE: u32 = 4;
/// Clock ID: ARM CPU clock
pub const MBOX_CLOCK_ARM: u32 = 3;
/// Clock ID: V3D GPU clock
pub const MBOX_CLOCK_V3D: u32 = 5;

/// Pixel format: RGB565 (16-bit)
pub const MBOX_PIXEL_RGB565: u32 = 0;
/// Pixel format: RGB888 (24-bit)
pub const MBOX_PIXEL_RGB888: u32 = 1;
/// Pixel format: RGBA8888 (32-bit with alpha)
pub const MBOX_PIXEL_RGBA8888: u32 = 2;
/// Pixel format: RGBX8888 (32-bit without alpha)
pub const MBOX_PIXEL_RGBX8888: u32 = 3;

/// Pixel order: BGR (Blue-Green-Red)
pub const MBOX_PIXEL_ORDER_BGR: u32 = 0;
/// Pixel order: RGB (Red-Green-Blue)
pub const MBOX_PIXEL_ORDER_RGB: u32 = 1;

/// Memory address space conversion for VC GPU
/// Convert ARM physical address to VideoCore address (uncached)
pub fn arm_to_vc_uncached(addr: u32) -> u32 {
    addr | 0x40000000
}

/// Convert ARM physical address to VideoCore address (cached)
pub fn arm_to_vc_cached(addr: u32) -> u32 {
    0xC0000000 + (addr & 0x1FFFFFFF)
}

/// Convert VideoCore address back to ARM physical address
pub fn vc_to_arm(addr: u32) -> u32 {
    addr & 0x3FFFFFFF
}

/// Mailbox driver state
pub struct MailboxDriver {
    base_addr: u64,
    initialized: AtomicBool,
}

impl MailboxDriver {
    /// Create a new mailbox driver from the base address
    pub fn new(base_addr: u64) -> Self {
        MailboxDriver {
            base_addr,
            initialized: AtomicBool::new(false),
        }
    }

    /// Initialize the mailbox
    pub fn init(&self) {
        // Clear the mailbox (read any pending data)
        while !self.is_empty(0) {
            self.read(0);
        }
        self.initialized.store(true, Ordering::Release);
    }

    /// Check if mailbox is empty
    fn is_empty(&self, mbox: u32) -> bool {
        let status = unsafe {
            ptr::read_volatile((self.base_addr + (mbox * 0x20 + MBOX_STATUS as u32) as u64) as *const u32)
        };
        (status & MBOX_STATUS_EMPTY) != 0
    }

    /// Check if mailbox is full
    fn is_full(&self, mbox: u32) -> bool {
        let status = unsafe {
            ptr::read_volatile((self.base_addr + (mbox * 0x20 + MBOX_STATUS as u32) as u64) as *const u32)
        };
        (status & MBOX_STATUS_FULL) != 0
    }

    /// Read from mailbox (blocking until data available)
    fn read(&self, mbox: u32) -> u32 {
        let addr = self.base_addr + (mbox * 0x20 + MBOX_READ as u32) as u64;
        loop {
            if !self.is_empty(mbox) {
                return unsafe { ptr::read_volatile(addr as *const u32) };
            }
            // Busy wait for data
            unsafe { core::arch::asm!("nop") };
        }
    }

    /// Write to mailbox (blocking until space available)
    fn write(&self, mbox: u32, value: u32) {
        let addr = self.base_addr + (mbox * 0x20 + MBOX_WRITE as u32) as u64;
        loop {
            if !self.is_full(mbox) {
                unsafe { ptr::write_volatile(addr as *mut u32, value) };
                break;
            }
            // Busy wait for space
            unsafe { core::arch::asm!("nop") };
        }
    }

    /// Send a raw message to the GPU via mailbox
    /// Returns the response message value
    pub fn send_message(&self, channel: u32, message: u32) -> u32 {
        // Encode message: upper 28 bits = message, lower 4 bits = channel
        let full_message = (message & 0xFFFFFFF0) | (channel & 0x0F);

        // Send to ARM-to-VC mailbox (mailbox 1)
        self.write(1, full_message);

        // Wait for response from VC-to-ARM mailbox (mailbox 0)
        // Keep reading until we get a response on our channel
        loop {
            let response = self.read(0);
            let response_channel = response & 0x0F;
            if response_channel == channel {
                // Extract message (upper 28 bits)
                return response & 0xFFFFFFF0;
            }
        }
    }

    /// Send property tag buffer to GPU
    /// Buffer format: [size, code, [tags...], 0]
    /// Returns true if successful (response code has MSB set)
    pub fn property_call(&self, buffer: &mut [u32]) -> bool {
        if buffer.len() < 5 {
            return false;
        }

        // Set request code
        buffer[1] = MBOX_REQUEST_CODE;

        // Ensure buffer is 16-byte aligned and in correct address space
        let buffer_addr = buffer.as_ptr() as u32;

        // Send buffer address to mailbox
        // The address must be in VC address space (with flags in lower bits)
        let vc_addr = arm_to_vc_uncached(buffer_addr);
        let _ = self.send_message(MBOX_CHANNEL_PROPERTY, vc_addr);

        // Check if response was successful
        buffer[1] == MBOX_RESPONSE_CODE
    }

    /// Get board revision via mailbox
    /// Returns the revision code, or 0 on failure
    pub fn get_board_revision(&self) -> u32 {
        // Allocate buffer on stack (must be 16-byte aligned)
        let mut buffer: [u32; 7] = [0; 7];

        // Setup message
        buffer[0] = 7 * 4; // Message size
        buffer[1] = MBOX_REQUEST_CODE;
        buffer[2] = MBOX_TAG_GET_BOARD_REVISION;
        buffer[3] = 4; // Response size
        buffer[4] = 0; // Request size
        buffer[5] = 0; // Revision value
        buffer[6] = MBOX_TAG_END;

        if self.property_call(&mut buffer) {
            buffer[5]
        } else {
            0
        }
    }

    /// Get ARM memory information
    /// Returns (address, size)
    pub fn get_arm_memory(&self) -> (u32, u32) {
        let mut buffer: [u32; 8] = [0; 8];

        buffer[0] = 8 * 4;
        buffer[1] = MBOX_REQUEST_CODE;
        buffer[2] = MBOX_TAG_GET_ARM_MEMORY;
        buffer[3] = 8; // Response size: 2 u32s
        buffer[4] = 0; // Request size
        buffer[5] = 0; // Address
        buffer[6] = 0; // Size
        buffer[7] = MBOX_TAG_END;

        if self.property_call(&mut buffer) {
            (buffer[5], buffer[6])
        } else {
            (0, 0)
        }
    }

    /// Get VideoCore memory information
    /// Returns (address, size)
    pub fn get_vc_memory(&self) -> (u32, u32) {
        let mut buffer: [u32; 8] = [0; 8];

        buffer[0] = 8 * 4;
        buffer[1] = MBOX_REQUEST_CODE;
        buffer[2] = MBOX_TAG_GET_VC_MEMORY;
        buffer[3] = 8;
        buffer[4] = 0;
        buffer[5] = 0;
        buffer[6] = 0;
        buffer[7] = MBOX_TAG_END;

        if self.property_call(&mut buffer) {
            (buffer[5], buffer[6])
        } else {
            (0, 0)
        }
    }

    /// Get current clock rate for a given clock ID
    /// Returns the rate in Hz, or 0 on failure
    pub fn get_clock_rate(&self, clock_id: u32) -> u32 {
        let mut buffer: [u32; 8] = [0; 8];

        buffer[0] = 8 * 4;
        buffer[1] = MBOX_REQUEST_CODE;
        buffer[2] = MBOX_TAG_GET_CLOCK_RATE;
        buffer[3] = 8; // Response size
        buffer[4] = 4; // Request size (clock ID)
        buffer[5] = clock_id;
        buffer[6] = 0; // Rate response
        buffer[7] = MBOX_TAG_END;

        if self.property_call(&mut buffer) {
            buffer[6]
        } else {
            0
        }
    }

    /// Set clock rate for a given clock ID
    /// Returns the actual set rate, or 0 on failure
    pub fn set_clock_rate(&self, clock_id: u32, rate: u32) -> u32 {
        let mut buffer: [u32; 9] = [0; 9];

        buffer[0] = 9 * 4;
        buffer[1] = MBOX_REQUEST_CODE;
        buffer[2] = MBOX_TAG_SET_CLOCK_RATE;
        buffer[3] = 8; // Response size
        buffer[4] = 8; // Request size
        buffer[5] = clock_id;
        buffer[6] = rate;
        buffer[7] = 0; // Skip turbo (0 = don't enable turbo)
        buffer[8] = MBOX_TAG_END;

        if self.property_call(&mut buffer) {
            buffer[6]
        } else {
            0
        }
    }

    /// Get temperature (CPU temperature)
    /// Returns temperature in thousandths of a degree Celsius
    pub fn get_temperature(&self) -> u32 {
        let mut buffer: [u32; 8] = [0; 8];

        buffer[0] = 8 * 4;
        buffer[1] = MBOX_REQUEST_CODE;
        buffer[2] = MBOX_TAG_GET_TEMPERATURE;
        buffer[3] = 4; // Response size
        buffer[4] = 4; // Request size
        buffer[5] = 0; // Measurement ID (0 = CPU)
        buffer[6] = 0; // Temperature response
        buffer[7] = MBOX_TAG_END;

        if self.property_call(&mut buffer) {
            buffer[6]
        } else {
            0
        }
    }
}

/// Global mailbox driver instance
static mut MAILBOX: Option<MailboxDriver> = None;
static MAILBOX_INIT: AtomicBool = AtomicBool::new(false);

/// Initialize global mailbox driver
pub fn mailbox_init(base_addr: u64) {
    unsafe {
        if !MAILBOX_INIT.swap(true, Ordering::Acquire) {
            MAILBOX = Some(MailboxDriver::new(base_addr));
            if let Some(ref mbox) = MAILBOX {
                mbox.init();
            }
        }
    }
}

/// Get reference to global mailbox driver
#[allow(unsafe_code)]
pub fn mailbox() -> Option<&'static MailboxDriver> {
    #[allow(static_mut_refs)]
    unsafe { MAILBOX.as_ref() }
}

/// Get mutable reference to global mailbox driver
#[allow(unsafe_code)]
pub fn mailbox_mut() -> Option<&'static mut MailboxDriver> {
    #[allow(static_mut_refs)]
    unsafe { MAILBOX.as_mut() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_conversion() {
        let arm_addr = 0x10000000u32;

        // Test uncached conversion
        let vc_uncached = arm_to_vc_uncached(arm_addr);
        assert_eq!(vc_uncached, 0x50000000);
        assert_eq!(vc_to_arm(vc_uncached), arm_addr);

        // Test cached conversion
        let vc_cached = arm_to_vc_cached(arm_addr);
        assert_eq!(vc_cached, 0xD0000000);
        assert_eq!(vc_to_arm(vc_cached), arm_addr);
    }

    #[test]
    fn test_message_encoding() {
        let channel = MBOX_CHANNEL_PROPERTY;
        let message = 0x12345670u32;
        let full_message = (message & 0xFFFFFFF0) | (channel & 0x0F);
        assert_eq!(full_message & 0x0F, channel);
        assert_eq!(full_message & 0xFFFFFFF0, message);
    }
}
