//! Futura OS Rust Drivers Library
//!
//! Type-safe, embedded drivers for Futura OS ARM64 platform.
//! Provides PL011 UART, GPIO, and other platform-specific drivers.

#![no_std]
#![warn(missing_docs)]

pub mod uart;
pub mod gpio;
pub mod registers;
pub mod mailbox;
pub mod gpu_framebuffer;

pub use uart::Pl011Uart;
pub use gpio::GpioController;
pub use mailbox::MailboxDriver;
pub use gpu_framebuffer::{FramebufferDriver, FramebufferConfig, PixelFormat};
