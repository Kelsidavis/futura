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
pub mod gpu_crtc;
pub mod gpu_hdmi;
pub mod gpu_v3d;
pub mod gpu_software;

pub use uart::Pl011Uart;
pub use gpio::GpioController;
pub use mailbox::MailboxDriver;
pub use gpu_framebuffer::{FramebufferDriver, FramebufferConfig, PixelFormat};
pub use gpu_crtc::{CrtcController, Plane, PlaneType, DisplayTiming, AlphaMode};
pub use gpu_hdmi::{HdmiController, DisplayMode, ColorSpace, ColorDepth, OutputMode};
pub use gpu_v3d::{
    V3dController, V3dVersion, TextureFormat, Texture, VertexBuffer, IndexBuffer, UniformBuffer,
    RenderJob, ComputeJob, JobStatus, PerformanceStats,
};
pub use gpu_software::{SoftwareRenderer, Color, Point, Rect, BlendMode};
