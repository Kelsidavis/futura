//! GPU Framebuffer Driver for Raspberry Pi
//!
//! This module implements framebuffer allocation and configuration
//! via the mailbox protocol. It provides the foundation for display
//! output on Raspberry Pi platforms.
//!
//! Framebuffer management includes:
//! - Memory allocation via mailbox
//! - Display configuration (resolution, color depth)
//! - Framebuffer enable/disable
//! - Palette support for indexed color modes

use core::ptr;

/// Pixel formats supported by the framebuffer
#[derive(Clone, Copy, Debug)]
pub enum PixelFormat {
    /// 16-bit RGB (5-6-5 format)
    Rgb565,
    /// 24-bit RGB (8-8-8 format)
    Rgb888,
    /// 32-bit RGBA with alpha channel
    Rgba8888,
    /// 32-bit RGBX (RGB with padding)
    Rgbx8888,
}

impl PixelFormat {
    /// Get bits per pixel for this format
    pub fn bits_per_pixel(&self) -> u32 {
        match self {
            PixelFormat::Rgb565 => 16,
            PixelFormat::Rgb888 => 24,
            PixelFormat::Rgba8888 | PixelFormat::Rgbx8888 => 32,
        }
    }

    /// Get bytes per pixel for this format
    pub fn bytes_per_pixel(&self) -> u32 {
        (self.bits_per_pixel() + 7) / 8
    }

    /// Convert to mailbox pixel format code
    pub fn mailbox_code(&self) -> u32 {
        match self {
            PixelFormat::Rgb565 => 0,    // MBOX_PIXEL_RGB565
            PixelFormat::Rgb888 => 1,    // MBOX_PIXEL_RGB888
            PixelFormat::Rgba8888 => 2,  // MBOX_PIXEL_RGBA8888
            PixelFormat::Rgbx8888 => 3,  // MBOX_PIXEL_RGBX8888
        }
    }
}

/// Framebuffer configuration
#[derive(Clone, Debug)]
pub struct FramebufferConfig {
    /// Physical width in pixels
    pub width: u32,
    /// Physical height in pixels
    pub height: u32,
    /// Virtual width (for panning)
    pub virtual_width: u32,
    /// Virtual height (for panning)
    pub virtual_height: u32,
    /// X offset for panning
    pub x_offset: u32,
    /// Y offset for panning
    pub y_offset: u32,
    /// Pixel format
    pub format: PixelFormat,
    /// Bytes per scanline (pitch)
    pub pitch: u32,
}

impl FramebufferConfig {
    /// Create a new framebuffer configuration
    pub fn new(width: u32, height: u32, format: PixelFormat) -> Self {
        let pitch = width * format.bytes_per_pixel();
        FramebufferConfig {
            width,
            height,
            virtual_width: width,
            virtual_height: height,
            x_offset: 0,
            y_offset: 0,
            format,
            pitch,
        }
    }

    /// Calculate total framebuffer size in bytes
    pub fn size(&self) -> u32 {
        self.pitch * self.height
    }
}

/// Framebuffer state
pub struct FramebufferDriver {
    config: Option<FramebufferConfig>,
    fb_address: u32,      // Physical address
    fb_size: u32,         // Size in bytes
    enabled: bool,
}

impl FramebufferDriver {
    /// Create a new framebuffer driver
    pub fn new() -> Self {
        FramebufferDriver {
            config: None,
            fb_address: 0,
            fb_size: 0,
            enabled: false,
        }
    }

    /// Allocate and configure framebuffer
    ///
    /// This function:
    /// 1. Allocates GPU memory via mailbox
    /// 2. Configures display parameters
    /// 3. Enables the display
    pub fn allocate(&mut self, config: FramebufferConfig) -> Result<(), &'static str> {
        let _size = config.size();

        // Build mailbox request buffer for framebuffer allocation
        // This would normally call the mailbox driver here
        // For now, this is a stub that shows the structure

        /*
        // Example mailbox sequence:
        // 1. Set physical size
        let mut buffer = [0u32; 128];
        buffer[0] = (128 * 4) as u32; // Message size
        buffer[1] = 0; // Request code (will be set by mailbox)
        buffer[2] = 0x48003; // MBOX_TAG_SET_PHYSICAL_SIZE
        buffer[3] = 8; // Response size
        buffer[4] = 8; // Request size
        buffer[5] = config.width;
        buffer[6] = config.height;

        // 2. Set virtual size
        // 3. Set depth
        // 4. Set pixel order
        // 5. Allocate framebuffer
        */

        self.config = Some(config);
        Ok(())
    }

    /// Enable the framebuffer display
    pub fn enable(&mut self) -> Result<(), &'static str> {
        if self.config.is_none() {
            return Err("Framebuffer not allocated");
        }

        self.enabled = true;
        Ok(())
    }

    /// Disable the framebuffer display
    pub fn disable(&mut self) {
        self.enabled = false;
    }

    /// Get current framebuffer configuration
    pub fn config(&self) -> Option<&FramebufferConfig> {
        self.config.as_ref()
    }

    /// Check if framebuffer is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Get physical framebuffer address
    pub fn address(&self) -> u32 {
        self.fb_address
    }

    /// Get framebuffer size in bytes
    pub fn size(&self) -> u32 {
        self.fb_size
    }

    /// Write a pixel to the framebuffer
    ///
    /// Safety: Assumes framebuffer is properly initialized and mapped
    pub unsafe fn write_pixel(&self, x: u32, y: u32, color: u32) {
        if let Some(ref config) = self.config {
            if x >= config.width || y >= config.height {
                return; // Out of bounds
            }

            let offset = (y * config.pitch / config.format.bytes_per_pixel()) + x;
            let pixel_addr = (self.fb_address as *mut u32).add(offset as usize);

            match config.format {
                PixelFormat::Rgb565 => {
                    // Convert 32-bit RGBA to 16-bit RGB565
                    let r = (color >> 16) & 0xFF;
                    let g = (color >> 8) & 0xFF;
                    let b = color & 0xFF;
                    let rgb565 = ((r & 0xF8) << 8) | ((g & 0xFC) << 3) | (b >> 3);
                    ptr::write_volatile(pixel_addr as *mut u16, rgb565 as u16);
                }
                PixelFormat::Rgb888 => {
                    // 24-bit RGB (3 bytes per pixel)
                    let addr = self.fb_address as *mut u8;
                    let base = (offset * 3) as usize;
                    ptr::write_volatile(addr.add(base), (color >> 16) as u8); // R
                    ptr::write_volatile(addr.add(base + 1), (color >> 8) as u8); // G
                    ptr::write_volatile(addr.add(base + 2), color as u8); // B
                }
                PixelFormat::Rgba8888 | PixelFormat::Rgbx8888 => {
                    // 32-bit direct write
                    ptr::write_volatile(pixel_addr, color);
                }
            }
        }
    }

    /// Fill rectangle with solid color
    ///
    /// Safety: Assumes framebuffer is properly initialized
    pub unsafe fn fill_rect(&self, x: u32, y: u32, width: u32, height: u32, color: u32) {
        for dy in 0..height {
            for dx in 0..width {
                self.write_pixel(x + dx, y + dy, color);
            }
        }
    }

    /// Clear framebuffer to black
    pub unsafe fn clear(&self) {
        if let Some(ref config) = self.config {
            self.fill_rect(0, 0, config.width, config.height, 0);
        }
    }

    /// Copy framebuffer region (memcpy style)
    ///
    /// Safety: Assumes source and destination regions are valid
    pub unsafe fn copy_region(&self, src_x: u32, src_y: u32, dst_x: u32, dst_y: u32,
                              width: u32, height: u32) {
        if let Some(ref config) = self.config {
            let bpp = config.format.bytes_per_pixel();
            let src_base = self.fb_address + (src_y * config.pitch) + (src_x * bpp);
            let dst_base = self.fb_address + (dst_y * config.pitch) + (dst_x * bpp);
            let row_size = width * bpp;

            for row in 0..height {
                let src = (src_base + (row * config.pitch)) as *const u8;
                let dst = (dst_base + (row * config.pitch)) as *mut u8;
                ptr::copy(src, dst, row_size as usize);
            }
        }
    }
}

impl Default for FramebufferDriver {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pixel_format_bits() {
        assert_eq!(PixelFormat::Rgb565.bits_per_pixel(), 16);
        assert_eq!(PixelFormat::Rgb888.bits_per_pixel(), 24);
        assert_eq!(PixelFormat::Rgba8888.bits_per_pixel(), 32);
    }

    #[test]
    fn test_pixel_format_bytes() {
        assert_eq!(PixelFormat::Rgb565.bytes_per_pixel(), 2);
        assert_eq!(PixelFormat::Rgb888.bytes_per_pixel(), 3);
        assert_eq!(PixelFormat::Rgba8888.bytes_per_pixel(), 4);
    }

    #[test]
    fn test_framebuffer_config() {
        let config = FramebufferConfig::new(1920, 1080, PixelFormat::Rgba8888);
        assert_eq!(config.width, 1920);
        assert_eq!(config.height, 1080);
        assert_eq!(config.pitch, 1920 * 4);
        assert_eq!(config.size(), 1920 * 1080 * 4);
    }

    #[test]
    fn test_framebuffer_driver() {
        let driver = FramebufferDriver::new();
        assert!(!driver.is_enabled());
        assert_eq!(driver.address(), 0);
        assert_eq!(driver.config(), None);
    }
}
