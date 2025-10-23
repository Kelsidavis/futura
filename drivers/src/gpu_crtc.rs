//! Display Controller (CRTC) Driver for Raspberry Pi
//!
//! This module implements the display controller (Cathode Ray Tube Controller)
//! abstraction for Raspberry Pi platforms. The CRTC manages display timing,
//! synchronization, and plane composition.
//!
//! Key responsibilities:
//! - Display mode configuration (resolution, refresh rate, timings)
//! - Plane composition (primary framebuffer + overlays)
//! - Interrupt synchronization (VSync, line events)
//! - Display enable/disable with proper sequencing

use core::fmt;

/// Display timing parameters (in pixels and scan lines)
#[derive(Clone, Copy, Debug)]
pub struct DisplayTiming {
    /// Horizontal active pixels
    pub h_active: u32,
    /// Horizontal front porch (blank pixels after active)
    pub h_front_porch: u32,
    /// Horizontal sync pulse width
    pub h_sync: u32,
    /// Horizontal back porch (blank pixels before active)
    pub h_back_porch: u32,
    /// Vertical active lines
    pub v_active: u32,
    /// Vertical front porch (blank lines after active)
    pub v_front_porch: u32,
    /// Vertical sync pulse width
    pub v_sync: u32,
    /// Vertical back porch (blank lines before active)
    pub v_back_porch: u32,
    /// Pixel clock frequency in Hz
    pub pixel_clock: u32,
    /// Refresh rate in Hz (derived from timing)
    pub refresh_rate: u32,
}

impl DisplayTiming {
    /// Calculate total horizontal scan time in pixels
    pub fn h_total(&self) -> u32 {
        self.h_active + self.h_front_porch + self.h_sync + self.h_back_porch
    }

    /// Calculate total vertical scan time in lines
    pub fn v_total(&self) -> u32 {
        self.v_active + self.v_front_porch + self.v_sync + self.v_back_porch
    }

    /// Calculate refresh rate from timing (Hz)
    pub fn calc_refresh_rate(&self) -> u32 {
        if self.h_total() == 0 || self.v_total() == 0 {
            0
        } else {
            self.pixel_clock / (self.h_total() * self.v_total())
        }
    }
}

/// Display plane types
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlaneType {
    /// Primary framebuffer plane (always visible)
    Primary,
    /// Cursor plane (hardware cursor)
    Cursor,
    /// Overlay plane (video or additional graphics)
    Overlay,
}

/// Plane composition order
#[derive(Clone, Copy, Debug)]
pub struct PlaneComposition {
    /// Z-order depth (0 = bottom, higher = on top)
    pub z_order: u32,
    /// Alpha blending mode
    pub alpha_mode: AlphaMode,
    /// Plane visibility
    pub visible: bool,
}

/// Alpha blending modes
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AlphaMode {
    /// No blending (opaque)
    Opaque,
    /// Per-pixel alpha blending
    PerPixel,
    /// Plane-wide constant alpha
    Constant(u8),
}

/// Display plane abstraction
#[derive(Clone, Copy, Debug)]
pub struct Plane {
    /// Plane type
    pub plane_type: PlaneType,
    /// Framebuffer address
    pub fb_address: u32,
    /// Plane position (x, y)
    pub x: u32,
    pub y: u32,
    /// Plane dimensions
    pub width: u32,
    pub height: u32,
    /// Composition settings
    pub composition: PlaneComposition,
}

impl Plane {
    /// Create a new plane
    pub fn new(plane_type: PlaneType, fb_address: u32, width: u32, height: u32) -> Self {
        Plane {
            plane_type,
            fb_address,
            x: 0,
            y: 0,
            width,
            height,
            composition: PlaneComposition {
                z_order: 0,
                alpha_mode: AlphaMode::Opaque,
                visible: true,
            },
        }
    }

    /// Set plane position
    pub fn set_position(&mut self, x: u32, y: u32) {
        self.x = x;
        self.y = y;
    }

    /// Set plane dimensions
    pub fn set_size(&mut self, width: u32, height: u32) {
        self.width = width;
        self.height = height;
    }

    /// Set plane visibility
    pub fn set_visible(&mut self, visible: bool) {
        self.composition.visible = visible;
    }

    /// Set alpha blending mode
    pub fn set_alpha_mode(&mut self, alpha_mode: AlphaMode) {
        self.composition.alpha_mode = alpha_mode;
    }
}

/// CRTC (display controller) state
pub struct CrtcController {
    /// Display timing configuration
    timing: Option<DisplayTiming>,
    /// Primary plane (framebuffer)
    primary_plane: Option<Plane>,
    /// Overlay planes
    overlay_planes: [Option<Plane>; 4],
    /// Display enabled flag
    enabled: bool,
    /// Vertical sync interrupts enabled
    vsync_enabled: bool,
    /// Current line number (for interrupt tracking)
    current_line: u32,
    /// Pixel clock frequency
    pixel_clock: u32,
}

impl CrtcController {
    /// Create a new CRTC controller
    pub fn new() -> Self {
        CrtcController {
            timing: None,
            primary_plane: None,
            overlay_planes: [None; 4],
            enabled: false,
            vsync_enabled: false,
            current_line: 0,
            pixel_clock: 0,
        }
    }

    /// Set display timing configuration
    pub fn set_timing(&mut self, timing: DisplayTiming) {
        self.pixel_clock = timing.pixel_clock;
        self.timing = Some(timing);
    }

    /// Get current timing configuration
    pub fn timing(&self) -> Option<&DisplayTiming> {
        self.timing.as_ref()
    }

    /// Set primary framebuffer plane
    pub fn set_primary_plane(&mut self, plane: Plane) {
        self.primary_plane = Some(plane);
    }

    /// Get primary plane
    pub fn primary_plane(&self) -> Option<&Plane> {
        self.primary_plane.as_ref()
    }

    /// Get mutable primary plane
    pub fn primary_plane_mut(&mut self) -> Option<&mut Plane> {
        self.primary_plane.as_mut()
    }

    /// Add or replace overlay plane at index (0-3)
    pub fn set_overlay_plane(&mut self, index: usize, plane: Plane) -> Result<(), &'static str> {
        if index >= 4 {
            return Err("Overlay plane index out of bounds (0-3)");
        }
        self.overlay_planes[index] = Some(plane);
        Ok(())
    }

    /// Get overlay plane at index
    pub fn overlay_plane(&self, index: usize) -> Option<&Plane> {
        if index >= 4 {
            None
        } else {
            self.overlay_planes[index].as_ref()
        }
    }

    /// Remove overlay plane at index
    pub fn remove_overlay_plane(&mut self, index: usize) -> Option<Plane> {
        if index < 4 {
            self.overlay_planes[index].take()
        } else {
            None
        }
    }

    /// Enable display output
    pub fn enable(&mut self) -> Result<(), &'static str> {
        if self.timing.is_none() {
            return Err("Display timing not configured");
        }
        if self.primary_plane.is_none() {
            return Err("Primary plane not configured");
        }

        self.enabled = true;
        Ok(())
    }

    /// Disable display output
    pub fn disable(&mut self) {
        self.enabled = false;
    }

    /// Check if display is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Enable VSync interrupts
    pub fn enable_vsync(&mut self) {
        self.vsync_enabled = true;
    }

    /// Disable VSync interrupts
    pub fn disable_vsync(&mut self) {
        self.vsync_enabled = false;
    }

    /// Check if VSync interrupts are enabled
    pub fn vsync_enabled(&self) -> bool {
        self.vsync_enabled
    }

    /// Get current scanline position (0 to v_total-1)
    pub fn current_line(&self) -> u32 {
        self.current_line
    }

    /// Wait for VSync (vertical blank)
    /// Safety: Should only be called with proper interrupt setup
    pub fn wait_vsync(&self) {
        // In real implementation, this would wait for VSync interrupt
        // For now, just busy-wait
        let mut count = 0;
        while count < 10000 {
            count += 1;
        }
    }

    /// Get total scanlines per frame
    pub fn total_lines(&self) -> u32 {
        self.timing.map(|t| t.v_total()).unwrap_or(0)
    }

    /// Get horizontal scanline duration in pixels
    pub fn total_pixels(&self) -> u32 {
        self.timing.map(|t| t.h_total()).unwrap_or(0)
    }

    /// Update scanline counter (called periodically by interrupt handler)
    pub fn update_scanline(&mut self) {
        if self.enabled {
            self.current_line = (self.current_line + 1) % self.total_lines();
        }
    }

    /// Check if we're in vertical blank period
    pub fn in_vblank(&self) -> bool {
        if let Some(timing) = self.timing {
            self.current_line >= timing.v_active
        } else {
            false
        }
    }

    /// Check if we're in horizontal blank period
    pub fn in_hblank(&self) -> bool {
        if let Some(timing) = self.timing {
            // This is per-scanline, would need pixel counter too
            // For now, simplified check
            self.current_line < timing.v_active
        } else {
            false
        }
    }
}

impl Default for CrtcController {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for CrtcController {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CrtcController")
            .field("enabled", &self.enabled)
            .field("vsync_enabled", &self.vsync_enabled)
            .field("current_line", &self.current_line)
            .field("pixel_clock", &self.pixel_clock)
            .field("has_timing", &self.timing.is_some())
            .field("has_primary_plane", &self.primary_plane.is_some())
            .finish()
    }
}

/// Standard display modes (VESA resolutions)
pub mod modes {
    use super::DisplayTiming;

    /// 640x480 @ 60Hz (VGA)
    pub const VGA_640X480_60HZ: DisplayTiming = DisplayTiming {
        h_active: 640,
        h_front_porch: 16,
        h_sync: 96,
        h_back_porch: 48,
        v_active: 480,
        v_front_porch: 10,
        v_sync: 2,
        v_back_porch: 33,
        pixel_clock: 25_175_000,
        refresh_rate: 60,
    };

    /// 800x600 @ 60Hz (SVGA)
    pub const SVGA_800X600_60HZ: DisplayTiming = DisplayTiming {
        h_active: 800,
        h_front_porch: 40,
        h_sync: 128,
        h_back_porch: 88,
        v_active: 600,
        v_front_porch: 1,
        v_sync: 4,
        v_back_porch: 23,
        pixel_clock: 40_000_000,
        refresh_rate: 60,
    };

    /// 1024x768 @ 60Hz (XGA)
    pub const XGA_1024X768_60HZ: DisplayTiming = DisplayTiming {
        h_active: 1024,
        h_front_porch: 24,
        h_sync: 136,
        h_back_porch: 160,
        v_active: 768,
        v_front_porch: 3,
        v_sync: 6,
        v_back_porch: 29,
        pixel_clock: 65_000_000,
        refresh_rate: 60,
    };

    /// 1280x1024 @ 60Hz (SXGA)
    pub const SXGA_1280X1024_60HZ: DisplayTiming = DisplayTiming {
        h_active: 1280,
        h_front_porch: 48,
        h_sync: 112,
        h_back_porch: 248,
        v_active: 1024,
        v_front_porch: 1,
        v_sync: 3,
        v_back_porch: 38,
        pixel_clock: 108_000_000,
        refresh_rate: 60,
    };

    /// 1920x1080 @ 60Hz (Full HD)
    pub const HD_1920X1080_60HZ: DisplayTiming = DisplayTiming {
        h_active: 1920,
        h_front_porch: 88,
        h_sync: 44,
        h_back_porch: 148,
        v_active: 1080,
        v_front_porch: 4,
        v_sync: 5,
        v_back_porch: 36,
        pixel_clock: 148_500_000,
        refresh_rate: 60,
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_display_timing() {
        let timing = modes::VGA_640X480_60HZ;
        assert_eq!(timing.h_total(), 640 + 16 + 96 + 48);
        assert_eq!(timing.v_total(), 480 + 10 + 2 + 33);
    }

    #[test]
    fn test_plane_creation() {
        let plane = Plane::new(PlaneType::Primary, 0x10000000, 1920, 1080);
        assert_eq!(plane.width, 1920);
        assert_eq!(plane.height, 1080);
        assert!(plane.composition.visible);
    }

    #[test]
    fn test_crtc_controller() {
        let mut crtc = CrtcController::new();
        assert!(!crtc.is_enabled());

        let timing = modes::VGA_640X480_60HZ;
        crtc.set_timing(timing);
        assert!(crtc.timing().is_some());

        let plane = Plane::new(PlaneType::Primary, 0x10000000, 640, 480);
        crtc.set_primary_plane(plane);
        assert!(crtc.primary_plane().is_some());

        assert!(crtc.enable().is_ok());
        assert!(crtc.is_enabled());

        crtc.disable();
        assert!(!crtc.is_enabled());
    }

    #[test]
    fn test_overlay_planes() {
        let mut crtc = CrtcController::new();

        let plane0 = Plane::new(PlaneType::Overlay, 0x20000000, 320, 240);
        assert!(crtc.set_overlay_plane(0, plane0).is_ok());
        assert!(crtc.overlay_plane(0).is_some());

        let plane1 = Plane::new(PlaneType::Overlay, 0x30000000, 160, 120);
        assert!(crtc.set_overlay_plane(1, plane1).is_ok());

        assert!(crtc.set_overlay_plane(5, plane0).is_err());
    }

    #[test]
    fn test_vblank_tracking() {
        let mut crtc = CrtcController::new();
        crtc.set_timing(modes::VGA_640X480_60HZ);
        crtc.enable().ok();

        // Start in active area
        assert!(!crtc.in_vblank());

        // Simulate scanline progression
        for _ in 0..480 {
            crtc.update_scanline();
        }

        // Now in blanking
        assert!(crtc.in_vblank());
    }
}
