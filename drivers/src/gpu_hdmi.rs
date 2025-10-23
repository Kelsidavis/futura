//! HDMI Output Driver for Raspberry Pi
//!
//! This module implements HDMI output support including:
//! - EDID (Extended Display Identification Data) parsing
//! - Display mode detection and enumeration
//! - Colorspace configuration
//! - Hot-plug detection support
//!
//! EDID is a standardized data structure that displays use to describe
//! their capabilities to the graphics subsystem.

use core::fmt;

/// EDID header magic bytes
const EDID_HEADER: [u8; 8] = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00];

/// EDID minimum size
const EDID_MIN_SIZE: usize = 128;

/// HDMI/DVI output modes
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputMode {
    /// DVI-D (digital video only)
    DviD,
    /// DVI-A (analog video only)
    DviA,
    /// DVI-I (integrated digital + analog)
    DviI,
    /// HDMI (with audio support)
    Hdmi,
}

/// Colorspace formats
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ColorSpace {
    /// RGB 4:4:4 (full bandwidth)
    Rgb444,
    /// YCbCr 4:4:4 (full chroma)
    YCbCr444,
    /// YCbCr 4:2:2 (reduced chroma bandwidth)
    YCbCr422,
}

/// Color depth (bits per color)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ColorDepth {
    /// 8 bits per color (24 bits total for RGB)
    Bpc8,
    /// 10 bits per color (30 bits total)
    Bpc10,
    /// 12 bits per color (36 bits total)
    Bpc12,
    /// 16 bits per color (48 bits total)
    Bpc16,
}

impl ColorDepth {
    /// Get bits per color for this depth
    pub fn bits(&self) -> u32 {
        match self {
            ColorDepth::Bpc8 => 8,
            ColorDepth::Bpc10 => 10,
            ColorDepth::Bpc12 => 12,
            ColorDepth::Bpc16 => 16,
        }
    }

    /// Get total bits per pixel for RGB
    pub fn total_bits_rgb(&self) -> u32 {
        self.bits() * 3
    }
}

impl fmt::Display for DisplayMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}x{}@{}Hz",
            self.width, self.height, self.refresh_rate
        )
    }
}

/// EDID basic display parameters
#[derive(Clone, Copy, Debug)]
pub struct EdidDisplayParams {
    /// Input type (analog or digital)
    pub digital_input: bool,
    /// Max horizontal image size in cm
    pub max_h_size: u32,
    /// Max vertical image size in cm
    pub max_v_size: u32,
    /// Gamma value (encode: (gamma + 100) / 100)
    pub gamma: u8,
    /// Supports DPMS power saving
    pub supports_dpms: bool,
    /// Supports RGB color space
    pub supports_rgb: bool,
    /// Supports YCbCr color space
    pub supports_ycbcr: bool,
}

/// EDID color characteristics
#[derive(Clone, Copy, Debug)]
pub struct EdidColorChars {
    /// Red point X coordinate (0.0 - 1.0, fixed-point)
    pub red_x: u16,
    /// Red point Y coordinate (0.0 - 1.0, fixed-point)
    pub red_y: u16,
    /// Green point X coordinate (0.0 - 1.0, fixed-point)
    pub green_x: u16,
    /// Green point Y coordinate (0.0 - 1.0, fixed-point)
    pub green_y: u16,
    /// Blue point X coordinate (0.0 - 1.0, fixed-point)
    pub blue_x: u16,
    /// Blue point Y coordinate (0.0 - 1.0, fixed-point)
    pub blue_y: u16,
    /// White point X coordinate (0.0 - 1.0, fixed-point)
    pub white_x: u16,
    /// White point Y coordinate (0.0 - 1.0, fixed-point)
    pub white_y: u16,
}

/// EDID information structure
#[derive(Clone, Copy, Debug)]
pub struct EdidInfo {
    /// Display parameters
    pub display: EdidDisplayParams,
    /// Color characteristics
    pub colors: EdidColorChars,
    /// Supported modes
    pub modes: [Option<DisplayMode>; 8],
    /// Number of supported modes
    pub num_modes: usize,
    /// HDMI/DVI mode
    pub output_mode: OutputMode,
    /// Native resolution
    pub native_mode: Option<DisplayMode>,
}

/// Display mode configuration
#[derive(Clone, Copy, Debug)]
pub struct DisplayMode {
    /// Display width in pixels
    pub width: u32,
    /// Display height in pixels
    pub height: u32,
    /// Refresh rate in Hz
    pub refresh_rate: u32,
    /// Pixel clock in Hz
    pub pixel_clock: u32,
    /// Interlaced or progressive
    pub interlaced: bool,
    /// Aspect ratio (4:3, 16:9, etc.)
    pub aspect_ratio: u16,
}

impl EdidInfo {
    /// Create default EDID info
    pub fn default() -> Self {
        EdidInfo {
            display: EdidDisplayParams {
                digital_input: true,
                max_h_size: 0,
                max_v_size: 0,
                gamma: 120,
                supports_dpms: true,
                supports_rgb: true,
                supports_ycbcr: true,
            },
            colors: EdidColorChars {
                red_x: 0,
                red_y: 0,
                green_x: 0,
                green_y: 0,
                blue_x: 0,
                blue_y: 0,
                white_x: 0,
                white_y: 0,
            },
            modes: [None; 8],
            num_modes: 0,
            output_mode: OutputMode::Hdmi,
            native_mode: None,
        }
    }

    /// Validate EDID checksum
    pub fn validate_checksum(data: &[u8]) -> bool {
        if data.len() < EDID_MIN_SIZE {
            return false;
        }

        // Calculate checksum of first 128 bytes
        let mut sum: u8 = 0;
        for &byte in &data[0..128] {
            sum = sum.wrapping_add(byte);
        }

        sum == 0
    }

    /// Parse EDID from raw data
    pub fn parse(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < EDID_MIN_SIZE {
            return Err("EDID data too short");
        }

        // Check header
        if &data[0..8] != &EDID_HEADER {
            return Err("Invalid EDID header");
        }

        // Validate checksum
        if !Self::validate_checksum(data) {
            return Err("EDID checksum invalid");
        }

        let mut edid = Self::default();

        // Parse basic display parameters (bytes 10-14)
        let input_type = data[10];
        edid.display.digital_input = (input_type & 0x80) != 0;

        // Parse display size (bytes 21-22)
        edid.display.max_h_size = data[21] as u32;
        edid.display.max_v_size = data[22] as u32;

        // Parse gamma (byte 23)
        if data[23] > 0 {
            edid.display.gamma = data[23];
        }

        // Parse feature flags (byte 24)
        let features = data[24];
        edid.display.supports_dpms = (features & 0x20) != 0;
        edid.display.supports_rgb = (features & 0x08) != 0;
        edid.display.supports_ycbcr = (features & 0x10) != 0;

        // Parse detailed timing descriptors (offset 54)
        // This is a simplified parser - full EDID parsing is complex
        edid.num_modes = 0;

        Ok(edid)
    }
}

/// HDMI output controller
pub struct HdmiController {
    /// Connected flag
    connected: bool,
    /// Current mode
    current_mode: Option<DisplayMode>,
    /// Colorspace
    colorspace: ColorSpace,
    /// Color depth
    color_depth: ColorDepth,
    /// EDID information
    edid: Option<EdidInfo>,
}

impl HdmiController {
    /// Create a new HDMI controller
    pub fn new() -> Self {
        HdmiController {
            connected: false,
            current_mode: None,
            colorspace: ColorSpace::Rgb444,
            color_depth: ColorDepth::Bpc8,
            edid: None,
        }
    }

    /// Detect HDMI connection (hotplug)
    pub fn detect_connection(&mut self) -> bool {
        // In real implementation, this would check GPIO/HPD pin
        // For now, return current connection state
        self.connected
    }

    /// Set connection state
    pub fn set_connected(&mut self, connected: bool) {
        self.connected = connected;
        if !connected {
            self.current_mode = None;
            self.edid = None;
        }
    }

    /// Check if HDMI is connected
    pub fn is_connected(&self) -> bool {
        self.connected
    }

    /// Load EDID from display
    pub fn load_edid(&mut self, data: &[u8]) -> Result<(), &'static str> {
        let edid = EdidInfo::parse(data)?;
        self.edid = Some(edid);
        self.connected = true;
        Ok(())
    }

    /// Get EDID information
    pub fn edid(&self) -> Option<&EdidInfo> {
        self.edid.as_ref()
    }

    /// Get supported modes from EDID
    pub fn get_modes(&self) -> &[Option<DisplayMode>; 8] {
        if let Some(ref edid) = self.edid {
            &edid.modes
        } else {
            &[None; 8]
        }
    }

    /// Set display mode
    pub fn set_mode(&mut self, mode: DisplayMode) -> Result<(), &'static str> {
        if !self.connected {
            return Err("HDMI not connected");
        }

        self.current_mode = Some(mode);
        Ok(())
    }

    /// Get current display mode
    pub fn current_mode(&self) -> Option<DisplayMode> {
        self.current_mode
    }

    /// Set colorspace
    pub fn set_colorspace(&mut self, colorspace: ColorSpace) {
        self.colorspace = colorspace;
    }

    /// Get colorspace
    pub fn colorspace(&self) -> ColorSpace {
        self.colorspace
    }

    /// Set color depth
    pub fn set_color_depth(&mut self, depth: ColorDepth) {
        self.color_depth = depth;
    }

    /// Get color depth
    pub fn color_depth(&self) -> ColorDepth {
        self.color_depth
    }

    /// Calculate required bandwidth for current configuration (Mbps)
    pub fn required_bandwidth(&self) -> u32 {
        if let Some(mode) = self.current_mode {
            let bits_per_pixel = match self.colorspace {
                ColorSpace::Rgb444 => self.color_depth.total_bits_rgb(),
                ColorSpace::YCbCr444 => self.color_depth.total_bits_rgb(),
                ColorSpace::YCbCr422 => (self.color_depth.bits() * 2) + self.color_depth.bits(),
            };

            // Bandwidth = pixel_clock * bits_per_pixel
            (mode.pixel_clock / 1_000_000) * bits_per_pixel / 1000
        } else {
            0
        }
    }
}

impl Default for HdmiController {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for HdmiController {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HdmiController")
            .field("connected", &self.connected)
            .field("current_mode", &self.current_mode)
            .field("colorspace", &self.colorspace)
            .field("color_depth", &self.color_depth)
            .field("has_edid", &self.edid.is_some())
            .finish()
    }
}

/// Standard HDMI modes
pub mod modes {
    use super::DisplayMode;

    /// 640x480 @ 60Hz (VGA)
    pub const VGA_640X480: DisplayMode = DisplayMode {
        width: 640,
        height: 480,
        refresh_rate: 60,
        pixel_clock: 25_175_000,
        interlaced: false,
        aspect_ratio: 4 * 100 / 3, // 4:3 ratio as fixed-point
    };

    /// 800x600 @ 60Hz (SVGA)
    pub const SVGA_800X600: DisplayMode = DisplayMode {
        width: 800,
        height: 600,
        refresh_rate: 60,
        pixel_clock: 40_000_000,
        interlaced: false,
        aspect_ratio: 4 * 100 / 3,
    };

    /// 1024x768 @ 60Hz (XGA)
    pub const XGA_1024X768: DisplayMode = DisplayMode {
        width: 1024,
        height: 768,
        refresh_rate: 60,
        pixel_clock: 65_000_000,
        interlaced: false,
        aspect_ratio: 4 * 100 / 3,
    };

    /// 1280x720 @ 60Hz (HD 720p)
    pub const HD_1280X720: DisplayMode = DisplayMode {
        width: 1280,
        height: 720,
        refresh_rate: 60,
        pixel_clock: 74_250_000,
        interlaced: false,
        aspect_ratio: 16 * 100 / 9, // 16:9 ratio
    };

    /// 1920x1080 @ 60Hz (Full HD 1080p)
    pub const FHD_1920X1080: DisplayMode = DisplayMode {
        width: 1920,
        height: 1080,
        refresh_rate: 60,
        pixel_clock: 148_500_000,
        interlaced: false,
        aspect_ratio: 16 * 100 / 9,
    };

    /// 2560x1440 @ 60Hz (2K/QHD)
    pub const QHD_2560X1440: DisplayMode = DisplayMode {
        width: 2560,
        height: 1440,
        refresh_rate: 60,
        pixel_clock: 241_500_000,
        interlaced: false,
        aspect_ratio: 16 * 100 / 9,
    };

    /// 3840x2160 @ 60Hz (4K UHD)
    pub const UHD_3840X2160: DisplayMode = DisplayMode {
        width: 3840,
        height: 2160,
        refresh_rate: 60,
        pixel_clock: 594_000_000,
        interlaced: false,
        aspect_ratio: 16 * 100 / 9,
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_color_depth() {
        assert_eq!(ColorDepth::Bpc8.bits(), 8);
        assert_eq!(ColorDepth::Bpc10.bits(), 10);
        assert_eq!(ColorDepth::Bpc12.bits(), 12);
        assert_eq!(ColorDepth::Bpc16.bits(), 16);

        assert_eq!(ColorDepth::Bpc8.total_bits_rgb(), 24);
        assert_eq!(ColorDepth::Bpc10.total_bits_rgb(), 30);
    }

    #[test]
    fn test_display_mode_display() {
        let mode = modes::FHD_1920X1080;
        assert_eq!(mode.width, 1920);
        assert_eq!(mode.height, 1080);
        assert_eq!(mode.refresh_rate, 60);
    }

    #[test]
    fn test_hdmi_controller() {
        let mut hdmi = HdmiController::new();
        assert!(!hdmi.is_connected());

        hdmi.set_connected(true);
        assert!(hdmi.is_connected());

        let mode = modes::FHD_1920X1080;
        assert!(hdmi.set_mode(mode).is_ok());
        assert_eq!(hdmi.current_mode(), Some(mode));
    }

    #[test]
    fn test_colorspace_config() {
        let mut hdmi = HdmiController::new();
        hdmi.set_colorspace(ColorSpace::YCbCr422);
        assert_eq!(hdmi.colorspace(), ColorSpace::YCbCr422);

        hdmi.set_color_depth(ColorDepth::Bpc10);
        assert_eq!(hdmi.color_depth(), ColorDepth::Bpc10);
    }

    #[test]
    fn test_bandwidth_calculation() {
        let mut hdmi = HdmiController::new();
        hdmi.set_connected(true);
        hdmi.set_mode(modes::FHD_1920X1080).ok();
        hdmi.set_color_depth(ColorDepth::Bpc8);

        let bandwidth = hdmi.required_bandwidth();
        assert!(bandwidth > 0);
    }

    #[test]
    fn test_edid_header_validation() {
        let mut data = [0u8; 128];
        data[0..8].copy_from_slice(&EDID_HEADER);

        // Set checksum to make it valid
        let mut sum = 0u8;
        for &byte in &data[0..127] {
            sum = sum.wrapping_add(byte);
        }
        data[127] = (256 - (sum as u16)) as u8;

        assert!(EdidInfo::validate_checksum(&data));
    }
}
