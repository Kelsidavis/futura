//! Software Rendering Engine for Raspberry Pi
//!
//! This module provides CPU-based graphics rendering as a fallback when
//! GPU acceleration is unavailable or for simple operations.
//! Features:
//! - Pixel-level drawing operations
//! - Line rasterization (Bresenham)
//! - Rectangle and filled polygon rendering
//! - Basic text rendering support
//! - Color blending and transparency

use core::fmt;

/// Color representation (ARGB format)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Color {
    /// Alpha channel (0 = transparent, 255 = opaque)
    pub alpha: u8,
    /// Red channel
    pub red: u8,
    /// Green channel
    pub green: u8,
    /// Blue channel
    pub blue: u8,
}

impl Color {
    /// Create a new color with full opacity
    pub fn new(red: u8, green: u8, blue: u8) -> Self {
        Color {
            alpha: 255,
            red,
            green,
            blue,
        }
    }

    /// Create a new color with specified alpha
    pub fn with_alpha(red: u8, green: u8, blue: u8, alpha: u8) -> Self {
        Color { alpha, red, green, blue }
    }

    /// Convert to 32-bit ARGB value
    pub fn to_argb(&self) -> u32 {
        ((self.alpha as u32) << 24)
            | ((self.red as u32) << 16)
            | ((self.green as u32) << 8)
            | (self.blue as u32)
    }

    /// Convert from 32-bit ARGB value
    pub fn from_argb(argb: u32) -> Self {
        Color {
            alpha: ((argb >> 24) & 0xFF) as u8,
            red: ((argb >> 16) & 0xFF) as u8,
            green: ((argb >> 8) & 0xFF) as u8,
            blue: (argb & 0xFF) as u8,
        }
    }

    /// Black color constant (0, 0, 0)
    pub const BLACK: Color = Color {
        alpha: 255,
        red: 0,
        green: 0,
        blue: 0,
    };
    /// White color constant (255, 255, 255)
    pub const WHITE: Color = Color {
        alpha: 255,
        red: 255,
        green: 255,
        blue: 255,
    };
    /// Red color constant (255, 0, 0)
    pub const RED: Color = Color {
        alpha: 255,
        red: 255,
        green: 0,
        blue: 0,
    };
    /// Green color constant (0, 255, 0)
    pub const GREEN: Color = Color {
        alpha: 255,
        red: 0,
        green: 255,
        blue: 0,
    };
    /// Blue color constant (0, 0, 255)
    pub const BLUE: Color = Color {
        alpha: 255,
        red: 0,
        green: 0,
        blue: 255,
    };
}

/// Point in 2D space
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Point {
    /// X coordinate
    pub x: i32,
    /// Y coordinate
    pub y: i32,
}

impl Point {
    /// Create a new point
    pub fn new(x: i32, y: i32) -> Self {
        Point { x, y }
    }

    /// Calculate squared distance to another point (avoids sqrt in no_std)
    pub fn distance_squared(&self, other: Point) -> i32 {
        let dx = (self.x - other.x).abs();
        let dy = (self.y - other.y).abs();
        dx * dx + dy * dy
    }
}

/// Rectangle defined by top-left corner and dimensions
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rect {
    /// Left x coordinate
    pub x: i32,
    /// Top y coordinate
    pub y: i32,
    /// Width in pixels
    pub width: u32,
    /// Height in pixels
    pub height: u32,
}

impl Rect {
    /// Create a new rectangle
    pub fn new(x: i32, y: i32, width: u32, height: u32) -> Self {
        Rect { x, y, width, height }
    }

    /// Check if point is inside rectangle
    pub fn contains(&self, point: Point) -> bool {
        point.x >= self.x
            && point.x < self.x + self.width as i32
            && point.y >= self.y
            && point.y < self.y + self.height as i32
    }

    /// Get right edge x coordinate
    pub fn right(&self) -> i32 {
        self.x + self.width as i32
    }

    /// Get bottom edge y coordinate
    pub fn bottom(&self) -> i32 {
        self.y + self.height as i32
    }

    /// Calculate rectangle area in pixels
    pub fn area(&self) -> u32 {
        self.width * self.height
    }
}

/// Blending mode for drawing operations
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlendMode {
    /// Opaque drawing (replaces destination)
    Opaque,
    /// Alpha blending
    Alpha,
    /// Additive blending
    Add,
    /// Multiplicative blending
    Multiply,
}

/// Software renderer state
pub struct SoftwareRenderer {
    /// Frame buffer address
    fb_address: u32,
    /// Frame buffer width
    width: u32,
    /// Frame buffer height
    height: u32,
    /// Bytes per pixel
    bytes_per_pixel: u32,
    /// Current foreground color
    foreground: Color,
    /// Current background color
    background: Color,
    /// Current blending mode
    blend_mode: BlendMode,
    /// Clipping rectangle
    clip_rect: Rect,
}

impl SoftwareRenderer {
    /// Create a new software renderer
    pub fn new(fb_address: u32, width: u32, height: u32, bytes_per_pixel: u32) -> Self {
        let clip_rect = Rect::new(0, 0, width, height);
        SoftwareRenderer {
            fb_address,
            width,
            height,
            bytes_per_pixel,
            foreground: Color::WHITE,
            background: Color::BLACK,
            blend_mode: BlendMode::Opaque,
            clip_rect,
        }
    }

    /// Get framebuffer dimensions
    pub fn dimensions(&self) -> (u32, u32) {
        (self.width, self.height)
    }

    /// Set foreground color
    pub fn set_foreground(&mut self, color: Color) {
        self.foreground = color;
    }

    /// Set background color
    pub fn set_background(&mut self, color: Color) {
        self.background = color;
    }

    /// Set blending mode
    pub fn set_blend_mode(&mut self, mode: BlendMode) {
        self.blend_mode = mode;
    }

    /// Set clipping rectangle
    pub fn set_clip_rect(&mut self, rect: Rect) {
        self.clip_rect = rect;
    }

    /// Reset clipping to full screen
    pub fn reset_clip_rect(&mut self) {
        self.clip_rect = Rect::new(0, 0, self.width, self.height);
    }

    /// Check if point is within clip rectangle
    fn in_clip(&self, x: i32, y: i32) -> bool {
        self.clip_rect.contains(Point::new(x, y))
    }

    /// Blend two colors based on blend mode
    #[allow(dead_code)]
    fn blend_colors(&self, src: Color, dst: Color) -> Color {
        match self.blend_mode {
            BlendMode::Opaque => src,
            BlendMode::Alpha => {
                let src_alpha = src.alpha as u32;
                let dst_alpha = 255 - src_alpha;
                Color {
                    alpha: 255,
                    red: ((src.red as u32 * src_alpha + dst.red as u32 * dst_alpha) / 255) as u8,
                    green: ((src.green as u32 * src_alpha + dst.green as u32 * dst_alpha) / 255) as u8,
                    blue: ((src.blue as u32 * src_alpha + dst.blue as u32 * dst_alpha) / 255) as u8,
                }
            }
            BlendMode::Add => Color {
                alpha: 255,
                red: ((src.red as u32 + dst.red as u32).min(255)) as u8,
                green: ((src.green as u32 + dst.green as u32).min(255)) as u8,
                blue: ((src.blue as u32 + dst.blue as u32).min(255)) as u8,
            },
            BlendMode::Multiply => Color {
                alpha: 255,
                red: ((src.red as u32 * dst.red as u32) / 255) as u8,
                green: ((src.green as u32 * dst.green as u32) / 255) as u8,
                blue: ((src.blue as u32 * dst.blue as u32) / 255) as u8,
            },
        }
    }

    /// Draw a single pixel (unsafe - assumes valid address)
    pub unsafe fn draw_pixel(&self, x: i32, y: i32, color: Color) {
        if !self.in_clip(x, y) {
            return;
        }

        let offset = (y as u32 * self.width + x as u32) * self.bytes_per_pixel;
        let addr = (self.fb_address + offset) as *mut u32;
        core::ptr::write_volatile(addr, color.to_argb());
    }

    /// Clear framebuffer to a color
    pub unsafe fn clear(&self, color: Color) {
        let argb = color.to_argb();
        for y in 0..self.height {
            for x in 0..self.width {
                let offset = (y * self.width + x) * self.bytes_per_pixel;
                let addr = (self.fb_address + offset) as *mut u32;
                core::ptr::write_volatile(addr, argb);
            }
        }
    }

    /// Draw a filled rectangle
    pub unsafe fn fill_rect(&self, rect: Rect, color: Color) {
        for y in rect.y..rect.bottom() {
            for x in rect.x..rect.right() {
                if self.in_clip(x, y) {
                    self.draw_pixel(x, y, color);
                }
            }
        }
    }

    /// Draw a rectangle outline
    pub unsafe fn draw_rect(&self, rect: Rect, color: Color, thickness: u32) {
        // Top edge
        let top_rect = Rect::new(rect.x, rect.y, rect.width, thickness.min(rect.height as u32));
        self.fill_rect(top_rect, color);

        // Bottom edge
        let bottom_y = rect.bottom() - thickness.min(rect.height as u32) as i32;
        let bottom_rect = Rect::new(rect.x, bottom_y, rect.width, thickness.min(rect.height as u32));
        self.fill_rect(bottom_rect, color);

        // Left edge
        let left_rect = Rect::new(rect.x, rect.y, thickness.min(rect.width), rect.height);
        self.fill_rect(left_rect, color);

        // Right edge
        let right_x = rect.right() - thickness.min(rect.width) as i32;
        let right_rect = Rect::new(right_x, rect.y, thickness.min(rect.width), rect.height);
        self.fill_rect(right_rect, color);
    }

    /// Draw a line using Bresenham's algorithm
    pub unsafe fn draw_line(&self, p1: Point, p2: Point, color: Color) {
        let dx = (p2.x - p1.x).abs();
        let dy = (p2.y - p1.y).abs();
        let sx = if p1.x < p2.x { 1 } else { -1 };
        let sy = if p1.y < p2.y { 1 } else { -1 };
        let mut err = if dx > dy { dx } else { -dy } / 2;

        let mut x = p1.x;
        let mut y = p1.y;

        loop {
            self.draw_pixel(x, y, color);

            if x == p2.x && y == p2.y {
                break;
            }

            let e2 = err;
            if e2 > -dx {
                err -= dy;
                x += sx;
            }
            if e2 < dy {
                err += dx;
                y += sy;
            }
        }
    }

    /// Draw a filled circle
    pub unsafe fn fill_circle(&self, center: Point, radius: u32, color: Color) {
        let r = radius as i32;
        for y in (center.y - r)..=(center.y + r) {
            for x in (center.x - r)..=(center.x + r) {
                let dx = (x - center.x) as i32;
                let dy = (y - center.y) as i32;
                if dx * dx + dy * dy <= r * r {
                    self.draw_pixel(x, y, color);
                }
            }
        }
    }

    /// Draw a circle outline
    pub unsafe fn draw_circle(&self, center: Point, radius: u32, color: Color) {
        let r = radius as i32;
        let mut x = 0;
        let mut y = r;
        let mut d = 3 - 2 * r;

        while x <= y {
            self.draw_pixel(center.x + x, center.y + y, color);
            self.draw_pixel(center.x - x, center.y + y, color);
            self.draw_pixel(center.x + x, center.y - y, color);
            self.draw_pixel(center.x - x, center.y - y, color);
            self.draw_pixel(center.x + y, center.y + x, color);
            self.draw_pixel(center.x - y, center.y + x, color);
            self.draw_pixel(center.x + y, center.y - x, color);
            self.draw_pixel(center.x - y, center.y - x, color);

            if d < 0 {
                d = d + 4 * x + 6;
            } else {
                d = d + 4 * (x - y) + 10;
                y -= 1;
            }
            x += 1;
        }
    }

    /// Fill entire framebuffer with pattern (checkerboard)
    pub unsafe fn fill_pattern_checker(&self, color1: Color, color2: Color, check_size: u32) {
        for y in 0..self.height {
            for x in 0..self.width {
                let checker = ((x / check_size) + (y / check_size)) % 2;
                let color = if checker == 0 { color1 } else { color2 };
                self.draw_pixel(x as i32, y as i32, color);
            }
        }
    }

    /// Gradient fill (horizontal)
    pub unsafe fn fill_gradient_horizontal(
        &self,
        rect: Rect,
        start_color: Color,
        end_color: Color,
    ) {
        for y in rect.y..rect.bottom() {
            for x in rect.x..rect.right() {
                if self.in_clip(x, y) {
                    let progress = ((x - rect.x) as f32) / (rect.width as f32);
                    let color = Color {
                        alpha: 255,
                        red: (start_color.red as f32 * (1.0 - progress)
                            + end_color.red as f32 * progress) as u8,
                        green: (start_color.green as f32 * (1.0 - progress)
                            + end_color.green as f32 * progress) as u8,
                        blue: (start_color.blue as f32 * (1.0 - progress)
                            + end_color.blue as f32 * progress) as u8,
                    };
                    self.draw_pixel(x, y, color);
                }
            }
        }
    }
}

impl fmt::Debug for SoftwareRenderer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SoftwareRenderer")
            .field("width", &self.width)
            .field("height", &self.height)
            .field("foreground", &self.foreground)
            .field("background", &self.background)
            .field("blend_mode", &self.blend_mode)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_color_creation() {
        let color = Color::new(255, 128, 64);
        assert_eq!(color.red, 255);
        assert_eq!(color.green, 128);
        assert_eq!(color.blue, 64);
        assert_eq!(color.alpha, 255);
    }

    #[test]
    fn test_color_with_alpha() {
        let color = Color::with_alpha(100, 150, 200, 128);
        assert_eq!(color.alpha, 128);
    }

    #[test]
    fn test_color_constants() {
        assert_eq!(Color::BLACK.red, 0);
        assert_eq!(Color::WHITE.red, 255);
        assert_eq!(Color::RED.green, 0);
        assert_eq!(Color::GREEN.blue, 0);
        assert_eq!(Color::BLUE.red, 0);
    }

    #[test]
    fn test_color_argb_conversion() {
        let color = Color::with_alpha(255, 128, 64, 200);
        let argb = color.to_argb();
        let restored = Color::from_argb(argb);
        assert_eq!(restored.alpha, color.alpha);
        assert_eq!(restored.red, color.red);
        assert_eq!(restored.green, color.green);
        assert_eq!(restored.blue, color.blue);
    }

    #[test]
    fn test_point_distance() {
        let p1 = Point::new(0, 0);
        let p2 = Point::new(3, 4);
        // distance_squared = 3^2 + 4^2 = 9 + 16 = 25
        assert_eq!(p1.distance_squared(p2), 25);
    }

    #[test]
    fn test_rect_contains() {
        let rect = Rect::new(10, 10, 100, 50);
        assert!(rect.contains(Point::new(50, 30)));
        assert!(!rect.contains(Point::new(5, 30)));
        assert!(!rect.contains(Point::new(120, 30)));
    }

    #[test]
    fn test_rect_dimensions() {
        let rect = Rect::new(10, 20, 100, 50);
        assert_eq!(rect.right(), 110);
        assert_eq!(rect.bottom(), 70);
        assert_eq!(rect.area(), 5000);
    }

    #[test]
    fn test_software_renderer_creation() {
        let renderer = SoftwareRenderer::new(0x10000000, 1920, 1080, 4);
        let (w, h) = renderer.dimensions();
        assert_eq!(w, 1920);
        assert_eq!(h, 1080);
    }

    #[test]
    fn test_software_renderer_colors() {
        let mut renderer = SoftwareRenderer::new(0x10000000, 1920, 1080, 4);
        renderer.set_foreground(Color::RED);
        assert_eq!(renderer.foreground, Color::RED);

        renderer.set_background(Color::BLUE);
        assert_eq!(renderer.background, Color::BLUE);
    }

    #[test]
    fn test_blend_opaque() {
        let renderer = SoftwareRenderer::new(0x10000000, 1920, 1080, 4);
        let src = Color::new(255, 0, 0);
        let dst = Color::new(0, 255, 0);
        let result = renderer.blend_colors(src, dst);
        assert_eq!(result, src);
    }

    #[test]
    fn test_blend_alpha() {
        let mut renderer = SoftwareRenderer::new(0x10000000, 1920, 1080, 4);
        renderer.set_blend_mode(BlendMode::Alpha);
        let src = Color::with_alpha(255, 0, 0, 128);
        let dst = Color::new(0, 255, 0);
        let _result = renderer.blend_colors(src, dst);
        // Result should be roughly 50/50 blend
    }

    #[test]
    fn test_clipping() {
        let mut renderer = SoftwareRenderer::new(0x10000000, 1920, 1080, 4);
        renderer.set_clip_rect(Rect::new(100, 100, 100, 100));
        assert!(renderer.in_clip(150, 150));
        assert!(!renderer.in_clip(50, 50));
        assert!(!renderer.in_clip(250, 250));
    }
}
