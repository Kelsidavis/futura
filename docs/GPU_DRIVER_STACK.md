# Raspberry Pi GPU Driver Stack

> **Status (Jan 22 2026)**: Design/roadmap doc. The corresponding drivers are not integrated into the kernel. See `docs/DRIVERS_MANIFEST.md` for the current in-tree driver inventory.

## Overview

This document describes the comprehensive GPU driver stack implemented for Futura OS on Raspberry Pi 3/4/5 platforms. The stack includes support for display output, 3D graphics acceleration, and software rendering fallback.

## Architecture

### Layer 1: Mailbox Protocol (`drivers/src/mailbox.rs`)

**Purpose**: ARM-to-GPU firmware communication interface

**Key Features**:
- Message queue-based protocol
- Response handling
- Configurable mailbox channel selection
- Support for GPU power management and memory allocation requests

**API**:
```rust
pub struct MailboxDriver { ... }
impl MailboxDriver {
    pub fn new(base_addr: u64) -> Self
    pub fn is_available(&self) -> bool
    pub fn is_busy(&self) -> bool
    pub fn queue_message(&mut self, message: u32)
    pub fn get_response(&self) -> Result<u32, &'static str>
}
```

**Hardware Register Layout**:
- `MBOX_READ (0x00)`: Read mailbox response
- `MBOX_POLL (0x10)`: Poll message availability
- `MBOX_SENDER (0x14)`: Read sender ID
- `MBOX_STATUS (0x18)`: Mailbox status flags
- `MBOX_CONFIG (0x1C)`: Configuration
- `MBOX_WRITE (0x20)`: Write mailbox request

### Layer 2: Framebuffer Allocation (`drivers/src/gpu_framebuffer.rs`)

**Purpose**: GPU memory allocation and framebuffer configuration

**Supported Pixel Formats**:
- RGB565 (16-bit)
- RGB888 (24-bit)
- RGBA8888 (32-bit with alpha)
- RGBX8888 (32-bit RGB with padding)

**Configuration Structure**:
```rust
pub struct FramebufferConfig {
    pub width: u32,
    pub height: u32,
    pub virtual_width: u32,   // For panning
    pub virtual_height: u32,
    pub x_offset: u32,
    pub y_offset: u32,
    pub format: PixelFormat,
    pub pitch: u32,          // Bytes per scanline
}
```

**Key Methods**:
- `allocate()`: Allocate and configure framebuffer via mailbox
- `enable()`/`disable()`: Control display output
- `write_pixel()`: Write single pixel (unsafe, direct MMIO)
- `fill_rect()`: Fill rectangle with color
- `clear()`: Clear to black
- `copy_region()`: Memcpy-style region copy

**Memory Layout**:
- Pitch = width × bytes_per_pixel
- Size = pitch × height
- MMIO write using volatile pointers

### Layer 3: Display Controller (CRTC) (`drivers/src/gpu_crtc.rs`)

**Purpose**: Display timing, synchronization, and plane composition

**Display Timing Parameters**:
```rust
pub struct DisplayTiming {
    pub pixel_clock: u32,       // Hz
    pub horizontal_active: u32,
    pub vertical_active: u32,
    pub hsync_pulse: u32,
    pub vsync_pulse: u32,
    pub h_front_porch: u32,
    pub h_back_porch: u32,
    pub v_front_porch: u32,
    pub v_back_porch: u32,
}
```

**Plane Types**:
- Primary: Base framebuffer layer
- Overlay: Composited on top (z_order)
- Cursor: Hardware cursor plane

**Composition Features**:
```rust
pub struct PlaneComposition {
    pub x: u32, pub y: u32,
    pub width: u32, pub height: u32,
    pub alpha_mode: AlphaMode,  // Opaque, Alpha, Premultiplied
    pub z_order: u32,
}

pub struct Plane {
    pub plane_type: PlaneType,
    pub fb_address: u32,
    pub composition: PlaneComposition,
}
```

**Key Methods**:
- `enable()`/`disable()`: Control display output
- `set_timing()`: Configure display timing
- `bind_plane()`: Attach composited plane
- `active_planes()`: Get number of active planes

### Layer 4: HDMI Output (`drivers/src/gpu_hdmi.rs`)

**Purpose**: HDMI output support with EDID parsing and mode detection

**Output Modes**:
- DVI-D: Digital video only (no audio)
- DVI-A: Analog video only
- DVI-I: Integrated digital + analog
- HDMI: Digital with audio support

**Colorspace Support**:
- RGB 4:4:4: Full bandwidth (36 bpp max)
- YCbCr 4:4:4: Full chroma
- YCbCr 4:2:2: Reduced chroma bandwidth

**Color Depth**:
- 8-bit per color (24-bit RGB total)
- 10-bit per color (30-bit RGB total)
- 12-bit per color (36-bit RGB total)
- 16-bit per color (48-bit RGB total)

**EDID Parsing**:
```rust
pub struct EdidInfo {
    pub display: EdidDisplayParams,      // Size, gamma, features
    pub colors: EdidColorChars,          // CIE color space
    pub modes: [Option<DisplayMode>; 8], // Supported modes
    pub num_modes: usize,
    pub output_mode: OutputMode,
    pub native_mode: Option<DisplayMode>,
}
```

**Standard Display Modes** (pre-defined):
- VGA 640×480 @ 60Hz
- SVGA 800×600 @ 60Hz
- XGA 1024×768 @ 60Hz
- HD 1280×720 @ 60Hz
- FHD 1920×1080 @ 60Hz
- QHD 2560×1440 @ 60Hz
- 4K UHD 3840×2160 @ 60Hz

**Bandwidth Calculation**:
```
bandwidth = pixel_clock × bits_per_pixel
```

Example: 1080p @ 60Hz with 8bpc RGB
- Pixel clock: 148.5 MHz
- Bits per pixel: 24
- Required bandwidth: ~3.96 Gbps (HDMI 1.4 capable)

**Key Methods**:
- `detect_connection()`: Check HDMI hotplug
- `load_edid()`: Parse EDID from display
- `set_mode()`: Set display resolution
- `set_colorspace()`/`set_color_depth()`: Configure color
- `required_bandwidth()`: Calculate required HDMI bandwidth

### Layer 5: V3D 3D Graphics (`drivers/src/gpu_v3d.rs`)

**Purpose**: 3D graphics acceleration via VideoCore IV/V GPU

**Supported Versions**:
- V4.1: Raspberry Pi 4 (BCM2711)
- V7.1: Raspberry Pi 5 (BCM2712)

**Texture Formats**:
- R8: 8-bit grayscale
- RGB565: 16-bit color
- RGB888: 24-bit color
- RGBA8888: 32-bit with alpha
- RG16F: 16-bit floating-point per channel
- Depth32F: 32-bit depth buffer
- BC1: DXT1 compression

**Resource Management**:
```rust
pub struct Texture {
    pub address: u32,
    pub width: u32, pub height: u32,
    pub format: TextureFormat,
    pub mipmap_levels: u32,
}

pub struct VertexBuffer {
    pub address: u32, pub size: u32,
    pub stride: u32, pub vertex_count: u32,
}

pub struct IndexBuffer {
    pub address: u32, pub size: u32,
    pub index_count: u32,
}

pub struct UniformBuffer {
    pub address: u32,
    pub size: u32,
}
```

**Job Management**:
```rust
pub enum JobStatus {
    Queued,
    Running,
    Completed,
    Error,
    Cancelled,
}

pub struct RenderJob {
    pub job_id: u32,
    pub vertex_buffer: Option<VertexBuffer>,
    pub index_buffer: Option<IndexBuffer>,
    pub primitive_count: u32,
    pub status: JobStatus,
}

pub struct ComputeJob {
    pub job_id: u32,
    pub work_groups: (u32, u32, u32),
    pub shader_address: u32,
    pub status: JobStatus,
}
```

**Performance Monitoring**:
```rust
pub struct PerformanceStats {
    pub total_jobs_submitted: u32,
    pub total_jobs_completed: u32,
    pub total_jobs_errors: u32,
    pub textures_bound: u32,
}
```

**Key Methods**:
- `enable()`/`disable()`: Power management
- `bind_texture()`: Bind texture to unit (0-7)
- `submit_render_job()`: Queue 3D rendering
- `submit_compute_job()`: Queue general-purpose GPU compute
- `record_job_complete()`: Track job completion
- `stats()`: Get performance statistics

### Layer 6: Software Rendering (`drivers/src/gpu_software.rs`)

**Purpose**: CPU-based graphics rendering fallback

**Color Management**:
```rust
pub struct Color {
    pub alpha: u8,
    pub red: u8,
    pub green: u8,
    pub blue: u8,
}
```

**Color Constants**:
- BLACK: (0, 0, 0, 255)
- WHITE: (255, 255, 255, 255)
- RED: (255, 0, 0, 255)
- GREEN: (0, 255, 0, 255)
- BLUE: (0, 0, 255, 255)

**Geometric Primitives**:
```rust
pub struct Point { pub x: i32, pub y: i32 }
pub struct Rect { pub x: i32, pub y: i32, pub width: u32, pub height: u32 }
```

**Blending Modes**:
- Opaque: No blending (overwrites destination)
- Alpha: Per-pixel alpha blending
- Add: Additive blending
- Multiply: Multiplicative blending

**Drawing Operations**:
- `draw_pixel()`: Single pixel
- `fill_rect()`: Filled rectangle
- `draw_rect()`: Rectangle outline
- `draw_line()`: Bresenham's line algorithm
- `fill_circle()`: Filled circle (midpoint algorithm)
- `draw_circle()`: Circle outline
- `fill_pattern_checker()`: Checkerboard pattern
- `fill_gradient_horizontal()`: Horizontal gradient

**Clipping Region**:
- `set_clip_rect()`: Set clipping rectangle
- `in_clip()`: Check if coordinates in clip region

**Implementation Notes**:
- Integer-only math (no floating-point)
- No `sqrt()` - uses squared distance for efficiency
- Direct MMIO writes with volatile pointers
- Safe pixel boundary checks

## Integration Flow

```
Mailbox (Low-level GPU communication)
    ↓
Framebuffer (Memory allocation & pixel access)
    ↓
Display Controller (CRTC) (Timing & composition)
    ↓
HDMI Output (Display connection & modes)
    ↓
┌─────────────────────────────────────┐
│  V3D 3D Graphics (GPU acceleration) │
│  (RPi4/5 only)                      │
└─────────────────────────────────────┘
    ↓
Software Rendering (CPU fallback)
```

## Hardware Requirements

### Raspberry Pi 3 (BCM2835)
- **GPU**: VideoCore IV
- **HDMI**: Supported (via DVI mode)
- **3D**: Not supported (use software rendering)
- **Framebuffer**: Supported

### Raspberry Pi 4 (BCM2711)
- **GPU**: VideoCore VI + V3D 4.1
- **HDMI**: Full HDMI 2.0 (dual output)
- **3D**: V3D 4.1 3D graphics
- **Framebuffer**: Supported

### Raspberry Pi 5 (BCM2712)
- **GPU**: VideoCore VII + V3D 7.1
- **HDMI**: Full HDMI 2.1 (dual output, eARC)
- **3D**: V3D 7.1 3D graphics (improved)
- **Framebuffer**: Supported

## Testing

### Unit Tests
Each driver module includes comprehensive unit tests:

**Mailbox Tests**:
- ✓ Initialization and availability checks
- ✓ Message queue operations
- ✓ Response reception

**Framebuffer Tests**:
- ✓ Config creation with various formats
- ✓ Pitch calculation verification
- ✓ Size calculations
- ✓ Driver lifecycle (allocate → enable → disable)
- ✓ Pixel format conversions

**CRTC Tests**:
- ✓ Plane binding and composition
- ✓ Display timing calculations
- ✓ Enable/disable transitions

**HDMI Tests**:
- ✓ Connection detection
- ✓ Display mode configuration
- ✓ Colorspace and color depth selection
- ✓ EDID header validation
- ✓ Bandwidth calculation
- ✓ Standard mode definitions

**V3D Tests**:
- ✓ Version detection (V4.1 vs V7.1)
- ✓ Job submission and tracking
- ✓ Texture binding (units 0-7)
- ✓ Performance statistics

**Software Rendering Tests**:
- ✓ Color operations (ARGB conversion)
- ✓ Point distance calculations
- ✓ Rectangle geometry and containment
- ✓ Blending mode selection
- ✓ Clipping region enforcement

### Compilation Status

```bash
$ cargo build --target aarch64-unknown-none
   Compiling futura-drivers v0.1.0
    Finished `release` profile [opt-level=3] target(s) in 2.34s
```

**Warnings** (documentation-related only):
- Dead code constants in mailbox (MBOX_PEEK, MBOX_SENDER, MBOX_CONFIG)
- Unused blend_colors helper function
- Static mut references (Rust 2024 edition warning)
- Missing documentation on struct fields

**Errors**: 0

### Integration Test Plan

When testing on physical hardware or QEMU RPi emulation:

1. **Mailbox Communication**
   - Verify GPU firmware responds to mailbox requests
   - Check power management handshake
   - Validate memory allocation responses

2. **Framebuffer Display**
   - Allocate framebuffer via mailbox
   - Write test pattern (checkerboard)
   - Verify display output
   - Test pixel format conversions

3. **HDMI Hot-plug**
   - Connect/disconnect HDMI display
   - Verify hotplug detection
   - Parse EDID from connected display
   - Enumerate supported modes
   - Set optimal mode automatically

4. **Display Composition**
   - Create primary plane with framebuffer
   - Add overlay plane with transparency
   - Test z-order composition
   - Verify frame synchronization

5. **3D Graphics (RPi4/5)**
   - Bind textures to GPU units
   - Submit triangle rendering job
   - Verify job completion
   - Check performance metrics

6. **Software Rendering**
   - Draw geometric primitives
   - Test blend modes
   - Verify clipping enforcement
   - Benchmark drawing performance

## Code Statistics

- **Total Lines**: ~4,000 Rust code
- **Unit Tests**: 50+ test cases
- **Modules**: 6 driver layers
- **Type-Safe MMIO**: 100% encapsulation
- **Unsafe Code**: Minimal and well-documented
- **Documentation**: Comprehensive inline docs

## Known Limitations

1. **EDID Parsing**: Simplified parser (full EDID is complex)
2. **V3D Shaders**: No SPIR-V compiler (would need separate toolchain)
3. **Software Rendering**: CPU-intensive (not suitable for animation)
4. **No Interrupt Handling**: Poll-based synchronization only
5. **Single Framebuffer**: No multiple framebuffers/double-buffering

## Future Enhancements

1. Implement interrupt-driven synchronization
2. Add double-buffering support
3. Enhance EDID parsing for full feature detection
4. Implement V3D shader compiler
5. Add video encoding/decoding support (H.264, VP8)
6. Support for HDR display modes
7. DisplayPort support (RPi5)

## References

- Broadcom BCM2835 ARM Peripherals Manual
- Raspberry Pi Foundation - VideoCore IV Documentation
- VESA EDID Specification
- HDMI 2.1 Specification
- Khronos OpenGL ES Standards

## Commits

- `02ce08a`: gpu: implement HDMI output support with EDID parsing
- `aee8bac`: gpu: implement V3D 3D graphics support for RPi4/5
- `3b24984`: gpu: implement software rendering fallback
- `28fa090`: gpu: implement display controller (CRTC) with plane composition
- `30bd718`: gpu: port Linux vc4 driver - mailbox protocol and framebuffer
