# Raspberry Pi GPU Driver Implementation (Design Doc)

> **Status (Jan 22 2026)**: Design/roadmap only. The Raspberry Pi GPU stack is **not integrated** into the kernel. Code under `drivers/src/` is scaffolding and does not yet drive hardware.

This document describes the intended VideoCore GPU driver architecture for Futura OS on Raspberry Pi platforms.

## Overview

The Raspberry Pi platforms use a VideoCore GPU that handles:
- Display output (HDMI, DPI, DSI, composite video)
- 3D graphics acceleration (V3D core on RPi4/5)
- Video encoding/decoding
- General-purpose compute

The long-term goal is to port the Linux `vc4` DRM driver to Futura OS.

## Architecture

### Layered Design

```
┌─────────────────────────────────────────┐
│  Application Layer (Wayland, OpenGL)    │
├─────────────────────────────────────────┤
│  DRM/KMS Abstraction Layer              │  gpu_vc4.h
│  (Display, Framebuffer, Planes)         │
├─────────────────────────────────────────┤
│  GPU Driver Core                        │  gpu_driver.c
│  (Memory, V3D, HVS, HDMI)               │
├─────────────────────────────────────────┤
│  Mailbox Protocol Driver                │  mailbox.rs
│  (GPU Firmware Communication)           │
├─────────────────────────────────────────┤
│  Hardware Registers (MMIO)              │
│  (V3D, HVS, HDMI, GIC, Mailbox)        │
└─────────────────────────────────────────┘
```

### Component Breakdown

#### 1. Mailbox Protocol Layer (`drivers/src/mailbox.rs`)

The mailbox is the primary communication mechanism between ARM CPU and VideoCore GPU:

- **Channels**: Multiple logical channels for different functions
  - Channel 0: Power management
  - Channel 1: Framebuffer interface
  - Channel 8: Property tags (primary control interface)

- **Message Format**:
  ```
  [4 bytes: total size]
  [4 bytes: request/response code]
  [... tags ...]
  [4 bytes: 0 (end marker)]
  ```

- **Key Operations**:
  - `mailbox_property_call()` - Send property tag buffer and wait for response
  - `mailbox_get_arm_memory()` - Query ARM memory layout
  - `mailbox_get_vc_memory()` - Query VideoCore memory layout
  - `mailbox_get_clock_rate()` - Read clock frequencies
  - `mailbox_set_clock_rate()` - Modify clock frequencies
  - `mailbox_get_temperature()` - Read GPU temperature

#### 2. GPU Driver Core (`include/drivers/gpu_vc4.h`)

High-level abstraction for GPU operations:

- **Memory Management**:
  - GPU memory pool allocation via mailbox
  - CMA (Contiguous Memory Allocator) support
  - Memory locking/unlocking for DMA stability

- **Display Pipeline**:
  - Framebuffer allocation and configuration
  - CRTC (display controller) support
  - Plane composition (hardware cursor, video overlays)

- **V3D 3D Graphics** (RPi4/5):
  - Command buffer submission
  - Texture management
  - Shader compilation (validation)
  - Performance monitoring

- **HDMI Output**:
  - EDID reading (display capabilities)
  - Mode detection and enumeration
  - Hot-plug detection
  - Colorspace configuration

#### 3. HVS (Hardware Video Scaler)

The HVS handles:
- Multi-channel display mixing
- Scaling and color conversion
- Display timing and synchronization
- Hardware cursor composition

## Platform-Specific Details

### Raspberry Pi 3 (VC4)

- **GPU**: VideoCore IV
- **Memory**: Typically 512MB-1GB GPU RAM
- **Display**: HDMI + composite video
- **3D Support**: Limited (no V3D core)
- **Approach**: Framebuffer-only, no hardware 3D acceleration

### Raspberry Pi 4 (VC6)

- **GPU**: VideoCore VI (enhanced IV)
- **Memory**: 1-8GB GPU RAM
- **3D Support**: V3D 4.1 3D graphics core
- **Display**: HDMI (2× on 4B), DPI, DSI
- **Approach**: Full DRM/KMS support with V3D driver

### Raspberry Pi 5 (VC7)

- **GPU**: VideoCore VII
- **Memory**: 4-8GB GPU RAM
- **3D Support**: V3D 7.1 (improved performance)
- **Display**: HDMI, DSI, DPI
- **Approach**: Full DRM/KMS with enhanced V3D

## Implementation Phases

### Phase 1: Mailbox Protocol (COMPLETED)

- [x] Mailbox register abstractions
- [x] Property tag message formatting
- [x] Firmware communication
- [x] Clock and temperature queries

**Files**:
- `include/drivers/rpi_mailbox.h` (280+ lines)
- `drivers/src/mailbox.rs` (580+ lines)

### Phase 2: Basic Framebuffer (IN PROGRESS)

- [ ] Framebuffer allocation via mailbox
- [ ] Display mode configuration
- [ ] Framebuffer enable/disable
- [ ] Basic cursor support

**Files to create**:
- `drivers/src/gpu_framebuffer.rs` (~400 lines)

### Phase 3: Display Controller (PLANNED)

- [ ] CRTC (display controller) abstraction
- [ ] Plane composition
- [ ] Timing and synchronization
- [ ] Interrupt handling

**Files to create**:
- `drivers/src/gpu_crtc.rs` (~300 lines)

### Phase 4: HDMI Output Support (PLANNED)

- [ ] EDID parsing
- [ ] Mode enumeration
- [ ] Hot-plug detection
- [ ] Audio support

**Files to create**:
- `drivers/src/gpu_hdmi.rs` (~400 lines)

### Phase 5: V3D 3D Graphics (PLANNED)

- [ ] V3D command submission
- [ ] Texture management
- [ ] Shader validation
- [ ] Job execution

**Files to create**:
- `drivers/src/gpu_v3d.rs` (~600 lines)

## Memory Layout

### VideoCore Address Space

VideoCore uses a different address space than ARM:

```
0x00000000 - 0x3FFFFFFF  Direct SDRAM access (VC-to-ARM)
0x40000000 - 0x7FFFFFFF  Uncached ARM memory (ARM-to-VC)
0x80000000 - 0xBFFFFFFF  Video RAM (if present)
0xC0000000 - 0xDFFFFFFF  L2-cached ARM memory
```

**Conversion Functions** (mailbox.rs):
- `arm_to_vc_uncached(addr)` - Add 0x40000000 for uncached access
- `arm_to_vc_cached(addr)` - Map to 0xC0000000 base for cached access
- `vc_to_arm(addr)` - Convert back to ARM physical address

### GPU Memory Allocation

Allocated via mailbox `MBOX_TAG_ALLOCATE_FRAMEBUFFER` and related tags:

```c
// Request framebuffer memory
mailbox_buffer[0] = buffer_size;
mailbox_buffer[1] = MBOX_REQUEST_CODE;
mailbox_buffer[2] = MBOX_TAG_ALLOCATE_FRAMEBUFFER;
mailbox_buffer[3] = response_size;
mailbox_buffer[4] = 0; // request size
// ... [response data] ...
mailbox_buffer[last] = MBOX_TAG_END;

// Call mailbox
mailbox_property_call(mailbox_buffer);

// Result in mailbox_buffer[response_index]
```

## Clock Configuration

### Supported Clocks

- **MBOX_CLOCK_ARM** - ARM CPU clock
- **MBOX_CLOCK_CORE** - GPU core clock
- **MBOX_CLOCK_V3D** - V3D 3D graphics clock
- **MBOX_CLOCK_EMMC** - SD card interface
- **MBOX_CLOCK_UART** - Serial console

### Rate Setting Example

```c
// Get current ARM clock rate
uint32_t current = mailbox_get_clock_rate(MBOX_CLOCK_ARM);

// Set to 1.5 GHz
uint32_t new_rate = 1500000000; // Hz
mailbox_set_clock_rate(MBOX_CLOCK_ARM, new_rate);
```

## Display Configuration

### Framebuffer Setup

1. **Allocate GPU Memory**
   ```c
   uint32_t fb_handle = gpu_mem_alloc(width * height * 4,
                                      GPU_MEM_FLAG_NORMAL,
                                      &vc_address);
   ```

2. **Lock Memory**
   ```c
   uint32_t vc_addr = gpu_mem_lock(fb_handle);
   ```

3. **Configure Display**
   ```c
   gpu_framebuffer_allocate(1920, 1080, GPU_PIXEL_FORMAT_RGBA8888);
   gpu_display_enable(1920, 1080, GPU_PIXEL_FORMAT_RGBA8888);
   ```

4. **Map to CPU**
   - Use virtual mapping or DMA for CPU access
   - Keep cache coherency in mind (GPU writes, CPU reads)

### HDMI Output

1. **Detect Connection**
   ```c
   if (gpu_hdmi_detect()) {
       uint32_t count;
       const hdmi_resolution_t *modes = gpu_hdmi_get_modes(&count);
   }
   ```

2. **Set Mode**
   ```c
   gpu_hdmi_set_mode(1920, 1080, 60); // 1920x1080 @ 60Hz
   ```

## Linux vc4 Driver Reference

The implementation is based on these key files from Linux:

- **vc4_drv.c** - Main driver initialization
- **vc4_drm.h** - DRM structures
- **vc4_bo.c** - Buffer object (memory) management
- **vc4_kms.c** - Kernel Mode Setting (display)
- **vc4_crtc.c** - Display controller
- **vc4_hdmi.c** - HDMI output
- **vc4_hvs.c** - Hardware video scaler
- **vc4_render_cl.c** - Rendering command lists
- **vc4_v3d.c** - V3D GPU integration
- **vc4_validate.c** - Command buffer validation

## Testing

### QEMU Emulation

Test on QEMU Raspberry Pi emulation (limited peripheral support):

```bash
# RPi3 emulation
qemu-system-aarch64 -M raspi3b \
  -kernel build/kernel8.elf \
  -dtb rpi3.dtb \
  -serial stdio

# RPi4 emulation
qemu-system-aarch64 -M raspi4b \
  -kernel build/kernel8.elf \
  -dtb rpi4.dtb \
  -serial stdio
```

### Real Hardware Testing

1. **Prepare SD Card**
   - Copy bootcode.bin, firmware files
   - Copy kernel8.elf (Futura kernel)
   - Create config.txt with GPU settings

2. **Serial Console**
   - Connect GPIO14/GPIO15 to USB UART adapter
   - Monitor boot messages at 115200 baud

3. **Display Connection**
   - Connect HDMI display
   - Observe framebuffer output

## Known Limitations

1. **RPi3**: No V3D 3D acceleration
2. **QEMU**: GPU emulation is minimal, test on real hardware
3. **V3D**: Requires shader validation (significant work)
4. **Audio**: HDMI audio not yet implemented
5. **Hotplug**: HDMI hot-plug detection requires interrupt support

## Future Enhancements

1. **Software Rendering**: Implement fallback CPU renderer for pixels operations
2. **V3D Scheduler**: Job submission and completion tracking
3. **Interrupt Handling**: Hot-plug detection, VSync synchronization
4. **Memory Pressure**: Kernel eviction and swapping
5. **Performance**: GPU profiling and optimization

## References

- Broadcom GPU Documentation (partially public)
- Linux vc4 driver source code
- Raspberry Pi firmware wiki
- ARM GIC interrupt controller documentation
- ARM generic timer documentation

## Building

```bash
# Build Rust drivers library
cd drivers && cargo build --release

# Build full kernel with GPU support
make PLATFORM=arm64 -j4

# Output: build/kernel8.elf (with GPU driver)
```

## Debugging

Enable mailbox logging:

```c
#define DEBUG_MAILBOX 1
```

This enables:
- Mailbox send/receive tracing
- Property tag enumeration
- Error code logging

## License

This GPU driver is licensed under the Mozilla Public License v2.0.
Derived from the Linux kernel vc4 driver (GPL v2), this implementation
is a clean-room port adapted for Futura OS.
