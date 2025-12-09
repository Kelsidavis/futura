# Futura OS UI & Wayland Infrastructure Report

## Executive Summary

Futura OS has a **functional Wayland compositor and client infrastructure** with basic features implemented. The system is **in early-stage development** but can boot and render windows. Key components are in place but some features remain incomplete or need optimization.

---

## 1. Wayland Compositor Implementation

### Location & Status
- **Path**: `/home/k/futura/src/user/compositor/futura-wayland/`
- **Binary**: `futura-wayland` (runs as PID 1 daemon)
- **Status**: FUNCTIONAL - boots and handles clients

### Architecture
The compositor consists of modular components:

| Component | File | Purpose | Status |
|-----------|------|---------|--------|
| **Main Loop** | `main.c`, `comp.c` | Event loop, damage tracking, rendering | ✓ Complete |
| **XDG Shell** | `xdg_shell.c`, `xdg_shell.h` | Window management (xdg-shell protocol) | ✓ Complete |
| **Output** | `output.c`, `output.h` | Display output information | ✓ Basic |
| **Seat/Input** | `seat.c`, `seat.h` | Keyboard/mouse/touch input | ✓ Partial |
| **SHM Backend** | `shm_backend.c` | Shared memory buffers (wl_shm) | ✓ Complete |
| **Data Device** | `data_device.c` | Copy/paste clipboard | ✓ Partial |
| **Rendering** | comp.c | Software composition & damage | ✓ Complete |
| **UI/Text** | `ui_text.c` | Text rendering in window bars | ✓ Basic |
| **Cursor** | `cursor.c` | Mouse cursor rendering | ✓ Basic |
| **Shadows** | `shadow.c` | Window drop shadows | ✓ Complete |

### Key Features Implemented
1. **Framebuffer Backend**
   - Direct `/dev/fb0` mapping (32-bit ARGB)
   - Double-buffering support (optional)
   - Damage tracking with region coalescing
   - Software composition (CPU-based blitting)

2. **Window Management**
   - Window creation/destruction
   - Z-order (stacking) control
   - Window decoration bars with title text
   - Window dragging (by title bar)
   - Window resizing (8-direction + diagonal)
   - Maximize/minimize buttons
   - Focus tracking

3. **Protocol Support**
   - Core Wayland protocol (wl_compositor, wl_surface, wl_buffer)
   - XDG Shell (xdg-wm-base, xdg-surface, xdg-toplevel)
   - Shared Memory (wl_shm) - uses POSIX shm, not memfd
   - Data Device (wl_data_device_manager, wl_data_source)
   - Seat (wl_seat, wl_keyboard, wl_pointer, wl_touch)

4. **Frame Scheduling**
   - Timer-based frame scheduling (16ms default = 60Hz)
   - Frame callbacks to clients
   - Throttling support (optional)

### Configuration Flags (Environment Variables)
```
WAYLAND_MULTI=1        # Multi-window mode (default: enabled)
WAYLAND_BACKBUFFER=1   # Double-buffering (default: disabled; set to 1 to opt in)
WAYLAND_DECO=1         # Window decorations (default: enabled)
WAYLAND_SHADOW=1       # Window shadows (default: enabled)
WAYLAND_RESIZE=1       # Resize support (default: enabled)
WAYLAND_THROTTLE=1     # Input throttling (default: enabled)
DEBUG_WAYLAND=1        # Debug logging (off by default)
```

### Known Limitations
- **No GPU acceleration** - all rendering is CPU-based
- **No EGL/OpenGL** - only software composition
- **POSIX SHM limitation** - uses tmpfs, not memfd_create (kernel doesn't support memfd yet)
- **Cursor not yet shown** - drawn but may not be visible in QEMU
- **Touch input** - protocol stubs exist but not fully implemented
- **Timer event loop** - timerfd doesn't support epoll in freestanding environment, uses fallback polling

---

## 2. Graphics/Display Drivers

### Framebuffer Driver (`/dev/fb0`)
**Location**: `/home/k/futura/drivers/video/fb.c`
**Status**: ✓ FUNCTIONAL

Features:
- Character device interface (major 29, minor 0)
- IOCTL support:
  - `FBIOGET_INFO` - get display parameters (width, height, pitch, bpp)
  - `FBIOSET_VSYNC_MS` - set vsync hint (for frame timing)
- mmap support for direct framebuffer access
- PAT (Page Attribute Table) support for write-combining
- Proper page alignment and size validation

### Virtio GPU Driver
**Location**: `/home/k/futura/kernel/video/virtio_gpu.c`
**Status**: ✓ IMPLEMENTED (not actively used by compositor)

Capabilities:
- PCI device enumeration (Virtio 1.0 compatible)
- 2D resource creation
- Scanout setup
- Transfer-to-host commands
- Display info queries
- Can initialize virtual displays in QEMU (-device virtio-gpu-pci)

### MMIO Framebuffer
**Location**: `/home/k/futura/kernel/video/fb_mmio.c`
**Status**: ✓ IMPLEMENTED

Supports:
- QEMU standard VGA (0xa0000 legacy address)
- Cirrus VGA
- Video memory mapping

### Boot Resolution Detection
- Probes BIOS for video modes
- Falls back to safe defaults (1024x768 or 1280x1024)
- **Current in qemu.log**: Likely 800x600 or standard VESA mode

---

## 3. Input Handling

### Keyboard Driver
**Location**: `/home/k/futura/drivers/input/ps2_kbd.c`
**Device**: `/dev/input/kbd0` (major 30, minor 0)
**Status**: ✓ FUNCTIONAL

- PS/2 scancode translation
- Extended key support (E0 prefix handling)
- Key press/release events
- Input event queue (struct fut_input_event)
- Integration with Wayland seat

### Mouse Driver  
**Location**: `/home/k/futura/drivers/input/ps2_mouse.c`
**Device**: `/dev/input/mouse0` (major 31, minor 0)
**Status**: ✓ FUNCTIONAL

- PS/2 protocol handling
- Relative motion tracking
- Button press/release
- Input queue integration

### Input System
**Location**: Kernel input subsystem
- Event queue in kernel (fut_input_queue_t)
- Timestamp support (nanosecond precision)
- Event types: KEY, MOTION, BUTTON, WHEEL
- Compositor polls input devices in event loop

### Touch Support
- Protocol stubs in seat (xdg-shell and wl_seat)
- Not yet tested with actual devices

---

## 4. Demo Clients

### wl-simple
**Location**: `/home/k/futura/src/user/clients/wl-simple/`
**Binary**: `wl-simple`
**Status**: ✓ FUNCTIONAL

Features:
- Creates 320x200 ARGB surface
- Animated gradient background
- Moving orange rectangle (bounces in window)
- Frame rate tracking (120 frame target)
- Basic Wayland protocol usage:
  - Registry binding
  - Compositor surface creation
  - XDG shell window setup
  - SHM buffer pool creation
  - Frame callbacks
- Keyboard events (Ctrl+C to copy test text)
- Clipboard integration (data_device, data_source)

### wl-colorwheel
**Location**: `/home/k/futura/src/user/clients/wl-colorwheel/`
**Binary**: `wl-colorwheel`
**Status**: ✓ FUNCTIONAL

Features:
- Creates 320x240 ARGB surface
- Renders HSV color wheel
- 120 frame animation
- Advanced Wayland usage:
  - Data offer handling (paste)
  - Selection tracking
  - Keyboard key events (V to paste)
  - Clipboard read operations

### Test Mode
Both clients can be launched via:
```bash
# From shell
wl-simple &
wl-colorwheel &

# Or directly in init
ENABLE_WAYLAND_DEMO=1 make wayland-step2
```

---

## 5. UI Applications & Windows

### Current State
The system **lacks traditional "applications"** - only demo clients exist.

### Existing App Framework
**Location**: `/home/k/futura/src/user/apps/`
- Only contains `winstub/` (legacy Windows subsystem remnant)
- No Wayland-native applications beyond demo clients

### Window Decorations
- ✓ Title bar (customizable height: 24px)
- ✓ Close button (right side, red X)
- ✓ Minimize button (left of close, minus sign)
- ✓ Hover state (color change on mouse over)
- ✓ Title text rendering (8x16 font, truncates with "...")
- ✓ Drop shadows (optional, configurable radius)
- ✓ Resize handles (6px margin on all edges)

### Window Features
- ✓ Dragging (click title bar, move window)
- ✓ Resizing (drag edges/corners)
- ✓ Maximize (button or window state)
- ✓ Minimize (button hides window)
- ✓ Z-order changes (click window to raise)
- ✓ Focus visual feedback (title bar color changes)
- ✓ Position clamping (keep window on-screen)
- ✓ Size constraints (min/max width/height)

---

## 6. Test Harness & Testing

### Build Integration
**File**: `/home/k/futura/Makefile` (targets: `wayland-step*`)

Three test scenarios:

#### `make wayland-step2`
Runs compositor + **wl-simple** client:
- Minimal smoke test
- Creates single animated window
- Validates basic Wayland handshake
- Exit criteria: 120 frames rendered

#### `make wayland-step3`
Runs compositor + **both demo clients**:
- Multi-window test
- Tests window stacking/focus
- Validates clipboard protocol
- More comprehensive scenario

#### `make wayland-stack3`
(Alias for wayland-step3)

### Test Environment
```bash
# Environment setup
XDG_RUNTIME_DIR=/tmp
WAYLAND_DISPLAY=wayland-0
WAYLAND_MULTI=1
WAYLAND_BACKBUFFER=0   # set to 1 to test double-buffer path explicitly
WAYLAND_DECO=1
WAYLAND_SHADOW=1
WAYLAND_RESIZE=1
WAYLAND_THROTTLE=1
```

### Success Criteria
Tests pass if:
1. Compositor boots (message: "futura-wayland running")
2. Clients connect successfully
3. Windows render (damage detection works)
4. Frame callbacks fire (animation smooth)
5. Clean shutdown (no crashes/segfaults)

### Limitations
- **No visual validation** - tests don't verify actual pixel output
- **No regression suite** - only manual QEMU runs
- **No CI integration** - tests run locally only
- **Timeouts** - QEMU can hang if event loop deadlocks

---

## 7. Known Issues & TODOs

### Critical Issues
1. **Timer event loop limitation**
   - `timerfd` doesn't support epoll in freestanding environment
   - **Workaround**: Implemented fallback polling in `comp_run()`
   - **Status**: WORKING but non-ideal performance

2. **POSIX SHM limitation**
   - Kernel doesn't implement `memfd_create()`
   - **Workaround**: Uses tmpfs-backed files via `fut_shm_create()`
   - **Issue**: Files not cleaned up properly (no unlink yet)
   - **File**: `src/user/libfutura/posix_shm.c` + `comp.c:fut_shm_unlink()`

3. **Cursor not visible**
   - Cursor is drawn in composition
   - **Issue**: May not be visible in QEMU software rasterization
   - **Status**: Code is correct, visual feedback may be missing

### Minor Issues
1. **Button press state tracking** - hover state works but pressed state needs refinement
2. **Resize during animation** - may cause frame tearing
3. **Large windows** - composition is slow for full-screen on slow CPUs
4. **Font rendering** - only basic 8x16 bitmap font (ui_text.c)
5. **Clipboard MIME types** - only supports "text/plain;charset=utf-8"

### TODOs in Code
1. **comp.c:fut_shm_unlink()** - marked as no-op, needs kernel `unlink()` syscall
2. **comp.c** - large write loops for buffer allocation (needs `ftruncate()`)
3. **seat.c** - touch input protocol stubs (not implemented)
4. **data_device.c** - paste buffer reading (may have issues)
5. **Damage region optimization** - coalescing could be more aggressive

### Missing Features
- [ ] GPU acceleration (virtio-gpu integration)
- [ ] EGL/OpenGL support
- [ ] Multiple displays (multi-output)
- [ ] Screen rotation support
- [ ] Hotplug detection (monitor plugging)
- [ ] Color management (ICC profiles)
- [ ] Accessibility (font scaling, high contrast)
- [ ] IME/text input methods
- [ ] Tablet/stylus support (beyond touch)

---

## 8. Architecture & Data Flow

### Boot Sequence
```
kernel starts
  → fb_char_init() - register /dev/fb0
  → ps2_kbd_init() - register /dev/input/kbd0
  → ps2_mouse_init() - register /dev/input/mouse0
  → init (PID 1)
    → ENABLE_WAYLAND_DEMO=1 spawns futura-wayland
      → comp_state_init() - open /dev/fb0, get display info
      → wl_display_create() - create Wayland server
      → compositor_global_init() - register wl_compositor
      → xdg_shell_global_init() - register xdg-wm-base
      → output_global_init() - advertise display
      → shm_backend_init() - set up SHM pool
      → seat_init() - create wl_seat, bind input devices
      → wl_display_add_socket_auto() - listen on WAYLAND_DISPLAY
      → comp_run() - enter event loop
        → wl_event_loop_dispatch() - handle client messages
        → comp_run() polls timerfd for frame ticks
        → comp_render_frame() - composite all windows
    → wl-simple or wl-colorwheel connects
      → wl_display_connect(NULL) - find socket via WAYLAND_DISPLAY
      → protocol negotiation (registry -> bind globals)
      → surface creation -> buffer attachment -> commit
      → compositor renders to framebuffer
      → client receives frame callbacks
```

### Rendering Pipeline
```
Input Events
  ↓
seat.c: input dispatch
  ↓
xdg_shell.c: window state changes
  ↓
comp.c: damage accumulation
  ↓
comp_render_frame():
  ├─ Clear damage regions
  ├─ Composite each window (in Z-order):
  │  ├─ Draw drop shadow (if enabled)
  │  ├─ Blit client buffer (content)
  │  ├─ Draw title bar background
  │  ├─ Draw minimize/close buttons
  │  └─ Draw title text
  ├─ Composite cursor
  └─ Blit final frame to /dev/fb0
  ↓
present_damage(): copy backbuffer to framebuffer
  ↓
comp_flush_frame_callbacks(): notify clients
  ↓
Next timer tick (16ms later)
```

### Data Structures
**Main compositor state** (`comp.h`):
```c
struct compositor_state {
    struct wl_display *display;
    struct wl_event_loop *loop;
    int fb_fd;                              // /dev/fb0 handle
    uint8_t *fb_map;                        // mmap'd framebuffer
    struct wl_list surfaces;                // z-ordered window list
    struct backbuffer bb[2];                // double-buffering
    struct damage_accum frame_damage;       // dirty regions
    struct seat_state *seat;                // input handling
    struct cursor_state *cursor;            // mouse cursor
    // ... configuration flags
};

struct comp_surface {
    int32_t x, y;                           // screen position
    int32_t width, height;                  // including decorations
    int32_t content_height;                 // without decorations
    uint8_t *backing;                       // client's buffer copy
    bool has_backing;                       // is buffer attached
    bool maximized;                         // state
    bool minimized;                         // state
    resize_edge_t resizing;                 // resize direction
    char title[WINDOW_TITLE_MAX];           // window title
    // ... decoration rects and hover states
};
```

### Buffer Flow
```
Client creates SHM pool
  → fut_shm_create() creates /dev/shm/wl-NAME with size
  → wl_shm_create_pool() creates wl_shm_pool
  → wl_shm_pool_create_buffer() creates wl_buffer wrapper
  ↓
Client paints to mapped memory
  ↓
Client calls wl_surface_attach() + wl_surface_commit()
  ↓
Compositor receives attach+commit events
  ↓
shm_buffer_import() in comp.c:comp_surface_commit()
  → Validates buffer via wl_shm_buffer_get()
  → Copies client's pixels to surface->backing
  → Marks damage region
  ↓
On next frame tick:
  → comp_render_frame() blits surface->backing to framebuffer
  → Sends wl_callback::done to client
  ↓
Client receives frame callback and can paint next frame
```

---

## 9. Current Test Status (from qemu.log)

**Latest boot** (2025-10-29):
```
[INIT] exec /sbin/futura-wayland -> 0
[INIT] ========================================
[INIT] Wayland Compositor Ready for Interaction
[INIT] Minimized windows feature: ACTIVE
[INIT] ========================================
```

**Indicates**:
- ✓ Compositor launched successfully
- ✓ Initialization complete
- ✓ Ready to accept client connections
- ✓ Feature flags processed correctly

**No error messages** about input, framebuffer, or protocol violations.

---

## 10. Completeness Assessment

### Functional (80-90% complete)
- ✓ Wayland server core
- ✓ Window management (create, destroy, move, resize, maximize)
- ✓ Input handling (keyboard, mouse buttons)
- ✓ Framebuffer rendering
- ✓ Damage tracking
- ✓ SHM buffer management
- ✓ Frame scheduling

### Partial (50-70% complete)
- ~  Decorations (title, buttons, shadows work but may need refinement)
- ~  Clipboard (basic copy/paste works)
- ~  Cursor (drawn but maybe not visible)
- ~  Focus management (works but edge cases may exist)

### Incomplete (0-20% complete)
- ✗ GPU acceleration
- ✗ OpenGL/EGL
- ✗ Touch input
- ✗ Multi-display
- ✗ High-DPI scaling
- ✗ Accessibility features
- ✗ IME/text composition

### Architecture Quality
- **Code organization**: Well-structured, modular design
- **Comments**: Detailed and helpful
- **Error handling**: Mostly present, some fallback gracefully
- **Memory management**: Static allocation where possible, heap for buffers
- **Thread safety**: No threads (event-driven), FIPC for IPC

---

## 11. Recommendations for Next Steps

### High Priority (Blocking issues)
1. **Implement kernel `unlink()` syscall** → fixes SHM cleanup
2. **Test in real hardware or QEMU with graphics passthrough** → verify cursor visibility
3. **Fix button state machines** → ensure hover/press feedback is correct

### Medium Priority (Feature gaps)
4. **Implement touch input protocol** → full seat capabilities
5. **Add font glyph caching** → improve text rendering performance
6. **Implement CLIPBOARD_MANAGER protocol** → robust clipboard

### Low Priority (Nice-to-have)
7. **GPU acceleration** → significant performance improvement but complex
8. **Multi-display support** → requires output enumeration protocol
9. **Accessibility features** → screen reader integration

### Testing Improvements
- Create automated pixel-output validation tests
- Add regression suite for window management
- Benchmark composition performance
- Fuzz protocol parser

---

## Summary

**Futura's Wayland compositor is in ALPHA stage - fundamentals work, but needs refinement and hardening.** The system successfully:
- Boots and initializes correctly
- Accepts client connections
- Renders windows with decorations
- Handles input events
- Manages buffers and damage

However, it's **not production-ready** for general GUI use cases due to:
- Limited feature set (no GPU, no accessibility)
- Incomplete clipboard/input protocols
- Unknown real-hardware compatibility
- Lack of automated testing

The architecture is sound and the code quality is good for a research OS, making it a solid foundation for further development.
