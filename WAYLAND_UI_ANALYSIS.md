# Wayland UI Display System Analysis

## Executive Summary

The Futura Wayland compositor is a sophisticated display system with comprehensive rendering capabilities, but faces critical blockers around socket creation for client connections and syscall interception. The system has "demo mode" fallback rendering logic that was recently added but is not fully integrated into the rendering pipeline.

---

## 1. UI RENDERING ARCHITECTURE

### Core Components

The Wayland compositor implements a complete graphics pipeline:

#### **1.1 Framebuffer I/O (fb.c)**
- Opens `/dev/fb0` for direct framebuffer access
- Queries framebuffer info via `FBIOGET_INFO` ioctl
- Validates pixel format (requires 32-bit ARGB8888)
- Maps framebuffer into compositor memory via `mmap()`

#### **1.2 Backbuffer System (comp.c:299-905)**
- **Dual-buffer architecture** for flicker-free rendering
- Two backbuffers (index 0 and 1) that swap each frame
- Optional fallback to direct framebuffer writes
- Controlled via `WAYLAND_BACKBUFFER` environment variable

#### **1.3 Rendering Pipeline (comp.c:1227-1371)**

**`comp_render_frame()` function:**
- Receives damage regions accumulated since last frame
- Coalesces overlapping damage rectangles to reduce redraws
- Clears damaged areas to black (`COLOR_CLEAR = 0xFF000000`)
- Renders surfaces in Z-order (back to front)
- For each surface:
  - Draws drop shadows (if `WAYLAND_SHADOW_BUILD`)
  - Draws window title bar (if `WAYLAND_DECO_BUILD`)
  - Draws minimize/close buttons
  - Blits surface content via optimized `blit_argb()`
- Renders cursor sprite on top
- Presents backbuffer to hardware framebuffer

**Damage Region Coalescing (comp.c:158-216):**
- Greedy single-pass merge algorithm
- Prevents excessive region fragmentation
- Limits to 4 regions after coalescing

**Optimized Rendering:**
- 64-bit bulk fill (`bb_fill_rect`) for large rectangles
- 64-bit pixel blit (`blit_argb`) for fast surface composition
- Clip-based rendering (only redraws damaged areas)

#### **1.4 Window Decorations (comp.c:331-379, 471-554)**
- **Title bar** (24px height, configurable)
- **Minimize button** (16x16px) - drawn as horizontal line
- **Close button** (16x16px) - drawn as X pattern
- **Window shadows** (10px default radius)
- Colors:
  - Focused bar: `0xFF2F6DB5` (blue)
  - Unfocused bar: `0xFF303030` (dark grey)
  - Button base: `0xFF444444`
  - Button hover: `0xFF666666`
  - Button pressed: `0xFF202020`

#### **1.5 Text Rendering (ui_text.c, font8x16.h)**
- 8x16 bitmap font in `font8x16.h`
- Window title rendering with truncation ("...")
- Supports focused/unfocused text colors
- Clip-region aware rendering

#### **1.6 Cursor Support (cursor.c, cursor.h)**
- Sprite-based cursor rendering
- Position tracking in `(pointer_x, pointer_y)`
- Damage tracking for cursor movement redraws

---

## 2. FRAME SCHEDULING & RENDERING PIPELINE

### Frame Scheduler (comp.c:1470-1560)

**Scheduler Architecture:**
- Uses `timerfd` for hardware-synchronized frame timing
- Target: 60 Hz (16ms per frame)
- Supports vsync hints from framebuffer driver
- Manual timer event handling (timerfd not supported in epoll)

**Key Functions:**
- `comp_scheduler_start()`: Creates timerfd, arms timer
- `comp_scheduler_stop()`: Disarms and closes timerfd
- `comp_handle_timer_tick()`: Updates next frame deadline
- `comp_timerfd_cb()`: Event loop callback (if registered)

**Event Loop Integration:**
- `wl_event_loop_dispatch()` with 16ms timeout
- Manual timerfd polling fallback (non-blocking read)
- Handles both registered and non-registered timer sources

### Frame Rendering Cycle (comp.c:1438-1468)

```c
comp_run():
  while (running):
    wl_display_flush_clients()      // Send protocol responses
    wl_event_loop_dispatch(16ms)   // Process events
    if (timerfd): 
      read(timerfd)
      comp_handle_timer_tick()
        comp_render_frame()
```

**Damage Accumulation:**
- `needs_repaint` flag triggers frame rendering
- Only renders if `frame_damage.count > 0`
- Surfaces mark damage via `comp_surface_mark_damage()`

### Surface Lifecycle (comp.c:907-1160)

**Attach/Commit Flow:**
1. Client attaches buffer → `comp_surface_attach()`
2. Client commits → `comp_surface_commit()`
   - Validates buffer format (must be ARGB/XRGB)
   - Copies client pixel data to backing buffer
   - Updates surface geometry
   - Marks damage regions
3. Frame rendering occurs on next timer tick
4. Frame callbacks flushed after render

---

## 3. ISSUES & BLOCKERS PREVENTING UI DISPLAY

### CRITICAL ISSUE #1: Socket Creation Failure (main.c:240-269)

**Location:** `/home/k/futura/src/user/compositor/futura-wayland/main.c:240-269`

**Problem:**
```c
const char *socket = wl_display_add_socket_auto(comp.display);
if (!socket) {
    // Fallback to manual socket
    int rc = wl_display_add_socket(comp.display, "wayland-0");
    if (rc < 0) {
        socket = "none";  // FAILURE: No socket created!
    }
}

// Demo mode fallback
if (!socket || strcmp(socket, "none") == 0) {
    printf("[WAYLAND] Demo mode: socket creation failed, skipping framebuffer UI\n");
    printf("[WAYLAND] fb_map address: %p\n", (void*)comp.fb_map);
}
```

**Why This Happens:**
1. `wl_display_add_socket_auto()` needs `XDG_RUNTIME_DIR` environment variable
2. Code attempts to set `XDG_RUNTIME_DIR=/tmp` (lines 226-233)
3. Unix socket creation via `__wrap_socket()` may fail
4. Fallback `wl_display_add_socket("wayland-0")` also fails
5. System continues but marks it as "Demo mode"

**Impact:**
- **NO CLIENTS CAN CONNECT** - Wayland clients need a socket to communicate
- Compositor still runs but isolated
- Rendering pipeline still executes (`comp_render_frame()` is called at line 272)
- But no client windows appear

### CRITICAL ISSUE #2: Socket Syscall Interception (syscall_wrappers.c)

**Location:** `/home/k/futura/src/user/compositor/futura-wayland/syscall_wrappers.c:238-249`

**Problem:**
Socket creation is wrapped for int 0x80 compatibility:
```c
int __wrap_socket(int domain, int type, int protocol) {
    int type_masked = type & 0xF;  // Strip SOCK_CLOEXEC, SOCK_NONBLOCK
    long result = int80_socket(domain, type_masked, protocol);
    if (result < 0) {
        errno = -result;
        return -1;
    }
    errno = 0;
    return (int)result;
}
```

**Wrappers Also Provide:**
- `bind()` (int 0x80 syscall #49)
- `listen()` (int 0x80 syscall #50)
- `connect()` (int 0x80 syscall #42)
- `fcntl()` (int 0x80 syscall #72) - for O_NONBLOCK

**Why It Matters:**
- Wayland socket creation uses these syscalls
- int 0x80 from 64-bit code requires register mapping:
  - i386 ABI: EBX/ECX/EDX
  - x86_64 ABI: RDI/RSI/RDX (what QEMU provides)
- QEMU bug workaround is in place (registers correctly mapped)

### POTENTIAL ISSUE #3: Event Loop Timer Registration (comp.c:1512-1534)

**Location:** `comp_scheduler_start()` at line 1512

**Problem:**
```c
comp->timer_source = wl_event_loop_add_fd(comp->loop,
                                          comp->timerfd,
                                          WL_EVENT_READABLE,
                                          comp_timerfd_cb,
                                          comp);
if (!comp->timer_source) {
    printf("[SCHEDULER-DEBUG] Event loop add_fd returned NULL\n");
    comp->timer_source_registered = false;  // Fallback to manual polling
}
```

**Why:**
- timerfd may not support epoll in this environment
- Code falls back to manual polling in `comp_run()` (lines 1458-1464)
- This is a known workaround, not critical

### POTENTIAL ISSUE #4: Demo Mode UI Rendering Incomplete (main.c:265-269)

**Location:** `/home/k/futura/src/user/compositor/futura-wayland/main.c:265-269`

**Current Code:**
```c
if (!socket || strcmp(socket, "none") == 0) {
    printf("[WAYLAND] Demo mode: socket creation failed, skipping framebuffer UI\n");
    printf("[WAYLAND] fb_map address: %p\n", (void*)comp.fb_map);
}
```

**Problem:**
- Message says "skipping framebuffer UI"
- Demo rendering code was removed (commit 92e25b5 added it, but appears to have been reverted)
- No actual fallback UI is rendered
- Frame is rendered but only to backbuffer if `backbuffer_enabled`

**Should Be:**
```c
if (!socket || strcmp(socket, "none") == 0) {
    printf("[WAYLAND] Demo mode: rendering fallback UI\n");
    // Render demo UI or skip client rendering
}
```

---

## 4. SOCKET CREATION & CLIENT CONNECTION

### Socket Setup (main.c:226-257)

**Sequence:**
1. Set `XDG_RUNTIME_DIR=/tmp` (line 232)
2. Clear errno to avoid stale values (line 237)
3. Call `wl_display_add_socket_auto(comp.display)` (line 240)
   - Wayland library creates Unix domain socket
   - Generates socket name from WAYLAND_DISPLAY env var
   - Stores in `$XDG_RUNTIME_DIR/`
4. If auto fails, try manual `wl_display_add_socket(comp.display, "wayland-0")`
5. If both fail, mark as demo mode

**Socket Creation Flow (inside libwayland-server):**
```
wl_display_add_socket_auto()
  → wl_socket_create()
    → socket(AF_UNIX, SOCK_STREAM)         [__wrap_socket]
    → bind(sockfd, &addr, sizeof(addr))   [__wrap_bind]
    → listen(sockfd, 1)                    [__wrap_listen]
    → chmod(socket_path, 0666)             [__wrap_chmod]
```

### Wayland Socket Lock (wayland internals)

Unix domain sockets require:
- **Lock file** (`wayland-0.lock`) in `XDG_RUNTIME_DIR`
- **Socket file** (`wayland-0`) as the actual socket
- Both created by libwayland-server during `wl_display_add_socket()`

### Known Limitations

From `syscall_wrappers.c`:
- **Single-process OS** - file locking always succeeds (line 147-152)
- **No file descriptors beyond socket types** - `AT_FDCWD` special handling (line 224-226)
- **Limited syscall set** - only specific syscalls wrapped for int 0x80

---

## 5. KEY RENDERING CODE SECTIONS

### `comp_state_init()` (comp.c:749-839)
- Opens `/dev/fb0` and mmaps framebuffer
- Queries framebuffer geometry
- Creates backbuffers if `backbuffer_enabled`
- Initializes cursor

### `comp_render_frame()` (comp.c:1227-1371)
- **Core rendering engine**
- Coalesces damage regions
- Renders all surfaces in Z-order
- Handles decorations, shadows, text, cursor
- Presents to hardware framebuffer

### `comp_surface_commit()` (comp.c:1046-1160)
- Receives client buffer
- Copies pixel data to backing store
- Marks damage regions
- Updates surface geometry

### `blit_argb()` (comp.c:429-469)
- **Optimized pixel copy** (64-bit bulk writes)
- Faster than memcpy for aligned data
- Used for all surface blitting

### `bb_fill_rect()` (comp.c:385-423)
- **Optimized rectangle fill** (64-bit pattern writes)
- Used for clearing and solid colors

---

## 6. CURRENT BUILD CONFIGURATION

**File:** `/home/k/futura/src/user/compositor/futura-wayland/Makefile`

**Build Features (enabled by default):**
```makefile
WAYLAND_MULTI_BUILD=1        # Multiple window support
WAYLAND_BACKBUFFER_BUILD=1   # Backbuffer system (default off at runtime)
WAYLAND_DECO_BUILD=1         # Window decorations
WAYLAND_SHADOW_BUILD=1       # Window shadows
WAYLAND_RESIZE_BUILD=1       # Window resizing
```

**Environment Variable Controls (main.c:60-95):**
```bash
WAYLAND_BACKBUFFER=0/1  # Enable backbuffer (default: 1)
WAYLAND_DECO=0/1        # Enable decorations (default: 1)
WAYLAND_SHADOW=0/1      # Enable shadows (default: 1)
WAYLAND_RESIZE=0/1      # Enable resizing (default: 1)
WAYLAND_THROTTLE=0/1    # Enable throttle (default: 1)
WAYLAND_MULTI=0/1       # Multiple windows (default: 1)
XDG_RUNTIME_DIR=path    # Socket directory (default: /tmp)
```

---

## 7. RENDERING STATUS

### What's Working:

1. **Framebuffer access** - `/dev/fb0` opens successfully
2. **Memory mapping** - Framebuffer mmaps and is writable
3. **Backbuffer system** - Dual-buffer architecture functional
4. **Rendering engine** - All drawing functions implemented:
   - Rectangle fills (64-bit optimized)
   - Pixel blits (64-bit optimized)
   - Text rendering (8x16 bitmap font)
   - Window decorations (title bar, buttons, shadows)
   - Cursor rendering
5. **Frame scheduling** - timerfd-based 60 Hz timer
6. **Surface management** - Surface creation, deletion, Z-ordering
7. **Damage tracking** - Efficient damage accumulation and region coalescing
8. **Syscall interception** - All socket-related syscalls wrapped for int 0x80

### What's NOT Working:

1. **Socket creation** - `wl_display_add_socket_auto()` fails
2. **Client connections** - No IPC path for clients
3. **Demo mode rendering** - Incomplete/reverted implementation
4. **User-visible output** - No client windows appear on display

### Why No UI Appears:

1. Compositor starts successfully
2. Frame rendering code executes (but renders empty backbuffer)
3. **No client windows exist** - because clients can't connect to socket
4. Display shows only:
   - Black background (from clear color)
   - Possibly cursor (if input devices work)
5. Compositor waits for client connections that never arrive

---

## 8. BLOCKERS SUMMARY

| Priority | Issue | Location | Status |
|----------|-------|----------|--------|
| CRITICAL | Socket creation fails | `main.c:240-257` | Unresolved |
| CRITICAL | No client connections possible | libwayland-server | Can't fix without socket |
| HIGH | Demo mode incomplete | `main.c:265-269` | Incomplete implementation |
| MEDIUM | Timer event loop registration | `comp.c:1512` | Fallback works |
| LOW | Syscall wrapping edge cases | `syscall_wrappers.c` | Mostly working |

---

## 9. RECOMMENDATIONS

### Immediate Actions:

1. **Debug socket creation:**
   - Add more verbose logging in `wl_display_add_socket*()` calls
   - Check `XDG_RUNTIME_DIR` permissions and availability
   - Verify socket() syscall succeeds
   - Test bind() to socket path

2. **Implement demo rendering:**
   - Add fallback UI when socket fails
   - Render solid background + test pattern
   - Shows system is alive but waiting for clients

3. **Test client connectivity:**
   - Run test Wayland client if socket exists
   - Monitor socket file creation in `$XDG_RUNTIME_DIR`

### Medium-term:

1. Verify all syscall wrappers work correctly
2. Test under different QEMU configurations
3. Add comprehensive logging to rendering pipeline

---

## 10. CRITICAL FILE REFERENCES

All absolute paths:

| File | Purpose | Lines |
|------|---------|-------|
| `/home/k/futura/src/user/compositor/futura-wayland/comp.h` | Core data structures | 1-376 |
| `/home/k/futura/src/user/compositor/futura-wayland/comp.c` | Main rendering engine | 1-2163 |
| `/home/k/futura/src/user/compositor/futura-wayland/main.c` | Compositor initialization | 45-283 |
| `/home/k/futura/src/user/compositor/futura-wayland/syscall_wrappers.c` | Syscall interception | 1-489 |
| `/home/k/futura/src/user/compositor/futura-wayland/seat.c` | Input device handling | 1-700+ |
| `/home/k/futura/src/user/compositor/futura-wayland/xdg_shell.c` | XDG shell protocol | 1-600+ |
| `/home/k/futura/src/user/compositor/futura-wayland/Makefile` | Build configuration | 1-82 |

---

## Conclusion

The Wayland compositor has **comprehensive rendering capabilities** with sophisticated damage tracking, optimization, and feature support. However, **no UI displays because socket creation fails**, preventing client connections. The rendering pipeline itself is sound and would display windows correctly if clients could connect. The immediate blocker is resolving Unix domain socket creation in the libwayland-server integration.

