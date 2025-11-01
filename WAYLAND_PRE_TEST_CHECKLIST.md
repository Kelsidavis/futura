# Wayland Compositor Pre-Test Checklist

## ✅ Build Status

- [x] All source files compile without errors
- [x] Linker wrapping configured for socket syscalls
- [x] Binary exists: `/home/k/futura/build/bin/user/futura-wayland`
- [x] Binary size reasonable (>500KB with debug symbols)
- [x] No undefined reference errors

## ✅ Code Components

### Core Rendering
- [x] `comp.c` - Demo rendering function implemented
- [x] `comp_render_demo_frame()` - 4-quadrant color test pattern
- [x] Frame scheduler integration verified
- [x] Backbuffer system ready

### Socket Debugging
- [x] `syscall_wrappers.c` - Enhanced with debug output
- [x] `__wrap_socket()` - Logs parameters and results
- [x] `__wrap_bind()` - Logs bind attempts
- [x] `__wrap_listen()` - Logs listen attempts
- [x] `debug_write_int()` - Converts numbers to strings
- [x] `strerror_simple()` - Maps errno to names
- [x] Forward declarations - All helper functions declared

### Socket Diagnostics in main.c
- [x] XDG_RUNTIME_DIR setup and verification
- [x] Test file creation to verify filesystem access
- [x] Socket creation attempt logging
- [x] Demo mode activation with scheduler stop
- [x] Error handling and errno capture

### Test Infrastructure
- [x] `test_socket.c` - Standalone socket test program
- [x] Can be compiled separately to verify syscalls
- [x] Tests socket(), bind(), listen() in isolation

## ✅ Documentation

- [x] WAYLAND_COMPLETE_SESSION_LOG.md - Full history
- [x] WAYLAND_SESSION_2_SUMMARY.md - Socket work details
- [x] WAYLAND_UI_ANALYSIS.md - Architecture overview
- [x] WAYLAND_QUICK_REFERENCE.txt - Quick lookup
- [x] WAYLAND_TESTING_GUIDE.md - Testing procedures
- [x] This checklist - Pre-test verification

## ✅ Git Status

- [x] All code committed to main branch
- [x] No uncommitted changes (except doc files)
- [x] Clean history with meaningful commit messages
- [x] Recent commits include critical fixes

## ✅ Expected Behavior

### Display
- [x] Should show 4-quadrant test pattern (if socket creation fails)
  - Top-left: RED (0xFFFF0000)
  - Top-right: GREEN (0xFF00FF00)
  - Bottom-left: BLUE (0xFF0000FF)
  - Bottom-right: YELLOW (0xFFFFFF00)

### Console Output
- [x] Should see initialization messages
- [x] Should see XDG_RUNTIME_DIR diagnostics
- [x] Should see [WRAP_SOCKET] messages if wrappers invoked
- [x] Should see errno value if socket creation fails
- [x] Should see "Demo mode" message if socket fails

## 🔍 What to Look For During Test

### Phase 1: Boot & Initialization
```
Expected:
[COMPOSITOR] Reached main, stdio initialized
[WAYLAND-DEBUG] About to call comp_state_init()
[WAYLAND-DEBUG] comp_state_init() succeeded
[WAYLAND-DEBUG] wl_display_create() returned: 0x...
```

### Phase 2: Filesystem Checks
```
Expected:
[WAYLAND-DEBUG] XDG_RUNTIME_DIR=/tmp
[WAYLAND-DEBUG] XDG_RUNTIME_DIR accessible
[WAYLAND-DEBUG] Test file created successfully
```

### Phase 3: Socket Creation
```
Expected:
[WAYLAND-DEBUG] Calling wl_display_add_socket_auto()
[WRAP_SOCKET] socket(1, 1, 0)
[WRAP_SOCKET] FAILED: <ERROR_NAME> (errno=<NUMBER>)
OR
[WRAP_SOCKET] SUCCESS: fd=3
[WRAP_BIND] bind(fd=3, ...)
[WRAP_LISTEN] listen(fd=3, ...)
```

### Phase 4: Demo Mode (Expected Current State)
```
[WAYLAND] Demo mode: socket creation failed, rendering test pattern
[WAYLAND] Frame scheduler stopped for demo mode
```

## 📊 Critical Files Verification

| File | Purpose | Status |
|------|---------|--------|
| `main.c` | Compositor init + socket diagnostics | ✅ Updated |
| `comp.c` | Rendering + demo mode | ✅ Updated |
| `comp.h` | Function declarations | ✅ Updated |
| `syscall_wrappers.c` | Socket syscall logging | ✅ Updated |
| `test_socket.c` | Isolated socket testing | ✅ Created |
| `Makefile` | Build configuration | ✅ Linker wrapping set |

## 🎯 Success Criteria

**Minimum Success**:
- System boots
- Demo mode activates
- 4-quadrant color test pattern displays
- Console logs socket creation attempt
- errno value visible in output

**Full Success**:
- All of above
- PLUS socket creation succeeds
- PLUS compositor ready for clients

## 🚨 Troubleshooting Plan

| Issue | Check | Action |
|-------|-------|--------|
| No display output | Build successful? | Rebuild with `make clean && make` |
| All-green screen | Scheduler stop working? | Check comp_scheduler_stop() call |
| No console messages | Debug build flags? | Verify DEBUG_WAYLAND defined |
| No [WRAP_SOCKET] messages | Wrappers invoked? | Verify linker --wrap flags |
| Wrong colors in pattern | Framebuffer format? | Check ARGB vs RGBA |

## 📈 Readiness Summary

**Overall Status**: ✅ **READY FOR TESTING**

All components:
- ✅ Compiled successfully
- ✅ Linked correctly
- ✅ Diagnostics integrated
- ✅ Documentation complete
- ✅ Test infrastructure ready

**Next Step**: Boot system and run compositor to capture diagnostic output

---

**Last Updated**: Session 2 completion
**Session**: Wayland UI Fixes - Sessions 1 & 2
**Branch**: main
**Binary**: `/home/k/futura/build/bin/user/futura-wayland` (589824 bytes)
