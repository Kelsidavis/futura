# Wayland Compositor Testing & Verification Guide

## 📋 Overview

This document provides a comprehensive guide for testing the Wayland compositor with all diagnostic infrastructure in place. It covers expected behavior, what to look for, and how to interpret the output.

## 🎯 Testing Objectives

1. **Verify demo mode rendering** - 4-quadrant color test pattern should display
2. **Capture socket debug output** - Identify why socket creation fails
3. **Verify diagnostic infrastructure** - Debug messages should be visible
4. **Analyze errno values** - Determine exact failure point

## 📊 Expected Behavior

### Success Path (Socket Creation Works)
```
[WAYLAND-DEBUG] Calling wl_display_add_socket_auto()
[WRAP_SOCKET] socket(1, 1, 0)
[WRAP_SOCKET] SUCCESS: fd=3
[WRAP_BIND] bind(fd=3, addr=..., addrlen=110)
[WRAP_BIND] SUCCESS
[WRAP_LISTEN] listen(fd=3, backlog=1)
[WRAP_LISTEN] SUCCESS
[WAYLAND] SUCCESS: auto socket created: wayland-0
[WAYLAND] compositor ready 1024x768 bpp=32 socket=wayland-0
```

Display: Wayland compositor running, ready for client connections

### Failure Path (Socket Creation Fails - Current State)
```
[WAYLAND-DEBUG] Calling wl_display_add_socket_auto()
[WRAP_SOCKET] socket(1, 1, 0)
[WRAP_SOCKET] FAILED: <ERROR_NAME> (errno=<NUMBER>)
[WAYLAND] Demo mode: socket creation failed, rendering test pattern
[WAYLAND] Frame scheduler stopped for demo mode
[WAYLAND] Demo mode complete - compositor idle
```

Display: 4-quadrant test pattern
- **Top-left**: Red (0xFFFF0000)
- **Top-right**: Green (0xFF00FF00)
- **Bottom-left**: Blue (0xFF0000FF)
- **Bottom-right**: Yellow (0xFFFFFF00)

## 🔍 Output Analysis Guide

### Phase 1: Initialization Messages

Look for these messages to verify the compositor is starting:

| Message | Meaning |
|---------|---------|
| `[COMPOSITOR] Reached main, stdio initialized` | Process started successfully |
| `[WAYLAND-DEBUG] About to call comp_state_init()` | Graphics initialization starting |
| `[WAYLAND-DEBUG] comp_state_init() succeeded` | Framebuffer access working |
| `[WAYLAND-DEBUG] wl_display_create() returned: 0x...` | Wayland display object created |

**Expected**: All initialization messages should appear in order

### Phase 2: XDG Runtime Directory Check

These messages indicate filesystem accessibility:

| Message | Meaning | Action |
|---------|---------|--------|
| `[WAYLAND-DEBUG] Setting XDG_RUNTIME_DIR=/tmp` | Using default /tmp | Normal behavior |
| `[WAYLAND-DEBUG] XDG_RUNTIME_DIR accessible` | /tmp is readable | Good sign |
| `[WAYLAND-DEBUG] Test file created successfully` | /tmp is writable | Socket creation likely possible |
| `[WAYLAND-DEBUG] WARNING: Could not create test file` | /tmp not writable | Permission issue - likely cause of EACCES |

**Expected**: Should see "accessible" and "created successfully"

### Phase 3: Socket Creation Attempt

Critical phase - look for these patterns:

#### Socket Syscall Information
```
[WRAP_SOCKET] socket(1, 1, 0)    # domain=1 (AF_UNIX), type=1 (SOCK_STREAM), protocol=0
[WRAP_BIND] bind(fd=3, addr=0x..., addrlen=110)
[WRAP_LISTEN] listen(fd=3, backlog=1)
```

**Interpretation**:
- `socket(1, 1, 0)` = AF_UNIX domain socket ✓
- `bind()` = Attempting to bind to socket path ✓
- `listen()` = Attempting to listen for connections ✓

#### Success Indicators
```
[WRAP_SOCKET] SUCCESS: fd=3
[WRAP_BIND] SUCCESS
[WRAP_LISTEN] SUCCESS
```

#### Failure Indicators
```
[WRAP_SOCKET] FAILED: <ERROR_NAME> (errno=<NUMBER>)
[WRAP_BIND] FAILED: <ERROR_NAME> (errno=<NUMBER>)
[WRAP_LISTEN] FAILED: <ERROR_NAME> (errno=<NUMBER>)
```

### Phase 4: Final State

Last message indicates what mode compositor enters:

| Message | Mode | Display |
|---------|------|---------|
| `[WAYLAND] SUCCESS: auto socket created: ...` | Normal | Waiting for clients |
| `[WAYLAND] Demo mode: socket creation failed, rendering test pattern` | Demo | Test pattern visible |

**Expected**: Currently, demo mode (test pattern should display)

## 🚨 Errno Values & Meanings

When socket creation fails, you'll see:

```
[WRAP_SOCKET] FAILED: <ERROR_NAME> (errno=<NUMBER>)
```

### Common Errno Values

| Errno | Name | Cause | Solution |
|-------|------|-------|----------|
| 13 | EACCES | Permission denied | Check /tmp permissions (should be 777) |
| 48 | EADDRINUSE | Address already in use | Old socket file exists at path |
| 22 | EINVAL | Invalid argument | Syscall parameters might be wrong |
| 2 | ENOENT | No such file or directory | /tmp directory doesn't exist |
| 1 | EPERM | Operation not permitted | Insufficient privileges |
| 28 | ENOSPC | No space left on device | Disk full or inode limit reached |

### Errno to Error Name Mapping

The `strerror_simple()` function maps errno values:

```c
0=SUCCESS
1=EPERM
2=ENOENT
13=EACCES
22=EINVAL
28=ENOSPC
48=EADDRINUSE
// ... and more
```

## 📸 What to Capture

### Complete Output Capture
Run the compositor and capture **ALL** console output:
```bash
./build/bin/user/futura-wayland | tee wayland-test-output.log
```

This captures everything to both screen and file.

### Key Lines to Extract
Search output for:
1. `[WRAP_SOCKET]` - Socket creation attempts
2. `[WRAP_BIND]` - Bind syscall attempts
3. `[WRAP_LISTEN]` - Listen syscall attempts
4. `[WAYLAND-DEBUG]` - Debug information
5. `FAILED:` - Any failure messages
6. `SUCCESS:` - Any success messages

### Example Analysis
```bash
# Find all socket-related messages
grep -E "\[WRAP_|socket creation failed" wayland-test-output.log

# Find first error
grep "FAILED:" wayland-test-output.log | head -1

# Get the errno value
grep "FAILED:" wayland-test-output.log | grep -oP 'errno=\K[0-9]+'
```

## 🎬 Testing Procedure

### Step 1: Build Verification
```bash
cd /home/k/futura
make clean
make
# Should complete with no errors
```

### Step 2: Pre-Test Filesystem Check
```bash
ls -ld /tmp
# Should show: drwxrwxrwt (permissions 1777)
```

### Step 3: Run Compositor
```bash
./build/bin/user/futura-wayland
```

### Step 4: Observe Display
- If test pattern appears: Socket creation failed (expected for now)
- If pattern is 4 colors: Great! Demo rendering works
- If screen stays green: Scheduler interference (should be fixed)
- If nothing appears: Framebuffer access issue

### Step 5: Capture Output Analysis
Once the system boots and compositor runs, look for:

1. **Did demo mode activate?**
   - Look for: `[WAYLAND] Demo mode: socket creation failed`
   - Expected: YES (current state)

2. **Did test file creation work?**
   - Look for: `[WAYLAND-DEBUG] Test file created successfully`
   - Expected: YES (indicates /tmp is writable)

3. **Did socket wrapper log anything?**
   - Look for: `[WRAP_SOCKET]` messages
   - Expected: YES (indicates wrappers are invoked)

4. **Which syscall failed?**
   - Look for: `[WRAP_SOCKET] FAILED:` or `[WRAP_BIND] FAILED:` or `[WRAP_LISTEN] FAILED:`
   - Note the errno value

5. **What's the errno name?**
   - Cross-reference with error table above
   - Determine what the error means

## 🔧 Diagnostic Tools Available

### 1. Socket Wrapper Debug Output
Location: `syscall_wrappers.c`
- Logs all socket(), bind(), listen() calls
- Shows parameters and results
- Maps errno to readable names

### 2. Test Socket Program
Location: `test_socket.c`
- Can be compiled separately
- Tests socket syscalls in isolation
- Useful if compositor output is unclear

### 3. Main.c Socket Verification
Location: `main.c` lines 256-284
- Tests filesystem accessibility
- Tests file creation in XDG_RUNTIME_DIR
- Logs environment variables

## 📈 Diagnostic Workflow

```
System boots
    ↓
Compositor starts
    ↓
Check [WAYLAND-DEBUG] messages
    ├─ XDG_RUNTIME_DIR accessible? ✓
    ├─ Test file created? ✓
    └─ Calling wl_display_add_socket_auto()
        ↓
    Check [WRAP_SOCKET] messages
        ├─ Socket created? → Check fd value
        ├─ Bind attempted? → Check result
        └─ Listen attempted? → Check result
            ↓
        If all SUCCESS → Normal mode (ready for clients)
        If any FAILED → Note errno value
            ↓
        Demo mode activates
            ↓
        [WAYLAND] Demo mode: socket creation failed
        [WAYLAND] Frame scheduler stopped
        [WAYLAND] Demo rendering...
            ↓
        Display: 4-quadrant test pattern
            ├─ Top-left: Red
            ├─ Top-right: Green
            ├─ Bottom-left: Blue
            └─ Bottom-right: Yellow
```

## ✅ Verification Checklist

Before analysis, verify:

- [ ] System boots to Wayland compositor
- [ ] Display shows something (color test pattern or green)
- [ ] Console output is visible
- [ ] Can capture output to a log file
- [ ] Can search output for [WRAP_SOCKET] messages
- [ ] Can identify errno values
- [ ] Can cross-reference errno meanings

## 🎯 Expected Results This Session

### Best Case
- Socket creation succeeds
- Display shows compositor (no demo)
- Clients can connect

### Current Expected Case
- Socket creation fails
- Demo mode activates
- 4-quadrant test pattern displays (RED, GREEN, BLUE, YELLOW)
- errno value logged for analysis
- Next session: Fix based on errno

### Problem Case
- No socket messages appear → Wrapper not invoked
- Test file creation failed → Permission issue
- Framebuffer not accessible → GPU/display issue
- Screen stays green → Scheduler still interfering

## 📝 Documentation References

- **WAYLAND_COMPLETE_SESSION_LOG.md** - Full session history
- **WAYLAND_SESSION_2_SUMMARY.md** - Socket debugging work
- **WAYLAND_UI_ANALYSIS.md** - Architecture overview
- **WAYLAND_QUICK_REFERENCE.txt** - Quick lookup guide

## 🚀 Next Steps After Testing

### If EACCES (errno 13)
- Permission issue with /tmp
- Check /tmp directory permissions
- May need to use different runtime directory
- May need to fix Futura permissions system

### If EADDRINUSE (errno 48)
- Socket file already exists
- Previous compositor crashed without cleanup
- Solution: Remove old socket files

### If EINVAL (errno 22)
- Invalid arguments to syscall
- Check how socket addresses are constructed
- May need to review int 0x80 wrapper implementation

### If No WRAP_SOCKET Messages
- Wrappers not being invoked
- Linker wrapping not working
- Check --wrap linker flags
- May need to verify libwayland-server is using socket()

### If Test Pattern Displays Correctly
- Socket is the only remaining issue
- Display rendering works perfectly
- Frame scheduling fixed correctly
- Ready to debug socket layer

## 💡 Key Insights

1. **Demo mode is a success** - It means rendering works, just socket fails
2. **Test pattern validates rendering** - All color modes, framebuffer access, pixel format
3. **Errno is diagnostic gold** - Exact error number tells us the root cause
4. **Wrappers are the window** - Debug output shows what syscalls are being made

---

**Status**: System ready for testing with comprehensive diagnostic infrastructure
**Next Action**: Boot system and analyze socket creation error
**Preparation**: Complete - All tools in place
