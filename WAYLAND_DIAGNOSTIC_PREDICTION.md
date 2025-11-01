# Wayland Socket Creation - Diagnostic Prediction Guide

**Purpose**: Predict what could go wrong and how to diagnose based on actual output

**Status**: Ready for testing phase - this guide will help interpret results

---

## 🔍 Analysis of Socket Creation Code Path

### Syscall Parameters Being Passed

```c
// From syscall_wrappers.c:244-255
int __wrap_socket(int domain, int type, int protocol) {
    int type_masked = type & 0xF;  // Strip SOCK_CLOEXEC, SOCK_NONBLOCK
    long result = int80_socket(domain, type_masked, protocol);

    // int80_socket uses:
    // RDI = domain (should be 1 for AF_UNIX)
    // RSI = type (should be 1 for SOCK_STREAM)
    // RDX = protocol (should be 0)
}
```

**Expected call**: `socket(AF_UNIX=1, SOCK_STREAM=1, protocol=0)`

### Kernel Side - Register Extraction

From `platform/x86_64/isr_stubs.S:154-174`, kernel extracts from saved registers:
```
movq 40(%rsp), %rsi       # arg1 = saved RDI
movq 32(%rsp), %rdx       # arg2 = saved RSI
movq 24(%rsp), %rcx       # arg3 = saved RDX
```

**This is correct** - registers are being passed correctly.

---

## 📊 Predicted Error Scenarios

### Scenario 1: EACCES (errno=13) - Permission Denied ✓ LIKELY

**Symptoms**:
```
[WRAP_SOCKET] socket(1, 1, 0)
[WRAP_SOCKET] FAILED: EACCES (errno=13)
```

**Root Cause**: Permission issue with /tmp directory
- /tmp might have wrong permissions
- /tmp might be owned by wrong user
- Filesystem might be read-only
- SELinux/AppArmor might be blocking

**Evidence to Look For**:
```
[WAYLAND-DEBUG] XDG_RUNTIME_DIR=/tmp
[WAYLAND-DEBUG] XDG_RUNTIME_DIR accessible  ← May fail
[WAYLAND-DEBUG] WARNING: Could not create test file  ← Will fail
```

**Probability**: **HIGH** (40%)
- This is the most common socket creation failure
- Especially likely in restricted environments like QEMU

**Fix Strategy**:
1. Check /tmp permissions: `ls -ld /tmp`
2. Change XDG_RUNTIME_DIR to different path
3. Fix /tmp permissions
4. Create alternative temporary directory

---

### Scenario 2: EADDRINUSE (errno=48) - Address Already in Use

**Symptoms**:
```
[WRAP_SOCKET] socket(1, 1, 0)
[WRAP_SOCKET] SUCCESS: fd=3
[WRAP_BIND] bind(fd=3, ...)
[WRAP_BIND] FAILED: EADDRINUSE (errno=48)
```

**Root Cause**: Socket file already exists at path
- Previous compositor crash left socket file
- Old socket file not cleaned up
- Multiple instances trying to use same socket path

**Evidence to Look For**:
```
[WAYLAND-DEBUG] Test file created successfully  ← Socket might be possible
[WRAP_SOCKET] SUCCESS  ← socket() works
[WRAP_BIND] FAILED: EADDRINUSE  ← bind() fails
```

**Probability**: **MEDIUM** (25%)
- Possible if system was tested before
- Socket cleanup not guaranteed on crash

**Fix Strategy**:
1. Check for leftover socket files: `ls /tmp/wayland* 2>/dev/null`
2. Remove old socket files: `rm /tmp/wayland*`
3. Implement socket cleanup at startup
4. Try different socket name

---

### Scenario 3: EINVAL (errno=22) - Invalid Argument

**Symptoms**:
```
[WRAP_SOCKET] socket(1, 1, 0)
[WRAP_SOCKET] FAILED: EINVAL (errno=22)
```

**Root Cause**: Invalid parameters to socket() syscall
- Domain value wrong (1 is correct for AF_UNIX)
- Type value wrong (1 is correct for SOCK_STREAM)
- Register passing broken
- Syscall number wrong

**Evidence to Look For**:
```
[WRAP_SOCKET] socket(1, 1, 0)  ← Parameters look right but fail
[WAYLAND-DEBUG] Test file created successfully  ← File creation works
```

**Probability**: **LOW** (10%)
- Code has been verified for correct register layout
- Unlikely unless QEMU bug

**Fix Strategy**:
1. Verify syscall numbers are correct
2. Check register passing in int80_socket()
3. Test with standalone test_socket.c program
4. Verify QEMU int 0x80 support

---

### Scenario 4: ENOENT (errno=2) - No Such File

**Symptoms**:
```
[WRAP_SOCKET] socket(1, 1, 0)
[WRAP_SOCKET] SUCCESS: fd=3
[WRAP_BIND] bind(fd=3, ...)
[WRAP_BIND] FAILED: ENOENT (errno=2)
```

**Root Cause**: Runtime directory doesn't exist
- /tmp doesn't exist (very unlikely)
- XDG_RUNTIME_DIR path doesn't exist
- Parent directory of socket doesn't exist

**Evidence to Look For**:
```
[WAYLAND-DEBUG] XDG_RUNTIME_DIR=/tmp
[WAYLAND-DEBUG] XDG_RUNTIME_DIR NOT accessible  ← Clear warning
[WAYLAND-DEBUG] WARNING: Could not create test file
[WRAP_SOCKET] SUCCESS  ← socket() works
[WRAP_BIND] FAILED: ENOENT  ← bind() fails on non-existent path
```

**Probability**: **VERY LOW** (5%)
- /tmp is created during boot
- Very unlikely in normal operation

**Fix Strategy**:
1. Verify /tmp exists: `test -d /tmp`
2. Create /tmp if missing: `mkdir -p /tmp`
3. Check directory permissions

---

### Scenario 5: Socket Creation Succeeds! ✓

**Symptoms**:
```
[WRAP_SOCKET] socket(1, 1, 0)
[WRAP_SOCKET] SUCCESS: fd=3
[WRAP_BIND] bind(fd=3, ...)
[WRAP_BIND] SUCCESS
[WRAP_LISTEN] listen(fd=3, backlog=1)
[WRAP_LISTEN] SUCCESS
[WAYLAND] SUCCESS: auto socket created: wayland-0
[WAYLAND] compositor ready 1024x768 bpp=32 socket=wayland-0
```

**Root Cause**: Everything works!

**Evidence**:
```
All [WRAP_*] calls show SUCCESS
No FAILED messages
No errno values
Display shows compositor (not demo pattern)
```

**Probability**: **MEDIUM-HIGH** (20%)
- Code appears correct
- Might just work

**Result**:
- Compositor ready for clients
- No need for socket fix
- Can proceed to client testing

---

## 🎯 Decision Tree for Diagnosis

```
Run: ./build/bin/user/futura-wayland

Did you see [WRAP_SOCKET] messages?
├─ NO → Wrappers not invoked
│       Problem: Linker wrapping not working
│       Check: Makefile linker flags, --wrap socket
│
└─ YES → Proceed to error analysis
    │
    Did [WRAP_SOCKET] say SUCCESS?
    ├─ NO → socket() syscall failed
    │       Check the errno value:
    │       ├─ errno=13 (EACCES) → Permission issue with /tmp
    │       ├─ errno=22 (EINVAL) → Invalid parameters
    │       ├─ errno=2 (ENOENT) → /tmp doesn't exist
    │       └─ Other → Consult strerror_simple() mapping
    │
    └─ YES → socket() succeeded, check bind()
        │
        Did [WRAP_BIND] say SUCCESS?
        ├─ NO → bind() syscall failed
        │       Check the errno value:
        │       ├─ errno=48 (EADDRINUSE) → Socket file exists
        │       ├─ errno=13 (EACCES) → Permission on /tmp
        │       └─ Other → Different issue
        │
        └─ YES → bind() succeeded, check listen()
            │
            Did [WRAP_LISTEN] say SUCCESS?
            ├─ NO → listen() syscall failed
            │       Rare - check errno
            │
            └─ YES → Socket creation complete!
                    Compositor should be ready
```

---

## 📋 What to Capture and Record

### During Test, Look For:

1. **[WAYLAND-DEBUG] messages** - Tell you system state
   ```
   [WAYLAND-DEBUG] XDG_RUNTIME_DIR=<path>
   [WAYLAND-DEBUG] XDG_RUNTIME_DIR accessible/NOT accessible
   [WAYLAND-DEBUG] Test file created/Could not create test file
   ```

2. **[WRAP_SOCKET] messages** - Tell you socket() result
   ```
   [WRAP_SOCKET] socket(1, 1, 0)
   [WRAP_SOCKET] SUCCESS: fd=<n>  OR  FAILED: <NAME> (errno=<n>)
   ```

3. **[WRAP_BIND] messages** - Tell you bind() result
   ```
   [WRAP_BIND] bind(fd=<n>, ...)
   [WRAP_BIND] SUCCESS  OR  FAILED: <NAME> (errno=<n>)
   ```

4. **[WRAP_LISTEN] messages** - Tell you listen() result
   ```
   [WRAP_LISTEN] listen(fd=<n>, backlog=1)
   [WRAP_LISTEN] SUCCESS  OR  FAILED: <NAME> (errno=<n>)
   ```

5. **Final message** - Tells you the outcome
   ```
   [WAYLAND] SUCCESS: auto socket created: <name>  ← Works!
   OR
   [WAYLAND] Demo mode: socket creation failed     ← Doesn't work
   ```

6. **Display state**
   ```
   4-quadrant test pattern → Demo mode (socket failed)
   Compositor display → Socket works
   All-green → Scheduler interference (shouldn't happen)
   ```

---

## 🔧 Quick Diagnosis Flowchart

```
Are you seeing [WRAP_SOCKET] output?
│
├─ NO (No socket messages at all)
│  └─ Action: Check linker configuration
│
└─ YES (Seeing [WRAP_SOCKET] line)
   │
   ├─ [WRAP_SOCKET] SUCCESS: fd=3
   │  └─ socket() works! Now check bind()
   │     │
   │     ├─ [WRAP_BIND] FAILED: EADDRINUSE
   │     │  └─ Action: rm /tmp/wayland* && retry
   │     │
   │     └─ [WRAP_BIND] SUCCESS
   │        └─ Now check listen()
   │           └─ Should see: [WRAP_LISTEN] SUCCESS
   │              └─ Result: Compositor ready!
   │
   └─ [WRAP_SOCKET] FAILED: <ERROR>
      │
      └─ Check errno value:
         ├─ errno=13 (EACCES)
         │  └─ Action: Check /tmp permissions, change runtime dir
         │
         ├─ errno=22 (EINVAL)
         │  └─ Action: Debug register passing, test test_socket.c
         │
         ├─ errno=2 (ENOENT)
         │  └─ Action: mkdir -p /tmp, check path
         │
         └─ Other
            └─ Action: Cross-reference with strerror_simple() mapping
```

---

## 🧪 Test Program Results Interpretation

### Running test_socket.c

```bash
# Compile and run test program
./build/bin/test_socket
```

**Output Interpretation**:

**If it succeeds**:
```
[TEST_SOCKET] Test 1: Creating AF_UNIX SOCK_STREAM socket
[TEST_SOCKET] SUCCESS: socket fd=3
[TEST_SOCKET] Test 2: Binding to socket path
[TEST_SOCKET] SUCCESS: bind() succeeded
[TEST_SOCKET] Test 3: Listening on socket
[TEST_SOCKET] SUCCESS: listen() succeeded
[TEST_SOCKET] All tests passed!
```

→ This means int 0x80 syscalls work perfectly

**If it fails same way as compositor**:
```
[TEST_SOCKET] Test 1: Creating AF_UNIX SOCK_STREAM socket
[TEST_SOCKET] SUCCESS: socket fd=3
[TEST_SOCKET] Test 2: Binding to socket path
[TEST_SOCKET] FAILED: bind() returned -1, errno=48
```

→ This confirms the problem is reproducible in isolation
→ Easier to debug without compositor complexity

---

## 📊 Probability Assessment

**Most Likely Outcome** (if I had to guess):
- **errno=13 (EACCES)** - 40% probability
  - /tmp or socket directory has permission issues
  - Most common socket creation failure in QEMU
  - Fix: Change XDG_RUNTIME_DIR or adjust permissions

**Secondary Likely Outcome**:
- **Socket creation succeeds** - 20% probability
  - Code looks correct
  - Wrappers implemented correctly
  - Could just work!

**Third Likely Outcome**:
- **errno=48 (EADDRINUSE)** - 15% probability
  - If system was tested before
  - Old socket file lingering

**Less Likely**:
- **errno=22 (EINVAL)** - 10%
- **errno=2 (ENOENT)** - 5%
- **Other errors** - 10%

---

## 🎯 Action Plan Based on Output

### If errno=13 (EACCES):

```bash
# Step 1: Check /tmp permissions
ls -ld /tmp

# Step 2: If not 1777, fix it
chmod 1777 /tmp

# Step 3: Verify with test file
touch /tmp/test && echo "writable" || echo "not writable"

# Step 4: If still fails, use different directory
export XDG_RUNTIME_DIR=/home/wayland
mkdir -p $XDG_RUNTIME_DIR
chmod 700 $XDG_RUNTIME_DIR

# Step 5: Try again
./build/bin/user/futura-wayland
```

### If errno=48 (EADDRINUSE):

```bash
# Step 1: Find and remove socket files
find /tmp -name "wayland*" -delete

# Step 2: Try again
./build/bin/user/futura-wayland

# Step 3: If still fails, try different socket name
# Edit main.c to use different name in wl_display_add_socket()
```

### If Success (No Errors):

```bash
# Step 1: Verify socket file exists
ls -la /tmp/wayland-*

# Step 2: Try connecting a client
# (Depends on having Wayland clients available)

# Step 3: Celebrate! ✓
```

---

## 🔍 Deep Dive: Why EACCES is Most Likely

1. **QEMU Environment**: Sandboxed with restricted permissions
2. **/tmp Permissions**: Often set to 755 instead of 1777 in restricted VMs
3. **Socket File Creation**: Requires write+execute on directory
4. **No Direct Error**: System doesn't tell why it failed
5. **Common Issue**: Appears in many QEMU-based systems

**Evidence**:
- Test file creation might fail: `[WAYLAND-DEBUG] WARNING: Could not create test file`
- Socket syscall itself might not fail, but bind() could
- XDG_RUNTIME_DIR might not be accessible

**Solution Path**:
1. Identify permission issue via test file failure
2. Change to writable directory
3. Update XDG_RUNTIME_DIR
4. Test again

---

## 📝 Summary

| Scenario | Probability | Key Indicator | First Action |
|----------|------------|---------------|--------------|
| EACCES | 40% | `errno=13` or test file fails | Check /tmp permissions |
| Socket Works | 20% | No errors, compositor ready | Celebrate! |
| EADDRINUSE | 15% | `errno=48` on bind() | Remove old socket files |
| EINVAL | 10% | `errno=22` on socket() | Test test_socket.c |
| ENOENT | 5% | `errno=2` on bind() | mkdir -p path |
| No Output | 10% | No [WRAP_SOCKET] | Check linker flags |

---

**This guide will be refined based on actual test results in the next phase.**

The diagnostic infrastructure is complete. The next step is to run the system and capture the actual errno value, which will definitively guide the fix.
