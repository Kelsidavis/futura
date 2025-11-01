# Wayland Socket Fix - Validation Framework

**Purpose**: Complete validation procedure to confirm socket creation is fixed

**When to Use**: After implementing the fallback handler code

**Duration**: 5-10 minutes for complete validation

---

## 🎯 Validation Overview

Three levels of validation:

1. **Level 1: Compilation** - Code builds without errors
2. **Level 2: Execution** - Compositor starts and attempts socket
3. **Level 3: Verification** - Socket actually created and working

---

## 📋 Level 1: Compilation Validation

### Step 1.1: Clean Build

```bash
cd /home/k/futura
make clean
```

**Expected Output**:
```
rm -f build/bin/user/futura-wayland
```

**✓ Checklist**:
- [ ] No errors from make clean
- [ ] Previous binary removed

### Step 1.2: Rebuild

```bash
make
```

**Expected Output**:
```
gcc ... -c src/user/compositor/futura-wayland/main.c ...
gcc ... -c src/user/compositor/futura-wayland/comp.c ...
gcc ... -o build/bin/user/futura-wayland ...
```

**✓ Checklist**:
- [ ] No compilation errors
- [ ] No "undefined reference" warnings
- [ ] No "implicit declaration" warnings
- [ ] Binary created successfully

### Step 1.3: Binary Verification

```bash
file build/bin/user/futura-wayland
```

**Expected Output**:
```
build/bin/user/futura-wayland: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, with debug_info, not stripped
```

**✓ Checklist**:
- [ ] File is ELF 64-bit executable
- [ ] Not corrupted
- [ ] Contains debug symbols

### Step 1.4: Check Executable

```bash
ls -lh build/bin/user/futura-wayland
```

**Expected Output**:
```
-rwxrwxr-x 1 user group 589K Nov  1 12:34 build/bin/user/futura-wayland
```

**✓ Checklist**:
- [ ] File size ~576-600 KB
- [ ] Executable bit set (x)
- [ ] Recent timestamp

---

## 📋 Level 2: Execution Validation

### Step 2.1: Run Compositor

```bash
./build/bin/user/futura-wayland 2>&1 | tee wayland-test-run.log
```

**Expected Output** (first part):
```
[COMPOSITOR] Reached main, stdio initialized
[WAYLAND-DEBUG] About to call comp_state_init()...
[WAYLAND-DEBUG] comp_state_init() succeeded
```

**✓ Checklist**:
- [ ] Process starts without immediate crash
- [ ] Initialization messages appear
- [ ] No "Segmentation fault" errors

### Step 2.2: Check Directory Testing

**Look for**:
```
[WAYLAND-DEBUG] Finding writable directory for sockets
[WAYLAND-DEBUG] Testing directory: /tmp
[WAYLAND-DEBUG]   Accessible
[WAYLAND-DEBUG]   Writable - GOOD!
[WAYLAND-DEBUG] ✓ Using runtime dir: /tmp
```

**✓ Checklist**:
- [ ] Directory testing code is executing
- [ ] At least one directory reported as writable
- [ ] Shows which directory was chosen
- [ ] Matches one of: /tmp, /run, /var/run, /dev/shm

### Step 2.3: Check Socket Syscalls

**Look for**:
```
[WRAP_SOCKET] socket(1, 1, 0)
[WRAP_SOCKET] SUCCESS: fd=3
```

**✓ Checklist**:
- [ ] socket() syscall is being attempted
- [ ] Returns fd=3 (or similar positive number)
- [ ] Not showing FAILED with errno

### Step 2.4: Check Bind Syscall

**Look for**:
```
[WRAP_BIND] bind(fd=3, addr=..., addrlen=110)
[WRAP_BIND] SUCCESS
```

**✓ Checklist**:
- [ ] bind() is called after socket()
- [ ] Uses fd from socket()
- [ ] Shows SUCCESS (not FAILED)

### Step 2.5: Check Listen Syscall

**Look for**:
```
[WRAP_LISTEN] listen(fd=3, backlog=1)
[WRAP_LISTEN] SUCCESS
```

**✓ Checklist**:
- [ ] listen() is called after bind()
- [ ] Shows SUCCESS (not FAILED)
- [ ] No errno values shown

### Step 2.6: Check Final Status

**Look for**:
```
[WAYLAND] SUCCESS: auto socket created: wayland-0
[WAYLAND] compositor ready 1024x768 bpp=32 socket=wayland-0
```

**✓ Checklist**:
- [ ] Socket name shows (wayland-0, wayland-1, etc.)
- [ ] Compositor shows ready message
- [ ] No ERROR or FAILED keywords

---

## 📋 Level 3: Verification Validation

### Step 3.1: Check Socket File

**Stop compositor** (Ctrl+C)

**Run**:
```bash
ls -la /tmp/wayland*
```

**Expected Output**:
```
srw------- 1 user group 0 Nov  1 12:34 /tmp/wayland-0
```

(Socket file shown with 's' for socket type)

**✓ Checklist**:
- [ ] Socket file exists in correct directory
- [ ] File type is 's' (socket)
- [ ] Correct permissions (readable by user)
- [ ] Has today's date/time

### Step 3.2: Check File Permissions

**Run**:
```bash
stat /tmp/wayland-0
```

**Expected Output**:
```
File: /tmp/wayland-0
Size: 0       Blocks: 0
Access: (0700/srwx------)
Uid: ( 1000/   user)   Gid: ( 1000/   user)
```

**✓ Checklist**:
- [ ] Size is 0 (Unix socket doesn't use disk space)
- [ ] File type is 's' (socket)
- [ ] Permissions are 0700 (user only)
- [ ] Owner is current user

### Step 3.3: Check with Test Socket Program

**Compile test program**:
```bash
gcc -o /tmp/test_socket src/user/compositor/futura-wayland/test_socket.c
```

**Run test**:
```bash
/tmp/test_socket
```

**Expected Output**:
```
[TEST_SOCKET] Testing int 0x80 socket syscalls
[TEST_SOCKET] Test 1: Creating AF_UNIX SOCK_STREAM socket
[TEST_SOCKET] SUCCESS: socket fd=3
[TEST_SOCKET] Test 2: Binding to socket path
[TEST_SOCKET] SUCCESS: bind() succeeded
[TEST_SOCKET] Test 3: Listening on socket
[TEST_SOCKET] SUCCESS: listen() succeeded
[TEST_SOCKET] All tests passed!
```

**✓ Checklist**:
- [ ] Test program compiles
- [ ] All three tests pass
- [ ] No FAILED messages
- [ ] Returns 0 (success)

### Step 3.4: Verify Compositor Display

**Run compositor again**:
```bash
./build/bin/user/futura-wayland
```

**Check Display**:
- Should NOT show all-green screen
- Should show compositor or test pattern
- If it shows green: scheduler still interfering (different issue)

**✓ Checklist**:
- [ ] Display is not solid green
- [ ] Shows meaningful content
- [ ] No visual glitches

### Step 3.5: Check Environment Variables

**In compositor output**, look for:
```
[WAYLAND-DEBUG] XDG_RUNTIME_DIR now set to: /tmp
```

**Run** (while compositor running in another terminal):
```bash
echo $XDG_RUNTIME_DIR
```

**Expected Output**:
```
/tmp
```

(Or whichever directory was chosen)

**✓ Checklist**:
- [ ] XDG_RUNTIME_DIR is set
- [ ] Points to correct directory
- [ ] Matches what compositor reported

---

## 🎯 Validation Summary Matrix

| Validation Level | Component | Expected | Actual | Status |
|-----------------|-----------|----------|--------|--------|
| 1.1 | Clean build | No errors | | [ ] |
| 1.2 | Compilation | No errors | | [ ] |
| 1.3 | Binary type | ELF 64-bit | | [ ] |
| 1.4 | Binary size | ~576-600 KB | | [ ] |
| 2.1 | Startup | Initializes | | [ ] |
| 2.2 | Directory test | Shows testing | | [ ] |
| 2.3 | Socket syscall | SUCCESS | | [ ] |
| 2.4 | Bind syscall | SUCCESS | | [ ] |
| 2.5 | Listen syscall | SUCCESS | | [ ] |
| 2.6 | Final message | AUTO socket created | | [ ] |
| 3.1 | Socket file | Exists | | [ ] |
| 3.2 | File permissions | 0700 socket | | [ ] |
| 3.3 | Test program | All pass | | [ ] |
| 3.4 | Display | Not green | | [ ] |
| 3.5 | Environment | XDG_RUNTIME_DIR set | | [ ] |

---

## 🚨 Common Validation Failures

### Failure: Build errors

**Symptom**: Compilation fails with undefined reference

**Check**:
1. Are helper functions in correct location?
2. Are they before main()?
3. Is syntax exactly correct?

**Fix**:
1. Re-read WAYLAND_CODE_MODIFICATION_CHECKLIST.md
2. Copy functions again exactly
3. Rebuild with make clean first

### Failure: [WRAP_SOCKET] FAILED still appears

**Symptom**: Still seeing EACCES error

**Check**:
1. Did you modify the initialization code?
2. Is find_working_runtime_dir() being called?
3. Are all candidate directories really blocked?

**Fix**:
1. Verify modification 2 was done
2. Check that initialization code calls the function
3. Try running test_socket.c standalone
4. Check system mount permissions

### Failure: No directory testing messages

**Symptom**: Don't see [WAYLAND-DEBUG] messages from testing

**Check**:
1. Are DEBUG_WAYLAND flags enabled?
2. Is code being executed?
3. Are printf messages going to stdout?

**Fix**:
1. Run with: `./build/bin/user/futura-wayland 2>&1 | tee output.log`
2. Check if any debug messages appear
3. May need to rebuild with debug flags

### Failure: Socket file not created

**Symptom**: No /tmp/wayland-0 file after compositor runs

**Check**:
1. Did socket syscalls show SUCCESS?
2. Is directory really writable?
3. Is permissions issue deeper?

**Fix**:
1. Create /tmp manually
2. Check /tmp is mounted
3. Try different directory
4. Check disk space: df /tmp

### Failure: Display still shows all green

**Symptom**: Socket works but display is green

**Check**:
1. Is this the expected behavior?
2. Is scheduler actually stopping?
3. Are demo patterns rendering?

**Fix**:
1. This might be separate issue
2. Check WAYLAND_SESSION_MASTER_SUMMARY.md for display fix status
3. Scheduler stop should happen at main.c:349

---

## ✅ Complete Validation Checklist

**Pre-Fix**:
- [ ] Error confirmed: EACCES (errno=13)
- [ ] Code changes planned
- [ ] Backup created: main.c.backup

**Compilation**:
- [ ] make clean succeeds
- [ ] make succeeds (no errors)
- [ ] Binary created (589 KB)

**Execution**:
- [ ] Compositor starts
- [ ] Directory testing appears
- [ ] Socket syscalls show SUCCESS
- [ ] Bind shows SUCCESS
- [ ] Listen shows SUCCESS
- [ ] Final message shows socket created

**Verification**:
- [ ] Socket file exists in filesystem
- [ ] Socket has correct permissions
- [ ] Test program works
- [ ] Display is not all-green
- [ ] XDG_RUNTIME_DIR is set

---

## 🎯 Success Criteria

All three levels must pass:

**Level 1: ✓ Code compiles**
- Build completes without errors
- Binary is created and executable

**Level 2: ✓ Compositor runs**
- All syscalls show SUCCESS
- No FAILED messages
- Socket creation reported

**Level 3: ✓ Socket works**
- File exists in filesystem
- Can be verified with ls
- Test program confirms functionality

---

## 📊 Validation Report Template

Use this to document your validation:

```
=== WAYLAND SOCKET FIX VALIDATION REPORT ===

Date: _______________
System: _______________

LEVEL 1: COMPILATION
[ ] make clean: PASS
[ ] make: PASS
[ ] Binary created: build/bin/user/futura-wayland
[ ] Size: ________ bytes

LEVEL 2: EXECUTION
[ ] Compositor starts
[ ] Directory selection: _________________
[ ] [WRAP_SOCKET] SUCCESS: ✓
[ ] [WRAP_BIND] SUCCESS: ✓
[ ] [WRAP_LISTEN] SUCCESS: ✓
[ ] Socket creation message: ✓

LEVEL 3: VERIFICATION
[ ] Socket file exists at: _______________
[ ] File permissions: _______________
[ ] Test program: PASS
[ ] Display: Not green ✓

OVERALL RESULT: _____ PASSED / FAILED

Notes:
_________________________________
_________________________________
```

---

## 📈 Validation Efficiency

- **Quick validation**: 5 minutes (just check output)
- **Full validation**: 10 minutes (all checks)
- **Documented validation**: 15 minutes (with report)

---

## 🔗 Related Documentation

- **WAYLAND_QUICK_FIX_GUIDE.md** - 5-minute implementation
- **WAYLAND_CODE_MODIFICATION_CHECKLIST.md** - Detailed changes
- **WAYLAND_IMPLEMENTATION_TEMPLATE_EACCES.md** - Code details
- **WAYLAND_TESTING_GUIDE.md** - Original testing guide

---

## 📞 If Validation Fails

1. **Check each level independently** - Don't skip ahead
2. **Document exactly what failed** - "Level 2.3 failed: FAILED in output"
3. **Compare to expected output** - Exact match required
4. **Re-read the modification checklist** - Likely missed a step
5. **Ask for help** - If stuck on a specific failure

---

**Follow this validation framework to confirm socket fix is complete.**

Success = All 3 levels pass + All checklist items checked.
