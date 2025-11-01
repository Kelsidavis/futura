# Wayland Socket Creation - Master Implementation Guide

**Purpose**: Single unified guide for complete socket fix implementation

**Time**: ~1 hour total (30 min implementation + 30 min testing/validation)

**Target**: Fix EACCES (errno=13) socket creation error

---

## 🎯 Quick Navigation

- **5 min**: WAYLAND_QUICK_FIX_GUIDE.md (ultra-quick path)
- **15 min**: WAYLAND_CODE_MODIFICATION_CHECKLIST.md (detailed changes)
- **30 min**: This guide + WAYLAND_IMPLEMENTATION_TEMPLATE_EACCES.md (complete implementation)
- **45 min**: Include WAYLAND_SOCKET_FIX_VALIDATION.md (full validation)

---

## 📋 Complete Workflow

### Phase 1: Confirmation (5 minutes)

#### Step 1.1: Verify Error

Run compositor:
```bash
./build/bin/user/futura-wayland
```

Look for:
```
[WRAP_SOCKET] FAILED: EACCES (errno=13)
```

**Decision**:
- ✓ Found EACCES → Continue with this guide
- ✓ Different errno → Use different strategy
- ✓ Socket works → Skip to client testing

#### Step 1.2: Document Error

Record in notepad:
```
Error: EACCES (errno=13)
Time: _______________
Attempt: _______________
```

---

### Phase 2: Preparation (5 minutes)

#### Step 2.1: Create Backup

```bash
cd /home/k/futura
cp src/user/compositor/futura-wayland/main.c \
   src/user/compositor/futura-wayland/main.c.backup
```

#### Step 2.2: Open Files

Open in editor:
- `src/user/compositor/futura-wayland/main.c` (target file)
- WAYLAND_IMPLEMENTATION_TEMPLATE_EACCES.md (reference)

#### Step 2.3: Review Changes

Read the 3 modification sections:
- [ ] Modification 1: Helper functions (~40 lines)
- [ ] Modification 2: Initialization (~4 lines)
- [ ] Modification 3: Debug output (~1 line)

---

### Phase 3: Implementation (15 minutes)

#### Step 3.1: Add Helper Functions

**Location**: After `sys_mkdir` function (line 58-60)

**Action**: Copy `test_socket_directory()` function

**Code**:
```c
static int test_socket_directory(const char *path) {
    printf("[WAYLAND-DEBUG] Testing directory: %s\n", path);

    int fd = sys_open(path, 0, 0);
    if (fd < 0) {
        printf("[WAYLAND-DEBUG]   Not accessible\n");
        return 0;
    }
    sys_close(fd);
    printf("[WAYLAND-DEBUG]   Accessible\n");

    char test_path[512];
    snprintf(test_path, sizeof(test_path), "%s/.wayland-test-%d", path, getuid());

    int test_fd = sys_open(test_path, O_RDWR | O_CREAT, 0666);
    if (test_fd < 0) {
        printf("[WAYLAND-DEBUG]   Not writable\n");
        return 0;
    }
    sys_close(test_fd);
    printf("[WAYLAND-DEBUG]   Writable - GOOD!\n");

    return 1;
}
```

**Checklist**:
- [ ] Pasted correctly
- [ ] Placed before main()
- [ ] Indentation correct

#### Step 3.2: Add Second Helper Function

**Action**: Copy `find_working_runtime_dir()` function right after first one

**Code**:
```c
static const char *find_working_runtime_dir(void) {
    const char *candidates[] = {
        "/tmp",
        "/run",
        "/var/run",
        "/dev/shm",
        NULL
    };

    printf("[WAYLAND-DEBUG] Finding writable directory for sockets\n");

    for (int i = 0; candidates[i]; i++) {
        if (test_socket_directory(candidates[i])) {
            printf("[WAYLAND-DEBUG] ✓ Using runtime dir: %s\n", candidates[i]);
            return candidates[i];
        }
    }

    printf("[WAYLAND-DEBUG] WARNING: No ideal directory found, using /tmp\n");
    return "/tmp";
}
```

**Checklist**:
- [ ] Pasted correctly
- [ ] Right after first function
- [ ] Before main()

#### Step 3.3: Replace Initialization Code

**Location**: Around line 243-250

**Find**:
```c
    if (!getenv("XDG_RUNTIME_DIR")) {
        setenv("XDG_RUNTIME_DIR", "/tmp", 1);
    }
```

**Replace With**:
```c
    if (!getenv("XDG_RUNTIME_DIR")) {
        const char *runtime_dir = find_working_runtime_dir();
        setenv("XDG_RUNTIME_DIR", runtime_dir, 1);
    }
```

**Checklist**:
- [ ] Found old code
- [ ] Deleted all of it
- [ ] Pasted new code
- [ ] Indentation matches

#### Step 3.4: Save File

```bash
# Ctrl+S in editor, or:
# (file should auto-save, but verify)
```

**Checklist**:
- [ ] File saved
- [ ] No unsaved indicator

---

### Phase 4: Build (5 minutes)

#### Step 4.1: Clean Build

```bash
cd /home/k/futura
make clean
```

**Expected**:
```
rm -f build/bin/user/futura-wayland ...
```

**Checklist**:
- [ ] No errors
- [ ] Old binary removed

#### Step 4.2: Rebuild

```bash
make
```

**Expected**:
```
gcc ... main.c ...
gcc ... -o build/bin/user/futura-wayland
```

**Checklist**:
- [ ] No compilation errors
- [ ] No warnings about undefined references
- [ ] Binary created

#### Step 4.3: Verify Binary

```bash
file build/bin/user/futura-wayland
```

**Expected**:
```
build/bin/user/futura-wayland: ELF 64-bit LSB executable
```

**Checklist**:
- [ ] Binary is valid
- [ ] Correct format
- [ ] Executable

---

### Phase 5: Testing (10 minutes)

#### Step 5.1: Run Compositor

```bash
./build/bin/user/futura-wayland 2>&1 | tee socket-test.log
```

**Let it run for 10 seconds**, then Ctrl+C

**Checklist**:
- [ ] Process starts
- [ ] No immediate crash
- [ ] Output captured to log

#### Step 5.2: Check Output

```bash
grep -E "Finding|Testing|Using|SUCCESS|FAILED" socket-test.log
```

**Expected Output**:
```
[WAYLAND-DEBUG] Finding writable directory for sockets
[WAYLAND-DEBUG] Testing directory: /tmp
[WAYLAND-DEBUG]   Accessible
[WAYLAND-DEBUG]   Writable - GOOD!
[WAYLAND-DEBUG] ✓ Using runtime dir: /tmp
[WRAP_SOCKET] socket(1, 1, 0)
[WRAP_SOCKET] SUCCESS: fd=3
[WRAP_BIND] bind(fd=3, ...)
[WRAP_BIND] SUCCESS
[WRAP_LISTEN] listen(fd=3, ...)
[WRAP_LISTEN] SUCCESS
[WAYLAND] SUCCESS: auto socket created: wayland-0
```

**Checklist**:
- [ ] Directory testing shows
- [ ] At least one directory marked GOOD
- [ ] All syscalls show SUCCESS
- [ ] No FAILED messages

#### Step 5.3: Verify Socket File

```bash
ls -la /tmp/wayland*
```

**Expected**:
```
srw------- 1 user group 0 Nov  1 12:34 /tmp/wayland-0
```

**Checklist**:
- [ ] Socket file exists
- [ ] Has 's' type (socket)
- [ ] Right permissions
- [ ] Right owner

#### Step 5.4: Test with Test Program

```bash
./build/bin/test_socket
```

**Expected**:
```
[TEST_SOCKET] All tests passed!
```

**Checklist**:
- [ ] Program runs
- [ ] All tests pass
- [ ] No FAILED messages

---

### Phase 6: Validation (10 minutes)

Use WAYLAND_SOCKET_FIX_VALIDATION.md to do complete validation:

#### Quick Validation Checklist

- [ ] Level 1: Compilation (binary created, no errors)
- [ ] Level 2: Execution (compositor runs, shows SUCCESS messages)
- [ ] Level 3: Verification (socket file exists and works)

#### Full Validation Checklist

Follow all steps in WAYLAND_SOCKET_FIX_VALIDATION.md:
- [ ] 1.1 - 1.4: Compilation checks (4 items)
- [ ] 2.1 - 2.6: Execution checks (6 items)
- [ ] 3.1 - 3.5: Verification checks (5 items)

---

## 📊 Workflow Summary

| Phase | Task | Time | Status |
|-------|------|------|--------|
| 1 | Confirm EACCES error | 5 min | [ ] |
| 2 | Prepare (backup, review) | 5 min | [ ] |
| 3 | Implement code changes | 15 min | [ ] |
| 4 | Build | 5 min | [ ] |
| 5 | Test | 10 min | [ ] |
| 6 | Validate | 10 min | [ ] |
| **Total** | | **~50 min** | [ ] |

---

## 🎯 Implementation Checklist

### Pre-Implementation
- [ ] EACCES error confirmed
- [ ] Backup created
- [ ] Files opened in editor
- [ ] Template reviewed

### Code Changes
- [ ] test_socket_directory() added
- [ ] find_working_runtime_dir() added
- [ ] Initialization code replaced
- [ ] File saved

### Build & Test
- [ ] make clean succeeds
- [ ] make succeeds
- [ ] Binary created
- [ ] Compositor runs
- [ ] SUCCESS messages appear
- [ ] Socket file created
- [ ] Test program passes

### Validation
- [ ] All 3 compilation checks pass
- [ ] All 6 execution checks pass
- [ ] All 5 verification checks pass

---

## 🚨 Troubleshooting Guide

### Issue: Build fails

**Action**:
1. Check syntax exactly matches template
2. Run `make clean` and try again
3. Look for undefined reference errors

**Documents**: WAYLAND_CODE_MODIFICATION_CHECKLIST.md

### Issue: Still seeing EACCES error

**Action**:
1. Verify Modification 2 was done correctly
2. Check that initialization code calls function
3. Try test_socket.c to isolate issue

**Documents**: WAYLAND_ALTERNATIVE_SOCKET_STRATEGIES.md

### Issue: Socket file not created

**Action**:
1. Check all syscalls show SUCCESS
2. Verify permissions on directories
3. Check available disk space

**Documents**: WAYLAND_SOCKET_FIX_VALIDATION.md

---

## 📚 Related Documents (Quick Reference)

**For this guide**:
- WAYLAND_IMPLEMENTATION_TEMPLATE_EACCES.md - Detailed code
- WAYLAND_CODE_MODIFICATION_CHECKLIST.md - Exact file modifications
- WAYLAND_SOCKET_FIX_VALIDATION.md - Complete validation procedure

**For reference**:
- WAYLAND_DIAGNOSTIC_PREDICTION.md - Why EACCES is likely
- WAYLAND_SOCKET_FALLBACK_HANDLER.md - Strategy explanation
- WAYLAND_QUICK_FIX_GUIDE.md - Ultra-quick version

**For alternatives** (if this doesn't work):
- WAYLAND_ALTERNATIVE_SOCKET_STRATEGIES.md - Other approaches

---

## ✅ Success Indicators

### During Implementation
✓ Code compiles without errors
✓ Binary created successfully
✓ Compositor starts

### During Testing
✓ Directory testing messages appear
✓ All syscalls show SUCCESS
✓ Socket creation reported

### During Validation
✓ Socket file exists
✓ File has correct permissions
✓ Test program passes
✓ Display not all-green

---

## 🎓 What Each Change Does

**Helper Function 1: test_socket_directory()**
- Tests if directory is accessible (readable)
- Tests if directory is writable (can create files)
- Returns 1 if both work, 0 if either fails

**Helper Function 2: find_working_runtime_dir()**
- Tries: /tmp, /run, /var/run, /dev/shm
- Uses first one that passes both tests
- Falls back to /tmp if all fail

**Initialization Change**
- Instead of hardcoding "/tmp"
- Calls function to find working directory
- Sets XDG_RUNTIME_DIR to whatever actually works

**Result**: Socket creation works regardless of which directory is writable

---

## 📈 Timeline

```
Start: Run compositor, see EACCES error
       ↓ (5 min)
Confirmation: Error confirmed
       ↓ (5 min)
Preparation: Backup, review, open files
       ↓ (15 min)
Implementation: Copy code changes
       ↓ (5 min)
Build: Clean and rebuild
       ↓ (10 min)
Testing: Run and check output
       ↓ (10 min)
Validation: Full verification
       ↓
Success: Socket creation fixed! ✓✓✓
```

---

## 🎯 End Goal

When complete:
- ✅ EACCES error gone
- ✅ Socket created successfully
- ✅ Compositor ready for clients
- ✅ System ready for next phase

---

## 📝 Implementation Checklist (Copy & Track)

```
EACCES FIX IMPLEMENTATION CHECKLIST

Date Started: _______________
Status: [ ] Not Started [ ] In Progress [ ] Complete

PHASE 1: CONFIRMATION
[ ] Run compositor
[ ] See EACCES error
[ ] Document error

PHASE 2: PREPARATION
[ ] Create backup
[ ] Open files
[ ] Review template

PHASE 3: IMPLEMENTATION (15 minutes)
[ ] Add test_socket_directory()
[ ] Add find_working_runtime_dir()
[ ] Replace initialization code
[ ] Save file

PHASE 4: BUILD (5 minutes)
[ ] make clean (success)
[ ] make (success)
[ ] Binary created

PHASE 5: TESTING (10 minutes)
[ ] Compositor runs
[ ] Directory selection shown
[ ] All SUCCESS messages
[ ] Socket file created

PHASE 6: VALIDATION (10 minutes)
[ ] Compilation checks pass
[ ] Execution checks pass
[ ] Verification checks pass

OVERALL RESULT: [ ] SUCCESS [ ] FAILED

Time Taken: _______________
Notes: _______________
```

---

## 🚀 When You're Ready

1. Print this guide (or have it in second window)
2. Have WAYLAND_IMPLEMENTATION_TEMPLATE_EACCES.md open
3. Open main.c in editor
4. Follow Phase 3 step by step
5. When done, run Phase 4 build
6. Check output in Phase 5
7. Do full validation in Phase 6

**Estimated total time: 50 minutes**

---

**This is the complete unified guide for socket creation fix implementation.**

Follow it phase by phase. Reference other documents as needed. You'll have a working socket creation within one hour.
