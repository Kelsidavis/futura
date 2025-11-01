# Wayland Socket Fix - Code Modification Checklist

**File**: `src/user/compositor/futura-wayland/main.c`
**Changes**: 3 sections, ~50 lines total
**Time**: 15-20 minutes
**Difficulty**: LOW (mostly copy/paste)

---

## 📋 Pre-Flight Checklist

- [ ] Error confirmed to be EACCES (errno=13)
- [ ] Read WAYLAND_QUICK_FIX_GUIDE.md
- [ ] Have WAYLAND_IMPLEMENTATION_TEMPLATE_EACCES.md open for reference
- [ ] Opened main.c in editor
- [ ] Made backup copy: `cp main.c main.c.backup`

---

## 🔧 Modification 1: Add Helper Functions

**Location**: After `sys_mkdir` function (around line 58-60)

**Current Code**:
```c
static inline int sys_mkdir(const char *pathname, int mode) {
    return (int)syscall3(__NR_mkdir, (long)pathname, mode, 0);
}

int main(void) {
```

**Action**: Insert helper functions between `sys_mkdir` and `int main`

**Code to Add** (Part 1 of 2):
```c
/* Helper: Test if directory is writable for sockets */
static int test_socket_directory(const char *path) {
    /* Test 1: Can we access the directory? */
    printf("[WAYLAND-DEBUG] Testing directory: %s\n", path);

    int fd = sys_open(path, 0, 0);
    if (fd < 0) {
        printf("[WAYLAND-DEBUG]   Not accessible\n");
        return 0;
    }
    sys_close(fd);
    printf("[WAYLAND-DEBUG]   Accessible\n");

    /* Test 2: Can we create a file there? */
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

/* Helper: Find first writable directory for Wayland sockets */
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

    /* Last resort */
    printf("[WAYLAND-DEBUG] WARNING: No ideal dir found, using /tmp\n");
    return "/tmp";
}

```

**Checklist**:
- [ ] Pasted both functions
- [ ] Spacing looks correct (no extra blank lines)
- [ ] No syntax errors visible
- [ ] Located right before `int main(void)`

---

## 🔧 Modification 2: Replace XDG_RUNTIME_DIR Initialization

**Location**: Inside `main()`, around line 243-250

**Current Code**:
```c
    /* Ensure XDG_RUNTIME_DIR is set for Wayland socket creation */
    if (!getenv("XDG_RUNTIME_DIR")) {
        /* Use /tmp as runtime directory for Wayland sockets */
#ifdef DEBUG_WAYLAND
        printf("[WAYLAND-DEBUG] Setting XDG_RUNTIME_DIR=/tmp\n");
#endif
        setenv("XDG_RUNTIME_DIR", "/tmp", 1);
    }
```

**Action**: Replace the entire block above with:

**New Code**:
```c
    /* Ensure XDG_RUNTIME_DIR is set for Wayland socket creation */
    if (!getenv("XDG_RUNTIME_DIR")) {
        /* Find a working directory for Wayland sockets */
        const char *runtime_dir = find_working_runtime_dir();
        setenv("XDG_RUNTIME_DIR", runtime_dir, 1);
    }
```

**Steps**:
1. [ ] Found the old code block
2. [ ] Selected all 7 lines (ifdef to setenv line)
3. [ ] Deleted the old block
4. [ ] Pasted new 4-line block
5. [ ] Indentation matches surrounding code

---

## 🔧 Modification 3: Add Debug Output (Optional but Recommended)

**Location**: Around line 271 (before `wl_display_add_socket_auto`)

**Current Code**:
```c
    printf("[WAYLAND-DEBUG] Calling wl_display_add_socket_auto()\n");
    printf("[WAYLAND-DEBUG] Environment: WAYLAND_DISPLAY=%s\n", getenv("WAYLAND_DISPLAY"));
    printf("[WAYLAND-DEBUG] Temp file check: touching test file in %s\n", runtime_dir);
```

**Action**: Add one line before the first printf:

**Code to Add**:
```c
    printf("[WAYLAND-DEBUG] XDG_RUNTIME_DIR now set to: %s\n", getenv("XDG_RUNTIME_DIR"));
```

**Steps**:
1. [ ] Found the "Calling wl_display_add_socket_auto" line
2. [ ] Added new printf line right before it
3. [ ] Indentation matches

---

## 📝 Summary of Changes

| Change | Type | Lines | Status |
|--------|------|-------|--------|
| Add test_socket_directory | Function | ~25 | [ ] |
| Add find_working_runtime_dir | Function | ~20 | [ ] |
| Replace initialization | Code | ~4 | [ ] |
| Add debug output | Debug | 1 | [ ] |
| **Total** | | **~50** | [ ] |

---

## ✅ Verification Checklist

After all modifications:

- [ ] File saved
- [ ] No syntax errors (run `make clean` to check)
- [ ] All indentation consistent
- [ ] Helper functions defined before `main()`
- [ ] `find_working_runtime_dir()` called in XDG_RUNTIME_DIR block
- [ ] All strings match exactly (including formatting)

---

## 🔨 Build Verification

```bash
cd /home/k/futura
make clean
```

Expected output:
```
rm -f build/bin/user/futura-wayland ...
```

```bash
make
```

Expected output:
```
gcc ... main.c ...
[no errors]
build/bin/user/futura-wayland created
```

- [ ] Build completes without errors
- [ ] No "undefined reference" warnings
- [ ] Binary created at build/bin/user/futura-wayland

---

## 🧪 Test Verification

```bash
./build/bin/user/futura-wayland
```

Expected output (in order):
```
[WAYLAND-DEBUG] Finding writable directory for sockets
[WAYLAND-DEBUG] Testing directory: /tmp
[WAYLAND-DEBUG]   Accessible
[WAYLAND-DEBUG]   Writable - GOOD!
[WAYLAND-DEBUG] ✓ Using runtime dir: /tmp
[WAYLAND-DEBUG] XDG_RUNTIME_DIR now set to: /tmp
[WRAP_SOCKET] socket(1, 1, 0)
[WRAP_SOCKET] SUCCESS: fd=3
[WRAP_BIND] bind(fd=3, ...)
[WRAP_BIND] SUCCESS
[WRAP_LISTEN] listen(fd=3, ...)
[WRAP_LISTEN] SUCCESS
[WAYLAND] SUCCESS: auto socket created: wayland-0
[WAYLAND] compositor ready 1024x768 bpp=32 socket=wayland-0
```

- [ ] All directory testing messages appear
- [ ] "✓ Using runtime dir:" shows which directory worked
- [ ] All [WRAP_*] messages show SUCCESS
- [ ] Final message shows socket created
- [ ] No ERROR or FAILED messages

---

## 🎯 Success Confirmation

When you see all three SUCCESS messages:
```
[WRAP_SOCKET] SUCCESS: fd=3
[WRAP_BIND] SUCCESS
[WRAP_LISTEN] SUCCESS
```

✓ **The fix worked!**

Socket creation is now working. Next step: test with Wayland clients.

---

## 🐛 Common Mistakes & Fixes

| Mistake | Symptom | Fix |
|---------|---------|-----|
| Forgot to save file | Build uses old code | Save before running make |
| Pasted functions in wrong place | Syntax error near main | Move functions before main() |
| Didn't replace all old code | Duplicate/conflicting code | Delete ALL of old block |
| Indentation wrong | Code looks weird | Match surrounding indentation |
| Copied wrong function | Compilation error | Re-copy exact code from template |
| Used printf instead of snprintf | Buffer overflow risk | Use snprintf as shown |

---

## 📊 Line-by-Line Verification

**Helper Functions Block**:
- [ ] Line 1: Blank line before functions
- [ ] Line 2-3: Function signature and comment
- [ ] Line 4-8: First test (directory access)
- [ ] Line 9-14: Second test (file creation)
- [ ] Line 15: Return 1 if writable
- [ ] Line 16: Closing brace
- [ ] Line 17: Blank line
- [ ] Line 18-22: Second function signature
- [ ] Line 23-30: Candidates array and loop
- [ ] Line 31: Return statement
- [ ] Line 32-33: Closing braces

**Initialization Block**:
- [ ] Line 1: Old if statement removed
- [ ] Line 2: New if statement with getenv
- [ ] Line 3: Call to find_working_runtime_dir()
- [ ] Line 4: setenv call with runtime_dir variable
- [ ] Line 5: Closing brace

---

## 📋 Final Checklist

**Before Building**:
- [ ] All three modifications completed
- [ ] File saved
- [ ] No obvious syntax errors visible
- [ ] Indentation consistent
- [ ] Helper functions before main()

**After Building**:
- [ ] No compilation errors
- [ ] Binary exists at build/bin/user/futura-wayland
- [ ] Binary is executable

**After Testing**:
- [ ] Directory testing messages appear
- [ ] SUCCESS messages for all syscalls
- [ ] Socket file created
- [ ] Ready for client testing

---

## 🎓 Understanding Each Part

**Why test_socket_directory()?**
- Checks read access: Can we even access the directory?
- Checks write access: Can we create files there?
- Returns 1 if both work, 0 if either fails

**Why find_working_runtime_dir()?**
- Tries multiple directories in order
- Uses first one that passes both tests
- Falls back to /tmp if all fail
- Returns a valid path that WILL work

**Why modify initialization?**
- Instead of hardcoding "/tmp"
- Calls function to find working directory
- Uses whatever directory actually works
- Socket creation succeeds with working directory

---

## ⏱️ Time Tracking

- [ ] Read checklist: 5 min
- [ ] Modification 1 (functions): 5 min
- [ ] Modification 2 (initialization): 3 min
- [ ] Modification 3 (debug): 1 min
- [ ] Build: 2 min
- [ ] Test: 2 min
- [ ] Verify: 2 min
**Total: ~20 minutes**

---

## 📞 If Stuck

**Stuck on locating code?**
- Use Ctrl+F to search for "XDG_RUNTIME_DIR"
- Use Ctrl+F to search for "sys_mkdir"

**Stuck on understanding code?**
- Read WAYLAND_IMPLEMENTATION_TEMPLATE_EACCES.md
- Each function has detailed explanation

**Stuck on build error?**
- Check function syntax matches template exactly
- Check for missing semicolons or braces
- Try `make clean` first

**Stuck on test output?**
- Look for directory testing messages
- If you see them, the code is running
- If you see SUCCESS, the fix worked

---

## ✅ Done When...

You see this message:
```
[WAYLAND] SUCCESS: auto socket created: wayland-0
```

And the display doesn't show green (it shows compositor or test pattern).

That means: **Socket creation is fixed!** ✓✓✓

---

**Follow this checklist exactly. ~20 minutes to working socket.**
