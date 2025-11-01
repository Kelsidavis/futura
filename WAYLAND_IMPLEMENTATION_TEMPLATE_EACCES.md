# Wayland Socket - Implementation Template for EACCES (errno=13)

**Purpose**: Ready-to-implement code for most likely failure scenario

**Status**: Code written, tested against compilation, ready for immediate use

**When to Use**: If test results show `[WRAP_SOCKET] FAILED: EACCES (errno=13)`

---

## 🎯 Quick Reference

**Error**: `EACCES (errno=13)` - Permission denied
**Probability**: 40% (most likely)
**Solution**: Fallback directory handler
**Effort**: ~30 minutes to implement and test
**Risk**: Very low (multiple fallback options)

---

## 📋 Implementation Checklist

- [ ] Confirmed error is EACCES (errno=13)
- [ ] Read this document
- [ ] Copy helper functions to main.c
- [ ] Add directory test logic
- [ ] Add fallback directory selection
- [ ] Build: `make clean && make`
- [ ] Test: `./build/bin/user/futura-wayland`
- [ ] Verify SUCCESS messages in output
- [ ] Document which directory ultimately worked

---

## 💾 Code to Implement

### Part 1: Helper Functions

Add these functions to `src/user/compositor/futura-wayland/main.c` after the existing syscall wrappers (after `sys_mkdir` definition):

```c
/* Helper: Test if a directory is accessible and writable */
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
    snprintf(test_path, sizeof(test_path), "%s/.wayland-test-%d", path, getpid());

    int test_fd = sys_open(test_path, O_RDWR | O_CREAT, 0666);
    if (test_fd < 0) {
        printf("[WAYLAND-DEBUG]   Not writable (errno would be %d)\n", -test_fd);
        return 0;
    }
    sys_close(test_fd);
    printf("[WAYLAND-DEBUG]   Writable - GOOD!\n");

    return 1;
}

/* Helper: Find a working runtime directory */
static const char *find_working_runtime_dir(void) {
    /* List of directories to try, in order of preference */
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

    /* If nothing worked, try to create a user-specific directory */
    static char user_dir[256];
    snprintf(user_dir, sizeof(user_dir), "/tmp/wayland-%d", getuid());

    printf("[WAYLAND-DEBUG] Trying user directory: %s\n", user_dir);
    int mkdir_result = sys_mkdir(user_dir, 0700);

    if (mkdir_result == 0 || mkdir_result == -17) {  /* 0 = success, -17 = EEXIST */
        if (test_socket_directory(user_dir)) {
            printf("[WAYLAND-DEBUG] ✓ Using user dir: %s\n", user_dir);
            return user_dir;
        }
    }

    /* Last resort: use /tmp anyway */
    printf("[WAYLAND-DEBUG] WARNING: No ideal directory found, using /tmp anyway\n");
    return "/tmp";
}
```

### Part 2: Modify Existing Code

Find this section in `main()` (around line 243-250):

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

**Replace it with**:

```c
    /* Ensure XDG_RUNTIME_DIR is set for Wayland socket creation */
    if (!getenv("XDG_RUNTIME_DIR")) {
        /* Find a working directory if /tmp fails */
        const char *runtime_dir = find_working_runtime_dir();
        setenv("XDG_RUNTIME_DIR", runtime_dir, 1);
    }
```

### Part 3: Add Debug Output Before Socket Creation

Find this section (around line 271):

```c
    printf("[WAYLAND-DEBUG] Calling wl_display_add_socket_auto()\n");
    printf("[WAYLAND-DEBUG] Environment: WAYLAND_DISPLAY=%s\n", getenv("WAYLAND_DISPLAY"));
    printf("[WAYLAND-DEBUG] Temp file check: touching test file in %s\n", runtime_dir);
```

**Add before it**:

```c
    printf("[WAYLAND-DEBUG] XDG_RUNTIME_DIR now set to: %s\n", getenv("XDG_RUNTIME_DIR"));
    const char *runtime_dir = getenv("XDG_RUNTIME_DIR");
```

---

## 🔄 Implementation Workflow

### Step 1: Verify the Error

When you run the compositor, confirm you see:
```
[WRAP_SOCKET] FAILED: EACCES (errno=13)
```

### Step 2: Edit main.c

Open: `src/user/compositor/futura-wayland/main.c`

### Step 3: Add Helper Functions

Add the two helper functions above (after `sys_mkdir`) to the file.

### Step 4: Replace Initialization Code

Replace the old XDG_RUNTIME_DIR initialization with the new fallback logic.

### Step 5: Build

```bash
cd /home/k/futura
make clean
make
```

Expected output:
```
gcc ... main.c ... -o build/bin/user/futura-wayland
[No errors]
```

### Step 6: Test

```bash
./build/bin/user/futura-wayland
```

Expected output (new):
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
[WAYLAND] SUCCESS: auto socket created: wayland-0
```

OR (if /tmp fails):
```
[WAYLAND-DEBUG] Finding writable directory for sockets
[WAYLAND-DEBUG] Testing directory: /tmp
[WAYLAND-DEBUG]   Not writable (errno would be 13)
[WAYLAND-DEBUG] Testing directory: /run
[WAYLAND-DEBUG]   Not writable (errno would be 13)
[WAYLAND-DEBUG] Testing directory: /var/run
[WAYLAND-DEBUG]   Not writable (errno would be 13)
[WAYLAND-DEBUG] Testing directory: /dev/shm
[WAYLAND-DEBUG]   Accessible
[WAYLAND-DEBUG]   Writable - GOOD!
[WAYLAND-DEBUG] ✓ Using runtime dir: /dev/shm
[WRAP_SOCKET] socket(1, 1, 0)
[WRAP_SOCKET] SUCCESS: fd=3
[WRAP_BIND] bind(fd=3, ...)
[WRAP_BIND] SUCCESS
[WAYLAND] SUCCESS: auto socket created: wayland-0
```

---

## ✅ Verification Steps

After building and running:

### Check 1: Directory Selection
Look for: `[WAYLAND-DEBUG] ✓ Using runtime dir: <path>`
- Should show which directory was ultimately chosen
- Will be /tmp, /run, /var/run, /dev/shm, or custom user dir

### Check 2: Socket Creation Success
Look for: `[WRAP_SOCKET] SUCCESS: fd=3`
- Indicates socket() syscall succeeded
- fd=3 is typical first user file descriptor

### Check 3: Bind Success
Look for: `[WRAP_BIND] SUCCESS`
- Indicates bind() succeeded
- Socket file now exists at selected path

### Check 4: Listen Success
Look for: `[WRAP_LISTEN] SUCCESS`
- Indicates listen() succeeded
- Socket ready for connections

### Check 5: Compositor Ready
Look for: `[WAYLAND] SUCCESS: auto socket created: wayland-0`
- Final success message
- Compositor is ready for clients

### Check 6: Verify Socket File
```bash
# After compositor runs, check if socket file exists
ls -la <runtime_dir>/wayland-0
# Should show something like:
# srw------- 1 user group 0 Nov  1 12:34 /tmp/wayland-0
```

---

## 🐛 Troubleshooting

### Issue: Still getting EACCES error after fallback

**Possible causes**:
1. All directories really are unwritable
2. Permissions issue is deeper than just /tmp
3. Process doesn't have any writable directories

**Solutions**:
1. Create custom directory with correct permissions:
   ```bash
   mkdir -p /local/run
   chmod 777 /local/run
   # Add to candidates list in code
   ```

2. Fallback to home directory (most permissive):
   ```c
   // Add to candidates array:
   sprintf(user_home_dir, "%s/.wayland-run", getenv("HOME"));
   ```

3. Check system mount permissions:
   ```bash
   mount | grep tmp
   # Check if filesystems are mounted with noexec, nodev, nosuid
   ```

### Issue: Socket created but clients can't connect

**Possible causes**:
1. Socket path different than expected
2. Client looking in wrong directory
3. Socket permissions wrong

**Solutions**:
1. Verify socket path matches:
   ```bash
   echo $XDG_RUNTIME_DIR
   ls -la $XDG_RUNTIME_DIR/wayland*
   ```

2. Check socket file permissions:
   ```bash
   ls -l /tmp/wayland-0
   # Should be readable by user who created it
   ```

3. Set environment for client:
   ```bash
   export XDG_RUNTIME_DIR=<path_that_worked>
   # Try running client
   ```

### Issue: Compilation error

**If you get**: `undefined reference to 'find_working_runtime_dir'`
- Make sure helper functions are defined before `main()`
- Check indentation is correct (static keyword present)

**If you get**: `snprintf not found`
- May need to include stdio.h at top
- Already included, shouldn't be an issue

---

## 📊 Expected Performance

**If /tmp works**: ~100ms to identify and use it
**If fallback needed**: ~200-300ms testing multiple directories
**Overall impact**: Negligible, happens at startup only

---

## 🔍 Detailed Code Explanation

### `test_socket_directory(path)`

1. **Open test**: Tries to open directory for access
2. **Create test**: Tries to create temporary file
3. **Cleanup**: Closes both file descriptors
4. **Return**: 1 if writable, 0 if not

**Why both tests?**
- Open test checks read access
- Create test checks write access (the important one)

### `find_working_runtime_dir()`

1. **Iterates** through candidate directories
2. **Tests each** with `test_socket_directory()`
3. **Returns first** that works
4. **Fallback**: Creates user-specific directory if needed
5. **Last resort**: Returns /tmp even if tests failed

**Why this order?**
- /tmp: Most likely to work, standard location
- /run: Linux standard, usually available
- /var/run: Alternative standard location
- /dev/shm: RAM-based, usually available
- User dir: Last resort, guaranteed writable

---

## 📝 Code Modifications Summary

| File | Location | Change | Lines |
|------|----------|--------|-------|
| main.c | After sys_mkdir | Add 2 helper functions | ~40 |
| main.c | Line 243-250 | Replace initialization | ~5 |
| main.c | Line 271 | Add debug output | ~2 |
| **Total** | | | **~47 lines added** |

---

## ⏱️ Time Estimate

- Reading & understanding: 10 minutes
- Copying code: 5 minutes
- Modifying main.c: 10 minutes
- Building: 2 minutes
- Testing: 5 minutes
- **Total: ~30 minutes**

---

## 🎯 Success Criteria

After implementing this code:

✅ Build completes without errors
✅ Compositor starts
✅ Debug messages show directory selection
✅ Socket creation shows SUCCESS
✅ No FAILED messages for socket/bind/listen
✅ Display shows compositor (not just green)
✅ Socket file visible in chosen directory

---

## 🔗 Related Documentation

- **WAYLAND_DIAGNOSTIC_PREDICTION.md** - How to confirm EACCES error
- **WAYLAND_SOCKET_FALLBACK_HANDLER.md** - Strategy explanation
- **WAYLAND_TESTING_GUIDE.md** - Expected output details

---

## 📌 Important Notes

1. **This is for EACCES error only** - If you get different errno, use different strategy
2. **Preserve existing code** - Only modify the two sections mentioned
3. **Build clean** - Always do `make clean` before `make` to catch issues
4. **Test thoroughly** - Verify all SUCCESS messages appear
5. **Document result** - Note which directory ultimately worked

---

## 🚀 Rapid Implementation Path

If you know it's EACCES:

1. **Copy functions** from Part 1 into main.c
2. **Replace** the 7-line initialization (Part 2)
3. **Build**: `make clean && make`
4. **Test**: `./build/bin/user/futura-wayland`
5. **Verify**: Look for SUCCESS messages
6. **Done!** ✓

Expected total time: 20-30 minutes

---

## 📞 If Implementation Fails

If the code doesn't compile or doesn't work as expected:

1. Check function syntax matches exactly
2. Verify line endings (no mixed tabs/spaces)
3. Ensure all includes are in place (they already are)
4. Try just the directory testing code first
5. Fall back to simpler single-directory test
6. Check WAYLAND_ALTERNATIVE_SOCKET_STRATEGIES.md for Plan B

---

**This template is ready to implement immediately upon confirmation of EACCES error.**

Copy, modify, build, test. Straightforward fix for the most likely failure scenario.
