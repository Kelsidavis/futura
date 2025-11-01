# Wayland Socket - Quick Fix Guide (5 Minutes)

**For**: When you confirm error is EACCES (errno=13)
**Time**: ~5 minutes to implement
**Complexity**: LOW - just copy/paste and build

---

## ⚡ Ultra-Quick Path

```
Error confirmed: EACCES (errno=13)
↓
1. Get template code (WAYLAND_IMPLEMENTATION_TEMPLATE_EACCES.md)
2. Paste helper functions into main.c
3. Replace 7 lines of initialization code
4. Build: make clean && make
5. Test: ./build/bin/user/futura-wayland
6. Check for SUCCESS messages
7. Done! ✓
```

---

## 🎯 The Fix in 30 Seconds

1. **File**: `src/user/compositor/futura-wayland/main.c`

2. **Add** (after `sys_mkdir` function):
```c
static int test_socket_directory(const char *path) {
    printf("[WAYLAND-DEBUG] Testing: %s\n", path);
    int fd = sys_open(path, 0, 0);
    if (fd < 0) return 0;
    sys_close(fd);
    char test_path[512];
    snprintf(test_path, sizeof(test_path), "%s/.wayland-test-%d", path, getuid());
    int test_fd = sys_open(test_path, O_RDWR | O_CREAT, 0666);
    if (test_fd < 0) return 0;
    sys_close(test_fd);
    return 1;
}

static const char *find_working_runtime_dir(void) {
    const char *candidates[] = {"/tmp", "/run", "/var/run", "/dev/shm", NULL};
    printf("[WAYLAND-DEBUG] Finding writable directory\n");
    for (int i = 0; candidates[i]; i++) {
        if (test_socket_directory(candidates[i])) {
            printf("[WAYLAND-DEBUG] ✓ Using: %s\n", candidates[i]);
            return candidates[i];
        }
    }
    return "/tmp";
}
```

3. **Replace** (around line 243-250):
```c
// OLD:
if (!getenv("XDG_RUNTIME_DIR")) {
    setenv("XDG_RUNTIME_DIR", "/tmp", 1);
}

// NEW:
if (!getenv("XDG_RUNTIME_DIR")) {
    const char *runtime_dir = find_working_runtime_dir();
    setenv("XDG_RUNTIME_DIR", runtime_dir, 1);
}
```

4. **Build**:
```bash
cd /home/k/futura
make clean && make
```

5. **Test**:
```bash
./build/bin/user/futura-wayland
```

6. **Verify**: Look for `[WRAP_SOCKET] SUCCESS`

---

## ✅ Before & After

**Before** (fails with EACCES):
```
[WRAP_SOCKET] socket(1, 1, 0)
[WRAP_SOCKET] FAILED: EACCES (errno=13)
[WAYLAND] Demo mode: socket creation failed
```

**After** (works):
```
[WAYLAND-DEBUG] Finding writable directory
[WAYLAND-DEBUG] Testing: /tmp
[WAYLAND-DEBUG] ✓ Using: /tmp
[WRAP_SOCKET] socket(1, 1, 0)
[WRAP_SOCKET] SUCCESS: fd=3
[WRAP_BIND] bind(fd=3, ...)
[WRAP_BIND] SUCCESS
[WAYLAND] SUCCESS: auto socket created: wayland-0
```

---

## 🐛 Troubleshoot in 1 Minute

| Issue | Check | Fix |
|-------|-------|-----|
| Compilation fails | Syntax? | Copy exact code from template |
| Still EACCES | All dirs tested? | All were rejected = system issue |
| Build takes forever | Clean? | Run `make clean` first |
| Socket not created | Check output | Look for SUCCESS message |

---

## 📋 Copy-Paste Checklist

- [ ] Opened: `src/user/compositor/futura-wayland/main.c`
- [ ] Found: `sys_mkdir` function (around line 58)
- [ ] Added: `test_socket_directory` function after it
- [ ] Added: `find_working_runtime_dir` function after that
- [ ] Found: XDG_RUNTIME_DIR initialization (around line 243)
- [ ] Replaced: Old initialization with new call
- [ ] Saved: main.c
- [ ] Built: `make clean && make`
- [ ] Tested: `./build/bin/user/futura-wayland`
- [ ] Verified: SUCCESS messages appear

---

## 🚀 Success Signs

✓ Compiles without errors
✓ Shows directory being tested
✓ Shows "✓ Using: /tmp" (or other path)
✓ [WRAP_SOCKET] shows SUCCESS
✓ [WRAP_BIND] shows SUCCESS
✓ [WRAP_LISTEN] shows SUCCESS
✓ [WAYLAND] SUCCESS: auto socket created

---

## ⏱️ Time Breakdown

- Read this: 1 min
- Get template: 30 sec
- Copy functions: 1 min
- Replace initialization: 1 min
- Build: 2 min
- Test: 30 sec
- Verify: 1 min
**Total: ~7 minutes** (with some buffer)

---

## 🎯 What Each Part Does

**`test_socket_directory(path)`**
- Checks if path is readable
- Checks if path is writable
- Returns 1 if both, 0 if either fails

**`find_working_runtime_dir()`**
- Tries /tmp first
- Falls back to /run, /var/run, /dev/shm
- Returns the first one that works
- Returns /tmp if all fail

**In main()**
- Instead of hardcoding "/tmp"
- Calls `find_working_runtime_dir()`
- Sets XDG_RUNTIME_DIR to whatever works
- Socket creation then succeeds

---

## 💡 Why This Works

EACCES = permission denied on /tmp

Solution: Try other directories that ARE writable

Most systems have at least ONE of:
- /tmp (unlikely if we got EACCES)
- /run (standard Linux)
- /var/run (alternative standard)
- /dev/shm (memory filesystem, usually available)

The code tries them in order, uses the first that works.

---

## 📞 If This Doesn't Work

1. **Verify it's EACCES**
   - Look for: `errno=13`
   - If different errno, use different template

2. **Check all directories are really blocked**
   ```bash
   ls -ld /tmp /run /var/run /dev/shm
   # Which ones are not accessible?
   ```

3. **Try different strategy**
   - Read: WAYLAND_ALTERNATIVE_SOCKET_STRATEGIES.md
   - Consider abstract namespace socket
   - Or custom directory creation

4. **Check system permissions**
   - Are you running as right user?
   - Are filesystems mounted with restrictive flags?
   - Is SELinux/AppArmor blocking?

---

## 🎓 Learning Path

If you want to understand the code:
1. Read: WAYLAND_SOCKET_FALLBACK_HANDLER.md (explains strategy)
2. Read: WAYLAND_IMPLEMENTATION_TEMPLATE_EACCES.md (detailed explanation)
3. Read: This guide (the quick version)

---

## 📝 Track Your Progress

```
Step 1: ERROR CONFIRMED
[ ] Saw [WRAP_SOCKET] FAILED: EACCES (errno=13)
[ ] Noted which directory was /tmp? _____

Step 2: CODE CHANGES
[ ] Added test_socket_directory function
[ ] Added find_working_runtime_dir function
[ ] Replaced initialization code
[ ] File saved

Step 3: BUILD & TEST
[ ] make clean && make (no errors?)
[ ] ./build/bin/user/futura-wayland (ran?)
[ ] Saw directory testing messages?
[ ] Saw SUCCESS messages?

Step 4: VERIFICATION
[ ] [WRAP_SOCKET] SUCCESS: fd=3 ✓
[ ] [WRAP_BIND] SUCCESS ✓
[ ] [WRAP_LISTEN] SUCCESS ✓
[ ] [WAYLAND] SUCCESS: auto socket created ✓

Step 5: CELEBRATE ✓✓✓
[ ] Socket creation works!
[ ] Ready for client testing!
```

---

## 🎯 Done When You See

```
[WAYLAND] SUCCESS: auto socket created: wayland-0
[WAYLAND] compositor ready 1024x768 bpp=32 socket=wayland-0
```

No more demo mode (green screen).
Compositor is actually running.
Ready for clients.

---

**Print this page and follow it step by step. ~7 minutes to socket creation fix.**
