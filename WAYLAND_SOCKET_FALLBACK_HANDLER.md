# Wayland Socket Creation - Fallback Handler Strategy

**Purpose**: Provide fallback mechanisms for socket creation failures

**Status**: Proactive solution ready to implement based on diagnostic results

---

## 🎯 Problem Statement

Socket creation is likely failing due to permission issues (errno=13 EACCES). The fallback handler will:

1. Try primary runtime directory (/tmp)
2. If that fails, try alternative directories
3. Log which directory ultimately works
4. Allow socket creation to succeed even with permission restrictions

---

## 🔧 Fallback Strategy

### Phase 1: Permission-Based Fallback

**Current Behavior**:
```c
// main.c currently uses:
setenv("XDG_RUNTIME_DIR", "/tmp", 1);
```

**Improved Behavior**:
```c
// Try multiple directories in order of preference
const char *runtime_dirs[] = {
    "/tmp",              // Default (most likely to work)
    "/run",              // Standard XDG location (needs permissions)
    "/var/run",          // Alternative standard location
    "/dev/shm",          // Shared memory (sometimes available)
    "/local/run",        // Custom location
    NULL                 // Sentinel
};

for (int i = 0; runtime_dirs[i]; i++) {
    if (try_directory(runtime_dirs[i])) {
        setenv("XDG_RUNTIME_DIR", runtime_dirs[i], 1);
        break;
    }
}
```

### Phase 2: Permission Testing

Test each directory before attempting socket creation:

```c
int test_directory(const char *path) {
    // Test 1: Can we open it?
    int fd = sys_open(path, 0, 0);
    if (fd < 0) {
        printf("[WAYLAND-DEBUG] %s not accessible\n", path);
        return 0;
    }
    sys_close(fd);
    printf("[WAYLAND-DEBUG] %s accessible\n", path);

    // Test 2: Can we create a file there?
    char test_file[256];
    snprintf(test_file, sizeof(test_file), "%s/.wayland-test", path);
    int test_fd = sys_open(test_file, O_RDWR | O_CREAT, 0666);
    if (test_fd < 0) {
        printf("[WAYLAND-DEBUG] %s not writable\n", path);
        return 0;
    }
    sys_close(test_fd);
    printf("[WAYLAND-DEBUG] %s writable\n", path);

    return 1;
}
```

---

## 📋 Implementation Plan

### Step 1: Identify the Actual Error

Run system with current code and capture errno value:
```
[WRAP_SOCKET] FAILED: <ERROR_NAME> (errno=<NUMBER>)
```

### Step 2: Implement Targeted Fix

**If errno=13 (EACCES)**:
- Implement directory fallback handler
- Try alternative paths
- Document which path ultimately works

**If errno=48 (EADDRINUSE)**:
- Check for existing socket files
- Clean up old sockets
- Use different socket name if needed

**If errno=22 (EINVAL)**:
- Review syscall parameters
- Check register passing
- May need to adjust how libwayland-server is called

**If errno=2 (ENOENT)**:
- Create missing directories
- Ensure path exists before socket creation

### Step 3: Test the Fix

With fallback handler in place:
```bash
./build/bin/user/futura-wayland
```

Expected improved behavior:
```
[WAYLAND-DEBUG] Trying /tmp... not writable
[WAYLAND-DEBUG] Trying /run... not writable
[WAYLAND-DEBUG] Trying /dev/shm... writable!
[WAYLAND-DEBUG] Using /dev/shm for sockets
[WRAP_SOCKET] socket(1, 1, 0)
[WRAP_SOCKET] SUCCESS: fd=3
[WRAP_BIND] bind(fd=3, ...)
[WRAP_BIND] SUCCESS
[WAYLAND] SUCCESS: auto socket created: wayland-0
```

---

## 🛠️ Code Implementation

### Fallback Directory Handler (proposed)

```c
// In main.c, before socket creation

static int try_socket_directory(const char *path) {
    /* Test 1: Can we access the directory? */
    int fd = sys_open(path, 0, 0);
    if (fd < 0) {
        return 0;
    }
    sys_close(fd);

    /* Test 2: Can we create a file? */
    char test_path[512];
    snprintf(test_path, sizeof(test_path), "%s/.wayland-test-%d", path, getpid());
    int test_fd = sys_open(test_path, O_RDWR | O_CREAT, 0666);
    if (test_fd < 0) {
        return 0;
    }
    sys_close(test_fd);

    return 1;
}

/* Find a working runtime directory */
static const char *find_runtime_dir(void) {
    const char *candidates[] = {
        "/tmp",
        "/run",
        "/var/run",
        "/dev/shm",
        NULL
    };

    for (int i = 0; candidates[i]; i++) {
        if (try_socket_directory(candidates[i])) {
            printf("[WAYLAND-DEBUG] Using runtime dir: %s\n", candidates[i]);
            return candidates[i];
        }
    }

    /* Fallback to /tmp even if tests fail */
    printf("[WAYLAND-DEBUG] WARNING: No accessible runtime dir found, using /tmp\n");
    return "/tmp";
}

/* In main(), before socket creation: */
const char *runtime_dir = find_runtime_dir();
setenv("XDG_RUNTIME_DIR", runtime_dir, 1);
```

### Location in Code

Insert before line 286 in `src/user/compositor/futura-wayland/main.c`:

```c
/* Current code at line 243-250: */
if (!getenv("XDG_RUNTIME_DIR")) {
    setenv("XDG_RUNTIME_DIR", "/tmp", 1);
}

/* Replace with: */
if (!getenv("XDG_RUNTIME_DIR")) {
    const char *runtime_dir = find_runtime_dir();  // NEW
    setenv("XDG_RUNTIME_DIR", runtime_dir, 1);
}
```

---

## 🎯 Expected Outcomes

### With EACCES Error (errno=13)

**Before Fix**:
```
[WAYLAND-DEBUG] XDG_RUNTIME_DIR=/tmp
[WAYLAND-DEBUG] XDG_RUNTIME_DIR accessible
[WAYLAND-DEBUG] Test file created successfully  ← May say this
[WRAP_SOCKET] socket(1, 1, 0)
[WRAP_SOCKET] FAILED: EACCES (errno=13)  ← Fails!
[WAYLAND] Demo mode: socket creation failed
```

**After Fix**:
```
[WAYLAND-DEBUG] Checking /tmp... accessible
[WAYLAND-DEBUG] Checking /tmp... writable!
[WAYLAND-DEBUG] Using runtime dir: /tmp
[WRAP_SOCKET] socket(1, 1, 0)
[WRAP_SOCKET] SUCCESS: fd=3  ← Works!
```

OR (if /tmp fails):
```
[WAYLAND-DEBUG] Checking /tmp... not writable
[WAYLAND-DEBUG] Checking /run... not writable
[WAYLAND-DEBUG] Checking /dev/shm... writable!
[WAYLAND-DEBUG] Using runtime dir: /dev/shm
[WRAP_SOCKET] socket(1, 1, 0)
[WRAP_SOCKET] SUCCESS: fd=3  ← Works with fallback!
```

---

## 📊 Directory Fallback Analysis

| Directory | Typical Permissions | When Available | Use Case |
|-----------|-------------------|-----------------|----------|
| /tmp | 1777 (world writable) | Always | First choice |
| /run | 755 (root only) | On Linux | Fallback |
| /var/run | 755 (root only) | On Linux | Additional fallback |
| /dev/shm | Varies | Always (on modern systems) | Emergency fallback |
| /local/run | Custom | Only if created | Custom environment |

**Selection Strategy**: Try in order until one works

---

## 🔄 Alternative: Per-User Socket Directory

If system permissions are heavily restricted:

```c
/* Create per-user socket directory */
char user_socket_dir[256];
snprintf(user_socket_dir, sizeof(user_socket_dir),
         "/tmp/wayland-%d", getuid());

int mkdir_fd = sys_mkdir(user_socket_dir, 0700);
if (mkdir_fd >= 0 || errno == EEXIST) {
    setenv("XDG_RUNTIME_DIR", user_socket_dir, 1);
}
```

**Advantage**: Guaranteed to be user-writable
**Disadvantage**: Non-standard location

---

## 🧪 Testing the Fallback

Once implemented, test with:

```bash
# Test 1: Normal case (should use /tmp)
./build/bin/user/futura-wayland 2>&1 | grep "Using runtime dir"

# Test 2: If /tmp is broken, verify fallback
chmod 000 /tmp
./build/bin/user/futura-wayland 2>&1 | grep "Using runtime dir"
chmod 1777 /tmp

# Test 3: Multiple fallback attempts
# (System will try /tmp, then /run, then /dev/shm, etc.)
```

---

## 📈 Implementation Phases

### Phase 1 (Current)
- ✅ Diagnostic infrastructure complete
- ✅ Error output shows exactly what's failing
- ⏳ Await test results

### Phase 2 (After Test Results)
- Implement fallback handler if errno=13
- Test with alternative directories
- Verify socket creation succeeds

### Phase 3 (Verification)
- Socket creation working
- Clients can connect
- Compositor fully functional

---

## 🎯 Success Criteria

**Before Fallback Implementation**:
```
Diagnostic output shows errno value
We know exactly what's failing
```

**After Fallback Implementation**:
```
Socket creation succeeds
Compositor ready for clients
Display shows actual compositor (not demo)
```

---

## 🔗 Related Documentation

- **WAYLAND_DIAGNOSTIC_PREDICTION.md** - How to interpret errors
- **WAYLAND_TESTING_GUIDE.md** - Testing procedures
- **WAYLAND_SESSION_MASTER_SUMMARY.md** - Overall context

---

## ⚙️ Implementation Checklist

- [ ] Run system to capture actual errno
- [ ] Identify which error occurred
- [ ] Implement appropriate fix:
  - [ ] If EACCES: Implement fallback handler
  - [ ] If EADDRINUSE: Cleanup mechanism
  - [ ] If EINVAL: Debug syscall parameters
  - [ ] If ENOENT: Directory creation
- [ ] Test the fix
- [ ] Verify socket creation succeeds
- [ ] Verify clients can connect
- [ ] Document the solution

---

**This strategy is ready to execute once actual test results are available.**

The fallback handler is the proactive solution for the most likely failure scenario (errno=13 EACCES). Once we know the actual error, we can implement the specific fix needed.
