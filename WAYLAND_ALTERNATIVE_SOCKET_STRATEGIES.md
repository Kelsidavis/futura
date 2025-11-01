# Wayland Socket Creation - Alternative Strategies

**Purpose**: Document alternative approaches to socket creation if standard methods fail

**Status**: Contingency plans ready for implementation if needed

---

## 🎯 Overview

If standard socket creation continues to fail even after fallback handlers, several alternative strategies are available. This document covers progressively more aggressive approaches.

---

## Strategy 1: Abstract Namespace Sockets (Unix Domain)

### Description

Instead of using filesystem-based sockets, use abstract namespace sockets (Linux-specific feature).

**Advantages**:
- No filesystem permissions needed
- Automatically cleaned up when daemon exits
- No lingering socket files
- Very reliable

**Disadvantages**:
- Linux-specific (not portable)
- Only works with int 0x80 (limited client compatibility)

### Implementation

```c
#include <sys/socket.h>
#include <sys/un.h>
#include <string.h>

// Create abstract namespace socket
struct sockaddr_un addr = {0};
addr.sun_family = AF_UNIX;
// Abstract namespace: first byte is 0, rest is name
addr.sun_path[0] = 0;  // Abstract namespace marker
strcpy(&addr.sun_path[1], "wayland");  // Name without leading /
socklen_t len = offsetof(struct sockaddr_un, sun_path) + 1 + strlen("wayland");

// Now bind to abstract socket
if (bind(sock, (struct sockaddr *)&addr, len) < 0) {
    printf("Abstract socket bind failed\n");
    return -1;
}
```

### Code Location

Would modify the socket binding in libwayland-server through LD_PRELOAD wrapper.

### Expected Result

```
[WRAP_SOCKET] socket(1, 1, 0)
[WRAP_SOCKET] SUCCESS: fd=3
[WRAP_BIND] bind(fd=3, abstract socket, len=18)
[WRAP_BIND] SUCCESS
[WAYLAND] Socket created in abstract namespace (no filesystem dependency)
```

---

## Strategy 2: In-Memory Socket via Memfd

### Description

Create socket and pass file descriptors directly instead of using filesystem paths.

**Advantages**:
- No filesystem needed
- Secure - no path-based access
- Works in sandboxed environments

**Disadvantages**:
- Requires fd passing protocol
- Not standard Wayland (custom protocol)
- Complex implementation

### Implementation

```c
// Use memfd for temporary socket storage
int memfd = syscall(__NR_memfd_create, "wayland-socket", 0);
if (memfd < 0) {
    printf("memfd_create failed\n");
    return -1;
}

// Can store socket metadata here
// Pass fd to clients directly
```

### When to Use

- If all storage is restricted
- If running in highly sandboxed environment
- If standard paths are unavailable

---

## Strategy 3: Socket via Environment Variables

### Description

Instead of filesystem path, pass socket FD directly to clients via environment variable.

**Advantages**:
- No filesystem needed
- Works with parent-child processes
- Simple implementation

**Disadvantages**:
- Only works with spawned processes
- Not standard Wayland protocol
- Limited to local connections

### Implementation

```c
// After creating and binding socket:
int socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
if (socket_fd < 0) {
    return -1;
}

// Instead of filesystem path:
char fd_str[32];
snprintf(fd_str, sizeof(fd_str), "%d", socket_fd);
setenv("WAYLAND_SOCKET_FD", fd_str, 1);

// Clients read WAYLAND_SOCKET_FD and use it directly
```

### When to Use

- Testing only
- Parent-child process model
- Controlled environment

---

## Strategy 4: TCP Socket Alternative

### Description

Use TCP sockets instead of Unix domain sockets (if network stack works).

**Advantages**:
- Works over network
- No filesystem/permissions issues
- Standard networking

**Disadvantages**:
- Not Wayland standard
- Security implications (network exposed)
- Different syscall flow

### Implementation

```c
// Create TCP socket
int sock = socket(AF_INET, SOCK_STREAM, 0);
struct sockaddr_in addr = {0};
addr.sin_family = AF_INET;
addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);  // Only localhost
addr.sin_port = htons(WAYLAND_PORT);  // Custom port

if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    return -1;
}
```

### When to Use

- Last resort
- When Unix domain fails completely
- Testing with remote clients

---

## Strategy 5: Shared Memory + Event Notification

### Description

Use shared memory (shm) for socket state instead of filesystem sockets.

**Advantages**:
- Uses /dev/shm (almost always available)
- Fast inter-process communication
- Can use mmap

**Disadvantages**:
- Complex implementation
- Non-standard protocol
- Requires custom client support

### Implementation

```c
// Create shared memory region for socket state
int shm_fd = shm_open("wayland-compositor", O_CREAT | O_RDWR, 0666);
if (shm_fd < 0) {
    return -1;
}

// mmap the region and write socket info
void *shm_addr = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                      MAP_SHARED, shm_fd, 0);
// Store socket info here
```

### When to Use

- If /dev/shm available but /tmp not
- High-performance requirements
- Sandboxed environments

---

## Strategy 6: Socket File in Home Directory

### Description

Fallback to creating socket in user's home directory.

**Advantages**:
- Usually always writable by user
- Standard location for user data
- No special permissions needed

**Disadvantages**:
- Non-standard location
- May be on different filesystem
- Potential path length issues

### Implementation

```c
// Fallback to home directory
char socket_dir[512];
const char *home = getenv("HOME");
if (home) {
    snprintf(socket_dir, sizeof(socket_dir), "%s/.local/run", home);
    mkdir(socket_dir, 0700);  // Create if needed
    setenv("XDG_RUNTIME_DIR", socket_dir, 1);
}
```

### When to Use

- /tmp and /run both unavailable
- User-specific Wayland instance
- Development/testing

---

## Strategy 7: Socket in Ramdisk

### Description

Use ramdisk (/dev/shm, /run) explicitly if available.

**Advantages**:
- Typically available and writable
- Fast (memory-based)
- Temporary by nature

**Disadvantages**:
- Limited size
- Non-standard location
- May lose data on reboot (okay for sockets)

### Implementation

```c
// Explicit ramdisk socket paths
const char *ramdisk_paths[] = {
    "/dev/shm",
    "/run",
    "/var/run",
    NULL
};

for (int i = 0; ramdisk_paths[i]; i++) {
    if (can_write_to(ramdisk_paths[i])) {
        setenv("XDG_RUNTIME_DIR", ramdisk_paths[i], 1);
        break;
    }
}
```

### When to Use

- Standard as first fallback (recommended)
- Combined with other strategies
- Most reliable cross-platform

---

## Recommended Priority Order

1. **Primary**: /tmp (standard, usually works)
2. **Fallback 1**: /run (Linux standard)
3. **Fallback 2**: /dev/shm (ramdisk, usually available)
4. **Fallback 3**: Home directory ($HOME/.local/run)
5. **Fallback 4**: Abstract namespace (if still failing)
6. **Last Resort**: Custom communication protocol

---

## 🎯 Quick Decision Guide

```
Is standard socket creation failing?
│
├─ YES, errno=EACCES → Try fallback directories (Strategy 1+7)
├─ YES, errno=EADDRINUSE → Check/remove old sockets
├─ YES, errno=EINVAL → Check syscall parameters
├─ YES, errno=ENOENT → Create missing directories
│
└─ If all strategies fail → Use abstract socket (Strategy 2)
```

---

## 📊 Strategy Comparison

| Strategy | Complexity | Reliability | Standard | Best For |
|----------|-----------|------------|----------|----------|
| Fallback dirs | Low | High | Yes | Permission issues |
| Abstract socket | Low | Medium | No | Linux-only systems |
| Memfd | Medium | Medium | No | Sandboxed env |
| Home directory | Low | Medium | No | User session |
| TCP socket | Medium | High | No | Network testing |
| Shared memory | High | Low | No | Custom systems |
| Ramdisk | Low | High | Yes | Most environments |

---

## 🧪 Implementation Sequence

### Phase 1: Standard Approach
```
Try /tmp with standard socket creation
If fails, capture errno for diagnosis
```

### Phase 2: Fallback Approach
```
If errno=EACCES (permission):
  Try /run, /dev/shm, other writable directories
If errno=EADDRINUSE (address in use):
  Remove old socket files
If errno=EINVAL (invalid params):
  Debug syscall parameters
If errno=ENOENT (no directory):
  Create missing directories
```

### Phase 3: Alternative Approach
```
If fallbacks fail:
  Consider abstract namespace socket
  May need custom client modifications
```

---

## ⚠️ Important Considerations

### Compatibility
- Some strategies are Linux-specific
- Some break Wayland protocol
- Client compatibility varies

### Security
- /tmp is world-readable
- Abstract sockets are more secure
- TCP sockets need firewall rules

### Performance
- Ramdisk is fastest
- Network sockets add latency
- Shared memory very fast

### Debugging
- Some strategies are harder to debug
- Good logging essential
- Test each strategy independently

---

## 🚀 Recommended Implementation

**Best approach**: Fallback directory strategy (Strategy 1 + 7)

**Why**:
1. Minimal code changes
2. High compatibility
3. Standardized locations
4. Easy to test and debug
5. Works with existing Wayland protocol

**Implementation**:
```c
// Try directories in order
const char *dirs[] = {
    "/tmp",
    "/run",
    "/dev/shm",
    "/var/run",
    NULL
};

for (int i = 0; dirs[i]; i++) {
    if (test_directory(dirs[i])) {
        setenv("XDG_RUNTIME_DIR", dirs[i], 1);
        printf("[WAYLAND] Using %s for sockets\n", dirs[i]);
        break;
    }
}
```

---

## 📝 Summary

**Available Strategies** (ordered by recommendation):
1. Fallback to alternative directories (RECOMMENDED)
2. Abstract namespace sockets (if filesystem fails)
3. Home directory socket (if nothing else works)
4. Ramdisk explicit paths (good fallback)
5. Environment variable passing (testing only)
6. TCP sockets (network fallback)
7. Shared memory (complex, custom)

**Next Step**:
- Run system to identify actual error
- Implement appropriate strategy
- Test socket creation with that strategy
- Verify clients can connect

---

## 🔗 Related Files

- **WAYLAND_DIAGNOSTIC_PREDICTION.md** - How to identify the problem
- **WAYLAND_SOCKET_FALLBACK_HANDLER.md** - Fallback implementation details
- **WAYLAND_TESTING_GUIDE.md** - Testing procedures

---

**This document provides contingency plans for socket creation failure.**

The primary recommendation is the **fallback directory strategy**, which is simple, reliable, and maintains standard Wayland protocol compatibility.

Once we identify the actual error from running the system, we can select and implement the most appropriate strategy.
