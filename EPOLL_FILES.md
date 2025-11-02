# Futura OS epoll/select() - File Reference Guide

## Document Overview

Two comprehensive documents have been created:

1. **EPOLL_ANALYSIS.md** (578 lines) - Complete technical analysis
2. **EPOLL_SUMMARY.md** (424 lines) - Quick reference with code examples

Both stored in: `/home/k/futura/`

---

## Key Files to Examine (Absolute Paths)

### 1. Current select() Implementation
**Path**: `/home/k/futura/subsystems/posix_compat/posix_syscall.c`
**Lines**: 852-998
**What to look for**:
- Polling loop (10ms intervals)
- FD readiness detection using vfs_get_file()
- Timeout handling (timeval parsing)
- fd_set manipulation

### 2. Syscall Dispatcher and Handler Table
**Path**: `/home/k/futura/subsystems/posix_compat/posix_syscall.c`
**Lines**: 1364-1452
**What to look for**:
- syscall_table definition
- Handler function type
- posix_syscall_dispatch() entry point
- Available syscall numbers (0-257, 400, etc.)

### 3. Socket FD Management System
**Path**: `/home/k/futura/subsystems/posix_compat/posix_syscall.c`
**Lines**: 94-156
**What to look for**:
- socket_fd_table (MAX_SOCKET_FDS = 256)
- get_socket_from_fd()
- allocate_socket_fd()
- release_socket_fd()

### 4. Syscall Numbers Definition
**Path**: `/home/k/futura/include/user/sysnums.h`
**Lines**: All
**What to look for**:
- #define SYS_* constants
- Available numbers for epoll (228-230 unused)
- Signal handling syscalls

### 5. Userland epoll Implementation
**Path**: `/home/k/futura/src/user/libfutura/epoll.c`
**Lines**: All (256 lines)
**What to look for**:
- epoll_stub structure (limits)
- epoll_create1(), epoll_ctl(), epoll_wait()
- Multi-layer event checking (__fut_timerfd_poll, __fut_unix_socket_poll, etc.)
- Polling loop with timeout handling

### 6. Userland poll() Implementation
**Path**: `/home/k/futura/src/user/libfutura/poll.c`
**Lines**: All (150 lines)
**What to look for**:
- Conversion between poll and epoll event masks
- Integration with same multi-layer event checking
- Ready event accumulation

### 7. Wait Queue API
**Path**: `/home/k/futura/include/kernel/fut_waitq.h`
**Lines**: All (28 lines)
**What to look for**:
- struct fut_waitq definition
- fut_waitq_sleep_locked()
- fut_waitq_wake_one() / fut_waitq_wake_all()
- Spinlock integration

### 8. Socket Object Structures
**Path**: `/home/k/futura/include/kernel/fut_socket.h`
**Lines**: 1-141 (data structures)
**What to look for**:
- fut_socket_state enum
- fut_socket_pair_t (with send_waitq, recv_waitq)
- fut_socket_listener_t (with accept_waitq)
- fut_socket_t (complete socket object)

### 9. Socket API (what to hook for epoll)
**Path**: `/home/k/futura/include/kernel/fut_socket.h`
**Lines**: 160-263 (function declarations)
**What to look for**:
- fut_socket_create()
- fut_socket_send() / fut_socket_recv()
- fut_socket_accept()
- fut_socket_poll() - readiness checking function

### 10. File Descriptor Structures
**Path**: `/home/k/futura/include/kernel/fut_vfs.h`
**Lines**: 280-289
**What to look for**:
- struct fut_file definition
- vnode pointer, flags, refcount
- Character device operations (chr_ops)

### 11. VNode Operations
**Path**: `/home/k/futura/include/kernel/fut_vfs.h`
**Lines**: 100-216
**What to look for**:
- struct fut_vnode_ops
- open(), close(), read(), write(), readdir()
- Generic file operations interface

### 12. Signal Delivery on Syscall Return
**Path**: `/home/k/futura/subsystems/posix_compat/posix_syscall.c`
**Lines**: 1648-1670
**What to look for**:
- syscall_entry_c() entry point
- Signal delivery before user return
- pending_signals checking
- Interrupt frame modification

---

## Quick Navigation Map

### To understand select():
1. Start: `/home/k/futura/subsystems/posix_compat/posix_syscall.c:852`
2. See how it checks FD readiness
3. Notice 10ms sleep in polling loop (line ~985-990)

### To understand existing epoll infrastructure:
1. Read: `/home/k/futura/src/user/libfutura/epoll.c`
2. See: Multiple event source checking (timerfd, socket, eventfd, signalfd)
3. Notice: Polling loop with nanosleep (line ~231)

### To understand kernel building blocks:
1. Wait queues: `/home/k/futura/include/kernel/fut_waitq.h`
2. Socket buffers: `/home/k/futura/include/kernel/fut_socket.h:82-98`
3. Listener state: `/home/k/futura/include/kernel/fut_socket.h:66-72`

### To understand syscall dispatch:
1. Table: `/home/k/futura/subsystems/posix_compat/posix_syscall.c:1375`
2. Dispatcher: `/home/k/futura/subsystems/posix_compat/posix_syscall.c:1432`
3. Entry point: `/home/k/futura/subsystems/posix_compat/posix_syscall.c:1648`

---

## File Search Tips

### Search for vfs_get_file usage:
```bash
grep -n "vfs_get_file" /home/k/futura/subsystems/posix_compat/posix_syscall.c
```

### Find all wait queue operations:
```bash
grep -n "fut_waitq" /home/k/futura/include/kernel/fut_socket.h
```

### Locate socket FD table:
```bash
grep -n "socket_fd_table" /home/k/futura/subsystems/posix_compat/posix_syscall.c
```

### See all epoll functions in userland:
```bash
grep -n "^int epoll" /home/k/futura/src/user/libfutura/epoll.c
```

### Check available syscall numbers:
```bash
grep "^#define SYS_" /home/k/futura/include/user/sysnums.h | sort -t'_' -k3 -n
```

---

## Code Structure Overview

```
/home/k/futura/
├── include/
│   ├── kernel/
│   │   ├── fut_waitq.h           [Wait queue API]
│   │   ├── fut_socket.h          [Socket objects + structures]
│   │   └── fut_vfs.h             [VFS + struct fut_file]
│   └── user/
│       └── sysnums.h             [Syscall numbers]
│
├── kernel/
│   ├── ipc/
│   │   ├── fut_socket.c          [Socket implementation]
│   │   └── (fut_epoll.c)         [NEW: To be created]
│   ├── scheduler/
│   │   └── fut_waitq.c           [Wait queue implementation]
│   └── vfs/
│       └── (VFS implementation)
│
├── subsystems/
│   └── posix_compat/
│       ├── posix_syscall.c       [Syscall dispatcher + select()]
│       └── posix_shim.h          [POSIX API declarations]
│
└── src/user/
    └── libfutura/
        ├── epoll.c               [Userland epoll (user-space)]
        └── poll.c                [Userland poll (user-space)]
```

---

## Integration Requirements Matrix

| Feature | Location | Type | Difficulty |
|---------|----------|------|------------|
| Add SYS_epoll_* | sysnums.h | Define | Easy |
| Create handlers | posix_syscall.c | Add 3 functions | Medium |
| Kernel epoll object | fut_epoll.c | NEW file | Hard |
| Socket integration | fut_socket.c | Modify | Medium |
| Wait queue blocking | fut_epoll.c | Use existing | Medium |
| FD management | posix_syscall.c | Extend FD table | Medium |
| Signal handling | posix_syscall.c | Use existing | Easy |

---

## Development Sequence

1. **Phase 1** (Easiest):
   - Add SYS_epoll_* to sysnums.h
   - Add stub handlers to posix_syscall.c

2. **Phase 2** (Medium):
   - Create kernel/ipc/fut_epoll.c (core logic)
   - Create include/kernel/fut_epoll.h (API)
   - Register in syscall_table

3. **Phase 3** (Medium):
   - Extend socket FD management
   - Add epoll FD lookup in dispatcher
   - Wire socket completion callbacks

4. **Phase 4** (Hard):
   - Replace select() polling with epoll
   - Implement efficient event queuing
   - Add performance optimizations

---

## Key Constants and Limits

From various sources:

```c
// From posix_syscall.c
#define MAX_SOCKET_FDS      256
#define MAX_SYSCALL         512
#define SYS_select          23

// From libfutura/epoll.c
#define MAX_EPOLL_SETS      8
#define MAX_EPOLL_ENTRIES   64

// From kernel fut_socket.h
#define FUT_SOCKET_QUEUE_MAX    16
#define FUT_SOCKET_BUFSIZE      4096

// Event flags (from libfutura/epoll.c)
#define EPOLLIN         0x001u
#define EPOLLOUT        0x004u
#define EPOLL_CTL_ADD   1
#define EPOLL_CTL_MOD   2
#define EPOLL_CTL_DEL   3
```

---

## Function Signatures to Understand

### Current select() handler:
```c
static int64_t sys_select_handler(
    uint64_t nfds,           // Highest FD + 1
    uint64_t readfds,        // fd_set pointer
    uint64_t writefds,       // fd_set pointer
    uint64_t exceptfds,      // fd_set pointer
    uint64_t timeout_ptr,    // timeval pointer
    uint64_t arg6
)
```

### Future epoll handlers (to implement):
```c
static int64_t sys_epoll_create_handler(
    uint64_t flags,
    uint64_t arg2, uint64_t arg3,
    uint64_t arg4, uint64_t arg5, uint64_t arg6
)

static int64_t sys_epoll_ctl_handler(
    uint64_t epfd,           // epoll fd
    uint64_t op,             // ADD/MOD/DEL
    uint64_t fd,             // Target fd
    uint64_t event,          // epoll_event pointer
    uint64_t arg5, uint64_t arg6
)

static int64_t sys_epoll_wait_handler(
    uint64_t epfd,           // epoll fd
    uint64_t events,         // epoll_event* array
    uint64_t maxevents,      // Array capacity
    uint64_t timeout,        // Timeout in ms
    uint64_t arg5, uint64_t arg6
)
```

---

## Testing Locations

Current tests (to reference):
- Kernel self-tests: `kernel/tests/`
- Host-side tests: `tests/`
- FIPC tests: `tests/fipc_*.c`

Future epoll tests should follow similar pattern.

---

## References Created

1. **EPOLL_ANALYSIS.md** (this directory)
   - 11 detailed sections
   - Full code snippets
   - Complete architecture explanation

2. **EPOLL_SUMMARY.md** (this directory)
   - Quick reference format
   - Diagrams and visual flow
   - Implementation steps

3. **EPOLL_FILES.md** (this file)
   - File navigation guide
   - Quick search tips
   - Code structure overview

All three documents complement each other for complete understanding.

