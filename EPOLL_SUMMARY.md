# Quick Reference: select() and epoll in Futura OS

## 1. Current select() at a Glance

**Where**: `/home/k/futura/subsystems/posix_compat/posix_syscall.c:852-998`
**Syscall#**: 23

```c
// How select() currently works:
for (attempt = 0; attempt < max_polls; attempt++) {
    for (fd = 0; fd < nfds; fd++) {
        struct fut_file *file = vfs_get_file(fd);
        if (file && file->vnode) {
            // Regular file - always ready
            mark_as_ready(fd);
        }
    }
    if (ready_count > 0 || timeout == 0) {
        return ready_count;
    }
    sys_nanosleep(10ms);  // Sleep then retry
}
```

**Problem**: Polling every 10ms instead of event-driven!

---

## 2. Existing Userland epoll Infrastructure

**Where**: `/home/k/futura/src/user/libfutura/epoll.c`
**Type**: User-space only (no kernel integration yet)

### What it provides:
- ✅ epoll_create()/epoll_create1()
- ✅ epoll_ctl(ADD/MOD/DEL)
- ✅ epoll_wait() with polling
- ✅ Integration with timerfd, eventfd, signalfd, unix sockets
- ❌ Not integrated with kernel
- ❌ Limited to 8 epoll instances × 64 FDs max

### Supported event sources:
```
┌─ timerfd events      (__fut_timerfd_poll)
├─ unix socket events  (__fut_unix_socket_poll)
├─ eventfd events      (__fut_eventfd_poll)
├─ signalfd events     (__fut_signalfd_poll)
└─ regular files       (always ready)
```

---

## 3. Kernel Pieces Already in Place

### Wait Queues
```c
// kernel/scheduler/fut_waitq.c
typedef struct fut_waitq {
    fut_thread_t *head;    // Blocked threads linked list
    fut_thread_t *tail;
    fut_spinlock_t lock;
} fut_waitq_t;

// Ready to use for blocking on events!
```

### Socket Buffers with Wait Queues
```c
// kernel/ipc/fut_socket.c
typedef struct fut_socket_pair {
    uint8_t *send_buf;
    uint8_t *recv_buf;
    struct fut_waitq *send_waitq;   // ← Ready for event notification
    struct fut_waitq *recv_waitq;   // ← Ready for event notification
    fut_spinlock_t lock;
} fut_socket_pair_t;
```

### File Descriptor System
```c
// kernel/vfs/fut_vfs.c
struct fut_file {
    struct fut_vnode *vnode;
    const struct fut_file_ops *chr_ops;
    void *chr_private;
    // Ready for readiness checking!
};
```

---

## 4. How to Add Kernel epoll

### Step 1: Syscall Numbers (2 files)

**File 1**: `include/user/sysnums.h`
```c
#define SYS_epoll_create  228
#define SYS_epoll_ctl     229
#define SYS_epoll_wait    230
```

**File 2**: `subsystems/posix_compat/posix_syscall.c`
```c
// Add handlers for all three syscalls
static int64_t sys_epoll_create_handler(...) { ... }
static int64_t sys_epoll_ctl_handler(...) { ... }
static int64_t sys_epoll_wait_handler(...) { ... }

// Register in syscall_table
syscall_table[SYS_epoll_create] = sys_epoll_create_handler;
syscall_table[SYS_epoll_ctl]    = sys_epoll_ctl_handler;
syscall_table[SYS_epoll_wait]   = sys_epoll_wait_handler;
```

### Step 2: Kernel epoll Object (1 new file)

**File**: `kernel/ipc/fut_epoll.c` + header `include/kernel/fut_epoll.h`

```c
// Data structure
struct fut_epoll {
    uint32_t epoll_id;
    fut_spinlock_t lock;
    struct fut_waitq *wait_queue;  // Threads waiting on epoll_wait
    
    struct {
        int fd;
        uint32_t events;
        void *priv;
    } *entries;
    uint32_t count;
    uint32_t capacity;
    
    struct epoll_event *ready_queue;
    uint32_t ready_count;
};

// API functions
int fut_epoll_create(int flags);
int fut_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);
int fut_epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout);
void fut_epoll_notify(int fd, uint32_t ready_events);  // Called on FD ready
```

### Step 3: Wire Socket Callbacks (1 existing file modification)

**File**: `kernel/ipc/fut_socket.c`

```c
// In fut_socket_send():
if (bytes_written > 0) {
    fut_epoll_notify(socket->fd, EPOLLOUT);  // NEW: notify epoll
    fut_waitq_wake_all(pair->send_waitq);    // EXISTING: wake select() waiters
}

// In fut_socket_recv():
if (bytes_available > 0) {
    fut_epoll_notify(socket->fd, EPOLLIN);   // NEW: notify epoll
    fut_waitq_wake_all(pair->recv_waitq);    // EXISTING: wake select() waiters
}
```

### Step 4: Refactor select() (modify 1 existing function)

**File**: `subsystems/posix_compat/posix_syscall.c`

```c
// BEFORE: Polling loop every 10ms
while (poll_attempt < max_polls) {
    ready_count = 0;
    for (fd = 0; fd < nfds; fd++) {
        // Check each FD
    }
    if (ready_count > 0 || timeout_ms == 0) break;
    sys_nanosleep(10ms);  // BAD: Polling
    poll_attempt++;
}

// AFTER: Event-driven
// 1. Convert fd_sets to epoll format
// 2. Call kernel epoll_wait() internally
// 3. Convert results back to fd_sets
// 4. Return count of ready FDs
```

---

## 5. Data Flow: Before vs After

### Current (Polling-Based)
```
User calls select()
  ↓
sys_select_handler (poll loop)
  ├─ For each FD: is it ready? (vfs_get_file check)
  ├─ If yes: mark in fd_set, return
  ├─ If no: sleep 10ms, retry
  └─ Return count

Problem: 10ms latency, CPU spinning
```

### Desired (Event-Driven)
```
User calls epoll_wait()
  ↓
sys_epoll_wait_handler
  ├─ Add waiters to epoll->wait_queue
  └─ Block thread on fut_waitq_sleep()
       ↓
       [Thread blocks until FD ready or timeout]
       ↓
Socket operation completes (e.g., data arrives)
  ├─ Call fut_epoll_notify(fd, EPOLLIN)
  ├─ Wakeup threads in epoll->wait_queue
  ├─ Return to sys_epoll_wait_handler
  └─ Return ready events to user

Benefit: Sub-microsecond latency, no spinning
```

---

## 6. Event Flow Diagram

```
┌─────────────────────────────────────────┐
│     User Process (libfutura)            │
│                                         │
│  epoll_ctl(epfd, ADD, sockfd, EPOLLIN) │
│  epoll_wait(epfd, events, 1, -1)       │
└─────────────────────────────────────────┘
              ↓ (syscall)
┌─────────────────────────────────────────────────────────┐
│          Kernel (POSIX Shim)                            │
│                                                         │
│  sys_epoll_ctl_handler()                               │
│    └─ fut_epoll_ctl(epfd, ADD, sockfd, events)        │
│       ↓                                                 │
│  ┌──────────────────────────────────┐                  │
│  │ Kernel epoll object              │                  │
│  │ {                                │                  │
│  │   entries[0]: {fd: sockfd, ...}  │                  │
│  │   wait_queue: [empty]            │                  │
│  │ }                                │                  │
│  └──────────────────────────────────┘                  │
│                                                         │
│  sys_epoll_wait_handler()                              │
│    └─ fut_epoll_wait()                                 │
│       ├─ found no ready events yet                      │
│       ├─ fut_waitq_sleep(&epoll->wait_queue)  ← BLOCKS │
│       └─ [waiting for socket event...]                 │
└─────────────────────────────────────────────────────────┘
              ↓
┌─────────────────────────────────────────────────────────┐
│          Another User Task (sending data)               │
│                                                         │
│  write(sockfd, "hello", 5)                              │
└─────────────────────────────────────────────────────────┘
              ↓ (syscall)
┌─────────────────────────────────────────────────────────┐
│          Kernel (Socket Layer)                          │
│                                                         │
│  sys_write_handler() → fut_socket_send()               │
│    ├─ Write data to socket->pair->send_buf             │
│    ├─ Signal: data is available!                        │
│    ├─ fut_socket_notify_ready(sockfd, EPOLLIN)  ← NEW  │
│    │  └─ fut_epoll_notify(sockfd, EPOLLIN)             │
│    │     ├─ Add event to epoll->ready_queue             │
│    │     └─ fut_waitq_wake_all(&epoll->wait_queue)     │
│    │        └─ WAKEUP epoll_wait() waiter!             │
│    └─ Return bytes written                             │
└─────────────────────────────────────────────────────────┘
              ↓
┌─────────────────────────────────────────────────────────┐
│          Kernel (POSIX Shim - resumed)                  │
│                                                         │
│  sys_epoll_wait_handler() [RESUMED]                    │
│    └─ fut_epoll_wait() returns:                        │
│       └─ events[0] = {events: EPOLLIN, data: sockfd}   │
│          ready_count = 1                               │
│    └─ Return ready_count=1 to user                     │
└─────────────────────────────────────────────────────────┘
              ↓ (syscall return)
┌─────────────────────────────────────────────────────────┐
│     User Process (resumed)                              │
│                                                         │
│  epoll_wait() returned: 1 ready event                  │
│    ├─ events[0].events = EPOLLIN                       │
│    ├─ events[0].data.fd = sockfd                       │
│    └─ Process: read(sockfd, buf, 4096)                 │
└─────────────────────────────────────────────────────────┘
```

---

## 7. Critical Integration Points

### Socket layer (fut_socket.c)
```c
// When data arrives or space becomes available:
void fut_socket_pair_wake_senders(fut_socket_pair_t *pair) {
    fut_waitq_wake_all(pair->send_waitq);      // Existing
    fut_epoll_notify_ready(..., EPOLLOUT);     // NEW
}

void fut_socket_pair_wake_receivers(fut_socket_pair_t *pair) {
    fut_waitq_wake_all(pair->recv_waitq);      // Existing
    fut_epoll_notify_ready(..., EPOLLIN);      // NEW
}
```

### Listener socket (fut_socket.c)
```c
// When connection arrives:
void fut_socket_listener_queue_connection(...) {
    // ... add to accept queue
    fut_waitq_wake_all(listener->accept_waitq);   // Existing
    fut_epoll_notify_ready(listener_fd, EPOLLIN); // NEW
}
```

### File readiness (VFS)
```c
// Most files always ready, so:
int fut_vfs_poll(struct fut_file *file, int events) {
    if (file->vnode->type == VN_REG) {
        return events;  // Regular files always ready
    }
    // Character devices may block
    if (file->chr_ops && file->chr_ops->poll) {
        return file->chr_ops->poll(file->chr_inode, events);
    }
}
```

---

## 8. Signal Safety Consideration

The signal delivery mechanism is already in place:

```c
long syscall_entry_c(...) {
    long ret = posix_syscall_dispatch(nr, a1, a2, ...);
    
    // Signal delivery BEFORE returning to user
    if (current->pending_signals != 0) {
        check_and_deliver_pending_signals(current, frame);
    }
    
    return ret;
}
```

**For epoll_wait**: Must check for signals and return EINTR before sleeping:

```c
// In sys_epoll_wait_handler:
if (current->pending_signals != 0) {
    return -EINTR;  // Return early if signals pending
}
```

---

## 9. Summary of Required Changes

| File | Changes | Impact |
|------|---------|--------|
| `include/user/sysnums.h` | Add SYS_epoll_* numbers | Low (3 lines) |
| `include/kernel/fut_epoll.h` | NEW file with API | Medium (50 lines) |
| `kernel/ipc/fut_epoll.c` | NEW implementation | High (500+ lines) |
| `kernel/ipc/fut_socket.c` | Add epoll notify callbacks | Medium (50+ lines) |
| `subsystems/posix_compat/posix_syscall.c` | Add 3 handlers + socket integration | High (200+ lines) |
| `kernel/ipc/fut_task.h` | Add per-task epoll FD table | Low (5 lines) |
| `src/user/libfutura/epoll.c` | Update to use kernel syscalls | Medium (100+ lines) |

**Total new code**: ~800 lines
**Modified existing**: ~300 lines
**Estimated effort**: 2-3 days for experienced developer

---

## 10. Testing Strategy

```bash
# Basic functionality
test_epoll_create_close()
test_epoll_ctl_add_mod_del()
test_epoll_wait_timeout()
test_epoll_wait_ready_event()

# Socket integration
test_epoll_socket_connect_readable()
test_epoll_socket_send_writable()
test_epoll_accept_queue_readable()

# Multiple FDs
test_epoll_multiple_fds()
test_epoll_ready_count_accuracy()

# Performance
test_epoll_latency_vs_select()
test_epoll_throughput()

# Edge cases
test_epoll_signal_interruption()
test_epoll_closed_fd_removal()
test_epoll_memory_limits()
```

---

## 11. Files to Review

1. **Current select()**: `subsystems/posix_compat/posix_syscall.c:852-998`
2. **Userland epoll**: `src/user/libfutura/epoll.c` (full file)
3. **Wait queues**: `include/kernel/fut_waitq.h` (full file)
4. **Socket objects**: `include/kernel/fut_socket.h:1-141` (data structures)
5. **VFS integration**: `include/kernel/fut_vfs.h:280-289` (struct fut_file)
6. **Syscall dispatcher**: `subsystems/posix_compat/posix_syscall.c:1364-1452`

