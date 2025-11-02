# Futura OS - select() and epoll Implementation Analysis

## Executive Summary

This document provides a comprehensive analysis of:
1. Current select() syscall implementation
2. Existing epoll infrastructure in userland
3. Integration points with kernel I/O multiplexing
4. Path forward for full epoll support

---

## 1. CURRENT SELECT() IMPLEMENTATION

### Location
**File**: `/home/k/futura/subsystems/posix_compat/posix_syscall.c` (lines 852-998)

### Syscall Numbers
- `SYS_select = 23` (defined in `/home/k/futura/include/user/sysnums.h`)

### Current Implementation Details

#### Handler Signature
```c
static int64_t sys_select_handler(uint64_t nfds, uint64_t readfds, uint64_t writefds,
                                  uint64_t exceptfds, uint64_t timeout_ptr, uint64_t arg6)
```

#### Parameters
1. `nfds`: Highest fd number + 1 (validated max 1024)
2. `readfds`: Pointer to fd_set for read events
3. `writefds`: Pointer to fd_set for write events
4. `exceptfds`: Pointer to fd_set for exceptional conditions
5. `timeout_ptr`: Pointer to timeval struct (NULL for blocking, 0 for non-blocking)

#### Current Behavior
1. **Timeout Handling**:
   - timeout=NULL: Blocking (uses polling loop with 10ms retries)
   - timeout=0: Non-blocking poll (return immediately)
   - timeout>0: Blocking with timeout (polls every 10ms up to timeout limit)

2. **FD Readiness Detection**:
   - Uses `vfs_get_file(fd)` to retrieve file object
   - Regular files/vnodes: Always report as readable and writable
   - Invalid FDs: Marked as exceptions
   - FD set manipulation via bitwise operations

3. **Return Value**:
   - Returns count of ready file descriptors
   - Modifies input fd_sets to contain only ready FDs (in-place)

#### Limitations
- **Polling-based**: No true blocking with wait queues
- **Inefficient timeout**: 10ms polling interval, not event-driven
- **Limited FD classification**: Only checks for regular files or invalid FDs
- **No socket integration**: Doesn't check socket-specific readiness
- **No event queue support**: No connection to kernel event subsystem

### Code Flow
```
sys_select_handler
├── Validate nfds <= 1024
├── Parse timeout parameter (timeval)
├── Loop polling (1 to max_polls iterations):
│   ├── For each fd in [0, nfds):
│   │   ├── Check read_set bit
│   │   │   └── Mark ready if vfs_get_file(fd) succeeds
│   │   └── Check write_set bit
│   │       └── Mark ready if vfs_get_file(fd) succeeds
│   ├── Return if ready_count > 0 or timeout_ms == 0
│   └── Sleep 10ms before next poll
└── Return ready_count
```

---

## 2. EXISTING EPOLL INFRASTRUCTURE

### Userland epoll.c Implementation
**Location**: `/home/k/futura/src/user/libfutura/epoll.c` (256 lines)

#### Key Data Structures

##### epoll_stub (Per-epoll-set state)
```c
struct epoll_stub {
    bool in_use;                              // Slot usage flag
    int handle;                               // Unique epoll fd
    int count;                                // Number of monitored FDs
    struct epoll_entry items[MAX_EPOLL_ENTRIES];  // Watched FDs
};

#define MAX_EPOLL_SETS 8        // 8 epoll instances per process
#define MAX_EPOLL_ENTRIES 64    // 64 FDs per epoll set
```

##### epoll_entry (Per-FD tracking)
```c
struct epoll_entry {
    int fd;                  // File descriptor
    uint32_t events;         // Requested events (EPOLLIN, EPOLLOUT, etc.)
};

#define EPOLLIN 0x001u
#define EPOLLOUT 0x004u
```

#### Implemented Functions

**epoll_create1(int flags)**
- Creates new epoll instance
- Returns handle (fd-like integer, starts from 3)
- Allocates from global epoll_sets array

**epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)**
- Modifies monitored FD set:
  - `EPOLL_CTL_ADD`: Add FD with events mask
  - `EPOLL_CTL_MOD`: Modify events mask for existing FD
  - `EPOLL_CTL_DEL`: Remove FD from monitoring
- Stores in epoll_stub::items array

**epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout)**
- Polls registered FDs and returns ready events
- **CRITICAL**: Includes multi-layer event checking:

```c
for (;;) {
    int produced = 0;
    for (i = 0; i < stub->count && produced < maxevents; ++i) {
        int fd = stub->items[i].fd;
        
        // Check timerfd readiness
        if (__fut_timerfd_is_timer(fd)) {
            if (__fut_timerfd_poll(fd, &ready_mask)) {
                // Report event
            }
            continue;
        }
        
        // Check unix socket readiness
        if (__fut_unix_socket_poll(fd, evmask, &ready_mask)) {
            // Report event
            continue;
        }
        
        // Check eventfd readiness
        if (__fut_eventfd_is(fd)) {
            if (__fut_eventfd_poll(fd, evmask, &mask)) {
                // Report event
            }
            continue;
        }
        
        // Check signalfd readiness
        if (__fut_signalfd_is(fd)) {
            if (__fut_signalfd_poll(fd, &mask)) {
                // Report event
            }
            continue;
        }
        
        // Default: always ready (regular files)
        events[produced].events = evmask;
        produced++;
    }
    
    if (produced > 0 || timeout == 0) {
        return produced;
    }
    
    // Intelligent timeout handling:
    wait_ms = determine_sleep_duration(timeout, remaining);
    sleep_millis(wait_ms);
}
```

**epoll_create(int size)**
- Wrapper: calls epoll_create1(0)

**__fut_epoll_close(int epfd)**
- Internal cleanup function
- Marks stub as unused

#### Limitations
- **User-space only**: No kernel support
- **Polling implementation**: Uses nanosleep in polling loop
- **Hardcoded limits**: 8 epoll sets × 64 entries max
- **No epoll_create2/epoll_wait4**: Missing Linux 2.6.27+ features
- **No semaphore epoll**: No EPOLLSEM support
- **No exclusive wakeup**: No EPOLLEXCLUSIVE flag

#### Supported Event Types
- **timerfd events** (via __fut_timerfd_poll)
- **unix socket events** (via __fut_unix_socket_poll)
- **eventfd events** (via __fut_eventfd_poll)
- **signalfd events** (via __fut_signalfd_poll)
- **Regular files** (always report as ready)

---

## 3. KERNEL I/O MULTIPLEXING INFRASTRUCTURE

### Wait Queue System
**Location**: `/home/k/futura/include/kernel/fut_waitq.h`

```c
typedef struct fut_waitq {
    fut_thread_t *head;              // Linked list of waiting threads
    fut_thread_t *tail;
    fut_spinlock_t lock;             // Protects queue operations
} fut_waitq_t;

// API Functions
void fut_waitq_init(fut_waitq_t *q);
void fut_waitq_sleep_locked(fut_waitq_t *q, fut_spinlock_t *released_lock,
                            enum fut_thread_state state);
void fut_waitq_wake_one(fut_waitq_t *q);
void fut_waitq_wake_all(fut_waitq_t *q);
bool fut_waitq_remove_thread(fut_waitq_t *q, fut_thread_t *thread);
```

**Purpose**: Low-level blocking primitive for scheduler integration

### Socket Readiness Checking
**Location**: `/home/k/futura/include/kernel/fut_socket.h` (line 263)

```c
/**
 * Check if socket is ready for I/O (for poll/select).
 *
 * @param socket Socket to check
 * @param events Requested events (POLLIN, POLLOUT, etc)
 * @return Bitmask of ready events
 */
int fut_socket_poll(fut_socket_t *socket, int events);
```

**Socket State Tracking**:
```c
enum fut_socket_state {
    FUT_SOCK_CREATED = 0,       // Newly created, unbound
    FUT_SOCK_BOUND = 1,         // Bound to path (not listening)
    FUT_SOCK_LISTENING = 2,     // Listening for connections
    FUT_SOCK_CONNECTING = 3,    // Connecting (pending)
    FUT_SOCK_CONNECTED = 4,     // Connected to peer
    FUT_SOCK_CLOSED = 5,        // Closed/invalid
};
```

**Connection State**:
```c
typedef struct fut_socket_pair {
    uint8_t *send_buf;              // Outgoing data buffer (4KB)
    uint32_t send_head;             // Write position
    uint32_t send_tail;             // Read position
    
    uint8_t *recv_buf;              // Incoming data buffer (4KB)
    uint32_t recv_head;
    uint32_t recv_tail;
    
    struct fut_waitq *send_waitq;   // ← Wait queue for send availability
    struct fut_waitq *recv_waitq;   // ← Wait queue for data availability
    struct fut_socket *peer;
    uint64_t refcount;
    fut_spinlock_t lock;
} fut_socket_pair_t;
```

**Listener State**:
```c
typedef struct fut_socket_listener {
    fut_socket_connection_entry_t queue[FUT_SOCKET_QUEUE_MAX];
    uint32_t queue_head;
    uint32_t queue_count;
    struct fut_waitq *accept_waitq;  // ← Wait queue for accept()
    int backlog;
} fut_socket_listener_t;
```

### File Descriptor System
**Location**: `/home/k/futura/include/kernel/fut_vfs.h`

```c
struct fut_file {
    struct fut_vnode *vnode;          // Associated vnode
    uint64_t offset;                  // Current file offset
    int flags;                        // Open flags
    uint32_t refcount;                // Reference count
    const struct fut_file_ops *chr_ops;  // Character device operations
    void *chr_inode;                  // Driver-provided inode
    void *chr_private;                // Driver private state
    int fd_flags;                     // FD-specific flags
};
```

---

## 4. SYSCALL DISPATCHER ARCHITECTURE

**Location**: `/home/k/futura/subsystems/posix_compat/posix_syscall.c` (lines 1364-1452)

### Handler Table
```c
typedef int64_t (*syscall_handler_t)(uint64_t arg1, uint64_t arg2,
                                      uint64_t arg3, uint64_t arg4,
                                      uint64_t arg5, uint64_t arg6);

static syscall_handler_t syscall_table[MAX_SYSCALL] = {
    [SYS_read]       = sys_read_handler,
    [SYS_write]      = sys_write_handler,
    [SYS_select]     = sys_select_handler,
    // ... more handlers
};

#define MAX_SYSCALL 512
```

### Dispatcher Entry Point
```c
int64_t posix_syscall_dispatch(uint64_t syscall_num,
                                uint64_t arg1, uint64_t arg2,
                                uint64_t arg3, uint64_t arg4,
                                uint64_t arg5, uint64_t arg6) {
    if (syscall_num >= MAX_SYSCALL) {
        return -1;  // ENOSYS
    }
    
    syscall_handler_t handler = syscall_table[syscall_num];
    if (handler == NULL) {
        handler = sys_unimplemented;
    }
    
    int64_t result = handler(arg1, arg2, arg3, arg4, arg5, arg6);
    
    // Signal delivery on return
    if (current && current->pending_signals != 0 && frame_ptr) {
        int sig_delivered = check_and_deliver_pending_signals(current, frame);
    }
    
    return result;
}
```

### Available Syscall Numbers
```
0: read          23: select       45: recvfrom     80: chdir
1: write         32: dup          49: bind         83: mkdir
2: open          33: dup2         50: listen       84: rmdir
3: close         35: nanosleep    51: accept       87: unlink
4: stat          39: getpid       53: connect      89: readlink
5: fstat         41: socket       57: fork         90: chmod
8: lseek         42: echo         59: execve      102: getuid
9: mmap          44: sendto       60: exit        104: getgid
11: munmap       45: recvfrom     61: wait4       217: getdents64
12: brk          49: bind         62: kill        257: openat
13: sigaction    50: listen       79: getcwd      400: time_millis
14: sigprocmask  51: accept       80: chdir
16: ioctl
22: pipe
```

**Available for epoll**:
- **228**: epoll_create (standard Linux)
- **229**: epoll_ctl (standard Linux)
- **230**: epoll_wait (standard Linux)
- **328**: epoll_create1 (newer, supports O_CLOEXEC)
- **329**: epoll_pwait (timeout with signal masking)

---

## 5. SOCKET FD MANAGEMENT

**Location**: `/home/k/futura/subsystems/posix_compat/posix_syscall.c` (lines 94-156)

```c
#define MAX_SOCKET_FDS 256

/** Per-task socket FD table mapping FDs to kernel socket objects */
static fut_socket_t *socket_fd_table[MAX_SOCKET_FDS] = {NULL};

// FD Management Functions:
static fut_socket_t *get_socket_from_fd(int fd)
static int set_socket_for_fd(int fd, fut_socket_t *socket)
static int allocate_socket_fd(fut_socket_t *socket)
static int release_socket_fd(int fd)
```

**Note**: Socket FDs are separate from regular file FDs. The dispatcher checks:
1. Socket FD table first (lines 278-284)
2. VFS FD table fallback (line 287)

---

## 6. INTEGRATION POINTS WITH EXISTING CODE

### Signal Delivery on Syscall Return
**Location**: `/home/k/futura/subsystems/posix_compat/posix_syscall.c` (lines 1648-1670)

```c
long syscall_entry_c(uint64_t nr, uint64_t a1, uint64_t a2, uint64_t a3,
                     uint64_t a4, uint64_t a5, uint64_t a6,
                     uint64_t *frame_ptr) {
    long ret = (long)posix_syscall_dispatch(nr, a1, a2, a3, a4, a5, a6);
    
    // Check for pending signals and deliver them before returning to user
    fut_task_t *current = fut_task_current();
    if (current && current->pending_signals != 0 && frame_ptr) {
        fut_interrupt_frame_t *frame = (fut_interrupt_frame_t *)frame_ptr;
        int sig_delivered = check_and_deliver_pending_signals(current, frame);
    }
    
    return ret;
}
```

**Implication**: epoll_wait must handle signal interruption (EINTR)

---

## 7. REQUIRED DATA STRUCTURES FOR KERNEL EPOLL

### Kernel epoll Set
```c
struct fut_epoll {
    uint32_t epoll_id;              // Unique ID for debugging
    fut_spinlock_t lock;            // Protects internal state
    struct fut_waitq *wait_queue;   // Threads waiting on epoll_wait
    
    // Hash table or array for tracked FDs
    struct fut_epoll_entry {
        int fd;                     // Monitored FD
        uint32_t events;            // Requested events (EPOLLIN, EPOLLOUT, ...)
        void *priv;                 // User data (void *ptr, u32, u64)
    } *entries;
    uint32_t entry_count;
    uint32_t entry_capacity;
    
    // For wake-up coordination
    uint64_t ready_mask;            // Bitmask of ready FDs (for small epoll sets)
    struct fut_epoll_entry *ready_queue;  // Queue of ready events
    uint32_t ready_count;           // Number of ready events
};
```

### Event Callback Registration
```c
// Per-FD event callback
typedef void (*epoll_callback_t)(int fd, uint32_t ready_events, void *context);

// When socket becomes ready:
// 1. Callback invoked in socket send/recv path
// 2. Wakeup epoll thread from wait queue
// 3. Return to epoll_wait with ready events
```

---

## 8. PATH FORWARD FOR KERNEL EPOLL

### Phase 1: Add syscall numbers and stubs
1. Add to `include/user/sysnums.h`:
   - `#define SYS_epoll_create 228`
   - `#define SYS_epoll_ctl 229`
   - `#define SYS_epoll_wait 230`

2. Add handlers in `posix_syscall.c`:
   - `sys_epoll_create_handler`
   - `sys_epoll_ctl_handler`
   - `sys_epoll_wait_handler`

3. Register in syscall_table

### Phase 2: Implement kernel epoll object system
1. Create `kernel/ipc/fut_epoll.c`:
   - epoll set creation/destruction
   - FD tracking and event masking
   - Ready event queuing

2. Create `include/kernel/fut_epoll.h`:
   - Public API for kernel components
   - Event callback mechanism

3. Integrate with wait queue system:
   - Use `fut_waitq_t` for blocking threads
   - Implement wake-up on event ready

### Phase 3: Add readiness checking to kernel components
1. Modify socket code:
   - Call epoll callback on `fut_socket_send` completion
   - Call epoll callback on `fut_socket_recv` completion
   - Call epoll callback on listener accept queue change

2. Modify VFS code:
   - Determine file readiness (mostly always ready)
   - Register callbacks for special files

3. Modify pipe code:
   - Similar to socket callbacks

### Phase 4: Optimize from polling to event-driven
1. Replace polling loop in `sys_epoll_wait_handler` with:
   - Sleep on `fut_waitq_t` associated with epoll set
   - Wake when any monitored FD becomes ready
   - Return ready events and counts

2. Replace 10ms polling in `sys_select_handler` with:
   - Convert fd_sets to epoll format
   - Use kernel epoll internally
   - Convert back to fd_sets format

---

## 9. KEY CONSIDERATIONS

### Per-Task vs Global
- **Current**: Socket FD table is per-task static (posix_syscall.c)
- **Issue**: Can't support multiple processes sharing epoll
- **Solution**: Move to per-task structure in `fut_task_t`

### epoll_create Return Value
- **Current select()**: Returns count of ready FDs
- **New epoll()**: Returns fd-like handle (integer)
- **Dispatcher challenge**: Must track epoll sets like sockets

### Signal Safety
- **epoll_wait must return EINTR on signal**
- **Current implementation**: Blocks until timeout/ready
- **Required**: Check pending_signals before returning

### Memory Efficiency
- **Current limits**: 8 epoll sets × 64 FDs max (userland)
- **Kernel should support**: Dynamic allocation per epoll_create

### Compatibility Layer
- **poll()** implementation in `libfutura/poll.c` already converts to epoll-like checks
- **select()** should internally use kernel epoll once available

---

## 10. IMPLEMENTATION CHECKLIST

- [ ] Define epoll syscall numbers (228-230)
- [ ] Add header `include/kernel/fut_epoll.h`
- [ ] Create `kernel/ipc/fut_epoll.c` with:
  - [ ] `fut_epoll_create(int flags)` → returns epoll_id
  - [ ] `fut_epoll_add(int epfd, int fd, uint32_t events, void *data)`
  - [ ] `fut_epoll_mod(int epfd, int fd, uint32_t events)`
  - [ ] `fut_epoll_del(int epfd, int fd)`
  - [ ] `fut_epoll_wait(int epfd, epoll_event *events, int maxevents, int timeout)`
  - [ ] Event callback registration system
- [ ] Add handlers in `posix_syscall.c`:
  - [ ] `sys_epoll_create_handler`
  - [ ] `sys_epoll_ctl_handler`
  - [ ] `sys_epoll_wait_handler`
- [ ] Integrate event callbacks in:
  - [ ] `kernel/ipc/fut_socket.c` (send/recv completion)
  - [ ] Character device layer (file/pipe readiness)
- [ ] Add epoll FD table to per-task state
- [ ] Refactor select() to use kernel epoll internally
- [ ] Update poll() to accept kernel epoll results
- [ ] Add tests for epoll functionality

---

## 11. FILE LOCATIONS REFERENCE

| Component | File | Lines |
|-----------|------|-------|
| Syscall numbers | include/user/sysnums.h | 1-48 |
| select() handler | subsystems/posix_compat/posix_syscall.c | 852-998 |
| Syscall dispatcher | subsystems/posix_compat/posix_syscall.c | 1364-1452 |
| Socket FD mgmt | subsystems/posix_compat/posix_syscall.c | 94-156 |
| Wait queues | include/kernel/fut_waitq.h | 1-28 |
| Socket objects | include/kernel/fut_socket.h | 1-264 |
| File descriptors | include/kernel/fut_vfs.h | 280-289 |
| Userland epoll | src/user/libfutura/epoll.c | 1-256 |
| Userland poll | src/user/libfutura/poll.c | 1-150 |

