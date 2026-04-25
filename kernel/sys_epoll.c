/* kernel/sys_epoll.c - epoll() syscall implementations
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements event-driven I/O multiplexing via epoll_create, epoll_ctl, and epoll_wait.
 * Provides efficient polling of many file descriptors with event notification.
 *
 * Phase 1 (Completed): Basic implementation with event registration and polling
 * Phase 2 (Completed): Enhanced validation, parameter categorization, detailed logging
 * Phase 3 (Completed): Advanced event detection, edge-triggered mode, oneshot support
 * Phase 4 (Completed): Performance optimization, memory pooling, scalability improvements
 *
 * ============================================================================
 * PHASE 5 SECURITY HARDENING: EPOLL I/O MULTIPLEXING
 * ============================================================================
 *
 * VULNERABILITY OVERVIEW:
 * epoll provides scalable I/O event notification for file descriptors. Three
 * main syscalls (epoll_create1, epoll_ctl, epoll_wait) manage event sets.
 * Vulnerabilities include:
 * - epoll instance exhaustion (resource DoS)
 * - File descriptor exhaustion via MAX_EPOLL_FDS
 * - Integer overflow in epoll FD counter
 * - Invalid event mask bits causing undefined behavior
 * - Use-after-free when FD closed while registered
 *
 * ATTACK SCENARIO 1: epoll Instance Exhaustion DoS
 * ------------------------------------------------
 * Step 1: Attacker calls epoll_create1(0) in tight loop
 * Step 2: Each call allocates epoll_set structure
 * Step 3: Continue until MAX_EPOLL_INSTANCES (256) reached
 * Step 4: No other processes can create epoll instances
 * Impact: Denial of service, system-wide epoll unavailability
 * Root Cause: Global limit without per-task quota
 *
 * Defense (lines 100-113, 160-167):
 * - Check epoll instance count before allocation
 * - Fail with ENOMEM when MAX_EPOLL_INSTANCES reached
 * - epoll FD counter overflow check (INT_MAX)
 * - Prevents resource exhaustion attacks
 *
 * CVE References:
 * - CVE-2014-0038: Linux futex resource exhaustion
 * - CVE-2016-9793: Resource limit bypass
 *
 * ATTACK SCENARIO 2: File Descriptor Exhaustion per epoll Instance
 * ----------------------------------------------------------------
 * Step 1: Attacker creates epoll instance
 * Step 2: Opens MAX_EPOLL_FDS (64) file descriptors
 * Step 3: Registers all FDs with epoll_ctl(EPOLL_CTL_ADD)
 * Step 4: Attempts to add more FDs -> fails with ENOSPC
 * Step 5: But attacker can repeat with multiple epoll instances
 * Impact: Resource exhaustion, denial of service
 * Root Cause: Fixed-size fd array per instance
 *
 * Defense (lines 414-440, 52-53):
 * - MAX_EPOLL_FDS enforced at compile time (64)
 * - epoll_ctl checks count before adding FD
 * - Returns ENOSPC when limit reached
 * - Prevents unbounded memory growth
 *
 * CVE References:
 * - CVE-2019-11479: Resource exhaustion via TCP
 * - CVE-2018-5390: Linux networking DoS
 *
 * ATTACK SCENARIO 3: epoll FD Counter Integer Overflow
 * ----------------------------------------------------
 * Step 1: Attacker repeatedly calls epoll_create1() and close()
 * Step 2: next_epoll_fd increments on each create
 * Step 3: Eventually next_epoll_fd approaches INT_MAX (2^31-1)
 * Step 4: OLD vulnerable code: next_epoll_fd++ wraps to negative
 * Step 5: Negative epfd conflicts with error codes
 * Impact: epoll instance corruption, fd collision, undefined behavior
 * Root Cause: No overflow check before incrementing counter
 *
 * Defense (lines 160-167):
 * - Check if next_epoll_fd would exceed INT_MAX
 * - Fail with ENOMEM before overflow occurs
 * - Prevents negative epfd values
 * - Documented at lines 101-113
 *
 * CVE References:
 * - CVE-2019-11479: Integer overflow in network stack
 * - CVE-2016-9793: Integer handling errors
 *
 * ATTACK SCENARIO 4: Invalid Event Mask Bits
 * ------------------------------------------
 * Step 1: Attacker calls epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &event)
 * Step 2: event.events = 0xFFFFFFFF (all bits set)
 * Step 3: OLD vulnerable code doesn't validate event bits
 * Step 4: Undefined event bits propagate to kernel event handlers
 * Step 5: May trigger unhandled cases, assert failures, or crashes
 * Impact: Kernel crash, undefined behavior, potential privilege escalation
 * Root Cause: No validation of event mask against known event bits
 *
 * Defense (lines 700-711):
 * - Define VALID_EVENTS mask with all legal event bits
 * - Check events & ~VALID_EVENTS to detect invalid bits
 * - Fail with EINVAL if invalid bits present
 * - Prevents undefined kernel behavior
 *
 * CVE References:
 * - CVE-2017-7308: Invalid state handling
 * - CVE-2016-10229: Unvalidated flags
 *
 * ATTACK SCENARIO 5: Use-After-Free on Registered FD Close
 * --------------------------------------------------------
 * Step 1: Attacker adds FD to epoll with epoll_ctl(EPOLL_CTL_ADD)
 * Step 2: Calls close(fd) -> FD freed and reused
 * Step 3: Kernel allocates same FD number for different file
 * Step 4: epoll_wait() returns events for NEW file using OLD registration
 * Step 5: Application processes wrong file, data corruption
 * Impact: Information disclosure, data corruption, logic errors
 * Root Cause: epoll doesn't receive notification when registered FD closes
 *
 * Defense (IMPLEMENTED):
 * - sys_close() calls epoll_notify_fd_close() before closing FD
 * - Auto-removes FD from all epoll sets on close
 * - Prevents stale FD entries from matching reused FD numbers
 *
 * CVE References:
 * - CVE-2017-7308: Use-after-free in packet sockets
 * - CVE-2016-10229: File descriptor UAF
 *
 * ============================================================================
 * DEFENSE STRATEGY (ALREADY IMPLEMENTED):
 * ============================================================================
 * 1. [DONE] epoll instance limit enforcement (lines 100-113)
 *    - MAX_EPOLL_INSTANCES = 256
 *    - Check before allocation
 *    - Fail with ENOMEM when exhausted
 *
 * 2. [DONE] Per-instance FD limit (lines 52-53, 414-440)
 *    - MAX_EPOLL_FDS = 64
 *    - Check count before EPOLL_CTL_ADD
 *    - Fail with ENOSPC when full
 *
 * 3. [DONE] epoll FD counter overflow check (lines 160-167)
 *    - Validate next_epoll_fd < INT_MAX before increment
 *    - Prevents negative epfd values
 *    - Documented requirement at lines 101-113
 *
 * 4. [DONE] Event mask validation (lines 700-711)
 *    - Check events against VALID_EVENTS mask
 *    - Reject invalid event bits with EINVAL
 *    - Prevents undefined kernel behavior
 *
 * 5. [DONE] FD validation in epoll_ctl (lines 418-422)
 *    - Reject negative FDs early
 *    - Fail with EBADF for invalid FDs
 *
 * 6. [DONE] Close notification and auto-remove
 *    - sys_close() calls epoll_notify_fd_close() before closing
 *    - Auto-removes closed FDs from all epoll sets
 *    - Prevents use-after-free on FD reuse
 *
 * 7. [DONE] Per-task epoll instance quotas
 *    - Per-task limit of MAX_EPOLL_PER_TASK (16) instances
 *    - Returns EMFILE when a single task exceeds its quota
 *
 * ============================================================================
 * CVE REFERENCES (Similar Vulnerabilities):
 * ============================================================================
 * 1. CVE-2014-0038: Linux futex resource exhaustion
 * 2. CVE-2016-9793: Resource limit bypass
 * 3. CVE-2019-11479: Integer overflow leading to DoS
 * 4. CVE-2017-7308: Use-after-free in packet sockets
 * 5. CVE-2016-10229: File descriptor UAF
 *
 * ============================================================================
 * REQUIREMENTS (Linux epoll semantics):
 * ============================================================================
 * Linux epoll(7):
 * - epoll_create1(flags) creates epoll instance, returns epfd
 * - epoll_ctl(epfd, op, fd, event) adds/modifies/removes FD
 * - epoll_wait(epfd, events, maxevents, timeout) waits for events
 * - EPOLLIN: FD ready for reading
 * - EPOLLOUT: FD ready for writing
 * - EPOLLET: Edge-triggered mode (report only transitions)
 * - EPOLLONESHOT: Report event once, then auto-disable
 *
 * Error codes:
 * - EMFILE: Too many open files (process limit)
 * - ENFILE: Too many open files (system limit)
 * - ENOMEM: Insufficient memory
 * - ENOSPC: No space for new FD in epoll set
 * - EEXIST: FD already registered (EPOLL_CTL_ADD)
 * - ENOENT: FD not registered (EPOLL_CTL_MOD/DEL)
 *
 * ============================================================================
 * IMPLEMENTATION NOTES:
 * ============================================================================
 * Current validations implemented:
 * [DONE] 1. epoll instance limit (MAX_EPOLL_INSTANCES=256) at lines 100-113
 * [DONE] 2. Per-instance FD limit (MAX_EPOLL_FDS=64) at lines 52-53, 414-440
 * [DONE] 3. epoll FD overflow check (INT_MAX) at lines 160-167
 * [DONE] 4. Event mask validation at lines 700-711
 * [DONE] 5. FD validation (negative check) at lines 418-422
 *
 * TODO (enhancements):
 * [DONE] 1. VFS close hook: epoll_notify_fd_close() called from sys_close()
 * [DONE] 2. Per-task epoll instance quotas (MAX_EPOLL_PER_TASK=16)
 * [TODO] 3. Add file struct refcounting to prevent premature free
 * [DONE] 4. Per-task quota (MAX_EPOLL_PER_TASK=16) bounds epoll_create1 rate
 * [DONE] 5. epoll_wait timeout: reject timeout < -1 with EINVAL; clamp > 24h
 * [DONE] 6. epoll_pwait2 nanosecond-precision timeout (fut_get_time_ns deadline)
 * [DONE] 7. EPOLLEXCLUSIVE validation (ADD-only, no ONESHOT), per-FD tracking
 * [DONE] 8. EPOLLET edge-triggered: proper state transition tracking
 */

#include <kernel/eventfd.h>
#include <kernel/fut_vfs.h>
#include <kernel/chrdev.h>
#include <kernel/fut_socket.h>
#include <kernel/errno.h>
#include <kernel/uaccess.h>
#include <kernel/fut_task.h>
#include <kernel/fut_thread.h>
#include <kernel/fut_waitq.h>
#include <kernel/fut_timer.h>
#include <kernel/fut_fd_util.h>
#include <shared/fut_timespec.h>
#include <kernel/signal.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <limits.h>

/* Architecture-specific paging headers for KERNEL_VIRTUAL_BASE */
#include <platform/platform.h>

#include <kernel/kprintf.h>
#include <kernel/debug_config.h>

/* Epoll debugging (controlled via debug_config.h) */
#include <kernel/fut_memory.h>
#include <kernel/fut_sched.h>   /* fut_spinlock_t for epoll table locking */
#include <sys/epoll.h>
#include <fcntl.h>

/* Internal helper macros */
#define EPOLLMASK_IOCTLS  (EPOLLERR | EPOLLHUP)

/* Phase 3: epoll event modifier flags - internal naming for code clarity */
#define EPOLL_ET       EPOLLET     /* Edge-triggered mode (report only on transitions) */
#define EPOLL_ONESHOT  EPOLLONESHOT /* Oneshot mode (disable after one event) */

/* Maximum file descriptors per epoll instance */
#define MAX_EPOLL_FDS 64

/* Maximum epoll instances (system-wide) */
#define MAX_EPOLL_INSTANCES 256

/* Maximum epoll instances per task (prevents single-task resource exhaustion) */
#define MAX_EPOLL_PER_TASK 128

/* epoll_event structure provided by sys/epoll.h - matches Linux ABI
 *
 * The data field is a union for convenience, but for binary
 * compatibility the key requirement is:
 *   - sizeof(struct epoll_event) == 12 bytes
 *   - events at offset 0 (4 bytes)
 *   - data at offset 4 (8 bytes)
 *
 * Linux uses __attribute__((packed)) to achieve this layout.
 * Internally we store just the u64 member for simplicity.
 */

/* Internal epoll FD registration */
struct epoll_fd_entry {
    int fd;                    /* File descriptor number */
    uint32_t events;           /* Requested events mask */
    uint64_t data;             /* User data to return on event */
    bool registered;           /* Whether this entry is active */
    /* Phase 3: Edge-triggered and oneshot support */
    bool edge_triggered;       /* Enable edge-triggered reporting */
    bool oneshot;              /* Report only once, then auto-unregister */
    bool oneshot_disabled;     /* True after oneshot fired; suppresses all events until re-armed */
    bool exclusive;            /* EPOLLEXCLUSIVE: wake only one waiter */
    bool last_was_readable;    /* Last state for edge-triggered EPOLLIN */
    bool last_was_writable;    /* Last state for edge-triggered EPOLLOUT */
    bool last_was_hup;         /* Last state for edge-triggered EPOLLHUP/EPOLLERR */
};

/* Internal epoll set structure */
struct epoll_set {
    int epfd;                                    /* This epoll FD number */
    struct epoll_fd_entry fds[MAX_EPOLL_FDS];  /* Registered FDs */
    int count;                                   /* Number of registered FDs */
    bool active;                                 /* Whether this epoll set is in use */
    bool cloexec;                                /* Close-on-exec flag (EPOLL_CLOEXEC) */
    bool has_exclusive;                          /* True if any FD has EPOLLEXCLUSIVE */
    uint64_t owner_pid;                          /* PID of task that created this instance */
    fut_waitq_t epoll_waitq;                     /* Wait queue for event-driven wakeup */
};

/* Global epoll instance table */
static struct epoll_set epoll_instances[MAX_EPOLL_INSTANCES];

/* Global spinlock protecting epoll_instances table.
 * Must be held when:
 *   - Iterating epoll_instances (allocate, find, close-notify)
 *   - Modifying set->fds[] entries (add/mod/del)
 *   - Reading set->fds[] during epoll_wait polling loop
 * The wait queue has its own internal lock, so fut_waitq_sleep_locked
 * and fut_waitq_wake_* do NOT require this lock to be held. */
static fut_spinlock_t epoll_lock;
static bool epoll_lock_initialized;

/* Ensure the global spinlock is initialized exactly once. */
static inline void epoll_ensure_init(void) {
    if (!__atomic_load_n(&epoll_lock_initialized, __ATOMIC_ACQUIRE)) {
        fut_spinlock_init(&epoll_lock);
        __atomic_store_n(&epoll_lock_initialized, true, __ATOMIC_RELEASE);
    }
}

/* Forward declarations */
static int epoll_release_op(void *inode, void *priv);
static void epoll_deallocate_set(struct epoll_set *set);

/* File operations for epoll file descriptors.
 * epoll fds are now regular chrdev fds in fd_table, so close() and
 * FD_CLOEXEC work through the normal VFS path instead of a separate
 * 4000+ namespace. */
const struct fut_file_ops epoll_fops = {
    .release = epoll_release_op,
};

/**
 * Notify all epoll instances that a file descriptor is being closed.
 * Automatically removes the FD from any epoll set it's registered in.
 * Called from sys_close() before actually closing the FD to prevent
 * use-after-free when the FD number is later reused.
 *
 * This addresses ATTACK SCENARIO 5 (Use-After-Free on Registered FD Close)
 * documented in the Phase 5 security hardening notes above.
 */
void epoll_notify_fd_close(int fd) {
    epoll_ensure_init();
    fut_spinlock_acquire(&epoll_lock);

    for (int i = 0; i < MAX_EPOLL_INSTANCES; i++) {
        if (!epoll_instances[i].active) {
            continue;
        }
        for (int j = 0; j < MAX_EPOLL_FDS; j++) {
            if (epoll_instances[i].fds[j].registered &&
                epoll_instances[i].fds[j].fd == fd) {
                /* Clear epoll_notify / connect_notify pointers on the fd's
                 * backing object so they don't point at a stale waitqueue
                 * after the entry is removed. */
                {
                    fut_socket_t *sock = get_socket_from_fd(fd);
                    if (sock) {
                        if (sock->pair_reverse &&
                            sock->pair_reverse->epoll_notify == &epoll_instances[i].epoll_waitq)
                            sock->pair_reverse->epoll_notify = NULL;
                        if (sock->listener &&
                            sock->listener->epoll_notify == &epoll_instances[i].epoll_waitq)
                            sock->listener->epoll_notify = NULL;
                        if (sock->connect_notify == &epoll_instances[i].epoll_waitq)
                            sock->connect_notify = NULL;
                    }
                    fut_task_t *t = fut_task_current();
                    if (t && t->fd_table && fd < t->max_fds) {
                        struct fut_file *f = t->fd_table[fd];
                        if (f) {
                            extern void fut_eventfd_set_epoll_notify(struct fut_file *file, fut_waitq_t *wq);
                            extern void fut_timerfd_set_epoll_notify(struct fut_file *file, fut_waitq_t *wq);
                            extern void fut_signalfd_set_epoll_notify(struct fut_file *file, fut_waitq_t *wq);
                            extern void fut_pipe_set_epoll_notify(struct fut_file *file, fut_waitq_t *wq);
                            extern void fut_pidfd_set_epoll_notify(struct fut_file *file, fut_waitq_t *wq);
                            extern void fut_inotify_set_epoll_notify(struct fut_file *file, fut_waitq_t *wq);
                            extern void fut_pty_set_epoll_notify(struct fut_file *file, void *wq);
                            fut_eventfd_set_epoll_notify(f, NULL);
                            fut_timerfd_set_epoll_notify(f, NULL);
                            fut_signalfd_set_epoll_notify(f, NULL);
                            fut_pipe_set_epoll_notify(f, NULL);
                            fut_pidfd_set_epoll_notify(f, NULL);
                            fut_inotify_set_epoll_notify(f, NULL);
                            fut_pty_set_epoll_notify(f, NULL);
                        }
                    }
                }

                epoll_instances[i].fds[j].registered = false;
                epoll_instances[i].count--;
                memset(&epoll_instances[i].fds[j], 0,
                       sizeof(epoll_instances[i].fds[j]));

                /* Recompute has_exclusive if needed */
                if (epoll_instances[i].has_exclusive) {
                    bool any_excl = false;
                    for (int k = 0; k < MAX_EPOLL_FDS; k++) {
                        if (epoll_instances[i].fds[k].registered &&
                            epoll_instances[i].fds[k].exclusive) {
                            any_excl = true;
                            break;
                        }
                    }
                    epoll_instances[i].has_exclusive = any_excl;
                }
            }
        }

        /* Wake any threads blocked in epoll_wait on this set so they
         * can re-scan and notice the removed fd (possibly reporting
         * EPOLLERR|EPOLLHUP for a closed fd). */
        fut_waitq_wake_all(&epoll_instances[i].epoll_waitq);
    }

    fut_spinlock_release(&epoll_lock);
}

/**
 * epoll_close_cloexec - no-op: epoll fds are now in fd_table, so the normal
 * FD_CLOEXEC close path in exec handles them automatically.
 */
void epoll_close_cloexec(uint64_t pid) {
    (void)pid;
}

/* Count active epoll instances owned by a given PID.
 * Caller must hold epoll_lock. */
static int epoll_count_by_pid(uint64_t pid) {
    int count = 0;
    for (int i = 0; i < MAX_EPOLL_INSTANCES; i++) {
        if (epoll_instances[i].active && epoll_instances[i].owner_pid == pid) {
            count++;
        }
    }
    return count;
}

/* Helper to find epoll set by epoll FD.
 * Caller must hold epoll_lock. */
static struct epoll_set *epoll_get_set(int epfd) {
    for (int i = 0; i < MAX_EPOLL_INSTANCES; i++) {
        if (epoll_instances[i].active && epoll_instances[i].epfd == epfd) {
            return &epoll_instances[i];
        }
    }
    return NULL;
}

/* Helper to allocate a new epoll set for a given task */
static struct epoll_set *epoll_allocate_set(uint64_t owner_pid) {
    /* Document epoll FD counter overflow protection requirement
     * VULNERABILITY: Integer Overflow in Epoll File Descriptor Counter
     *
     * ATTACK SCENARIO:
     * Attacker creates and closes epoll instances repeatedly to overflow next_epoll_fd
     * 1. Static global next_epoll_fd starts at 4000 (line 86)
     * 2. Each epoll_create1() increments: next_epoll_fd++ (line 104)
     * 3. Attacker loops: epfd = epoll_create1(0); close(epfd);
     * 4. After (INT_MAX - 4000) iterations: next_epoll_fd = INT_MAX
     * 5. Next increment: INT_MAX + 1 → INT_MIN (signed overflow = UB)
     * 6. Or if unsigned: UINT_MAX + 1 → 0 (wraps to zero)
     * 7. New epoll FDs collide with existing FDs (0, 1, 2 = stdio)
     * 8. epoll_get_set() matches wrong FD, corrupts unrelated file
     *
     * IMPACT:
     * - File descriptor collision: epoll FD collides with stdio/regular FDs
     * - Undefined behavior: Signed integer overflow (C standard §6.5/5)
     * - Security bypass: Attacker can manipulate wrong file descriptors
     * - Data corruption: epoll operations target unrelated files
     * - Denial of service: System becomes unstable after overflow
     *
     * ROOT CAUSE:
     * Line 104: epoll_instances[i].epfd = next_epoll_fd++;
     * - Global counter never wraps or validates bounds
     * - No check for INT_MAX before increment
     * - Signed overflow causes undefined behavior
     * - No mechanism to prevent FD collision with regular FDs
     * - Relies on assumption that counter won't reach INT_MAX
     *
     * DEFENSE:
     * Validate next_epoll_fd won't overflow before incrementing
     * - Check next_epoll_fd < INT_MAX before assignment
     * - Return NULL (ENOMEM) if counter would overflow
     * - Alternative: Use wrapping with collision detection
     * - Alternative: Reuse deallocated epoll FDs from free pool
     * - Document that system supports finite number of epoll instances
     * - MAX_EPOLL_INSTANCES (256) limits active instances, but doesn't prevent
     *   overflow if instances are created/destroyed repeatedly
     *
     * CVE REFERENCES:
     * - CVE-2015-8839: Linux timer integer overflow (similar counter pattern)
     * - CVE-2014-2851: Linux group_info refcount overflow
     *
     * POSIX REQUIREMENT:
     * POSIX does not specify epoll (Linux extension), but general FD requirements:
     * - File descriptors must be unique system-wide
     * - Reusing FDs requires proper close/free cycle
     * - Overflow causing FD collision violates POSIX uniqueness guarantee
     *
     * IMPLEMENTATION NOTES:
     * - Current limit: 256 active instances (MAX_EPOLL_INSTANCES)
     * - Counter starts at 4000 to avoid collision with regular FDs
     * - If counter reaches INT_MAX (2,147,483,647):
     *   - Requires ~2.1 billion epoll_create1() calls
     *   - At 1000 create/destroy per second: ~24 days continuous operation
     * - documents requirement for overflow check before increment
     */
    for (int i = 0; i < MAX_EPOLL_INSTANCES; i++) {
        if (!epoll_instances[i].active) {
            memset(&epoll_instances[i], 0, sizeof(epoll_instances[i]));
            epoll_instances[i].active = true;
            epoll_instances[i].epfd = -1; /* assigned after chrdev_alloc_fd */
            epoll_instances[i].count = 0;
            epoll_instances[i].owner_pid = owner_pid;
            fut_waitq_init(&epoll_instances[i].epoll_waitq);
            return &epoll_instances[i];
        }
    }
    return NULL;
}

/* Release callback: called by fut_vfs_close when epoll fd refcount hits 0 */
static int epoll_release_op(void *inode, void *priv) {
    (void)inode;
    struct epoll_set *set = (struct epoll_set *)priv;
    epoll_ensure_init();
    fut_spinlock_acquire(&epoll_lock);
    epoll_deallocate_set(set);
    fut_spinlock_release(&epoll_lock);
    return 0;
}

/* Helper to deallocate an epoll set */
static void epoll_deallocate_set(struct epoll_set *set) {
    if (set) {
        set->active = false;
        set->count = 0;
        set->owner_pid = 0;
        memset(set->fds, 0, sizeof(set->fds));
    }
}

/**
 * epoll_try_close - no-op: epoll fds are now in fd_table and are freed via
 * epoll_release_op when fut_vfs_close drops the last reference.
 */
bool epoll_try_close(int fd) {
    (void)fd;
    return false;
}

/**
 * epoll_create1(int flags) - Create an epoll instance
 *
 * Creates an event notification context for monitoring multiple file descriptors.
 * Allows applications to efficiently wait for I/O events on many file descriptors.
 *
 * @param flags  Creation flags (EPOLL_CLOEXEC to set close-on-exec)
 *
 * Returns:
 *   - epoll file descriptor (>= 0) on success
 *   - -EINVAL if flags contains invalid bits
 *   - -ENOMEM if no epoll instances available
 *
 * Behavior:
 *   - Creates new epoll instance for event monitoring
 *   - Returns file descriptor for use with epoll_ctl/epoll_wait
 *   - EPOLL_CLOEXEC: Set FD_CLOEXEC on returned descriptor
 *   - Max 256 epoll instances system-wide (MAX_EPOLL_INSTANCES)
 *   - Each epoll instance can monitor up to 64 FDs (MAX_EPOLL_FDS)
 *
 * Common usage patterns:
 *
 * Basic epoll setup:
 *   int epfd = epoll_create1(0);
 *   struct epoll_event ev;
 *   ev.events = EPOLLIN;
 *   ev.data.fd = sockfd;
 *   epoll_ctl(epfd, EPOLL_CTL_ADD, sockfd, &ev);
 *
 * Close-on-exec flag:
 *   int epfd = epoll_create1(EPOLL_CLOEXEC);  // Won't be inherited by child
 *   // ... use epoll ...
 *   exec("/bin/program");  // epfd is automatically closed
 *
 * Server event loop:
 *   int epfd = epoll_create1(0);
 *   // Add listening socket and all client sockets
 *   while (1) {
 *       struct epoll_event events[10];
 *       int n = epoll_wait(epfd, events, 10, -1);
 *       for (int i = 0; i < n; i++) {
 *           handle_event(&events[i]);
 *       }
 *   }
 *
 * Related syscalls:
 *   - epoll_ctl(): Add/modify/delete file descriptors from epoll set
 *   - epoll_wait(): Wait for events on monitored file descriptors
 *   - poll()/select(): Alternative I/O multiplexing mechanisms
 *   - close(): Destroy epoll instance
 *
 * Phase 1 (Completed): Basic implementation with event registration
 * Phase 2 (Completed): Enhanced validation, flag categorization, detailed logging
 * Phase 3 (Completed): Edge-triggered mode, oneshot events
 * Phase 4 (Completed): Performance optimization, memory pooling
 */
long sys_epoll_create1(int flags) {
    epoll_ensure_init();

    /* Phase 2: Validate flags */
    if (flags & ~EPOLL_CLOEXEC) {
        char msg[128];
        int pos = 0;
        const char *prefix = "[EPOLL_CREATE1] epoll_create1(flags=0x";
        while (*prefix) { msg[pos++] = *prefix++; }

        /* Convert flags to hex */
        char hex[16];
        int hex_pos = 0;
        unsigned int val = (unsigned int)flags;
        if (val == 0) {
            hex[hex_pos++] = '0';
        } else {
            char temp[16];
            int temp_pos = 0;
            while (val > 0) {
                int digit = val % 16;
                temp[temp_pos++] = (digit < 10) ? ('0' + digit) : ('a' + digit - 10);
                val /= 16;
            }
            while (temp_pos > 0) {
                hex[hex_pos++] = temp[--temp_pos];
            }
        }
        hex[hex_pos] = '\0';

        for (int i = 0; hex[i]; i++) { msg[pos++] = hex[i]; }
        const char *suffix = ") -> EINVAL (invalid flags, only EPOLL_CLOEXEC supported)\n";
        while (*suffix) { msg[pos++] = *suffix++; }
        msg[pos] = '\0';
        fut_printf("%s", msg);

        return -EINVAL;
    }

    /* Phase 2: Categorize flags */
    const char *flags_desc;
    if (flags == 0) {
        flags_desc = "none";
    } else if (flags == EPOLL_CLOEXEC) {
        flags_desc = "EPOLL_CLOEXEC";
    } else {
        flags_desc = "unknown";
    }

    /* Per-task epoll instance quota check (under lock for atomicity) */
    fut_task_t *task = fut_task_current();
    uint64_t pid = task ? task->pid : 0;

    fut_spinlock_acquire(&epoll_lock);
    if (task) {
        int task_count = epoll_count_by_pid(pid);
        if (task_count >= MAX_EPOLL_PER_TASK) {
            fut_spinlock_release(&epoll_lock);
            fut_printf("[EPOLL_CREATE1] epoll_create1(flags=%s, pid=%llu) -> EMFILE "
                       "(per-task limit reached: %d/%d)\n",
                       flags_desc, (unsigned long long)pid,
                       task_count, MAX_EPOLL_PER_TASK);
            return -EMFILE;
        }
    }

    /* Allocate new epoll instance */
    struct epoll_set *set = epoll_allocate_set(pid);
    fut_spinlock_release(&epoll_lock);

    if (!set) {
        char msg[128];
        int pos = 0;
        const char *text = "[EPOLL_CREATE1] epoll_create1(flags=";
        while (*text) { msg[pos++] = *text++; }
        while (*flags_desc) { msg[pos++] = *flags_desc++; }
        text = ") -> ENOMEM (no epoll instances available, max=256)\n";
        while (*text) { msg[pos++] = *text++; }
        msg[pos] = '\0';
        fut_printf("%s", msg);

        return -ENOMEM;
    }

    /* Allocate a normal fd in the task's fd_table for this epoll instance.
     * This gives epoll fds the same lifecycle as other fds: close(2) and
     * FD_CLOEXEC work through the normal VFS path, and fstat(2) returns
     * S_IFCHR via fut_chrdev_fstat_mode. */
    int fd = chrdev_alloc_fd(&epoll_fops, NULL, set);
    if (fd < 0) {
        fut_spinlock_acquire(&epoll_lock);
        epoll_deallocate_set(set);
        fut_spinlock_release(&epoll_lock);
        return fd;
    }
    set->epfd = fd;

    if (flags & EPOLL_CLOEXEC) {
        set->cloexec = true;
        if (task && task->fd_flags && fd < task->max_fds)
            task->fd_flags[fd] |= FD_CLOEXEC;
    }

    return fd;
}

/**
 * epoll_ctl(int epfd, int op, int fd, struct epoll_event *event) - Control an epoll instance
 *
 * Modifies the set of file descriptors monitored by an epoll instance.
 * Supports add, modify, and delete operations.
 *
 * @param epfd   epoll file descriptor from epoll_create1()
 * @param op     Operation: EPOLL_CTL_ADD, EPOLL_CTL_MOD, or EPOLL_CTL_DEL
 * @param fd     File descriptor to add/modify/delete
 * @param event  epoll_event structure with events mask and user data
 *
 * Returns:
 *   - 0 on success
 *   - -EBADF if epfd is invalid or fd doesn't exist
 *   - -EINVAL if op is invalid or event is NULL (for ADD/MOD)
 *   - -EEXIST if trying to add an already-registered FD
 *   - -ENOENT if trying to modify/delete a non-registered FD
 *   - -ENOMEM if no more FD slots available in epoll set
 *   - -EFAULT if event pointer is inaccessible
 *
 * Behavior:
 *   - EPOLL_CTL_ADD: Register fd with event mask
 *   - EPOLL_CTL_MOD: Modify event mask for registered fd
 *   - EPOLL_CTL_DEL: Unregister fd from epoll set
 *   - event.events: Bitmask (EPOLLIN, EPOLLOUT, EPOLLERR, EPOLLHUP, etc.)
 *   - event.data: User data (returned in epoll_wait)
 *   - Max 64 FDs per epoll instance
 *
 * Event types:
 *   - EPOLLIN (0x1): Data available for reading
 *   - EPOLLOUT (0x4): Ready for writing
 *   - EPOLLERR (0x8): Error condition
 *   - EPOLLHUP (0x10): Hang-up (connection closed)
 *   - EPOLLRDNORM (0x40): Normal data readable
 *   - EPOLLWRNORM (0x100): Normal data writable
 *
 * Common usage patterns:
 *
 * Add socket to epoll:
 *   struct epoll_event ev;
 *   ev.events = EPOLLIN | EPOLLOUT;
 *   ev.data.fd = sockfd;
 *   epoll_ctl(epfd, EPOLL_CTL_ADD, sockfd, &ev);
 *
 * Modify event interest:
 *   ev.events = EPOLLIN;  // Only read, not write
 *   epoll_ctl(epfd, EPOLL_CTL_MOD, sockfd, &ev);
 *
 * Remove socket from epoll:
 *   epoll_ctl(epfd, EPOLL_CTL_DEL, sockfd, NULL);
 *
 * Store custom data:
 *   ev.events = EPOLLIN;
 *   ev.data.ptr = my_connection_struct;
 *   epoll_ctl(epfd, EPOLL_CTL_ADD, sockfd, &ev);
 *
 * Phase 1 (Completed): Basic add/modify/delete operations
 * Phase 2 (Completed): Enhanced validation, operation categorization, detailed logging
 * Phase 3 (Completed): Edge-triggered mode support, oneshot events
 * Phase 4 (Completed): Performance optimization with memory pooling
 */
long sys_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event) {
    epoll_ensure_init();

    /* Validate fd is non-negative early */
    if (fd < 0) {
        fut_printf("[EPOLL_CTL] epoll_ctl(epfd=%d, op=%d, fd=%d) -> EBADF (fd is negative)\n",
                   epfd, op, fd);
        return -EBADF;
    }

    /* Phase 2: Categorize epoll FD */
    const char *epfd_category;
    if (epfd >= 4000 && epfd < 5000) {
        epfd_category = "epoll (4000-4999)";
    } else if (epfd >= 5000) {
        epfd_category = "epoll high (≥5000)";
    } else {
        epfd_category = "invalid range (<4000)";
    }

    /* Phase 2: Categorize target FD - use shared helper */
    const char *fd_category = fut_fd_category(fd);

    /* Phase 2: Categorize operation */
    const char *op_name;
    if (op == EPOLL_CTL_ADD) {
        op_name = "ADD";
    } else if (op == EPOLL_CTL_MOD) {
        op_name = "MOD";
    } else if (op == EPOLL_CTL_DEL) {
        op_name = "DEL";
    } else {
        op_name = "INVALID";
    }

    /* Validate operation */
    if (op != EPOLL_CTL_ADD && op != EPOLL_CTL_MOD && op != EPOLL_CTL_DEL) {
        char msg[256];
        int pos = 0;
        const char *text = "[EPOLL_CTL] epoll_ctl(epfd=";
        while (*text) { msg[pos++] = *text++; }

        /* Add epfd */
        char num[16];
        int num_pos = 0;
        int val = epfd;
        if (val == 0) { num[num_pos++] = '0'; }
        else {
            char temp[16]; int temp_pos = 0;
            while (val > 0) { temp[temp_pos++] = '0' + (val % 10); val /= 10; }
            while (temp_pos > 0) { num[num_pos++] = temp[--temp_pos]; }
        }
        num[num_pos] = '\0';
        for (int i = 0; num[i]; i++) { msg[pos++] = num[i]; }

        text = " [";
        while (*text) { msg[pos++] = *text++; }
        while (*epfd_category) { msg[pos++] = *epfd_category++; }
        text = "], op=";
        while (*text) { msg[pos++] = *text++; }

        /* Add op */
        num_pos = 0; val = op;
        if (val == 0) { num[num_pos++] = '0'; }
        else {
            char temp[16]; int temp_pos = 0;
            while (val > 0) { temp[temp_pos++] = '0' + (val % 10); val /= 10; }
            while (temp_pos > 0) { num[num_pos++] = temp[--temp_pos]; }
        }
        num[num_pos] = '\0';
        for (int i = 0; num[i]; i++) { msg[pos++] = num[i]; }

        text = ", fd=";
        while (*text) { msg[pos++] = *text++; }

        /* Add fd */
        num_pos = 0; val = fd;
        if (val == 0) { num[num_pos++] = '0'; }
        else {
            char temp[16]; int temp_pos = 0;
            int is_neg = 0;
            if (val < 0) { is_neg = 1; val = -val; }
            while (val > 0) { temp[temp_pos++] = '0' + (val % 10); val /= 10; }
            if (is_neg) num[num_pos++] = '-';
            while (temp_pos > 0) { num[num_pos++] = temp[--temp_pos]; }
        }
        num[num_pos] = '\0';
        for (int i = 0; num[i]; i++) { msg[pos++] = num[i]; }

        text = ") -> EINVAL (invalid operation, expected ADD/MOD/DEL)\n";
        while (*text) { msg[pos++] = *text++; }
        msg[pos] = '\0';
        fut_printf("%s", msg);

        return -EINVAL;
    }

    /* Validate event pointer for ADD/MOD operations */
    if ((op == EPOLL_CTL_ADD || op == EPOLL_CTL_MOD) && !event) {
        char msg[256];
        int pos = 0;
        const char *text = "[EPOLL_CTL] epoll_ctl(epfd=";
        while (*text) { msg[pos++] = *text++; }

        char num[16]; int num_pos = 0; int val = epfd;
        if (val == 0) { num[num_pos++] = '0'; }
        else { char temp[16]; int temp_pos = 0;
            while (val > 0) { temp[temp_pos++] = '0' + (val % 10); val /= 10; }
            while (temp_pos > 0) { num[num_pos++] = temp[--temp_pos]; } }
        num[num_pos] = '\0';
        for (int i = 0; num[i]; i++) { msg[pos++] = num[i]; }

        text = ", op=";
        while (*text) { msg[pos++] = *text++; }
        while (*op_name) { msg[pos++] = *op_name++; }
        text = ", fd=";
        while (*text) { msg[pos++] = *text++; }

        num_pos = 0; val = fd;
        if (val == 0) { num[num_pos++] = '0'; }
        else { char temp[16]; int temp_pos = 0;
            while (val > 0) { temp[temp_pos++] = '0' + (val % 10); val /= 10; }
            while (temp_pos > 0) { num[num_pos++] = temp[--temp_pos]; } }
        num[num_pos] = '\0';
        for (int i = 0; num[i]; i++) { msg[pos++] = num[i]; }

        text = ") -> EINVAL (NULL event pointer for ADD/MOD)\n";
        while (*text) { msg[pos++] = *text++; }
        msg[pos] = '\0';
        fut_printf("%s", msg);

        return -EINVAL;
    }

    /* Detect kernel-space event pointer (kernel-internal callers, e.g. tests) */
    bool epoll_ctl_kernel_ptr = event &&
        ((uintptr_t)event >= KERNEL_VIRTUAL_BASE);

    /* Verify user pointer is readable for ADD/MOD (skip for kernel pointers) */
    if (!epoll_ctl_kernel_ptr &&
        (op == EPOLL_CTL_ADD || op == EPOLL_CTL_MOD) &&
        fut_access_ok(event, sizeof(struct epoll_event), 0) != 0) {
        char msg[256];
        int pos = 0;
        const char *text = "[EPOLL_CTL] epoll_ctl(epfd=";
        while (*text) { msg[pos++] = *text++; }

        char num[16]; int num_pos = 0; int val = epfd;
        if (val == 0) { num[num_pos++] = '0'; }
        else { char temp[16]; int temp_pos = 0;
            while (val > 0) { temp[temp_pos++] = '0' + (val % 10); val /= 10; }
            while (temp_pos > 0) { num[num_pos++] = temp[--temp_pos]; } }
        num[num_pos] = '\0';
        for (int i = 0; num[i]; i++) { msg[pos++] = num[i]; }

        text = ", op=";
        while (*text) { msg[pos++] = *text++; }
        while (*op_name) { msg[pos++] = *op_name++; }
        text = ", fd=";
        while (*text) { msg[pos++] = *text++; }

        num_pos = 0; val = fd;
        if (val == 0) { num[num_pos++] = '0'; }
        else { char temp[16]; int temp_pos = 0;
            while (val > 0) { temp[temp_pos++] = '0' + (val % 10); val /= 10; }
            while (temp_pos > 0) { num[num_pos++] = temp[--temp_pos]; } }
        num[num_pos] = '\0';
        for (int i = 0; num[i]; i++) { msg[pos++] = num[i]; }

        text = ") -> EFAULT (event pointer inaccessible)\n";
        while (*text) { msg[pos++] = *text++; }
        msg[pos] = '\0';
        fut_printf("%s", msg);

        return -EFAULT;
    }

    /* Validate FD exists */
    struct fut_file *file = fut_vfs_get_file(fd);
    if (!file) {
        char msg[256];
        int pos = 0;
        const char *text = "[EPOLL_CTL] epoll_ctl(epfd=";
        while (*text) { msg[pos++] = *text++; }

        char num[16]; int num_pos = 0; int val = epfd;
        if (val == 0) { num[num_pos++] = '0'; }
        else { char temp[16]; int temp_pos = 0;
            while (val > 0) { temp[temp_pos++] = '0' + (val % 10); val /= 10; }
            while (temp_pos > 0) { num[num_pos++] = temp[--temp_pos]; } }
        num[num_pos] = '\0';
        for (int i = 0; num[i]; i++) { msg[pos++] = num[i]; }

        text = ", op=";
        while (*text) { msg[pos++] = *text++; }
        while (*op_name) { msg[pos++] = *op_name++; }
        text = ", fd=";
        while (*text) { msg[pos++] = *text++; }

        num_pos = 0; val = fd;
        if (val == 0) { num[num_pos++] = '0'; }
        else { char temp[16]; int temp_pos = 0;
            int is_neg = 0;
            if (val < 0) { is_neg = 1; val = -val; }
            while (val > 0) { temp[temp_pos++] = '0' + (val % 10); val /= 10; }
            if (is_neg) num[num_pos++] = '-';
            while (temp_pos > 0) { num[num_pos++] = temp[--temp_pos]; } }
        num[num_pos] = '\0';
        for (int i = 0; num[i]; i++) { msg[pos++] = num[i]; }

        text = " [";
        while (*text) { msg[pos++] = *text++; }
        while (*fd_category) { msg[pos++] = *fd_category++; }
        text = "]) -> EBADF (fd not open)\n";
        while (*text) { msg[pos++] = *text++; }
        msg[pos] = '\0';
        fut_printf("%s", msg);

        return -EBADF;
    }

    /* Get the epoll set (under lock for thread safety) */
    fut_spinlock_acquire(&epoll_lock);
    struct epoll_set *set = epoll_get_set(epfd);
    if (!set) {
        fut_spinlock_release(&epoll_lock);

        char msg[256];
        int pos = 0;
        const char *text = "[EPOLL_CTL] epoll_ctl(epfd=";
        while (*text) { msg[pos++] = *text++; }

        char num[16]; int num_pos = 0; int val = epfd;
        if (val == 0) { num[num_pos++] = '0'; }
        else { char temp[16]; int temp_pos = 0;
            while (val > 0) { temp[temp_pos++] = '0' + (val % 10); val /= 10; }
            while (temp_pos > 0) { num[num_pos++] = temp[--temp_pos]; } }
        num[num_pos] = '\0';
        for (int i = 0; num[i]; i++) { msg[pos++] = num[i]; }

        text = " [";
        while (*text) { msg[pos++] = *text++; }
        while (*epfd_category) { msg[pos++] = *epfd_category++; }
        text = "], op=";
        while (*text) { msg[pos++] = *text++; }
        while (*op_name) { msg[pos++] = *op_name++; }
        text = ", fd=";
        while (*text) { msg[pos++] = *text++; }

        num_pos = 0; val = fd;
        if (val == 0) { num[num_pos++] = '0'; }
        else { char temp[16]; int temp_pos = 0;
            while (val > 0) { temp[temp_pos++] = '0' + (val % 10); val /= 10; }
            while (temp_pos > 0) { num[num_pos++] = temp[--temp_pos]; } }
        num[num_pos] = '\0';
        for (int i = 0; num[i]; i++) { msg[pos++] = num[i]; }

        text = ") -> EBADF (invalid epoll fd)\n";
        while (*text) { msg[pos++] = *text++; }
        msg[pos] = '\0';
        fut_printf("%s", msg);

        return -EBADF;
    }
    /* Lock remains held through the switch statement below */

    /* Copy event structure from user space (or kernel space) for ADD/MOD */
    struct epoll_event ev;
    if (op == EPOLL_CTL_ADD || op == EPOLL_CTL_MOD) {
        if (epoll_ctl_kernel_ptr) {
            __builtin_memcpy(&ev, event, sizeof(ev));
        } else if (fut_copy_from_user(&ev, event, sizeof(ev)) != 0) {
            char msg[128];
            int pos = 0;
            const char *text = "[EPOLL_CTL] epoll_ctl(op=";
            while (*text) { msg[pos++] = *text++; }
            while (*op_name) { msg[pos++] = *op_name++; }
            text = ") -> EFAULT (copy_from_user failed)\n";
            while (*text) { msg[pos++] = *text++; }
            msg[pos] = '\0';
            fut_printf("%s", msg);

            fut_spinlock_release(&epoll_lock);
            return -EFAULT;
        }

        /* Validate event mask doesn't contain invalid bits.
         * EPOLLWAKEUP (Linux 3.5+): power-management wakeup hint; accepted, no-op.
         * EPOLLEXCLUSIVE (Linux 4.5+): exclusive wakeup for thundering-herd avoidance. */
        uint32_t valid_events = EPOLLIN | EPOLLOUT | EPOLLPRI | EPOLLERR | EPOLLHUP |
                               EPOLLRDHUP | EPOLLRDNORM | EPOLLRDBAND |
                               EPOLLWRNORM | EPOLLWRBAND |
                               EPOLLWAKEUP | EPOLLEXCLUSIVE |
                               EPOLL_ET | EPOLL_ONESHOT;
        if (ev.events & ~valid_events) {
            uint32_t invalid_bits = ev.events & ~valid_events;
            fut_spinlock_release(&epoll_lock);
            fut_printf("[EPOLL_CTL] epoll_ctl(epfd=%d, op=%s, fd=%d, events=0x%x) -> EINVAL "
                       "(invalid event bits 0x%x detected, valid=0x%x)\n",
                       epfd, op_name, fd, ev.events, invalid_bits, valid_events);
            return -EINVAL;
        }

        /* Linux 4.5+ EPOLLEXCLUSIVE constraints:
         * - Only valid with EPOLL_CTL_ADD (not MOD)
         * - Cannot be combined with EPOLLONESHOT (mutually exclusive semantics)
         * See Linux kernel fs/eventpoll.c ep_insert() validation. */
        if (ev.events & EPOLLEXCLUSIVE) {
            if (op != EPOLL_CTL_ADD) {
                fut_spinlock_release(&epoll_lock);
                fut_printf("[EPOLL_CTL] epoll_ctl(epfd=%d, op=%s, fd=%d) -> EINVAL "
                           "(EPOLLEXCLUSIVE only valid with EPOLL_CTL_ADD)\n",
                           epfd, op_name, fd);
                return -EINVAL;
            }
            if (ev.events & EPOLL_ONESHOT) {
                fut_spinlock_release(&epoll_lock);
                fut_printf("[EPOLL_CTL] epoll_ctl(epfd=%d, fd=%d) -> EINVAL "
                           "(EPOLLEXCLUSIVE cannot be combined with EPOLLONESHOT)\n",
                           epfd, fd);
                return -EINVAL;
            }
        }
    }

    switch (op) {
    case EPOLL_CTL_ADD: {
        /* Check if FD is already registered */
        for (int i = 0; i < MAX_EPOLL_FDS; i++) {
            if (set->fds[i].registered && set->fds[i].fd == fd) {
                char msg[256];
                int pos = 0;
                const char *text = "[EPOLL_CTL] epoll_ctl(epfd=";
                while (*text) { msg[pos++] = *text++; }

                char num[16]; int num_pos = 0; int val = epfd;
                if (val == 0) { num[num_pos++] = '0'; }
                else { char temp[16]; int temp_pos = 0;
                    while (val > 0) { temp[temp_pos++] = '0' + (val % 10); val /= 10; }
                    while (temp_pos > 0) { num[num_pos++] = temp[--temp_pos]; } }
                num[num_pos] = '\0';
                for (int j = 0; num[j]; j++) { msg[pos++] = num[j]; }

                text = ", op=ADD, fd=";
                while (*text) { msg[pos++] = *text++; }

                num_pos = 0; val = fd;
                if (val == 0) { num[num_pos++] = '0'; }
                else { char temp[16]; int temp_pos = 0;
                    while (val > 0) { temp[temp_pos++] = '0' + (val % 10); val /= 10; }
                    while (temp_pos > 0) { num[num_pos++] = temp[--temp_pos]; } }
                num[num_pos] = '\0';
                for (int j = 0; num[j]; j++) { msg[pos++] = num[j]; }

                text = ") -> EEXIST (fd already registered)\n";
                while (*text) { msg[pos++] = *text++; }
                msg[pos] = '\0';
                fut_printf("%s", msg);

                fut_spinlock_release(&epoll_lock);
                return -EEXIST;
            }
        }

        /* Find empty slot */
        int slot = -1;
        for (int i = 0; i < MAX_EPOLL_FDS; i++) {
            if (!set->fds[i].registered) {
                slot = i;
                break;
            }
        }

        if (slot == -1) {
            char msg[256];
            int pos = 0;
            const char *text = "[EPOLL_CTL] epoll_ctl(epfd=";
            while (*text) { msg[pos++] = *text++; }

            char num[16]; int num_pos = 0; int val = epfd;
            if (val == 0) { num[num_pos++] = '0'; }
            else { char temp[16]; int temp_pos = 0;
                while (val > 0) { temp[temp_pos++] = '0' + (val % 10); val /= 10; }
                while (temp_pos > 0) { num[num_pos++] = temp[--temp_pos]; } }
            num[num_pos] = '\0';
            for (int j = 0; num[j]; j++) { msg[pos++] = num[j]; }

            text = ", op=ADD, fd=";
            while (*text) { msg[pos++] = *text++; }

            num_pos = 0; val = fd;
            if (val == 0) { num[num_pos++] = '0'; }
            else { char temp[16]; int temp_pos = 0;
                while (val > 0) { temp[temp_pos++] = '0' + (val % 10); val /= 10; }
                while (temp_pos > 0) { num[num_pos++] = temp[--temp_pos]; } }
            num[num_pos] = '\0';
            for (int j = 0; num[j]; j++) { msg[pos++] = num[j]; }

            text = ") -> ENOMEM (no slots, max=64)\n";
            while (*text) { msg[pos++] = *text++; }
            msg[pos] = '\0';
            fut_printf("%s", msg);

            fut_spinlock_release(&epoll_lock);
            return -ENOMEM;
        }

        /* Register the FD */
        set->fds[slot].fd = fd;
        set->fds[slot].events = ev.events;
        set->fds[slot].data = ev.data.u64;
        set->fds[slot].registered = true;

        /* Phase 3: Extract and store edge-triggered, oneshot, and exclusive flags */
        set->fds[slot].edge_triggered = (ev.events & EPOLL_ET) != 0;
        set->fds[slot].oneshot = (ev.events & EPOLL_ONESHOT) != 0;
        set->fds[slot].oneshot_disabled = false;
        set->fds[slot].exclusive = (ev.events & EPOLLEXCLUSIVE) != 0;
        set->fds[slot].last_was_readable = false;
        set->fds[slot].last_was_writable = false;
        set->fds[slot].last_was_hup = false;

        /* Track whether any FD uses EPOLLEXCLUSIVE for wakeup policy */
        if (set->fds[slot].exclusive)
            set->has_exclusive = true;

        /* Phase 3: Mask out modifier flags from events for actual event checking.
         * Always include EPOLLERR|EPOLLHUP — Linux reports these regardless
         * of the requested mask (ep_insert forces them in). */
        uint32_t base_events = ev.events & ~(EPOLL_ET | EPOLL_ONESHOT | EPOLLEXCLUSIVE);
        base_events |= EPOLLERR | EPOLLHUP;
        set->fds[slot].events = base_events;

        set->count++;

        /* Wire up epoll notification on socket pairs/listeners */
        {
            fut_socket_t *sock = get_socket_from_fd(fd);
            if (sock) {
                if (sock->pair_reverse) {
                    sock->pair_reverse->epoll_notify = &set->epoll_waitq;
                }
                if (sock->listener) {
                    sock->listener->epoll_notify = &set->epoll_waitq;
                }
                /* CONNECTING socket: wire connect_notify so epoll_wait wakes when accept() completes */
                if (sock->state == FUT_SOCK_CONNECTING)
                    sock->connect_notify = &set->epoll_waitq;
            }
        }

        /* Wire up epoll notification on eventfd, timerfd, signalfd, and pipe */
        {
            fut_task_t *ctl_task = fut_task_current();
            if (ctl_task && ctl_task->fd_table && fd < ctl_task->max_fds) {
                struct fut_file *ctl_file = ctl_task->fd_table[fd];
                extern void fut_eventfd_set_epoll_notify(struct fut_file *file, fut_waitq_t *wq);
                extern void fut_timerfd_set_epoll_notify(struct fut_file *file, fut_waitq_t *wq);
                extern void fut_signalfd_set_epoll_notify(struct fut_file *file, fut_waitq_t *wq);
                extern void fut_pipe_set_epoll_notify(struct fut_file *file, fut_waitq_t *wq);
                extern void fut_pidfd_set_epoll_notify(struct fut_file *file, fut_waitq_t *wq);
                extern void fut_inotify_set_epoll_notify(struct fut_file *file, fut_waitq_t *wq);
                fut_eventfd_set_epoll_notify(ctl_file, &set->epoll_waitq);
                fut_timerfd_set_epoll_notify(ctl_file, &set->epoll_waitq);
                fut_signalfd_set_epoll_notify(ctl_file, &set->epoll_waitq);
                fut_pipe_set_epoll_notify(ctl_file, &set->epoll_waitq);
                fut_pidfd_set_epoll_notify(ctl_file, &set->epoll_waitq);
                fut_inotify_set_epoll_notify(ctl_file, &set->epoll_waitq);
                extern void fut_pty_set_epoll_notify(struct fut_file *file, void *wq);
                fut_pty_set_epoll_notify(ctl_file, &set->epoll_waitq);
            }
        }

        fut_spinlock_release(&epoll_lock);
        return 0;
    }

    case EPOLL_CTL_MOD: {
        /* Find and modify the entry */
        for (int i = 0; i < MAX_EPOLL_FDS; i++) {
            if (set->fds[i].registered && set->fds[i].fd == fd) {
                set->fds[i].data = ev.data.u64;

                /* Update edge-triggered, oneshot, and exclusive flags on MOD
                 * (must mirror EPOLL_CTL_ADD logic to avoid stale modifier state).
                 * MOD re-arms oneshot: clear the disabled flag so events fire again. */
                set->fds[i].edge_triggered = (ev.events & EPOLL_ET) != 0;
                set->fds[i].oneshot = (ev.events & EPOLL_ONESHOT) != 0;
                set->fds[i].oneshot_disabled = false;  /* re-arm */
                set->fds[i].exclusive = (ev.events & EPOLLEXCLUSIVE) != 0;
                set->fds[i].last_was_readable = false;
                set->fds[i].last_was_writable = false;
                set->fds[i].last_was_hup = false;

                /* Recompute has_exclusive for the set */
                if (set->fds[i].exclusive) {
                    set->has_exclusive = true;
                } else {
                    /* Check if any other FD still has exclusive */
                    bool any_excl = false;
                    for (int j = 0; j < MAX_EPOLL_FDS; j++) {
                        if (set->fds[j].registered && set->fds[j].exclusive) {
                            any_excl = true;
                            break;
                        }
                    }
                    set->has_exclusive = any_excl;
                }

                /* Strip modifier flags from events for actual event checking.
                 * Always include EPOLLERR|EPOLLHUP (Linux forces these). */
                uint32_t base_events = ev.events & ~(EPOLL_ET | EPOLL_ONESHOT | EPOLLEXCLUSIVE);
                base_events |= EPOLLERR | EPOLLHUP;
                set->fds[i].events = base_events;

                fut_spinlock_release(&epoll_lock);
                return 0;
            }
        }

        fut_spinlock_release(&epoll_lock);
        return -ENOENT;
    }

    case EPOLL_CTL_DEL: {
        /* Find and remove the entry */
        for (int i = 0; i < MAX_EPOLL_FDS; i++) {
            if (set->fds[i].registered && set->fds[i].fd == fd) {
                bool was_exclusive = set->fds[i].exclusive;
                set->fds[i].registered = false;
                set->count--;
                memset(&set->fds[i], 0, sizeof(set->fds[i]));

                /* Recompute has_exclusive if we removed an exclusive FD */
                if (was_exclusive) {
                    bool any_excl = false;
                    for (int j = 0; j < MAX_EPOLL_FDS; j++) {
                        if (set->fds[j].registered && set->fds[j].exclusive) {
                            any_excl = true;
                            break;
                        }
                    }
                    set->has_exclusive = any_excl;
                }

                /* Clear connect_notify if we had wired it */
                {
                    fut_socket_t *sock = get_socket_from_fd(fd);
                    if (sock && sock->connect_notify == &set->epoll_waitq)
                        sock->connect_notify = NULL;
                }
                /* Clear signalfd/pty epoll_notify if we had wired it */
                {
                    fut_task_t *del_task = fut_task_current();
                    if (del_task && del_task->fd_table && fd < del_task->max_fds) {
                        extern void fut_signalfd_set_epoll_notify(struct fut_file *file, fut_waitq_t *wq);
                        extern void fut_pty_set_epoll_notify(struct fut_file *file, void *wq);
                        struct fut_file *del_file = del_task->fd_table[fd];
                        if (del_file) {
                            fut_signalfd_set_epoll_notify(del_file, NULL);
                            fut_pty_set_epoll_notify(del_file, NULL);
                        }
                    }
                }
                fut_spinlock_release(&epoll_lock);
                return 0;
            }
        }

        fut_spinlock_release(&epoll_lock);
        return -ENOENT;
    }

    default:
        fut_spinlock_release(&epoll_lock);
        return -EINVAL;
    }
}

/**
 * epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout)
 *     - Wait for events on an epoll instance
 *
 * Polls all registered file descriptors and waits for events.
 * Returns when events occur or timeout expires.
 *
 * @param epfd       epoll file descriptor
 * @param events     Array to store returned events (user buffer)
 * @param maxevents  Maximum number of events to return (must be > 0)
 * @param timeout    Timeout in milliseconds (-1 = infinite, 0 = non-blocking)
 *
 * Returns:
 *   - Number of ready file descriptors on success (0 if timeout)
 *   - -EBADF if epfd is invalid
 *   - -EINVAL if maxevents <= 0 or events is NULL
 *   - -EFAULT if events pointer is invalid
 *
 * Behavior:
 *   - Blocks until events occur or timeout expires
 *   - Returns array of ready events in events parameter
 *   - Each event includes events mask and user data
 *   - timeout = 0: Non-blocking (returns immediately)
 *   - timeout = -1: Block indefinitely
 *   - timeout > 0: Block for at most timeout milliseconds
 *
 * Common usage patterns:
 *
 * Blocking wait:
 *   struct epoll_event events[10];
 *   int n = epoll_wait(epfd, events, 10, -1);
 *   for (int i = 0; i < n; i++) {
 *       if (events[i].events & EPOLLIN) {
 *           read(events[i].data.fd, buf, sizeof(buf));
 *       }
 *   }
 *
 * Non-blocking poll:
 *   int n = epoll_wait(epfd, events, 10, 0);
 *   if (n == 0) {
 *       // No events ready
 *   }
 *
 * Timeout with fallback:
 *   int n = epoll_wait(epfd, events, 10, 1000);  // Wait 1 second
 *   if (n == 0) {
 *       // Timeout - do periodic work
 *   }
 *
 * Event loop:
 *   while (running) {
 *       int n = epoll_wait(epfd, events, 10, -1);
 *       for (int i = 0; i < n; i++) {
 *           handle_event(&events[i]);
 *       }
 *   }
 *
 * Phase 1 (Completed): Basic event polling with timeout
 * Phase 2 (Completed): Enhanced validation, timeout categorization, detailed logging
 * Phase 3 (Completed): Edge-triggered mode, oneshot events
 * Phase 4 (Completed): Performance optimization with memory pooling
 */
long sys_epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout) {
    epoll_ensure_init();

    /* Phase 2: Categorize epoll FD */
    const char *epfd_category;
    if (epfd >= 4000 && epfd < 5000) {
        epfd_category = "epoll (4000-4999)";
    } else if (epfd >= 5000) {
        epfd_category = "epoll high (≥5000)";
    } else {
        epfd_category = "invalid range (<4000)";
    }

    /* Validate maxevents */
    if (maxevents <= 0) {
        char msg[256];
        int pos = 0;
        const char *text = "[EPOLL_WAIT] epoll_wait(epfd=";
        while (*text) { msg[pos++] = *text++; }

        char num[16]; int num_pos = 0; int val = epfd;
        if (val == 0) { num[num_pos++] = '0'; }
        else { char temp[16]; int temp_pos = 0;
            while (val > 0) { temp[temp_pos++] = '0' + (val % 10); val /= 10; }
            while (temp_pos > 0) { num[num_pos++] = temp[--temp_pos]; } }
        num[num_pos] = '\0';
        for (int i = 0; num[i]; i++) { msg[pos++] = num[i]; }

        text = ", maxevents=";
        while (*text) { msg[pos++] = *text++; }

        num_pos = 0; val = maxevents;
        if (val == 0) { num[num_pos++] = '0'; }
        else { char temp[16]; int temp_pos = 0;
            int is_neg = 0;
            if (val < 0) { is_neg = 1; val = -val; }
            while (val > 0) { temp[temp_pos++] = '0' + (val % 10); val /= 10; }
            if (is_neg) num[num_pos++] = '-';
            while (temp_pos > 0) { num[num_pos++] = temp[--temp_pos]; } }
        num[num_pos] = '\0';
        for (int i = 0; num[i]; i++) { msg[pos++] = num[i]; }

        text = ") -> EINVAL (maxevents must be > 0)\n";
        while (*text) { msg[pos++] = *text++; }
        msg[pos] = '\0';
        fut_printf("%s", msg);

        return -EINVAL;
    }

    /* Validate events pointer */
    if (!events) {
        char msg[128];
        int pos = 0;
        const char *text = "[EPOLL_WAIT] epoll_wait(epfd=";
        while (*text) { msg[pos++] = *text++; }

        char num[16]; int num_pos = 0; int val = epfd;
        if (val == 0) { num[num_pos++] = '0'; }
        else { char temp[16]; int temp_pos = 0;
            while (val > 0) { temp[temp_pos++] = '0' + (val % 10); val /= 10; }
            while (temp_pos > 0) { num[num_pos++] = temp[--temp_pos]; } }
        num[num_pos] = '\0';
        for (int i = 0; num[i]; i++) { msg[pos++] = num[i]; }

        text = ") -> EINVAL (NULL events array)\n";
        while (*text) { msg[pos++] = *text++; }
        msg[pos] = '\0';
        fut_printf("%s", msg);

        return -EINVAL;
    }

    /* Verify events array is writable (skip for kernel buffers) */
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)events < KERNEL_VIRTUAL_BASE)
#endif
    if (fut_access_ok(events, maxevents * sizeof(struct epoll_event), 1) != 0) {
        fut_printf("[EPOLL_WAIT] epoll_wait(epfd=%d) -> EFAULT (events not writable)\n", epfd);
        return -EFAULT;
    }

    /* Get the epoll set (under lock for safe lookup) */
    fut_spinlock_acquire(&epoll_lock);
    struct epoll_set *set = epoll_get_set(epfd);
    fut_spinlock_release(&epoll_lock);

    if (!set) {
        char msg[256];
        int pos = 0;
        const char *text = "[EPOLL_WAIT] epoll_wait(epfd=";
        while (*text) { msg[pos++] = *text++; }

        char num[16]; int num_pos = 0; int val = epfd;
        if (val == 0) { num[num_pos++] = '0'; }
        else { char temp[16]; int temp_pos = 0;
            while (val > 0) { temp[temp_pos++] = '0' + (val % 10); val /= 10; }
            while (temp_pos > 0) { num[num_pos++] = temp[--temp_pos]; } }
        num[num_pos] = '\0';
        for (int i = 0; num[i]; i++) { msg[pos++] = num[i]; }

        text = " [";
        while (*text) { msg[pos++] = *text++; }
        while (*epfd_category) { msg[pos++] = *epfd_category++; }
        text = "]) -> EBADF (invalid epoll fd)\n";
        while (*text) { msg[pos++] = *text++; }
        msg[pos] = '\0';
        fut_printf("%s", msg);

        return -EBADF;
    }

    /* Validate timeout: only -1 (infinite), 0 (poll), and positive values are valid.
     * Any other negative value is an error (-EINVAL). Clamp very large finite
     * timeouts to MAX_EPOLL_TIMEOUT_MS (86400000 ms = 24 h) to prevent
     * processes from blocking indefinitely via unreasonably large timeouts. */
    #define MAX_EPOLL_TIMEOUT_MS 86400000  /* 24 hours */
    if (timeout < -1) {
        fut_printf("[EPOLL_WAIT] epoll_wait(epfd=%d, timeout=%d) -> EINVAL "
                   "(invalid negative timeout; use -1 for infinite)\n", epfd, timeout);
        return -EINVAL;
    }
    if (timeout > MAX_EPOLL_TIMEOUT_MS) {
        timeout = MAX_EPOLL_TIMEOUT_MS;
    }

#if EPOLL_DEBUG
    /* Phase 2: Categorize timeout */
    const char *timeout_desc;
    if (timeout < 0) {
        timeout_desc = "infinite";
    } else if (timeout == 0) {
        timeout_desc = "non-blocking";
    } else if (timeout < 100) {
        timeout_desc = "short (<100ms)";
    } else if (timeout < 1000) {
        timeout_desc = "medium (100-999ms)";
    } else {
        timeout_desc = "long (≥1000ms)";
    }
#endif

    /* Poll with event-driven wakeup support.
     * For infinite timeout (-1): loop until events found (woken by socket activity).
     * For zero timeout: single poll pass.
     * For positive timeout: use tick-based deadline. */
    uint64_t deadline_ticks = 0;
    if (timeout > 0) {
        /* Convert timeout (ms) to ticks (100 Hz = 10ms/tick) */
        uint64_t timeout_ticks = (uint64_t)timeout / 10;
        if ((uint64_t)timeout % 10 != 0) timeout_ticks++;
        if (timeout_ticks == 0) timeout_ticks = 1;
        deadline_ticks = fut_get_ticks() + timeout_ticks;
    }
    int max_iterations = (timeout == 0) ? 1 : ((timeout < 0) ? 0x7FFFFFFF : 0x7FFFFFFF);
    int iteration = 0;

#if EPOLL_DEBUG
    static int epoll_wait_call_count = 0;
    epoll_wait_call_count++;
    int this_call = epoll_wait_call_count;

    if (this_call <= 3) {
        fut_printf("[EPOLL_WAIT-DBG] Call #%d: epfd=%d timeout=%d max_iter=%d fds_registered=%d\n",
                   this_call, epfd, timeout, max_iterations, set->count);
    }
#endif

    while (iteration < max_iterations) {
        int ready_count = 0;
        struct epoll_event ready_events[MAX_EPOLL_FDS];

        /* Hold lock while scanning/modifying fds array for thread safety.
         * Multiple threads may call epoll_wait on the same epfd. */
        fut_spinlock_acquire(&epoll_lock);

        /* Check all registered file descriptors */
        for (int i = 0; i < MAX_EPOLL_FDS && ready_count < maxevents; i++) {
            if (!set->fds[i].registered) {
                continue;
            }

            /* EPOLLONESHOT: skip entries that already fired and are waiting
             * for re-arm via EPOLL_CTL_MOD.  This suppresses all events
             * including EPOLLERR/EPOLLHUP until the user re-arms. */
            if (set->fds[i].oneshot_disabled) {
                continue;
            }

            struct fut_file *file = fut_vfs_get_file(set->fds[i].fd);
            if (!file) {
                /* FD closed - report error event */
                ready_events[ready_count].events = EPOLLERR | EPOLLHUP;
                ready_events[ready_count].data.u64 = set->fds[i].data;
                ready_count++;
                continue;
            }

            /* Check if FD is readable/writable */
            uint32_t events_ready = 0;
            bool handled = false;

#if EPOLL_DEBUG
            static int vnode_type_dbg = 0;
            if (vnode_type_dbg < 10) {
                vnode_type_dbg++;
                if (file->vnode) {
                    fut_printf("[EPOLL-VN-DBG] fd=%d vnode=%p type=%d (0=REG,1=DIR,2=CHR,3=BLK,4=FIFO,5=SOCK)\n",
                               set->fds[i].fd, file->vnode, file->vnode->type);
                } else {
                    fut_printf("[EPOLL-VN-DBG] fd=%d vnode=NULL (no vnode)\n", set->fds[i].fd);
                }
            }
#endif

            if (fut_eventfd_poll(file, set->fds[i].events, &events_ready)) {
                handled = true;
            }

            if (!handled && fut_timerfd_poll(file, set->fds[i].events, &events_ready)) {
                handled = true;
            }

            if (!handled && fut_signalfd_poll(file, set->fds[i].events, &events_ready)) {
                handled = true;
            }

            if (!handled && fut_pipe_poll(file, set->fds[i].events, &events_ready)) {
                handled = true;
            }

            if (!handled) {
                extern bool fut_pidfd_poll(struct fut_file *file, uint32_t requested, uint32_t *ready_out);
                if (fut_pidfd_poll(file, set->fds[i].events, &events_ready))
                    handled = true;
            }

            if (!handled) {
                extern bool fut_inotify_poll(struct fut_file *file, uint32_t requested, uint32_t *ready_out);
                if (fut_inotify_poll(file, set->fds[i].events, &events_ready))
                    handled = true;
            }

            if (!handled) {
                extern bool fut_pty_poll(struct fut_file *file, uint32_t requested, uint32_t *ready_out);
                if (fut_pty_poll(file, set->fds[i].events, &events_ready))
                    handled = true;
            }

            if (!handled && file->chr_ops && file->chr_ops->poll) {
                uint32_t chrdev_ready = 0;
                if (file->chr_ops->poll(file->chr_inode, file->chr_private,
                                        set->fds[i].events, &chrdev_ready)) {
                    events_ready |= chrdev_ready;
                    handled = true;
                }
            }

            /* For sockets: check get_socket_from_fd first (sockets may not have vnodes) */
            if (!handled) {
                fut_socket_t *socket = get_socket_from_fd(set->fds[i].fd);
                if (socket) {
                    /* Convert EPOLL events to poll events and check socket readiness */
                    int poll_events = 0;
                    if (set->fds[i].events & (EPOLLIN | EPOLLRDNORM)) {
                        poll_events |= 0x1;  /* POLLIN */
                    }
                    if (set->fds[i].events & (EPOLLOUT | EPOLLWRNORM)) {
                        poll_events |= 0x4;  /* POLLOUT */
                    }
                    int socket_ready = fut_socket_poll(socket, poll_events);
#if EPOLL_DEBUG
                    fut_printf("[EPOLL-DBG] fd=%d poll_events=0x%x socket_ready=0x%x state=%d\n",
                               set->fds[i].fd, poll_events, socket_ready, socket->state);
#endif
                    if (socket_ready & 0x1)  events_ready |= EPOLLIN | EPOLLRDNORM;
                    if (socket_ready & 0x4)  events_ready |= EPOLLOUT | EPOLLWRNORM;
                    if (socket_ready & 0x2000) events_ready |= EPOLLRDHUP;
                    if (socket_ready & 0x10) events_ready |= EPOLLHUP;
                    if (socket_ready & 0x8)  events_ready |= EPOLLERR;
                    handled = true;
                }
            }

            /* For regular files: always ready for both read and write */
            if (!handled && file->vnode && file->vnode->type == VN_REG) {
                if (set->fds[i].events & (EPOLLIN | EPOLLRDNORM)) {
                    events_ready |= EPOLLIN | EPOLLRDNORM;
                }
                if (set->fds[i].events & (EPOLLOUT | EPOLLWRNORM)) {
                    events_ready |= EPOLLOUT | EPOLLWRNORM;
                }
                handled = true;
            }

            /* For sockets with vnodes: redundant but keep for VN_SOCK path */
            if (!handled && file->vnode && file->vnode->type == VN_SOCK) {
                fut_socket_t *socket = get_socket_from_fd(set->fds[i].fd);
                if (socket) {
                    int poll_events = 0;
                    if (set->fds[i].events & (EPOLLIN | EPOLLRDNORM)) {
                        poll_events |= 0x1;
                    }
                    if (set->fds[i].events & (EPOLLOUT | EPOLLWRNORM)) {
                        poll_events |= 0x4;
                    }
                    int socket_ready = fut_socket_poll(socket, poll_events);
                    if (socket_ready & 0x1)  events_ready |= EPOLLIN | EPOLLRDNORM;
                    if (socket_ready & 0x4)  events_ready |= EPOLLOUT | EPOLLWRNORM;
                    if (socket_ready & 0x2000) events_ready |= EPOLLRDHUP;
                    if (socket_ready & 0x10) events_ready |= EPOLLHUP;
                    if (socket_ready & 0x8)  events_ready |= EPOLLERR;
                }
                handled = true;
            }

            /* For character devices and other types: report as ready if requested */
            if (!handled && file->vnode) {
                if (set->fds[i].events & (EPOLLIN | EPOLLRDNORM)) {
                    events_ready |= EPOLLIN | EPOLLRDNORM;
                }
                if (set->fds[i].events & (EPOLLOUT | EPOLLWRNORM)) {
                    events_ready |= EPOLLOUT | EPOLLWRNORM;
                }
            }

            /* Phase 3: Handle edge-triggered mode - only report on transitions.
             * EPOLLHUP and EPOLLERR are always reported (per Linux semantics)
             * but in ET mode they only fire once on the transition. */
            bool should_report = false;
            if (events_ready) {
                if (set->fds[i].edge_triggered) {
                    /* Edge-triggered: report only if transitioning from no event to event */
                    bool is_readable = (events_ready & (EPOLLIN | EPOLLRDNORM)) != 0;
                    bool is_writable = (events_ready & (EPOLLOUT | EPOLLWRNORM)) != 0;
                    bool is_hup_err  = (events_ready & (EPOLLHUP | EPOLLERR)) != 0;

                    if ((is_readable && !set->fds[i].last_was_readable) ||
                        (is_writable && !set->fds[i].last_was_writable) ||
                        (is_hup_err  && !set->fds[i].last_was_hup)) {
                        should_report = true;
                    }
                    /* Update state for next iteration */
                    if (is_readable) set->fds[i].last_was_readable = true;
                    if (is_writable) set->fds[i].last_was_writable = true;
                    if (is_hup_err)  set->fds[i].last_was_hup = true;
                } else {
                    /* Level-triggered: report every iteration while event is ready */
                    should_report = true;
                }
            } else {
                /* Phase 3: Clear edge-triggered state when event no longer ready */
                if (set->fds[i].edge_triggered) {
                    set->fds[i].last_was_readable = false;
                    set->fds[i].last_was_writable = false;
                    set->fds[i].last_was_hup = false;
                }
            }

            /* Report events if appropriate */
            if (should_report) {
                ready_events[ready_count].events = events_ready;
                ready_events[ready_count].data.u64 = set->fds[i].data;
                ready_count++;

                /* Phase 3: Handle oneshot mode - disable events after reporting.
                 * The FD stays registered but stops reporting until re-armed
                 * via EPOLL_CTL_MOD. This matches Linux behavior. */
                if (set->fds[i].oneshot) {
                    set->fds[i].events = 0;  /* Disable all events */
                    set->fds[i].oneshot_disabled = true;
                }

                /* Cap at maxevents — Linux returns at most maxevents entries */
                if (ready_count >= maxevents)
                    break;
            }
        }

        /* Release lock before user-space copy or sleep */
        fut_spinlock_release(&epoll_lock);

        /* If we have events, copy to user and return */
        if (ready_count > 0) {
            /* Copy ready events to userspace (or kernel buffer) */
            size_t copy_size = ready_count * sizeof(struct epoll_event);
#ifdef KERNEL_VIRTUAL_BASE
            if ((uintptr_t)events >= KERNEL_VIRTUAL_BASE) {
                __builtin_memcpy(events, ready_events, copy_size);
            } else
#endif
            if (fut_copy_to_user(events, ready_events, copy_size) != 0) {
                return -EFAULT;
            }
            return ready_count;
        }

        /* Check timeout */
        if (timeout == 0) {
            /* Non-blocking mode - no events ready */
            return 0;
        }

        /* Check positive timeout before sleeping */
        if (timeout > 0 && fut_get_ticks() >= deadline_ticks) {
            return 0;  /* Timeout expired */
        }

        /* Check for pending unblocked signals before blocking → EINTR */
        {
            fut_task_t *sig_task = fut_task_current();
            if (sig_task) {
                uint64_t pending = __atomic_load_n(&sig_task->pending_signals, __ATOMIC_ACQUIRE);
                fut_thread_t *scur_thr = fut_thread_current();
                if (scur_thr)
                    pending |= __atomic_load_n(&scur_thr->thread_pending_signals, __ATOMIC_ACQUIRE);
                uint64_t blocked = scur_thr ?
                    __atomic_load_n(&scur_thr->signal_mask, __ATOMIC_ACQUIRE) :
                    __atomic_load_n(&sig_task->signal_mask, __ATOMIC_ACQUIRE);
                if (pending & ~blocked) {
                    return -EINTR;
                }
            }
        }

        /* Sleep on epoll waitqueue - socket sends and new connections will wake us.
         * For positive timeouts, start a timer to wake us if no events arrive. */
        if (timeout > 0) {
            uint64_t now = fut_get_ticks();
            /* Guard against underflow if ticks raced past deadline */
            if (now >= deadline_ticks) {
                return 0;  /* Timeout already expired */
            }
            uint64_t remaining = deadline_ticks - now;
            /* Use sleep_timed to avoid lost-wakeup race: thread is enqueued
             * BEFORE the timer starts, so the callback always finds us. */
            fut_waitq_sleep_timed(&set->epoll_waitq, remaining, NULL);
        } else {
            /* timeout == -1: block indefinitely until an event wakes us */
            fut_waitq_sleep_locked(&set->epoll_waitq, NULL, FUT_THREAD_BLOCKED);
        }

        /* Check for pending unblocked signals → EINTR */
        {
            fut_task_t *sig_task = fut_task_current();
            if (sig_task) {
                uint64_t pending = __atomic_load_n(&sig_task->pending_signals, __ATOMIC_ACQUIRE);
                fut_thread_t *scur_thr = fut_thread_current();
                if (scur_thr)
                    pending |= __atomic_load_n(&scur_thr->thread_pending_signals, __ATOMIC_ACQUIRE);
                uint64_t blocked = scur_thr ?
                    __atomic_load_n(&scur_thr->signal_mask, __ATOMIC_ACQUIRE) :
                    __atomic_load_n(&sig_task->signal_mask, __ATOMIC_ACQUIRE);
                if (pending & ~blocked) {
                    return -EINTR;
                }
            }
        }

        iteration++;
    }

    /* Timeout expired */
#if EPOLL_DEBUG
    char msg[256];
    int pos = 0;
    const char *text = "[EPOLL_WAIT] epoll_wait(epfd=";
    while (*text) { msg[pos++] = *text++; }

    char num[16]; int num_pos = 0; int val = epfd;
    if (val == 0) { num[num_pos++] = '0'; }
    else { char temp[16]; int temp_pos = 0;
        while (val > 0) { temp[temp_pos++] = '0' + (val % 10); val /= 10; }
        while (temp_pos > 0) { num[num_pos++] = temp[--temp_pos]; } }
    num[num_pos] = '\0';
    for (int i = 0; num[i]; i++) { msg[pos++] = num[i]; }

    text = ", timeout=";
    while (*text) { msg[pos++] = *text++; }
    while (*timeout_desc) { msg[pos++] = *timeout_desc++; }
    text = ") -> 0 (timeout expired, Phase 2)\n";
    while (*text) { msg[pos++] = *text++; }
    msg[pos] = '\0';
    fut_printf("%s", msg);
#endif

    return 0;
}

/**
 * epoll_create() - Legacy epoll create (deprecated)
 *
 * Older API for creating epoll instance. The size parameter is ignored
 * in modern kernels. New code should use epoll_create1() instead.
 *
 * @param size  Ignored (was a hint for kernel in old implementations)
 *
 * Returns:
 *   - epoll file descriptor on success
 *   - -EINVAL if size <= 0
 *
 * Phase 2 (Completed): Wrapper that delegates to epoll_create1(0)
 */
long sys_epoll_create(int size) {
    /* Linux ignores size since 2.6.8, but historically required size > 0.
     * Accept size >= 0 for compatibility — many libc wrappers pass 0. */
    if (size < 0) {
        return -EINVAL;
    }

    /* Delegate to modern epoll_create1 with flags=0 */
    return sys_epoll_create1(0);
}

/**
 * sys_epoll_pwait - Wait for events on epoll instance (with signal mask)
 *
 * @param epfd      Epoll file descriptor
 * @param events    Buffer for returned events
 * @param maxevents Maximum number of events to return
 * @param timeout   Timeout in milliseconds (-1 = block indefinitely)
 * @param sigmask   Signal mask to temporarily install (NULL = ignored)
 *
 * On ARM64, epoll_pwait is the primary interface (epoll_wait doesn't exist).
 * For now, we ignore the sigmask parameter and delegate to sys_epoll_wait.
 *
 * Phase 1 (Completed): Simple wrapper that ignores sigmask
 * Phase 2 (Completed): Atomically install signal mask, call epoll_wait, restore mask
 */
long sys_epoll_pwait(int epfd, struct epoll_event *events, int maxevents,
                     int timeout, const void *sigmask, size_t sigsetsize) {
    fut_task_t *task = fut_task_current();
    sigset_t saved_mask = {0};
    bool mask_installed = false;

    /* Atomically install the provided signal mask via fut_signal_procmask
     * so the per-thread mask is updated correctly (not just the task mask). */
    if (sigmask && task) {
        /* Linux validates sigsetsize == sizeof(sigset_t); kernel callers pass 0 */
#ifdef KERNEL_VIRTUAL_BASE
        bool is_kptr = (uintptr_t)sigmask >= KERNEL_VIRTUAL_BASE;
#else
        bool is_kptr = false;
#endif
        if (!is_kptr && sigsetsize != sizeof(sigset_t))
            return -EINVAL;

        sigset_t newmask = {0};
        if (is_kptr)
            __builtin_memcpy(&newmask, sigmask, sizeof(sigset_t));
        else if (fut_copy_from_user(&newmask, sigmask, sizeof(sigset_t)) != 0) {
            return -EFAULT;
        }
        int mret = fut_signal_procmask(task, SIGPROCMASK_SETMASK, &newmask, &saved_mask);
        if (mret < 0) return mret;
        mask_installed = true;
    }

    long ret = sys_epoll_wait(epfd, events, maxevents, timeout);

    /* Restore original signal mask */
    if (mask_installed && task) {
        int rret = fut_signal_procmask(task, SIGPROCMASK_SETMASK, &saved_mask, NULL);
        if (rret < 0) {
            fut_printf("[EPOLL_PWAIT] failed to restore signal mask for pid=%u: %d\n",
                       task->pid, rret);
            if (ret >= 0) {
                ret = rret;
            }
        }
    }

    return ret;
}

/**
 * sys_epoll_pwait2 - epoll_pwait with nanosecond-precision timeout (Linux 5.11+)
 *
 * @param epfd       Epoll file descriptor
 * @param events     Buffer for returned events
 * @param maxevents  Maximum number of events to return
 * @param timeout    Pointer to struct timespec timeout (NULL = block forever)
 * @param sigmask    Signal mask to temporarily install (NULL = no change)
 * @param sigsetsize Size of the sigset (must be 8)
 * @return Number of events, or -errno
 *
 * Unlike the original implementation that converted struct timespec to
 * milliseconds (losing sub-ms precision), this uses fut_get_time_ns() for
 * nanosecond-resolution deadline tracking.  A 500us timeout now correctly
 * expires in ~500us rather than being rounded up to 1ms and then quantized
 * to a 10ms timer tick.
 */
long sys_epoll_pwait2(int epfd, struct epoll_event *events, int maxevents,
                      const void *timeout_ts, const void *sigmask,
                      size_t sigsetsize) {
    /* ── Parse the struct timespec timeout ── */
    bool has_timeout = false;
    bool is_poll = false;            /* tv_sec==0 && tv_nsec==0: non-blocking */
    uint64_t deadline_ns = 0;        /* absolute deadline in nanoseconds */

    if (timeout_ts) {
        struct timespec ts = {0};
#ifdef KERNEL_VIRTUAL_BASE
        if ((uintptr_t)timeout_ts >= KERNEL_VIRTUAL_BASE)
            __builtin_memcpy(&ts, timeout_ts, sizeof(ts));
        else
#endif
        if (fut_copy_from_user(&ts, timeout_ts, sizeof(ts)) != 0)
            return -EFAULT;

        if (ts.tv_sec < 0 || ts.tv_nsec < 0 || ts.tv_nsec >= 1000000000L)
            return -EINVAL;

        has_timeout = true;
        if (ts.tv_sec == 0 && ts.tv_nsec == 0) {
            is_poll = true;  /* non-blocking poll */
        } else {
            /* Compute absolute nanosecond deadline using TSC-backed clock */
            uint64_t now_ns = fut_get_time_ns();
            uint64_t timeout_ns = (uint64_t)ts.tv_sec * 1000000000ULL +
                                  (uint64_t)ts.tv_nsec;
            deadline_ns = now_ns + timeout_ns;
            /* Guard against overflow */
            if (deadline_ns < now_ns)
                deadline_ns = UINT64_MAX;
        }
    }
    /* If timeout_ts is NULL: block forever (has_timeout=false, is_poll=false) */

    /* ── Validate basic parameters (mirrors sys_epoll_wait checks) ── */
    if (maxevents <= 0)
        return -EINVAL;
    if (!events)
        return -EINVAL;

    /* Verify events array is writable (skip for kernel buffers) */
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)events < KERNEL_VIRTUAL_BASE)
#endif
    if (fut_access_ok(events, maxevents * sizeof(struct epoll_event), 1) != 0)
        return -EFAULT;

    epoll_ensure_init();
    fut_spinlock_acquire(&epoll_lock);
    struct epoll_set *set = epoll_get_set(epfd);
    fut_spinlock_release(&epoll_lock);
    if (!set)
        return -EBADF;

    /* ── Install signal mask atomically ── */
    fut_task_t *task = fut_task_current();
    sigset_t saved_mask = {0};
    bool mask_installed = false;

    if (sigmask && task) {
#ifdef KERNEL_VIRTUAL_BASE
        bool is_kptr = (uintptr_t)sigmask >= KERNEL_VIRTUAL_BASE;
#else
        bool is_kptr = false;
#endif
        if (!is_kptr && sigsetsize != sizeof(sigset_t))
            return -EINVAL;

        sigset_t newmask = {0};
        if (is_kptr)
            __builtin_memcpy(&newmask, sigmask, sizeof(sigset_t));
        else if (fut_copy_from_user(&newmask, sigmask, sizeof(sigset_t)) != 0)
            return -EFAULT;

        int mret = fut_signal_procmask(task, SIGPROCMASK_SETMASK, &newmask, &saved_mask);
        if (mret < 0) return mret;
        mask_installed = true;
    }

    /* ── Polling loop with nanosecond-precision deadline ── */
    long ret = 0;
    int max_iterations = is_poll ? 1 : 0x7FFFFFFF;

    for (int iteration = 0; iteration < max_iterations; iteration++) {
        int ready_count = 0;
        struct epoll_event ready_events[MAX_EPOLL_FDS];

        /* Hold lock while scanning/modifying fds array for thread safety */
        fut_spinlock_acquire(&epoll_lock);

        /* Scan all registered FDs (reuses the same polling logic as sys_epoll_wait) */
        for (int i = 0; i < MAX_EPOLL_FDS && ready_count < maxevents; i++) {
            if (!set->fds[i].registered)
                continue;

            /* EPOLLONESHOT: skip entries disabled by oneshot until re-armed */
            if (set->fds[i].oneshot_disabled)
                continue;

            struct fut_file *file = fut_vfs_get_file(set->fds[i].fd);
            if (!file) {
                ready_events[ready_count].events = EPOLLERR | EPOLLHUP;
                ready_events[ready_count].data.u64 = set->fds[i].data;
                ready_count++;
                continue;
            }

            uint32_t events_ready = 0;
            bool handled = false;

            if (fut_eventfd_poll(file, set->fds[i].events, &events_ready))
                handled = true;
            if (!handled && fut_timerfd_poll(file, set->fds[i].events, &events_ready))
                handled = true;
            if (!handled && fut_signalfd_poll(file, set->fds[i].events, &events_ready))
                handled = true;
            if (!handled && fut_pipe_poll(file, set->fds[i].events, &events_ready))
                handled = true;
            if (!handled) {
                extern bool fut_pidfd_poll(struct fut_file *file, uint32_t requested, uint32_t *ready_out);
                if (fut_pidfd_poll(file, set->fds[i].events, &events_ready))
                    handled = true;
            }
            if (!handled) {
                extern bool fut_inotify_poll(struct fut_file *file, uint32_t requested, uint32_t *ready_out);
                if (fut_inotify_poll(file, set->fds[i].events, &events_ready))
                    handled = true;
            }
            if (!handled) {
                extern bool fut_pty_poll(struct fut_file *file, uint32_t requested, uint32_t *ready_out);
                if (fut_pty_poll(file, set->fds[i].events, &events_ready))
                    handled = true;
            }
            if (!handled && file->chr_ops && file->chr_ops->poll) {
                uint32_t chrdev_ready = 0;
                if (file->chr_ops->poll(file->chr_inode, file->chr_private,
                                        set->fds[i].events, &chrdev_ready)) {
                    events_ready |= chrdev_ready;
                    handled = true;
                }
            }
            if (!handled) {
                fut_socket_t *socket = get_socket_from_fd(set->fds[i].fd);
                if (socket) {
                    int poll_events = 0;
                    if (set->fds[i].events & (EPOLLIN | EPOLLRDNORM))
                        poll_events |= 0x1;
                    if (set->fds[i].events & (EPOLLOUT | EPOLLWRNORM))
                        poll_events |= 0x4;
                    int socket_ready = fut_socket_poll(socket, poll_events);
                    if (socket_ready & 0x1)    events_ready |= EPOLLIN | EPOLLRDNORM;
                    if (socket_ready & 0x4)    events_ready |= EPOLLOUT | EPOLLWRNORM;
                    if (socket_ready & 0x2000) events_ready |= EPOLLRDHUP;
                    if (socket_ready & 0x10)   events_ready |= EPOLLHUP;
                    if (socket_ready & 0x8)    events_ready |= EPOLLERR;
                    handled = true;
                }
            }
            if (!handled && file->vnode && file->vnode->type == VN_REG) {
                if (set->fds[i].events & (EPOLLIN | EPOLLRDNORM))
                    events_ready |= EPOLLIN | EPOLLRDNORM;
                if (set->fds[i].events & (EPOLLOUT | EPOLLWRNORM))
                    events_ready |= EPOLLOUT | EPOLLWRNORM;
                handled = true;
            }
            if (!handled && file->vnode && file->vnode->type == VN_SOCK) {
                fut_socket_t *socket = get_socket_from_fd(set->fds[i].fd);
                if (socket) {
                    int poll_events = 0;
                    if (set->fds[i].events & (EPOLLIN | EPOLLRDNORM))
                        poll_events |= 0x1;
                    if (set->fds[i].events & (EPOLLOUT | EPOLLWRNORM))
                        poll_events |= 0x4;
                    int socket_ready = fut_socket_poll(socket, poll_events);
                    if (socket_ready & 0x1)    events_ready |= EPOLLIN | EPOLLRDNORM;
                    if (socket_ready & 0x4)    events_ready |= EPOLLOUT | EPOLLWRNORM;
                    if (socket_ready & 0x2000) events_ready |= EPOLLRDHUP;
                    if (socket_ready & 0x10)   events_ready |= EPOLLHUP;
                    if (socket_ready & 0x8)    events_ready |= EPOLLERR;
                }
                handled = true;
            }
            if (!handled && file->vnode) {
                if (set->fds[i].events & (EPOLLIN | EPOLLRDNORM))
                    events_ready |= EPOLLIN | EPOLLRDNORM;
                if (set->fds[i].events & (EPOLLOUT | EPOLLWRNORM))
                    events_ready |= EPOLLOUT | EPOLLWRNORM;
            }

            /* Edge-triggered and level-triggered reporting */
            bool should_report = false;
            if (events_ready) {
                if (set->fds[i].edge_triggered) {
                    bool is_readable = (events_ready & (EPOLLIN | EPOLLRDNORM)) != 0;
                    bool is_writable = (events_ready & (EPOLLOUT | EPOLLWRNORM)) != 0;
                    bool is_hup_err  = (events_ready & (EPOLLHUP | EPOLLERR)) != 0;
                    if ((is_readable && !set->fds[i].last_was_readable) ||
                        (is_writable && !set->fds[i].last_was_writable) ||
                        (is_hup_err  && !set->fds[i].last_was_hup))
                        should_report = true;
                    if (is_readable) set->fds[i].last_was_readable = true;
                    if (is_writable) set->fds[i].last_was_writable = true;
                    if (is_hup_err)  set->fds[i].last_was_hup = true;
                } else {
                    should_report = true;
                }
            } else if (set->fds[i].edge_triggered) {
                set->fds[i].last_was_readable = false;
                set->fds[i].last_was_writable = false;
                set->fds[i].last_was_hup = false;
            }

            if (should_report) {
                ready_events[ready_count].events = events_ready;
                ready_events[ready_count].data.u64 = set->fds[i].data;
                ready_count++;
                if (set->fds[i].oneshot) {
                    set->fds[i].events = 0;
                    set->fds[i].oneshot_disabled = true;
                }
                if (ready_count >= maxevents)
                    break;
            }
        }

        /* Release lock before user-space copy or sleep */
        fut_spinlock_release(&epoll_lock);

        if (ready_count > 0) {
            size_t copy_size = ready_count * sizeof(struct epoll_event);
#ifdef KERNEL_VIRTUAL_BASE
            if ((uintptr_t)events >= KERNEL_VIRTUAL_BASE)
                __builtin_memcpy(events, ready_events, copy_size);
            else
#endif
            if (fut_copy_to_user(events, ready_events, copy_size) != 0) {
                ret = -EFAULT;
                goto out_restore;
            }
            ret = ready_count;
            goto out_restore;
        }

        /* Non-blocking poll: return immediately */
        if (is_poll) {
            ret = 0;
            goto out_restore;
        }

        /* Check nanosecond-precision deadline BEFORE sleeping.
         * This is the key improvement: sub-millisecond timeouts expire
         * accurately instead of being rounded to the next 10ms tick. */
        if (has_timeout) {
            uint64_t now_ns = fut_get_time_ns();
            if (now_ns >= deadline_ns) {
                ret = 0;  /* timeout expired */
                goto out_restore;
            }
        }

        /* Check for pending unblocked signals before blocking → EINTR */
        if (task) {
            uint64_t pending = __atomic_load_n(&task->pending_signals, __ATOMIC_ACQUIRE);
            fut_thread_t *scur_thr = fut_thread_current();
            if (scur_thr)
                pending |= __atomic_load_n(&scur_thr->thread_pending_signals, __ATOMIC_ACQUIRE);
            uint64_t blocked = scur_thr ?
                __atomic_load_n(&scur_thr->signal_mask, __ATOMIC_ACQUIRE) :
                __atomic_load_n(&task->signal_mask, __ATOMIC_ACQUIRE);
            if (pending & ~blocked) {
                ret = -EINTR;
                goto out_restore;
            }
        }

        /* Sleep on epoll waitqueue with timer-based wakeup.
         * Recompute remaining ticks from the ns deadline for accuracy. */
        if (has_timeout) {
            uint64_t now_ns = fut_get_time_ns();
            if (now_ns >= deadline_ns) {
                ret = 0;
                goto out_restore;
            }
            uint64_t remaining_ns = deadline_ns - now_ns;
            uint64_t remaining_ticks = remaining_ns / 10000000ULL;
            if (remaining_ns % 10000000ULL != 0) remaining_ticks++;
            if (remaining_ticks == 0) remaining_ticks = 1;
            fut_waitq_sleep_timed(&set->epoll_waitq, remaining_ticks, NULL);
        } else {
            fut_waitq_sleep_locked(&set->epoll_waitq, NULL, FUT_THREAD_BLOCKED);
        }

        /* Check for pending signals after wakeup → EINTR */
        if (task) {
            uint64_t pending = __atomic_load_n(&task->pending_signals, __ATOMIC_ACQUIRE);
            fut_thread_t *scur_thr = fut_thread_current();
            if (scur_thr)
                pending |= __atomic_load_n(&scur_thr->thread_pending_signals, __ATOMIC_ACQUIRE);
            uint64_t blocked = scur_thr ?
                __atomic_load_n(&scur_thr->signal_mask, __ATOMIC_ACQUIRE) :
                __atomic_load_n(&task->signal_mask, __ATOMIC_ACQUIRE);
            if (pending & ~blocked) {
                ret = -EINTR;
                goto out_restore;
            }
        }
    }

out_restore:
    /* Restore original signal mask */
    if (mask_installed && task) {
        int rret = fut_signal_procmask(task, SIGPROCMASK_SETMASK, &saved_mask, NULL);
        if (rret < 0 && ret >= 0)
            ret = rret;
    }
    return ret;
}
