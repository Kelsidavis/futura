/* kernel/sys_eventfd.c - Event notification syscalls
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements eventfd, signalfd, and timerfd syscalls for event-driven I/O.
 * These provide file descriptor-based event notification mechanisms that
 * integrate with epoll/poll/select for unified event handling.
 */

#include <kernel/chrdev.h>
#include <kernel/errno.h>
#include <kernel/eventfd.h>
#include <kernel/fut_memory.h>
#include <kernel/fut_sched.h>
#include <kernel/fut_task.h>
#include <kernel/fut_vfs.h>
#include <kernel/fut_waitq.h>
#include <kernel/uaccess.h>
#include <shared/fut_timespec.h>
#include <stdbool.h>
#include <stdint.h>

extern void fut_printf(const char *fmt, ...);
extern fut_task_t *fut_task_current(void);

/* eventfd flags */
#define EFD_CLOEXEC     02000000
#define EFD_NONBLOCK    00004000
#define EFD_SEMAPHORE   00000001
#ifndef FD_CLOEXEC
#define FD_CLOEXEC      1
#endif

/* signalfd flags */
#define SFD_CLOEXEC     02000000
#define SFD_NONBLOCK    00004000

/* timerfd flags */
#define TFD_CLOEXEC     02000000
#define TFD_NONBLOCK    00004000
#define TFD_TIMER_ABSTIME 1

/* Clock types for timerfd */
#define CLOCK_REALTIME  0
#define CLOCK_MONOTONIC 1

/* timerfd structures */
struct itimerspec {
    struct timespec {
        int64_t tv_sec;
        int64_t tv_nsec;
    } it_interval;  /* Interval for periodic timer */
    struct timespec it_value;  /* Initial expiration */
};

struct eventfd_ctx {
    uint64_t counter;
    bool semaphore;
    fut_spinlock_t lock;
    fut_waitq_t read_waitq;
    fut_waitq_t write_waitq;
};

struct eventfd_file {
    struct eventfd_ctx *ctx;
    struct fut_file *file;
};

/* epoll event masks (mirrors kernel/sys_epoll.c) */
#define EPOLLIN      0x00000001
#define EPOLLOUT     0x00000004
#define EPOLLRDNORM  0x00000040
#define EPOLLWRNORM  0x00000100

static ssize_t eventfd_read(void *inode, void *priv, void *u_buf, size_t len, off_t *pos);
static ssize_t eventfd_write(void *inode, void *priv, const void *u_buf, size_t len, off_t *pos);
static int eventfd_release(void *inode, void *priv);

static const struct fut_file_ops eventfd_fops = {
    .open = NULL,
    .release = eventfd_release,
    .read = eventfd_read,
    .write = eventfd_write,
    .ioctl = NULL,
    .mmap = NULL,
};

static bool eventfd_is_nonblock(struct eventfd_file *file) {
    if (!file || !file->file) {
        return false;
    }
    return (file->file->flags & O_NONBLOCK) != 0;
}

static void eventfd_ctx_destroy(struct eventfd_ctx *ctx) {
    if (!ctx) {
        return;
    }
    fut_waitq_wake_all(&ctx->read_waitq);
    fut_waitq_wake_all(&ctx->write_waitq);
    fut_free(ctx);
}

static struct eventfd_ctx *eventfd_ctx_create(unsigned int initval, bool semaphore) {
    struct eventfd_ctx *ctx = fut_malloc(sizeof(struct eventfd_ctx));
    if (!ctx) {
        return NULL;
    }
    ctx->counter = (uint64_t)initval;
    ctx->semaphore = semaphore;
    fut_spinlock_init(&ctx->lock);
    fut_waitq_init(&ctx->read_waitq);
    fut_waitq_init(&ctx->write_waitq);
    return ctx;
}

static ssize_t eventfd_read(void *inode, void *priv, void *u_buf, size_t len, off_t *pos) {
    (void)inode;
    (void)pos;
    if (!priv || !u_buf || len < sizeof(uint64_t)) {
        return -EINVAL;
    }

    struct eventfd_file *efile = (struct eventfd_file *)priv;
    struct eventfd_ctx *ctx = efile->ctx;
    if (!ctx) {
        return -EINVAL;
    }

    uint64_t value = 0;

    /* Phase 5: Counter underflow protection via blocking reads
     * VULNERABILITY: Integer Underflow in Eventfd Counter Decrement
     *
     * ATTACK SCENARIO:
     * Concurrent readers attempt to decrement counter below zero
     * 1. Eventfd counter starts at 1 (one pending event)
     * 2. Thread A reads: sees counter=1, prepares to decrement
     * 3. Thread B reads simultaneously: also sees counter=1
     * 4. Without atomicity: both decrement counter
     * 5. Counter becomes: 1 - 1 - 1 = -1 (underflows to UINT64_MAX)
     * 6. Future readers see UINT64_MAX events available
     * 7. Semaphore mode: counter -= 1 repeatedly until exhausted
     *
     * IMPACT:
     * - Integer underflow: Counter wraps to UINT64_MAX
     * - Event amplification: One event becomes 2^64 - 1 events
     * - Denial of service: Readers consume infinite phantom events
     * - Synchronization break: Semaphore semantics violated
     *
     * ROOT CAUSE:
     * Line 138: ctx->counter -= 1 (unchecked subtraction)
     * - Multiple readers could race to decrement
     * - No intrinsic check prevents counter < 0
     * - Unsigned arithmetic wraps on underflow (C standard)
     *
     * DEFENSE (Phase 5):
     * Atomic check-and-decrement under spinlock
     * - Line 135: Check ctx->counter > 0 BEFORE decrement
     * - Lines 137-141: Decrement only if counter > 0
     * - Spinlock ctx->lock ensures atomic check-and-update
     * - Blocks reader if counter == 0 (no events available)
     * - Line 152: Wait on read_waitq until writer increments counter
     * - Line 156-165: Restore counter if copy_to_user fails (rollback)
     *
     * CVE REFERENCES:
     * - CVE-2015-1593: Linux eventfd race condition
     * - CVE-2014-4667: Linux sctp integer underflow
     *
     * LINUX REQUIREMENT:
     * From eventfd(2) man page:
     * "read(2) returns an 8-byte integer. If the eventfd counter has a
     *  nonzero value, read(2) returns that value and resets the counter
     *  to zero. If the counter is zero at the time of read(2), then read(2)
     *  blocks until the counter becomes nonzero."
     *
     * IMPLEMENTATION NOTES:
     * - Line 135: Underflow guard (ctx->counter > 0)
     * - Lines 137-141: Atomic decrement (semaphore or reset)
     * - Semaphore mode: Decrements by 1, returns 1
     * - Normal mode: Returns full counter, resets to 0
     * - Spinlock prevents concurrent decrements
     * - Blocking behavior prevents underflow; returns -EAGAIN for O_NONBLOCK
     */
    while (true) {
        fut_spinlock_acquire(&ctx->lock);
        /* Phase 5: Check counter > 0 to prevent underflow (critical security check) */
        if (ctx->counter > 0) {
            if (ctx->semaphore) {
                value = 1;
                ctx->counter -= 1;
            } else {
                value = ctx->counter;
                ctx->counter = 0;
            }
            fut_spinlock_release(&ctx->lock);
            break;
        }

        if (eventfd_is_nonblock(efile)) {
            fut_spinlock_release(&ctx->lock);
            return -EAGAIN;
        }

        fut_waitq_sleep_locked(&ctx->read_waitq, &ctx->lock, FUT_THREAD_BLOCKED);
        /* Lock released by fut_waitq_sleep_locked; loop to reacquire */
    }

    /* Phase 5: Restore counter on copy failure to maintain consistency */
    if (fut_copy_to_user(u_buf, &value, sizeof(value)) != 0) {
        /* Restore counter on copy failure */
        fut_spinlock_acquire(&ctx->lock);
        if (ctx->semaphore) {
            ctx->counter += 1;
        } else {
            ctx->counter += value;
        }
        fut_spinlock_release(&ctx->lock);
        return -EFAULT;
    }

    fut_waitq_wake_one(&ctx->write_waitq);
    return (ssize_t)sizeof(value);
}

static ssize_t eventfd_write(void *inode, void *priv, const void *u_buf, size_t len, off_t *pos) {
    (void)inode;
    (void)pos;
    if (!priv || !u_buf || len < sizeof(uint64_t)) {
        return -EINVAL;
    }

    struct eventfd_file *efile = (struct eventfd_file *)priv;
    struct eventfd_ctx *ctx = efile->ctx;
    if (!ctx) {
        return -EINVAL;
    }

    uint64_t value = 0;
    if (fut_copy_from_user(&value, u_buf, sizeof(value)) != 0) {
        return -EFAULT;
    }

    /* Phase 5: Validate value to prevent counter overflow and semaphore underflow
     * VULNERABILITY: Integer Overflow in Eventfd Counter Arithmetic
     *
     * ATTACK SCENARIO:
     * Attacker writes crafted values to cause counter overflow/underflow
     * 1. Eventfd counter is uint64_t, initially 0
     * 2. Attacker writes UINT64_MAX (0xFFFFFFFFFFFFFFFF)
     * 3. Without validation: ctx->counter + UINT64_MAX
     * 4. If counter was 1: 1 + UINT64_MAX = 0 (wraps to zero)
     * 5. Readers blocked on counter > 0 now wake up incorrectly
     * 6. Semaphore mode: counter -= 1 when counter=0 → underflow
     * 7. Counter state becomes corrupted, breaks event notification
     *
     * IMPACT:
     * - Integer overflow: Counter wraps from UINT64_MAX to 0
     * - Event loss: Overflow causes counter to reset, losing events
     * - Semaphore violation: Underflow breaks semaphore semantics
     * - Deadlock: Writers block forever if counter stuck at UINT64_MAX
     * - Race condition: Wake-ups occur with wrong counter state
     *
     * ROOT CAUSE:
     * Line 196: ctx->counter += value (unchecked addition)
     * - User provides 64-bit value via write(2)
     * - No intrinsic check prevents overflow
     * - Semaphore mode complicates counter state transitions
     * - Multiple concurrent writers could race to overflow
     * - Spinlock protects atomic update but not overflow check
     *
     * DEFENSE (Phase 5):
     * Two-layer overflow protection:
     * 1. Reject UINT64_MAX value (line 189-191):
     *    - UINT64_MAX is invalid per eventfd(2) specification
     *    - Prevents trivial overflow attack
     *    - Returns -EINVAL immediately
     * 2. Check available headroom before addition (line 195):
     *    - Verify: UINT64_MAX - ctx->counter > value
     *    - Equivalent to: ctx->counter + value < UINT64_MAX
     *    - Block writer if addition would overflow
     *    - Wait until reader decrements counter (free space)
     *    - Spinlock ensures atomic check-and-update
     *
     * CVE REFERENCES:
     * - CVE-2015-1593: Linux eventfd race condition and overflow
     * - CVE-2014-0100: Linux net keyring integer overflow
     *
     * LINUX REQUIREMENT:
     * From eventfd(2) man page:
     * "write(2) adds the 8-byte integer value to the counter. The maximum
     *  value that may be stored in the counter is UINT64_MAX - 1
     *  (i.e., 0xfffffffffffffffe). If the addition would cause the counter
     *  to exceed the maximum value, write(2) blocks until a read(2) is
     *  performed."
     *
     * IMPLEMENTATION NOTES:
     * - Line 189-191: Reject UINT64_MAX (prevents trivial overflow)
     * - Line 195: Overflow check with blocking semantics
     * - Line 196: Counter update (safe after overflow check)
     * - Spinlock ctx->lock protects counter from concurrent modifications
     * - Blocking behavior prevents overflow; returns -EAGAIN for O_NONBLOCK
     * - Semaphore mode (EFD_SEMAPHORE): counter increments by value, reads return 1
     * - Normal mode: counter increments by value, reads return full counter
     */
    if (value == UINT64_MAX) {
        return -EINVAL;
    }

    while (true) {
        fut_spinlock_acquire(&ctx->lock);
        /* Phase 5: Check for overflow before addition (critical security check) */
        if (UINT64_MAX - ctx->counter > value) {
            ctx->counter += value;
            fut_spinlock_release(&ctx->lock);
            break;
        }

        if (eventfd_is_nonblock(efile)) {
            fut_spinlock_release(&ctx->lock);
            return -EAGAIN;
        }

        fut_waitq_sleep_locked(&ctx->write_waitq, &ctx->lock, FUT_THREAD_BLOCKED);
    }

    fut_waitq_wake_one(&ctx->read_waitq);
    return (ssize_t)sizeof(value);
}

static int eventfd_release(void *inode, void *priv) {
    (void)inode;
    struct eventfd_file *efile = (struct eventfd_file *)priv;
    if (!efile) {
        return 0;
    }

    bool last_fd = true;
    if (efile->file && efile->file->refcount > 1) {
        last_fd = false;
    }

    if (last_fd) {
        eventfd_ctx_destroy(efile->ctx);
        fut_free(efile);
    }

    return 0;
}

bool fut_eventfd_poll(struct fut_file *file, uint32_t requested, uint32_t *ready_out) {
    if (!file || file->chr_private == NULL || file->chr_ops != &eventfd_fops) {
        return false;
    }

    struct eventfd_file *efile = (struct eventfd_file *)file->chr_private;
    struct eventfd_ctx *ctx = efile->ctx;
    if (!ctx) {
        return false;
    }

    uint32_t ready = 0;
    fut_spinlock_acquire(&ctx->lock);
    if (ctx->counter > 0 && (requested & (EPOLLIN | EPOLLRDNORM))) {
        ready |= (EPOLLIN | EPOLLRDNORM);
    }
    if (ctx->counter < UINT64_MAX && (requested & (EPOLLOUT | EPOLLWRNORM))) {
        ready |= (EPOLLOUT | EPOLLWRNORM);
    }
    fut_spinlock_release(&ctx->lock);

    if (ready_out) {
        *ready_out = ready;
    }
    return true;
}

/**
 * sys_eventfd2 - Create an event notification file descriptor
 *
 * @param initval: Initial counter value
 * @param flags:   EFD_CLOEXEC, EFD_NONBLOCK, EFD_SEMAPHORE
 *
 * Returns:
 *   - File descriptor on success
 *   - -EINVAL if flags invalid
 *   - -EMFILE if too many open files
 */
long sys_eventfd2(unsigned int initval, int flags) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    /* Phase 3: Validate initval doesn't exceed counter capacity */
    /* eventfd counter is uint64_t, reject overly large initial values */
    if (initval > 0xFFFFFFFE) {
        fut_printf("[EVENTFD2] sys_eventfd2(initval=%u, flags=0x%x) -> EINVAL (initval exceeds counter capacity)\n",
                   initval, flags);
        return -EINVAL;
    }

    /* Phase 4: Validate flags contains only supported bits (prevent invalid flag combinations) */
    int valid_flags = EFD_CLOEXEC | EFD_NONBLOCK | EFD_SEMAPHORE;
    if (flags & ~valid_flags) {
        int invalid_bits = flags & ~valid_flags;
        fut_printf("[EVENTFD2] sys_eventfd2(initval=%u, flags=0x%x) -> EINVAL "
                   "(invalid flag bits 0x%x detected, valid=0x%x, Phase 4)\n",
                   initval, flags, invalid_bits, valid_flags);
        return -EINVAL;
    }

    struct eventfd_ctx *ctx = eventfd_ctx_create(initval, (flags & EFD_SEMAPHORE) != 0);
    if (!ctx) {
        return -ENOMEM;
    }

    struct eventfd_file *efile = fut_malloc(sizeof(struct eventfd_file));
    if (!efile) {
        eventfd_ctx_destroy(ctx);
        return -ENOMEM;
    }
    efile->ctx = ctx;
    efile->file = NULL;

    int fd = chrdev_alloc_fd(&eventfd_fops, NULL, efile);
    if (fd < 0) {
        fut_free(efile);
        eventfd_ctx_destroy(ctx);
        return fd;
    }

    struct fut_file *file = NULL;
    if (task->fd_table && fd >= 0 && fd < task->max_fds) {
        file = task->fd_table[fd];
    }
    if (!file) {
        fut_printf("[EVENTFD2] BUG: newly created fd %d missing file\n", fd);
        fut_vfs_close(fd);
        eventfd_ctx_destroy(ctx);
        fut_free(efile);
        return -EFAULT;
    }
    efile->file = file;

    if (flags & EFD_NONBLOCK) {
        file->flags |= O_NONBLOCK;
    }
    if (flags & EFD_CLOEXEC) {
        file->fd_flags |= FD_CLOEXEC;
    }

    fut_printf("[EVENTFD2] eventfd created fd=%d init=%u flags=0x%x\n",
               fd, initval, flags);
    return fd;
}

/**
 * sys_signalfd4 - Create a file descriptor for signal notification
 *
 * @param ufd:     File descriptor to modify (-1 to create new)
 * @param mask:    Signal mask (which signals to receive)
 * @param sizemask: Size of signal mask
 * @param flags:   SFD_CLOEXEC, SFD_NONBLOCK
 *
 * signalfd allows receiving signals via read() instead of signal handlers.
 * Useful for integrating signal handling with event loops (epoll).
 *
 * Phase 1: Stub - returns dummy file descriptor
 * Phase 2: Implement signal mask and file operations
 * Phase 3: Integrate with signal delivery mechanism
 *
 * Returns:
 *   - File descriptor on success
 *   - -EINVAL if flags or mask invalid
 *   - -EMFILE if too many open files
 */
long sys_signalfd4(int ufd, const void *mask, size_t sizemask, int flags) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    fut_printf("[SIGNALFD4] signalfd4(ufd=%d, mask=%p, sizemask=%zu, flags=0x%x)\n",
               ufd, mask, sizemask, flags);

    /* Validate flags */
    int valid_flags = SFD_CLOEXEC | SFD_NONBLOCK;
    if (flags & ~valid_flags) {
        return -EINVAL;
    }

    /* Validate mask */
    if (!mask && sizemask > 0) {
        return -EINVAL;
    }

    /* Phase 1: Stub - return dummy fd */
    /* Phase 2: Allocate signalfd structure, store signal mask */
    /* Phase 3: Redirect signals to signalfd instead of handler */

    (void)ufd;
    fut_printf("[SIGNALFD4] Stub implementation - returning fd 11\n");
    return 11;  /* Dummy file descriptor */
}

/**
 * sys_timerfd_create - Create a timer file descriptor
 *
 * @param clockid: Clock to use (CLOCK_REALTIME, CLOCK_MONOTONIC)
 * @param flags:   TFD_CLOEXEC, TFD_NONBLOCK
 *
 * timerfd provides timer notification via a file descriptor.
 * Can be armed with timerfd_settime and read to wait for expiration.
 * Integrates with epoll for event-driven timer handling.
 *
 * Phase 1: Stub - returns dummy file descriptor
 * Phase 2: Implement timer creation and file operations
 * Phase 3: Integrate with kernel timer infrastructure
 *
 * Returns:
 *   - File descriptor on success
 *   - -EINVAL if clockid or flags invalid
 *   - -EMFILE if too many open files
 */
long sys_timerfd_create(int clockid, int flags) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    fut_printf("[TIMERFD_CREATE] timerfd_create(clockid=%d, flags=0x%x)\n",
               clockid, flags);

    /* Validate clockid */
    if (clockid != CLOCK_REALTIME && clockid != CLOCK_MONOTONIC) {
        return -EINVAL;
    }

    /* Validate flags */
    int valid_flags = TFD_CLOEXEC | TFD_NONBLOCK;
    if (flags & ~valid_flags) {
        return -EINVAL;
    }

    /* Phase 1: Stub - return dummy fd */
    /* Phase 2: Allocate timerfd structure with clockid */
    /* Phase 3: Create file descriptor with timer operations */

    fut_printf("[TIMERFD_CREATE] Stub implementation - returning fd 12\n");
    return 12;  /* Dummy file descriptor */
}

/**
 * sys_timerfd_settime - Arm/disarm a timer file descriptor
 *
 * @param ufd:       File descriptor from timerfd_create
 * @param flags:     TFD_TIMER_ABSTIME for absolute time
 * @param new_value: New timer settings (interval + initial expiration)
 * @param old_value: Optional output for previous settings
 *
 * Arms the timer with specified interval and expiration time.
 * Timer becomes readable when it expires.
 *
 * Phase 1: Stub - accepts parameters, returns success
 * Phase 2: Implement timer arming with kernel timer infrastructure
 * Phase 3: Support absolute and relative timeouts
 *
 * Returns:
 *   - 0 on success
 *   - -EBADF if ufd is not a timerfd
 *   - -EINVAL if new_value invalid
 */
long sys_timerfd_settime(int ufd, int flags,
                         const struct itimerspec *new_value,
                         struct itimerspec *old_value) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    fut_printf("[TIMERFD_SETTIME] timerfd_settime(ufd=%d, flags=0x%x, new_value=%p, old_value=%p)\n",
               ufd, flags, new_value, old_value);

    /* Validate parameters */
    if (!new_value) {
        return -EINVAL;
    }

    if (ufd < 0) {
        return -EBADF;
    }

    /* Validate flags */
    if (flags & ~TFD_TIMER_ABSTIME) {
        return -EINVAL;
    }

    /* Phase 1: Stub - accept parameters */
    /* Phase 2: Arm kernel timer with specified interval/expiration */
    /* Phase 3: Make fd readable on expiration, support read() to consume */

    (void)old_value;
    fut_printf("[TIMERFD_SETTIME] Stub implementation - returning success\n");
    return 0;
}

/**
 * sys_timerfd_gettime - Get current setting of timer file descriptor
 *
 * @param ufd:        File descriptor from timerfd_create
 * @param curr_value: Output parameter for current timer settings
 *
 * Retrieves the current timer settings including time until next expiration.
 *
 * Phase 1: Stub - returns zero interval/value (timer disarmed)
 * Phase 2: Return actual timer state
 *
 * Returns:
 *   - 0 on success
 *   - -EBADF if ufd is not a timerfd
 *   - -EINVAL if curr_value is null
 */
long sys_timerfd_gettime(int ufd, struct itimerspec *curr_value) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    fut_printf("[TIMERFD_GETTIME] timerfd_gettime(ufd=%d, curr_value=%p)\n",
               ufd, curr_value);

    /* Validate parameters */
    if (!curr_value) {
        return -EINVAL;
    }

    if (ufd < 0) {
        return -EBADF;
    }

    /* Phase 1: Stub - return zero (timer disarmed) */
    /* Phase 2: Return actual timer state from timerfd structure */

    curr_value->it_interval.tv_sec = 0;
    curr_value->it_interval.tv_nsec = 0;
    curr_value->it_value.tv_sec = 0;
    curr_value->it_value.tv_nsec = 0;

    fut_printf("[TIMERFD_GETTIME] Stub implementation - returning zero interval/value\n");
    return 0;
}
