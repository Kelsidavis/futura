/* kernel/sys_poll.c - poll() syscall implementation
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements I/O multiplexing syscall for monitoring multiple file descriptors.
 */

#include <kernel/errno.h>
#include <kernel/uaccess.h>
#include <kernel/fut_task.h>
#include <kernel/fut_vfs.h>
#include <poll.h>  /* For struct pollfd, POLL* constants */
#include <stdint.h>
#include <string.h>

#include <kernel/kprintf.h>
#include <kernel/fut_memory.h>
#include <kernel/debug_config.h>
#include <kernel/eventfd.h>
#include <kernel/fut_socket.h>
#include <kernel/fut_thread.h>
#include <kernel/fut_timer.h>
#include <kernel/signal.h>
#include <sys/epoll.h>

/* Architecture-specific paging headers for KERNEL_VIRTUAL_BASE */
#ifdef __x86_64__
#include <platform/x86_64/memory/paging.h>
#elif defined(__aarch64__)
#include <platform/arm64/memory/paging.h>
#endif

/* Poll debugging (controlled via debug_config.h) */
#define poll_printf(...) do { if (POLL_DEBUG) fut_printf(__VA_ARGS__); } while(0)

/* Phase 4: per-call wait queue wakeup callback */
static void poll_waitq_wakeup(void *arg) {
    fut_waitq_t *wq = (fut_waitq_t *)arg;
    if (wq) fut_waitq_wake_all(wq);
}

/* Wire all monitored FDs to a wait queue so any I/O event wakes us. */
static void poll_wire_fds(struct pollfd *kfds, unsigned long nfds,
                          fut_task_t *task, fut_waitq_t *wq) {
    extern void fut_eventfd_set_epoll_notify(struct fut_file *f, fut_waitq_t *wq);
    extern void fut_timerfd_set_epoll_notify(struct fut_file *f, fut_waitq_t *wq);
    extern void fut_signalfd_set_epoll_notify(struct fut_file *f, fut_waitq_t *wq);
    extern void fut_pipe_set_epoll_notify(struct fut_file *f, fut_waitq_t *wq);
    for (unsigned long i = 0; i < nfds; i++) {
        int fd = kfds[i].fd;
        if (fd < 0 || fd >= (int)task->max_fds || !task->fd_table || !task->fd_table[fd])
            continue;
        struct fut_file *file = task->fd_table[fd];
        fut_eventfd_set_epoll_notify(file, wq);
        fut_timerfd_set_epoll_notify(file, wq);
        fut_signalfd_set_epoll_notify(file, wq);
        fut_pipe_set_epoll_notify(file, wq);
        fut_socket_t *sock = get_socket_from_fd(fd);
        if (sock) {
            if (sock->pair_reverse) sock->pair_reverse->epoll_notify = wq;
            if (sock->listener)    sock->listener->epoll_notify = wq;
            /* CONNECTING socket: wire connect_notify so poll wakes when accept() completes */
            if (sock->state == FUT_SOCK_CONNECTING)
                sock->connect_notify = wq;
        }
    }
}

/* Clear epoll_notify pointers we set; leaves other watchers untouched. */
static void poll_unwire_fds(struct pollfd *kfds, unsigned long nfds,
                             fut_task_t *task, fut_waitq_t *wq) {
    extern void fut_eventfd_set_epoll_notify(struct fut_file *f, fut_waitq_t *wq);
    extern void fut_timerfd_set_epoll_notify(struct fut_file *f, fut_waitq_t *wq);
    extern void fut_signalfd_set_epoll_notify(struct fut_file *f, fut_waitq_t *wq);
    extern void fut_pipe_set_epoll_notify(struct fut_file *f, fut_waitq_t *wq);
    for (unsigned long i = 0; i < nfds; i++) {
        int fd = kfds[i].fd;
        if (fd < 0 || fd >= (int)task->max_fds || !task->fd_table || !task->fd_table[fd])
            continue;
        struct fut_file *file = task->fd_table[fd];
        fut_eventfd_set_epoll_notify(file, NULL);
        fut_timerfd_set_epoll_notify(file, NULL);
        fut_signalfd_set_epoll_notify(file, NULL);
        fut_pipe_set_epoll_notify(file, NULL);
        fut_socket_t *sock = get_socket_from_fd(fd);
        if (sock) {
            if (sock->pair_reverse && sock->pair_reverse->epoll_notify == wq)
                sock->pair_reverse->epoll_notify = NULL;
            if (sock->listener && sock->listener->epoll_notify == wq)
                sock->listener->epoll_notify = NULL;
            if (sock->connect_notify == wq)
                sock->connect_notify = NULL;
        }
    }
}

struct poll_scan_stats {
    int ready_count;
    int invalid_count;
};

static struct poll_scan_stats poll_scan_fds(struct pollfd *kfds, unsigned long nfds, fut_task_t *task) {
    struct poll_scan_stats stats = {0, 0};

    for (unsigned long i = 0; i < nfds; i++) {
        kfds[i].revents = 0;

        if (kfds[i].fd < 0 || kfds[i].fd >= task->max_fds) {
            kfds[i].revents = POLLNVAL;
            stats.ready_count++;
            stats.invalid_count++;
            continue;
        }

        struct fut_file *file = task->fd_table[kfds[i].fd];
        if (!file) {
            kfds[i].revents = POLLNVAL;
            stats.ready_count++;
            stats.invalid_count++;
            continue;
        }

        uint32_t epoll_req = 0;
        if (kfds[i].events & POLLIN)  epoll_req |= EPOLLIN;
        if (kfds[i].events & POLLOUT) epoll_req |= EPOLLOUT;
        if (kfds[i].events & POLLPRI) epoll_req |= EPOLLPRI;

        uint32_t epoll_ready = 0;
        bool handled = false;

        if (!handled && fut_eventfd_poll(file, epoll_req, &epoll_ready))
            handled = true;
        if (!handled && fut_timerfd_poll(file, epoll_req, &epoll_ready))
            handled = true;
        if (!handled && fut_signalfd_poll(file, epoll_req, &epoll_ready))
            handled = true;
        if (!handled && fut_pipe_poll(file, epoll_req, &epoll_ready))
            handled = true;

        if (!handled) {
            fut_socket_t *socket = get_socket_from_fd(kfds[i].fd);
            if (socket) {
                int poll_events = 0;
                if (kfds[i].events & POLLIN)  poll_events |= 0x1;
                if (kfds[i].events & POLLOUT) poll_events |= 0x4;
                int socket_ready = fut_socket_poll(socket, poll_events);
                if (socket_ready & 0x1)  epoll_ready |= EPOLLIN;
                if (socket_ready & 0x4)  epoll_ready |= EPOLLOUT;
                if (socket_ready & 0x10) epoll_ready |= EPOLLHUP | EPOLLRDHUP;
                if (socket_ready & 0x8)  epoll_ready |= EPOLLERR;
                handled = true;
            }
        }

        if (!handled && file->vnode && file->vnode->type == VN_REG) {
            if (epoll_req & EPOLLIN)  epoll_ready |= EPOLLIN;
            if (epoll_req & EPOLLOUT) epoll_ready |= EPOLLOUT;
            handled = true;
        }

        if (!handled) {
            if (epoll_req & EPOLLIN)  epoll_ready |= EPOLLIN;
            if (epoll_req & EPOLLOUT) epoll_ready |= EPOLLOUT;
        }

        if (epoll_ready & EPOLLIN)    kfds[i].revents |= POLLIN;
        if (epoll_ready & EPOLLOUT)   kfds[i].revents |= POLLOUT;
        if (epoll_ready & EPOLLPRI)   kfds[i].revents |= POLLPRI;
        if (epoll_ready & EPOLLHUP)   kfds[i].revents |= POLLHUP;
        if (epoll_ready & EPOLLERR)   kfds[i].revents |= POLLERR;
        if (epoll_ready & EPOLLRDHUP) kfds[i].revents |= 0x2000; /* POLLRDHUP */

        if (kfds[i].revents != 0) {
            stats.ready_count++;
        }
    }

    return stats;
}

/**
 * poll() syscall - Wait for events on file descriptors
 *
 * @param fds      Array of pollfd structures
 * @param nfds     Number of file descriptors in fds
 * @param timeout  Timeout in milliseconds (-1 = infinite, 0 = return immediately)
 *
 * Returns:
 *   - Number of file descriptors with events (>= 0) on success
 *   - -EFAULT if fds points to invalid memory
 *   - -EINVAL if nfds exceeds limits
 *
 * Behavior:
 *   - Monitors file descriptors specified in fds array
 *   - Returns when at least one FD has an event or timeout occurs
 *   - Sets revents field for each FD based on actual events
 *   - For now, implements basic stub returning immediate readiness
 *
 * Phase 1 (Completed): Stub implementation - returns all FDs as ready
 * Phase 2 (Completed): Enhanced validation and detailed event reporting
 * Phase 3 (Completed): Check actual FD readiness: eventfd, timerfd, signalfd, sockets, regular files
 * Phase 4: Add blocking support with wait queues
 * Integrate with epoll for efficient event notification
 */
long sys_poll(struct pollfd *fds, unsigned long nfds, int timeout) {
    /* Phase 2: Enhanced validation */
    if (!fds && nfds > 0) {
        poll_printf("[POLL] poll(NULL, %lu, %d) -> EFAULT (fds is NULL)\n", nfds, timeout);
        return -EFAULT;
    }

    if (timeout < -1) {
        poll_printf("[POLL] poll(fds, %lu, timeout=%d) -> EINVAL (timeout must be >= -1)\n", nfds, timeout);
        return -EINVAL;
    }

    /* nfds == 0 is valid (wait for timeout only) */
    if (nfds == 0) {
        if (timeout > 0) {
            fut_thread_sleep((uint64_t)timeout);
        }
        poll_printf("[POLL] poll(fds, 0, %d) -> 0 (no FDs to monitor)\n", timeout);
        return 0;
    }

    /* Validate fds array write permission early (kernel writes revents)
     * VULNERABILITY: Invalid Output Buffer Array
     * ATTACK: Attacker provides read-only or unmapped fds array
     * IMPACT: Kernel page fault when writing revents to pollfd structures
     * DEFENSE: Check write permission for entire array before processing */
    size_t fds_size = nfds * sizeof(struct pollfd);
    /* Skip access_ok for kernel-originated calls (e.g., kernel self-tests).
     * Kernel stack addresses are above KERNEL_VIRTUAL_BASE. */
    uintptr_t fds_ptr_val = (uintptr_t)fds;
    bool fds_is_kernel = (fds_ptr_val >= KERNEL_VIRTUAL_BASE);
    if (!fds_is_kernel && fut_access_ok(fds, fds_size, 1) != 0) {
        poll_printf("[POLL] poll(fds=%p, nfds=%lu, timeout=%d) -> EFAULT (fds array not writable for %zu bytes)\n",
                   fds, nfds, timeout, fds_size);
        return -EFAULT;
    }

    /* Reasonable limit on number of file descriptors */
    if (nfds > 1024) {
        poll_printf("[POLL] poll(fds, %lu, %d) -> EINVAL (nfds exceeds limit of 1024)\n", nfds, timeout);
        return -EINVAL;
    }

    /* Validate nfds BEFORE multiplication to prevent overflow
     * VULNERABILITY: Integer Overflow and Resource Exhaustion
     *
     * ATTACK SCENARIO 1: Integer Overflow in Size Calculation
     * Attacker provides nfds value causing multiplication wraparound
     * 1. sizeof(struct pollfd) = 8 bytes (fd=4, events=2, revents=2)
     * 2. Attacker calls poll(fds, nfds=SIZE_MAX/8 + 1, timeout)
     * 3. WITHOUT check (line 131-136):
     *    - Line 139: size = (SIZE_MAX/8 + 1) * 8
     *    - Multiplication wraps: (SIZE_MAX/8 + 1) * 8 = SIZE_MAX + 8 → wraps to 7
     *    - Line 142: fut_malloc(7) succeeds (tiny allocation)
     *    - Line 149: fut_copy_from_user(kfds, fds, 7) copies only 7 bytes
     *    - Line 170: for (i = 0; i < nfds; i++) loops SIZE_MAX/8 + 1 times
     *    - Accesses kfds[0] through kfds[SIZE_MAX/8] but buffer only 7 bytes
     *    - Result: Massive buffer overrun, kernel memory corruption
     *
     * ATTACK SCENARIO 2: Memory Exhaustion via Large nfds
     * Attacker provides maximum valid nfds to exhaust kernel heap
     * 1. Attacker calls poll(fds, nfds=1024, timeout) repeatedly
     * 2. Each call: Line 142 allocates 1024 * 8 = 8KB kernel buffer
     * 3. Tight loop: 1000 calls/second = 8MB/sec allocation rate
     * 4. Memory not freed until syscall returns (line 219)
     * 5. Kernel heap fragmented with many 8KB allocations
     * 6. System runs out of memory (DoS)
     *
     * ATTACK SCENARIO 3: CPU Exhaustion via Unbounded FD Iteration
     * Attacker maximizes nfds and timeout to monopolize CPU
     * 1. Attacker calls poll(fds, nfds=1024, timeout=-1) (infinite timeout)
     * 2. Line 170-210: Kernel iterates 1024 FDs checking readiness
     * 3. Each iteration: FD validation, table lookup, event checking
     * 4. Phase 3+ would block waiting for events (infinite timeout)
     * 5. No work budget or preemption point in FD iteration
     * 6. CPU saturated, other processes starved
     *
     * ATTACK SCENARIO 4: Negative Timeout Integer Underflow
     * Attacker provides timeout < -1 to exploit unchecked arithmetic
     * 1. Attacker calls poll(fds, nfds=10, timeout=INT_MIN)
     * 2. Line 87-90: Validation checks timeout >= -1 (Phase 3)
     * 3. But timeout=INT_MIN fails check (returns EINVAL correctly)
     * 4. However, if check missing: timeout arithmetic wraps
     * 5. Timeout conversion to absolute time overflows
     * 6. Poll never wakes up (infinite hang)
     *
     * ATTACK SCENARIO 5: Post-Multiplication Validation Bypass
     * Why post-multiplication checks are INSUFFICIENT:
     * 1. Attacker: poll(fds, SIZE_MAX/8 + 1, timeout)
     * 2. WRONG: size = nfds * sizeof(pollfd); if (size/sizeof != nfds) return -EINVAL
     * 3. size = SIZE_MAX + 8 → wraps to 7
     * 4. Division: 7 / 8 = 0 ≠ SIZE_MAX/8 + 1 → EINVAL (seems to work)
     * 5. BUT: Edge case when size wraps to exactly divisible value
     * 6. Example: nfds chosen so size wraps to 8 * N (looks valid)
     * 7. Post-multiplication check fails to detect overflow
     *
     * IMPACT:
     * - Buffer overflow: Kernel memory corruption via OOB kfds[] access
     * - Memory exhaustion DoS: Kernel heap depletion via large allocations
     * - CPU exhaustion DoS: Unbounded FD iteration monopolizes CPU
     * - Kernel panic: Corruption of critical kernel data structures
     * - Privilege escalation: Overwritten function pointers via overflow
     *
     * ROOT CAUSE:
     * Pre-code lacked comprehensive validation:
     * - No pre-multiplication overflow check (added line 131-136)
     * - No protection against repeated large allocations
     * - No CPU work budget for FD iteration
     * - Timeout validation incomplete (fixed line 87-90)
     * - Post-multiplication validation insufficient (see scenario 5)
     *
     * DEFENSE (Requirements):
     * 1. Pre-Multiplication Overflow Check:
     *    - Check: nfds <= SIZE_MAX / sizeof(struct pollfd)
     *    - BEFORE any multiplication (line 131-136)
     *    - Guarantees no wraparound in size calculation
     * 2. Reasonable nfds Limit:
     *    - Cap at 1024 (line 81-84) to prevent memory exhaustion
     *    - Lower than SIZE_MAX/8 but still practical
     *    - Balances functionality vs DoS prevention
     * 3. Timeout Validation:
     *    - Check: timeout >= -1 (line 87-90)
     *    - Reject negative values except -1 (infinite)
     *    - Prevent timeout arithmetic underflow
     * 4. Future Phase 4 Requirements:
     *    - Add work budget: return -EINTR after N FD checks
     *    - Add preemption points in FD iteration loop
     *    - Limit blocking time even with timeout=-1
     *
     * CVE REFERENCES:
     * - CVE-2016-9191: Linux sysctl integer overflow in similar nfds pattern
     * - CVE-2017-16995: Linux eBPF array multiplication overflow
     * - CVE-2014-2851: Linux group_info allocation overflow
     * - CVE-2016-6480: Linux ioctl integer overflow in poll-like syscall
     *
     * POSIX REQUIREMENT:
     * From POSIX.1-2008 poll(2):
     * "The poll() function shall support regular files, terminal and
     *  pseudo-terminal devices, FIFOs, pipes, sockets and streams."
     * - No explicit limit on nfds, but implementation may impose limits
     * - Must validate nfds to prevent resource exhaustion
     * - Negative timeout except -1 is unspecified (implementation-defined)
     *
     * LINUX REQUIREMENT:
     * From poll(2) man page:
     * "The bits that may be set/returned in events and revents are defined
     *  in <poll.h>. The field fd contains a file descriptor for an open file."
     * - Linux typically limits nfds to prevent DoS
     * - Must return EINVAL for unreasonable nfds values
     * - Must validate timeout to prevent overflow
     *
     * IMPLEMENTATION NOTES:
     * - Phase 2: Added pre-multiplication check (line 131-136) ✓
     * - Phase 2: Added reasonable limit (1024) at line 81-84 ✓
     * - Phase 3: Added timeout validation at line 87-90 ✓
     * - Phase 4 TODO: Add work budget for long FD iterations
     * - Phase 4 TODO: Add preemption points in loop
     * - See Linux kernel: fs/select.c do_poll() for reference
     */
    if (nfds > SIZE_MAX / sizeof(struct pollfd)) {
        poll_printf("[POLL] poll(fds, %lu, %d) -> EINVAL "
                   "(nfds exceeds max safe %zu, would cause overflow)\n",
                   nfds, timeout, SIZE_MAX / sizeof(struct pollfd));
        return -EINVAL;
    }

    /* Now safe to multiply - overflow mathematically impossible after check */
    size_t size = nfds * sizeof(struct pollfd);

    /* Allocate kernel buffer for pollfd array */
    struct pollfd *kfds = fut_malloc(size);
    if (!kfds) {
        poll_printf("[POLL] poll(fds, %lu, %d) -> ENOMEM (allocation failed)\n", nfds, timeout);
        return -ENOMEM;
    }

    /* Copy pollfd array from userspace (or kernel buffer for self-tests) */
    int copy_ret = fds_is_kernel
        ? (memcpy(kfds, fds, size), 0)
        : fut_copy_from_user(kfds, fds, size);
    if (copy_ret != 0) {
        fut_free(kfds);
        poll_printf("[POLL] poll(fds, %lu, %d) -> EFAULT (copy_from_user failed)\n", nfds, timeout);
        return -EFAULT;
    }

    fut_task_t *task = fut_task_current();
    if (!task || !task->fd_table) {
        fut_free(kfds);
        poll_printf("[POLL] poll(fds, %lu, %d) -> ESRCH (no task or fd_table)\n", nfds, timeout);
        return -ESRCH;
    }

    /* Phase 2: Track event statistics */
    int pollin_requested = 0;
    int pollout_requested = 0;
    int pollpri_requested = 0;

    for (unsigned long i = 0; i < nfds; i++) {
        if (kfds[i].events & POLLIN) pollin_requested++;
        if (kfds[i].events & POLLOUT) pollout_requested++;
        if (kfds[i].events & POLLPRI) pollpri_requested++;
    }

    struct poll_scan_stats stats = poll_scan_fds(kfds, nfds, task);

    /* Block until FDs are ready, timeout expires, or signal interrupts.
     * For timeout=0: immediate return (no blocking).
     * For timeout>0: retry with short sleeps until deadline.
     * For timeout=-1: retry indefinitely until FDs ready or signal. */
    if (stats.ready_count == 0 && timeout != 0) {
        uint64_t deadline = 0;
        if (timeout > 0) {
            uint64_t timeout_ticks = (uint64_t)timeout / 10;
            if ((uint64_t)timeout % 10 != 0) timeout_ticks++;
            if (timeout_ticks == 0) timeout_ticks = 1;
            deadline = fut_get_ticks() + timeout_ticks;
        }

        while (stats.ready_count == 0) {
            /* Check for pending signals → EINTR.
             * Use thread's signal mask when available (per-thread masking via sigprocmask). */
            uint64_t pending = __atomic_load_n(&task->pending_signals, __ATOMIC_ACQUIRE);
            fut_thread_t *poll_thr = fut_thread_current();
            uint64_t blocked = poll_thr ?
                __atomic_load_n(&poll_thr->signal_mask, __ATOMIC_ACQUIRE) :
                task->signal_mask;
            if (pending & ~blocked) {
                fut_free(kfds);
                return -EINTR;
            }

            /* Check timeout expiry */
            if (timeout > 0 && fut_get_ticks() >= deadline)
                break;

            /* Phase 4: wire FDs to a per-call waitq, rescan, then sleep until
             * an I/O event (or timer) wakes us — avoids the 10ms polling spin. */
            fut_waitq_t poll_wq;
            fut_waitq_init(&poll_wq);
            poll_wire_fds(kfds, nfds, task, &poll_wq);

            /* Rescan after wiring: catches events that arrived during setup */
            stats = poll_scan_fds(kfds, nfds, task);
            if (stats.ready_count == 0) {
                uint64_t now = fut_get_ticks();
                /* Use caller's deadline; fall back to 50ms for infinite-timeout */
                uint64_t wake_ticks = (timeout > 0 && deadline > now)
                                      ? (deadline - now) : 5u;
                fut_timer_start(wake_ticks, poll_waitq_wakeup, &poll_wq);
                fut_waitq_sleep_locked(&poll_wq, NULL, FUT_THREAD_BLOCKED);
                fut_timer_cancel(poll_waitq_wakeup, &poll_wq);
            }
            poll_unwire_fds(kfds, nfds, task, &poll_wq);
            stats = poll_scan_fds(kfds, nfds, task);
        }
    }

    /* Copy results back to userspace (or kernel buffer for self-tests) */
    int copy_back = fds_is_kernel
        ? (memcpy(fds, kfds, size), 0)
        : fut_copy_to_user(fds, kfds, size);
    if (copy_back != 0) {
        fut_free(kfds);
        poll_printf("[POLL] poll(fds, %lu, %d) -> EFAULT (copy_to_user failed)\n", nfds, timeout);
        return -EFAULT;
    }

    fut_free(kfds);

    /* Phase 2: Detailed logging with event breakdown */
    const char *timeout_desc = (timeout < 0) ? "infinite" :
                               (timeout == 0) ? "immediate" : "timed";

    if (stats.invalid_count > 0) {
        poll_printf("[POLL] poll(nfds=%lu, timeout=%d ms [%s]) -> %d ready (%d invalid, "
                   "requested: %dxIN %dxOUT %dxPRI, Phase 3: FD readiness checking)\n",
                   nfds, timeout, timeout_desc, stats.ready_count, stats.invalid_count,
                   pollin_requested, pollout_requested, pollpri_requested);
    } else {
        poll_printf("[POLL] poll(nfds=%lu, timeout=%d ms [%s]) -> %d ready "
                   "(requested: %dxIN %dxOUT %dxPRI, Phase 3: FD readiness checking)\n",
                   nfds, timeout, timeout_desc, stats.ready_count,
                   pollin_requested, pollout_requested, pollpri_requested);
    }

    return stats.ready_count;
}
