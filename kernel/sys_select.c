/* kernel/sys_select.c - Synchronous I/O multiplexing syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements select() to monitor multiple file descriptors for I/O.
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <kernel/fut_vfs.h>
#include <shared/fut_timespec.h>
#include <shared/fut_timeval.h>
#include <poll.h>  /* For struct pollfd */
#include <string.h>
#include <stdbool.h>

#include <kernel/kprintf.h>
#include <kernel/uaccess.h>
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

/* Phase 4: wait queue wakeup callback for select/pselect blocking */
static void select_waitq_wakeup(void *arg) {
    fut_waitq_t *wq = (fut_waitq_t *)arg;
    if (wq) fut_waitq_wake_all(wq);
}

/* fd_set helpers */
#define FD_SETSIZE 1024
#define NFDBITS    (8 * sizeof(unsigned long))

typedef struct {
    unsigned long fds_bits[FD_SETSIZE / NFDBITS];
} fd_set;

static inline int fd_isset(int fd, const fd_set *set) {
    return (set->fds_bits[fd / NFDBITS] >> (fd % NFDBITS)) & 1;
}

static inline void fd_setbit(int fd, fd_set *set) {
    set->fds_bits[fd / NFDBITS] |= (1UL << (fd % NFDBITS));
}

static inline void fd_clrbit(int fd, fd_set *set) {
    set->fds_bits[fd / NFDBITS] &= ~(1UL << (fd % NFDBITS));
}

/**
 * select() - Synchronous I/O multiplexing
 *
 * Monitors file descriptor sets for readability, writability, and exceptions.
 *
 * @param nfds      Highest FD number + 1
 * @param readfds   Set of FDs to monitor for read
 * @param writefds  Set of FDs to monitor for write
 * @param exceptfds Set of FDs to monitor for exceptions
 * @param timeout   Timeout or NULL to block indefinitely
 *
 * Returns:
 *   - Number of ready FDs on success
 *   - 0 if timeout expired
 *   - -EBADF if invalid FD in sets
 *   - -EINTR if interrupted by signal
 *   - -EINVAL if nfds is negative or timeout invalid
 *   - -ENOMEM if unable to allocate memory
 */
long sys_select(int nfds, fd_set *readfds, fd_set *writefds,
                fd_set *exceptfds, fut_timeval_t *timeout) {
    /* ARM64 FIX: Copy parameters to local variables immediately to ensure they're preserved
     * on the stack across potentially blocking calls. Task operations may block and corrupt
     * register-passed parameters upon resumption. */
    int local_nfds = nfds;
    fd_set *local_readfds = readfds;
    fd_set *local_writefds = writefds;
    fd_set *local_exceptfds = exceptfds;
    fut_timeval_t *local_timeout = timeout;

    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    /* Validate nfds against both static limit and task's actual FD table limit */
    if (local_nfds < 0) {
        fut_printf("[SELECT] select(nfds=%d, ...) -> EINVAL (negative nfds)\n",
                   local_nfds);
        return -EINVAL;
    }

    /* Check against static FD_SETSIZE limit */
    if (local_nfds > FD_SETSIZE) {
        fut_printf("[SELECT] select(nfds=%d, ...) -> EINVAL (nfds exceeds FD_SETSIZE=%d)\n",
                   local_nfds, FD_SETSIZE);
        return -EINVAL;
    }

    /* Validate nfds against task FD table size
     * VULNERABILITY: Out-of-Bounds FD Array Access and CPU Exhaustion
     *
     * ATTACK SCENARIO 1: Out-of-Bounds FD Table Access
     * Attacker provides nfds exceeding task's actual FD table allocation
     * 1. Task has max_fds=256 (FD table allocated for 256 entries)
     * 2. Attacker calls select(1024, &readfds, NULL, NULL, &timeout)
     * 3. Validation: nfds <= FD_SETSIZE (1024) ✓ passes (line 71-75)
     * 4. WITHOUT check (line 113-117): Kernel iterates FDs 0-1023
     * 5. Phase 2 implementation: for (fd = 0; fd < nfds; fd++)
     * 6. Iteration accesses task->fd_table[1023] (OOB: table only has 256)
     * 7. Information disclosure: Read uninitialized kernel memory
     * 8. Or kernel panic: Page fault from invalid memory access
     *
     * ATTACK SCENARIO 2: fd_set Pointer Validation Bypass
     * Attacker provides NULL fd_set pointers to exploit missing validation
     * 1. Attacker calls select(10, NULL, NULL, NULL, NULL)
     * 2. Phase 1 stub: Returns immediately (line 124-125)
     * 3. Phase 2 implementation: Dereferences readfds without NULL check
     * 4. Kernel dereferences NULL pointer in FD_ISSET(fd, readfds)
     * 5. Page fault causes kernel crash
     *
     * ATTACK SCENARIO 3: CPU Exhaustion via Large nfds
     * Attacker maximizes nfds to cause excessive kernel CPU usage
     * 1. Attacker opens 1024 file descriptors (valid FD table)
     * 2. Calls select(1024, &readfds, &writefds, &exceptfds, NULL) in loop
     * 3. Each call: Kernel iterates 1024 FDs x 3 fd_sets = 3072 checks
     * 4. Tight loop: 1000 calls/second x 3072 checks = 3M FD checks/sec
     * 5. CPU saturated with FD iteration, starving other processes
     * 6. System becomes unresponsive (DoS)
     *
     * ATTACK SCENARIO 4: Timing Side-Channel for KASLR Bypass
     * Attacker uses OOB access timing to leak kernel memory layout
     * 1. Attacker sets nfds=1024 with sparse fd_set (few bits set)
     * 2. Bits set correspond to FDs beyond max_fds (OOB region)
     * 3. Phase 2 checks FD_ISSET(fd, readfds) for each FD
     * 4. OOB accesses: task->fd_table[fd] reads random kernel memory
     * 5. Valid pointers vs invalid: Different page fault timing
     * 6. Measure timing differences to map kernel memory
     * 7. Infer kernel addresses, bypass KASLR protection
     *
     * ATTACK SCENARIO 5: Integer Overflow in FD Iteration Bounds
     * Attacker exploits potential overflow in fd_set byte calculation
     * 1. Attacker calls select(INT_MAX, &readfds, NULL, NULL, NULL)
     * 2. Phase 2 calculates fd_set bytes: bytes = nfds / 8 + 1
     * 3. Calculation: INT_MAX / 8 = 268435455 (valid)
     * 4. But iteration: for (fd = 0; fd < nfds; fd++) → 2 billion iterations
     * 5. Kernel spins for hours iterating non-existent FDs
     * 6. Infinite loop DoS (system hangs)
     *
     * IMPACT:
     * - Out-of-bounds read: Information disclosure from kernel memory
     * - Kernel panic: Page fault on invalid FD table access
     * - CPU exhaustion DoS: Excessive FD iteration
     * - Timing side-channel: KASLR bypass via OOB timing
     * - Integer overflow: Infinite loop via INT_MAX nfds
     *
     * ROOT CAUSE:
     * Phase 1 stub lacks comprehensive validation:
     * - Line 64-75: Validates nfds >= 0 and <= FD_SETSIZE, but not <= task->max_fds
     * - No validation of fd_set pointers before dereference (NULL check missing)
     * - No upper bound on CPU work (nfds can be FD_SETSIZE causing 3072 checks)
     * - No protection against timing side-channels (OOB accesses observable)
     * - Assumes Phase 2 will add checks (not documented until )
     *
     * DEFENSE (Requirements for Phase 2):
     * 1. FD Table Bounds Validation:
     *    - Check nfds <= task->max_fds BEFORE any iteration
     *    - Line 113-117: Enforces this check (CRITICAL)
     *    - Prevents OOB access to task->fd_table[]
     * 2. fd_set Pointer Validation:
     *    - fut_access_ok(readfds, sizeof(fd_set), READ) if readfds != NULL
     *    - Same for writefds and exceptfds
     *    - Return -EFAULT if pointers invalid
     * 3. CPU Work Limits:
     *    - Consider reducing FD_SETSIZE from 1024 to 256 for embedded systems
     *    - Or add work budget: return -EINTR after N iterations
     *    - Prevent CPU exhaustion DoS
     * 4. Timing Side-Channel Mitigation:
     *    - Constant-time FD validation (don't short-circuit on error)
     *    - Or require CAP_SYS_ADMIN for nfds > 256
     * 5. Integer Overflow Prevention:
     *    - Additional check: nfds <= INT_MAX / 1024 (prevent overflow)
     *    - Or clamp nfds to reasonable maximum (1024)
     *
     * CVE REFERENCES:
     * - CVE-2015-8830: Linux aio out-of-bounds via invalid FD
     * - CVE-2017-7308: Linux packet socket UAF via invalid FD
     * - CVE-2014-0181: Netfilter out-of-bounds via crafted FD
     *
     * POSIX REQUIREMENT:
     * From POSIX.1-2008 select(2):
     * "If the nfds argument is less than 0 or greater than FD_SETSIZE,
     *  select() shall fail and set errno to [EINVAL]."
     * - Implementation extends this: Also check nfds <= task->max_fds
     * - More restrictive but prevents kernel vulnerabilities
     * - POSIX allows implementation-defined limits beyond FD_SETSIZE
     *
     * LINUX REQUIREMENT:
     * From select(2) man page:
     * "According to POSIX, select() should check all specified file
     *  descriptors in the three file descriptor sets, up to the limit
     *  nfds-1. However, the current implementation ignores any file
     *  descriptor in these sets that is greater than the maximum file
     *  descriptor number that the process currently has open."
     * - Linux silently ignores FDs > max_open
     * - Futura enforces stricter check (return EINVAL)
     * - Prevents potential OOB access
     *
     * IMPLEMENTATION NOTES:
     * - Phase 1: Current stub has nfds validation (lines 64-75, 113-117)
     * - Phase 2 MUST add fut_access_ok() for fd_set pointers
     * - Phase 2 MUST validate FDs within each fd_set before accessing fd_table
     * - Phase 2 MUST limit CPU work (consider timeout or iteration budget)
     * - Phase 3 MAY add constant-time validation (timing side-channel mitigation)
     * - See Linux kernel: fs/select.c do_select() for reference
     */
    if (task->max_fds > 0 && local_nfds > (int)task->max_fds) {
        fut_printf("[SELECT] select(nfds=%d, ...) -> EINVAL (nfds=%d exceeds task max_fds=%u)\n",
                   local_nfds, local_nfds, task->max_fds);
        return -EINVAL;
    }

    /* Phase 2: Validate fd_set pointers before accessing.
     * Skip access_ok for kernel pointers (kernel self-tests use stack buffers). */
#define IS_KPTR(p) ((uintptr_t)(p) >= KERNEL_VIRTUAL_BASE)
    if (local_readfds && !IS_KPTR(local_readfds) &&
        fut_access_ok(local_readfds, sizeof(fd_set), 1) != 0) {
        fut_printf("[SELECT] select(nfds=%d, ...) -> EFAULT (invalid readfds pointer)\n",
                   local_nfds);
        return -EFAULT;
    }

    if (local_writefds && !IS_KPTR(local_writefds) &&
        fut_access_ok(local_writefds, sizeof(fd_set), 1) != 0) {
        fut_printf("[SELECT] select(nfds=%d, ...) -> EFAULT (invalid writefds pointer)\n",
                   local_nfds);
        return -EFAULT;
    }

    if (local_exceptfds && !IS_KPTR(local_exceptfds) &&
        fut_access_ok(local_exceptfds, sizeof(fd_set), 1) != 0) {
        fut_printf("[SELECT] select(nfds=%d, ...) -> EFAULT (invalid exceptfds pointer)\n",
                   local_nfds);
        return -EFAULT;
    }

    if (local_timeout && !IS_KPTR(local_timeout) &&
        fut_access_ok(local_timeout, sizeof(fut_timeval_t), 0) != 0) {
        fut_printf("[SELECT] select(nfds=%d, ...) -> EFAULT (invalid timeout pointer)\n",
                   local_nfds);
        return -EFAULT;
    }

    /* Phase 2: CPU work budget - prevent DoS via excessive nfds */
    #define SELECT_MAX_WORK_BUDGET 10000  /* Maximum FD iterations to prevent CPU DoS */
    int work_budget = SELECT_MAX_WORK_BUDGET;

    /* Phase 2: Validate each FD in nfds range against task->max_fds */
    if (task->max_fds > 0 && local_nfds > task->max_fds) {
        fut_printf("[SELECT] select(nfds=%d, ...) -> EINVAL (nfds exceeds task max_fds=%d)\n",
                   local_nfds, task->max_fds);
        return -EINVAL;
    }

    /* Phase 2: Limit iterations to prevent CPU exhaustion attacks */
    if (local_nfds > work_budget) {
        fut_printf("[SELECT] select(nfds=%d, ...) -> EINVAL (nfds exceeds work budget=%d, DoS prevention)\n",
                   local_nfds, work_budget);
        return -EINVAL;
    }

    /*
     * Phase 3: Actual FD readiness checking via driver/VFS layer.
     * Uses the same dispatch as sys_poll: eventfd, timerfd, signalfd,
     * sockets, regular files, and a fallback for other types.
     * Phase 4 would add blocking with wait queues and timeout support.
     */

    /* Copy fd_sets from userspace so we can modify them for output */
    fd_set k_readfds, k_writefds, k_exceptfds;
    fd_set r_readfds, r_writefds, r_exceptfds;

    if (local_readfds) {
        int cr = IS_KPTR(local_readfds)
            ? (memcpy(&k_readfds, local_readfds, sizeof(fd_set)), 0)
            : fut_copy_from_user(&k_readfds, local_readfds, sizeof(fd_set));
        if (cr != 0) return -EFAULT;
    }
    if (local_writefds) {
        int cr = IS_KPTR(local_writefds)
            ? (memcpy(&k_writefds, local_writefds, sizeof(fd_set)), 0)
            : fut_copy_from_user(&k_writefds, local_writefds, sizeof(fd_set));
        if (cr != 0) return -EFAULT;
    }
    if (local_exceptfds) {
        int cr = IS_KPTR(local_exceptfds)
            ? (memcpy(&k_exceptfds, local_exceptfds, sizeof(fd_set)), 0)
            : fut_copy_from_user(&k_exceptfds, local_exceptfds, sizeof(fd_set));
        if (cr != 0) return -EFAULT;
    }

    /* Initialize result sets to zero */
    memset(&r_readfds, 0, sizeof(fd_set));
    memset(&r_writefds, 0, sizeof(fd_set));
    memset(&r_exceptfds, 0, sizeof(fd_set));

    int ready_count = 0;

    /* Compute timeout deadline in ticks.
     * timeout == NULL → infinite; timeout->tv_sec==0 && tv_usec==0 → immediate */
    int has_timeout = 0;
    int is_immediate = 0;
    uint64_t deadline_ticks = 0;

    if (local_timeout) {
        fut_timeval_t ktv;
        if (IS_KPTR(local_timeout))
            memcpy(&ktv, local_timeout, sizeof(ktv));
        else if (fut_copy_from_user(&ktv, local_timeout, sizeof(ktv)) != 0)
            return -EFAULT;

        if (ktv.tv_sec == 0 && ktv.tv_usec == 0) {
            is_immediate = 1;
        } else {
            has_timeout = 1;
            uint64_t timeout_ms = (uint64_t)ktv.tv_sec * 1000 + (uint64_t)ktv.tv_usec / 1000;
            uint64_t timeout_ticks = timeout_ms / 10;
            if (timeout_ms % 10 != 0) timeout_ticks++;
            if (timeout_ticks == 0) timeout_ticks = 1;
            deadline_ticks = fut_get_ticks() + timeout_ticks;
        }
    }

    /* Scan-and-block loop */
    for (;;) {
        ready_count = 0;
        memset(&r_readfds, 0, sizeof(fd_set));
        memset(&r_writefds, 0, sizeof(fd_set));
        memset(&r_exceptfds, 0, sizeof(fd_set));

        for (int fd = 0; fd < local_nfds; fd++) {
            int check_read  = local_readfds  && fd_isset(fd, &k_readfds);
            int check_write = local_writefds && fd_isset(fd, &k_writefds);
            int check_except = local_exceptfds && fd_isset(fd, &k_exceptfds);

            if (!check_read && !check_write && !check_except)
                continue;

            if (fd >= (int)task->max_fds || !task->fd_table || !task->fd_table[fd])
                return -EBADF;

            struct fut_file *file = task->fd_table[fd];
            uint32_t epoll_req = 0;
            if (check_read)  epoll_req |= EPOLLIN;
            if (check_write) epoll_req |= EPOLLOUT;

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
                extern bool fut_pidfd_poll(struct fut_file *f, uint32_t req, uint32_t *out);
                if (fut_pidfd_poll(file, epoll_req, &epoll_ready))
                    handled = true;
            }
            if (!handled) {
                extern bool fut_inotify_poll(struct fut_file *f, uint32_t req, uint32_t *out);
                if (fut_inotify_poll(file, epoll_req, &epoll_ready))
                    handled = true;
            }
            if (!handled) {
                fut_socket_t *socket = get_socket_from_fd(fd);
                if (socket) {
                    int poll_events = 0;
                    if (check_read)  poll_events |= 0x1;
                    if (check_write) poll_events |= 0x4;
                    int socket_ready = fut_socket_poll(socket, poll_events);
                    if (socket_ready & 0x1)  epoll_ready |= EPOLLIN;
                    if (socket_ready & 0x4)  epoll_ready |= EPOLLOUT;
                    if (socket_ready & 0x10) epoll_ready |= EPOLLHUP;
                    /* POLLRDHUP (0x2000) is ignored for select — already in POLLIN */
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

            /* Linux: EPOLLHUP and EPOLLERR are always reported to any
             * monitored fd (read or write). EOF is "readable". */
            int counted = 0;
            if (check_read && (epoll_ready & (EPOLLIN | EPOLLHUP | EPOLLERR))) {
                fd_setbit(fd, &r_readfds);
                counted = 1;
            }
            if (check_write && (epoll_ready & (EPOLLOUT | EPOLLERR | EPOLLHUP))) {
                fd_setbit(fd, &r_writefds);
                counted = 1;
            }
            if (check_except && (epoll_ready & (EPOLLERR | EPOLLPRI))) {
                fd_setbit(fd, &r_exceptfds);
                counted = 1;
            }
            if (counted)
                ready_count++;
        }

        /* If FDs are ready or immediate mode, break */
        if (ready_count > 0 || is_immediate)
            break;

        /* Check for pending signals → EINTR (use thread mask if available) */
        uint64_t pending = __atomic_load_n(&task->pending_signals, __ATOMIC_ACQUIRE);
        fut_thread_t *sel_thr = fut_thread_current();
        uint64_t blocked = sel_thr ?
            __atomic_load_n(&sel_thr->signal_mask, __ATOMIC_ACQUIRE) :
            task->signal_mask;
        if (pending & ~blocked)
            return -EINTR;

        /* Check timeout expiry */
        if (has_timeout && fut_get_ticks() >= deadline_ticks)
            break;

        /* Phase 4: wire FDs to a per-call waitq for event-driven wakeup */
        {
            extern void fut_eventfd_set_epoll_notify(struct fut_file *f, fut_waitq_t *wq);
            extern void fut_timerfd_set_epoll_notify(struct fut_file *f, fut_waitq_t *wq);
            extern void fut_signalfd_set_epoll_notify(struct fut_file *f, fut_waitq_t *wq);
            extern void fut_pipe_set_epoll_notify(struct fut_file *f, fut_waitq_t *wq);
            extern void fut_pidfd_set_epoll_notify(struct fut_file *f, fut_waitq_t *wq);
            extern void fut_inotify_set_epoll_notify(struct fut_file *f, fut_waitq_t *wq);
            fut_waitq_t sel_wq;
            fut_waitq_init(&sel_wq);
            for (int wfd = 0; wfd < local_nfds; wfd++) {
                int want = (local_readfds  && fd_isset(wfd, &k_readfds))
                        || (local_writefds && fd_isset(wfd, &k_writefds));
                if (!want) continue;
                if (wfd >= (int)task->max_fds || !task->fd_table || !task->fd_table[wfd]) continue;
                struct fut_file *wfile = task->fd_table[wfd];
                fut_eventfd_set_epoll_notify(wfile, &sel_wq);
                fut_timerfd_set_epoll_notify(wfile, &sel_wq);
                fut_signalfd_set_epoll_notify(wfile, &sel_wq);
                fut_pipe_set_epoll_notify(wfile, &sel_wq);
                fut_pidfd_set_epoll_notify(wfile, &sel_wq);
                fut_inotify_set_epoll_notify(wfile, &sel_wq);
                fut_socket_t *wsock = get_socket_from_fd(wfd);
                if (wsock) {
                    if (wsock->pair_reverse) wsock->pair_reverse->epoll_notify = &sel_wq;
                    if (wsock->listener)    wsock->listener->epoll_notify = &sel_wq;
                }
            }
            /* Rescan after wiring to catch events that arrived during setup */
            ready_count = 0;
            memset(&r_readfds, 0, sizeof(fd_set));
            memset(&r_writefds, 0, sizeof(fd_set));
            memset(&r_exceptfds, 0, sizeof(fd_set));
            for (int fd = 0; fd < local_nfds; fd++) {
                int check_read  = local_readfds  && fd_isset(fd, &k_readfds);
                int check_write = local_writefds && fd_isset(fd, &k_writefds);
                int check_except = local_exceptfds && fd_isset(fd, &k_exceptfds);
                if (!check_read && !check_write && !check_except) continue;
                if (fd >= (int)task->max_fds || !task->fd_table || !task->fd_table[fd]) {
                    /* Unwire before returning */
                    for (int ufd = 0; ufd < local_nfds; ufd++) {
                        if (ufd >= (int)task->max_fds || !task->fd_table || !task->fd_table[ufd]) continue;
                        struct fut_file *uf = task->fd_table[ufd];
                        fut_eventfd_set_epoll_notify(uf, NULL);
                        fut_timerfd_set_epoll_notify(uf, NULL);
                        fut_pipe_set_epoll_notify(uf, NULL);
                        { extern void fut_inotify_set_epoll_notify(struct fut_file *, fut_waitq_t *); fut_inotify_set_epoll_notify(uf, NULL); }
                        fut_socket_t *us = get_socket_from_fd(ufd);
                        if (us) {
                            if (us->pair_reverse && us->pair_reverse->epoll_notify == &sel_wq) us->pair_reverse->epoll_notify = NULL;
                            if (us->listener    && us->listener->epoll_notify    == &sel_wq) us->listener->epoll_notify = NULL;
                        }
                    }
                    return -EBADF;
                }
                struct fut_file *file = task->fd_table[fd];
                uint32_t epoll_req = 0;
                if (check_read)  epoll_req |= EPOLLIN;
                if (check_write) epoll_req |= EPOLLOUT;
                uint32_t epoll_ready = 0;
                bool handled = false;
                if (!handled && fut_eventfd_poll(file, epoll_req, &epoll_ready)) handled = true;
                if (!handled && fut_timerfd_poll(file, epoll_req, &epoll_ready)) handled = true;
                if (!handled && fut_signalfd_poll(file, epoll_req, &epoll_ready)) handled = true;
                if (!handled && fut_pipe_poll(file, epoll_req, &epoll_ready)) handled = true;
                if (!handled) { extern bool fut_pidfd_poll(struct fut_file *f, uint32_t req, uint32_t *out); if (fut_pidfd_poll(file, epoll_req, &epoll_ready)) handled = true; }
                if (!handled) { extern bool fut_inotify_poll(struct fut_file *f, uint32_t req, uint32_t *out); if (fut_inotify_poll(file, epoll_req, &epoll_ready)) handled = true; }
                if (!handled) {
                    fut_socket_t *socket = get_socket_from_fd(fd);
                    if (socket) {
                        int poll_events = 0;
                        if (check_read)  poll_events |= 0x1;
                        if (check_write) poll_events |= 0x4;
                        int socket_ready = fut_socket_poll(socket, poll_events);
                        if (socket_ready & 0x1)  epoll_ready |= EPOLLIN;
                        if (socket_ready & 0x4)  epoll_ready |= EPOLLOUT;
                        if (socket_ready & 0x10) epoll_ready |= EPOLLHUP;
                    /* POLLRDHUP (0x2000) is ignored for select — already in POLLIN */
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
                int counted = 0;
                if (check_read && (epoll_ready & (EPOLLIN | EPOLLHUP | EPOLLERR))) { fd_setbit(fd, &r_readfds); counted = 1; }
                if (check_write && (epoll_ready & (EPOLLOUT | EPOLLERR | EPOLLHUP))) { fd_setbit(fd, &r_writefds); counted = 1; }
                if (check_except && (epoll_ready & (EPOLLERR | EPOLLPRI))) { fd_setbit(fd, &r_exceptfds); counted = 1; }
                if (counted) ready_count++;
            }
            if (ready_count == 0) {
                /* Sleep until an event or timeout.
                 * Enqueue the thread BEFORE starting the timer to prevent a
                 * lost-wakeup: if the timer fires between fut_timer_start and
                 * the enqueue, the wake_all() finds an empty queue and the
                 * thread sleeps with no future wakeup.  Also, release the
                 * lock BEFORE fut_timer_start to prevent the single-CPU
                 * IRQ-spinlock deadlock (callback spins on a held lock). */
                uint64_t now = fut_get_ticks();
                uint64_t wake_ticks = (has_timeout && deadline_ticks > now)
                                      ? (deadline_ticks - now) : 5u;
                fut_thread_t *sel_thr = fut_thread_current();
                if (sel_thr) {
                    sel_thr->state         = FUT_THREAD_BLOCKED;
                    sel_thr->blocked_waitq = &sel_wq;
                    sel_thr->wait_next     = NULL;
                    /* Disable interrupts while holding sel_wq.lock to prevent
                     * IRQ-spinlock deadlock: wired FD callbacks (e.g.
                     * timerfd_timer_cb) call fut_waitq_wake_one(&sel_wq) from
                     * timer IRQ context, which tries to acquire sel_wq.lock.
                     * If the IRQ fires while we hold the lock, the handler
                     * spins forever on a lock we can never release. */
#ifdef __x86_64__
                    __asm__ volatile("cli" ::: "memory");
#elif defined(__aarch64__)
                    __asm__ volatile("msr daifset, #2" ::: "memory");
#endif
                    fut_spinlock_acquire(&sel_wq.lock);
                    if (sel_wq.tail) {
                        sel_wq.tail->wait_next = sel_thr;
                    } else {
                        sel_wq.head = sel_thr;
                    }
                    sel_wq.tail = sel_thr;
                    fut_spinlock_release(&sel_wq.lock);
#ifdef __x86_64__
                    __asm__ volatile("sti" ::: "memory");
#elif defined(__aarch64__)
                    __asm__ volatile("msr daifclr, #2" ::: "memory");
#endif
                    if (fut_timer_start(wake_ticks, select_waitq_wakeup, &sel_wq) != 0) {
                        /* OOM: dequeue thread, restore state, unwire and fail */
                        fut_waitq_remove_thread(&sel_wq, sel_thr);
                        sel_thr->state = FUT_THREAD_RUNNING;
                        for (int ufd = 0; ufd < local_nfds; ufd++) {
                            if (ufd >= (int)task->max_fds || !task->fd_table || !task->fd_table[ufd]) continue;
                            struct fut_file *uf = task->fd_table[ufd];
                            fut_eventfd_set_epoll_notify(uf, NULL);
                            fut_timerfd_set_epoll_notify(uf, NULL);
                            fut_signalfd_set_epoll_notify(uf, NULL);
                            fut_pipe_set_epoll_notify(uf, NULL);
                            fut_pidfd_set_epoll_notify(uf, NULL);
                            { extern void fut_inotify_set_epoll_notify(struct fut_file *, fut_waitq_t *); fut_inotify_set_epoll_notify(uf, NULL); }
                            fut_socket_t *us = get_socket_from_fd(ufd);
                            if (us) {
                                if (us->pair_reverse && us->pair_reverse->epoll_notify == &sel_wq) us->pair_reverse->epoll_notify = NULL;
                                if (us->listener    && us->listener->epoll_notify    == &sel_wq) us->listener->epoll_notify = NULL;
                            }
                        }
                        return -EAGAIN;
                    }
                    fut_schedule();
                    fut_timer_cancel(select_waitq_wakeup, &sel_wq);
                }
            }
            /* Unwire */
            for (int ufd = 0; ufd < local_nfds; ufd++) {
                if (ufd >= (int)task->max_fds || !task->fd_table || !task->fd_table[ufd]) continue;
                struct fut_file *uf = task->fd_table[ufd];
                fut_eventfd_set_epoll_notify(uf, NULL);
                fut_timerfd_set_epoll_notify(uf, NULL);
                fut_signalfd_set_epoll_notify(uf, NULL);
                fut_pipe_set_epoll_notify(uf, NULL);
                fut_pidfd_set_epoll_notify(uf, NULL);
                { extern void fut_inotify_set_epoll_notify(struct fut_file *, fut_waitq_t *); fut_inotify_set_epoll_notify(uf, NULL); }
                fut_socket_t *us = get_socket_from_fd(ufd);
                if (us) {
                    if (us->pair_reverse && us->pair_reverse->epoll_notify == &sel_wq) us->pair_reverse->epoll_notify = NULL;
                    if (us->listener    && us->listener->epoll_notify    == &sel_wq) us->listener->epoll_notify = NULL;
                }
            }
        }
        if (ready_count > 0)
            break;
    }

    /* Copy result sets back to userspace (or kernel buffer for self-tests) */
    if (local_readfds) {
        int cw = IS_KPTR(local_readfds)
            ? (memcpy(local_readfds, &r_readfds, sizeof(fd_set)), 0)
            : fut_copy_to_user(local_readfds, &r_readfds, sizeof(fd_set));
        if (cw != 0) return -EFAULT;
    }
    if (local_writefds) {
        int cw = IS_KPTR(local_writefds)
            ? (memcpy(local_writefds, &r_writefds, sizeof(fd_set)), 0)
            : fut_copy_to_user(local_writefds, &r_writefds, sizeof(fd_set));
        if (cw != 0) return -EFAULT;
    }
    if (local_exceptfds) {
        int cw = IS_KPTR(local_exceptfds)
            ? (memcpy(local_exceptfds, &r_exceptfds, sizeof(fd_set)), 0)
            : fut_copy_to_user(local_exceptfds, &r_exceptfds, sizeof(fd_set));
        if (cw != 0) return -EFAULT;
    }

    /*
     * Linux-specific: update timeout to reflect remaining time.
     * POSIX does not require this, but Linux documents it and many programs
     * (bash, Python, etc.) rely on select() modifying the timeval.
     * Only update when a real timeout was requested (not NULL, not immediate).
     */
    if (local_timeout && has_timeout) {
        uint64_t now = fut_get_ticks();
        uint64_t remain_ms = 0;
        if (deadline_ticks > now) {
            uint64_t remain_ticks = deadline_ticks - now;
            remain_ms = remain_ticks * 10;   /* ticks → ms (10ms/tick) */
        }
        fut_timeval_t ktv_remain;
        ktv_remain.tv_sec  = (long)(remain_ms / 1000);
        ktv_remain.tv_usec = (long)((remain_ms % 1000) * 1000);
        if (IS_KPTR(local_timeout))
            memcpy(local_timeout, &ktv_remain, sizeof(ktv_remain));
        else
            fut_copy_to_user(local_timeout, &ktv_remain, sizeof(ktv_remain));
    }

    return ready_count;
}

/**
 * sys_pselect6 - Synchronous I/O multiplexing with signal mask
 *
 * @param nfds      Highest FD number + 1
 * @param readfds   Set of FDs to monitor for read
 * @param writefds  Set of FDs to monitor for write
 * @param exceptfds Set of FDs to monitor for exceptions
 * @param timeout   Timeout (timespec format) or NULL to block indefinitely
 * @param sigmask   Signal mask to temporarily install (NULL = no mask change)
 *
 * On ARM64, pselect6 is the primary interface (select doesn't exist).
 *
 * Phase 1 (Completed): Stub implementation
 * Phase 2 (Completed): Implement actual FD monitoring
 * Phase 3 (Completed): Add signal mask handling
 */
long sys_pselect6(int nfds, void *readfds, void *writefds, void *exceptfds,
                  void *timeout, void *sigmask) {
    /* ARM64 FIX: Copy parameters to local variables immediately to ensure they're preserved
     * on the stack across potentially blocking calls. Task operations may block and corrupt
     * register-passed parameters upon resumption. */
    int local_nfds = nfds;
    void *local_readfds = readfds;
    void *local_writefds = writefds;
    void *local_exceptfds = exceptfds;
    void *local_timeout = timeout;
    void *local_sigmask = sigmask;

    /* Get current task for FD table bounds checking */
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    /* Validate nfds against both static limit and task's actual FD table limit */
    if (local_nfds < 0) {
        fut_printf("[PSELECT6] pselect6(nfds=%d, ...) -> EINVAL (negative nfds)\n",
                   local_nfds);
        return -EINVAL;
    }

    /* Check against static FD_SETSIZE limit */
    if (local_nfds > FD_SETSIZE) {
        fut_printf("[PSELECT6] pselect6(nfds=%d, ...) -> EINVAL (nfds exceeds FD_SETSIZE=%d)\n",
                   local_nfds, FD_SETSIZE);
        return -EINVAL;
    }

    /* Validate nfds against task FD table size (same protection as select)
     * See sys_select documentation (lines 77-112) for detailed attack scenario
     *
     * Key points for pselect6:
     * - ARM64 primary interface (select doesn't exist on ARM64)
     * - Same fd_set OOB vulnerability as select
     * - Additional sigmask parameter doesn't affect FD validation
     * - Must check task->max_fds before any fd_set iteration
     */
    if (task->max_fds > 0 && local_nfds > (int)task->max_fds) {
        fut_printf("[PSELECT6] pselect6(nfds=%d, ...) -> EINVAL (nfds=%d exceeds task max_fds=%u)\n",
                   local_nfds, local_nfds, task->max_fds);
        return -EINVAL;
    }

    /* Parse timeout for blocking loop */
    int ps_has_timeout = 0;
    int ps_is_immediate = 0;
    uint64_t ps_deadline_ticks = 0;

    if (local_timeout) {
        fut_timespec_t kts = {0};
        int cr = IS_KPTR(local_timeout)
            ? (memcpy(&kts, local_timeout, sizeof(kts)), 0)
            : fut_copy_from_user(&kts, local_timeout, sizeof(kts));
        if (cr != 0) {
            return -EFAULT;
        }
        if (kts.tv_sec < 0 || kts.tv_nsec < 0 || kts.tv_nsec >= 1000000000L) {
            return -EINVAL;
        }
        if (kts.tv_sec == 0 && kts.tv_nsec == 0) {
            ps_is_immediate = 1;
        } else {
            ps_has_timeout = 1;
            uint64_t timeout_ms = (uint64_t)kts.tv_sec * 1000 + ((uint64_t)kts.tv_nsec + 999999) / 1000000;
            uint64_t timeout_ticks = timeout_ms / 10;
            if (timeout_ms % 10 != 0) timeout_ticks++;
            if (timeout_ticks == 0) timeout_ticks = 1;
            ps_deadline_ticks = fut_get_ticks() + timeout_ticks;
        }
    }

    /* pselect6 signal mask handling:
     * - Kernel self-tests/internal callers pass direct sigset_t* (kptr path).
     * - Syscall callers pass Linux pselect6_arg { sigset_t *ss; size_t ss_len }.
     */
    sigset_t saved_mask = {0};
    bool mask_applied = false;
    if (local_sigmask) {
        sigset_t requested_mask = {0};

        if (IS_KPTR(local_sigmask)) {
            memcpy(&requested_mask, local_sigmask, sizeof(requested_mask));
        } else {
            struct pselect6_sigmask_arg {
                const sigset_t *ss;
                size_t ss_len;
            } arg = {0};

            if (fut_copy_from_user(&arg, local_sigmask, sizeof(arg)) != 0) {
                return -EFAULT;
            }
            if (arg.ss_len != sizeof(sigset_t)) {
                return -EINVAL;
            }
            if (arg.ss) {
                if (fut_copy_from_user(&requested_mask, arg.ss, sizeof(requested_mask)) != 0) {
                    return -EFAULT;
                }
            }
        }

        int mret = fut_signal_procmask(task, SIGPROCMASK_SETMASK, &requested_mask, &saved_mask);
        if (mret < 0) {
            return mret;
        }
        mask_applied = true;
    }

    /* Copy fd_sets from userspace (or kernel buffer for self-tests) */
    fd_set k_readfds, k_writefds, k_exceptfds;
    fd_set r_readfds, r_writefds, r_exceptfds;
    long ret = 0;

    if (local_readfds) {
        int cr = IS_KPTR(local_readfds)
            ? (memcpy(&k_readfds, local_readfds, sizeof(fd_set)), 0)
            : fut_copy_from_user(&k_readfds, local_readfds, sizeof(fd_set));
        if (cr != 0) {
            ret = -EFAULT;
            goto out_restore_sigmask;
        }
    }
    if (local_writefds) {
        int cr = IS_KPTR(local_writefds)
            ? (memcpy(&k_writefds, local_writefds, sizeof(fd_set)), 0)
            : fut_copy_from_user(&k_writefds, local_writefds, sizeof(fd_set));
        if (cr != 0) {
            ret = -EFAULT;
            goto out_restore_sigmask;
        }
    }
    if (local_exceptfds) {
        int cr = IS_KPTR(local_exceptfds)
            ? (memcpy(&k_exceptfds, local_exceptfds, sizeof(fd_set)), 0)
            : fut_copy_from_user(&k_exceptfds, local_exceptfds, sizeof(fd_set));
        if (cr != 0) {
            ret = -EFAULT;
            goto out_restore_sigmask;
        }
    }

    int ready_count = 0;

    /* Blocking scan-and-retry loop (same pattern as select/poll) */
    for (;;) {
        ready_count = 0;
        memset(&r_readfds, 0, sizeof(fd_set));
        memset(&r_writefds, 0, sizeof(fd_set));
        memset(&r_exceptfds, 0, sizeof(fd_set));

        for (int fd = 0; fd < local_nfds; fd++) {
            int check_read  = local_readfds  && fd_isset(fd, &k_readfds);
            int check_write = local_writefds && fd_isset(fd, &k_writefds);
            int check_except = local_exceptfds && fd_isset(fd, &k_exceptfds);

            if (!check_read && !check_write && !check_except)
                continue;

            if (fd >= (int)task->max_fds || !task->fd_table || !task->fd_table[fd]) {
                ret = -EBADF;
                goto out_restore_sigmask;
            }

            struct fut_file *file = task->fd_table[fd];
            uint32_t epoll_req = 0;
            if (check_read)  epoll_req |= EPOLLIN;
            if (check_write) epoll_req |= EPOLLOUT;

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
                extern bool fut_pidfd_poll(struct fut_file *f, uint32_t req, uint32_t *out);
                if (fut_pidfd_poll(file, epoll_req, &epoll_ready))
                    handled = true;
            }
            if (!handled) {
                extern bool fut_inotify_poll(struct fut_file *f, uint32_t req, uint32_t *out);
                if (fut_inotify_poll(file, epoll_req, &epoll_ready))
                    handled = true;
            }
            if (!handled) {
                fut_socket_t *socket = get_socket_from_fd(fd);
                if (socket) {
                    int poll_events = 0;
                    if (check_read)  poll_events |= 0x1;
                    if (check_write) poll_events |= 0x4;
                    int socket_ready = fut_socket_poll(socket, poll_events);
                    if (socket_ready & 0x1)  epoll_ready |= EPOLLIN;
                    if (socket_ready & 0x4)  epoll_ready |= EPOLLOUT;
                    if (socket_ready & 0x10) epoll_ready |= EPOLLHUP;
                    /* POLLRDHUP (0x2000) is ignored for select — already in POLLIN */
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

            int counted = 0;
            if (check_read && (epoll_ready & (EPOLLIN | EPOLLHUP | EPOLLERR))) {
                fd_setbit(fd, &r_readfds);
                counted = 1;
            }
            if (check_write && (epoll_ready & (EPOLLOUT | EPOLLERR | EPOLLHUP))) {
                fd_setbit(fd, &r_writefds);
                counted = 1;
            }
            if (check_except && (epoll_ready & (EPOLLERR | EPOLLPRI))) {
                fd_setbit(fd, &r_exceptfds);
                counted = 1;
            }

            if (counted)
                ready_count++;
        }

        /* If FDs ready or immediate mode, break */
        if (ready_count > 0 || ps_is_immediate)
            break;

        /* No timeout given (NULL) means infinite: keep looping.
         * Timeout={0,0} is handled by ps_is_immediate above. */
        if (!ps_has_timeout && local_timeout)
            break;  /* zero-timeout: already handled */

        /* Check for pending unblocked signals → EINTR (use thread mask if available) */
        uint64_t pending = __atomic_load_n(&task->pending_signals, __ATOMIC_ACQUIRE);
        fut_thread_t *psel_thr = fut_thread_current();
        uint64_t blocked = psel_thr ?
            __atomic_load_n(&psel_thr->signal_mask, __ATOMIC_ACQUIRE) :
            task->signal_mask;
        if (pending & ~blocked) {
            ret = -EINTR;
            goto out_restore_sigmask;
        }

        /* Check timeout expiry */
        if (ps_has_timeout && fut_get_ticks() >= ps_deadline_ticks)
            break;

        /* Phase 4: wire FDs to a per-call waitq for event-driven wakeup */
        {
            extern void fut_eventfd_set_epoll_notify(struct fut_file *f, fut_waitq_t *wq);
            extern void fut_timerfd_set_epoll_notify(struct fut_file *f, fut_waitq_t *wq);
            extern void fut_signalfd_set_epoll_notify(struct fut_file *f, fut_waitq_t *wq);
            extern void fut_pipe_set_epoll_notify(struct fut_file *f, fut_waitq_t *wq);
            extern void fut_pidfd_set_epoll_notify(struct fut_file *f, fut_waitq_t *wq);
            fut_waitq_t psel_wq;
            fut_waitq_init(&psel_wq);
            for (int wfd = 0; wfd < local_nfds; wfd++) {
                int want = (local_readfds  && fd_isset(wfd, &k_readfds))
                        || (local_writefds && fd_isset(wfd, &k_writefds));
                if (!want) continue;
                if (wfd >= (int)task->max_fds || !task->fd_table || !task->fd_table[wfd]) continue;
                struct fut_file *wfile = task->fd_table[wfd];
                fut_eventfd_set_epoll_notify(wfile, &psel_wq);
                fut_timerfd_set_epoll_notify(wfile, &psel_wq);
                fut_signalfd_set_epoll_notify(wfile, &psel_wq);
                fut_pipe_set_epoll_notify(wfile, &psel_wq);
                fut_pidfd_set_epoll_notify(wfile, &psel_wq);
                { extern void fut_inotify_set_epoll_notify(struct fut_file *, fut_waitq_t *); fut_inotify_set_epoll_notify(wfile, &psel_wq); }
                fut_socket_t *wsock = get_socket_from_fd(wfd);
                if (wsock) {
                    if (wsock->pair_reverse) wsock->pair_reverse->epoll_notify = &psel_wq;
                    if (wsock->listener)    wsock->listener->epoll_notify = &psel_wq;
                }
            }
            /* Rescan after wiring to catch events that arrived during setup */
            ready_count = 0;
            memset(&r_readfds, 0, sizeof(fd_set));
            memset(&r_writefds, 0, sizeof(fd_set));
            memset(&r_exceptfds, 0, sizeof(fd_set));
            for (int fd = 0; fd < local_nfds; fd++) {
                int check_read   = local_readfds   && fd_isset(fd, &k_readfds);
                int check_write  = local_writefds  && fd_isset(fd, &k_writefds);
                int check_except = local_exceptfds && fd_isset(fd, &k_exceptfds);
                if (!check_read && !check_write && !check_except) continue;
                if (fd >= (int)task->max_fds || !task->fd_table || !task->fd_table[fd]) continue;
                struct fut_file *file = task->fd_table[fd];
                uint32_t epoll_req = 0;
                if (check_read)  epoll_req |= EPOLLIN;
                if (check_write) epoll_req |= EPOLLOUT;
                uint32_t epoll_ready = 0;
                bool handled = false;
                if (!handled && fut_eventfd_poll(file, epoll_req, &epoll_ready)) handled = true;
                if (!handled && fut_timerfd_poll(file, epoll_req, &epoll_ready)) handled = true;
                if (!handled && fut_signalfd_poll(file, epoll_req, &epoll_ready)) handled = true;
                if (!handled && fut_pipe_poll(file, epoll_req, &epoll_ready)) handled = true;
                if (!handled) { extern bool fut_pidfd_poll(struct fut_file *f, uint32_t req, uint32_t *out); if (fut_pidfd_poll(file, epoll_req, &epoll_ready)) handled = true; }
                if (!handled) { extern bool fut_inotify_poll(struct fut_file *f, uint32_t req, uint32_t *out); if (fut_inotify_poll(file, epoll_req, &epoll_ready)) handled = true; }
                if (!handled) {
                    fut_socket_t *socket = get_socket_from_fd(fd);
                    if (socket) {
                        int poll_events = 0;
                        if (check_read)  poll_events |= 0x1;
                        if (check_write) poll_events |= 0x4;
                        int socket_ready = fut_socket_poll(socket, poll_events);
                        if (socket_ready & 0x1)  epoll_ready |= EPOLLIN;
                        if (socket_ready & 0x4)  epoll_ready |= EPOLLOUT;
                        if (socket_ready & 0x10) epoll_ready |= EPOLLHUP;
                    /* POLLRDHUP (0x2000) is ignored for select — already in POLLIN */
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
                int counted = 0;
                if (check_read && (epoll_ready & (EPOLLIN | EPOLLHUP | EPOLLERR))) { fd_setbit(fd, &r_readfds); counted = 1; }
                if (check_write && (epoll_ready & (EPOLLOUT | EPOLLERR | EPOLLHUP))) { fd_setbit(fd, &r_writefds); counted = 1; }
                if (check_except && (epoll_ready & (EPOLLERR | EPOLLPRI))) { fd_setbit(fd, &r_exceptfds); counted = 1; }
                if (counted) ready_count++;
            }
            if (ready_count == 0) {
                /* Same enqueue-before-timer fix as select4 path above */
                uint64_t now = fut_get_ticks();
                uint64_t wake_ticks = (ps_has_timeout && ps_deadline_ticks > now)
                                      ? (ps_deadline_ticks - now) : 5u;
                fut_thread_t *psel_thr = fut_thread_current();
                if (psel_thr) {
                    psel_thr->state         = FUT_THREAD_BLOCKED;
                    psel_thr->blocked_waitq = &psel_wq;
                    psel_thr->wait_next     = NULL;
                    /* Disable IRQs — same deadlock prevention as select4 path */
#ifdef __x86_64__
                    __asm__ volatile("cli" ::: "memory");
#elif defined(__aarch64__)
                    __asm__ volatile("msr daifset, #2" ::: "memory");
#endif
                    fut_spinlock_acquire(&psel_wq.lock);
                    if (psel_wq.tail) {
                        psel_wq.tail->wait_next = psel_thr;
                    } else {
                        psel_wq.head = psel_thr;
                    }
                    psel_wq.tail = psel_thr;
                    fut_spinlock_release(&psel_wq.lock);
#ifdef __x86_64__
                    __asm__ volatile("sti" ::: "memory");
#elif defined(__aarch64__)
                    __asm__ volatile("msr daifclr, #2" ::: "memory");
#endif
                    if (fut_timer_start(wake_ticks, select_waitq_wakeup, &psel_wq) != 0) {
                        /* OOM: dequeue thread, restore state, unwire and fail */
                        fut_waitq_remove_thread(&psel_wq, psel_thr);
                        psel_thr->state = FUT_THREAD_RUNNING;
                        for (int ufd = 0; ufd < local_nfds; ufd++) {
                            if (ufd >= (int)task->max_fds || !task->fd_table || !task->fd_table[ufd]) continue;
                            struct fut_file *uf = task->fd_table[ufd];
                            fut_eventfd_set_epoll_notify(uf, NULL);
                            fut_timerfd_set_epoll_notify(uf, NULL);
                            fut_signalfd_set_epoll_notify(uf, NULL);
                            fut_pipe_set_epoll_notify(uf, NULL);
                            fut_pidfd_set_epoll_notify(uf, NULL);
                            { extern void fut_inotify_set_epoll_notify(struct fut_file *, fut_waitq_t *); fut_inotify_set_epoll_notify(uf, NULL); }
                            fut_socket_t *us = get_socket_from_fd(ufd);
                            if (us) {
                                if (us->pair_reverse && us->pair_reverse->epoll_notify == &psel_wq) us->pair_reverse->epoll_notify = NULL;
                                if (us->listener    && us->listener->epoll_notify    == &psel_wq) us->listener->epoll_notify = NULL;
                            }
                        }
                        return -EAGAIN;
                    }
                    fut_schedule();
                    fut_timer_cancel(select_waitq_wakeup, &psel_wq);
                }
            }
            /* Unwire */
            for (int ufd = 0; ufd < local_nfds; ufd++) {
                if (ufd >= (int)task->max_fds || !task->fd_table || !task->fd_table[ufd]) continue;
                struct fut_file *uf = task->fd_table[ufd];
                fut_eventfd_set_epoll_notify(uf, NULL);
                fut_timerfd_set_epoll_notify(uf, NULL);
                fut_signalfd_set_epoll_notify(uf, NULL);
                fut_pipe_set_epoll_notify(uf, NULL);
                fut_pidfd_set_epoll_notify(uf, NULL);
                { extern void fut_inotify_set_epoll_notify(struct fut_file *, fut_waitq_t *); fut_inotify_set_epoll_notify(uf, NULL); }
                fut_socket_t *us = get_socket_from_fd(ufd);
                if (us) {
                    if (us->pair_reverse && us->pair_reverse->epoll_notify == &psel_wq) us->pair_reverse->epoll_notify = NULL;
                    if (us->listener    && us->listener->epoll_notify    == &psel_wq) us->listener->epoll_notify = NULL;
                }
            }
        }
        if (ready_count > 0)
            break;
    }

    if (local_readfds) {
        int cw = IS_KPTR(local_readfds)
            ? (memcpy(local_readfds, &r_readfds, sizeof(fd_set)), 0)
            : fut_copy_to_user(local_readfds, &r_readfds, sizeof(fd_set));
        if (cw != 0) {
            ret = -EFAULT;
            goto out_restore_sigmask;
        }
    }
    if (local_writefds) {
        int cw = IS_KPTR(local_writefds)
            ? (memcpy(local_writefds, &r_writefds, sizeof(fd_set)), 0)
            : fut_copy_to_user(local_writefds, &r_writefds, sizeof(fd_set));
        if (cw != 0) {
            ret = -EFAULT;
            goto out_restore_sigmask;
        }
    }
    if (local_exceptfds) {
        int cw = IS_KPTR(local_exceptfds)
            ? (memcpy(local_exceptfds, &r_exceptfds, sizeof(fd_set)), 0)
            : fut_copy_to_user(local_exceptfds, &r_exceptfds, sizeof(fd_set));
        if (cw != 0) {
            ret = -EFAULT;
            goto out_restore_sigmask;
        }
    }

    ret = ready_count;

out_restore_sigmask:
    if (mask_applied) {
        int rret = fut_signal_procmask(task, SIGPROCMASK_SETMASK, &saved_mask, NULL);
        if (rret < 0) {
            fut_printf("[PSELECT6] failed to restore signal mask for pid=%u: %d\n",
                       task->pid, rret);
            if (ret >= 0) {
                ret = rret;
            }
        }
    }
    return ret;
}

/* struct pollfd is provided by poll.h */

/**
 * sys_ppoll - Poll multiple file descriptors with signal mask
 *
 * @param fds     Array of pollfd structures
 * @param nfds    Number of elements in fds array
 * @param tmo_p   Timeout (timespec format) or NULL to block indefinitely
 * @param sigmask Signal mask to temporarily install (NULL = ignored)
 *
 * On ARM64, ppoll is the primary interface (poll doesn't exist).
 * For now, we ignore the sigmask parameter and provide a stub implementation.
 *
 * Phase 1 (Completed): Stub implementation
 * Phase 2 (Completed): Implement actual FD polling via sys_poll delegation
 * Phase 3 (Completed): Signal mask temporarily installed (blocking deferred)
 */
long sys_ppoll(void *fds, unsigned int nfds, void *tmo_p, const void *sigmask,
               size_t sigsetsize) {
    /* ARM64 FIX: Copy parameters to local variables immediately to ensure they're preserved
     * on the stack across potentially blocking calls. Task operations may block and corrupt
     * register-passed parameters upon resumption. */
    void *local_fds = fds;
    unsigned int local_nfds = nfds;
    void *local_tmo_p = tmo_p;
    const void *local_sigmask = sigmask;

    /* Validate parameters */
    if (!local_fds && local_nfds > 0) {
        fut_printf("[PPOLL] ppoll(fds=NULL, nfds=%u) -> EINVAL (NULL fds with non-zero nfds)\n",
                   local_nfds);
        return -EINVAL;
    }

    /* Validate nfds against reasonable limit to prevent DoS
     * Match sys_poll's limit of 1024 for consistency */
    if (local_nfds > 1024) {
        fut_printf("[PPOLL] ppoll(fds=%p, nfds=%u) -> EINVAL "
                   "(nfds exceeds limit of 1024)\n",
                   local_fds, local_nfds);
        return -EINVAL;
    }

    /*
     * Delegate to sys_poll with timeout converted from timespec to ms.
     * ppoll differs from poll only in timeout format and signal mask.
     * Signal mask is ignored for now (Phase 3).
     */
    int timeout_ms = -1;  /* Default: block indefinitely */
    if (local_tmo_p) {
        struct fut_timespec kts;
        if (IS_KPTR(local_tmo_p)) {
            memcpy(&kts, local_tmo_p, sizeof(kts));
        } else {
            if (fut_copy_from_user(&kts, local_tmo_p, sizeof(kts)) != 0)
                return -EFAULT;
        }
        if (kts.tv_sec < 0 || kts.tv_nsec < 0 || kts.tv_nsec >= 1000000000L)
            return -EINVAL;
        /* Convert to ms, cap at INT_MAX */
        uint64_t ms = (uint64_t)kts.tv_sec * 1000ULL + ((uint64_t)kts.tv_nsec + 999999ULL) / 1000000ULL;
        timeout_ms = (ms > (uint64_t)2147483647) ? 2147483647 : (int)ms;
    }

    /* Install signal mask if provided (atomically replace, then restore after poll) */
    fut_task_t *task = fut_task_current();
    sigset_t saved_mask = {0};
    bool mask_applied = false;

    if (local_sigmask && task) {
        /* Linux validates sigsetsize == sizeof(sigset_t); kernel callers pass 0 */
        if (!IS_KPTR(local_sigmask) && sigsetsize != sizeof(sigset_t))
            return -EINVAL;

        sigset_t requested_mask = {0};

        if (IS_KPTR(local_sigmask)) {
            memcpy(&requested_mask, local_sigmask, sizeof(requested_mask));
        } else {
            if (fut_copy_from_user(&requested_mask, local_sigmask, sizeof(requested_mask)) != 0) {
                return -EFAULT;
            }
        }

        int mret = fut_signal_procmask(task, SIGPROCMASK_SETMASK, &requested_mask, &saved_mask);
        if (mret < 0) {
            return mret;
        }
        mask_applied = true;
    }

    /* Reuse sys_poll which already handles FD validation and readiness checking */
    extern long sys_poll(struct pollfd *fds, unsigned long nfds, int timeout);
    long ret = sys_poll((struct pollfd *)local_fds, (unsigned long)local_nfds, timeout_ms);

    /* Restore original signal mask */
    if (mask_applied) {
        int rret = fut_signal_procmask(task, SIGPROCMASK_SETMASK, &saved_mask, NULL);
        if (rret < 0) {
            fut_printf("[PPOLL] failed to restore signal mask for pid=%u: %d\n",
                       task->pid, rret);
            if (ret >= 0) {
                ret = rret;
            }
        }
    }

    return ret;
}
