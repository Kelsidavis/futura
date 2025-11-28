/* kernel/sys_select.c - Synchronous I/O multiplexing syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements select() to monitor multiple file descriptors for I/O.
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <shared/fut_timespec.h>
#include <shared/fut_timeval.h>

extern void fut_printf(const char *fmt, ...);
extern fut_task_t *fut_task_current(void);

/* fd_set helpers */
#define FD_SETSIZE 1024
#define NFDBITS    (8 * sizeof(unsigned long))

typedef struct {
    unsigned long fds_bits[FD_SETSIZE / NFDBITS];
} fd_set;

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

    fut_printf("[SELECT] nfds=%d readfds=0x%p writefds=0x%p exceptfds=0x%p timeout=0x%p\n",
               local_nfds, local_readfds, local_writefds, local_exceptfds, local_timeout);

    /* Phase 5: Validate nfds against both static limit and task's actual FD table limit */
    if (local_nfds < 0) {
        fut_printf("[SELECT] select(nfds=%d, ...) -> EINVAL (negative nfds, Phase 5)\n",
                   local_nfds);
        return -EINVAL;
    }

    /* Check against static FD_SETSIZE limit */
    if (local_nfds > FD_SETSIZE) {
        fut_printf("[SELECT] select(nfds=%d, ...) -> EINVAL (nfds exceeds FD_SETSIZE=%d, Phase 5)\n",
                   local_nfds, FD_SETSIZE);
        return -EINVAL;
    }

    /* Phase 5: Check against task's actual max_fds to prevent out-of-bounds access */
    if (task->max_fds > 0 && local_nfds > (int)task->max_fds) {
        fut_printf("[SELECT] select(nfds=%d, ...) -> EINVAL (nfds=%d exceeds task max_fds=%u, Phase 5)\n",
                   local_nfds, local_nfds, task->max_fds);
        return -EINVAL;
    }

    /* Phase 1: Stub - return immediately indicating all FDs ready */
    /* Phase 2: Implement actual FD monitoring with poll backend */
    /* Phase 3: Implement timeout support */
    /* Phase 4: Optimize with epoll backend */

    fut_printf("[SELECT] Stub implementation - returning 0 (timeout)\n");
    return 0;  /* Simulate timeout */
}

/**
 * sys_pselect6 - Synchronous I/O multiplexing with signal mask
 *
 * @param nfds      Highest FD number + 1
 * @param readfds   Set of FDs to monitor for read
 * @param writefds  Set of FDs to monitor for write
 * @param exceptfds Set of FDs to monitor for exceptions
 * @param timeout   Timeout (timespec format) or NULL to block indefinitely
 * @param sigmask   Signal mask to temporarily install (NULL = ignored)
 *
 * On ARM64, pselect6 is the primary interface (select doesn't exist).
 * For now, we ignore the sigmask parameter and provide a stub implementation.
 *
 * Phase 1: Stub implementation
 * Phase 2: Implement actual FD monitoring
 * Phase 3: Add signal mask handling
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

    (void)local_sigmask;  /* Ignore signal mask for now */

    fut_printf("[PSELECT6] pselect6(nfds=%d, readfds=%p, writefds=%p, exceptfds=%p, "
               "timeout=%p, sigmask=%p)\n",
               local_nfds, local_readfds, local_writefds, local_exceptfds, local_timeout, local_sigmask);

    /* Get current task for FD table bounds checking */
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    /* Phase 5: Validate nfds against both static limit and task's actual FD table limit */
    if (local_nfds < 0) {
        fut_printf("[PSELECT6] pselect6(nfds=%d, ...) -> EINVAL (negative nfds, Phase 5)\n",
                   local_nfds);
        return -EINVAL;
    }

    /* Check against static FD_SETSIZE limit */
    if (local_nfds > FD_SETSIZE) {
        fut_printf("[PSELECT6] pselect6(nfds=%d, ...) -> EINVAL (nfds exceeds FD_SETSIZE=%d, Phase 5)\n",
                   local_nfds, FD_SETSIZE);
        return -EINVAL;
    }

    /* Phase 5: Check against task's actual max_fds to prevent out-of-bounds access */
    if (task->max_fds > 0 && local_nfds > (int)task->max_fds) {
        fut_printf("[PSELECT6] pselect6(nfds=%d, ...) -> EINVAL (nfds=%d exceeds task max_fds=%u, Phase 5)\n",
                   local_nfds, local_nfds, task->max_fds);
        return -EINVAL;
    }

    fut_printf("[PSELECT6] Stub implementation - returning 0 (timeout)\n");
    return 0;  /* Simulate timeout */
}

/* pollfd structure (for ppoll) */
struct pollfd {
    int fd;         /* File descriptor */
    short events;   /* Requested events */
    short revents;  /* Returned events */
};

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
 * Phase 1: Stub implementation
 * Phase 2: Implement actual FD polling
 * Phase 3: Add signal mask handling
 */
long sys_ppoll(void *fds, unsigned int nfds, void *tmo_p, const void *sigmask) {
    /* ARM64 FIX: Copy parameters to local variables immediately to ensure they're preserved
     * on the stack across potentially blocking calls. Task operations may block and corrupt
     * register-passed parameters upon resumption. */
    void *local_fds = fds;
    unsigned int local_nfds = nfds;
    void *local_tmo_p = tmo_p;
    const void *local_sigmask = sigmask;

    (void)local_sigmask;  /* Ignore signal mask for now */

    fut_printf("[PPOLL] ppoll(fds=%p, nfds=%u, tmo_p=%p, sigmask=%p)\n",
               local_fds, local_nfds, local_tmo_p, local_sigmask);

    /* Validate parameters */
    if (!local_fds && local_nfds > 0) {
        fut_printf("[PPOLL] ppoll(fds=NULL, nfds=%u) -> EINVAL (NULL fds with non-zero nfds)\n",
                   local_nfds);
        return -EINVAL;
    }

    /* Phase 5: Validate nfds against reasonable limit to prevent DoS
     * Match sys_poll's limit of 1024 for consistency */
    if (local_nfds > 1024) {
        fut_printf("[PPOLL] ppoll(fds=%p, nfds=%u) -> EINVAL "
                   "(nfds exceeds limit of 1024, Phase 5)\n",
                   local_fds, local_nfds);
        return -EINVAL;
    }

    fut_printf("[PPOLL] Stub implementation - returning 0 (timeout)\n");
    return 0;  /* Simulate timeout */
}
