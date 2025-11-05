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
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    fut_printf("[SELECT] nfds=%d readfds=0x%p writefds=0x%p exceptfds=0x%p timeout=0x%p\n",
               nfds, readfds, writefds, exceptfds, timeout);

    /* Validate nfds */
    if (nfds < 0 || nfds > FD_SETSIZE) {
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
    (void)sigmask;  /* Ignore signal mask for now */

    fut_printf("[PSELECT6] pselect6(nfds=%d, readfds=%p, writefds=%p, exceptfds=%p, "
               "timeout=%p, sigmask=%p)\n",
               nfds, readfds, writefds, exceptfds, timeout, sigmask);

    /* Validate nfds */
    if (nfds < 0 || nfds > FD_SETSIZE) {
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
    (void)sigmask;  /* Ignore signal mask for now */

    fut_printf("[PPOLL] ppoll(fds=%p, nfds=%u, tmo_p=%p, sigmask=%p)\n",
               fds, nfds, tmo_p, sigmask);

    /* Validate parameters */
    if (!fds && nfds > 0) {
        return -EINVAL;
    }

    fut_printf("[PPOLL] Stub implementation - returning 0 (timeout)\n");
    return 0;  /* Simulate timeout */
}
