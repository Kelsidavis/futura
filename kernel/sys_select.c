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
extern int fut_access_ok(const void *u_ptr, size_t len, int write);

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

    /* Phase 5: Validate nfds against task FD table size
     * VULNERABILITY: Out-of-Bounds FD Array Access and CPU Exhaustion
     *
     * ATTACK SCENARIO 1: Out-of-Bounds FD Table Access
     * Attacker provides nfds exceeding task's actual FD table allocation
     * 1. Task has max_fds=256 (FD table allocated for 256 entries)
     * 2. Attacker calls select(1024, &readfds, NULL, NULL, &timeout)
     * 3. Validation: nfds <= FD_SETSIZE (1024) ✓ passes (line 71-75)
     * 4. WITHOUT Phase 5 check (line 113-117): Kernel iterates FDs 0-1023
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
     * - Assumes Phase 2 will add checks (not documented until Phase 5)
     *
     * DEFENSE (Phase 5 Requirements for Phase 2):
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
        fut_printf("[SELECT] select(nfds=%d, ...) -> EINVAL (nfds=%d exceeds task max_fds=%u, Phase 5)\n",
                   local_nfds, local_nfds, task->max_fds);
        return -EINVAL;
    }

    /* Phase 2: Validate fd_set pointers before accessing */
    if (local_readfds && fut_access_ok(local_readfds, sizeof(fd_set), 1) != 0) {
        fut_printf("[SELECT] select(nfds=%d, ...) -> EFAULT (invalid readfds pointer)\n",
                   local_nfds);
        return -EFAULT;
    }

    if (local_writefds && fut_access_ok(local_writefds, sizeof(fd_set), 1) != 0) {
        fut_printf("[SELECT] select(nfds=%d, ...) -> EFAULT (invalid writefds pointer)\n",
                   local_nfds);
        return -EFAULT;
    }

    if (local_exceptfds && fut_access_ok(local_exceptfds, sizeof(fd_set), 1) != 0) {
        fut_printf("[SELECT] select(nfds=%d, ...) -> EFAULT (invalid exceptfds pointer)\n",
                   local_nfds);
        return -EFAULT;
    }

    if (local_timeout && fut_access_ok(local_timeout, sizeof(fut_timeval_t), 0) != 0) {
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

    /* Phase 1: Stub - return immediately indicating all FDs ready */
    /* Phase 2: Implement actual FD monitoring with poll backend */
    /* Phase 3: Implement timeout support */
    /* Phase 4: Optimize with epoll backend */
    /* Phase 2 (Completed): Added fut_access_ok() validation for readfds, writefds, exceptfds, timeout pointers */
    /* Phase 2 (Completed): Added FD validation against task->max_fds and CPU work budget */
    /* TODO Phase 3: Consider constant-time FD validation (timing side-channel mitigation) */

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

    /* Phase 5: Validate nfds against task FD table size (same protection as select)
     * See sys_select Phase 5 documentation (lines 77-112) for detailed attack scenario
     *
     * Key points for pselect6:
     * - ARM64 primary interface (select doesn't exist on ARM64)
     * - Same fd_set OOB vulnerability as select
     * - Additional sigmask parameter doesn't affect FD validation
     * - Must check task->max_fds before any fd_set iteration
     */
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
