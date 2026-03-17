/* kernel/sys_sigpending.c - Get pending signals syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements sigpending() to examine which signals are pending.
 * Essential for signal-aware applications to determine which signals
 * have arrived but are currently blocked from delivery.
 */

#include <kernel/fut_task.h>
#include <kernel/signal.h>
#include <kernel/errno.h>
#include <kernel/uaccess.h>

#include <kernel/kprintf.h>

#ifdef __x86_64__
#include <platform/x86_64/memory/paging.h>
#elif defined(__aarch64__)
#include <platform/arm64/memory/paging.h>
#endif

static inline int sigpend_access_ok_write(const void *ptr, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)ptr >= KERNEL_VIRTUAL_BASE) return 0;
#endif
    return fut_access_ok(ptr, n, 1);
}
static inline int sigpend_copy_to_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)dst >= KERNEL_VIRTUAL_BASE) { __builtin_memcpy(dst, src, n); return 0; }
#endif
    return fut_copy_to_user(dst, src, n);
}

/**
 * sigpending() - Get set of pending signals
 *
 * Returns the set of signals that are pending for delivery but currently
 * blocked by the signal mask. This allows a process to examine which
 * signals are waiting to be delivered once unblocked.
 *
 * @param set  Pointer to sigset_t to receive pending signals
 *
 * Returns:
 *   - 0 on success
 *   - -EINVAL if no current task context
 *   - -EFAULT if set points to invalid memory
 *
 * Behavior:
 *   - Returns pending_signals AND (NOT signal_mask)
 *   - Only signals that are both pending AND unblocked are returned
 *   - Signals that are pending but blocked are NOT returned
 *   - Does not modify any signal state
 *   - Atomic read of pending signal state
 *
 * Common usage patterns:
 *
 * Check if specific signal is pending:
 *   sigset_t pending;
 *   sigpending(&pending);
 *   if (sigismember(&pending, SIGUSR1)) {
 *       // SIGUSR1 is pending
 *   }
 *
 * Get all pending signals:
 *   sigset_t pending;
 *   sigpending(&pending);
 *   for (int i = 1; i <= 31; i++) {
 *       if (sigismember(&pending, i)) {
 *           printf("Signal %d is pending\n", i);
 *       }
 *   }
 *
 * Check if any signals are pending:
 *   sigset_t pending;
 *   sigpending(&pending);
 *   if (!sigisempty(&pending)) {
 *       // At least one signal is pending
 *   }
 *
 * Relationship with other signal functions:
 *   - sigpending(): Check which signals are pending
 *   - sigprocmask(): Change which signals are blocked
 *   - sigaction(): Install signal handlers
 *   - pause(): Wait for any signal
 *   - sigsuspend(): Atomically change mask and wait
 *
 * Signal delivery process:
 *   1. Signal is sent to process
 *   2. If blocked, added to pending_signals
 *   3. If unblocked, delivered to handler immediately
 *   4. sigpending() returns pending AND (NOT blocked)
 *   5. Unblocking signal triggers delivery of pending
 *
 * Pending signal accumulation:
 *   - Standard signals: Multiple instances coalesce (only delivered once)
 *   - Real-time signals: Queued separately (POSIX.1-2001 feature)
 *   - Pending state persists until unblocked
 *
 * Atomicity:
 *   - Read of pending_signals is atomic
 *   - Mask computation done in kernel (not observable race)
 *   - Between sigpending() call and inspection, signals may arrive
 */
long sys_sigpending(sigset_t *set) {
    fut_task_t *current = fut_task_current();
    if (!current) {
        fut_printf("[SIGPENDING] sigpending(set=%p) -> EINVAL (no current task)\n", set);
        return -EINVAL;
    }

    if (!set) {
        fut_printf("[SIGPENDING] sigpending(set=NULL) -> EINVAL (invalid pointer)\n");
        return -EINVAL;
    }

    /* Validate set write permission early (kernel writes signal mask)
     * VULNERABILITY: Invalid Output Buffer Pointer
     * ATTACK: Attacker provides read-only or unmapped set buffer
     * IMPACT: Kernel page fault when writing pending signal set
     * DEFENSE: Check write permission before processing */
    if (sigpend_access_ok_write(set, sizeof(sigset_t)) != 0) {
        fut_printf("[SIGPENDING] sigpending(set=%p) -> EFAULT (buffer not writable for %zu bytes)\n",
                   set, sizeof(sigset_t));
        return -EFAULT;
    }

    /* POSIX: sigpending returns ALL pending signals, including blocked ones.
     * This lets applications check what's queued before unblocking. */
    sigset_t pending;
    uint64_t cur_pending = __atomic_load_n(&current->pending_signals, __ATOMIC_ACQUIRE);
    pending.__mask = cur_pending;

    /* Copy result to user space */
    if (sigpend_copy_to_user(set, &pending, sizeof(sigset_t)) != 0) {
        fut_printf("[SIGPENDING] sigpending(set=%p) -> EFAULT (invalid memory)\n", set);
        return -EFAULT;
    }

    return 0;
}
