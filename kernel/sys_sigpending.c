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

    /* Phase 5: Validate set write permission early (kernel writes signal mask)
     * VULNERABILITY: Invalid Output Buffer Pointer
     * ATTACK: Attacker provides read-only or unmapped set buffer
     * IMPACT: Kernel page fault when writing pending signal set
     * DEFENSE: Check write permission before processing */
    if (fut_access_ok(set, sizeof(sigset_t), 1) != 0) {
        fut_printf("[SIGPENDING] sigpending(set=%p) -> EFAULT (buffer not writable for %zu bytes, Phase 5)\n",
                   set, sizeof(sigset_t));
        return -EFAULT;
    }

    /* Get pending signals that are unblocked (deliverable) */
    sigset_t pending;
    pending.__mask = current->pending_signals & ~current->signal_mask;

    /* Copy result to user space */
    if (fut_copy_to_user(set, &pending, sizeof(sigset_t)) != 0) {
        fut_printf("[SIGPENDING] sigpending(set=%p) -> EFAULT (invalid memory)\n", set);
        return -EFAULT;
    }

    fut_printf("[SIGPENDING] sigpending(set=%p) -> 0 (pending=0x%llx, mask=0x%llx, "
               "deliverable=0x%llx, pid=%u)\n",
               set, current->pending_signals, current->signal_mask,
               pending.__mask, current->pid);

    return 0;
}
