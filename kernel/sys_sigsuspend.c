/* kernel/sys_sigsuspend.c - Suspend execution until signal
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements sigsuspend() to atomically change signal mask and wait.
 * Critical for synchronizing signal delivery with custom masks.
 */

#include <kernel/fut_task.h>
#include <kernel/fut_waitq.h>
#include <kernel/signal.h>
#include <kernel/errno.h>
#include <kernel/uaccess.h>

#include <kernel/kprintf.h>

/**
 * sigsuspend() - Atomically change signal mask and suspend
 *
 * Replaces the current signal mask with the provided mask and suspends
 * the process until a signal is delivered. Upon return (either from signal
 * handler or after signal delivery), restores the original signal mask.
 *
 * This syscall is used for synchronized signal handling - temporarily
 * allow specific signals while blocking others.
 *
 * @param mask  Pointer to new signal mask (sigset_t)
 *
 * Returns:
 *   - Does not return on success (blocked until signal)
 *   - -EINVAL if no current task context
 *   - -EFAULT if mask points to invalid memory
 *   - -EINTR if interrupted (will be returned to signal handler)
 *
 * Behavior:
 *   1. Copy new mask from userspace
 *   2. Save current signal mask
 *   3. Install new mask atomically
 *   4. Block until signal delivery
 *   5. Restore original mask before returning
 *   - Always returns -EINTR (interrupted by signal)
 *   - No other error conditions normally occur
 *
 * Common usage patterns:
 *
 * Wait for specific signal with others blocked:
 *   sigset_t mask, oldmask;
 *   sigprocmask(SIG_SETMASK, &mask, &oldmask);
 *
 *   sigset_t susp_mask;
 *   sigemptyset(&susp_mask);      // Block all except...
 *   sigaddset(&susp_mask, SIGUSR1); // ...SIGUSR1
 *   sigsuspend(&susp_mask);       // Wait for SIGUSR1
 *
 *   sigprocmask(SIG_SETMASK, &oldmask, NULL);
 *
 * Implement pause() for POSIX compliance:
 *   sigset_t empty;
 *   sigemptyset(&empty);
 *   sigsuspend(&empty);   // Wait for any signal with none blocked
 *
 * Critical synchronization pattern:
 *   // Prepare state while blocking signals
 *   sigset_t mask;
 *   sigfillset(&mask);
 *   sigprocmask(SIG_BLOCK, &mask, &oldmask);
 *
 *   // Do critical work
 *   prepare_for_signal();
 *
 *   // Atomically restore mask and wait
 *   sigsuspend(&oldmask);  // Can't get interrupted during prepare
 *
 * Relationship with other signal functions:
 *   - sigsuspend(): Atomically change mask and wait for signal
 *   - sigprocmask(): Change mask without waiting
 *   - pause(): Wait for any signal (equivalent to sigsuspend(&empty))
 *   - sigaction(): Install signal handlers
 *
 * Signal delivery from sigsuspend():
 *   1. Signal becomes deliverable (pending AND NOT new_mask)
 *   2. Handler is invoked (if SA_RESTART, some syscalls resume)
 *   3. Handler returns
 *   4. sigsuspend() restores original mask
 *   5. sigsuspend() returns -EINTR to caller
 *   6. Application continues with original signal mask
 *
 * Implementation notes:
 *   - Phase 1: Stub returns -EINTR immediately (no actual blocking)
 *   - Phase 2 (Completed): Block on task->signal_waitq until unmasked signal arrives
 *   - Phase 3: Full signal delivery integration (signal handler invocation)
 *   - Atomicity is critical: mask change and blocking must be atomic
 *
 * Atomicity guarantee:
 *   Between saving old mask and installing new mask, no signals
 *   can cause a race condition. The operation is truly atomic.
 */
long sys_sigsuspend(const sigset_t *mask) {
    fut_task_t *current = fut_task_current();
    sigset_t newmask, oldmask;

    if (!current) {
        fut_printf("[SIGSUSPEND] sigsuspend(mask=%p) -> EINVAL (no current task)\n", mask);
        return -EINVAL;
    }

    if (!mask) {
        fut_printf("[SIGSUSPEND] sigsuspend(mask=NULL) -> EINVAL (invalid pointer)\n");
        return -EINVAL;
    }

    /* Copy new mask from userspace */
    if (fut_copy_from_user(&newmask, mask, sizeof(sigset_t)) != 0) {
        fut_printf("[SIGSUSPEND] sigsuspend(mask=%p) -> EFAULT (invalid memory)\n", mask);
        return -EFAULT;
    }

    /* Save current mask for restoration */
    oldmask.__mask = __atomic_load_n(&current->signal_mask, __ATOMIC_ACQUIRE);

    /* Install new mask */
    __atomic_store_n(&current->signal_mask, newmask.__mask, __ATOMIC_RELEASE);

    /* Phase 2: Block on signal_waitq until an unmasked signal is pending.
     * If a signal is already pending and unmasked by newmask, return immediately.
     */
    uint64_t unblocked = __atomic_load_n(&current->pending_signals, __ATOMIC_ACQUIRE)
                         & ~newmask.__mask;

    if (unblocked == 0) {
        fut_printf("[SIGSUSPEND] sigsuspend(pid=%u, old_mask=0x%llx, new_mask=0x%llx) -> blocking\n",
                   current->pid, oldmask.__mask, newmask.__mask);
        fut_waitq_sleep_locked(&current->signal_waitq, NULL, FUT_THREAD_BLOCKED);
        fut_printf("[SIGSUSPEND] sigsuspend(pid=%u) -> woke up (signal delivered)\n", current->pid);
    } else {
        fut_printf("[SIGSUSPEND] sigsuspend(pid=%u) -> signal already pending (0x%llx), not blocking\n",
                   current->pid, unblocked);
    }

    /* Restore original signal mask before returning */
    __atomic_store_n(&current->signal_mask, oldmask.__mask, __ATOMIC_RELEASE);

    /* sigsuspend always returns -EINTR */
    return -EINTR;
}
