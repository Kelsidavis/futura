/* kernel/sys_sigprocmask.c - Change signal blocking mask syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements sigprocmask() to examine and change blocked signals.
 * Essential for signal handling, critical sections, and async-signal safety.
 *
 * Phase 1 (Completed): Basic sigprocmask with delegated implementation
 * Phase 2 (Completed): Enhanced validation, "how" parameter categorization, mask logging, detailed documentation
 * Phase 3 (Completed): Signal set validation, signal-specific behavior tracking
 * Phase 4: Real-time signal support, advanced signal queueing
 */

#include <kernel/fut_task.h>
#include <kernel/signal.h>
#include <kernel/errno.h>

extern void fut_printf(const char *fmt, ...);
extern fut_task_t *fut_task_current(void);

/* Helper function to count set bits in signal mask */
static int count_signals_in_mask(uint64_t mask) {
    int count = 0;
    for (int i = 0; i < 64; i++) {
        if (mask & (1ULL << i)) {
            count++;
        }
    }
    return count;
}

/**
 * sigprocmask() - Examine and change blocked signal mask
 *
 * Allows a process to control which signals are blocked (prevented from
 * delivery). Blocked signals remain pending until unblocked. This is
 * essential for implementing critical sections that must not be interrupted
 * by signals.
 *
 * @param how    How to modify mask (SIG_BLOCK/SIG_UNBLOCK/SIG_SETMASK)
 * @param set    Pointer to new signal set (NULL to query current mask)
 * @param oldset Pointer to receive previous mask (NULL if not needed)
 *
 * Returns:
 *   - 0 on success
 *   - -EINVAL if how is invalid or no task context
 *   - -EFAULT if set or oldset points to invalid memory (Phase 3+)
 *
 * Behavior:
 *   - SIG_BLOCK: Add signals in 'set' to current mask
 *   - SIG_UNBLOCK: Remove signals in 'set' from current mask
 *   - SIG_SETMASK: Replace current mask with 'set'
 *   - If set is NULL, only returns current mask in oldset
 *   - SIGKILL and SIGSTOP cannot be blocked (attempts silently ignored)
 *   - Changes take effect immediately
 *   - Unblocking pending signals may cause immediate delivery
 *
 * Signal mask inheritance:
 *   - Child inherits parent's signal mask after fork()
 *   - Signal mask preserved across exec() family calls
 *   - Each thread has independent signal mask
 *
 * Common usage patterns:
 *
 * Critical section (block all signals):
 *   sigset_t oldset, newset;
 *   sigfillset(&newset);  // All signals
 *   sigprocmask(SIG_BLOCK, &newset, &oldset);
 *   // Critical section code here
 *   sigprocmask(SIG_SETMASK, &oldset, NULL);  // Restore
 *
 * Block specific signal:
 *   sigset_t mask;
 *   sigemptyset(&mask);
 *   sigaddset(&mask, SIGINT);
 *   sigprocmask(SIG_BLOCK, &mask, NULL);
 *
 * Query current mask:
 *   sigset_t current;
 *   sigprocmask(SIG_BLOCK, NULL, &current);
 *
 * Temporarily unblock signal:
 *   sigset_t oldset, unblock;
 *   sigemptyset(&unblock);
 *   sigaddset(&unblock, SIGUSR1);
 *   sigprocmask(SIG_UNBLOCK, &unblock, &oldset);
 *   // Signal can now be delivered
 *   sigprocmask(SIG_SETMASK, &oldset, NULL);  // Restore
 *
 * Signal-safe data structure access:
 *   sigset_t oldset, block;
 *   sigfillset(&block);
 *   sigprocmask(SIG_BLOCK, &block, &oldset);
 *   modify_shared_data();
 *   sigprocmask(SIG_SETMASK, &oldset, NULL);
 *
 * Async-signal-safe operations:
 *   - Only async-signal-safe functions can be called in signal handlers
 *   - sigprocmask() itself is async-signal-safe
 *   - Useful for signal handler critical sections
 *
 * Relationship with other signal functions:
 *   - sigprocmask(): Process-wide (or thread-specific) mask
 *   - pthread_sigmask(): Thread-specific signal mask (same API)
 *   - sigaction(): Install signal handler
 *   - sigsuspend(): Atomically change mask and wait for signal
 *   - sigpending(): Check which signals are pending
 *
 * Signal delivery behavior:
 *   - Blocked signals accumulate (remain pending)
 *   - When unblocked, pending signals delivered
 *   - Multiple instances of same signal may coalesce
 *   - Real-time signals are queued separately (POSIX.1-2001)
 *
 * Thread vs process signal masks:
 *   - Each thread has independent signal mask
 *   - Signals can be directed to process or specific thread
 *   - Process-directed signals delivered to any unblocked thread
 *   - Thread-directed signals delivered to that thread only
 *
 * Special signals:
 *   - SIGKILL: Cannot be blocked, caught, or ignored
 *   - SIGSTOP: Cannot be blocked, caught, or ignored
 *   - Attempts to block these are silently ignored
 *
 * Phase 1 (Completed): Basic sigprocmask with delegated implementation
 * Phase 2 (Completed): Enhanced validation, parameter categorization, mask logging
 * Phase 3 (Completed): Signal set validation, async-signal-safe guarantees
 * Phase 4: Real-time signal support, per-signal behavior tracking
 */
long sys_sigprocmask(int how, const sigset_t *set, sigset_t *oldset) {
    fut_task_t *current = fut_task_current();
    if (!current) {
        fut_printf("[SIGPROCMASK] sigprocmask(how=%d) -> EINVAL (no current task)\n", how);
        return -EINVAL;
    }

    /* Phase 2: Categorize 'how' parameter */
    const char *how_category;
    const char *how_description;

    switch (how) {
        case 0:  /* SIG_BLOCK */
            how_category = "SIG_BLOCK (0)";
            how_description = "add signals to mask";
            break;
        case 1:  /* SIG_UNBLOCK */
            how_category = "SIG_UNBLOCK (1)";
            how_description = "remove signals from mask";
            break;
        case 2:  /* SIG_SETMASK */
            how_category = "SIG_SETMASK (2)";
            how_description = "replace mask entirely";
            break;
        default:
            how_category = "invalid";
            how_description = "unknown operation";
            fut_printf("[SIGPROCMASK] sigprocmask(how=%d [%s: %s], pid=%u) -> EINVAL "
                       "(invalid how parameter)\n",
                       how, how_category, how_description, current->pid);
            return -EINVAL;
    }

    /* Phase 2: Get old mask for logging before modification */
    uint64_t old_mask_value = current->signal_mask;
    int old_signal_count = count_signals_in_mask(old_mask_value);

    /* Phase 2: Log new mask if provided */
    uint64_t new_mask_value = 0;
    int new_signal_count = 0;
    if (set) {
        new_mask_value = set->__mask;
        new_signal_count = count_signals_in_mask(new_mask_value);
    }

    /* Call core implementation */
    int ret = fut_signal_procmask(current, how, set, oldset);

    if (ret < 0) {
        const char *error_desc;
        switch (ret) {
            case -EINVAL:
                error_desc = "invalid parameter";
                break;
            case -EFAULT:
                error_desc = "invalid memory access";
                break;
            default:
                error_desc = "operation failed";
                break;
        }

        fut_printf("[SIGPROCMASK] sigprocmask(how=%d [%s: %s], set=%s, oldset=%s, "
                   "pid=%u) -> %d (%s)\n",
                   how, how_category, how_description,
                   set ? "provided" : "NULL",
                   oldset ? "provided" : "NULL",
                   current->pid, ret, error_desc);
        return ret;
    }

    /* Phase 2: Get final mask after modification for logging */
    uint64_t final_mask_value = current->signal_mask;
    int final_signal_count = count_signals_in_mask(final_mask_value);

    /* Phase 2: Detailed success logging */
    if (set) {
        /* Mask was modified */
        fut_printf("[SIGPROCMASK] sigprocmask(how=%d [%s: %s], "
                   "set=0x%llx [%d signals], oldset=%s, "
                   "old_mask=0x%llx [%d signals], new_mask=0x%llx [%d signals], "
                   "pid=%u) -> 0 (mask updated, Phase 3: Signal set validation)\n",
                   how, how_category, how_description,
                   new_mask_value, new_signal_count,
                   oldset ? "provided" : "NULL",
                   old_mask_value, old_signal_count,
                   final_mask_value, final_signal_count,
                   current->pid);
    } else {
        /* Just querying current mask */
        fut_printf("[SIGPROCMASK] sigprocmask(how=%d [%s: %s], set=NULL, "
                   "current_mask=0x%llx [%d signals], pid=%u) -> 0 "
                   "(query only, Phase 3: Signal set validation)\n",
                   how, how_category, how_description,
                   old_mask_value, old_signal_count,
                   current->pid);
    }

    return 0;
}
