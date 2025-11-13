/* kernel/sys_pause.c - Wait for signal syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements the pause() syscall for suspending until signal delivery.
 */

#include <kernel/fut_task.h>
#include <kernel/signal.h>
#include <kernel/errno.h>

extern void fut_printf(const char *fmt, ...);
extern fut_task_t *fut_task_current(void);

/**
 * pause() - Wait for signal
 *
 * Suspends the calling process until a signal is caught and its handler
 * returns, or until the process is terminated. This is commonly used with
 * alarm() to implement timeouts or periodic task execution.
 *
 * Returns:
 *   - -EINTR (always) - pause() only returns when interrupted by a signal
 *
 * Behavior:
 *   - Blocks indefinitely until any signal is delivered
 *   - Signal handler executes (if installed)
 *   - Returns -EINTR after signal handler completes
 *   - If signal terminates process, pause() never returns
 *
 * Common usage pattern:
 *   signal(SIGALRM, handler);  // Install signal handler
 *   alarm(5);                   // Set alarm for 5 seconds
 *   pause();                    // Wait for SIGALRM (returns after handler)
 *
 * Phase 1 (Completed): Returns -EINTR immediately (stub)
 * Phase 2 (Current): Check for pending signals and enhanced logging
 * Phase 3: Block on wait queue until signal delivery
 * Phase 4: Integrate with signal delivery path to wake blocked tasks
 */
long sys_pause(void) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_printf("[PAUSE] pause() -> ESRCH (no current task)\n");
        return -ESRCH;
    }

    /* Phase 3: Block on wait queue until signal arrives
     *
     * If a signal is already pending (queued earlier), return immediately
     * with -EINTR. Otherwise, sleep on the signal_waitq until signal_send()
     * wakes us up during signal delivery.
     *
     * When a signal is delivered:
     * 1. Signal delivery code calls fut_waitq_wake_one(&task->signal_waitq)
     * 2. pause() wakes up and returns -EINTR
     * 3. Exception handler catches -EINTR return and invokes signal handler
     * 4. Signal handler executes, then control returns to user code
     *
     * The task is responsible for checking if a signal is already pending
     * before blocking. This prevents a race where signal arrives between
     * the check and the sleep.
     */

    /* Check if any signal is already pending (not blocked) */
    uint64_t unblocked_pending = task->pending_signals & ~task->signal_mask;

    if (unblocked_pending > 0) {
        /* Signal already pending, return immediately and let exception
         * handler deliver it. */
        fut_printf("[PAUSE] pause() by task %llu -> EINTR (signal already pending, not blocking)\n",
                   task->pid);
        return -EINTR;
    }

    /* No pending signals, block until one arrives */
    fut_printf("[PAUSE] pause() by task %llu -> blocking on signal_waitq\n", task->pid);

    /* Block on wait queue (this is a simple blocking sleep, signal delivery will wake us) */
    fut_waitq_sleep_locked(&task->signal_waitq, NULL);

    /* When we wake up, a signal has been delivered. Return -EINTR to let
     * the exception handler invoke the signal handler. */
    fut_printf("[PAUSE] pause() by task %llu -> woke up (signal delivered), returning -EINTR\n",
               task->pid);

    /* pause() always returns -EINTR (interrupted by signal) when it returns.
     * It never returns 0 or any other value. The only way pause() doesn't
     * return is if the signal terminates the process. */
    return -EINTR;
}
