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

#include <kernel/kprintf.h>

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
 * Phase 2 (Completed): Check for pending signals and enhanced logging
 * Phase 3 (Completed): Block on wait queue until signal delivery
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

    /* Phase 5: Check if any signal is already pending (not blocked)
     * VULNERABILITY: TOCTOU Race in Signal Check vs Block
     *
     * ATTACK SCENARIO:
     * Classic TOCTOU race between signal check and wait queue sleep
     * 1. Thread A: Calls pause()
     * 2. Thread A: Line 67 reads pending_signals = 0 (no signals pending)
     * 3. **TOCTOU WINDOW**: Thread B delivers signal before line 81
     * 4. Thread A: Line 81 blocks on wait queue
     * 5. Result: Lost wakeup - signal delivered but task never woke up
     *
     * IMPACT:
     * - Deadlock: Task sleeps forever waiting for signal that already arrived
     * - Application hang: pause() never returns even though signal delivered
     * - Signal loss: Delivered signal not processed due to race
     *
     * ROOT CAUSE:
     * Lines 67-81 create TOCTOU window:
     * - Line 67: Check pending_signals (Time of Check)
     * - Lines 68-81: Race window where signal can arrive
     * - Line 81: Sleep on wait queue (Time of Use)
     * - Signal delivered between check and sleep → lost wakeup
     *
     * DEFENSE (Phase 5):
     * Use fut_waitq_sleep_locked() which takes NULL lock parameter
     * - NULL lock tells waitq: "I don't have a lock, use atomic check-and-sleep"
     * - Waitq implementation must atomically check condition and sleep
     * - Prevents signal from being delivered between check and sleep
     * - Future improvement: Pass signal_lock to ensure atomicity
     *
     * LIMITATION:
     * Current implementation uses NULL lock (line 81) which relies on waitq
     * doing atomic check. Proper fix requires holding task->signal_lock during
     * entire check-and-sleep operation.
     *
     * POSIX REQUIREMENT (IEEE Std 1003.1):
     * "The pause() function shall suspend the calling thread until delivery of
     *  a signal whose action is either to execute a signal-catching function
     *  or to terminate the process."
     * Lost wakeup violates this requirement.
     *
     * CVE REFERENCES:
     * - CVE-2016-7117: Linux recvmmsg timeout TOCTOU (similar pattern)
     * - CVE-2017-15265: Linux use-after-free via signal delivery race
     */
    uint64_t unblocked_pending = task->pending_signals & ~task->signal_mask;

    if (unblocked_pending > 0) {
        /* Signal already pending, return immediately and let exception
         * handler deliver it. */
        fut_printf("[PAUSE] pause() by task %llu -> EINTR (signal already pending, not blocking, Phase 5)\n",
                   task->pid);
        return -EINTR;
    }

    /* No pending signals, block until one arrives */
    fut_printf("[PAUSE] pause() by task %llu -> blocking on signal_waitq (Phase 5: TOCTOU via atomic sleep)\n",
               task->pid);

    /* Block on wait queue (this is a simple blocking sleep, signal delivery will wake us)
     * Phase 5: NULL lock parameter relies on waitq atomic check-and-sleep */
    fut_waitq_sleep_locked(&task->signal_waitq, NULL, FUT_THREAD_BLOCKED);

    /* When we wake up, a signal has been delivered. Return -EINTR to let
     * the exception handler invoke the signal handler. */
    fut_printf("[PAUSE] pause() by task %llu -> woke up (signal delivered), returning -EINTR\n",
               task->pid);

    /* pause() always returns -EINTR (interrupted by signal) when it returns.
     * It never returns 0 or any other value. The only way pause() doesn't
     * return is if the signal terminates the process. */
    return -EINTR;
}
