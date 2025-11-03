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
 * Phase 1 (Current): Returns -EINTR immediately (stub)
 * Phase 2: Block on wait queue until signal delivery
 * Phase 3: Integrate with signal delivery path to wake blocked tasks
 */
long sys_pause(void) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    fut_printf("[PAUSE] pause() called by task %llu (stub - returns immediately)\n",
               task->pid);

    /* Phase 1: Return immediately with -EINTR
     * Phase 2: Block task on wait queue, wake when signal delivered
     * Phase 3: Signal delivery path will set EINTR and resume task */

    /* pause() always returns -EINTR (interrupted by signal) when it returns.
     * It never returns 0 or any other value. The only way pause() doesn't
     * return is if the signal terminates the process. */
    return -EINTR;
}
