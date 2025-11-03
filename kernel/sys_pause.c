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

    /* Phase 2: Check for pending signals and report state */
    int pending_signals = 0;
    int first_pending = -1;

    /* Check all standard signals for pending status */
    for (int signum = 1; signum < _NSIG; signum++) {
        if (fut_signal_is_pending(task, signum)) {
            pending_signals++;
            if (first_pending == -1) {
                first_pending = signum;
            }
        }
    }

    /* Build signal name for logging */
    const char *signal_name = "UNKNOWN";
    if (first_pending > 0) {
        switch (first_pending) {
            case SIGHUP:   signal_name = "SIGHUP"; break;
            case SIGINT:   signal_name = "SIGINT"; break;
            case SIGQUIT:  signal_name = "SIGQUIT"; break;
            case SIGILL:   signal_name = "SIGILL"; break;
            case SIGTRAP:  signal_name = "SIGTRAP"; break;
            case SIGABRT:  signal_name = "SIGABRT"; break;
            case SIGBUS:   signal_name = "SIGBUS"; break;
            case SIGFPE:   signal_name = "SIGFPE"; break;
            case SIGKILL:  signal_name = "SIGKILL"; break;
            case SIGUSR1:  signal_name = "SIGUSR1"; break;
            case SIGSEGV:  signal_name = "SIGSEGV"; break;
            case SIGUSR2:  signal_name = "SIGUSR2"; break;
            case SIGPIPE:  signal_name = "SIGPIPE"; break;
            case SIGALRM:  signal_name = "SIGALRM"; break;
            case SIGTERM:  signal_name = "SIGTERM"; break;
            case SIGCHLD:  signal_name = "SIGCHLD"; break;
            case SIGCONT:  signal_name = "SIGCONT"; break;
            case SIGSTOP:  signal_name = "SIGSTOP"; break;
            case SIGTSTP:  signal_name = "SIGTSTP"; break;
            case SIGTTIN:  signal_name = "SIGTTIN"; break;
            case SIGTTOU:  signal_name = "SIGTTOU"; break;
            default: signal_name = "UNKNOWN"; break;
        }
    }

    if (pending_signals > 0) {
        if (pending_signals == 1) {
            fut_printf("[PAUSE] pause() by task %llu -> EINTR (1 pending signal: %s, Phase 2: not blocking)\n",
                       task->pid, signal_name);
        } else {
            fut_printf("[PAUSE] pause() by task %llu -> EINTR (%d pending signals, first: %s, Phase 2: not blocking)\n",
                       task->pid, pending_signals, signal_name);
        }
    } else {
        fut_printf("[PAUSE] pause() by task %llu -> EINTR (no pending signals, Phase 2: not blocking)\n",
                   task->pid);
    }

    /* Phase 2: Still returns immediately, but with better diagnostics
     * Phase 3: Will block task on wait queue
     * Phase 4: Signal delivery path will set EINTR and resume task
     *
     * Future implementation (Phase 3+):
     * if (pending_signals > 0) {
     *     // Signal already pending, return immediately
     *     return -EINTR;
     * }
     * // No pending signal, block until one arrives
     * fut_waitq_sleep_interruptible(&task->signal_waitq);
     * // When woken by signal delivery, return -EINTR
     */

    /* pause() always returns -EINTR (interrupted by signal) when it returns.
     * It never returns 0 or any other value. The only way pause() doesn't
     * return is if the signal terminates the process. */
    return -EINTR;
}
