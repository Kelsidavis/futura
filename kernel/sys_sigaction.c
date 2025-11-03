/* kernel/sys_sigaction.c - Install signal handler syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements sigaction() to install signal handlers.
 */

#include <kernel/fut_task.h>
#include <kernel/signal.h>
#include <kernel/errno.h>

extern void fut_printf(const char *fmt, ...);
extern fut_task_t *fut_task_current(void);

long sys_sigaction(int signum, const struct sigaction *act, struct sigaction *oldact) {
    fut_task_t *current = fut_task_current();
    if (!current) {
        return -EINVAL;
    }

    (void)act;
    (void)oldact;

    /* Validate signal number */
    if (signum < 1 || signum >= _NSIG) {
        return -EINVAL;
    }

    /* SIGKILL and SIGSTOP cannot be caught */
    if (signum == SIGKILL || signum == SIGSTOP) {
        return -EINVAL;
    }

    /* Phase 1: Stub - signal handling infrastructure exists in kernel/signal/signal.c
     * Phase 2: Implement full sigaction with sa_handler, sa_mask, sa_flags */
    fut_printf("[SIGACTION] signum=%d -> 0 (Phase 1 stub)\n", signum);
    return 0;
}
