/* kernel/sys_kill.c - Send signal to process syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements kill() to send signals to processes.
 */

#include <kernel/fut_task.h>
#include <kernel/signal.h>
#include <kernel/errno.h>

extern void fut_printf(const char *fmt, ...);
extern fut_task_t *fut_task_current(void);

long sys_kill(int pid, int sig) {
    fut_task_t *current = fut_task_current();
    if (!current) {
        return -EINVAL;
    }

    /* Find target task by PID */
    fut_task_t *target = NULL;

    if (pid == 0) {
        /* Send to current process group - not yet implemented */
        return -EINVAL;
    } else {
        /* Send to specific process */
        if ((uint64_t)pid == current->pid) {
            target = current;
        } else {
            /* Look through children */
            target = current->first_child;
            while (target && target->pid != (uint64_t)pid) {
                target = target->sibling;
            }
        }
    }

    if (!target) {
        return -ESRCH;  /* No such process */
    }

    /* Validate signal number */
    if (sig < 1 || sig >= _NSIG) {
        return -EINVAL;
    }

    /* Queue the signal */
    return fut_signal_send(target, sig);
}
