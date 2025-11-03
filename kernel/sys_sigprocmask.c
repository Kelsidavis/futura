/* kernel/sys_sigprocmask.c - Change signal blocking mask syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements sigprocmask() to examine and change blocked signals.
 */

#include <kernel/fut_task.h>
#include <kernel/signal.h>
#include <kernel/errno.h>

extern void fut_printf(const char *fmt, ...);
extern fut_task_t *fut_task_current(void);

long sys_sigprocmask(int how, const sigset_t *set, sigset_t *oldset) {
    fut_task_t *current = fut_task_current();
    if (!current) {
        return -EINVAL;
    }

    return fut_signal_procmask(current, how, set, oldset);
}
