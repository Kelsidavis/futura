/* kernel/sys_sigaction.c - Install signal handler syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements sigaction() to install signal handlers with full POSIX semantics.
 * Supports handler functions, signal masking during handler execution, and
 * various flags like SA_RESTART and SA_RESETHAND.
 *
 * Phase 1 (Completed): Basic validation stub
 * Phase 2 (Completed): Full sigaction implementation with sa_handler, sa_mask, sa_flags
 * Phase 3 (Completed): Signal delivery and trampoline setup
 * Phase 4: Nested signal handling and sigreturn
 */

#include <kernel/fut_task.h>
#include <kernel/signal.h>
#include <kernel/errno.h>
#include <kernel/uaccess.h>

extern void fut_printf(const char *fmt, ...);
extern fut_task_t *fut_task_current(void);

/**
 * sigaction() - Examine and change a signal action
 *
 * Allows inspection and modification of the action taken by a process
 * when a specific signal is received. This is the standard POSIX method
 * for installing signal handlers.
 *
 * @param signum  Signal number to configure (1-30)
 * @param act     New action to install (or NULL to query only)
 * @param oldact  Buffer to receive previous action (or NULL if not needed)
 *
 * Returns:
 *   - 0 on success
 *   - -EINVAL if signal number is invalid or uncatchable
 *   - -EFAULT if act or oldact points to invalid memory
 *
 * Features:
 * - sa_handler: Signal handler function (or SIG_DFL/SIG_IGN)
 * - sa_mask: Signals to block during handler execution
 * - sa_flags: Handler behavior flags (SA_RESTART, SA_RESETHAND, etc.)
 *
 * Phase 2 (Completed): Fully manages signal action storage in task structure
 * Phase 3 (Completed): Signal delivery will invoke handlers with proper masking
 * Phase 4: Nested signals and SA_RESETHAND handling
 */
long sys_sigaction(int signum, const struct sigaction *act, struct sigaction *oldact) {
    fut_task_t *current = fut_task_current();
    if (!current) {
        return -ESRCH;
    }

    /* Validate signal number */
    if (signum < 1 || signum >= _NSIG) {
        return -EINVAL;
    }

    /* SIGKILL and SIGSTOP cannot be caught or ignored */
    if (signum == SIGKILL || signum == SIGSTOP) {
        return -EINVAL;
    }

    /* If oldact is provided, return the current action */
    if (oldact) {
        struct sigaction old;

        /* Retrieve current action from task structure */
        old.sa_handler = current->signal_handlers[signum - 1];
        old.sa_mask = current->signal_handler_masks[signum - 1];
        old.sa_flags = current->signal_handler_flags[signum - 1];

        /* Copy to userspace */
        if (fut_copy_to_user(oldact, &old, sizeof(struct sigaction)) != 0) {
            return -EFAULT;
        }

        fut_printf("[SIGACTION] Retrieved old action for signal %d: handler=%p mask=0x%llx flags=0x%x\n",
                   signum, old.sa_handler, old.sa_mask, old.sa_flags);
    }

    /* If act is provided, install the new action */
    if (act) {
        struct sigaction new_act;

        /* Copy from userspace */
        if (fut_copy_from_user(&new_act, act, sizeof(struct sigaction)) != 0) {
            return -EFAULT;
        }

        /* Install the new action in task structure */
        current->signal_handlers[signum - 1] = new_act.sa_handler;
        current->signal_handler_masks[signum - 1] = new_act.sa_mask;
        current->signal_handler_flags[signum - 1] = new_act.sa_flags;

        fut_printf("[SIGACTION] Installed new action for signal %d: handler=%p mask=0x%llx flags=0x%x\n",
                   signum, new_act.sa_handler, new_act.sa_mask, new_act.sa_flags);
    }

    return 0;
}
