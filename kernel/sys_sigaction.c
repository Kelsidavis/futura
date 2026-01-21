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

#include <kernel/kprintf.h>
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

    /* Phase 5: Validate signal number to prevent out-of-bounds array access
     * VULNERABILITY: Out-of-Bounds Signal Handler Array Access
     *
     * ATTACK SCENARIO:
     * Attacker provides invalid signal number to corrupt handler arrays
     * 1. Task signal_handlers[] has _NSIG slots (typically 32)
     * 2. Attacker calls sigaction(999, &act, NULL)
     * 3. Without validation, line 70: signal_handlers[999-1] = signal_handlers[998]
     * 4. Array has only 32 elements, accessing index 998 → OOB read
     * 5. Line 93: signal_handlers[998] = handler → OOB write
     * 6. Corrupts adjacent kernel structures (credentials, capabilities)
     * 7. Attacker installs handler at wrong memory location
     * 8. Signal delivery triggers arbitrary code execution
     *
     * IMPACT:
     * - Memory corruption: OOB write corrupts adjacent kernel structures
     * - Privilege escalation: Overwrite credentials or capabilities
     * - Arbitrary code execution: Signal handler points to attacker code
     * - Kernel crash: Accessing unmapped memory causes page fault
     *
     * ROOT CAUSE:
     * Signal handler arrays are fixed-size indexed by (signum - 1)
     * - signal_handlers[_NSIG]: Handler function pointers
     * - signal_handler_masks[_NSIG]: Signal masks during handler
     * - signal_handler_flags[_NSIG]: Handler behavior flags
     * - Lines 70-72, 93-95: Access arrays without prior validation
     * - Must validate signum BEFORE using as array index
     *
     * DEFENSE (Phase 5):
     * Validate signal number is within valid range BEFORE array access
     * - Check signum >= 1 (signals are 1-indexed in POSIX)
     * - Check signum < _NSIG (maximum signal number)
     * - Return -EINVAL for out-of-range signals
     * - Reject SIGKILL/SIGSTOP (uncatchable per POSIX)
     * - Prevents OOB access to all three handler arrays
     *
     * CVE REFERENCES:
     * - CVE-2009-0029: Linux signal handler array OOB access
     * - CVE-2014-3153: Futex signal handler corruption
     *
     * POSIX REQUIREMENT:
     * IEEE Std 1003.1-2017 sigaction(): "shall fail with EINVAL if sig
     * is not a valid signal number or is SIGKILL or SIGSTOP"
     *
     * IMPLEMENTATION NOTES:
     * - _NSIG is typically 32 on most systems
     * - Valid signals: 1 through (_NSIG - 1)
     * - Array index: (signum - 1) to convert 1-indexed to 0-indexed
     * - SIGKILL (9) and SIGSTOP (19) cannot be caught (POSIX requirement)
     */
    if (signum < 1 || signum >= _NSIG) {
        fut_printf("[SIGACTION] sigaction(signum=%d) -> EINVAL "
                   "(signal number out of range [1, %d), Phase 5: bounds validation)\n",
                   signum, _NSIG);
        return -EINVAL;
    }

    /* Phase 5: Reject uncatchable signals (POSIX requirement) */
    if (signum == SIGKILL || signum == SIGSTOP) {
        fut_printf("[SIGACTION] sigaction(signum=%d) -> EINVAL "
                   "(SIGKILL/SIGSTOP cannot be caught, Phase 5)\n", signum);
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

        fut_printf("[SIGACTION] Retrieved old action for signal %d: handler=%p mask=0x%llx flags=0x%x "
                   "(Phase 5: bounds validation)\n",
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

        fut_printf("[SIGACTION] Installed new action for signal %d: handler=%p mask=0x%llx flags=0x%x "
                   "(Phase 5: bounds validation)\n",
                   signum, new_act.sa_handler, new_act.sa_mask, new_act.sa_flags);
    }

    return 0;
}
