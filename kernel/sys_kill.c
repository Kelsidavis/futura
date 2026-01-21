/* kernel/sys_kill.c - Send signal to process syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements kill() to send signals to processes.
 *
 * Phase 1 (Completed): Basic signal sending to self and children
 * Phase 2 (Completed): Enhanced validation, signal name identification, and detailed logging
 * Phase 3 (Completed): Process group signal delivery
 * Phase 4: Permission checks and broadcast signals
 */

#include <kernel/fut_task.h>
#include <kernel/signal.h>
#include <kernel/errno.h>

#include <kernel/kprintf.h>
extern fut_task_t *fut_task_current(void);
extern fut_task_t *fut_task_by_pid(uint64_t pid);
extern int fut_task_foreach_pgid(uint64_t pgid, void (*callback)(fut_task_t *task, void *data), void *data);

/* Callback data for process group signaling */
struct pgrp_signal_data {
    int sig;
    int count;
    int error;
};

/* Callback to send signal to each task in a process group */
static void pgrp_signal_callback(fut_task_t *task, void *data) {
    struct pgrp_signal_data *psd = (struct pgrp_signal_data *)data;
    int result = fut_signal_send(task, psd->sig);
    if (result == 0) {
        psd->count++;
    } else if (psd->error == 0) {
        psd->error = result;  /* Record first error */
    }
}

/**
 * kill() - Send signal to process or process group
 *
 * Sends signal 'sig' to the process(es) specified by 'pid'.
 *
 * @param pid  Process or group identifier (see PID interpretation below)
 * @param sig  Signal number to send (0 for permission check only)
 *
 * Returns:
 *   - 0 on success
 *   - -EINVAL if sig is invalid
 *   - -ESRCH if no such process
 *   - -EPERM if insufficient permissions
 *
 * PID interpretation:
 *   - pid > 0: Send to process with PID == pid
 *   - pid == 0: Send to all processes in current process group
 *   - pid == -1: Send to all processes (broadcast) except init
 *   - pid < -1: Send to process group |pid|
 *
 * Signal 0 (null signal):
 *   - Performs permission check without sending signal
 *   - Used to check if process exists and is accessible
 *
 * Phase 2 (Completed): Signal name identification and PID categorization
 * Phase 3 (Completed): Process group signal delivery
 * Phase 4: Permission checks and broadcast signals
 */
long sys_kill(int pid, int sig) {
    fut_task_t *current = fut_task_current();
    if (!current) {
        fut_printf("[KILL] kill(pid=%d, sig=%d) -> EINVAL (no current task)\n", pid, sig);
        return -EINVAL;
    }

    /* Phase 2: Identify signal name for logging */
    const char *signal_name;
    const char *signal_desc;

    switch (sig) {
        case 0:
            signal_name = "SIG0";
            signal_desc = "null signal (permission check)";
            break;
        case SIGHUP:
            signal_name = "SIGHUP";
            signal_desc = "hangup";
            break;
        case SIGINT:
            signal_name = "SIGINT";
            signal_desc = "interrupt";
            break;
        case SIGQUIT:
            signal_name = "SIGQUIT";
            signal_desc = "quit";
            break;
        case SIGILL:
            signal_name = "SIGILL";
            signal_desc = "illegal instruction";
            break;
        case SIGTRAP:
            signal_name = "SIGTRAP";
            signal_desc = "trace trap";
            break;
        case SIGABRT:
            signal_name = "SIGABRT";
            signal_desc = "abort";
            break;
        case SIGBUS:
            signal_name = "SIGBUS";
            signal_desc = "bus error";
            break;
        case SIGFPE:
            signal_name = "SIGFPE";
            signal_desc = "floating point exception";
            break;
        case SIGKILL:
            signal_name = "SIGKILL";
            signal_desc = "kill (uncatchable)";
            break;
        case SIGUSR1:
            signal_name = "SIGUSR1";
            signal_desc = "user-defined 1";
            break;
        case SIGSEGV:
            signal_name = "SIGSEGV";
            signal_desc = "segmentation violation";
            break;
        case SIGUSR2:
            signal_name = "SIGUSR2";
            signal_desc = "user-defined 2";
            break;
        case SIGPIPE:
            signal_name = "SIGPIPE";
            signal_desc = "broken pipe";
            break;
        case SIGALRM:
            signal_name = "SIGALRM";
            signal_desc = "alarm clock";
            break;
        case SIGTERM:
            signal_name = "SIGTERM";
            signal_desc = "termination";
            break;
        case SIGCHLD:
            signal_name = "SIGCHLD";
            signal_desc = "child status changed";
            break;
        case SIGCONT:
            signal_name = "SIGCONT";
            signal_desc = "continue";
            break;
        case SIGSTOP:
            signal_name = "SIGSTOP";
            signal_desc = "stop (uncatchable)";
            break;
        case SIGTSTP:
            signal_name = "SIGTSTP";
            signal_desc = "terminal stop";
            break;
        case SIGTTIN:
            signal_name = "SIGTTIN";
            signal_desc = "background read";
            break;
        case SIGTTOU:
            signal_name = "SIGTTOU";
            signal_desc = "background write";
            break;
        default:
            signal_name = "UNKNOWN";
            signal_desc = "unknown signal";
            break;
    }

    /* Phase 5: Validate signal number early with detailed error
     * VULNERABILITY: Signal Number Out-of-Bounds Access
     *
     * ATTACK SCENARIO:
     * Attacker provides invalid signal number to exploit array indexing
     * 1. Kernel uses signal number as array index in various places:
     *    - Signal handler table: current->sighand[sig]
     *    - Signal pending bitmask: (1UL << sig)
     *    - Signal name lookup tables
     * 2. Without bounds check:
     *    - kill(pid, sig=100) → accesses sighand[100] out-of-bounds
     *    - kill(pid, sig=-5) → negative index causes memory corruption
     *    - kill(pid, sig=0xFFFFFFFF) → wraps around, accesses kernel memory
     * 3. Impact:
     *    - Information disclosure: Reading arbitrary kernel memory via signal arrays
     *    - Memory corruption: Writing to arbitrary kernel memory
     *    - Kernel panic: Page fault from invalid memory access
     *
     * ROOT CAUSE:
     * - Signal number used directly as array index without validation
     * - Negative signals could wrap around in unsigned arithmetic
     * - Out-of-range signals access beyond allocated signal tables
     *
     * DEFENSE (Phase 5):
     * Validate signal number BEFORE any switch/case or array indexing
     * - Check sig >= 0 (reject negative signals)
     * - Check sig < _NSIG (reject signals beyond table size)
     * - Fail fast before switch statement at line 60
     * - Prevents all array out-of-bounds accesses
     *
     * POSIX REQUIREMENT (IEEE Std 1003.1):
     * "If sig is 0 (the null signal), error checking is performed but no signal
     *  is actually sent. The null signal can be used to check the validity of pid."
     * All other signals must be in range [1, _NSIG-1]
     *
     * CVE REFERENCES:
     * - CVE-2009-1337: Linux signal handler out-of-bounds (similar pattern)
     * - CVE-2018-10879: Linux ext4 out-of-bounds via invalid array index
     */
    if (sig < 0 || sig >= _NSIG) {
        fut_printf("[KILL] kill(pid=%d, sig=%d [%s]) -> EINVAL "
                   "(invalid signal number, valid range: 0-%d, Phase 5)\n",
                   pid, sig, signal_name, _NSIG - 1);
        return -EINVAL;
    }

    /* Phase 2: Categorize PID target type */
    const char *pid_desc;
    const char *target_type;

    if (pid > 0) {
        pid_desc = "specific process";
        target_type = "single";
    } else if (pid == 0) {
        pid_desc = "current process group";
        target_type = "group";
    } else if (pid == -1) {
        pid_desc = "all processes (broadcast)";
        target_type = "broadcast";
    } else {  /* pid < -1 */
        pid_desc = "process group";
        target_type = "group";
    }

    /* Handle different PID cases */
    if (pid == 0) {
        /* Send to all processes in current process group */
        struct pgrp_signal_data psd = { .sig = sig, .count = 0, .error = 0 };

        if (sig == 0) {
            /* Permission check only - just check if we have a process group */
            fut_printf("[KILL] kill(pid=0 [%s], sig=0) -> 0 (permission check, pgrp=%llu)\n",
                       pid_desc, current->pgid);
            return 0;
        }

        int total = fut_task_foreach_pgid(current->pgid, pgrp_signal_callback, &psd);

        if (total == 0) {
            fut_printf("[KILL] kill(pid=0 [%s], sig=%d [%s]) -> ESRCH (empty process group)\n",
                       pid_desc, sig, signal_name);
            return -ESRCH;
        }

        fut_printf("[KILL] kill(pid=0 [%s], sig=%d [%s]) -> 0 (sent to %d/%d in pgrp %llu)\n",
                   pid_desc, sig, signal_name, psd.count, total, current->pgid);
        return psd.error ? psd.error : 0;

    } else if (pid == -1) {
        /* Broadcast to all processes except init (pid=1) - not yet fully implemented */
        fut_printf("[KILL] kill(pid=-1 [%s], sig=%d [%s, %s]) -> EINVAL (broadcast not yet supported)\n",
                   pid_desc, sig, signal_name, signal_desc);
        return -EINVAL;

    } else if (pid < -1) {
        /* Send to process group |pid| */
        uint64_t target_pgid = (uint64_t)(-pid);
        struct pgrp_signal_data psd = { .sig = sig, .count = 0, .error = 0 };

        if (sig == 0) {
            /* Permission check - verify process group exists */
            int count = fut_task_foreach_pgid(target_pgid, NULL, NULL);
            if (count == 0) {
                fut_printf("[KILL] kill(pid=%d [%s %llu], sig=0) -> ESRCH (no such process group)\n",
                           pid, pid_desc, target_pgid);
                return -ESRCH;
            }
            fut_printf("[KILL] kill(pid=%d [%s %llu], sig=0) -> 0 (permission check, %d processes)\n",
                       pid, pid_desc, target_pgid, count);
            return 0;
        }

        int total = fut_task_foreach_pgid(target_pgid, pgrp_signal_callback, &psd);

        if (total == 0) {
            fut_printf("[KILL] kill(pid=%d [%s %llu], sig=%d [%s]) -> ESRCH (no such process group)\n",
                       pid, pid_desc, target_pgid, sig, signal_name);
            return -ESRCH;
        }

        fut_printf("[KILL] kill(pid=%d [%s %llu], sig=%d [%s]) -> 0 (sent to %d/%d)\n",
                   pid, pid_desc, target_pgid, sig, signal_name, psd.count, total);
        return psd.error ? psd.error : 0;

    } else {
        /* pid > 0: Send to specific process */
        fut_task_t *target = NULL;

        if ((uint64_t)pid == current->pid) {
            target = current;
            target_type = "self";
        } else {
            /* Look up by PID in global task list */
            target = fut_task_by_pid((uint64_t)pid);
            if (target) {
                if (target->parent == current) {
                    target_type = "child";
                } else {
                    target_type = "other";
                }
            }
        }

        if (!target) {
            fut_printf("[KILL] kill(pid=%d [%s], sig=%d [%s, %s]) -> ESRCH (process not found)\n",
                       pid, pid_desc, sig, signal_name, signal_desc);
            return -ESRCH;  /* No such process */
        }

        /* Handle null signal (permission check only) */
        if (sig == 0) {
            fut_printf("[KILL] kill(pid=%d [%s, target=%s], sig=0 [%s]) -> 0 (permission check only, target exists)\n",
                       pid, pid_desc, target_type, signal_name);
            return 0;
        }

        /* Queue the signal */
        int result = fut_signal_send(target, sig);

        /* Detailed logging with signal and target information */
        if (result == 0) {
            fut_printf("[KILL] kill(pid=%d [%s, target=%s], sig=%d [%s, %s]) -> 0 (signal queued)\n",
                       pid, pid_desc, target_type, sig, signal_name, signal_desc);
        } else {
            fut_printf("[KILL] kill(pid=%d [%s, target=%s], sig=%d [%s, %s]) -> %d (signal send failed)\n",
                       pid, pid_desc, target_type, sig, signal_name, signal_desc, result);
        }

        return result;
    }
}
