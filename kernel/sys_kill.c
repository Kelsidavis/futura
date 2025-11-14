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

extern void fut_printf(const char *fmt, ...);
extern fut_task_t *fut_task_current(void);

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

    /* Phase 2: Validate signal number early with detailed error */
    if (sig < 0 || sig >= _NSIG) {
        fut_printf("[KILL] kill(pid=%d, sig=%d [%s]) -> EINVAL (invalid signal number, valid range: 0-%d)\n",
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

    /* Find target task by PID */
    fut_task_t *target = NULL;

    if (pid == 0) {
        /* Phase 2: Send to current process group - not yet implemented */
        fut_printf("[KILL] kill(pid=0 [%s], sig=%d [%s, %s]) -> EINVAL (process groups not yet supported, Phase 2)\n",
                   pid_desc, sig, signal_name, signal_desc);
        return -EINVAL;
    } else if (pid == -1) {
        /* Phase 2: Broadcast to all processes - not yet implemented */
        fut_printf("[KILL] kill(pid=-1 [%s], sig=%d [%s, %s]) -> EINVAL (broadcast not yet supported, Phase 2)\n",
                   pid_desc, sig, signal_name, signal_desc);
        return -EINVAL;
    } else if (pid < -1) {
        /* Phase 2: Send to process group |pid| - not yet implemented */
        fut_printf("[KILL] kill(pid=%d [%s %d], sig=%d [%s, %s]) -> EINVAL (process groups not yet supported, Phase 2)\n",
                   pid, pid_desc, -pid, sig, signal_name, signal_desc);
        return -EINVAL;
    } else {
        /* pid > 0: Send to specific process */
        if ((uint64_t)pid == current->pid) {
            target = current;
            target_type = "self";
        } else {
            /* Look through children */
            target = current->first_child;
            while (target && target->pid != (uint64_t)pid) {
                target = target->sibling;
            }
            if (target) {
                target_type = "child";
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

    /* Phase 2: Detailed logging with signal and target information */
    if (result == 0) {
        fut_printf("[KILL] kill(pid=%d [%s, target=%s], sig=%d [%s, %s]) -> 0 (signal queued, Phase 2)\n",
                   pid, pid_desc, target_type, sig, signal_name, signal_desc);
    } else {
        fut_printf("[KILL] kill(pid=%d [%s, target=%s], sig=%d [%s, %s]) -> %d (signal send failed)\n",
                   pid, pid_desc, target_type, sig, signal_name, signal_desc, result);
    }

    return result;
}
