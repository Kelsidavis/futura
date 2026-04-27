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
 * Phase 4 (Completed): Broadcast signal delivery (kill -1) and permission model
 */

#include <kernel/fut_task.h>
#include <kernel/signal.h>
#include <kernel/errno.h>
#include <sys/capability.h>

#include <kernel/kprintf.h>

/* Callback data for process group signaling */
struct pgrp_signal_data {
    int sig;
    int count;
    int error;
    uint32_t sender_ruid;   /* Sender's real UID for permission checks */
    uint32_t sender_uid;    /* Sender's effective UID */
    uint64_t sender_caps;   /* Sender's effective capabilities */
};

/* Callback to send signal to each task in a process group.
 * POSIX: For kill(0) and kill(-pgid), the permission model requires that
 * the sender's real or effective UID matches the target's real UID, or
 * the sender is root (uid 0) or has CAP_KILL. */
static void pgrp_signal_callback(fut_task_t *task, void *data) {
    struct pgrp_signal_data *psd = (struct pgrp_signal_data *)data;

    /* Permission check: root and CAP_KILL bypass, otherwise UID must match */
    if (psd->sender_ruid != 0 &&
        !(psd->sender_caps & (1ULL << CAP_KILL)) &&
        psd->sender_ruid != task->ruid &&
        psd->sender_uid  != task->ruid) {
        if (psd->error == 0)
            psd->error = -EPERM;
        return;
    }

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
 * Phase 4 (Completed): Broadcast signal delivery (kill -1) and permission model
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

    /* Validate signal number early with detailed error
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
     * DEFENSE:
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
                   "(invalid signal number, valid range: 0-%d)\n",
                   pid, sig, signal_name, _NSIG - 1);
        return -EINVAL;
    }

    /* Categorize PID target for error logging */
    const char *pid_desc;

    if (pid > 0) {
        pid_desc = "specific process";
    } else if (pid == 0) {
        pid_desc = "current process group";
    } else if (pid == -1) {
        pid_desc = "all processes (broadcast)";
    } else {
        pid_desc = "process group";
    }

    /* Handle different PID cases */
    if (pid == 0) {
        /* Send to all processes in current process group */
        struct pgrp_signal_data psd = {
            .sig = sig, .count = 0, .error = 0,
            .sender_ruid = current->ruid, .sender_uid = current->uid,
            .sender_caps = current->cap_effective
        };

        if (sig == 0) {
            /* Permission check only - just check if we have a process group */
            return 0;
        }

        int total = fut_task_foreach_pgid(current->pgid, pgrp_signal_callback, &psd);

        if (total == 0) {
            fut_printf("[KILL] kill(pid=0 [%s], sig=%d [%s]) -> ESRCH (empty process group)\n",
                       pid_desc, sig, signal_name);
            return -ESRCH;
        }

        /* POSIX: succeed if at least one signal was actually delivered. */
        if (psd.count > 0) return 0;
        return psd.error ? psd.error : 0;

    } else if (pid == -1) {
        /* Broadcast to all processes except init (pid=1) and self.
         * Permission model: root (uid=0) may signal any process;
         * non-root may only signal processes with the same real UID. */
        if (sig == 0) {
            /* Permission check: succeed if any eligible process exists */
            int count = fut_task_foreach_all(current->pid, NULL, NULL);
            return (count > 0) ? 0 : -ESRCH;
        }

        struct pgrp_signal_data psd = {
            .sig = sig, .count = 0, .error = 0,
            .sender_ruid = current->ruid, .sender_uid = current->uid,
            .sender_caps = current->cap_effective
        };
        int total = fut_task_foreach_all(current->pid, pgrp_signal_callback, &psd);

        if (total == 0) {
            fut_printf("[KILL] kill(pid=-1 [%s], sig=%d [%s]) -> ESRCH (no eligible processes)\n",
                       pid_desc, sig, signal_name);
            return -ESRCH;
        }

        if (psd.count > 0) return 0;
        return psd.error ? psd.error : 0;

    } else if (pid < -1) {
        /* Send to process group |pid|.
         *
         * Compute the absolute value via int64_t first: '-pid' done in
         * 'int' arithmetic is undefined behavior when pid == INT_MIN
         * (2's complement -INT_MIN doesn't fit in int). Linux's
         * kill(2) accepts pid == INT_MIN as 'process group |INT_MIN|'
         * via unsigned arithmetic; mirror that by widening before
         * negating. */
        uint64_t target_pgid = (uint64_t)(-(int64_t)pid);
        struct pgrp_signal_data psd = {
            .sig = sig, .count = 0, .error = 0,
            .sender_ruid = current->ruid, .sender_uid = current->uid,
            .sender_caps = current->cap_effective
        };

        if (sig == 0) {
            /* Permission check - verify process group exists */
            int count = fut_task_foreach_pgid(target_pgid, NULL, NULL);
            if (count == 0) {
                fut_printf("[KILL] kill(pid=%d [%s %llu], sig=0) -> ESRCH (no such process group)\n",
                           pid, pid_desc, target_pgid);
                return -ESRCH;
            }
            return 0;
        }

        int total = fut_task_foreach_pgid(target_pgid, pgrp_signal_callback, &psd);

        if (total == 0) {
            fut_printf("[KILL] kill(pid=%d [%s %llu], sig=%d [%s]) -> ESRCH (no such process group)\n",
                       pid, pid_desc, target_pgid, sig, signal_name);
            return -ESRCH;
        }

        if (psd.count > 0) return 0;
        return psd.error ? psd.error : 0;

    } else {
        /* pid > 0: Send to specific process */
        fut_task_t *target = NULL;

        if ((uint64_t)pid == current->pid) {
            target = current;
        } else {
            target = fut_task_by_pid((uint64_t)pid);
        }

        if (!target) {
            fut_printf("[KILL] kill(pid=%d [%s], sig=%d [%s, %s]) -> ESRCH (process not found)\n",
                       pid, pid_desc, sig, signal_name, signal_desc);
            return -ESRCH;  /* No such process */
        }

        /* Permission check: Linux's kill_ok_by_cred allows the signal
         * when ANY of these caller-uid × target-uid pairs match:
         *
         *   caller.euid ↔ target.uid       (effective)
         *   caller.euid ↔ target.suid      (saved)
         *   caller.ruid ↔ target.uid
         *   caller.ruid ↔ target.suid
         *
         * Plus root (uid==0) and CAP_KILL bypass. The previous check
         * only compared the caller's real / effective UIDs against the
         * target's *real* UID, missing the target.uid (effective) and
         * target.suid (saved) sides — so a privileged target that
         * dropped its effective UID to a regular user (the standard
         * setuid pattern) was un-killable by that user, even though
         * Linux explicitly permits this case. */
        if (target != current &&
            current->ruid != 0 &&
            !(current->cap_effective & (1ULL << CAP_KILL))) {
            int ok = (current->ruid == target->uid)  ||
                     (current->ruid == target->suid) ||
                     (current->uid  == target->uid)  ||
                     (current->uid  == target->suid);
            if (!ok)
                return -EPERM;
        }

        /* Handle null signal (permission check only) */
        if (sig == 0) {
            return 0;
        }

        /* Queue the signal */
        int result = fut_signal_send(target, sig);

        /* Detailed logging with signal and target information */
        if (result != 0) {
            fut_printf("[KILL] kill(pid=%d, sig=%d) -> %d (signal send failed)\n",
                       pid, sig, result);
        }

        return result;
    }
}
