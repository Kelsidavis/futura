/* kernel/sys_waitid.c - Advanced process wait syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements waitid for waiting on child process state changes with more
 * flexibility than wait4/waitpid. Essential for advanced process management
 * and signal handling.
 *
 * Phase 1 (Completed): Validation and stub implementation
 * Phase 2 (Completed): Implement wait queue integration
 * Phase 3 (Completed): Support P_ALL/P_PID/P_PGID, WNOHANG, WEXITED; populate siginfo_t
 * Phase 4: WNOWAIT peek support, WSTOPPED/WCONTINUED, si_uid from reaped child
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <kernel/signal_frame.h>
#include <kernel/uaccess.h>
#include <sys/wait.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include <kernel/kprintf.h>

/* P_ALL, P_PID, P_PGID (idtype_t) and wait options (WNOHANG, WUNTRACED,
 * WSTOPPED, WEXITED, WCONTINUED, WNOWAIT) are provided by sys/wait.h */
/* siginfo_t provided by kernel/signal_frame.h */

/* P_PIDFD: Linux extension for PID file descriptor (not in POSIX) */
#ifndef P_PIDFD
#define P_PIDFD  3  /* Wait for child via PID file descriptor */
#endif

/* CLD_* codes for siginfo_t.si_code when si_signo == SIGCHLD */
#define CLD_EXITED    1   /* Child exited normally */
#define CLD_KILLED    2   /* Child was killed by a signal */
#define CLD_DUMPED    3   /* Child killed by signal + core dump */
#define CLD_TRAPPED   4   /* Traced child trapped */
#define CLD_STOPPED   5   /* Child stopped by a signal */
#define CLD_CONTINUED 6   /* Child continued by SIGCONT */

/**
 * waitid() - Wait for child process state change (advanced)
 *
 * Waits for a child process to change state, with more control than
 * wait4/waitpid. Can wait for specific processes, process groups, or
 * any child. Provides detailed information via siginfo_t structure.
 *
 * @param idtype   Type of ID (P_ALL, P_PID, P_PGID, P_PIDFD)
 * @param id       ID value (pid, pgid, or pidfd depending on idtype)
 * @param infop    Pointer to siginfo_t to receive status information
 * @param options  Wait options (WNOHANG, WEXITED, WSTOPPED, WCONTINUED, etc.)
 * @param rusage   Optional pointer to rusage structure (can be NULL, ignored)
 *
 * Returns:
 *   - 0 on success (child status stored in infop)
 *   - -EFAULT if infop or rusage points to invalid memory
 *   - -EINVAL if idtype or options are invalid
 *   - -ECHILD if no matching child processes exist
 *   - -EINTR if interrupted by signal
 *
 * Phase 1 (Completed): Validate parameters and return -ECHILD
 * Phase 2 (Completed): Implement wait queue integration and child polling
 * Phase 3 (Completed): Support all idtypes, WNOHANG, WEXITED; populate siginfo_t
 */
long sys_waitid(int idtype, int id, siginfo_t *infop, int options,
                void *rusage) {
    (void)rusage;   /* Phase 4: populate with resource usage of reaped child */
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    /* Validate idtype */
    const char *idtype_desc;
    switch (idtype) {
        case P_ALL:   idtype_desc = "P_ALL";   break;
        case P_PID:   idtype_desc = "P_PID";   break;
        case P_PGID:  idtype_desc = "P_PGID";  break;
        case P_PIDFD: idtype_desc = "P_PIDFD"; break;
        default:
            fut_printf("[WAITID] waitid(idtype=%d [invalid]) -> EINVAL\n", idtype);
            return -EINVAL;
    }

    /* P_PIDFD is not supported yet */
    if (idtype == P_PIDFD) {
        fut_printf("[WAITID] waitid(P_PIDFD) -> EINVAL (PID file descriptors not supported)\n");
        return -EINVAL;
    }

    /* options must include at least one event type */
    if (!(options & (WEXITED | WSTOPPED | WCONTINUED))) {
        fut_printf("[WAITID] waitid(options=0x%x) -> EINVAL (no event type in options)\n", options);
        return -EINVAL;
    }

    /* Validate infop pointer (required, not optional) */
    if (!infop) {
        fut_printf("[WAITID] waitid(infop=NULL) -> EFAULT\n");
        return -EFAULT;
    }

    /* Validate infop is writable */
    if (fut_access_ok(infop, sizeof(siginfo_t), 1) != 0) {
        fut_printf("[WAITID] waitid(infop=%p) -> EFAULT (not writable)\n", (void *)infop);
        return -EFAULT;
    }

    /* Convert idtype/id to the pid argument for fut_task_waitpid:
     *   P_ALL:  pid = -1  (any child)
     *   P_PID:  pid = id  (specific child)
     *   P_PGID: pid = -|id| if id > 0, else pid = 0 (current pgrp) */
    int wait_pid;
    switch (idtype) {
        case P_ALL:
            wait_pid = -1;
            break;
        case P_PID:
            if (id <= 0) {
                fut_printf("[WAITID] waitid(P_PID, id=%d) -> EINVAL (id must be > 0)\n", id);
                return -EINVAL;
            }
            wait_pid = id;
            break;
        case P_PGID:
            wait_pid = (id > 0) ? -id : 0;
            break;
        default:
            return -EINVAL;
    }

    /* Build waitpid flags.
     * WNOHANG: pass through.
     * WSTOPPED/WCONTINUED: we only support WEXITED for now;
     * stopped/continued children are not tracked, so ignore those bits. */
    int wait_flags = 0;
    if (options & WNOHANG) {
        wait_flags |= WNOHANG;  /* WNOHANG = 1 */
    }

    /* Phase 4 TODO: WNOWAIT — peek without reaping.
     * For now, we always reap if a child is available. */

    /* Call the core wait implementation */
    int status = 0;
    int child_pid = fut_task_waitpid(wait_pid, &status, wait_flags);

    if (child_pid < 0) {
        /* -ECHILD, -EINTR, etc. */
        fut_printf("[WAITID] waitid(%s, id=%d, options=0x%x) -> %d\n",
                   idtype_desc, id, options, child_pid);
        return child_pid;
    }

    if (child_pid == 0) {
        /* WNOHANG and no child ready: fill infop with zeros (si_pid=0 signals no event) */
        siginfo_t info_zero;
        memset(&info_zero, 0, sizeof(info_zero));
        if (fut_copy_to_user(infop, &info_zero, sizeof(siginfo_t)) != 0) {
            return -EFAULT;
        }
        fut_printf("[WAITID] waitid(%s, id=%d, WNOHANG) -> 0 (no child ready)\n",
                   idtype_desc, id);
        return 0;
    }

    /* Child reaped: populate siginfo_t */
    siginfo_t info;
    memset(&info, 0, sizeof(info));
    info.si_signum = SIGCHLD;

    if (WIFEXITED(status)) {
        info.si_code   = CLD_EXITED;
        info.si_status = WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
        info.si_code   = CLD_KILLED;
        info.si_status = WTERMSIG(status);
    } else {
        info.si_code   = CLD_EXITED;
        info.si_status = 0;
    }

    info.si_pid = (int64_t)child_pid;
    /* si_uid: Phase 4 — requires saving uid before reaping the child.
     * For now, leave as 0 (acceptable; most callers don't use si_uid from waitid). */
    info.si_uid = 0;

    if (fut_copy_to_user(infop, &info, sizeof(siginfo_t)) != 0) {
        return -EFAULT;
    }

    fut_printf("[WAITID] waitid(%s, id=%d, options=0x%x) -> 0 "
               "(child_pid=%d, code=%s, status=%d)\n",
               idtype_desc, id, options, child_pid,
               (info.si_code == CLD_EXITED) ? "CLD_EXITED" : "CLD_KILLED",
               info.si_status);
    return 0;
}
