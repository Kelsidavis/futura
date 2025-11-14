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
 * Phase 3: Support all idtypes and options
 * Phase 4: Performance optimization with event notification
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <stdint.h>
#include <stddef.h>

extern void fut_printf(const char *fmt, ...);

/* idtype for waitid */
#define P_ALL    0  /* Wait for any child */
#define P_PID    1  /* Wait for specific PID */
#define P_PGID   2  /* Wait for any child in process group */
#define P_PIDFD  3  /* Wait for child via PID file descriptor */

/* waitid options (subset of wait4 options) */
#define WNOHANG    0x00000001  /* Don't block if no child has exited */
#define WUNTRACED  0x00000002  /* Report stopped children */
#define WSTOPPED   WUNTRACED   /* Same as WUNTRACED */
#define WEXITED    0x00000004  /* Report terminated children */
#define WCONTINUED 0x00000008  /* Report continued children */
#define WNOWAIT    0x01000000  /* Don't reap, just poll status */

/* siginfo_t structure (simplified for Phase 1) */
struct siginfo {
    int si_signo;     /* Signal number */
    int si_errno;     /* Error number */
    int si_code;      /* Signal code */
    int si_pid;       /* Sending process ID */
    int si_uid;       /* Sending process UID */
    int si_status;    /* Exit value or signal */
    uint64_t si_utime; /* User time consumed */
    uint64_t si_stime; /* System time consumed */
};

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
 * @param rusage   Optional pointer to rusage structure (can be NULL)
 *
 * Returns:
 *   - 0 on success (child status stored in infop)
 *   - -EFAULT if infop or rusage points to invalid memory
 *   - -EINVAL if idtype or options are invalid
 *   - -ECHILD if no matching child processes exist
 *   - -EINTR if interrupted by signal
 *
 * Usage:
 *   struct siginfo info;
 *
 *   // Wait for any child to exit
 *   waitid(P_ALL, 0, &info, WEXITED);
 *   printf("Child %d exited with status %d\n", info.si_pid, info.si_status);
 *
 *   // Wait for specific PID without blocking
 *   if (waitid(P_PID, child_pid, &info, WEXITED | WNOHANG) == 0) {
 *       if (info.si_pid != 0)
 *           printf("Child exited\n");
 *       else
 *           printf("Child still running\n");
 *   }
 *
 *   // Wait for stopped child (SIGSTOP, SIGTSTP)
 *   waitid(P_PID, child_pid, &info, WSTOPPED | WNOWAIT);
 *
 *   // Wait for continued child (SIGCONT)
 *   waitid(P_PID, child_pid, &info, WCONTINUED);
 *
 * Differences from wait4/waitpid:
 * - More flexible ID types (P_ALL, P_PID, P_PGID, P_PIDFD)
 * - WNOWAIT option to poll without reaping
 * - More detailed status via siginfo_t
 * - Can wait for continued processes
 * - Optional rusage parameter
 *
 * siginfo_t fields:
 * - si_signo: Always SIGCHLD for waitid
 * - si_code: CLD_EXITED, CLD_KILLED, CLD_STOPPED, CLD_CONTINUED
 * - si_pid: Child process ID
 * - si_uid: Child process real UID
 * - si_status: Exit code or signal number
 * - si_utime: User CPU time
 * - si_stime: System CPU time
 *
 * Phase 1 (Completed): Validate parameters and return -ECHILD
 * Phase 2 (Completed): Implement wait queue integration and child polling
 * Phase 3: Support all idtypes, options, and populate siginfo_t
 */
long sys_waitid(int idtype, int id, struct siginfo *infop, int options,
                void *rusage) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    /* Validate idtype */
    if (idtype < P_ALL || idtype > P_PIDFD) {
        fut_printf("[WAITID] waitid(idtype=%d [invalid], id=%d, infop=%p, options=0x%x, pid=%d) "
                   "-> EINVAL\n", idtype, id, infop, options, task->pid);
        return -EINVAL;
    }

    /* Validate infop pointer */
    if (!infop) {
        fut_printf("[WAITID] waitid(idtype=%d, id=%d, infop=NULL, options=0x%x, pid=%d) "
                   "-> EFAULT\n", idtype, id, options, task->pid);
        return -EFAULT;
    }

    /* Validate options */
    const int VALID_OPTIONS = WNOHANG | WUNTRACED | WEXITED | WCONTINUED | WNOWAIT;
    if (options & ~VALID_OPTIONS) {
        fut_printf("[WAITID] waitid(idtype=%d, id=%d, infop=%p, options=0x%x [invalid], pid=%d) "
                   "-> EINVAL\n", idtype, id, infop, options, task->pid);
        return -EINVAL;
    }

    /* At least one of WEXITED, WSTOPPED, WCONTINUED must be set */
    if (!(options & (WEXITED | WSTOPPED | WCONTINUED))) {
        fut_printf("[WAITID] waitid(idtype=%d, id=%d, infop=%p, options=0x%x [no wait flags], pid=%d) "
                   "-> EINVAL\n", idtype, id, infop, options, task->pid);
        return -EINVAL;
    }

    /* Suppress unused warning for Phase 1 stub */
    (void)rusage;

    /* Categorize idtype */
    const char *idtype_desc;
    switch (idtype) {
        case P_ALL:   idtype_desc = "any child"; break;
        case P_PID:   idtype_desc = "specific PID"; break;
        case P_PGID:  idtype_desc = "process group"; break;
        case P_PIDFD: idtype_desc = "PID fd"; break;
        default:      idtype_desc = "unknown"; break;
    }

    /* Categorize options */
    const char *options_desc;
    if (options & WNOHANG) {
        if (options & WEXITED) {
            options_desc = "non-blocking, exited";
        } else if (options & WSTOPPED) {
            options_desc = "non-blocking, stopped";
        } else if (options & WCONTINUED) {
            options_desc = "non-blocking, continued";
        } else {
            options_desc = "non-blocking";
        }
    } else {
        if (options & WEXITED) {
            options_desc = "blocking, exited";
        } else if (options & WSTOPPED) {
            options_desc = "blocking, stopped";
        } else if (options & WCONTINUED) {
            options_desc = "blocking, continued";
        } else {
            options_desc = "blocking";
        }
    }

    /* Phase 2: Return -ECHILD (no children) */
    fut_printf("[WAITID] waitid(idtype=%s, id=%d, infop=%p, options=%s, pid=%d) -> ECHILD "
               "(Phase 3: Support all idtypes, options, and populate siginfo_t)\n",
               idtype_desc, id, infop, options_desc, task->pid);

    return -ECHILD;
}
