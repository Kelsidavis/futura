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
 * Phase 4 (Completed): WNOWAIT peek support, si_uid from reaped child
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

#include <platform/platform.h>

static inline int waitid_copy_to_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)dst >= KERNEL_VIRTUAL_BASE) { __builtin_memcpy(dst, src, n); return 0; }
#endif
    return fut_copy_to_user(dst, src, n);
}
static inline int waitid_access_ok(const void *ptr, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)ptr >= KERNEL_VIRTUAL_BASE) return 0;
#endif
    return fut_access_ok(ptr, n, 1);
}

/* P_ALL, P_PID, P_PGID (idtype_t) and wait options (WNOHANG, WUNTRACED,
 * WSTOPPED, WEXITED, WCONTINUED, WNOWAIT) are provided by sys/wait.h */
/* siginfo_t provided by kernel/signal_frame.h */

/* P_PIDFD: Linux extension for PID file descriptor (not in POSIX) */
#ifndef P_PIDFD
#define P_PIDFD  3  /* Wait for child via PID file descriptor */
#endif

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
 * Phase 4 (Completed): WNOWAIT peek without reaping, si_uid from child
 */
long sys_waitid(int idtype, int id, siginfo_t *infop, int options,
                void *rusage) {
    (void)rusage;   /* rusage: out of scope — not tracked per-process yet */
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

    /* P_PIDFD: resolve pidfd to PID, then proceed as P_PID */
    if (idtype == P_PIDFD) {
        extern int pidfd_get_pid(int fd);
        int pidfd_fd = id;
        int resolved_pid = pidfd_get_pid(pidfd_fd);
        if (resolved_pid < 0) {
            fut_printf("[WAITID] waitid(P_PIDFD, fd=%d) -> EBADF (fd is not a valid pidfd)\n",
                       pidfd_fd);
            return -EBADF;
        }
        fut_printf("[WAITID] waitid(P_PIDFD, fd=%d) -> resolved pid=%d\n", pidfd_fd, resolved_pid);
        idtype = P_PID;
        id = resolved_pid;
        idtype_desc = "P_PIDFD->P_PID";
    }

    /* Reject unknown option bits (Linux returns EINVAL) */
#define WAITID_VALID_OPTIONS (WNOHANG | WEXITED | WSTOPPED | WCONTINUED | WNOWAIT | __WALL | __WCLONE | __WNOTHREAD)
    if (options & ~WAITID_VALID_OPTIONS) {
        fut_printf("[WAITID] waitid(options=0x%x) -> EINVAL (unknown flags 0x%x)\n",
                   options, options & ~WAITID_VALID_OPTIONS);
        return -EINVAL;
    }

    /* options must include at least one event type */
    if (!(options & (WEXITED | WSTOPPED | WCONTINUED))) {
        fut_printf("[WAITID] waitid(options=0x%x) -> EINVAL (no event type in options)\n", options);
        return -EINVAL;
    }

    /* Linux's kernel/exit.c:SYSCALL_DEFINE5(waitid) treats infop == NULL
     * as a documented 'don't write the siginfo back' form (the syscall
     * still reaps and returns the same status, just skips the
     * unsafe_put_user block):
     *
     *   if (!infop) return err;
     *   user_access_begin();
     *   unsafe_put_user(signo, &infop->si_signo, Efault);
     *   ...
     *
     * This is how libc waitid wrappers compiled with !__USE_GNU pass
     * NULL when the caller only wants the side effect of reaping the
     * child. The previous Futura EFAULT diverged from that contract
     * and broke probes that check 'kernel honours the NULL form'. Keep
     * EFAULT for non-NULL but unmapped pointers so genuine fault classes
     * still surface; just allow NULL to pass through to the wait. */
    if (infop && waitid_access_ok(infop, sizeof(siginfo_t)) != 0) {
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
            /* Linux's kernel_waitid rejects P_PGID with a negative id
             * (the previous code silently re-mapped it to 0 == 'caller's
             * pgroup', so e.g. waitid(P_PGID, -1, ...) returned children
             * from the wrong group instead of EINVAL). id == 0 is the
             * documented 'caller's process group' shortcut. */
            if (id < 0) {
                fut_printf("[WAITID] waitid(P_PGID, id=%d) -> EINVAL (negative id)\n", id);
                return -EINVAL;
            }
            wait_pid = (id > 0) ? -id : 0;
            break;
        default:
            return -EINVAL;
    }

    /* Build waitpid flags — pass through WNOHANG, WNOWAIT, WSTOPPED, WCONTINUED */
    int wait_flags = 0;
    if (options & WNOHANG)    wait_flags |= WNOHANG;     /* 0x1 */
    if (options & WNOWAIT)    wait_flags |= WNOWAIT;     /* 0x01000000 */
    if (options & WSTOPPED)   wait_flags |= WUNTRACED;   /* WUNTRACED = 0x2 */
    if (options & WCONTINUED) wait_flags |= WCONTINUED;  /* 0x8 */

    /* Call the extended wait implementation (returns uid for si_uid) */
    int status = 0;
    uint32_t child_uid = 0;
    int child_pid = fut_task_waitpid_ex(wait_pid, &status, wait_flags, &child_uid);

    if (child_pid < 0) {
        /* -ECHILD, -EINTR, etc. */
        fut_printf("[WAITID] waitid(%s, id=%d, options=0x%x) -> %d\n",
                   idtype_desc, id, options, child_pid);
        return child_pid;
    }

    if (child_pid == 0) {
        /* WNOHANG and no child ready: fill infop with zeros (si_pid=0 signals no event).
         * Skip the writeback when infop is NULL (Linux 'don't write' form). */
        if (infop) {
            siginfo_t info_zero;
            memset(&info_zero, 0, sizeof(info_zero));
            if (waitid_copy_to_user(infop, &info_zero, sizeof(siginfo_t)) != 0) {
                return -EFAULT;
            }
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
        info.si_code   = (status & 0x80) ? CLD_DUMPED : CLD_KILLED;
        info.si_status = WTERMSIG(status);
    } else if (WIFSTOPPED(status)) {
        info.si_code   = CLD_STOPPED;
        info.si_status = WSTOPSIG(status);
    } else if (WIFCONTINUED(status)) {
        info.si_code   = CLD_CONTINUED;
        info.si_status = SIGCONT;
    } else {
        info.si_code   = CLD_EXITED;
        info.si_status = 0;
    }

    info.si_pid = (int64_t)child_pid;
    info.si_uid = (int64_t)child_uid;  /* real UID of child at exit time */

    if (infop && waitid_copy_to_user(infop, &info, sizeof(siginfo_t)) != 0) {
        return -EFAULT;
    }

    fut_printf("[WAITID] waitid(%s, id=%d, options=0x%x) -> 0 "
               "(child_pid=%d, uid=%u, code=%s, status=%d%s)\n",
               idtype_desc, id, options, child_pid, child_uid,
               (info.si_code == CLD_EXITED) ? "CLD_EXITED" :
               (info.si_code == CLD_DUMPED) ? "CLD_DUMPED" :
               (info.si_code == CLD_STOPPED) ? "CLD_STOPPED" :
               (info.si_code == CLD_CONTINUED) ? "CLD_CONTINUED" : "CLD_KILLED",
               info.si_status,
               (options & WNOWAIT) ? ", peek" : "");
    return 0;
}
