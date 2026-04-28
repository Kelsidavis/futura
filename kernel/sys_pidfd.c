/* kernel/sys_pidfd.c - pidfd_open / pidfd_send_signal / pidfd_getfd
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements process file descriptors (Linux 5.2+).
 * pidfd_open(pid, flags) creates an FD that references a process.
 * pidfd_send_signal(pidfd, sig, info, flags) sends a signal via that FD.
 * pidfd_getfd(pidfd, targetfd, flags) duplicates an FD from another process.
 *
 * Phase 1 (Completed): pidfd_open and pidfd_send_signal.
 * Phase 2 (Completed): pidfd_getfd — duplicate another process's FD.
 */

#include <kernel/chrdev.h>
#include <kernel/errno.h>
#include <kernel/fut_memory.h>
#include <kernel/fut_task.h>
#include <kernel/fut_vfs.h>
#include <kernel/fut_waitq.h>
#include <kernel/kprintf.h>
#include <kernel/signal.h>
#include <kernel/uaccess.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <platform/platform.h>

/* pidfd context: remembers the PID at open time */
struct pidfd_ctx {
    int          pid;
    fut_waitq_t *epoll_notify;  /* set by epoll/poll/select to receive wakeup */
};

/* Forward declaration so pidfd_fops can reference it */
static int pidfd_release(void *inode, void *priv);

static struct fut_file_ops pidfd_fops;

static int pidfd_release(void *inode, void *priv) {
    (void)inode;
    struct pidfd_ctx *ctx = (struct pidfd_ctx *)priv;
    if (ctx) {
        /* Remove from task's notify array before freeing */
        if (ctx->epoll_notify) {
            fut_task_t *task = fut_task_by_pid((uint64_t)ctx->pid);
            if (task) {
                fut_spinlock_acquire(&task->pidfd_notify_lock);
                for (int i = 0; i < FUT_PIDFD_NOTIFY_MAX; i++) {
                    if (task->pidfd_notify[i] == ctx->epoll_notify) {
                        task->pidfd_notify[i] = NULL;
                        break;
                    }
                }
                fut_spinlock_release(&task->pidfd_notify_lock);
            }
        }
        fut_free(ctx);
    }
    return 0;
}

/**
 * fut_pidfd_set_epoll_notify - Register or clear an epoll/poll/select waitq for a pidfd.
 *
 * Called with wq != NULL to register (epoll_ctl ADD / poll wire-up) and with
 * wq == NULL to unregister (unwire after poll/select returns).
 * No-op if file is not a pidfd.
 */
void fut_pidfd_set_epoll_notify(struct fut_file *file, fut_waitq_t *wq) {
    if (!file || file->chr_ops != &pidfd_fops || !file->chr_private)
        return;
    struct pidfd_ctx *ctx = (struct pidfd_ctx *)file->chr_private;

    fut_task_t *task = fut_task_by_pid((uint64_t)ctx->pid);

    if (wq) {
        /* Register: add to task's notify array */
        ctx->epoll_notify = wq;
        if (task) {
            /* If already zombie, fire immediately */
            if (task->state == FUT_TASK_ZOMBIE) {
                fut_waitq_wake_all(wq);
                return;
            }
            fut_spinlock_acquire(&task->pidfd_notify_lock);
            for (int i = 0; i < FUT_PIDFD_NOTIFY_MAX; i++) {
                if (task->pidfd_notify[i] == NULL) {
                    task->pidfd_notify[i] = wq;
                    break;
                }
            }
            fut_spinlock_release(&task->pidfd_notify_lock);
        }
    } else {
        /* Unregister: remove from task's notify array */
        if (task && ctx->epoll_notify) {
            fut_spinlock_acquire(&task->pidfd_notify_lock);
            for (int i = 0; i < FUT_PIDFD_NOTIFY_MAX; i++) {
                if (task->pidfd_notify[i] == ctx->epoll_notify) {
                    task->pidfd_notify[i] = NULL;
                    break;
                }
            }
            fut_spinlock_release(&task->pidfd_notify_lock);
        }
        ctx->epoll_notify = NULL;
    }
}

/**
 * fut_pidfd_poll - Check pidfd readiness for epoll/poll/select.
 * Returns true if handled (file is a pidfd), false otherwise.
 * Sets *ready_out to POLLIN (1) when the process has exited.
 */
bool fut_pidfd_poll(struct fut_file *file, uint32_t requested, uint32_t *ready_out) {
    if (!file || file->chr_ops != &pidfd_fops || !file->chr_private)
        return false;
    struct pidfd_ctx *ctx = (struct pidfd_ctx *)file->chr_private;
    fut_task_t *task = fut_task_by_pid((uint64_t)ctx->pid);
    /* POLLIN is ready when the process no longer exists or is a zombie */
    if (!task || task->state == FUT_TASK_ZOMBIE) {
        if (requested & (1u /* POLLIN */ | 0x2000u /* EPOLLRDHUP */))
            *ready_out |= 1u; /* POLLIN */
    }
    return true;
}

/* pidfd_open flags */
#define PIDFD_NONBLOCK  0x800

/**
 * sys_pidfd_open - Open a file descriptor for a process.
 *
 * @param pid    Target PID (must be > 0)
 * @param flags  PIDFD_NONBLOCK or 0
 * @return New file descriptor, or -errno
 */
long sys_pidfd_open(int pid, unsigned int flags) {
    if (!pidfd_fops.release) {
        pidfd_fops.release = pidfd_release;
    }
    /* Linux kernel/pid.c:sys_pidfd_open validates flags FIRST, then pid:
     *
     *   if (flags & ~(PIDFD_NONBLOCK | PIDFD_THREAD)) return -EINVAL;
     *   if (pid <= 0) return -EINVAL;
     *
     * Both branches return -EINVAL, so the observable effect on a single
     * input is the same.  But callers walking the flag space with a
     * fixed bad pid (or vice versa) get a more consistent class signal
     * by hitting the same gate Linux does.  Match the order. */
    if (flags & ~PIDFD_NONBLOCK)
        return -EINVAL;
    if (pid <= 0)
        return -EINVAL;

    /* Verify process exists.  Linux distinguishes two failure cases:
     *   - pid does not exist at all                 -> ESRCH
     *   - pid exists but is a non-leader thread TID -> EINVAL
     *     (because pidfd_open without PIDFD_THREAD requires a
     *     thread-group leader; pid_has_task(p, PIDTYPE_TGID)).
     *
     * The previous Futura code only consulted fut_task_by_pid (which
     * finds TGIDs), so a caller passing a non-leader TID got ESRCH —
     * indistinguishable from "process doesn't exist".  Linux returns
     * EINVAL there so userspace can detect "you passed me a TID, you
     * probably wanted PIDFD_THREAD or the process's TGID".  Walk the
     * thread table to surface the EINVAL case. */
    fut_task_t *task = fut_task_by_pid((uint64_t)pid);
    if (!task) {
        extern fut_thread_t *fut_thread_find(uint64_t tid);
        if (fut_thread_find((uint64_t)pid))
            return -EINVAL;
        return -ESRCH;
    }

    struct pidfd_ctx *ctx = fut_malloc(sizeof(struct pidfd_ctx));
    if (!ctx)
        return -ENOMEM;
    ctx->pid = pid;
    ctx->epoll_notify = NULL;

    int fd = chrdev_alloc_fd(&pidfd_fops, NULL, ctx);
    if (fd < 0) {
        fut_free(ctx);
        return fd;
    }

    fut_task_t *cur = fut_task_current();

    /* Apply PIDFD_NONBLOCK if requested */
    if ((flags & PIDFD_NONBLOCK) && cur && cur->fd_table && fd < cur->max_fds &&
        cur->fd_table[fd])
        cur->fd_table[fd]->flags |= 0x800; /* O_NONBLOCK */

    /* Linux pidfd_open(2) always returns the pidfd with FD_CLOEXEC set:
     * 'The returned file descriptor has the close-on-exec flag set.'
     * The previous code never set it, so an exec across the pidfd would
     * leak the process-reference fd into the new program (silent
     * privilege transfer for any pidfd a setuid wrapper had open). */
    if (cur && cur->fd_flags && fd < cur->max_fds)
        cur->fd_flags[fd] |= 1 /* FD_CLOEXEC */;

    return fd;
}

/**
 * pidfd_get_pid - Extract the PID from a pidfd file descriptor.
 *
 * Used by waitid(P_PIDFD, fd, ...) to convert a pidfd to a PID.
 *
 * @param fd  File descriptor returned by pidfd_open()
 * @return    PID (> 0) on success, -EBADF if fd is not a valid pidfd
 */
int pidfd_get_pid(int fd) {
    fut_task_t *task = fut_task_current();
    if (!task || !task->fd_table || fd < 0 || fd >= task->max_fds)
        return -EBADF;
    struct fut_file *file = task->fd_table[fd];
    if (!file || file->chr_ops != &pidfd_fops)
        return -EBADF;
    struct pidfd_ctx *ctx = (struct pidfd_ctx *)file->chr_private;
    if (!ctx)
        return -EBADF;
    return ctx->pid;
}

/**
 * sys_pidfd_send_signal - Send a signal to a process via its pidfd.
 *
 * @param pidfd  File descriptor from pidfd_open
 * @param sig    Signal number (0 = existence check only)
 * @param info   Pointer to siginfo_t (may be NULL)
 * @param flags  Must be 0
 * @return 0 on success, -errno on error
 */
long sys_pidfd_send_signal(int pidfd, int sig, const void *info, unsigned int flags) {
    if (flags != 0)
        return -EINVAL;
    if (sig < 0 || sig > 64)
        return -EINVAL;

    fut_task_t *task = fut_task_current();
    if (!task) return -ESRCH;

    /* Look up the pidfd */
    if (!task->fd_table || pidfd < 0 || pidfd >= task->max_fds)
        return -EBADF;
    struct fut_file *file = task->fd_table[pidfd];
    if (!file || file->chr_ops != &pidfd_fops || !file->chr_private)
        return -EBADF;

    struct pidfd_ctx *ctx = (struct pidfd_ctx *)file->chr_private;
    int target_pid = ctx->pid;

    /* Linux's pidfd_send_signal copies siginfo from user when info != NULL
     * and enforces two invariants:
     *   1. info->si_signo must equal the 'sig' argument (else -EINVAL) —
     *      prevents the caller from claiming to send signal X while
     *      actually faking signal Y in si_signo.
     *   2. For a cross-task target, si_code must be one of the user-
     *      generated codes (SI_USER = 0, SI_QUEUE = -1).  Kernel-generated
     *      codes (>= 0 except SI_USER itself, or SI_TKILL = -6) would
     *      let a caller spoof 'sent by the kernel' / 'sent by tgkill'
     *      to processes they shouldn't.  Sending to self is unrestricted.
     * The previous '(void)info' silently ignored both invariants, so
     * any unprivileged caller could pidfd_send_signal a peer with a
     * spoofed siginfo claiming kernel origin. */
    if (info) {
        struct mini_siginfo {
            int si_signo;
            int si_errno;
            int si_code;
            /* tail bytes ignored — we only validate the prefix */
        } kinfo;
#ifdef KERNEL_VIRTUAL_BASE
        if ((uintptr_t)info >= KERNEL_VIRTUAL_BASE) {
            __builtin_memcpy(&kinfo, info, sizeof(kinfo));
        } else
#endif
        if (fut_copy_from_user(&kinfo, info, sizeof(kinfo)) != 0)
            return -EFAULT;
        if (kinfo.si_signo != sig)
            return -EINVAL;
        /* For cross-task delivery, only user-origin codes are allowed.
         * SI_USER == 0, SI_QUEUE == -1.  Anything else (kernel-generated
         * positive codes like SI_KERNEL=0x80, or SI_TKILL=-6) is rejected
         * with EPERM unless the target is self. */
        if ((unsigned int)target_pid != task->pid &&
            kinfo.si_code != 0 /* SI_USER */ &&
            kinfo.si_code != -1 /* SI_QUEUE */)
            return -EPERM;
    }

    /* Find target task */
    fut_task_t *target = fut_task_by_pid((uint64_t)target_pid);
    if (!target)
        return -ESRCH;

    /* Permission check: Linux's kill_ok_by_cred uid-pair test — match
     * caller.{euid,ruid} against target.{uid,suid}. The previous gate
     * compared only against target.ruid, so a privilege-dropped daemon
     * (ruid kept at 0, euid moved to a regular user) was un-killable
     * by that user via pidfd despite Linux allowing it through both
     * kill(2) and pidfd_send_signal(2). Mirror sys_kill / sys_tgkill. */
    if (target != task &&
        task->ruid != 0 &&
        !(task->cap_effective & (1ULL << 5 /* CAP_KILL */))) {
        /* Linux's kill_ok_by_cred compares the caller's effective and
         * real uids against the target's saved and REAL uids:
         *
         *   return uid_eq(cred->euid, tcred->suid) ||
         *          uid_eq(cred->euid, tcred->uid)  ||  // tcred->uid == real
         *          uid_eq(cred->uid,  tcred->suid) ||
         *          uid_eq(cred->uid,  tcred->uid);
         *
         * The previous Futura check compared against target->uid
         * (effective) where Linux compares against target->ruid (real).
         * That made Futura more permissive than Linux: a setuid-down
         * target (ruid=0, euid=1000, suid=0) could be killed by an
         * unprivileged caller (ruid==1000) that matched the dropped
         * effective uid, even though Linux requires the match against
         * the saved or real uid.  Closes the same setuid-down kill
         * vector that the matching kill / tgkill paths already gate. */
        int ok = (task->ruid == target->ruid) ||
                 (task->ruid == target->suid) ||
                 (task->uid  == target->ruid) ||
                 (task->uid  == target->suid);
        if (!ok)
            return -EPERM;
    }

    /* sig == 0: existence check only */
    if (sig == 0)
        return 0;

    /* Deliver signal */
    fut_signal_send(target, sig);
    return 0;
}

/**
 * sys_pidfd_getfd - Duplicate an FD from another process via its pidfd.
 *
 * @param pidfd     File descriptor from pidfd_open (references target process)
 * @param targetfd  FD number in the target process to duplicate
 * @param flags     Must be 0 (no flags defined)
 * @return New FD in current process on success, -errno on error
 *
 * Linux 5.6+. Requires the pidfd to reference a live process and targetfd
 * to be open in that process. PTRACE_MODE_ATTACH equivalent: caller must
 * be root, hold CAP_SYS_PTRACE, or share the target's uid.
 */
long sys_pidfd_getfd(int pidfd, int targetfd, unsigned int flags) {
    if (flags != 0)
        return -EINVAL;
    if (targetfd < 0)
        return -EBADF;

    fut_task_t *cur = fut_task_current();
    if (!cur)
        return -ESRCH;

    /* Resolve pidfd → target PID */
    if (!cur->fd_table || pidfd < 0 || pidfd >= cur->max_fds)
        return -EBADF;
    struct fut_file *pf = cur->fd_table[pidfd];
    if (!pf || pf->chr_ops != &pidfd_fops || !pf->chr_private)
        return -EBADF;

    struct pidfd_ctx *ctx = (struct pidfd_ctx *)pf->chr_private;
    fut_task_t *target = fut_task_by_pid((uint64_t)ctx->pid);
    if (!target)
        return -ESRCH;

    /* PTRACE_MODE_ATTACH_REALCREDS equivalent: Linux's pidfd_getfd
     * goes through ptrace_may_access(PTRACE_MODE_ATTACH_REALCREDS),
     * which compares the caller's REAL uid (cred->uid) against ALL
     * THREE of the target's uids (real, effective, saved):
     *
     *   caller_uid = cred->uid;                  // REALCREDS
     *   if (uid_eq(caller_uid, tcred->euid) &&
     *       uid_eq(caller_uid, tcred->suid) &&
     *       uid_eq(caller_uid, tcred->uid))
     *       goto ok;
     *
     * Without this strict check, any unprivileged caller could
     * pidfd_open a root daemon (or a dropped-setuid victim still
     * holding suid==0) and duplicate its open fds (e.g. /dev/mem, an
     * authenticated socket, a raw block device) into its own fd
     * table — a direct privilege-escalation primitive.  Same
     * triple-match pattern as the recent ptrace / process_vm / kcmp
     * fixes. */
    if (cur->ruid != 0 &&
        !(cur->cap_effective & (1ULL << 19 /* CAP_SYS_PTRACE */)) &&
        (cur->ruid != target->uid  ||
         cur->ruid != target->ruid ||
         cur->ruid != target->suid))
        return -EPERM;

    /* Look up targetfd in the target task */
    if (!target->fd_table || targetfd >= target->max_fds)
        return -EBADF;
    struct fut_file *file = vfs_get_file_from_task(target, targetfd);
    if (!file)
        return -EBADF;

    /* Find a free FD slot in the current task, respecting RLIMIT_NOFILE.
     * Treat rlim_cur == 0 as 'unset' so kernel tasks with uninitialized
     * rlimits still get an fd. */
    int max = cur->max_fds;
    {
        uint64_t lim = cur->rlimits[7].rlim_cur; /* RLIMIT_NOFILE */
        if (lim > 0 && lim < (uint64_t)max)
            max = (int)lim;
    }
    int newfd = -1;
    for (int i = 0; i < max; i++) {
        if (!cur->fd_table[i]) { newfd = i; break; }
    }
    if (newfd < 0)
        return -EMFILE;

    /* Install a reference to the file in the current task. Linux's
     * pidfd_getfd(2) returns the fd with FD_CLOEXEC set ('the file
     * descriptor returned ... has the close-on-exec flag set'); without
     * it, an exec across the duplicated fd would silently leak it into
     * the new program. Mirror sys_pidfd_open's CLOEXEC default. */
    vfs_file_ref(file);
    cur->fd_table[newfd] = file;
    if (cur->fd_flags) cur->fd_flags[newfd] = 1 /* FD_CLOEXEC */;

    return newfd;
}
