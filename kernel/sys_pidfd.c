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
    if (pid <= 0)
        return -EINVAL;
    if (flags & ~PIDFD_NONBLOCK)
        return -EINVAL;

    /* Verify process exists */
    fut_task_t *task = fut_task_by_pid((uint64_t)pid);
    if (!task)
        return -ESRCH;

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

    /* Apply PIDFD_NONBLOCK if requested */
    if (flags & PIDFD_NONBLOCK) {
        fut_task_t *cur = fut_task_current();
        if (cur && cur->fd_table && fd < cur->max_fds && cur->fd_table[fd])
            cur->fd_table[fd]->flags |= 0x800; /* O_NONBLOCK */
    }

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
    (void)info;  /* siginfo_t contents not used for basic signal delivery */

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

    /* Find target task */
    fut_task_t *target = fut_task_by_pid((uint64_t)target_pid);
    if (!target)
        return -ESRCH;

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
 * to be open in that process. In Linux this requires PTRACE_MODE_ATTACH;
 * Futura allows it for any process (no ptrace credential model yet).
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

    /* Look up targetfd in the target task */
    if (!target->fd_table || targetfd >= target->max_fds)
        return -EBADF;
    struct fut_file *file = vfs_get_file_from_task(target, targetfd);
    if (!file)
        return -EBADF;

    /* Find a free FD slot in the current task, respecting RLIMIT_NOFILE */
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

    /* Install a reference to the file in the current task */
    vfs_file_ref(file);
    cur->fd_table[newfd] = file;
    if (cur->fd_flags) cur->fd_flags[newfd] = 0;

    return newfd;
}
