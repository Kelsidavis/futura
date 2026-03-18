/* kernel/sys_pidfd.c - pidfd_open / pidfd_send_signal
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements process file descriptors (Linux 5.2+).
 * pidfd_open(pid, flags) creates an FD that references a process.
 * pidfd_send_signal(pidfd, sig, info, flags) sends a signal via that FD.
 *
 * Phase 1 (Completed): Full implementation.
 *   - pidfd_open: validates pid, finds task, allocates chrdev FD
 *   - pidfd_send_signal: looks up task by stored pid, calls fut_signal_send
 *   - pidfd_release: frees pidfd context
 */

#include <kernel/chrdev.h>
#include <kernel/errno.h>
#include <kernel/fut_memory.h>
#include <kernel/fut_task.h>
#include <kernel/fut_vfs.h>
#include <kernel/kprintf.h>
#include <kernel/signal.h>
#include <kernel/uaccess.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __x86_64__
#include <platform/x86_64/memory/paging.h>
#elif defined(__aarch64__)
#include <platform/arm64/memory/paging.h>
#endif

/* pidfd context: remembers the PID at open time */
struct pidfd_ctx {
    int pid;
};

static int pidfd_release(void *inode, void *priv) {
    (void)inode;
    struct pidfd_ctx *ctx = (struct pidfd_ctx *)priv;
    if (ctx) fut_free(ctx);
    return 0;
}

static const struct fut_file_ops pidfd_fops = {
    .open    = NULL,
    .release = pidfd_release,
    .read    = NULL,
    .write   = NULL,
    .ioctl   = NULL,
    .mmap    = NULL,
};

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
