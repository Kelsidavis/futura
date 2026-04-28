/* kernel/sys_signalfd.c - Signal file descriptor syscalls
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 -- see LICENSE for details.
 *
 * Implements signalfd and signalfd4 syscalls for signal-driven I/O.
 * Signals matching a caller-specified mask are intercepted from the normal
 * delivery path and queued for retrieval via read(2), enabling integration
 * with epoll/poll/select event loops.
 *
 * Signal interception:
 *   When fut_signal_send() delivers a signal whose bit is set in an
 *   open signalfd's mask, the signal remains in task->pending_signals
 *   and the signalfd's read waitqueue + epoll notify are woken.
 *   signalfd_read_op() then atomically consumes the pending bit and
 *   returns a struct signalfd_siginfo (128 bytes) to userspace.
 *
 * Lifecycle:
 *   signalfd4(fd=-1, mask, size, flags)  -> create new signalfd
 *   signalfd4(fd>=0, mask, size, flags)  -> update existing mask
 *   signalfd(fd, mask, size)             -> signalfd4 with flags=0
 *   read(fd, buf, n)                     -> dequeue matching signals
 *   poll/epoll                           -> POLLIN when signals pending
 *   close(fd)                            -> release signalfd resources
 */

#include <kernel/chrdev.h>
#include <kernel/errno.h>
#include <kernel/eventfd.h>
#include <kernel/fut_memory.h>
#include <kernel/fut_sched.h>
#include <kernel/fut_task.h>
#include <kernel/fut_thread.h>
#include <kernel/fut_vfs.h>
#include <kernel/fut_waitq.h>
#include <kernel/uaccess.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdint.h>
#include <sys/epoll.h>

#include <kernel/kprintf.h>

#include <platform/platform.h>  /* KERNEL_VIRTUAL_BASE: do NOT fall back to a
                                 * hardcoded x86_64 constant — on ARM64 the
                                 * kernel half starts at 0xFFFF800000000000,
                                 * not 0xFFFFFFFF80000000, so a hardcoded
                                 * x86 default would skip the kernel-pointer
                                 * bypass for ARM64 kernel addresses. */

/* ---- user/kernel copy helpers ------------------------------------------ */

static inline int sfd_copy_to_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)dst >= KERNEL_VIRTUAL_BASE) { __builtin_memcpy(dst, src, n); return 0; }
#endif
    return fut_copy_to_user(dst, src, n);
}

static inline int sfd_copy_from_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)src >= KERNEL_VIRTUAL_BASE) { __builtin_memcpy(dst, src, n); return 0; }
#endif
    return fut_copy_from_user(dst, src, n);
}

/* ---- signalfd flags ---------------------------------------------------- */

#define SFD_CLOEXEC     02000000   /* 0x80000 */
#define SFD_NONBLOCK    00004000   /* 0x800   */

#ifndef FD_CLOEXEC
#define FD_CLOEXEC      1
#endif

/* ---- POSIX signalfd_siginfo -- 128 bytes (Linux x86-64 ABI) ------------ */

struct signalfd_siginfo {
    uint32_t ssi_signo;
    int32_t  ssi_errno;
    int32_t  ssi_code;
    uint32_t ssi_pid;
    uint32_t ssi_uid;
    int32_t  ssi_fd;
    uint32_t ssi_tid;
    uint32_t ssi_band;
    uint32_t ssi_overrun;
    uint32_t ssi_trapno;
    int32_t  ssi_status;
    int32_t  ssi_int;
    uint64_t ssi_ptr;
    uint64_t ssi_utime;
    uint64_t ssi_stime;
    uint64_t ssi_addr;
    uint16_t ssi_addr_lsb;
    uint16_t __pad2;
    int32_t  ssi_syscall;
    uint64_t ssi_call_addr;
    uint32_t ssi_arch;
    uint8_t  __pad[28];
};

/* ---- signalfd context and per-fd state --------------------------------- */

struct signalfd_ctx {
    uint64_t sigmask;           /* Signals this fd will dequeue */
    fut_task_t *task;           /* Owning task */
    fut_waitq_t read_waitq;     /* Threads blocked in read() */
    fut_spinlock_t lock;
    fut_waitq_t *epoll_notify;  /* Wakes epoll/poll/select when signal arrives */
};

struct signalfd_file {
    struct signalfd_ctx *ctx;
    struct fut_file *file;
};

/* ---- forward declarations ---------------------------------------------- */

static ssize_t signalfd_read_op(void *inode, void *priv,
                                void *u_buf, size_t len, off_t *pos);
static int signalfd_release(void *inode, void *priv);

/* Global fops structure -- non-static so sys_eventfd.c (fut_chrdev_fstat_mode)
 * and epoll/poll/select can compare chr_ops pointers. */
struct fut_file_ops signalfd_fops;

/* ============================================================
 *   signalfd read -- dequeue signals as signalfd_siginfo
 * ============================================================ */

/**
 * signalfd_read_op - Read pending signals matching the signalfd mask.
 *
 * Returns one struct signalfd_siginfo (128 bytes) per consumed signal.
 * Blocks if no matching signals are pending (unless O_NONBLOCK).
 * Multiple siginfos are returned when the buffer is large enough and
 * multiple matching signals are pending.
 */
static ssize_t signalfd_read_op(void *inode, void *priv,
                                void *u_buf, size_t len, off_t *pos) {
    (void)inode; (void)pos;
    struct signalfd_file *sfile = (struct signalfd_file *)priv;
    if (!sfile || !sfile->ctx) return -EBADF;
    struct signalfd_ctx *ctx = sfile->ctx;
    fut_task_t *task = ctx->task;
    if (!task) return -ESRCH;

    if (len < sizeof(struct signalfd_siginfo)) return -EINVAL;

    ssize_t total = 0;
    uint8_t *out = (uint8_t *)u_buf;
    size_t remain = len;

    while (remain >= sizeof(struct signalfd_siginfo)) {
        /* Find lowest-numbered pending signal in our mask.
         *
         * Linux's signalfd_dequeue calls dequeue_signal() which checks
         * BOTH per-task and per-thread pending masks; otherwise a
         * signal sent via tgkill / pthread_kill (which lands in
         * thread_pending_signals) is invisible to signalfd_read on the
         * targeted thread.  The previous code only consulted
         * task->pending_signals, so tgkill targets reported a
         * permanent EINTR (via the fast-path block-check below) and
         * never delivered the siginfo through the fd.  We dequeue from
         * the matching queue so the right siginfo_t is read out. */
        uint64_t pending;
        bool from_thread = false;
        fut_spinlock_acquire(&ctx->lock);
        pending = task->pending_signals & ctx->sigmask;
        if (!pending) {
            fut_thread_t *cur_thr = fut_thread_current();
            if (cur_thr) {
                uint64_t tp = __atomic_load_n(&cur_thr->thread_pending_signals,
                                              __ATOMIC_ACQUIRE);
                pending = tp & ctx->sigmask;
                if (pending)
                    from_thread = true;
            }
        }
        fut_spinlock_release(&ctx->lock);

        if (!pending) {
            /* No matching signals */
            if (total > 0) break;  /* Already returned some -- don't block */
            if (sfile->file && (sfile->file->flags & O_NONBLOCK))
                return -EAGAIN;
            /* Check for pending unblocked process signals -> EINTR.
             * Include thread_pending_signals so a tgkill / pthread_kill
             * targeted at this thread fires EINTR. */
            {
                fut_task_t *stask = fut_task_current();
                if (stask) {
                    uint64_t ppend = __atomic_load_n(&stask->pending_signals, __ATOMIC_ACQUIRE);
                    fut_thread_t *scur_thr = fut_thread_current();
                    if (scur_thr)
                        ppend |= __atomic_load_n(&scur_thr->thread_pending_signals, __ATOMIC_ACQUIRE);
                    uint64_t blocked = scur_thr ?
                        __atomic_load_n(&scur_thr->signal_mask, __ATOMIC_ACQUIRE) :
                        __atomic_load_n(&stask->signal_mask, __ATOMIC_ACQUIRE);
                    if (ppend & ~blocked)
                        return -EINTR;
                }
            }
            /* Block on task's signal waitq -- woken by fut_signal_send().
             *
             * Lost-wakeup avoidance: a signal could arrive between the
             * pending check above (after we released ctx->lock) and the
             * point at which we put ourselves on signal_waitq. The wake
             * call from fut_signal_send would hit an empty waitq, and
             * then we'd queue ourselves and sleep forever for the next
             * signal that may never come. Re-check pending under the
             * waitq lock; if a signal landed in the gap, drop the lock
             * and re-enter the outer loop to consume it. */
            fut_spinlock_acquire(&task->signal_waitq.lock);
            uint64_t recheck = __atomic_load_n(&task->pending_signals, __ATOMIC_ACQUIRE)
                               & ctx->sigmask;
            if (recheck) {
                fut_spinlock_release(&task->signal_waitq.lock);
                continue;
            }
            fut_waitq_sleep_locked(&task->signal_waitq, &task->signal_waitq.lock, FUT_THREAD_BLOCKED);
            continue;
        }

        /* Take lowest set bit */
        int signo = __builtin_ctzll(pending) + 1;  /* signals are 1-based */
        uint64_t bit = 1ULL << (signo - 1);

        /* Atomically consume the signal from the matching queue.
         * For thread-pending (tgkill/pthread_kill) signals, we dequeue
         * from thread_pending_signals; for task-wide (kill/raise) we
         * dequeue from task->pending_signals. */
        fut_thread_t *cur_thr_dq = fut_thread_current();
        fut_spinlock_acquire(&ctx->lock);
        if (from_thread && cur_thr_dq) {
            if (!(cur_thr_dq->thread_pending_signals & bit)) {
                fut_spinlock_release(&ctx->lock);
                continue;
            }
            __atomic_and_fetch(&cur_thr_dq->thread_pending_signals,
                               ~bit, __ATOMIC_RELEASE);
        } else {
            /* Re-check: another reader may have taken it */
            if (!(task->pending_signals & bit)) {
                fut_spinlock_release(&ctx->lock);
                continue;
            }
            task->pending_signals &= ~bit;
        }
        fut_spinlock_release(&ctx->lock);

        /* Fill in signalfd_siginfo from the per-signal queue info.
         * Linux copies all available siginfo_t fields so applications
         * (e.g. SIGCHLD handlers, timer consumers) get complete data.
         * Per-thread signals carry their own queue info; pull from the
         * right place so si_pid / si_uid reflect the tgkill sender. */
        struct signalfd_siginfo info;
        __builtin_memset(&info, 0, sizeof(info));
        const siginfo_t *qi = (from_thread && cur_thr_dq)
            ? &cur_thr_dq->thread_sig_queue_info[signo - 1]
            : &task->sig_queue_info[signo - 1];
        info.ssi_signo   = (uint32_t)signo;
        info.ssi_errno   = qi->si_errno;
        info.ssi_code    = qi->si_code;
        info.ssi_pid     = (uint32_t)qi->si_pid;
        info.ssi_uid     = qi->si_uid;
        info.ssi_status  = qi->si_status;
        info.ssi_int     = (int32_t)qi->si_value;
        info.ssi_ptr     = (uint64_t)qi->si_value;
        info.ssi_addr    = (uint64_t)(uintptr_t)qi->si_addr;
        info.ssi_overrun = (uint32_t)qi->si_overrun;

        if (sfd_copy_to_user(out, &info, sizeof(info)) != 0)
            return total > 0 ? total : -EFAULT;

        out    += sizeof(info);
        remain -= sizeof(info);
        total  += (ssize_t)sizeof(info);
    }

    return total;
}

/* ============================================================
 *   signalfd release -- cleanup on close()
 * ============================================================ */

static int signalfd_release(void *inode, void *priv) {
    (void)inode;
    struct signalfd_file *sfile = (struct signalfd_file *)priv;
    if (!sfile) return 0;
    if (sfile->ctx) fut_free(sfile->ctx);
    fut_free(sfile);
    return 0;
}

/* ============================================================
 *   sys_signalfd4 -- create or update a signalfd
 * ============================================================ */

/**
 * sys_signalfd4 - Create or update a signal notification file descriptor.
 *
 * @param ufd:      -1 to create new fd, or existing signalfd to update its mask
 * @param mask:     Pointer to signal mask (uint64_t bitmask, sizemask bytes)
 * @param sizemask: Size of mask in bytes (must be >= 4)
 * @param flags:    SFD_CLOEXEC (0x80000), SFD_NONBLOCK (0x800)
 *
 * signalfd allows receiving signals via read() instead of signal handlers.
 * When a signal matching the mask is delivered to the process, instead of
 * invoking the handler, it is queued for the signalfd to deliver via read().
 * This enables integration with epoll/poll/select event loops.
 *
 * Returns:
 *   - File descriptor on success
 *   - -EINVAL if flags or mask invalid
 *   - -EBADF if ufd does not refer to a signalfd
 */
long sys_signalfd4(int ufd, const void *mask, size_t sizemask, int flags) {
    fut_task_t *task = fut_task_current();
    if (!task) return -ESRCH;

    static int signalfd_fops_inited = 0;
    if (!signalfd_fops_inited) {
        signalfd_fops.open = NULL;
        signalfd_fops.release = signalfd_release;
        signalfd_fops.read = signalfd_read_op;
        signalfd_fops.write = NULL;
        signalfd_fops.ioctl = NULL;
        signalfd_fops.mmap = NULL;
        signalfd_fops_inited = 1;
    }

    /* Validate flags -- reject any bits not in SFD_CLOEXEC | SFD_NONBLOCK */
    int valid_flags = SFD_CLOEXEC | SFD_NONBLOCK;
    if (flags & ~valid_flags) return -EINVAL;

    /* Linux splits these two failure modes: EINVAL for bad sigsetsize,
     * EFAULT for a bad pointer. The previous combined NULL+EINVAL gate
     * collapsed pointer faults into parameter-domain errors. */
    /* Linux's fs/signalfd.c:signalfd4 requires sizemask == sizeof(sigset_t)
     * (8 bytes for the 64-bit syscall ABI), not >= 4. The previous laxer
     * check accepted 4-byte masks and silently zero-extended to 64 bits;
     * that breaks ABI parity for libc wrappers that probe for "kernel
     * supports the modern 8-byte sigset" and treat any non-EINVAL as a
     * yes. Match Linux's strict equality gate. */
    if (sizemask != sizeof(uint64_t)) return -EINVAL;
    if (!mask) return -EFAULT;
    uint64_t sigmask = 0;
    if (sfd_copy_from_user(&sigmask, mask, sizeof(sigmask)) != 0) return -EFAULT;

    /* SIGKILL and SIGSTOP cannot be caught via signalfd (POSIX) */
    sigmask &= ~((1ULL << (9  - 1)) |   /* SIGKILL */
                 (1ULL << (19 - 1)));    /* SIGSTOP */

    /* ---- Update-mask case: ufd refers to an existing signalfd ---- */
    if (ufd != -1) {
        if (!task->fd_table || ufd < 0 || ufd >= task->max_fds) return -EBADF;
        struct fut_file *file = task->fd_table[ufd];
        if (!file || file->chr_ops != &signalfd_fops || !file->chr_private)
            return -EBADF;
        struct signalfd_file *sfile = (struct signalfd_file *)file->chr_private;
        if (!sfile->ctx) return -EBADF;
        fut_spinlock_acquire(&sfile->ctx->lock);
        sfile->ctx->sigmask = sigmask;
        fut_spinlock_release(&sfile->ctx->lock);
        return ufd;
    }

    /* ---- Create new signalfd ---- */
    struct signalfd_ctx *ctx = fut_malloc(sizeof(struct signalfd_ctx));
    if (!ctx) return -ENOMEM;
    ctx->sigmask       = sigmask;
    ctx->task          = task;
    ctx->epoll_notify  = NULL;
    fut_spinlock_init(&ctx->lock);
    fut_waitq_init(&ctx->read_waitq);

    struct signalfd_file *sfile = fut_malloc(sizeof(struct signalfd_file));
    if (!sfile) {
        fut_free(ctx);
        return -ENOMEM;
    }
    sfile->ctx  = ctx;
    sfile->file = NULL;

    int fd = chrdev_alloc_fd(&signalfd_fops, NULL, sfile);
    if (fd < 0) {
        fut_free(ctx);
        fut_free(sfile);
        return fd;
    }

    /* Attach fut_file pointer back into context */
    if (task->fd_table && fd >= 0 && fd < task->max_fds)
        sfile->file = task->fd_table[fd];

    if (!sfile->file) {
        fut_vfs_close(fd);
        return -EFAULT;
    }

    if (flags & SFD_NONBLOCK) sfile->file->flags    |= O_NONBLOCK;
    if (flags & SFD_CLOEXEC) {
        if (task->fd_flags && fd < task->max_fds)
            task->fd_flags[fd] |= FD_CLOEXEC;
    }

    return fd;
}

/* ============================================================
 *   poll/epoll/select support
 * ============================================================ */

/**
 * fut_signalfd_poll - Query readiness for a signalfd file descriptor.
 *
 * Returns POLLIN/EPOLLRDNORM when pending signals match the signalfd mask.
 * Called by epoll_wait, poll, and select to check readability.
 *
 * @param file        Kernel file structure to test.
 * @param requested   Bitmask of EPOLL* events being requested.
 * @param ready_out   Optional pointer that receives the ready mask.
 * @return true if file refers to a signalfd, false otherwise.
 */
bool fut_signalfd_poll(struct fut_file *file, uint32_t requested, uint32_t *ready_out) {
    if (!file || file->chr_private == NULL || file->chr_ops != &signalfd_fops) {
        return false;
    }
    struct signalfd_file *sfile = (struct signalfd_file *)file->chr_private;
    struct signalfd_ctx *ctx = sfile->ctx;
    if (!ctx || !ctx->task) return false;

    uint32_t ready = 0;
    fut_spinlock_acquire(&ctx->lock);
    uint64_t pending = ctx->task->pending_signals & ctx->sigmask;
    if (pending != 0 && (requested & (EPOLLIN | EPOLLRDNORM))) {
        ready |= (EPOLLIN | EPOLLRDNORM);
    }
    fut_spinlock_release(&ctx->lock);

    if (ready_out) *ready_out = ready;
    return true;
}

/**
 * fut_signalfd_set_epoll_notify - Wire/unwire epoll notification on a signalfd.
 *
 * Called from epoll_ctl ADD, poll_wire_fds(), and select wiring.
 * Pass wq=NULL to unwire (e.g. on EPOLL_CTL_DEL or fd close).
 */
void fut_signalfd_set_epoll_notify(struct fut_file *file, fut_waitq_t *wq) {
    if (!file || file->chr_private == NULL || file->chr_ops != &signalfd_fops)
        return;
    struct signalfd_file *sfile = (struct signalfd_file *)file->chr_private;
    if (!sfile || !sfile->ctx)
        return;
    sfile->ctx->epoll_notify = wq;
}

/**
 * fut_signalfd_wake_epoll - Wake epoll watchers when a signal arrives.
 *
 * Called by fut_signal_send() after setting the pending bit and waking
 * task->signal_waitq. Walks the task's fd_table looking for signalfd FDs
 * whose mask covers the delivered signal, and wakes their epoll_notify.
 */
void fut_signalfd_wake_epoll(fut_task_t *task, int signo) {
    if (!task || !task->fd_table || signo < 1 || signo > 64)
        return;
    uint64_t bit = 1ULL << (signo - 1);
    for (int i = 0; i < (int)task->max_fds; i++) {
        struct fut_file *f = task->fd_table[i];
        if (!f || f->chr_ops != &signalfd_fops || !f->chr_private)
            continue;
        struct signalfd_file *sfile = (struct signalfd_file *)f->chr_private;
        if (!sfile->ctx)
            continue;
        if (!(sfile->ctx->sigmask & bit))
            continue;
        if (sfile->ctx->epoll_notify)
            fut_waitq_wake_one(sfile->ctx->epoll_notify);
    }
}

/* ---- fdinfo helper (used by procfs) ------------------------------------ */

/**
 * fut_signalfd_get_sigmask - Read signalfd sigmask for /proc/<pid>/fdinfo/<n>.
 * Returns the signal mask as a 64-bit word, or 0 if not a signalfd.
 */
uint64_t fut_signalfd_get_sigmask(struct fut_file *file) {
    if (!file || file->chr_ops != &signalfd_fops || !file->chr_private)
        return 0;
    struct signalfd_file *sfile = (struct signalfd_file *)file->chr_private;
    if (!sfile->ctx)
        return 0;
    return sfile->ctx->sigmask;
}
