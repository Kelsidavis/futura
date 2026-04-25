/* kernel/sys_mqueue.c - POSIX message queue syscalls
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements POSIX message queues: mq_open, mq_unlink, mq_timedsend,
 * mq_timedreceive, mq_notify, mq_getsetattr. Each queue is named
 * (starts with '/') and backed by an FD via chrdev_alloc_fd.
 *
 * Phase 1 (Completed):
 *   - Named queue creation/open/close/unlink
 *   - Priority-ordered send/receive (highest priority first)
 *   - Blocking send/receive with abs_timeout (ms-granular via ticks)
 *   - O_NONBLOCK support on both the queue and per-operation
 *   - mq_getsetattr: query/set O_NONBLOCK flag
 *   - Registered in x86_64 (240-245) and ARM64 (180-185) syscall tables
 *
 * Phase 2 (Completed):
 *   - mq_notify: one-shot SIGEV_SIGNAL and SIGEV_NONE notifications
 *   - Signal delivered when message arrives at empty queue, then cleared
 *   - EBUSY if another task is already registered
 */

#include <kernel/chrdev.h>
#include <kernel/errno.h>
#include <kernel/fut_memory.h>
#include <kernel/fut_sched.h>
#include <kernel/fut_task.h>
#include <kernel/fut_thread.h>
#include <kernel/fut_timer.h>
#include <kernel/fut_waitq.h>
#include <kernel/kprintf.h>
#include <kernel/uaccess.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <limits.h>
/* Include fut_vfs.h for struct fut_file with chr_ops/chr_private and O_* flags */
#include <kernel/fut_vfs.h>
#include <kernel/signal.h>
#include <shared/fut_sigevent.h>

/* Forward declaration: runtime-initialized in sys_mq_open */
static struct fut_file_ops mq_fops;

#include <platform/platform.h>

/* ---- POSIX mq_attr ABI structure ---------------------------------- */

struct mq_attr {
    long mq_flags;    /* 0 or O_NONBLOCK */
    long mq_maxmsg;   /* max queued messages */
    long mq_msgsize;  /* max bytes per message */
    long mq_curmsgs;  /* current messages (output, read-only) */
    long __pad[4];
};

/* ---- Limits ------------------------------------------------------- */

#define MQ_NAME_MAX   255
#define MQ_MAXMSG_DEF 10
#define MQ_MSGSIZE_DEF 8192
#define MQ_MAXMSG_LIMIT 1024
#define MQ_MSGSIZE_LIMIT (1024 * 1024)
#define MQ_PRIO_MAX   32768
#define MAX_MQUEUES   64

/* ---- Internal structures ------------------------------------------ */

/* Node in the priority-sorted message list (highest prio first) */
struct mq_node {
    unsigned    prio;
    size_t      len;
    struct mq_node *next;
    char        data[];   /* variable-length payload */
};

struct mqueue {
    char            name[MQ_NAME_MAX + 1];
    long            mq_maxmsg;
    long            mq_msgsize;
    atomic_long     mq_curmsgs;
    bool            unlinked;
    atomic_int      refcnt;
    struct mq_node *msgs;           /* priority list, head = highest prio */
    fut_spinlock_t  lock;
    fut_waitq_t     send_waitq;     /* waiters blocked on full queue (send side) */
    fut_waitq_t     recv_waitq;     /* waiters blocked on empty queue (recv side) */
    /* Phase 2: one-shot notification via mq_notify */
    uint64_t        notify_pid;     /* registered task PID; (uint64_t)-1 = none */
    int             notify_signo;   /* signal to deliver; 0 = SIGEV_NONE (no signal) */
};

struct mq_fd {
    struct mqueue  *mq;
    int             oflag;  /* O_RDONLY / O_WRONLY / O_RDWR | O_NONBLOCK */
};

/* ---- Global queue table ------------------------------------------- */

static struct mqueue  *mq_table[MAX_MQUEUES];
static fut_spinlock_t  mq_global_lock;
static bool            mq_global_init_done = false;

static void mq_global_init(void) {
    if (!mq_global_init_done) {
        fut_spinlock_init(&mq_global_lock);
        mq_global_init_done = true;
    }
}

/* ---- Kernel-pointer bypass for copy helpers ----------------------- */

static inline int mq_copy_from_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)src >= KERNEL_VIRTUAL_BASE) {
        __builtin_memcpy(dst, src, n);
        return 0;
    }
#endif
    return fut_copy_from_user(dst, src, n);
}

static inline int mq_copy_to_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)dst >= KERNEL_VIRTUAL_BASE) {
        __builtin_memcpy(dst, src, n);
        return 0;
    }
#endif
    return fut_copy_to_user(dst, src, n);
}

/* ---- Name validation ---------------------------------------------- */

static int mq_validate_name(const char *name, char *out, size_t outsz) {
    if (!name)
        return -EFAULT;
    /* Must start with '/' */
    if (name[0] != '/')
        return -EINVAL;
    size_t len = __builtin_strlen(name);
    if (len < 2 || len > MQ_NAME_MAX)
        return -EINVAL;
    /* No embedded '/' after the leading one */
    for (size_t i = 1; i < len; i++) {
        if (name[i] == '/')
            return -EINVAL;
    }
    if (out) {
        if (len >= outsz)
            return -ENAMETOOLONG;
        __builtin_memcpy(out, name, len + 1);
    }
    return 0;
}

/* ---- Queue reference counting ------------------------------------- */

static void mq_put(struct mqueue *mq) {
    if (!mq)
        return;
    if (atomic_fetch_sub_explicit(&mq->refcnt, 1, memory_order_acq_rel) == 1) {
        /* Free all remaining messages */
        fut_spinlock_acquire(&mq->lock);
        struct mq_node *n = mq->msgs;
        mq->msgs = NULL;
        fut_spinlock_release(&mq->lock);
        while (n) {
            struct mq_node *next = n->next;
            fut_free(n);
            n = next;
        }
        fut_free(mq);
    }
}

/* ---- Table helpers ------------------------------------------------ */

/* Find queue by name (caller holds mq_global_lock) */
static struct mqueue *mq_table_find(const char *name) {
    for (int i = 0; i < MAX_MQUEUES; i++) {
        if (mq_table[i] && !mq_table[i]->unlinked &&
            __builtin_strcmp(mq_table[i]->name, name) == 0) {
            return mq_table[i];
        }
    }
    return NULL;
}

/* Insert queue into table (caller holds mq_global_lock) */
static int mq_table_insert(struct mqueue *mq) {
    for (int i = 0; i < MAX_MQUEUES; i++) {
        if (!mq_table[i]) {
            mq_table[i] = mq;
            return 0;
        }
    }
    return -EMFILE;
}

/* Remove queue from table (caller holds mq_global_lock) */
static void mq_table_remove(struct mqueue *mq) {
    for (int i = 0; i < MAX_MQUEUES; i++) {
        if (mq_table[i] == mq) {
            mq_table[i] = NULL;
            return;
        }
    }
}

/* ---- FD lookup helper --------------------------------------------- */

/* Get the mq_fd from a numeric fd, or NULL on error. */
static struct mq_fd *mq_fd_lookup(int fd) {
    fut_task_t *task = fut_task_current();
    if (!task || !task->fd_table || fd < 0 || fd >= task->max_fds)
        return NULL;
    struct fut_file *file = task->fd_table[fd];
    if (!file || file->chr_ops != &mq_fops || !file->chr_private)
        return NULL;
    return (struct mq_fd *)file->chr_private;
}

/* ---- FD file operations ------------------------------------------- */

static int mq_fop_release(void *inode, void *priv) {
    (void)inode;
    struct mq_fd *mfd = (struct mq_fd *)priv;
    if (mfd) {
        mq_put(mfd->mq);
        fut_free(mfd);
    }
    return 0;
}

static ssize_t mq_fop_read(void *inode, void *priv, void *buf, size_t count, off_t *pos) {
    (void)inode; (void)priv; (void)buf; (void)count; (void)pos;
    return -EBADF; /* use mq_timedreceive, not read() */
}

static ssize_t mq_fop_write(void *inode, void *priv, const void *buf, size_t count, off_t *pos) {
    (void)inode; (void)priv; (void)buf; (void)count; (void)pos;
    return -EBADF; /* use mq_timedsend, not write() */
}

static struct fut_file_ops mq_fops;

/* ---- sys_mq_open -------------------------------------------------- */

long sys_mq_open(const char *name, int oflag, unsigned int mode,
                 const struct mq_attr *attr)
{
    if (!mq_fops.read) {
        mq_fops.release = mq_fop_release;
        mq_fops.read = mq_fop_read;
        mq_fops.write = mq_fop_write;
    }
    (void)mode; /* mode applies to newly created queues; not checked against umask */
    mq_global_init();

    /* Copy name from user */
    char kname[MQ_NAME_MAX + 2];
    if (mq_copy_from_user(kname, name, sizeof(kname) - 1) != 0)
        return -EFAULT;
    kname[sizeof(kname) - 1] = '\0';

    int err = mq_validate_name(kname, NULL, 0);
    if (err)
        return err;

    /* Validate oflag: must have at least one access mode */
    int accmode = oflag & O_ACCMODE;
    if (accmode != O_RDONLY && accmode != O_WRONLY && accmode != O_RDWR)
        return -EINVAL;

    /* Parse optional attr */
    long maxmsg  = MQ_MAXMSG_DEF;
    long msgsize = MQ_MSGSIZE_DEF;
    if (attr && (oflag & O_CREAT)) {
        struct mq_attr kattr;
        if (mq_copy_from_user(&kattr, attr, sizeof(kattr)) != 0)
            return -EFAULT;
        if (kattr.mq_maxmsg <= 0 || kattr.mq_maxmsg > MQ_MAXMSG_LIMIT)
            return -EINVAL;
        if (kattr.mq_msgsize <= 0 || kattr.mq_msgsize > MQ_MSGSIZE_LIMIT)
            return -EINVAL;
        maxmsg  = kattr.mq_maxmsg;
        msgsize = kattr.mq_msgsize;
    }

    fut_spinlock_acquire(&mq_global_lock);

    struct mqueue *mq = mq_table_find(kname);
    bool created_here = false;

    if (mq) {
        /* Queue exists */
        if ((oflag & O_CREAT) && (oflag & O_EXCL)) {
            fut_spinlock_release(&mq_global_lock);
            return -EEXIST;
        }
        /* Existing queue: retain reference */
        atomic_fetch_add_explicit(&mq->refcnt, 1, memory_order_acq_rel);
        fut_spinlock_release(&mq_global_lock);
    } else {
        /* No existing queue */
        if (!(oflag & O_CREAT)) {
            fut_spinlock_release(&mq_global_lock);
            return -ENOENT;
        }
        /* Create new queue */
        mq = (struct mqueue *)fut_malloc(sizeof(struct mqueue));
        if (!mq) {
            fut_spinlock_release(&mq_global_lock);
            return -ENOMEM;
        }
        __builtin_memset(mq, 0, sizeof(*mq));
        __builtin_memcpy(mq->name, kname, __builtin_strlen(kname) + 1);
        mq->mq_maxmsg  = maxmsg;
        mq->mq_msgsize = msgsize;
        atomic_store_explicit(&mq->mq_curmsgs, 0, memory_order_relaxed);
        atomic_store_explicit(&mq->refcnt, 2, memory_order_relaxed); /* table + fd */
        fut_spinlock_init(&mq->lock);
        fut_waitq_init(&mq->send_waitq);
        fut_waitq_init(&mq->recv_waitq);
        mq->msgs       = NULL;
        mq->unlinked   = false;
        mq->notify_pid   = (uint64_t)-1; /* no notification registered */
        mq->notify_signo = 0;

        err = mq_table_insert(mq);
        if (err) {
            fut_spinlock_release(&mq_global_lock);
            fut_free(mq);
            return err;
        }
        created_here = true;
        fut_spinlock_release(&mq_global_lock);
    }

    /* Create FD private data */
    struct mq_fd *mfd = (struct mq_fd *)fut_malloc(sizeof(struct mq_fd));
    if (!mfd) {
        mq_put(mq);
        return -ENOMEM;
    }
    mfd->mq    = mq;
    mfd->oflag = oflag;

    int fd = chrdev_alloc_fd(&mq_fops, NULL, mfd);
    if (fd < 0) {
        fut_free(mfd);
        /* If we just created this queue and the fd alloc failed, the
         * queue would otherwise be orphaned in mq_table forever
         * (refcnt=1 held by the table, no fd to close it through).
         * Remove it so a retry with O_CREAT|O_EXCL doesn't see a
         * ghost EEXIST and the kernel doesn't leak the buffer. */
        if (created_here) {
            fut_spinlock_acquire(&mq_global_lock);
            mq_table_remove(mq);
            fut_spinlock_release(&mq_global_lock);
            mq_put(mq); /* drop the table's reference */
        }
        mq_put(mq); /* drop the fd-side reference taken above */
        return fd;
    }
    return fd;
}

/* ---- sys_mq_unlink ------------------------------------------------ */

long sys_mq_unlink(const char *name)
{
    mq_global_init();

    char kname[MQ_NAME_MAX + 2];
    if (mq_copy_from_user(kname, name, sizeof(kname) - 1) != 0)
        return -EFAULT;
    kname[sizeof(kname) - 1] = '\0';

    int err = mq_validate_name(kname, NULL, 0);
    if (err)
        return err;

    fut_spinlock_acquire(&mq_global_lock);
    struct mqueue *mq = mq_table_find(kname);
    if (!mq) {
        fut_spinlock_release(&mq_global_lock);
        return -ENOENT;
    }
    /* Mark unlinked so no new opens can find it by name */
    mq->unlinked = true;
    mq_table_remove(mq);
    fut_spinlock_release(&mq_global_lock);

    /* Drop table's reference; existing FDs keep theirs */
    mq_put(mq);
    return 0;
}

/* ---- Insert message in priority order ----------------------------- */

/* Inserts node into priority list (highest priority first, FIFO within priority) */
static void mq_insert_msg(struct mqueue *mq, struct mq_node *node) {
    struct mq_node **pp = &mq->msgs;
    while (*pp && (*pp)->prio >= node->prio)
        pp = &(*pp)->next;
    node->next = *pp;
    *pp = node;
    atomic_fetch_add_explicit(&mq->mq_curmsgs, 1, memory_order_acq_rel);
}

/* ---- sys_mq_timedsend --------------------------------------------- */

long sys_mq_timedsend(int mqdes, const char *msg_ptr, size_t msg_len,
                      unsigned msg_prio, const void *abs_timeout)
{
    if (msg_prio >= (unsigned)MQ_PRIO_MAX)
        return -EINVAL;

    /* Get the mq_fd from the FD */
    struct mq_fd *mfd = mq_fd_lookup(mqdes);
    if (!mfd)
        return -EBADF;
    struct mqueue *mq = mfd->mq;
    if (!mq || mq->unlinked)
        return -EBADF;

    /* Check write permission */
    int accmode = mfd->oflag & O_ACCMODE;
    if (accmode == O_RDONLY)
        return -EBADF;

    /* Validate message length */
    if (msg_len > (size_t)mq->mq_msgsize)
        return -EMSGSIZE;

    /* Parse timeout */
    uint64_t deadline = 0;
    bool has_timeout = false;
    if (abs_timeout) {
        struct { long tv_sec; long tv_nsec; } ts;
        if (mq_copy_from_user(&ts, abs_timeout, sizeof(ts)) != 0)
            return -EFAULT;
        if (ts.tv_nsec < 0 || ts.tv_nsec >= 1000000000L)
            return -EINVAL;
        /* Convert absolute CLOCK_REALTIME to deadline in ticks.
         * Simplified: convert ns from now until timeout to ticks. */
        uint64_t abs_ns = (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
        uint64_t now_ns = fut_get_ticks() * (1000000000ULL / FUT_TIMER_HZ);
        if (abs_ns <= now_ns) {
            deadline = 0; /* already expired */
        } else {
            uint64_t delta_ms = (abs_ns - now_ns) / 1000000ULL;
            uint64_t ticks    = delta_ms / (1000 / FUT_TIMER_HZ);
            deadline = fut_get_ticks() + (ticks ? ticks : 1);
        }
        has_timeout = true;
    }

    int nonblock = (mfd->oflag & O_NONBLOCK);

    /* Allocate message node */
    struct mq_node *node = (struct mq_node *)fut_malloc(sizeof(struct mq_node) + msg_len);
    if (!node)
        return -ENOMEM;
    node->prio = msg_prio;
    node->len  = msg_len;
    node->next = NULL;

    if (msg_len > 0) {
        if (mq_copy_from_user(node->data, msg_ptr, msg_len) != 0) {
            fut_free(node);
            return -EFAULT;
        }
    }

    /* Try to enqueue, blocking if full */
    fut_spinlock_acquire(&mq->lock);
    for (;;) {
        long cur = atomic_load_explicit(&mq->mq_curmsgs, memory_order_relaxed);
        if (cur < mq->mq_maxmsg) {
            bool was_empty = (cur == 0);
            mq_insert_msg(mq, node);
            /* Phase 2: fire one-shot mq_notify if queue was empty */
            uint64_t npid  = mq->notify_pid;
            int      nsig  = mq->notify_signo;
            if (was_empty && npid != (uint64_t)-1)
                mq->notify_pid = (uint64_t)-1;  /* one-shot: clear before release */
            /* Wake any blocked receivers */
            fut_waitq_wake_all(&mq->recv_waitq);
            fut_spinlock_release(&mq->lock);
            if (was_empty && npid != (uint64_t)-1 && nsig > 0) {
                fut_task_t *ntask = fut_task_by_pid(npid);
                if (ntask)
                    fut_signal_send(ntask, nsig);
            }
            return 0;
        }

        /* Queue is full */
        if (nonblock) {
            fut_spinlock_release(&mq->lock);
            fut_free(node);
            return -EAGAIN;
        }
        if (has_timeout && fut_get_ticks() >= deadline) {
            fut_spinlock_release(&mq->lock);
            fut_free(node);
            return -ETIMEDOUT;
        }

        /* Check for signals */
        fut_task_t *task = fut_task_current();
        if (task) {
            uint64_t pending = __atomic_load_n(&task->pending_signals, __ATOMIC_ACQUIRE);
            fut_thread_t *thr = fut_thread_current();
            uint64_t blocked = thr ? __atomic_load_n(&thr->signal_mask, __ATOMIC_ACQUIRE)
                                   : task->signal_mask;
            if (pending & ~blocked) {
                fut_spinlock_release(&mq->lock);
                fut_free(node);
                return -EINTR;
            }
        }

        /* Sleep until a receiver dequeues a message, freeing space */
        fut_waitq_sleep_locked(&mq->send_waitq, &mq->lock, FUT_THREAD_BLOCKED);
        fut_spinlock_acquire(&mq->lock);
    }
}

/* ---- sys_mq_timedreceive ------------------------------------------ */

long sys_mq_timedreceive(int mqdes, char *msg_ptr, size_t msg_len,
                         unsigned *msg_prio, const void *abs_timeout)
{
    struct mq_fd *mfd = mq_fd_lookup(mqdes);
    if (!mfd)
        return -EBADF;
    struct mqueue *mq = mfd->mq;
    if (!mq || mq->unlinked)
        return -EBADF;

    /* Check read permission */
    int accmode = mfd->oflag & O_ACCMODE;
    if (accmode == O_WRONLY)
        return -EBADF;

    /* msg_len must be >= mq_msgsize */
    if (msg_len < (size_t)mq->mq_msgsize)
        return -EMSGSIZE;

    /* Parse timeout */
    uint64_t deadline = 0;
    bool has_timeout = false;
    if (abs_timeout) {
        struct { long tv_sec; long tv_nsec; } ts;
        if (mq_copy_from_user(&ts, abs_timeout, sizeof(ts)) != 0)
            return -EFAULT;
        if (ts.tv_nsec < 0 || ts.tv_nsec >= 1000000000L)
            return -EINVAL;
        uint64_t abs_ns = (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
        uint64_t now_ns = fut_get_ticks() * (1000000000ULL / FUT_TIMER_HZ);
        if (abs_ns <= now_ns) {
            deadline = 0;
        } else {
            uint64_t delta_ms = (abs_ns - now_ns) / 1000000ULL;
            uint64_t ticks    = delta_ms / (1000 / FUT_TIMER_HZ);
            deadline = fut_get_ticks() + (ticks ? ticks : 1);
        }
        has_timeout = true;
    }

    int nonblock = (mfd->oflag & O_NONBLOCK);

    fut_spinlock_acquire(&mq->lock);
    for (;;) {
        struct mq_node *node = mq->msgs;
        if (node) {
            mq->msgs = node->next;
            atomic_fetch_sub_explicit(&mq->mq_curmsgs, 1, memory_order_acq_rel);
            /* Wake any blocked senders — a slot just opened */
            fut_waitq_wake_all(&mq->send_waitq);
            fut_spinlock_release(&mq->lock);

            /* Copy message to user */
            size_t copy_len = node->len;
            if (copy_len > msg_len)
                copy_len = msg_len;
            if (copy_len > 0) {
                if (mq_copy_to_user(msg_ptr, node->data, copy_len) != 0) {
                    fut_free(node);
                    return -EFAULT;
                }
            }
            if (msg_prio) {
                unsigned kprio = node->prio;
                if (mq_copy_to_user(msg_prio, &kprio, sizeof(kprio)) != 0) {
                    fut_free(node);
                    return -EFAULT;
                }
            }
            long ret = (long)node->len;
            fut_free(node);
            return ret;
        }

        /* Queue is empty */
        if (nonblock) {
            fut_spinlock_release(&mq->lock);
            return -EAGAIN;
        }
        if (has_timeout && fut_get_ticks() >= deadline) {
            fut_spinlock_release(&mq->lock);
            return -ETIMEDOUT;
        }

        /* Check for signals */
        fut_task_t *task = fut_task_current();
        if (task) {
            uint64_t pending = __atomic_load_n(&task->pending_signals, __ATOMIC_ACQUIRE);
            fut_thread_t *thr = fut_thread_current();
            uint64_t blocked = thr ? __atomic_load_n(&thr->signal_mask, __ATOMIC_ACQUIRE)
                                   : task->signal_mask;
            if (pending & ~blocked) {
                fut_spinlock_release(&mq->lock);
                return -EINTR;
            }
        }

        /* Sleep until a sender enqueues a message */
        fut_waitq_sleep_locked(&mq->recv_waitq, &mq->lock, FUT_THREAD_BLOCKED);
        fut_spinlock_acquire(&mq->lock);
    }
}

/* ---- sys_mq_notify ------------------------------------------------ */

/*
 * Phase 2: mq_notify() — register a one-shot signal notification.
 *
 * Per POSIX:
 *   - sevp == NULL: unregister. Only the task that registered may do this.
 *   - sevp->sigev_notify == SIGEV_SIGNAL: deliver sigev_signo when a message
 *     arrives at an empty queue. Notification fires once, then clears.
 *   - sevp->sigev_notify == SIGEV_NONE: register without delivering a signal
 *     (prevents other tasks from registering; clears on first send).
 *   - Only one task may be registered per queue; -EBUSY if another is waiting.
 */
long sys_mq_notify(int mqdes, const void *sevp)
{
    struct mq_fd *mfd = mq_fd_lookup(mqdes);
    if (!mfd)
        return -EBADF;
    struct mqueue *mq = mfd->mq;
    if (!mq || mq->unlinked)
        return -EBADF;

    fut_task_t *task = fut_task_current();
    if (!task)
        return -ESRCH;

    fut_spinlock_acquire(&mq->lock);

    if (!sevp) {
        /* Unregister: only the registered task may de-register */
        if (mq->notify_pid == task->pid)
            mq->notify_pid = (uint64_t)-1;
        fut_spinlock_release(&mq->lock);
        return 0;
    }

    /* Another task is already registered → EBUSY */
    if (mq->notify_pid != (uint64_t)-1 && mq->notify_pid != task->pid) {
        fut_spinlock_release(&mq->lock);
        return -EBUSY;
    }

    /* Copy sigevent from caller */
    struct sigevent kev;
    if (mq_copy_from_user(&kev, sevp, sizeof(kev)) != 0) {
        fut_spinlock_release(&mq->lock);
        return -EFAULT;
    }

    if (kev.sigev_notify == SIGEV_SIGNAL) {
        if (kev.sigev_signo < 1 || kev.sigev_signo > 64) {
            fut_spinlock_release(&mq->lock);
            return -EINVAL;
        }
        mq->notify_pid   = task->pid;
        mq->notify_signo = kev.sigev_signo;
    } else if (kev.sigev_notify == SIGEV_NONE) {
        mq->notify_pid   = task->pid;
        mq->notify_signo = 0;
    } else {
        /* SIGEV_THREAD not supported */
        fut_spinlock_release(&mq->lock);
        return -EINVAL;
    }

    fut_spinlock_release(&mq->lock);
    return 0;
}

/* ---- sys_mq_getsetattr -------------------------------------------- */

long sys_mq_getsetattr(int mqdes, const struct mq_attr *newattr,
                       struct mq_attr *oldattr)
{
    struct mq_fd *mfd = mq_fd_lookup(mqdes);
    if (!mfd)
        return -EBADF;
    struct mqueue *mq = mfd->mq;
    if (!mq || mq->unlinked)
        return -EBADF;

    /* Return old attr */
    if (oldattr) {
        struct mq_attr kold;
        __builtin_memset(&kold, 0, sizeof(kold));
        kold.mq_flags   = (mfd->oflag & O_NONBLOCK) ? O_NONBLOCK : 0;
        kold.mq_maxmsg  = mq->mq_maxmsg;
        kold.mq_msgsize = mq->mq_msgsize;
        kold.mq_curmsgs = atomic_load_explicit(&mq->mq_curmsgs, memory_order_acquire);
        if (mq_copy_to_user(oldattr, &kold, sizeof(kold)) != 0)
            return -EFAULT;
    }

    /* Apply new attr (only mq_flags / O_NONBLOCK can be changed) */
    if (newattr) {
        struct mq_attr knew;
        if (mq_copy_from_user(&knew, newattr, sizeof(knew)) != 0)
            return -EFAULT;
        if (knew.mq_flags & O_NONBLOCK)
            mfd->oflag |= O_NONBLOCK;
        else
            mfd->oflag &= ~O_NONBLOCK;
    }
    return 0;
}
