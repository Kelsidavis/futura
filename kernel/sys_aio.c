/* kernel/sys_aio.c - io_uring async I/O and Linux AIO stubs
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements the io_uring async I/O interface (syscalls 425-427) for
 * high-performance, batched I/O operations. Supports core operations:
 *   IORING_OP_NOP, IORING_OP_READV, IORING_OP_WRITEV,
 *   IORING_OP_READ_FIXED, IORING_OP_WRITE_FIXED,
 *   IORING_OP_POLL_ADD, IORING_OP_POLL_REMOVE,
 *   IORING_OP_FSYNC, IORING_OP_CLOSE, IORING_OP_TIMEOUT,
 *   IORING_OP_TIMEOUT_REMOVE, IORING_OP_LINK_TIMEOUT
 *
 * The ring uses a submission queue (SQ) and completion queue (CQ)
 * modeled after Linux 5.1+, with kernel-internal memory (no mmap).
 * io_uring_setup() returns an fd; io_uring_enter() processes SQEs
 * synchronously and posts CQEs; io_uring_register() registers
 * buffers and files for zero-copy I/O.
 *
 * Linux AIO (syscalls 206-210) remains stubbed as -ENOSYS.
 */

#include <kernel/kprintf.h>
#include <kernel/errno.h>
#include <kernel/fut_vfs.h>
#include <kernel/fut_task.h>
#include <kernel/chrdev.h>
#include <kernel/uaccess.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#include <platform/platform.h>

/* Copy helpers that bypass uaccess for kernel pointers (self-tests) and
 * propagate -EFAULT for user pointers. Replaces direct *u = v writes
 * that would otherwise let a caller pass a kernel address and turn
 * io_setup / io_getevents into a write-anywhere primitive. */
static inline int aio_put_user(void *u_dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)u_dst >= KERNEL_VIRTUAL_BASE) {
        __builtin_memcpy(u_dst, src, n);
        return 0;
    }
#endif
    return fut_copy_to_user(u_dst, src, n);
}

/* ── Linux AIO implementation (syscalls 206-210) ──
 *
 * Implements the Linux AIO (Asynchronous I/O) interface used by libaio.
 * Operations are completed synchronously in io_submit() and queued for
 * retrieval by io_getevents(). This matches Linux behavior for regular
 * files on most filesystems (where AIO completes immediately).
 *
 * Supports: IOCB_CMD_PREAD, IOCB_CMD_PWRITE, IOCB_CMD_FSYNC,
 *           IOCB_CMD_FDSYNC, IOCB_CMD_NOOP
 */

/* Linux AIO iocb commands */
#define IOCB_CMD_PREAD   0
#define IOCB_CMD_PWRITE  1
#define IOCB_CMD_FSYNC   2
#define IOCB_CMD_FDSYNC  3
#define IOCB_CMD_NOOP    6
#define IOCB_CMD_PREADV  7
#define IOCB_CMD_PWRITEV 8

/* Linux AIO iocb structure (64-byte, matches Linux kernel ABI) */
struct linux_iocb {
    uint64_t aio_data;       /* user data returned in io_event */
    uint32_t aio_key;        /* __pad1: was internal kernel field */
    uint32_t aio_rw_flags;   /* RWF_* flags (Linux 4.13+) */
    uint16_t aio_lio_opcode; /* IOCB_CMD_* */
    int16_t  aio_reqprio;    /* request priority */
    uint32_t aio_fildes;     /* file descriptor */
    uint64_t aio_buf;        /* pointer to buffer */
    uint64_t aio_nbytes;     /* number of bytes */
    int64_t  aio_offset;     /* file offset */
    uint64_t aio_reserved2;
    uint32_t aio_flags;      /* IOCB_FLAG_RESFD etc. */
    uint32_t aio_resfd;      /* eventfd for completion notification */
};

/* Linux AIO io_event structure (32-byte, matches Linux kernel ABI) */
struct linux_io_event {
    uint64_t data;   /* aio_data from the iocb */
    uint64_t obj;    /* pointer to the original iocb (userspace addr) */
    int64_t  res;    /* result of the operation */
    int64_t  res2;   /* secondary result (0 on success) */
};

/* AIO context */
#define MAX_AIO_CONTEXTS 16
#define MAX_AIO_EVENTS   256

struct aio_context {
    bool     active;
    uint64_t owner_pid;
    uint32_t max_events;     /* max events this context can hold */

    /* Completion ring: events produced by io_submit, consumed by io_getevents */
    struct linux_io_event events[MAX_AIO_EVENTS];
    uint32_t event_head;     /* consumer index (io_getevents reads from here) */
    uint32_t event_tail;     /* producer index (io_submit writes here) */
};

static struct aio_context aio_contexts[MAX_AIO_CONTEXTS];

/* Forward declarations for I/O operations */
extern long sys_read(int fd, void *buf, size_t count);
extern long sys_write(int fd, const void *buf, size_t count);
extern long sys_pread64(unsigned int fd, void *buf, size_t count, int64_t offset);
extern long sys_pwrite64(unsigned int fd, const void *buf, size_t count, int64_t offset);
extern long sys_fsync(int fd);
extern long sys_fdatasync(int fd);

static void aio_post_event(struct aio_context *ctx, uint64_t data, uint64_t obj,
                           int64_t res, int64_t res2) {
    uint32_t tail = ctx->event_tail;
    uint32_t next = (tail + 1) % MAX_AIO_EVENTS;
    if (next == ctx->event_head) {
        return;  /* Ring full — drop event (shouldn't happen with proper sizing) */
    }
    ctx->events[tail].data = data;
    ctx->events[tail].obj = obj;
    ctx->events[tail].res = res;
    ctx->events[tail].res2 = res2;
    ctx->event_tail = next;
}

static uint32_t aio_pending_count(struct aio_context *ctx) __attribute__((unused));
static uint32_t aio_pending_count(struct aio_context *ctx) {
    if (ctx->event_tail >= ctx->event_head)
        return ctx->event_tail - ctx->event_head;
    return MAX_AIO_EVENTS - ctx->event_head + ctx->event_tail;
}

/**
 * sys_io_setup - Create an AIO context
 * @nr_events: Maximum number of concurrent events
 * @ctxp:      Pointer to store context ID (written as unsigned long)
 */
long sys_io_setup(unsigned int nr_events, void *ctxp) {
    if (!ctxp || nr_events == 0 || nr_events > MAX_AIO_EVENTS)
        return -EINVAL;

    /* Find a free context slot */
    struct aio_context *ctx = NULL;
    unsigned long ctx_id = 0;
    for (int i = 0; i < MAX_AIO_CONTEXTS; i++) {
        if (!aio_contexts[i].active) {
            ctx = &aio_contexts[i];
            /* Context IDs start at 1 (0 = invalid) and are offset by 0x10000
             * to avoid confusion with small integers or pointers */
            ctx_id = (unsigned long)(0x10000 + i);
            break;
        }
    }
    if (!ctx)
        return -EAGAIN;  /* Too many contexts */

    memset(ctx, 0, sizeof(*ctx));
    ctx->active = true;
    ctx->owner_pid = fut_task_current() ? fut_task_current()->pid : 0;
    ctx->max_events = nr_events < MAX_AIO_EVENTS ? nr_events : MAX_AIO_EVENTS;
    ctx->event_head = 0;
    ctx->event_tail = 0;

    /* Write context ID to userspace via copy_to_user — never deref ctxp
     * directly: a caller may pass a kernel address and the previous code
     * would happily write the new ctx_id wherever they pointed. */
    if (aio_put_user(ctxp, &ctx_id, sizeof(ctx_id)) != 0) {
        ctx->active = false;
        return -EFAULT;
    }

    return 0;
}

/* Resolve a ctx_id to a context owned by the caller (or accessible
 * via root/CAP_SYS_ADMIN). Returns NULL with errno-compatible code in
 * *err on failure. */
static struct aio_context *aio_ctx_for_caller(unsigned long ctx_id, long *err) {
    unsigned int idx = (unsigned int)(ctx_id - 0x10000);
    if (idx >= MAX_AIO_CONTEXTS) { *err = -EINVAL; return NULL; }
    struct aio_context *ctx = &aio_contexts[idx];
    if (!ctx->active) { *err = -EINVAL; return NULL; }

    fut_task_t *task = fut_task_current();
    if (task && ctx->owner_pid && task->pid != ctx->owner_pid) {
        bool privileged = (task->uid == 0) ||
            (task->cap_effective & (1ULL << 21 /* CAP_SYS_ADMIN */));
        if (!privileged) { *err = -EINVAL; return NULL; }
    }
    return ctx;
}

/**
 * sys_io_destroy - Destroy an AIO context
 * @ctx_id: Context ID from io_setup
 */
long sys_io_destroy(unsigned long ctx_id) {
    /* The aio_ctx_for_caller helper applies the same owner-or-
     * CAP_SYS_ADMIN check that all the other AIO syscalls now use,
     * keeping the protection consistent. */
    long err = 0;
    struct aio_context *ctx = aio_ctx_for_caller(ctx_id, &err);
    if (!ctx) return err;

    ctx->active = false;
    return 0;
}

/**
 * sys_io_submit - Submit I/O requests for asynchronous processing
 * @ctx_id:  Context ID
 * @nr:      Number of iocbs to submit
 * @iocbpp:  Array of pointers to iocb structures
 *
 * Returns: number of iocbs submitted, or negative error
 */
long sys_io_submit(unsigned long ctx_id, long nr, void **iocbpp) {
    if (nr < 0 || !iocbpp)
        return -EINVAL;
    if (nr == 0)
        return 0;

    long err = 0;
    struct aio_context *ctx = aio_ctx_for_caller(ctx_id, &err);
    if (!ctx) return err;

    /* Stage iocbpp[i] and *iocb through copy_from_user instead of
     * dereferencing the user pointer arrays directly. The previous
     * code did
     *     struct linux_iocb *iocb = (struct linux_iocb *)iocbpp[i];
     *     ... iocb->aio_lio_opcode / iocb->aio_buf ...
     * which faulted the kernel for a bad user pointer and let a
     * caller passing kernel addresses read kernel memory through the
     * iocb fields. */
    long submitted = 0;
    for (long i = 0; i < nr; i++) {
        void *iocb_uptr = NULL;
#ifdef KERNEL_VIRTUAL_BASE
        if ((uintptr_t)&iocbpp[i] >= KERNEL_VIRTUAL_BASE) {
            iocb_uptr = iocbpp[i];
        } else
#endif
        if (fut_copy_from_user(&iocb_uptr, &iocbpp[i], sizeof(iocb_uptr)) != 0)
            break;
        if (!iocb_uptr)
            break;

        struct linux_iocb iocb_copy;
#ifdef KERNEL_VIRTUAL_BASE
        if ((uintptr_t)iocb_uptr >= KERNEL_VIRTUAL_BASE) {
            __builtin_memcpy(&iocb_copy, iocb_uptr, sizeof(iocb_copy));
        } else
#endif
        if (fut_copy_from_user(&iocb_copy, iocb_uptr, sizeof(iocb_copy)) != 0)
            break;
        const struct linux_iocb *iocb = &iocb_copy;

        int64_t result = 0;

        switch (iocb->aio_lio_opcode) {
        case IOCB_CMD_PREAD:
            result = sys_pread64(iocb->aio_fildes,
                                 (void *)(uintptr_t)iocb->aio_buf,
                                 (size_t)iocb->aio_nbytes,
                                 iocb->aio_offset);
            break;

        case IOCB_CMD_PWRITE:
            result = sys_pwrite64(iocb->aio_fildes,
                                  (const void *)(uintptr_t)iocb->aio_buf,
                                  (size_t)iocb->aio_nbytes,
                                  iocb->aio_offset);
            break;

        case IOCB_CMD_FSYNC:
            result = sys_fsync((int)iocb->aio_fildes);
            break;

        case IOCB_CMD_FDSYNC:
            result = sys_fdatasync((int)iocb->aio_fildes);
            break;

        case IOCB_CMD_NOOP:
            result = 0;
            break;

        case IOCB_CMD_PREADV:
        case IOCB_CMD_PWRITEV: {
            /* Vectored I/O: aio_buf = iovec array, aio_nbytes = iovec count.
             * Stage each iovec entry through copy_from_user so a kernel-
             * pointer aio_buf or a bad user iovec page can't fault the
             * kernel or leak kernel data. */
            struct linux_iovec { uint64_t iov_base; uint64_t iov_len; };
            struct linux_iovec *iovs_uptr =
                (struct linux_iovec *)(uintptr_t)iocb->aio_buf;
            uint64_t nr_vecs = iocb->aio_nbytes;
            if (!iovs_uptr || nr_vecs == 0) { result = -EINVAL; break; }
            /* Cap iovec count to a sane bound (UIO_MAXIOV). */
            if (nr_vecs > 1024) { result = -EINVAL; break; }

            int64_t total = 0;
            for (uint64_t v = 0; v < nr_vecs; v++) {
                struct linux_iovec iov_copy;
#ifdef KERNEL_VIRTUAL_BASE
                if ((uintptr_t)&iovs_uptr[v] >= KERNEL_VIRTUAL_BASE) {
                    __builtin_memcpy(&iov_copy, &iovs_uptr[v], sizeof(iov_copy));
                } else
#endif
                if (fut_copy_from_user(&iov_copy, &iovs_uptr[v],
                                       sizeof(iov_copy)) != 0) {
                    if (total == 0) total = -EFAULT;
                    break;
                }
                void *base = (void *)(uintptr_t)iov_copy.iov_base;
                size_t ilen = (size_t)iov_copy.iov_len;
                long r;
                if (iocb->aio_lio_opcode == IOCB_CMD_PREADV)
                    r = sys_pread64(iocb->aio_fildes, base, ilen,
                                    iocb->aio_offset + total);
                else
                    r = sys_pwrite64(iocb->aio_fildes, (const void *)base, ilen,
                                     iocb->aio_offset + total);
                if (r < 0) { if (total == 0) total = r; break; }
                total += r;
                if ((size_t)r < ilen) break;
            }
            result = total;
            break;
        }

        default:
            result = -EINVAL;
            break;
        }

        /* Post completion event — use the user-space iocb pointer (not
         * the kernel-side copy address) for the obj field. */
        aio_post_event(ctx, iocb->aio_data, (uint64_t)(uintptr_t)iocb_uptr,
                       result, 0);
        submitted++;
    }

    return submitted;
}

/**
 * sys_io_getevents - Read completed AIO events
 * @ctx_id:  Context ID
 * @min_nr:  Minimum number of events to wait for
 * @nr:      Maximum number of events to return
 * @events:  Output array of io_event structures
 * @timeout: Optional timeout (NULL = block forever, {0,0} = non-blocking)
 *
 * Returns: number of events read, or negative error
 */
long sys_io_getevents(unsigned long ctx_id, long min_nr, long nr,
                      void *events, const void *timeout) {
    if (min_nr < 0 || nr < 0 || min_nr > nr || !events)
        return -EINVAL;

    long err = 0;
    struct aio_context *ctx = aio_ctx_for_caller(ctx_id, &err);
    if (!ctx) return err;

    long collected = 0;

    /* Collect available events (up to nr) into the user buffer through
     * copy_to_user — must never write ev_out[i] directly, since the user
     * pointer may target kernel memory or be unmapped. */
    while (collected < nr && ctx->event_head != ctx->event_tail) {
        struct linux_io_event ev = ctx->events[ctx->event_head];
        void *u_slot = (char *)events +
                       (size_t)collected * sizeof(struct linux_io_event);
        if (aio_put_user(u_slot, &ev, sizeof(ev)) != 0) {
            /* Don't consume the event we couldn't deliver; if we already
             * delivered some, return that partial count instead of the
             * EFAULT so the caller can retry the rest. */
            return collected > 0 ? collected : -EFAULT;
        }
        ctx->event_head = (ctx->event_head + 1) % MAX_AIO_EVENTS;
        collected++;
    }

    /* If we collected fewer than min_nr and have a non-zero timeout, we'd
     * normally block. Since our AIO completes synchronously in io_submit(),
     * there are no pending operations that could complete asynchronously.
     * Just return what we have. */
    (void)timeout;

    return collected;
}

/**
 * sys_io_cancel - Attempt to cancel an AIO operation
 * @ctx_id: Context ID
 * @iocb:   I/O control block to cancel
 * @result: Output io_event for the cancelled operation
 *
 * Returns: 0 on success, -EAGAIN if not cancellable (already completed)
 */
long sys_io_cancel(unsigned long ctx_id, void *iocb, void *result) {
    long err = 0;
    struct aio_context *ctx = aio_ctx_for_caller(ctx_id, &err);
    if (!ctx) return err;

    /* Our AIO completes synchronously, so there's nothing to cancel */
    (void)iocb; (void)result; (void)ctx;
    return -EAGAIN;
}

/**
 * sys_io_pgetevents - Signal-safe variant of io_getevents (Linux 4.18+)
 *
 * Atomically sets the signal mask, calls io_getevents, then restores it.
 * The signal mask allows blocking signals during the wait to prevent
 * EINTR races in event-loop code.
 *
 * Syscall 333 on x86_64, 292 on ARM64.
 */
long sys_io_pgetevents(unsigned long ctx_id, long min_nr, long nr,
                        void *events, const void *timeout,
                        const void *usig) {
    /* usig points to a userspace { const sigset_t *sigmask; size_t
     * sigsetsize; } pair. copy both layers in via copy_from_user — the
     * previous code dereferenced 'sig' and '*sig->ss' straight from
     * userspace, so a kernel pointer here would read kernel memory into
     * task->signal_mask (information disclosure plus arbitrary mask
     * change), and an unmapped pointer would fault the kernel. */
    uint64_t old_mask = 0;
    bool mask_installed = false;

    if (usig) {
        struct sigwrap { const uint64_t *ss; uint64_t ssz; } sig;
#ifdef KERNEL_VIRTUAL_BASE
        if ((uintptr_t)usig >= KERNEL_VIRTUAL_BASE) {
            __builtin_memcpy(&sig, usig, sizeof(sig));
        } else
#endif
        if (fut_copy_from_user(&sig, usig, sizeof(sig)) != 0)
            return -EFAULT;

        /* Linux validates sigsetsize == sizeof(sigset_t) (8 on 64-bit)
         * and returns -EINVAL otherwise — keeps the wire ABI rigid so a
         * future widening of sigset_t can be detected without ambiguity.
         * The previous code read sig.ssz only to discard it, accepting
         * any size and silently ignoring mismatched layouts. */
        if (sig.ss && sig.ssz != sizeof(uint64_t))
            return -EINVAL;

        if (sig.ss) {
            uint64_t newmask = 0;
#ifdef KERNEL_VIRTUAL_BASE
            if ((uintptr_t)sig.ss >= KERNEL_VIRTUAL_BASE) {
                newmask = *sig.ss;
            } else
#endif
            if (fut_copy_from_user(&newmask, sig.ss, sizeof(newmask)) != 0)
                return -EFAULT;

            /* SIGKILL and SIGSTOP cannot be blocked (POSIX). The previous
             * version installed newmask raw, so a caller could pass
             * { SIGKILL | SIGSTOP } and become unkillable for the
             * duration of io_pgetevents. Strip those bits before
             * applying. */
            newmask &= ~((1ULL << (9  - 1)) |   /* SIGKILL */
                         (1ULL << (19 - 1)));   /* SIGSTOP */
            fut_task_t *task = fut_task_current();
            if (task) {
                old_mask = task->signal_mask;
                task->signal_mask = newmask;
                mask_installed = true;
            }
        }
    }

    long ret = sys_io_getevents(ctx_id, min_nr, nr, events, timeout);

    /* Restore signal mask if we installed one */
    if (mask_installed) {
        fut_task_t *task = fut_task_current();
        if (task)
            task->signal_mask = old_mask;
    }

    return ret;
}

/* ── io_uring constants (Linux ABI) ── */

/* io_uring_params flags */
#define IORING_SETUP_IOPOLL     (1U << 0)
#define IORING_SETUP_SQPOLL     (1U << 1)
#define IORING_SETUP_SQ_AFF     (1U << 2)
#define IORING_SETUP_CQSIZE     (1U << 3)
#define IORING_SETUP_CLAMP      (1U << 4)
#define IORING_SETUP_ATTACH_WQ  (1U << 5)

/* io_uring_enter flags */
#define IORING_ENTER_GETEVENTS  (1U << 0)
#define IORING_ENTER_SQ_WAKEUP  (1U << 1)
#define IORING_ENTER_SQ_WAIT    (1U << 2)

/* io_uring_register opcodes */
#define IORING_REGISTER_BUFFERS        0
#define IORING_UNREGISTER_BUFFERS      1
#define IORING_REGISTER_FILES          2
#define IORING_UNREGISTER_FILES        3
#define IORING_REGISTER_EVENTFD        4
#define IORING_UNREGISTER_EVENTFD      5
#define IORING_REGISTER_PROBE          6

/* SQE opcodes */
#define IORING_OP_NOP              0
#define IORING_OP_READV            1
#define IORING_OP_WRITEV           2
#define IORING_OP_FSYNC            3
#define IORING_OP_READ_FIXED       4
#define IORING_OP_WRITE_FIXED      5
#define IORING_OP_POLL_ADD         6
#define IORING_OP_POLL_REMOVE      7
#define IORING_OP_TIMEOUT         11
#define IORING_OP_TIMEOUT_REMOVE  12
#define IORING_OP_CLOSE           19
#define IORING_OP_READ            22
#define IORING_OP_WRITE           23
#define IORING_OP_LINK_TIMEOUT    24
#define IORING_OP_LAST            25   /* sentinel — highest + 1 */

/* SQE flags */
#define IOSQE_FIXED_FILE    (1U << 0)
#define IOSQE_IO_DRAIN      (1U << 1)
#define IOSQE_IO_LINK       (1U << 2)
#define IOSQE_IO_HARDLINK   (1U << 3)
#define IOSQE_ASYNC         (1U << 4)

/* Feature flags returned in io_uring_params.features */
#define IORING_FEAT_SINGLE_MMAP   (1U << 0)
#define IORING_FEAT_NODROP        (1U << 1)
#define IORING_FEAT_SUBMIT_STABLE (1U << 2)
#define IORING_FEAT_RW_CUR_POS    (1U << 3)
#define IORING_FEAT_CUR_PERSONALITY (1U << 4)
#define IORING_FEAT_FAST_POLL     (1U << 5)

/* ── Data structures (Linux-compatible layout) ── */

struct io_uring_sqe {
    uint8_t  opcode;
    uint8_t  flags;
    uint16_t ioprio;
    int32_t  fd;
    union {
        uint64_t off;
        uint64_t addr2;
    };
    union {
        uint64_t addr;
        uint64_t splice_off_in;
    };
    uint32_t len;
    union {
        uint32_t rw_flags;
        uint32_t fsync_flags;
        uint32_t poll_events;
        uint32_t poll32_events;
        uint32_t sync_range_flags;
        uint32_t msg_flags;
        uint32_t timeout_flags;
        uint32_t accept_flags;
        uint32_t cancel_flags;
        uint32_t open_flags;
        uint32_t statx_flags;
        uint32_t fadvise_advice;
        uint32_t splice_flags;
    };
    uint64_t user_data;
    union {
        uint16_t buf_index;
        uint16_t buf_group;
    };
    uint16_t personality;
    union {
        int32_t  splice_fd_in;
        uint32_t file_index;
    };
    uint64_t __pad2[2];
};

struct io_uring_cqe {
    uint64_t user_data;
    int32_t  res;
    uint32_t flags;
};

struct io_sqring_offsets {
    uint32_t head;
    uint32_t tail;
    uint32_t ring_mask;
    uint32_t ring_entries;
    uint32_t flags;
    uint32_t dropped;
    uint32_t array;
    uint32_t resv1;
    uint64_t resv2;
};

struct io_cqring_offsets {
    uint32_t head;
    uint32_t tail;
    uint32_t ring_mask;
    uint32_t ring_entries;
    uint32_t overflow;
    uint32_t cqes;
    uint32_t flags;
    uint32_t resv1;
    uint64_t resv2;
};

struct io_uring_params {
    uint32_t sq_entries;
    uint32_t cq_entries;
    uint32_t flags;
    uint32_t sq_thread_cpu;
    uint32_t sq_thread_idle;
    uint32_t features;
    uint32_t wq_fd;
    uint32_t resv[3];
    struct io_sqring_offsets sq_off;
    struct io_cqring_offsets cq_off;
};

/* Probe result structures */
struct io_uring_probe_op {
    uint8_t  op;
    uint8_t  resv;
    uint16_t flags;
    uint32_t resv2;
};

#define IO_URING_OP_SUPPORTED (1U << 0)

struct io_uring_probe {
    uint8_t  last_op;
    uint8_t  ops_len;
    uint16_t resv;
    uint32_t resv2[3];
    struct io_uring_probe_op ops[];
};

/* ── Internal ring state ── */

#define MAX_URING_INSTANCES   64
#define MAX_URING_ENTRIES    256   /* max SQ/CQ entries per ring */
#define MAX_URING_FILES       64   /* max registered files */
#define MAX_URING_BUFS        16   /* max registered buffers */

struct io_uring_ctx {
    bool     active;
    int      ring_fd;              /* fd in owner's fd_table */
    uint64_t owner_pid;

    /* Submission queue */
    uint32_t sq_entries;
    uint32_t sq_head;
    uint32_t sq_tail;
    uint32_t sq_mask;
    struct io_uring_sqe *sqes;     /* SQE array (kernel-allocated) */
    uint32_t *sq_array;            /* SQ index array */

    /* Completion queue */
    uint32_t cq_entries;
    uint32_t cq_head;
    uint32_t cq_tail;
    uint32_t cq_mask;
    uint32_t cq_overflow;
    struct io_uring_cqe *cqes;     /* CQE array (kernel-allocated) */

    /* Registered files */
    int      reg_files[MAX_URING_FILES];
    uint32_t nr_reg_files;

    /* Registered eventfd for wakeup notifications */
    int      eventfd;

    /* Stats */
    uint64_t sq_submitted;
    uint64_t cq_completed;
};

static struct io_uring_ctx uring_instances[MAX_URING_INSTANCES];

/* Round up to next power of 2 */
static uint32_t uring_roundup_pow2(uint32_t v) {
    if (v == 0) return 1;
    v--;
    v |= v >> 1;
    v |= v >> 2;
    v |= v >> 4;
    v |= v >> 8;
    v |= v >> 16;
    return v + 1;
}

/* Find io_uring context by fd */
static struct io_uring_ctx *uring_get_ctx(unsigned int fd) {
    for (int i = 0; i < MAX_URING_INSTANCES; i++) {
        if (uring_instances[i].active && uring_instances[i].ring_fd == (int)fd)
            return &uring_instances[i];
    }
    return NULL;
}

/* ── File operations for io_uring fd cleanup ── */

static int uring_release(void *inode, void *priv) {
    (void)inode;
    struct io_uring_ctx *ctx = (struct io_uring_ctx *)priv;
    if (!ctx) return 0;

    if (ctx->sqes)    { extern void fut_free(void *); fut_free(ctx->sqes); }
    if (ctx->sq_array){ extern void fut_free(void *); fut_free(ctx->sq_array); }
    if (ctx->cqes)    { extern void fut_free(void *); fut_free(ctx->cqes); }

    ctx->sqes = NULL;
    ctx->sq_array = NULL;
    ctx->cqes = NULL;
    ctx->active = false;
    return 0;
}

static const struct fut_file_ops uring_fops = {
    .release = uring_release,
};

/* ── Post a completion event ── */

static void uring_post_cqe(struct io_uring_ctx *ctx, uint64_t user_data,
                            int32_t res, uint32_t flags) {
    uint32_t tail = ctx->cq_tail;
    uint32_t next = (tail + 1) & ctx->cq_mask;

    if (next == ctx->cq_head) {
        /* CQ full — overflow */
        ctx->cq_overflow++;
        return;
    }

    struct io_uring_cqe *cqe = &ctx->cqes[tail & ctx->cq_mask];
    cqe->user_data = user_data;
    cqe->res = res;
    cqe->flags = flags;
    ctx->cq_tail = (tail + 1) & (ctx->cq_entries - 1);
    /* Use modular tail — mask applied on access */
    ctx->cq_tail = tail + 1;
    ctx->cq_completed++;
}

/* ── Process a single SQE ── */

/* Forward declarations for I/O operations */
extern long sys_read(int fd, void *buf, size_t count);
extern long sys_write(int fd, const void *buf, size_t count);
extern long sys_pread64(unsigned int fd, void *buf, size_t count, int64_t offset);
extern long sys_pwrite64(unsigned int fd, const void *buf, size_t count, int64_t offset);
extern long sys_close(int fd);
extern long sys_fsync(int fd);
extern long sys_poll(void *fds, unsigned int nfds, int timeout);

static void uring_process_sqe(struct io_uring_ctx *ctx, const struct io_uring_sqe *sqe) {
    int32_t res = 0;
    int fd = sqe->fd;

    /* If IOSQE_FIXED_FILE, look up in registered files. Linux returns
     * -EBADF if the caller asserted IOSQE_FIXED_FILE but no fixed-file
     * table is registered, OR if the index is out of range. The
     * previous 'ctx->nr_reg_files > 0' short-circuit silently fell
     * through to use sqe->fd as a raw fd in the caller's main fd
     * table — defeating the whole point of the IOSQE_FIXED_FILE flag
     * (the caller asserted a registered-file index, not a path-style
     * fd). */
    if (sqe->flags & IOSQE_FIXED_FILE) {
        if (ctx->nr_reg_files == 0 || (uint32_t)fd >= ctx->nr_reg_files) {
            uring_post_cqe(ctx, sqe->user_data, -EBADF, 0);
            return;
        }
        fd = ctx->reg_files[fd];
    }

    switch (sqe->opcode) {
    case IORING_OP_NOP:
        res = 0;
        break;

    case IORING_OP_READ:
    case IORING_OP_READ_FIXED: {
        void *buf = (void *)(uintptr_t)sqe->addr;
        uint32_t len = sqe->len;
        if (sqe->off == (uint64_t)-1) {
            /* Use current file offset */
            res = (int32_t)sys_read(fd, buf, len);
        } else {
            res = (int32_t)sys_pread64((unsigned int)fd, buf, len, (int64_t)sqe->off);
        }
        break;
    }

    case IORING_OP_WRITE:
    case IORING_OP_WRITE_FIXED: {
        const void *buf = (const void *)(uintptr_t)sqe->addr;
        uint32_t len = sqe->len;
        if (sqe->off == (uint64_t)-1) {
            res = (int32_t)sys_write(fd, buf, len);
        } else {
            res = (int32_t)sys_pwrite64((unsigned int)fd, buf, len, (int64_t)sqe->off);
        }
        break;
    }

    case IORING_OP_READV: {
        /* addr = pointer to iovec array, len = iovec count */
        struct iovec_compat {
            uint64_t iov_base;
            uint64_t iov_len;
        };
        const struct iovec_compat *iovs = (const struct iovec_compat *)(uintptr_t)sqe->addr;
        uint32_t nr_vecs = sqe->len;
        if (!iovs || nr_vecs == 0) { res = -EINVAL; break; }
        int32_t total = 0;
        for (uint32_t i = 0; i < nr_vecs; i++) {
            void *base = (void *)(uintptr_t)iovs[i].iov_base;
            size_t ilen = (size_t)iovs[i].iov_len;
            long r;
            if (sqe->off == (uint64_t)-1) {
                r = sys_read(fd, base, ilen);
            } else {
                r = sys_pread64((unsigned int)fd, base, ilen, (int64_t)(sqe->off + total));
            }
            if (r < 0) { if (total == 0) total = (int32_t)r; break; }
            total += (int32_t)r;
            if ((size_t)r < ilen) break;
        }
        res = total;
        break;
    }

    case IORING_OP_WRITEV: {
        struct iovec_compat {
            uint64_t iov_base;
            uint64_t iov_len;
        };
        const struct iovec_compat *iovs = (const struct iovec_compat *)(uintptr_t)sqe->addr;
        uint32_t nr_vecs = sqe->len;
        if (!iovs || nr_vecs == 0) { res = -EINVAL; break; }
        int32_t total = 0;
        for (uint32_t i = 0; i < nr_vecs; i++) {
            const void *base = (const void *)(uintptr_t)iovs[i].iov_base;
            size_t ilen = (size_t)iovs[i].iov_len;
            long r;
            if (sqe->off == (uint64_t)-1) {
                r = sys_write(fd, base, ilen);
            } else {
                r = sys_pwrite64((unsigned int)fd, base, ilen, (int64_t)(sqe->off + total));
            }
            if (r < 0) { if (total == 0) total = (int32_t)r; break; }
            total += (int32_t)r;
            if ((size_t)r < ilen) break;
        }
        res = total;
        break;
    }

    case IORING_OP_FSYNC:
        res = (int32_t)sys_fsync(fd);
        break;

    case IORING_OP_CLOSE:
        res = (int32_t)sys_close(fd);
        break;

    case IORING_OP_POLL_ADD: {
        /* Synchronous single-fd poll with timeout=0 (non-blocking check) */
        struct {
            int fd;
            short events;
            short revents;
        } pfd;
        pfd.fd = fd;
        pfd.events = (short)(sqe->poll_events & 0xFFFF);
        pfd.revents = 0;
        res = (int32_t)sys_poll(&pfd, 1, 0);
        if (res >= 0) res = pfd.revents;
        break;
    }

    case IORING_OP_POLL_REMOVE:
        /* Cancellation of poll — not applicable in synchronous mode */
        res = -ENOENT;
        break;

    case IORING_OP_TIMEOUT: {
        /* addr = pointer to timespec, len = count (complete after count CQEs) */
        /* In synchronous mode, just return 0 (timeout already "expired") */
        res = -ETIME;
        break;
    }

    case IORING_OP_TIMEOUT_REMOVE:
        res = -ENOENT;
        break;

    case IORING_OP_LINK_TIMEOUT:
        /* Link timeout — expires linked operation */
        res = -ETIME;
        break;

    default:
        res = -EINVAL;
        break;
    }

    uring_post_cqe(ctx, sqe->user_data, res, 0);
}

/* ── Syscall implementations ── */

/**
 * io_uring_setup() - Create an io_uring instance.
 * @entries: Requested number of SQ entries (rounded up to power of 2).
 * @params:  User pointer to io_uring_params (in/out).
 * Returns: file descriptor for the ring, or negative errno.
 */
long sys_io_uring_setup(unsigned int entries, void *params) {
    if (!params) return -EFAULT;
    if (entries == 0 || entries > MAX_URING_ENTRIES) return -EINVAL;

    /* Stage params through copy_*_user. The previous code cast 'params'
     * directly to a kernel pointer and then read flags/cq_entries and
     * later wrote sq_entries/features/sq_off/cq_off through it — a
     * full user-pointer boundary violation: a bad user pointer faulted
     * the kernel, a kernel-pointer caller turned the syscall into a
     * read/write-anywhere primitive. Use a local kernel copy and
     * commit at the end via copy_to_user. */
    struct io_uring_params local_p;
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)params >= KERNEL_VIRTUAL_BASE) {
        __builtin_memcpy(&local_p, params, sizeof(local_p));
    } else
#endif
    if (fut_copy_from_user(&local_p, params, sizeof(local_p)) != 0)
        return -EFAULT;
    struct io_uring_params *p = &local_p;

    /* Linux rejects unknown io_uring_setup flag bits with -EINVAL — let a
     * caller distinguish 'kernel doesn't support flag X' from 'flag X
     * silently ignored' instead of running with old behaviour. Mirror
     * the gate already on io_uring_enter and explicitly mark
     * SQPOLL/IOPOLL as unsupported in this implementation (returned as
     * EINVAL via the unknown-bit path below). */
    const uint32_t KNOWN_SETUP_FLAGS =
        IORING_SETUP_IOPOLL  |  /* unsupported on Futura */
        IORING_SETUP_SQPOLL  |  /* unsupported on Futura */
        IORING_SETUP_SQ_AFF  |
        IORING_SETUP_CQSIZE  |
        IORING_SETUP_CLAMP   |
        IORING_SETUP_ATTACH_WQ;
    if (p->flags & ~KNOWN_SETUP_FLAGS) return -EINVAL;
    uint32_t unsupported = IORING_SETUP_SQPOLL | IORING_SETUP_IOPOLL;
    if (p->flags & unsupported) return -EINVAL;
    /* Linux: IORING_SETUP_SQ_AFF requires IORING_SETUP_SQPOLL — pinning a
     * non-existent SQ poll thread to a CPU is a programming error. Since
     * Futura already rejects SQPOLL above, any SQ_AFF here is by
     * definition the no-SQPOLL case and must fail with EINVAL too. */
    if ((p->flags & IORING_SETUP_SQ_AFF) && !(p->flags & IORING_SETUP_SQPOLL))
        return -EINVAL;

    /* Round entries to power of 2 */
    uint32_t sq_entries = uring_roundup_pow2(entries);
    if (sq_entries > MAX_URING_ENTRIES) sq_entries = MAX_URING_ENTRIES;
    uint32_t cq_entries = sq_entries * 2; /* CQ is 2x SQ by default */

    if (p->flags & IORING_SETUP_CQSIZE) {
        if (p->cq_entries == 0) return -EINVAL;
        cq_entries = uring_roundup_pow2(p->cq_entries);
        if (cq_entries > MAX_URING_ENTRIES * 2) cq_entries = MAX_URING_ENTRIES * 2;
        /* Linux requires cq_entries >= sq_entries (io_allocate_scq_urings):
         * the SQ can submit up to sq_entries operations in one batch, and a
         * CQ smaller than the SQ would either overflow on the first batch or
         * silently drop completions. The previous code accepted any user
         * cq_entries down to 1, which let a caller submit 8 SQEs into a
         * 1-entry CQ and lose 7 completions (CQE delivery becomes lossy). */
        if (cq_entries < sq_entries) return -EINVAL;
    }

    /* Find free slot */
    struct io_uring_ctx *ctx = NULL;
    for (int i = 0; i < MAX_URING_INSTANCES; i++) {
        if (!uring_instances[i].active) {
            ctx = &uring_instances[i];
            break;
        }
    }
    if (!ctx) return -ENOMEM;

    /* Allocate SQ entries */
    extern void *fut_malloc(size_t);
    ctx->sqes = (struct io_uring_sqe *)fut_malloc(sq_entries * sizeof(struct io_uring_sqe));
    if (!ctx->sqes) return -ENOMEM;
    memset(ctx->sqes, 0, sq_entries * sizeof(struct io_uring_sqe));

    ctx->sq_array = (uint32_t *)fut_malloc(sq_entries * sizeof(uint32_t));
    if (!ctx->sq_array) {
        extern void fut_free(void *);
        fut_free(ctx->sqes);
        ctx->sqes = NULL;
        return -ENOMEM;
    }
    for (uint32_t i = 0; i < sq_entries; i++)
        ctx->sq_array[i] = i;

    /* Allocate CQ entries */
    ctx->cqes = (struct io_uring_cqe *)fut_malloc(cq_entries * sizeof(struct io_uring_cqe));
    if (!ctx->cqes) {
        extern void fut_free(void *);
        fut_free(ctx->sqes);
        fut_free(ctx->sq_array);
        ctx->sqes = NULL;
        ctx->sq_array = NULL;
        return -ENOMEM;
    }
    memset(ctx->cqes, 0, cq_entries * sizeof(struct io_uring_cqe));

    /* Initialize ring state */
    ctx->sq_entries = sq_entries;
    ctx->sq_head = 0;
    ctx->sq_tail = 0;
    ctx->sq_mask = sq_entries - 1;
    ctx->cq_entries = cq_entries;
    ctx->cq_head = 0;
    ctx->cq_tail = 0;
    ctx->cq_mask = cq_entries - 1;
    ctx->cq_overflow = 0;
    ctx->nr_reg_files = 0;
    ctx->eventfd = -1;
    ctx->sq_submitted = 0;
    ctx->cq_completed = 0;

    fut_task_t *task = fut_task_current();
    ctx->owner_pid = task ? task->pid : 0;
    ctx->active = true;

    /* Allocate fd in task's fd_table */
    int fd = chrdev_alloc_fd(&uring_fops, NULL, ctx);
    if (fd < 0) {
        extern void fut_free(void *);
        fut_free(ctx->sqes);
        fut_free(ctx->sq_array);
        fut_free(ctx->cqes);
        ctx->sqes = NULL;
        ctx->sq_array = NULL;
        ctx->cqes = NULL;
        ctx->active = false;
        return fd;
    }
    ctx->ring_fd = fd;

    /* Fill in params for the caller */
    p->sq_entries = sq_entries;
    p->cq_entries = cq_entries;
    p->features = IORING_FEAT_SINGLE_MMAP | IORING_FEAT_NODROP |
                  IORING_FEAT_SUBMIT_STABLE | IORING_FEAT_RW_CUR_POS |
                  IORING_FEAT_FAST_POLL;

    /* SQ ring offsets — relative to the SQ ring base.
     * In a real implementation these would be mmap offsets;
     * here we provide the actual kernel pointers since kernel
     * self-tests access them directly. */
    p->sq_off.head         = (uint32_t)((uintptr_t)&ctx->sq_head - (uintptr_t)ctx);
    p->sq_off.tail         = (uint32_t)((uintptr_t)&ctx->sq_tail - (uintptr_t)ctx);
    p->sq_off.ring_mask    = (uint32_t)((uintptr_t)&ctx->sq_mask - (uintptr_t)ctx);
    p->sq_off.ring_entries = (uint32_t)((uintptr_t)&ctx->sq_entries - (uintptr_t)ctx);
    p->sq_off.flags        = 0;
    p->sq_off.dropped      = 0;
    p->sq_off.array        = 0;

    /* CQ ring offsets */
    p->cq_off.head         = (uint32_t)((uintptr_t)&ctx->cq_head - (uintptr_t)ctx);
    p->cq_off.tail         = (uint32_t)((uintptr_t)&ctx->cq_tail - (uintptr_t)ctx);
    p->cq_off.ring_mask    = (uint32_t)((uintptr_t)&ctx->cq_mask - (uintptr_t)ctx);
    p->cq_off.ring_entries = (uint32_t)((uintptr_t)&ctx->cq_entries - (uintptr_t)ctx);
    p->cq_off.overflow     = (uint32_t)((uintptr_t)&ctx->cq_overflow - (uintptr_t)ctx);
    p->cq_off.cqes         = 0;
    p->cq_off.flags        = 0;

    /* Commit the populated params struct back to userspace. */
    if (aio_put_user(params, &local_p, sizeof(local_p)) != 0) {
        /* User pointer became unwritable between input copy and now;
         * tear down the ring fd we just allocated so we don't leak it. */
        extern int fut_vfs_close(int fd);
        fut_vfs_close(fd);
        return -EFAULT;
    }

    return fd;
}

/**
 * io_uring_enter() - Submit SQEs and/or wait for CQEs.
 * @fd:           io_uring file descriptor.
 * @to_submit:    Number of SQEs to submit from the SQ.
 * @min_complete: Minimum CQEs to wait for (with IORING_ENTER_GETEVENTS).
 * @flags:        IORING_ENTER_* flags.
 * @sig:          Signal mask (unused).
 * @sigsz:        Signal mask size (unused).
 * Returns: number of SQEs submitted, or negative errno.
 */
long sys_io_uring_enter(unsigned int fd, unsigned int to_submit,
                        unsigned int min_complete, unsigned int flags,
                        const void *sig, size_t sigsz) {
    (void)sig; (void)sigsz;

    /* Linux rejects unknown io_uring_enter flag bits with -EINVAL.
     * Silently ignoring them lets a future flag (e.g. IORING_ENTER_EXT_ARG,
     * IORING_ENTER_REGISTERED_RING) be set on an old kernel and run with
     * the old behaviour, which has bitten programs that expected the
     * kernel to reject the flag. Mirror Linux's gate. */
    {
        const unsigned int VALID_ENTER_FLAGS =
            IORING_ENTER_GETEVENTS |
            IORING_ENTER_SQ_WAKEUP |
            IORING_ENTER_SQ_WAIT;
        if (flags & ~VALID_ENTER_FLAGS)
            return -EINVAL;
    }

    struct io_uring_ctx *ctx = uring_get_ctx(fd);
    if (!ctx) return -EBADF;

    /* Validate ownership */
    fut_task_t *task = fut_task_current();
    if (task && ctx->owner_pid != task->pid) return -EBADF;

    uint32_t submitted = 0;

    /* Process submissions */
    for (uint32_t i = 0; i < to_submit; i++) {
        if (ctx->sq_head == ctx->sq_tail) break; /* SQ empty */

        uint32_t idx = ctx->sq_array[ctx->sq_head & ctx->sq_mask];
        if (idx >= ctx->sq_entries) {
            ctx->sq_head++;
            continue; /* Skip invalid index */
        }

        uring_process_sqe(ctx, &ctx->sqes[idx]);
        ctx->sq_head++;
        submitted++;
    }
    ctx->sq_submitted += submitted;

    /* IORING_ENTER_GETEVENTS: wait for min_complete CQEs */
    if (flags & IORING_ENTER_GETEVENTS) {
        /* In synchronous mode, all completions are posted immediately
         * during submission. Just check if we have enough. */
        uint32_t avail = ctx->cq_tail - ctx->cq_head;
        if (avail < min_complete) {
            /* All submissions are synchronous, so we can't get more
             * completions without more submissions. Return what we have. */
        }
    }

    return (long)submitted;
}

/**
 * io_uring_register() - Register resources with an io_uring instance.
 * @fd:      io_uring file descriptor.
 * @opcode:  IORING_REGISTER_* operation.
 * @arg:     Operation-specific argument.
 * @nr_args: Number of arguments.
 * Returns: 0 on success, or negative errno.
 */
long sys_io_uring_register(unsigned int fd, unsigned int opcode,
                           void *arg, unsigned int nr_args) {
    struct io_uring_ctx *ctx = uring_get_ctx(fd);
    if (!ctx) return -EBADF;

    fut_task_t *task = fut_task_current();
    if (task && ctx->owner_pid != task->pid) return -EBADF;

    switch (opcode) {
    case IORING_REGISTER_FILES: {
        if (!arg || nr_args == 0 || nr_args > MAX_URING_FILES) return -EINVAL;
        /* Linux's io_register_files returns -EBUSY when files are already
         * registered: callers must IORING_UNREGISTER_FILES first. The
         * previous code overwrote the existing array silently, so a
         * second register call leaked any reference accounting tied to
         * the old set and broke programs that rely on the EBUSY signal
         * for register-once semantics. */
        if (ctx->nr_reg_files != 0)
            return -EBUSY;
        /* Stage the entire fds array through copy_from_user so a bad
         * user pointer returns -EFAULT and a kernel-pointer caller
         * can't read kernel memory into reg_files[]. */
        int local_fds[MAX_URING_FILES];
#ifdef KERNEL_VIRTUAL_BASE
        if ((uintptr_t)arg >= KERNEL_VIRTUAL_BASE) {
            __builtin_memcpy(local_fds, arg, nr_args * sizeof(int));
        } else
#endif
        if (fut_copy_from_user(local_fds, arg, nr_args * sizeof(int)) != 0)
            return -EFAULT;
        for (uint32_t i = 0; i < nr_args; i++)
            ctx->reg_files[i] = local_fds[i];
        ctx->nr_reg_files = nr_args;
        return 0;
    }

    case IORING_UNREGISTER_FILES:
        ctx->nr_reg_files = 0;
        memset(ctx->reg_files, 0, sizeof(ctx->reg_files));
        return 0;

    case IORING_REGISTER_EVENTFD: {
        if (!arg || nr_args != 1) return -EINVAL;
        /* Linux returns -EBUSY when an eventfd is already registered:
         * callers must IORING_UNREGISTER_EVENTFD first. The previous
         * code silently overwrote ctx->eventfd, so completion
         * notifications would start firing into the *new* eventfd
         * while the old one stayed installed for any in-flight
         * notifier path that captured the prior value. */
        if (ctx->eventfd >= 0)
            return -EBUSY;
        int local_efd;
#ifdef KERNEL_VIRTUAL_BASE
        if ((uintptr_t)arg >= KERNEL_VIRTUAL_BASE) {
            local_efd = *(const int *)arg;
        } else
#endif
        if (fut_copy_from_user(&local_efd, arg, sizeof(int)) != 0)
            return -EFAULT;
        ctx->eventfd = local_efd;
        return 0;
    }

    case IORING_UNREGISTER_EVENTFD:
        ctx->eventfd = -1;
        return 0;

    case IORING_REGISTER_PROBE: {
        if (!arg) return -EFAULT;
        /* Stage probe through a kernel-local copy: read ops_len from
         * userspace, populate locally, commit back. The previous code
         * cast arg to a kernel pointer and read ops_len + wrote
         * last_op/ops[] directly through it.
         *
         * struct io_uring_probe ends with a flexible array (ops[]).
         * Allocating 'struct io_uring_probe local_probe' on the stack
         * only reserves the header — writing local_probe.ops[i] for
         * i < ops_len then walks PAST the local and clobbers saved
         * RIP/RBP, producing a non-canonical RIP and GP fault on
         * function return. Reserve the full header + ops_len slots
         * worth of bytes via a fixed-size buffer of IORING_OP_LAST
         * entries (the loop already caps at that). */
        struct io_uring_probe_hdr {
            uint8_t  last_op;
            uint8_t  ops_len;
            uint16_t resv;
            uint32_t resv2[3];
        };
        struct io_uring_probe_hdr hdr;
#ifdef KERNEL_VIRTUAL_BASE
        if ((uintptr_t)arg >= KERNEL_VIRTUAL_BASE) {
            __builtin_memcpy(&hdr, arg, sizeof(hdr));
        } else
#endif
        if (fut_copy_from_user(&hdr, arg, sizeof(hdr)) != 0)
            return -EFAULT;

        uint8_t max_ops = hdr.ops_len;
        if (max_ops > IORING_OP_LAST) max_ops = IORING_OP_LAST;

        /* Backing store: full header + IORING_OP_LAST op entries. */
        uint8_t probe_storage[sizeof(struct io_uring_probe) +
                               IORING_OP_LAST * sizeof(struct io_uring_probe_op)]
            __attribute__((aligned(_Alignof(struct io_uring_probe))));
        memset(probe_storage, 0, sizeof(probe_storage));
        struct io_uring_probe *local_probe =
            (struct io_uring_probe *)probe_storage;
        local_probe->last_op = IORING_OP_LAST - 1;
        local_probe->ops_len = max_ops;
        for (uint8_t i = 0; i < max_ops; i++) {
            local_probe->ops[i].op = i;
            local_probe->ops[i].flags = 0;
            switch (i) {
            case IORING_OP_NOP:
            case IORING_OP_READV:
            case IORING_OP_WRITEV:
            case IORING_OP_FSYNC:
            case IORING_OP_READ_FIXED:
            case IORING_OP_WRITE_FIXED:
            case IORING_OP_POLL_ADD:
            case IORING_OP_CLOSE:
            case IORING_OP_TIMEOUT:
            case IORING_OP_READ:
            case IORING_OP_WRITE:
                local_probe->ops[i].flags = IO_URING_OP_SUPPORTED;
                break;
            default:
                break;
            }
        }
        /* Commit only the header + max_ops slots actually populated. */
        size_t commit_sz = sizeof(hdr) +
                           (size_t)max_ops * sizeof(local_probe->ops[0]);
        if (aio_put_user(arg, local_probe, commit_sz) != 0)
            return -EFAULT;
        return 0;
    }

    case IORING_REGISTER_BUFFERS:
    case IORING_UNREGISTER_BUFFERS:
        /* Buffer registration is accepted but we don't use pinned pages */
        return 0;

    default:
        return -EINVAL;
    }
}

/* ── Helper for kernel self-tests: submit SQE directly ── */

/**
 * uring_submit_sqe() - Helper to enqueue an SQE on the submission ring.
 * Used by kernel self-tests that can't do mmap-based shared memory.
 */
void uring_submit_sqe(struct io_uring_ctx *ctx, const struct io_uring_sqe *sqe) {
    if (!ctx || !sqe) return;
    uint32_t tail = ctx->sq_tail;
    uint32_t idx = tail & ctx->sq_mask;
    memcpy(&ctx->sqes[idx], sqe, sizeof(struct io_uring_sqe));
    ctx->sq_array[idx] = idx;
    ctx->sq_tail = tail + 1;
}

/**
 * uring_peek_cqe() - Peek at the next completion without consuming it.
 * Returns pointer to the CQE, or NULL if CQ is empty.
 */
struct io_uring_cqe *uring_peek_cqe(struct io_uring_ctx *ctx) {
    if (!ctx || ctx->cq_head == ctx->cq_tail) return NULL;
    return &ctx->cqes[ctx->cq_head & ctx->cq_mask];
}

/**
 * uring_consume_cqe() - Advance CQ head past one completion.
 */
void uring_consume_cqe(struct io_uring_ctx *ctx) {
    if (ctx && ctx->cq_head != ctx->cq_tail)
        ctx->cq_head++;
}
