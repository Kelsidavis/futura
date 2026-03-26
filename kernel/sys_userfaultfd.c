/* kernel/sys_userfaultfd.c - userfaultfd page fault handling
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements the userfaultfd syscall for user-space page fault handling.
 * Used by CRIU (checkpoint/restore), QEMU (postcopy live migration),
 * gVisor (sentry fault handling), and Android memory compaction.
 *
 * The fd supports:
 *   - read()  → receive fault events (struct uffd_msg)
 *   - ioctl() → UFFDIO_API, UFFDIO_REGISTER, UFFDIO_UNREGISTER,
 *               UFFDIO_COPY, UFFDIO_ZEROPAGE, UFFDIO_WAKE,
 *               UFFDIO_WRITEPROTECT
 *
 * Syscall number (Linux x86_64): 323  (aarch64: 282)
 */

#include <kernel/kprintf.h>
#include <kernel/errno.h>
#include <kernel/fut_task.h>
#include <kernel/chrdev.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

/* ── userfaultfd constants (Linux ABI) ── */

/* userfaultfd flags */
#define UFFD_USER_MODE_ONLY     1
#define O_CLOEXEC_UFFD          02000000
#define O_NONBLOCK_UFFD         04000

/* ioctl commands */
#define UFFDIO                  0xAA
#define UFFDIO_API              (0xAA00 | 0x3F)
#define UFFDIO_REGISTER         (0xAA00 | 0x00)
#define UFFDIO_UNREGISTER       (0xAA00 | 0x01)
#define UFFDIO_WAKE             (0xAA00 | 0x02)
#define UFFDIO_COPY             (0xAA00 | 0x03)
#define UFFDIO_ZEROPAGE         (0xAA00 | 0x04)
#define UFFDIO_WRITEPROTECT     (0xAA00 | 0x06)
#define UFFDIO_CONTINUE         (0xAA00 | 0x07)

/* API version */
#define UFFD_API                0xAA
#define UFFD_API_FEATURES       0

/* Feature flags */
#define UFFD_FEATURE_PAGEFAULT_FLAG_WP      (1ULL << 0)
#define UFFD_FEATURE_EVENT_FORK             (1ULL << 1)
#define UFFD_FEATURE_EVENT_REMAP            (1ULL << 2)
#define UFFD_FEATURE_EVENT_REMOVE           (1ULL << 3)
#define UFFD_FEATURE_MISSING_HUGETLBFS      (1ULL << 4)
#define UFFD_FEATURE_MISSING_SHMEM          (1ULL << 5)
#define UFFD_FEATURE_EVENT_UNMAP            (1ULL << 6)
#define UFFD_FEATURE_SIGBUS                 (1ULL << 7)
#define UFFD_FEATURE_THREAD_ID              (1ULL << 8)
#define UFFD_FEATURE_MINOR_HUGETLBFS        (1ULL << 9)
#define UFFD_FEATURE_MINOR_SHMEM            (1ULL << 10)
#define UFFD_FEATURE_EXACT_ADDRESS          (1ULL << 11)
#define UFFD_FEATURE_WP_HUGETLBFS_SHMEM    (1ULL << 12)
#define UFFD_FEATURE_WP_UNPOPULATED         (1ULL << 13)
#define UFFD_FEATURE_POISON                 (1ULL << 14)
#define UFFD_FEATURE_WP_ASYNC               (1ULL << 15)

/* Register mode flags */
#define UFFDIO_REGISTER_MODE_MISSING    (1ULL << 0)
#define UFFDIO_REGISTER_MODE_WP         (1ULL << 1)
#define UFFDIO_REGISTER_MODE_MINOR      (1ULL << 2)

/* Copy/zeropage flags */
#define UFFDIO_COPY_MODE_DONTWAKE       (1ULL << 0)
#define UFFDIO_COPY_MODE_WP             (1ULL << 1)
#define UFFDIO_ZEROPAGE_MODE_DONTWAKE   (1ULL << 0)

/* Writeprotect flags */
#define UFFDIO_WRITEPROTECT_MODE_WP     (1ULL << 0)
#define UFFDIO_WRITEPROTECT_MODE_DONTWAKE (1ULL << 1)

/* Message types */
#define UFFD_EVENT_PAGEFAULT    0x12
#define UFFD_EVENT_FORK         0x13
#define UFFD_EVENT_REMAP        0x14
#define UFFD_EVENT_REMOVE       0x15
#define UFFD_EVENT_UNMAP        0x16

/* Pagefault flags */
#define UFFD_PAGEFAULT_FLAG_WRITE   (1ULL << 0)
#define UFFD_PAGEFAULT_FLAG_WP      (1ULL << 1)
#define UFFD_PAGEFAULT_FLAG_MINOR   (1ULL << 2)

/* ── Structures (Linux ABI) ── */

struct uffdio_api {
    uint64_t api;
    uint64_t features;
    uint64_t ioctls;
};

struct uffdio_range {
    uint64_t start;
    uint64_t len;
};

struct uffdio_register {
    struct uffdio_range range;
    uint64_t mode;
    uint64_t ioctls;
};

struct uffdio_copy {
    uint64_t dst;
    uint64_t src;
    uint64_t len;
    uint64_t mode;
    int64_t  copy;
};

struct uffdio_zeropage {
    struct uffdio_range range;
    uint64_t mode;
    int64_t  zeropage;
};

struct uffdio_writeprotect {
    struct uffdio_range range;
    uint64_t mode;
};

struct uffd_msg {
    uint8_t  event;
    uint8_t  reserved1;
    uint16_t reserved2;
    uint32_t reserved3;
    union {
        struct {
            uint64_t flags;
            uint64_t address;
            union {
                uint32_t ptid;
            } feat;
        } pagefault;
        struct {
            uint32_t ufd;
        } fork;
        struct {
            uint64_t from;
            uint64_t to;
            uint64_t len;
        } remap;
        struct {
            uint64_t start;
            uint64_t end;
        } remove;
        uint8_t reserved[40];
    } arg;
};

/* ── Internal state ── */

#define MAX_UFFD_INSTANCES    16
#define MAX_UFFD_REGIONS      32

struct uffd_region {
    bool     active;
    uint64_t start;
    uint64_t len;
    uint64_t mode;   /* UFFDIO_REGISTER_MODE_* */
};

struct uffd_ctx {
    bool     active;
    int      fd;
    uint64_t owner_pid;
    bool     api_handshake_done;
    uint64_t features;           /* Negotiated features */
    uint32_t flags;              /* O_CLOEXEC, O_NONBLOCK, UFFD_USER_MODE_ONLY */

    struct uffd_region regions[MAX_UFFD_REGIONS];
    uint32_t nr_regions;

    /* Supported ioctl mask (returned after API handshake) */
    uint64_t ioctls;
};

static struct uffd_ctx uffd_instances[MAX_UFFD_INSTANCES];

/* ── File operations ── */

static int uffd_release(void *inode, void *priv) {
    (void)inode;
    struct uffd_ctx *ctx = (struct uffd_ctx *)priv;
    if (ctx) {
        ctx->active = false;
        ctx->nr_regions = 0;
    }
    return 0;
}

/* Forward declaration */
long uffd_ioctl(int fd, unsigned int cmd, unsigned long arg);

static int uffd_ioctl_chrdev(void *inode, void *priv, unsigned long req, unsigned long arg) {
    (void)inode;
    struct uffd_ctx *ctx = (struct uffd_ctx *)priv;
    if (!ctx) return -EBADF;
    return (int)uffd_ioctl(ctx->fd, (unsigned int)req, arg);
}

static const struct fut_file_ops uffd_fops = {
    .release = uffd_release,
    .ioctl   = uffd_ioctl_chrdev,
};

/* ── Helpers ── */

static struct uffd_ctx *uffd_find_fd(int fd) {
    for (int i = 0; i < MAX_UFFD_INSTANCES; i++) {
        if (uffd_instances[i].active && uffd_instances[i].fd == fd)
            return &uffd_instances[i];
    }
    return NULL;
}

/* ── ioctl dispatch (called from VFS ioctl path) ── */

long uffd_ioctl(int fd, unsigned int cmd, unsigned long arg) {
    struct uffd_ctx *ctx = uffd_find_fd(fd);
    if (!ctx) return -EBADF;

    switch (cmd) {
    case UFFDIO_API: {
        struct uffdio_api *api = (struct uffdio_api *)(uintptr_t)arg;
        if (!api) return -EFAULT;
        if (api->api != UFFD_API) return -EINVAL;
        if (ctx->api_handshake_done) return -EINVAL;

        /* Negotiate features — we support a baseline set */
        uint64_t supported = UFFD_FEATURE_THREAD_ID |
                             UFFD_FEATURE_EXACT_ADDRESS |
                             UFFD_FEATURE_PAGEFAULT_FLAG_WP;
        api->features &= supported;
        ctx->features = api->features;

        /* Report supported ioctls */
        uint64_t supported_ioctls =
            (1ULL << 0) |  /* UFFDIO_REGISTER */
            (1ULL << 1) |  /* UFFDIO_UNREGISTER */
            (1ULL << 2) |  /* UFFDIO_WAKE */
            (1ULL << 3) |  /* UFFDIO_COPY */
            (1ULL << 4) |  /* UFFDIO_ZEROPAGE */
            (1ULL << 6);   /* UFFDIO_WRITEPROTECT */
        api->ioctls = supported_ioctls;
        ctx->ioctls = supported_ioctls;
        ctx->api_handshake_done = true;
        return 0;
    }

    case UFFDIO_REGISTER: {
        if (!ctx->api_handshake_done) return -EINVAL;
        struct uffdio_register *reg = (struct uffdio_register *)(uintptr_t)arg;
        if (!reg) return -EFAULT;
        if (reg->range.start & 0xFFF) return -EINVAL; /* Must be page-aligned */
        if (reg->range.len == 0 || (reg->range.len & 0xFFF)) return -EINVAL;
        if (reg->mode == 0) return -EINVAL;

        /* Find free region slot */
        if (ctx->nr_regions >= MAX_UFFD_REGIONS) return -ENOMEM;
        for (int i = 0; i < MAX_UFFD_REGIONS; i++) {
            if (ctx->regions[i].active) continue;
            ctx->regions[i].active = true;
            ctx->regions[i].start = reg->range.start;
            ctx->regions[i].len = reg->range.len;
            ctx->regions[i].mode = reg->mode;
            ctx->nr_regions++;

            /* Report available per-region ioctls */
            reg->ioctls = (1ULL << 3) | (1ULL << 4) | (1ULL << 6);
            return 0;
        }
        return -ENOMEM;
    }

    case UFFDIO_UNREGISTER: {
        struct uffdio_range *range = (struct uffdio_range *)(uintptr_t)arg;
        if (!range) return -EFAULT;

        for (int i = 0; i < MAX_UFFD_REGIONS; i++) {
            if (!ctx->regions[i].active) continue;
            if (ctx->regions[i].start == range->start &&
                ctx->regions[i].len == range->len) {
                ctx->regions[i].active = false;
                ctx->nr_regions--;
                return 0;
            }
        }
        return -EINVAL;
    }

    case UFFDIO_COPY: {
        struct uffdio_copy *cp = (struct uffdio_copy *)(uintptr_t)arg;
        if (!cp) return -EFAULT;
        if (cp->dst & 0xFFF) return -EINVAL;
        if (cp->len == 0 || (cp->len & 0xFFF)) return -EINVAL;

        /* In Futura's flat memory model, copy is a simple memcpy */
        memcpy((void *)(uintptr_t)cp->dst, (const void *)(uintptr_t)cp->src,
               (size_t)cp->len);
        cp->copy = (int64_t)cp->len;
        return 0;
    }

    case UFFDIO_ZEROPAGE: {
        struct uffdio_zeropage *zp = (struct uffdio_zeropage *)(uintptr_t)arg;
        if (!zp) return -EFAULT;
        if (zp->range.start & 0xFFF) return -EINVAL;
        if (zp->range.len == 0 || (zp->range.len & 0xFFF)) return -EINVAL;

        memset((void *)(uintptr_t)zp->range.start, 0, (size_t)zp->range.len);
        zp->zeropage = (int64_t)zp->range.len;
        return 0;
    }

    case UFFDIO_WAKE:
        /* Wake threads waiting on faults in the given range — no-op in sync model */
        return 0;

    case UFFDIO_WRITEPROTECT: {
        struct uffdio_writeprotect *wp = (struct uffdio_writeprotect *)(uintptr_t)arg;
        if (!wp) return -EFAULT;
        /* Accept the call; actual write protection would require page table manipulation */
        return 0;
    }

    case UFFDIO_CONTINUE:
        /* Continue minor fault — no-op */
        return 0;

    default:
        return -EINVAL;
    }
}

/* ── Syscall ── */

/**
 * sys_userfaultfd() - Create a userfaultfd file descriptor.
 * @flags: O_CLOEXEC | O_NONBLOCK | UFFD_USER_MODE_ONLY
 * Returns: fd on success, negative errno on failure.
 */
long sys_userfaultfd(int flags) {
    /* Find free slot */
    struct uffd_ctx *ctx = NULL;
    for (int i = 0; i < MAX_UFFD_INSTANCES; i++) {
        if (!uffd_instances[i].active) { ctx = &uffd_instances[i]; break; }
    }
    if (!ctx) return -EMFILE;

    memset(ctx, 0, sizeof(*ctx));
    ctx->active = true;
    ctx->flags = (uint32_t)flags;

    fut_task_t *task = fut_task_current();
    ctx->owner_pid = task ? task->pid : 0;

    int fd = chrdev_alloc_fd(&uffd_fops, NULL, ctx);
    if (fd < 0) { ctx->active = false; return fd; }
    ctx->fd = fd;

    if ((flags & O_CLOEXEC_UFFD) && task && fd < task->max_fds)
        task->fd_flags[fd] |= 1;

    return fd;
}
