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
#include <kernel/fut_vfs.h>
#include <kernel/chrdev.h>
#include <kernel/uaccess.h>
#include <fcntl.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#include <platform/platform.h>

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
        /* Stage the request through copy_from_user instead of dereferencing
         * the raw user pointer.  The previous code did
         *     api = (struct uffdio_api *)arg;
         *     if (api->api != UFFD_API) ...
         *     api->ioctls = ...;
         * which faulted the kernel for a bad user pointer and let any
         * caller pass a kernel-half address as 'arg' to read/write kernel
         * memory through the api/features/ioctls fields.  Stage a kernel
         * copy and emit via copy_to_user with the standard
         * KERNEL_VIRTUAL_BASE bypass so in-kernel selftests still work. */
        if (!arg) return -EFAULT;
        struct uffdio_api kapi;
#ifdef KERNEL_VIRTUAL_BASE
        if (arg >= KERNEL_VIRTUAL_BASE) {
            __builtin_memcpy(&kapi, (const void *)(uintptr_t)arg, sizeof(kapi));
        } else
#endif
        if (fut_copy_from_user(&kapi, (const void *)(uintptr_t)arg,
                               sizeof(kapi)) != 0)
            return -EFAULT;

        if (kapi.api != UFFD_API) return -EINVAL;
        if (ctx->api_handshake_done) return -EINVAL;

        /* Linux's userfaultfd_api rejects any feature bit the kernel
         * doesn't recognise (`if (features & ~UFFD_API_FEATURES) ret =
         * -EINVAL`). Silently masking unsupported bits — as we used to —
         * lets userspace believe a feature was negotiated and then fail
         * mysteriously when its events never carry the expected payload
         * (e.g. THREAD_ID set but no thread id in messages). Reject
         * unknown bits up front so libc feature-detection code-paths
         * see EINVAL the same way they do on Linux. */
        uint64_t supported = UFFD_FEATURE_THREAD_ID |
                             UFFD_FEATURE_EXACT_ADDRESS |
                             UFFD_FEATURE_PAGEFAULT_FLAG_WP;
        if (kapi.features & ~supported)
            return -EINVAL;
        ctx->features = kapi.features;

        /* Report supported ioctls */
        uint64_t supported_ioctls =
            (1ULL << 0) |  /* UFFDIO_REGISTER */
            (1ULL << 1) |  /* UFFDIO_UNREGISTER */
            (1ULL << 2) |  /* UFFDIO_WAKE */
            (1ULL << 3) |  /* UFFDIO_COPY */
            (1ULL << 4) |  /* UFFDIO_ZEROPAGE */
            (1ULL << 6);   /* UFFDIO_WRITEPROTECT */
        kapi.ioctls = supported_ioctls;
        ctx->ioctls = supported_ioctls;
        ctx->api_handshake_done = true;

        /* Commit the response back to userspace. */
#ifdef KERNEL_VIRTUAL_BASE
        if (arg >= KERNEL_VIRTUAL_BASE) {
            __builtin_memcpy((void *)(uintptr_t)arg, &kapi, sizeof(kapi));
        } else
#endif
        if (fut_copy_to_user((void *)(uintptr_t)arg, &kapi, sizeof(kapi)) != 0)
            return -EFAULT;
        return 0;
    }

    case UFFDIO_REGISTER: {
        if (!ctx->api_handshake_done) return -EINVAL;
        if (!arg) return -EFAULT;
        /* Stage the request through copy_from_user — see UFFDIO_API for
         * the same uaccess hazard pattern.  The previous code dereferenced
         * the raw user pointer for read AND write, exposing a kernel
         * write-anywhere primitive via the ioctls output field. */
        struct uffdio_register kreg;
#ifdef KERNEL_VIRTUAL_BASE
        if (arg >= KERNEL_VIRTUAL_BASE) {
            __builtin_memcpy(&kreg, (const void *)(uintptr_t)arg, sizeof(kreg));
        } else
#endif
        if (fut_copy_from_user(&kreg, (const void *)(uintptr_t)arg,
                               sizeof(kreg)) != 0)
            return -EFAULT;
        if (kreg.range.start & 0xFFF) return -EINVAL; /* Must be page-aligned */
        if (kreg.range.len == 0 || (kreg.range.len & 0xFFF)) return -EINVAL;
        /* Linux userfaultfd_register validates mode against the known
         * MISSING/WP/MINOR bits and returns -EINVAL on any unknown bit. */
        if (kreg.mode & ~(UFFDIO_REGISTER_MODE_MISSING |
                          UFFDIO_REGISTER_MODE_WP |
                          UFFDIO_REGISTER_MODE_MINOR))
            return -EINVAL;
        if (kreg.mode == 0) return -EINVAL;

        /* Find free region slot */
        if (ctx->nr_regions >= MAX_UFFD_REGIONS) return -ENOMEM;
        for (int i = 0; i < MAX_UFFD_REGIONS; i++) {
            if (ctx->regions[i].active) continue;
            ctx->regions[i].active = true;
            ctx->regions[i].start = kreg.range.start;
            ctx->regions[i].len = kreg.range.len;
            ctx->regions[i].mode = kreg.mode;
            ctx->nr_regions++;

            /* Report available per-region ioctls.  Commit through
             * copy_to_user — never write the response field directly. */
            kreg.ioctls = (1ULL << 3) | (1ULL << 4) | (1ULL << 6);
#ifdef KERNEL_VIRTUAL_BASE
            if (arg >= KERNEL_VIRTUAL_BASE) {
                __builtin_memcpy((void *)(uintptr_t)arg, &kreg, sizeof(kreg));
            } else
#endif
            if (fut_copy_to_user((void *)(uintptr_t)arg, &kreg,
                                 sizeof(kreg)) != 0)
                return -EFAULT;
            return 0;
        }
        return -ENOMEM;
    }

    case UFFDIO_UNREGISTER: {
        if (!arg) return -EFAULT;
        /* Stage the request through copy_from_user — same hazard. */
        struct uffdio_range krange;
#ifdef KERNEL_VIRTUAL_BASE
        if (arg >= KERNEL_VIRTUAL_BASE) {
            __builtin_memcpy(&krange, (const void *)(uintptr_t)arg, sizeof(krange));
        } else
#endif
        if (fut_copy_from_user(&krange, (const void *)(uintptr_t)arg,
                               sizeof(krange)) != 0)
            return -EFAULT;

        for (int i = 0; i < MAX_UFFD_REGIONS; i++) {
            if (!ctx->regions[i].active) continue;
            if (ctx->regions[i].start == krange.start &&
                ctx->regions[i].len == krange.len) {
                ctx->regions[i].active = false;
                ctx->nr_regions--;
                return 0;
            }
        }
        return -EINVAL;
    }

    case UFFDIO_COPY: {
        if (!arg) return -EFAULT;
        /* Stage the request through copy_from_user — same hazard as
         * UFFDIO_API/REGISTER.  The previous code dereferenced the raw
         * user pointer to read dst/src/len/mode AND wrote 'copy' back
         * directly, exposing the same write-anywhere primitive on the
         * 'copy' field for unprivileged callers passing kernel-half
         * addresses. */
        struct uffdio_copy kcp;
#ifdef KERNEL_VIRTUAL_BASE
        if (arg >= KERNEL_VIRTUAL_BASE) {
            __builtin_memcpy(&kcp, (const void *)(uintptr_t)arg, sizeof(kcp));
        } else
#endif
        if (fut_copy_from_user(&kcp, (const void *)(uintptr_t)arg,
                               sizeof(kcp)) != 0)
            return -EFAULT;
        if (kcp.dst & 0xFFF) return -EINVAL;
        if (kcp.len == 0 || (kcp.len & 0xFFF)) return -EINVAL;
        if (kcp.mode & ~(UFFDIO_COPY_MODE_DONTWAKE | UFFDIO_COPY_MODE_WP))
            return -EINVAL;
        /* dst and src are user-space addresses for the userfaultfd-
         * registered region. Reject any address that lands in kernel
         * memory for unprivileged callers: the memcpy below would
         * otherwise hand the kernel a read-anywhere / write-anywhere
         * primitive. Privileged callers (uid==0/CAP_SYS_ADMIN) are
         * allowed kernel ranges so kernel-side selftests can target a
         * static .bss page. */
#ifdef KERNEL_VIRTUAL_BASE
        if (kcp.dst + kcp.len < kcp.dst ||
            kcp.src + kcp.len < kcp.src)
            return -EFAULT;
        {
            extern fut_task_t *fut_task_current(void);
            fut_task_t *uffd_task = fut_task_current();
            bool uffd_kernel_buf_ok = uffd_task &&
                (uffd_task->uid == 0 ||
                 (uffd_task->cap_effective & (1ULL << 21 /* CAP_SYS_ADMIN */)));
            if (!uffd_kernel_buf_ok &&
                (kcp.dst >= KERNEL_VIRTUAL_BASE ||
                 kcp.src >= KERNEL_VIRTUAL_BASE ||
                 kcp.dst + kcp.len > KERNEL_VIRTUAL_BASE ||
                 kcp.src + kcp.len > KERNEL_VIRTUAL_BASE))
                return -EFAULT;
        }
#endif

        /* In Futura's flat memory model, copy is a simple memcpy */
        memcpy((void *)(uintptr_t)kcp.dst, (const void *)(uintptr_t)kcp.src,
               (size_t)kcp.len);
        kcp.copy = (int64_t)kcp.len;

        /* Commit the response — never write the 'copy' field directly. */
#ifdef KERNEL_VIRTUAL_BASE
        if (arg >= KERNEL_VIRTUAL_BASE) {
            __builtin_memcpy((void *)(uintptr_t)arg, &kcp, sizeof(kcp));
        } else
#endif
        if (fut_copy_to_user((void *)(uintptr_t)arg, &kcp, sizeof(kcp)) != 0)
            return -EFAULT;
        return 0;
    }

    case UFFDIO_ZEROPAGE: {
        if (!arg) return -EFAULT;
        /* Stage through copy_from_user — same hazard pattern as
         * UFFDIO_API/REGISTER/COPY: the previous code dereferenced the
         * raw user pointer to read range/mode AND wrote 'zeropage' back
         * directly, exposing a kernel write-anywhere primitive. */
        struct uffdio_zeropage kzp;
#ifdef KERNEL_VIRTUAL_BASE
        if (arg >= KERNEL_VIRTUAL_BASE) {
            __builtin_memcpy(&kzp, (const void *)(uintptr_t)arg, sizeof(kzp));
        } else
#endif
        if (fut_copy_from_user(&kzp, (const void *)(uintptr_t)arg,
                               sizeof(kzp)) != 0)
            return -EFAULT;
        if (kzp.range.start & 0xFFF) return -EINVAL;
        if (kzp.range.len == 0 || (kzp.range.len & 0xFFF)) return -EINVAL;
        if (kzp.mode & ~UFFDIO_ZEROPAGE_MODE_DONTWAKE)
            return -EINVAL;
        /* Same gate as UFFDIO_COPY: kernel ranges are blocked for
         * unprivileged callers (would let the memset wipe arbitrary
         * kernel pages) but allowed for uid==0/CAP_SYS_ADMIN so
         * kernel-side selftests can zero a static page. */
#ifdef KERNEL_VIRTUAL_BASE
        if (kzp.range.start + kzp.range.len < kzp.range.start)
            return -EFAULT;
        {
            extern fut_task_t *fut_task_current(void);
            fut_task_t *uffd_task = fut_task_current();
            bool uffd_kernel_buf_ok = uffd_task &&
                (uffd_task->uid == 0 ||
                 (uffd_task->cap_effective & (1ULL << 21 /* CAP_SYS_ADMIN */)));
            if (!uffd_kernel_buf_ok &&
                (kzp.range.start >= KERNEL_VIRTUAL_BASE ||
                 kzp.range.start + kzp.range.len > KERNEL_VIRTUAL_BASE))
                return -EFAULT;
        }
#endif

        memset((void *)(uintptr_t)kzp.range.start, 0, (size_t)kzp.range.len);
        kzp.zeropage = (int64_t)kzp.range.len;
#ifdef KERNEL_VIRTUAL_BASE
        if (arg >= KERNEL_VIRTUAL_BASE) {
            __builtin_memcpy((void *)(uintptr_t)arg, &kzp, sizeof(kzp));
        } else
#endif
        if (fut_copy_to_user((void *)(uintptr_t)arg, &kzp, sizeof(kzp)) != 0)
            return -EFAULT;
        return 0;
    }

    case UFFDIO_WAKE:
        /* Wake threads waiting on faults in the given range — no-op in sync model */
        return 0;

    case UFFDIO_WRITEPROTECT: {
        if (!arg) return -EFAULT;
        /* Stage through copy_from_user — same hazard pattern. */
        struct uffdio_writeprotect kwp;
#ifdef KERNEL_VIRTUAL_BASE
        if (arg >= KERNEL_VIRTUAL_BASE) {
            __builtin_memcpy(&kwp, (const void *)(uintptr_t)arg, sizeof(kwp));
        } else
#endif
        if (fut_copy_from_user(&kwp, (const void *)(uintptr_t)arg,
                               sizeof(kwp)) != 0)
            return -EFAULT;
        if (kwp.range.start & 0xFFF) return -EINVAL;
        if (kwp.range.len == 0 || (kwp.range.len & 0xFFF)) return -EINVAL;
        if (kwp.mode & ~(UFFDIO_WRITEPROTECT_MODE_WP |
                         UFFDIO_WRITEPROTECT_MODE_DONTWAKE))
            return -EINVAL;
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
    /* Validate flags: only the documented bits are accepted. Unknown
     * bits get -EINVAL like Linux. */
    const int VALID_UFFD_FLAGS = O_CLOEXEC_UFFD | 0x800 /* O_NONBLOCK */
                                  | UFFD_USER_MODE_ONLY;
    if (flags & ~VALID_UFFD_FLAGS)
        return -EINVAL;

    /* Permission gate: Linux defaults vm.unprivileged_userfaultfd=0
     * since 5.2, meaning userfaultfd(2) requires CAP_SYS_PTRACE for
     * non-root callers. uffd lets the holder pause arbitrary page
     * faults, including kernel-mode ones, which has been used as a
     * use-after-free exploitation primitive in the past — gate behind
     * the same capability. UFFD_USER_MODE_ONLY restricts the new fd
     * to user-mode faults and is allowed without CAP_SYS_PTRACE on
     * Linux 5.11+. */
    fut_task_t *task = fut_task_current();
    if (task && task->uid != 0 &&
        !(flags & UFFD_USER_MODE_ONLY) &&
        !(task->cap_effective & (1ULL << 19 /* CAP_SYS_PTRACE */))) {
        return -EPERM;
    }

    /* Find free slot */
    struct uffd_ctx *ctx = NULL;
    for (int i = 0; i < MAX_UFFD_INSTANCES; i++) {
        if (!uffd_instances[i].active) { ctx = &uffd_instances[i]; break; }
    }
    if (!ctx) return -EMFILE;

    memset(ctx, 0, sizeof(*ctx));
    ctx->active = true;
    ctx->flags = (uint32_t)flags;

    ctx->owner_pid = task ? task->pid : 0;

    int fd = chrdev_alloc_fd(&uffd_fops, NULL, ctx);
    if (fd < 0) { ctx->active = false; return fd; }
    ctx->fd = fd;

    /* Apply O_NONBLOCK to the file struct so subsequent read()/poll()
     * see the non-blocking semantics the caller asked for.  Linux's
     * userfaultfd_create installs the flag via anon_inode_getfile;
     * Futura previously validated the flag bit and stored it on ctx
     * but never propagated it to the fut_file, so blocking reads still
     * blocked even after the caller requested O_NONBLOCK. */
    if ((flags & 0x800 /* O_NONBLOCK */) && task && task->fd_table &&
        fd < task->max_fds && task->fd_table[fd])
        task->fd_table[fd]->flags |= 0x800 /* O_NONBLOCK */;

    /* Apply FD_CLOEXEC. Guard task->fd_flags non-NULL: the field is lazily
     * allocated and may still be NULL for early-init / kernel-thread
     * callers. The previous unconditional task->fd_flags[fd] |= 1 was a
     * straight NULL deref in those contexts (and FD_CLOEXEC is bit 1, so
     * spell it out instead of the magic number). */
    if ((flags & O_CLOEXEC_UFFD) && task && task->fd_flags &&
        fd < task->max_fds)
        task->fd_flags[fd] |= FD_CLOEXEC;

    return fd;
}
