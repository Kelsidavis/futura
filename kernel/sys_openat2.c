/* kernel/sys_openat2.c - openat2() syscall (Linux 5.6+)
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * openat2() extends openat() with a struct open_how that includes:
 *   - flags:   open flags (O_RDONLY, O_WRONLY, etc.)
 *   - mode:    file creation mode (for O_CREAT)
 *   - resolve: path resolution control (RESOLVE_* flags)
 *
 * Phase 1 (Completed):
 *   - Validates usize (must be >= sizeof(open_how))
 *   - Copies open_how from userspace
 *   - Validates resolve flags (only known RESOLVE_* accepted)
 *   - RESOLVE_NO_XDEV, RESOLVE_NO_MAGICLINKS, RESOLVE_CACHED: no-op (accepted)
 *   - RESOLVE_NO_SYMLINKS, RESOLVE_BENEATH, RESOLVE_IN_ROOT: accepted as no-op
 *   - Delegates to sys_openat with flags and mode
 *   - Returns EINVAL for unknown resolve flags or usize too small
 */

#include <kernel/fut_task.h>
#include <kernel/fut_vfs.h>
#include <kernel/errno.h>
#include <kernel/uaccess.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef __x86_64__
#include <platform/x86_64/memory/paging.h>
#elif defined(__aarch64__)
#include <platform/arm64/memory/paging.h>
#endif

/* struct open_how — matches Linux uapi/linux/openat2.h */
struct open_how {
    uint64_t flags;   /* open flags (O_*) */
    uint64_t mode;    /* file creation mode */
    uint64_t resolve; /* RESOLVE_* flags */
};

#define OPEN_HOW_SIZE_VER0   24  /* sizeof(struct open_how) */

/* RESOLVE_* flags */
#define RESOLVE_NO_XDEV        0x01  /* Block traversal across mount points */
#define RESOLVE_NO_MAGICLINKS  0x02  /* Block magic link traversal */
#define RESOLVE_NO_SYMLINKS    0x04  /* Block symlink traversal */
#define RESOLVE_BENEATH        0x08  /* Confine resolution to subtree */
#define RESOLVE_IN_ROOT        0x10  /* Treat dirfd as root (chroot-like) */
#define RESOLVE_CACHED         0x20  /* Only use cached data */
#define RESOLVE_VALID          (RESOLVE_NO_XDEV | RESOLVE_NO_MAGICLINKS | \
                                RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH | \
                                RESOLVE_IN_ROOT | RESOLVE_CACHED)

static inline int openat2_copy_from_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)src >= KERNEL_VIRTUAL_BASE) { __builtin_memcpy(dst, src, n); return 0; }
#endif
    return fut_copy_from_user(dst, src, n);
}

/**
 * sys_openat2 - Open file with extended path resolution control.
 *
 * @param dirfd  Directory fd or AT_FDCWD
 * @param path   Path to file
 * @param how    Pointer to struct open_how
 * @param usize  Size of struct open_how as provided by userspace
 * @return fd on success, -errno on error
 */
long sys_openat2(int dirfd, const char *path, const struct open_how *how,
                 size_t usize) {
    /* usize must be at least OPEN_HOW_SIZE_VER0 */
    if (usize < OPEN_HOW_SIZE_VER0)
        return -EINVAL;

    if (!how)
        return -EFAULT;

    /* Copy open_how from user/kernel space */
    struct open_how kow = {0};
    if (openat2_copy_from_user(&kow, how, sizeof(kow)) != 0)
        return -EFAULT;

    /* Validate resolve flags — unknown bits rejected */
    if (kow.resolve & ~RESOLVE_VALID)
        return -EINVAL;

    /* Phase 1: resolve flags are accepted but treated as hints (no-op).
     * Futura's VFS is a simple in-memory FS with no mount points or
     * magic links, so RESOLVE_NO_XDEV, RESOLVE_NO_MAGICLINKS, and
     * RESOLVE_CACHED are naturally satisfied. RESOLVE_BENEATH /
     * RESOLVE_IN_ROOT / RESOLVE_NO_SYMLINKS are validated but not enforced. */

    /* Copy pathname to kernel buffer (bypass kernel-pointer EFAULT) */
    char kpath[256];
    if (!path)
        return -EFAULT;
    size_t plen = 0;
    char ch;
    while (plen < 255) {
        if (openat2_copy_from_user(&ch, path + plen, 1) != 0)
            return -EFAULT;
        kpath[plen] = ch;
        if (ch == '\0') break;
        plen++;
    }
    kpath[plen] = '\0';

    fut_task_t *task = fut_task_current();
    int fd = fut_vfs_open_at(task, dirfd, kpath, (int)kow.flags, (int)kow.mode);

    /* Set FD_CLOEXEC if O_CLOEXEC requested */
#define OA2_O_CLOEXEC 0x80000
    if (fd >= 0 && (kow.flags & OA2_O_CLOEXEC)) {
        if (task && task->fd_flags && fd < task->max_fds)
            task->fd_flags[fd] |= 1 /* FD_CLOEXEC */;
    }
    return (long)fd;
}
