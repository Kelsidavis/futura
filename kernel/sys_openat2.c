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
 * Implemented:
 *   - Validates usize (must be >= sizeof(open_how))
 *   - Copies open_how from userspace
 *   - Validates resolve flags (only known RESOLVE_* accepted)
 *   - RESOLVE_NO_XDEV, RESOLVE_NO_MAGICLINKS, RESOLVE_CACHED: no-op (accepted)
 *   - RESOLVE_NO_SYMLINKS, RESOLVE_IN_ROOT: accepted as no-op
 *   - RESOLVE_BENEATH: enforced — path must stay within dirfd's subtree
 *   - Returns EINVAL for unknown resolve flags or usize too small
 *   - Returns EXDEV when RESOLVE_BENEATH is violated
 */

#include <kernel/fut_task.h>
#include <kernel/fut_vfs.h>
#include <kernel/errno.h>
#include <kernel/uaccess.h>
#include <fcntl.h>
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

/**
 * Normalize an absolute POSIX path by resolving "." and ".." components.
 * Writes result to out (out_size bytes). Returns 0 on success, negative on error.
 * Input must start with '/'.
 */
static int normalize_abs_path(const char *in, char *out, size_t out_size) {
    if (!in || in[0] != '/' || out_size < 2)
        return -1;
    char *o     = out;
    char *o_end = out + out_size - 1;
    *o++ = '/';

    /* seg_pos[depth] = position in out just before this segment was written.
     * Restored to seg_pos[depth-1] when ".." is encountered. */
    char *seg_pos[256];
    int depth = 0;

    const char *p = in + 1; /* skip leading '/' */
    while (*p) {
        while (*p == '/') p++;    /* skip consecutive slashes */
        if (!*p) break;

        const char *q = p;
        while (*q && *q != '/') q++;
        size_t len = (size_t)(q - p);

        if (len == 1 && p[0] == '.') {
            p = q;
            continue;
        }
        if (len == 2 && p[0] == '.' && p[1] == '.') {
            if (depth > 0)
                o = seg_pos[--depth]; /* pop last segment */
            /* at root ".." stays at root */
            p = q;
            continue;
        }
        if (depth >= 256)
            return -ENAMETOOLONG;
        seg_pos[depth] = o;          /* save restore point for future ".." */
        if (depth > 0) {
            if (o >= o_end) return -ENAMETOOLONG;
            *o++ = '/';
        }
        if (o + len > o_end) return -ENAMETOOLONG;
        __builtin_memcpy(o, p, len);
        o += len;
        depth++;
        p = q;
    }
    *o = '\0';
    return 0;
}

/* Returns 1 if resolved is equal to dir_path or is a direct descendant. */
static int path_is_within(const char *resolved, const char *dir_path) {
    if (!resolved || !dir_path) return 0;
    size_t dlen = 0;
    while (dir_path[dlen]) dlen++;
    /* strip trailing slash (except root) */
    while (dlen > 1 && dir_path[dlen - 1] == '/') dlen--;
    /* "/" contains everything */
    if (dlen == 1 && dir_path[0] == '/') return 1;
    /* resolved must have dir_path as prefix */
    for (size_t i = 0; i < dlen; i++)
        if (resolved[i] != dir_path[i]) return 0;
    return resolved[dlen] == '/' || resolved[dlen] == '\0';
}

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

    /* RESOLVE_NO_XDEV, RESOLVE_NO_MAGICLINKS, RESOLVE_CACHED: naturally satisfied
     * by Futura's in-memory VFS (no mount points or magic links).
     * RESOLVE_NO_SYMLINKS, RESOLVE_IN_ROOT: accepted as no-op.
     * RESOLVE_BENEATH: enforced below after path resolution. */

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

    /* Enforce RESOLVE_BENEATH: the final resolved path must remain within
     * the dirfd's subtree.  Returns -EXDEV on violation (matching Linux). */
    if ((kow.resolve & RESOLVE_BENEATH) && dirfd != AT_FDCWD) {
        struct fut_file *dir_file = vfs_get_file_from_task(task, dirfd);
        if (dir_file && dir_file->path) {
            char raw_buf[FUT_VFS_PATH_BUFFER_SIZE];
            char norm_buf[FUT_VFS_PATH_BUFFER_SIZE];
            const char *to_check;
            if (kpath[0] == '/') {
                /* Absolute path: normalize kpath itself */
                if (normalize_abs_path(kpath, norm_buf, sizeof(norm_buf)) == 0)
                    to_check = norm_buf;
                else
                    to_check = kpath;
            } else {
                /* Relative path: combine with dirfd's path, then normalize */
                int rc = fut_vfs_resolve_at(task, dirfd, kpath,
                                            raw_buf, sizeof(raw_buf));
                if (rc < 0) return -EXDEV;
                if (normalize_abs_path(raw_buf, norm_buf, sizeof(norm_buf)) == 0)
                    to_check = norm_buf;
                else
                    to_check = raw_buf;
            }
            if (!path_is_within(to_check, dir_file->path))
                return -EXDEV;
        }
    }

    /* Set transient VFS flags for path resolution control */
    if (task && (kow.resolve & RESOLVE_NO_SYMLINKS))
        task->vfs_no_symlinks = 1;

    int fd = fut_vfs_open_at(task, dirfd, kpath, (int)kow.flags, (int)kow.mode);

    /* Clear transient flags */
    if (task)
        task->vfs_no_symlinks = 0;

    /* Set FD_CLOEXEC if O_CLOEXEC requested */
#define OA2_O_CLOEXEC 0x80000
    if (fd >= 0 && (kow.flags & OA2_O_CLOEXEC)) {
        if (task && task->fd_flags && fd < task->max_fds)
            task->fd_flags[fd] |= 1 /* FD_CLOEXEC */;
    }
    return (long)fd;
}
