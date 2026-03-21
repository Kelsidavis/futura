/* kernel/sys_fadvise.c - File access pattern advisory
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements fadvise64() to allow applications to hint about their
 * intended file access patterns, enabling I/O optimization.
 * Currently accepts all valid hints as no-ops (common for early-stage
 * kernels and in-memory filesystems like ramfs).
 */

#include <kernel/fut_task.h>
#include <kernel/fut_vfs.h>
#include <kernel/errno.h>
#include <fcntl.h>
#include <stdint.h>

/* POSIX_FADV_* constants (Linux ABI) */
#define POSIX_FADV_NORMAL     0  /* No special treatment */
#define POSIX_FADV_RANDOM     1  /* Expect random access */
#define POSIX_FADV_SEQUENTIAL 2  /* Expect sequential access */
#define POSIX_FADV_WILLNEED   3  /* Will need this data soon */
#define POSIX_FADV_DONTNEED   4  /* Don't need this data anymore */
#define POSIX_FADV_NOREUSE    5  /* Data will be accessed once */

/**
 * sys_fadvise64 - Provide file access advisory
 *
 * @param fd:     File descriptor
 * @param offset: Starting offset of advisory region
 * @param len:    Length of advisory region (0 = to end of file)
 * @param advice: Advisory hint (POSIX_FADV_*)
 *
 * Unlike most syscalls, fadvise64 returns error codes directly
 * (not negated) per POSIX. However Linux returns negative errno,
 * and we follow Linux convention for consistency.
 *
 * Returns:
 *   - 0 on success (advisory accepted)
 *   - -EBADF if fd is invalid
 *   - -EINVAL if advice is unknown
 *   - -ESPIPE if fd refers to a pipe or socket
 */
long sys_fadvise64(int fd, int64_t offset, int64_t len, int advice) {
    /* Validate advice parameter */
    if (advice < POSIX_FADV_NORMAL || advice > POSIX_FADV_NOREUSE) {
        return -EINVAL;
    }

    /* Validate offset and length */
    if (offset < 0 || len < 0) {
        return -EINVAL;
    }

    /* Validate fd */
    if (fd < 0) {
        return -EBADF;
    }

    struct fut_file *file = fut_vfs_get_file(fd);
    if (!file) {
        return -EBADF;
    }

    /* O_PATH fds cannot be used for I/O — only path-based operations */
    if (file->flags & O_PATH)
        return -EBADF;

    /* Pipes and sockets are not seekable — fadvise doesn't apply */
    if (file->vnode && (file->vnode->type == VN_FIFO || file->vnode->type == VN_SOCK)) {
        return -ESPIPE;
    }

    /* Accept the advisory — ramfs and in-memory filesystems benefit from
     * the WILLNEED/DONTNEED hints once page cache is implemented.
     * For now, all hints are no-ops which is valid per POSIX. */
    return 0;
}
