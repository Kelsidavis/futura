/* sys_dup2.c - dup2() syscall implementation
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements file descriptor duplication for I/O redirection.
 */

#include <kernel/errno.h>
#include <kernel/fut_vfs.h>

extern void fut_printf(const char *fmt, ...);

/* Internal VFS functions for fd manipulation */
extern struct fut_file *vfs_get_file(int fd);
extern int vfs_alloc_specific_fd(int target_fd, struct fut_file *file);
extern void vfs_free_fd(int fd);
extern void vfs_file_ref(struct fut_file *file);

/**
 * dup2() syscall - Duplicate a file descriptor to a specific number.
 *
 * @param oldfd Source file descriptor
 * @param newfd Target file descriptor number
 *
 * Returns:
 *   - newfd on success
 *   - -errno on error
 *
 * Behavior:
 *   - If oldfd is not valid, return -EBADF
 *   - If oldfd == newfd, return newfd without closing it
 *   - If newfd is open, close it first
 *   - Duplicate oldfd to newfd
 */
long sys_dup2(int oldfd, int newfd) {
    /* Validate oldfd */
    if (oldfd < 0 || newfd < 0) {
        return -EBADF;
    }

    /* Get the file structure for oldfd */
    struct fut_file *old_file = vfs_get_file(oldfd);
    if (!old_file) {
        return -EBADF;
    }

    /* If oldfd == newfd, just return newfd */
    if (oldfd == newfd) {
        return newfd;
    }

    /* Close newfd if it's already open */
    struct fut_file *new_file = vfs_get_file(newfd);
    if (new_file) {
        /* Close the existing file at newfd */
        extern int fut_vfs_close(int fd);
        fut_vfs_close(newfd);
    }

    /* Increment reference count on the file since we're creating another reference */
    vfs_file_ref(old_file);

    /* Allocate newfd pointing to the same file */
    int ret = vfs_alloc_specific_fd(newfd, old_file);
    if (ret < 0) {
        /* Failed to allocate, decrement ref count */
        old_file->refcount--;
        return ret;
    }

    fut_printf("[DUP2] Duplicated fd %d to %d\n", oldfd, newfd);

    return newfd;
}
