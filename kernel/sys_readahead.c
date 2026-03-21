/* kernel/sys_readahead.c - Read-ahead hint syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements readahead() to hint the kernel to prefetch file data into
 * the page cache. Since futura uses ramfs (all data in RAM), this is
 * effectively a no-op that validates parameters and returns success.
 *
 * Linux syscall number: 187 (x86_64), 213 (ARM64)
 */

#include <kernel/fut_task.h>
#include <kernel/fut_vfs.h>
#include <kernel/errno.h>
#include <fcntl.h>
#include <stdint.h>

/**
 * readahead() - Initiate read-ahead on a file
 *
 * @param fd      File descriptor to read ahead
 * @param offset  Starting offset for read-ahead
 * @param count   Number of bytes to read ahead
 *
 * Returns 0 on success, negative errno on failure.
 *
 * This is a hint — the kernel may ignore it. For ramfs, all data is
 * already in memory so no prefetching is needed.
 */
long sys_readahead(int fd, int64_t offset, size_t count) {
    (void)count;

    if (fd < 0)
        return -EBADF;

    if (offset < 0)
        return -EINVAL;

    struct fut_file *file = fut_vfs_get_file(fd);
    if (!file)
        return -EBADF;

    /* O_PATH fds cannot be used for I/O — only path-based operations */
    if (file->flags & O_PATH)
        return -EBADF;

    /* Pipes and sockets are not seekable */
    if (file->vnode && (file->vnode->type == VN_FIFO || file->vnode->type == VN_SOCK))
        return -EINVAL;

    /* Hint accepted — for ramfs, data is already in memory */
    return 0;
}
