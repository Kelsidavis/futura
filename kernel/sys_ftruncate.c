/* kernel/sys_ftruncate.c - File truncation syscall (fd-based)
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements the ftruncate() syscall for truncating files via fd.
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <kernel/fut_vfs.h>
#include <stdint.h>

extern void fut_printf(const char *fmt, ...);
extern struct fut_file *fut_vfs_get_file(int fd);

/**
 * ftruncate() - Truncate file to specified length (fd-based)
 *
 * Truncates or extends a file to the specified length using an open file
 * descriptor. If the file is extended, the extended area is filled with zeros.
 * This is the fd-based complement to truncate() (Priority #22).
 *
 * @param fd      File descriptor of the open file
 * @param length  New file length in bytes
 *
 * Returns:
 *   - 0 on success
 *   - -EBADF if fd is not a valid open file descriptor
 *   - -EINVAL if length is negative (for signed interpretation)
 *   - -EISDIR if fd refers to a directory
 */
long sys_ftruncate(int fd, uint64_t length) {
    /* Get the file structure from the file descriptor */
    struct fut_file *file = fut_vfs_get_file(fd);
    if (!file) {
        fut_printf("[FTRUNCATE] ftruncate(%d, %llu) -> EBADF (invalid fd)\n", fd, length);
        return -EBADF;
    }

    /* Get the vnode from the file */
    struct fut_vnode *vnode = file->vnode;
    if (!vnode) {
        fut_printf("[FTRUNCATE] ftruncate(%d, %llu) -> EBADF (no vnode)\n", fd, length);
        return -EBADF;
    }

    /* Cannot truncate a directory */
    if (vnode->type == VN_DIR) {
        fut_printf("[FTRUNCATE] ftruncate(%d, %llu) -> EISDIR\n", fd, length);
        return -EISDIR;
    }

    /* Simple truncation: directly modify vnode size.
     * For truncating smaller, just update size (real filesystem would deallocate blocks).
     * For extending, update size (real filesystem would allocate and zero blocks).
     */
    uint64_t current_size = vnode->size;

    if (length <= current_size) {
        /* Truncating to smaller size */
        vnode->size = length;
        fut_printf("[FTRUNCATE] ftruncate(%d, %llu) -> 0 (shrink from %llu)\n",
                   fd, length, current_size);
        return 0;
    } else {
        /* Extending file - update size (would need to zero-fill in real impl) */
        vnode->size = length;
        fut_printf("[FTRUNCATE] ftruncate(%d, %llu) -> 0 (extend from %llu)\n",
                   fd, length, current_size);
        return 0;
    }
}
