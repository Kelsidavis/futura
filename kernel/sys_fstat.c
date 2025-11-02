/* kernel/sys_fstat.c - File status syscall (fd-based)
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements the fstat() syscall for retrieving file metadata via fd.
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <kernel/fut_vfs.h>
#include <stdint.h>

extern void fut_printf(const char *fmt, ...);
extern struct fut_file *fut_vfs_get_file(int fd);
extern int fut_copy_to_user(void *to, const void *from, size_t size);
extern uint64_t fut_get_time_ns(void);

/**
 * fstat() - Get file status (fd-based)
 *
 * Retrieves file metadata including size, mode, timestamps, and inode number
 * using an open file descriptor. This is the fd-based complement to stat()
 * (Priority #27).
 *
 * @param fd       File descriptor of the open file
 * @param statbuf  Pointer to userspace stat buffer to fill
 *
 * Returns:
 *   - 0 on success
 *   - -EBADF if fd is not a valid open file descriptor
 *   - -EFAULT if statbuf is inaccessible
 *   - -EINVAL if statbuf is NULL
 */
long sys_fstat(int fd, struct fut_stat *statbuf) {
    if (!statbuf) {
        return -EINVAL;
    }

    /* Get the file structure from the file descriptor */
    struct fut_file *file = fut_vfs_get_file(fd);
    if (!file) {
        fut_printf("[FSTAT] fstat(%d) -> EBADF (invalid fd)\n", fd);
        return -EBADF;
    }

    /* Get the vnode from the file */
    struct fut_vnode *vnode = file->vnode;
    if (!vnode) {
        fut_printf("[FSTAT] fstat(%d) -> EBADF (no vnode)\n", fd);
        return -EBADF;
    }

    /* Build stat structure */
    struct fut_stat kernel_stat = {0};
    int ret = 0;

    /* Call vnode getattr operation if available */
    if (vnode->ops && vnode->ops->getattr) {
        ret = vnode->ops->getattr(vnode, &kernel_stat);
    } else {
        /* Fill basic stat info from vnode */
        kernel_stat.st_ino = vnode->ino;
        kernel_stat.st_mode = vnode->mode;
        kernel_stat.st_nlink = vnode->nlinks;
        kernel_stat.st_size = vnode->size;
        kernel_stat.st_dev = vnode->mount ? vnode->mount->st_dev : 0;
        kernel_stat.st_uid = 0;
        kernel_stat.st_gid = 0;
        kernel_stat.st_blksize = 4096;
        kernel_stat.st_blocks = (vnode->size + 4095) / 4096;

        /* Set timestamps */
        uint64_t now_ns = fut_get_time_ns();
        kernel_stat.st_atime = now_ns;
        kernel_stat.st_mtime = now_ns;
        kernel_stat.st_ctime = now_ns;
        ret = 0;
    }

    if (ret < 0) {
        fut_printf("[FSTAT] fstat(%d) -> %d (getattr error)\n", fd, ret);
        return ret;
    }

    /* Copy stat buffer to userspace */
    if (fut_copy_to_user(statbuf, &kernel_stat, sizeof(struct fut_stat)) != 0) {
        fut_printf("[FSTAT] fstat(%d) -> EFAULT (copy_to_user failed)\n", fd);
        return -EFAULT;
    }

    fut_printf("[FSTAT] fstat(%d) -> 0 (size=%llu, mode=%o, ino=%llu)\n",
               fd, kernel_stat.st_size, kernel_stat.st_mode, kernel_stat.st_ino);
    return 0;
}
