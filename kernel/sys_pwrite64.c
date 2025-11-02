/* kernel/sys_pwrite64.c - Position-based write syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements the pwrite64() syscall for writing to a file at a specific
 * offset without changing the file position.
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <kernel/fut_vfs.h>
#include <stdint.h>

extern void fut_printf(const char *fmt, ...);
extern int fut_copy_from_user(void *to, const void *from, size_t size);
extern int fut_copy_to_user(void *to, const void *from, size_t size);
extern void *fut_malloc(size_t size);
extern void fut_free(void *ptr);
extern fut_task_t *fut_task_current(void);
extern struct fut_file *vfs_get_file_from_task(struct fut_task *task, int fd);

/**
 * pwrite64() - Write to file at specific offset
 *
 * Writes up to count bytes to file descriptor fd at offset offset from
 * the buffer buf. The file offset is not changed. This is useful for
 * multithreaded applications where multiple threads need to write to the
 * same file without interfering with each other's file positions.
 *
 * @param fd      File descriptor to write to
 * @param buf     Buffer containing data to write
 * @param count   Number of bytes to write
 * @param offset  Offset in file to write to
 *
 * Returns:
 *   - Number of bytes written on success
 *   - -EBADF if fd is not a valid file descriptor
 *   - -EFAULT if buf points to invalid memory
 *   - -EINVAL if fd is associated with an object that cannot be written
 *   - -EISDIR if fd refers to a directory
 *   - -ESPIPE if fd is associated with a pipe or socket
 */
long sys_pwrite64(unsigned int fd, const void *buf, size_t count, int64_t offset) {
    if (!buf) {
        return -EFAULT;
    }

    if (offset < 0) {
        return -EINVAL;
    }

    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    struct fut_file *file = vfs_get_file_from_task(task, (int)fd);
    if (!file) {
        return -EBADF;
    }

    /* pwrite() not supported on character devices, pipes, or sockets */
    if (file->chr_ops) {
        return -ESPIPE;
    }

    /* Check if this is a directory */
    if (file->vnode && file->vnode->type == VN_DIR) {
        return -EISDIR;
    }

    /* Call vnode write operation at specified offset */
    if (!file->vnode || !file->vnode->ops || !file->vnode->ops->write) {
        return -EINVAL;
    }

    /* Allocate kernel buffer */
    void *kbuf = fut_malloc(count);
    if (!kbuf) {
        return -ENOMEM;
    }

    /* Copy from userspace */
    if (fut_copy_from_user(kbuf, buf, count) != 0) {
        fut_free(kbuf);
        return -EFAULT;
    }

    /* Write to file at the specified offset without changing file->offset */
    ssize_t ret = file->vnode->ops->write(file->vnode, kbuf, count, (uint64_t)offset);

    fut_free(kbuf);
    return ret;
}
