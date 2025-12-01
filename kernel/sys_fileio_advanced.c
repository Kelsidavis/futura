/* kernel/sys_fileio_advanced.c - Advanced file I/O syscalls for ARM64
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements advanced file I/O syscalls: sync, chroot, sendfile.
 * These provide system-wide sync, filesystem isolation, and efficient file copying.
 */

#include <kernel/fut_task.h>
#include <kernel/fut_vfs.h>
#include <kernel/errno.h>
#include <stdint.h>
#include <string.h>

extern void fut_printf(const char *fmt, ...);
extern fut_task_t *fut_task_current(void);
extern struct fut_file *vfs_get_file_from_task(struct fut_task *task, int fd);
extern int fut_copy_from_user(void *to, const void *from, size_t size);

/**
 * sys_chroot - Change root directory
 *
 * @param path: New root directory path
 *
 * Changes the root directory for the calling process to the specified path.
 * This is used for filesystem isolation and sandboxing.
 *
 * Phase 1: Validate path, stub (don't actually change root)
 * Phase 2: Resolve path to vnode, store in task structure
 * Phase 3: Integrate with VFS path resolution
 *
 * Returns:
 *   - 0 on success
 *   - -EFAULT if path is NULL or invalid
 *   - -ENOENT if path doesn't exist
 *   - -ENOTDIR if path is not a directory
 *   - -EPERM if insufficient privileges (requires CAP_SYS_CHROOT)
 *   - -ESRCH if no current task
 */
long sys_chroot(const char *path) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_printf("[CHROOT] chroot(path=%p) -> ESRCH (no current task)\n", path);
        return -ESRCH;
    }

    /* Validate path pointer */
    if (!path) {
        fut_printf("[CHROOT] chroot(path=NULL) -> EFAULT (null path)\n");
        return -EFAULT;
    }

    /* Phase 1: Validate path string (basic safety check)
     * In Phase 2, we would:
     * - Resolve path to vnode
     * - Verify it's a directory
     * - Check CAP_SYS_CHROOT capability
     * - Store in task->chroot_vnode
     */

    /* Estimate path length for categorization */
    size_t path_len = 0;
    const char *p = path;
    while (path_len < 4096 && *p != '\0') {
        path_len++;
        p++;
    }

    if (path_len == 0) {
        fut_printf("[CHROOT] chroot(path='') -> ENOENT (empty path, pid=%d)\n", task->pid);
        return -ENOENT;
    }

    if (path_len >= 4096) {
        fut_printf("[CHROOT] chroot(path=<too long>) -> ENAMETOOLONG (path >4096, pid=%d)\n",
                   task->pid);
        return -ENAMETOOLONG;
    }

    /* Categorize path length */
    const char *path_category;
    if (path_len <= 16) {
        path_category = "short";
    } else if (path_len <= 128) {
        path_category = "medium";
    } else if (path_len <= 512) {
        path_category = "long";
    } else {
        path_category = "very long";
    }

    /* Log first 64 characters of path for debugging */
    char path_preview[65];
    size_t preview_len = (path_len < 64) ? path_len : 64;
    for (size_t i = 0; i < preview_len; i++) {
        path_preview[i] = path[i];
    }
    path_preview[preview_len] = '\0';

    /* Phase 1: Accept but don't change root */
    /* Phase 2: Resolve path, check it's a directory, store in task */
    /* Phase 3: Check CAP_SYS_CHROOT capability */

    fut_printf("[CHROOT] chroot(path='%s%s', len=%zu [%s], pid=%d) -> 0 "
               "(accepted, Phase 1 stub)\n",
               path_preview, (path_len > 64) ? "..." : "", path_len, path_category, task->pid);

    return 0;
}

/**
 * sys_sendfile - Copy data between file descriptors
 *
 * @param out_fd: File descriptor opened for writing
 * @param in_fd: File descriptor opened for reading
 * @param offset: Pointer to offset in input file (NULL = use current position)
 * @param count: Number of bytes to transfer
 *
 * Efficiently copies data between two file descriptors without transferring
 * data to/from userspace. This is much faster than read()+write() for large
 * file copies.
 *
 * Phase 1 (Completed): Validate parameters, return stub value
 * Phase 2 (Completed): Copy offset parameter from userspace with validation
 * Phase 3: Implement via read()+write() loop (inefficient but functional)
 * Phase 4: Zero-copy transfer using kernel buffers
 *
 * Returns:
 *   - Number of bytes transferred on success
 *   - -EBADF if in_fd or out_fd is invalid
 *   - -EINVAL if descriptors not suitable for sendfile
 *   - -EFAULT if offset pointer is invalid
 *   - -ESRCH if no current task
 */
long sys_sendfile(int out_fd, int in_fd, uint64_t *offset, size_t count) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_printf("[SENDFILE] sendfile(out_fd=%d, in_fd=%d, offset=%p, count=%zu) -> ESRCH "
                   "(no current task)\n",
                   out_fd, in_fd, offset, count);
        return -ESRCH;
    }

    /* Validate file descriptors */
    if (out_fd < 0) {
        fut_printf("[SENDFILE] sendfile(out_fd=%d, in_fd=%d, count=%zu, pid=%d) -> EBADF "
                   "(invalid out_fd)\n",
                   out_fd, in_fd, count, task->pid);
        return -EBADF;
    }

    if (in_fd < 0) {
        fut_printf("[SENDFILE] sendfile(out_fd=%d, in_fd=%d, count=%zu, pid=%d) -> EBADF "
                   "(invalid in_fd)\n",
                   out_fd, in_fd, count, task->pid);
        return -EBADF;
    }

    /* Get file structures */
    struct fut_file *in_file = vfs_get_file_from_task(task, in_fd);
    if (!in_file) {
        fut_printf("[SENDFILE] sendfile(out_fd=%d, in_fd=%d, count=%zu, pid=%d) -> EBADF "
                   "(in_fd not open)\n",
                   out_fd, in_fd, count, task->pid);
        return -EBADF;
    }

    struct fut_file *out_file = vfs_get_file_from_task(task, out_fd);
    if (!out_file) {
        fut_printf("[SENDFILE] sendfile(out_fd=%d, in_fd=%d, count=%zu, pid=%d) -> EBADF "
                   "(out_fd not open)\n",
                   out_fd, in_fd, count, task->pid);
        return -EBADF;
    }

    /* Categorize transfer size */
    const char *size_category;
    const char *size_desc;
    if (count == 0) {
        size_category = "zero";
        size_desc = "no-op";
    } else if (count < 4096) {
        size_category = "tiny (<4KB)";
        size_desc = "less than a page";
    } else if (count < 65536) {
        size_category = "small (4KB-64KB)";
        size_desc = "few pages";
    } else if (count < 1048576) {
        size_category = "medium (64KB-1MB)";
        size_desc = "moderate transfer";
    } else if (count < 104857600) {
        size_category = "large (1MB-100MB)";
        size_desc = "significant transfer";
    } else {
        size_category = "huge (≥100MB)";
        size_desc = "very large transfer";
    }

    /* Handle offset parameter */
    const char *offset_mode;
    uint64_t start_offset = 0;
    if (offset) {
        /* Phase 2: Copy offset from userspace */
        if (fut_copy_from_user(&start_offset, offset, sizeof(uint64_t)) != 0) {
            fut_printf("[SENDFILE] sendfile(out_fd=%d, in_fd=%d, count=%zu, pid=%d) -> EFAULT "
                       "(invalid offset pointer)\n",
                       out_fd, in_fd, count, task->pid);
            return -EFAULT;
        }
        offset_mode = "explicit offset";
    } else {
        offset_mode = "current position";
        start_offset = in_file->offset;
    }

    /* Phase 1: Return 0 bytes transferred (stub)
     * Phase 2: Implement via kernel buffer read()+write() loop
     * Phase 3: Zero-copy transfer using splice/pipe or direct buffer sharing
     */

    fut_printf("[SENDFILE] sendfile(out_fd=%d, in_fd=%d, offset=%s [%lu], count=%zu [%s], "
               "pid=%d) -> 0 (%s, Phase 2: offset validated)\n",
               out_fd, in_fd, offset_mode, start_offset, count, size_category,
               task->pid, size_desc);

    /* Phase 2: Return 0 bytes transferred (offset validated, transfer not implemented) */
    return 0;
}
