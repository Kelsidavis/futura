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
#include <kernel/fut_socket.h>
#include <kernel/chrdev.h>
#include <kernel/errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>

#include <kernel/kprintf.h>
#include <kernel/uaccess.h>

#ifdef __x86_64__
#include <platform/x86_64/memory/paging.h>
#elif defined(__aarch64__)
#include <platform/arm64/memory/paging.h>
#endif

static inline int fileio_copy_to_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)dst >= KERNEL_VIRTUAL_BASE) { __builtin_memcpy(dst, src, n); return 0; }
#endif
    return fut_copy_to_user(dst, src, n);
}
static inline int fileio_copy_from_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)src >= KERNEL_VIRTUAL_BASE) { __builtin_memcpy(dst, src, n); return 0; }
#endif
    return fut_copy_from_user(dst, src, n);
}

/**
 * sys_chroot - Change root directory
 *
 * @param path: New root directory path
 *
 * Changes the root directory for the calling process to the specified path.
 * This is used for filesystem isolation and sandboxing.
 *
 * Phase 1 (Completed): Validate path, check CAP_SYS_CHROOT
 * Phase 2 (Completed): Resolve path to vnode, store in task->chroot_vnode
 * Phase 3 (Completed): VFS path resolution integration with chroot inheritance
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
    /* ARM64 FIX: Copy register params to local stack vars before blocking calls */
    const char *local_path = path;

    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_printf("[CHROOT] chroot(path=%p) -> ESRCH (no current task)\n", local_path);
        return -ESRCH;
    }

    /* Validate path pointer */
    if (!local_path) {
        fut_printf("[CHROOT] chroot(path=NULL) -> EFAULT (null path)\n");
        return -EFAULT;
    }

    /* Copy path from userspace instead of direct dereference */
    char path_buf[FUT_VFS_PATH_BUFFER_SIZE];
    if (fileio_copy_from_user(path_buf, local_path, sizeof(path_buf)) != 0) {
        fut_printf("[CHROOT] chroot -> EFAULT (copy_from_user failed, pid=%d)\n", task->pid);
        return -EFAULT;
    }
    if (memchr(path_buf, '\0', sizeof(path_buf)) == NULL) {
        fut_printf("[CHROOT] chroot -> ENAMETOOLONG (path >%zu, pid=%d)\n",
                   sizeof(path_buf), task->pid);
        return -ENAMETOOLONG;
    }

    if (path_buf[0] == '\0') {
        return -ENOENT;
    }

    /* Resolve path to vnode and verify it's a directory */
    struct fut_vnode *vnode = NULL;
    int ret = fut_vfs_lookup(path_buf, &vnode);
    if (ret < 0) {
        return -ENOENT;
    }

    if (vnode->type != VN_DIR) {
        fut_vnode_unref(vnode);
        return -ENOTDIR;
    }

    /* Check CAP_SYS_CHROOT capability - only privileged processes may chroot */
    #define CAP_SYS_CHROOT 18
    bool has_cap = (task->cap_effective & (1ULL << CAP_SYS_CHROOT)) != 0;
    bool is_root = (task->uid == 0);
    if (!has_cap && !is_root) {
        fut_vnode_unref(vnode);
        fut_printf("[CHROOT] chroot('%s') -> EPERM (need CAP_SYS_CHROOT, pid=%d)\n",
                   path_buf, task->pid);
        return -EPERM;
    }

    /* Release old chroot vnode if already set */
    if (task->chroot_vnode) {
        fut_vnode_unref(task->chroot_vnode);
    }

    /* Install new chroot root — vnode already ref'd by fut_vfs_lookup above */
    task->chroot_vnode = vnode;

    fut_printf("[CHROOT] chroot('%s') -> 0 (pid=%llu)\n", path_buf, (unsigned long long)task->pid);
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
 * Phase 3 (Completed): Read+write loop with kernel buffer, offset tracking
 * Phase 4: Zero-copy transfer via page remapping
 *
 * Returns:
 *   - Number of bytes transferred on success
 *   - -EBADF if in_fd or out_fd is invalid
 *   - -EINVAL if descriptors not suitable for sendfile
 *   - -EFAULT if offset pointer is invalid
 *   - -ESRCH if no current task
 */
long sys_sendfile(int out_fd, int in_fd, int64_t *offset, size_t count) {
    /* ARM64 FIX: Copy register params to local stack vars before blocking calls */
    int local_out_fd = out_fd;
    int local_in_fd = in_fd;
    int64_t *local_offset = offset;
    size_t local_count = count;

    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_printf("[SENDFILE] sendfile(out_fd=%d, in_fd=%d, offset=%p, count=%zu) -> ESRCH "
                   "(no current task)\n",
                   local_out_fd, local_in_fd, local_offset, local_count);
        return -ESRCH;
    }

    /* Validate file descriptors */
    if (local_out_fd < 0) {
        fut_printf("[SENDFILE] sendfile(out_fd=%d, in_fd=%d, count=%zu, pid=%d) -> EBADF "
                   "(invalid out_fd)\n",
                   local_out_fd, local_in_fd, local_count, task->pid);
        return -EBADF;
    }

    if (local_in_fd < 0) {
        fut_printf("[SENDFILE] sendfile(out_fd=%d, in_fd=%d, count=%zu, pid=%d) -> EBADF "
                   "(invalid in_fd)\n",
                   local_out_fd, local_in_fd, local_count, task->pid);
        return -EBADF;
    }

    /* Validate FD upper bounds to prevent OOB array access */
    if (local_out_fd >= task->max_fds) {
        fut_printf("[SENDFILE] sendfile(out_fd=%d, in_fd=%d, max_fds=%d, count=%zu, pid=%d) -> EBADF "
                   "(out_fd exceeds max_fds, FD bounds validation)\n",
                   local_out_fd, local_in_fd, task->max_fds, local_count, task->pid);
        return -EBADF;
    }

    if (local_in_fd >= task->max_fds) {
        fut_printf("[SENDFILE] sendfile(out_fd=%d, in_fd=%d, max_fds=%d, count=%zu, pid=%d) -> EBADF "
                   "(in_fd exceeds max_fds, FD bounds validation)\n",
                   local_out_fd, local_in_fd, task->max_fds, local_count, task->pid);
        return -EBADF;
    }

    /* Get file structures */
    struct fut_file *in_file = vfs_get_file_from_task(task, local_in_fd);
    if (!in_file) {
        fut_printf("[SENDFILE] sendfile(out_fd=%d, in_fd=%d, count=%zu, pid=%d) -> EBADF "
                   "(in_fd not open)\n",
                   local_out_fd, local_in_fd, local_count, task->pid);
        return -EBADF;
    }

    struct fut_file *out_file = vfs_get_file_from_task(task, local_out_fd);
    if (!out_file) {
        fut_printf("[SENDFILE] sendfile(out_fd=%d, in_fd=%d, count=%zu, pid=%d) -> EBADF "
                   "(out_fd not open)\n",
                   local_out_fd, local_in_fd, local_count, task->pid);
        return -EBADF;
    }

    /* O_PATH fds cannot be used for I/O — only path-based operations */
    if ((in_file->flags & O_PATH) || (out_file->flags & O_PATH))
        return -EBADF;

    /* Enforce access mode: in_fd must be readable; out_fd must be writable */
    if ((in_file->flags & O_ACCMODE) == O_WRONLY)
        return -EBADF;
    if ((out_file->flags & O_ACCMODE) == O_RDONLY)
        return -EBADF;

    /* Handle offset parameter — Linux uses off_t (signed) */
    int64_t signed_offset = 0;
    uint64_t start_offset = 0;
    if (local_offset) {
        /* Copy offset from userspace */
        if (fileio_copy_from_user(&signed_offset, local_offset, sizeof(int64_t)) != 0) {
            fut_printf("[SENDFILE] sendfile(out_fd=%d, in_fd=%d, count=%zu, pid=%d) -> EFAULT "
                       "(invalid offset pointer)\n",
                       local_out_fd, local_in_fd, local_count, task->pid);
            return -EFAULT;
        }
        if (signed_offset < 0)
            return -EINVAL;
        start_offset = (uint64_t)signed_offset;
    } else {
        start_offset = in_file->offset;
    }

    /* Validate in_file supports reading */
    if (!in_file->vnode || !in_file->vnode->ops || !in_file->vnode->ops->read) {
        /* Check chr_ops path too */
        if (!in_file->chr_ops || !in_file->chr_ops->read) {
            return -EINVAL;
        }
    }

    /* Reject socket source — sendfile() only reads from regular files/pipes.
     * Linux returns EINVAL when in_fd is a socket. */
    extern fut_socket_t *get_socket_from_fd(int fd);
    if (get_socket_from_fd(local_in_fd)) {
        return -EINVAL;
    }

    /* Check if out_fd is a socket — socket sends use fut_socket_send, not vnode write */
    fut_socket_t *out_sock = get_socket_from_fd(local_out_fd);

    /* Validate out_file supports writing (sockets are always writable) */
    if (!out_sock) {
        if (!out_file->vnode || !out_file->vnode->ops || !out_file->vnode->ops->write) {
            if (!out_file->chr_ops || !out_file->chr_ops->write) {
                return -EINVAL;
            }
        }
    }

    /* Transfer data via kernel buffer */
    #define SENDFILE_BUF_SIZE 4096
    char kbuf[SENDFILE_BUF_SIZE];
    size_t total = 0;
    uint64_t read_offset = start_offset;

    while (total < local_count) {
        size_t chunk = local_count - total;
        if (chunk > SENDFILE_BUF_SIZE)
            chunk = SENDFILE_BUF_SIZE;

        /* Read from input file at specified offset */
        ssize_t nread;
        if (in_file->chr_ops && in_file->chr_ops->read) {
            off_t pos = (off_t)read_offset;
            nread = in_file->chr_ops->read(in_file->chr_inode, in_file->chr_private,
                                           kbuf, chunk, &pos);
        } else {
            nread = in_file->vnode->ops->read(in_file->vnode, kbuf, chunk, read_offset);
        }

        if (nread <= 0)
            break;

        /* Write to output fd — socket path or regular file path */
        ssize_t nwritten;
        if (out_sock) {
            nwritten = fut_socket_send(out_sock, kbuf, (size_t)nread);

        } else if (out_file->chr_ops && out_file->chr_ops->write) {
            off_t pos = (off_t)out_file->offset;
            nwritten = out_file->chr_ops->write(out_file->chr_inode, out_file->chr_private,
                                                kbuf, (size_t)nread, &pos);
            if (nwritten > 0)
                out_file->offset = (uint64_t)pos;
        } else {
            /* O_APPEND: seek to end atomically before each write */
            int sf_append = (out_file->flags & O_APPEND) != 0;
            if (sf_append) {
                fut_spinlock_acquire(&out_file->vnode->write_lock);
                out_file->offset = out_file->vnode->size;
            }
            nwritten = out_file->vnode->ops->write(out_file->vnode, kbuf, (size_t)nread,
                                                   out_file->offset);
            if (sf_append)
                fut_spinlock_release(&out_file->vnode->write_lock);
            if (nwritten > 0)
                out_file->offset += nwritten;
        }

        if (nwritten <= 0)
            break;

        read_offset += nwritten;
        total += nwritten;
    }

    /* POSIX/Linux: clear setuid/setgid bits on destination after successful write */
    if (total > 0 && out_file->vnode && out_file->vnode->type == VN_REG) {
        uint32_t mode = out_file->vnode->mode;
        int needs_clear = 0;
        if (mode & 04000) needs_clear = 1;
        if ((mode & 02000) && (mode & 00010)) needs_clear = 1;
        if (needs_clear) {
            int has_cap_fsetid = task &&
                (task->cap_effective & (1ULL << 4 /* CAP_FSETID */));
            if (!has_cap_fsetid) {
                if (mode & 04000)
                    out_file->vnode->mode &= ~(uint32_t)04000;
                if ((mode & 02000) && (mode & 00010))
                    out_file->vnode->mode &= ~(uint32_t)02000;
            }
        }
    }

    /* Update offset for caller; propagate write-back failure */
    if (local_offset) {
        int64_t final_offset = (int64_t)read_offset;
        if (fileio_copy_to_user(local_offset, &final_offset, sizeof(int64_t)) != 0) {
            return -EFAULT;
        }
    } else {
        /* No explicit offset: update in_file's position */
        in_file->offset = read_offset;
    }

    return (long)total;
}
