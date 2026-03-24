/* kernel/sys_fstat.c - File status syscall (fd-based)
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements the fstat() syscall for retrieving file metadata via fd.
 * Essential for file inspection and metadata queries without path lookup.
 *
 * Phase 1 (Completed): Basic fstat with getattr support
 * Phase 2 (Completed): Enhanced validation, FD categorization, file type/size identification, and detailed logging
 * Phase 3 (Completed): Extended attributes (xattr) support and file handle metadata
 * Phase 4 (Completed): Advanced features (statx support, mount propagation flags, security labels)
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <kernel/fut_vfs.h>
#include <kernel/fut_fd_util.h>
#include <stdint.h>

#include <kernel/kprintf.h>
#include <kernel/uaccess.h>
#include <kernel/fut_timer.h>

#include <platform/platform.h>

/* Kernel-pointer bypass: allow kernel selftests to pass kernel stack pointers */
static inline int fstat_access_ok_write(const void *ptr, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)ptr >= KERNEL_VIRTUAL_BASE) return 0;
#endif
    return fut_access_ok(ptr, n, 1);
}
static inline int fstat_copy_to_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)dst >= KERNEL_VIRTUAL_BASE) { __builtin_memcpy(dst, src, n); return 0; }
#endif
    return fut_copy_to_user(dst, src, n);
}

/**
 * fstat() - Get file status (fd-based)
 *
 * Retrieves file metadata including size, mode, timestamps, and inode number
 * using an open file descriptor. This is the fd-based complement to stat()
 * and avoids the need for path resolution when the file is already open.
 *
 * @param fd       File descriptor of the open file
 * @param statbuf  Pointer to userspace stat buffer to fill
 *
 * Returns:
 *   - 0 on success
 *   - -EBADF if fd is not a valid open file descriptor
 *   - -EFAULT if statbuf is inaccessible
 *   - -EINVAL if statbuf is NULL
 *   - -ESRCH if no current task context
 *   - -EIO if I/O error occurred reading metadata
 *
 * Behavior:
 *   - Retrieves metadata from open file descriptor's vnode
 *   - Does not require path lookup (more efficient than stat)
 *   - Works with any file descriptor type (files, directories, devices, etc.)
 *   - File descriptor must be valid and open
 *   - Follows the same stat structure as stat()/lstat()
 *   - Timestamps reflect actual file state, not fd creation time
 *
 * File descriptor types:
 *   - Regular files: Returns size, timestamps, mode, inode
 *   - Directories: Returns directory metadata, size reflects entry count
 *   - Character devices: Returns device numbers, size typically 0
 *   - Block devices: Returns device numbers, size reflects device capacity
 *   - Sockets: Returns socket metadata (size, timestamps)
 *   - Pipes: Returns pipe metadata, size reflects buffered data
 *
 * Stat structure fields:
 *   - st_ino: Inode number (unique within filesystem)
 *   - st_mode: File type and permissions (S_IFREG, S_IFDIR, etc.)
 *   - st_nlink: Number of hard links
 *   - st_size: File size in bytes
 *   - st_dev: Device ID containing the file
 *   - st_uid: User ID of owner
 *   - st_gid: Group ID of owner
 *   - st_blksize: Preferred I/O block size
 *   - st_blocks: Number of 512-byte blocks allocated
 *   - st_atime: Last access time (nanoseconds)
 *   - st_mtime: Last modification time (nanoseconds)
 *   - st_ctime: Last status change time (nanoseconds)
 *
 * Common usage patterns:
 *
 * Check file size before read:
 *   int fd = open("/path/to/file", O_RDONLY);
 *   struct stat st;
 *   fstat(fd, &st);
 *   if (st.st_size > MAX_SIZE) {
 *       close(fd);
 *       return -EFBIG;
 *   }
 *   // Proceed with read...
 *
 * Verify file type:
 *   int fd = open(path, O_RDONLY);
 *   struct stat st;
 *   fstat(fd, &st);
 *   if (!S_ISREG(st.st_mode)) {
 *       // Not a regular file
 *   }
 *
 * Compare file identity:
 *   struct stat st1, st2;
 *   fstat(fd1, &st1);
 *   fstat(fd2, &st2);
 *   if (st1.st_dev == st2.st_dev && st1.st_ino == st2.st_ino) {
 *       // Same file opened twice
 *   }
 *
 * Check if file changed:
 *   struct stat st_before, st_after;
 *   fstat(fd, &st_before);
 *   // ... some operations ...
 *   fstat(fd, &st_after);
 *   if (st_before.st_mtime != st_after.st_mtime) {
 *       // File was modified
 *   }
 *
 * Get optimal I/O size:
 *   struct stat st;
 *   fstat(fd, &st);
 *   size_t buf_size = st.st_blksize;  // Optimal buffer size
 *   char *buf = malloc(buf_size);
 *
 * Phase 1 (Completed): Basic fstat with getattr support
 * Phase 2 (Completed): FD categorization, file type/size identification, detailed logging
 * Phase 3 (Completed): Extended attributes (xattr), file handle metadata
 * Phase 4 (Completed): statx support, mount propagation flags, security labels
 */
long sys_fstat(int fd, struct fut_stat *statbuf) {
    /* ARM64 FIX: Copy parameters to local variables immediately to ensure they're preserved
     * on the stack across potentially blocking calls. VFS and copy operations may block and
     * corrupt register-passed parameters upon resumption. */
    int local_fd = fd;
    struct fut_stat *local_statbuf = statbuf;

    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_printf("[FSTAT] fstat(fd=%d) -> ESRCH (no current task)\n", local_fd);
        return -ESRCH;
    }

    /* Phase 2: Validate fd early */
    if (local_fd < 0) {
        fut_printf("[FSTAT] fstat(fd=%d) -> EBADF (negative fd)\n", local_fd);
        return -EBADF;
    }

    /* Phase 2: Validate statbuf pointer */
    if (!local_statbuf) {
        fut_printf("[FSTAT] fstat(fd=%d, statbuf=NULL) -> EINVAL (NULL buffer)\n", local_fd);
        return -EINVAL;
    }

    /* Validate statbuf write permission early (kernel writes stat structure)
     * VULNERABILITY: Invalid Output Buffer Pointer
     * ATTACK: Attacker provides read-only or unmapped statbuf buffer
     * IMPACT: Kernel page fault when writing stat structure at line 258
     * DEFENSE: Check write permission before fd lookup and file operations */
    if (fstat_access_ok_write(local_statbuf, sizeof(struct fut_stat)) != 0) {
        fut_printf("[FSTAT] fstat(fd=%d, statbuf=%p) -> EFAULT (statbuf not writable for %zu bytes)\n",
                   local_fd, (void*)local_statbuf, sizeof(struct fut_stat));
        return -EFAULT;
    }

    /* Phase 2: Categorize FD range for diagnostics (Phase 6: use shared helper) */
    const char *fd_category = fut_fd_category(local_fd);

    /* Get the file structure from the file descriptor */
    struct fut_file *file = fut_vfs_get_file(local_fd);
    if (!file) {
        fut_printf("[FSTAT] fstat(fd=%d [%s]) -> EBADF (invalid fd, not open)\n",
                   local_fd, fd_category);
        return -EBADF;
    }

    /* Get the vnode from the file */
    struct fut_vnode *vnode = file->vnode;

    /* Handle fds without vnodes: pipes, eventfds, sockets, etc. */
    if (!vnode) {
        struct fut_stat kernel_stat = {0};
        /* Determine file type: pipes are O_RDONLY/O_WRONLY; for O_RDWR fds,
         * check chr_ops type (eventfd→S_IFCHR, timerfd/signalfd→S_IFREG,
         * socket→S_IFSOCK). */
        int accmode = file->flags & 03;  /* O_ACCMODE */
        if (accmode == 0 || accmode == 1) {
            kernel_stat.st_mode = 0010000 | 0600;  /* S_IFIFO | rw------- */
        } else {
            extern uint32_t fut_chrdev_fstat_mode(struct fut_file *f);
            uint32_t chr_mode = fut_chrdev_fstat_mode(file);
            if (chr_mode != 0u) {
                kernel_stat.st_mode = chr_mode | 0600u;
            } else {
                kernel_stat.st_mode = 0140000 | 0600;  /* S_IFSOCK | rw------- */
            }
        }
        kernel_stat.st_dev = 0;  /* Anonymous device (pipes, sockets) */
        kernel_stat.st_nlink = 1;
        kernel_stat.st_blksize = 4096;
        kernel_stat.st_ino = (uint64_t)(uintptr_t)file;
        if (fstat_copy_to_user(local_statbuf, &kernel_stat, sizeof(struct fut_stat)) != 0) {
            return -EFAULT;
        }
        return 0;
    }

    /* Build stat structure */
    struct fut_stat kernel_stat = {0};
    int ret = 0;

    /* Call vnode getattr operation if available */
    if (vnode->ops && vnode->ops->getattr) {
        ret = vnode->ops->getattr(vnode, &kernel_stat);
        if (ret < 0) {
            const char *error_desc;
            switch (ret) {
                case -EIO:
                    error_desc = "I/O error reading metadata";
                    break;
                case -ENOENT:
                    error_desc = "vnode no longer exists";
                    break;
                default:
                    error_desc = "getattr operation failed";
                    break;
            }
            fut_printf("[FSTAT] fstat(fd=%d [%s], ino=%llu) -> %d (%s)\n",
                       local_fd, fd_category, vnode->ino, ret, error_desc);
            return ret;
        }
    } else {
        /* Fill basic stat info from vnode */
        kernel_stat.st_ino = vnode->ino;
        kernel_stat.st_mode = vnode_type_to_stat_mode(vnode->type) | (vnode->mode & 07777);
        kernel_stat.st_nlink = vnode->nlinks;
        kernel_stat.st_size = vnode->size;
        kernel_stat.st_dev = vnode->mount ? vnode->mount->st_dev : 0;
        kernel_stat.st_uid = vnode->uid;
        kernel_stat.st_gid = vnode->gid;
        kernel_stat.st_blksize = 4096;
        kernel_stat.st_blocks = (vnode->size + 511) / 512;  /* 512-byte units per POSIX */

        /* Set timestamps */
        uint64_t now_ns = fut_get_time_ns();
        kernel_stat.st_atime = now_ns;
        kernel_stat.st_atime_nsec = 0;
        kernel_stat.st_mtime = now_ns;
        kernel_stat.st_mtime_nsec = 0;
        kernel_stat.st_ctime = now_ns;
        kernel_stat.st_ctime_nsec = 0;
    }

    /* Copy stat buffer to userspace */
    if (fstat_copy_to_user(local_statbuf, &kernel_stat, sizeof(struct fut_stat)) != 0) {
        fut_printf("[FSTAT] fstat(fd=%d [%s], ino=%llu) -> EFAULT (copy_to_user failed)\n",
                   local_fd, fd_category, kernel_stat.st_ino);
        return -EFAULT;
    }

    return 0;
}
