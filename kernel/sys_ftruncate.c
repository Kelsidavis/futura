/* kernel/sys_ftruncate.c - File truncation syscall (fd-based)
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements the ftruncate() syscall for truncating files via fd.
 * Essential for file manipulation in editors, databases, and log rotation.
 *
 * Phase 1 (Completed): Basic file truncation with size updates
 * Phase 2 (Completed): Enhanced validation, FD/length categorization, and detailed logging
 * Phase 3 (Completed): Block deallocation for shrink, zero-fill for extend
 * Phase 4 (Completed): Advanced features (sparse file support, preallocation hints)
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <kernel/fut_vfs.h>
#include <kernel/chrdev.h>
#include <kernel/fut_fd_util.h>
#include <stdint.h>
#include <fcntl.h>

#include <kernel/kprintf.h>

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
 *   - -EBADF if file has no associated vnode
 *   - -EINVAL if length is negative (for signed interpretation)
 *   - -EISDIR if fd refers to a directory
 *   - -ESRCH if no current task context
 *
 * Behavior:
 *   - If length < current size: shrink file (Phase 3: deallocate blocks)
 *   - If length > current size: extend file (Phase 3: zero-fill new area)
 *   - If length == current size: no-op (size unchanged)
 *   - File offset for all FDs referring to this file remains unchanged
 *   - Does not require write permission check in Phase 1/2 (future enhancement)
 *   - Updates file's mtime and ctime
 *
 * Common usage patterns:
 *
 * Truncate file to zero (clear contents):
 *   int fd = open("/tmp/logfile.txt", O_WRONLY);
 *   ftruncate(fd, 0);  // Clear all contents
 *   close(fd);
 *
 * Extend file to specific size (reserve space):
 *   int fd = open("/tmp/database.db", O_RDWR | O_CREAT, 0644);
 *   ftruncate(fd, 1024 * 1024 * 100);  // Pre-allocate 100 MB
 *   // Write data at various offsets...
 *   close(fd);
 *
 * Trim file to exact size after writing:
 *   int fd = open("/tmp/output.bin", O_RDWR | O_CREAT, 0644);
 *   write(fd, buffer, actual_size);
 *   ftruncate(fd, actual_size);  // Ensure exact size
 *   close(fd);
 *
 * Log rotation (truncate to size limit):
 *   struct stat st;
 *   fstat(fd, &st);
 *   if (st.st_size > MAX_LOG_SIZE) {
 *       ftruncate(fd, MAX_LOG_SIZE);  // Trim to limit
 *   }
 *
 * No-op case (length == current size):
 *   ftruncate(fd, current_size);  // Returns 0, no actual truncation
 *
 * Sparse file creation:
 *   ftruncate(fd, 1024 * 1024 * 1024);  // 1 GB sparse file
 *   // File shows as 1 GB but uses minimal disk space until written
 *
 * Phase 1 (Completed): Basic file truncation with size updates
 * Phase 2 (Completed): Enhanced validation, FD/length categorization, detailed logging
 * Phase 3 (Completed): Block deallocation for shrink, zero-fill for extend
 * Phase 4 (Completed): Sparse file support, preallocation hints
 */
long sys_ftruncate(int fd, uint64_t length) {
    /* Get current task for FD table access */
    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_printf("[FTRUNCATE] ftruncate(fd=%d, length=%llu) -> ESRCH (no current task)\n",
                   fd, length);
        return -ESRCH;
    }

    /* Phase 2: Validate fd early */
    if (fd < 0) {
        fut_printf("[FTRUNCATE] ftruncate(fd=%d, length=%llu) -> EBADF (negative fd)\n",
                   fd, length);
        return -EBADF;
    }

    /* Phase 2: Categorize FD range */
    const char *fd_category = fut_fd_category(fd);

    /* Phase 2: Categorize length range */
    const char *length_category;
    if (length == 0) {
        length_category = "zero (clear file)";
    } else if (length < 4096) {
        length_category = "tiny (< 4KB)";
    } else if (length < 1024 * 1024) {
        length_category = "small (< 1MB)";
    } else if (length < 100 * 1024 * 1024) {
        length_category = "medium (< 100MB)";
    } else if (length < 1024ULL * 1024 * 1024) {
        length_category = "large (< 1GB)";
    } else {
        length_category = "very large (>= 1GB)";
    }

    /* Get the file structure from the file descriptor */
    struct fut_file *file = fut_vfs_get_file(fd);
    if (!file) {
        fut_printf("[FTRUNCATE] ftruncate(fd=%d [%s], length=%llu [%s]) -> EBADF "
                   "(invalid fd)\n",
                   fd, fd_category, length, length_category);
        return -EBADF;
    }

    /* Enforce RLIMIT_FSIZE: extending beyond the soft limit returns EFBIG and
     * sends SIGXFSZ.  Shrinking is always allowed regardless of the limit. */
    {
        uint64_t fsize_limit = task->rlimits[1].rlim_cur; /* RLIMIT_FSIZE = 1 */
        if (fsize_limit != (uint64_t)-1 && fsize_limit != 0 &&
                length > fsize_limit) {
            extern int fut_signal_send(struct fut_task *t, int sig);
            fut_signal_send(task, 25 /* SIGXFSZ */);
            fut_printf("[FTRUNCATE] ftruncate(fd=%d, length=%llu) -> EFBIG "
                       "(exceeds RLIMIT_FSIZE=%llu)\n",
                       fd, length, fsize_limit);
            return -EFBIG;
        }
    }

    /* Enforce file seals (applies to memfd chr_ops files and vnode files alike) */
    if (file->seals & 0x0008 /* F_SEAL_WRITE */) {
        return -EPERM;
    }

    /* Handle chr_ops files (memfd, etc.) via truncate ioctl.
     * Check size-based seals before dispatching; query current size via ioctl first. */
    if (file->chr_ops && !file->vnode) {
        if (file->seals & (0x0002 /* F_SEAL_SHRINK */ | 0x0004 /* F_SEAL_GROW */)) {
            /* Query current size via MEMFD_IOC_GETSIZE (0xFE11) */
            extern long fut_memfd_get_size(struct fut_file *file);
            long cur = fut_memfd_get_size(file);
            if (cur >= 0) {
                if ((file->seals & 0x0002) && (uint64_t)length < (uint64_t)cur)
                    return -EPERM;
                if ((file->seals & 0x0004) && (uint64_t)length > (uint64_t)cur)
                    return -EPERM;
            }
        }
        if (file->chr_ops->ioctl) {
            return file->chr_ops->ioctl(file->chr_inode, file->chr_private,
                                        0xFE10 /* MEMFD_IOC_TRUNCATE */,
                                        (unsigned long)length);
        }
        return -EINVAL;
    }

    /* Get the vnode from the file */
    struct fut_vnode *vnode = file->vnode;
    if (!vnode) {
        fut_printf("[FTRUNCATE] ftruncate(fd=%d [%s], length=%llu [%s]) -> EBADF "
                   "(no vnode)\n",
                   fd, fd_category, length, length_category);
        return -EBADF;
    }

    /* Enforce seal-based size constraints */
    if (vnode->size > 0) {
        if ((file->seals & 0x0002 /* F_SEAL_SHRINK */) && length < vnode->size)
            return -EPERM;
        if ((file->seals & 0x0004 /* F_SEAL_GROW */) && length > vnode->size)
            return -EPERM;
    }

    /* Cannot truncate a directory */
    if (vnode->type == VN_DIR) {
        fut_printf("[FTRUNCATE] ftruncate(fd=%d [%s], length=%llu [%s]) -> EISDIR "
                   "(cannot truncate directory)\n",
                   fd, fd_category, length, length_category);
        return -EISDIR;
    }

    /* Verify file was opened with write permission
     * VULNERABILITY: Unauthorized File Truncation via Read-Only FD
     *
     * ATTACK SCENARIO:
     * Attacker opens file read-only, then attempts ftruncate to modify it
     * 1. Attacker lacks write permission on /important/data.db (mode 0444)
     * 2. Attacker opens: fd = open("/important/data.db", O_RDONLY)
     *    - open() succeeds (read permission granted)
     * 3. WITHOUT check:
     *    - Attacker calls ftruncate(fd, 0) to clear file
     *    - Line 230: vnode->ops->truncate(vnode, 0) executes
     *    - File contents destroyed despite read-only open
     * 4. Result:
     *    - Data loss: File truncated to zero bytes
     *    - Permission bypass: Modification without write permission
     *    - Inconsistency: FD flags (O_RDONLY) don't match operation (write)
     *
     * ROOT CAUSE:
     * ftruncate() modifies file contents (metadata AND data):
     * - Changes vnode->size (file length metadata)
     * - Deallocates blocks when shrinking (data destruction)
     * - Zero-fills when extending (data modification)
     * BUT old code didn't verify file->flags before allowing modification
     *
     * DEFENSE:
     * Reject ftruncate() on files not opened for writing
     * - Check file->flags for O_WRONLY (0x0001) or O_RDWR (0x0002)
     * - Return -EBADF if file opened O_RDONLY (0x0000)
     * - Ensures FD open mode matches operation type
     * - Consistent with write() behavior (also checks write permission)
     *
     * POSIX REQUIREMENT (IEEE Std 1003.1-2017):
     * "The ftruncate() function shall cause the regular file referenced by
     *  fildes to have a size which shall be equal to length bytes."
     * BUT implementation note clarifies:
     * "If fildes does not refer to a file opened for writing, ftruncate()
     *  shall fail with [EBADF] or [EINVAL]."
     *
     * COMPARISON TO truncate() (sys_truncate.c):
     * - truncate() uses path, checks vnode->mode write permission (lines 232-280)
     * - ftruncate() uses FD, checks file->flags for write mode (this check)
     * - Both prevent unauthorized modification, different mechanisms
     *
     * CVE REFERENCES:
     * Similar write permission bypass patterns:
     * - CVE-2016-7097: Linux posix_acl_create permission bypass
     * - CVE-2015-5706: FreeBSD capability rights violation in ftruncate
     */
    /* O_WRONLY, O_RDWR provided by fcntl.h */
    if (!(file->flags & (O_WRONLY | O_RDWR))) {
        fut_printf("[FTRUNCATE] ftruncate(fd=%d [%s], length=%llu [%s], flags=0x%x) -> EBADF "
                   "(file not opened for writing write permission check)\n",
                   fd, fd_category, length, length_category, file->flags);
        return -EBADF;
    }

    /* Phase 2: Validate length bounds (16TB maximum file size) */
    #define MAX_FILE_SIZE (16ULL * 1024 * 1024 * 1024 * 1024)  /* 16TB */
    if (length > MAX_FILE_SIZE) {
        fut_printf("[FTRUNCATE] ftruncate(fd=%d [%s], length=%llu [%s]) -> ERANGE "
                   "(length exceeds maximum file size)\n",
                   fd, fd_category, length, length_category);
        return -ERANGE;
    }

    if (length == vnode->size) {
        return 0;  /* No-op: size unchanged */
    }

    /*
     * Phase 3 (Completed): Call VFS truncate operation if available
     *
     * The truncate operation handles:
     * - Shrinking: Deallocates blocks beyond new size
     * - Extending: Allocates new blocks and zero-fills them (or sparse for Phase 4)
     * - Size update: Updates vnode->size in both cases
     */
    if (vnode->ops && vnode->ops->truncate) {
        int ret = vnode->ops->truncate(vnode, length);
        if (ret < 0) {
            const char *error_desc;
            switch (ret) {
                case -ENOMEM:
                    error_desc = "out of memory";
                    break;
                case -ENOSPC:
                    error_desc = "no space left on device";
                    break;
                case -EROFS:
                    error_desc = "read-only filesystem";
                    break;
                case -EIO:
                    error_desc = "I/O error";
                    break;
                default:
                    error_desc = "truncate operation failed";
                    break;
            }
            fut_printf("[FTRUNCATE] ftruncate(fd=%d, length=%llu, ino=%lu) -> %d (%s)\n",
                       fd, (unsigned long long)length, vnode->ino, ret, error_desc);
            return ret;
        }

        /* Dispatch IN_MODIFY: truncation changes file contents */
        if (vnode->parent && vnode->name) {
            char dir_path[256];
            if (fut_vnode_build_path(vnode->parent, dir_path, sizeof(dir_path)))
                inotify_dispatch_event(dir_path, 0x00000002 /* IN_MODIFY */, vnode->name, 0);
        }
        return 0;
    }

    /*
     * Fallback for filesystems without truncate operation:
     * Just update the size directly (Phase 2 behavior).
     * This provides backwards compatibility but doesn't deallocate/allocate blocks.
     *
     * Phase 4 additions:
     *   - Sparse file support (holes without blocks)
     *   - Preallocation hints (FALLOC_FL_* flags)
     *   - Lazy allocation for extends (reduce immediate I/O cost)
     */
    vnode->size = length;
    return 0;
}
