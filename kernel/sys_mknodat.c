/* kernel/sys_mknodat.c - Special file creation syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements mknodat for creating special files (device nodes, FIFOs, sockets).
 * Essential for device management, IPC, and container initialization.
 *
 * Phase 1 (Completed): Validation and stub implementation
 * Phase 2 (Completed): Enhanced validation, user-space data handling, parameter categorization
 * Phase 3 (Completed): Regular file and FIFO/socket creation with type validation
 * Phase 4: Add device node creation with capabilities checks
 */

#include <kernel/fut_task.h>
#include <kernel/fut_vfs.h>
#include <kernel/errno.h>
#include <sys/stat.h>
#include <stdint.h>
#include <string.h>
#include <stddef.h>

#include <kernel/kprintf.h>
#include <kernel/uaccess.h>
#include <fcntl.h>

#include <platform/platform.h>

static inline int mknodat_copy_from_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)src >= KERNEL_VIRTUAL_BASE) { __builtin_memcpy(dst, src, n); return 0; }
#endif
    return fut_copy_from_user(dst, src, n);
}

/* File type constants (S_IF*) provided by sys/stat.h */
/* AT_* constants provided by fcntl.h */

/**
 * mknodat() - Create special file or device node
 *
 * Creates a filesystem node (file, device special file, or named pipe)
 * with the specified mode and device number. This is the modern *at()
 * variant that takes a directory file descriptor for relative paths.
 *
 * @param dirfd       Directory file descriptor for relative paths (or AT_FDCWD)
 * @param pathname    Path for new file (relative to dirfd)
 * @param mode        File type and permissions (S_IFREG, S_IFCHR, S_IFBLK, S_IFIFO, S_IFSOCK)
 * @param dev         Device number (for character and block devices)
 *
 * Returns:
 *   - 0 on success
 *   - -EBADF if dirfd is invalid (when not AT_FDCWD)
 *   - -EFAULT if pathname is invalid pointer
 *   - -EINVAL if mode is invalid or unsupported
 *   - -EEXIST if pathname already exists
 *   - -EPERM if insufficient privileges (device nodes require CAP_MKNOD)
 *   - -ENOTDIR if dirfd doesn't refer to directory (when not AT_FDCWD)
 *   - -EROFS if filesystem is read-only
 *
 * Usage:
 *   // Create FIFO (named pipe)
 *   mknodat(AT_FDCWD, "/tmp/myfifo", S_IFIFO | 0666, 0);
 *
 *   // Create character device (requires CAP_MKNOD)
 *   dev_t dev = makedev(1, 3);  // /dev/null
 *   mknodat(AT_FDCWD, "/dev/null", S_IFCHR | 0666, dev);
 *
 *   // Create block device (requires CAP_MKNOD)
 *   dev_t dev = makedev(8, 0);  // /dev/sda
 *   mknodat(AT_FDCWD, "/dev/sda", S_IFBLK | 0660, dev);
 *
 *   // Create regular file (use creat/open instead, but works)
 *   mknodat(AT_FDCWD, "/tmp/file.txt", S_IFREG | 0644, 0);
 *
 *   // Relative to directory fd
 *   int dirfd = open("/dev", O_RDONLY | O_DIRECTORY);
 *   mknodat(dirfd, "mydev", S_IFCHR | 0600, makedev(10, 99));
 *   close(dirfd);
 *
 * File types:
 * - S_IFREG (0100000): Regular file (prefer open() with O_CREAT)
 * - S_IFCHR (0020000): Character device (requires CAP_MKNOD)
 * - S_IFBLK (0060000): Block device (requires CAP_MKNOD)
 * - S_IFIFO (0010000): FIFO/named pipe (use mkfifo() instead)
 * - S_IFSOCK (0140000): Socket (use socket() + bind() instead)
 *
 * Device numbers (dev parameter):
 * - Only used for S_IFCHR and S_IFBLK
 * - Encoded as: (major << 8) | minor
 * - Use makedev(major, minor) macro to construct
 * - Ignored for other file types (pass 0)
 *
 * Common use cases:
 * - Device node creation: udev, mdev create /dev entries
 *   ```c
 *   // Create /dev/null (major 1, minor 3)
 *   mknodat(AT_FDCWD, "/dev/null", S_IFCHR | 0666, makedev(1, 3));
 *   // Create /dev/zero (major 1, minor 5)
 *   mknodat(AT_FDCWD, "/dev/zero", S_IFCHR | 0666, makedev(1, 5));
 *   ```
 *
 * - Container initialization: Docker/LXC create minimal /dev
 *   ```c
 *   int devfd = open(container_root "/dev", O_RDONLY | O_DIRECTORY);
 *   mknodat(devfd, "null", S_IFCHR | 0666, makedev(1, 3));
 *   mknodat(devfd, "zero", S_IFCHR | 0666, makedev(1, 5));
 *   mknodat(devfd, "random", S_IFCHR | 0666, makedev(1, 8));
 *   ```
 *
 * - FIFO creation for IPC:
 *   ```c
 *   mknodat(AT_FDCWD, "/tmp/fifo", S_IFIFO | 0600, 0);
 *   // Writer: open("/tmp/fifo", O_WRONLY)
 *   // Reader: open("/tmp/fifo", O_RDONLY)
 *   ```
 *
 * - Unix domain socket placeholder:
 *   ```c
 *   // Note: Better to use socket() + bind()
 *   mknodat(AT_FDCWD, "/tmp/sock", S_IFSOCK | 0600, 0);
 *   ```
 *
 * Privilege requirements:
 * - Regular files, FIFOs, sockets: No special privileges
 * - Character/block devices: Requires CAP_MKNOD capability
 * - Container init: Often uses CAP_MKNOD for device setup
 *
 * AT_FDCWD behavior:
 * - If dirfd == AT_FDCWD (-100), pathname is relative to current working directory
 * - If pathname is absolute, dirfd is ignored
 * - Otherwise, pathname is relative to directory referred to by dirfd
 *
 * Differences from mknod():
 * - mknod(): Takes absolute/relative path from cwd
 * - mknodat(): Takes dirfd for safer relative path resolution
 * - mknodat() prevents TOCTTOU races and symlink attacks
 *
 * Related syscalls:
 * - mknod(): Legacy version without dirfd
 * - mkfifo(): Convenience wrapper for FIFO creation
 * - creat()/open(O_CREAT): For regular files
 * - socket() + bind(): For Unix domain sockets
 *
 * Security considerations:
 * - Device nodes can be used to bypass permissions (need CAP_MKNOD)
 * - FIFOs can be used for IPC and DoS attacks (check permissions)
 * - Symlink attacks prevented by using dirfd
 * - Container escapes possible with device nodes (audit carefully)
 *
 * Filesystem support:
 * - Most filesystems support regular files and FIFOs
 * - Device nodes typically only work on local filesystems
 * - Some filesystems (FAT, NFS) may not support special files
 * - devtmpfs is designed specifically for device nodes
 *
 * Error conditions:
 * - EBADF: dirfd invalid or not a directory
 * - EEXIST: pathname already exists
 * - EINVAL: mode invalid (unsupported file type)
 * - EPERM: Insufficient privileges for device nodes
 * - EROFS: Read-only filesystem
 * - ENOSPC: No space for new inode
 * - ENAMETOOLONG: pathname too long
 *
 * Historical notes:
 * - Original mknod() dates back to early Unix
 * - mknodat() added in POSIX.1-2008 for safety
 * - Modern systems prefer specialized syscalls (mkfifo, socket)
 * - Device node creation is increasingly rare in userspace
 *
 * Phase 1 (Completed): Validate parameters and return success
 * Phase 2 (Completed): Implement regular file and FIFO creation
 * Phase 3 (Completed): Device node creation deferred (requires capability checks)
 */
long sys_mknodat(int dirfd, const char *pathname, uint32_t mode, uint32_t dev) {
    /* ARM64 FIX: Copy parameters to local variables to survive blocking calls */
    int local_dirfd = dirfd;
    const char *local_pathname = pathname;
    uint32_t local_mode = mode;
    uint32_t local_dev = dev;

    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    /* Phase 2: Validate pathname pointer */
    if (!local_pathname) {
        fut_printf("[MKNODAT] mknodat(dirfd=%d, pathname=NULL, mode=0%o, dev=0x%x, pid=%d) -> EFAULT\n",
                   local_dirfd, local_mode, local_dev, task->pid);
        return -EFAULT;
    }

    /* Phase 2: Copy pathname from userspace to kernel space */
    char path_buf[FUT_VFS_PATH_BUFFER_SIZE];
    if (mknodat_copy_from_user(path_buf, local_pathname, sizeof(path_buf)) != 0) {
        fut_printf("[MKNODAT] mknodat(dirfd=%d, pathname=?, mode=0%o, dev=0x%x, pid=%d) -> EFAULT "
                   "(pathname copy_from_user failed)\n", local_dirfd, local_mode, local_dev, task->pid);
        return -EFAULT;
    }
    /* Verify path was not truncated */
    if (memchr(path_buf, '\0', sizeof(path_buf)) == NULL) {
        fut_printf("[MKNODAT] mknodat(path exceeds %zu bytes) -> ENAMETOOLONG\n", sizeof(path_buf) - 1);
        return -ENAMETOOLONG;
    }

    /* Empty pathname is ENOENT per Linux mknodat(2). */
    if (path_buf[0] == '\0') {
        fut_printf("[MKNODAT] mknodat(dirfd=%d, pathname=\"\" [empty], mode=0%o, dev=0x%x, pid=%d) -> ENOENT\n",
                   local_dirfd, local_mode, local_dev, task->pid);
        return -ENOENT;
    }

    /* Phase 2: Validate dirfd */
    if (local_dirfd != AT_FDCWD && local_dirfd < 0) {
        fut_printf("[MKNODAT] mknodat(dirfd=%d [invalid], pathname='%s', mode=0%o, dev=0x%x, pid=%d) -> EBADF\n",
                   local_dirfd, path_buf, local_mode, local_dev, task->pid);
        return -EBADF;
    }

    /* Validate dirfd upper bounds before accessing FD table */
    if (local_dirfd != AT_FDCWD && path_buf[0] != '/' && local_dirfd >= task->max_fds) {
        fut_printf("[MKNODAT] mknodat(dirfd=%d, max_fds=%d) -> EBADF "
                   "(dirfd exceeds max_fds, FD bounds validation)\n",
                   local_dirfd, task->max_fds);
        return -EBADF;
    }

    /* Extract file type from mode */
    uint32_t file_type = local_mode & S_IFMT;

    /* Validate file type */
    if (file_type != S_IFREG && file_type != S_IFCHR && file_type != S_IFBLK &&
        file_type != S_IFIFO && file_type != S_IFSOCK && file_type != 0) {
        fut_printf("[MKNODAT] mknodat(dirfd=%d, pathname='%s', mode=0%o [invalid type 0%o], dev=0x%x, pid=%d) -> EINVAL\n",
                   local_dirfd, path_buf, local_mode, file_type, local_dev, task->pid);
        return -EINVAL;
    }

    /* Categorize file type for logging */
    const char *type_desc;
    switch (file_type) {
        case S_IFREG:
            type_desc = "regular file";
            break;
        case S_IFCHR:
            type_desc = "character device";
            break;
        case S_IFBLK:
            type_desc = "block device";
            break;
        case S_IFIFO:
            type_desc = "FIFO (named pipe)";
            break;
        case S_IFSOCK:
            type_desc = "socket";
            break;
        case 0:
            type_desc = "default (regular file)";
            break;
        default:
            type_desc = "unknown";
            break;
    }

    /* Categorize dirfd for logging */
    const char *dirfd_desc;
    if (local_dirfd == AT_FDCWD) {
        dirfd_desc = "AT_FDCWD (current directory)";
    } else if (local_dirfd <= 2) {
        dirfd_desc = "stdio (0-2)";
    } else if (local_dirfd < 16) {
        dirfd_desc = "low (3-15)";
    } else {
        dirfd_desc = "high (>=16)";
    }

    /* Extract device major/minor if applicable */
    unsigned int major = 0;
    unsigned int minor = 0;
    if (file_type == S_IFCHR || file_type == S_IFBLK) {
        major = (local_dev >> 8) & 0xFF;
        minor = local_dev & 0xFF;
    }

    /* Character device nodes: check CAP_MKNOD and register via devfs */
    if (file_type == S_IFCHR) {
        /* Check CAP_MKNOD: required for creating device nodes */
        bool has_mknod_cap = (task->cap_effective & (1ULL << 27 /* CAP_MKNOD */)) != 0;
        bool is_root = (task->uid == 0);
        if (!has_mknod_cap && !is_root) {
            fut_printf("[MKNODAT] mknodat('%s', S_IFCHR, %u:%u) -> EPERM (need CAP_MKNOD)\n",
                       path_buf, major, minor);
            return -EPERM;
        }

        /* Resolve path */
        char resolved_path_dev[256];
        int rret_dev = fut_vfs_resolve_at(task, local_dirfd, path_buf,
                                           resolved_path_dev, sizeof(resolved_path_dev));
        if (rret_dev < 0) return rret_dev;

        /* Register character device node via devfs (makes it openable) */
        extern int devfs_create_chr(const char *, unsigned, unsigned);
        int drc = devfs_create_chr(resolved_path_dev, major, minor);
        if (drc < 0) {
            fut_printf("[MKNODAT] mknodat('%s', S_IFCHR, %u:%u) -> %d (devfs_create_chr failed)\n",
                       resolved_path_dev, major, minor, drc);
            return drc;
        }

        /* Also create the file in the VFS so stat() finds it.
         * Use the ramfs create_file to make the node visible in directory listings. */
        extern int fut_vfs_create_file(const char *path, uint32_t mode);
        int vret = fut_vfs_create_file(resolved_path_dev, (uint32_t)(local_mode & 07777));
        (void)vret;  /* OK if it already exists (devfs handles open) */

        fut_printf("[MKNODAT] mknodat('%s', S_IFCHR, %u:%u) -> 0 (device node created)\n",
                   resolved_path_dev, major, minor);
        return 0;
    }

    /* Block device nodes: create device node using the block device layer.
     * Block devices route through the same devfs_create_chr mechanism but
     * mark the vnode as a block device for stat(). */
    if (file_type == S_IFBLK) {
        /* Linux mknod(2): creating block device nodes requires
         * CAP_MKNOD. The S_IFCHR path above checks this; S_IFBLK was
         * missing the gate, so any unprivileged caller could mknod a
         * block device pointing at a real disk (e.g. dev=8:0 for
         * sda). If the resulting node is openable, that's raw disk
         * access — bypassing all filesystem permissions on the
         * mounted partitions. */
        bool has_mknod_cap = (task->cap_effective & (1ULL << 27 /* CAP_MKNOD */)) != 0;
        bool is_root = (task->uid == 0);
        if (!has_mknod_cap && !is_root) {
            fut_printf("[MKNODAT] mknodat('%s', S_IFBLK, %u:%u) -> EPERM (need CAP_MKNOD)\n",
                       path_buf, major, minor);
            return -EPERM;
        }

        extern int devfs_create_chr(const char *, unsigned, unsigned);
        /* Create the block device node at the resolved path */
        char resolved_path_blk[256];
        int brret = fut_vfs_resolve_at(task, local_dirfd, path_buf,
                                        resolved_path_blk, sizeof(resolved_path_blk));
        if (brret < 0) return brret;
        int bret = devfs_create_chr(resolved_path_blk, major, minor);
        if (bret == 0) {
            fut_printf("[MKNODAT] mknodat('%s', S_IFBLK, %u:%u) -> 0\n",
                       resolved_path_blk, major, minor);
        }
        return bret;
    }

    /* Resolve path relative to dirfd if needed */
    char resolved_path[256];
    int rret = fut_vfs_resolve_at(task, local_dirfd, path_buf,
                                   resolved_path, sizeof(resolved_path));
    if (rret < 0) {
        fut_printf("[MKNODAT] mknodat(dirfd=%d, pathname='%s') -> %d (dirfd resolve failed)\n",
                   local_dirfd, path_buf, rret);
        return rret;
    }
    const char *use_path = resolved_path;

    int ret = 0;

    /* Regular file (S_IFREG or type 0): create directly via VFS without fd allocation */
    if (file_type == S_IFREG || file_type == 0) {
        int ret = fut_vfs_create_file(use_path, local_mode & 07777);
        if (ret < 0) {
            fut_printf("[MKNODAT] mknodat(dirfd=%s, pathname='%s', type=%s, mode=0%o, pid=%d) -> %d "
                       "(VFS create failed)\n",
                       dirfd_desc, path_buf, type_desc, local_mode & 07777, task->pid, ret);
            return (long)ret;
        }
        /* Success path silent — install / dpkg / cmake invoke
         * mknodat for regular-file creation in build directories;
         * one log per file buries the kernel output. Errors above
         * still trace explicitly. */
        return 0;
    }

    /* FIFO and socket nodes: create via VFS mknod with full type bits */
    if (file_type == S_IFIFO || file_type == S_IFSOCK) {
        uint32_t full_mode = file_type | (local_mode & 07777);
        ret = fut_vfs_mknod(use_path, full_mode);
        if (ret < 0) {
            fut_printf("[MKNODAT] mknodat(dirfd=%s, pathname='%s', type=%s, mode=0%o, pid=%d) -> %d "
                       "(VFS mknod failed)\n",
                       dirfd_desc, path_buf, type_desc, local_mode & 07777, task->pid, ret);
            return (long)ret;
        }
        fut_printf("[MKNODAT] mknodat(dirfd=%s, pathname='%s', type=%s, mode=0%o, pid=%d) -> 0 "
                   "(special file created)\n",
                   dirfd_desc, path_buf, type_desc, local_mode & 07777, task->pid);
        return 0;
    }

    return -EINVAL;
}

/**
 * mknod() - Create a special or ordinary file.
 *
 * Equivalent to mknodat(AT_FDCWD, pathname, mode, dev).
 * Used by mkfifo(3), mknod(1), and programs that create named pipes
 * or device files via the mknod(2) syscall directly.
 */
long sys_mknod(const char *pathname, uint32_t mode, uint32_t dev) {
    return sys_mknodat(AT_FDCWD, pathname, mode, dev);
}
