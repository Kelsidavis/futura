/* kernel/sys_filesystem_stats.c - Filesystem statistics and allocation syscalls for ARM64
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements filesystem statistics and allocation syscalls: statfs, fstatfs, fallocate, sysinfo.
 * These provide filesystem space information, file preallocation, and system-wide statistics.
 */

#include <kernel/fut_task.h>
#include <kernel/fut_vfs.h>
#include <kernel/errno.h>
#include <stdint.h>
#include <string.h>

extern void fut_printf(const char *fmt, ...);
extern fut_task_t *fut_task_current(void);
extern struct fut_file *vfs_get_file_from_task(struct fut_task *task, int fd);

/* Filesystem type constants */
#define FUT_TMPFS_MAGIC   0x01021994
#define FUT_RAMFS_MAGIC   0x858458F6
#define FUT_EXT2_MAGIC    0xEF53
#define FUT_EXT4_MAGIC    0xEF53

/* Mount flags */
#define FUT_ST_RDONLY     0x0001  /* Read-only filesystem */
#define FUT_ST_NOSUID     0x0002  /* Ignore suid and sgid bits */
#define FUT_ST_NODEV      0x0004  /* Disallow access to device special files */
#define FUT_ST_NOEXEC     0x0008  /* Disallow program execution */

/**
 * sys_statfs - Get filesystem statistics by path
 *
 * @param path: Path to any file within the mounted filesystem
 * @param buf: Buffer to store filesystem statistics
 *
 * Returns information about the mounted filesystem containing the specified path.
 * This includes total/free space, block sizes, and filesystem type.
 *
 * Phase 1: Validate parameters, return stub data
 * Phase 2: Resolve path to vnode, query filesystem-specific statfs operation
 * Phase 3: Implement for all supported filesystems (tmpfs, ramfs, ext4)
 *
 * Returns:
 *   - 0 on success
 *   - -EFAULT if path or buf is NULL
 *   - -ENOENT if path doesn't exist
 *   - -ENAMETOOLONG if path is too long
 *   - -ESRCH if no current task
 */
long sys_statfs(const char *path, struct fut_linux_statfs *buf) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_printf("[STATFS] statfs(path=%p, buf=%p) -> ESRCH (no current task)\n", path, buf);
        return -ESRCH;
    }

    /* Validate path pointer */
    if (!path) {
        fut_printf("[STATFS] statfs(path=NULL, buf=%p, pid=%d) -> EFAULT (null path)\n",
                   buf, task->pid);
        return -EFAULT;
    }

    /* Validate buffer pointer */
    if (!buf) {
        fut_printf("[STATFS] statfs(path=%p, buf=NULL, pid=%d) -> EFAULT (null buffer)\n",
                   path, task->pid);
        return -EFAULT;
    }

    /* Estimate path length for logging */
    size_t path_len = 0;
    const char *p = path;
    while (path_len < 4096 && *p != '\0') {
        path_len++;
        p++;
    }

    if (path_len == 0) {
        fut_printf("[STATFS] statfs(path='', pid=%d) -> ENOENT (empty path)\n", task->pid);
        return -ENOENT;
    }

    if (path_len >= 4096) {
        fut_printf("[STATFS] statfs(path=<too long>, pid=%d) -> ENAMETOOLONG (path >4096)\n",
                   task->pid);
        return -ENAMETOOLONG;
    }

    /* Log first 64 characters of path */
    char path_preview[65];
    size_t preview_len = (path_len < 64) ? path_len : 64;
    for (size_t i = 0; i < preview_len; i++) {
        path_preview[i] = path[i];
    }
    path_preview[preview_len] = '\0';

    /* Phase 1: Return stub filesystem statistics
     * Phase 2: Resolve path to vnode, get mount point, call fs-specific statfs
     * Phase 3: Support all filesystem types (tmpfs, ramfs, ext4)
     */

    /* Stub data: 1GB filesystem with 512MB free */
    struct fut_linux_statfs stub_stats = {
        .f_type = FUT_TMPFS_MAGIC,       /* tmpfs filesystem */
        .f_bsize = 4096,                 /* 4KB blocks */
        .f_blocks = 262144,              /* 1GB total (262144 * 4KB) */
        .f_bfree = 131072,               /* 512MB free */
        .f_bavail = 131072,              /* 512MB available to user */
        .f_files = 65536,                /* 64K inodes total */
        .f_ffree = 32768,                /* 32K inodes free */
        .f_fsid = {0x12345678, 0x9ABCDEF0},
        .f_namelen = 255,                /* Max filename length */
        .f_frsize = 4096,                /* Fragment size */
        .f_flags = 0,                    /* No special flags */
    };

    /* Copy to userspace buffer (Phase 1: direct copy, Phase 2: copy_to_user) */
    memcpy(buf, &stub_stats, sizeof(struct fut_linux_statfs));

    fut_printf("[STATFS] statfs(path='%s%s', len=%zu, pid=%d) -> 0 "
               "(type=tmpfs, blocks=262144, free=131072, Phase 1 stub)\n",
               path_preview, (path_len > 64) ? "..." : "", path_len, task->pid);

    return 0;
}

/**
 * sys_fstatfs - Get filesystem statistics by file descriptor
 *
 * @param fd: File descriptor of any file within the mounted filesystem
 * @param buf: Buffer to store filesystem statistics
 *
 * Like statfs, but takes a file descriptor instead of a path.
 *
 * Phase 1: Validate parameters, return stub data
 * Phase 2: Get vnode from fd, query filesystem-specific statfs operation
 * Phase 3: Implement for all supported filesystems
 *
 * Returns:
 *   - 0 on success
 *   - -EBADF if fd is invalid
 *   - -EFAULT if buf is NULL
 *   - -ESRCH if no current task
 */
long sys_fstatfs(int fd, struct fut_linux_statfs *buf) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_printf("[FSTATFS] fstatfs(fd=%d, buf=%p) -> ESRCH (no current task)\n", fd, buf);
        return -ESRCH;
    }

    /* Validate buffer pointer */
    if (!buf) {
        fut_printf("[FSTATFS] fstatfs(fd=%d, buf=NULL, pid=%d) -> EFAULT (null buffer)\n",
                   fd, task->pid);
        return -EFAULT;
    }

    /* Validate file descriptor */
    if (fd < 0) {
        fut_printf("[FSTATFS] fstatfs(fd=%d, pid=%d) -> EBADF (invalid fd)\n", fd, task->pid);
        return -EBADF;
    }

    /* Get file structure */
    struct fut_file *file = vfs_get_file_from_task(task, fd);
    if (!file) {
        fut_printf("[FSTATFS] fstatfs(fd=%d, pid=%d) -> EBADF (fd not open)\n", fd, task->pid);
        return -EBADF;
    }

    /* Phase 1: Return stub filesystem statistics
     * Phase 2: Get vnode from file, get mount point, call fs-specific statfs
     */

    /* Stub data: same as statfs */
    struct fut_linux_statfs stub_stats = {
        .f_type = FUT_TMPFS_MAGIC,
        .f_bsize = 4096,
        .f_blocks = 262144,
        .f_bfree = 131072,
        .f_bavail = 131072,
        .f_files = 65536,
        .f_ffree = 32768,
        .f_fsid = {0x12345678, 0x9ABCDEF0},
        .f_namelen = 255,
        .f_frsize = 4096,
        .f_flags = 0,
    };

    /* Copy to userspace buffer */
    memcpy(buf, &stub_stats, sizeof(struct fut_linux_statfs));

    fut_printf("[FSTATFS] fstatfs(fd=%d, pid=%d) -> 0 "
               "(type=tmpfs, blocks=262144, free=131072, Phase 1 stub)\n",
               fd, task->pid);

    return 0;
}

/**
 * sys_fallocate - Preallocate or deallocate file space
 *
 * @param fd: File descriptor opened for writing
 * @param mode: Allocation mode flags
 * @param offset: Starting offset for allocation
 * @param len: Number of bytes to allocate
 *
 * Preallocates disk space for a file to avoid ENOSPC errors during writes.
 * Can also punch holes in files to free up space.
 *
 * Phase 1: Validate parameters, return success stub
 * Phase 2: Implement basic preallocation by extending file size
 * Phase 3: Implement zero-copy hole punching and space reservation
 *
 * Mode flags:
 *   - 0x00: Default mode (allocate space)
 *   - 0x01: FALLOC_FL_KEEP_SIZE (don't change file size)
 *   - 0x02: FALLOC_FL_PUNCH_HOLE (deallocate space, must use with KEEP_SIZE)
 *   - 0x04: FALLOC_FL_COLLAPSE_RANGE (remove a range from file)
 *   - 0x08: FALLOC_FL_ZERO_RANGE (zero a range without deallocating)
 *
 * Returns:
 *   - 0 on success
 *   - -EBADF if fd is invalid or not opened for writing
 *   - -EINVAL if mode is invalid or offset/len are invalid
 *   - -ENOSPC if not enough space available
 *   - -ESPIPE if fd refers to a pipe
 *   - -ESRCH if no current task
 */
long sys_fallocate(int fd, int mode, uint64_t offset, uint64_t len) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_printf("[FALLOCATE] fallocate(fd=%d, mode=0x%x, offset=%lu, len=%lu) -> ESRCH "
                   "(no current task)\n",
                   fd, mode, offset, len);
        return -ESRCH;
    }

    /* Validate file descriptor */
    if (fd < 0) {
        fut_printf("[FALLOCATE] fallocate(fd=%d, mode=0x%x, offset=%lu, len=%lu, pid=%d) -> EBADF "
                   "(invalid fd)\n",
                   fd, mode, offset, len, task->pid);
        return -EBADF;
    }

    /* Get file structure */
    struct fut_file *file = vfs_get_file_from_task(task, fd);
    if (!file) {
        fut_printf("[FALLOCATE] fallocate(fd=%d, mode=0x%x, offset=%lu, len=%lu, pid=%d) -> EBADF "
                   "(fd not open)\n",
                   fd, mode, offset, len, task->pid);
        return -EBADF;
    }

    /* Validate mode flags */
    const int FALLOC_FL_KEEP_SIZE = 0x01;
    const int FALLOC_FL_PUNCH_HOLE = 0x02;
    const int FALLOC_FL_COLLAPSE_RANGE = 0x04;
    const int FALLOC_FL_ZERO_RANGE = 0x08;
    const int VALID_FLAGS = FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE |
                            FALLOC_FL_COLLAPSE_RANGE | FALLOC_FL_ZERO_RANGE;

    if (mode & ~VALID_FLAGS) {
        fut_printf("[FALLOCATE] fallocate(fd=%d, mode=0x%x, pid=%d) -> EINVAL "
                   "(invalid mode flags)\n",
                   fd, mode, task->pid);
        return -EINVAL;
    }

    /* PUNCH_HOLE requires KEEP_SIZE */
    if ((mode & FALLOC_FL_PUNCH_HOLE) && !(mode & FALLOC_FL_KEEP_SIZE)) {
        fut_printf("[FALLOCATE] fallocate(fd=%d, mode=0x%x, pid=%d) -> EINVAL "
                   "(PUNCH_HOLE requires KEEP_SIZE)\n",
                   fd, mode, task->pid);
        return -EINVAL;
    }

    /* Validate offset and length */
    if (offset > INT64_MAX || len > INT64_MAX || (offset + len) > INT64_MAX) {
        fut_printf("[FALLOCATE] fallocate(fd=%d, offset=%lu, len=%lu, pid=%d) -> EINVAL "
                   "(offset/len overflow)\n",
                   fd, offset, len, task->pid);
        return -EINVAL;
    }

    /* Categorize allocation size */
    const char *size_category;
    if (len == 0) {
        size_category = "zero (no-op)";
    } else if (len < 4096) {
        size_category = "tiny (<4KB)";
    } else if (len < 1048576) {
        size_category = "small (4KB-1MB)";
    } else if (len < 104857600) {
        size_category = "medium (1MB-100MB)";
    } else if (len < 1073741824) {
        size_category = "large (100MB-1GB)";
    } else {
        size_category = "huge (≥1GB)";
    }

    /* Determine operation type */
    const char *op_type;
    if (mode & FALLOC_FL_PUNCH_HOLE) {
        op_type = "punch hole";
    } else if (mode & FALLOC_FL_COLLAPSE_RANGE) {
        op_type = "collapse range";
    } else if (mode & FALLOC_FL_ZERO_RANGE) {
        op_type = "zero range";
    } else if (mode & FALLOC_FL_KEEP_SIZE) {
        op_type = "allocate (keep size)";
    } else {
        op_type = "allocate (extend)";
    }

    /* Phase 1: Accept but don't actually allocate
     * Phase 2: Implement basic allocation by extending file size
     * Phase 3: Implement hole punching and advanced modes
     */

    fut_printf("[FALLOCATE] fallocate(fd=%d, mode=0x%x [%s], offset=%lu, len=%lu [%s], pid=%d) -> 0 "
               "(accepted, Phase 1 stub)\n",
               fd, mode, op_type, offset, len, size_category, task->pid);

    return 0;
}

/**
 * sys_sysinfo - Get system-wide statistics
 *
 * @param info: Buffer to store system information
 *
 * Returns overall system statistics including uptime, load averages, memory usage,
 * and process count. Used by tools like 'free', 'top', and 'uptime'.
 *
 * Phase 1: Return stub data with reasonable values
 * Phase 2: Implement real uptime, memory stats from kernel
 * Phase 3: Implement load averages and swap statistics
 *
 * Returns:
 *   - 0 on success
 *   - -EFAULT if info is NULL
 *   - -ESRCH if no current task
 */
long sys_sysinfo(struct fut_linux_sysinfo *info) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_printf("[SYSINFO] sysinfo(info=%p) -> ESRCH (no current task)\n", info);
        return -ESRCH;
    }

    /* Validate buffer pointer */
    if (!info) {
        fut_printf("[SYSINFO] sysinfo(info=NULL, pid=%d) -> EFAULT (null buffer)\n", task->pid);
        return -EFAULT;
    }

    /* Phase 1: Return stub system information
     * Phase 2: Get real values from kernel memory manager and scheduler
     * Phase 3: Implement swap statistics and accurate load averages
     */

    /* Stub data: reasonable values for a small embedded system */
    struct fut_linux_sysinfo stub_info = {
        .uptime = 3600,           /* 1 hour uptime */
        .loads = {65536, 65536, 65536},  /* Load averages (1.0, 1.0, 1.0) in fixed-point */
        .totalram = 1073741824,   /* 1GB total RAM */
        .freeram = 536870912,     /* 512MB free RAM */
        .sharedram = 0,           /* No shared memory */
        .bufferram = 16777216,    /* 16MB in buffers */
        .totalswap = 0,           /* No swap */
        .freeswap = 0,
        .procs = 5,               /* 5 processes */
        .pad = 0,
        .totalhigh = 0,           /* No high memory on ARM64 */
        .freehigh = 0,
        .mem_unit = 1,            /* Memory units in bytes */
    };

    /* Copy to userspace buffer */
    memcpy(info, &stub_info, sizeof(struct fut_linux_sysinfo));

    fut_printf("[SYSINFO] sysinfo(pid=%d) -> 0 "
               "(uptime=3600s, totalram=1GB, freeram=512MB, procs=5, Phase 1 stub)\n",
               task->pid);

    return 0;
}
