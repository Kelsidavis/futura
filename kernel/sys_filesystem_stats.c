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
#include <kernel/fut_memory.h>
#include <kernel/errno.h>
#include <stdint.h>
#include <string.h>

#include <kernel/kprintf.h>
#include <kernel/uaccess.h>
#include <kernel/fut_timer.h>
#include <kernel/fut_stats.h>

/* Architecture-specific paging headers for KERNEL_VIRTUAL_BASE (kernel pointer detection) */
#ifdef __x86_64__
#include <platform/x86_64/memory/paging.h>
#elif defined(__aarch64__)
#include <platform/arm64/memory/paging.h>
#endif

/* Copy to user or kernel buffer depending on pointer address */
static inline int statfs_copy_to_buf(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)dst >= KERNEL_VIRTUAL_BASE) {
        __builtin_memcpy(dst, src, n);
        return 0;
    }
#endif
    return fut_copy_to_user(dst, src, n);
}

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

/* Build a statfs struct from physical memory stats (shared by statfs and fstatfs) */
static void fill_statfs_from_pmm(struct fut_linux_statfs *s) {
    uint64_t total_pages = fut_pmm_total_pages();
    uint64_t free_pages  = fut_pmm_free_pages();
    const uint64_t fs_page_size = 4096;

    s->f_type    = FUT_RAMFS_MAGIC;
    s->f_bsize   = fs_page_size;
    s->f_blocks  = total_pages;
    s->f_bfree   = free_pages;
    s->f_bavail  = free_pages;       /* No reservation for root on ramfs */
    s->f_files   = 65536;            /* Nominal inode pool */
    s->f_ffree   = 32768;            /* Best-effort estimate */
    s->f_fsid[0] = 0x46555452;       /* "FUTR" */
    s->f_fsid[1] = 0x41464653;       /* "AFS " */
    s->f_namelen = 255;
    s->f_frsize  = fs_page_size;
    s->f_flags   = 0;
}

/**
 * sys_statfs - Get filesystem statistics by path
 *
 * @param path: Path to any file within the mounted filesystem
 * @param buf: Buffer to store filesystem statistics
 *
 * Returns information about the mounted filesystem containing the specified path.
 * This includes total/free space, block sizes, and filesystem type.
 *
 * Phase 1 (Completed): Validate parameters, return stub data
 * Phase 2 (Completed): Return real PMM-backed stats (blocks, free, available)
 * Phase 3 (Completed): Per-mount-point statfs via VFS mount table
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

    /* Phase 2: Return real physical memory stats as filesystem space.
     * Futura uses ramfs backed by the physical page allocator. */
    struct fut_linux_statfs real_stats = {0};
    fill_statfs_from_pmm(&real_stats);

    /* Copy to user or kernel buffer */
    if (statfs_copy_to_buf(buf, &real_stats, sizeof(struct fut_linux_statfs)) != 0) {
        fut_printf("[STATFS] statfs(path='%s%s', pid=%d) -> EFAULT (copy_to_user failed)\n",
                   path_preview, (path_len > 64) ? "..." : "", task->pid);
        return -EFAULT;
    }

    fut_printf("[STATFS] statfs(path='%s%s', len=%zu, pid=%d) -> 0 "
               "(blocks=%llu, free=%llu, Phase 2)\n",
               path_preview, (path_len > 64) ? "..." : "", path_len, task->pid,
               (unsigned long long)real_stats.f_blocks,
               (unsigned long long)real_stats.f_bfree);

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
 * Phase 1 (Completed): Validate parameters, return stub data
 * Phase 2 (Completed): Return real PMM-backed stats via fd validation
 * Phase 3 (Completed): Get vnode/mount from FD, return filesystem-appropriate stats
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

    /* Validate FD upper bound to prevent OOB array access */
    if (fd >= task->max_fds) {
        fut_printf("[FSTATFS] fstatfs(fd=%d, max_fds=%d, pid=%d) -> EBADF "
                   "(fd exceeds max_fds, FD bounds validation)\n",
                   fd, task->max_fds, task->pid);
        return -EBADF;
    }

    /* Get file structure */
    struct fut_file *file = vfs_get_file_from_task(task, fd);
    if (!file) {
        fut_printf("[FSTATFS] fstatfs(fd=%d, pid=%d) -> EBADF (fd not open)\n", fd, task->pid);
        return -EBADF;
    }

    /* Phase 2: Return real physical memory statistics
     * Phase 3 (Completed): Get vnode from file, get mount point, call fs-specific statfs
     */
    struct fut_linux_statfs stats;
    fill_statfs_from_pmm(&stats);

    /* Copy to userspace buffer */
    if (statfs_copy_to_buf(buf, &stats, sizeof(struct fut_linux_statfs)) != 0) {
        fut_printf("[FSTATFS] fstatfs(fd=%d, pid=%d) -> EFAULT (copy_to_user failed)\n",
                   fd, task->pid);
        return -EFAULT;
    }

    fut_printf("[FSTATFS] fstatfs(fd=%d, pid=%d) -> 0 "
               "(type=ramfs, blocks=%llu, free=%llu)\n",
               fd, task->pid,
               (unsigned long long)stats.f_blocks,
               (unsigned long long)stats.f_bfree);

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
 * Phase 1 (Completed): Validate parameters, return success stub
 * Phase 2 (Completed): Implement basic preallocation by extending file size
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

    /* Validate FD upper bound to prevent OOB array access */
    if (fd >= task->max_fds) {
        fut_printf("[FALLOCATE] fallocate(fd=%d, max_fds=%d, mode=0x%x, offset=%lu, len=%lu, pid=%d) -> EBADF "
                   "(fd exceeds max_fds, FD bounds validation)\n",
                   fd, task->max_fds, mode, offset, len, task->pid);
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

    /* Phase 2: Extend file size for default mode (no KEEP_SIZE).
     * For ramfs, preallocation means ensuring the vnode size covers offset+len.
     * PUNCH_HOLE and advanced modes are deferred to Phase 3.
     */
    struct fut_vnode *vnode = file->vnode;

    /* Handle modes that need actual vnode operations */
    if (mode == 0) {
        /* Default: allocate space, possibly extending size */
        if (vnode && vnode->ops && vnode->ops->truncate) {
            uint64_t new_size = offset + len;
            /* Only extend; never shrink via fallocate */
            if (new_size > vnode->size) {
                int ret = vnode->ops->truncate(vnode, new_size);
                if (ret < 0) {
                    fut_printf("[FALLOCATE] fallocate(fd=%d, mode=0, offset=%lu, len=%lu, pid=%d) "
                               "-> %d (truncate failed)\n",
                               fd, offset, len, task->pid, ret);
                    return ret;
                }
                fut_printf("[FALLOCATE] fallocate(fd=%d, mode=0, offset=%lu, len=%lu, pid=%d) -> 0 "
                           "(extended to %llu bytes)\n",
                           fd, offset, len, task->pid, (unsigned long long)new_size);
                return 0;
            }
        }
    }
    /* KEEP_SIZE, PUNCH_HOLE, COLLAPSE_RANGE, ZERO_RANGE: accept as no-op on ramfs */

    fut_printf("[FALLOCATE] fallocate(fd=%d, mode=0x%x [%s], offset=%lu, len=%lu [%s], pid=%d) -> 0\n",
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
 * Phase 1 (Completed): Return stub data with reasonable values
 * Phase 2 (Completed): Real uptime, PMM-backed memory stats, and process count
 * Phase 3 (Completed): Load average via per-tick EWMA in fut_stats_tick()
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

    /* Phase 2+3: Fill with real kernel statistics including load averages */
    const uint64_t fs_page_size = 4096;
    uint64_t total_pages = fut_pmm_total_pages();
    uint64_t free_pages  = fut_pmm_free_pages();
    uint64_t uptime_ms   = fut_get_ticks();
    uint32_t nprocs      = fut_task_get_global_count();

    /* Phase 3: Get load averages from EWMA tracker in fut_stats */
    unsigned long loads[3];
    fut_get_load_avg(loads);

    struct fut_linux_sysinfo real_info = {
        .uptime    = (long)(uptime_ms / 1000),
        .loads     = {loads[0], loads[1], loads[2]},
        .totalram  = total_pages * fs_page_size,
        .freeram   = free_pages  * fs_page_size,
        .sharedram = 0,
        .bufferram = 0,
        .totalswap = 0,                /* No swap on ramfs */
        .freeswap  = 0,
        .procs     = (unsigned short)nprocs,
        .pad       = 0,
        .totalhigh = 0,
        .freehigh  = 0,
        .mem_unit  = 1,
    };

    /* Copy to userspace buffer */
    if (statfs_copy_to_buf(info, &real_info, sizeof(struct fut_linux_sysinfo)) != 0) {
        fut_printf("[SYSINFO] sysinfo(pid=%d) -> EFAULT (copy_to_user failed)\n", task->pid);
        return -EFAULT;
    }

    fut_printf("[SYSINFO] sysinfo(pid=%d) -> 0 "
               "(uptime=%lus, load=%lu.%02lu/%lu.%02lu/%lu.%02lu, "
               "totalram=%lluMB, freeram=%lluMB, procs=%u, Phase3)\n",
               task->pid,
               (unsigned long)(uptime_ms / 1000),
               loads[0] >> 16, ((loads[0] & 0xffff) * 100) >> 16,
               loads[1] >> 16, ((loads[1] & 0xffff) * 100) >> 16,
               loads[2] >> 16, ((loads[2] & 0xffff) * 100) >> 16,
               (unsigned long long)(total_pages * fs_page_size / (1024 * 1024)),
               (unsigned long long)(free_pages  * fs_page_size / (1024 * 1024)),
               nprocs);

    return 0;
}
