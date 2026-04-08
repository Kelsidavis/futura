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
#include <fcntl.h>
#include <stdint.h>
#include <string.h>

#include <kernel/kprintf.h>
#include <kernel/uaccess.h>
#include <kernel/fut_timer.h>
#include <kernel/fut_stats.h>

/* Architecture-specific paging headers for KERNEL_VIRTUAL_BASE (kernel pointer detection) */
#include <platform/platform.h>

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
#define FUT_TMPFS_MAGIC        0x01021994
#define FUT_RAMFS_MAGIC        0x858458F6
#define FUT_EXT2_MAGIC         0xEF53
#define FUT_EXT4_MAGIC         0xEF53
#define PROC_SUPER_MAGIC       0x9fa0
#define SYSFS_MAGIC            0x62656572
#define DEVTMPFS_MAGIC         0x1373
#define CGROUP_SUPER_MAGIC     0x27e0eb
#define CGROUP2_SUPER_MAGIC    0x63677270
#define SECURITYFS_MAGIC       0x73636673
#define DEBUGFS_MAGIC          0x64626720
#define TRACEFS_MAGIC          0x74726163
#define HUGETLBFS_MAGIC        0x958458F6
#define MQUEUE_MAGIC           0x19800202
#define BPF_FS_MAGIC           0xcafe4a11

/* Mount flags */
#define FUT_ST_RDONLY     0x0001  /* Read-only filesystem */
#define FUT_ST_NOSUID     0x0002  /* Ignore suid and sgid bits */
#define FUT_ST_NODEV      0x0004  /* Disallow access to device special files */
#define FUT_ST_NOEXEC     0x0008  /* Disallow program execution */

/* Helper: does `path` start with `prefix` and is followed by '/' or NUL? */
static inline int path_starts_with(const char *path, const char *prefix) {
    size_t n = 0;
    while (prefix[n]) { if (path[n] != prefix[n]) return 0; n++; }
    return path[n] == '\0' || path[n] == '/';
}

/* Return the correct filesystem magic for the given path prefix.
 * Maps well-known Linux mount points to their canonical f_type values. */
static uint32_t statfs_magic_for_path(const char *path) {
    if (!path) return FUT_RAMFS_MAGIC;
    if (path_starts_with(path, "/proc"))
        return PROC_SUPER_MAGIC;
    if (path_starts_with(path, "/sys/fs/cgroup"))
        return CGROUP2_SUPER_MAGIC;
    if (path_starts_with(path, "/sys/kernel/security"))
        return SECURITYFS_MAGIC;
    if (path_starts_with(path, "/sys/kernel/debug"))
        return DEBUGFS_MAGIC;
    if (path_starts_with(path, "/sys/kernel/tracing"))
        return TRACEFS_MAGIC;
    if (path_starts_with(path, "/sys"))
        return SYSFS_MAGIC;
    if (path_starts_with(path, "/dev/shm") ||
        path_starts_with(path, "/dev/mqueue"))
        return FUT_TMPFS_MAGIC;
    if (path_starts_with(path, "/dev/hugepages"))
        return HUGETLBFS_MAGIC;
    if (path_starts_with(path, "/dev"))
        return DEVTMPFS_MAGIC;
    /* Common tmpfs mounts: /tmp, /run, /run/shm, /var/volatile */
    if (path_starts_with(path, "/tmp") ||
        path_starts_with(path, "/run") ||
        path_starts_with(path, "/var/volatile"))
        return FUT_TMPFS_MAGIC;
    return FUT_RAMFS_MAGIC;
}

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

    /* Validate pointers */
    if (!path || !buf) {
        return -EFAULT;
    }

    /* Copy path from user space (SMAP prevents direct access) */
    char path_preview[256];
    if (fut_copy_from_user(path_preview, path, sizeof(path_preview)) != 0) {
        return -EFAULT;
    }
    path_preview[sizeof(path_preview) - 1] = '\0';

    size_t path_len = 0;
    while (path_len < sizeof(path_preview) - 1 && path_preview[path_len] != '\0')
        path_len++;

    if (path_len == 0) {
        return -ENOENT;
    }

    /* Try to get real filesystem stats from the mounted filesystem.
     * Look up the vnode, find its mount, and call the fs's statfs if available. */
    struct fut_linux_statfs real_stats = {0};
    {
        extern int fut_vfs_statfs(const char *mountpoint, struct fut_statfs *out);
        struct fut_statfs vfs_stats = {0};
        int fs_rc = fut_vfs_statfs(path_preview, &vfs_stats);
        if (fs_rc == 0 && vfs_stats.block_size > 0) {
            /* Use real filesystem stats */
            real_stats.f_type = 0x46555446ULL; /* "FUTF" */
            real_stats.f_bsize = vfs_stats.block_size;
            real_stats.f_blocks = vfs_stats.blocks_total;
            real_stats.f_bfree = vfs_stats.blocks_free;
            real_stats.f_bavail = vfs_stats.blocks_free;
            real_stats.f_files = vfs_stats.inodes_total;
            real_stats.f_ffree = vfs_stats.inodes_free;
            real_stats.f_namelen = 255;
            real_stats.f_frsize = vfs_stats.block_size;
        } else {
            /* Fall back to PMM-based stats */
            fill_statfs_from_pmm(&real_stats);
        }
    }
    real_stats.f_type = statfs_magic_for_path(path_preview);

    /* Copy to user or kernel buffer */
    if (statfs_copy_to_buf(buf, &real_stats, sizeof(struct fut_linux_statfs)) != 0) {
        return -EFAULT;
    }

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

    /* Return real physical memory stats with correct f_type from the file's path.
     * Use file->path (absolute path) or vnode->mount->mountpoint as fallback. */
    struct fut_linux_statfs stats;
    fill_statfs_from_pmm(&stats);
    {
        const char *mp = file->path;
        if (!mp && file->vnode && file->vnode->mount)
            mp = file->vnode->mount->mountpoint;
        stats.f_type = statfs_magic_for_path(mp);
    }

    /* Copy to userspace buffer */
    if (statfs_copy_to_buf(buf, &stats, sizeof(struct fut_linux_statfs)) != 0) {
        fut_printf("[FSTATFS] fstatfs(fd=%d, pid=%d) -> EFAULT (copy_to_user failed)\n",
                   fd, task->pid);
        return -EFAULT;
    }

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
 * Phase 3 (Completed): ZERO_RANGE and PUNCH_HOLE via VFS write with zero buffer
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

    /* O_PATH fds cannot be used for I/O — only path-based operations */
    if (file->flags & O_PATH)
        return -EBADF;

    /* fallocate requires write access */
    if ((file->flags & O_ACCMODE) == O_RDONLY)
        return -EBADF;

    /* Validate mode flags (values must match Linux uapi/linux/falloc.h) */
    const int FALLOC_FL_KEEP_SIZE = 0x01;
    const int FALLOC_FL_PUNCH_HOLE = 0x02;
    const int FALLOC_FL_COLLAPSE_RANGE = 0x08;
    const int FALLOC_FL_ZERO_RANGE = 0x10;
    const int FALLOC_FL_INSERT_RANGE = 0x20;
    const int VALID_FLAGS = FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE |
                            FALLOC_FL_COLLAPSE_RANGE | FALLOC_FL_ZERO_RANGE |
                            FALLOC_FL_INSERT_RANGE;

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

    /* Determine operation type */
    const char *op_type;
    if (mode & FALLOC_FL_PUNCH_HOLE) {
        op_type = "punch hole";
    } else if (mode & FALLOC_FL_COLLAPSE_RANGE) {
        op_type = "collapse range";
    } else if (mode & FALLOC_FL_INSERT_RANGE) {
        op_type = "insert range";
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
                return 0;
            }
        }
    }
    /*
     * Phase 3: ZERO_RANGE and PUNCH_HOLE write zeros over the byte range via
     * the VFS write operation.  PUNCH_HOLE always specifies KEEP_SIZE so the
     * file size is not altered; for in-memory ramfs "freeing" a hole is the
     * same as zeroing it.  COLLAPSE_RANGE is deferred to Phase 4 (requires
     * moving file data and is rarely used).
     */
    if ((mode & FALLOC_FL_ZERO_RANGE) ||
        ((mode & FALLOC_FL_PUNCH_HOLE) && (mode & FALLOC_FL_KEEP_SIZE))) {

        if (!vnode || !vnode->ops || !vnode->ops->write) {
            fut_printf("[FALLOCATE] fallocate(fd=%d, mode=0x%x [%s], pid=%d) -> EOPNOTSUPP "
                       "(filesystem does not support write)\n",
                       fd, mode, op_type, task->pid);
            return -EOPNOTSUPP;
        }

        /* Guard: range must lie within the current file */
        if (offset >= vnode->size) {
            fut_printf("[FALLOCATE] fallocate(fd=%d, mode=0x%x [%s], offset=%lu >= size=%llu, pid=%d) "
                       "-> 0 (range beyond EOF, no-op)\n",
                       fd, mode, op_type, offset, (unsigned long long)vnode->size, task->pid);
            return 0;
        }

        uint64_t clamp_len = len;
        if (offset + clamp_len > vnode->size)
            clamp_len = vnode->size - offset;

        /* Write zeros in 4 KB chunks to avoid a large stack allocation */
        static const uint8_t zero_page[4096];  /* BSS-zero static buffer */
        uint64_t remaining = clamp_len;
        uint64_t cur_off   = offset;

        while (remaining > 0) {
            size_t chunk = (remaining > sizeof(zero_page))
                           ? sizeof(zero_page) : (size_t)remaining;
            ssize_t written = vnode->ops->write(vnode, zero_page, chunk, cur_off);
            if (written < 0) {
                fut_printf("[FALLOCATE] fallocate(fd=%d, mode=0x%x [%s], pid=%d) -> %zd "
                           "(write zero failed at offset %llu)\n",
                           fd, mode, op_type, task->pid, written, (unsigned long long)cur_off);
                return (long)written;
            }
            cur_off   += (uint64_t)written;
            remaining -= (uint64_t)written;
        }

        goto clear_suid;
    }

    /* Phase 4: COLLAPSE_RANGE removes a byte range and shifts remaining data down.
     * The file size shrinks by len bytes.  Both offset and len must be
     * filesystem-block-aligned (4096 on ramfs). */
    if (mode & FALLOC_FL_COLLAPSE_RANGE) {
        /* COLLAPSE_RANGE must not be combined with other flags */
        if (mode != FALLOC_FL_COLLAPSE_RANGE) {
            return -EINVAL;
        }

        if (!vnode || !vnode->ops || !vnode->ops->read || !vnode->ops->write) {
            return -EOPNOTSUPP;
        }

        /* Linux requires block-aligned offset and len */
        if ((offset & 0xFFF) || (len & 0xFFF)) {
            return -EINVAL;
        }

        /* Range must be within the file; cannot collapse past EOF */
        if (offset + len > vnode->size) {
            return -EINVAL;
        }

        /* Shift data from [offset+len, size) down to [offset, size-len) */
        uint64_t src = offset + len;
        uint64_t dst = offset;
        uint64_t tail_bytes = vnode->size - src;
        uint8_t chunk_buf[4096];

        while (tail_bytes > 0) {
            size_t chunk = (tail_bytes > sizeof(chunk_buf))
                           ? sizeof(chunk_buf) : (size_t)tail_bytes;
            ssize_t rd = vnode->ops->read(vnode, chunk_buf, chunk, src);
            if (rd <= 0) break;
            ssize_t wr = vnode->ops->write(vnode, chunk_buf, (size_t)rd, dst);
            if (wr <= 0) break;
            src += (uint64_t)wr;
            dst += (uint64_t)wr;
            tail_bytes -= (uint64_t)wr;
        }

        /* Shrink the file by len bytes */
        if (vnode->ops->truncate) {
            vnode->ops->truncate(vnode, vnode->size - len);
        } else {
            vnode->size -= len;
        }

        goto clear_suid;
    }

    /* INSERT_RANGE: insert a zero-filled gap at offset, shifting existing data up.
     * The file grows by len bytes. Both offset and len must be block-aligned. */
    if (mode & FALLOC_FL_INSERT_RANGE) {
        /* INSERT_RANGE must not be combined with other flags */
        if (mode != FALLOC_FL_INSERT_RANGE) {
            return -EINVAL;
        }

        if (!vnode || !vnode->ops || !vnode->ops->read || !vnode->ops->write) {
            return -EOPNOTSUPP;
        }

        /* Linux requires block-aligned offset and len */
        if ((offset & 0xFFF) || (len & 0xFFF)) {
            return -EINVAL;
        }

        /* Offset must be within the file */
        if (offset > vnode->size) {
            return -EINVAL;
        }

        /* Extend file first */
        uint64_t new_size = vnode->size + len;
        if (vnode->ops->truncate) {
            int ret = vnode->ops->truncate(vnode, new_size);
            if (ret < 0) return (long)ret;
        } else {
            vnode->size = new_size;
        }

        /* Shift data from [offset, old_end) up to [offset+len, new_end).
         * Work backwards to avoid overwriting data we haven't read yet. */
        uint64_t old_end = new_size - len;  /* original file size */
        uint64_t tail_bytes = old_end - offset;
        uint8_t chunk_buf[4096];

        while (tail_bytes > 0) {
            size_t chunk = (tail_bytes > sizeof(chunk_buf))
                           ? sizeof(chunk_buf) : (size_t)tail_bytes;
            uint64_t src_off = offset + tail_bytes - chunk;
            uint64_t dst_off = src_off + len;
            ssize_t rd = vnode->ops->read(vnode, chunk_buf, chunk, src_off);
            if (rd <= 0) break;
            vnode->ops->write(vnode, chunk_buf, (size_t)rd, dst_off);
            tail_bytes -= chunk;
        }

        /* Zero the inserted gap */
        static const uint8_t zero_page[4096];
        uint64_t remaining = len;
        uint64_t cur = offset;
        while (remaining > 0) {
            size_t chunk = (remaining > sizeof(zero_page))
                           ? sizeof(zero_page) : (size_t)remaining;
            vnode->ops->write(vnode, zero_page, chunk, cur);
            cur += chunk;
            remaining -= chunk;
        }

        goto clear_suid;
    }

    return 0;

clear_suid:
    /* POSIX/Linux: clear setuid/setgid bits after fallocate modifies content */
    if (vnode && vnode->type == VN_REG) {
        uint32_t fmode = vnode->mode;
        int needs_clear = 0;
        if (fmode & 04000) needs_clear = 1;
        if ((fmode & 02000) && (fmode & 00010)) needs_clear = 1;
        if (needs_clear) {
            int has_cap_fsetid = task &&
                (task->cap_effective & (1ULL << 4 /* CAP_FSETID */));
            if (!has_cap_fsetid) {
                if (fmode & 04000)
                    vnode->mode &= ~(uint32_t)04000;
                if ((fmode & 02000) && (fmode & 00010))
                    vnode->mode &= ~(uint32_t)02000;
            }
        }
    }
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
    uint64_t uptime_ticks = fut_get_ticks();
    uint32_t nprocs       = fut_task_get_global_count();

    /* Phase 3: Get load averages from EWMA tracker in fut_stats */
    unsigned long loads[3];
    fut_get_load_avg(loads);

    struct fut_linux_sysinfo real_info = {
        .uptime    = (long)(uptime_ticks / 100),  /* ticks (100 Hz) → seconds */
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

    return 0;
}
