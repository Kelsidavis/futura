/* kernel/sys_statx.c - Extended file status syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements the statx() syscall for retrieving extended file metadata.
 * statx() is the modern replacement for stat/fstat/lstat, providing
 * additional information like birth time, mount ID, and attribute flags.
 *
 * Linux syscall number: 332 (x86_64)
 *
 * Phase 1 (Completed): Full statx with AT_FDCWD, AT_EMPTY_PATH,
 *                       AT_SYMLINK_NOFOLLOW, dirfd-relative paths,
 *                       and mask-based field selection.
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <kernel/fut_vfs.h>
#include <kernel/userns.h>
#include <kernel/fut_fd_util.h>
#include <kernel/kprintf.h>
#include <kernel/uaccess.h>
#include <kernel/fut_timer.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>

/* Architecture-specific paging headers for KERNEL_VIRTUAL_BASE */
#include <platform/platform.h>

/* Kernel-pointer bypass helpers for selftest compatibility */
static inline int statx_copy_to_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)dst >= KERNEL_VIRTUAL_BASE) { __builtin_memcpy(dst, src, n); return 0; }
#endif
    return fut_copy_to_user(dst, src, n);
}

static inline int statx_copy_from_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)src >= KERNEL_VIRTUAL_BASE) { __builtin_memcpy(dst, src, n); return 0; }
#endif
    return fut_copy_from_user(dst, src, n);
}

static inline int statx_access_ok_write(const void *ptr, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)ptr >= KERNEL_VIRTUAL_BASE) return 0;
#endif
    return fut_access_ok(ptr, n, 1);
}

/* ============================================================
 *   statx structures and constants (Linux UAPI)
 * ============================================================ */

/* statx_timestamp: sub-second precision timestamps */
struct fut_statx_timestamp {
    int64_t  tv_sec;       /* Seconds since epoch */
    uint32_t tv_nsec;      /* Nanoseconds (0..999999999) */
    int32_t  __reserved;   /* Padding */
};

/* statx: extended file attributes */
struct fut_statx {
    uint32_t stx_mask;           /* What results were written */
    uint32_t stx_blksize;       /* Preferred I/O block size */
    uint64_t stx_attributes;    /* Flags conveying information about the file */
    uint32_t stx_nlink;         /* Number of hard links */
    uint32_t stx_uid;           /* User ID of owner */
    uint32_t stx_gid;           /* Group ID of owner */
    uint16_t stx_mode;          /* File mode */
    uint16_t __spare0[1];
    uint64_t stx_ino;           /* Inode number */
    uint64_t stx_size;          /* File size */
    uint64_t stx_blocks;        /* Number of 512-byte blocks */
    uint64_t stx_attributes_mask; /* Mask to show what's supported in stx_attributes */

    /* Timestamps */
    struct fut_statx_timestamp stx_atime;  /* Last access time */
    struct fut_statx_timestamp stx_btime;  /* File creation (birth) time */
    struct fut_statx_timestamp stx_ctime;  /* Last attribute change time */
    struct fut_statx_timestamp stx_mtime;  /* Last data modification time */

    /* Device IDs (if device file) */
    uint32_t stx_rdev_major;
    uint32_t stx_rdev_minor;
    uint32_t stx_dev_major;
    uint32_t stx_dev_minor;

    uint64_t stx_mnt_id;        /* Mount ID */
    uint32_t stx_dio_mem_align;  /* Memory buffer alignment for direct I/O */
    uint32_t stx_dio_offset_align; /* File offset alignment for direct I/O */

    uint64_t __spare3[12];       /* Spare space for future extensions */
};

/* STATX_* mask bits — which fields the caller wants */
#define STATX_TYPE        0x00000001U  /* stx_mode & S_IFMT */
#define STATX_MODE        0x00000002U  /* stx_mode & ~S_IFMT */
#define STATX_NLINK       0x00000004U  /* stx_nlink */
#define STATX_UID         0x00000008U  /* stx_uid */
#define STATX_GID         0x00000010U  /* stx_gid */
#define STATX_ATIME       0x00000020U  /* stx_atime */
#define STATX_MTIME       0x00000040U  /* stx_mtime */
#define STATX_CTIME       0x00000080U  /* stx_ctime */
#define STATX_INO         0x00000100U  /* stx_ino */
#define STATX_SIZE        0x00000200U  /* stx_size */
#define STATX_BLOCKS      0x00000400U  /* stx_blocks */
#define STATX_BASIC_STATS 0x000007ffU  /* All of the above */
#define STATX_BTIME       0x00000800U  /* stx_btime (birth time) */
#define STATX_MNT_ID      0x00001000U  /* stx_mnt_id */
#define STATX_DIOALIGN    0x00002000U  /* stx_dio_*_align */
#define STATX_ALL         0x00000fffU  /* All currently defined flags */

/* AT_STATX_* flags (in addition to standard AT_* flags) */
#define AT_STATX_SYNC_TYPE    0x6000
#define AT_STATX_SYNC_AS_STAT 0x0000  /* Default: sync as stat() */
#define AT_STATX_FORCE_SYNC   0x2000  /* Force sync with backing store */
#define AT_STATX_DONT_SYNC    0x4000  /* Don't sync — use cached data */

/* STATX_ATTR_* attribute flags */
#define STATX_ATTR_COMPRESSED  0x00000004U
#define STATX_ATTR_IMMUTABLE   0x00000010U
#define STATX_ATTR_APPEND      0x00000020U
#define STATX_ATTR_NODUMP      0x00000040U
#define STATX_ATTR_ENCRYPTED   0x00000800U
#define STATX_ATTR_AUTOMOUNT   0x00001000U
#define STATX_ATTR_MOUNT_ROOT  0x00002000U
#define STATX_ATTR_VERITY      0x00100000U
#define STATX_ATTR_DAX         0x00200000U

/* Valid AT_* flags for statx */
#define STATX_VALID_FLAGS (AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH | \
                           AT_STATX_SYNC_TYPE | AT_NO_AUTOMOUNT)

/* AT_NO_AUTOMOUNT if not defined */
#ifndef AT_NO_AUTOMOUNT
#define AT_NO_AUTOMOUNT 0x800
#endif

/* Helper: convert vnode type to S_IF* mode bits */
/* Use vnode_type_to_stat_mode() from fut_vfs.h */
#define vnode_type_to_mode(t) ((uint16_t)vnode_type_to_stat_mode(t))

/* Fill statx from a vnode */
static void fill_statx_from_vnode(struct fut_vnode *vnode, struct fut_statx *sx,
                                  uint32_t mask) {
    __builtin_memset(sx, 0, sizeof(*sx));

    /* We can provide all basic stats from vnode */
    uint32_t result_mask = 0;
    fut_task_t *cur = fut_task_current();
    struct user_namespace *ns = cur ? cur->user_ns : NULL;

    if (mask & STATX_TYPE) {
        sx->stx_mode = vnode_type_to_mode(vnode->type);
        result_mask |= STATX_TYPE;
    }

    if (mask & STATX_MODE) {
        sx->stx_mode |= (uint16_t)(vnode->mode & 07777);
        result_mask |= STATX_MODE;
    }

    if (mask & STATX_NLINK) {
        sx->stx_nlink = vnode->nlinks;
        result_mask |= STATX_NLINK;
    }

    if (mask & STATX_UID) {
        sx->stx_uid = userns_host_to_ns_uid(ns, vnode->uid);
        result_mask |= STATX_UID;
    }

    if (mask & STATX_GID) {
        sx->stx_gid = userns_host_to_ns_gid(ns, vnode->gid);
        result_mask |= STATX_GID;
    }

    if (mask & STATX_INO) {
        sx->stx_ino = vnode->ino;
        result_mask |= STATX_INO;
    }

    if (mask & STATX_SIZE) {
        sx->stx_size = vnode->size;
        result_mask |= STATX_SIZE;
    }

    if (mask & STATX_BLOCKS) {
        sx->stx_blocks = (vnode->size + 511) / 512;
        result_mask |= STATX_BLOCKS;
    }

    /* Block size for I/O */
    sx->stx_blksize = 4096;

    /* Timestamps: use getattr if available, else best-effort from timer */
    struct fut_stat tmp_stat = {0};
    int has_stat = 0;
    if (vnode->ops && vnode->ops->getattr) {
        if (vnode->ops->getattr(vnode, &tmp_stat) == 0)
            has_stat = 1;
    }

    if (mask & STATX_ATIME) {
        if (has_stat) {
            sx->stx_atime.tv_sec = tmp_stat.st_atime;
        } else {
            sx->stx_atime.tv_sec = (int64_t)(fut_get_time_ns() / 1000000000ULL);
        }
        sx->stx_atime.tv_nsec = 0;
        result_mask |= STATX_ATIME;
    }

    if (mask & STATX_MTIME) {
        if (has_stat) {
            sx->stx_mtime.tv_sec = tmp_stat.st_mtime;
        } else {
            sx->stx_mtime.tv_sec = (int64_t)(fut_get_time_ns() / 1000000000ULL);
        }
        sx->stx_mtime.tv_nsec = 0;
        result_mask |= STATX_MTIME;
    }

    if (mask & STATX_CTIME) {
        if (has_stat) {
            sx->stx_ctime.tv_sec = tmp_stat.st_ctime;
        } else {
            sx->stx_ctime.tv_sec = (int64_t)(fut_get_time_ns() / 1000000000ULL);
        }
        sx->stx_ctime.tv_nsec = 0;
        result_mask |= STATX_CTIME;
    }

    if (mask & STATX_BTIME) {
        /* Birth time: use ctime as approximation (ramfs doesn't track btime) */
        if (has_stat) {
            sx->stx_btime.tv_sec = tmp_stat.st_ctime;
        } else {
            sx->stx_btime.tv_sec = (int64_t)(fut_get_time_ns() / 1000000000ULL);
        }
        sx->stx_btime.tv_nsec = 0;
        result_mask |= STATX_BTIME;
    }

    /* Device numbers */
    if (vnode->mount) {
        uint64_t dev = vnode->mount->st_dev;
        sx->stx_dev_major = (uint32_t)(dev >> 8);
        sx->stx_dev_minor = (uint32_t)(dev & 0xFF);
    }

    /* rdev for device files: not tracked in VFS stat, leave as 0 */

    /* Mount ID: use st_dev as a stand-in */
    if (mask & STATX_MNT_ID) {
        sx->stx_mnt_id = vnode->mount ? vnode->mount->st_dev : 0;
        result_mask |= STATX_MNT_ID;
    }

    /* Attributes: report what we support */
    sx->stx_attributes = 0;
    sx->stx_attributes_mask = STATX_ATTR_IMMUTABLE | STATX_ATTR_APPEND;

    /* Check if this is a mount root */
    if (vnode->mount && vnode->mount->root == vnode)
        sx->stx_attributes |= STATX_ATTR_MOUNT_ROOT;
    sx->stx_attributes_mask |= STATX_ATTR_MOUNT_ROOT;

    sx->stx_mask = result_mask;
}

/**
 * statx() - Get extended file status
 *
 * @param dirfd     Directory FD or AT_FDCWD
 * @param pathname  Path relative to dirfd (or absolute)
 * @param flags     AT_SYMLINK_NOFOLLOW, AT_EMPTY_PATH, AT_STATX_*
 * @param mask      STATX_* mask indicating which fields to fill
 * @param statxbuf  Pointer to userspace statx buffer
 *
 * Returns 0 on success, negative errno on failure.
 */
long sys_statx(int dirfd, const char *pathname, int flags,
               unsigned int mask, struct fut_statx *statxbuf) {
    /* ARM64 FIX: Copy parameters to locals */
    int local_dirfd = dirfd;
    const char *local_pathname = pathname;
    int local_flags = flags;
    unsigned int local_mask = mask;
    struct fut_statx *local_statxbuf = statxbuf;

    fut_task_t *task = fut_task_current();
    if (!task)
        return -ESRCH;

    /* Linux's fs/stat.c:do_statx validates mask BEFORE flags:
     *   if (mask & STATX__RESERVED) return -EINVAL;
     *   if ((flags & AT_STATX_SYNC_TYPE) == AT_STATX_SYNC_TYPE)
     *       return -EINVAL;
     * STATX__RESERVED is 0x80000000 (bit 31) — reserved for future
     * use to extend the mask beyond 31 bits.  Without this gate a
     * caller probing for future STATX_* fields by walking through
     * mask bits silently 'succeeded' on Futura where Linux returns
     * EINVAL, so userspace couldn't detect the kernel-too-old case
     * for new fields.  Match Linux's mask-first ordering so probes
     * with simultaneously-bad-mask + bad-flags get the documented
     * mask-EINVAL class. */
    if (local_mask & 0x80000000U /* STATX__RESERVED */) {
        fut_printf("[STATX] statx(mask=0x%x) -> EINVAL (STATX__RESERVED set)\n", local_mask);
        return -EINVAL;
    }

    /* Validate flags */
    if (local_flags & ~STATX_VALID_FLAGS) {
        fut_printf("[STATX] statx(flags=0x%x) -> EINVAL (invalid flags)\n", local_flags);
        return -EINVAL;
    }

    /* Linux's do_statx rejects the AT_STATX_FORCE_SYNC | AT_STATX_DONT_SYNC
     * combination — they're mutually-exclusive selectors of a 2-bit
     * sync-mode field:
     *   if ((flags & AT_STATX_SYNC_TYPE) == AT_STATX_SYNC_TYPE)
     *       return -EINVAL;
     * The previous Futura code accepted this nonsense combination as
     * 'unknown bits not set' since both bits are individually within
     * STATX_VALID_FLAGS — masking the documented Linux gate that lets
     * libc statx wrappers detect malformed flag combos. */
    if ((local_flags & AT_STATX_SYNC_TYPE) == AT_STATX_SYNC_TYPE) {
        fut_printf("[STATX] statx(flags=0x%x) -> EINVAL (FORCE_SYNC|DONT_SYNC both set)\n",
                   local_flags);
        return -EINVAL;
    }

    /* Validate output buffer */
    if (!local_statxbuf)
        return -EFAULT;

    if (statx_access_ok_write(local_statxbuf, sizeof(struct fut_statx)) != 0)
        return -EFAULT;

    /* Validate pathname */
    if (!local_pathname)
        return -EFAULT;

    /* Copy pathname from userspace */
    char path_buf[256];
    if (statx_copy_from_user(path_buf, local_pathname, sizeof(path_buf)) != 0)
        return -EFAULT;
    if (memchr(path_buf, '\0', sizeof(path_buf)) == NULL)
        return -ENAMETOOLONG;

    struct fut_statx kernel_sx;
    struct fut_vnode *vnode = NULL;

    /* AT_EMPTY_PATH: stat the fd itself */
    if (path_buf[0] == '\0') {
        if (!(local_flags & AT_EMPTY_PATH))
            return -ENOENT;

        if (local_dirfd == AT_FDCWD)
            return -EINVAL;

        if (local_dirfd < 0 || local_dirfd >= task->max_fds)
            return -EBADF;

        struct fut_file *file = vfs_get_file_from_task(task, local_dirfd);
        if (!file || !file->vnode)
            return -EBADF;

        vnode = file->vnode;
        fill_statx_from_vnode(vnode, &kernel_sx, local_mask);
    } else {
        /* Resolve path to a full path based on dirfd */
        char resolved_path[256];

        if (path_buf[0] == '/') {
            /* Absolute path — use directly */
            size_t len = strnlen(path_buf, sizeof(resolved_path) - 1);
            __builtin_memcpy(resolved_path, path_buf, len);
            resolved_path[len] = '\0';
        } else if (local_dirfd == AT_FDCWD) {
            /* Relative to CWD — VFS handles this */
            size_t len = strnlen(path_buf, sizeof(resolved_path) - 1);
            __builtin_memcpy(resolved_path, path_buf, len);
            resolved_path[len] = '\0';
        } else {
            /* Relative to dirfd */
            if (local_dirfd < 0 || local_dirfd >= task->max_fds)
                return -EBADF;

            struct fut_file *dir_file = vfs_get_file_from_task(task, local_dirfd);
            if (!dir_file || !dir_file->vnode)
                return -EBADF;
            if (dir_file->vnode->type != VN_DIR)
                return -ENOTDIR;

            if (dir_file->path) {
                size_t dir_len = strlen(dir_file->path);
                size_t rel_len = strnlen(path_buf, sizeof(resolved_path) - 1);
                int has_trail = (dir_len > 0 && dir_file->path[dir_len - 1] == '/');
                if (dir_len + (has_trail ? 0 : 1) + rel_len >= sizeof(resolved_path))
                    return -ENAMETOOLONG;
                size_t pos = 0;
                for (size_t j = 0; j < dir_len; j++) resolved_path[pos++] = dir_file->path[j];
                if (!has_trail) resolved_path[pos++] = '/';
                for (size_t j = 0; j <= rel_len; j++) resolved_path[pos++] = path_buf[j];
            } else {
                size_t len = strnlen(path_buf, sizeof(resolved_path) - 1);
                __builtin_memcpy(resolved_path, path_buf, len);
                resolved_path[len] = '\0';
            }
        }

        /* Perform the stat via VFS to get the vnode.
         * Zero-init: fut_vfs_stat fills only a subset of fields; any
         * padding or reserved bytes would otherwise carry kernel-stack
         * content into the fallback fill_statx path below (same class
         * as the sys_fstatfs leak fixed earlier). */
        struct fut_stat tmp = {0};
        int ret;
        if (local_flags & AT_SYMLINK_NOFOLLOW)
            ret = fut_vfs_lstat(resolved_path, &tmp);
        else
            ret = fut_vfs_stat(resolved_path, &tmp);

        if (ret < 0)
            return ret;

        /* We have a stat result, but we need the vnode for richer data.
         * Look up the vnode via VFS. If lookup fails, build statx from fut_stat. */
        struct fut_vnode *lookup_vnode = NULL;
        int lookup_ret;
        if (local_flags & AT_SYMLINK_NOFOLLOW)
            lookup_ret = fut_vfs_lookup_nofollow(resolved_path, &lookup_vnode);
        else
            lookup_ret = fut_vfs_lookup(resolved_path, &lookup_vnode);

        if (lookup_ret == 0 && lookup_vnode) {
            fill_statx_from_vnode(lookup_vnode, &kernel_sx, local_mask);
        } else {
            /* Fallback: fill from fut_stat */
            __builtin_memset(&kernel_sx, 0, sizeof(kernel_sx));
            uint32_t result_mask = 0;

            if (local_mask & STATX_TYPE) {
                kernel_sx.stx_mode = (uint16_t)(tmp.st_mode & 0170000);
                result_mask |= STATX_TYPE;
            }
            if (local_mask & STATX_MODE) {
                kernel_sx.stx_mode |= (uint16_t)(tmp.st_mode & 07777);
                result_mask |= STATX_MODE;
            }
            if (local_mask & STATX_NLINK) {
                kernel_sx.stx_nlink = tmp.st_nlink;
                result_mask |= STATX_NLINK;
            }
            if (local_mask & STATX_UID) {
                kernel_sx.stx_uid = tmp.st_uid;
                result_mask |= STATX_UID;
            }
            if (local_mask & STATX_GID) {
                kernel_sx.stx_gid = tmp.st_gid;
                result_mask |= STATX_GID;
            }
            if (local_mask & STATX_INO) {
                kernel_sx.stx_ino = tmp.st_ino;
                result_mask |= STATX_INO;
            }
            if (local_mask & STATX_SIZE) {
                kernel_sx.stx_size = tmp.st_size;
                result_mask |= STATX_SIZE;
            }
            if (local_mask & STATX_BLOCKS) {
                kernel_sx.stx_blocks = tmp.st_blocks;
                result_mask |= STATX_BLOCKS;
            }
            if (local_mask & STATX_ATIME) {
                kernel_sx.stx_atime.tv_sec = tmp.st_atime;
                result_mask |= STATX_ATIME;
            }
            if (local_mask & STATX_MTIME) {
                kernel_sx.stx_mtime.tv_sec = tmp.st_mtime;
                result_mask |= STATX_MTIME;
            }
            if (local_mask & STATX_CTIME) {
                kernel_sx.stx_ctime.tv_sec = tmp.st_ctime;
                result_mask |= STATX_CTIME;
            }
            if (local_mask & STATX_BTIME) {
                kernel_sx.stx_btime.tv_sec = tmp.st_ctime;
                result_mask |= STATX_BTIME;
            }

            kernel_sx.stx_blksize = tmp.st_blksize;
            kernel_sx.stx_dev_major = (uint32_t)(tmp.st_dev >> 8);
            kernel_sx.stx_dev_minor = (uint32_t)(tmp.st_dev & 0xFF);
            /* rdev not tracked in fut_stat (VFS version) */
            kernel_sx.stx_mask = result_mask;
        }
    }

    /* Copy result to userspace */
    if (statx_copy_to_user(local_statxbuf, &kernel_sx, sizeof(kernel_sx)) != 0)
        return -EFAULT;

    return 0;
}
