/* kernel/sys_faccessat.c - Directory-based file accessibility check syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements the faccessat() syscall for checking file accessibility relative
 * to a directory FD. Essential for thread-safe permission checking and avoiding
 * race conditions.
 *
 * Phase 1 (Completed): Basic faccessat with directory FD support
 * Phase 2 (Completed): Enhanced validation, directory FD resolution, AT_EACCESS support
 * Phase 3 (Completed): Full AT_SYMLINK_NOFOLLOW support with lstat-based checking
 */

#include <kernel/fut_task.h>
#include <kernel/fut_vfs.h>
#include <kernel/errno.h>
#include <kernel/userns.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <kernel/kprintf.h>
#include <kernel/uaccess.h>
#include <kernel/syscalls.h>
#include <fcntl.h>

#include <platform/platform.h>

static inline int faccessat_copy_from_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)src >= KERNEL_VIRTUAL_BASE) { __builtin_memcpy(dst, src, n); return 0; }
#endif
    return fut_copy_from_user(dst, src, n);
}

/* AT_* constants provided by fcntl.h */
#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH    0x1000   /* Allow empty relative pathname (faccessat2) */
#endif

/* access() mode bits */
#define F_OK 0  /* File exists */
#define X_OK 1  /* Execute permission */
#define W_OK 2  /* Write permission */
#define R_OK 4  /* Read permission */

/**
 * faccessat() - Check file accessibility relative to directory FD
 *
 * Like access(), but pathname is interpreted relative to dirfd instead of
 * the current working directory. This enables race-free permission checking
 * when working with directory hierarchies in multithreaded applications.
 *
 * @param dirfd    Directory file descriptor (or AT_FDCWD for CWD)
 * @param pathname Path relative to dirfd (or absolute path)
 * @param mode     Accessibility mode (F_OK, R_OK, W_OK, X_OK, or combination)
 * @param flags    AT_EACCESS or AT_SYMLINK_NOFOLLOW, or 0
 *
 * Returns:
 *   - 0 if file is accessible with requested permissions
 *   - -EBADF if dirfd is invalid
 *   - -EACCES if permission denied
 *   - -EFAULT if pathname is inaccessible
 *   - -EINVAL if pathname is empty, NULL, mode invalid, or flags invalid
 *   - -ENOENT if file doesn't exist
 *   - -ENOTDIR if path component is not a directory
 *   - -ENAMETOOLONG if pathname too long
 *
 * Behavior:
 *   - If pathname is absolute, dirfd is ignored
 *   - If pathname is relative and dirfd is AT_FDCWD, uses current directory
 *   - If pathname is relative and dirfd is FD, uses that directory
 *   - Default: Checks access using real UID/GID
 *   - AT_EACCESS: Check using effective UID/GID instead of real UID/GID
 *   - AT_SYMLINK_NOFOLLOW: Don't follow symbolic links
 *   - Prevents TOCTOU races vs separate getcwd() + access()
 *
 * Common usage patterns:
 *
 * Thread-safe file existence check:
 *   int dirfd = open("/some/dir", O_RDONLY | O_DIRECTORY);
 *   if (faccessat(dirfd, "file.txt", F_OK, 0) == 0) {
 *       // File exists
 *   }
 *   close(dirfd);
 *
 * Check read permission:
 *   if (faccessat(dirfd, "data.txt", R_OK, 0) == 0) {
 *       // File is readable
 *       int fd = openat(dirfd, "data.txt", O_RDONLY);
 *   }
 *
 * Use current directory:
 *   faccessat(AT_FDCWD, "file.txt", R_OK | W_OK, 0);
 *   // Same as access("file.txt", R_OK | W_OK)
 *
 * Absolute pathname (dirfd ignored):
 *   faccessat(dirfd, "/tmp/file", F_OK, 0);  // dirfd not used
 *
 * Check with effective IDs (setuid programs):
 *   faccessat(dirfd, "file.txt", R_OK, AT_EACCESS);
 *   // Check using effective UID/GID instead of real UID/GID
 *
 * Don't follow symlinks:
 *   faccessat(dirfd, "symlink", F_OK, AT_SYMLINK_NOFOLLOW);
 *   // Check if symlink itself exists, not what it points to
 *
 * Race-free permission check:
 *   int dirfd = open("/etc", O_RDONLY | O_DIRECTORY);
 *   // Directory can't be renamed/moved while we have it open
 *   if (faccessat(dirfd, "config", R_OK, 0) == 0) {
 *       // Safe to read config
 *       int fd = openat(dirfd, "config", O_RDONLY);
 *   }
 *   close(dirfd);
 *
 * Advantages over access():
 * 1. Thread-safe: Works correctly with multiple threads
 * 2. Race-free: Directory context locked by FD
 * 3. Flexible: Can use CWD or specific directory
 * 4. Effective IDs: Can check effective UID/GID with AT_EACCESS
 * 5. Symlink control: Can choose to follow or not follow symlinks
 *
 * Phase 1 (Completed): Basic implementation with dirfd support
 * Phase 3 (Completed): Full AT_SYMLINK_NOFOLLOW with lstat-based permission checking
 */
long sys_faccessat(int dirfd, const char *pathname, int mode, int flags) {
    /* ARM64 FIX: Copy parameters to local variables */
    int local_dirfd = dirfd;
    const char *local_pathname = pathname;
    int local_mode = mode;
    int local_flags = flags;

    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_printf("[FACCESSAT] faccessat(dirfd=%d, mode=%d, flags=0x%x) -> ESRCH (no current task)\n",
                   local_dirfd, local_mode, local_flags);
        return -ESRCH;
    }

    /* Validate flags — AT_EMPTY_PATH accepted (faccessat2 path) */
    const int VALID_FLAGS = AT_EACCESS | AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH;
    if (local_flags & ~VALID_FLAGS) {
        fut_printf("[FACCESSAT] faccessat(dirfd=%d, mode=%d, flags=0x%x) -> EINVAL (invalid flags)\n",
                   local_dirfd, local_mode, local_flags);
        return -EINVAL;
    }

    /* Validate mode bits */
    const int VALID_MODE = F_OK | R_OK | W_OK | X_OK;
    if (local_mode & ~VALID_MODE) {
        fut_printf("[FACCESSAT] faccessat(dirfd=%d, mode=%d) -> EINVAL (invalid mode bits)\n",
                   local_dirfd, local_mode);
        return -EINVAL;
    }

    /* NULL pathname is a pointer fault (EFAULT) per Linux faccessat(2). */
    if (!local_pathname) {
        fut_printf("[FACCESSAT] faccessat(dirfd=%d, pathname=NULL) -> EFAULT\n",
                   local_dirfd);
        return -EFAULT;
    }

    /* Copy pathname from userspace */
    char path_buf[FUT_VFS_PATH_BUFFER_SIZE];
    if (faccessat_copy_from_user(path_buf, local_pathname, sizeof(path_buf)) != 0) {
        fut_printf("[FACCESSAT] faccessat(dirfd=%d) -> EFAULT (copy_from_user failed)\n",
                   local_dirfd);
        return -EFAULT;
    }
    if (memchr(path_buf, '\0', sizeof(path_buf)) == NULL) {
        fut_printf("[FACCESSAT] faccessat(dirfd=%d) -> ENAMETOOLONG\n",
                   local_dirfd);
        return -ENAMETOOLONG;
    }

    /* AT_EMPTY_PATH: empty pathname means operate on dirfd itself.
     * Note: Futura test 409 pins faccessat(fd, "", 0, 0) -> EINVAL
     * (not Linux's ENOENT). Per the project rule 'local tests take
     * precedence over Linux ABI parity', keep EINVAL here. */
    if (path_buf[0] == '\0') {
        if (!(local_flags & AT_EMPTY_PATH)) {
            fut_printf("[FACCESSAT] faccessat(dirfd=%d, pathname=\"\" [empty]) -> EINVAL\n",
                       local_dirfd);
            return -EINVAL;
        }

        /* Get the vnode for dirfd (or cwd when dirfd == AT_FDCWD) */
        struct fut_vnode *vnode = NULL;
        if (local_dirfd == AT_FDCWD) {
            /* Look up the cwd vnode by path */
            const char *cwd = (task && task->cwd_cache && task->cwd_cache[0])
                              ? task->cwd_cache : "/";
            extern int fut_vfs_lookup(const char *path, struct fut_vnode **out);
            fut_vfs_lookup(cwd, &vnode);
        } else {
            if (local_dirfd < 0 || local_dirfd >= task->max_fds)
                return -EBADF;
            struct fut_file *epfile = vfs_get_file_from_task(task, local_dirfd);
            if (!epfile || !epfile->vnode)
                return -EBADF;
            vnode = epfile->vnode;
        }

        if (!vnode)
            return -EBADF;

        /* F_OK: vnode exists */
        if (local_mode == F_OK)
            return 0;

        uint32_t check_uid_ns = (local_flags & AT_EACCESS) ? task->uid  : task->ruid;
        uint32_t check_gid_ns = (local_flags & AT_EACCESS) ? task->gid  : task->rgid;
        uint32_t check_uid = userns_ns_to_host_uid(task->user_ns, check_uid_ns);
        uint32_t check_gid = userns_ns_to_host_gid(task->user_ns, check_gid_ns);
        uint32_t file_mode = vnode->mode & 0777;
        uint32_t perm_bits;

        if (check_uid == 0) {
            /* Root override: full DAC bypass except X_OK on a regular file
             * still needs at least one execute bit (Linux CAP_DAC_OVERRIDE).
             * Directories always grant search to root regardless of mode. */
            if ((local_mode & X_OK) && vnode->type == VN_REG &&
                !(file_mode & 0111))
                return -EACCES;
            return 0;
        } else if (check_uid == vnode->uid) {
            perm_bits = (file_mode >> 6) & 7;
        } else if (check_gid == vnode->gid) {
            perm_bits = (file_mode >> 3) & 7;
        } else {
            int in_group = 0;
            for (int gi = 0; gi < task->ngroups; gi++) {
                if (userns_ns_to_host_gid(task->user_ns, task->groups[gi]) == vnode->gid) { in_group = 1; break; }
            }
            perm_bits = in_group ? ((file_mode >> 3) & 7) : (file_mode & 7);
        }

        if ((local_mode & R_OK) && !(perm_bits & 4)) return -EACCES;
        if ((local_mode & W_OK) && !(perm_bits & 2)) return -EACCES;
        if ((local_mode & X_OK) && !(perm_bits & 1)) return -EACCES;
        return 0;
    }

    /* Categorize pathname */
    const char *path_type;
    if (path_buf[0] == '/') {
        path_type = "absolute";
    } else if (local_dirfd == AT_FDCWD) {
        path_type = "relative to CWD";
    } else {
        path_type = "relative to dirfd";
    }

    /* Categorize mode */
    const char *mode_desc;
    if (local_mode == F_OK) {
        mode_desc = "F_OK (file exists)";
    } else if (local_mode == R_OK) {
        mode_desc = "R_OK (read permission)";
    } else if (local_mode == W_OK) {
        mode_desc = "W_OK (write permission)";
    } else if (local_mode == X_OK) {
        mode_desc = "X_OK (execute permission)";
    } else if (local_mode == (R_OK | W_OK)) {
        mode_desc = "R_OK|W_OK (read+write)";
    } else if (local_mode == (R_OK | X_OK)) {
        mode_desc = "R_OK|X_OK (read+execute)";
    } else if (local_mode == (W_OK | X_OK)) {
        mode_desc = "W_OK|X_OK (write+execute)";
    } else if (local_mode == (R_OK | W_OK | X_OK)) {
        mode_desc = "R_OK|W_OK|X_OK (all permissions)";
    } else {
        mode_desc = "custom combination";
    }

    /* Categorize flags */
    const char *flags_desc;
    if (local_flags == 0) {
        flags_desc = "none (real IDs, follow symlinks)";
    } else if (local_flags == AT_EACCESS) {
        flags_desc = "AT_EACCESS (effective IDs)";
    } else if (local_flags == AT_SYMLINK_NOFOLLOW) {
        flags_desc = "AT_SYMLINK_NOFOLLOW (check symlink itself)";
    } else if (local_flags == (AT_EACCESS | AT_SYMLINK_NOFOLLOW)) {
        flags_desc = "AT_EACCESS|AT_SYMLINK_NOFOLLOW";
    } else {
        flags_desc = "unknown flags";
    }

    /* Calculate path length */
    size_t path_len = strlen(path_buf);

    /* Phase 2: Implement proper directory FD resolution via VFS and flags */

    /* Resolve the full path based on dirfd */
    char resolved_path[256];

    /* If pathname is absolute, use it directly */
    if (path_buf[0] == '/') {
        /* Copy absolute path */
        size_t len = strnlen(path_buf, sizeof(resolved_path) - 1);
        memcpy(resolved_path, path_buf, len);
        resolved_path[len] = '\0';
    }
    /* If dirfd is AT_FDCWD, use current working directory */
    else if (local_dirfd == AT_FDCWD) {
        /* For now, use relative path as-is (CWD resolution happens in VFS) */
        size_t len = strnlen(path_buf, sizeof(resolved_path) - 1);
        memcpy(resolved_path, path_buf, len);
        resolved_path[len] = '\0';
    }
    /* Dirfd is a real FD - resolve via VFS */
    else {
        /* Validate dirfd bounds before accessing FD table */
        if (local_dirfd < 0) {
            fut_printf("[FACCESSAT] faccessat(dirfd=%d) -> EBADF (invalid negative dirfd)\n",
                       local_dirfd);
            return -EBADF;
        }

        if (local_dirfd >= task->max_fds) {
            fut_printf("[FACCESSAT] faccessat(dirfd=%d, max_fds=%d) -> EBADF "
                       "(dirfd exceeds max_fds, FD bounds validation)\n",
                       local_dirfd, task->max_fds);
            return -EBADF;
        }

        /* Get file structure from dirfd */
        struct fut_file *dir_file = vfs_get_file_from_task(task, local_dirfd);

        if (!dir_file) {
            fut_printf("[FACCESSAT] faccessat(dirfd=%d) -> EBADF (invalid dirfd)\n",
                       local_dirfd);
            return -EBADF;
        }

        /* Verify dirfd refers to a directory */
        if (!dir_file->vnode) {
            fut_printf("[FACCESSAT] faccessat(dirfd=%d) -> EBADF (dirfd has no vnode)\n",
                       local_dirfd);
            return -EBADF;
        }

        /* Check if vnode is a directory */
        if (dir_file->vnode->type != VN_DIR) {
            fut_printf("[FACCESSAT] faccessat(dirfd=%d) -> ENOTDIR (dirfd not a directory)\n",
                       local_dirfd);
            return -ENOTDIR;
        }

        /* Construct path relative to directory using stored file->path */
        if (dir_file->path) {
            size_t dir_len = strlen(dir_file->path);
            size_t rel_len = strnlen(path_buf, sizeof(resolved_path) - 1);
            bool has_trail = (dir_len > 0 && dir_file->path[dir_len - 1] == '/');
            if (dir_len + (has_trail ? 0 : 1) + rel_len >= sizeof(resolved_path)) {
                return -ENAMETOOLONG;
            }
            size_t pos = 0;
            for (size_t j = 0; j < dir_len; j++) resolved_path[pos++] = dir_file->path[j];
            if (!has_trail) resolved_path[pos++] = '/';
            for (size_t j = 0; j <= rel_len; j++) resolved_path[pos++] = path_buf[j];
        } else {
            /* No stored path; fall through with relative path (best-effort) */
            size_t len = strnlen(path_buf, sizeof(resolved_path) - 1);
            memcpy(resolved_path, path_buf, len);
            resolved_path[len] = '\0';
        }
    }

    /* Determine which IDs to use for access check */
    uint32_t check_uid;
    uint32_t check_gid;

    if (local_flags & AT_EACCESS) {
        /* Use effective IDs */
        check_uid = task->uid;   /* Effective UID */
        check_gid = task->gid;   /* Effective GID */
    } else {
        /* Use real IDs (standard behavior) */
        check_uid = task->ruid;  /* Real UID */
        check_gid = task->rgid;  /* Real GID */
    }

    /* Perform the access check */
    int ret;

    if (local_flags & AT_SYMLINK_NOFOLLOW) {
        /* Phase 3: AT_SYMLINK_NOFOLLOW - check symlink itself, don't follow it
         *
         * When this flag is set, we need to check access permissions on the
         * symbolic link itself rather than the file it points to. This is
         * useful for backup utilities and file managers that need to inspect
         * symlinks without resolving them.
         *
         * Implementation: Use fut_vfs_lstat to get file info without following
         * symlinks, then check permissions based on the returned stat info.
         */
        extern int fut_vfs_lstat(const char *path, struct fut_stat *stat);
        struct fut_stat st;

        ret = fut_vfs_lstat(resolved_path, &st);
        if (ret < 0) {
            /* lstat failed - propagate error */
            goto handle_error;
        }

        /* F_OK: File existence check passed (lstat succeeded) */
        if (local_mode == F_OK) {
            ret = 0;
            goto success;
        }

        /* Check permissions using the appropriate uid/gid
         * Permission bits in st_mode are:
         *   Owner: bits 8-6 (0700)
         *   Group: bits 5-3 (0070)
         *   Other: bits 2-0 (0007)
         */
        uint32_t file_mode = st.st_mode & 0777;
        uint32_t perm_bits;

        if (check_uid == 0) {
            /* Root override: X_OK on a regular file still requires at least
             * one execute bit. Directories grant search unconditionally. */
            if ((local_mode & X_OK) &&
                ((st.st_mode & 0170000) == 0100000 /* S_IFREG */) &&
                !(file_mode & 0111)) {
                ret = -EACCES;
                goto handle_error;
            }
            ret = 0;
            goto success;
        } else if (check_uid == st.st_uid) {
            /* Owner permissions (bits 8-6) */
            perm_bits = (file_mode >> 6) & 7;
        } else if (check_gid == st.st_gid) {
            /* Primary group permissions (bits 5-3) */
            perm_bits = (file_mode >> 3) & 7;
        } else {
            /* Check supplementary groups */
            int in_group = 0;
            if (task) {
                for (int i = 0; i < task->ngroups; i++) {
                    if (task->groups[i] == st.st_gid) {
                        in_group = 1;
                        break;
                    }
                }
            }
            if (in_group) {
                perm_bits = (file_mode >> 3) & 7;
            } else {
                /* Other permissions (bits 2-0) */
                perm_bits = file_mode & 7;
            }
        }

        /* Check requested permissions against available permissions */
        if ((local_mode & R_OK) && !(perm_bits & 4)) {
            ret = -EACCES;
            goto handle_error;
        }
        if ((local_mode & W_OK) && !(perm_bits & 2)) {
            ret = -EACCES;
            goto handle_error;
        }
        if ((local_mode & X_OK) && !(perm_bits & 1)) {
            ret = -EACCES;
            goto handle_error;
        }

        ret = 0;
        goto success;
    } else if (local_flags & AT_EACCESS) {
        /* AT_EACCESS without AT_SYMLINK_NOFOLLOW: follow symlinks but
         * use effective IDs for the check.  Cannot delegate to sys_access()
         * because it always uses real IDs. */
        extern int fut_vfs_stat(const char *path, struct fut_stat *stat);
        struct fut_stat st;

        ret = fut_vfs_stat(resolved_path, &st);
        if (ret < 0) {
            goto handle_error;
        }

        if (local_mode == F_OK) {
            ret = 0;
            goto success;
        }

        uint32_t file_mode = st.st_mode & 0777;
        uint32_t perm_bits;

        if (check_uid == 0) {
            /* Root override: see notes above — directories always pass X_OK. */
            if ((local_mode & X_OK) &&
                ((st.st_mode & 0170000) == 0100000 /* S_IFREG */) &&
                !(file_mode & 0111)) {
                ret = -EACCES;
                goto handle_error;
            }
            ret = 0;
            goto success;
        } else if (check_uid == st.st_uid) {
            perm_bits = (file_mode >> 6) & 7;
        } else if (check_gid == st.st_gid) {
            perm_bits = (file_mode >> 3) & 7;
        } else {
            int in_group = 0;
            if (task) {
                for (int i = 0; i < task->ngroups; i++) {
                    if (task->groups[i] == st.st_gid) {
                        in_group = 1;
                        break;
                    }
                }
            }
            perm_bits = in_group ? ((file_mode >> 3) & 7) : (file_mode & 7);
        }

        if ((local_mode & R_OK) && !(perm_bits & 4)) { ret = -EACCES; goto handle_error; }
        if ((local_mode & W_OK) && !(perm_bits & 2)) { ret = -EACCES; goto handle_error; }
        if ((local_mode & X_OK) && !(perm_bits & 1)) { ret = -EACCES; goto handle_error; }

        ret = 0;
        goto success;
    } else {
        /* Default behavior: follow symlinks, use real IDs (delegate to sys_access) */
        ret = (int)sys_access(resolved_path, local_mode);
    }

    /* Log AT_EACCESS if used */
    if ((local_flags & AT_EACCESS) && ret >= 0) {
        fut_printf("[FACCESSAT] Note: AT_EACCESS flag - using effective UID=%u GID=%u instead of real UID=%u GID=%u (Phase 3)\n",
                   check_uid, check_gid, task->ruid, task->rgid);
    }

handle_error:
    /* Handle errors */
    if (ret < 0) {
        const char *error_desc;
        switch (ret) {
            case -EACCES:
                error_desc = "permission denied";
                break;
            case -ENOENT:
                error_desc = "file not found";
                break;
            case -ENOTDIR:
                error_desc = "path component not a directory";
                break;
            default:
                error_desc = "access check failed";
                break;
        }

        fut_printf("[FACCESSAT] faccessat(dirfd=%d, pathname='%s' [%s, len=%lu], mode=%s, flags=%s) -> %d (%s)\n",
                   local_dirfd, path_buf, path_type, (unsigned long)path_len, mode_desc, flags_desc, ret, error_desc);
        return ret;
    }

success:
    /* Success */
    fut_printf("[FACCESSAT] faccessat(dirfd=%d, pathname='%s' [%s, len=%lu], mode=%s, flags=%s) -> 0 "
               "(accessible, Phase 3: AT_SYMLINK_NOFOLLOW + AT_EACCESS)\n",
               local_dirfd, path_buf, path_type, (unsigned long)path_len, mode_desc, flags_desc);

    return 0;
}
