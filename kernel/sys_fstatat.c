/* kernel/sys_fstatat.c - Directory-based file status syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements the fstatat() syscall (also called newfstatat) for retrieving
 * file metadata relative to a directory FD. Essential for thread-safe file
 * inspection and avoiding race conditions.
 *
 * Phase 1 (Completed): Basic fstatat with dirfd and AT_SYMLINK_NOFOLLOW support
 * Phase 2 (Completed): Directory FD resolution via VFS with proper validation
 * Phase 3 (Completed): AT_EMPTY_PATH support for fstat via dirfd
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <kernel/fut_vfs.h>
#include <stdint.h>
#include <stdbool.h>

#include <kernel/kprintf.h>
#include <kernel/uaccess.h>
#include <string.h>
#include <fcntl.h>

#include <platform/platform.h>

static inline int fstatat_copy_from_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)src >= KERNEL_VIRTUAL_BASE) { __builtin_memcpy(dst, src, n); return 0; }
#endif
    return fut_copy_from_user(dst, src, n);
}
static inline int fstatat_access_ok(const void *ptr, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)ptr >= KERNEL_VIRTUAL_BASE) return 0;
#endif
    return fut_access_ok(ptr, n, 1);
}

/* AT_* constants provided by fcntl.h */

/**
 * fstatat() - Get file status relative to directory FD
 *
 * Like stat(), but pathname is interpreted relative to dirfd instead of
 * the current working directory. This enables race-free file inspection
 * when working with directory hierarchies in multithreaded applications.
 *
 * Also known as newfstatat() on some systems.
 *
 * @param dirfd    Directory file descriptor (or AT_FDCWD for CWD)
 * @param pathname Path relative to dirfd (or absolute path)
 * @param statbuf  Pointer to userspace stat buffer to fill
 * @param flags    AT_SYMLINK_NOFOLLOW to not follow symlinks, or 0
 *
 * Returns:
 *   - 0 on success
 *   - -EBADF if dirfd is invalid
 *   - -EFAULT if pathname or statbuf is inaccessible
 *   - -EINVAL if pathname is empty, statbuf is NULL, or flags invalid
 *   - -ENOENT if file does not exist
 *   - -ENOTDIR if path component is not a directory
 *   - -ENAMETOOLONG if pathname too long
 *
 * Behavior:
 *   - If pathname is absolute, dirfd is ignored
 *   - If pathname is relative and dirfd is AT_FDCWD, uses current directory
 *   - If pathname is relative and dirfd is FD, uses that directory
 *   - AT_SYMLINK_NOFOLLOW: Don't follow final symlink (like lstat)
 *   - AT_EMPTY_PATH: If pathname is empty, stat the FD itself
 *   - Prevents TOCTOU races vs separate getcwd() + stat()
 *
 * Common usage patterns:
 *
 * Thread-safe file inspection:
 *   int dirfd = open("/some/dir", O_RDONLY | O_DIRECTORY);
 *   struct fut_stat st;
 *   fstatat(dirfd, "file.txt", &st, 0);
 *   printf("Size: %llu bytes\n", st.st_size);
 *   close(dirfd);
 *
 * Check if symlink (don't follow):
 *   struct fut_stat st;
 *   fstatat(dirfd, "link", &st, AT_SYMLINK_NOFOLLOW);
 *   if (S_ISLNK(st.st_mode)) {
 *       printf("Is a symbolic link\n");
 *   }
 *
 * Use current directory:
 *   struct fut_stat st;
 *   fstatat(AT_FDCWD, "file.txt", &st, 0);
 *   // Same as stat("file.txt", &st)
 *
 * Absolute path (dirfd ignored):
 *   struct fut_stat st;
 *   fstatat(dirfd, "/tmp/file", &st, 0);
 *   // dirfd not used
 *
 * Stat the directory itself:
 *   struct fut_stat st;
 *   fstatat(dirfd, "", &st, AT_EMPTY_PATH);
 *   // Stats the directory that dirfd refers to
 *
 * Race-free file verification:
 *   int dirfd = open("/etc", O_RDONLY | O_DIRECTORY);
 *   // Directory can't be renamed/moved while we have it open
 *   struct fut_stat st;
 *   fstatat(dirfd, "config", &st, 0);
 *   if (st.st_size > 0) {
 *       // Safe to read config
 *   }
 *   close(dirfd);
 *
 * Advantages over stat():
 * 1. Thread-safe: Works correctly with multiple threads
 * 2. Race-free: Directory context locked by FD
 * 3. Flexible: Can use CWD or specific directory
 * 4. Symlink control: Can choose to follow or not follow symlinks
 *
 * Phase 1 (Completed): Basic implementation with dirfd and AT_SYMLINK_NOFOLLOW support
 */
long sys_fstatat(int dirfd, const char *pathname, void *statbuf, int flags) {
    /* ARM64 FIX: Copy parameters to local variables */
    int local_dirfd = dirfd;
    const char *local_pathname = pathname;
    void *local_statbuf = statbuf;
    int local_flags = flags;

    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_printf("[FSTATAT] fstatat(dirfd=%d, flags=0x%x) -> ESRCH (no current task)\n",
                   local_dirfd, local_flags);
        return -ESRCH;
    }

    /* Phase 1: Validate flags - only AT_SYMLINK_NOFOLLOW and AT_EMPTY_PATH are valid */
    const int VALID_FLAGS = AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH;
    if (local_flags & ~VALID_FLAGS) {
        fut_printf("[FSTATAT] fstatat(dirfd=%d, flags=0x%x) -> EINVAL (invalid flags)\n",
                   local_dirfd, local_flags);
        return -EINVAL;
    }

    /* NULL statbuf is a pointer fault (EFAULT) per Linux fstatat(2) — the
     * kernel must write stat results through this pointer. */
    if (!local_statbuf) {
        fut_printf("[FSTATAT] fstatat(dirfd=%d, statbuf=NULL) -> EFAULT\n",
                   local_dirfd);
        return -EFAULT;
    }

    /* Validate statbuf write permission early (kernel writes stat structure)
     * VULNERABILITY: Invalid Output Buffer Pointer
     * ATTACK: Attacker provides read-only or unmapped statbuf buffer
     * IMPACT: Kernel page fault when writing stat structure
     * DEFENSE: Check write permission before path resolution and VFS operations */
    if (fstatat_access_ok(local_statbuf, sizeof(struct fut_stat)) != 0) {
        fut_printf("[FSTATAT] fstatat(dirfd=%d, statbuf=%p) -> EFAULT (statbuf not writable for %zu bytes)\n",
                   local_dirfd, local_statbuf, sizeof(struct fut_stat));
        return -EFAULT;
    }

    /* NULL pathname is a pointer fault (EFAULT) per Linux fstatat(2). */
    if (!local_pathname) {
        fut_printf("[FSTATAT] fstatat(dirfd=%d, pathname=NULL) -> EFAULT\n",
                   local_dirfd);
        return -EFAULT;
    }

    /* Copy pathname from userspace */
    char path_buf[FUT_VFS_PATH_BUFFER_SIZE];
    if (fstatat_copy_from_user(path_buf, local_pathname, sizeof(path_buf)) != 0) {
        fut_printf("[FSTATAT] fstatat(dirfd=%d) -> EFAULT (copy_from_user failed)\n",
                   local_dirfd);
        return -EFAULT;
    }
    /* Verify path was not truncated */
    if (memchr(path_buf, '\0', sizeof(path_buf)) == NULL) {
        fut_printf("[FSTATAT] fstatat(dirfd=%d, path exceeds %zu bytes) -> ENAMETOOLONG\n",
                   local_dirfd, sizeof(path_buf) - 1);
        return -ENAMETOOLONG;
    }

    /* Check for empty pathname with AT_EMPTY_PATH */
    if (path_buf[0] == '\0') {
        if (local_flags & AT_EMPTY_PATH) {
            /* Phase 3: Implement fstat via dirfd
             * When pathname is empty and AT_EMPTY_PATH is set, stat the FD itself */

            if (local_dirfd == AT_FDCWD) {
                /* Stat the current working directory */
                fut_printf("[FSTATAT] fstatat(dirfd=AT_FDCWD, pathname=\"\" [empty], flags=AT_EMPTY_PATH) -> EINVAL (cannot fstat CWD)\n",
                           local_dirfd);
                return -EINVAL;
            }

            /* Validate dirfd bounds before accessing FD table */
            if (local_dirfd < 0) {
                fut_printf("[FSTATAT] fstatat(dirfd=%d, pathname=\"\" [empty], flags=AT_EMPTY_PATH) -> EBADF "
                           "(invalid negative dirfd)\n", local_dirfd);
                return -EBADF;
            }

            if (local_dirfd >= task->max_fds) {
                fut_printf("[FSTATAT] fstatat(dirfd=%d, max_fds=%d, pathname=\"\" [empty], flags=AT_EMPTY_PATH) -> EBADF "
                           "(dirfd exceeds max_fds, FD bounds validation)\n",
                           local_dirfd, task->max_fds);
                return -EBADF;
            }

            /* Get file structure from dirfd */
            struct fut_file *dir_file = vfs_get_file_from_task(task, local_dirfd);

            if (!dir_file) {
                fut_printf("[FSTATAT] fstatat(dirfd=%d, pathname=\"\" [empty], flags=AT_EMPTY_PATH) -> EBADF (dirfd not open)\n",
                           local_dirfd);
                return -EBADF;
            }

            /* Delegate to sys_fstat() — handles vnode-less fds (pipes, sockets,
             * eventfd, signalfd, timerfd) as well as regular vnode-backed fds.
             * This is correct Linux semantics: AT_EMPTY_PATH is equivalent to fstat(). */
            extern long sys_fstat(int fd, struct fut_stat *statbuf);
            int ret = (int)sys_fstat(local_dirfd, local_statbuf);
            fut_printf("[FSTATAT] fstatat(dirfd=%d, pathname=\"\" [empty], flags=AT_EMPTY_PATH) -> %d (delegated to fstat)\n",
                       local_dirfd, ret);
            return ret;
        } else {
            fut_printf("[FSTATAT] fstatat(dirfd=%d, pathname=\"\" [empty]) -> EINVAL (empty pathname without AT_EMPTY_PATH)\n",
                       local_dirfd);
            return -EINVAL;
        }
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

    /* Categorize flags */
    const char *flags_desc;
    if (local_flags == 0) {
        flags_desc = "none (follow symlinks)";
    } else if (local_flags == AT_SYMLINK_NOFOLLOW) {
        flags_desc = "AT_SYMLINK_NOFOLLOW (lstat behavior)";
    } else if (local_flags == AT_EMPTY_PATH) {
        flags_desc = "AT_EMPTY_PATH (fstat via dirfd)";
    } else {
        flags_desc = "multiple flags";
    }

    /* Calculate path length */
    size_t path_len = strlen(path_buf);

    /* Phase 2: Implement proper directory FD resolution via VFS */

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
            fut_printf("[FSTATAT] fstatat(dirfd=%d) -> EBADF (invalid negative dirfd)\n",
                       local_dirfd);
            return -EBADF;
        }

        if (local_dirfd >= task->max_fds) {
            fut_printf("[FSTATAT] fstatat(dirfd=%d, max_fds=%d) -> EBADF "
                       "(dirfd exceeds max_fds, FD bounds validation)\n",
                       local_dirfd, task->max_fds);
            return -EBADF;
        }

        /* Get file structure from dirfd */
        struct fut_file *dir_file = vfs_get_file_from_task(task, local_dirfd);

        if (!dir_file) {
            fut_printf("[FSTATAT] fstatat(dirfd=%d) -> EBADF (dirfd not open)\n",
                       local_dirfd);
            return -EBADF;
        }

        /* Verify dirfd refers to a directory */
        if (!dir_file->vnode) {
            fut_printf("[FSTATAT] fstatat(dirfd=%d) -> EBADF (dirfd has no vnode)\n",
                       local_dirfd);
            return -EBADF;
        }

        /* Check if vnode is a directory */
        if (dir_file->vnode->type != VN_DIR) {
            fut_printf("[FSTATAT] fstatat(dirfd=%d) -> ENOTDIR (dirfd not a directory)\n",
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

    /* Perform the stat operation via VFS */
    int ret;
    /* Stage stat through a kernel-local struct, then copy_to_user.
     * The previous code passed local_statbuf (a user pointer) straight
     * into fut_vfs_stat/lstat, which write through it as if it were a
     * kernel pointer (stat->st_ino = ..., etc.). A bad user pointer
     * faulted the kernel; a kernel-pointer caller turned the syscall
     * into a write-anywhere primitive across the stat fields. */
    struct fut_stat kstat = {0};
    if (local_flags & AT_SYMLINK_NOFOLLOW) {
        /* lstat behavior - don't follow symlinks */
        ret = fut_vfs_lstat(resolved_path, &kstat);
    } else {
        /* stat behavior - follow symlinks */
        ret = fut_vfs_stat(resolved_path, &kstat);
    }
    if (ret == 0) {
#ifdef KERNEL_VIRTUAL_BASE
        if ((uintptr_t)local_statbuf >= KERNEL_VIRTUAL_BASE) {
            __builtin_memcpy(local_statbuf, &kstat, sizeof(kstat));
        } else
#endif
        if (fut_copy_to_user(local_statbuf, &kstat, sizeof(kstat)) != 0)
            return -EFAULT;
    }

    /* Handle errors */
    if (ret < 0) {
        const char *error_desc;
        switch (ret) {
            case -ENOENT:
                error_desc = "file not found";
                break;
            case -ENOTDIR:
                error_desc = "path component not a directory";
                break;
            case -EACCES:
                error_desc = "permission denied";
                break;
            default:
                error_desc = "VFS stat failed";
                break;
        }

        fut_printf("[FSTATAT] fstatat(dirfd=%d, pathname='%s' [%s, len=%lu], flags=%s) -> %d (%s)\n",
                   local_dirfd, path_buf, path_type, (unsigned long)path_len, flags_desc, ret, error_desc);
        return ret;
    }

    return 0;
}
