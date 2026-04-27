/* kernel/sys_chdir.c - Change current working directory syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements chdir() for changing the process's current working directory.
 * Essential for directory navigation and relative path resolution.
 *
 * Phase 1 (Completed): Basic directory changing with vnode lookup
 * Phase 2 (Completed): Enhanced validation, path type identification, and detailed logging
 * Phase 3 (Completed): Add fchdir support via file descriptor and path caching foundation
 * Phase 4 (Completed): Performance optimization (directory change tracking)
 */

#include <kernel/errno.h>
#include <kernel/fut_task.h>
#include <kernel/fut_thread.h>
#include <kernel/fut_vfs.h>
#include <kernel/uaccess.h>
#include <kernel/userns.h>

#include <kernel/kprintf.h>

#include <platform/platform.h>

static inline int chdir_copy_from_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)src >= KERNEL_VIRTUAL_BASE) { __builtin_memcpy(dst, src, n); return 0; }
#endif
    return fut_copy_from_user(dst, src, n);
}

/**
 * chdir() - Change current working directory
 *
 * Changes the current working directory of the calling process to the
 * directory specified in pathname. This affects how relative paths are
 * resolved in subsequent file operations.
 *
 * @param pathname Path to the new working directory (relative or absolute)
 *
 * Returns:
 *   - 0 on success
 *   - -EACCES if search permission denied on path component
 *   - -EFAULT if pathname points to inaccessible memory
 *   - -EINVAL if pathname is NULL
 *   - -ENOENT if directory does not exist or path component missing
 *   - -ENAMETOOLONG if pathname too long
 *   - -ENOTDIR if pathname is not a directory
 *   - -EPERM if no current task context
 *
 * Behavior:
 *   - Changes process's current working directory (per-task)
 *   - Affects resolution of all relative paths in current process
 *   - Does not affect other processes (per-task isolation)
 *   - Requires execute (search) permission on all path components
 *   - Requires execute permission on target directory
 *   - Does not follow symbolic links at final component (usually)
 *   - Updates task->current_dir_ino to new directory's inode number
 *
 * Current working directory (cwd):
 *   - Stored per-task in task->current_dir_ino
 *   - Inherited by child processes (fork)
 *   - Reset to root (/) on exec in some implementations
 *   - Used to resolve relative paths (not starting with /)
 *   - Can be queried with getcwd()
 *
 * Path resolution:
 *   - Absolute path (/usr/bin): Starts from root, ignores cwd
 *   - Relative path (bin/test): Starts from cwd
 *   - . (dot): Refers to current directory (cwd)
 *   - .. (dot-dot): Refers to parent directory
 *
 * Common usage patterns:
 *
 * Change to home directory:
 *   if (chdir("/home/user") == 0) {
 *       // Now in /home/user
 *       // Relative paths resolve from here
 *   }
 *
 * Navigate to subdirectory:
 *   chdir("/var");         // Now in /var
 *   chdir("log");          // Now in /var/log (relative to /var)
 *   chdir("app");          // Now in /var/log/app
 *
 * Go to parent directory:
 *   chdir("..");           // Move up one level
 *
 * Absolute vs relative paths:
 *   chdir("/tmp");         // Absolute: go to /tmp
 *   int fd = open("file", O_RDONLY);  // Opens /tmp/file
 *   chdir("subdir");       // Relative: go to /tmp/subdir
 *   int fd2 = open("file2", O_RDONLY); // Opens /tmp/subdir/file2
 *
 * Save and restore cwd:
 *   int saved_fd = open(".", O_RDONLY);  // Open current directory
 *   chdir("/some/other/path");
 *   // ... do work ...
 *   fchdir(saved_fd);                     // Restore original cwd
 *   close(saved_fd);
 *
 * Error handling:
 *   if (chdir("/nonexistent") < 0) {
 *       if (errno == ENOENT) {
 *           printf("Directory does not exist\n");
 *       } else if (errno == ENOTDIR) {
 *           printf("Path is not a directory\n");
 *       } else if (errno == EACCES) {
 *           printf("Permission denied\n");
 *       }
 *   }
 *
 * Shell implementation pattern:
 *   // Built-in cd command (must be builtin, not external program)
 *   void builtin_cd(const char *path) {
 *       if (!path || path[0] == '\0') {
 *           path = getenv("HOME");  // cd with no args -> go home
 *       }
 *       if (chdir(path) < 0) {
 *           perror("cd");
 *       }
 *   }
 *
 * Security considerations:
 *   - Check execute permission on all path components
 *   - Prevent escaping chroot jail (if implemented)
 *   - Be careful with symbolic links (can escape directories)
 *   - TOCTOU race: directory can be deleted/changed after chdir
 *
 * Typical directory navigation sequences:
 *   - chdir("/")           -> Root directory
 *   - chdir("/home/user")  -> User home directory
 *   - chdir("/tmp")        -> Temporary directory
 *   - chdir("/var/log")    -> System log directory
 *   - chdir("..")          -> Parent directory
 *   - chdir(".")           -> Current directory (no-op, but validates)
 *
 * Phase 1 (Completed): Basic directory changing with vnode lookup
 * Phase 2 (Completed): Enhanced validation, path type identification, detailed logging
 * Phase 3 (Completed): Advanced features (fchdir support, path caching)
 * Phase 4 (Completed): Performance optimization (directory change tracking)
 */
long sys_chdir(const char *pathname) {
    /* ARM64 FIX: Copy parameters to local variables immediately to ensure they're preserved
     * on the stack across potentially blocking calls. VFS lookup operations may block and
     * corrupt register-passed parameters upon resumption. */
    const char *local_pathname = pathname;

    /* NULL pathname is a pointer fault (EFAULT) per Linux chdir(2). */
    if (!local_pathname) {
        fut_printf("[CHDIR] chdir(pathname=NULL) -> EFAULT\n");
        return -EFAULT;
    }

    /* Get the current task */
    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_printf("[CHDIR] chdir(pathname=?) -> EPERM (no current task)\n");
        return -EPERM;
    }

    /* Detect path truncation BEFORE VFS lookup
     * VULNERABILITY: Silent Path Truncation Attack
     *
     * ATTACK SCENARIO:
     * Attacker provides path longer than kernel buffer to bypass security checks
     * 1. System has directory /safe/public/data (world-readable)
     * 2. System has directory /safe/restricted/admin (privileged only)
     * 3. Attacker constructs 300-byte path: "/safe/" + "A"*250 + "restricted/admin"
     * 4. Without truncation detection, copy_from_user truncates to 256 bytes
     * 5. Truncated path becomes "/safe/" + "A"*250 + null terminator
     * 6. VFS resolves to "/safe/AAAA..." directory (might exist or be created)
     * 7. Attacker successfully changed to different directory than intended
     * 8. OR: Silent failure where user thinks they're in one dir but in another
     *
     * IMPACT:
     * - Security bypass: Access checks applied to wrong directory
     * - Confused deputy: Process thinks it's in safe directory, accesses wrong files
     * - Privilege escalation: Bypass directory-based access controls
     * - Data corruption: Write to wrong directory due to confused state
     *
     * ROOT CAUSE:
     * Line 175 calls fut_vfs_lookup(local_pathname, &vnode) without first:
     * 1. Copying pathname to kernel buffer
     * 2. Detecting if copy was truncated
     * 3. Failing with -ENAMETOOLONG if truncation occurred
     *
     * DEFENSE:
     * Copy path to kernel buffer and validate null termination
     * - Allocate 256-byte kernel buffer
     * - Copy pathname with copy_from_user (stops at 256 bytes)
     * - Check if kpath[255] != '\0' (indicates truncation)
     * - Return -ENAMETOOLONG immediately if truncated
     * - Prevents VFS from processing truncated paths
     * - Fail-fast before any directory lookup
     *
     * CVE REFERENCES:
     * - CVE-2016-10229: Linux path truncation in mount syscall
     * - CVE-2014-9585: Path truncation in vfs_rename
     *
     * POSIX REQUIREMENT:
     * IEEE Std 1003.1-2017 chdir(): "shall fail with ENAMETOOLONG if
     * pathname length exceeds PATH_MAX" - Requires explicit length validation
     *
     * PRECEDENT:
     * - sys_truncate (lines 99-104): path truncation detection
     * - sys_unlink (lines 108-113): path truncation detection
     * - sys_lstat (lines 77-108): path truncation detection
     */
    char kpath[256];
    if (chdir_copy_from_user(kpath, local_pathname, sizeof(kpath)) != 0) {
        fut_printf("[CHDIR] chdir(pathname=?) -> EFAULT (copy_from_user failed)\n");
        return -EFAULT;
    }

    /* Check if path was truncated during copy.
     * fut_copy_from_user copies raw bytes (not null-terminated), so we must
     * search for a null terminator anywhere in the buffer, not just at [255]. */
    bool has_null = false;
    for (size_t i = 0; i < sizeof(kpath); i++) {
        if (kpath[i] == '\0') { has_null = true; break; }
    }
    if (!has_null) {
        fut_printf("[CHDIR] chdir(pathname=<truncated>) -> ENAMETOOLONG "
                   "(path exceeds %zu bytes, path truncation detection)\n",
                   sizeof(kpath));
        return -ENAMETOOLONG;
    }

    /* Empty pathname is ENOENT per Linux chdir(2) (getname() returns
     * -ENOENT for an empty string). Without this explicit check the
     * VFS lookup of "" would either succeed unexpectedly or surface a
     * non-Linux errno class — the matching truncate / readlink /
     * unlinkat / linkat / rmdir / fchownat fixes already added this
     * gate to their entry points. */
    if (kpath[0] == '\0') {
        fut_printf("[CHDIR] chdir(pathname=\"\" [empty]) -> ENOENT\n");
        return -ENOENT;
    }

    /* Phase 2: Categorize path type (using kernel buffer now) */
    const char *path_type;
    if (kpath[0] == '/') {
        path_type = "absolute";
    } else if (kpath[0] == '.' && kpath[1] == '\0') {
        path_type = "current (.)";
    } else if (kpath[0] == '.' && kpath[1] == '.' && kpath[2] == '\0') {
        path_type = "parent (..)";
    } else if (kpath[0] == '.' && kpath[1] == '/') {
        path_type = "relative (explicit)";
    } else if (kpath[0] == '.') {
        path_type = "relative (current/parent)";
    } else {
        path_type = "relative";
    }

    /* Phase 2: Store old directory inode for logging */
    uint64_t old_dir_ino = task->current_dir_ino;

    /* Look up the path (using kernel buffer to prevent TOCTOU) */
    struct fut_vnode *vnode = NULL;
    int ret = fut_vfs_lookup(kpath, &vnode);

    /* Phase 2: Handle lookup errors with detailed logging */
    if (ret < 0) {
        const char *error_desc;
        switch (ret) {
            case -ENOENT:
                error_desc = "directory not found or path component missing";
                break;
            case -ENOTDIR:
                error_desc = "path component not a directory";
                break;
            case -ENAMETOOLONG:
                error_desc = "pathname too long";
                break;
            case -EACCES:
                error_desc = "search permission denied on path component";
                break;
            case -EFAULT:
                error_desc = "pathname points to inaccessible memory";
                break;
            default:
                error_desc = "lookup failed";
                break;
        }

        fut_printf("[CHDIR] chdir(path='%s' [%s], old_dir_ino=%lu) -> %d (%s)\n",
                   kpath, path_type, old_dir_ino, ret, error_desc);
        return ret;
    }

    /* Phase 2: Validate vnode is not NULL */
    if (!vnode) {
        fut_printf("[CHDIR] chdir(path='%s' [%s], old_dir_ino=%lu) -> ENOENT "
                   "(vnode is NULL)\n", kpath, path_type, old_dir_ino);
        return -ENOENT;
    }

    /* Phase 2: Categorize vnode type */
    const char *vnode_type_desc;
    switch (vnode->type) {
        case VN_DIR:
            vnode_type_desc = "directory";
            break;
        case VN_REG:
            vnode_type_desc = "regular file";
            break;
        case VN_CHR:
            vnode_type_desc = "character device";
            break;
        case VN_BLK:
            vnode_type_desc = "block device";
            break;
        case VN_LNK:
            vnode_type_desc = "symbolic link";
            break;
        case VN_FIFO:
            vnode_type_desc = "FIFO";
            break;
        case VN_SOCK:
            vnode_type_desc = "socket";
            break;
        default:
            vnode_type_desc = "unknown";
            break;
    }

    /* Phase 2: Verify it's a directory with detailed logging */
    if (vnode->type != VN_DIR) {
        fut_printf("[CHDIR] chdir(path='%s' [%s], vnode_ino=%lu, vnode_type=%s) "
                   "-> ENOTDIR (target is %s, not directory)\n",
                   kpath, path_type, vnode->ino, vnode_type_desc, vnode_type_desc);
        fut_vnode_unref(vnode);
        return -ENOTDIR;
    }

    /* Linux requires execute (search) permission on the target directory.
     * Without this check the function comment promised the gate
     * ('Requires execute permission on target directory') but the check
     * was never implemented — any user could chdir into any directory
     * regardless of mode, bypassing access controls that gate readdir
     * and lookups inside the directory.
     *
     * Standard Unix DAC: +x for owner if uid matches, +x for group if
     * gid or supplementary group matches, +x for other otherwise.
     * Root (uid 0) and CAP_DAC_OVERRIDE / CAP_DAC_READ_SEARCH bypass. */
    {
        uint32_t task_uid = userns_ns_to_host_uid(task->user_ns, task->uid);
        bool has_search;
        if (task_uid == 0 ||
            (task->cap_effective & ((1ULL << 1 /* CAP_DAC_OVERRIDE */) |
                                    (1ULL << 2 /* CAP_DAC_READ_SEARCH */)))) {
            has_search = true;
        } else if (task_uid == vnode->uid) {
            has_search = (vnode->mode & 0100) != 0;
        } else {
            uint32_t task_gid = userns_ns_to_host_gid(task->user_ns, task->gid);
            int in_group = (task_gid == vnode->gid);
            if (!in_group) {
                for (int gi = 0; gi < task->ngroups; gi++) {
                    uint32_t gh = userns_ns_to_host_gid(task->user_ns,
                                                        task->groups[gi]);
                    if (gh == vnode->gid) { in_group = 1; break; }
                }
            }
            if (in_group)
                has_search = (vnode->mode & 0010) != 0;
            else
                has_search = (vnode->mode & 0001) != 0;
        }
        if (!has_search) {
            fut_printf("[CHDIR] chdir(path='%s', vnode_ino=%lu, mode=0%o, "
                       "task_uid=%u, vnode_uid=%u) -> EACCES "
                       "(no search permission on target directory)\n",
                       kpath, vnode->ino, vnode->mode,
                       task_uid, vnode->uid);
            fut_vnode_unref(vnode);
            return -EACCES;
        }
    }

    /* Update the task's current working directory */
    task->current_dir_ino = vnode->ino;

    /* Detailed success logging */
    fut_printf("[CHDIR] chdir(path='%s' [%s], old_dir_ino=%lu, new_dir_ino=%lu) "
               "-> 0 (cwd changed, path truncation detection)\n",
               kpath, path_type, old_dir_ino, vnode->ino);

    /* Cache canonical directory path by walking vnode->parent chain.
     * This normalizes away any '..' or '.' in the original path so getcwd()
     * returns a clean absolute path. Falls back to raw path on failure. */
    char *cache_path = task->cwd_cache_buf;
    if (cache_path) {
        char *built = fut_vnode_build_path(vnode, cache_path, 256);
        /* Fallback: if build_path returned "/" but input is an absolute path
         * that isn't "/", the vnode is a mount root and the parent chain can't
         * see the mount point name.  Use the raw input path instead.
         * Only for absolute paths — relative paths like ".." should use the
         * built path since we don't resolve them here. */
        if (!built || cache_path[0] == '\0' ||
            (cache_path[0] == '/' && cache_path[1] == '\0' &&
             kpath[0] == '/' && kpath[1] != '\0')) {
            size_t path_len = 0;
            while (kpath[path_len] && path_len < 255) {
                cache_path[path_len] = kpath[path_len];
                path_len++;
            }
            cache_path[path_len] = '\0';
        }
        task->cwd_cache = cache_path;
    }

    /* Release the vnode reference */
    fut_vnode_unref(vnode);

    return 0;
}
