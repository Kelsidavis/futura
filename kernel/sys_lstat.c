/* kernel/sys_lstat.c - File status syscall (no symlink follow)
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements lstat() for retrieving file metadata without following symlinks.
 * This is the symbolic-link-aware variant of stat().
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <kernel/fut_vfs.h>
#include <stdint.h>

#include <kernel/kprintf.h>
#include <kernel/uaccess.h>

/**
 * lstat() - Get file status without following symbolic links
 *
 * Retrieves file metadata like stat(), but if the path refers to a symbolic
 * link, returns information about the link itself rather than the target.
 * This is essential for tools like 'ls -l', 'find', and backup utilities
 * that need to distinguish symlinks from regular files.
 *
 * Differences from stat():
 * - stat() follows symlinks and returns info about the target
 * - lstat() does NOT follow symlinks and returns info about the link itself
 * - For non-symlinks, both behave identically
 *
 * @param path     Path to the file or symbolic link
 * @param statbuf  Pointer to userspace stat buffer to fill
 *
 * Returns:
 *   - 0 on success
 *   - -EFAULT if path or statbuf is inaccessible
 *   - -ENOENT if file does not exist
 *   - -EINVAL if path is empty or statbuf is NULL
 *
 * Phase 1 (Completed): Calls fut_vfs_stat() (same as stat)
 * Phase 2 (Completed): Enhanced validation and detailed file status reporting
 * Phase 3 (Completed): Call fut_vfs_lstat() to distinguish symlinks
 * Phase 4: Support AT_SYMLINK_NOFOLLOW flag in fstatat()
 *
 * Uses:
 * - File managers displaying symlink properties
 * - ls -l (shows 'l' type for symlinks)
 * - find command with -type l
 * - Backup tools preserving symlink structure
 * - Security tools checking for symlink attacks
 * - Package managers verifying file integrity
 *
 * Example behavior:
 *   /tmp/link -> /etc/passwd
 *   stat("/tmp/link")  returns info about /etc/passwd (size ~2KB, mode 0644)
 *   lstat("/tmp/link") returns info about the link (size ~11, mode 0777|S_IFLNK)
 *
 * Technical notes:
 * - Symlink size is typically the length of the target path string
 * - Symlink mode has S_IFLNK bit set (0120000 octal prefix)
 * - Permissions on symlinks are usually 0777 (ignored by kernel)
 * - Hard links are indistinguishable by stat/lstat (same inode)
 */
long sys_lstat(const char *path, struct fut_stat *statbuf) {
    /* ARM64 FIX: Copy parameters to local variables immediately to ensure they're preserved
     * on the stack across potentially blocking calls. VFS and copy operations may block and
     * corrupt register-passed parameters upon resumption. */
    const char *local_path = path;
    struct fut_stat *local_statbuf = statbuf;

    if (!local_path || !local_statbuf) {
        fut_printf("[LSTAT] lstat(%p, %p) -> EINVAL (NULL pointer)\n", local_path, local_statbuf);
        return -EINVAL;
    }

    /* Phase 5: Validate statbuf write permission early (kernel writes stat structure)
     * VULNERABILITY: Invalid Output Buffer Pointer
     * ATTACK: Attacker provides read-only or unmapped statbuf buffer
     * IMPACT: Kernel page fault when writing stat structure
     * DEFENSE: Check write permission before path resolution and VFS operations */
    if (fut_access_ok(local_statbuf, sizeof(struct fut_stat), 1) != 0) {
        fut_printf("[LSTAT] lstat(path=%p, statbuf=%p) -> EFAULT (statbuf not writable for %zu bytes, Phase 5)\n",
                   local_path, local_statbuf, sizeof(struct fut_stat));
        return -EFAULT;
    }

    /* Phase 5: Validate path length BEFORE copying to prevent truncation attacks
     * Check original path is null-terminated within reasonable length */
    const size_t MAX_PATH = 4096;  /* PATH_MAX */
    size_t orig_path_len = 0;
    bool found_null = false;

    for (size_t i = 0; i < MAX_PATH; i++) {
        char c;
        if (fut_copy_from_user(&c, (const char *)local_path + i, 1) != 0) {
            fut_printf("[LSTAT] lstat(%p) -> EFAULT "
                       "(path not accessible at offset %zu, Phase 5)\n",
                       local_path, i);
            return -EFAULT;
        }
        if (c == '\0') {
            found_null = true;
            orig_path_len = i;
            break;
        }
    }

    if (!found_null) {
        fut_printf("[LSTAT] lstat(%p) -> ENAMETOOLONG "
                   "(path exceeds PATH_MAX %zu bytes without null terminator, Phase 5)\n",
                   local_path, MAX_PATH);
        return -ENAMETOOLONG;
    }

    /* Validate path is not empty */
    if (orig_path_len == 0) {
        fut_printf("[LSTAT] lstat(\"\") -> EINVAL (empty path, Phase 5)\n");
        return -EINVAL;
    }

    /* Phase 5: Validate path fits in our buffer before copying
     * Prevents silent truncation that could cause path confusion */
    char path_buf[FUT_VFS_PATH_BUFFER_SIZE];
    if (orig_path_len >= sizeof(path_buf)) {
        fut_printf("[LSTAT] lstat(path_len=%zu) -> ENAMETOOLONG "
                   "(exceeds kernel buffer %zu bytes, Phase 5 truncation prevention)\n",
                   orig_path_len, sizeof(path_buf) - 1);
        return -ENAMETOOLONG;
    }

    /* Safe to copy - we know the exact length and it fits */
    if (fut_copy_from_user(path_buf, local_path, orig_path_len + 1) != 0) {
        fut_printf("[LSTAT] lstat(%p, %p) -> EFAULT (path copy failed, Phase 5)\n",
                   local_path, local_statbuf);
        return -EFAULT;
    }
    path_buf[orig_path_len] = '\0';  /* Ensure null termination */

    /* Path length already validated above - Phase 5 complete */
    (void)orig_path_len;  /* Used for validation and copy, now done */

    /* Phase 3: Call fut_vfs_lstat() which doesn't follow the final symlink
     * This returns metadata about the symlink itself, not its target.
     */
    struct fut_stat kernel_stat;
    int ret = fut_vfs_lstat(path_buf, &kernel_stat);
    if (ret < 0) {
        const char *err_desc = (ret == -ENOENT) ? "not found" :
                               (ret == -EACCES) ? "access denied" :
                               (ret == -ENOTDIR) ? "not a directory" : "VFS error";
        fut_printf("[LSTAT] lstat(\"%s\") -> %d (%s)\n", path_buf, ret, err_desc);
        return ret;
    }

    /* Detect file type from st_mode */
    const char *file_type;
    uint32_t mode = kernel_stat.st_mode;
    if ((mode & 0170000) == 0040000) {       /* S_IFDIR */
        file_type = "directory";
    } else if ((mode & 0170000) == 0100000) { /* S_IFREG */
        file_type = "regular file";
    } else if ((mode & 0170000) == 0120000) { /* S_IFLNK */
        file_type = "symlink";
    } else if ((mode & 0170000) == 0060000) { /* S_IFBLK */
        file_type = "block device";
    } else if ((mode & 0170000) == 0020000) { /* S_IFCHR */
        file_type = "character device";
    } else if ((mode & 0170000) == 0010000) { /* S_IFIFO */
        file_type = "FIFO";
    } else if ((mode & 0170000) == 0140000) { /* S_IFSOCK */
        file_type = "socket";
    } else {
        file_type = "unknown";
    }

    /* Copy stat buffer to userspace */
    if (fut_copy_to_user(local_statbuf, &kernel_stat, sizeof(struct fut_stat)) != 0) {
        fut_printf("[LSTAT] lstat(\"%s\") -> EFAULT (copy_to_user failed)\n", path_buf);
        return -EFAULT;
    }

    fut_printf("[LSTAT] lstat(\"%s\") -> 0 (type=%s, size=%llu, mode=%o, ino=%llu)\n",
               path_buf, file_type, kernel_stat.st_size, kernel_stat.st_mode, kernel_stat.st_ino);
    return 0;
}
