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

extern void fut_printf(const char *fmt, ...);
extern int fut_copy_from_user(void *to, const void *from, size_t size);
extern int fut_copy_to_user(void *to, const void *from, size_t size);

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
 * Phase 1 (Current): Calls fut_vfs_stat() (same as stat)
 * Phase 2: Call fut_vfs_lstat() to distinguish symlinks
 * Phase 3: Support AT_SYMLINK_NOFOLLOW flag in fstatat()
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
    if (!path || !statbuf) {
        return -EINVAL;
    }

    /* Copy path from userspace to kernel space */
    char path_buf[256];
    if (fut_copy_from_user(path_buf, path, sizeof(path_buf) - 1) != 0) {
        return -EFAULT;
    }
    path_buf[sizeof(path_buf) - 1] = '\0';

    /* Validate path is not empty */
    if (path_buf[0] == '\0') {
        return -EINVAL;
    }

    /* Phase 1: Use fut_vfs_stat() (same as stat - follows symlinks)
     * Phase 2: Will call fut_vfs_lstat() which doesn't follow symlinks
     *
     * Future implementation:
     * int ret = fut_vfs_lstat(path_buf, &kernel_stat);
     *
     * The VFS layer will need to:
     * 1. Resolve path components up to the final component
     * 2. For the final component, if it's a symlink:
     *    - lstat: return symlink inode metadata
     *    - stat:  follow symlink and return target metadata
     * 3. Set st_mode with S_IFLNK (0120000) for symlinks
     * 4. Set st_size to strlen(symlink_target)
     */
    struct fut_stat kernel_stat;
    int ret = fut_vfs_stat(path_buf, &kernel_stat);
    if (ret < 0) {
        fut_printf("[LSTAT] lstat(%s) -> %d (VFS error)\n", path_buf, ret);
        return ret;
    }

    /* Copy stat buffer to userspace */
    if (fut_copy_to_user(statbuf, &kernel_stat, sizeof(struct fut_stat)) != 0) {
        fut_printf("[LSTAT] lstat(%s) -> EFAULT (copy_to_user failed)\n", path_buf);
        return -EFAULT;
    }

    fut_printf("[LSTAT] lstat(%s) -> 0 (size=%llu, mode=%o, ino=%llu)\n",
               path_buf, kernel_stat.st_size, kernel_stat.st_mode, kernel_stat.st_ino);
    return 0;
}
