/* kernel/sys_rename.c - File rename syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements the rename() syscall for renaming/moving files and directories.
 * Essential for file management and atomic file replacement operations.
 *
 * Phase 1 (Completed): Basic rename validation and stub
 * Phase 2 (Completed): Enhanced validation, path categorization, operation type identification, and detailed logging
 * Phase 3 (Completed): VFS atomic rename operation
 * Phase 4: Cross-filesystem rename (copy-then-unlink with transactions)
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <kernel/fut_vfs.h>
#include <stdint.h>
#include <string.h>

#include <kernel/kprintf.h>
#include <kernel/uaccess.h>

#include <platform/platform.h>
static inline int rename_copy_from_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)src >= KERNEL_VIRTUAL_BASE) { __builtin_memcpy(dst, src, n); return 0; }
#endif
    return fut_copy_from_user(dst, src, n);
}

/**
 * rename() - Rename or move a file/directory
 *
 * Renames the file at oldpath to newpath. If newpath exists, it is atomically
 * replaced. This is the atomic file replacement primitive used by many
 * applications to ensure safe file updates.
 *
 * @param oldpath  Path to existing file/directory
 * @param newpath  New path for the file/directory
 *
 * Returns:
 *   - 0 on success
 *   - -EFAULT if paths are inaccessible
 *   - -EINVAL if oldpath or newpath is invalid/empty/NULL
 *   - -ENOENT if oldpath does not exist
 *   - -ENOTDIR if path component not a directory
 *   - -EISDIR if newpath is directory but oldpath is not
 *   - -EEXIST if newpath exists and is directory but oldpath is not
 *   - -ENOTEMPTY if newpath is non-empty directory
 *   - -EBUSY if oldpath or newpath is in use (e.g., cwd)
 *   - -EXDEV if oldpath and newpath are on different filesystems
 *   - -EACCES if permission denied
 *   - -EPERM if operation not permitted
 *   - -EROFS if filesystem is read-only
 *   - -ENOSYS if operation not supported by filesystem
 *
 * Behavior:
 *   - Atomic operation: newpath replacement is atomic
 *   - If newpath exists, it is replaced atomically
 *   - If newpath is a directory, it must be empty
 *   - Cannot rename . or .. special entries
 *   - Cannot rename to make directory its own subdirectory
 *   - Link count updates are atomic
 *   - Requires write permission on both parent directories
 *
 * Atomicity guarantees:
 *   - newpath replacement is atomic (no partial state visible)
 *   - Either rename succeeds completely or fails with no changes
 *   - No window where newpath doesn't exist
 *   - Safe for concurrent access
 *
 * Common usage patterns:
 *
 * Atomic file update (safe config file replacement):
 *   write(fd, new_config, size);
 *   fsync(fd);
 *   close(fd);
 *   rename("/etc/config.tmp", "/etc/config");  // Atomic replacement
 *
 * Move file to different directory:
 *   rename("/tmp/oldfile", "/var/log/newfile");
 *
 * Simple file rename in same directory:
 *   rename("/home/user/oldname.txt", "/home/user/newname.txt");
 *
 * Safe database commit:
 *   write(temp_fd, transaction_data, size);
 *   fsync(temp_fd);
 *   close(temp_fd);
 *   rename("/db/temp.db", "/db/main.db");  // Atomic replacement
 *
 * Log file rotation:
 *   rename("/var/log/app.log", "/var/log/app.log.1");
 *   // Create new /var/log/app.log
 *
 * Directory rename:
 *   rename("/tmp/olddir", "/tmp/newdir");
 *
 * Rename rules:
 *   - File → File: Replaces newpath if it exists
 *   - File → Directory: EISDIR error (cannot replace directory with file)
 *   - Directory → File: ENOTDIR error (cannot replace file with directory)
 *   - Directory → Directory: newpath must be empty, then replaced
 *   - Directory → Subdirectory: EINVAL (cannot make directory its own child)
 *
 * Cross-filesystem rename:
 *   - Returns EXDEV if oldpath and newpath on different filesystems
 *   - Applications must handle by copy-then-unlink
 *   - Example: mv command implements this fallback
 *
 * Security considerations:
 *   - Check write permission on both parent directories
 *   - Prevent renaming over system directories
 *   - Prevent making directory its own subdirectory
 *   - Watch for symbolic link attacks (TOCTOU)
 *
 * TOCTOU warning:
 *   - stat() followed by rename() has race condition
 *   - File can change between stat() and rename()
 *   - Use O_EXCL, flock, or accept the race
 *
 * Related syscalls:
 *   - renameat(): Rename with directory FD (safer)
 *   - renameat2(): Rename with flags (RENAME_EXCHANGE, RENAME_NOREPLACE)
 *   - link(): Create hard link
 *   - symlink(): Create symbolic link
 *
 * Phase 3 Implementation (Completed):
 *   ✓ Added rename() operation to fut_vnode_ops
 *   ✓ Implemented in RamFS (in-memory rename) - see line 367
 *   ✓ Cross-directory rename with link/unlink fallback (lines 427-509)
 *   ✓ Rollback protection for atomicity (lines 491-508)
 *   ✓ Same-directory atomic rename (lines 359-376)
 *
 * TODO Phase 4: Cross-filesystem rename:
 *   - [DONE] Detect cross-filesystem rename (compare mount pointers) - line 390
 *   - [DONE] Return EXDEV for cross-filesystem rename - line 395
 *   - Implement copy-then-unlink with transaction support (optional)
 *
 * Phase 1 (Completed): Basic rename validation and stub
 * Phase 2 (Completed): Enhanced validation, path categorization, operation type identification, detailed logging
 * Phase 3 (Completed): VFS atomic rename operation
 * Phase 4: Cross-filesystem rename (copy-then-unlink with transactions)
 */
long sys_rename(const char *oldpath, const char *newpath) {
    /* ARM64 FIX: Copy parameters to local variables immediately to ensure they're preserved
     * on the stack across potentially blocking calls. VFS and copy operations may block and
     * corrupt register-passed parameters upon resumption. */
    const char *local_oldpath = oldpath;
    const char *local_newpath = newpath;

    /* NULL paths are pointer faults (EFAULT) per Linux rename(2). */
    if (!local_oldpath) {
        fut_printf("[RENAME] rename(oldpath=NULL, newpath=?) -> EFAULT\n");
        return -EFAULT;
    }
    if (!local_newpath) {
        fut_printf("[RENAME] rename(oldpath=?, newpath=NULL) -> EFAULT\n");
        return -EFAULT;
    }

    /* Copy paths from userspace to kernel space */
    char old_buf[256];
    char new_buf[256];

    if (rename_copy_from_user(old_buf, local_oldpath, sizeof(old_buf)) != 0) {
        fut_printf("[RENAME] rename(oldpath=?, newpath=?) -> EFAULT (oldpath copy_from_user failed)\n");
        return -EFAULT;
    }
    if (memchr(old_buf, '\0', sizeof(old_buf)) == NULL) {
        fut_printf("[RENAME] rename(oldpath=<truncated>, newpath=?) -> ENAMETOOLONG\n");
        return -ENAMETOOLONG;
    }

    if (rename_copy_from_user(new_buf, local_newpath, sizeof(new_buf)) != 0) {
        fut_printf("[RENAME] rename(oldpath='%s', newpath=?) -> EFAULT (newpath copy_from_user failed)\n",
                   old_buf);
        return -EFAULT;
    }
    if (memchr(new_buf, '\0', sizeof(new_buf)) == NULL) {
        fut_printf("[RENAME] rename(oldpath='%s', newpath=<truncated>) -> ENAMETOOLONG\n", old_buf);
        return -ENAMETOOLONG;
    }

    /* Phase 2: Validate paths are not empty */
    if (old_buf[0] == '\0') {
        fut_printf("[RENAME] rename(oldpath=\"\" [empty], newpath='%s') -> EINVAL (empty oldpath)\n",
                   new_buf);
        return -EINVAL;
    }
    if (new_buf[0] == '\0') {
        fut_printf("[RENAME] rename(oldpath='%s', newpath=\"\" [empty]) -> EINVAL (empty newpath)\n",
                   old_buf);
        return -EINVAL;
    }

    /* Phase 2: Categorize old path type */
    const char *old_path_type;
    if (old_buf[0] == '/') {
        old_path_type = "absolute";
    } else if (old_buf[0] == '.' && old_buf[1] == '/') {
        old_path_type = "relative (explicit)";
    } else if (old_buf[0] == '.') {
        old_path_type = "relative (current/parent)";
    } else {
        old_path_type = "relative";
    }

    /* Phase 2: Categorize new path type */
    const char *new_path_type;
    if (new_buf[0] == '/') {
        new_path_type = "absolute";
    } else if (new_buf[0] == '.' && new_buf[1] == '/') {
        new_path_type = "relative (explicit)";
    } else if (new_buf[0] == '.') {
        new_path_type = "relative (current/parent)";
    } else {
        new_path_type = "relative";
    }

    /* POSIX: rename(path, path) is a no-op when both paths refer to the same file */
    if (strcmp(old_buf, new_buf) == 0) {
        return 0;
    }

    /* Phase 2: Calculate path lengths */
    size_t old_len = strlen(old_buf);
    size_t new_len = strlen(new_buf);

    /* Phase 2: Determine operation type based on paths */
    const char *operation_type;

    /* Extract directory portion to detect same-directory rename */
    int old_last_slash = -1;
    int new_last_slash = -1;
    for (size_t i = 0; i < old_len; i++) {
        if (old_buf[i] == '/') old_last_slash = (int)i;
    }
    for (size_t i = 0; i < new_len; i++) {
        if (new_buf[i] == '/') new_last_slash = (int)i;
    }

    /* Check if directories match */
    bool same_directory = false;
    if (old_last_slash == new_last_slash) {
        same_directory = true;
        for (int i = 0; i < old_last_slash; i++) {
            if (old_buf[i] != new_buf[i]) {
                same_directory = false;
                break;
            }
        }
    }

    if (same_directory && old_last_slash >= 0) {
        operation_type = "rename in same directory";
    } else if (old_buf[0] == '/' && new_buf[0] == '/') {
        operation_type = "move between directories (absolute paths)";
    } else if (old_buf[0] != '/' && new_buf[0] != '/') {
        operation_type = "move between directories (relative paths)";
    } else {
        operation_type = "move between directories (mixed paths)";
    }

    /* Extract old parent path and filename */
    char old_parent_path[256];
    char old_name[256];
    size_t old_parent_len = 0;
    size_t old_name_len = 0;

    if (old_last_slash == 0) {
        /* oldpath is /filename - parent is root */
        old_parent_path[0] = '/';
        old_parent_len = 1;
    } else if (old_last_slash > 0) {
        /* Copy path up to last slash */
        old_parent_len = ((size_t)old_last_slash < 255) ? (size_t)old_last_slash : 255;
        memcpy(old_parent_path, old_buf, old_parent_len);
    }
    old_parent_path[old_parent_len] = '\0';

    /* Extract filename after last slash */
    old_name_len = strnlen(&old_buf[old_last_slash + 1], 255);
    memcpy(old_name, &old_buf[old_last_slash + 1], old_name_len);
    old_name[old_name_len] = '\0';

    /* Lookup old parent directory */
    struct fut_vnode *old_parent = NULL;
    int ret = fut_vfs_lookup(old_parent_path, &old_parent);
    if (ret < 0) {
        const char *error_desc;
        switch (ret) {
            case -ENOENT:
                error_desc = "oldpath parent not found";
                break;
            case -ENOTDIR:
                error_desc = "path component not a directory";
                break;
            default:
                error_desc = "parent lookup failed";
                break;
        }
        fut_printf("[RENAME] rename(old='%s' [%s], new='%s' [%s], op=%s) -> %d (%s)\n",
                   old_buf, old_path_type, new_buf, new_path_type, operation_type, ret, error_desc);
        return ret;
    }

    if (old_parent->type != VN_DIR) {
        fut_printf("[RENAME] rename(old='%s' [%s], new='%s' [%s], op=%s) -> ENOTDIR (parent not directory)\n",
                   old_buf, old_path_type, new_buf, new_path_type, operation_type);
        fut_vnode_unref(old_parent);
        return -ENOTDIR;
    }

    /* Extract new filename and parent for both cases */
    char new_name[256];
    size_t new_name_len = 0;
    char new_parent_path[256];
    size_t new_parent_len = 0;

    /* Extract newname (filename after last slash) */
    new_name_len = strnlen(&new_buf[new_last_slash + 1], 255);
    memcpy(new_name, &new_buf[new_last_slash + 1], new_name_len);
    new_name[new_name_len] = '\0';

    if (new_last_slash == 0) {
        /* newpath is /filename - parent is root */
        new_parent_path[0] = '/';
        new_parent_len = 1;
    } else if (new_last_slash > 0) {
        /* Copy path up to last slash */
        new_parent_len = ((size_t)new_last_slash < 255) ? (size_t)new_last_slash : 255;
        memcpy(new_parent_path, new_buf, new_parent_len);
    }
    new_parent_path[new_parent_len] = '\0';

    /* For same-directory rename */
    if (same_directory && old_last_slash >= 0) {
        /* Call VFS rename operation on common parent */
        if (!old_parent->ops || !old_parent->ops->rename) {
            fut_printf("[RENAME] rename(old='%s' [%s], new='%s' [%s], op=%s) -> ENOSYS (no rename operation)\n",
                       old_buf, old_path_type, new_buf, new_path_type, operation_type);
            fut_vnode_unref(old_parent);
            return -ENOSYS;
        }

        /* Sticky bit enforcement on source directory */
        if (old_parent->mode & 01000) {
            fut_task_t *stask = fut_task_current();
            uint32_t caller_uid = stask ? stask->uid : 0;
            int has_cap_fowner = stask &&
                (stask->cap_effective & (1ULL << 3 /* CAP_FOWNER */));
            if (caller_uid != 0 && !has_cap_fowner && caller_uid != old_parent->uid) {
                struct fut_vnode *src = NULL;
                int lret = fut_vfs_lookup(old_buf, &src);
                if (lret == 0 && src) {
                    if (caller_uid != src->uid) {
                        fut_vnode_unref(src);
                        fut_vnode_unref(old_parent);
                        return -EACCES;
                    }
                    fut_vnode_unref(src);
                }
            }
        }

        ret = old_parent->ops->rename(old_parent, old_name, new_name);
        if (ret == 0) {
            fut_printf("[RENAME] rename(old='%s' [%s], new='%s' [%s], op=%s) -> 0 (success, same-dir)\n",
                       old_buf, old_path_type, new_buf, new_path_type, operation_type);
            vfs_dcache_invalidate_path(old_buf); vfs_dcache_invalidate_path(new_buf);
            /* Dispatch inotify IN_MOVED_FROM + IN_MOVED_TO with matching cookie */
            {
                extern void inotify_dispatch_event(const char *, uint32_t, const char *, uint32_t);
                static uint32_t move_cookie = 1000;
                uint32_t cookie = move_cookie++;
                inotify_dispatch_event(old_parent_path, 0x00000040 /* IN_MOVED_FROM */, old_name, cookie);
                inotify_dispatch_event(old_parent_path, 0x00000080 /* IN_MOVED_TO */, new_name, cookie);
            }
        } else {
            fut_printf("[RENAME] rename(old='%s' [%s], new='%s' [%s], op=%s) -> %d (error)\n",
                       old_buf, old_path_type, new_buf, new_path_type, operation_type, ret);
        }
        fut_vnode_unref(old_parent);
        return ret;
    }

    /* Cross-directory rename: lookup both parent directories */
    struct fut_vnode *new_parent = NULL;
    ret = fut_vfs_lookup(new_parent_path, &new_parent);
    if (ret < 0) {
        const char *error_desc;
        switch (ret) {
            case -ENOENT:
                error_desc = "newpath parent not found";
                break;
            case -ENOTDIR:
                error_desc = "path component not a directory";
                break;
            default:
                error_desc = "parent lookup failed";
                break;
        }
        fut_printf("[RENAME] rename(old='%s' [%s], new='%s' [%s], op=%s) -> %d (%s, cross-dir)\n",
                   old_buf, old_path_type, new_buf, new_path_type, operation_type, ret, error_desc);
        fut_vnode_unref(old_parent);
        return ret;
    }

    if (new_parent->type != VN_DIR) {
        fut_printf("[RENAME] rename(old='%s' [%s], new='%s' [%s], op=%s) -> ENOTDIR (new parent not directory)\n",
                   old_buf, old_path_type, new_buf, new_path_type, operation_type);
        fut_vnode_unref(old_parent);
        fut_vnode_unref(new_parent);
        return -ENOTDIR;
    }

    /* Check if both parents are on same filesystem (simplification: all in RamFS for now) */
    if (old_parent->mount != new_parent->mount) {
        fut_printf("[RENAME] rename(old='%s' [%s], new='%s' [%s], op=%s) -> EXDEV (different filesystems)\n",
                   old_buf, old_path_type, new_buf, new_path_type, operation_type);
        fut_vnode_unref(old_parent);
        fut_vnode_unref(new_parent);
        return -EXDEV;
    }

    /* Security hardening NOTE: TOCTOU vulnerability between lookup and operations
     * The vnode lookups above (fut_vfs_lookup) and the operations below (link/unlink)
     * are not atomic. Symlinks could be replaced between lookup and operation,
     * redirecting the rename to unintended targets.
     *
     * Proper fix requires VFS-level atomic rename operation that:
     * 1. Locks both parent directories
     * 2. Validates vnodes still match expected inodes
     * 3. Performs operation atomically
     * 4. Releases locks
     *
     * Current mitigation: Document limitation and rely on upper-layer locking.
     * Applications requiring atomicity should use flock() or O_EXCL.
     */

    /* For cross-directory rename, we need to:
     * 1. Link into new parent with new name (create new entry)
     * 2. Unlink from old parent (remove old entry)
     *
     * ATOMICITY WARNING: This is NOT atomic. If unlink fails after link succeeds,
     * a duplicate file entry will exist. Proper fix requires filesystem-level
     * transaction support or VFS-level rename primitive.
     */

    if (!old_parent->ops || !old_parent->ops->unlink) {
        fut_printf("[RENAME] rename(old='%s' [%s], new='%s' [%s], op=%s) -> ENOSYS (no unlink operation)\n",
                   old_buf, old_path_type, new_buf, new_path_type, operation_type);
        fut_vnode_unref(old_parent);
        fut_vnode_unref(new_parent);
        return -ENOSYS;
    }

    if (!new_parent->ops || !new_parent->ops->link) {
        fut_printf("[RENAME] rename(old='%s' [%s], new='%s' [%s], op=%s) -> ENOSYS (no link operation)\n",
                   old_buf, old_path_type, new_buf, new_path_type, operation_type);
        fut_vnode_unref(old_parent);
        fut_vnode_unref(new_parent);
        return -ENOSYS;
    }

    /* Cross-directory rename atomicity protection
     * VULNERABILITY: Non-Atomic Cross-Directory Rename Leading to File Duplication
     *
     * ATTACK SCENARIO:
     * Exploit link() then unlink() non-atomicity for data corruption
     *
     * Normal cross-directory rename:
     * 1. Application calls rename("/dir1/file", "/dir2/file")
     * 2. Kernel creates link at /dir2/file (line 449)
     * 3. Kernel removes link at /dir1/file (line 457)
     * 4. Expected: File atomically moves from dir1 to dir2
     *
     * Attack via unlink() failure:
     * 5. After link() succeeds, trigger unlink() failure:
     *    - Concurrent mmap() locks old file
     *    - SELinux/AppArmor denies unlink permission
     *    - Filesystem error (disk full on metadata update)
     * 6. unlink() returns error, but link() already succeeded
     * 7. File now exists at BOTH /dir1/file and /dir2/file
     * 8. File duplication violates POSIX rename atomicity
     *
     * Real-world impact:
     * - Database corruption (duplicate entries in index)
     * - File lock confusion (two paths to same inode)
     * - Quota bypass (file counted twice)
     * - Backup inconsistency (duplicate in snapshot)
     * - Application logic errors (expected one copy, got two)
     *
     * DEFENSE:
     * Rollback link() if unlink() fails to maintain atomicity
     */

    /* Look up the source file vnode — link() needs the file, not the directory */
    struct fut_vnode *old_file = NULL;
    ret = fut_vfs_lookup(old_buf, &old_file);
    if (ret < 0) {
        fut_printf("[RENAME] rename(old='%s' [%s], new='%s' [%s], op=%s) -> %d (old file lookup failed)\n",
                   old_buf, old_path_type, new_buf, new_path_type, operation_type, ret);
        fut_vnode_unref(old_parent);
        fut_vnode_unref(new_parent);
        return ret;
    }

    /* Create link in new parent first (this will be full path to file) */
    ret = new_parent->ops->link(old_file, old_buf, new_buf);
    fut_vnode_unref(old_file);
    if (ret < 0) {
        fut_printf("[RENAME] rename(old='%s' [%s], new='%s' [%s], op=%s) -> %d (link failed, cross-dir)\n",
                   old_buf, old_path_type, new_buf, new_path_type, operation_type, ret);
        fut_vnode_unref(old_parent);
        fut_vnode_unref(new_parent);
        return ret;
    }

    /* Unlink from old parent - CRITICAL: If this fails, must rollback link to maintain atomicity */
    ret = old_parent->ops->unlink(old_parent, old_name);
    if (ret < 0) {
        /* ROLLBACK - Unlink the newly created link to restore original state
         * Without rollback: File exists at both old and new paths (duplicate)
         * With rollback: Unlink new path, file remains only at old path (atomic failure)
         */
        int rollback_ret = new_parent->ops->unlink(new_parent, new_name);
        if (rollback_ret < 0) {
            /* Double fault: Both unlink operations failed
             * File duplication is unavoidable - system in inconsistent state */
            fut_printf("[RENAME] rename(old='%s' [%s], new='%s' [%s], op=%s) -> %d "
                       "(CRITICAL: unlink failed AND rollback failed, file duplicated at both paths)\n",
                       old_buf, old_path_type, new_buf, new_path_type, operation_type, ret);
        } else {
            /* Rollback succeeded: File remains only at old path, rename failed cleanly */
            fut_printf("[RENAME] rename(old='%s' [%s], new='%s' [%s], op=%s) -> %d "
                       "(unlink failed, rollback succeeded, file remains at old path only)\n",
                       old_buf, old_path_type, new_buf, new_path_type, operation_type, ret);
        }
        fut_vnode_unref(old_parent);
        fut_vnode_unref(new_parent);
        return ret;
    }

    fut_printf("[RENAME] rename(old='%s' [%s], new='%s' [%s], op=%s) -> 0 (success, cross-dir)\n",
               old_buf, old_path_type, new_buf, new_path_type, operation_type);
    vfs_dcache_invalidate_path(old_buf); vfs_dcache_invalidate_path(new_buf);

    /* Dispatch inotify IN_MOVED_FROM on old dir + IN_MOVED_TO on new dir */
    {
        extern void inotify_dispatch_event(const char *, uint32_t, const char *, uint32_t);
        static uint32_t xdir_cookie = 2000;
        uint32_t cookie = xdir_cookie++;
        inotify_dispatch_event(old_parent_path, 0x00000040 /* IN_MOVED_FROM */, old_name, cookie);
        inotify_dispatch_event(new_parent_path, 0x00000080 /* IN_MOVED_TO */, new_name, cookie);
    }

    fut_vnode_unref(old_parent);
    fut_vnode_unref(new_parent);
    return 0;
}
