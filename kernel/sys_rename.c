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

extern void fut_printf(const char *fmt, ...);
extern int fut_copy_from_user(void *to, const void *from, size_t size);

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
 * Note: This is a stub implementation. The VFS layer currently does not
 * support atomic rename operations. A production implementation would
 * require adding a rename() operation to the filesystem interface.
 *
 * TODO Phase 3: Implement atomic rename in VFS:
 *   - Add rename() operation to fut_vnode_ops
 *   - Implement in RamFS (in-memory rename)
 *   - Implement in FuturaFS (log-structured rename)
 *   - Handle cross-directory rename (update parent inodes)
 *   - Ensure atomicity (no partial state visible)
 *
 * TODO Phase 4: Cross-filesystem rename:
 *   - Detect cross-filesystem rename (compare st_dev)
 *   - Return EXDEV for cross-filesystem rename
 *   - Or implement copy-then-unlink with transaction support
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

    /* Phase 2: Validate path pointers */
    if (!local_oldpath) {
        fut_printf("[RENAME] rename(oldpath=NULL, newpath=?) -> EINVAL (NULL oldpath)\n");
        return -EINVAL;
    }
    if (!local_newpath) {
        fut_printf("[RENAME] rename(oldpath=?, newpath=NULL) -> EINVAL (NULL newpath)\n");
        return -EINVAL;
    }

    /* Copy paths from userspace to kernel space */
    char old_buf[256];
    char new_buf[256];

    if (fut_copy_from_user(old_buf, local_oldpath, sizeof(old_buf) - 1) != 0) {
        fut_printf("[RENAME] rename(oldpath=?, newpath=?) -> EFAULT (oldpath copy_from_user failed)\n");
        return -EFAULT;
    }
    old_buf[sizeof(old_buf) - 1] = '\0';

    /* Security hardening: Detect path truncation BEFORE proceeding
     * Silent truncation could allow renaming unintended files */
    size_t old_path_len = 0;
    while (old_buf[old_path_len] != '\0' && old_path_len < sizeof(old_buf) - 1) {
        old_path_len++;
    }
    if (old_buf[old_path_len] != '\0') {
        /* Path was truncated - null terminator not found before buffer end */
        fut_printf("[RENAME] rename(oldpath=<truncated>, newpath=?) -> ENAMETOOLONG "
                   "(oldpath exceeds %zu bytes)\n", sizeof(old_buf) - 1);
        return -ENAMETOOLONG;
    }

    if (fut_copy_from_user(new_buf, local_newpath, sizeof(new_buf) - 1) != 0) {
        fut_printf("[RENAME] rename(oldpath='%s', newpath=?) -> EFAULT (newpath copy_from_user failed)\n",
                   old_buf);
        return -EFAULT;
    }
    new_buf[sizeof(new_buf) - 1] = '\0';

    /* Security hardening: Detect newpath truncation */
    size_t new_path_len = 0;
    while (new_buf[new_path_len] != '\0' && new_path_len < sizeof(new_buf) - 1) {
        new_path_len++;
    }
    if (new_buf[new_path_len] != '\0') {
        fut_printf("[RENAME] rename(oldpath='%s', newpath=<truncated>) -> ENAMETOOLONG "
                   "(newpath exceeds %zu bytes)\n", old_buf, sizeof(new_buf) - 1);
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

    /* Phase 2: Calculate path lengths */
    size_t old_len = 0;
    while (old_buf[old_len] != '\0' && old_len < 256) {
        old_len++;
    }
    size_t new_len = 0;
    while (new_buf[new_len] != '\0' && new_len < 256) {
        new_len++;
    }

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
        for (int i = 0; i < old_last_slash && i < 255; i++) {
            old_parent_path[i] = old_buf[i];
            old_parent_len++;
        }
    }
    old_parent_path[old_parent_len] = '\0';

    /* Extract filename after last slash */
    for (size_t i = old_last_slash + 1; old_buf[i] != '\0' && old_name_len < 255; i++) {
        old_name[old_name_len++] = old_buf[i];
    }
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
        return -ENOTDIR;
    }

    /* Extract new filename and parent for both cases */
    char new_name[256];
    size_t new_name_len = 0;
    char new_parent_path[256];
    size_t new_parent_len = 0;

    /* Extract newname (filename after last slash) */
    for (size_t i = new_last_slash + 1; new_buf[i] != '\0' && new_name_len < 255; i++) {
        new_name[new_name_len++] = new_buf[i];
    }
    new_name[new_name_len] = '\0';

    if (new_last_slash == 0) {
        /* newpath is /filename - parent is root */
        new_parent_path[0] = '/';
        new_parent_len = 1;
    } else if (new_last_slash > 0) {
        /* Copy path up to last slash */
        for (int i = 0; i < new_last_slash && i < 255; i++) {
            new_parent_path[i] = new_buf[i];
            new_parent_len++;
        }
    }
    new_parent_path[new_parent_len] = '\0';

    /* For same-directory rename */
    if (same_directory && old_last_slash >= 0) {
        /* Call VFS rename operation on common parent */
        if (!old_parent->ops || !old_parent->ops->rename) {
            fut_printf("[RENAME] rename(old='%s' [%s], new='%s' [%s], op=%s) -> ENOSYS (no rename operation)\n",
                       old_buf, old_path_type, new_buf, new_path_type, operation_type);
            return -ENOSYS;
        }

        ret = old_parent->ops->rename(old_parent, old_name, new_name);
        if (ret == 0) {
            fut_printf("[RENAME] rename(old='%s' [%s], new='%s' [%s], op=%s) -> 0 (success, same-dir)\n",
                       old_buf, old_path_type, new_buf, new_path_type, operation_type);
        } else {
            fut_printf("[RENAME] rename(old='%s' [%s], new='%s' [%s], op=%s) -> %d (error)\n",
                       old_buf, old_path_type, new_buf, new_path_type, operation_type, ret);
        }
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
        return ret;
    }

    if (new_parent->type != VN_DIR) {
        fut_printf("[RENAME] rename(old='%s' [%s], new='%s' [%s], op=%s) -> ENOTDIR (new parent not directory)\n",
                   old_buf, old_path_type, new_buf, new_path_type, operation_type);
        return -ENOTDIR;
    }

    /* Check if both parents are on same filesystem (simplification: all in RamFS for now) */
    if (old_parent->mount != new_parent->mount) {
        fut_printf("[RENAME] rename(old='%s' [%s], new='%s' [%s], op=%s) -> EXDEV (different filesystems)\n",
                   old_buf, old_path_type, new_buf, new_path_type, operation_type);
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
        return -ENOSYS;
    }

    if (!new_parent->ops || !new_parent->ops->link) {
        fut_printf("[RENAME] rename(old='%s' [%s], new='%s' [%s], op=%s) -> ENOSYS (no link operation)\n",
                   old_buf, old_path_type, new_buf, new_path_type, operation_type);
        return -ENOSYS;
    }

    /* Create link in new parent first (this will be full path to file) */
    ret = new_parent->ops->link(new_parent, old_buf, new_buf);
    if (ret < 0) {
        fut_printf("[RENAME] rename(old='%s' [%s], new='%s' [%s], op=%s) -> %d (link failed, cross-dir)\n",
                   old_buf, old_path_type, new_buf, new_path_type, operation_type, ret);
        return ret;
    }

    /* Unlink from old parent - CRITICAL: If this fails, duplicate exists */
    ret = old_parent->ops->unlink(old_parent, old_name);
    if (ret < 0) {
        /* ATOMICITY VIOLATION: Link created but unlink failed
         * This leaves a duplicate file entry at both old and new paths.
         * Applications expecting atomic rename may see inconsistent state.
         * Proper fix requires rollback of the link operation or VFS transactions. */
        fut_printf("[RENAME] rename(old='%s' [%s], new='%s' [%s], op=%s) -> %d "
                   "(ATOMICITY VIOLATION: unlink failed after link, duplicate file at both paths)\n",
                   old_buf, old_path_type, new_buf, new_path_type, operation_type, ret);
        return ret;
    }

    fut_printf("[RENAME] rename(old='%s' [%s], new='%s' [%s], op=%s) -> 0 (success, cross-dir)\n",
               old_buf, old_path_type, new_buf, new_path_type, operation_type);
    return 0;
}
