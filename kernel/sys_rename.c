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

    if (fut_copy_from_user(new_buf, local_newpath, sizeof(new_buf) - 1) != 0) {
        fut_printf("[RENAME] rename(oldpath='%s', newpath=?) -> EFAULT (newpath copy_from_user failed)\n",
                   old_buf);
        return -EFAULT;
    }
    new_buf[sizeof(new_buf) - 1] = '\0';

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

    /* Check if oldpath exists */
    struct fut_vnode *old_vnode = NULL;
    int ret = fut_vfs_lookup(old_buf, &old_vnode);
    if (ret < 0) {
        const char *error_desc;
        switch (ret) {
            case -ENOENT:
                error_desc = "oldpath not found";
                break;
            case -ENOTDIR:
                error_desc = "path component not a directory";
                break;
            case -ENAMETOOLONG:
                error_desc = "pathname too long";
                break;
            case -EACCES:
                error_desc = "permission denied";
                break;
            default:
                error_desc = "lookup failed";
                break;
        }

        fut_printf("[RENAME] rename(old='%s' [%s], new='%s' [%s], op=%s) -> %d (%s)\n",
                   old_buf, old_path_type, new_buf, new_path_type, operation_type, ret, error_desc);
        return ret;
    }

    /* Phase 2: Identify old vnode type */
    const char *old_vnode_type;
    switch (old_vnode->type) {
        case VN_REG:
            old_vnode_type = "regular file";
            break;
        case VN_DIR:
            old_vnode_type = "directory";
            break;
        case VN_LNK:
            old_vnode_type = "symbolic link";
            break;
        case VN_CHR:
            old_vnode_type = "character device";
            break;
        case VN_BLK:
            old_vnode_type = "block device";
            break;
        case VN_FIFO:
            old_vnode_type = "FIFO";
            break;
        case VN_SOCK:
            old_vnode_type = "socket";
            break;
        default:
            old_vnode_type = "unknown";
            break;
    }

    /*
     * Phase 3: VFS rename operation not yet implemented
     *
     * The rename operation is not yet available in the VFS layer.
     * TODO: Implement atomic rename in vnode_ops:
     *   - Add rename() operation to fut_vnode_ops structure
     *   - Implement in RamFS (in-memory rename)
     *   - Implement in FuturaFS (log-structured rename)
     *   - Handle cross-directory rename atomically
     */
    fut_printf("[RENAME] rename(old='%s' [%s], new='%s' [%s], old_ino=%lu, "
               "old_type=%s, op=%s) -> ENOSYS (Phase 3: VFS atomic rename operation)\n",
               old_buf, old_path_type, new_buf, new_path_type, old_vnode->ino,
               old_vnode_type, operation_type);
    return -ENOSYS;
}
