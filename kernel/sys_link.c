/* kernel/sys_link.c - Hard link creation syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements the link() syscall for creating hard links to existing files.
 * Hard links create additional directory entries that reference the same
 * inode, allowing a file to be accessed via multiple pathnames.
 *
 * Phase 1 (Completed): Stub implementation returning -ENOSYS
 * Phase 2 (Completed): Enhanced validation, path categorization, link count tracking, detailed logging
 * Phase 3 (Completed): Full VFS integration with link count tracking and filesystem operations
 * Phase 4: Cross-filesystem link prevention and performance optimization
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <kernel/fut_vfs.h>
#include <stdint.h>
#include <string.h>

extern void fut_printf(const char *fmt, ...);
extern int fut_copy_from_user(void *to, const void *from, size_t size);

/**
 * link() - Create a hard link to an existing file
 *
 * Creates a new directory entry (hard link) at newpath that refers to the
 * same inode as oldpath. Both paths then refer to the same file data on
 * disk. The file's link count (nlinks) is incremented. The file is only
 * deleted when all links are removed (link count reaches zero) and no
 * processes have the file open.
 *
 * Hard links vs Symbolic links:
 *
 * Hard links:
 *   - Point directly to the same inode (file data)
 *   - Share all metadata (permissions, ownership, timestamps)
 *   - Cannot span filesystems (must be on same device)
 *   - Cannot link to directories (prevents filesystem cycles)
 *   - Removing original doesn't affect link (both are equal)
 *   - Indistinguishable from original (same inode number)
 *   - File persists until all hard links removed
 *   - Created with link() syscall
 *
 * Symbolic links (symlinks):
 *   - Point to pathname (not inode)
 *   - Separate inode with its own metadata
 *   - Can span filesystems
 *   - Can link to directories
 *   - Removing target breaks the symlink (dangling link)
 *   - Distinguishable (different inode, lstat shows SYMLINK)
 *   - File can be deleted while symlinks exist
 *   - Created with symlink() syscall
 *
 * @param oldpath  Path to existing file (the link target)
 * @param newpath  Path where hard link should be created (the new name)
 *
 * Returns:
 *   - 0 on success (link count incremented)
 *   - -ENOSYS (not implemented) - current Phase 2 behavior
 *
 * Future error codes (Phase 3):
 *   - -EFAULT if oldpath or newpath points to inaccessible memory
 *   - -EINVAL if oldpath or newpath is NULL or empty
 *   - -EEXIST if newpath already exists
 *   - -ENOENT if oldpath doesn't exist or path component missing
 *   - -ENOTDIR if path component is not a directory
 *   - -EISDIR if oldpath is a directory (hard links to dirs prohibited)
 *   - -EXDEV if oldpath and newpath on different filesystems
 *   - -EPERM if filesystem doesn't support hard links
 *   - -EMLINK if oldpath already has maximum number of links
 *   - -ENOSPC if no space available for new directory entry
 *   - -EROFS if filesystem is read-only
 *   - -EACCES if write permission denied on newpath directory
 *   - -ENAMETOOLONG if pathname too long
 *   - -EIO if I/O error occurred
 *
 * Behavior:
 *   - Both paths must be on same filesystem (checked via mount point)
 *   - Cannot create hard link to directory (prevents cycles)
 *   - Increments link count (nlinks) in inode
 *   - Preserves all file metadata (same inode)
 *   - newpath must not exist (no overwrite)
 *   - Requires write permission on parent directory of newpath
 *   - Does not follow symbolic links in oldpath (operates on symlink itself)
 *
 * Link count tracking:
 *   - New files start with nlinks=1 (the original name)
 *   - Each hard link increments nlinks
 *   - unlink() decrements nlinks
 *   - File data deleted when nlinks reaches 0 and no open file descriptors
 *   - Maximum links typically 65000 (filesystem dependent)
 *
 * Common usage patterns:
 *
 * Create backup reference before modifying:
 *   link("/etc/config", "/etc/config.backup");
 *   // Now both refer to same file
 *   // Modify /etc/config
 *   // Original data preserved in /etc/config.backup
 *   unlink("/etc/config.backup");  // Remove backup when done
 *
 * Atomic file replacement pattern:
 *   // Write new version to temp file
 *   int fd = open("/etc/config.new", O_WRONLY | O_CREAT, 0644);
 *   write(fd, data, len);
 *   close(fd);
 *   // Atomically replace old with new
 *   link("/etc/config.new", "/etc/config.tmp");
 *   rename("/etc/config.tmp", "/etc/config");  // Atomic replacement
 *   unlink("/etc/config.new");
 *
 * Share file across directories:
 *   link("/home/user/doc.txt", "/tmp/shared-doc.txt");
 *   // Same file accessible from both locations
 *   // Changes via either path affect the same data
 *   // File persists until both links removed
 *
 * Prevent accidental deletion:
 *   link("/important/data", "/backup/data-link");
 *   // File survives even if /important/data is unlinked
 *   // Must remove both links to delete file
 *
 * Check link count:
 *   struct stat st;
 *   stat("/path/to/file", &st);
 *   printf("Link count: %lu\n", st.st_nlink);
 *   if (st.st_nlink > 1) {
 *       printf("File has multiple hard links\n");
 *   }
 *
 * Detect if two paths refer to same file:
 *   struct stat st1, st2;
 *   stat("/path/one", &st1);
 *   stat("/path/two", &st2);
 *   if (st1.st_dev == st2.st_dev && st1.st_ino == st2.st_ino) {
 *       printf("Paths refer to same file (hard links)\n");
 *   }
 *
 * Limitations and restrictions:
 *
 * Cannot link directories:
 *   link("/home/user", "/tmp/userlink");  // Returns -EISDIR
 *   // Prevents filesystem cycles and maintains tree structure
 *   // Use symbolic links for directory links
 *
 * Cannot cross filesystem boundaries:
 *   link("/home/file", "/mnt/usb/file");  // Returns -EXDEV if different fs
 *   // Hard links share inode, inodes are filesystem-specific
 *   // Use cp or symbolic links for cross-filesystem references
 *
 * Cannot overwrite existing file:
 *   // If /tmp/link exists:
 *   link("/home/file", "/tmp/link");  // Returns -EEXIST
 *   // Must unlink() first or choose different newpath
 *
 * Maximum link count:
 *   // After many link() calls:
 *   link("/file", "/link1000");  // May return -EMLINK
 *   // Filesystem-specific limit (typically 65000 for ext4)
 *
 * Phase 1 (Completed): Stub implementation returning -ENOSYS
 * Phase 2 (Completed): Enhanced validation, path categorization, link count tracking, detailed logging
 * Phase 3 (Completed): Full VFS integration with link count tracking and filesystem operations
 * Phase 4: Cross-filesystem link prevention and performance optimization
 */
long sys_link(const char *oldpath, const char *newpath) {
    /* ARM64 FIX: Copy parameters to local variables immediately to ensure they're preserved
     * on the stack across potentially blocking calls. VFS and copy operations may block and
     * corrupt register-passed parameters upon resumption. */
    const char *local_oldpath = oldpath;
    const char *local_newpath = newpath;

    /* Phase 2: Validate oldpath pointer */
    if (!local_oldpath) {
        fut_printf("[LINK] link(oldpath=NULL, newpath=?) -> EINVAL "
                   "(NULL oldpath, Phase 2)\n");
        return -EINVAL;
    }

    /* Phase 2: Validate newpath pointer */
    if (!local_newpath) {
        fut_printf("[LINK] link(oldpath=?, newpath=NULL) -> EINVAL "
                   "(NULL newpath, Phase 2)\n");
        return -EINVAL;
    }

    /* Copy oldpath from userspace to kernel space */
    char old_buf[256];
    if (fut_copy_from_user(old_buf, local_oldpath, sizeof(old_buf) - 1) != 0) {
        fut_printf("[LINK] link(oldpath=?, newpath=?) -> EFAULT "
                   "(copy_from_user failed for oldpath, Phase 2)\n");
        return -EFAULT;
    }
    old_buf[sizeof(old_buf) - 1] = '\0';

    /* Copy newpath from userspace to kernel space */
    char new_buf[256];
    if (fut_copy_from_user(new_buf, local_newpath, sizeof(new_buf) - 1) != 0) {
        fut_printf("[LINK] link(oldpath='%s', newpath=?) -> EFAULT "
                   "(copy_from_user failed for newpath, Phase 2)\n", old_buf);
        return -EFAULT;
    }
    new_buf[sizeof(new_buf) - 1] = '\0';

    /* Phase 2: Validate oldpath is not empty */
    if (old_buf[0] == '\0') {
        fut_printf("[LINK] link(oldpath=\"\" [empty], newpath='%s') -> EINVAL "
                   "(empty oldpath, Phase 2)\n", new_buf);
        return -EINVAL;
    }

    /* Phase 2: Validate newpath is not empty */
    if (new_buf[0] == '\0') {
        fut_printf("[LINK] link(oldpath='%s', newpath=\"\" [empty]) -> EINVAL "
                   "(empty newpath, Phase 2)\n", old_buf);
        return -EINVAL;
    }

    /* Phase 2: Categorize oldpath type */
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

    /* Phase 2: Categorize newpath type */
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

    /* Phase 3: Lookup oldpath (existing file to hard link to) */
    struct fut_vnode *old_vnode = NULL;
    int old_lookup_ret = fut_vfs_lookup(old_buf, &old_vnode);

    if (old_lookup_ret < 0) {
        /* Return appropriate error code for oldpath lookup failure */
        const char *error_desc;
        switch (old_lookup_ret) {
            case -ENOENT:
                error_desc = "oldpath not found or path component missing";
                break;
            case -ENOTDIR:
                error_desc = "oldpath component not a directory";
                break;
            case -ENAMETOOLONG:
                error_desc = "oldpath too long";
                break;
            case -EACCES:
                error_desc = "search permission denied on oldpath component";
                break;
            default:
                error_desc = "oldpath lookup failed";
                break;
        }

        fut_printf("[LINK] link(oldpath='%s' [%s], newpath='%s' [%s]) -> %d "
                   "(%s, Phase 3)\n",
                   old_buf, old_path_type, new_buf, new_path_type, old_lookup_ret, error_desc);
        return old_lookup_ret;
    }

    if (!old_vnode) {
        fut_printf("[LINK] link(oldpath='%s' [%s], newpath='%s' [%s]) -> EINVAL "
                   "(oldpath vnode is NULL, Phase 3)\n",
                   old_buf, old_path_type, new_buf, new_path_type);
        return -EINVAL;
    }

    /* Phase 2: File type validation - cannot hard link directories */
    const char *file_type_desc;
    int would_fail_type_check = 0;
    int type_error = 0;

    switch (old_vnode->type) {
        case VN_REG:
            file_type_desc = "regular file";
            break;
        case VN_DIR:
            file_type_desc = "directory";
            would_fail_type_check = 1;
            type_error = -EISDIR;
            break;
        case VN_LNK:
            file_type_desc = "symbolic link";
            /* Note: link() operates on symlink itself, not target */
            break;
        case VN_CHR:
            file_type_desc = "character device";
            break;
        case VN_BLK:
            file_type_desc = "block device";
            break;
        case VN_FIFO:
            file_type_desc = "named pipe";
            break;
        case VN_SOCK:
            file_type_desc = "socket";
            break;
        default:
            file_type_desc = "unknown";
            would_fail_type_check = 1;
            type_error = -EINVAL;
            break;
    }

    /* Phase 2: Track link count for diagnostics */
    uint32_t current_nlinks = old_vnode->nlinks;
    uint32_t would_be_nlinks = current_nlinks + 1;

    /* Phase 2: Categorize link count */
    const char *link_count_category;
    if (current_nlinks == 1) {
        link_count_category = "single link (original only)";
    } else if (current_nlinks <= 5) {
        link_count_category = "few links (2-5)";
    } else if (current_nlinks <= 100) {
        link_count_category = "many links (6-100)";
    } else {
        link_count_category = "very many links (>100)";
    }

    /* Phase 3: File type validation - cannot hard link directories */
    if (would_fail_type_check) {
        fut_printf("[LINK] link(oldpath='%s' [%s, %s, nlinks=%u [%s]], "
                   "newpath='%s' [%s]) -> %d "
                   "(cannot hard link %s, Phase 3)\n",
                   old_buf, old_path_type, file_type_desc, current_nlinks,
                   link_count_category, new_buf, new_path_type, type_error, file_type_desc);
        return type_error;
    }

    /* Phase 3: Lookup newpath's parent directory to check filesystem compatibility */
    char new_parent_path[256];
    size_t new_parent_len = 0;
    int new_last_slash = -1;

    for (size_t i = 0; new_buf[i] != '\0'; i++) {
        if (new_buf[i] == '/') new_last_slash = (int)i;
    }

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

    struct fut_vnode *new_parent = NULL;
    int new_parent_lookup_ret = fut_vfs_lookup(new_parent_path, &new_parent);

    if (new_parent_lookup_ret < 0) {
        const char *error_desc;
        switch (new_parent_lookup_ret) {
            case -ENOENT:
                error_desc = "newpath parent not found";
                break;
            case -ENOTDIR:
                error_desc = "newpath parent component not a directory";
                break;
            default:
                error_desc = "newpath parent lookup failed";
                break;
        }
        fut_printf("[LINK] link(old='%s' [%s], new='%s' [%s]) -> %d "
                   "(%s)\n",
                   old_buf, old_path_type, new_buf, new_path_type,
                   new_parent_lookup_ret, error_desc);
        return new_parent_lookup_ret;
    }

    if (!new_parent) {
        fut_printf("[LINK] link(old='%s' [%s], new='%s' [%s]) -> EINVAL "
                   "(newpath parent vnode is NULL)\n",
                   old_buf, old_path_type, new_buf, new_path_type);
        return -EINVAL;
    }

    /* Phase 3: Check if both files are on same filesystem (EXDEV error for cross-fs) */
    if (old_vnode->mount != new_parent->mount) {
        fut_printf("[LINK] link(old='%s' [%s, %s], new='%s' [%s]) -> EXDEV "
                   "(different filesystems)\n",
                   old_buf, old_path_type, file_type_desc, new_buf, new_path_type);
        return -EXDEV;
    }

    /* Phase 3: Check if newpath already exists (will be checked by VFS layer too) */
    struct fut_vnode *new_vnode = NULL;
    int new_lookup_ret = fut_vfs_lookup(new_buf, &new_vnode);

    if (new_lookup_ret == 0 && new_vnode) {
        fut_printf("[LINK] link(oldpath='%s' [%s, %s, nlinks=%u [%s]], "
                   "newpath='%s' [%s]) -> EEXIST "
                   "(newpath already exists, Phase 3)\n",
                   old_buf, old_path_type, file_type_desc, current_nlinks,
                   link_count_category, new_buf, new_path_type);
        return -EEXIST;
    }

    /* Phase 3: Detailed logging before VFS integration */
    fut_printf("[LINK] link(oldpath='%s' [%s, %s, ino=%lu, nlinks=%u [%s]], "
               "newpath='%s' [%s]) attempting to create hard link "
               "(would increment nlinks %u->%u, Phase 3)\n",
               old_buf, old_path_type, file_type_desc, old_vnode->ino, current_nlinks,
               link_count_category, new_buf, new_path_type, current_nlinks, would_be_nlinks);

    /*
     * Phase 3: VFS Integration - Call filesystem-specific link operation
     *
     * The vnode's ops->link() function handles the actual hard link creation
     * in the filesystem (RamFS, FuturaFS, etc). We already have the target
     * vnode (old_vnode) and have validated that it's not a directory.
     */
    if (old_vnode->ops && old_vnode->ops->link) {
        int ret = old_vnode->ops->link(old_vnode, old_buf, new_buf);
        if (ret < 0) {
            const char *error_desc;
            switch (ret) {
                case -EEXIST:
                    error_desc = "newpath already exists";
                    break;
                case -ENOSPC:
                    error_desc = "no space for new directory entry";
                    break;
                /* case -EMLINK: TODO: Define EMLINK errno constant */
                /*    error_desc = "too many hard links to file";
                    break; */
                case -EROFS:
                    error_desc = "read-only filesystem";
                    break;
                case -ENOTDIR:
                    error_desc = "newpath parent is not a directory";
                    break;
                case -EACCES:
                    error_desc = "permission denied";
                    break;
                default:
                    error_desc = "link operation failed";
                    break;
            }
            fut_printf("[LINK] link(old='%s' [%s], new='%s' [%s], old_type=%s, "
                       "old_ino=%lu, old_nlinks=%u) -> %d (%s)\n",
                       old_buf, old_path_type, new_buf, new_path_type,
                       file_type_desc, old_vnode->ino, current_nlinks, ret, error_desc);
            return ret;
        }

        /* Success */
        fut_printf("[LINK] link(old='%s' [%s], new='%s' [%s], old_type=%s, "
                   "old_ino=%lu, old_nlinks=%u->%u) -> 0 (success)\n",
                   old_buf, old_path_type, new_buf, new_path_type,
                   file_type_desc, old_vnode->ino, current_nlinks, would_be_nlinks);
        return 0;
    }

    /* Filesystem doesn't support hard links */
    fut_printf("[LINK] link(old='%s' [%s], new='%s' [%s], old_type=%s, "
               "old_ino=%lu) -> ENOSYS (filesystem doesn't support link)\n",
               old_buf, old_path_type, new_buf, new_path_type,
               file_type_desc, old_vnode->ino);
    return -ENOSYS;
}
