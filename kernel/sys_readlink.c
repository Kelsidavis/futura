/* kernel/sys_readlink.c - Symbolic link reading syscall (stub)
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements the readlink() syscall stub. Full symbolic link support
 * is not yet implemented in the VFS layer, so this returns -ENOSYS.
 *
 * Phase 1 (Completed): Basic stub returning ENOSYS
 * Phase 2 (Current): Enhanced validation, parameter categorization, and detailed logging
 * Phase 3: VFS symbolic link support (readlink vnode operation)
 * Phase 4: Performance optimization (link target caching, path resolution)
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <kernel/fut_vfs.h>
#include <stdint.h>

extern void fut_printf(const char *fmt, ...);
extern int fut_copy_from_user(void *to, const void *from, size_t size);
extern int fut_copy_to_user(void *to, const void *from, size_t size);

/**
 * readlink() - Read value of a symbolic link (stub implementation)
 *
 * Reads the target path of a symbolic link into a buffer. This is essential
 * for resolving symbolic links and understanding filesystem structure.
 * This is currently a stub implementation that returns -ENOSYS because the
 * VFS layer does not yet have full symbolic link support.
 *
 * @param path    Path to the symbolic link
 * @param buf     Buffer to store the link target
 * @param bufsiz  Size of the buffer
 *
 * Returns:
 *   - Number of bytes placed in buffer on success (when implemented)
 *   - -ENOSYS (not implemented) - current stub behavior
 *
 * Future error codes (when implemented):
 *   - -EFAULT if path or buf is inaccessible
 *   - -EINVAL if path is empty, NULL, or bufsiz <= 0
 *   - -ENOENT if symbolic link doesn't exist
 *   - -ENOTDIR if a component of path is not a directory
 *   - -EINVAL if path does not refer to a symbolic link
 *   - -EIO if I/O error occurred
 *   - -ENAMETOOLONG if pathname too long
 *   - -EACCES if search permission denied on path component
 *
 * Behavior (when implemented):
 *   - Reads symbolic link target into buffer
 *   - Does not null-terminate the buffer
 *   - Returns number of bytes placed in buffer
 *   - If link target is longer than bufsiz, it is truncated
 *   - Does not follow the symbolic link (unlike stat)
 *   - Requires read permission on the symbolic link itself
 *
 * Buffer handling:
 *   - Buffer is NOT null-terminated
 *   - Caller must handle truncation
 *   - PATH_MAX is typical buffer size (4096 bytes)
 *   - Return value indicates actual length (may exceed bufsiz)
 *
 * Common usage patterns:
 *
 * Read symbolic link target:
 *   char target[PATH_MAX];
 *   ssize_t len = readlink("/path/to/link", target, sizeof(target));
 *   if (len >= 0) {
 *       target[len] = '\0';  // Null-terminate manually
 *       printf("Link points to: %s\n", target);
 *   }
 *
 * Check if path is a symbolic link:
 *   struct stat st;
 *   if (lstat(path, &st) == 0 && S_ISLNK(st.st_mode)) {
 *       char target[PATH_MAX];
 *       ssize_t len = readlink(path, target, sizeof(target));
 *       // ...
 *   }
 *
 * Resolve symbolic link chain:
 *   char current[PATH_MAX];
 *   strcpy(current, original_path);
 *   while (1) {
 *       char target[PATH_MAX];
 *       ssize_t len = readlink(current, target, sizeof(target));
 *       if (len < 0) {
 *           break;  // Not a symlink or error
 *       }
 *       target[len] = '\0';
 *       strcpy(current, target);
 *   }
 *
 * Safe readlink with truncation check:
 *   char target[PATH_MAX];
 *   ssize_t len = readlink(path, target, sizeof(target) - 1);
 *   if (len < 0) {
 *       // Error
 *   } else if (len >= sizeof(target) - 1) {
 *       // Truncated (target path too long)
 *   } else {
 *       target[len] = '\0';
 *       // Use target
 *   }
 *
 * Difference from stat/lstat:
 *   - readlink(): Returns link target path
 *   - lstat(): Returns link metadata (not target)
 *   - stat(): Follows link and returns target metadata
 *
 * Symbolic link types:
 *   - Absolute symlink: /usr/bin/python -> /usr/bin/python3.9
 *   - Relative symlink: docs/README -> ../README.md
 *   - Dangling symlink: broken -> /nonexistent (readlink succeeds, stat fails)
 *
 * Security considerations:
 *   - Check link target for path traversal attacks (../)
 *   - Validate link target before using
 *   - Watch for circular symlink chains
 *   - Symlinks can point outside chroot jail
 *
 * Related syscalls:
 *   - symlink(): Create symbolic link
 *   - lstat(): Get link metadata (not target)
 *   - readlinkat(): Read link relative to directory FD
 *   - realpath(): Resolve all symlinks in path
 *
 * TODO: Implement full symbolic link support in VFS layer:
 *   - Add readlink operation to fut_vnode_ops
 *   - Implement fut_vfs_readlink() in kernel/vfs/fut_vfs.c
 *   - Add symbolic link support to RamFS
 *   - Add symbolic link support to FuturaFS
 *   - Coordinate with symlink() implementation
 *
 * Phase 1 (Completed): Basic stub returning ENOSYS
 * Phase 2 (Current): Enhanced validation, parameter categorization, detailed logging
 * Phase 3: VFS symbolic link support (readlink vnode operation)
 * Phase 4: Performance optimization (link target caching, path resolution)
 */
long sys_readlink(const char *path, char *buf, size_t bufsiz) {
    /* Phase 2: Validate path pointer */
    if (!path) {
        fut_printf("[READLINK] readlink(path=NULL, buf=?, bufsiz=%zu) -> EINVAL (NULL path)\n",
                   bufsiz);
        return -EINVAL;
    }

    /* Phase 2: Validate buffer pointer */
    if (!buf) {
        fut_printf("[READLINK] readlink(path=?, buf=NULL, bufsiz=%zu) -> EFAULT (NULL buffer)\n",
                   bufsiz);
        return -EFAULT;
    }

    /* Phase 2: Validate buffer size */
    if (bufsiz == 0) {
        fut_printf("[READLINK] readlink(path=?, buf=?, bufsiz=0) -> EINVAL (zero buffer size)\n");
        return -EINVAL;
    }

    /* Phase 2: Categorize buffer size */
    const char *bufsiz_category;
    if (bufsiz < 256) {
        bufsiz_category = "small (<256 bytes)";
    } else if (bufsiz < 1024) {
        bufsiz_category = "medium (<1 KB)";
    } else if (bufsiz < 4096) {
        bufsiz_category = "large (<4 KB)";
    } else if (bufsiz == 4096) {
        bufsiz_category = "PATH_MAX (4 KB)";
    } else {
        bufsiz_category = "very large (>4 KB)";
    }

    /* Phase 2: Copy path from userspace to validate it */
    char path_buf[256];
    if (fut_copy_from_user(path_buf, path, sizeof(path_buf) - 1) != 0) {
        fut_printf("[READLINK] readlink(path=?, buf=?, bufsiz=%zu [%s]) -> EFAULT "
                   "(path copy_from_user failed)\n", bufsiz, bufsiz_category);
        return -EFAULT;
    }
    path_buf[sizeof(path_buf) - 1] = '\0';

    /* Phase 2: Validate path is not empty */
    if (path_buf[0] == '\0') {
        fut_printf("[READLINK] readlink(path=\"\" [empty], buf=?, bufsiz=%zu [%s]) -> EINVAL "
                   "(empty path)\n", bufsiz, bufsiz_category);
        return -EINVAL;
    }

    /* Phase 2: Categorize path type */
    const char *path_type;
    if (path_buf[0] == '/') {
        path_type = "absolute";
    } else if (path_buf[0] == '.' && path_buf[1] == '/') {
        path_type = "relative (explicit)";
    } else if (path_buf[0] == '.') {
        path_type = "relative (current/parent)";
    } else {
        path_type = "relative";
    }

    /* Phase 2: Calculate path length */
    size_t path_len = 0;
    while (path_buf[path_len] != '\0' && path_len < 256) {
        path_len++;
    }

    /* Phase 2: Categorize path length */
    const char *length_category;
    if (path_len <= 16) {
        length_category = "short (≤16 chars)";
    } else if (path_len <= 64) {
        length_category = "medium (≤64 chars)";
    } else if (path_len <= 128) {
        length_category = "long (≤128 chars)";
    } else {
        length_category = "very long (>128 chars)";
    }

    /*
     * Phase 3: VFS symbolic link support
     *
     * Lookup symlink vnode and call VFS readlink operation
     */

    /* Lookup the symbolic link vnode */
    struct fut_vnode *vnode = NULL;
    int ret = fut_vfs_lookup(path_buf, &vnode);
    if (ret < 0) {
        const char *error_desc;
        switch (ret) {
            case -ENOENT:
                error_desc = "symbolic link not found";
                break;
            case -ENOTDIR:
                error_desc = "path component not a directory";
                break;
            case -EACCES:
                error_desc = "permission denied";
                break;
            default:
                error_desc = "lookup failed";
                break;
        }
        fut_printf("[READLINK] readlink(path='%s' [%s, %s], bufsiz=%zu [%s]) -> %d (%s)\n",
                   path_buf, path_type, length_category, bufsiz, bufsiz_category,
                   ret, error_desc);
        return ret;
    }

    /* Verify vnode is a symbolic link */
    if (vnode->type != VN_LNK) {
        fut_printf("[READLINK] readlink(path='%s' [%s, %s], ino=%lu, bufsiz=%zu [%s]) -> EINVAL "
                   "(not a symbolic link)\n",
                   path_buf, path_type, length_category, vnode->ino, bufsiz, bufsiz_category);
        return -EINVAL;
    }

    /* Check if filesystem supports readlink operation */
    if (!vnode->ops || !vnode->ops->readlink) {
        fut_printf("[READLINK] readlink(path='%s' [%s, %s], ino=%lu, bufsiz=%zu [%s]) -> ENOSYS "
                   "(filesystem doesn't support readlink)\n",
                   path_buf, path_type, length_category, vnode->ino, bufsiz, bufsiz_category);
        return -ENOSYS;
    }

    /* Allocate kernel buffer for readlink result */
    extern void *fut_malloc(size_t size);
    extern void fut_free(void *ptr);

    char *target_buf = fut_malloc(bufsiz);
    if (!target_buf) {
        return -ENOMEM;
    }

    /* Call VFS readlink operation */
    ssize_t len = vnode->ops->readlink(vnode, target_buf, bufsiz);
    if (len < 0) {
        const char *error_desc;
        switch (len) {
            case -EIO:
                error_desc = "I/O error reading link";
                break;
            default:
                error_desc = "readlink operation failed";
                break;
        }
        fut_printf("[READLINK] readlink(path='%s' [%s, %s], ino=%lu, bufsiz=%zu [%s]) -> %d (%s)\n",
                   path_buf, path_type, length_category, vnode->ino, bufsiz, bufsiz_category,
                   (int)len, error_desc);
        fut_free(target_buf);
        return len;
    }

    /* Copy result to userspace buffer */
    if (fut_copy_to_user(buf, target_buf, len) != 0) {
        fut_free(target_buf);
        return -EFAULT;
    }

    /* Clean up and return bytes read */
    fut_free(target_buf);

    fut_printf("[READLINK] readlink(path='%s' [%s, %s], ino=%lu, bufsiz=%zu [%s], "
               "target_len=%zd) -> %zd (success)\n",
               path_buf, path_type, length_category, vnode->ino, bufsiz, bufsiz_category,
               len, len);
    return len;
}
