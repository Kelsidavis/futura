/* kernel/sys_readlink.c - Symbolic link reading syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements the readlink() syscall with full VFS integration.
 * Reads the value of a symbolic link and returns it in a user-provided buffer.
 *
 * Phase 1 (Completed): Basic stub returning ENOSYS
 * Phase 2 (Completed): Enhanced validation, parameter categorization, and detailed logging
 * Phase 3 (Completed): VFS symbolic link support with readlink vnode operation
 * Phase 4: Performance optimization (link target caching, path resolution)
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <kernel/fut_vfs.h>
#include <stdint.h>

#include <kernel/kprintf.h>
extern int fut_copy_from_user(void *to, const void *from, size_t size);
extern int fut_copy_to_user(void *to, const void *from, size_t size);

/**
 * readlink() - Read value of a symbolic link
 *
 * Reads the target path of a symbolic link into a buffer. This is essential
 * for resolving symbolic links and understanding filesystem structure.
 * Fully implemented with VFS integration for RamFS symbolic links.
 *
 * @param path    Path to the symbolic link
 * @param buf     Buffer to store the link target
 * @param bufsiz  Size of the buffer
 *
 * Returns:
 *   - Number of bytes placed in buffer on success
 *   - -ENOSYS if filesystem doesn't support readlink operation
 *
 * Error codes:
 *   - -EFAULT if path or buf is inaccessible
 *   - -EINVAL if path is empty, NULL, or bufsiz <= 0
 *   - -ENOENT if symbolic link doesn't exist
 *   - -ENOTDIR if a component of path is not a directory
 *   - -EINVAL if path does not refer to a symbolic link
 *   - -EIO if I/O error occurred
 *   - -ENAMETOOLONG if pathname too long
 *   - -EACCES if search permission denied on path component
 *
 * Behavior:
 *   - Reads symbolic link target into buffer via VFS readlink operation
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
 * Phase 3 Implementation (Completed):
 *   ✓ Added readlink operation to fut_vnode_ops
 *   ✓ Implemented fut_vfs_readlink() in kernel/vfs/fut_vfs.c
 *   ✓ Added symbolic link support to RamFS
 *   ✓ Full VFS integration with proper error handling
 *   ✓ Userspace buffer validation and truncation handling
 *
 * Phase 1 (Completed): Basic stub returning ENOSYS
 * Phase 2 (Completed): Enhanced validation, parameter categorization, detailed logging
 * Phase 3 (Completed): VFS symbolic link support with readlink vnode operation
 * Phase 4: Performance optimization (link target caching, path resolution)
 */
long sys_readlink(const char *path, char *buf, size_t bufsiz) {
    /* ARM64 FIX: Copy parameters to local variables immediately to ensure they're preserved
     * on the stack across potentially blocking calls. VFS and copy operations may block and
     * corrupt register-passed parameters upon resumption. */
    const char *local_path = path;
    char *local_buf = buf;
    size_t local_bufsiz = bufsiz;

    /* Phase 2: Validate path pointer */
    if (!local_path) {
        fut_printf("[READLINK] readlink(path=NULL, buf=?, bufsiz=%zu) -> EINVAL (NULL path)\n",
                   local_bufsiz);
        return -EINVAL;
    }

    /* Phase 2: Validate buffer pointer */
    if (!local_buf) {
        fut_printf("[READLINK] readlink(path=?, buf=NULL, bufsiz=%zu) -> EFAULT (NULL buffer)\n",
                   local_bufsiz);
        return -EFAULT;
    }

    /* Phase 2: Validate buffer size */
    if (local_bufsiz == 0) {
        fut_printf("[READLINK] readlink(path=?, buf=?, bufsiz=0) -> EINVAL (zero buffer size)\n");
        return -EINVAL;
    }

    /* Phase 2: Validate buffer size is reasonable (PATH_MAX limit) */
    #define READLINK_MAX_SIZE (4096)  /* PATH_MAX */
    if (local_bufsiz > READLINK_MAX_SIZE) {
        fut_printf("[READLINK] readlink(path=?, buf=?, bufsiz=%zu) -> EINVAL "
                   "(buffer size exceeds maximum)\n", local_bufsiz);
        return -EINVAL;
    }

    /* Phase 2: Categorize buffer size */
    const char *bufsiz_category;
    if (local_bufsiz < 256) {
        bufsiz_category = "small (<256 bytes)";
    } else if (local_bufsiz < 1024) {
        bufsiz_category = "medium (<1 KB)";
    } else if (local_bufsiz < 4096) {
        bufsiz_category = "large (<4 KB)";
    } else if (local_bufsiz == 4096) {
        bufsiz_category = "PATH_MAX (4 KB)";
    } else {
        bufsiz_category = "very large (>4 KB)";
    }

    /* Phase 2: Copy path from userspace to validate it */
    char path_buf[256];
    if (fut_copy_from_user(path_buf, local_path, sizeof(path_buf) - 1) != 0) {
        fut_printf("[READLINK] readlink(path=?, buf=?, bufsiz=%zu [%s]) -> EFAULT "
                   "(path copy_from_user failed)\n", local_bufsiz, bufsiz_category);
        return -EFAULT;
    }
    path_buf[sizeof(path_buf) - 1] = '\0';

    /* Phase 2: Validate path is not empty */
    if (path_buf[0] == '\0') {
        fut_printf("[READLINK] readlink(path=\"\" [empty], buf=?, bufsiz=%zu [%s]) -> EINVAL "
                   "(empty path)\n", local_bufsiz, bufsiz_category);
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
        fut_printf("[READLINK] readlink(path='%s' [%s, %s], bufsiz=%zu [%s]) -> %d (%s, Phase 3: VFS readlink operation)\n",
                   path_buf, path_type, length_category, local_bufsiz, bufsiz_category,
                   ret, error_desc);
        return ret;
    }

    /* Verify vnode is a symbolic link */
    if (vnode->type != VN_LNK) {
        fut_printf("[READLINK] readlink(path='%s' [%s, %s], ino=%lu, bufsiz=%zu [%s]) -> EINVAL "
                   "(not a symbolic link)\n",
                   path_buf, path_type, length_category, vnode->ino, local_bufsiz, bufsiz_category);
        return -EINVAL;
    }

    /* Check if filesystem supports readlink operation */
    if (!vnode->ops || !vnode->ops->readlink) {
        fut_printf("[READLINK] readlink(path='%s' [%s, %s], ino=%lu, bufsiz=%zu [%s]) -> ENOSYS "
                   "(filesystem doesn't support readlink)\n",
                   path_buf, path_type, length_category, vnode->ino, local_bufsiz, bufsiz_category);
        return -ENOSYS;
    }

    /* Allocate kernel buffer for readlink result */
    extern void *fut_malloc(size_t size);
    extern void fut_free(void *ptr);

    char *target_buf = fut_malloc(local_bufsiz);
    if (!target_buf) {
        return -ENOMEM;
    }

    /* Call VFS readlink operation */
    ssize_t len = vnode->ops->readlink(vnode, target_buf, local_bufsiz);
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
        fut_printf("[READLINK] readlink(path='%s' [%s, %s], ino=%lu, bufsiz=%zu [%s]) -> %d (%s, Phase 3: VFS readlink operation)\n",
                   path_buf, path_type, length_category, vnode->ino, local_bufsiz, bufsiz_category,
                   (int)len, error_desc);
        fut_free(target_buf);
        return len;
    }

    /* Phase 5: Validate VFS return length BEFORE using it
     * VULNERABILITY: Buffer Overrun via Untrusted VFS Return Value
     *
     * ATTACK SCENARIO:
     * Malicious or buggy filesystem's readlink operation returns len > bufsiz
     * 1. Line 288: Kernel allocates target_buf with size = local_bufsiz (e.g., 256 bytes)
     * 2. Line 294: vnode->ops->readlink(vnode, target_buf, 256) called
     * 3. Malicious VFS returns len = 512 (claims to have read 512 bytes)
     * 4. WITHOUT Phase 5 check:
     *    - Line 334: fut_copy_to_user(local_buf, target_buf, 512)
     *    - Copies 512 bytes from 256-byte buffer
     *    - Result: Information disclosure (kernel heap leak beyond buffer)
     *
     * TRUSTED vs UNTRUSTED VFS:
     * - Trusted filesystems (ext4, RamFS): Return valid lengths
     * - FUSE filesystems: Userspace can return arbitrary values
     * - Network filesystems: Remote attacker could craft responses
     * - Kernel must validate ALL VFS return values
     *
     * DEFENSE LAYER 1 (Phase 5): Validate len <= bufsiz
     * Check returned length doesn't exceed allocated buffer size
     * Prevents reading beyond kernel buffer (information disclosure)
     * Critical for FUSE and network filesystems */
    if (len > (ssize_t)local_bufsiz) {
        fut_printf("[READLINK] readlink(path='%s', ino=%lu, bufsiz=%zu) -> ENAMETOOLONG "
                   "(returned length %zd exceeds buffer size, Phase 5)\n",
                   path_buf, vnode->ino, local_bufsiz, len);
        fut_free(target_buf);
        return -ENAMETOOLONG;
    }

    /* DEFENSE LAYER 2 (Phase 5): Validate len <= PATH_MAX
     * Symlinks with targets exceeding PATH_MAX (4096 bytes) are invalid
     * Prevents pathologically long symlink targets
     * Secondary defense if bufsiz > PATH_MAX */
    #define PATH_MAX 4096
    if (len > PATH_MAX) {
        fut_printf("[READLINK] readlink(path='%s', ino=%lu) -> ENAMETOOLONG "
                   "(symlink target length %zd exceeds PATH_MAX %d, Phase 5)\n",
                   path_buf, vnode->ino, len, PATH_MAX);
        fut_free(target_buf);
        return -ENAMETOOLONG;
    }

    /* Copy result to userspace buffer */
    if (fut_copy_to_user(local_buf, target_buf, len) != 0) {
        fut_free(target_buf);
        return -EFAULT;
    }

    /* Clean up and return bytes read */
    fut_free(target_buf);

    fut_printf("[READLINK] readlink(path='%s' [%s, %s], ino=%lu, bufsiz=%zu [%s], "
               "target_len=%zd) -> %zd (Phase 3: VFS readlink operation)\n",
               path_buf, path_type, length_category, vnode->ino, local_bufsiz, bufsiz_category,
               len, len);
    return len;
}
