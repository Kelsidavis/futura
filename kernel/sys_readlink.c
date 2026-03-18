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
#include <string.h>

#include <kernel/kprintf.h>
#include <kernel/uaccess.h>
#include <kernel/fut_memory.h>

#ifdef __x86_64__
#include <platform/x86_64/memory/paging.h>
#elif defined(__aarch64__)
#include <platform/arm64/memory/paging.h>
#endif
static inline int readlink_copy_from_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)src >= KERNEL_VIRTUAL_BASE) { __builtin_memcpy(dst, src, n); return 0; }
#endif
    return fut_copy_from_user(dst, src, n);
}
static inline int readlink_copy_to_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)dst >= KERNEL_VIRTUAL_BASE) { __builtin_memcpy(dst, src, n); return 0; }
#endif
    return fut_copy_to_user(dst, src, n);
}

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
    char path_buf[FUT_VFS_PATH_BUFFER_SIZE];
    if (readlink_copy_from_user(path_buf, local_path, sizeof(path_buf)) != 0) {
        fut_printf("[READLINK] readlink(path=?, buf=?, bufsiz=%zu [%s]) -> EFAULT "
                   "(path copy_from_user failed)\n", local_bufsiz, bufsiz_category);
        return -EFAULT;
    }
    /* Verify path was not truncated */
    if (memchr(path_buf, '\0', sizeof(path_buf)) == NULL) {
        fut_printf("[READLINK] readlink(path exceeds %zu bytes) -> ENAMETOOLONG\n", sizeof(path_buf) - 1);
        return -ENAMETOOLONG;
    }

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

    /* Phase 2: Categorize path length */
    size_t path_len = strlen(path_buf);
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
     * Phase 3 (Completed): VFS symbolic link support
     *
     * Use VFS readlink helper so final component is not followed.
     */

    /* Allocate kernel buffer for readlink result */
    char *target_buf = fut_malloc(local_bufsiz);
    if (!target_buf) {
        return -ENOMEM;
    }

    /* Read symbolic link target without following the final component */
    ssize_t len = fut_vfs_readlink(path_buf, target_buf, local_bufsiz);
    if (len < 0) {
        const char *error_desc;
        switch ((int)len) {
            case -ENOENT:
                error_desc = "symbolic link not found";
                break;
            case -ENOTDIR:
                error_desc = "path component not a directory";
                break;
            case -EACCES:
                error_desc = "permission denied";
                break;
            case -EINVAL:
                error_desc = "not a symbolic link";
                break;
            case -ENOSYS:
                error_desc = "filesystem doesn't support readlink";
                break;
            default:
                error_desc = "readlink operation failed";
                break;
        }
        fut_printf("[READLINK] readlink(path='%s' [%s, %s], bufsiz=%zu [%s]) -> %d (%s, Phase 3: VFS readlink operation)\n",
                   path_buf, path_type, length_category, local_bufsiz, bufsiz_category,
                   (int)len, error_desc);
        fut_free(target_buf);
        return len;
    }

    /* Validate VFS return length BEFORE using it
     * VULNERABILITY: Buffer Overrun via Untrusted VFS Return Value
     *
     * ATTACK SCENARIO:
     * Malicious or buggy filesystem's readlink operation returns len > bufsiz
     * 1. Line 288: Kernel allocates target_buf with size = local_bufsiz (e.g., 256 bytes)
     * 2. Line 294: vnode->ops->readlink(vnode, target_buf, 256) called
     * 3. Malicious VFS returns len = 512 (claims to have read 512 bytes)
     * 4. WITHOUT check:
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
     * DEFENSE LAYER 1: Validate len <= bufsiz
     * Check returned length doesn't exceed allocated buffer size
     * Prevents reading beyond kernel buffer (information disclosure)
     * Critical for FUSE and network filesystems */
    if (len > (ssize_t)local_bufsiz) {
        fut_printf("[READLINK] readlink(path='%s', bufsiz=%zu) -> ENAMETOOLONG "
                   "(returned length %zd exceeds buffer size)\n",
                   path_buf, local_bufsiz, len);
        fut_free(target_buf);
        return -ENAMETOOLONG;
    }

    /* DEFENSE LAYER 2: Validate len <= PATH_MAX
     * Symlinks with targets exceeding PATH_MAX (4096 bytes) are invalid
     * Prevents pathologically long symlink targets
     * Secondary defense if bufsiz > PATH_MAX */
    #define PATH_MAX 4096
    if (len > PATH_MAX) {
        fut_printf("[READLINK] readlink(path='%s') -> ENAMETOOLONG "
                   "(symlink target length %zd exceeds PATH_MAX %d)\n",
                   path_buf, len, PATH_MAX);
        fut_free(target_buf);
        return -ENAMETOOLONG;
    }

    /* Copy result to userspace buffer */
    if (readlink_copy_to_user(local_buf, target_buf, len) != 0) {
        fut_free(target_buf);
        return -EFAULT;
    }

    /* Clean up and return bytes read */
    fut_free(target_buf);

    fut_printf("[READLINK] readlink(path='%s' [%s, %s], bufsiz=%zu [%s], "
               "target_len=%zd) -> %zd (Phase 3: VFS readlink operation)\n",
               path_buf, path_type, length_category, local_bufsiz, bufsiz_category,
               len, len);
    return len;
}
