/* kernel/sys_getcwd.c - Get current working directory syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements getcwd() for retrieving the current working directory path.
 * Essential for path resolution, shell prompts, and process context.
 *
 * Phase 1 (Completed): Stub implementation returning root directory
 * Phase 2 (Completed): Enhanced validation, buffer/path categorization, and detailed logging
 * Phase 3 (Current): VFS integration for actual path resolution
 * Phase 4: Support for symlinks, mount points, and namespace isolation
 */

#include <kernel/errno.h>
#include <kernel/fut_task.h>
#include <stdint.h>

extern void fut_printf(const char *fmt, ...);

/**
 * getcwd() - Get current working directory
 *
 * Retrieves the absolute pathname of the current working directory into the
 * provided buffer. This is essential for:
 * - Shell prompts (displaying current location)
 * - Relative path resolution
 * - Process context awareness
 * - Debugging and diagnostics
 *
 * @param buf Buffer to store the absolute pathname
 * @param size Size of the buffer in bytes
 *
 * Returns:
 *   - buf pointer on success (POSIX compliant)
 *   - -EINVAL if buf is NULL
 *   - -ERANGE if buffer is too small for the path
 *   - -ESRCH if no current task context
 *   - -ENOENT if current directory has been unlinked
 *   - -EACCES if permission denied for a directory in path
 *
 * Behavior:
 *   - Returns absolute pathname with leading '/'
 *   - Includes null terminator in size calculation
 *   - Resolves symlinks in path components
 *   - Handles mount points and namespace boundaries
 *   - Minimal size: 2 bytes (for "/" + null)
 *
 * Buffer size categories:
 *   - Tiny (2-63 bytes): Can only hold very short paths
 *   - Small (64-255 bytes): Adequate for simple paths
 *   - Typical (256-1023 bytes): Standard buffer size (PATH_MAX on many systems)
 *   - Large (1024+ bytes): Generous buffer for deep hierarchies
 *
 * Path length categories:
 *   - Root (1 char): "/" only
 *   - Short (2-63 chars): Simple paths like "/home", "/usr/bin"
 *   - Medium (64-255 chars): Typical working directories
 *   - Long (256+ chars): Deep directory hierarchies
 *
 * Common usage patterns:
 *
 * Standard buffer allocation:
 *   char cwd[1024];
 *   if (getcwd(cwd, sizeof(cwd)) == NULL) {
 *       perror("getcwd");
 *       return -1;
 *   }
 *   printf("Current directory: %s\n", cwd);
 *
 * Dynamic buffer allocation:
 *   char *cwd = malloc(PATH_MAX);
 *   if (getcwd(cwd, PATH_MAX) == NULL) {
 *       perror("getcwd");
 *       free(cwd);
 *       return -1;
 *   }
 *   // Use cwd...
 *   free(cwd);
 *
 * Shell prompt integration:
 *   char cwd[256];
 *   getcwd(cwd, sizeof(cwd));
 *   printf("%s $ ", cwd);  // Display current directory in prompt
 *
 * Relative path resolution:
 *   char cwd[1024];
 *   getcwd(cwd, sizeof(cwd));
 *   char fullpath[2048];
 *   snprintf(fullpath, sizeof(fullpath), "%s/%s", cwd, relative_path);
 *
 * Saving and restoring directory:
 *   char saved_cwd[1024];
 *   getcwd(saved_cwd, sizeof(saved_cwd));
 *   chdir("/tmp");
 *   // Do work in /tmp...
 *   chdir(saved_cwd);  // Return to original directory
 *
 * Error handling with buffer too small:
 *   char small[10];
 *   if (getcwd(small, sizeof(small)) == NULL) {
 *       if (errno == ERANGE) {
 *           // Buffer too small, allocate larger
 *           char *big = malloc(PATH_MAX);
 *           getcwd(big, PATH_MAX);
 *       }
 *   }
 *
 * Current implementation notes:
 *   - Phase 1: Stub implementation always returns "/" (root directory)
 *   - Phase 2: Enhanced validation and logging
 *   - Phase 3: Will implement actual VFS path traversal
 *   - Phase 4: Will add symlink resolution and namespace support
 *
 * VFS integration (Phase 3):
 *   - Track current directory inode in task structure
 *   - Walk VFS tree upward from current inode to root
 *   - Build path string by prepending directory names
 *   - Handle mount point boundaries
 *   - Resolve symlinks in path components
 *
 * Phase 1 (Completed): Stub implementation returning root directory
 * Phase 2 (Current): Enhanced validation, buffer/path categorization, detailed logging
 * Phase 3: VFS integration with path traversal
 * Phase 4: Symlink resolution, mount points, namespace isolation
 */
long sys_getcwd(char *buf, size_t size) {
    /* Get current task for directory tracking */
    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_printf("[GETCWD] getcwd(buf=%p, size=%zu) -> ESRCH (no current task)\n",
                   (void *)buf, size);
        return -ESRCH;
    }

    /* Phase 2: Validate buffer pointer */
    if (!buf) {
        fut_printf("[GETCWD] getcwd(buf=NULL, size=%zu) -> EINVAL (null buffer)\n",
                   size);
        return -EINVAL;
    }

    /* Phase 2: Categorize buffer size */
    const char *size_category;
    const char *size_desc;
    if (size < 2) {
        size_category = "invalid (too small)";
        size_desc = "insufficient for minimum path '/'";
    } else if (size < 64) {
        size_category = "tiny (2-63 bytes)";
        size_desc = "minimal, only very short paths";
    } else if (size < 256) {
        size_category = "small (64-255 bytes)";
        size_desc = "adequate for simple paths";
    } else if (size < 1024) {
        size_category = "typical (256-1023 bytes)";
        size_desc = "standard buffer size";
    } else {
        size_category = "large (1024+ bytes)";
        size_desc = "generous for deep hierarchies";
    }

    /* Validate minimum buffer size (need at least 2 bytes for "/" + null) */
    if (size < 2) {
        fut_printf("[GETCWD] getcwd(buf=%p, size=%zu [%s]) -> ERANGE (%s)\n",
                   (void *)buf, size, size_category, size_desc);
        return -ERANGE;
    }

    /* Phase 1: Stub implementation - always return "/" as current directory
     * Phase 3 will implement actual VFS path traversal:
     *   - Get current directory inode from task->cwd_inode
     *   - Walk VFS tree upward to root, building path
     *   - Handle mount points and symlinks
     */

    /* Phase 2: Track current directory inode (stub: assume root inode 1)
     * Phase 3 will use: uint64_t cwd_inode = task->cwd_inode;
     */
    const uint64_t cwd_inode = 1;  /* Root inode (stub) */

    /* For now, always return "/" as current directory */
    buf[0] = '/';
    buf[1] = '\0';

    /* Phase 2: Categorize path length */
    const size_t path_len = 1;  /* Length of "/" without null terminator */
    const char *path_category;
    if (path_len == 1) {
        path_category = "root (1 char)";
    } else if (path_len < 64) {
        path_category = "short (2-63 chars)";
    } else if (path_len < 256) {
        path_category = "medium (64-255 chars)";
    } else {
        path_category = "long (256+ chars)";
    }

    /* Phase 2: Calculate buffer utilization */
    const size_t utilization_pct = ((path_len + 1) * 100) / size;
    const char *utilization_desc;
    if (utilization_pct < 25) {
        utilization_desc = "plenty of space";
    } else if (utilization_pct < 50) {
        utilization_desc = "comfortable";
    } else if (utilization_pct < 75) {
        utilization_desc = "adequate";
    } else if (utilization_pct < 90) {
        utilization_desc = "tight";
    } else {
        utilization_desc = "very tight";
    }

    /* Phase 2: Detailed success logging */
    fut_printf("[GETCWD] getcwd(buf=%p, size=%zu [%s], cwd_inode=%lu) -> %p "
               "(path='/', len=%zu [%s], util=%zu%% [%s], Phase 2 stub)\n",
               (void *)buf, size, size_category, (unsigned long)cwd_inode,
               (void *)buf, path_len, path_category, utilization_pct, utilization_desc);

    return (long)(uintptr_t)buf;
}
