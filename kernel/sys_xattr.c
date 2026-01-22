/* kernel/sys_xattr.c - Extended attribute syscalls
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements extended attribute (xattr) syscalls for storing metadata on files.
 * Extended attributes store name-value pairs associated with filesystem objects.
 *
 * Phase 1 (Completed): Validation and stub implementations
 * Phase 2 (Completed): Implement actual xattr storage via vnode->ops->setxattr/getxattr
 * Phase 3: Add namespace validation and security checks
 * Phase 4: Performance optimization with caching
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <kernel/fut_vfs.h>
#include <stdint.h>
#include <stddef.h>

#include <kernel/kprintf.h>
#include <kernel/uaccess.h>

/* Error code for missing xattr */
#ifndef ENODATA
#define ENODATA 61  /* No data available */
#endif

/* Extended attribute flags */
#define XATTR_CREATE  0x1  /* Create new attribute (fail if exists) */
#define XATTR_REPLACE 0x2  /* Replace existing attribute (fail if doesn't exist) */

/* Common xattr namespaces */
#define XATTR_USER_PREFIX      "user."
#define XATTR_TRUSTED_PREFIX   "trusted."
#define XATTR_SECURITY_PREFIX  "security."
#define XATTR_SYSTEM_PREFIX    "system."

/* Maximum sizes */
#define XATTR_NAME_MAX  255    /* Maximum attribute name length */
#define XATTR_SIZE_MAX  65536  /* Maximum attribute value size (64KB) */
#define XATTR_LIST_MAX  65536  /* Maximum size for list operations */

/* ============================================================================
 * Internal Helper Functions
 * ============================================================================
 *
 * These helpers reduce code duplication across the 12 xattr syscall variants
 * (setxattr/lsetxattr/fsetxattr, getxattr/lgetxattr/fgetxattr, etc.)
 */

/**
 * xattr_copy_path_and_name - Copy path and attribute name from userspace
 *
 * @param path      Userspace path pointer
 * @param name      Userspace attribute name pointer
 * @param path_buf  Buffer to receive path (FUT_VFS_PATH_BUFFER_SIZE bytes)
 * @param name_buf  Buffer to receive name (XATTR_NAME_MAX + 1 bytes)
 * @param syscall   Syscall name for logging (e.g., "setxattr", "getxattr")
 *
 * Returns: 0 on success, negative errno on failure
 */
static inline long xattr_copy_path_and_name(const char *path, const char *name,
                                            char *path_buf, char *name_buf,
                                            const char *syscall) {
    fut_task_t *task = fut_task_current();
    int64_t pid = task ? (int64_t)task->pid : -1;

    /* Copy path from userspace */
    if (fut_copy_from_user(path_buf, path, FUT_VFS_PATH_BUFFER_SIZE - 1) != 0) {
        fut_printf("[XATTR] %s(path=? [bad addr], name=%p, pid=%d) -> EFAULT\n",
                   syscall, name, pid);
        return -EFAULT;
    }
    path_buf[FUT_VFS_PATH_BUFFER_SIZE - 1] = '\0';

    /* Copy name from userspace */
    if (fut_copy_from_user(name_buf, name, XATTR_NAME_MAX) != 0) {
        fut_printf("[XATTR] %s(path='%s', name=? [bad addr], pid=%d) -> EFAULT\n",
                   syscall, path_buf, pid);
        return -EFAULT;
    }
    name_buf[XATTR_NAME_MAX] = '\0';

    /* Validate name is not empty */
    if (name_buf[0] == '\0') {
        fut_printf("[XATTR] %s(path='%s', name='' [empty], pid=%d) -> EINVAL\n",
                   syscall, path_buf, pid);
        return -EINVAL;
    }

    return 0;
}

/**
 * xattr_copy_name - Copy attribute name from userspace (for fsetxattr/fgetxattr)
 *
 * @param name      Userspace attribute name pointer
 * @param name_buf  Buffer to receive name (XATTR_NAME_MAX + 1 bytes)
 * @param syscall   Syscall name for logging
 * @param fd        File descriptor for logging
 *
 * Returns: 0 on success, negative errno on failure
 */
static inline long xattr_copy_name(const char *name, char *name_buf,
                                   const char *syscall, int fd) {
    fut_task_t *task = fut_task_current();
    int64_t pid = task ? (int64_t)task->pid : -1;

    if (fut_copy_from_user(name_buf, name, XATTR_NAME_MAX) != 0) {
        fut_printf("[XATTR] %s(fd=%d, name=? [bad addr], pid=%d) -> EFAULT\n",
                   syscall, fd, pid);
        return -EFAULT;
    }
    name_buf[XATTR_NAME_MAX] = '\0';

    if (name_buf[0] == '\0') {
        fut_printf("[XATTR] %s(fd=%d, name='' [empty], pid=%d) -> EINVAL\n",
                   syscall, fd, pid);
        return -EINVAL;
    }

    return 0;
}

/**
 * xattr_validate_setxattr_flags - Validate setxattr flags and size
 *
 * @param flags     XATTR_CREATE | XATTR_REPLACE flags
 * @param size      Attribute value size
 * @param value     Attribute value pointer
 * @param syscall   Syscall name for logging
 *
 * Returns: 0 on success, negative errno on failure
 */
static inline long xattr_validate_setxattr_flags(int flags, size_t size,
                                                  const void *value,
                                                  const char *syscall) {
    fut_task_t *task = fut_task_current();
    int64_t pid = task ? (int64_t)task->pid : -1;

    /* Validate: value must be non-NULL if size > 0 */
    if (!value && size > 0) {
        fut_printf("[XATTR] %s(...) -> EINVAL (NULL value with size > 0, pid=%d)\n",
                   syscall, pid);
        return -EINVAL;
    }

    /* Validate flags */
    if (flags & ~(XATTR_CREATE | XATTR_REPLACE)) {
        fut_printf("[XATTR] %s(...) -> EINVAL (invalid flags=0x%x, pid=%d)\n",
                   syscall, flags, pid);
        return -EINVAL;
    }

    /* Validate size */
    if (size > XATTR_SIZE_MAX) {
        fut_printf("[XATTR] %s(...) -> E2BIG (size=%zu too large, pid=%d)\n",
                   syscall, size, pid);
        return -E2BIG;
    }

    return 0;
}

/**
 * xattr_get_flags_desc - Get human-readable description of xattr flags
 */
static inline const char *xattr_get_flags_desc(int flags) {
    return (flags == 0) ? "none (create or replace)" :
           (flags == XATTR_CREATE) ? "XATTR_CREATE" :
           (flags == XATTR_REPLACE) ? "XATTR_REPLACE" :
           "XATTR_CREATE|XATTR_REPLACE";
}

/**
 * xattr_get_size_desc - Get human-readable description of size category
 */
static inline const char *xattr_get_size_desc(size_t size) {
    return (size == 0) ? "empty" :
           (size < 256) ? "small (<256)" :
           (size < 4096) ? "medium (<4KB)" :
           "large (≥4KB)";
}

/**
 * xattr_copy_path - Copy path from userspace (for listxattr operations)
 *
 * @param path      Userspace path pointer
 * @param path_buf  Buffer to receive path (FUT_VFS_PATH_BUFFER_SIZE bytes)
 * @param syscall   Syscall name for logging
 *
 * Returns: 0 on success, negative errno on failure
 */
static inline long xattr_copy_path(const char *path, char *path_buf,
                                   const char *syscall) {
    fut_task_t *task = fut_task_current();
    int64_t pid = task ? (int64_t)task->pid : -1;

    if (fut_copy_from_user(path_buf, path, FUT_VFS_PATH_BUFFER_SIZE - 1) != 0) {
        fut_printf("[XATTR] %s(path=? [bad addr], pid=%d) -> EFAULT\n",
                   syscall, pid);
        return -EFAULT;
    }
    path_buf[FUT_VFS_PATH_BUFFER_SIZE - 1] = '\0';

    return 0;
}

/**
 * setxattr() - Set extended attribute value
 *
 * Sets the value of an extended attribute on a file specified by path.
 * Extended attributes are name-value pairs providing extra metadata beyond
 * traditional file attributes.
 *
 * @param path   Path to the file
 * @param name   Attribute name (namespace:attribute format, e.g. "user.comment")
 * @param value  Attribute value (arbitrary bytes)
 * @param size   Size of value in bytes
 * @param flags  XATTR_CREATE (fail if exists) or XATTR_REPLACE (fail if doesn't exist)
 *
 * Returns:
 *   - 0 on success
 *   - -ENOENT if file does not exist
 *   - -EEXIST if XATTR_CREATE and attribute exists
 *   - -ENODATA if XATTR_REPLACE and attribute doesn't exist
 *   - -ERANGE if name or value too large
 *   - -EINVAL if name is invalid or flags invalid
 *   - -EFAULT if path, name, or value points to inaccessible memory
 *   - -ENOSPC if no space for attribute
 *   - -ENOTSUP if filesystem doesn't support xattrs
 */
long sys_setxattr(const char *path, const char *name, const void *value,
                  size_t size, int flags) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_printf("[XATTR] setxattr(...) -> ESRCH (no current task)\n");
        return -ESRCH;
    }

    if (!path || !name) {
        fut_printf("[XATTR] setxattr(path=%p, name=%p, pid=%d) -> EINVAL (NULL pointer)\n",
                   path, name, task->pid);
        return -EINVAL;
    }

    /* Validate flags and size using helper */
    long ret = xattr_validate_setxattr_flags(flags, size, value, "setxattr");
    if (ret < 0) {
        return ret;
    }

    /* Copy path and name from userspace using helper */
    char path_buf[FUT_VFS_PATH_BUFFER_SIZE];
    char name_buf[XATTR_NAME_MAX + 1];
    ret = xattr_copy_path_and_name(path, name, path_buf, name_buf, "setxattr");
    if (ret < 0) {
        return ret;
    }

    /* Phase 1: Stub - accept and log */
    fut_printf("[XATTR] setxattr(path='%s', name='%s', size=%zu [%s], flags=%s, pid=%d) "
               "-> 0 (Phase 1 stub - not actually stored yet)\n",
               path_buf, name_buf, size, xattr_get_size_desc(size),
               xattr_get_flags_desc(flags), task->pid);

    return 0;
}

/**
 * lsetxattr() - Set extended attribute value (don't follow symlinks)
 *
 * Like setxattr(), but if path is a symbolic link, sets the attribute on the
 * link itself rather than the file it points to.
 */
long sys_lsetxattr(const char *path, const char *name, const void *value,
                   size_t size, int flags) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    if (!path || !name) {
        return -EINVAL;
    }

    long ret = xattr_validate_setxattr_flags(flags, size, value, "lsetxattr");
    if (ret < 0) {
        return ret;
    }

    char path_buf[FUT_VFS_PATH_BUFFER_SIZE];
    char name_buf[XATTR_NAME_MAX + 1];
    ret = xattr_copy_path_and_name(path, name, path_buf, name_buf, "lsetxattr");
    if (ret < 0) {
        return ret;
    }

    fut_printf("[XATTR] lsetxattr(path='%s', name='%s', size=%zu [%s], flags=%s, pid=%d) "
               "-> 0 (Phase 1 stub - symlink variant)\n",
               path_buf, name_buf, size, xattr_get_size_desc(size),
               xattr_get_flags_desc(flags), task->pid);

    return 0;
}

/**
 * fsetxattr() - Set extended attribute value via file descriptor
 *
 * Like setxattr(), but operates on an open file descriptor instead of a path.
 */
long sys_fsetxattr(int fd, const char *name, const void *value,
                   size_t size, int flags) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    if (fd < 0) {
        fut_printf("[XATTR] fsetxattr(fd=%d [invalid], pid=%d) -> EBADF\n",
                   fd, task->pid);
        return -EBADF;
    }

    if (!name) {
        return -EINVAL;
    }

    long ret = xattr_validate_setxattr_flags(flags, size, value, "fsetxattr");
    if (ret < 0) {
        return ret;
    }

    char name_buf[XATTR_NAME_MAX + 1];
    ret = xattr_copy_name(name, name_buf, "fsetxattr", fd);
    if (ret < 0) {
        return ret;
    }

    fut_printf("[XATTR] fsetxattr(fd=%d, name='%s', size=%zu [%s], flags=%s, pid=%d) "
               "-> 0 (Phase 1 stub)\n", fd, name_buf, size, xattr_get_size_desc(size),
               xattr_get_flags_desc(flags), task->pid);

    return 0;
}

/**
 * getxattr() - Get extended attribute value
 *
 * Retrieves the value of an extended attribute.
 *
 * @param path   Path to the file
 * @param name   Attribute name
 * @param value  Buffer to receive attribute value
 * @param size   Size of buffer (or 0 to query size)
 *
 * Returns:
 *   - Positive number = size of attribute value (copied to buffer if size > 0)
 *   - If size is 0, returns required buffer size without copying
 *   - -ENOENT if file does not exist
 *   - -ENODATA if attribute doesn't exist
 *   - -ERANGE if buffer too small
 *   - -EINVAL if name is invalid
 *   - -EFAULT if path, name, or value points to inaccessible memory
 */
long sys_getxattr(const char *path, const char *name, void *value, size_t size) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    (void)value;  /* Suppress unused warning for Phase 1 stub */

    if (!path || !name) {
        return -EINVAL;
    }

    char path_buf[FUT_VFS_PATH_BUFFER_SIZE];
    char name_buf[XATTR_NAME_MAX + 1];
    long ret = xattr_copy_path_and_name(path, name, path_buf, name_buf, "getxattr");
    if (ret < 0) {
        return ret;
    }

    fut_printf("[XATTR] getxattr(path='%s', name='%s', size=%zu, pid=%d) "
               "-> ENODATA (Phase 1 stub - no storage yet)\n",
               path_buf, name_buf, size, task->pid);

    return -ENODATA;
}

/**
 * lgetxattr() - Get extended attribute value (don't follow symlinks)
 */
long sys_lgetxattr(const char *path, const char *name, void *value, size_t size) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    (void)value;

    if (!path || !name) {
        return -EINVAL;
    }

    char path_buf[FUT_VFS_PATH_BUFFER_SIZE];
    char name_buf[XATTR_NAME_MAX + 1];
    long ret = xattr_copy_path_and_name(path, name, path_buf, name_buf, "lgetxattr");
    if (ret < 0) {
        return ret;
    }

    fut_printf("[XATTR] lgetxattr(path='%s', name='%s', size=%zu, pid=%d) "
               "-> ENODATA (Phase 1 stub - symlink variant)\n",
               path_buf, name_buf, size, task->pid);

    return -ENODATA;
}

/**
 * fgetxattr() - Get extended attribute value via file descriptor
 */
long sys_fgetxattr(int fd, const char *name, void *value, size_t size) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    (void)value;

    if (fd < 0) {
        return -EBADF;
    }

    if (!name) {
        return -EINVAL;
    }

    char name_buf[XATTR_NAME_MAX + 1];
    long ret = xattr_copy_name(name, name_buf, "fgetxattr", fd);
    if (ret < 0) {
        return ret;
    }

    fut_printf("[XATTR] fgetxattr(fd=%d, name='%s', size=%zu, pid=%d) "
               "-> ENODATA (Phase 1 stub)\n", fd, name_buf, size, task->pid);

    return -ENODATA;
}

/**
 * listxattr() - List extended attribute names
 *
 * Retrieves the list of extended attribute names associated with a file.
 * Names are returned as a sequence of null-terminated strings.
 *
 * @param path  Path to the file
 * @param list  Buffer to receive attribute names (null-separated)
 * @param size  Size of buffer (or 0 to query size)
 *
 * Returns:
 *   - Positive number = size of name list
 *   - If size is 0, returns required buffer size without copying
 *   - -ENOENT if file does not exist
 *   - -ERANGE if buffer too small
 */
long sys_listxattr(const char *path, char *list, size_t size) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    (void)list;

    if (!path) {
        return -EINVAL;
    }

    char path_buf[FUT_VFS_PATH_BUFFER_SIZE];
    long ret = xattr_copy_path(path, path_buf, "listxattr");
    if (ret < 0) {
        return ret;
    }

    fut_printf("[XATTR] listxattr(path='%s', size=%zu, pid=%d) "
               "-> 0 (Phase 1 stub - no attributes yet)\n",
               path_buf, size, task->pid);

    return 0;
}

/**
 * llistxattr() - List extended attribute names (don't follow symlinks)
 */
long sys_llistxattr(const char *path, char *list, size_t size) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    (void)list;

    if (!path) {
        return -EINVAL;
    }

    char path_buf[FUT_VFS_PATH_BUFFER_SIZE];
    long ret = xattr_copy_path(path, path_buf, "llistxattr");
    if (ret < 0) {
        return ret;
    }

    fut_printf("[XATTR] llistxattr(path='%s', size=%zu, pid=%d) "
               "-> 0 (Phase 1 stub - symlink variant)\n",
               path_buf, size, task->pid);

    return 0;
}

/**
 * flistxattr() - List extended attribute names via file descriptor
 */
long sys_flistxattr(int fd, char *list, size_t size) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    /* Suppress unused warnings for Phase 1 stub */
    (void)list;

    if (fd < 0) {
        return -EBADF;
    }

    fut_printf("[XATTR] flistxattr(fd=%d, size=%zu, pid=%d) "
               "-> 0 (Phase 1 stub)\n", fd, size, task->pid);

    return 0;
}

/**
 * removexattr() - Remove extended attribute
 *
 * Removes an extended attribute from a file.
 *
 * @param path  Path to the file
 * @param name  Attribute name to remove
 *
 * Returns:
 *   - 0 on success
 *   - -ENOENT if file does not exist
 *   - -ENODATA if attribute doesn't exist
 */
long sys_removexattr(const char *path, const char *name) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    if (!path || !name) {
        return -EINVAL;
    }

    char path_buf[FUT_VFS_PATH_BUFFER_SIZE];
    char name_buf[XATTR_NAME_MAX + 1];
    long ret = xattr_copy_path_and_name(path, name, path_buf, name_buf, "removexattr");
    if (ret < 0) {
        return ret;
    }

    fut_printf("[XATTR] removexattr(path='%s', name='%s', pid=%d) "
               "-> ENODATA (Phase 1 stub - no storage yet)\n",
               path_buf, name_buf, task->pid);

    return -ENODATA;
}

/**
 * lremovexattr() - Remove extended attribute (don't follow symlinks)
 */
long sys_lremovexattr(const char *path, const char *name) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    if (!path || !name) {
        return -EINVAL;
    }

    char path_buf[FUT_VFS_PATH_BUFFER_SIZE];
    char name_buf[XATTR_NAME_MAX + 1];
    long ret = xattr_copy_path_and_name(path, name, path_buf, name_buf, "lremovexattr");
    if (ret < 0) {
        return ret;
    }

    fut_printf("[XATTR] lremovexattr(path='%s', name='%s', pid=%d) "
               "-> ENODATA (Phase 1 stub - symlink variant)\n",
               path_buf, name_buf, task->pid);

    return -ENODATA;
}

/**
 * fremovexattr() - Remove extended attribute via file descriptor
 */
long sys_fremovexattr(int fd, const char *name) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    if (fd < 0) {
        return -EBADF;
    }

    if (!name) {
        return -EINVAL;
    }

    char name_buf[XATTR_NAME_MAX + 1];
    long ret = xattr_copy_name(name, name_buf, "fremovexattr", fd);
    if (ret < 0) {
        return ret;
    }

    fut_printf("[XATTR] fremovexattr(fd=%d, name='%s', pid=%d) "
               "-> ENODATA (Phase 1 stub)\n", fd, name_buf, task->pid);

    return -ENODATA;
}
