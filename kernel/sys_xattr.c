/* kernel/sys_xattr.c - Extended attribute syscalls
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements extended attribute (xattr) syscalls for storing metadata on files.
 * Extended attributes store name-value pairs associated with filesystem objects.
 *
 * Phase 1 (Current): Validation and stub implementations
 * Phase 2: Implement actual xattr storage via vnode->ops->setxattr/getxattr
 * Phase 3: Add namespace validation and security checks
 * Phase 4: Performance optimization with caching
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <kernel/fut_vfs.h>
#include <stdint.h>
#include <stddef.h>

extern void fut_printf(const char *fmt, ...);
extern int fut_copy_from_user(void *to, const void *from, size_t size);
extern int fut_copy_to_user(void *to, const void *from, size_t size);

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
        fut_printf("[XATTR] setxattr(path=%p, name=%p, value=%p, size=%zu, flags=0x%x) "
                   "-> ESRCH (no current task)\n", path, name, value, size, flags);
        return -ESRCH;
    }

    /* Validate parameters */
    if (!path || !name || (!value && size > 0)) {
        fut_printf("[XATTR] setxattr(path=%p, name=%p, value=%p, size=%zu, flags=0x%x, pid=%d) "
                   "-> EINVAL (NULL pointer)\n", path, name, value, size, flags, task->pid);
        return -EINVAL;
    }

    /* Validate flags */
    if (flags & ~(XATTR_CREATE | XATTR_REPLACE)) {
        fut_printf("[XATTR] setxattr(path=%p, name=%p, size=%zu, flags=0x%x, pid=%d) "
                   "-> EINVAL (invalid flags)\n", path, name, size, flags, task->pid);
        return -EINVAL;
    }

    /* Validate size */
    if (size > XATTR_SIZE_MAX) {
        fut_printf("[XATTR] setxattr(path=%p, name=%p, size=%zu [too large], flags=0x%x, pid=%d) "
                   "-> E2BIG (value too large)\n", path, name, size, flags, task->pid);
        return -E2BIG;
    }

    /* Copy path from userspace */
    char path_buf[256];
    if (fut_copy_from_user(path_buf, path, sizeof(path_buf) - 1) != 0) {
        fut_printf("[XATTR] setxattr(path=? [bad addr], name=%p, size=%zu, pid=%d) "
                   "-> EFAULT\n", name, size, task->pid);
        return -EFAULT;
    }
    path_buf[sizeof(path_buf) - 1] = '\0';

    /* Copy name from userspace */
    char name_buf[XATTR_NAME_MAX + 1];
    if (fut_copy_from_user(name_buf, name, sizeof(name_buf) - 1) != 0) {
        fut_printf("[XATTR] setxattr(path='%s', name=? [bad addr], size=%zu, pid=%d) "
                   "-> EFAULT\n", path_buf, size, task->pid);
        return -EFAULT;
    }
    name_buf[sizeof(name_buf) - 1] = '\0';

    /* Validate name is not empty */
    if (name_buf[0] == '\0') {
        fut_printf("[XATTR] setxattr(path='%s', name='' [empty], size=%zu, pid=%d) "
                   "-> EINVAL\n", path_buf, size, task->pid);
        return -EINVAL;
    }

    /* Categorize flags */
    const char *flags_desc = (flags == 0) ? "none (create or replace)" :
                            (flags == XATTR_CREATE) ? "XATTR_CREATE" :
                            (flags == XATTR_REPLACE) ? "XATTR_REPLACE" :
                            "XATTR_CREATE|XATTR_REPLACE";

    /* Categorize size */
    const char *size_desc = (size == 0) ? "empty" :
                           (size < 256) ? "small (<256)" :
                           (size < 4096) ? "medium (<4KB)" :
                           "large (≥4KB)";

    /* Phase 1: Stub - accept and log */
    fut_printf("[XATTR] setxattr(path='%s', name='%s', size=%zu [%s], flags=%s, pid=%d) "
               "-> 0 (Phase 1 stub - not actually stored yet)\n",
               path_buf, name_buf, size, size_desc, flags_desc, task->pid);

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

    /* Phase 1: Same validation as setxattr */
    if (!path || !name || (!value && size > 0)) {
        return -EINVAL;
    }

    if (flags & ~(XATTR_CREATE | XATTR_REPLACE)) {
        return -EINVAL;
    }

    if (size > XATTR_SIZE_MAX) {
        return -E2BIG;
    }

    char path_buf[256];
    if (fut_copy_from_user(path_buf, path, sizeof(path_buf) - 1) != 0) {
        return -EFAULT;
    }
    path_buf[sizeof(path_buf) - 1] = '\0';

    char name_buf[XATTR_NAME_MAX + 1];
    if (fut_copy_from_user(name_buf, name, sizeof(name_buf) - 1) != 0) {
        return -EFAULT;
    }
    name_buf[sizeof(name_buf) - 1] = '\0';

    if (name_buf[0] == '\0') {
        return -EINVAL;
    }

    fut_printf("[XATTR] lsetxattr(path='%s', name='%s', size=%zu, flags=0x%x, pid=%d) "
               "-> 0 (Phase 1 stub - symlink variant)\n",
               path_buf, name_buf, size, flags, task->pid);

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

    /* Validate fd */
    if (fd < 0) {
        fut_printf("[XATTR] fsetxattr(fd=%d [invalid], name=%p, size=%zu, pid=%d) "
                   "-> EBADF\n", fd, name, size, task->pid);
        return -EBADF;
    }

    /* Phase 1: Same validation as setxattr */
    if (!name || (!value && size > 0)) {
        return -EINVAL;
    }

    if (flags & ~(XATTR_CREATE | XATTR_REPLACE)) {
        return -EINVAL;
    }

    if (size > XATTR_SIZE_MAX) {
        return -E2BIG;
    }

    char name_buf[XATTR_NAME_MAX + 1];
    if (fut_copy_from_user(name_buf, name, sizeof(name_buf) - 1) != 0) {
        return -EFAULT;
    }
    name_buf[sizeof(name_buf) - 1] = '\0';

    if (name_buf[0] == '\0') {
        return -EINVAL;
    }

    fut_printf("[XATTR] fsetxattr(fd=%d, name='%s', size=%zu, flags=0x%x, pid=%d) "
               "-> 0 (Phase 1 stub)\n", fd, name_buf, size, flags, task->pid);

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

    /* Suppress unused warnings for Phase 1 stub */
    (void)value;

    if (!path || !name) {
        return -EINVAL;
    }

    char path_buf[256];
    if (fut_copy_from_user(path_buf, path, sizeof(path_buf) - 1) != 0) {
        return -EFAULT;
    }
    path_buf[sizeof(path_buf) - 1] = '\0';

    char name_buf[XATTR_NAME_MAX + 1];
    if (fut_copy_from_user(name_buf, name, sizeof(name_buf) - 1) != 0) {
        return -EFAULT;
    }
    name_buf[sizeof(name_buf) - 1] = '\0';

    if (name_buf[0] == '\0') {
        return -EINVAL;
    }

    /* Phase 1: Return ENODATA (attribute doesn't exist) */
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

    /* Suppress unused warnings for Phase 1 stub */
    (void)value;

    if (!path || !name) {
        return -EINVAL;
    }

    char path_buf[256];
    if (fut_copy_from_user(path_buf, path, sizeof(path_buf) - 1) != 0) {
        return -EFAULT;
    }
    path_buf[sizeof(path_buf) - 1] = '\0';

    char name_buf[XATTR_NAME_MAX + 1];
    if (fut_copy_from_user(name_buf, name, sizeof(name_buf) - 1) != 0) {
        return -EFAULT;
    }
    name_buf[sizeof(name_buf) - 1] = '\0';

    if (name_buf[0] == '\0') {
        return -EINVAL;
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

    /* Suppress unused warnings for Phase 1 stub */
    (void)value;

    if (fd < 0) {
        return -EBADF;
    }

    if (!name) {
        return -EINVAL;
    }

    char name_buf[XATTR_NAME_MAX + 1];
    if (fut_copy_from_user(name_buf, name, sizeof(name_buf) - 1) != 0) {
        return -EFAULT;
    }
    name_buf[sizeof(name_buf) - 1] = '\0';

    if (name_buf[0] == '\0') {
        return -EINVAL;
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

    /* Suppress unused warnings for Phase 1 stub */
    (void)list;

    if (!path) {
        return -EINVAL;
    }

    char path_buf[256];
    if (fut_copy_from_user(path_buf, path, sizeof(path_buf) - 1) != 0) {
        return -EFAULT;
    }
    path_buf[sizeof(path_buf) - 1] = '\0';

    /* Phase 1: Return 0 (no attributes) */
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

    /* Suppress unused warnings for Phase 1 stub */
    (void)list;

    if (!path) {
        return -EINVAL;
    }

    char path_buf[256];
    if (fut_copy_from_user(path_buf, path, sizeof(path_buf) - 1) != 0) {
        return -EFAULT;
    }
    path_buf[sizeof(path_buf) - 1] = '\0';

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

    char path_buf[256];
    if (fut_copy_from_user(path_buf, path, sizeof(path_buf) - 1) != 0) {
        return -EFAULT;
    }
    path_buf[sizeof(path_buf) - 1] = '\0';

    char name_buf[XATTR_NAME_MAX + 1];
    if (fut_copy_from_user(name_buf, name, sizeof(name_buf) - 1) != 0) {
        return -EFAULT;
    }
    name_buf[sizeof(name_buf) - 1] = '\0';

    if (name_buf[0] == '\0') {
        return -EINVAL;
    }

    /* Phase 1: Return ENODATA (attribute doesn't exist) */
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

    char path_buf[256];
    if (fut_copy_from_user(path_buf, path, sizeof(path_buf) - 1) != 0) {
        return -EFAULT;
    }
    path_buf[sizeof(path_buf) - 1] = '\0';

    char name_buf[XATTR_NAME_MAX + 1];
    if (fut_copy_from_user(name_buf, name, sizeof(name_buf) - 1) != 0) {
        return -EFAULT;
    }
    name_buf[sizeof(name_buf) - 1] = '\0';

    if (name_buf[0] == '\0') {
        return -EINVAL;
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
    if (fut_copy_from_user(name_buf, name, sizeof(name_buf) - 1) != 0) {
        return -EFAULT;
    }
    name_buf[sizeof(name_buf) - 1] = '\0';

    if (name_buf[0] == '\0') {
        return -EINVAL;
    }

    fut_printf("[XATTR] fremovexattr(fd=%d, name='%s', pid=%d) "
               "-> ENODATA (Phase 1 stub)\n", fd, name_buf, task->pid);

    return -ENODATA;
}
