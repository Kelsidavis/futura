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
 * Phase 3 (Completed): Namespace validation and privilege checks for trusted/security namespaces
 * Phase 4: Performance optimization with caching
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <kernel/fut_vfs.h>
#include <kernel/fut_memory.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include <kernel/kprintf.h>
#include <kernel/uaccess.h>

#include <platform/platform.h>

static inline int xattr_copy_from_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)src >= KERNEL_VIRTUAL_BASE) { __builtin_memcpy(dst, src, n); return 0; }
#endif
    return fut_copy_from_user(dst, src, n);
}
static inline int xattr_copy_to_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)dst >= KERNEL_VIRTUAL_BASE) { __builtin_memcpy(dst, src, n); return 0; }
#endif
    return fut_copy_to_user(dst, src, n);
}

/* ============================================================================
 * Internal VFS helpers for xattr dispatch
 *
 * Each helper resolves a path/fd to a vnode then dispatches to the FS-specific
 * xattr op.  When the FS does not provide native xattr ops the generic
 * per-vnode linked-list storage is used as a fallback so that *every* vnode
 * (procfs, sysfs, overlayfs, etc.) can hold xattrs — critical for containers.
 * ============================================================================ */

/* Generic per-vnode xattr helpers (kernel/vfs/fut_vfs.c) */
extern int     vnode_generic_setxattr(struct fut_vnode *, const char *,
                                      const void *, size_t, int);
extern ssize_t vnode_generic_getxattr(struct fut_vnode *, const char *,
                                      void *, size_t);
extern ssize_t vnode_generic_listxattr(struct fut_vnode *, char *, size_t);
extern int     vnode_generic_removexattr(struct fut_vnode *, const char *);

/* Call setxattr on the vnode obtained from path (follows symlinks). */
static long vnode_setxattr_by_path(const char *path_buf, const char *name,
                                   const void *value, size_t size, int flags) {
    struct fut_vnode *vnode = NULL;
    int ret = fut_vfs_lookup(path_buf, &vnode);
    if (ret < 0) return (ret == -ENOENT) ? -ENOENT : ret;
    if (vnode->ops && vnode->ops->setxattr) {
        ret = vnode->ops->setxattr(vnode, name, value, size, flags);
    } else {
        ret = vnode_generic_setxattr(vnode, name, value, size, flags);
    }
    fut_vnode_unref(vnode);
    return ret;
}

/* Call getxattr on the vnode obtained from path (follows symlinks). */
static ssize_t vnode_getxattr_by_path(const char *path_buf, const char *name,
                                      void *kbuf, size_t size) {
    struct fut_vnode *vnode = NULL;
    int ret = fut_vfs_lookup(path_buf, &vnode);
    if (ret < 0) return (ret == -ENOENT) ? -ENOENT : ret;
    ssize_t r;
    if (vnode->ops && vnode->ops->getxattr) {
        r = vnode->ops->getxattr(vnode, name, kbuf, size);
    } else {
        r = vnode_generic_getxattr(vnode, name, kbuf, size);
    }
    fut_vnode_unref(vnode);
    return r;
}

/* Call listxattr on the vnode obtained from path (follows symlinks). */
static ssize_t vnode_listxattr_by_path(const char *path_buf, char *kbuf, size_t size) {
    struct fut_vnode *vnode = NULL;
    int ret = fut_vfs_lookup(path_buf, &vnode);
    if (ret < 0) return (ret == -ENOENT) ? -ENOENT : ret;
    ssize_t r;
    if (vnode->ops && vnode->ops->listxattr) {
        r = vnode->ops->listxattr(vnode, kbuf, size);
    } else {
        r = vnode_generic_listxattr(vnode, kbuf, size);
    }
    fut_vnode_unref(vnode);
    return r;
}

/* Call removexattr on the vnode obtained from path (follows symlinks). */
static long vnode_removexattr_by_path(const char *path_buf, const char *name) {
    struct fut_vnode *vnode = NULL;
    int ret = fut_vfs_lookup(path_buf, &vnode);
    if (ret < 0) return (ret == -ENOENT) ? -ENOENT : ret;
    if (vnode->ops && vnode->ops->removexattr) {
        ret = vnode->ops->removexattr(vnode, name);
    } else {
        ret = vnode_generic_removexattr(vnode, name);
    }
    fut_vnode_unref(vnode);
    return ret;
}

/* Call setxattr on the vnode obtained from path (does NOT follow final symlink). */
static long vnode_setxattr_nofollow(const char *path_buf, const char *name,
                                    const void *value, size_t size, int flags) {
    struct fut_vnode *vnode = NULL;
    int ret = fut_vfs_lookup_nofollow(path_buf, &vnode);
    if (ret < 0) return ret;
    if (vnode->ops && vnode->ops->setxattr) {
        ret = vnode->ops->setxattr(vnode, name, value, size, flags);
    } else {
        ret = vnode_generic_setxattr(vnode, name, value, size, flags);
    }
    fut_vnode_unref(vnode);
    return ret;
}

/* Call getxattr on the vnode obtained from path (does NOT follow final symlink). */
static ssize_t vnode_getxattr_nofollow(const char *path_buf, const char *name,
                                       void *kbuf, size_t size) {
    struct fut_vnode *vnode = NULL;
    int ret = fut_vfs_lookup_nofollow(path_buf, &vnode);
    if (ret < 0) return ret;
    ssize_t r;
    if (vnode->ops && vnode->ops->getxattr) {
        r = vnode->ops->getxattr(vnode, name, kbuf, size);
    } else {
        r = vnode_generic_getxattr(vnode, name, kbuf, size);
    }
    fut_vnode_unref(vnode);
    return r;
}

/* Call listxattr on the vnode obtained from path (does NOT follow final symlink). */
static ssize_t vnode_listxattr_nofollow(const char *path_buf, char *kbuf, size_t size) {
    struct fut_vnode *vnode = NULL;
    int ret = fut_vfs_lookup_nofollow(path_buf, &vnode);
    if (ret < 0) return ret;
    ssize_t r;
    if (vnode->ops && vnode->ops->listxattr) {
        r = vnode->ops->listxattr(vnode, kbuf, size);
    } else {
        r = vnode_generic_listxattr(vnode, kbuf, size);
    }
    fut_vnode_unref(vnode);
    return r;
}

/* Call removexattr on the vnode obtained from path (does NOT follow final symlink). */
static long vnode_removexattr_nofollow(const char *path_buf, const char *name) {
    struct fut_vnode *vnode = NULL;
    int ret = fut_vfs_lookup_nofollow(path_buf, &vnode);
    if (ret < 0) return ret;
    if (vnode->ops && vnode->ops->removexattr) {
        ret = vnode->ops->removexattr(vnode, name);
    } else {
        ret = vnode_generic_removexattr(vnode, name);
    }
    fut_vnode_unref(vnode);
    return ret;
}

/* Resolve fd to vnode (caller must not unref — vnode is owned by the file). */
static struct fut_vnode *vnode_from_fd(struct fut_task *task, int fd) {
    if (fd < 0 || fd >= task->max_fds) return NULL;
    struct fut_file *file = vfs_get_file_from_task(task, fd);
    return file ? file->vnode : NULL;
}

/* ENODATA (61) provided by errno.h for missing xattr */

/* Extended attribute flags */
#define XATTR_CREATE  0x1  /* Create new attribute (fail if exists) */
#define XATTR_REPLACE 0x2  /* Replace existing attribute (fail if doesn't exist) */

/* Common xattr namespaces */
#define XATTR_USER_PREFIX      "user."
#define XATTR_TRUSTED_PREFIX   "trusted."
#define XATTR_SECURITY_PREFIX  "security."
#define XATTR_SYSTEM_PREFIX    "system."

/* Capability for privileged xattr namespaces */
#define CAP_SYS_ADMIN  21

/* Maximum sizes (also used below in helpers) */
#define XATTR_NAME_MAX  255    /* Maximum attribute name length */

/**
 * xattr_validate_namespace - Phase 3: Validate xattr name namespace and privileges
 *
 * Linux xattr names must belong to a known namespace separated by '.'.
 * The 'trusted.' and 'security.' namespaces require CAP_SYS_ADMIN or uid==0.
 *
 * @param name_buf  Null-terminated attribute name (already copied from userspace)
 * @param syscall   Syscall name for logging
 *
 * Returns: 0 on success, -ENOTSUP for unknown namespace, -EPERM if privileged
 *          namespace requires privileges the caller lacks.
 */
static long xattr_validate_namespace(const char *name_buf, const char *syscall) {
    fut_task_t *task = fut_task_current();
    int64_t pid = task ? (int64_t)task->pid : -1;

    /* Name must contain a '.' namespace separator */
    const char *dot = (const char *)memchr(name_buf, '.', XATTR_NAME_MAX + 1);
    if (!dot || dot == name_buf) {
        fut_printf("[XATTR] %s(name='%s', pid=%d) -> ENOTSUP "
                   "(name lacks namespace prefix, Phase 3)\n",
                   syscall, name_buf, pid);
        return -ENOTSUP;
    }

    /* Determine namespace prefix length */
    size_t ns_len = (size_t)(dot - name_buf) + 1;  /* includes the '.' */

    /* Validate against known namespaces */
    bool is_user     = (ns_len == 5  && memcmp(name_buf, XATTR_USER_PREFIX,     5) == 0);
    bool is_trusted  = (ns_len == 8  && memcmp(name_buf, XATTR_TRUSTED_PREFIX,  8) == 0);
    bool is_security = (ns_len == 9  && memcmp(name_buf, XATTR_SECURITY_PREFIX, 9) == 0);
    bool is_system   = (ns_len == 7  && memcmp(name_buf, XATTR_SYSTEM_PREFIX,   7) == 0);

    if (!is_user && !is_trusted && !is_security && !is_system) {
        fut_printf("[XATTR] %s(name='%s', pid=%d) -> ENOTSUP "
                   "(unknown namespace, Phase 3)\n",
                   syscall, name_buf, pid);
        return -ENOTSUP;
    }

    /* 'trusted.' and 'security.' require CAP_SYS_ADMIN or root */
    if (is_trusted || is_security) {
        bool is_root = (task && task->uid == 0);
        bool has_cap = (task && (task->cap_effective & (1ULL << CAP_SYS_ADMIN)) != 0);
        if (!is_root && !has_cap) {
            fut_printf("[XATTR] %s(name='%s', pid=%d) -> EPERM "
                       "(namespace requires CAP_SYS_ADMIN, Phase 3)\n",
                       syscall, name_buf, pid);
            return -EPERM;
        }
    }

    return 0;
}

/* Maximum sizes (XATTR_NAME_MAX defined above near CAP_SYS_ADMIN) */
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

    /* Copy path from userspace (full buffer to detect truncation)
     * VULNERABILITY: Path Truncation Attack
     * DEFENSE: Copy full buffer and check for null terminator presence */
    if (xattr_copy_from_user(path_buf, path, FUT_VFS_PATH_BUFFER_SIZE) != 0) {
        fut_printf("[XATTR] %s(path=? [bad addr], name=%p, pid=%d) -> EFAULT\n",
                   syscall, name, pid);
        return -EFAULT;
    }
    if (memchr(path_buf, '\0', FUT_VFS_PATH_BUFFER_SIZE) == NULL) {
        fut_printf("[XATTR] %s(path=<truncated>, pid=%d) -> ENAMETOOLONG "
                   "(path exceeds %d bytes)\n",
                   syscall, pid, FUT_VFS_PATH_BUFFER_SIZE - 1);
        return -ENAMETOOLONG;
    }

    /* Copy name from userspace (full buffer to detect truncation) */
    if (xattr_copy_from_user(name_buf, name, XATTR_NAME_MAX + 1) != 0) {
        fut_printf("[XATTR] %s(path='%s', name=? [bad addr], pid=%d) -> EFAULT\n",
                   syscall, path_buf, pid);
        return -EFAULT;
    }
    if (memchr(name_buf, '\0', XATTR_NAME_MAX + 1) == NULL) {
        fut_printf("[XATTR] %s(path='%s', name=<truncated>, pid=%d) -> ERANGE "
                   "(name exceeds %d bytes)\n",
                   syscall, path_buf, pid, XATTR_NAME_MAX);
        return -ERANGE;
    }

    /* Validate name is not empty */
    if (name_buf[0] == '\0') {
        fut_printf("[XATTR] %s(path='%s', name='' [empty], pid=%d) -> EINVAL\n",
                   syscall, path_buf, pid);
        return -EINVAL;
    }

    /* Phase 3: Validate namespace prefix and check privileges */
    return xattr_validate_namespace(name_buf, syscall);
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

    if (xattr_copy_from_user(name_buf, name, XATTR_NAME_MAX + 1) != 0) {
        fut_printf("[XATTR] %s(fd=%d, name=? [bad addr], pid=%d) -> EFAULT\n",
                   syscall, fd, pid);
        return -EFAULT;
    }
    if (memchr(name_buf, '\0', XATTR_NAME_MAX + 1) == NULL) {
        fut_printf("[XATTR] %s(fd=%d, name=<truncated>, pid=%d) -> ERANGE "
                   "(name exceeds %d bytes)\n",
                   syscall, fd, pid, XATTR_NAME_MAX);
        return -ERANGE;
    }

    if (name_buf[0] == '\0') {
        fut_printf("[XATTR] %s(fd=%d, name='' [empty], pid=%d) -> EINVAL\n",
                   syscall, fd, pid);
        return -EINVAL;
    }

    /* Phase 3: Validate namespace prefix and check privileges */
    return xattr_validate_namespace(name_buf, syscall);
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

    if (xattr_copy_from_user(path_buf, path, FUT_VFS_PATH_BUFFER_SIZE) != 0) {
        fut_printf("[XATTR] %s(path=? [bad addr], pid=%d) -> EFAULT\n",
                   syscall, pid);
        return -EFAULT;
    }
    if (memchr(path_buf, '\0', FUT_VFS_PATH_BUFFER_SIZE) == NULL) {
        fut_printf("[XATTR] %s(path=<truncated>, pid=%d) -> ENAMETOOLONG "
                   "(path exceeds %d bytes)\n",
                   syscall, pid, FUT_VFS_PATH_BUFFER_SIZE - 1);
        return -ENAMETOOLONG;
    }

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

    /* Copy value from userspace if needed */
    void *kvalue = NULL;
    if (size > 0 && value) {
        kvalue = fut_malloc(size);
        if (!kvalue) return -ENOMEM;
        if (xattr_copy_from_user(kvalue, value, size) != 0) {
            fut_free(kvalue);
            return -EFAULT;
        }
    }

    ret = vnode_setxattr_by_path(path_buf, name_buf, kvalue, size, flags);
    if (kvalue) fut_free(kvalue);
    return ret;
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

    /* lsetxattr operates on the symlink itself — use nofollow lookup. */
    void *kvalue = NULL;
    if (size > 0 && value) {
        kvalue = fut_malloc(size);
        if (!kvalue) return -ENOMEM;
        if (xattr_copy_from_user(kvalue, value, size) != 0) {
            fut_free(kvalue);
            return -EFAULT;
        }
    }
    ret = vnode_setxattr_nofollow(path_buf, name_buf, kvalue, size, flags);
    if (kvalue) fut_free(kvalue);
    return ret;
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

    struct fut_vnode *vnode = vnode_from_fd(task, fd);
    if (!vnode) return -EBADF;

    void *kvalue = NULL;
    if (size > 0 && value) {
        kvalue = fut_malloc(size);
        if (!kvalue) return -ENOMEM;
        if (xattr_copy_from_user(kvalue, value, size) != 0) {
            fut_free(kvalue);
            return -EFAULT;
        }
    }
    if (vnode->ops && vnode->ops->setxattr) {
        ret = vnode->ops->setxattr(vnode, name_buf, kvalue, size, flags);
    } else {
        ret = vnode_generic_setxattr(vnode, name_buf, kvalue, size, flags);
    }
    if (kvalue) fut_free(kvalue);
    return ret;
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

    if (!path || !name) {
        return -EINVAL;
    }

    char path_buf[FUT_VFS_PATH_BUFFER_SIZE];
    char name_buf[XATTR_NAME_MAX + 1];
    long ret = xattr_copy_path_and_name(path, name, path_buf, name_buf, "getxattr");
    if (ret < 0) {
        return ret;
    }

    /* Query size first, then copy to user */
    ssize_t attr_size = vnode_getxattr_by_path(path_buf, name_buf, NULL, 0);
    if (attr_size < 0) return (long)attr_size;
    if (size == 0) return (long)attr_size;
    if ((size_t)attr_size > size) return -ERANGE;

    void *kbuf = fut_malloc((size_t)attr_size + 1);
    if (!kbuf) return -ENOMEM;
    ssize_t got = vnode_getxattr_by_path(path_buf, name_buf, kbuf, (size_t)attr_size);
    if (got < 0) { fut_free(kbuf); return (long)got; }
    /* Clamp against TOCTOU: a concurrent setxattr could swap the value
     * for a longer one between the size query and this fetch, leaving
     * got > the kbuf we allocated and the copy_to_user reading past the
     * heap allocation into adjacent memory. */
    if ((size_t)got > (size_t)attr_size) got = (ssize_t)attr_size;
    if (value && xattr_copy_to_user(value, kbuf, (size_t)got) != 0) {
        fut_free(kbuf); return -EFAULT;
    }
    fut_free(kbuf);
    return (long)got;
}

/**
 * lgetxattr() - Get extended attribute value (don't follow symlinks)
 */
long sys_lgetxattr(const char *path, const char *name, void *value, size_t size) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    if (!path || !name) {
        return -EINVAL;
    }

    char path_buf[FUT_VFS_PATH_BUFFER_SIZE];
    char name_buf[XATTR_NAME_MAX + 1];
    long ret = xattr_copy_path_and_name(path, name, path_buf, name_buf, "lgetxattr");
    if (ret < 0) {
        return ret;
    }

    /* lgetxattr operates on the symlink itself — use nofollow lookup. */
    ssize_t attr_size = vnode_getxattr_nofollow(path_buf, name_buf, NULL, 0);
    if (attr_size < 0) return (long)attr_size;
    if (size == 0) return (long)attr_size;
    if ((size_t)attr_size > size) return -ERANGE;

    void *kbuf = fut_malloc((size_t)attr_size + 1);
    if (!kbuf) return -ENOMEM;
    ssize_t got = vnode_getxattr_nofollow(path_buf, name_buf, kbuf, (size_t)attr_size);
    if (got < 0) { fut_free(kbuf); return (long)got; }
    if ((size_t)got > (size_t)attr_size) got = (ssize_t)attr_size;
    if (value && xattr_copy_to_user(value, kbuf, (size_t)got) != 0) {
        fut_free(kbuf); return -EFAULT;
    }
    fut_free(kbuf);
    return (long)got;
}

/**
 * fgetxattr() - Get extended attribute value via file descriptor
 */
long sys_fgetxattr(int fd, const char *name, void *value, size_t size) {
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
    long ret = xattr_copy_name(name, name_buf, "fgetxattr", fd);
    if (ret < 0) {
        return ret;
    }

    struct fut_vnode *vnode = vnode_from_fd(task, fd);
    if (!vnode) return -EBADF;

    ssize_t attr_size;
    if (vnode->ops && vnode->ops->getxattr) {
        attr_size = vnode->ops->getxattr(vnode, name_buf, NULL, 0);
    } else {
        attr_size = vnode_generic_getxattr(vnode, name_buf, NULL, 0);
    }
    if (attr_size < 0) return (long)attr_size;
    if (size == 0) return (long)attr_size;
    if ((size_t)attr_size > size) return -ERANGE;

    void *kbuf = fut_malloc((size_t)attr_size + 1);
    if (!kbuf) return -ENOMEM;
    ssize_t got;
    if (vnode->ops && vnode->ops->getxattr) {
        got = vnode->ops->getxattr(vnode, name_buf, kbuf, (size_t)attr_size);
    } else {
        got = vnode_generic_getxattr(vnode, name_buf, kbuf, (size_t)attr_size);
    }
    if (got < 0) { fut_free(kbuf); return (long)got; }
    if ((size_t)got > (size_t)attr_size) got = (ssize_t)attr_size;
    if (value && xattr_copy_to_user(value, kbuf, (size_t)got) != 0) {
        fut_free(kbuf); return -EFAULT;
    }
    fut_free(kbuf);
    return (long)got;
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

    if (!path) {
        return -EINVAL;
    }

    char path_buf[FUT_VFS_PATH_BUFFER_SIZE];
    long ret = xattr_copy_path(path, path_buf, "listxattr");
    if (ret < 0) {
        return ret;
    }

    ssize_t total = vnode_listxattr_by_path(path_buf, NULL, 0);
    if (total < 0) return (long)total;
    if (size == 0) return (long)total;
    if ((size_t)total > size) return -ERANGE;

    char *kbuf = fut_malloc((size_t)total + 1);
    if (!kbuf) return -ENOMEM;
    ssize_t got = vnode_listxattr_by_path(path_buf, kbuf, (size_t)total);
    if (got < 0) { fut_free(kbuf); return (long)got; }
    /* Defensive clamp: the second call could in principle race with
     * setxattr/removexattr and return more bytes than the size hint we
     * sized kbuf for. Cap got to the buffer we actually allocated so the
     * subsequent copy_to_user can never read past kbuf. */
    if ((size_t)got > (size_t)total) got = (ssize_t)total;
    if (got > 0 && list && xattr_copy_to_user(list, kbuf, (size_t)got) != 0) {
        fut_free(kbuf); return -EFAULT;
    }
    fut_free(kbuf);
    return (long)got;
}

/**
 * llistxattr() - List extended attribute names (don't follow symlinks)
 */
long sys_llistxattr(const char *path, char *list, size_t size) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    if (!path) {
        return -EINVAL;
    }

    char path_buf[FUT_VFS_PATH_BUFFER_SIZE];
    long ret = xattr_copy_path(path, path_buf, "llistxattr");
    if (ret < 0) {
        return ret;
    }

    /* llistxattr operates on the symlink itself — use nofollow lookup. */
    ssize_t total = vnode_listxattr_nofollow(path_buf, NULL, 0);
    if (total < 0) return (long)total;
    if (size == 0) return (long)total;
    if ((size_t)total > size) return -ERANGE;

    char *kbuf = fut_malloc((size_t)total + 1);
    if (!kbuf) return -ENOMEM;
    ssize_t got = vnode_listxattr_nofollow(path_buf, kbuf, (size_t)total);
    if (got < 0) { fut_free(kbuf); return (long)got; }
    if ((size_t)got > (size_t)total) got = (ssize_t)total;
    if (got > 0 && list && xattr_copy_to_user(list, kbuf, (size_t)got) != 0) {
        fut_free(kbuf); return -EFAULT;
    }
    fut_free(kbuf);
    return (long)got;
}

/**
 * flistxattr() - List extended attribute names via file descriptor
 */
long sys_flistxattr(int fd, char *list, size_t size) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    if (fd < 0) {
        return -EBADF;
    }

    struct fut_vnode *vnode = vnode_from_fd(task, fd);
    if (!vnode) return -EBADF;

    ssize_t total;
    if (vnode->ops && vnode->ops->listxattr) {
        total = vnode->ops->listxattr(vnode, NULL, 0);
    } else {
        total = vnode_generic_listxattr(vnode, NULL, 0);
    }
    if (total < 0) return (long)total;
    if (size == 0) return (long)total;
    if ((size_t)total > size) return -ERANGE;

    char *kbuf = fut_malloc((size_t)total + 1);
    if (!kbuf) return -ENOMEM;
    ssize_t got;
    if (vnode->ops && vnode->ops->listxattr) {
        got = vnode->ops->listxattr(vnode, kbuf, (size_t)total);
    } else {
        got = vnode_generic_listxattr(vnode, kbuf, (size_t)total);
    }
    if (got < 0) { fut_free(kbuf); return (long)got; }
    if ((size_t)got > (size_t)total) got = (ssize_t)total;
    if (got > 0 && list && xattr_copy_to_user(list, kbuf, (size_t)got) != 0) {
        fut_free(kbuf); return -EFAULT;
    }
    fut_free(kbuf);
    return (long)got;
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

    return vnode_removexattr_by_path(path_buf, name_buf);
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

    /* lremovexattr operates on the symlink itself — use nofollow lookup. */
    return vnode_removexattr_nofollow(path_buf, name_buf);
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

    struct fut_vnode *vnode = vnode_from_fd(task, fd);
    if (!vnode) return -EBADF;
    if (vnode->ops && vnode->ops->removexattr) {
        return vnode->ops->removexattr(vnode, name_buf);
    }
    return vnode_generic_removexattr(vnode, name_buf);
}
