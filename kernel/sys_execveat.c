/* kernel/sys_execveat.c - execveat() syscall (Linux 3.19+)
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * execveat() executes a program relative to a directory file descriptor.
 *
 * Phase 1 (Completed):
 *   - AT_FDCWD + absolute/relative path: delegate to sys_execve
 *   - Real dirfd + relative path: resolve via fut_vfs_resolve_at, then exec
 *   - AT_EMPTY_PATH: execute the file represented by dirfd itself
 *   - Flags: AT_EMPTY_PATH (0x1000), AT_SYMLINK_NOFOLLOW (0x100)
 */

#include <kernel/fut_task.h>
#include <kernel/fut_vfs.h>
#include <kernel/errno.h>
#include <kernel/kprintf.h>
#include <kernel/uaccess.h>
#include <fcntl.h>
#include <stddef.h>
#include <string.h>

#ifdef __x86_64__
#include <platform/x86_64/memory/paging.h>
#elif defined(__aarch64__)
#include <platform/arm64/memory/paging.h>
#endif

/* Supported flags */
#define EXECVEAT_AT_EMPTY_PATH       0x1000
#define EXECVEAT_AT_SYMLINK_NOFOLLOW 0x100
#define EXECVEAT_FLAGS_VALID         (EXECVEAT_AT_EMPTY_PATH | EXECVEAT_AT_SYMLINK_NOFOLLOW)

static inline int evat_is_kptr(const void *p) {
#ifdef KERNEL_VIRTUAL_BASE
    return (uintptr_t)p >= KERNEL_VIRTUAL_BASE;
#else
    return 0;
#endif
}
static inline int evat_copy_from_user(void *dst, const void *src, size_t n) {
    if (evat_is_kptr(src)) { __builtin_memcpy(dst, src, n); return 0; }
    return fut_copy_from_user(dst, src, n);
}

/**
 * sys_execveat - Execute program relative to directory FD.
 *
 * @param dirfd    Directory FD, or AT_FDCWD for current directory
 * @param pathname Path to executable (absolute, relative, or "" with AT_EMPTY_PATH)
 * @param argv     Argument vector (NULL-terminated)
 * @param envp     Environment vector (NULL-terminated)
 * @param flags    AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW
 * @return Does not return on success; -errno on error
 */
long sys_execveat(int dirfd, const char *pathname,
                  char *const argv[], char *const envp[], int flags) {
    /* Validate flags */
    if (flags & ~EXECVEAT_FLAGS_VALID)
        return -EINVAL;

    /* Copy pathname to kernel buffer */
    char kpath[256];
    if (!pathname) {
        if (!(flags & EXECVEAT_AT_EMPTY_PATH))
            return -EFAULT;
        kpath[0] = '\0';
    } else {
        size_t len = 0;
        char ch;
        while (len < 255) {
            if (evat_copy_from_user(&ch, pathname + len, 1) != 0)
                return -EFAULT;
            kpath[len] = ch;
            if (ch == '\0') break;
            len++;
        }
        kpath[len] = '\0';
    }

    /* AT_EMPTY_PATH with empty pathname: execute dirfd itself */
    if ((flags & EXECVEAT_AT_EMPTY_PATH) && kpath[0] == '\0') {
        if (dirfd < 0 && dirfd != AT_FDCWD)
            return -EBADF;
        if (dirfd == AT_FDCWD) {
            /* Empty path + AT_FDCWD is ambiguous; POSIX says ENOENT */
            return -ENOENT;
        }
        /* Get the path stored in the dirfd */
        fut_task_t *task = fut_task_current();
        if (!task || !task->fd_table || dirfd >= task->max_fds)
            return -EBADF;
        struct fut_file *f = task->fd_table[dirfd];
        if (!f)
            return -EBADF;
        if (!f->path)
            return -ENOENT;
        /* Use the dirfd's own path as the exec target */
        extern long sys_execve(const char *, char *const *, char *const *);
        return sys_execve(f->path, argv, envp);
    }

    /* Absolute path or AT_FDCWD + relative: delegate directly */
    if (kpath[0] == '/' || dirfd == AT_FDCWD) {
        extern long sys_execve(const char *, char *const *, char *const *);
        return sys_execve(kpath, argv, envp);
    }

    /* Relative path with real dirfd: resolve to absolute */
    char resolved[256];
    fut_task_t *task = fut_task_current();
    int rc = fut_vfs_resolve_at(task, dirfd, kpath, resolved, sizeof(resolved));
    if (rc != 0)
        return rc;

    extern long sys_execve(const char *, char *const *, char *const *);
    return sys_execve(resolved, argv, envp);
}
