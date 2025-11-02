/* sys_execve.c - execve() syscall implementation
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements program execution via execve().
 */

#include <kernel/fut_task.h>
#include <kernel/fut_thread.h>
#include <kernel/fut_vfs.h>
#include <kernel/errno.h>
#include <kernel/uaccess.h>
#include <stddef.h>

/* FD_CLOEXEC flag value */
#define FD_CLOEXEC 1

extern void fut_printf(const char *fmt, ...);
extern int fut_exec_elf(const char *path, char *const argv[], char *const envp[]);

/**
 * execve() syscall - Execute a program.
 *
 * @param pathname  Path to executable file
 * @param argv      Argument vector (NULL-terminated array)
 * @param envp      Environment vector (NULL-terminated array)
 *
 * Returns:
 *   - Does not return on success (current process is replaced)
 *   - -errno on error
 */
long sys_execve(const char *pathname, char *const argv[], char *const envp[]) {
    /* Validate inputs */
    if (!pathname) {
        return -EINVAL;
    }

    /* Validate that pathname is a valid userspace pointer (readable) */
    if (fut_access_ok(pathname, 1, 0) != 0) {
        return -EFAULT;
    }

    /* Validate that argv is a valid userspace pointer (readable) */
    if (argv && fut_access_ok(argv, sizeof(char *), 0) != 0) {
        return -EFAULT;
    }

    /* Validate that envp is a valid userspace pointer (readable) if provided */
    if (envp && fut_access_ok(envp, sizeof(char *), 0) != 0) {
        return -EFAULT;
    }

    fut_printf("[EXECVE] path=%s envp=%p\n", pathname, (void*)envp);

    /* Get current task to handle close-on-exec FDs */
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    /* Close all FDs marked with FD_CLOEXEC before executing new binary */
    if (task->fd_table) {
        for (int i = 0; i < task->max_fds; i++) {
            struct fut_file *file = task->fd_table[i];
            if (file != NULL && (file->fd_flags & FD_CLOEXEC)) {
                /* Close this FD (CLOEXEC means "close on exec") */
                fut_vfs_close(i);
                /* Note: fut_vfs_close will remove from task's FD table */
            }
        }
    }

    /* Call the ELF loader which replaces the current process */
    int ret = fut_exec_elf(pathname, argv, envp);

    /*
     * If fut_exec_elf returns, it failed.
     * On success, it never returns (process is replaced).
     */
    return ret;
}
