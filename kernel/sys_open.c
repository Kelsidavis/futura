/* kernel/sys_open.c - Open file syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements open() to open files and obtain file descriptors.
 * Core primitive for file system access.
 */

#include <kernel/fut_task.h>
#include <kernel/fut_vfs.h>
#include <kernel/uaccess.h>
#include <kernel/errno.h>
#include <stddef.h>

extern void fut_printf(const char *fmt, ...);
extern fut_task_t *fut_task_current(void);

/* Forward declaration for copy_user_string */
extern int copy_user_string(const char *user_str, char *kernel_buf, size_t max_len);

/**
 * open() - Open file and return file descriptor
 *
 * Opens the file specified by pathname and returns a file descriptor.
 *
 * @param pathname Path to file to open
 * @param flags    Open flags (O_RDONLY, O_WRONLY, O_RDWR, O_CREAT, etc.)
 * @param mode     Permission mode if creating file
 *
 * Returns:
 *   - Non-negative file descriptor on success
 *   - -EACCES if permission denied
 *   - -EEXIST if O_CREAT | O_EXCL and file exists
 *   - -EFAULT if pathname is invalid
 *   - -EISDIR if O_WRONLY | O_RDWR and pathname is directory
 *   - -ENOENT if file doesn't exist and O_CREAT not specified
 *   - -ENOMEM if out of memory
 *   - -ENOTDIR if component of path is not a directory
 */
long sys_open(const char *pathname, int flags, int mode) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    fut_printf("[SYS-OPEN] called: pathname=0x%p flags=0x%x mode=0%o\n",
               pathname, flags, mode);

    /* Copy pathname from userspace */
    char kpath[256];
    int rc = copy_user_string(pathname, kpath, sizeof(kpath));
    fut_printf("[SYS-OPEN] copy_user_string returned %d, kpath='%s'\n", rc, kpath);
    if (rc != 0) {
        fut_printf("[SYS-OPEN] returning error %d\n", rc);
        return rc;
    }

    /* Open via VFS */
    int result = fut_vfs_open(kpath, flags, mode);
    fut_printf("[SYS-OPEN] fut_vfs_open returned %d\n", result);

    return (long)result;
}
