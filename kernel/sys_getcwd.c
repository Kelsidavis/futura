// SPDX-License-Identifier: MPL-2.0

#include <kernel/errno.h>
#include <kernel/fut_task.h>
#include <kernel/fut_thread.h>
#include <kernel/fut_vfs.h>
#include <kernel/fut_memory.h>

/**
 * Get the current working directory.
 * @param buf Buffer to store the path
 * @param size Size of the buffer
 * @return Pointer to buf on success, NULL on error (errno set)
 */
long sys_getcwd(char *buf, size_t size) {
    /* Get the current task */
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -EPERM;
    }

    if (!buf) {
        return -EINVAL;
    }

    if (size < 2) {
        return -ERANGE;
    }

    /* For now, return "/" for all directories since full path reconstruction
     * would require traversing parent pointers which aren't stored in vnodes.
     * TODO: Implement full path reconstruction by storing parent refs in inodes
     */

    buf[0] = '/';
    buf[1] = '\0';

    return (long)(uintptr_t)buf;
}
