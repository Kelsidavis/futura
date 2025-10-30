// SPDX-License-Identifier: MPL-2.0

#include <kernel/errno.h>
#include <kernel/fut_task.h>

/**
 * Get the current working directory.
 * Stub implementation - returns "/" as current working directory.
 * Full implementation requires VFS inode lookup support.
 *
 * @param buf Buffer to store the path
 * @param size Size of the buffer
 * @return Pointer to buf on success, or error code (negative) on failure
 */
long sys_getcwd(char *buf, size_t size) {
    if (!buf) {
        return -EINVAL;
    }

    if (size < 2) {
        return -ERANGE;
    }

    /* For now, always return "/" as current directory */
    buf[0] = '/';
    buf[1] = '\0';
    return (long)(uintptr_t)buf;
}
