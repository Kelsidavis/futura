// SPDX-License-Identifier: MPL-2.0
/*
 * sys_echo.c - Minimal syscall exercising uaccess helpers
 */

#include <kernel/syscalls.h>
#include <kernel/uaccess.h>
#include <kernel/errno.h>

#include <stddef.h>

#define SYS_ECHO_MAX (4096u)

ssize_t sys_echo(const char *u_in, char *u_out, size_t n) {
    if (!u_in || !u_out) {
        return -EFAULT;
    }

    if (n > SYS_ECHO_MAX) {
        n = SYS_ECHO_MAX;
    }

    char buffer[512];
    size_t offset = 0;

    while (offset < n) {
        size_t chunk = n - offset;
        if (chunk > sizeof(buffer)) {
            chunk = sizeof(buffer);
        }

        int rc = fut_copy_from_user(buffer, u_in + offset, chunk);
        if (rc != 0) {
            return rc;
        }

        for (size_t i = 0; i < chunk; ++i) {
            buffer[i] ^= 0x20u;
        }

        rc = fut_copy_to_user(u_out + offset, buffer, chunk);
        if (rc != 0) {
            return rc;
        }

        offset += chunk;
    }

    return (ssize_t)offset;
}
