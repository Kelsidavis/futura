// SPDX-License-Identifier: MPL-2.0

#include <kernel/fut_task.h>
#include <kernel/uaccess.h>
#include <kernel/errno.h>

#include <stddef.h>

long sys_waitpid(int pid, int *u_status, int flags) {
    (void)flags;

    int status = 0;
    int rc = fut_task_waitpid(pid, &status);
    if (rc < 0) {
        return rc;
    }

    if (u_status) {
        if (fut_copy_to_user(u_status, &status, sizeof(status)) != 0) {
            return -EFAULT;
        }
    }

    return rc;
}
