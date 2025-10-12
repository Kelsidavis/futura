// SPDX-License-Identifier: MPL-2.0

#include <kernel/fut_task.h>

long sys_exit(int status) {
    fut_task_exit_current(status);
    return 0;
}
