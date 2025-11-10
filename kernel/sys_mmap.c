// SPDX-License-Identifier: MPL-2.0

#include <stddef.h>
#include <stdint.h>

#include <kernel/errno.h>
#include <kernel/fut_mm.h>
#include <kernel/fut_task.h>
#include <kernel/fut_thread.h>
#include <kernel/fut_vfs.h>
#include <platform/platform.h>

#define MAP_SHARED      0x01
#define MAP_PRIVATE     0x02
#define MAP_FIXED       0x10
#define MAP_ANONYMOUS   0x20

long sys_mmap(void *addr, size_t len, int prot, int flags, int fd, long offset) {
    if (len == 0) {
        return -EINVAL;
    }

    if (flags & MAP_ANONYMOUS) {
        fut_task_t *task = fut_task_current();
        if (!task) {
            return -EPERM;
        }

        fut_mm_t *mm = fut_task_get_mm(task);
        if (!mm) {
            return -ENOMEM;
        }

        void *res = fut_mm_map_anonymous(mm, (uintptr_t)addr, len, prot, flags);
        if ((intptr_t)res < 0) {
            return (long)(intptr_t)res;
        }
        return (long)(intptr_t)res;
    }

    void *mapped = fut_vfs_mmap(fd, addr, len, prot, flags, (off_t)offset);
    fut_printf("[SYS_MMAP] fd=%d returning 0x%llx\n", fd, (unsigned long long)(uintptr_t)mapped);
    return (long)(intptr_t)mapped;
}

long sys_munmap(void *addr, size_t len) {
    if (!addr || len == 0) {
        return -EINVAL;
    }

    fut_task_t *task = fut_task_current();
    if (!task) {
        return -EPERM;
    }

    fut_mm_t *mm = fut_task_get_mm(task);
    if (!mm) {
        return -ENOMEM;
    }

    return fut_mm_unmap(mm, (uintptr_t)addr, len);
}
