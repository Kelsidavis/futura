// SPDX-License-Identifier: MPL-2.0

#include <stddef.h>
#include <stdint.h>
#include <limits.h>

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

/* Standard prot flags */
#define PROT_NONE       0x0
#define PROT_READ       0x1
#define PROT_WRITE      0x2
#define PROT_EXEC       0x4

extern void fut_printf(const char *fmt, ...);

long sys_mmap(void *addr, size_t len, int prot, int flags, int fd, long offset) {
    if (len == 0) {
        return -EINVAL;
    }

    /* Phase 5: Validate length is within reasonable bounds before overflow arithmetic
     * Limit to half of address space to prevent integer overflow in subsequent checks.
     * This ensures len can be safely used in offset+len calculations. */
    const size_t MAX_MMAP_LEN = (SIZE_MAX / 2);
    if (len > MAX_MMAP_LEN) {
        fut_printf("[MMAP] mmap(addr=%p, len=%zu) -> EINVAL "
                   "(length exceeds maximum %zu, Phase 5)\n",
                   addr, len, MAX_MMAP_LEN);
        return -EINVAL;
    }

    /* Phase 5: Validate prot flags don't contain unsupported bits */
    int valid_prot = PROT_NONE | PROT_READ | PROT_WRITE | PROT_EXEC;
    if (prot & ~valid_prot) {
        int invalid_bits = prot & ~valid_prot;
        fut_printf("[MMAP] mmap(addr=%p, len=%zu, prot=0x%x) -> EINVAL "
                   "(invalid prot bits 0x%x detected, valid=0x%x, Phase 5)\n",
                   addr, len, prot, invalid_bits, valid_prot);
        return -EINVAL;
    }

    /* Phase 5: Validate flags don't mix MAP_SHARED and MAP_PRIVATE */
    if ((flags & MAP_SHARED) && (flags & MAP_PRIVATE)) {
        fut_printf("[MMAP] mmap(addr=%p, len=%zu, flags=0x%x) -> EINVAL "
                   "(MAP_SHARED and MAP_PRIVATE are mutually exclusive, Phase 5)\n",
                   addr, len, flags);
        return -EINVAL;
    }

    /* Phase 5: Validate offset is non-negative and won't overflow */
    if (offset < 0) {
        fut_printf("[MMAP] mmap(addr=%p, len=%zu, offset=%ld) -> EINVAL "
                   "(offset is negative, Phase 5)\n",
                   addr, len, offset);
        return -EINVAL;
    }

    /* Phase 5: Check for offset + len overflow (now safe since len <= MAX_MMAP_LEN) */
    if (offset > LONG_MAX - (long)len) {
        fut_printf("[MMAP] mmap(addr=%p, len=%zu, offset=%ld) -> EINVAL "
                   "(offset + len would overflow, Phase 5)\n",
                   addr, len, offset);
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
