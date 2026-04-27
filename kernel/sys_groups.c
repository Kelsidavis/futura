/* kernel/sys_groups.c - Supplementary group ID syscalls
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements getgroups() and setgroups() for managing supplementary
 * group memberships. Required for POSIX credential management and
 * proper file permission checking.
 *
 * Linux syscall numbers: getgroups=115, setgroups=116 (x86_64)
 *                        getgroups=80, setgroups=81 (ARM64)
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <kernel/uaccess.h>
#include <stdint.h>

#include <platform/platform.h>

/* Kernel-pointer bypass helpers */
static inline int groups_copy_to_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)dst >= KERNEL_VIRTUAL_BASE) { __builtin_memcpy(dst, src, n); return 0; }
#endif
    return fut_copy_to_user(dst, src, n);
}

static inline int groups_copy_from_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)src >= KERNEL_VIRTUAL_BASE) { __builtin_memcpy(dst, src, n); return 0; }
#endif
    return fut_copy_from_user(dst, src, n);
}

#define NGROUPS_MAX 32

/**
 * getgroups() - Get supplementary group IDs
 *
 * @param size    Size of grouplist array (0 to query count)
 * @param list    Array to receive group IDs
 *
 * Returns number of supplementary groups on success, negative errno on failure.
 * If size is 0, returns the number of supplementary groups without writing.
 */
long sys_getgroups(int size, uint32_t *list) {
    fut_task_t *task = fut_task_current();
    if (!task)
        return -ESRCH;

    int ngroups = task->ngroups;

    /* Query mode: return count */
    if (size == 0)
        return ngroups;

    if (size < 0)
        return -EINVAL;

    if (size < ngroups)
        return -EINVAL;

    if (!list)
        return -EFAULT;

    if (ngroups > 0) {
        if (groups_copy_to_user(list, task->groups, ngroups * sizeof(uint32_t)) != 0)
            return -EFAULT;
    }

    return ngroups;
}

/**
 * setgroups() - Set supplementary group IDs
 *
 * @param size    Number of groups to set
 * @param list    Array of group IDs
 *
 * Returns 0 on success, negative errno on failure.
 * Requires CAP_SETGID (or root) in a real system.
 */
long sys_setgroups(int size, const uint32_t *list) {
    fut_task_t *task = fut_task_current();
    if (!task)
        return -ESRCH;

    /* CAP_SETGID required to modify supplementary groups, but root
     * (uid==0) bypasses the explicit cap-bit check — matching Linux's
     * ns_capable() which treats root-in-the-namespace as holding every
     * capability regardless of cap_effective state. The previous
     * cap-only check would deny setgroups to a uid=0 process whose
     * cap_effective had been cleared (e.g. during early boot before
     * exec_init populates the full cap mask, or after a manual capset
     * that didn't include CAP_SETGID), diverging from every other
     * privileged-op gate in the kernel which uses the
     *   uid != 0 && !cap   pattern. */
#define CAP_SETGID_BIT 6
    if (task->uid != 0 &&
        !(task->cap_effective & (1ULL << CAP_SETGID_BIT))) {
        return -EPERM;
    }

    if (size < 0 || size > NGROUPS_MAX)
        return -EINVAL;

    if (size > 0 && !list)
        return -EFAULT;

    if (size > 0) {
        /* Stage in a kernel-local buffer first so a faulting copy never
         * leaves task->groups partially overwritten — concurrent
         * permission checks on another CPU would otherwise see torn
         * credentials before EFAULT propagates back. */
        uint32_t tmp[NGROUPS_MAX];
        if (groups_copy_from_user(tmp, list, size * sizeof(uint32_t)) != 0)
            return -EFAULT;
        for (int i = 0; i < size; i++)
            task->groups[i] = tmp[i];
    }

    task->ngroups = size;
    return 0;
}
