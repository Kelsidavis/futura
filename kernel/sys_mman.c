/* kernel/sys_mman.c - Memory locking syscalls for ARM64
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements mlock/munlock, mlockall/munlockall syscalls for ARM64 platform.
 * Note: madvise, msync, and mincore are provided by shared kernel sources
 * (kernel/sys_madvise.c, kernel/sys_msync.c, kernel/sys_mincore.c).
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>

extern void fut_printf(const char *fmt, ...);
extern fut_task_t *fut_task_current(void);

/* mlockall flags */
#define MCL_CURRENT      1  /* Lock currently mapped pages */
#define MCL_FUTURE       2  /* Lock future mappings */
#define MCL_ONFAULT      4  /* Lock pages only on fault */

/**
 * sys_mlock - Lock memory pages in RAM
 *
 * @param addr: Starting address (must be page-aligned)
 * @param len:  Number of bytes to lock
 *
 * Locks the specified memory range in physical RAM, preventing it from
 * being swapped out. Useful for security-sensitive data or real-time code.
 *
 * Phase 1: Stub - validates parameters, returns success
 * Phase 2: Mark pages as locked in VMA structures
 * Phase 3: Integrate with page reclamation to prevent swapping
 *
 * Returns:
 *   - 0 on success
 *   - -EINVAL if addr not aligned
 *   - -ENOMEM if would exceed RLIMIT_MEMLOCK
 *   - -EPERM if insufficient privileges
 */
long sys_mlock(const void *addr, size_t len) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    fut_printf("[MLOCK] mlock(addr=%p, len=%zu)\n", addr, len);

    /* Validate address alignment */
    if ((uintptr_t)addr & 0xFFF) {
        return -EINVAL;
    }

    /* Phase 1: Stub - accept parameters */
    /* Phase 2: Mark VMA as VM_LOCKED, prefault pages */
    /* Phase 3: Check RLIMIT_MEMLOCK, implement page pinning */

    fut_printf("[MLOCK] Stub implementation - pages marked locked\n");
    return 0;
}

/**
 * sys_munlock - Unlock memory pages
 *
 * @param addr: Starting address (must be page-aligned)
 * @param len:  Number of bytes to unlock
 *
 * Removes memory lock, allowing pages to be swapped if needed.
 *
 * Phase 1: Stub - validates parameters, returns success
 * Phase 2: Clear VM_LOCKED flag from VMAs
 *
 * Returns:
 *   - 0 on success
 *   - -EINVAL if addr not aligned
 */
long sys_munlock(const void *addr, size_t len) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    fut_printf("[MUNLOCK] munlock(addr=%p, len=%zu)\n", addr, len);

    /* Validate address alignment */
    if ((uintptr_t)addr & 0xFFF) {
        return -EINVAL;
    }

    /* Phase 1: Stub - accept parameters */
    /* Phase 2: Clear VM_LOCKED flag from VMAs */

    fut_printf("[MUNLOCK] Stub implementation - pages unlocked\n");
    return 0;
}

/**
 * sys_mlockall - Lock all current and future memory pages
 *
 * @param flags: MCL_CURRENT, MCL_FUTURE, MCL_ONFAULT
 *
 * Locks all pages in the address space. MCL_CURRENT locks existing pages,
 * MCL_FUTURE locks future mappings, MCL_ONFAULT defers locking until fault.
 *
 * Phase 1: Stub - validates flags, returns success
 * Phase 2: Lock all current VMAs, set flag for future mappings
 * Phase 3: Implement MCL_ONFAULT deferred locking
 *
 * Returns:
 *   - 0 on success
 *   - -EINVAL if flags invalid
 *   - -ENOMEM if would exceed RLIMIT_MEMLOCK
 *   - -EPERM if insufficient privileges
 */
long sys_mlockall(int flags) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    fut_printf("[MLOCKALL] mlockall(flags=0x%x)\n", flags);

    /* Validate flags */
    int valid_flags = MCL_CURRENT | MCL_FUTURE | MCL_ONFAULT;
    if (flags & ~valid_flags) {
        return -EINVAL;
    }

    /* Phase 1: Stub - accept flags */
    /* Phase 2: Walk VMAs, lock if MCL_CURRENT, set task flag for MCL_FUTURE */
    /* Phase 3: Implement MCL_ONFAULT lazy locking */

    fut_printf("[MLOCKALL] Stub implementation - all pages marked locked\n");
    return 0;
}

/**
 * sys_munlockall - Unlock all memory pages
 *
 * Removes all memory locks from the process address space.
 *
 * Phase 1: Stub - returns success
 * Phase 2: Clear VM_LOCKED from all VMAs, clear task flags
 *
 * Returns:
 *   - 0 on success
 */
long sys_munlockall(void) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    fut_printf("[MUNLOCKALL] munlockall()\n");

    /* Phase 1: Stub - accept call */
    /* Phase 2: Walk VMAs, clear VM_LOCKED, clear task mlockall flags */

    fut_printf("[MUNLOCKALL] Stub implementation - all pages unlocked\n");
    return 0;
}
