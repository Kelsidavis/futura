/* kernel/sys_prctl.c - Process control operations
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements prctl() for per-process attribute control.
 * Supports commonly-used operations needed by libc and runtime libraries.
 */

#include <kernel/fut_task.h>
#include <kernel/fut_memory.h>
#include <kernel/uaccess.h>
#include <kernel/errno.h>
#include <kernel/kprintf.h>
#include <stdint.h>
#include <string.h>
#ifdef __x86_64__
#include <platform/x86_64/memory/paging.h>
#elif defined(__aarch64__)
#include <platform/arm64/memory/paging.h>
#endif

/* prctl option constants (Linux ABI) */
#define PR_SET_PDEATHSIG     1
#define PR_GET_PDEATHSIG     2
#define PR_SET_DUMPABLE      4
#define PR_GET_DUMPABLE      3
#define PR_SET_NAME         15
#define PR_GET_NAME         16
#define PR_SET_NO_NEW_PRIVS 38
#define PR_GET_NO_NEW_PRIVS 39
#define PR_SET_TIMERSLACK   29
#define PR_GET_TIMERSLACK   30
#define PR_CAPBSET_READ     23
#define PR_CAPBSET_DROP     24

/* Additional prctl options (Linux ABI) */
#define PR_GET_SECUREBITS   27   /* Get secure-bits */
#define PR_SET_SECUREBITS   28   /* Set secure-bits */
#define PR_SET_KEEPCAPS      8   /* Retain capabilities across setuid */
#define PR_GET_KEEPCAPS      7   /* Get keepcaps flag */
#define PR_MCE_KILL         33   /* MCE kill policy for process */
#define PR_MCE_KILL_GET     34   /* Get MCE kill policy */
#define PR_SET_CHILD_SUBREAPER 36 /* Become subreaper for orphaned children */
#define PR_GET_CHILD_SUBREAPER 37 /* Get subreaper status */
#define PR_SET_MM           35   /* Modify mm_struct fields */
#define PR_SET_VMA          0x53564d41 /* Set VMA name */

/* Maximum valid signal number */
#define PR_MAX_SIGNAL       64

/**
 * sys_prctl - Process control operations
 *
 * @param option: Operation to perform (PR_SET_*, PR_GET_*)
 * @param arg2-arg5: Operation-specific arguments
 *
 * Returns:
 *   - 0 on success (for SET operations)
 *   - Requested value on success (for GET operations)
 *   - -EINVAL for unknown options or invalid arguments
 *   - -ESRCH if no task context
 *   - -EFAULT for invalid pointers
 */
long sys_prctl(int option, unsigned long arg2, unsigned long arg3,
               unsigned long arg4, unsigned long arg5) {
    (void)arg3; (void)arg4; (void)arg5;

    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    switch (option) {

    case PR_SET_PDEATHSIG: {
        /* Set signal to deliver when parent dies */
        int sig = (int)arg2;
        if (sig < 0 || sig > PR_MAX_SIGNAL) {
            return -EINVAL;
        }
        task->pdeathsig = sig;
        return 0;
    }

    case PR_GET_PDEATHSIG: {
        /* Get parent-death signal — writes to userspace int pointer */
        int *uptr = (int *)(uintptr_t)arg2;
        if (!uptr) {
            return -EFAULT;
        }
        int val = task->pdeathsig;
        if (fut_copy_to_user(uptr, &val, sizeof(int)) != 0) {
            return -EFAULT;
        }
        return 0;
    }

    case PR_SET_NAME: {
        /* Set process/thread name (max 15 chars + null) */
        const char *name = (const char *)(uintptr_t)arg2;
        if (!name) {
            return -EFAULT;
        }
        /* Copy up to 15 bytes from userspace (or kernel pointer) */
        char kname[16];
        memset(kname, 0, sizeof(kname));
        if (fut_copy_from_user(kname, name, 15) != 0) {
            /* If copy_from_user fails, try direct copy (kernel pointer) */
            for (int i = 0; i < 15 && name[i]; i++) {
                kname[i] = name[i];
            }
        }
        kname[15] = '\0';
        memcpy(task->comm, kname, 16);
        return 0;
    }

    case PR_GET_NAME: {
        /* Get process/thread name */
        char *uname = (char *)(uintptr_t)arg2;
        if (!uname) {
            return -EFAULT;
        }
        if (fut_copy_to_user(uname, task->comm, 16) != 0) {
            /* If copy_to_user fails, try direct copy (kernel pointer) */
            memcpy(uname, task->comm, 16);
        }
        return 0;
    }

    case PR_SET_DUMPABLE: {
        /* Control whether core dumps are produced */
        int val = (int)arg2;
        if (val != 0 && val != 1) {
            return -EINVAL;
        }
        task->dumpable = val;
        return 0;
    }

    case PR_GET_DUMPABLE:
        return task->dumpable;

    case PR_SET_NO_NEW_PRIVS: {
        /* Sticky flag: once set, cannot be unset (prevents execve setuid escalation) */
        if (arg2 != 1) {
            return -EINVAL;  /* Can only set to 1 */
        }
        task->no_new_privs = 1;
        return 0;
    }

    case PR_GET_NO_NEW_PRIVS:
        return (long)task->no_new_privs;

    case PR_SET_TIMERSLACK:
        /* Accept but ignore — Futura uses fixed timer resolution */
        return 0;

    case PR_GET_TIMERSLACK:
        /* Return default timer slack (50us in nanoseconds, matching Linux default) */
        return 50000;

    case PR_CAPBSET_READ: {
        /* Check if capability is in the bounding set */
        int cap = (int)arg2;
        if (cap < 0 || cap > 63) {
            return -EINVAL;
        }
        /* All capabilities in bounding set by default */
        return 1;
    }

    case PR_CAPBSET_DROP: {
        /* Drop a capability from the bounding set */
        int cap = (int)arg2;
        if (cap < 0 || cap > 63) {
            return -EINVAL;
        }
        /* Accept but don't enforce (no bounding set tracking yet) */
        return 0;
    }

    case PR_GET_SECUREBITS:
        /* No secure-bits tracking; return 0 (no bits set) */
        return 0;

    case PR_SET_SECUREBITS:
        /* Accept but don't enforce secure-bits changes */
        return 0;

    case PR_GET_KEEPCAPS:
        return 0;  /* Not keeping capabilities across setuid */

    case PR_SET_KEEPCAPS:
        /* Accept flag (arg2 must be 0 or 1) */
        if (arg2 != 0 && arg2 != 1)
            return -EINVAL;
        return 0;

    case PR_MCE_KILL:
        /* Accept MCE kill policy; we don't enforce it */
        return 0;

    case PR_MCE_KILL_GET:
        return 0;  /* PR_MCE_KILL_DEFAULT */

    case PR_SET_CHILD_SUBREAPER:
        /* Mark this task as a subreaper for orphaned children.
         * Store in task->personality field bit 31 as a subreaper flag.
         * For now, accept without enforcement. */
        if (arg2)
            task->personality |= (1UL << 31);
        else
            task->personality &= ~(1UL << 31);
        return 0;

    case PR_GET_CHILD_SUBREAPER: {
        /* Return 1 if we are a subreaper, 0 otherwise */
        unsigned long is_subreaper = (task->personality >> 31) & 1;
        if (!arg2)
            return -EFAULT;
#ifdef KERNEL_VIRTUAL_BASE
        if ((uintptr_t)arg2 >= KERNEL_VIRTUAL_BASE) {
            *(unsigned long *)arg2 = is_subreaper;
            return 0;
        }
#endif
        if (fut_copy_to_user((void *)arg2, &is_subreaper, sizeof(unsigned long)) != 0)
            return -EFAULT;
        return 0;
    }

    case PR_SET_MM:
        /* Modifying mm_struct fields not supported; return EPERM */
        return -EPERM;

    case PR_SET_VMA:
        /* VMA naming not supported; silently accept */
        return 0;

    default:
        fut_printf("[PRCTL] prctl(option=%d) -> EINVAL (unsupported option)\n", option);
        return -EINVAL;
    }
}
