/* kernel/sys_seccomp.c - seccomp() syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements seccomp() for syscall filtering (Linux 3.17).
 * In Futura's kernel-selftest environment all code runs at kernel privilege
 * so strict mode is a no-op and BPF filter mode is not yet supported.
 *
 * Phase 1 (Completed):
 *   - SECCOMP_SET_MODE_STRICT: accepted, no-op (kernel is already trusted)
 *   - SECCOMP_SET_MODE_FILTER: ENOSYS (BPF not yet implemented)
 *   - SECCOMP_GET_ACTION_AVAIL: returns 0 for basic actions
 *   - SECCOMP_GET_NOTIF_SIZES: returns -EINVAL (unotify not supported)
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <kernel/kprintf.h>
#include <stdint.h>
#include <stddef.h>

/* seccomp() operation types */
#define SECCOMP_SET_MODE_STRICT    0
#define SECCOMP_SET_MODE_FILTER    1
#define SECCOMP_GET_ACTION_AVAIL   2
#define SECCOMP_GET_NOTIF_SIZES    3

/* seccomp() flags */
#define SECCOMP_FILTER_FLAG_TSYNC       (1UL << 0)
#define SECCOMP_FILTER_FLAG_LOG         (1UL << 1)
#define SECCOMP_FILTER_FLAG_SPEC_ALLOW  (1UL << 2)

/* seccomp actions (for GET_ACTION_AVAIL) */
#define SECCOMP_RET_KILL_PROCESS  0x80000000U
#define SECCOMP_RET_KILL_THREAD   0x00000000U
#define SECCOMP_RET_TRAP          0x00030000U
#define SECCOMP_RET_ERRNO         0x00050000U
#define SECCOMP_RET_USER_NOTIF    0x7fc00000U
#define SECCOMP_RET_TRACE         0x7ff00000U
#define SECCOMP_RET_LOG           0x7ffc0000U
#define SECCOMP_RET_ALLOW         0x7fff0000U

/**
 * sys_seccomp - Operate on a process's secure computing state.
 *
 * @param operation  SECCOMP_SET_MODE_STRICT, SECCOMP_SET_MODE_FILTER,
 *                   SECCOMP_GET_ACTION_AVAIL, or SECCOMP_GET_NOTIF_SIZES
 * @param flags      Operation-specific flags
 * @param uargs      Operation-specific pointer argument
 * @return 0 on success (or value for GET operations), -errno on error
 */
long sys_seccomp(unsigned int operation, unsigned int flags, const void *uargs) {
    switch (operation) {
    case SECCOMP_SET_MODE_STRICT:
        /* Strict mode: only read/write/exit/sigreturn allowed.
         * In Futura's kernel selftest all code is trusted; accept silently. */
        if (flags != 0)
            return -EINVAL;
        if (uargs != NULL)
            return -EINVAL;
        return 0;

    case SECCOMP_SET_MODE_FILTER:
        /* BPF filter mode: not yet implemented */
        return -ENOSYS;

    case SECCOMP_GET_ACTION_AVAIL: {
        /* Check if a given action is supported.
         * Return 0 for any action we nominally support. */
        if (!uargs)
            return -EFAULT;
        uint32_t action = 0;
        /* Read 4 bytes from uargs */
        __builtin_memcpy(&action, uargs, sizeof(action));
        switch (action) {
        case SECCOMP_RET_KILL_PROCESS:
        case SECCOMP_RET_KILL_THREAD:
        case SECCOMP_RET_TRAP:
        case SECCOMP_RET_ERRNO:
        case SECCOMP_RET_TRACE:
        case SECCOMP_RET_LOG:
        case SECCOMP_RET_ALLOW:
            return 0;
        default:
            return -EOPNOTSUPP;
        }
    }

    case SECCOMP_GET_NOTIF_SIZES:
        /* Userspace notification not supported */
        return -EINVAL;

    default:
        return -EINVAL;
    }
}
