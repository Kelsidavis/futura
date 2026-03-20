/* kernel/sys_prctl.c - Process control operations
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements prctl() for per-process attribute control.
 * Supports commonly-used operations needed by libc and runtime libraries.
 */

#include <kernel/fut_task.h>
#include <kernel/fut_thread.h>
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
#define PR_GET_SECCOMP      21   /* Get current seccomp mode */
#define PR_SET_SECCOMP      22   /* Set seccomp mode */
#define PR_GET_TID_ADDRESS  50   /* Get pointer set by set_tid_address() */
#define PR_GET_SPECULATION_CTRL 52 /* Get Spectre mitigation state */
#define PR_SET_SPECULATION_CTRL 53 /* Set Spectre mitigation state */
#define PR_CAP_AMBIENT      47   /* Ambient capability management (Linux 4.3+) */
#define PR_CAP_AMBIENT_IS_SET  1   /* arg3: check if cap arg3 is in ambient set */
#define PR_CAP_AMBIENT_RAISE   2   /* arg3: add cap arg3 to ambient set */
#define PR_CAP_AMBIENT_LOWER   3   /* arg3: remove cap arg3 from ambient set */
#define PR_CAP_AMBIENT_CLEAR_ALL 4 /* Clear all ambient capabilities */
#define PR_SPEC_STORE_BYPASS     0 /* Spectre v4 store bypass (arg2 to GET/SET) */
#define PR_SPEC_INDIRECT_BRANCH  1 /* Spectre v2 indirect branch (arg2) */
#define PR_SPEC_L1D_FLUSH        2 /* L1D cache flush on context switch */
/* Speculation values returned by PR_GET_SPECULATION_CTRL */
#define PR_SPEC_NOT_AFFECTED     0
#define PR_SPEC_PRCTL            (1UL << 0)
#define PR_SPEC_ENABLE           (1UL << 1)
#define PR_SPEC_DISABLE          (1UL << 2)
#define PR_SPEC_FORCE_DISABLE    (1UL << 3)
#define PR_SPEC_DISABLE_NOEXEC   (1UL << 4)

/* Maximum valid signal number */
#define PR_MAX_SIGNAL       64

/* Kernel-pointer-safe copy to user (for selftest support) */
static inline int prctl_copy_to_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)dst >= KERNEL_VIRTUAL_BASE) {
        __builtin_memcpy(dst, src, n);
        return 0;
    }
#endif
    return fut_copy_to_user(dst, src, n);
}

/* Linux 5.6+ prctl options (accepted as no-ops) */
#define PR_SET_IO_FLUSHER   57  /* Mark thread as I/O flusher (memory-pressure exempt) */
#define PR_GET_IO_FLUSHER   58  /* Get I/O flusher state */

/* Linux 5.14+ */
#define PR_SCHED_CORE       62  /* Core scheduling operations */

/* Linux 6.3+ */
#define PR_SET_MDWE         65  /* Memory-deny-write-execute policy */
#define PR_GET_MDWE         66  /* Get MDWE policy */

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
    (void)arg4; (void)arg5;

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
        if (prctl_copy_to_user(uptr, &val, sizeof(int)) != 0) {
            return -EFAULT;
        }
        return 0;
    }

    case PR_SET_NAME: {
        /* Set calling thread's name (max 15 chars + null).
         * Linux semantics: per-thread name, not per-process.
         * Also update task->comm so /proc/<pid>/status Name: is consistent
         * when the main thread (tid == pid) renames itself. */
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
        /* Set per-thread name */
        fut_thread_t *cur_thread = fut_thread_current();
        if (cur_thread)
            memcpy(cur_thread->comm, kname, 16);
        /* Keep task->comm in sync (used by /proc/<pid>/status Name: field) */
        memcpy(task->comm, kname, 16);
        return 0;
    }

    case PR_GET_NAME: {
        /* Get calling thread's name (per-thread in Linux). */
        char *uname = (char *)(uintptr_t)arg2;
        if (!uname) {
            return -EFAULT;
        }
        fut_thread_t *cur_thread = fut_thread_current();
        const char *src = (cur_thread && cur_thread->comm[0]) ? cur_thread->comm : task->comm;
        if (fut_copy_to_user(uname, src, 16) != 0) {
            /* If copy_to_user fails, try direct copy (kernel pointer) */
            memcpy(uname, src, 16);
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

    case PR_GET_SECCOMP:
        /* No seccomp filter active; return SECCOMP_MODE_DISABLED (0) */
        return 0;

    case PR_SET_SECCOMP:
        /* Accept all seccomp modes as no-op (no BPF enforcement in Futura).
         * SECCOMP_MODE_DISABLED=0, SECCOMP_MODE_STRICT=1, SECCOMP_MODE_FILTER=2 */
        if (arg2 > 2)
            return -EINVAL;
        return 0;

    case PR_GET_TID_ADDRESS: {
        /* Return the address registered via set_tid_address() for this thread.
         * gdb and thread-library diagnostics use this to find a thread's TID word. */
        if (!arg2)
            return -EFAULT;
        fut_thread_t *thr = fut_thread_current();
        void *tid_addr = thr ? (void *)thr->clear_child_tid : (void *)task->clear_child_tid;
        uint64_t *out = (uint64_t *)arg2;
#ifdef KERNEL_VIRTUAL_BASE
        if ((uintptr_t)out >= KERNEL_VIRTUAL_BASE) {
            *out = (uint64_t)(uintptr_t)tid_addr;
            return 0;
        }
#endif
        uint64_t val = (uint64_t)(uintptr_t)tid_addr;
        if (fut_copy_to_user(out, &val, sizeof(val)) != 0)
            return -EFAULT;
        return 0;
    }

    case PR_GET_SPECULATION_CTRL:
        /* Futura has no speculative-execution hardware vulnerabilities in emulation;
         * report NOT_AFFECTED for all speculation types. */
        (void)arg2;
        return PR_SPEC_NOT_AFFECTED;

    case PR_SET_SPECULATION_CTRL:
        /* Silently accept — no real speculation mitigations needed. */
        return 0;

    case PR_CAP_AMBIENT: {
        /* Ambient capability management (Linux 4.3+).
         * arg2 = operation (IS_SET/RAISE/LOWER/CLEAR_ALL), arg3 = capability number.
         * Futura has no ambient capability set yet; accept all ops as stubs. */
        int op = (int)arg2;
        switch (op) {
        case PR_CAP_AMBIENT_IS_SET:
            /* Check if cap arg3 is in ambient set — always not set */
            if ((int)arg3 < 0 || (int)arg3 > 63)
                return -EINVAL;
            return 0;
        case PR_CAP_AMBIENT_RAISE:
            /* Add cap to ambient set — accept without enforcement */
            if ((int)arg3 < 0 || (int)arg3 > 63)
                return -EINVAL;
            return 0;
        case PR_CAP_AMBIENT_LOWER:
            /* Remove cap from ambient set — no-op */
            if ((int)arg3 < 0 || (int)arg3 > 63)
                return -EINVAL;
            return 0;
        case PR_CAP_AMBIENT_CLEAR_ALL:
            /* Clear all ambient capabilities — no-op */
            return 0;
        default:
            return -EINVAL;
        }
    }

    case PR_SET_IO_FLUSHER:
        /* Linux 5.6+: mark thread as memory-pressure-exempt I/O flusher.
         * No I/O pressure management in Futura; accept and return 0. */
        return 0;

    case PR_GET_IO_FLUSHER:
        /* Return 0: thread is not an I/O flusher. */
        return 0;

    case PR_SCHED_CORE:
        /* Linux 5.14+ core scheduling; no scheduling domain support. */
        return -ENOTSUP;

    case PR_SET_MDWE:
        /* Linux 6.3+ memory-deny-write-execute; silently accept. */
        return 0;

    case PR_GET_MDWE:
        /* Return 0: no MDWE restrictions. */
        return 0;

    default:
        fut_printf("[PRCTL] prctl(option=%d) -> EINVAL (unsupported option)\n", option);
        return -EINVAL;
    }
}
