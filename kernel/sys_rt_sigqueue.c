// SPDX-License-Identifier: MPL-2.0
/*
 * sys_rt_sigqueue.c - rt_sigqueueinfo and rt_tgsigqueueinfo syscalls
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements:
 *   rt_sigqueueinfo(2)  — send a signal with attached siginfo_t to a process
 *   rt_tgsigqueueinfo(2) — send a signal with attached siginfo_t to a specific
 *                          thread within a process (thread-group-kill semantics)
 *
 * These syscalls power libc's sigqueue(3) and pthread_sigqueue(3), which allow
 * callers to attach a sigval_t (int or pointer) to a signal for SA_SIGINFO
 * handlers to read via siginfo_t->si_value.
 *
 * Security:
 *   POSIX requires that the caller may only supply si_code <= 0.  Positive
 *   si_code values are reserved for the kernel (hardware faults, timer
 *   expiry, etc.) and must not be forged by userspace.  Processes with
 *   CAP_KILL may send signals to arbitrary processes; otherwise the caller
 *   must have the same effective UID as the target (or SIGCONT to same
 *   session), matching standard kill(2) rules.
 */

#include <kernel/fut_task.h>
#include <kernel/fut_thread.h>
#include <kernel/signal.h>
#include <kernel/signal_frame.h>
#include <kernel/errno.h>
#include <kernel/kprintf.h>
#include <kernel/uaccess.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#ifdef __x86_64__
#include <platform/x86_64/memory/paging.h>
#elif defined(__aarch64__)
#include <platform/arm64/memory/paging.h>
#endif

/* Bypass helper: kernel selftest pointers don't go through copy_from_user */
static inline int rtq_copy_from_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)src >= KERNEL_VIRTUAL_BASE) { __builtin_memcpy(dst, src, n); return 0; }
#endif
    return fut_copy_from_user(dst, src, n);
}

static inline int rtq_access_ok_read(const void *ptr, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)ptr >= KERNEL_VIRTUAL_BASE) return 0;
#endif
    return fut_access_ok(ptr, n, 0);
}

/* ------------------------------------------------------------------ *
 *  rt_sigqueueinfo — send signal + siginfo_t to a process (by PID)   *
 * ------------------------------------------------------------------ */
long sys_rt_sigqueueinfo(int tgid, int sig, const void *uinfo) {
    /* sig == 0: permission check only, no signal delivered */
    if (sig < 0 || sig >= _NSIG)
        return -EINVAL;

    if (uinfo == NULL)
        return -EINVAL;

    if (rtq_access_ok_read(uinfo, sizeof(siginfo_t)) != 0)
        return -EFAULT;

    siginfo_t info;
    if (rtq_copy_from_user(&info, uinfo, sizeof(siginfo_t)) != 0)
        return -EFAULT;

    /* Security: userspace may only set si_code <= 0 (SI_USER, SI_QUEUE, etc.)
     * Positive values are reserved for kernel-generated infos and cannot be
     * forged by an unprivileged caller. */
    if (info.si_code > 0) {
        fut_task_t *caller = fut_task_current();
        /* Allow if caller has CAP_KILL (capability bit 5) */
        if (!caller || !(caller->cap_effective & (1ULL << 5)))
            return -EPERM;
    }

    /* Ensure si_signo matches the requested signal */
    info.si_signum = sig;

    /* Locate target process */
    fut_task_t *target = fut_task_by_pid(tgid);
    if (!target)
        return -ESRCH;

    /* Permission check: caller's eUID must match target's eUID, or caller
     * must have CAP_KILL (bit 5), unless sending SIGCONT to same session. */
    fut_task_t *caller = fut_task_current();
    if (caller && caller->pid != (uint64_t)tgid) {
        bool cap_kill = (caller->cap_effective & (1ULL << 5)) != 0;
        bool same_uid = (caller->uid == target->uid) ||
                        (caller->uid == target->ruid) ||
                        (caller->ruid == target->uid);
        bool sigcont_same_session = (sig == SIGCONT) &&
                                    (caller->pgid == target->pgid);
        if (!cap_kill && !same_uid && !sigcont_same_session)
            return -EPERM;
    }

    if (sig == 0)
        return 0;  /* Permission check passed, no delivery */

    return fut_signal_send_with_info(target, sig, &info);
}

/* ------------------------------------------------------------------ *
 *  rt_tgsigqueueinfo — send signal + siginfo_t to a specific thread  *
 * ------------------------------------------------------------------ */
long sys_rt_tgsigqueueinfo(int tgid, int tid, int sig, const void *uinfo) {
    if (sig < 0 || sig >= _NSIG)
        return -EINVAL;

    if (uinfo == NULL)
        return -EINVAL;

    if (rtq_access_ok_read(uinfo, sizeof(siginfo_t)) != 0)
        return -EFAULT;

    siginfo_t info;
    if (rtq_copy_from_user(&info, uinfo, sizeof(siginfo_t)) != 0)
        return -EFAULT;

    if (info.si_code > 0) {
        fut_task_t *caller = fut_task_current();
        if (!caller || !(caller->cap_effective & (1ULL << 5)))
            return -EPERM;
    }

    info.si_signum = sig;

    /* Locate the target process by TGID */
    fut_task_t *target = fut_task_by_pid(tgid);
    if (!target)
        return -ESRCH;

    /* Permission check (same rules as rt_sigqueueinfo) */
    fut_task_t *caller = fut_task_current();
    if (caller && caller->pid != (uint64_t)tgid) {
        bool cap_kill = (caller->cap_effective & (1ULL << 5)) != 0;
        bool same_uid = (caller->uid == target->uid) ||
                        (caller->uid == target->ruid) ||
                        (caller->ruid == target->uid);
        bool sigcont_same_session = (sig == SIGCONT) &&
                                    (caller->pgid == target->pgid);
        if (!cap_kill && !same_uid && !sigcont_same_session)
            return -EPERM;
    }

    if (sig == 0)
        return 0;

    /* Find the specific thread by TID within the target task */
    fut_thread_t *thr = target->threads;
    while (thr) {
        if ((int)thr->tid == tid)
            break;
        thr = thr->next;
    }
    if (!thr)
        return -ESRCH;

    return fut_signal_send_thread_with_info(thr, sig, &info);
}
