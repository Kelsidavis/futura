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

#include <platform/platform.h>

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

    /* Linux's rt_sigqueueinfo surfaces a NULL/bad uinfo pointer through
     * __copy_siginfo_from_user → copy_from_user as -EFAULT. The previous
     * gate collapsed pointer faults into parameter-domain errors. */
    if (uinfo == NULL)
        return -EFAULT;

    if (rtq_access_ok_read(uinfo, sizeof(siginfo_t)) != 0)
        return -EFAULT;

    siginfo_t info;
    if (rtq_copy_from_user(&info, uinfo, sizeof(siginfo_t)) != 0)
        return -EFAULT;

    fut_task_t *caller = fut_task_current();

    /* Kernel-reserved si_code: any positive value is reserved for the
     * kernel (hardware faults, timer expiry, etc.) and must not be
     * forged by an unprivileged caller — applies to self-delivery too,
     * because handlers in the same process may switch on si_code. */
    if (info.si_code > 0) {
        if (!caller || !(caller->cap_effective & (1ULL << 5 /* CAP_KILL */)))
            return -EPERM;
    }

    /* Linux origin-impersonation gate: when delivering to a *different*
     * process, also forbid si_code == 0 (SI_USER, kill(2)) and
     * si_code == SI_TKILL. Both forge the signal's apparent origin — a
     * setuid program that trusts si_pid/si_uid from a SI_USER siginfo
     * could be tricked into believing the signal came from a different
     * sender, or that it was delivered via tkill(2) when it was not. */
    if (caller && caller->pid != (uint64_t)tgid) {
        if (info.si_code == 0 /* SI_USER */ || info.si_code == SI_TKILL)
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
    /* Linux's kernel/signal.c:do_rt_tgsigqueueinfo gates pid/tgid up
     * front: 'if (pid <= 0 || tgid <= 0) return -EINVAL'. The previous
     * Futura code skipped that check, so negative or zero ids fell
     * through to fut_task_by_pid() (or the thread walk) and returned
     * ESRCH instead. ESRCH suggests 'process exists but is gone',
     * which causes libc rt_tgsigqueueinfo wrappers to retry; EINVAL
     * is the documented 'bad argument' error and lets the caller
     * abort fast. */
    if (tgid <= 0 || tid <= 0)
        return -EINVAL;
    if (sig < 0 || sig >= _NSIG)
        return -EINVAL;

    /* NULL uinfo is a pointer fault (EFAULT), matching the
     * rt_sigqueueinfo branch above and Linux's copy_from_user contract. */
    if (uinfo == NULL)
        return -EFAULT;

    if (rtq_access_ok_read(uinfo, sizeof(siginfo_t)) != 0)
        return -EFAULT;

    siginfo_t info;
    if (rtq_copy_from_user(&info, uinfo, sizeof(siginfo_t)) != 0)
        return -EFAULT;

    fut_task_t *caller = fut_task_current();

    /* Kernel-reserved si_code: any positive value requires CAP_KILL. */
    if (info.si_code > 0) {
        if (!caller || !(caller->cap_effective & (1ULL << 5 /* CAP_KILL */)))
            return -EPERM;
    }

    /* Cross-process origin-impersonation gate: forbid forged SI_USER (0)
     * and SI_TKILL (-6) when delivering via rt_tgsigqueueinfo to another
     * process. Same-process delivery is unrestricted. */
    if (caller && caller->pid != (uint64_t)tgid) {
        if (info.si_code == 0 /* SI_USER */ || info.si_code == SI_TKILL)
            return -EPERM;
    }

    info.si_signum = sig;

    /* Locate the target process by TGID */
    fut_task_t *target = fut_task_by_pid(tgid);
    if (!target)
        return -ESRCH;

    /* Permission check (same rules as rt_sigqueueinfo) */
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
