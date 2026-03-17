/* kernel/sys_sigtimedwait.c - rt_sigtimedwait() syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Synchronously wait for a queued signal. Used by sigwaitinfo(3),
 * sigtimedwait(3), and internally by thread cancellation.
 */

#include <kernel/fut_task.h>
#include <kernel/fut_thread.h>
#include <kernel/fut_timer.h>
#include <kernel/errno.h>
#include <kernel/kprintf.h>
#include <kernel/uaccess.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>

#ifdef __x86_64__
#include <platform/x86_64/memory/paging.h>
#elif defined(__aarch64__)
#include <platform/arm64/memory/paging.h>
#endif

/* siginfo_t for returning signal info to userspace */
struct kernel_siginfo {
    int      si_signo;
    int      si_errno;
    int      si_code;
    int      __pad0;
    uint32_t si_pid;
    uint32_t si_uid;
    /* Remaining fields zero-filled */
    char     __pad[128 - 24];
};

static inline int sigtimedwait_copy_to_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)dst >= KERNEL_VIRTUAL_BASE) {
        __builtin_memcpy(dst, src, n);
        return 0;
    }
#endif
    return fut_copy_to_user(dst, src, n);
}

static inline int sigtimedwait_copy_from_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)src >= KERNEL_VIRTUAL_BASE) {
        __builtin_memcpy(dst, src, n);
        return 0;
    }
#endif
    return fut_copy_from_user(dst, src, n);
}

/**
 * sys_rt_sigtimedwait - Synchronously wait for a pending signal
 *
 * @param uthese   Set of signals to wait for (bitmask)
 * @param uinfo    Output siginfo_t (may be NULL)
 * @param uts      Timeout (NULL = wait indefinitely)
 * @param sigsetsize  Size of signal set (must be 8)
 *
 * Returns signal number on success, negative error on failure.
 * Dequeues the signal from pending_signals before returning.
 */
long sys_rt_sigtimedwait(const uint64_t *uthese, void *uinfo,
                         const void *uts, size_t sigsetsize) {
    if (sigsetsize != sizeof(uint64_t))
        return -EINVAL;

    if (!uthese)
        return -EINVAL;

    /* Copy signal set from user */
    uint64_t these = 0;
    if (sigtimedwait_copy_from_user(&these, uthese, sizeof(these)) != 0)
        return -EFAULT;

    if (these == 0)
        return -EINVAL;

    /* Parse timeout if provided */
    int64_t deadline_ticks = -1;  /* -1 = infinite */
    if (uts) {
        struct { int64_t tv_sec; long tv_nsec; } ts;
        if (sigtimedwait_copy_from_user(&ts, uts, sizeof(ts)) != 0)
            return -EFAULT;
        if (ts.tv_sec < 0 || ts.tv_nsec < 0 || ts.tv_nsec >= 1000000000L)
            return -EINVAL;
        /* Convert to ticks: sec*100 + nsec/10000000 */
        uint64_t timeout_ticks = (uint64_t)ts.tv_sec * 100;
        timeout_ticks += (uint64_t)ts.tv_nsec / 10000000ULL;
        if (timeout_ticks == 0 && (ts.tv_sec > 0 || ts.tv_nsec > 0))
            timeout_ticks = 1;
        deadline_ticks = (int64_t)(fut_get_ticks() + timeout_ticks);
    }

    fut_task_t *task = fut_task_current();
    if (!task)
        return -ESRCH;

    fut_thread_t *cur_thread = fut_thread_current();

    /* Poll for matching pending signal (per-thread first, then task-wide) */
    for (;;) {
        /* Check per-thread pending (tgkill) first */
        uint64_t matching = 0;
        bool from_thread = false;
        if (cur_thread) {
            uint64_t tp = __atomic_load_n(&cur_thread->thread_pending_signals, __ATOMIC_ACQUIRE);
            matching = tp & these;
            if (matching) from_thread = true;
        }
        if (!matching) {
            uint64_t pending = __atomic_load_n(&task->pending_signals, __ATOMIC_ACQUIRE);
            matching = pending & these;
        }

        if (matching) {
            /* Find lowest-numbered matching signal */
            int signo = __builtin_ctzll(matching) + 1;
            if (signo < 1 || signo > 64)
                signo = 1;

            /* Dequeue from the right bitmask */
            uint64_t bit = (1ULL << (signo - 1));
            if (from_thread && cur_thread)
                __atomic_and_fetch(&cur_thread->thread_pending_signals, ~bit, __ATOMIC_RELEASE);
            else
                __atomic_and_fetch(&task->pending_signals, ~bit, __ATOMIC_RELEASE);

            /* Fill siginfo if requested */
            if (uinfo) {
                struct kernel_siginfo info;
                memset(&info, 0, sizeof(info));
                info.si_signo = signo;
                info.si_code = 0;  /* SI_USER */
                info.si_pid = task->pid;
                info.si_uid = task->uid;
                sigtimedwait_copy_to_user(uinfo, &info, sizeof(info));
            }

            return signo;
        }

        /* Check timeout */
        if (deadline_ticks >= 0 && (int64_t)fut_get_ticks() >= deadline_ticks)
            return -EAGAIN;

        /* Block on signal waitq — woken immediately by fut_signal_send().
         * If timeout is set, limit sleep to remaining time. */
        if (deadline_ticks >= 0) {
            int64_t remain = deadline_ticks - (int64_t)fut_get_ticks();
            if (remain <= 0)
                return -EAGAIN;
            /* Sleep with timed wakeup; fut_signal_send wakes sleeping threads early */
            fut_thread_sleep((uint64_t)remain);
        } else {
            /* No timeout — block indefinitely on signal waitq */
            fut_spinlock_acquire(&task->signal_waitq.lock);
            fut_waitq_sleep_locked(&task->signal_waitq, &task->signal_waitq.lock,
                                   FUT_THREAD_BLOCKED);
        }
    }
}
