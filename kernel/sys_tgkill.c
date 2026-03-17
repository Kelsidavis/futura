/* kernel/sys_tgkill.c - Thread-directed signal delivery
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements tgkill() and tkill() syscalls for sending signals to specific
 * threads. Essential for pthread_kill(), pthread_cancel(), and thread-directed
 * signal delivery (e.g., SIGSEGV to faulting thread).
 *
 * tgkill(tgid, tid, sig): Send signal to thread tid in thread group tgid.
 * tkill(tid, sig): Legacy version without tgid (race-prone, deprecated).
 *
 * Linux syscall numbers: tgkill=234, tkill=200 (x86_64)
 */

#include <kernel/fut_task.h>
#include <kernel/fut_thread.h>
#include <kernel/signal.h>
#include <kernel/errno.h>
#include <kernel/kprintf.h>
#include <stdint.h>

/**
 * tgkill() - Send signal to specific thread in a thread group
 *
 * @param tgid  Thread group ID (i.e., the PID of the process)
 * @param tid   Thread ID of the target thread
 * @param sig   Signal number (0 for permission check only)
 *
 * Returns:
 *   - 0 on success
 *   - -EINVAL if sig is invalid or tgid/tid <= 0
 *   - -ESRCH if thread not found or tgid mismatch
 *
 * This is the preferred way to send signals to threads because the tgid
 * parameter prevents accidental signal delivery to a recycled TID that
 * now belongs to a different process.
 */
long sys_tgkill(int tgid, int tid, int sig) {
    fut_task_t *current = fut_task_current();
    if (!current)
        return -ESRCH;

    /* Validate tgid and tid */
    if (tgid <= 0 || tid <= 0)
        return -EINVAL;

    /* Validate signal number */
    if (sig < 0 || sig > 64) {
        fut_printf("[TGKILL] tgkill(tgid=%d, tid=%d, sig=%d) -> EINVAL (invalid signal)\n",
                   tgid, tid, sig);
        return -EINVAL;
    }

    /* Look up the target thread */
    fut_thread_t *thread = fut_thread_find((uint64_t)tid);
    if (!thread) {
        fut_printf("[TGKILL] tgkill(tgid=%d, tid=%d, sig=%d) -> ESRCH (thread not found)\n",
                   tgid, tid, sig);
        return -ESRCH;
    }

    /* Verify the thread belongs to the specified thread group (tgid == pid) */
    if (!thread->task || thread->task->pid != (uint64_t)tgid) {
        fut_printf("[TGKILL] tgkill(tgid=%d, tid=%d, sig=%d) -> ESRCH (tgid mismatch, thread belongs to pid=%llu)\n",
                   tgid, tid, sig, thread->task ? thread->task->pid : 0ULL);
        return -ESRCH;
    }

    /* Permission check: same UID, root, or CAP_KILL required */
    if (thread->task != current &&
        current->ruid != 0 &&
        !(current->cap_effective & (1ULL << 5 /* CAP_KILL */)) &&
        current->ruid != thread->task->ruid &&
        current->uid  != thread->task->ruid) {
        return -EPERM;
    }

    /* Signal 0: permission check only */
    if (sig == 0)
        return 0;

    /* Deliver signal to the thread's parent task */
    int result = fut_signal_send(thread->task, sig);
    if (result != 0) {
        fut_printf("[TGKILL] tgkill(tgid=%d, tid=%d, sig=%d) -> %d (signal delivery failed)\n",
                   tgid, tid, sig, result);
    }

    return result;
}

/**
 * tkill() - Send signal to specific thread (legacy, deprecated)
 *
 * @param tid  Thread ID of the target thread
 * @param sig  Signal number (0 for permission check only)
 *
 * Returns:
 *   - 0 on success
 *   - -EINVAL if sig is invalid or tid <= 0
 *   - -ESRCH if thread not found
 *
 * Note: tkill() is deprecated in favor of tgkill() because it doesn't
 * verify the thread group, making it susceptible to PID recycling races.
 * New code should use tgkill() instead.
 */
long sys_tkill(int tid, int sig) {
    fut_task_t *current = fut_task_current();
    if (!current)
        return -ESRCH;

    /* Validate tid */
    if (tid <= 0)
        return -EINVAL;

    /* Validate signal number */
    if (sig < 0 || sig > 64)
        return -EINVAL;

    /* Look up the target thread */
    fut_thread_t *thread = fut_thread_find((uint64_t)tid);
    if (!thread || !thread->task)
        return -ESRCH;

    /* Permission check */
    if (thread->task != current &&
        current->ruid != 0 &&
        !(current->cap_effective & (1ULL << 5 /* CAP_KILL */)) &&
        current->ruid != thread->task->ruid &&
        current->uid  != thread->task->ruid) {
        return -EPERM;
    }

    /* Signal 0: permission check only */
    if (sig == 0)
        return 0;

    /* Deliver signal to the thread's parent task */
    return fut_signal_send(thread->task, sig);
}
