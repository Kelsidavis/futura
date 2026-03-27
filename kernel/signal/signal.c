// SPDX-License-Identifier: MPL-2.0
/*
 * signal.c - Signal handling infrastructure
 *
 * Implements basic POSIX signal delivery, blocking, and default actions.
 */

#include <kernel/signal.h>
#include <kernel/signal_frame.h>
#include <kernel/fut_task.h>
#include <kernel/fut_thread.h>
#include <kernel/fut_timer.h>
#include <kernel/errno.h>
#include <string.h>
#include <stddef.h>

#include <kernel/kprintf.h>

/**
 * Default signal actions
 * Determines what happens when a signal is delivered with no handler installed.
 */
enum {
    SIG_ACTION_TERM = 0,    /* Terminate process */
    SIG_ACTION_CORE,        /* Terminate and generate core dump */
    SIG_ACTION_STOP,        /* Stop process */
    SIG_ACTION_CONT,        /* Continue if stopped */
    SIG_ACTION_IGN,         /* Ignore signal */
};

/* Default action for each signal (indexed by signal number, 0 is unused placeholder)
 *
 * security: Array is indexed by signum directly (1-based), so element [0]
 * is a placeholder to avoid off-by-one. Array has _NSIG (65) elements so that
 * signum values 1..64 are all valid indices (1-31 standard, 32-64 real-time). */
static const int signal_default_action[_NSIG] = {
    [0]  = SIG_ACTION_TERM,  /* placeholder - never accessed (signum >= 1) */
    [1]  = SIG_ACTION_TERM,  /* SIGHUP */
    [2]  = SIG_ACTION_TERM,  /* SIGINT */
    [3]  = SIG_ACTION_CORE,  /* SIGQUIT */
    [4]  = SIG_ACTION_CORE,  /* SIGILL */
    [5]  = SIG_ACTION_CORE,  /* SIGTRAP */
    [6]  = SIG_ACTION_CORE,  /* SIGABRT */
    [7]  = SIG_ACTION_CORE,  /* SIGBUS */
    [8]  = SIG_ACTION_CORE,  /* SIGFPE */
    [9]  = SIG_ACTION_TERM,  /* SIGKILL (cannot be caught) */
    [10] = SIG_ACTION_TERM,  /* SIGUSR1 */
    [11] = SIG_ACTION_CORE,  /* SIGSEGV */
    [12] = SIG_ACTION_TERM,  /* SIGUSR2 */
    [13] = SIG_ACTION_TERM,  /* SIGPIPE */
    [14] = SIG_ACTION_TERM,  /* SIGALRM */
    [15] = SIG_ACTION_TERM,  /* SIGTERM */
    [16] = SIG_ACTION_IGN,   /* (reserved) */
    [17] = SIG_ACTION_IGN,   /* SIGCHLD */
    [18] = SIG_ACTION_CONT,  /* SIGCONT */
    [19] = SIG_ACTION_STOP,  /* SIGSTOP (cannot be caught) */
    [20] = SIG_ACTION_STOP,  /* SIGTSTP */
    [21] = SIG_ACTION_STOP,  /* SIGTTIN */
    [22] = SIG_ACTION_STOP,  /* SIGTTOU */
    [23] = SIG_ACTION_IGN,   /* SIGURG */
    [24] = SIG_ACTION_TERM,  /* SIGXCPU */
    [25] = SIG_ACTION_CORE,  /* SIGXFSZ */
    [26] = SIG_ACTION_TERM,  /* SIGVTALRM */
    [27] = SIG_ACTION_TERM,  /* SIGPROF */
    [28] = SIG_ACTION_IGN,   /* SIGWINCH */
    [29] = SIG_ACTION_IGN,   /* SIGIO */
    [30] = SIG_ACTION_TERM,  /* SIGPWR */
    [31] = SIG_ACTION_CORE,  /* SIGSYS */
    /* Real-time signals 32-64: default action is terminate (POSIX) */
    [32] = SIG_ACTION_TERM,  [33] = SIG_ACTION_TERM,  [34] = SIG_ACTION_TERM,
    [35] = SIG_ACTION_TERM,  [36] = SIG_ACTION_TERM,  [37] = SIG_ACTION_TERM,
    [38] = SIG_ACTION_TERM,  [39] = SIG_ACTION_TERM,  [40] = SIG_ACTION_TERM,
    [41] = SIG_ACTION_TERM,  [42] = SIG_ACTION_TERM,  [43] = SIG_ACTION_TERM,
    [44] = SIG_ACTION_TERM,  [45] = SIG_ACTION_TERM,  [46] = SIG_ACTION_TERM,
    [47] = SIG_ACTION_TERM,  [48] = SIG_ACTION_TERM,  [49] = SIG_ACTION_TERM,
    [50] = SIG_ACTION_TERM,  [51] = SIG_ACTION_TERM,  [52] = SIG_ACTION_TERM,
    [53] = SIG_ACTION_TERM,  [54] = SIG_ACTION_TERM,  [55] = SIG_ACTION_TERM,
    [56] = SIG_ACTION_TERM,  [57] = SIG_ACTION_TERM,  [58] = SIG_ACTION_TERM,
    [59] = SIG_ACTION_TERM,  [60] = SIG_ACTION_TERM,  [61] = SIG_ACTION_TERM,
    [62] = SIG_ACTION_TERM,  [63] = SIG_ACTION_TERM,  [64] = SIG_ACTION_TERM,
};

/**
 * Initialize signal subsystem.
 * Called during kernel startup.
 */
void fut_signal_init(void) {
    fut_printf("[SIGNAL] OK\n");
}

/**
 * Get the default action for a signal.
 *
 * @param signum Signal number (1-30)
 * @return Default action (SIG_ACTION_*)
 */
int fut_signal_get_default_action(int signum) {
    if (signum < 1 || signum >= _NSIG) {
        return SIG_ACTION_TERM;  /* Default if out of range */
    }
    return signal_default_action[signum];
}

/**
 * Check if a signal is pending for delivery to a task.
 *
 * A signal is pending if:
 * 1. It's in the pending_signals bitmask
 * 2. It's not in the signal_mask (not blocked)
 * 3. The signal is 1-30
 *
 * @param task Task to check
 * @param signum Signal number
 * @return Non-zero if signal is pending and unblocked
 */
int fut_signal_is_pending(struct fut_task *task, int signum) {
    if (!task || signum < 1 || signum >= _NSIG) {
        return 0;
    }

    uint64_t signal_bit = (1ULL << (signum - 1));

    /* security: Use atomic load for pending_signals since it can be
     * modified by fut_signal_send() on another CPU (SMP race condition). */
    uint64_t pending = __atomic_load_n(&task->pending_signals, __ATOMIC_ACQUIRE);

    /* Check if signal is pending and not blocked */
    uint64_t mask = __atomic_load_n(&task->signal_mask, __ATOMIC_ACQUIRE);
    if ((pending & signal_bit) &&
        !(mask & signal_bit)) {
        return 1;
    }

    return 0;
}

/**
 * Queue a signal for delivery to a task.
 * The signal will be delivered when the task runs and is not blocked.
 * If the task is blocked on pause(), this will wake it up.
 *
 * @param task Target task
 * @param signum Signal number
 * @return 0 on success, -EINVAL on invalid signal
 */
int fut_signal_send(struct fut_task *task, int signum) {
    if (!task || signum < 1 || signum >= _NSIG) {
        return -EINVAL;
    }

    uint64_t signal_bit = (1ULL << (signum - 1));

    /* SIG_IGN: don't queue ignored signals (except SIGKILL/SIGSTOP which
     * cannot be ignored). POSIX: "Setting a signal action to SIG_IGN for
     * a signal that is pending shall cause the pending signal to be
     * discarded." We prevent new ones from being queued. */
    if (signum != 9 /* SIGKILL */ && signum != 19 /* SIGSTOP */ &&
        task->signal_handlers[signum - 1] == SIG_IGN) {
        return 0;
    }

    /* Fill default siginfo_t (SI_USER) for SA_SIGINFO handlers.
     * Overwritten by fut_signal_send_with_info() for rt_sigqueueinfo.
     * si_pid/si_uid must be the SENDER's identity (POSIX: SI_USER signals
     * from kill() carry the calling process's pid and uid, not the target's). */
    {
        siginfo_t *qi = &task->sig_queue_info[signum - 1];
        fut_task_t *sender = fut_task_current();
        qi->si_signum  = signum;
        qi->si_errno   = 0;
        qi->si_code    = SI_USER;
        qi->si_pid     = sender ? (int64_t)sender->pid : 0;
        qi->si_uid     = sender ? (uint32_t)sender->uid : 0;
        qi->si_status  = 0;
        qi->si_addr    = (void *)0;
        qi->si_value   = 0;
        qi->si_overrun = 0;
        qi->si_timerid = 0;
    }

    /* Atomic OR to queue the signal. pending_signals can be read/cleared
     * by the target task on another CPU during signal delivery. */
    __atomic_or_fetch(&task->pending_signals, signal_bit, __ATOMIC_RELEASE);

    /* Handle default signal actions for unblocked, uncaught signals.
     * SIGKILL and SIGSTOP cannot be caught or blocked.
     * For signals with SIG_DFL whose default is terminate, mark the task. */
    if (signum == 9 /* SIGKILL */) {
        /* SIGKILL: unconditional termination */
        task->exit_code = 0;
        task->term_signal = 9;
        /* Mark all threads for termination so they exit at next opportunity */
        fut_thread_t *kt = task->threads;
        while (kt) {
            kt->state = FUT_THREAD_TERMINATED;
            kt = kt->next;
        }
    } else if (task->signal_handlers[signum - 1] == SIG_DFL) {
        /* Check if blocked — blocked signals defer default action */
        uint64_t blocked = task->signal_mask;
        if (!(blocked & signal_bit)) {
            int action = signal_default_action[signum];
            if (action == SIG_ACTION_TERM || action == SIG_ACTION_CORE) {
                task->exit_code = 0;
                task->term_signal = signum;
            }
        }
    }

    /* Wake all threads blocked on the signal waitq (pause, sigsuspend,
     * signalfd read). Using wake_all ensures both pause() and signalfd
     * readers are notified when a signal arrives. */
    fut_waitq_wake_all(&task->signal_waitq);

    /* Wake any epoll/poll/select instances watching a signalfd for this signal */
    {
        extern void fut_signalfd_wake_epoll(struct fut_task *task, int signo);
        fut_signalfd_wake_epoll(task, signum);
    }

    /* Wake any sleeping or blocked threads in this task for EINTR delivery.
     * SLEEPING threads: interrupted nanosleep/poll/select via fut_thread_wake_sleeping.
     * BLOCKED threads: interrupted pipe read/socket recv/futex wait via wait queue removal. */
    fut_thread_t *t = task->threads;
    while (t) {
        if (t->state == FUT_THREAD_SLEEPING) {
            fut_thread_wake_sleeping(t);
        } else if (t->state == FUT_THREAD_BLOCKED && t->blocked_waitq) {
            /* Remove from wait queue and make ready so the blocking syscall
             * can check pending_signals and return -EINTR. */
            extern bool fut_waitq_remove_thread(fut_waitq_t *q, fut_thread_t *thread);
            if (fut_waitq_remove_thread(t->blocked_waitq, t)) {
                t->blocked_waitq = NULL;
                t->state = FUT_THREAD_READY;
                fut_sched_add_thread(t);
            }
        }
        t = t->next;
    }

    return 0;
}

/**
 * Send a signal with explicit siginfo_t (rt_sigqueueinfo semantics).
 * Stores the caller-provided info, then delegates to fut_signal_send().
 *
 * @param task   Target task
 * @param signum Signal number (1-64)
 * @param info   Pointer to siginfo_t with si_code/si_value filled by caller
 * @return 0 on success, -EINVAL on bad args
 */
int fut_signal_send_with_info(struct fut_task *task, int signum, const void *info) {
    if (!task || signum < 1 || signum >= _NSIG)
        return -EINVAL;

    /* Call fut_signal_send() first to handle pending-bit, wakeup, and
     * default siginfo fill.  Then overwrite the default with the caller's
     * siginfo_t so the correct si_code/si_value reach the handler.
     * Signal delivery only happens when returning to userspace, so there
     * is no race between setting the pending bit and storing the info. */
    int rc = fut_signal_send(task, signum);
    if (rc != 0)
        return rc;

    if (info) {
        __builtin_memcpy(&task->sig_queue_info[signum - 1], info, sizeof(siginfo_t));
        /* Ensure si_signum is correct regardless of what caller provided */
        task->sig_queue_info[signum - 1].si_signum = signum;
    }

    return 0;
}

/**
 * Send a thread-directed signal (tgkill/tkill semantics).
 *
 * Sets the signal bit in thread->thread_pending_signals rather than the
 * task-wide pending_signals. Delivery checks both per-thread and task-wide
 * pending when looking for signals to deliver to a given thread.
 * This is the POSIX model: tgkill() targets a specific thread only.
 *
 * @param thread Target thread
 * @param signum Signal number (1-64)
 * @return 0 on success, -EINVAL on bad args
 */
int fut_signal_send_thread(struct fut_thread *thread, int signum) {
    if (!thread || signum < 1 || signum >= _NSIG)
        return -EINVAL;

    fut_task_t *task = thread->task;
    if (!task)
        return -EINVAL;

    uint64_t signal_bit = (1ULL << (signum - 1));

    /* SIGKILL/SIGSTOP: always deliver to whole task, not thread-directed */
    if (signum == SIGKILL || signum == SIGSTOP)
        return fut_signal_send(task, signum);

    /* SIG_IGN: don't queue */
    if (task->signal_handlers[signum - 1] == SIG_IGN)
        return 0;

    /* Fill default SI_TKILL siginfo_t for SA_SIGINFO delivery.
     * si_pid/si_uid must be the SENDER's identity (tgkill() caller). */
    {
        siginfo_t *qi = &thread->thread_sig_queue_info[signum - 1];
        fut_task_t *sender = fut_task_current();
        qi->si_signum  = signum;
        qi->si_errno   = 0;
        qi->si_code    = SI_TKILL;
        qi->si_pid     = sender ? (int64_t)sender->pid : 0;
        qi->si_uid     = sender ? (uint32_t)sender->uid : 0;
        qi->si_status  = 0;
        qi->si_addr    = (void *)0;
        qi->si_value   = 0;
        qi->si_overrun = 0;
        qi->si_timerid = 0;
    }

    /* Set the per-thread pending bit atomically */
    __atomic_or_fetch(&thread->thread_pending_signals, signal_bit, __ATOMIC_RELEASE);

    /* Handle default TERM/CORE action for unblocked, uncaught signals.
     * Use the target thread's mask (not task-wide) for blocked check. */
    if (task->signal_handlers[signum - 1] == SIG_DFL) {
        uint64_t blocked = __atomic_load_n(&thread->signal_mask, __ATOMIC_ACQUIRE);
        if (!(blocked & signal_bit)) {
            int action = signal_default_action[signum];
            if (action == SIG_ACTION_TERM || action == SIG_ACTION_CORE) {
                task->exit_code = 0;
                task->term_signal = signum;
            }
        }
    }

    /* Wake the specific target thread if sleeping or blocked */
    if (thread->state == FUT_THREAD_SLEEPING) {
        fut_thread_wake_sleeping(thread);
    } else if (thread->state == FUT_THREAD_BLOCKED && thread->blocked_waitq) {
        extern bool fut_waitq_remove_thread(fut_waitq_t *q, fut_thread_t *t);
        if (fut_waitq_remove_thread(thread->blocked_waitq, thread)) {
            thread->blocked_waitq = NULL;
            thread->state = FUT_THREAD_READY;
            fut_sched_add_thread(thread);
        }
    }

    /* Also wake signal waitq (for pause/sigsuspend/signalfd) */
    fut_waitq_wake_all(&task->signal_waitq);

    /* Wake any epoll/poll/select instances watching a signalfd for this signal */
    {
        extern void fut_signalfd_wake_epoll(struct fut_task *task, int signo);
        fut_signalfd_wake_epoll(task, signum);
    }

    return 0;
}

/**
 * Send a thread-directed signal with explicit siginfo_t (rt_tgsigqueueinfo).
 *
 * @param thread Target thread
 * @param signum Signal number (1-64)
 * @param info   Pointer to siginfo_t; if NULL, falls back to fut_signal_send_thread()
 * @return 0 on success, -EINVAL on bad args
 */
int fut_signal_send_thread_with_info(struct fut_thread *thread, int signum, const void *info) {
    if (!thread || signum < 1 || signum >= _NSIG)
        return -EINVAL;

    /* Same ordering as fut_signal_send_with_info: send first (fills SI_TKILL
     * default), then overwrite with caller's siginfo_t. */
    int rc = fut_signal_send_thread(thread, signum);
    if (rc != 0)
        return rc;

    if (info) {
        __builtin_memcpy(&thread->thread_sig_queue_info[signum - 1], info, sizeof(siginfo_t));
        thread->thread_sig_queue_info[signum - 1].si_signum = signum;
    }

    return 0;
}

/**
 * Register a signal handler for a task.
 *
 * @param task Target task
 * @param signum Signal number
 * @param handler Handler function (or SIG_DFL/SIG_IGN)
 * @return 0 on success, -EINVAL on invalid signal
 */
int fut_signal_set_handler(struct fut_task *task, int signum, sighandler_t handler) {
    if (!task || signum < 1 || signum >= _NSIG) {
        return -EINVAL;
    }

    /* SIGKILL and SIGSTOP cannot be caught */
    if (signum == SIGKILL || signum == SIGSTOP) {
        return -EINVAL;
    }

    task->signal_handlers[signum - 1] = handler;

    return 0;
}

/**
 * Get the installed handler for a signal.
 *
 * @param task Target task
 * @param signum Signal number
 * @return Handler function pointer, SIG_DFL, SIG_IGN, or NULL
 */
sighandler_t fut_signal_get_handler(struct fut_task *task, int signum) {
    if (!task || signum < 1 || signum >= _NSIG) {
        return SIG_DFL;
    }

    sighandler_t handler = task->signal_handlers[signum - 1];
    return handler ? handler : SIG_DFL;
}

/**
 * Set signal mask for a task (block/unblock signals).
 *
 * @param task Target task
 * @param how How to modify mask (SIGPROCMASK_BLOCK, etc)
 * @param set Signals to modify
 * @param oldset Previous mask (optional, can be NULL)
 * @return 0 on success
 */
int fut_signal_procmask(struct fut_task *task, int how,
                        const sigset_t *set, sigset_t *oldset) {
    if (!task) {
        return -EINVAL;
    }

    /* POSIX: each thread has its own signal mask.  Prefer the current
     * thread's mask; fall back to the task-wide mask for early-boot or
     * contexts where no thread is scheduled yet. */
    fut_thread_t *cur_thread = fut_thread_current();
    uint64_t *mask_ptr = cur_thread ? &cur_thread->signal_mask : &task->signal_mask;

    /* Save old mask if requested */
    if (oldset) {
        oldset->__mask = __atomic_load_n(mask_ptr, __ATOMIC_ACQUIRE);
    }

    /* security: SIGKILL and SIGSTOP cannot be blocked (POSIX requirement).
     * Strip these bits from the requested set to prevent userspace from making
     * a process unkillable or unstoppable. */
    uint64_t unblockable = (1ULL << (SIGKILL - 1)) | (1ULL << (SIGSTOP - 1));

    /* Modify mask according to 'how' — use atomic operations since signal
     * delivery and other threads may read/write signal_mask concurrently. */
    if (set) {
        uint64_t sanitized = set->__mask & ~unblockable;
        switch (how) {
            case SIGPROCMASK_BLOCK:
                __atomic_or_fetch(mask_ptr, sanitized, __ATOMIC_ACQ_REL);
                break;
            case SIGPROCMASK_UNBLOCK:
                __atomic_and_fetch(mask_ptr, ~sanitized, __ATOMIC_ACQ_REL);
                break;
            case SIGPROCMASK_SETMASK:
                __atomic_store_n(mask_ptr, sanitized, __ATOMIC_RELEASE);
                break;
            default:
                return -EINVAL;
        }
    }

    return 0;
}

/**
 * ARM64: Deliver a pending signal to a task via exception frame modification.
 *
 * This function is called before returning to userspace from an exception.
 * If a signal is pending and unblocked, it constructs an rt_sigframe on the
 * user stack and modifies the exception frame to transfer control to the
 * signal handler.
 *
 * @param task Target task
 * @param frame Interrupt frame to modify (exception context)
 * @return Signal number if delivered, 0 if no pending signal, <0 on error
 */
#ifdef __aarch64__

#include <kernel/signal_frame.h>
#include <kernel/uaccess.h>
#include <platform/arm64/memory/paging.h>

int fut_signal_deliver(struct fut_task *task, void *frame) {
    if (!task || !frame) {
        return 0;
    }

    /* ARM64 exception frame type (must match fut_interrupt_frame_t in
     * exception_handlers.c and the layout built by arm64_exception_entry.S) */
    typedef struct {
        uint64_t x[31];
        uint64_t sp;         /* offset 248: kernel SP (SP_EL1) — NOT the user SP */
        uint64_t pc;         /* offset 256: ELR_EL1 */
        uint64_t pstate;     /* offset 264: SPSR_EL1 */
        uint64_t esr;        /* offset 272 */
        uint64_t far;        /* offset 280 */
        uint64_t fpu_state[64]; /* offset 288..799 */
        uint32_t fpsr;       /* offset 800 */
        uint32_t fpcr;       /* offset 804 */
        uint64_t sp_el0;     /* offset 808: user mode stack pointer */
        uint64_t ttbr0_el1;  /* offset 816: user page table base */
    } arm64_frame_t;

    arm64_frame_t *f = (arm64_frame_t *)frame;

    /* Find first pending, unblocked signal.
     * Check per-thread pending first (tgkill), then task-wide (kill).
     * Use current thread's per-thread signal mask (POSIX per-thread masks). */
    int signum = 0;
    bool from_thread_arm64 = false;
    fut_thread_t *cur_thread_arm64 = fut_thread_current();
    uint64_t cur_mask = cur_thread_arm64 ?
        __atomic_load_n(&cur_thread_arm64->signal_mask, __ATOMIC_ACQUIRE) :
        __atomic_load_n(&task->signal_mask, __ATOMIC_ACQUIRE);

    if (cur_thread_arm64) {
        uint64_t tp = __atomic_load_n(&cur_thread_arm64->thread_pending_signals, __ATOMIC_ACQUIRE);
        for (int i = 1; i < _NSIG; i++) {
            uint64_t bit = (1ULL << (i - 1));
            if ((tp & bit) && !(cur_mask & bit)) { signum = i; from_thread_arm64 = true; break; }
        }
    }
    if (!signum) {
        uint64_t cur_pending = __atomic_load_n(&task->pending_signals, __ATOMIC_ACQUIRE);
        for (int i = 1; i < _NSIG; i++) {
            uint64_t bit = (1ULL << (i - 1));
            if ((cur_pending & bit) && !(cur_mask & bit)) { signum = i; break; }
        }
    }

    /* No pending signal to deliver */
    if (signum == 0) {
        return 0;
    }

    /* Get handler for this signal */
    sighandler_t handler = fut_signal_get_handler(task, signum);

    /* Clear pending signal bit from the appropriate bitmask */
    uint64_t signal_bit = (1ULL << (signum - 1));
    if (from_thread_arm64 && cur_thread_arm64)
        __atomic_and_fetch(&cur_thread_arm64->thread_pending_signals, ~signal_bit, __ATOMIC_ACQ_REL);
    else
        __atomic_and_fetch(&task->pending_signals, ~signal_bit, __ATOMIC_ACQ_REL);

    /* If handler is SIG_DFL or SIG_IGN, don't deliver frame */
    if (handler == SIG_DFL || handler == SIG_IGN) {
        return signum;  /* Caller will handle default action */
    }

    /* Phase 2: Select signal stack — use alternate stack if SA_ONSTACK set
     * and the alternate stack is active (not disabled, not already on it). */
    unsigned long handler_flags = task->signal_handler_flags[signum - 1];
    /* Snapshot altstack BEFORE any modification so uc_stack captures original state. */
    struct sigaltstack saved_altstack = task->sig_altstack;
    uint64_t sp;
    if ((handler_flags & SA_ONSTACK) &&
        !(task->sig_altstack.ss_flags & SS_DISABLE) &&
        !(task->sig_altstack.ss_flags & SS_ONSTACK) &&
        task->sig_altstack.ss_sp != NULL &&
        task->sig_altstack.ss_size >= sizeof(struct rt_sigframe)) {
        /* Deliver on top of alternate stack (grows down from top) */
        sp = (uint64_t)task->sig_altstack.ss_sp + task->sig_altstack.ss_size;
        /* Mark we are now executing on the alternate stack */
        task->sig_altstack.ss_flags |= SS_ONSTACK;
        /* SS_AUTODISARM (Linux 4.7+): atomically disable the altstack when
         * delivering a signal to it, so nested signals cannot reuse it. */
        if (task->sig_altstack.ss_flags & SS_AUTODISARM)
            task->sig_altstack.ss_flags = SS_DISABLE;
    } else {
        /* Use the user-mode stack pointer (SP_EL0), not the kernel stack.
         * f->sp holds the kernel stack pointer (SP_EL1) on ARM64, while
         * f->sp_el0 holds the actual user stack pointer saved on exception
         * entry.  Using f->sp would push the signal frame onto the kernel
         * stack (or garbage if the frame is from an IRQ handler). */
#if defined(__aarch64__)
        sp = f->sp_el0;
#else
        sp = f->sp;
#endif
    }

    /* Allocate rt_sigframe on selected stack with 16-byte alignment.
     * security: Subtract first, then align, to ensure the entire
     * frame fits below the original SP. Aligning before subtracting could
     * leave the frame partially overlapping with the interrupted context. */
    sp -= sizeof(struct rt_sigframe);
    sp &= ~0xFULL;  /* Align to 16 bytes */

    /* security: Check for stack pointer underflow/wraparound.
     * If sp wrapped past zero or is above the original stack pointer,
     * the subtraction overflowed. Also validate sp is in user space
     * using the platform-defined USER_SPACE_END constant. */
    if (sp < 0x1000 || sp >= USER_SPACE_END) {
        return -EFAULT;
    }

    /* Build rt_sigframe on kernel stack first */
    struct rt_sigframe sframe;
    memset(&sframe, 0, sizeof(sframe));

    /* Fill siginfo_t from stored per-signal info (set by fut_signal_send_with_info
     * or defaulted to SI_USER/SI_TKILL by fut_signal_send/fut_signal_send_thread).
     * For thread-directed signals use thread's queue; else use task's. */
    if (from_thread_arm64 && cur_thread_arm64) {
        __builtin_memcpy(&sframe.info, &cur_thread_arm64->thread_sig_queue_info[signum - 1],
                         sizeof(siginfo_t));
    } else {
        __builtin_memcpy(&sframe.info, &task->sig_queue_info[signum - 1], sizeof(siginfo_t));
    }
    /* Always override si_signum for safety; si_addr uses fault address for SIGSEGV etc. */
    sframe.info.si_signum = signum;
    if (sframe.info.si_code == SI_KERNEL || sframe.info.si_code == SI_USER)
        sframe.info.si_addr = (void *)f->far;

    /* Fill ucontext_t */
    sframe.uc.uc_flags = 0;
    sframe.uc.uc_link = NULL;
    /* Save altstack state at delivery time (before SS_AUTODISARM disabled it)
     * so that sigreturn can re-arm the altstack when returning. */
    sframe.uc.uc_stack.ss_sp    = saved_altstack.ss_sp;
    sframe.uc.uc_stack.ss_flags = saved_altstack.ss_flags;
    sframe.uc.uc_stack.ss_size  = saved_altstack.ss_size;

    /* Copy registers from exception frame to sigcontext */
    for (int i = 0; i < 31; i++) {
        sframe.uc.uc_mcontext.gregs.x[i] = f->x[i];
    }
#if defined(__aarch64__)
    sframe.uc.uc_mcontext.gregs.sp = f->sp_el0;  /* User SP, not kernel SP */
#else
    sframe.uc.uc_mcontext.gregs.sp = f->sp;
#endif
    /* SA_RESTART: if syscall was interrupted (x0 == -EINTR) and handler
     * has SA_RESTART, rewind PC to 'svc' instruction (4 bytes back) so
     * the syscall is transparently restarted after the handler returns. */
    {
        int64_t ret_val = (int64_t)f->x[0];
        if ((handler_flags & SA_RESTART) && ret_val == -EINTR) {
            sframe.uc.uc_mcontext.gregs.pc = f->pc - 4;
        } else {
            sframe.uc.uc_mcontext.gregs.pc = f->pc;
        }
    }
    sframe.uc.uc_mcontext.gregs.pstate = f->pstate;
    sframe.uc.uc_mcontext.gregs.fault_address = f->far;

    /* Copy NEON/FPU registers (v[32] are 128-bit, stored as 2x uint64_t) */
    for (int i = 0; i < 32; i++) {
        sframe.uc.uc_mcontext.gregs.v[i] =
            ((__uint128_t)f->fpu_state[2*i+1] << 64) | f->fpu_state[2*i];
    }

    sframe.uc.uc_mcontext.gregs.fpsr = f->fpsr;
    sframe.uc.uc_mcontext.gregs.fpcr = f->fpcr;

    /* Signal mask for restoration — save current thread's mask */
    sframe.uc.uc_sigmask.__mask = cur_mask;

    /* Set return_address field for struct consistency.
     * ARM64 uses x30 (LR) for the actual return, not a stack pop. */
    sframe.return_address = ((handler_flags & SA_RESTORER) &&
                              task->signal_handler_restorers[signum - 1])
        ? task->signal_handler_restorers[signum - 1] : NULL;

    /* Copy rt_sigframe to user stack */
    if (fut_copy_to_user((void *)sp, &sframe, sizeof(sframe)) != 0) {
        return -EFAULT;
    }

    /* Modify exception frame to invoke signal handler */
    f->pc = (uint64_t)handler;
    f->sp = sp;

    /* Set up arguments for signal handler (ARM64 ABI calling convention)
     * x0 = signal number
     * x1 = pointer to siginfo_t (within rt_sigframe)
     * x2 = pointer to ucontext_t (within rt_sigframe)
     * x30 (LR) = sa_restorer: when handler executes 'ret' (br x30), CPU
     *            jumps to sa_restorer which calls rt_sigreturn to restore
     *            the interrupted context. */
    f->x[0] = signum;
    f->x[1] = sp + offsetof(struct rt_sigframe, info);
    f->x[2] = sp + offsetof(struct rt_sigframe, uc);
    /* Set LR to sa_restorer so handler return reaches the trampoline */
    f->x[30] = ((handler_flags & SA_RESTORER) &&
                task->signal_handler_restorers[signum - 1])
        ? (uint64_t)(uintptr_t)task->signal_handler_restorers[signum - 1] : 0;

    /* Block signals during handler: sa_mask + the delivered signal itself.
     * SA_NODEFER: don't block the delivered signal (allow recursive delivery).
     * Update the current thread's mask (per-thread signal mask semantics). */
    uint64_t new_mask_bits = task->signal_handler_masks[signum - 1] &
                             ~((1ULL << (SIGKILL - 1)) | (1ULL << (SIGSTOP - 1)));
    if (!(handler_flags & SA_NODEFER)) {
        new_mask_bits |= signal_bit;
    }
    uint64_t *mask_ptr_arm64 = cur_thread_arm64 ?
        &cur_thread_arm64->signal_mask : &task->signal_mask;
    __atomic_or_fetch(mask_ptr_arm64, new_mask_bits, __ATOMIC_ACQ_REL);

    /* SA_RESETHAND: reset handler to SIG_DFL after delivery */
    if (handler_flags & SA_RESETHAND) {
        task->signal_handlers[signum - 1] = SIG_DFL;
        task->signal_handler_flags[signum - 1] = 0;
    }

    return signum;
}

#elif defined(__x86_64__)

#include <kernel/signal_frame.h>
#include <kernel/uaccess.h>
#include <platform/x86_64/regs.h>
#include <platform/x86_64/memory/paging.h>

/**
 * x86-64: Deliver a pending signal to a task via interrupt frame modification.
 *
 * This is the standalone signal delivery function for x86-64. It is typically
 * called from the POSIX syscall compatibility layer (posix_syscall.c) which
 * has its own more complete implementation. This function serves as a fallback
 * and for non-syscall interrupt returns.
 *
 * For syscall returns, the posix_deliver_signal() function in posix_syscall.c
 * handles signal delivery with full SA_* flags support.
 *
 * @param task Target task
 * @param frame Interrupt frame to modify (fut_interrupt_frame_t *)
 * @return Signal number if delivered, 0 if no pending signal, <0 on error
 */
int fut_signal_deliver(struct fut_task *task, void *frame) {
    if (!task || !frame) {
        return 0;
    }

    fut_interrupt_frame_t *f = (fut_interrupt_frame_t *)frame;

    /* Only deliver signals when returning to userspace (CPL 3) */
    if ((f->cs & 3) == 0) {
        return 0;  /* Returning to kernel mode, don't deliver */
    }

    /* Find first pending, unblocked signal.
     * Check per-thread pending first (tgkill), then task-wide (kill).
     * Use current thread's per-thread signal mask (POSIX per-thread masks). */
    int signum = 0;
    bool from_thread_x86 = false;
    fut_thread_t *cur_thread_x86 = fut_thread_current();
    uint64_t cur_mask = cur_thread_x86 ?
        __atomic_load_n(&cur_thread_x86->signal_mask, __ATOMIC_ACQUIRE) :
        __atomic_load_n(&task->signal_mask, __ATOMIC_ACQUIRE);

    if (cur_thread_x86) {
        uint64_t tp = __atomic_load_n(&cur_thread_x86->thread_pending_signals, __ATOMIC_ACQUIRE);
        for (int i = 1; i < _NSIG; i++) {
            uint64_t bit = (1ULL << (i - 1));
            if ((tp & bit) && !(cur_mask & bit)) { signum = i; from_thread_x86 = true; break; }
        }
    }
    if (!signum) {
        uint64_t cur_pending = __atomic_load_n(&task->pending_signals, __ATOMIC_ACQUIRE);
        for (int i = 1; i < _NSIG; i++) {
            uint64_t bit = (1ULL << (i - 1));
            if ((cur_pending & bit) && !(cur_mask & bit)) { signum = i; break; }
        }
    }

    /* No pending signal to deliver */
    if (signum == 0) {
        return 0;
    }

    /* Get handler for this signal */
    sighandler_t handler = fut_signal_get_handler(task, signum);

    /* Clear pending signal bit from the appropriate bitmask */
    uint64_t signal_bit = (1ULL << (signum - 1));
    if (from_thread_x86 && cur_thread_x86)
        __atomic_and_fetch(&cur_thread_x86->thread_pending_signals, ~signal_bit, __ATOMIC_ACQ_REL);
    else
        __atomic_and_fetch(&task->pending_signals, ~signal_bit, __ATOMIC_ACQ_REL);

    /* Handle SIG_IGN - just ignore the signal */
    if (handler == SIG_IGN) {
        return signum;
    }

    /* Handle SIG_DFL - perform default action */
    if (handler == SIG_DFL) {
        int action = fut_signal_get_default_action(signum);
        switch (action) {
            case SIG_ACTION_TERM:
            case SIG_ACTION_CORE:
                fut_printf("[SIGNAL] Default action: terminate task %llu on signal %d\n",
                           task->pid, signum);
                fut_task_signal_exit(signum);
                return signum;
            case SIG_ACTION_STOP: {
                extern void fut_task_do_stop(struct fut_task *t, int sig);
                fut_task_do_stop(task, signum);
                return signum;
            }
            case SIG_ACTION_CONT: {
                extern void fut_task_do_cont(struct fut_task *t);
                fut_task_do_cont(task);
                return signum;
            }
            case SIG_ACTION_IGN:
            default:
                return signum;
        }
    }

    /* User-defined handler - set up signal frame on user stack */

    unsigned long handler_flags_pre = task->signal_handler_flags[signum - 1];
    /* Snapshot altstack BEFORE any modification so uc_stack captures original state. */
    struct sigaltstack saved_altstack_x86 = task->sig_altstack;
    uint64_t sp;
    if ((handler_flags_pre & SA_ONSTACK) &&
        !(task->sig_altstack.ss_flags & SS_DISABLE) &&
        !(task->sig_altstack.ss_flags & SS_ONSTACK) &&
        task->sig_altstack.ss_sp != NULL &&
        task->sig_altstack.ss_size >= sizeof(struct rt_sigframe)) {
        /* Deliver on top of alternate stack (grows down from top) */
        sp = (uint64_t)task->sig_altstack.ss_sp + task->sig_altstack.ss_size;
        task->sig_altstack.ss_flags |= SS_ONSTACK;
        if (task->sig_altstack.ss_flags & SS_AUTODISARM)
            task->sig_altstack.ss_flags = SS_DISABLE;
    } else {
        sp = f->rsp;
    }

    /* Allocate rt_sigframe on selected stack.
     * x86-64 ABI: at function entry (just after 'call'), RSP % 16 == 8.
     * Signal delivery is equivalent to a 'call': pretcode sits at [RSP]
     * as if the call instruction pushed it.  Linux uses:
     *   sp = round_down(sp - frame_size, 16) - 8
     * so that the frame base (= RSP on handler entry) is 8-byte aligned. */
    sp -= sizeof(struct rt_sigframe);
    sp &= ~0xFULL;  /* Align to 16 bytes */
    sp -= 8;         /* x86-64: RSP must be (16n+8) at handler entry */

    /* security: Check for stack pointer underflow/wraparound.
     * If sp wrapped past zero or is above the original stack pointer,
     * the subtraction overflowed. Also validate sp is in user space. */
    if (sp > f->rsp || sp < 0x1000 || sp >= USER_SPACE_END) {
        fut_printf("[SIGNAL] Invalid user stack pointer %llx for task %llu\n",
                   sp, task->pid);
        return -EFAULT;
    }

    /* Build rt_sigframe on kernel stack first */
    struct rt_sigframe sframe;
    memset(&sframe, 0, sizeof(sframe));

    /* Fill siginfo_t from stored per-signal info (set by fut_signal_send_with_info
     * or defaulted to SI_USER/SI_TKILL by fut_signal_send/fut_signal_send_thread). */
    if (from_thread_x86 && cur_thread_x86) {
        __builtin_memcpy(&sframe.info, &cur_thread_x86->thread_sig_queue_info[signum - 1],
                         sizeof(siginfo_t));
    } else {
        __builtin_memcpy(&sframe.info, &task->sig_queue_info[signum - 1], sizeof(siginfo_t));
    }
    sframe.info.si_signum = signum;

    /* Fill ucontext_t */
    sframe.uc.uc_flags = 0;
    sframe.uc.uc_link = NULL;
    /* Save altstack state at delivery time (before SS_ONSTACK/SS_AUTODISARM
     * modified it) so sigreturn can re-arm the altstack when returning. */
    sframe.uc.uc_stack.ss_sp    = saved_altstack_x86.ss_sp;
    sframe.uc.uc_stack.ss_flags = saved_altstack_x86.ss_flags;
    sframe.uc.uc_stack.ss_size  = saved_altstack_x86.ss_size;

    /* Copy registers from interrupt frame to sigcontext */
    sframe.uc.uc_mcontext.gregs.r8 = f->r8;
    sframe.uc.uc_mcontext.gregs.r9 = f->r9;
    sframe.uc.uc_mcontext.gregs.r10 = f->r10;
    sframe.uc.uc_mcontext.gregs.r11 = f->r11;
    sframe.uc.uc_mcontext.gregs.r12 = f->r12;
    sframe.uc.uc_mcontext.gregs.r13 = f->r13;
    sframe.uc.uc_mcontext.gregs.r14 = f->r14;
    sframe.uc.uc_mcontext.gregs.r15 = f->r15;
    sframe.uc.uc_mcontext.gregs.rdi = f->rdi;
    sframe.uc.uc_mcontext.gregs.rsi = f->rsi;
    sframe.uc.uc_mcontext.gregs.rbp = f->rbp;
    sframe.uc.uc_mcontext.gregs.rbx = f->rbx;
    sframe.uc.uc_mcontext.gregs.rdx = f->rdx;
    sframe.uc.uc_mcontext.gregs.rax = f->rax;
    sframe.uc.uc_mcontext.gregs.rcx = f->rcx;
    sframe.uc.uc_mcontext.gregs.rsp = f->rsp;
    sframe.uc.uc_mcontext.gregs.rip = f->rip;
    sframe.uc.uc_mcontext.gregs.eflags = f->rflags;
    sframe.uc.uc_mcontext.gregs.cs = (uint16_t)f->cs;
    sframe.uc.uc_mcontext.gregs.gs = (uint16_t)f->gs;
    sframe.uc.uc_mcontext.gregs.fs = (uint16_t)f->fs;
    sframe.uc.uc_mcontext.gregs.err = f->error_code;
    sframe.uc.uc_mcontext.gregs.trapno = f->vector;

    /* Signal mask for restoration — save current thread's mask */
    sframe.uc.uc_sigmask.__mask = cur_mask;

    /* Set return address to sa_restorer if SA_RESTORER is set (libc trampoline).
     * On x86_64 RSP is set to &sigframe (offset 0 = return_address), so when
     * the handler executes 'ret', CPU pops return_address into RIP → restorer
     * calls rt_sigreturn to restore the interrupted context. */
    unsigned long h_flags_ret = task->signal_handler_flags[signum - 1];
    sframe.return_address = ((h_flags_ret & SA_RESTORER) &&
                              task->signal_handler_restorers[signum - 1])
        ? task->signal_handler_restorers[signum - 1] : NULL;

    /* Copy rt_sigframe to user stack */
    if (fut_copy_to_user((void *)sp, &sframe, sizeof(sframe)) != 0) {
        fut_printf("[SIGNAL] Failed to copy sigframe to user stack for task %llu\n",
                   task->pid);
        return -EFAULT;
    }

    /* Modify interrupt frame to invoke signal handler.
     * RSP points to &sigframe.return_address (offset 0) so 'ret' lands there. */
    f->rip = (uint64_t)handler;
    f->rsp = sp;

    /* Set up arguments for signal handler (System V AMD64 ABI)
     * rdi = signal number
     * rsi = pointer to siginfo_t (within rt_sigframe)
     * rdx = pointer to ucontext_t (within rt_sigframe)
     */
    f->rdi = signum;
    f->rsi = sp + offsetof(struct rt_sigframe, info);
    f->rdx = sp + offsetof(struct rt_sigframe, uc);

    /* Block signals during handler: sa_mask + the delivered signal itself.
     * SA_NODEFER: don't block the delivered signal (allow recursive delivery).
     * Update the current thread's mask (per-thread signal mask semantics). */
    unsigned long handler_flags_x86 = task->signal_handler_flags[signum - 1];
    uint64_t new_mask_bits_x86 = task->signal_handler_masks[signum - 1] &
                                 ~((1ULL << (SIGKILL - 1)) | (1ULL << (SIGSTOP - 1)));
    if (!(handler_flags_x86 & SA_NODEFER)) {
        new_mask_bits_x86 |= signal_bit;
    }
    uint64_t *mask_ptr_x86 = cur_thread_x86 ?
        &cur_thread_x86->signal_mask : &task->signal_mask;
    __atomic_or_fetch(mask_ptr_x86, new_mask_bits_x86, __ATOMIC_ACQ_REL);

    /* SA_RESETHAND: reset handler to SIG_DFL after delivery */
    if (handler_flags_x86 & SA_RESETHAND) {
        task->signal_handlers[signum - 1] = SIG_DFL;
        task->signal_handler_flags[signum - 1] = 0;
    }

    return signum;
}

#else
#error "Unsupported architecture for signal delivery"
#endif

/**
 * Send signal to the foreground process group.
 * Used by the console driver for Ctrl+C (SIGINT), Ctrl+Z (SIGTSTP), etc.
 *
 * If a foreground process group is set on the console/PTY, sends the signal
 * only to processes in that group. Otherwise falls back to all user processes.
 */
void fut_signal_send_group(int sig) {
    extern fut_task_t *fut_task_list;

    /* Try to find the foreground pgid from the console PTY (fd 0 of the shell) */
    extern int fut_pty_get_fg_pgid(int fd);
    int fg_pgid = 0;

    /* Scan user tasks for one with a controlling terminal that has a fg pgid */
    fut_task_t *scan = fut_task_list;
    while (scan) {
        if (scan->pid > 1 && scan->tty_nr != 0) {
            /* Try to get fg_pgid from any fd that's a PTY */
            if (scan->fd_table) {
                for (int fdi = 0; fdi < scan->max_fds && fdi < 3; fdi++) {
                    if (scan->fd_table[fdi]) {
                        int pg = fut_pty_get_fg_pgid(fdi);
                        if (pg > 0) { fg_pgid = pg; break; }
                    }
                }
            }
            if (fg_pgid > 0) break;
        }
        scan = scan->next;
    }

    fut_task_t *task = fut_task_list;
    while (task) {
        if (task->pid > 1 && task->state != FUT_TASK_ZOMBIE) {
            if (fg_pgid > 0) {
                /* Send only to processes in the foreground group */
                if ((int)task->pgid == fg_pgid)
                    fut_signal_send(task, sig);
            } else {
                /* No fg pgid known: fall back to all user processes */
                fut_signal_send(task, sig);
            }
        }
        task = task->next;
    }
}
