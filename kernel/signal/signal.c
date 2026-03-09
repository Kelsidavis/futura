// SPDX-License-Identifier: MPL-2.0
/*
 * signal.c - Signal handling infrastructure
 *
 * Implements basic POSIX signal delivery, blocking, and default actions.
 */

#include <kernel/signal.h>
#include <kernel/fut_task.h>
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
 * is a placeholder to avoid off-by-one. Array has _NSIG (31) elements so that
 * signum values 1..30 are all valid indices. */
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
    [16] = SIG_ACTION_IGN,   /* (unused) */
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
    if ((pending & signal_bit) &&
        !(task->signal_mask & signal_bit)) {
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

    /* security: Use atomic OR to queue the signal. pending_signals
     * can be read/cleared by the target task on another CPU during signal
     * delivery. Non-atomic |= is a read-modify-write race on SMP. */
    __atomic_or_fetch(&task->pending_signals, signal_bit, __ATOMIC_RELEASE);

    /* Wake task if it's blocked on pause() syscall.
     * When the task wakes, sys_pause() will check pending_signals
     * and return -EINTR to deliver the signal. */
    fut_waitq_wake_one(&task->signal_waitq);

    fut_printf("[SIGNAL] Queued signal %d for task %llu\n", signum, task->pid);

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

    fut_printf("[SIGNAL] Set handler for signal %d in task %llu to %p\n",
               signum, task->pid, handler);

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

    /* Save old mask if requested */
    if (oldset) {
        oldset->__mask = task->signal_mask;
    }

    /* security: SIGKILL and SIGSTOP cannot be blocked (POSIX requirement).
     * Strip these bits from the requested set to prevent userspace from making
     * a process unkillable or unstoppable. */
    uint64_t unblockable = (1ULL << (SIGKILL - 1)) | (1ULL << (SIGSTOP - 1));

    /* Modify mask according to 'how' */
    if (set) {
        uint64_t sanitized = set->__mask & ~unblockable;
        switch (how) {
            case SIGPROCMASK_BLOCK:
                task->signal_mask |= sanitized;
                break;
            case SIGPROCMASK_UNBLOCK:
                task->signal_mask &= ~(sanitized);
                break;
            case SIGPROCMASK_SETMASK:
                task->signal_mask = sanitized;
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

    /* ARM64 exception frame type */
    typedef struct {
        uint64_t x[31];
        uint64_t sp;
        uint64_t pc;
        uint64_t pstate;
        uint64_t esr;
        uint64_t far;
        uint64_t fpu_state[64];
        uint32_t fpsr;
        uint32_t fpcr;
    } arm64_frame_t;

    arm64_frame_t *f = (arm64_frame_t *)frame;

    /* Find first pending, unblocked signal */
    int signum = 0;
    for (int i = 1; i < _NSIG; i++) {
        uint64_t signal_bit = (1ULL << (i - 1));
        if ((task->pending_signals & signal_bit) &&
            !(task->signal_mask & signal_bit)) {
            signum = i;
            break;
        }
    }

    /* No pending signal to deliver */
    if (signum == 0) {
        return 0;
    }

    /* Get handler for this signal */
    sighandler_t handler = fut_signal_get_handler(task, signum);

    /* Clear pending signal bit first */
    uint64_t signal_bit = (1ULL << (signum - 1));
    task->pending_signals &= ~signal_bit;

    /* If handler is SIG_DFL or SIG_IGN, don't deliver frame */
    if (handler == SIG_DFL || handler == SIG_IGN) {
        return signum;  /* Caller will handle default action */
    }

    /* Allocate rt_sigframe on user stack with 16-byte alignment.
     * security: Subtract first, then align, to ensure the entire
     * frame fits below the original SP. Aligning before subtracting could
     * leave the frame partially overlapping with the interrupted context. */
    uint64_t sp = f->sp;
    sp -= sizeof(struct rt_sigframe);
    sp &= ~0xFULL;  /* Align to 16 bytes */

    /* security: Check for stack pointer underflow/wraparound.
     * If sp wrapped past zero or is above the original stack pointer,
     * the subtraction overflowed. Also validate sp is in user space
     * using the platform-defined USER_SPACE_END constant. */
    if (sp > f->sp || sp < 0x1000 || sp >= USER_SPACE_END) {
        return -EFAULT;
    }

    /* Build rt_sigframe on kernel stack first */
    struct rt_sigframe sframe;
    memset(&sframe, 0, sizeof(sframe));

    /* Fill siginfo_t */
    sframe.info.si_signum = signum;
    sframe.info.si_errno = 0;
    sframe.info.si_code = SI_USER;
    sframe.info.si_pid = 0;
    sframe.info.si_uid = 0;
    sframe.info.si_addr = (void *)f->far;

    /* Fill ucontext_t */
    sframe.uc.uc_flags = 0;
    sframe.uc.uc_link = NULL;
    sframe.uc.uc_stack.ss_sp = (void *)f->sp;
    sframe.uc.uc_stack.ss_flags = 0;
    sframe.uc.uc_stack.ss_size = 0x1000;

    /* Copy registers from exception frame to sigcontext */
    for (int i = 0; i < 31; i++) {
        sframe.uc.uc_mcontext.gregs.x[i] = f->x[i];
    }
    sframe.uc.uc_mcontext.gregs.sp = f->sp;
    sframe.uc.uc_mcontext.gregs.pc = f->pc;
    sframe.uc.uc_mcontext.gregs.pstate = f->pstate;
    sframe.uc.uc_mcontext.gregs.fault_address = f->far;

    /* Copy NEON/FPU registers (v[32] are 128-bit, stored as 2x uint64_t) */
    for (int i = 0; i < 32; i++) {
        sframe.uc.uc_mcontext.gregs.v[i] =
            ((__uint128_t)f->fpu_state[2*i+1] << 64) | f->fpu_state[2*i];
    }

    sframe.uc.uc_mcontext.gregs.fpsr = f->fpsr;
    sframe.uc.uc_mcontext.gregs.fpcr = f->fpcr;

    /* Signal mask for restoration */
    sframe.uc.uc_sigmask.__mask = task->signal_mask;

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
     */
    f->x[0] = signum;
    f->x[1] = sp + offsetof(struct rt_sigframe, info);
    f->x[2] = sp + offsetof(struct rt_sigframe, uc);

    /* security: Block the delivered signal while handler is running.
     * This prevents recursive signal delivery which could overflow the user
     * stack. Matches x86-64 behavior. The mask is restored by sigreturn(). */
    task->signal_mask |= signal_bit;

    fut_printf("[SIGNAL] Delivered signal %d to task %llu (handler=%p, sp=%llx)\n",
               signum, task->pid, handler, sp);

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

    /* Find first pending, unblocked signal */
    int signum = 0;
    for (int i = 1; i < _NSIG; i++) {
        uint64_t signal_bit = (1ULL << (i - 1));
        if ((task->pending_signals & signal_bit) &&
            !(task->signal_mask & signal_bit)) {
            signum = i;
            break;
        }
    }

    /* No pending signal to deliver */
    if (signum == 0) {
        return 0;
    }

    /* Get handler for this signal */
    sighandler_t handler = fut_signal_get_handler(task, signum);

    /* Clear pending signal bit first */
    uint64_t signal_bit = (1ULL << (signum - 1));
    task->pending_signals &= ~signal_bit;

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
            case SIG_ACTION_STOP:
            case SIG_ACTION_CONT:
                /* Not yet implemented */
                return signum;
            case SIG_ACTION_IGN:
            default:
                return signum;
        }
    }

    /* User-defined handler - set up signal frame on user stack */

    /* Allocate rt_sigframe on user stack with 16-byte alignment */
    uint64_t sp = f->rsp;
    sp -= sizeof(struct rt_sigframe);
    sp &= ~0xFULL;  /* Align to 16 bytes */

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

    /* Fill siginfo_t */
    sframe.info.si_signum = signum;
    sframe.info.si_errno = 0;
    sframe.info.si_code = SI_USER;
    sframe.info.si_pid = 0;
    sframe.info.si_uid = 0;
    sframe.info.si_addr = NULL;

    /* Fill ucontext_t */
    sframe.uc.uc_flags = 0;
    sframe.uc.uc_link = NULL;
    sframe.uc.uc_stack.ss_sp = (void *)f->rsp;
    sframe.uc.uc_stack.ss_flags = 0;
    sframe.uc.uc_stack.ss_size = 0x1000;

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

    /* Signal mask for restoration */
    sframe.uc.uc_sigmask.__mask = task->signal_mask;

    /* Set return address to NULL - handler should call sigreturn explicitly */
    sframe.return_address = NULL;

    /* Copy rt_sigframe to user stack */
    if (fut_copy_to_user((void *)sp, &sframe, sizeof(sframe)) != 0) {
        fut_printf("[SIGNAL] Failed to copy sigframe to user stack for task %llu\n",
                   task->pid);
        return -EFAULT;
    }

    /* Modify interrupt frame to invoke signal handler */
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

    /* Block the signal while handler is running */
    task->signal_mask |= signal_bit;

    fut_printf("[SIGNAL] Delivered signal %d to task %llu (handler=%p, sp=%llx)\n",
               signum, task->pid, handler, sp);

    return signum;
}

#else
#error "Unsupported architecture for signal delivery"
#endif
