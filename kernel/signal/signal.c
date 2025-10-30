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

extern void fut_printf(const char *fmt, ...);

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

/* Default action for each signal */
static const int signal_default_action[] = {
    /* Index 0 is unused */
    SIG_ACTION_TERM,        /* 1:  SIGHUP */
    SIG_ACTION_TERM,        /* 2:  SIGINT */
    SIG_ACTION_CORE,        /* 3:  SIGQUIT */
    SIG_ACTION_CORE,        /* 4:  SIGILL */
    SIG_ACTION_CORE,        /* 5:  SIGTRAP */
    SIG_ACTION_CORE,        /* 6:  SIGABRT */
    SIG_ACTION_CORE,        /* 7:  SIGBUS */
    SIG_ACTION_CORE,        /* 8:  SIGFPE */
    SIG_ACTION_TERM,        /* 9:  SIGKILL (cannot be caught) */
    SIG_ACTION_TERM,        /* 10: SIGUSR1 */
    SIG_ACTION_CORE,        /* 11: SIGSEGV */
    SIG_ACTION_TERM,        /* 12: SIGUSR2 */
    SIG_ACTION_TERM,        /* 13: SIGPIPE */
    SIG_ACTION_TERM,        /* 14: SIGALRM */
    SIG_ACTION_TERM,        /* 15: SIGTERM */
    SIG_ACTION_IGN,         /* 16: (unused) */
    SIG_ACTION_IGN,         /* 17: SIGCHLD */
    SIG_ACTION_CONT,        /* 18: SIGCONT */
    SIG_ACTION_STOP,        /* 19: SIGSTOP (cannot be caught) */
    SIG_ACTION_STOP,        /* 20: SIGTSTP */
    SIG_ACTION_STOP,        /* 21: SIGTTIN */
    SIG_ACTION_STOP,        /* 22: SIGTTOU */
    SIG_ACTION_IGN,         /* 23: SIGURG */
    SIG_ACTION_TERM,        /* 24: SIGXCPU */
    SIG_ACTION_CORE,        /* 25: SIGXFSZ */
    SIG_ACTION_TERM,        /* 26: SIGVTALRM */
    SIG_ACTION_TERM,        /* 27: SIGPROF */
    SIG_ACTION_IGN,         /* 28: SIGWINCH */
    SIG_ACTION_IGN,         /* 29: SIGIO */
    SIG_ACTION_TERM,        /* 30: SIGPWR */
};

/**
 * Initialize signal subsystem.
 * Called during kernel startup.
 */
void fut_signal_init(void) {
    fut_printf("[SIGNAL] Signal subsystem initialized\n");
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

    /* Check if signal is pending and not blocked */
    if ((task->pending_signals & signal_bit) &&
        !(task->signal_mask & signal_bit)) {
        return 1;
    }

    return 0;
}

/**
 * Queue a signal for delivery to a task.
 * The signal will be delivered when the task runs and is not blocked.
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

    /* Queue the signal */
    task->pending_signals |= signal_bit;

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

    /* Modify mask according to 'how' */
    if (set) {
        switch (how) {
            case SIGPROCMASK_BLOCK:
                task->signal_mask |= set->__mask;
                break;
            case SIGPROCMASK_UNBLOCK:
                task->signal_mask &= ~(set->__mask);
                break;
            case SIGPROCMASK_SETMASK:
                task->signal_mask = set->__mask;
                break;
            default:
                return -EINVAL;
        }
    }

    return 0;
}
