// SPDX-License-Identifier: MPL-2.0
/*
 * signal.h - Signal handling for process control
 */

#pragma once

#include <stdint.h>
#include <stddef.h>

/* Standard POSIX signals */
#define SIGHUP   1   /* Hangup detected on controlling terminal */
#define SIGINT   2   /* Interrupt (Ctrl+C) */
#define SIGQUIT  3   /* Quit from keyboard */
#define SIGILL   4   /* Illegal Instruction */
#define SIGTRAP  5   /* Trace/breakpoint trap */
#define SIGABRT  6   /* Abort signal */
#define SIGBUS   7   /* Bus error */
#define SIGFPE   8   /* Floating point exception */
#define SIGKILL  9   /* Kill signal (cannot be caught or ignored) */
#define SIGUSR1  10  /* User-defined signal 1 */
#define SIGSEGV  11  /* Segmentation fault */
#define SIGUSR2  12  /* User-defined signal 2 */
#define SIGPIPE  13  /* Broken pipe */
#define SIGALRM  14  /* Alarm clock */
#define SIGTERM  15  /* Termination signal */
#define SIGCHLD  17  /* Child process terminated or stopped */
#define SIGCONT  18  /* Continue if stopped */
#define SIGSTOP  19  /* Stop process (cannot be caught or ignored) */
#define SIGTSTP  20  /* Terminal stop (Ctrl+Z) */
#define SIGTTIN  21  /* Background read from tty */
#define SIGTTOU  22  /* Background write to tty */
#define SIGURG   23  /* Urgent condition on socket */
#define SIGXCPU  24  /* CPU time limit exceeded */
#define SIGXFSZ  25  /* File size limit exceeded */
#define SIGVTALRM 26 /* Virtual alarm clock */
#define SIGPROF  27  /* Profiling timer expired */
#define SIGWINCH 28  /* Window size change */
#define SIGIO    29  /* I/O now possible */
#define SIGPWR   30  /* Power failure */

#define _NSIG    31  /* Number of signals */

/* Signal handler type - function called when signal delivered */
typedef void (*sighandler_t)(int);

/* Default signal handlers */
#define SIG_DFL  ((sighandler_t) 0)   /* Default action */
#define SIG_IGN  ((sighandler_t) 1)   /* Ignore signal */
#define SIG_ERR  ((sighandler_t) -1)  /* Error return value */

/* sigaction - Detailed signal handler specification */
struct sigaction {
    sighandler_t sa_handler;           /* Handler function or SIG_DFL/SIG_IGN */
    uint64_t     sa_mask;              /* Signals to block during handler */
    int          sa_flags;             /* Flags (SA_RESTART, etc.) */
};

/* sigaction() flags */
#define SA_NOCLDSTOP  0x00000001  /* Don't send SIGCHLD when child stops */
#define SA_RESTART    0x10000000  /* Restart syscall when signal returns */
#define SA_RESETHAND  0x80000000  /* Reset handler to SIG_DFL after delivery */

/* Signal masks and operations */
typedef struct {
    uint64_t __mask;
} sigset_t;

#define SIGPROCMASK_BLOCK   0   /* SIG_BLOCK: Add signals to mask */
#define SIGPROCMASK_UNBLOCK 1   /* SIG_UNBLOCK: Remove signals from mask */
#define SIGPROCMASK_SETMASK 2   /* SIG_SETMASK: Set mask exactly */

/* Forward declaration */
struct fut_task;

/* Kernel signal handling initialization */
void fut_signal_init(void);

/* Get standard signal action (default action for a signal) */
int fut_signal_get_default_action(int signum);

/* Queue a signal for delivery to a task */
int fut_signal_send(struct fut_task *task, int signum);

/* Register a signal handler for a task */
int fut_signal_set_handler(struct fut_task *task, int signum, sighandler_t handler);

/* Get the installed handler for a signal */
sighandler_t fut_signal_get_handler(struct fut_task *task, int signum);

/* Set signal mask for a task (block/unblock signals) */
int fut_signal_procmask(struct fut_task *task, int how,
                        const sigset_t *set, sigset_t *oldset);

/* Internal: Check if signal should be delivered to a task */
int fut_signal_is_pending(struct fut_task *task, int signum);
