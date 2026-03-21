// SPDX-License-Identifier: MPL-2.0
/*
 * signal.h - Signal handling for process control
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements POSIX-compatible signal handling for inter-process
 * communication and process lifecycle control. Signals are software
 * interrupts delivered to processes for events like:
 *   - Terminal input (Ctrl+C → SIGINT, Ctrl+Z → SIGTSTP)
 *   - Hardware faults (SIGSEGV, SIGBUS, SIGFPE)
 *   - Process management (SIGKILL, SIGTERM, SIGCHLD)
 *   - I/O events (SIGPIPE, SIGIO)
 *
 * Features:
 *   - Standard POSIX signals (1-31)
 *   - Custom signal handlers via sigaction()
 *   - Signal masking (blocking/unblocking)
 *   - Alternate signal stacks (sigaltstack)
 *
 * Signal delivery:
 *   1. Signal is queued to target task
 *   2. When task returns to userspace, pending signals are checked
 *   3. If signal is not blocked, handler is invoked on task's stack
 *   4. After handler returns, task continues from interrupted point
 */

#pragma once

#include <stdint.h>
#include <stddef.h>

/* Standard POSIX signals (1-31) */
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
#define SIGSYS   31  /* Bad system call (seccomp, ptrace) */

/* Real-time signals (32-64) — used by NPTL/pthreads for internal management */
#define SIGRTMIN 32  /* First real-time signal */
#define SIGRTMAX 64  /* Last real-time signal */

/* _NSIG: total signal count + 1 (signals are 1-based).
 * Supports signals 1-64: 1-31 standard POSIX + 32-64 real-time (SIGRT). */
#define _NSIG    65

/* Signal handler type - function called when signal delivered */
typedef void (*sighandler_t)(int);

/* Default signal handlers */
#define SIG_DFL  ((sighandler_t) 0)   /* Default action */
#define SIG_IGN  ((sighandler_t) 1)   /* Ignore signal */
#define SIG_ERR  ((sighandler_t) -1)  /* Error return value */

/* Signal masks and operations — defined before struct sigaction which uses sigset_t */
typedef struct {
    uint64_t __mask;
} sigset_t;

/* sigaction - Signal handler specification (matches Linux kernel ABI for rt_sigaction)
 *
 * Linux kernel ABI layout (x86_64/ARM64):
 *   offset  0: sa_handler / sa_sigaction  (8 bytes)
 *   offset  8: sa_flags                   (8 bytes, unsigned long)
 *   offset 16: sa_restorer                (8 bytes)
 *   offset 24: sa_mask                    (8 bytes)
 *
 * This matches the struct passed by glibc/musl k_sigaction to rt_sigaction.
 */
struct sigaction {
    union {
        sighandler_t sa_handler;           /* Simple handler: void (*)(int) */
        void        (*sa_sigaction)(int, void *, void *);  /* SA_SIGINFO handler */
    };
    unsigned long sa_flags;               /* SA_* flags (unsigned long = 8 bytes) */
    void         (*sa_restorer)(void);    /* Signal trampoline (set by libc via SA_RESTORER) */
    sigset_t      sa_mask;               /* Signals to block during handler execution */
};

/* sigaction() flags (Linux x86_64/ARM64 values) */
#define SA_NOCLDSTOP  0x00000001  /* Don't send SIGCHLD when child stops */
#define SA_NOCLDWAIT  0x00000002  /* Don't create zombies for stopped children */
#define SA_SIGINFO    0x00000004  /* Handler takes siginfo_t and ucontext args */
#define SA_ONSTACK    0x08000000  /* Deliver signal on alternate signal stack */
#define SA_RESTART    0x10000000  /* Restart syscall when signal returns */
#define SA_RESTORER   0x04000000  /* sa_restorer field is valid (set by libc) */
#define SA_NODEFER    0x40000000  /* Don't block signal during handler */
#define SA_RESETHAND  0x80000000  /* Reset handler to SIG_DFL after delivery */

/* Signal info codes */
#define SI_USER    0    /* Generated by kill() or raise() */
#define SI_QUEUE   (-1) /* Generated by sigqueue() / rt_sigqueueinfo() */
#define SI_TIMER   (-2) /* Generated by POSIX timer expiry */
#define SI_MESGQ   (-3) /* Generated by POSIX message queue */
#define SI_ASYNCIO (-4) /* Generated by AIO completion */
#define SI_SIGIO   (-5) /* Generated by SIGIO */
#define SI_TKILL   (-6) /* Generated by tkill / tgkill */
#define SI_KERNEL  128  /* Generated by kernel */

/* SIGSEGV si_code values (si_code field in siginfo_t for SIGSEGV) */
#define SEGV_MAPERR  1   /* Address not mapped to an object */
#define SEGV_ACCERR  2   /* Invalid permissions for mapped object */
#define SEGV_BNDERR  3   /* Failed address bound checks */
#define SEGV_PKUERR  4   /* Access was denied by memory protection keys */

/* SIGBUS si_code values */
#define BUS_ADRALN   1   /* Invalid address alignment */
#define BUS_ADRERR   2   /* Non-existent physical address */
#define BUS_OBJERR   3   /* Object-specific hardware error */

/* SIGILL si_code values */
#define ILL_ILLOPC   1   /* Illegal opcode */
#define ILL_ILLOPN   2   /* Illegal operand */
#define ILL_ILLADR   3   /* Illegal addressing mode */
#define ILL_ILLTRP   4   /* Illegal trap */
#define ILL_PRVOPC   5   /* Privileged opcode */
#define ILL_PRVREG   6   /* Privileged register */
#define ILL_COPROC   7   /* Coprocessor error */
#define ILL_BADSTK   8   /* Internal stack error */

/* SIGFPE si_code values */
#define FPE_INTDIV   1   /* Integer divide by zero */
#define FPE_INTOVF   2   /* Integer overflow */
#define FPE_FLTDIV   3   /* Floating-point divide by zero */
#define FPE_FLTOVF   4   /* Floating-point overflow */
#define FPE_FLTUND   5   /* Floating-point underflow */
#define FPE_FLTRES   6   /* Floating-point inexact result */
#define FPE_FLTINV   7   /* Floating-point invalid operation */
#define FPE_FLTSUB   8   /* Subscript out of range */

/* SIGCHLD si_code values */
#define CLD_EXITED    1  /* Child exited normally */
#define CLD_KILLED    2  /* Child killed by signal */
#define CLD_DUMPED    3  /* Child killed by signal + core dump */
#define CLD_TRAPPED   4  /* Traced child trapped */
#define CLD_STOPPED   5  /* Child stopped by signal */
#define CLD_CONTINUED 6  /* Stopped child continued */

#define SIGPROCMASK_BLOCK   0   /* SIG_BLOCK: Add signals to mask */
#define SIGPROCMASK_UNBLOCK 1   /* SIG_UNBLOCK: Remove signals from mask */
#define SIGPROCMASK_SETMASK 2   /* SIG_SETMASK: Set mask exactly */

/* Signal alternate stack (sigaltstack) */
struct sigaltstack {
    void   *ss_sp;      /* Stack base pointer */
    int     ss_flags;   /* Flags (SS_DISABLE, SS_ONSTACK) */
    size_t  ss_size;    /* Stack size in bytes */
};

/* sigaltstack flags */
#define SS_ONSTACK    0x01          /* Currently executing on signal stack */
#define SS_DISABLE    0x02          /* Disable signal stack */
#define SS_AUTODISARM 0x80000000    /* Auto-disarm altstack when signal delivered (Linux 4.7+) */

/* Minimum signal stack size (4 KiB) */
#define MINSIGSTKSZ 4096

/* Forward declarations */
struct fut_task;
struct fut_thread;

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

/* Queue a signal with explicit siginfo_t (for rt_sigqueueinfo) */
int fut_signal_send_with_info(struct fut_task *task, int signum, const void *info);

/* Queue a thread-directed signal (tgkill/tkill); sets per-thread pending */
int fut_signal_send_thread(struct fut_thread *thread, int signum);

/* Queue a thread-directed signal with explicit siginfo_t (for rt_tgsigqueueinfo) */
int fut_signal_send_thread_with_info(struct fut_thread *thread, int signum, const void *info);

/* Internal: Check if signal should be delivered to a task */
int fut_signal_is_pending(struct fut_task *task, int signum);

/* Deliver a pending signal by modifying the interrupt frame to redirect to handler.
 * Called before returning to userspace from an exception or syscall.
 * Returns the delivered signal number, 0 if none, or <0 on error. */
int fut_signal_deliver(struct fut_task *task, void *frame);
