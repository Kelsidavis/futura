// SPDX-License-Identifier: MPL-2.0
/*
 * signal.h - Userspace signal handling
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Provides POSIX-compatible signal handling for userspace programs.
 */

#pragma once

#include <stdint.h>

#ifdef __has_include
#if __has_include(<signal.h>) && !defined(FUTURA_FORCE_MINIMAL_SIGNAL)
#define FUTURA_HAVE_NATIVE_SIGNAL 1
#include <signal.h>
#endif
#endif

/* ============================================================
 *   Signal Set Type
 * ============================================================ */

#ifndef __sigset_t_defined
#define __sigset_t_defined 1
typedef struct {
    unsigned long __bits[2];
} sigset_t;
#endif

#ifndef FUTURA_HAVE_NATIVE_SIGNAL

/* ============================================================
 *   Signal Numbers
 * ============================================================ */

#ifndef SIGHUP
#define SIGHUP      1   /* Hangup (terminal disconnected) */
#endif
#ifndef SIGINT
#define SIGINT      2   /* Interrupt (Ctrl+C) */
#endif
#ifndef SIGQUIT
#define SIGQUIT     3   /* Quit (Ctrl+\) */
#endif
#ifndef SIGILL
#define SIGILL      4   /* Illegal instruction */
#endif
#ifndef SIGTRAP
#define SIGTRAP     5   /* Trace/breakpoint trap */
#endif
#ifndef SIGABRT
#define SIGABRT     6   /* Abort signal */
#endif
#ifndef SIGBUS
#define SIGBUS      7   /* Bus error */
#endif
#ifndef SIGFPE
#define SIGFPE      8   /* Floating point exception */
#endif
#ifndef SIGKILL
#define SIGKILL     9   /* Kill (cannot be caught or ignored) */
#endif
#ifndef SIGUSR1
#define SIGUSR1     10  /* User-defined signal 1 */
#endif
#ifndef SIGSEGV
#define SIGSEGV     11  /* Segmentation fault */
#endif
#ifndef SIGUSR2
#define SIGUSR2     12  /* User-defined signal 2 */
#endif
#ifndef SIGPIPE
#define SIGPIPE     13  /* Broken pipe */
#endif
#ifndef SIGALRM
#define SIGALRM     14  /* Alarm clock */
#endif
#ifndef SIGTERM
#define SIGTERM     15  /* Termination signal */
#endif
#ifndef SIGSTKFLT
#define SIGSTKFLT   16  /* Stack fault */
#endif
#ifndef SIGCHLD
#define SIGCHLD     17  /* Child process terminated or stopped */
#endif
#ifndef SIGCONT
#define SIGCONT     18  /* Continue if stopped */
#endif
#ifndef SIGSTOP
#define SIGSTOP     19  /* Stop (cannot be caught or ignored) */
#endif
#ifndef SIGTSTP
#define SIGTSTP     20  /* Terminal stop (Ctrl+Z) */
#endif
#ifndef SIGTTIN
#define SIGTTIN     21  /* Background read from tty */
#endif
#ifndef SIGTTOU
#define SIGTTOU     22  /* Background write to tty */
#endif
#ifndef SIGURG
#define SIGURG      23  /* Urgent condition on socket */
#endif
#ifndef SIGXCPU
#define SIGXCPU     24  /* CPU time limit exceeded */
#endif
#ifndef SIGXFSZ
#define SIGXFSZ     25  /* File size limit exceeded */
#endif
#ifndef SIGVTALRM
#define SIGVTALRM   26  /* Virtual alarm clock */
#endif
#ifndef SIGPROF
#define SIGPROF     27  /* Profiling timer expired */
#endif
#ifndef SIGWINCH
#define SIGWINCH    28  /* Window size change */
#endif
#ifndef SIGIO
#define SIGIO       29  /* I/O now possible */
#endif
#ifndef SIGPWR
#define SIGPWR      30  /* Power failure */
#endif
#ifndef SIGSYS
#define SIGSYS      31  /* Bad system call */
#endif

/* Number of signals */
#ifndef _NSIG
#define _NSIG       32
#endif
#ifndef NSIG
#define NSIG        _NSIG
#endif

/* ============================================================
 *   Signal Handler Types
 * ============================================================ */

typedef void (*sighandler_t)(int);

/* Default signal handlers */
#ifndef SIG_DFL
#define SIG_DFL     ((sighandler_t) 0)      /* Default action */
#endif
#ifndef SIG_IGN
#define SIG_IGN     ((sighandler_t) 1)      /* Ignore signal */
#endif
#ifndef SIG_ERR
#define SIG_ERR     ((sighandler_t) -1)     /* Error return */
#endif

/* ============================================================
 *   sigaction Structure
 * ============================================================ */

struct sigaction {
    union {
        sighandler_t sa_handler;
        void (*sa_sigaction)(int, void *, void *);
    };
    sigset_t sa_mask;
    int sa_flags;
};

/* ============================================================
 *   Signal Mask Operations
 * ============================================================ */

#ifndef SIG_BLOCK
#define SIG_BLOCK   0   /* Add signals to mask */
#endif
#ifndef SIG_UNBLOCK
#define SIG_UNBLOCK 1   /* Remove signals from mask */
#endif
#ifndef SIG_SETMASK
#define SIG_SETMASK 2   /* Set mask exactly */
#endif

/* ============================================================
 *   sigaction Flags
 * ============================================================ */

#ifndef SA_NOCLDSTOP
#define SA_NOCLDSTOP    0x00000001  /* Don't send SIGCHLD when child stops */
#endif
#ifndef SA_NOCLDWAIT
#define SA_NOCLDWAIT    0x00000002  /* Don't create zombie on child death */
#endif
#ifndef SA_SIGINFO
#define SA_SIGINFO      0x00000004  /* Use sa_sigaction instead of sa_handler */
#endif
#ifndef SA_ONSTACK
#define SA_ONSTACK      0x08000000  /* Use signal stack */
#endif
#ifndef SA_RESTART
#define SA_RESTART      0x10000000  /* Restart syscall on signal return */
#endif
#ifndef SA_NODEFER
#define SA_NODEFER      0x40000000  /* Don't block signal during handler */
#endif
#ifndef SA_RESETHAND
#define SA_RESETHAND    0x80000000  /* Reset handler to SIG_DFL */
#endif

/* ============================================================
 *   Timer-related Types (sigevent, timer_t, sigval)
 *   Provided by shared/fut_sigevent.h
 * ============================================================ */

#include <shared/fut_sigevent.h>

/* ============================================================
 *   Function Declarations
 * ============================================================ */

int sigemptyset(sigset_t *set);
int sigfillset(sigset_t *set);
int sigaddset(sigset_t *set, int signum);
int sigdelset(sigset_t *set, int signum);
int sigismember(const sigset_t *set, int signum);
int sigprocmask(int how, const sigset_t *set, sigset_t *oldset);
int sigaction(int signum, const struct sigaction *act, struct sigaction *oldact);
int raise(int sig);
int kill(int pid, int sig);
int sigpending(sigset_t *set);
int sigsuspend(const sigset_t *mask);

#endif /* FUTURA_HAVE_NATIVE_SIGNAL */
