// SPDX-License-Identifier: MPL-2.0
#pragma once

#include <stdint.h>

typedef unsigned long sigset_t;

typedef void (*sighandler_t)(int);

struct sigaction {
    union {
        sighandler_t sa_handler;
        void (*sa_sigaction)(int, void *, void *);
    };
    sigset_t sa_mask;
    int sa_flags;
};

#define SIG_BLOCK   0
#define SIG_UNBLOCK 1
#define SIG_SETMASK 2

#define SA_SIGINFO  0x04

int sigemptyset(sigset_t *set);
int sigfillset(sigset_t *set);
int sigaddset(sigset_t *set, int signum);
int sigdelset(sigset_t *set, int signum);
int sigismember(const sigset_t *set, int signum);
int sigprocmask(int how, const sigset_t *set, sigset_t *oldset);
int sigaction(int signum, const struct sigaction *act, struct sigaction *oldact);
int raise(int sig);
