// SPDX-License-Identifier: MPL-2.0
/*
 * sys/wait.h - Process wait interface
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Provides constants and macros for waitpid(), wait(), and related
 * process status checking functions.
 */

#pragma once

#include <stdint.h>
#include <sys/types.h>

/* ============================================================
 *   Wait Option Flags (for waitpid/wait4)
 * ============================================================ */

#ifndef WNOHANG
#define WNOHANG     0x00000001  /* Don't block if no child has exited */
#endif
#ifndef WUNTRACED
#define WUNTRACED   0x00000002  /* Report stopped (but not traced) children */
#endif
#ifndef WSTOPPED
#define WSTOPPED    WUNTRACED   /* Alias for WUNTRACED */
#endif
#ifndef WEXITED
#define WEXITED     0x00000004  /* Report dead child (waitid only) */
#endif
#ifndef WCONTINUED
#define WCONTINUED  0x00000008  /* Report continued child */
#endif
#ifndef WNOWAIT
#define WNOWAIT     0x01000000  /* Don't reap, just poll status (waitid only) */
#endif

/* ============================================================
 *   Status Evaluation Macros
 *
 *   These macros interpret the status value returned by wait/waitpid.
 *   The status is encoded as follows:
 *   - Normal exit: bits 8-15 contain exit code, bits 0-7 are 0
 *   - Signal termination: bits 0-6 contain signal number, bit 7 may be core dump
 *   - Stopped: bits 8-15 contain stop signal, bits 0-7 are 0x7f
 *   - Continued: status is 0xffff
 * ============================================================ */

/* Check if child exited normally (via exit() or return from main) */
#ifndef WIFEXITED
#define WIFEXITED(status)   (((status) & 0x7f) == 0)
#endif

/* Get exit code (only valid if WIFEXITED is true) */
#ifndef WEXITSTATUS
#define WEXITSTATUS(status) (((status) >> 8) & 0xff)
#endif

/* Check if child was terminated by a signal */
#ifndef WIFSIGNALED
#define WIFSIGNALED(status) (((status) & 0x7f) != 0 && ((status) & 0x7f) != 0x7f)
#endif

/* Get terminating signal number (only valid if WIFSIGNALED is true) */
#ifndef WTERMSIG
#define WTERMSIG(status)    ((status) & 0x7f)
#endif

/* Check if child produced a core dump (only valid if WIFSIGNALED is true) */
#ifndef WCOREDUMP
#define WCOREDUMP(status)   ((status) & 0x80)
#endif

/* Check if child is currently stopped */
#ifndef WIFSTOPPED
#define WIFSTOPPED(status)  (((status) & 0xff) == 0x7f)
#endif

/* Get stop signal number (only valid if WIFSTOPPED is true) */
#ifndef WSTOPSIG
#define WSTOPSIG(status)    (((status) >> 8) & 0xff)
#endif

/* Check if child was resumed by SIGCONT */
#ifndef WIFCONTINUED
#define WIFCONTINUED(status) ((status) == 0xffff)
#endif

/* ============================================================
 *   Type Definitions
 * ============================================================ */

/* pid_t and id_t are provided by sys/types.h */

/* idtype_t for waitid() */
typedef enum {
    P_ALL  = 0,     /* Wait for any child */
    P_PID  = 1,     /* Wait for specific process ID */
    P_PGID = 2,     /* Wait for any child in process group */
} idtype_t;

/* ============================================================
 *   Function Declarations
 * ============================================================ */

extern pid_t wait(int *status);
extern pid_t waitpid(pid_t pid, int *status, int options);
extern pid_t wait3(int *status, int options, void *rusage);
extern pid_t wait4(pid_t pid, int *status, int options, void *rusage);
/* extern int waitid(idtype_t idtype, id_t id, siginfo_t *infop, int options); */
