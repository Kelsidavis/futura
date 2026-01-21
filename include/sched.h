// SPDX-License-Identifier: MPL-2.0
/*
 * sched.h - Scheduling declarations
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Provides scheduling policies, clone flags, and related constants
 * for process/thread creation and CPU scheduling.
 */

#pragma once

#include <stdint.h>
#include <stddef.h>

/* ============================================================
 *   Scheduling Policies
 * ============================================================ */

#ifndef SCHED_OTHER
#define SCHED_OTHER     0   /* Standard round-robin time-sharing */
#endif
#ifndef SCHED_FIFO
#define SCHED_FIFO      1   /* First-in, first-out real-time */
#endif
#ifndef SCHED_RR
#define SCHED_RR        2   /* Round-robin real-time */
#endif
#ifndef SCHED_BATCH
#define SCHED_BATCH     3   /* Batch-style execution */
#endif
#ifndef SCHED_ISO
#define SCHED_ISO       4   /* Isochronous scheduling (reserved) */
#endif
#ifndef SCHED_IDLE
#define SCHED_IDLE      5   /* Very low priority background tasks */
#endif
#ifndef SCHED_DEADLINE
#define SCHED_DEADLINE  6   /* Deadline-based scheduling */
#endif

/* Scheduling flags for sched_setattr() */
#ifndef SCHED_FLAG_RESET_ON_FORK
#define SCHED_FLAG_RESET_ON_FORK    0x01
#endif
#ifndef SCHED_FLAG_RECLAIM
#define SCHED_FLAG_RECLAIM          0x02
#endif
#ifndef SCHED_FLAG_DL_OVERRUN
#define SCHED_FLAG_DL_OVERRUN       0x04
#endif

/* ============================================================
 *   Clone Flags (for clone/clone3)
 * ============================================================ */

#ifndef CLONE_VM
#define CLONE_VM            0x00000100  /* Share memory space */
#endif
#ifndef CLONE_FS
#define CLONE_FS            0x00000200  /* Share filesystem information */
#endif
#ifndef CLONE_FILES
#define CLONE_FILES         0x00000400  /* Share file descriptor table */
#endif
#ifndef CLONE_SIGHAND
#define CLONE_SIGHAND       0x00000800  /* Share signal handlers */
#endif
#ifndef CLONE_PIDFD
#define CLONE_PIDFD         0x00001000  /* Create pidfd for child */
#endif
#ifndef CLONE_PTRACE
#define CLONE_PTRACE        0x00002000  /* Allow ptrace by parent */
#endif
#ifndef CLONE_VFORK
#define CLONE_VFORK         0x00004000  /* Parent wants vfork semantics */
#endif
#ifndef CLONE_PARENT
#define CLONE_PARENT        0x00008000  /* Share parent with cloning process */
#endif
#ifndef CLONE_THREAD
#define CLONE_THREAD        0x00010000  /* Same thread group */
#endif
#ifndef CLONE_NEWNS
#define CLONE_NEWNS         0x00020000  /* New mount namespace */
#endif
#ifndef CLONE_SYSVSEM
#define CLONE_SYSVSEM       0x00040000  /* Share System V SEM_UNDO semantics */
#endif
#ifndef CLONE_SETTLS
#define CLONE_SETTLS        0x00080000  /* Set TLS in child */
#endif
#ifndef CLONE_PARENT_SETTID
#define CLONE_PARENT_SETTID 0x00100000  /* Store TID in parent */
#endif
#ifndef CLONE_CHILD_CLEARTID
#define CLONE_CHILD_CLEARTID 0x00200000 /* Clear TID in child on exit */
#endif
#ifndef CLONE_DETACHED
#define CLONE_DETACHED      0x00400000  /* Unused (legacy) */
#endif
#ifndef CLONE_UNTRACED
#define CLONE_UNTRACED      0x00800000  /* Cannot force CLONE_PTRACE */
#endif
#ifndef CLONE_CHILD_SETTID
#define CLONE_CHILD_SETTID  0x01000000  /* Store TID in child */
#endif
#ifndef CLONE_NEWCGROUP
#define CLONE_NEWCGROUP     0x02000000  /* New cgroup namespace */
#endif
#ifndef CLONE_NEWUTS
#define CLONE_NEWUTS        0x04000000  /* New UTS namespace */
#endif
#ifndef CLONE_NEWIPC
#define CLONE_NEWIPC        0x08000000  /* New IPC namespace */
#endif
#ifndef CLONE_NEWUSER
#define CLONE_NEWUSER       0x10000000  /* New user namespace */
#endif
#ifndef CLONE_NEWPID
#define CLONE_NEWPID        0x20000000  /* New PID namespace */
#endif
#ifndef CLONE_NEWNET
#define CLONE_NEWNET        0x40000000  /* New network namespace */
#endif
#ifndef CLONE_IO
#define CLONE_IO            0x80000000  /* Share I/O context */
#endif

/* ============================================================
 *   Scheduling Parameter Structure
 * ============================================================ */

#ifndef _STRUCT_SCHED_PARAM
#define _STRUCT_SCHED_PARAM
struct sched_param {
    int sched_priority;
};
#endif

/* Extended scheduling attributes (for sched_setattr/sched_getattr) */
#ifndef _STRUCT_SCHED_ATTR
#define _STRUCT_SCHED_ATTR
struct sched_attr {
    uint32_t size;              /* Size of this structure */
    uint32_t sched_policy;      /* Policy (SCHED_*) */
    uint64_t sched_flags;       /* Flags */
    int32_t  sched_nice;        /* Nice value (SCHED_OTHER, SCHED_BATCH) */
    uint32_t sched_priority;    /* Static priority (SCHED_FIFO, SCHED_RR) */
    /* For SCHED_DEADLINE */
    uint64_t sched_runtime;     /* Runtime per period (nanoseconds) */
    uint64_t sched_deadline;    /* Relative deadline (nanoseconds) */
    uint64_t sched_period;      /* Period (nanoseconds) */
};
#endif

/* ============================================================
 *   CPU Affinity
 * ============================================================ */

/* Size in bytes for cpu_set_t */
#ifndef CPU_SETSIZE
#define CPU_SETSIZE 1024
#endif

#ifndef _CPU_SET_T
#define _CPU_SET_T
typedef struct {
    unsigned long __bits[CPU_SETSIZE / (8 * sizeof(unsigned long))];
} cpu_set_t;
#endif

/* CPU set manipulation macros */
#define CPU_SET(cpu, setp)    ((setp)->__bits[(cpu) / (8 * sizeof(unsigned long))] |= (1UL << ((cpu) % (8 * sizeof(unsigned long)))))
#define CPU_CLR(cpu, setp)    ((setp)->__bits[(cpu) / (8 * sizeof(unsigned long))] &= ~(1UL << ((cpu) % (8 * sizeof(unsigned long)))))
#define CPU_ISSET(cpu, setp)  (((setp)->__bits[(cpu) / (8 * sizeof(unsigned long))] & (1UL << ((cpu) % (8 * sizeof(unsigned long))))) != 0)
#define CPU_ZERO(setp)        do { \
    for (size_t __i = 0; __i < sizeof((setp)->__bits) / sizeof((setp)->__bits[0]); __i++) \
        (setp)->__bits[__i] = 0; \
} while (0)

/* ============================================================
 *   Function Declarations
 * ============================================================ */

extern int sched_setscheduler(int pid, int policy, const struct sched_param *param);
extern int sched_getscheduler(int pid);
extern int sched_setparam(int pid, const struct sched_param *param);
extern int sched_getparam(int pid, struct sched_param *param);
extern int sched_get_priority_max(int policy);
extern int sched_get_priority_min(int policy);
extern int sched_yield(void);
extern int sched_setaffinity(int pid, size_t cpusetsize, const cpu_set_t *mask);
extern int sched_getaffinity(int pid, size_t cpusetsize, cpu_set_t *mask);

