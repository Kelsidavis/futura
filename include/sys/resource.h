// SPDX-License-Identifier: MPL-2.0
/*
 * sys/resource.h - Resource limits and usage
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Provides constants and structures for resource limits (rlimit),
 * resource usage (rusage), and process priority (nice).
 */

#pragma once

#include <stdint.h>
#include <stddef.h>

/* ============================================================
 *   Resource Limit Types
 * ============================================================ */

#ifndef RLIMIT_CPU
#define RLIMIT_CPU          0   /* CPU time in seconds */
#endif
#ifndef RLIMIT_FSIZE
#define RLIMIT_FSIZE        1   /* Maximum file size */
#endif
#ifndef RLIMIT_DATA
#define RLIMIT_DATA         2   /* Maximum data segment size */
#endif
#ifndef RLIMIT_STACK
#define RLIMIT_STACK        3   /* Maximum stack size */
#endif
#ifndef RLIMIT_CORE
#define RLIMIT_CORE         4   /* Maximum core file size */
#endif
#ifndef RLIMIT_RSS
#define RLIMIT_RSS          5   /* Maximum resident set size */
#endif
#ifndef RLIMIT_NPROC
#define RLIMIT_NPROC        6   /* Maximum number of processes */
#endif
#ifndef RLIMIT_NOFILE
#define RLIMIT_NOFILE       7   /* Maximum number of open files */
#endif
#ifndef RLIMIT_MEMLOCK
#define RLIMIT_MEMLOCK      8   /* Maximum locked-in-memory address space */
#endif
#ifndef RLIMIT_AS
#define RLIMIT_AS           9   /* Address space limit */
#endif
#ifndef RLIMIT_LOCKS
#define RLIMIT_LOCKS        10  /* Maximum file locks held */
#endif
#ifndef RLIMIT_SIGPENDING
#define RLIMIT_SIGPENDING   11  /* Maximum pending signals */
#endif
#ifndef RLIMIT_MSGQUEUE
#define RLIMIT_MSGQUEUE     12  /* Maximum bytes in POSIX message queues */
#endif
#ifndef RLIMIT_NICE
#define RLIMIT_NICE         13  /* Maximum nice priority allowed to raise to */
#endif
#ifndef RLIMIT_RTPRIO
#define RLIMIT_RTPRIO       14  /* Maximum realtime priority */
#endif
#ifndef RLIMIT_RTTIME
#define RLIMIT_RTTIME       15  /* Timeout for RT tasks (microseconds) */
#endif
#ifndef RLIMIT_NLIMITS
#define RLIMIT_NLIMITS      16  /* Number of limit types */
#endif

/* rlim_t type for resource limits */
#ifndef rlim_t
typedef uint64_t rlim_t;
#endif

/* Special value for unlimited resource */
#ifndef RLIM_INFINITY
#define RLIM_INFINITY       (~0UL)
#endif

/* Saved current/max pair for getrlimit()/setrlimit() */
#ifndef RLIM_SAVED_MAX
#define RLIM_SAVED_MAX      RLIM_INFINITY
#endif
#ifndef RLIM_SAVED_CUR
#define RLIM_SAVED_CUR      RLIM_INFINITY
#endif

/* ============================================================
 *   Resource Limit Structure
 * ============================================================ */

#ifndef _STRUCT_RLIMIT
#define _STRUCT_RLIMIT
struct rlimit {
    rlim_t rlim_cur;    /* Soft limit */
    rlim_t rlim_max;    /* Hard limit (ceiling for rlim_cur) */
};
#endif

/* Extended rlimit structure for prlimit64() */
#ifndef _STRUCT_RLIMIT64
#define _STRUCT_RLIMIT64
struct rlimit64 {
    uint64_t rlim_cur;
    uint64_t rlim_max;
};
#endif

/* ============================================================
 *   Resource Usage (rusage)
 * ============================================================ */

/* Who values for getrusage() */
#ifndef RUSAGE_SELF
#define RUSAGE_SELF         0   /* Resource usage by the calling process */
#endif
#ifndef RUSAGE_CHILDREN
#define RUSAGE_CHILDREN     (-1) /* Resource usage by all children */
#endif
#ifndef RUSAGE_THREAD
#define RUSAGE_THREAD       1   /* Resource usage by the calling thread */
#endif

#ifndef _STRUCT_TIMEVAL
#define _STRUCT_TIMEVAL
struct timeval {
    int64_t tv_sec;     /* Seconds */
    int64_t tv_usec;    /* Microseconds */
};
#endif

#ifndef _STRUCT_RUSAGE
#define _STRUCT_RUSAGE
struct rusage {
    struct timeval ru_utime;    /* User CPU time used */
    struct timeval ru_stime;    /* System CPU time used */
    long ru_maxrss;             /* Maximum resident set size */
    long ru_ixrss;              /* Integral shared memory size */
    long ru_idrss;              /* Integral unshared data size */
    long ru_isrss;              /* Integral unshared stack size */
    long ru_minflt;             /* Page reclaims (soft page faults) */
    long ru_majflt;             /* Page faults (hard page faults) */
    long ru_nswap;              /* Swaps */
    long ru_inblock;            /* Block input operations */
    long ru_oublock;            /* Block output operations */
    long ru_msgsnd;             /* IPC messages sent */
    long ru_msgrcv;             /* IPC messages received */
    long ru_nsignals;           /* Signals received */
    long ru_nvcsw;              /* Voluntary context switches */
    long ru_nivcsw;             /* Involuntary context switches */
};
#endif

/* ============================================================
 *   Process Priority (nice)
 * ============================================================ */

/* Which argument for getpriority()/setpriority() */
#ifndef PRIO_PROCESS
#define PRIO_PROCESS        0   /* Process identifier */
#endif
#ifndef PRIO_PGRP
#define PRIO_PGRP           1   /* Process group identifier */
#endif
#ifndef PRIO_USER
#define PRIO_USER           2   /* User identifier */
#endif

/* Priority value range */
#ifndef PRIO_MIN
#define PRIO_MIN            (-20)   /* Minimum (highest) priority */
#endif
#ifndef PRIO_MAX
#define PRIO_MAX            20      /* Maximum (lowest) priority */
#endif

/* ============================================================
 *   Function Declarations
 * ============================================================ */

extern int getrlimit(int resource, struct rlimit *rlim);
extern int setrlimit(int resource, const struct rlimit *rlim);
extern int prlimit(int pid, int resource,
                   const struct rlimit *new_limit, struct rlimit *old_limit);
extern int getrusage(int who, struct rusage *usage);
extern int getpriority(int which, int who);
extern int setpriority(int which, int who, int prio);

