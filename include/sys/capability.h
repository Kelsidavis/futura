// SPDX-License-Identifier: MPL-2.0
/*
 * sys/capability.h - POSIX capabilities
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Provides POSIX capability constants and structures for fine-grained
 * privilege management. Capabilities allow specific privileges without
 * requiring full root access.
 */

#pragma once

#include <stdint.h>

/* ============================================================
 *   Capability Version Constants
 * ============================================================ */

#ifndef _LINUX_CAPABILITY_VERSION_1
#define _LINUX_CAPABILITY_VERSION_1     0x19980330
#endif
#ifndef _LINUX_CAPABILITY_VERSION_2
#define _LINUX_CAPABILITY_VERSION_2     0x20071026
#endif
#ifndef _LINUX_CAPABILITY_VERSION_3
#define _LINUX_CAPABILITY_VERSION_3     0x20080522
#endif

/* Number of __u32s needed for capability version 3 */
#ifndef _LINUX_CAPABILITY_U32S_1
#define _LINUX_CAPABILITY_U32S_1        1
#endif
#ifndef _LINUX_CAPABILITY_U32S_2
#define _LINUX_CAPABILITY_U32S_2        2
#endif
#ifndef _LINUX_CAPABILITY_U32S_3
#define _LINUX_CAPABILITY_U32S_3        2
#endif

/* ============================================================
 *   Capability Constants
 * ============================================================ */

/* File/ownership capabilities */
#ifndef CAP_CHOWN
#define CAP_CHOWN               0   /* Change file ownership */
#endif
#ifndef CAP_DAC_OVERRIDE
#define CAP_DAC_OVERRIDE        1   /* Bypass file read/write/execute permission checks */
#endif
#ifndef CAP_DAC_READ_SEARCH
#define CAP_DAC_READ_SEARCH     2   /* Bypass file read and directory search permission checks */
#endif
#ifndef CAP_FOWNER
#define CAP_FOWNER              3   /* Bypass permission checks requiring file ownership */
#endif
#ifndef CAP_FSETID
#define CAP_FSETID              4   /* Don't clear set-user-ID and set-group-ID bits on modification */
#endif

/* Process credentials capabilities */
#ifndef CAP_KILL
#define CAP_KILL                5   /* Bypass permission checks for sending signals */
#endif
#ifndef CAP_SETGID
#define CAP_SETGID              6   /* Make arbitrary manipulations of process GIDs */
#endif
#ifndef CAP_SETUID
#define CAP_SETUID              7   /* Make arbitrary manipulations of process UIDs */
#endif
#ifndef CAP_SETPCAP
#define CAP_SETPCAP             8   /* Transfer capabilities between processes */
#endif

/* File system capabilities */
#ifndef CAP_LINUX_IMMUTABLE
#define CAP_LINUX_IMMUTABLE     9   /* Set immutable and append-only flags on files */
#endif

/* Network capabilities */
#ifndef CAP_NET_BIND_SERVICE
#define CAP_NET_BIND_SERVICE    10  /* Bind to privileged ports (< 1024) */
#endif
#ifndef CAP_NET_BROADCAST
#define CAP_NET_BROADCAST       11  /* Allow broadcasting and listening to multicast */
#endif
#ifndef CAP_NET_ADMIN
#define CAP_NET_ADMIN           12  /* Perform network administration tasks */
#endif
#ifndef CAP_NET_RAW
#define CAP_NET_RAW             13  /* Use RAW and PACKET sockets */
#endif

/* IPC capabilities */
#ifndef CAP_IPC_LOCK
#define CAP_IPC_LOCK            14  /* Lock memory (mlock, mlockall, mmap, shmctl) */
#endif
#ifndef CAP_IPC_OWNER
#define CAP_IPC_OWNER           15  /* Bypass permission checks for System V IPC operations */
#endif

/* System capabilities */
#ifndef CAP_SYS_MODULE
#define CAP_SYS_MODULE          16  /* Load and unload kernel modules */
#endif
#ifndef CAP_SYS_RAWIO
#define CAP_SYS_RAWIO           17  /* Perform I/O port operations (iopl, ioperm) */
#endif
#ifndef CAP_SYS_CHROOT
#define CAP_SYS_CHROOT          18  /* Use chroot() */
#endif
#ifndef CAP_SYS_PTRACE
#define CAP_SYS_PTRACE          19  /* Trace arbitrary processes using ptrace */
#endif
#ifndef CAP_SYS_PACCT
#define CAP_SYS_PACCT           20  /* Use acct() */
#endif
#ifndef CAP_SYS_ADMIN
#define CAP_SYS_ADMIN           21  /* General system administration operations */
#endif
#ifndef CAP_SYS_BOOT
#define CAP_SYS_BOOT            22  /* Use reboot() and kexec_load() */
#endif
#ifndef CAP_SYS_NICE
#define CAP_SYS_NICE            23  /* Raise nice value, set real-time scheduling */
#endif
#ifndef CAP_SYS_RESOURCE
#define CAP_SYS_RESOURCE        24  /* Override resource limits */
#endif
#ifndef CAP_SYS_TIME
#define CAP_SYS_TIME            25  /* Set system clock and real-time clock */
#endif
#ifndef CAP_SYS_TTY_CONFIG
#define CAP_SYS_TTY_CONFIG      26  /* Configure tty devices (vhangup) */
#endif

/* Device capabilities */
#ifndef CAP_MKNOD
#define CAP_MKNOD               27  /* Create special files using mknod() */
#endif

/* File lease capability */
#ifndef CAP_LEASE
#define CAP_LEASE               28  /* Establish leases on files */
#endif

/* Audit capabilities */
#ifndef CAP_AUDIT_WRITE
#define CAP_AUDIT_WRITE         29  /* Write records to kernel auditing log */
#endif
#ifndef CAP_AUDIT_CONTROL
#define CAP_AUDIT_CONTROL       30  /* Enable and disable kernel auditing */
#endif

/* File capabilities */
#ifndef CAP_SETFCAP
#define CAP_SETFCAP             31  /* Set file capabilities */
#endif

/* Extended capabilities (Linux 2.6.25+) */
#ifndef CAP_MAC_OVERRIDE
#define CAP_MAC_OVERRIDE        32  /* Override MAC (Mandatory Access Control) */
#endif
#ifndef CAP_MAC_ADMIN
#define CAP_MAC_ADMIN           33  /* Allow MAC configuration or state changes */
#endif
#ifndef CAP_SYSLOG
#define CAP_SYSLOG              34  /* Perform privileged syslog operations */
#endif
#ifndef CAP_WAKE_ALARM
#define CAP_WAKE_ALARM          35  /* Trigger wake-up alarms */
#endif
#ifndef CAP_BLOCK_SUSPEND
#define CAP_BLOCK_SUSPEND       36  /* Block system suspend */
#endif
#ifndef CAP_AUDIT_READ
#define CAP_AUDIT_READ          37  /* Read audit log */
#endif
#ifndef CAP_PERFMON
#define CAP_PERFMON             38  /* Privileged performance monitoring */
#endif
#ifndef CAP_BPF
#define CAP_BPF                 39  /* BPF operations */
#endif
#ifndef CAP_CHECKPOINT_RESTORE
#define CAP_CHECKPOINT_RESTORE  40  /* Checkpoint/restore operations */
#endif

/* Last valid capability + 1 */
#ifndef CAP_LAST_CAP
#define CAP_LAST_CAP            CAP_CHECKPOINT_RESTORE
#endif

/* ============================================================
 *   Capability Structures
 * ============================================================ */

/* User-space capability header */
#ifndef _STRUCT_CAP_USER_HEADER
#define _STRUCT_CAP_USER_HEADER
typedef struct __user_cap_header_struct {
    uint32_t version;   /* Capability version (_LINUX_CAPABILITY_VERSION_*) */
    int      pid;       /* Target process ID (0 = current process) */
} *cap_user_header_t;
#endif

/* User-space capability data */
#ifndef _STRUCT_CAP_USER_DATA
#define _STRUCT_CAP_USER_DATA
typedef struct __user_cap_data_struct {
    uint32_t effective;     /* Effective capabilities */
    uint32_t permitted;     /* Permitted capabilities */
    uint32_t inheritable;   /* Inheritable capabilities */
} *cap_user_data_t;
#endif

/* ============================================================
 *   Capability Macros
 * ============================================================ */

/* Convert capability number to bitmask */
#define CAP_TO_MASK(x)      (1U << ((x) & 31))

/* Get capability index (which __u32) */
#define CAP_TO_INDEX(x)     ((x) >> 5)

/* ============================================================
 *   Function Declarations
 * ============================================================ */

/**
 * capget - Get capabilities of a process
 *
 * @hdrp  Pointer to capability header (specifies version and target PID)
 * @datap Pointer to capability data (receives capability sets)
 *
 * Returns 0 on success, -1 on error.
 */
extern int capget(cap_user_header_t hdrp, cap_user_data_t datap);

/**
 * capset - Set capabilities of a process
 *
 * @hdrp  Pointer to capability header (specifies version and target PID)
 * @datap Pointer to capability data (contains new capability sets)
 *
 * Returns 0 on success, -1 on error.
 */
extern int capset(cap_user_header_t hdrp, const cap_user_data_t datap);

