/* kernel/sys_capability.c - POSIX capabilities syscalls
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements POSIX capabilities for fine-grained privilege management.
 * Capabilities provide an alternative to the traditional superuser model,
 * allowing specific privileges without full root access.
 *
 * Phase 1 (Current): Validation and stub implementations
 * Phase 2: Implement capability storage in task structure
 * Phase 3: Integrate with permission checks throughout kernel
 * Phase 4: Full capability inheritance and ambient capabilities
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <stdint.h>
#include <stddef.h>

extern void fut_printf(const char *fmt, ...);

/* Capability version */
#define _LINUX_CAPABILITY_VERSION_1  0x19980330
#define _LINUX_CAPABILITY_VERSION_2  0x20071026
#define _LINUX_CAPABILITY_VERSION_3  0x20080522
#define _LINUX_CAPABILITY_U32S_3     2  /* Number of u32s for version 3 */

/* Common capabilities (subset) */
#define CAP_CHOWN            0   /* Change file ownership */
#define CAP_DAC_OVERRIDE     1   /* Bypass file read/write/execute permission checks */
#define CAP_DAC_READ_SEARCH  2   /* Bypass file read and directory search checks */
#define CAP_FOWNER           3   /* Bypass permission checks on operations that require file ownership */
#define CAP_FSETID           4   /* Don't clear set-user-ID and set-group-ID on file modification */
#define CAP_KILL             5   /* Bypass permission checks for sending signals */
#define CAP_SETGID           6   /* Make arbitrary manipulations of process GIDs */
#define CAP_SETUID           7   /* Make arbitrary manipulations of process UIDs */
#define CAP_SETPCAP          8   /* Transfer capability sets */
#define CAP_LINUX_IMMUTABLE  9   /* Set immutable and append-only flags */
#define CAP_NET_BIND_SERVICE 10  /* Bind to ports < 1024 */
#define CAP_NET_BROADCAST    11  /* Allow broadcasting and listening to multicast */
#define CAP_NET_ADMIN        12  /* Network administration */
#define CAP_NET_RAW          13  /* Use RAW and PACKET sockets */
#define CAP_IPC_LOCK         14  /* Lock memory (mlock, etc.) */
#define CAP_IPC_OWNER        15  /* Bypass permission checks for System V IPC */
#define CAP_SYS_MODULE       16  /* Load and unload kernel modules */
#define CAP_SYS_RAWIO        17  /* Perform I/O port operations */
#define CAP_SYS_CHROOT       18  /* Use chroot() */
#define CAP_SYS_PTRACE       19  /* Trace arbitrary processes */
#define CAP_SYS_PACCT        20  /* Use acct() */
#define CAP_SYS_ADMIN        21  /* General system administration */
#define CAP_SYS_BOOT         22  /* Reboot and load/unload modules */
#define CAP_SYS_NICE         23  /* Raise process nice value and change priorities */
#define CAP_SYS_RESOURCE     24  /* Override resource limits */
#define CAP_SYS_TIME         25  /* Set system clock and real-time clock */
#define CAP_SYS_TTY_CONFIG   26  /* Configure tty devices */
#define CAP_MKNOD            27  /* Create special files using mknod() */
#define CAP_LEASE            28  /* Establish leases on files */
#define CAP_AUDIT_WRITE      29  /* Write records to kernel auditing log */
#define CAP_AUDIT_CONTROL    30  /* Enable and disable kernel auditing */
#define CAP_SETFCAP          31  /* Set file capabilities */

/**
 * struct __user_cap_header_struct - Capability header
 *
 * Specifies the capability version and target process.
 */
struct __user_cap_header_struct {
    uint32_t version;  /* Capability version */
    int      pid;      /* Target process ID (0 = current) */
};

/**
 * struct __user_cap_data_struct - Capability data
 *
 * Contains the three capability sets: effective, permitted, and inheritable.
 */
struct __user_cap_data_struct {
    uint32_t effective;    /* Effective capabilities */
    uint32_t permitted;    /* Permitted capabilities */
    uint32_t inheritable;  /* Inheritable capabilities */
};

/**
 * capget() - Get process capabilities
 *
 * Retrieves the capability sets (effective, permitted, inheritable) for
 * a specified process. Capabilities provide fine-grained privilege control,
 * allowing processes to have specific powers without full root access.
 *
 * @param hdrp   Pointer to capability header (version and pid)
 * @param datap  Pointer to capability data (effective, permitted, inheritable)
 *
 * Returns:
 *   - 0 on success (datap filled with capabilities)
 *   - -EFAULT if hdrp or datap points to invalid memory
 *   - -EINVAL if version is not supported
 *   - -ESRCH if target process not found
 *
 * Usage:
 *   struct __user_cap_header_struct hdr = { _LINUX_CAPABILITY_VERSION_3, 0 };
 *   struct __user_cap_data_struct data[2];
 *   if (capget(&hdr, data) == 0) {
 *       printf("Effective caps: 0x%x\n", data[0].effective);
 *   }
 *
 * Capability sets:
 * - Effective: Capabilities currently active for permission checks
 * - Permitted: Capabilities that can be made effective
 * - Inheritable: Capabilities preserved across execve()
 *
 * Phase 1: Validate parameters and return empty capability sets
 * Phase 2: Return actual capabilities from task structure
 */
long sys_capget(struct __user_cap_header_struct *hdrp,
                struct __user_cap_data_struct *datap) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    /* Validate header pointer */
    if (!hdrp) {
        fut_printf("[CAPABILITY] capget(hdrp=NULL, datap=%p, pid=%d) -> EFAULT\n",
                   datap, task->pid);
        return -EFAULT;
    }

    /* Validate data pointer */
    if (!datap) {
        fut_printf("[CAPABILITY] capget(hdrp=%p, datap=NULL, pid=%d) -> EFAULT\n",
                   hdrp, task->pid);
        return -EFAULT;
    }

    /* Suppress unused warnings for Phase 1 stub */
    (void)hdrp;
    (void)datap;

    /* Phase 1: Accept capability query */
    fut_printf("[CAPABILITY] capget(hdrp=%p, datap=%p, pid=%d) -> 0 "
               "(Phase 1 stub - returning empty capabilities)\n",
               hdrp, datap, task->pid);

    return 0;
}

/**
 * capset() - Set process capabilities
 *
 * Sets the capability sets (effective, permitted, inheritable) for
 * a specified process. This allows fine-grained privilege escalation
 * and de-escalation without full root access.
 *
 * @param hdrp   Pointer to capability header (version and pid)
 * @param datap  Pointer to capability data (effective, permitted, inheritable)
 *
 * Returns:
 *   - 0 on success
 *   - -EFAULT if hdrp or datap points to invalid memory
 *   - -EINVAL if version is not supported or capability values invalid
 *   - -ESRCH if target process not found
 *   - -EPERM if caller lacks permission to set capabilities
 *
 * Usage:
 *   struct __user_cap_header_struct hdr = { _LINUX_CAPABILITY_VERSION_3, 0 };
 *   struct __user_cap_data_struct data[2] = {0};
 *   data[0].effective = (1 << CAP_NET_BIND_SERVICE);  // Allow binding to port 80
 *   capset(&hdr, data);
 *
 * Permission requirements:
 * - Can only set capabilities within permitted set
 * - Can only modify own capabilities (unless CAP_SETPCAP)
 * - Cannot add new permitted capabilities without CAP_SETPCAP
 *
 * Phase 1: Validate parameters and return success
 * Phase 2: Store capabilities in task structure, enforce permission rules
 */
long sys_capset(struct __user_cap_header_struct *hdrp,
                const struct __user_cap_data_struct *datap) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    /* Validate header pointer */
    if (!hdrp) {
        fut_printf("[CAPABILITY] capset(hdrp=NULL, datap=%p, pid=%d) -> EFAULT\n",
                   datap, task->pid);
        return -EFAULT;
    }

    /* Validate data pointer */
    if (!datap) {
        fut_printf("[CAPABILITY] capset(hdrp=%p, datap=NULL, pid=%d) -> EFAULT\n",
                   hdrp, task->pid);
        return -EFAULT;
    }

    /* Suppress unused warnings for Phase 1 stub */
    (void)hdrp;
    (void)datap;

    /* Phase 1: Accept capability modification */
    fut_printf("[CAPABILITY] capset(hdrp=%p, datap=%p, pid=%d) -> 0 "
               "(Phase 1 stub - no actual capability change yet)\n",
               hdrp, datap, task->pid);

    return 0;
}
