/* kernel/sys_capability.c - POSIX capabilities syscalls
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements POSIX capabilities for fine-grained privilege management.
 * Capabilities provide an alternative to the traditional superuser model,
 * allowing specific privileges without full root access.
 *
 * Phase 1 (Completed): Validation and stub implementations
 * Phase 2 (Current): Enhanced validation, version checking, parameter categorization, detailed logging
 * Phase 3: Implement capability storage in task structure
 * Phase 4: Integrate with permission checks throughout kernel
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
 * Phase 1 (Completed): Validate parameters and return empty capability sets
 * Phase 2 (Current): Enhanced validation, version checking, capability structure validation
 */
long sys_capget(struct __user_cap_header_struct *hdrp,
                struct __user_cap_data_struct *datap) {
    extern int fut_copy_from_user(void *to, const void *from, size_t size);

    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    /* Phase 2: Validate header pointer */
    if (!hdrp) {
        fut_printf("[CAPABILITY] capget(hdrp=NULL, datap=%p, pid=%d) -> EFAULT\n",
                   datap, task->pid);
        return -EFAULT;
    }

    /* Phase 2: Validate data pointer */
    if (!datap) {
        fut_printf("[CAPABILITY] capget(hdrp=%p, datap=NULL, pid=%d) -> EFAULT\n",
                   hdrp, task->pid);
        return -EFAULT;
    }

    /* Phase 2: Copy capability header from userspace */
    struct __user_cap_header_struct hdr;
    if (fut_copy_from_user(&hdr, hdrp, sizeof(hdr)) != 0) {
        fut_printf("[CAPABILITY] capget(hdrp=?, datap=%p, pid=%d) -> EFAULT "
                   "(header copy_from_user failed)\n", datap, task->pid);
        return -EFAULT;
    }

    /* Phase 2: Validate capability version */
    const char *version_desc;
    if (hdr.version == _LINUX_CAPABILITY_VERSION_1) {
        version_desc = "v1 (obsolete)";
    } else if (hdr.version == _LINUX_CAPABILITY_VERSION_2) {
        version_desc = "v2 (legacy)";
    } else if (hdr.version == _LINUX_CAPABILITY_VERSION_3) {
        version_desc = "v3 (current)";
    } else {
        version_desc = "unknown/invalid";
    }

    /* Phase 2: Validate target PID */
    const char *pid_desc;
    if (hdr.pid == 0) {
        pid_desc = "current process";
    } else if (hdr.pid > 0) {
        pid_desc = "other process";
    } else {
        pid_desc = "invalid (<0)";
    }

    /*
     * Phase 3: Capability retrieval from task structure
     *
     * Copy task capabilities (effective, permitted, inheritable) to userspace
     */

    /* Phase 3: Task capability retrieval not yet implemented */
    fut_printf("[CAPABILITY] capget(hdrp=? [version=%s, pid=%s], datap=%p, caller_pid=%d) "
               "-> ENOSYS (Phase 3: task capability retrieval not yet implemented)\n",
               version_desc, pid_desc, datap, task->pid);

    return -ENOSYS;
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
 * Phase 1 (Completed): Validate parameters and return success
 * Phase 2 (Current): Enhanced validation, version checking, capability data validation
 */
long sys_capset(struct __user_cap_header_struct *hdrp,
                const struct __user_cap_data_struct *datap) {
    extern int fut_copy_from_user(void *to, const void *from, size_t size);

    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    /* Phase 2: Validate header pointer */
    if (!hdrp) {
        fut_printf("[CAPABILITY] capset(hdrp=NULL, datap=%p, pid=%d) -> EFAULT\n",
                   datap, task->pid);
        return -EFAULT;
    }

    /* Phase 2: Validate data pointer */
    if (!datap) {
        fut_printf("[CAPABILITY] capset(hdrp=%p, datap=NULL, pid=%d) -> EFAULT\n",
                   hdrp, task->pid);
        return -EFAULT;
    }

    /* Phase 2: Copy capability header from userspace */
    struct __user_cap_header_struct hdr;
    if (fut_copy_from_user(&hdr, hdrp, sizeof(hdr)) != 0) {
        fut_printf("[CAPABILITY] capset(hdrp=?, datap=%p, pid=%d) -> EFAULT "
                   "(header copy_from_user failed)\n", datap, task->pid);
        return -EFAULT;
    }

    /* Phase 2: Copy capability data from userspace */
    struct __user_cap_data_struct data;
    if (fut_copy_from_user(&data, datap, sizeof(data)) != 0) {
        fut_printf("[CAPABILITY] capset(hdrp=?, datap=?, pid=%d) -> EFAULT "
                   "(data copy_from_user failed)\n", task->pid);
        return -EFAULT;
    }

    /* Phase 2: Validate capability version */
    const char *version_desc;
    if (hdr.version == _LINUX_CAPABILITY_VERSION_1) {
        version_desc = "v1 (obsolete)";
    } else if (hdr.version == _LINUX_CAPABILITY_VERSION_2) {
        version_desc = "v2 (legacy)";
    } else if (hdr.version == _LINUX_CAPABILITY_VERSION_3) {
        version_desc = "v3 (current)";
    } else {
        version_desc = "unknown/invalid";
    }

    /* Phase 2: Validate target PID */
    const char *pid_desc;
    if (hdr.pid == 0) {
        pid_desc = "current process";
    } else if (hdr.pid > 0) {
        pid_desc = "other process";
    } else {
        pid_desc = "invalid (<0)";
    }

    /* Phase 2: Categorize operation type */
    const char *operation_type;
    if (data.effective == 0 && data.permitted == 0 && data.inheritable == 0) {
        operation_type = "drop all capabilities";
    } else if (data.effective != 0) {
        operation_type = "modify effective capabilities";
    } else if (data.permitted != 0) {
        operation_type = "modify permitted capabilities";
    } else if (data.inheritable != 0) {
        operation_type = "modify inheritable capabilities";
    } else {
        operation_type = "set capabilities";
    }

    /*
     * Phase 3: Capability storage and permission checking
     *
     * Store new capabilities in task structure, validate permissions, and update effective set
     */

    /* Phase 3: Task capability setting not yet implemented */
    fut_printf("[CAPABILITY] capset(hdrp=? [version=%s, pid=%s], datap=? [op=%s], "
               "caller_pid=%d) -> ENOSYS (Phase 3: task capability storage not yet implemented)\n",
               version_desc, pid_desc, operation_type, task->pid);

    return -ENOSYS;
}
