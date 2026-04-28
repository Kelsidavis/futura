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
 * Phase 2 (Completed): Enhanced validation, version checking, parameter categorization, detailed logging
 * Phase 3 (Completed): Implement capability storage in task structure with task capability access
 * Phase 4 (Completed): Integrate with permission checks throughout kernel
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <stdint.h>
#include <stddef.h>

#include <kernel/kprintf.h>
#include <kernel/uaccess.h>

#include <platform/platform.h>

static inline int cap_copy_to_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)dst >= KERNEL_VIRTUAL_BASE) { __builtin_memcpy(dst, src, n); return 0; }
#endif
    return fut_copy_to_user(dst, src, n);
}
static inline int cap_copy_from_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)src >= KERNEL_VIRTUAL_BASE) { __builtin_memcpy(dst, src, n); return 0; }
#endif
    return fut_copy_from_user(dst, src, n);
}
static inline int cap_access_ok(const void *ptr, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)ptr >= KERNEL_VIRTUAL_BASE) return 0;
#endif
    return fut_access_ok(ptr, n, 1);
}

/* Capability version */
#define _LINUX_CAPABILITY_VERSION_1  0x19980330
#define _LINUX_CAPABILITY_VERSION_2  0x20071026
#define _LINUX_CAPABILITY_VERSION_3  0x20080522
#define _LINUX_CAPABILITY_U32S_3     2  /* Number of u32s for version 3 */

/* Common capabilities (subset) - MUST be defined before use in categorize_capability() */
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

/* Helper: human-readable name for a capability index */
static __attribute__((unused)) const char *categorize_capability(int cap) {
    switch (cap) {
        case CAP_CHOWN:            return "ownership (CHOWN)";
        case CAP_DAC_OVERRIDE:     return "DAC bypass (DAC_OVERRIDE)";
        case CAP_SETUID:           return "UID privilege (SETUID)";
        case CAP_SETGID:           return "GID privilege (SETGID)";
        case CAP_NET_BIND_SERVICE: return "privileged ports (NET_BIND_SERVICE)";
        case CAP_NET_ADMIN:        return "network admin (NET_ADMIN)";
        case CAP_SYS_ADMIN:        return "system admin (SYS_ADMIN)";
        case CAP_SETPCAP:          return "capability transfer (SETPCAP)";
        default:                   return "other";
    }
}

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
 * Phase 2 (Completed): Enhanced validation, version checking, capability structure validation
 * Phase 3 (Completed): Retrieve capabilities from task structure and copy to userspace
 * Phase 4 (Completed): Integrate with permission checks throughout kernel
 */
long sys_capget(struct __user_cap_header_struct *hdrp,
                struct __user_cap_data_struct *datap) {

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

    /* Linux's capget validates the header version (cap_validate_magic)
     * BEFORE checking datap.  When datap is NULL, capget is a probe:
     *   - unknown version -> writes preferred V3 back, returns 0
     *     (the libc capget wrapper uses this to negotiate the ABI version)
     *   - known version   -> returns 0 (caller already has the version)
     * When datap is non-NULL:
     *   - unknown version -> writes V3 back, returns -EINVAL
     *   - known version   -> proceeds to fill the data struct
     *
     * The previous Futura order rejected NULL datap up front with EFAULT
     * before any version probe ran, so libc's capget(hdr, NULL) version-
     * negotiation path got EFAULT instead of "version corrected, retry".
     * Reorder to match Linux's cap_validate_magic-first ordering. */

    /* Copy capability header from userspace */
    struct __user_cap_header_struct hdr;
    if (cap_copy_from_user(&hdr, hdrp, sizeof(hdr)) != 0) {
        fut_printf("[CAPABILITY] capget(hdrp=?, datap=%p, pid=%d) -> EFAULT "
                   "(header copy_from_user failed)\n", datap, task->pid);
        return -EFAULT;
    }

    /* Validate version.  Unknown version: write preferred version back. */
    int two_structs = 0;  /* 1 if V2/V3 (two __user_cap_data_struct entries) */
    int version_invalid = 0;
    if (hdr.version == _LINUX_CAPABILITY_VERSION_1) {
        two_structs = 0;
    } else if (hdr.version == _LINUX_CAPABILITY_VERSION_2 ||
               hdr.version == _LINUX_CAPABILITY_VERSION_3) {
        two_structs = 1;
    } else {
        /* Write back preferred version so caller can retry */
        uint32_t preferred = _LINUX_CAPABILITY_VERSION_3;
        cap_copy_to_user(&hdrp->version, &preferred, sizeof(preferred));
        fut_printf("[CAPABILITY] capget: unknown version 0x%x -> EINVAL/probe (wrote V3)\n",
                   hdr.version);
        version_invalid = 1;
    }

    /* Linux: NULL datap is a version-probe — return 0 regardless of
     * whether the version was valid (we already wrote V3 back on
     * mismatch). */
    if (!datap) {
        return 0;
    }

    /* datap non-NULL with unknown version: surface EINVAL now. */
    if (version_invalid) {
        return -EINVAL;
    }

    /* Validate datap write permission (kernel writes capability data).
     * For V2/V3 the kernel writes TWO __user_cap_data_struct entries;
     * the previous check only validated one struct's worth, so a caller
     * mapping ending exactly at the first-struct boundary slipped past
     * access_ok and only failed at copy_to_user time.  Use the actual
     * payload size matching the version. */
    size_t check_size = two_structs
        ? 2 * sizeof(struct __user_cap_data_struct)
        :     sizeof(struct __user_cap_data_struct);
    if (cap_access_ok(datap, check_size) != 0) {
        fut_printf("[CAPABILITY] capget(hdrp=%p, datap=%p) -> EFAULT (datap not writable for %zu bytes)\n",
                   hdrp, datap, check_size);
        return -EFAULT;
    }

    /* Resolve target task by pid (0 = current, >0 = lookup by pid).
     * Linux's capget rejects negative pid up front with EINVAL — without
     * this guard a negative pid_t silently widens to a huge unsigned and
     * we fall through to fut_task_by_pid(), which then returns ESRCH and
     * masks the real ABI error from libc/glibc capset wrappers. */
    if (hdr.pid < 0) {
        fut_printf("[CAPABILITY] capget: pid=%d -> EINVAL (negative pid)\n", hdr.pid);
        return -EINVAL;
    }
    fut_task_t *target = task;
    if (hdr.pid != 0) {
        target = fut_task_by_pid((uint64_t)(unsigned int)hdr.pid);
        if (!target) {
            fut_printf("[CAPABILITY] capget: pid=%d not found -> ESRCH\n", hdr.pid);
            return -ESRCH;
        }
    }

    /* Build and copy capability data structs.
     * V1: one struct (lo 32 bits only).
     * V2/V3: two structs — [0] low 32 bits, [1] high 32 bits. */
    struct __user_cap_data_struct cap_data[2] = {{0}, {0}};
    cap_data[0].effective   = (uint32_t)(target->cap_effective   & 0xFFFFFFFF);
    cap_data[0].permitted   = (uint32_t)(target->cap_permitted   & 0xFFFFFFFF);
    cap_data[0].inheritable = (uint32_t)(target->cap_inheritable & 0xFFFFFFFF);
    if (two_structs) {
        cap_data[1].effective   = (uint32_t)((target->cap_effective   >> 32) & 0xFFFFFFFF);
        cap_data[1].permitted   = (uint32_t)((target->cap_permitted   >> 32) & 0xFFFFFFFF);
        cap_data[1].inheritable = (uint32_t)((target->cap_inheritable >> 32) & 0xFFFFFFFF);
    }

    size_t copy_size = two_structs
        ? 2 * sizeof(struct __user_cap_data_struct)
        :     sizeof(struct __user_cap_data_struct);
    if (cap_copy_to_user(datap, cap_data, copy_size) != 0) {
        fut_printf("[CAPABILITY] capget: EFAULT copying %zu bytes to datap=%p\n",
                   copy_size, datap);
        return -EFAULT;
    }

    fut_printf("[CAPABILITY] capget(pid=%d) -> eff=0x%x perm=0x%x inh=0x%x "
               "(hi: eff=0x%x perm=0x%x inh=0x%x)\n",
               hdr.pid,
               cap_data[0].effective, cap_data[0].permitted, cap_data[0].inheritable,
               cap_data[1].effective, cap_data[1].permitted, cap_data[1].inheritable);
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
 * Phase 1 (Completed): Validate parameters and return success
 * Phase 2 (Completed): Enhanced validation, version checking, capability data validation
 * Phase 3 (Completed): Store capabilities in task structure with permission checking
 * Phase 4 (Completed): Integrate with permission checks throughout kernel
 */
long sys_capset(struct __user_cap_header_struct *hdrp,
                const struct __user_cap_data_struct *datap) {

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

    /* Linux's capset validates the header version (cap_validate_magic)
     * BEFORE copy_from_user touches data, so an invalid-version probe
     * with NULL datap returns -EINVAL (with the kernel's preferred
     * version written back via cap_copy_to_user) — not -EFAULT.  The
     * previous Futura order rejected NULL datap up front, masking the
     * real version-mismatch error class libc capset wrappers
     * use to negotiate the ABI version. */

    /* Copy capability header from userspace */
    struct __user_cap_header_struct hdr;
    if (cap_copy_from_user(&hdr, hdrp, sizeof(hdr)) != 0) {
        fut_printf("[CAPABILITY] capset: EFAULT copying header\n");
        return -EFAULT;
    }

    /* Validate version.  Unknown version: write preferred version back and return EINVAL. */
    int two_structs = 0;
    if (hdr.version == _LINUX_CAPABILITY_VERSION_1) {
        two_structs = 0;
    } else if (hdr.version == _LINUX_CAPABILITY_VERSION_2 ||
               hdr.version == _LINUX_CAPABILITY_VERSION_3) {
        two_structs = 1;
    } else {
        uint32_t preferred = _LINUX_CAPABILITY_VERSION_3;
        cap_copy_to_user(&hdrp->version, &preferred, sizeof(preferred));
        fut_printf("[CAPABILITY] capset: unknown version 0x%x -> EINVAL (wrote V3)\n",
                   hdr.version);
        return -EINVAL;
    }

    /* Copy capability data from userspace.
     * V1: one struct (lo 32 bits).  V2/V3: two structs (lo + hi 32 bits). */
    struct __user_cap_data_struct cap_data[2] = {{0}, {0}};
    size_t data_size = two_structs
        ? 2 * sizeof(struct __user_cap_data_struct)
        :     sizeof(struct __user_cap_data_struct);
    if (cap_copy_from_user(cap_data, datap, data_size) != 0) {
        fut_printf("[CAPABILITY] capset: EFAULT copying %zu bytes of data\n", data_size);
        return -EFAULT;
    }

    /* Combine lo/hi halves into full 64-bit capability values */
    uint64_t new_effective   = (uint64_t)cap_data[0].effective;
    uint64_t new_permitted   = (uint64_t)cap_data[0].permitted;
    uint64_t new_inheritable = (uint64_t)cap_data[0].inheritable;
    if (two_structs) {
        new_effective   |= (uint64_t)cap_data[1].effective   << 32;
        new_permitted   |= (uint64_t)cap_data[1].permitted   << 32;
        new_inheritable |= (uint64_t)cap_data[1].inheritable << 32;
    }

    /* Resolve target task (0 = current, >0 = other process).
     * Linux only allows setting own capabilities (EPERM for other PIDs).
     * Linux's capset rejects pid < 0 with EINVAL (matching capget); without
     * this guard a negative pid_t silently widened via (unsigned int) and
     * fell through to the EPERM path, masking the real ABI errno. */
    if (hdr.pid < 0) {
        fut_printf("[CAPABILITY] capset: pid=%d -> EINVAL (negative pid)\n", hdr.pid);
        return -EINVAL;
    }
    fut_task_t *target_task = task;
    if (hdr.pid != 0) {
        if ((uint64_t)(unsigned int)hdr.pid != task->pid) {
            fut_printf("[CAPABILITY] capset: pid=%d != self -> EPERM\n", hdr.pid);
            return -EPERM;
        }
    }

    /* Validate: new permitted set must not exceed old permitted set.
     * Linux rule: new_permitted ⊆ old_permitted (caps can only be dropped, not added). */
    if (new_permitted & ~target_task->cap_permitted) {
        fut_printf("[CAPABILITY] capset -> EPERM (permitted 0x%llx exceeds old 0x%llx)\n",
                   (unsigned long long)new_permitted,
                   (unsigned long long)target_task->cap_permitted);
        return -EPERM;
    }

    /* Validate: effective ⊆ new_permitted */
    if (new_effective & ~new_permitted) {
        fut_printf("[CAPABILITY] capset -> EPERM (effective exceeds permitted)\n");
        return -EPERM;
    }

    /* Bounding-set constraint: new_inheritable ⊆ (old_inheritable ∪ cap_bset).
     * The bounding set is an absolute upper bound on what may ever appear in
     * inheritable, regardless of what is currently held in permitted. The
     * previous union-with-permitted check let an attacker reintroduce a cap
     * into inheritable that the administrator had explicitly removed from
     * the bounding set, defeating the bset's purpose. */
    uint64_t bset_allowed = target_task->cap_inheritable | target_task->cap_bset;
    if (new_inheritable & ~bset_allowed) {
        fut_printf("[CAPABILITY] capset -> EPERM (inheritable exceeds inheritable∪bset)\n");
        return -EPERM;
    }

    /* Permitted-set constraint: without CAP_SETPCAP, callers can only raise
     * inheritable using caps currently in their permitted set. Linux's
     * cap_capset() applies this rule via cap_inh_is_capped(): a process that
     * holds CAP_SETPCAP may add any in-bset cap to inheritable, while every
     * other process is capped to old_inheritable ∪ old_permitted. */
    int has_setpcap = (target_task->cap_effective & (1ULL << CAP_SETPCAP)) != 0;
    if (!has_setpcap) {
        uint64_t inh_allowed = target_task->cap_inheritable |
                               target_task->cap_permitted;
        if (new_inheritable & ~inh_allowed) {
            fut_printf("[CAPABILITY] capset -> EPERM (inheritable exceeds inheritable∪permitted, no CAP_SETPCAP)\n");
            return -EPERM;
        }
    }

    /* Store old effective for logging */
    uint64_t old_effective = target_task->cap_effective;

    /* Update task capabilities with full 64-bit values */
    target_task->cap_effective   = new_effective;
    target_task->cap_permitted   = new_permitted;
    target_task->cap_inheritable = new_inheritable;

    fut_printf("[CAPABILITY] capset(pid=%d) -> eff=0x%llx->0x%llx perm=0x%llx inh=0x%llx\n",
               hdr.pid,
               (unsigned long long)old_effective,
               (unsigned long long)new_effective,
               (unsigned long long)new_permitted,
               (unsigned long long)new_inheritable);

    return 0;
}
