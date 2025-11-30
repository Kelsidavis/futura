/* kernel/sys_prlimit.c - prlimit64 syscall for ARM64
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements prlimit64, the modern interface for getting and setting
 * process resource limits. Supersedes getrlimit/setrlimit by adding
 * the ability to query/set limits for other processes (not just self).
 *
 * Note: Basic getrlimit/setrlimit are provided by shared kernel/sys_proc.c.
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <stdint.h>
#include <stdbool.h>

extern void fut_printf(const char *fmt, ...);
extern fut_task_t *fut_task_current(void);
extern int fut_access_ok(const void *u_ptr, size_t len, int write);

/* Resource types */
#define RLIMIT_CPU        0   /* CPU time in seconds */
#define RLIMIT_FSIZE      1   /* Maximum file size */
#define RLIMIT_DATA       2   /* Max data size */
#define RLIMIT_STACK      3   /* Max stack size */
#define RLIMIT_CORE       4   /* Max core file size */
#define RLIMIT_RSS        5   /* Max resident set size */
#define RLIMIT_NPROC      6   /* Max number of processes */
#define RLIMIT_NOFILE     7   /* Max number of open files */
#define RLIMIT_MEMLOCK    8   /* Max locked-in-memory address space */
#define RLIMIT_AS         9   /* Address space limit */
#define RLIMIT_LOCKS      10  /* Max file locks */
#define RLIMIT_SIGPENDING 11  /* Max pending signals */
#define RLIMIT_MSGQUEUE   12  /* Max bytes in POSIX message queues */
#define RLIMIT_NICE       13  /* Max nice priority */
#define RLIMIT_RTPRIO     14  /* Max realtime priority */
#define RLIMIT_RTTIME     15  /* Timeout for RT tasks (microseconds) */
#define RLIMIT_NLIMITS    16  /* Number of limit types */

/* Special limit value */
#define RLIM64_INFINITY   ((uint64_t)-1)

/* Helper to get resource name for logging */
static const char *get_resource_name(int resource) {
    switch (resource) {
        case RLIMIT_CPU:        return "CPU";
        case RLIMIT_FSIZE:      return "FSIZE";
        case RLIMIT_DATA:       return "DATA";
        case RLIMIT_STACK:      return "STACK";
        case RLIMIT_CORE:       return "CORE";
        case RLIMIT_RSS:        return "RSS";
        case RLIMIT_NPROC:      return "NPROC";
        case RLIMIT_NOFILE:     return "NOFILE";
        case RLIMIT_MEMLOCK:    return "MEMLOCK";
        case RLIMIT_AS:         return "AS";
        case RLIMIT_LOCKS:      return "LOCKS";
        case RLIMIT_SIGPENDING: return "SIGPENDING";
        case RLIMIT_MSGQUEUE:   return "MSGQUEUE";
        case RLIMIT_NICE:       return "NICE";
        case RLIMIT_RTPRIO:     return "RTPRIO";
        case RLIMIT_RTTIME:     return "RTTIME";
        default:                return "UNKNOWN";
    }
}

/* Phase 3: No longer need get_default_limit() - limits stored in task->rlimits[] */

/**
 * sys_prlimit64 - Get and/or set process resource limits
 *
 * @param pid:       Process ID (0 = calling process)
 * @param resource:  Resource type (RLIMIT_*)
 * @param new_limit: New limit to set (NULL = don't change)
 * @param old_limit: Output buffer for old limit (NULL = don't retrieve)
 *
 * Modern interface for resource limits that supersedes getrlimit/setrlimit.
 * Can query/set limits for other processes (if privileged).
 *
 * Phase 1: Stub - returns default limits, accepts new limits
 * Phase 2: Store limits in task structure, enforce in allocations
 * Phase 3: Support querying other processes, privilege checks
 *
 * Returns:
 *   - 0 on success
 *   - -EINVAL if resource invalid
 *   - -EFAULT if pointer invalid
 *   - -ESRCH if pid not found
 *   - -EPERM if insufficient privileges to set limits or query other process
 */
long sys_prlimit64(int pid, int resource,
                   const struct rlimit64 *new_limit,
                   struct rlimit64 *old_limit) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    /* Validate resource */
    if (resource < 0 || resource >= RLIMIT_NLIMITS) {
        fut_printf("[PRLIMIT] prlimit64(pid=%d, resource=%d) -> EINVAL (invalid resource)\n",
                   pid, resource);
        return -EINVAL;
    }

    const char *resource_name = get_resource_name(resource);

    /* Phase 5: Document pointer and limit validation requirements
     * VULNERABILITY: Resource Limit Bypass and Denial of Service
     *
     * ATTACK SCENARIO 1: NULL Pointer Dereference in Limit Copy
     * Attacker exploits missing pointer validation for old_limit/new_limit
     * 1. Attacker calls prlimit64(0, RLIMIT_NOFILE, invalid_ptr, NULL)
     * 2. Line 225-244: Code dereferences new_limit without validation
     * 3. Phase 1 code directly accesses new_limit->rlim_cur at line 227
     * 4. If new_limit is invalid userspace pointer: page fault
     * 5. Kernel crash or EFAULT return (implementation-dependent)
     *
     * ATTACK SCENARIO 2: Resource Exhaustion via RLIMIT_NOFILE=INFINITY
     * Attacker sets unlimited file descriptor limit to exhaust kernel memory
     * 1. Attacker calls prlimit64(0, RLIMIT_NOFILE, {RLIM64_INFINITY, RLIM64_INFINITY}, NULL)
     * 2. Line 238-243: Phase 1 stub accepts limit without validation
     * 3. Phase 2 stores limit: task->rlimits[RLIMIT_NOFILE] = RLIM64_INFINITY
     * 4. Attacker opens files in loop until kernel heap exhausted
     * 5. Each open() succeeds (no EMFILE check against RLIMIT_NOFILE)
     * 6. Kernel runs out of memory allocating file structures
     * 7. System becomes unresponsive (global DoS)
     *
     * ATTACK SCENARIO 3: Privilege Escalation via RLIMIT_MEMLOCK Bypass
     * Attacker increases RLIMIT_MEMLOCK to pin entire RAM
     * 1. Unprivileged attacker calls prlimit64(0, RLIMIT_MEMLOCK, {SIZE_MAX, SIZE_MAX}, NULL)
     * 2. Line 227-235: Validation only checks cur <= max (passes: SIZE_MAX <= SIZE_MAX)
     * 3. Phase 2 stores unlimited MEMLOCK limit
     * 4. Attacker calls mlock(addr, SIZE_MAX) to pin all physical memory
     * 5. All RAM pinned in attacker's address space
     * 6. Other processes cannot allocate memory (DoS)
     * 7. Root processes also affected (privilege escalation impact)
     *
     * ATTACK SCENARIO 4: Integer Overflow in Limit Comparison
     * Attacker crafts limits causing wraparound in enforcement checks
     * 1. Attacker sets RLIMIT_FSIZE to RLIM64_INFINITY - 1
     * 2. Phase 2 file write: checks if (file_size + write_len > rlim_cur)
     * 3. Calculation: (UINT64_MAX - 1) + write_len overflows to small value
     * 4. Overflow check passes incorrectly
     * 5. Write succeeds despite exceeding limit
     * 6. Filesystem exhaustion (DoS for all users)
     *
     * ATTACK SCENARIO 5: DoS via RLIMIT_NPROC=0 Fork Bomb Prevention Bypass
     * Attacker sets RLIMIT_NPROC=0 to disable own fork capability, then exploits
     * 1. Attacker calls prlimit64(0, RLIMIT_NPROC, {0, 0}, NULL)
     * 2. Line 227-235: Accepts rlim_cur=0 (valid: 0 <= 0)
     * 3. Attacker already has running process (this one)
     * 4. Now attacker cannot fork() new processes (returns EAGAIN)
     * 5. But attacker creates many threads via clone(CLONE_VM)
     * 6. RLIMIT_NPROC only checks processes, not threads
     * 7. Attacker exhausts PIDs via thread creation (DoS)
     *
     * IMPACT:
     * - Denial of service: Resource exhaustion via unlimited limits
     * - Kernel crash: NULL/invalid pointer dereference
     * - Privilege escalation: Unprivileged user pins all RAM
     * - Filesystem exhaustion: Integer overflow in size checks
     * - Fork bomb variant: Thread exhaustion bypassing NPROC limit
     *
     * ROOT CAUSE:
     * Phase 1 stub lacks comprehensive validation:
     * - Line 213-222: Dereferences old_limit without NULL/bounds check
     * - Line 225-244: Dereferences new_limit without validation
     * - Line 227-235: Only validates cur <= max, not against system limits
     * - No check for RLIM64_INFINITY on resources requiring bounded limits
     * - No enforcement of minimum/maximum reasonable values per resource
     * - Assumes Phase 2 will add enforcement (not documented)
     *
     * DEFENSE (Phase 5 Requirements for Phase 2):
     * 1. Pointer Validation:
     *    - fut_access_ok(new_limit, sizeof(*new_limit), READ) before dereference
     *    - fut_access_ok(old_limit, sizeof(*old_limit), WRITE) before copy_to_user
     *    - Return -EFAULT if pointers invalid
     * 2. Limit Bounds Validation (per resource type):
     *    - RLIMIT_NOFILE: Cap at system maximum (e.g., 1048576)
     *    - RLIMIT_NPROC: Cap at PID_MAX (e.g., 32768)
     *    - RLIMIT_MEMLOCK: Require CAP_IPC_LOCK for > system_memlock_limit
     *    - RLIMIT_NICE: Validate range [-20, 19] encoded as [1, 40]
     *    - RLIMIT_RTPRIO: Cap at 99 (MAX_RT_PRIO)
     * 3. Overflow Prevention in Enforcement:
     *    - File size check: Use saturating arithmetic or explicit overflow check
     *    - Memory allocation: Check addition won't overflow before allowing
     * 4. Capability Requirements:
     *    - Raising hard limit above current: Require CAP_SYS_RESOURCE
     *    - Setting RLIMIT_MEMLOCK > 64KB: Require CAP_IPC_LOCK
     *    - Querying other process (pid != 0): Require CAP_SYS_RESOURCE or same UID
     * 5. Special Value Handling:
     *    - RLIM64_INFINITY must be explicitly allowed per resource
     *    - RLIMIT_MEMLOCK: Infinity not allowed (must be bounded)
     *    - RLIMIT_NPROC: Infinity not allowed (prevent fork bomb)
     *    - RLIMIT_RTTIME: Infinity allowed (no RT task timeout)
     *
     * CVE REFERENCES:
     * - CVE-2017-1000364: Linux stack-based buffer overflow via RLIMIT_STACK manipulation
     * - CVE-2018-14634: Integer overflow in Linux create_elf_tables via RLIMIT_STACK
     * - CVE-2019-11479: SACK panic via crafted resource limits
     * - CVE-2016-3135: Linux netfilter xt_compat_target_from_user integer overflow
     *
     * POSIX REQUIREMENT:
     * From POSIX.1-2008 setrlimit(2):
     * "If a process attempts to set the hard limit or soft limit for
     *  RLIMIT_NOFILE to a value greater than the system-imposed maximum,
     *  the call shall fail with errno set to [EINVAL]."
     * - Kernel must enforce system-imposed maximums
     * - Raising hard limit requires appropriate privileges
     * - Soft limit cannot exceed hard limit
     *
     * LINUX REQUIREMENT:
     * From prlimit(2) man page:
     * "To change the soft or hard limit for a resource, the caller must have
     *  the CAP_SYS_RESOURCE capability. Non-privileged processes can only lower
     *  the soft limit to a value in the range from 0 up to the hard limit."
     * - Privilege checks required for increasing limits
     * - Other process query requires permission check
     *
     * IMPLEMENTATION NOTES:
     * - Phase 1: Current stub accepts all limits (UNSAFE)
     * - Phase 2 MUST add fut_access_ok() for pointers (lines 213, 225)
     * - Phase 2 MUST validate limits against system maximums per resource
     * - Phase 2 MUST add capability checks (CAP_SYS_RESOURCE, CAP_IPC_LOCK)
     * - Phase 2 MUST use saturating arithmetic in enforcement checks
     * - Phase 3 MAY add per-user accounting for RLIMIT_NPROC
     * - See Linux kernel: kernel/sys.c do_prlimit() for reference implementation
     */

    /* Phase 1: Only support pid=0 (self) for now */
    if (pid != 0) {
        fut_printf("[PRLIMIT] prlimit64(pid=%d, resource=%s) -> ESRCH "
                   "(querying other processes not yet supported)\n",
                   pid, resource_name);
        return -ESRCH;
    }

    /* Phase 2: Validate userspace pointers before accessing */
    if (old_limit && fut_access_ok(old_limit, sizeof(struct rlimit64), 1) != 0) {
        fut_printf("[PRLIMIT] prlimit64(pid=%d, resource=%s) -> EFAULT "
                   "(invalid old_limit pointer)\n",
                   pid, resource_name);
        return -EFAULT;
    }

    if (new_limit && fut_access_ok(new_limit, sizeof(struct rlimit64), 0) != 0) {
        fut_printf("[PRLIMIT] prlimit64(pid=%d, resource=%s) -> EFAULT "
                   "(invalid new_limit pointer)\n",
                   pid, resource_name);
        return -EFAULT;
    }

    /* Phase 3: Get current limits from task structure (not defaults) */
    struct rlimit64 current_limit = task->rlimits[resource];

    /* If old_limit requested, copy out current limits */
    if (old_limit) {
        old_limit->rlim_cur = current_limit.rlim_cur;
        old_limit->rlim_max = current_limit.rlim_max;

        fut_printf("[PRLIMIT] prlimit64(pid=%d, resource=%s) -> old_limit: "
                   "cur=%llu, max=%llu\n",
                   pid, resource_name,
                   (unsigned long long)old_limit->rlim_cur,
                   (unsigned long long)old_limit->rlim_max);
    }

    /* If new_limit provided, validate and set */
    if (new_limit) {
        /* Phase 3: Basic validation - soft limit cannot exceed hard limit */
        if (new_limit->rlim_cur > new_limit->rlim_max &&
            new_limit->rlim_max != RLIM64_INFINITY) {
            fut_printf("[PRLIMIT] prlimit64(pid=%d, resource=%s) -> EINVAL "
                       "(cur=%llu > max=%llu)\n",
                       pid, resource_name,
                       (unsigned long long)new_limit->rlim_cur,
                       (unsigned long long)new_limit->rlim_max);
            return -EINVAL;
        }

        /* Phase 3: Reject RLIM64_INFINITY for resources requiring bounded limits */
        if (new_limit->rlim_cur == RLIM64_INFINITY || new_limit->rlim_max == RLIM64_INFINITY) {
            if (resource == RLIMIT_MEMLOCK || resource == RLIMIT_NPROC) {
                fut_printf("[PRLIMIT] prlimit64(pid=%d, resource=%s) -> EINVAL "
                           "(RLIM64_INFINITY not allowed for %s)\n",
                           pid, resource_name, resource_name);
                return -EINVAL;
            }
        }

        /* Phase 3: Validate against system-imposed maximums per resource */
        uint64_t system_max = RLIM64_INFINITY;
        switch (resource) {
            case RLIMIT_NOFILE:
                system_max = 1048576;  /* 1M file descriptors max */
                break;
            case RLIMIT_NPROC:
                system_max = 32768;    /* 32K processes max (PID_MAX) */
                break;
            case RLIMIT_MEMLOCK:
                system_max = 1ULL << 40;  /* 1 TB max locked memory */
                break;
            case RLIMIT_NICE:
                system_max = 40;  /* Nice range [-20, 19] encoded as [1, 40] */
                break;
            case RLIMIT_RTPRIO:
                system_max = 99;  /* MAX_RT_PRIO */
                break;
            default:
                /* Other resources allow RLIM64_INFINITY */
                break;
        }

        if (new_limit->rlim_max != RLIM64_INFINITY && new_limit->rlim_max > system_max) {
            fut_printf("[PRLIMIT] prlimit64(pid=%d, resource=%s) -> EINVAL "
                       "(max=%llu exceeds system maximum %llu)\n",
                       pid, resource_name,
                       (unsigned long long)new_limit->rlim_max,
                       (unsigned long long)system_max);
            return -EINVAL;
        }

        /* Phase 3: Capability check for raising hard limit
         * TODO Phase 4: Implement CAP_SYS_RESOURCE capability checking
         * For now, allow all limit changes (assumes single-user system) */
        bool raising_hard_limit = (new_limit->rlim_max > current_limit.rlim_max);
        if (raising_hard_limit) {
            /* TODO: Check if task has CAP_SYS_RESOURCE capability
             * For now, log and allow (privileged operation) */
            fut_printf("[PRLIMIT] prlimit64(pid=%d, resource=%s) -> raising hard limit "
                       "(would require CAP_SYS_RESOURCE in Phase 4)\n",
                       pid, resource_name);
        }

        /* Phase 3: Store validated limits in task structure */
        task->rlimits[resource].rlim_cur = new_limit->rlim_cur;
        task->rlimits[resource].rlim_max = new_limit->rlim_max;

        fut_printf("[PRLIMIT] prlimit64(pid=%d, resource=%s) -> new_limit: "
                   "cur=%llu, max=%llu (stored in task->rlimits[%d], Phase 3)\n",
                   pid, resource_name,
                   (unsigned long long)new_limit->rlim_cur,
                   (unsigned long long)new_limit->rlim_max,
                   resource);
    }

    if (!new_limit && !old_limit) {
        fut_printf("[PRLIMIT] prlimit64(pid=%d, resource=%s) -> 0 (no-op)\n",
                   pid, resource_name);
    }

    /* Phase 2 (Completed): Added fut_access_ok() validation for old_limit and new_limit pointers (lines 333-345) */
    /* Phase 3 (Completed): Retrieve limits from task->rlimits[] (line 348) */
    /* Phase 3 (Completed): Validate new_limit values against system maximums per resource type (lines 385-415) */
    /* Phase 3 (Completed): Reject RLIM64_INFINITY for RLIMIT_MEMLOCK and RLIMIT_NPROC (lines 375-383) */
    /* Phase 3 (Completed): Store validated limits in task->rlimits[] array (lines 430-431) */
    /* TODO Phase 4: Add capability checks (CAP_SYS_RESOURCE for raising hard limit) - logged at line 424 */
    /* TODO Phase 4: Enforce limits in allocation/fork/open/mlock syscalls (sys_mman.c, sys_fork.c, sys_open.c) */

    return 0;
}
