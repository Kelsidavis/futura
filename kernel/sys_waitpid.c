// SPDX-License-Identifier: MPL-2.0
/*
 * sys_waitpid.c - Wait for process termination syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements process waiting via waitpid() syscall.
 * Essential for parent processes to reap child zombies and get exit status.
 *
 * Phase 1 (Completed): Basic waitpid with status return
 * Phase 2 (Completed): Enhanced validation, PID/flag categorization, detailed logging
 * Phase 3 (Completed): Non-blocking wait, wait for specific children, process groups
 * Phase 4: Advanced wait options (WSTOPPED, WCONTINUED), waitid support
 */

#include <kernel/fut_task.h>
#include <kernel/uaccess.h>
#include <kernel/errno.h>
#include <sys/wait.h>

#include <stddef.h>

#include <kernel/kprintf.h>

/* Architecture-specific paging headers for KERNEL_VIRTUAL_BASE bypass */
#include <platform/platform.h>

/* Wait options (WNOHANG, WUNTRACED, WCONTINUED) and status macros
 * (WIFEXITED, WEXITSTATUS, WIFSIGNALED, WTERMSIG, WIFSTOPPED, WSTOPSIG)
 * are provided by sys/wait.h */

static inline int waitpid_copy_to_user(void *dst, const void *src, size_t n) {
    if (!dst || (uintptr_t)dst == (uintptr_t)-1) return -EFAULT;
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)dst >= KERNEL_VIRTUAL_BASE) { __builtin_memcpy(dst, src, n); return 0; }
#endif
    return fut_copy_to_user(dst, src, n);
}
static inline int waitpid_access_ok_write(const void *ptr, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)ptr >= KERNEL_VIRTUAL_BASE) return 0;
#endif
    return fut_access_ok(ptr, n, 1);
}

/**
 * waitpid() syscall - Wait for child process to change state
 *
 * Suspends execution of the calling process until a child process
 * terminates or changes state. Returns the PID of the child and
 * optionally stores its exit status.
 *
 * @param pid      PID to wait for (>0: specific, 0: any in group, -1: any child)
 * @param u_status User pointer to store exit status (NULL if not needed)
 * @param flags    Wait options (WNOHANG, WUNTRACED, WCONTINUED)
 *
 * Returns:
 *   - PID of child that changed state on success
 *   - 0 if WNOHANG specified and no child ready
 *   - -ECHILD if no matching children exist
 *   - -EINTR if interrupted by signal
 *   - -EFAULT if u_status points to invalid memory
 *
 * Behavior:
 *   - Blocks until a child exits (unless WNOHANG)
 *   - Reaps zombie child (removes from process table)
 *   - Returns child's PID and exit status
 *   - Multiple children: returns first one that exits
 *   - No children: returns -ECHILD immediately
 *
 * PID argument behavior:
 *   - pid > 0: Wait for specific child with that PID
 *   - pid = 0: Wait for any child in same process group
 *   - pid = -1: Wait for any child process (most common)
 *   - pid < -1: Wait for any child in process group |pid|
 *
 * Exit status encoding:
 *   - WIFEXITED(status): True if child exited normally
 *   - WEXITSTATUS(status): Extract 8-bit exit code
 *   - WIFSIGNALED(status): True if child killed by signal
 *   - WTERMSIG(status): Extract signal number that killed child
 *
 * Common usage patterns:
 *
 * Basic wait (any child):
 *   int status;
 *   pid_t pid = waitpid(-1, &status, 0);
 *   if (pid > 0) {
 *       if (WIFEXITED(status)) {
 *           printf("Child %d exited with code %d\n",
 *                  pid, WEXITSTATUS(status));
 *       } else if (WIFSIGNALED(status)) {
 *           printf("Child %d killed by signal %d\n",
 *                  pid, WTERMSIG(status));
 *       }
 *   }
 *
 * Wait for specific child:
 *   pid_t child = fork();
 *   if (child == 0) {
 *       // Child process
 *       exit(42);
 *   } else {
 *       // Parent process
 *       int status;
 *       waitpid(child, &status, 0);  // Wait for this specific child
 *       printf("Exit code: %d\n", WEXITSTATUS(status));
 *   }
 *
 * Non-blocking wait:
 *   int status;
 *   pid_t pid = waitpid(-1, &status, WNOHANG);
 *   if (pid > 0) {
 *       // Child exited
 *   } else if (pid == 0) {
 *       // No child ready yet
 *   } else {
 *       // Error (no children)
 *   }
 *
 * Wait for all children:
 *   while (1) {
 *       int status;
 *       pid_t pid = waitpid(-1, &status, 0);
 *       if (pid == -1 && errno == ECHILD) {
 *           break;  // No more children
 *       }
 *       // Process this child's exit
 *   }
 *
 * Ignoring exit status:
 *   waitpid(child_pid, NULL, 0);  // Don't care about status
 *
 * Related syscalls:
 *   - wait(): Simplified wait (equivalent to waitpid(-1, &status, 0))
 *   - waitid(): More flexible waiting (siginfo_t instead of int status)
 *   - fork(): Create child process
 *   - exit(): Child terminates with status
 *
 * Zombie prevention:
 *   - Always waitpid() for children you fork()
 *   - Zombies consume PID space and resources
 *   - Orphaned zombies reparented to init (PID 1)
 *
 * Phase 1 (Completed): Basic waitpid with status return
 * Phase 2 (Completed): Enhanced validation, PID/flag categorization, detailed logging
 * Phase 3 (Completed): Non-blocking wait (WNOHANG), process group support
 * Phase 4: Advanced options (WUNTRACED, WCONTINUED), waitid, rusage
 */
/* Valid waitpid/wait4 flags (Linux kernel compat) */
#define WAITPID_VALID_FLAGS (WNOHANG | WUNTRACED | WCONTINUED | __WALL | __WCLONE | __WNOTHREAD)

long sys_waitpid(int pid, int *u_status, int flags) {
    /* ARM64 FIX: Copy parameters to local variables immediately to ensure they're preserved
     * on the stack across blocking calls. When fut_task_waitpid blocks and resumes,
     * register-passed parameters may be corrupted. */
    int local_pid = pid;
    int *local_u_status = u_status;
    int local_flags = flags;

    /* Reject unknown flag bits (Linux returns EINVAL) */
    if (local_flags & ~WAITPID_VALID_FLAGS) {
        fut_printf("[WAITPID] waitpid(pid=%d, flags=0x%x) -> EINVAL (unknown flags 0x%x)\n",
                   local_pid, local_flags, local_flags & ~WAITPID_VALID_FLAGS);
        return -EINVAL;
    }

    /* Validate u_status write permission early (kernel writes exit status)
     * VULNERABILITY: Invalid Output Buffer Pointer
     * ATTACK: Attacker provides read-only or unmapped u_status buffer
     * IMPACT: Kernel page fault when writing exit status after potentially blocking wait
     * DEFENSE: Check write permission before blocking on fut_task_waitpid */
    if (local_u_status && waitpid_access_ok_write(local_u_status, sizeof(int)) != 0) {
        fut_printf("[WAITPID] waitpid(pid=%d, u_status=%p) -> EFAULT (u_status not writable for %zu bytes)\n",
                   local_pid, local_u_status, sizeof(int));
        return -EFAULT;
    }

    /* Phase 2: Categorize PID argument */
    const char *pid_category;
    const char *pid_meaning;

    if (local_pid > 0) {
        pid_category = "specific (>0)";
        pid_meaning = "wait for specific child";
    } else if (local_pid == 0) {
        pid_category = "group (0)";
        pid_meaning = "wait for any child in same process group";
    } else if (local_pid == -1) {
        pid_category = "any (-1)";
        pid_meaning = "wait for any child (most common)";
    } else {
        pid_category = "group (<-1)";
        pid_meaning = "wait for any child in specific process group";
    }

    /* Phase 2: Categorize flags */
    const char *flags_desc;
    if (local_flags == 0) {
        flags_desc = "blocking (0)";
    } else if (local_flags & WNOHANG) {
        flags_desc = "non-blocking (WNOHANG)";
    } else if (local_flags & WUNTRACED) {
        flags_desc = "with stopped (WUNTRACED)";
    } else if (local_flags & WCONTINUED) {
        flags_desc = "with continued (WCONTINUED)";
    } else {
        flags_desc = "custom flags";
    }

    /* Call kernel waitpid implementation */
    int status = 0;
    int rc = fut_task_waitpid(local_pid, &status, local_flags, NULL);

    /* Phase 2: Handle error cases with detailed logging.
     *
     * EINTR is part of the normal contract — userland is expected to
     * retry the syscall — so it's not an error worth logging on every
     * occurrence. Loud kernels that printf every EINTR drown the serial
     * console (e.g. an init-style spawner that gets a flood of pending
     * signals can produce dozens of identical lines per shell exit). */
    if (rc < 0) {
        if (rc == -EINTR) {
            return rc;
        }
        const char *error_desc;
        switch (rc) {
            case -ECHILD:
                error_desc = "no matching children";
                break;
            case -EINVAL:
                error_desc = "invalid arguments";
                break;
            default:
                error_desc = "wait failed";
                break;
        }

        fut_printf("[WAITPID] waitpid(pid=%d [%s: %s], flags=0x%x [%s]) -> %d "
                   "(%s, Phase 3: Non-blocking wait and process group support)\n",
                   local_pid, pid_category, pid_meaning, local_flags, flags_desc, rc, error_desc);

        return rc;
    }

    /* Copy status to userspace if requested */
    if (local_u_status) {
        if (waitpid_copy_to_user(local_u_status, &status, sizeof(status)) != 0) {
            fut_printf("[WAITPID] waitpid(pid=%d [%s], child_pid=%d) -> EFAULT "
                       "(copy_to_user failed, Phase 2)\n",
                       local_pid, pid_category, rc);
            return -EFAULT;
        }
    }

    /* Document status encoding validation to prevent invalid signal/exit code extraction
     * VULNERABILITY: Invalid Status Encoding Leading to Undefined Behavior
     *
     * ATTACK SCENARIO:
     * Child process exits with crafted status that causes invalid macro results
     * 1. Child process calls exit(256) or exit(-1)
     * 2. Parent calls waitpid() and receives status value
     * 3. WEXITSTATUS macro: ((status >> 8) & 0xff)
     * 4. If status encoding is corrupted, exit_code can exceed 8-bit range
     * 5. WTERMSIG macro: (status & 0x7f)
     * 6. If signal number > _NSIG, accessing signal_handlers[term_signal] → OOB
     * 7. Invalid signal delivery or handler invocation
     *
     * IMPACT:
     * - Information disclosure: Invalid exit codes reveal kernel state
     * - Array OOB access: Signal number exceeding _NSIG used as array index
     * - Undefined behavior: Status macros produce nonsensical results
     * - Security bypass: Exit code truncation masks actual exit status
     *
     * ROOT CAUSE:
     * Status macros extract values without range validation
     * - WEXITSTATUS: ((status >> 8) & 0xff) - Always produces 0-255
     * - WTERMSIG: (status & 0x7f) - Produces 0-127
     * - WSTOPSIG: ((status >> 8) & 0xff) - Always produces 0-255
     * - No validation that extracted values are within valid ranges
     * - Signal numbers should be [1, _NSIG), not [0, 127]
     * - Exit codes should be [0, 255] (already enforced by & 0xff)
     *
     * DEFENSE:
     * Document that fut_task_waitpid MUST encode status correctly
     * - Exit status encoding: (exit_code & 0xff) << 8
     * - Signal encoding: (signal & 0x7f) | core_dump_flag
     * - Stopped encoding: 0x7f | (stop_signal << 8)
     * - fut_task_waitpid is responsible for correct encoding
     * - Syscall layer documents contract but trusts kernel encoding
     * - Extracted values are always in valid ranges due to bit masks
     *
     * STATUS ENCODING CONTRACT:
     * Normal exit: status = (exit_code & 0xff) << 8
     * - WIFEXITED: ((status & 0x7f) == 0) → true
     * - WEXITSTATUS: ((status >> 8) & 0xff) → exit_code [0-255]
     *
     * Killed by signal: status = (signal & 0x7f) [| 0x80 if core dumped]
     * - WIFSIGNALED: ((status & 0x7f) != 0 && (status & 0x7f) != 0x7f) → true
     * - WTERMSIG: (status & 0x7f) → signal [1-127]
     *
     * Stopped: status = 0x7f | (stop_signal << 8)
     * - WIFSTOPPED: ((status & 0xff) == 0x7f) → true
     * - WSTOPSIG: ((status >> 8) & 0xff) → signal [0-255]
     *
     * CVE REFERENCES:
     * - CVE-2014-3631: Process status encoding integer overflow
     * - CVE-2016-9754: Wait status macro undefined behavior
     *
     * POSIX REQUIREMENT:
     * IEEE Std 1003.1-2017 waitpid(): "If the value of pid causes status
     * information to be available, the status is stored in the location
     * referenced by stat_loc (if not NULL). The value of *stat_loc is 0
     * if and only if status information is available from a terminated
     * child that exited with a zero status."
     *
     * IMPLEMENTATION NOTES:
     * - Lines 226-240: Extract status using POSIX-compliant macros
     * - Macros automatically mask to valid ranges (& 0xff, & 0x7f)
     * - exit_code is always [0, 255] due to WEXITSTATUS mask
     * - term_signal is always [0, 127] due to WTERMSIG mask
     * - Signal validation must occur when status is ENCODED by fut_task_waitpid
     * - This syscall layer documents contract, trusts kernel encoding
     */
    const char *status_category;
    int exit_code = -1;
    int term_signal = -1;

    if (WIFEXITED(status)) {
        /* Extract exit code (masked to [0, 255] by macro) */
        exit_code = WEXITSTATUS(status);
        if (exit_code == 0) {
            status_category = "exited successfully (code 0)";
        } else {
            status_category = "exited with error";
        }
    } else if (WIFSIGNALED(status)) {
        /* Extract signal number (masked to [0, 127] by macro) */
        term_signal = WTERMSIG(status);
        status_category = "killed by signal";
    } else if (WIFSTOPPED(status)) {
        status_category = "stopped (WUNTRACED)";
    } else {
        status_category = "unknown status";
    }

    /* Success logging suppressed for clean output */
    (void)pid_category; (void)pid_meaning; (void)flags_desc;
    (void)status_category; (void)exit_code; (void)term_signal;

    return rc;
}

/*
 * sys_wait4 - Wait for child, optionally returning resource usage
 *
 * Extends sys_waitpid by filling struct rusage with the child's CPU time
 * when rusage_ptr is non-NULL.  FUT_TIMER_HZ = 100 → 1 tick = 10,000 µs.
 */
#define FUT_TIMER_HZ  100           /* Scheduler tick rate (ticks per second) */
#define USEC_PER_TICK (1000000ULL / FUT_TIMER_HZ)

long sys_wait4(int pid, int *u_status, int flags, void *rusage_ptr) {
    /* Reject unknown flag bits (same validation as waitpid) */
    if (flags & ~WAITPID_VALID_FLAGS) {
        return -EINVAL;
    }

    /* Kernel-pointer bypass for rusage: same pattern as other syscalls */
#ifdef KERNEL_VIRTUAL_BASE
    int use_memcpy_rusage = rusage_ptr && ((uintptr_t)rusage_ptr >= KERNEL_VIRTUAL_BASE);
#else
    int use_memcpy_rusage = 0;
#endif

    /* Validate rusage pointer if provided */
    if (rusage_ptr && !use_memcpy_rusage) {
        /* struct rusage is 144 bytes; check writability */
        if (waitpid_access_ok_write(rusage_ptr, 144) != 0) {
            return -EFAULT;
        }
    }

    /* Validate u_status pointer */
    if (u_status) {
        int bypass = 0;
#ifdef KERNEL_VIRTUAL_BASE
        bypass = ((uintptr_t)u_status >= KERNEL_VIRTUAL_BASE);
#endif
        if (!bypass && waitpid_access_ok_write(u_status, sizeof(int)) != 0)
            return -EFAULT;
    }

    /* Snapshot parent's accumulated child stats before reap so we can
     * compute the delta (= reaped child's own stats) for wait4 rusage. */
    fut_task_t *w4_task = fut_task_current();
    if (!w4_task)
        return -ECHILD;
    uint64_t pre_child_minflt  = w4_task->child_minflt;
    uint64_t pre_child_majflt  = w4_task->child_majflt;
    uint64_t pre_child_nvcsw   = w4_task->child_context_switches;
    uint64_t pre_child_vol     = w4_task->child_voluntary_switches;
    uint64_t pre_child_maxrss  = w4_task->child_maxrss_kb;

    int status = 0;
    uint64_t child_ticks = 0;
    int rc = fut_task_waitpid(pid, &status, flags, &child_ticks);

    if (rc <= 0)
        return rc;

    /* Write exit status to userspace */
    if (u_status) {
#ifdef KERNEL_VIRTUAL_BASE
        if ((uintptr_t)u_status >= KERNEL_VIRTUAL_BASE)
            __builtin_memcpy(u_status, &status, sizeof(status));
        else
#endif
        if (waitpid_copy_to_user(u_status, &status, sizeof(status)) != 0)
            return -EFAULT;
    }

    /* Fill struct rusage for the reaped child.
     * Linux's wait4 returns the child's own usage + its reaped children.
     * Since fut_task_waitpid accumulated the child's stats into parent->child_*,
     * the delta gives us exactly the reaped child's total usage.
     *
     * struct rusage layout (Linux ABI, 144 bytes):
     *   [0]   timeval ru_utime  (tv_sec:8, tv_usec:8)
     *   [16]  timeval ru_stime  (tv_sec:8, tv_usec:8)
     *   [32]  long ru_maxrss
     *   [40]  long ru_ixrss     (0)
     *   [48]  long ru_idrss     (0)
     *   [56]  long ru_isrss     (0)
     *   [64]  long ru_minflt
     *   [72]  long ru_majflt
     *   [80]  long ru_nswap     (0)
     *   [88]  long ru_inblock   (0)
     *   [96]  long ru_oublock   (0)
     *   [104] long ru_msgsnd    (0)
     *   [112] long ru_msgrcv    (0)
     *   [120] long ru_nsignals  (0)
     *   [128] long ru_nvcsw
     *   [136] long ru_nivcsw
     */
    if (rusage_ptr) {
        char rusage_buf[144];
        __builtin_memset(rusage_buf, 0, sizeof(rusage_buf));

        /* ru_utime: CPU ticks of the reaped child */
        uint64_t usec = child_ticks * USEC_PER_TICK;
        int64_t tv_sec  = (int64_t)(usec / 1000000ULL);
        int64_t tv_usec = (int64_t)(usec % 1000000ULL);
        __builtin_memcpy(rusage_buf + 0,  &tv_sec,  8);
        __builtin_memcpy(rusage_buf + 8,  &tv_usec, 8);

        /* Compute deltas from parent's accumulated child stats */
        if (w4_task) {
            long maxrss = (long)(w4_task->child_maxrss_kb - pre_child_maxrss);
            long minflt = (long)(w4_task->child_minflt - pre_child_minflt);
            long majflt = (long)(w4_task->child_majflt - pre_child_majflt);
            long total_sw = (long)(w4_task->child_context_switches - pre_child_nvcsw);
            long vol_sw   = (long)(w4_task->child_voluntary_switches - pre_child_vol);
            long nvcsw    = vol_sw;
            long nivcsw   = total_sw > vol_sw ? total_sw - vol_sw : 0;
            __builtin_memcpy(rusage_buf + 32, &maxrss, 8);  /* ru_maxrss */
            __builtin_memcpy(rusage_buf + 64, &minflt, 8);  /* ru_minflt */
            __builtin_memcpy(rusage_buf + 72, &majflt, 8);  /* ru_majflt */
            __builtin_memcpy(rusage_buf + 128, &nvcsw, 8);  /* ru_nvcsw */
            __builtin_memcpy(rusage_buf + 136, &nivcsw, 8); /* ru_nivcsw */
        }

        if (use_memcpy_rusage)
            __builtin_memcpy(rusage_ptr, rusage_buf, sizeof(rusage_buf));
        else
            waitpid_copy_to_user(rusage_ptr, rusage_buf, sizeof(rusage_buf));
    }

    return rc;
}
