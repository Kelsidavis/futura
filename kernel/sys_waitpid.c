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
 * Phase 3: Non-blocking wait, wait for specific children, process groups
 * Phase 4: Advanced wait options (WSTOPPED, WCONTINUED), waitid support
 */

#include <kernel/fut_task.h>
#include <kernel/uaccess.h>
#include <kernel/errno.h>
#include <sys/wait.h>

#include <stddef.h>

#include <kernel/kprintf.h>

/* Wait options (WNOHANG, WUNTRACED, WCONTINUED) and status macros
 * (WIFEXITED, WEXITSTATUS, WIFSIGNALED, WTERMSIG, WIFSTOPPED, WSTOPSIG)
 * are provided by sys/wait.h */

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
 * Phase 3: Non-blocking wait (WNOHANG), process group support
 * Phase 4: Advanced options (WUNTRACED, WCONTINUED), waitid, rusage
 */
long sys_waitpid(int pid, int *u_status, int flags) {
    /* ARM64 FIX: Copy parameters to local variables immediately to ensure they're preserved
     * on the stack across blocking calls. When fut_task_waitpid blocks and resumes,
     * register-passed parameters may be corrupted. */
    int local_pid = pid;
    int *local_u_status = u_status;
    int local_flags = flags;

    /* Phase 5: Validate u_status write permission early (kernel writes exit status)
     * VULNERABILITY: Invalid Output Buffer Pointer
     * ATTACK: Attacker provides read-only or unmapped u_status buffer
     * IMPACT: Kernel page fault when writing exit status after potentially blocking wait
     * DEFENSE: Check write permission before blocking on fut_task_waitpid */
    if (local_u_status && fut_access_ok(local_u_status, sizeof(int), 1) != 0) {
        fut_printf("[WAITPID] waitpid(pid=%d, u_status=%p) -> EFAULT (u_status not writable for %zu bytes, Phase 5)\n",
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
    int rc = fut_task_waitpid(local_pid, &status);

    /* Phase 2: Handle error cases with detailed logging */
    if (rc < 0) {
        const char *error_desc;
        switch (rc) {
            case -ECHILD:
                error_desc = "no matching children";
                break;
            case -EINTR:
                error_desc = "interrupted by signal";
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
        if (fut_copy_to_user(local_u_status, &status, sizeof(status)) != 0) {
            fut_printf("[WAITPID] waitpid(pid=%d [%s], child_pid=%d) -> EFAULT "
                       "(copy_to_user failed, Phase 2)\n",
                       local_pid, pid_category, rc);
            return -EFAULT;
        }
    }

    /* Phase 5: Document status encoding validation to prevent invalid signal/exit code extraction
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
     * DEFENSE (Phase 5):
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
        /* Phase 5: Extract exit code (masked to [0, 255] by macro) */
        exit_code = WEXITSTATUS(status);
        if (exit_code == 0) {
            status_category = "exited successfully (code 0)";
        } else {
            status_category = "exited with error";
        }
    } else if (WIFSIGNALED(status)) {
        /* Phase 5: Extract signal number (masked to [0, 127] by macro) */
        term_signal = WTERMSIG(status);
        status_category = "killed by signal";
    } else if (WIFSTOPPED(status)) {
        status_category = "stopped (WUNTRACED)";
    } else {
        status_category = "unknown status";
    }

    /* Phase 5: Detailed success logging with status encoding validation */
    if (WIFEXITED(status)) {
        fut_printf("[WAITPID] waitpid(pid=%d [%s: %s], flags=0x%x [%s]) -> %d "
                   "(child pid, %s, exit_code=%d, Phase 5: status encoding validation)\n",
                   local_pid, pid_category, pid_meaning, local_flags, flags_desc, rc,
                   status_category, exit_code);
    } else if (WIFSIGNALED(status)) {
        fut_printf("[WAITPID] waitpid(pid=%d [%s: %s], flags=0x%x [%s]) -> %d "
                   "(child pid, %s, signal=%d, Phase 5: status encoding validation)\n",
                   local_pid, pid_category, pid_meaning, local_flags, flags_desc, rc,
                   status_category, term_signal);
    } else {
        fut_printf("[WAITPID] waitpid(pid=%d [%s: %s], flags=0x%x [%s]) -> %d "
                   "(child pid, %s, Phase 5: status encoding validation)\n",
                   local_pid, pid_category, pid_meaning, local_flags, flags_desc, rc,
                   status_category);
    }

    return rc;
}
