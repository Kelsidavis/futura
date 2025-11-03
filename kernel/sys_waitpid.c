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
 * Phase 2 (Current): Enhanced validation, PID/flag categorization, detailed logging
 * Phase 3: Non-blocking wait, wait for specific children, process groups
 * Phase 4: Advanced wait options (WSTOPPED, WCONTINUED), waitid support
 */

#include <kernel/fut_task.h>
#include <kernel/uaccess.h>
#include <kernel/errno.h>

#include <stddef.h>

extern void fut_printf(const char *fmt, ...);

/* Wait options (for Phase 3+) */
#define WNOHANG    0x00000001  /* Don't block if no child has exited */
#define WUNTRACED  0x00000002  /* Report stopped children */
#define WCONTINUED 0x00000008  /* Report continued children */

/* Status macros (for documentation) */
#define WIFEXITED(status)    (((status) & 0x7f) == 0)
#define WEXITSTATUS(status)  (((status) >> 8) & 0xff)
#define WIFSIGNALED(status)  (((status) & 0x7f) != 0 && ((status) & 0x7f) != 0x7f)
#define WTERMSIG(status)     ((status) & 0x7f)
#define WIFSTOPPED(status)   (((status) & 0xff) == 0x7f)
#define WSTOPSIG(status)     (((status) >> 8) & 0xff)

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
 * Phase 2 (Current): Enhanced validation, PID/flag categorization, detailed logging
 * Phase 3: Non-blocking wait (WNOHANG), process group support
 * Phase 4: Advanced options (WUNTRACED, WCONTINUED), waitid, rusage
 */
long sys_waitpid(int pid, int *u_status, int flags) {
    /* Phase 2: Categorize PID argument */
    const char *pid_category;
    const char *pid_meaning;

    if (pid > 0) {
        pid_category = "specific (>0)";
        pid_meaning = "wait for specific child";
    } else if (pid == 0) {
        pid_category = "group (0)";
        pid_meaning = "wait for any child in same process group";
    } else if (pid == -1) {
        pid_category = "any (-1)";
        pid_meaning = "wait for any child (most common)";
    } else {
        pid_category = "group (<-1)";
        pid_meaning = "wait for any child in specific process group";
    }

    /* Phase 2: Categorize flags */
    const char *flags_desc;
    if (flags == 0) {
        flags_desc = "blocking (0)";
    } else if (flags & WNOHANG) {
        flags_desc = "non-blocking (WNOHANG)";
    } else if (flags & WUNTRACED) {
        flags_desc = "with stopped (WUNTRACED)";
    } else if (flags & WCONTINUED) {
        flags_desc = "with continued (WCONTINUED)";
    } else {
        flags_desc = "custom flags";
    }

    /* Call kernel waitpid implementation */
    int status = 0;
    int rc = fut_task_waitpid(pid, &status);

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
                   "(%s, Phase 2)\n",
                   pid, pid_category, pid_meaning, flags, flags_desc, rc, error_desc);

        return rc;
    }

    /* Copy status to userspace if requested */
    if (u_status) {
        if (fut_copy_to_user(u_status, &status, sizeof(status)) != 0) {
            fut_printf("[WAITPID] waitpid(pid=%d [%s], child_pid=%d) -> EFAULT "
                       "(copy_to_user failed, Phase 2)\n",
                       pid, pid_category, rc);
            return -EFAULT;
        }
    }

    /* Phase 2: Categorize exit status */
    const char *status_category;
    int exit_code = -1;
    int term_signal = -1;

    if (WIFEXITED(status)) {
        exit_code = WEXITSTATUS(status);
        if (exit_code == 0) {
            status_category = "exited successfully (code 0)";
        } else {
            status_category = "exited with error";
        }
    } else if (WIFSIGNALED(status)) {
        term_signal = WTERMSIG(status);
        status_category = "killed by signal";
    } else if (WIFSTOPPED(status)) {
        status_category = "stopped (WUNTRACED)";
    } else {
        status_category = "unknown status";
    }

    /* Phase 2: Detailed success logging */
    if (WIFEXITED(status)) {
        fut_printf("[WAITPID] waitpid(pid=%d [%s: %s], flags=0x%x [%s]) -> %d "
                   "(child pid, %s, exit_code=%d, Phase 2)\n",
                   pid, pid_category, pid_meaning, flags, flags_desc, rc,
                   status_category, exit_code);
    } else if (WIFSIGNALED(status)) {
        fut_printf("[WAITPID] waitpid(pid=%d [%s: %s], flags=0x%x [%s]) -> %d "
                   "(child pid, %s, signal=%d, Phase 2)\n",
                   pid, pid_category, pid_meaning, flags, flags_desc, rc,
                   status_category, term_signal);
    } else {
        fut_printf("[WAITPID] waitpid(pid=%d [%s: %s], flags=0x%x [%s]) -> %d "
                   "(child pid, %s, Phase 2)\n",
                   pid, pid_category, pid_meaning, flags, flags_desc, rc,
                   status_category);
    }

    return rc;
}
