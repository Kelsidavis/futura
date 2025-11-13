// SPDX-License-Identifier: MPL-2.0
/*
 * sys_exit.c - Process termination syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements process termination via exit() syscall.
 * Essential for normal program completion and error reporting.
 *
 * Phase 1 (Completed): Basic exit with status code
 * Phase 2 (Completed): Enhanced validation, exit code categorization, detailed logging
 * Phase 3 (Completed): Resource cleanup tracking, exit hooks
 * Phase 4 (Current): Process groups, session leaders, zombie reaping
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>

extern void fut_printf(const char *fmt, ...);
extern int fut_vfs_close(int fd);

/* Phase 3: Exit hook structure for resource cleanup */
struct exit_hook {
    void (*cleanup_fn)(void *arg);
    void *arg;
};

#define MAX_EXIT_HOOKS 16

/* Phase 3: Static exit hooks array per task */
static struct {
    struct exit_hook hooks[MAX_EXIT_HOOKS];
    int count;
} exit_hooks = {0};

/**
 * exit() syscall - Terminate calling process
 *
 * Terminates the calling process and returns an exit status to the parent.
 * This syscall never returns to the caller.
 *
 * @param status Exit status code (0-255 accessible to parent)
 *
 * Returns:
 *   - Never returns (process is terminated)
 *
 * Behavior:
 *   - Immediately terminates the calling process
 *   - Returns exit status to parent process (waitpid)
 *   - Closes all open file descriptors
 *   - Releases memory and resources
 *   - Becomes zombie until parent reaps with waitpid()
 *   - Orphaned children are reparented to init (PID 1)
 *   - Never returns to caller
 *
 * Exit status convention:
 *   - 0: Success, normal termination
 *   - 1-127: Application-specific errors
 *   - 128+N: Terminated by signal N (128+SIGKILL=137)
 *   - 255: Often used for "generic error"
 *
 * Exit status encoding:
 *   - Low 8 bits: Exit code (0-255)
 *   - High bits: Signal info (if killed by signal)
 *   - Parent extracts with WEXITSTATUS(status)
 *
 * Common usage patterns:
 *
 * Success exit:
 *   exit(0);  // or return 0 from main()
 *
 * Error exit:
 *   if (error_condition) {
 *       fprintf(stderr, "Error: %s\n", strerror(errno));
 *       exit(1);  // or EXIT_FAILURE
 *   }
 *
 * Signal-like exit (by convention):
 *   exit(128 + SIGTERM);  // Simulate SIGTERM termination
 *
 * Shell exit codes:
 *   - 0: Command succeeded
 *   - 1: General error
 *   - 2: Misuse of shell command
 *   - 126: Command cannot execute
 *   - 127: Command not found
 *   - 130: Terminated by Ctrl+C (128 + SIGINT)
 *
 * Difference from _exit():
 *   - exit(): Calls atexit() handlers, flushes stdio buffers
 *   - _exit(): Immediate termination, no cleanup
 *   - Kernel exit() is like _exit() (no userspace cleanup)
 *
 * Parent checking exit status:
 *   int status;
 *   pid_t pid = waitpid(child_pid, &status, 0);
 *   if (WIFEXITED(status)) {
 *       int exit_code = WEXITSTATUS(status);
 *       printf("Child exited with code %d\n", exit_code);
 *   }
 *
 * Related syscalls:
 *   - waitpid(): Parent waits for child to exit
 *   - kill(): Send signal to process (alternative termination)
 *   - fork(): Create child process
 *
 * Phase 1 (Completed): Basic exit with status code
 * Phase 2 (Completed): Enhanced validation, exit code categorization, detailed logging
 * Phase 3 (Current): Resource cleanup tracking, exit hooks, coredumps
 * Phase 4: Process groups, session leaders, zombie reaping
 */
long sys_exit(int status) {
    /* Get current task for context */
    fut_task_t *task = fut_task_current();

    /* Phase 2: Categorize exit status */
    const char *status_category;
    const char *status_meaning;

    if (status == 0) {
        status_category = "success (0)";
        status_meaning = "normal termination";
    } else if (status > 0 && status < 64) {
        status_category = "error (1-63)";
        status_meaning = "application error";
    } else if (status >= 64 && status < 128) {
        status_category = "error (64-127)";
        status_meaning = "application error (high)";
    } else if (status >= 128 && status < 192) {
        status_category = "signal (128-191)";
        status_meaning = "simulated signal termination";
    } else {
        status_category = "unusual (≥192)";
        status_meaning = "non-standard exit code";
    }

    /* Phase 2: Detailed exit logging */
    if (task) {
        fut_printf("[EXIT] exit(status=%d [%s: %s], pid=%u) "
                   "(terminating process, Phase 2)\n",
                   status, status_category, status_meaning,
                   task->pid);
    } else {
        fut_printf("[EXIT] exit(status=%d [%s: %s], no task context) "
                   "(terminating, Phase 2)\n",
                   status, status_category, status_meaning);
    }

    /* Phase 3: Resource cleanup tracking */
    int fds_closed = 0;
    int hooks_executed = 0;

    if (task) {
        /* Phase 3: Close all open file descriptors */
        if (task->fd_table) {
            for (int i = 0; i < task->max_fds; i++) {
                if (task->fd_table[i] != NULL) {
                    fut_vfs_close(i);
                    fds_closed++;
                }
            }
        }

        /* Phase 3: Execute registered exit hooks for cleanup callbacks */
        for (int i = 0; i < exit_hooks.count && i < MAX_EXIT_HOOKS; i++) {
            if (exit_hooks.hooks[i].cleanup_fn != NULL) {
                exit_hooks.hooks[i].cleanup_fn(exit_hooks.hooks[i].arg);
                hooks_executed++;
            }
        }

        /* Phase 3: Log resource cleanup statistics */
        fut_printf("[EXIT] exit(status=%d, pid=%u) resource cleanup: "
                   "fds_closed=%d, hooks_executed=%d, "
                   "mem_usage=%lu bytes (Phase 3 cleanup)\n",
                   status, task->pid, fds_closed, hooks_executed,
                   task->memory_used ?: 0);
    }

    /* Phase 3: Clear exit hooks array after execution */
    exit_hooks.count = 0;

    /* Terminate the current task */
    fut_task_exit_current(status);

    /* Never reached - exit never returns */
    return 0;
}
