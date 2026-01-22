/* fut_task.h - Futura OS Task (Process) Subsystem (C23)
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Tasks are containers for threads, representing processes.
 * Each task has its own address space (future VMM integration).
 */

#pragma once

#include <stdint.h>
#include <stddef.h>
#include "fut_thread.h"
#include "fut_waitq.h"
#include "signal.h"

struct fut_mm;

/* Forward declaration */
typedef struct fut_task fut_task_t;

/* ============================================================
 *   Task Configuration Constants
 * ============================================================ */

/* Initial file descriptor table size for new tasks */
#define FUT_FD_TABLE_INITIAL_SIZE 64

/* ============================================================
 *   Task Structure (Process Container)
 * ============================================================ */

struct fut_task {
    uint64_t pid;                      // Process ID (64-bit)

    struct fut_mm *mm;                 // Address space

    struct fut_task *parent;           // Parent task
    struct fut_task *first_child;      // Child list head
    struct fut_task *sibling;          // Next sibling in parent list
    fut_waitq_t child_waiters;         // Wait queue for waitpid callers

    enum {
        FUT_TASK_RUNNING = 0,
        FUT_TASK_ZOMBIE,
    } state;

    int exit_code;                     // Exit status (8-bit in low byte)
    int term_signal;                   // Terminating signal (0 if normal exit)

    fut_thread_t *threads;             // Linked list of threads
    uint64_t thread_count;             // Number of threads in task

    /* Process credentials (POSIX three-tier UID/GID model)
     *
     * Real UID/GID: Original process owner, used for accounting
     * Effective UID/GID: Used for permission checks (file access, signals, etc.)
     * Saved UID/GID: Backup of previous effective UID/GID for privilege swapping
     *
     * Privilege model:
     * - Superuser (uid 0): Can set any UID/GID values
     * - Regular user: Can only set to current real, effective, or saved UID/GID
     */
    uint32_t uid;                      // Effective UID (used for permission checks)
    uint32_t gid;                      // Effective GID (used for permission checks)
    uint32_t ruid;                     // Real UID (original process owner)
    uint32_t rgid;                     // Real GID (original process group)
    uint32_t suid;                     // Saved UID (backup for privilege swapping)
    uint32_t sgid;                     // Saved GID (backup for privilege swapping)

    /* Process group and session (job control) */
    uint64_t pgid;                     // Process group ID (for job control)
    uint64_t sid;                      // Session ID (controlling terminal session)

    /* Signal handling */
    sighandler_t signal_handlers[_NSIG];  // Array of signal handlers (index 1-30)
    uint64_t signal_mask;                 // Mask of currently blocked signals
    uint64_t signal_handler_masks[_NSIG]; // Per-handler masks (signals to block during handler)
    int signal_handler_flags[_NSIG];      // Per-handler flags (SA_RESTART, SA_RESETHAND, etc.)
    uint64_t pending_signals;          // Bitmask of pending signals awaiting delivery
    fut_waitq_t signal_waitq;          // Wait queue for pause() blocking until signal
    struct sigaltstack sig_altstack;   // Alternate signal stack configuration

    /* Alarm timer */
    uint64_t alarm_expires_ms;         // Alarm expiration time in milliseconds (0 = no alarm)

    /* Thread cleanup (for NPTL/pthread support) */
    int *clear_child_tid;              // Address to clear and wake on thread exit (set_tid_address)

    /* File system context */
    uint64_t current_dir_ino;          // Current working directory inode (root=1)
    char *cwd_cache;                   // Cached current working directory path (points to cwd_cache_buf)
    char cwd_cache_buf[256];           // Buffer for caching current working directory path
    uint32_t umask;                    // File creation mask (per-task, not global)

    /* I/O priority */
    int ioprio;                        // I/O priority (class + level encoded)
    int ioprio_class;                  // I/O priority class (0=none, 1=RT, 2=BE, 3=IDLE)
    int ioprio_level;                  // I/O priority level (0-7 for BE/RT, ignored for IDLE)

    /* POSIX capabilities */
    uint64_t cap_effective;            // Effective capability set
    uint64_t cap_permitted;            // Permitted capability set
    uint64_t cap_inheritable;          // Inheritable capability set

    /* File descriptor table (per-task, for process isolation) */
    struct fut_file **fd_table;        // Array of file pointers
    int max_fds;                       // Allocated size of fd_table
    int next_fd;                       // Next FD index to allocate

    /* Resource limits (POSIX rlimits) */
    struct rlimit64 {
        uint64_t rlim_cur;             // Soft limit
        uint64_t rlim_max;             // Hard limit (ceiling for rlim_cur)
    } rlimits[16];                     // RLIMIT_NLIMITS = 16

    /* I/O Budget Tracking (Phase 4 - Rate Limiting) */
    uint64_t io_bytes_per_sec;         // Bytes allowed per second (0 = unlimited)
    uint64_t io_ops_per_sec;           // I/O operations allowed per second (0 = unlimited)
    uint64_t io_bytes_current;         // Current second's bytes consumed (resets every 1000ms)
    uint64_t io_ops_current;           // Current second's operations consumed (resets every 1000ms)
    uint64_t io_budget_reset_time_ms;  // Last time budget counters were reset (milliseconds)
    uint64_t io_budget_limit_wait_ms;  // Time to wait before allowing next large I/O (0 = not waiting)

    fut_task_t *next;                  // Next task in system list
};

/* ============================================================
 *   Task API
 * ============================================================ */

/**
 * Create a new task (process).
 *
 * @return Task handle, or nullptr on failure
 */
[[nodiscard]] fut_task_t *fut_task_create(void);

/**
 * Add a thread to a task's thread list.
 *
 * @param task    Task to add thread to
 * @param thread  Thread to add
 */
void fut_task_add_thread(fut_task_t *task, fut_thread_t *thread);

/**
 * Remove a thread from a task's thread list.
 *
 * @param task    Task to remove thread from
 * @param thread  Thread to remove
 */
void fut_task_remove_thread(fut_task_t *task, fut_thread_t *thread);

/**
 * Destroy a task and all its threads.
 *
 * @param task  Task to destroy
 */
void fut_task_destroy(fut_task_t *task);

/**
 * Assign an address space to a task.
 */
void fut_task_set_mm(fut_task_t *task, struct fut_mm *mm);

/**
 * Fetch the address space associated with a task.
 */
struct fut_mm *fut_task_get_mm(const fut_task_t *task);

fut_task_t *fut_task_current(void);
void fut_task_exit_current(int status);
int fut_task_waitpid(int pid, int *status_out);
void fut_task_signal_exit(int signal);

/**
 * Look up a task by PID.
 *
 * @param pid Process ID to find
 * @return Task with that PID, or NULL if not found
 *
 * NOTE: Caller must hold task_list_lock or accept potential races.
 */
fut_task_t *fut_task_by_pid(uint64_t pid);

/**
 * Iterate all tasks in a process group and call callback for each.
 *
 * @param pgid Process group ID
 * @param callback Function to call for each task in the group
 * @param data User data passed to callback
 * @return Number of tasks in the group
 */
int fut_task_foreach_pgid(uint64_t pgid, void (*callback)(fut_task_t *task, void *data), void *data);

/**
 * Count processes owned by a specific UID.
 *
 * @param uid User ID to count processes for
 * @return Number of non-zombie processes owned by the UID
 */
int fut_task_count_by_uid(uint32_t uid);

/**
 * Get total number of active tasks system-wide.
 *
 * @return Current global task count
 */
uint32_t fut_task_get_global_count(void);

/**
 * Check if a new process can be created (global limit check).
 *
 * @param is_root Whether the caller is root (UID 0)
 * @return 1 if fork is allowed, 0 if system is at limit
 */
int fut_task_can_fork(int is_root);

/**
 * Get the effective UID of a task.
 *
 * @param task Task (NULL for current task)
 * @return Effective UID
 */
uint32_t fut_task_get_uid(fut_task_t *task);

/**
 * Get the effective GID of a task.
 *
 * @param task Task (NULL for current task)
 * @return Effective GID
 */
uint32_t fut_task_get_gid(fut_task_t *task);

/**
 * Set the effective UID and GID of a task.
 *
 * @param task Task to modify (NULL for current task)
 * @param uid  New effective UID
 * @param gid  New effective GID
 */
void fut_task_set_credentials(fut_task_t *task, uint32_t uid, uint32_t gid);
