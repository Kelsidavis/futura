/* fut_task.c - Futura OS Task Implementation (C23)
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Tasks are process containers that hold threads and resources.
 * Migrated to x86-64 long mode architecture.
 */

#include "../../include/kernel/fut_task.h"
#include "../../include/kernel/fut_sched.h"
#include "../../include/kernel/fut_mm.h"
#include "../../include/kernel/fut_memory.h"
#include "../../include/kernel/fut_vfs.h"
#include "../../include/kernel/errno.h"
#include <stdatomic.h>
#include <string.h>

/* ============================================================
 *   Task Management
 * ============================================================ */

/* Global task list */
fut_task_t *fut_task_list = NULL;  /* Exposed for stats/debugging */
static _Atomic uint64_t next_pid __attribute__((aligned(8))) = 1;  /* 64-bit PID counter (8-byte aligned for ARM64 atomics) */
static _Atomic uint32_t global_task_count = 0;  /* Total number of active tasks */

/* Task list lock */
static fut_spinlock_t task_list_lock = { .locked = 0 };

/* Global task limits */
#define FUT_MAX_TASKS_GLOBAL    30000  /* Leave headroom below 32768 PID limit */
#define FUT_RESERVED_FOR_ROOT   1000   /* Reserve last 1000 PIDs for root */

/* Resource limit constants (matching sys_prlimit.c) */
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

#define RLIM64_INFINITY   ((uint64_t)-1)

static void task_attach_child(fut_task_t *parent, fut_task_t *child) {
    if (!parent || !child) {
        return;
    }
    child->sibling = parent->first_child;
    parent->first_child = child;
}

static void task_detach_child(fut_task_t *parent, fut_task_t *child) {
    if (!parent || !child) {
        return;
    }
    fut_task_t **it = &parent->first_child;
    while (*it) {
        if (*it == child) {
            *it = child->sibling;
            child->sibling = NULL;
            return;
        }
        it = &(*it)->sibling;
    }
}

/**
 * Create a new task (process container).
 */
fut_task_t *fut_task_create(void) {
    fut_task_t *task = (fut_task_t *)fut_malloc(sizeof(fut_task_t));
    if (!task) {
        return NULL;
    }

    /* Zero out the entire structure first to avoid uninitialized memory */
    memset(task, 0, sizeof(fut_task_t));

#ifdef DEBUG_TASK
    extern void fut_printf(const char *, ...);
    fut_printf("[TASK-CREATE-DBG] After memset: task=%p task->threads=%p\n", task, task->threads);
#endif

    fut_task_t *parent = NULL;
    fut_thread_t *curr = fut_thread_current();
    if (curr) {
        parent = curr->task;
    }

    /* ARM64 workaround: Use inline assembly for atomic fetch-add instead of C11 atomics
     * The C11 atomic intrinsics have issues on ARM64 bare metal (cause alignment faults) */
#if defined(__aarch64__)
    uint64_t new_pid, tmp;
    __asm__ volatile(
        "1: ldxr    %0, [%2]\n"          /* Load exclusive from next_pid */
        "   add     %1, %0, #1\n"        /* Add 1 to loaded value */
        "   stxr    w3, %1, [%2]\n"      /* Store exclusive back to next_pid */
        "   cbnz    w3, 1b\n"            /* Retry if store failed */
        : "=&r"(new_pid), "=&r"(tmp)
        : "r"(&next_pid)
        : "w3", "memory"
    );
#else
    uint64_t new_pid = atomic_fetch_add_explicit(&next_pid, 1, memory_order_seq_cst);
#endif

    *task = (fut_task_t){
        .pid = new_pid,
        .mm = NULL,
        .parent = parent,
        .first_child = NULL,
        .sibling = NULL,
        .state = FUT_TASK_RUNNING,
        .exit_code = 0,
        .term_signal = 0,
        .threads = NULL,
        .thread_count = 0,
        .uid = 0,          /* Default to root UID */
        .gid = 0,          /* Default to root GID */
        .ruid = 0,         /* Real UID (for future use) */
        .rgid = 0,         /* Real GID (for future use) */
        .pgid = (parent ? parent->pgid : new_pid),  /* Inherit parent's PGID, or self if init */
        .sid = (parent ? parent->sid : new_pid),    /* Inherit parent's SID, or self if init */
        .signal_mask = 0,  /* No signals blocked initially */
        .pending_signals = 0,  /* No pending signals */
        .current_dir_ino = (parent ? parent->current_dir_ino : 1),  /* Inherit parent's cwd, default to root (inode 1) */
        .cwd_cache = NULL,  /* No cached path initially */
        .umask = 0022,  /* Default umask: owner read/write, group/others read only */
        .fd_table = NULL,   /* FD table initialized below */
        .max_fds = 0,
        .next_fd = 0,
        .io_bytes_per_sec = 0,  /* No I/O rate limit by default (0 = unlimited) */
        .io_ops_per_sec = 0,  /* No operation rate limit by default */
        .io_bytes_current = 0,  /* No bytes consumed initially */
        .io_ops_current = 0,  /* No operations consumed initially */
        .io_budget_reset_time_ms = 0,  /* Will be set on first budget check */
        .io_budget_limit_wait_ms = 0,  /* Not waiting initially */
        .next = NULL
    };
    fut_waitq_init(&task->child_waiters);

    /* Initialize signal handlers array - all default actions */
    for (int i = 0; i < 31; i++) {
        task->signal_handlers[i] = NULL;  /* NULL = use default action */
        task->signal_handler_masks[i] = 0;  /* No additional signals blocked during handler */
        task->signal_handler_flags[i] = 0;  /* No SA_* flags set initially */
    }

    /* Initialize resource limits with default values */
    task->rlimits[RLIMIT_CPU] = (struct rlimit64){RLIM64_INFINITY, RLIM64_INFINITY};
    task->rlimits[RLIMIT_FSIZE] = (struct rlimit64){RLIM64_INFINITY, RLIM64_INFINITY};
    task->rlimits[RLIMIT_DATA] = (struct rlimit64){RLIM64_INFINITY, RLIM64_INFINITY};
    task->rlimits[RLIMIT_STACK] = (struct rlimit64){8 * 1024 * 1024, RLIM64_INFINITY};  /* 8 MB soft */
    task->rlimits[RLIMIT_CORE] = (struct rlimit64){0, RLIM64_INFINITY};  /* No core dumps */
    task->rlimits[RLIMIT_RSS] = (struct rlimit64){RLIM64_INFINITY, RLIM64_INFINITY};
    task->rlimits[RLIMIT_NPROC] = (struct rlimit64){1024, 2048};  /* 1024 soft, 2048 hard */
    task->rlimits[RLIMIT_NOFILE] = (struct rlimit64){1024, 4096};  /* 1024 soft, 4096 hard */
    task->rlimits[RLIMIT_MEMLOCK] = (struct rlimit64){64 * 1024, 64 * 1024};  /* 64 KB */
    task->rlimits[RLIMIT_AS] = (struct rlimit64){RLIM64_INFINITY, RLIM64_INFINITY};
    task->rlimits[RLIMIT_LOCKS] = (struct rlimit64){RLIM64_INFINITY, RLIM64_INFINITY};
    task->rlimits[RLIMIT_SIGPENDING] = (struct rlimit64){1024, 1024};
    task->rlimits[RLIMIT_MSGQUEUE] = (struct rlimit64){819200, 819200};  /* 800 KB */
    task->rlimits[RLIMIT_NICE] = (struct rlimit64){0, 0};
    task->rlimits[RLIMIT_RTPRIO] = (struct rlimit64){0, 0};
    task->rlimits[RLIMIT_RTTIME] = (struct rlimit64){RLIM64_INFINITY, RLIM64_INFINITY};

    /* Initialize per-task file descriptor table */
    task->max_fds = FUT_FD_TABLE_INITIAL_SIZE;
    task->fd_table = (struct fut_file **)fut_malloc(FUT_FD_TABLE_INITIAL_SIZE * sizeof(struct fut_file *));
    if (!task->fd_table) {
        fut_free(task);
        return NULL;
    }
    /* Zero out the FD table */
    for (int i = 0; i < FUT_FD_TABLE_INITIAL_SIZE; i++) {
        task->fd_table[i] = NULL;
    }
    task->next_fd = 0;

    fut_spinlock_acquire(&task_list_lock);
    if (parent) {
        task_attach_child(parent, task);
    }
    task->next = fut_task_list;
    fut_task_list = task;
    atomic_fetch_add_explicit(&global_task_count, 1, memory_order_relaxed);
    fut_spinlock_release(&task_list_lock);

    return task;
}

/**
 * Add a thread to a task's thread list.
 */
void fut_task_add_thread(fut_task_t *task, fut_thread_t *thread) {
#ifdef DEBUG_TASK
    extern void fut_printf(const char *, ...);
#endif

    if (!task || !thread) {
        return;
    }

#ifdef DEBUG_TASK
    // Debug: Log task->threads value before linking
    fut_printf("[ADD-THREAD-DBG] task=%p thread=%p task->threads=%p thread_count=%d\n",
               task, thread, task->threads, task->thread_count);
#endif

    // Link thread into task's thread list
    thread->next = task->threads;
    if (task->threads) {
#ifdef DEBUG_TASK
        fut_printf("[ADD-THREAD-DBG] About to write prev: task->threads=%p task->threads->prev_addr=%p\n",
                   task->threads, &task->threads->prev);
#endif
        task->threads->prev = thread;
    }
    thread->prev = NULL;
    task->threads = thread;

    task->thread_count++;
}

/**
 * Remove a thread from a task's thread list.
 */
void fut_task_remove_thread(fut_task_t *task, fut_thread_t *thread) {
    if (!task || !thread) {
        return;
    }

    // Unlink thread from task's thread list
    if (thread->prev) {
        thread->prev->next = thread->next;
    } else {
        task->threads = thread->next;
    }

    if (thread->next) {
        thread->next->prev = thread->prev;
    }

    thread->next = NULL;
    thread->prev = NULL;

    task->thread_count--;
}

/**
 * Destroy a task and all its threads.
 */
void fut_task_destroy(fut_task_t *task) {
    if (!task) {
        return;
    }

    fut_thread_t *thread = task->threads;
    while (thread) {
        fut_thread_t *next = thread->next;
        fut_free(thread->stack_base);
        fut_free(thread->alloc_base);  // Free original pointer, not aligned one
        thread = next;
    }

    /* Close all open file descriptors */
    if (task->fd_table) {
        for (int i = 0; i < task->max_fds; i++) {
            if (task->fd_table[i] != NULL) {
                struct fut_file *file = task->fd_table[i];
                /* Decrement refcount - VFS layer manages actual cleanup */
                if (file->refcount > 0) {
                    file->refcount--;
                }
                task->fd_table[i] = NULL;
            }
        }
        fut_free(task->fd_table);
        task->fd_table = NULL;
    }

    fut_spinlock_acquire(&task_list_lock);
    if (task->parent) {
        task_detach_child(task->parent, task);
    }
    if (fut_task_list == task) {
        fut_task_list = task->next;
    } else {
        fut_task_t *prev = fut_task_list;
        while (prev && prev->next != task) {
            prev = prev->next;
        }
        if (prev) {
            prev->next = task->next;
        }
    }
    atomic_fetch_sub_explicit(&global_task_count, 1, memory_order_relaxed);
    fut_spinlock_release(&task_list_lock);

    if (task->mm) {
        fut_mm_release(task->mm);
        task->mm = NULL;
    }

    fut_free(task);
}

void fut_task_set_mm(fut_task_t *task, struct fut_mm *mm) {
    if (!task) {
        return;
    }
    if (task->mm == mm) {
        return;
    }

    if (mm) {
        fut_mm_retain(mm);
    }

    if (task->mm) {
        fut_mm_release(task->mm);
    }

    task->mm = mm;

#ifdef __aarch64__
    /* ARM64: Update current thread's TTBR0 if we're modifying the current task */
    fut_thread_t *current = fut_thread_current();
    if (current && current->task == task && mm) {
        current->context.ttbr0_el1 = mm->ctx.ttbr0_el1;
    }
#endif
}

struct fut_mm *fut_task_get_mm(const fut_task_t *task) {
    if (!task) {
        return NULL;
    }
    return task->mm;
}

fut_task_t *fut_task_current(void) {
    fut_thread_t *thread = fut_thread_current();
    return thread ? thread->task : NULL;
}

static void task_mark_exit(fut_task_t *task, int status, int signal) {
    fut_task_t *parent = task ? task->parent : NULL;

    fut_spinlock_acquire(&task_list_lock);
    task->state = FUT_TASK_ZOMBIE;
    task->exit_code = status & 0xFF;
    task->term_signal = signal & 0x7F;
    fut_spinlock_release(&task_list_lock);

    if (parent) {
        fut_waitq_wake_all(&parent->child_waiters);
    }
}

void fut_task_exit_current(int status) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_thread_exit();
    }

    task_mark_exit(task, status, 0);

    if (task->mm) {
        fut_mm_switch(fut_mm_kernel());
        fut_mm_release(task->mm);
        task->mm = NULL;
    }

    fut_thread_exit();
}

void fut_task_signal_exit(int signal) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_thread_exit();
    }

    task_mark_exit(task, 0, signal);

    if (task->mm) {
        fut_mm_switch(fut_mm_kernel());
        fut_mm_release(task->mm);
        task->mm = NULL;
    }

    fut_thread_exit();
}

static int encode_wait_status(const fut_task_t *task) {
    if (task->term_signal) {
        return task->term_signal & 0x7F;
    }
    return (task->exit_code & 0xFF) << 8;
}

int fut_task_waitpid(int pid, int *status_out) {
    fut_task_t *parent = fut_task_current();
    if (!parent) {
        return -ECHILD;
    }

    for (;;) {
        fut_spinlock_acquire(&task_list_lock);

        bool has_children = parent->first_child != NULL;
        fut_task_t *child = parent->first_child;
        fut_task_t *match = NULL;

        while (child) {
            if ((pid <= 0) || ((int)child->pid == pid)) {
                if (child->state == FUT_TASK_ZOMBIE) {
                    match = child;
                    break;
                }
            }
            child = child->sibling;
        }

        if (!has_children) {
            fut_spinlock_release(&task_list_lock);
            return -ECHILD;
        }

        if (match) {
            int status = encode_wait_status(match);
            uint64_t child_pid = match->pid;
            task_detach_child(parent, match);
            fut_spinlock_release(&task_list_lock);

            if (status_out) {
                *status_out = status;
            }

            fut_task_destroy(match);
            return (int)child_pid;
        }

        fut_waitq_sleep_locked(&parent->child_waiters, &task_list_lock, FUT_THREAD_BLOCKED);
    }
}

/**
 * Get the effective UID of a task.
 * If task is NULL, returns the UID of the current task.
 */
uint32_t fut_task_get_uid(fut_task_t *task) {
    if (!task) {
        task = fut_task_current();
    }
    if (!task) {
        return 0;  /* Default to root UID if no current task */
    }
    return task->uid;
}

/**
 * Get the effective GID of a task.
 * If task is NULL, returns the GID of the current task.
 */
uint32_t fut_task_get_gid(fut_task_t *task) {
    if (!task) {
        task = fut_task_current();
    }
    if (!task) {
        return 0;  /* Default to root GID if no current task */
    }
    return task->gid;
}

/**
 * Set the effective UID and GID of a task.
 * If task is NULL, sets the credentials of the current task.
 */
void fut_task_set_credentials(fut_task_t *task, uint32_t uid, uint32_t gid) {
    if (!task) {
        task = fut_task_current();
    }
    if (!task) {
        return;
    }
    task->uid = uid;
    task->gid = gid;
}

/**
 * Look up a task by PID.
 * Iterates the global task list to find a task with the specified PID.
 *
 * NOTE: This does NOT hold the task_list_lock. Caller should be aware
 * of potential races in preemptive contexts.
 */
fut_task_t *fut_task_by_pid(uint64_t pid) {
    fut_spinlock_acquire(&task_list_lock);
    fut_task_t *task = fut_task_list;
    while (task) {
        if (task->pid == pid) {
            fut_spinlock_release(&task_list_lock);
            return task;
        }
        task = task->next;
    }
    fut_spinlock_release(&task_list_lock);
    return NULL;
}

/**
 * Iterate all tasks in a process group and call callback for each.
 * Used for sending signals to process groups (kill -pgrp).
 * If callback is NULL, just counts the tasks in the group.
 */
int fut_task_foreach_pgid(uint64_t pgid, void (*callback)(fut_task_t *task, void *data), void *data) {
    int count = 0;
    fut_spinlock_acquire(&task_list_lock);
    fut_task_t *task = fut_task_list;
    while (task) {
        if (task->pgid == pgid && task->state != FUT_TASK_ZOMBIE) {
            if (callback) {
                callback(task, data);
            }
            count++;
        }
        task = task->next;
    }
    fut_spinlock_release(&task_list_lock);
    return count;
}

/**
 * fut_task_count_by_uid - Count processes owned by a specific UID
 * @uid: User ID to count processes for
 *
 * Returns: Number of non-zombie processes owned by the specified UID
 *
 * Used for RLIMIT_NPROC enforcement to prevent fork bombs.
 * Iterates the global task list and counts tasks matching the UID.
 * Excludes zombie processes from the count.
 */
int fut_task_count_by_uid(uint32_t uid) {
    int count = 0;
    fut_spinlock_acquire(&task_list_lock);
    fut_task_t *task = fut_task_list;
    while (task) {
        if (task->uid == uid && task->state != FUT_TASK_ZOMBIE) {
            count++;
        }
        task = task->next;
    }
    fut_spinlock_release(&task_list_lock);
    return count;
}

/**
 * fut_task_get_global_count - Get total number of active tasks
 *
 * Returns the current global task count. Used for enforcing system-wide
 * process limits and reserving PIDs for privileged users.
 */
uint32_t fut_task_get_global_count(void) {
    return atomic_load_explicit(&global_task_count, memory_order_relaxed);
}

/**
 * fut_task_can_fork - Check if a new process can be created
 *
 * @param is_root Whether the caller is root (UID 0)
 * @return 1 if fork is allowed, 0 if system is at limit
 *
 * Enforces global task limits while reserving capacity for root.
 * Non-root users are blocked at FUT_MAX_TASKS_GLOBAL - FUT_RESERVED_FOR_ROOT.
 * Root can use the full capacity up to FUT_MAX_TASKS_GLOBAL.
 */
int fut_task_can_fork(int is_root) {
    uint32_t count = fut_task_get_global_count();

    if (is_root) {
        /* Root can use full capacity */
        return count < FUT_MAX_TASKS_GLOBAL;
    } else {
        /* Non-root users have lower limit to reserve PIDs for root */
        return count < (FUT_MAX_TASKS_GLOBAL - FUT_RESERVED_FOR_ROOT);
    }
}
