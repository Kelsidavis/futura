/* fut_task.c - Futura OS Task Implementation (C23)
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Tasks are process containers that hold threads and resources.
 * Migrated to x86-64 long mode architecture.
 */

#include "../../include/kernel/fut_task.h"
#include "../../include/kernel/fut_thread.h"
#include "../../include/kernel/fut_personality.h"
#include "../../include/kernel/fut_sched.h"
#include "../../include/kernel/fut_mm.h"
#include "../../include/kernel/fut_memory.h"
#include "../../include/kernel/fut_vfs.h"
#include "../../include/kernel/errno.h"
#include <kernel/signal.h>
#include "../../include/kernel/uaccess.h"
#include <kernel/kprintf.h>
#include <stdatomic.h>
#include <string.h>
#include <sys/resource.h>

/* Kernel-internal futex wake function (defined in kernel/sys_futex.c) */
extern int futex_wake_one(uint32_t *uaddr);

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

/* RLIMIT_* constants provided by sys/resource.h */

#define RLIM64_INFINITY   ((uint64_t)-1)

/* Exit status encoding masks (POSIX waitpid() format) */
#define EXIT_CODE_MASK      0xFF    /* Low 8 bits: exit code (0-255) */
#define SIGNAL_MASK         0x7F    /* Low 7 bits: signal number (1-127) */
#define WAIT_STATUS_SHIFT   8       /* Exit code shifted left 8 bits in wait status */

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
        .uid = 0,          /* Default to root effective UID */
        .gid = 0,          /* Default to root effective GID */
        .ruid = 0,         /* Default to root real UID */
        .rgid = 0,         /* Default to root real GID */
        .suid = 0,         /* Default to root saved UID */
        .sgid = 0,         /* Default to root saved GID */
        .pgid = (parent ? parent->pgid : new_pid),  /* Inherit parent's PGID, or self if init */
        .sid = (parent ? parent->sid : new_pid),    /* Inherit parent's SID, or self if init */
        .signal_mask = 0,  /* No signals blocked initially */
        .pending_signals = 0,  /* No pending signals */
        .current_dir_ino = (parent ? parent->current_dir_ino : 1),  /* Inherit parent's cwd, default to root (inode 1) */
        .cwd_cache = NULL,  /* Set to cwd_cache_buf below */
        .umask = FUT_UMASK_DEFAULT,  /* Default umask: owner read/write, group/others read only */
        .personality = PER_LINUX,   /* Default Linux personality */
        .dumpable = 1,              /* Linux default: processes are dumpable (PR_GET_DUMPABLE=1) */
        .nice = 0,                  /* Default nice value (normal priority) */
        .clear_child_tid = NULL,  /* No tid address set initially (set via set_tid_address) */
        .fd_table = NULL,   /* FD table initialized below */
        .max_fds = 0,
        .next_fd = 0,
        .io_bytes_per_sec = 0,  /* No I/O rate limit by default (0 = unlimited) */
        .io_ops_per_sec = 0,  /* No operation rate limit by default */
        .io_bytes_current = 0,  /* No bytes consumed initially */
        .io_ops_current = 0,  /* No operations consumed initially */
        .io_budget_reset_time_ms = 0,  /* Will be set on first budget check */
        .io_budget_limit_wait_ms = 0,  /* Not waiting initially */
        .dupfd_ops_per_sec = 1000,  /* Limit to 1000 F_DUPFD ops/sec by default */
        .dupfd_ops_current = 0,  /* No F_DUPFD operations consumed initially */
        .dupfd_reset_time_ms = 0,  /* Will be set on first F_DUPFD call */
        .next = NULL
    };
    /* Root tasks (uid=0) get all capabilities by default.
     * On Linux, init starts with full caps; child processes inherit them. */
    if (task->uid == 0) {
        task->cap_effective   = 0xFFFFFFFFFFFFFFFFULL;  /* All 64 capability bits */
        task->cap_permitted   = 0xFFFFFFFFFFFFFFFFULL;
        task->cap_inheritable = 0xFFFFFFFFFFFFFFFFULL;
    }
    /* Bounding set: all caps 0..40 (cap_last_cap=40); dropped via PR_CAPBSET_DROP */
    task->cap_bset = (1ULL << 41) - 1;  /* 0x000001ffffffffff */

    fut_waitq_init(&task->child_waiters);
    fut_spinlock_init(&task->pidfd_notify_lock);
    for (int pni = 0; pni < FUT_PIDFD_NOTIFY_MAX; pni++)
        task->pidfd_notify[pni] = NULL;
    fut_waitq_init(&task->stop_waitq);
    fut_spinlock_init(&task->cap_recv_lock);
    fut_waitq_init(&task->cap_recv_waitq);

    /* Initialize cwd_cache to parent's path or "/" */
    if (parent && parent->cwd_cache) {
        size_t len = 0;
        while (parent->cwd_cache[len] && len < 255) len++;
        for (size_t i = 0; i <= len; i++) {
            task->cwd_cache_buf[i] = parent->cwd_cache[i];
        }
    } else {
        task->cwd_cache_buf[0] = '/';
        task->cwd_cache_buf[1] = '\0';
    }
    task->cwd_cache = task->cwd_cache_buf;

    /* Initialize signal handlers array - all default actions */
    for (int i = 0; i < _NSIG; i++) {
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

    /* Sentinel: RLIMIT_CPU last-signaled second starts at UINT64_MAX so that
     * even a soft limit of 0 fires SIGXCPU on the very first timer tick. */
    task->rlimit_cpu_last_sec = (uint64_t)-1;

    /* Record creation time for /proc/pid/stat starttime field */
    { extern uint64_t fut_get_ticks(void); task->start_ticks = fut_get_ticks(); }

    /* Initialize per-task file descriptor table */
    task->max_fds = FUT_FD_TABLE_INITIAL_SIZE;
    task->fd_table = (struct fut_file **)fut_malloc(FUT_FD_TABLE_INITIAL_SIZE * sizeof(struct fut_file *));
    if (!task->fd_table) {
        fut_free(task);
        return NULL;
    }
    task->fd_flags = (int *)fut_malloc(FUT_FD_TABLE_INITIAL_SIZE * sizeof(int));
    if (!task->fd_flags) {
        fut_free(task->fd_table);
        fut_free(task);
        return NULL;
    }
    /* Zero out the FD table and flags */
    for (int i = 0; i < FUT_FD_TABLE_INITIAL_SIZE; i++) {
        task->fd_table[i] = NULL;
        task->fd_flags[i] = 0;
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
                /* Atomically decrement refcount - VFS layer manages actual cleanup */
                if (file->refcount > 0) {
                    __atomic_sub_fetch(&file->refcount, 1, __ATOMIC_ACQ_REL);
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

    /* Release chroot jail vnode if set */
    if (task->chroot_vnode) {
        fut_vnode_unref(task->chroot_vnode);
        task->chroot_vnode = NULL;
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
    task->exit_code = status & EXIT_CODE_MASK;
    task->term_signal = signal & SIGNAL_MASK;
    fut_spinlock_release(&task_list_lock);

    /* Wake any epoll/poll/select waitqs registered via pidfds for this task */
    fut_spinlock_acquire(&task->pidfd_notify_lock);
    for (int pni = 0; pni < FUT_PIDFD_NOTIFY_MAX; pni++) {
        if (task->pidfd_notify[pni])
            fut_waitq_wake_all(task->pidfd_notify[pni]);
    }
    fut_spinlock_release(&task->pidfd_notify_lock);

    if (parent) {
        /* SA_NOCLDWAIT / SIGCHLD=SIG_IGN: auto-reap the child.
         * POSIX / Linux: if the parent has SIGCHLD=SIG_IGN or SA_NOCLDWAIT,
         * the child must NOT become a zombie.  Instead it is reaped
         * immediately: detached from the parent's child list so that a
         * subsequent waitpid() returns -ECHILD.  The task struct is freed
         * lazily in fut_thread_exit() once the last thread has switched
         * away (see auto_reap handling there). */
        sighandler_t chld_handler = parent->signal_handlers[SIGCHLD - 1];
        unsigned long chld_flags  = parent->signal_handler_flags[SIGCHLD - 1];
        bool suppress_chld = (chld_handler == SIG_IGN) ||
                             (chld_flags & SA_NOCLDWAIT);
        if (suppress_chld) {
            /* Mark for lazy free in fut_thread_exit() */
            task->auto_reap = 1;
            /* Detach from parent now so waitpid() returns ECHILD */
            fut_spinlock_acquire(&task_list_lock);
            task_detach_child(parent, task);
            /* Remove from global task list so fut_task_by_pid() returns NULL */
            if (fut_task_list == task) {
                fut_task_list = task->next;
            } else {
                fut_task_t *prev = fut_task_list;
                while (prev && prev->next != task) {
                    prev = prev->next;
                }
                if (prev) prev->next = task->next;
            }
            atomic_fetch_sub_explicit(&global_task_count, 1, memory_order_relaxed);
            task->next = NULL;
            fut_spinlock_release(&task_list_lock);
            /* Wake any blocked waitpid() — it will return ECHILD */
            fut_waitq_wake_all(&parent->child_waiters);
        } else {
            siginfo_t chld_info;
            __builtin_memset(&chld_info, 0, sizeof(chld_info));
            chld_info.si_signum = SIGCHLD;
            chld_info.si_code   = signal ? CLD_KILLED : CLD_EXITED;
            chld_info.si_pid    = task->pid;
            chld_info.si_uid    = task->uid;
            chld_info.si_status = signal ? signal : status;
            fut_signal_send_with_info(parent, SIGCHLD, &chld_info);
            /* Wake waitpid/wait4 blockers */
            fut_waitq_wake_all(&parent->child_waiters);
        }
    }
}

/**
 * fut_task_find_new_parent - Find the new parent for a dying task's orphaned children.
 *
 * Walks up the ancestor chain looking for the nearest subreaper
 * (PR_SET_CHILD_SUBREAPER). Falls back to init (pid 1) if none found.
 * Caller must hold task_list_lock.
 */
fut_task_t *fut_task_find_new_parent(fut_task_t *dying_task) {
    fut_task_t *new_parent = NULL;
    fut_task_t *ancestor = dying_task->parent;
    while (ancestor && ancestor->pid != 1) {
        if ((ancestor->personality >> 31) & 1) {  /* PR_SET_CHILD_SUBREAPER bit */
            new_parent = ancestor;
            break;
        }
        ancestor = ancestor->parent;
    }
    if (!new_parent) {
        fut_task_t *t = fut_task_list;
        while (t) {
            if (t->pid == 1) {
                new_parent = t;
                break;
            }
            t = t->next;
        }
    }
    return new_parent;
}

/**
 * Internal helper: Clean up task memory and exit thread.
 * Consolidates common exit cleanup to avoid code duplication.
 */
static void task_cleanup_and_exit(fut_task_t *task, int status, int signal) {
    if (!task) {
        fut_thread_exit();
    }

    /* Phase 4: Implement clear_child_tid for NPTL/pthread support
     *
     * When a thread exits and clear_child_tid is set (via set_tid_address syscall):
     * 1. Write 0 to the address pointed to by clear_child_tid
     * 2. Wake one futex waiter on that address
     *
     * This is essential for pthread_join() to work correctly:
     * - Thread library calls set_tid_address(&thread_struct->tid) at thread creation
     * - When thread exits, kernel writes 0 to clear tid
     * - Kernel wakes futex waiter (pthread_join waiting on tid)
     * - Joining thread sees tid==0 and knows thread has exited
     *
     * Must be done BEFORE releasing mm since we need to write to userspace memory.
     */
    if (task->clear_child_tid != NULL) {
        /* Write 0 to the tid address */
        int zero = 0;
        if (fut_copy_to_user(task->clear_child_tid, &zero, sizeof(int)) == 0) {
            futex_wake_one((uint32_t *)task->clear_child_tid);
        }
        task->clear_child_tid = NULL;  /* Clear the address so we don't do this twice */
    }

    /* Reparent orphaned children before marking zombie.
     * Linux semantics: reparent to the nearest ancestor that is a subreaper
     * (PR_SET_CHILD_SUBREAPER), falling back to init (pid 1).
     * Without this, children of dying processes become permanently
     * unreapable zombies since no parent can wait4() on them. */
    fut_spinlock_acquire(&task_list_lock);
    if (task->first_child) {
        fut_task_t *new_parent = fut_task_find_new_parent(task);
        if (new_parent && new_parent != task) {
            /* Move all children to new_parent. Deliver pdeathsig if configured. */
            fut_task_t *child = task->first_child;
            while (child) {
                fut_task_t *next = child->sibling;
                /* Deliver parent-death signal if child requested one via prctl */
                if (child->pdeathsig > 0 && child->state != FUT_TASK_ZOMBIE) {
                    fut_signal_send(child, child->pdeathsig);
                }
                child->parent = new_parent;
                child->sibling = new_parent->first_child;
                new_parent->first_child = child;
                child = next;
            }
            task->first_child = NULL;
            /* Wake new_parent in case any reparented children are zombies */
            fut_waitq_wake_all(&new_parent->child_waiters);
        }
    }
    fut_spinlock_release(&task_list_lock);

    /* Write process accounting record before marking zombie.
     * Threads are still attached here so cpu_ticks are readable. */
    acct_write_record(task, status, signal);

    task_mark_exit(task, status, signal);

    /* Release user-space memory manager before exiting */
    if (task->mm) {
        fut_mm_switch(fut_mm_kernel());
        fut_mm_release(task->mm);
        task->mm = NULL;
    }

    fut_thread_exit();
}

void fut_task_exit_current(int status) {
    task_cleanup_and_exit(fut_task_current(), status, 0);
}

void fut_task_signal_exit(int signal) {
    fut_task_t *task = fut_task_current();
    if (task) {
        fut_printf("[TASK-EXIT] Task PID=%d killed by signal %d\n", task->pid, signal);
    } else {
        fut_printf("[TASK-EXIT] Unknown task killed by signal %d\n", signal);
    }
    task_cleanup_and_exit(task, 0, signal);
}

static int encode_wait_status(const fut_task_t *task) {
    if (task->term_signal) {
        return task->term_signal & SIGNAL_MASK;
    }
    return (task->exit_code & EXIT_CODE_MASK) << WAIT_STATUS_SHIFT;
}

/**
 * fut_task_do_stop() - Stop a task due to SIGSTOP/SIGTSTP/SIGTTIN/SIGTTOU.
 * Sets the task state to FUT_TASK_STOPPED, records the stop signal, notifies
 * the parent (for WUNTRACED), then sleeps the current thread on stop_waitq.
 */
void fut_task_do_stop(fut_task_t *task, int sig) {
    if (!task) return;
    fut_spinlock_acquire(&task_list_lock);
    task->state = FUT_TASK_STOPPED;
    task->stop_signal = sig;
    task->stop_reported = 0;  /* new stop — reset so WUNTRACED can report it */
    if (task->parent) {
        /* SA_NOCLDSTOP: don't send SIGCHLD for stop events if parent set this flag.
         * Wake waitpid blockers (WUNTRACED) regardless. */
        unsigned long chld_flags = task->parent->signal_handler_flags[SIGCHLD - 1];
        bool send_sigchld = !(chld_flags & SA_NOCLDSTOP);
        fut_waitq_wake_all(&task->parent->child_waiters);
        fut_spinlock_release(&task_list_lock);
        if (send_sigchld) {
            siginfo_t chld_info;
            __builtin_memset(&chld_info, 0, sizeof(chld_info));
            chld_info.si_signum = SIGCHLD;
            chld_info.si_code   = CLD_STOPPED;
            chld_info.si_pid    = task->pid;
            chld_info.si_uid    = task->uid;
            chld_info.si_status = sig;
            fut_signal_send_with_info(task->parent, SIGCHLD, &chld_info);
        }
    } else {
        fut_spinlock_release(&task_list_lock);
    }
    /* Block current thread until SIGCONT wakes the stop_waitq */
    fut_waitq_sleep_locked(&task->stop_waitq, NULL, FUT_THREAD_BLOCKED);
}

/**
 * fut_task_do_cont() - Resume a stopped task due to SIGCONT.
 * Wakes all threads sleeping on stop_waitq and notifies the parent
 * (for WCONTINUED).
 */
void fut_task_do_cont(fut_task_t *task) {
    if (!task) return;
    fut_task_t *parent = NULL;
    bool send_sigchld = false;
    fut_spinlock_acquire(&task_list_lock);
    if (task->state == FUT_TASK_STOPPED) {
        task->state = FUT_TASK_RUNNING;
        task->stop_signal = -1;  /* sentinel: just continued */
        task->stop_reported = 0;
        parent = task->parent;
        if (parent) {
            /* SA_NOCLDSTOP also suppresses SIGCHLD on continue */
            unsigned long chld_flags = parent->signal_handler_flags[SIGCHLD - 1];
            send_sigchld = !(chld_flags & SA_NOCLDSTOP);
            fut_waitq_wake_all(&parent->child_waiters);
        }
    }
    fut_spinlock_release(&task_list_lock);
    if (parent && send_sigchld) {
        siginfo_t chld_info;
        __builtin_memset(&chld_info, 0, sizeof(chld_info));
        chld_info.si_signum = SIGCHLD;
        chld_info.si_code   = CLD_CONTINUED;
        chld_info.si_pid    = task->pid;
        chld_info.si_uid    = task->uid;
        chld_info.si_status = SIGCONT;
        fut_signal_send_with_info(parent, SIGCHLD, &chld_info);
    }
    fut_waitq_wake_all(&task->stop_waitq);
}

int fut_task_waitpid(int pid, int *status_out, int flags, uint64_t *child_ticks_out) {
    fut_task_t *parent = fut_task_current();
    if (!parent) {
        return -ECHILD;
    }

    for (;;) {
        fut_spinlock_acquire(&task_list_lock);

        fut_task_t *child = parent->first_child;
        fut_task_t *match = NULL;
        bool has_matching_children = false;

        while (child) {
            bool matches = false;
            if (pid > 0) {
                /* Wait for specific child PID */
                matches = ((int)child->pid == pid);
            } else if (pid == -1) {
                /* Wait for any child */
                matches = true;
            } else if (pid == 0) {
                /* Wait for any child in same process group */
                matches = (child->pgid == parent->pgid);
            } else {
                /* pid < -1: Wait for any child in process group |pid| */
                matches = (child->pgid == (uint64_t)(-pid));
            }

            if (matches) {
                has_matching_children = true;
                if (child->state == FUT_TASK_ZOMBIE) {
                    match = child;
                    break;
                }
                /* WUNTRACED (0x2): report stopped children */
                if ((flags & 2) && child->state == FUT_TASK_STOPPED &&
                    !child->stop_reported) {
                    int stop_status = 0x7f | ((child->stop_signal & 0xff) << 8);
                    uint64_t child_pid = child->pid;
                    /* Mark as reported so we don't re-report until next stop */
                    child->stop_reported = 1;
                    fut_spinlock_release(&task_list_lock);
                    if (status_out) *status_out = stop_status;
                    return (int)child_pid;
                }
                /* WCONTINUED (0x8): report children continued with SIGCONT */
                if ((flags & 8) && child->stop_signal == -1) {
                    int cont_status = 0xffff;  /* WIFCONTINUED encoding */
                    uint64_t child_pid = child->pid;
                    child->stop_signal = 0;
                    fut_spinlock_release(&task_list_lock);
                    if (status_out) *status_out = cont_status;
                    return (int)child_pid;
                }
            }
            child = child->sibling;
        }

        if (!has_matching_children) {
            fut_spinlock_release(&task_list_lock);
            return -ECHILD;
        }

        if (match) {
            int status = encode_wait_status(match);
            uint64_t child_pid = match->pid;

            /* Accumulate child's CPU ticks into parent before reaping.
             * This provides tms_cutime data for sys_times(). */
            uint64_t child_ticks = 0;
            for (fut_thread_t *t = match->threads; t; t = t->next) {
                child_ticks += t->stats.cpu_ticks;
            }
            uint64_t total_child_ticks = child_ticks + match->child_cpu_ticks;
            parent->child_cpu_ticks += total_child_ticks;

            task_detach_child(parent, match);
            fut_spinlock_release(&task_list_lock);

            if (status_out) {
                *status_out = status;
            }
            if (child_ticks_out) {
                *child_ticks_out = total_child_ticks;
            }

            fut_task_destroy(match);
            return (int)child_pid;
        }

        /* WNOHANG: return 0 immediately if no child has exited */
        if (flags & 1) {  /* WNOHANG = 1 */
            fut_spinlock_release(&task_list_lock);
            return 0;
        }

        /* Check for pending unblocked signals → EINTR */
        {
            uint64_t pending = __atomic_load_n(&parent->pending_signals, __ATOMIC_ACQUIRE);
            fut_thread_t *wp_thr = fut_thread_current();
            uint64_t wp_mask = wp_thr ?
                __atomic_load_n(&wp_thr->signal_mask, __ATOMIC_ACQUIRE) :
                __atomic_load_n(&parent->signal_mask, __ATOMIC_ACQUIRE);
            if (pending & ~wp_mask) {
                fut_spinlock_release(&task_list_lock);
                return -EINTR;
            }
        }

        fut_waitq_sleep_locked(&parent->child_waiters, &task_list_lock, FUT_THREAD_BLOCKED);
    }
}

/**
 * Extended waitpid: like fut_task_waitpid but also returns the child's real
 * UID and supports WNOWAIT (peek without reaping).
 *
 * @param pid        Same semantics as fut_task_waitpid
 * @param status_out Receives encoded wait status
 * @param flags      WNOHANG (0x1) and/or WNOWAIT (0x01000000)
 * @param uid_out    If non-NULL, receives child's real UID (ruid)
 *
 * Returns child PID on success, 0 for WNOHANG/no-ready-child, or -ECHILD/-EINTR.
 */
int fut_task_waitpid_ex(int pid, int *status_out, int flags, uint32_t *uid_out) {
    fut_task_t *parent = fut_task_current();
    if (!parent) {
        return -ECHILD;
    }

    int peek = (flags & 0x01000000) ? 1 : 0;  /* WNOWAIT */
    int nohang = (flags & 1) ? 1 : 0;          /* WNOHANG */

    for (;;) {
        fut_spinlock_acquire(&task_list_lock);

        fut_task_t *child = parent->first_child;
        fut_task_t *match = NULL;
        bool has_matching_children = false;

        while (child) {
            bool matches = false;
            if (pid > 0) {
                matches = ((int)child->pid == pid);
            } else if (pid == -1) {
                matches = true;
            } else if (pid == 0) {
                matches = (child->pgid == parent->pgid);
            } else {
                matches = (child->pgid == (uint64_t)(-pid));
            }

            if (matches) {
                has_matching_children = true;
                if (child->state == FUT_TASK_ZOMBIE) {
                    match = child;
                    break;
                }
                /* WUNTRACED/WSTOPPED (0x2): report stopped children */
                if ((flags & 2) && child->state == FUT_TASK_STOPPED &&
                    !child->stop_reported) {
                    int stop_status = 0x7f | ((child->stop_signal & 0xff) << 8);
                    uint64_t child_pid = child->pid;
                    uint32_t child_uid = child->ruid;
                    child->stop_reported = 1;
                    fut_spinlock_release(&task_list_lock);
                    if (status_out) *status_out = stop_status;
                    if (uid_out)    *uid_out    = child_uid;
                    return (int)child_pid;
                }
                /* WCONTINUED (0x8): report continued children */
                if ((flags & 8) && child->stop_signal == -1) {
                    uint64_t child_pid = child->pid;
                    uint32_t child_uid = child->ruid;
                    child->stop_signal = 0;
                    fut_spinlock_release(&task_list_lock);
                    if (status_out) *status_out = 0xffff;
                    if (uid_out)    *uid_out    = child_uid;
                    return (int)child_pid;
                }
            }
            child = child->sibling;
        }

        if (!has_matching_children) {
            fut_spinlock_release(&task_list_lock);
            return -ECHILD;
        }

        if (match) {
            int status = encode_wait_status(match);
            uint64_t child_pid = match->pid;
            uint32_t child_uid = match->ruid;

            if (peek) {
                /* WNOWAIT: return child info without reaping */
                fut_spinlock_release(&task_list_lock);
                if (status_out) *status_out = status;
                if (uid_out)    *uid_out    = child_uid;
                return (int)child_pid;
            }

            /* Normal reap path */
            uint64_t child_ticks = 0;
            for (fut_thread_t *t = match->threads; t; t = t->next) {
                child_ticks += t->stats.cpu_ticks;
            }
            parent->child_cpu_ticks += child_ticks + match->child_cpu_ticks;

            task_detach_child(parent, match);
            fut_spinlock_release(&task_list_lock);

            if (status_out) *status_out = status;
            if (uid_out)    *uid_out    = child_uid;

            fut_task_destroy(match);
            return (int)child_pid;
        }

        if (nohang) {
            fut_spinlock_release(&task_list_lock);
            return 0;
        }

        /* Check for pending unblocked signals → EINTR */
        {
            uint64_t pending = __atomic_load_n(&parent->pending_signals, __ATOMIC_ACQUIRE);
            fut_thread_t *wp_thr = fut_thread_current();
            uint64_t wp_mask = wp_thr ?
                __atomic_load_n(&wp_thr->signal_mask, __ATOMIC_ACQUIRE) :
                __atomic_load_n(&parent->signal_mask, __ATOMIC_ACQUIRE);
            if (pending & ~wp_mask) {
                fut_spinlock_release(&task_list_lock);
                return -EINTR;
            }
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
 * fut_task_foreach_all - Iterate all non-zombie tasks except init and one excluded PID.
 *
 * Used by kill(pid=-1) to broadcast signals to all eligible processes.
 * Skips: zombie tasks, init (pid 1), and the task identified by exclude_pid.
 *
 * @param exclude_pid  PID to exclude (typically the caller's PID)
 * @param callback     Function called for each matching task (may be NULL for count-only)
 * @param data         Opaque pointer forwarded to callback
 * @return Number of tasks visited (regardless of whether callback was supplied)
 */
int fut_task_foreach_all(uint64_t exclude_pid,
                         void (*callback)(fut_task_t *task, void *data),
                         void *data) {
    int count = 0;
    fut_spinlock_acquire(&task_list_lock);
    fut_task_t *task = fut_task_list;
    while (task) {
        if (task->pid != 1 &&
            task->pid != exclude_pid &&
            task->state != FUT_TASK_ZOMBIE) {
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
