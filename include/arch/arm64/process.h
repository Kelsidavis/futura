/* process.h - ARM64 Process and Thread Management
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * ARM64 (AArch64) process creation, thread spawning, and task management.
 */

#pragma once

#include <arch/arm64/regs.h>
#include <arch/arm64/paging.h>
#include <arch/arm64/context.h>
#include <stdint.h>
#include <stdbool.h>

/* ============================================================
 *   Process/Thread Structure
 * ============================================================ */

/**
 * ARM64 thread/task structure.
 * Represents a single execution context (thread or process).
 */
typedef struct fut_thread {
    /* Basic identification */
    uint32_t tid;                   /* Thread ID */
    uint32_t pid;                   /* Process ID */
    uint8_t state;                  /* Thread state (READY, RUNNING, BLOCKED, etc.) */
    uint8_t priority;               /* Thread priority (0=highest, 255=lowest) */

    /* CPU context */
    fut_cpu_context_t context;      /* Saved CPU context for context switches */
    fut_interrupt_frame_t *int_frame; /* Interrupt frame if preempted */

    /* Memory management */
    fut_vmem_context_t *vmem;       /* Virtual memory context (page tables) */
    void *kernel_stack;             /* Kernel stack for this thread */
    uint64_t kernel_stack_size;     /* Kernel stack size */
    void *user_stack;               /* User stack (if user thread) */
    uint64_t user_stack_size;       /* User stack size */

    /* Scheduling */
    uint32_t timeslice;             /* Time slice remaining (ms) */
    uint32_t total_runtime;         /* Total runtime in ms */
    uint32_t wake_time;             /* Time to wake from sleep (0 if not sleeping) */

    /* Thread linking */
    struct fut_thread *next;        /* Next thread in scheduler queue */
    struct fut_thread *prev;        /* Previous thread in scheduler queue */

    /* Flags */
    uint8_t flags;                  /* Thread flags (KERNEL_THREAD, etc.) */
} fut_thread_t;

/* Thread states */
#define FUT_THREAD_READY        0x01
#define FUT_THREAD_RUNNING      0x02
#define FUT_THREAD_BLOCKED      0x03
#define FUT_THREAD_SLEEPING     0x04
#define FUT_THREAD_STOPPED      0x05
#define FUT_THREAD_TERMINATED   0x06

/* Thread flags */
#define FUT_THREAD_KERNEL       0x01  /* Kernel thread (no user mode) */
#define FUT_THREAD_PINNED       0x02  /* Pinned to specific CPU */
#define FUT_THREAD_NEEDS_FPU    0x04  /* Needs FPU context save/restore */

/* ============================================================
 *   Process Structure
 * ============================================================ */

/**
 * Process/task structure.
 * Represents a process with its own address space and threads.
 */
typedef struct fut_process {
    uint32_t pid;                   /* Process ID */
    uint32_t ppid;                  /* Parent process ID */
    uint8_t state;                  /* Process state */

    /* Memory management */
    fut_mm_t *mm;                   /* Memory management context (shared with threads) */
    void *entry_point;              /* Process entry point */

    /* Thread management */
    fut_thread_t *main_thread;      /* Main/first thread */
    fut_thread_t *threads;          /* List of all threads in this process */
    uint32_t num_threads;           /* Number of threads */

    /* Scheduling */
    uint32_t total_runtime;         /* Total runtime across all threads */

    /* Process linking */
    struct fut_process *next;       /* Next process */
    struct fut_process *prev;       /* Previous process */
} fut_process_t;

/* Process states */
#define FUT_PROCESS_CREATED     0x01
#define FUT_PROCESS_RUNNING     0x02
#define FUT_PROCESS_STOPPED     0x03
#define FUT_PROCESS_TERMINATED  0x04

/* ============================================================
 *   Thread Creation and Management
 * ============================================================ */

/**
 * Create a new kernel thread.
 * Creates a thread that runs in kernel space only.
 * @param entry Entry point function
 * @param arg Argument to pass to entry point
 * @param priority Thread priority
 * @param name Thread name (for debugging)
 * @return Pointer to new thread, or NULL on failure
 */
fut_thread_t *fut_thread_create_kernel(void (*entry)(void *), void *arg,
                                       uint8_t priority, const char *name);

/**
 * Create a new user-space thread.
 * Creates a thread that runs in both user and kernel space.
 * @param process Parent process
 * @param entry User-space entry point
 * @param arg Argument to pass to entry point
 * @param priority Thread priority
 * @return Pointer to new thread, or NULL on failure
 */
fut_thread_t *fut_thread_create_user(fut_process_t *process, void (*entry)(void *),
                                     void *arg, uint8_t priority);

/**
 * Terminate a thread.
 * @param thread Thread to terminate
 */
void fut_thread_terminate(fut_thread_t *thread);

/**
 * Get current thread.
 * @return Pointer to current thread
 */
fut_thread_t *fut_thread_current(void);

/**
 * Yield to scheduler (request context switch).
 */
void fut_thread_yield(void);

/**
 * Set thread priority.
 * @param thread Thread to modify
 * @param priority New priority (0=highest, 255=lowest)
 */
void fut_thread_set_priority(fut_thread_t *thread, uint8_t priority);

/**
 * Sleep thread for specified time.
 * @param milliseconds Time to sleep
 */
void fut_thread_sleep(uint32_t milliseconds);

/**
 * Wake thread from sleep.
 * @param thread Thread to wake
 */
void fut_thread_wake(fut_thread_t *thread);

/**
 * Get thread ID.
 * @param thread Thread (NULL = current)
 * @return Thread ID
 */
uint32_t fut_thread_get_id(fut_thread_t *thread);

/**
 * Get process ID.
 * @param thread Thread (NULL = current)
 * @return Process ID
 */
uint32_t fut_thread_get_pid(fut_thread_t *thread);

/* ============================================================
 *   Process Creation and Management
 * ============================================================ */

/**
 * Create a new process.
 * Creates a process with its own address space and first thread.
 * @param entry User-space entry point
 * @param arg Argument to pass
 * @param name Process name (for debugging)
 * @return Pointer to new process, or NULL on failure
 */
fut_process_t *fut_process_create(void (*entry)(void *), void *arg, const char *name);

/**
 * Terminate a process and all its threads.
 * @param process Process to terminate
 */
void fut_process_terminate(fut_process_t *process);

/**
 * Get current process.
 * @return Pointer to current process
 */
fut_process_t *fut_process_current(void);

/**
 * Get process by ID.
 * @param pid Process ID to find
 * @return Pointer to process, or NULL if not found
 */
fut_process_t *fut_process_get(uint32_t pid);

/**
 * Get process ID.
 * @param process Process (NULL = current)
 * @return Process ID
 */
uint32_t fut_process_get_id(fut_process_t *process);

/**
 * Get parent process ID.
 * @param process Process (NULL = current)
 * @return Parent process ID
 */
uint32_t fut_process_get_ppid(fut_process_t *process);

/* ============================================================
 *   Scheduler
 * ============================================================ */

/**
 * Initialize scheduler.
 * Sets up the thread scheduler and creates idle thread.
 */
void fut_scheduler_init(void);

/**
 * Get next thread to run.
 * Called by timer interrupt or when current thread yields.
 * @return Next thread to run
 */
fut_thread_t *fut_scheduler_next(void);

/**
 * Add thread to ready queue.
 * @param thread Thread to add
 */
void fut_scheduler_enqueue(fut_thread_t *thread);

/**
 * Remove thread from ready queue.
 * @param thread Thread to remove
 */
void fut_scheduler_dequeue(fut_thread_t *thread);

/**
 * Update thread state.
 * @param thread Thread to update
 * @param new_state New thread state
 */
void fut_scheduler_set_state(fut_thread_t *thread, uint8_t new_state);

/**
 * Check if rescheduling is needed.
 * @return true if current thread should be preempted
 */
bool fut_scheduler_should_preempt(void);

/**
 * Run scheduler (perform context switch if needed).
 * Called at end of timer interrupt.
 * @param frame Current interrupt frame (for preemption)
 */
void fut_scheduler_run(fut_interrupt_frame_t *frame);

/* ============================================================
 *   Exit Handling
 * ============================================================ */

/**
 * Exit current thread.
 * @param exit_code Exit code
 */
void fut_thread_exit(int exit_code) __attribute__((noreturn));

/**
 * Exit current process.
 * Terminates all threads and frees process resources.
 * @param exit_code Exit code
 */
void fut_process_exit(int exit_code) __attribute__((noreturn));

/* ============================================================
 *   Stack Setup Helpers
 * ============================================================ */

/**
 * Set up user-space stack and call entry point.
 * Used as a trampoline to properly initialize user-space execution.
 * @param entry User entry point
 * @param arg Argument to pass
 */
void fut_user_entry_trampoline(void (*entry)(void *), void *arg)
    __attribute__((noreturn));

/**
 * Set up kernel-space stack and call entry point.
 * Used as a trampoline to properly initialize kernel thread execution.
 * @param entry Kernel entry point
 * @param arg Argument to pass
 */
void fut_kernel_entry_trampoline(void (*entry)(void *), void *arg)
    __attribute__((noreturn));
