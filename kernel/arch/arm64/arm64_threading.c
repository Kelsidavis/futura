/* arm64_threading.c - Minimal ARM64 Threading Support
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Provides minimal threading infrastructure for ARM64 to support fork/exec.
 */

#include <kernel/fut_thread.h>
#include <kernel/fut_task.h>
#include <kernel/fut_percpu.h>
#include <kernel/fut_memory.h>
#include <string.h>

/* Simple current thread tracking for single-CPU ARM64 */
static fut_thread_t *arm64_boot_thread = NULL;

/* Static storage for fork testing (avoids need for heap) */
#define MAX_STATIC_TASKS 12
#define STATIC_STACK_SIZE (8192)  /* 8KB per thread */
static fut_task_t static_tasks[MAX_STATIC_TASKS] __attribute__((aligned(16)));
static fut_thread_t static_threads[MAX_STATIC_TASKS] __attribute__((aligned(16)));
static void *static_fd_tables[MAX_STATIC_TASKS][FUT_FD_TABLE_INITIAL_SIZE] __attribute__((aligned(16)));  /* FD tables for each task */
static uint8_t static_stacks[MAX_STATIC_TASKS][STATIC_STACK_SIZE] __attribute__((aligned(16)));  /* Thread stacks */
static uint8_t static_heap[16384] __attribute__((aligned(16)));  /* 16KB for misc allocations */
static size_t static_heap_used = 0;
static int next_static_task = 1;  /* 0 is boot task */
static int next_static_stack = 0;  /* Track stack allocations separately */

/* Use external fut_percpu_init from kernel/percpu/fut_percpu.c */
extern void fut_percpu_init(uint32_t cpu_id, uint32_t cpu_index);

/* External declarations */
extern void fut_serial_puts(const char *str);

/**
 * Create a minimal boot thread so fork() has a context.
 * NOTE: per-CPU data must be initialized BEFORE calling this function!
 */
void arm64_init_boot_thread(void) {
    /* Verify per-CPU is accessible (should already be initialized) */
    fut_percpu_t *percpu = fut_percpu_get();
    if (!percpu) {
        fut_serial_puts("[ARM64_THREAD] ERROR: fut_percpu_get() returned NULL\n");
        return;
    }

    /* Allocate minimal task structure directly (avoid fut_task_create complexity) */
    static fut_task_t boot_task_storage;
    fut_task_t *boot_task = &boot_task_storage;
    memset(boot_task, 0, sizeof(fut_task_t));
    boot_task->pid = 1;  /* Boot process is PID 1 */
    boot_task->state = FUT_TASK_RUNNING;

    /* Initialize FD table - allocate FD slots (matches fut_task_create pattern) */
    boot_task->max_fds = FUT_FD_TABLE_INITIAL_SIZE;
    boot_task->fd_table = (struct fut_file **)fut_malloc(FUT_FD_TABLE_INITIAL_SIZE * sizeof(struct fut_file *));
    if (!boot_task->fd_table) {
        fut_serial_puts("[ARM64_THREAD] ERROR: failed to allocate FD table for boot task\n");
        return;
    }
    /* Zero out FD table entries */
    for (int i = 0; i < FUT_FD_TABLE_INITIAL_SIZE; i++) {
        boot_task->fd_table[i] = NULL;
    }
    boot_task->next_fd = 0;

    /* Allocate minimal thread structure directly */
    static fut_thread_t boot_thread_storage;
    static uint8_t boot_stack[8192] __attribute__((aligned(16)));  /* 8KB boot stack */
    arm64_boot_thread = &boot_thread_storage;
    memset(arm64_boot_thread, 0, sizeof(fut_thread_t));
    arm64_boot_thread->tid = 1;
    arm64_boot_thread->task = boot_task;
    arm64_boot_thread->state = FUT_THREAD_RUNNING;
    arm64_boot_thread->priority = 128;
    arm64_boot_thread->stack_base = boot_stack;
    arm64_boot_thread->stack_size = sizeof(boot_stack);

    /* Link thread to task */
    boot_task->threads = arm64_boot_thread;
    boot_task->thread_count = 1;

    /* Set as current thread in per-CPU data */
    percpu->current_thread = arm64_boot_thread;

    /* Mark per-CPU as safe to access */
    extern void fut_thread_mark_percpu_safe(void);
    fut_thread_mark_percpu_safe();

    fut_serial_puts("[ARM64_THREAD] Boot thread initialized successfully\n");
}

/**
 * Simple malloc replacement for ARM64 testing (uses static storage).
 * Returns pre-allocated task/thread structures to avoid need for heap.
 */
void *arm64_static_malloc(size_t size) {
    /* Check if this is a task allocation */
    if (size == sizeof(fut_task_t)) {
        if (next_static_task < MAX_STATIC_TASKS) {
            return &static_tasks[next_static_task];
        }
        fut_serial_puts("[ARM64_MALLOC] Out of static tasks\n");
        return NULL;
    }

    /* Check if this is a thread allocation (may include extra for alignment) */
    if (size >= sizeof(fut_thread_t) && size <= sizeof(fut_thread_t) + 32) {
        if (next_static_task < MAX_STATIC_TASKS) {
            void *thread = &static_threads[next_static_task];
            next_static_task++;  /* Increment after thread alloc (task+thread pair) */
            return thread;
        }
        fut_serial_puts("[ARM64_MALLOC] Out of static threads\n");
        return NULL;
    }

    /* Check if this is an FD table allocation (FUT_FD_TABLE_INITIAL_SIZE * 8 = 512 bytes) */
    if (size == (FUT_FD_TABLE_INITIAL_SIZE * sizeof(void*))) {
        if (next_static_task > 0 && next_static_task <= MAX_STATIC_TASKS) {
            return static_fd_tables[next_static_task - 1];
        }
    }

    /* Check if this is a stack allocation (typically 4KB-16KB) */
    if (size >= 4096 && size <= STATIC_STACK_SIZE) {
        if (next_static_stack < MAX_STATIC_TASKS) {
            void *stack = &static_stacks[next_static_stack][0];
            next_static_stack++;
            return stack;
        }
        fut_serial_puts("[ARM64_MALLOC] Out of static stacks\n");
        return NULL;
    }

    /* For small misc allocations, use static heap */
    if (size <= sizeof(static_heap) - static_heap_used) {
        void *ptr = &static_heap[static_heap_used];
        static_heap_used += (size + 15) & ~15;  /* 16-byte align */
        return ptr;
    }

    /* Can't satisfy this allocation */
    fut_serial_puts("[ARM64_MALLOC] Failed allocation size=");
    return NULL;
}
