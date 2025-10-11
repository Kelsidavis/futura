/* kernel_main.c - Futura OS Kernel Main Entry Point
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * This is the main kernel initialization sequence.
 * Called from platform_init after platform-specific setup is complete.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <kernel/fut_memory.h>
#include <kernel/fut_sched.h>
#include <kernel/fut_thread.h>
#include <kernel/fut_task.h>
#include <kernel/fut_fipc.h>
#include <platform/platform.h>

/* ============================================================
 *   External Symbols from Linker Script
 * ============================================================ */

/* Kernel memory layout symbols from link.ld */
extern char _kernel_end[];
extern char _bss_start[];
extern char _bss_end[];

/* ============================================================
 *   Configuration Constants
 * ============================================================ */

/* Memory configuration - for now assume 128MB available in QEMU */
#define TOTAL_MEMORY_SIZE       (128 * 1024 * 1024)  /* 128 MiB */
#define KERNEL_HEAP_SIZE        (4 * 1024 * 1024)    /* 4 MiB heap (must fit in 8MB mapped by boot.S) */

/* ============================================================
 *   Test Thread Functions
 * ============================================================ */

/**
 * Test thread entry point - demonstrates scheduler is working.
 */
static void test_thread_entry(void *arg) {
    uint64_t thread_id = (uint64_t)arg;

    fut_printf("[TEST-THREAD-%llu] Hello from test thread!\n", thread_id);

    /* Thread runs for a few iterations then exits */
    for (int i = 0; i < 5; i++) {
        fut_printf("[TEST-THREAD-%llu] Iteration %d\n", thread_id, i);
        fut_thread_yield();  /* Yield to other threads */
    }

    fut_printf("[TEST-THREAD-%llu] Exiting...\n", thread_id);
    fut_thread_exit();  /* This should never return */
}

/* ============================================================
 *   Kernel Main Entry Point
 * ============================================================ */

/**
 * Main kernel initialization and startup.
 * Called from platform_init after platform-specific initialization.
 *
 * This function:
 * 1. Initializes kernel subsystems (memory, scheduler, IPC)
 * 2. Creates initial test threads
 * 3. Starts scheduling (never returns)
 */
void fut_kernel_main(void) {
    fut_printf("\n");
    fut_printf("=======================================================\n");
    fut_printf("   Futura OS Nanokernel Initialization\n");
    fut_printf("=======================================================\n\n");

    /* ========================================
     *   Step 1: Initialize Memory Subsystem
     * ======================================== */

    fut_printf("[INIT] Initializing physical memory manager...\n");

    /* Calculate memory base (starts after kernel) - use VIRTUAL address */
    /* In a higher-half kernel, all memory accesses must use virtual addresses */
    uintptr_t kernel_virt_end = (uintptr_t)_kernel_end;
    uintptr_t mem_base = (kernel_virt_end + 0xFFF) & ~0xFFFULL;  /* Page-align */

    /* Initialize PMM with total available memory */
    fut_pmm_init(TOTAL_MEMORY_SIZE, mem_base);

    fut_printf("[INIT] PMM initialized: %llu pages total, %llu pages free\n",
               fut_pmm_total_pages(), fut_pmm_free_pages());

    /* Initialize kernel heap */
    fut_printf("[INIT] Initializing kernel heap...\n");

    /* Heap region in virtual memory (after kernel end) */
    uintptr_t heap_start = (uintptr_t)_kernel_end;
    heap_start = (heap_start + 0xFFF) & ~0xFFFULL;  /* Page-align */
    uintptr_t heap_end = heap_start + KERNEL_HEAP_SIZE;

    /* Debug: print heap addresses before initialization */
    fut_printf("[DEBUG] _kernel_end address: 0x\n");
    fut_printf("[DEBUG] heap_start: 0x\n");
    fut_printf("[DEBUG] heap_end: 0x\n");
    fut_printf("[DEBUG] heap_size: \n");

    /* Test: Try writing to heap memory directly */
    fut_printf("[DEBUG] Testing heap memory write...\n");
    volatile uint64_t *test_ptr = (volatile uint64_t *)heap_start;
    *test_ptr = 0xDEADBEEFCAFEBABE;
    fut_printf("[DEBUG] Write test successful! Value: \n");

    fut_heap_init(heap_start, heap_end);

    fut_printf("[INIT] Heap initialized: 0x%llx - 0x%llx (%llu MiB)\n",
               heap_start, heap_end, KERNEL_HEAP_SIZE / (1024 * 1024));

    /* ========================================
     *   Step 2: Initialize FIPC Subsystem
     * ======================================== */

    fut_printf("[INIT] Initializing FIPC (Futura Inter-Process Communication)...\n");
    fut_fipc_init();
    fut_printf("[INIT] FIPC initialized\n");

    /* ========================================
     *   Step 3: Initialize Scheduler
     * ======================================== */

    fut_printf("[INIT] Initializing scheduler...\n");
    fut_sched_init();
    fut_printf("[INIT] Scheduler initialized with idle thread\n");

    /* ========================================
     *   Step 4: Create Test Threads
     * ======================================== */

    fut_printf("[INIT] Creating test task and threads...\n");

    /* Create a test task (process container) */
    fut_task_t *test_task = fut_task_create();
    if (!test_task) {
        fut_printf("[ERROR] Failed to create test task!\n");
        fut_platform_panic("Failed to create test task");
    }

    fut_printf("[INIT] Test task created (PID %llu)\n", test_task->pid);

    /* Create first test thread */
    fut_thread_t *thread1 = fut_thread_create(
        test_task,
        test_thread_entry,
        (void *)1,              /* Thread ID = 1 */
        16 * 1024,              /* 16 KB stack */
        128                     /* Normal priority */
    );

    if (!thread1) {
        fut_printf("[ERROR] Failed to create test thread 1!\n");
        fut_platform_panic("Failed to create test thread");
    }

    fut_printf("[INIT] Test thread 1 created (TID %llu)\n", thread1->tid);

    /* Create second test thread */
    fut_thread_t *thread2 = fut_thread_create(
        test_task,
        test_thread_entry,
        (void *)2,              /* Thread ID = 2 */
        16 * 1024,              /* 16 KB stack */
        128                     /* Normal priority */
    );

    if (!thread2) {
        fut_printf("[ERROR] Failed to create test thread 2!\n");
        fut_platform_panic("Failed to create test thread");
    }

    fut_printf("[INIT] Test thread 2 created (TID %llu)\n", thread2->tid);

    /* ========================================
     *   Step 5: Start Scheduling
     * ======================================== */

    fut_printf("\n");
    fut_printf("=======================================================\n");
    fut_printf("   Kernel initialization complete!\n");
    fut_printf("   Starting scheduler...\n");
    fut_printf("=======================================================\n\n");

    /* Enable interrupts and start scheduling */
    /* This should never return - scheduler takes over */
    fut_schedule();

    /* Should never reach here */
    fut_printf("[PANIC] Scheduler returned unexpectedly!\n");
    fut_platform_panic("Scheduler returned to kernel_main");
}
