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
#include <kernel/fut_vfs.h>
#include <kernel/fut_ramfs.h>
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

/* Global FIPC channel for testing */
static struct fut_fipc_channel *g_test_channel = NULL;

/**
 * FIPC sender thread - sends test messages.
 */
static void fipc_sender_thread(void *arg) {
    (void)arg;
    fut_printf("[FIPC-SENDER] Starting sender thread\n");

    /* Wait a bit for receiver to be ready */
    fut_thread_yield();

    /* Send test messages */
    for (int i = 0; i < 3; i++) {
        char msg[64];
        fut_printf("[FIPC-SENDER] Sending message %d\n", i);

        /* Build message payload */
        msg[0] = 'M';
        msg[1] = 'S';
        msg[2] = 'G';
        msg[3] = '0' + i;
        msg[4] = '\0';

        /* Send through FIPC channel */
        int ret = fut_fipc_send(g_test_channel, FIPC_MSG_USER_BASE, msg, 5);
        if (ret < 0) {
            fut_printf("[FIPC-SENDER] Send failed with error %d\n", ret);
        }

        fut_thread_yield();
    }

    fut_printf("[FIPC-SENDER] All messages sent, exiting\n");
    fut_thread_exit();
}

/**
 * FIPC receiver thread - receives and processes messages.
 */
static void fipc_receiver_thread(void *arg) {
    (void)arg;
    fut_printf("[FIPC-RECEIVER] Starting receiver thread\n");

    /* Receive messages */
    for (int i = 0; i < 3; i++) {
        fut_printf("[FIPC-RECEIVER] Waiting for message %d...\n", i);

        /* Allocate buffer for message (header + payload) */
        uint8_t buf[128];

        /* Poll until message arrives */
        while (fut_fipc_poll(g_test_channel, FIPC_EVENT_MESSAGE) == 0) {
            fut_thread_yield();
        }

        /* Receive message */
        ssize_t received = fut_fipc_recv(g_test_channel, buf, sizeof(buf));
        if (received < 0) {
            fut_printf("[FIPC-RECEIVER] Receive failed with error %lld\n", (long long)received);
            continue;
        }

        /* Parse message */
        struct fut_fipc_msg *msg = (struct fut_fipc_msg *)buf;
        char *payload = (char *)msg->payload;

        fut_printf("[FIPC-RECEIVER] Received message: type=0x%x, len=%u, payload='%s'\n",
                   msg->type, msg->length, payload);

        fut_thread_yield();
    }

    fut_printf("[FIPC-RECEIVER] All messages received, exiting\n");
    fut_thread_exit();
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
     *   Step 3: Initialize VFS and Root Filesystem
     * ======================================== */

    fut_printf("[INIT] Initializing VFS (Virtual Filesystem)...\n");
    fut_vfs_init();

    /* Register ramfs filesystem type */
    fut_ramfs_init();
    fut_printf("[INIT] Registered ramfs filesystem\n");

    /* Mount ramfs as root filesystem */
    int vfs_ret = fut_vfs_mount(NULL, "/", "ramfs", 0, NULL);
    if (vfs_ret < 0) {
        fut_printf("[ERROR] Failed to mount root filesystem (error %d)\n", vfs_ret);
        fut_platform_panic("Failed to mount root filesystem");
    }

    fut_printf("[INIT] Root filesystem mounted (ramfs at /)\n");

    /* ========================================
     *   Step 4: Initialize Scheduler
     * ======================================== */

    fut_printf("[INIT] Initializing scheduler...\n");
    fut_sched_init();
    fut_printf("[INIT] Scheduler initialized with idle thread\n");

    /* ========================================
     *   Step 5: Create Test Task and FIPC Channel
     * ======================================== */

    fut_printf("[INIT] Creating test task for FIPC demonstration...\n");

    /* Create a test task (process container) */
    fut_task_t *test_task = fut_task_create();
    if (!test_task) {
        fut_printf("[ERROR] Failed to create test task!\n");
        fut_platform_panic("Failed to create test task");
    }

    fut_printf("[INIT] Test task created (PID %llu)\n", test_task->pid);

    /* Create FIPC channel for inter-thread communication */
    fut_printf("[INIT] Creating FIPC test channel...\n");
    int ret = fut_fipc_channel_create(
        test_task,              /* Sender task */
        test_task,              /* Receiver task (same task, different threads) */
        4096,                   /* 4KB message queue */
        FIPC_CHANNEL_NONBLOCKING,  /* Non-blocking mode */
        &g_test_channel
    );

    if (ret != 0) {
        fut_printf("[ERROR] Failed to create FIPC channel (error %d)\n", ret);
        fut_platform_panic("Failed to create FIPC channel");
    }

    fut_printf("[INIT] FIPC channel created (ID %llu)\n", g_test_channel->id);

    /* ========================================
     *   Step 6: Create FIPC Test Threads
     * ======================================== */

    fut_printf("[INIT] Creating FIPC test threads...\n");

    /* Create sender thread */
    fut_thread_t *sender_thread = fut_thread_create(
        test_task,
        fipc_sender_thread,
        NULL,                   /* No argument needed */
        16 * 1024,              /* 16 KB stack */
        128                     /* Normal priority */
    );

    if (!sender_thread) {
        fut_printf("[ERROR] Failed to create sender thread!\n");
        fut_platform_panic("Failed to create sender thread");
    }

    fut_printf("[INIT] FIPC sender thread created (TID %llu)\n", sender_thread->tid);

    /* Create receiver thread */
    fut_thread_t *receiver_thread = fut_thread_create(
        test_task,
        fipc_receiver_thread,
        NULL,                   /* No argument needed */
        16 * 1024,              /* 16 KB stack */
        128                     /* Normal priority */
    );

    if (!receiver_thread) {
        fut_printf("[ERROR] Failed to create receiver thread!\n");
        fut_platform_panic("Failed to create receiver thread");
    }

    fut_printf("[INIT] FIPC receiver thread created (TID %llu)\n", receiver_thread->tid);

    /* ========================================
     *   Step 7: Start Scheduling
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
