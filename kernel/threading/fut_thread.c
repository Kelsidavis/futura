/* fut_thread.c - Futura OS Thread Implementation (C23)
 *
 * Copyright (c) 2025 Kelsi Davis / Licensed under the MPL v2.0 — see LICENSE for details
 *
 * Thread creation, lifecycle management, and synchronization primitives.
 */

#include "../../include/kernel/fut_thread.h"
#include "../../include/kernel/fut_task.h"
#include "../../include/kernel/fut_sched.h"
#include "../../include/kernel/fut_memory.h"
#include <stdatomic.h>

/* External declarations */
extern void fut_printf(const char *fmt, ...);
extern void fut_sleep_until(fut_thread_t *thread, uint64_t wake_time);
extern void fut_thread_entry_stub(void);  /* Assembly stub in fut_thread_entry.S */

/* Thread ID counter */
static _Atomic uint32_t next_tid = 1;

/* Global thread list (for stats/debugging) */
fut_thread_t *fut_thread_list = nullptr;

/* ============================================================
 *   Thread Creation
 * ============================================================ */

/**
 * Create a new thread within a task.
 */
fut_thread_t *fut_thread_create(
    fut_task_t *task,
    void (*entry)(void *),
    void *arg,
    size_t stack_size,
    int priority
) {
    if (!task || !entry || stack_size == 0) {
        return nullptr;
    }

    // Clamp priority
    if (priority < 0) priority = 0;
    if (priority >= FUT_MAX_PRIORITY) priority = FUT_MAX_PRIORITY - 1;

    // Allocate thread structure
    auto thread = (fut_thread_t *)kmalloc(sizeof(fut_thread_t));
    if (!thread) {
        return nullptr;
    }

    // Allocate stack (page-aligned)
    size_t aligned_stack_size = FUT_PAGE_ALIGN(stack_size);
    void *stack = kmalloc(aligned_stack_size);
    if (!stack) {
        kfree(thread);
        return nullptr;
    }

    // Place guard canary at bottom of stack (lowest address)
    // This helps detect stack overflow during debugging
    *(uint32_t *)stack = 0xCAFECAFE;  // FUT_STACK_CANARY

    // Initialize thread structure
    *thread = (fut_thread_t){
        .tid = atomic_fetch_add_explicit(&next_tid, 1, memory_order_seq_cst),
        .task = task,
        .stack_base = stack,
        .stack_size = aligned_stack_size,
        .irq_frame = nullptr,  // No saved interrupt frame initially
        .state = FUT_THREAD_READY,
        .priority = priority,
        .wake_time = 0,
        .stats = {0},  // Initialize performance counters to zero
        .next = nullptr,
        .prev = nullptr
    };

    // Setup initial stack frame
    uintptr_t sp = (uintptr_t)stack + aligned_stack_size;

    // Align to 16 bytes (x86 ABI requirement)
    sp &= ~0xFUL;

    // Push argument and entry function for wrapper (IRET will jump to wrapper, no return address needed)
    sp -= sizeof(void *);
    *(void **)sp = arg;           // sp[1] when wrapper starts

    sp -= sizeof(void *);
    *(void **)sp = (void *)entry; // sp[0] when wrapper starts

    // Save the desired ESP for when thread starts running
    // After IRET, ESP will point here (at entry function pointer)
    uintptr_t thread_start_esp = sp;

    // Initialize context to start at assembly stub (used for regular context switch)
    thread->context.esp = (uint32_t)sp;
    thread->context.eip = (uint32_t)fut_thread_entry_stub;
    thread->context.ebp = 0;
    thread->context.ebx = 0;
    thread->context.esi = 0;
    thread->context.edi = 0;
    thread->context.eflags = 0x202;  // IF (interrupts enabled) + reserved bit

    // Build pre-initialized interrupt frame ON THE STACK
    // After IRET in ring 0, ESP will be: frame_ptr + 60 bytes
    // So we position the frame such that after IRET, ESP = thread_start_esp
    //
    // NOTE: We calculate the frame position to ensure proper ESP restoration.
    // After POP GS/FS/ES/DS (16 bytes) + POPA (32 bytes) + IRET (12 bytes) = 60 bytes,
    // ESP will be at frame_ptr + 60. We want this to equal thread_start_esp.
    // thread_start_esp now points to: sp[0]=entry, sp[1]=arg (no return address)
    sp = thread_start_esp - 60;

    // Verify frame is within stack bounds
    if (sp < (uintptr_t)stack || sp >= (uintptr_t)stack + aligned_stack_size) {
        extern void serial_puts(const char *s);
        serial_puts("[THREAD] ERROR: IRQ frame outside stack bounds\n");
        kfree(stack);
        kfree(thread);
        return nullptr;
    }

    // Now build the frame structure at this location
    fut_interrupt_frame_t *frame = (fut_interrupt_frame_t *)sp;

    // CPU-pushed values (will be popped by IRET)
    frame->eip = thread->context.eip;
    frame->cs = 0x10;  // Actual kernel code segment (CS=0x10)
    frame->eflags = 0x202;  // IF (bit 9) + reserved bit 1 - match running context

    // Ring 0 → Ring 0 IRET: CPU does NOT pop/push ESP and SS
    // These fields exist in the struct but are NOT on the stack for ring 0 transitions
    // CRITICAL: Do NOT write these - they overlap with entry/arg at thread_start_esp!
    // frame->user_esp is at (sp + 60) = thread_start_esp (where entry is stored)
    // frame->ss is at (sp + 64) = thread_start_esp + 4 (where arg is stored)
    // Writing to these would overwrite entry/arg with zeros!
    // frame->user_esp = 0;  // REMOVED: Would overwrite entry pointer!
    // frame->ss = 0;        // REMOVED: Would overwrite arg pointer!

    // Segment registers (will be popped by POP instructions)
    frame->ds = 0x18;  // Actual kernel data segment (DS=0x18)
    frame->es = 0x18;
    frame->fs = 0x18;
    frame->gs = 0x18;

    // General-purpose registers (will be restored by POPA)
    frame->edi = thread->context.edi;
    frame->esi = thread->context.esi;
    frame->ebp = thread->context.ebp;
    frame->esp_dummy = 0;  // Not used by POPA (it skips this field)
    frame->ebx = thread->context.ebx;
    frame->edx = 0;  // Caller-saved, starts at zero
    frame->ecx = 0;  // Caller-saved, starts at zero
    frame->eax = 0;  // Caller-saved, starts at zero

    // Store frame pointer in thread structure
    thread->irq_frame = frame;

    // Add to parent task
    fut_task_add_thread(task, thread);

    // Add to scheduler ready queue
    fut_sched_add_thread(thread);

    return thread;
}

/* ============================================================
 *   Thread Lifecycle
 * ============================================================ */

/**
 * Voluntarily yield CPU to another thread.
 */
void fut_thread_yield(void) {
    fut_schedule();
}

/**
 * Exit current thread (does not return).
 */
[[noreturn]] void fut_thread_exit(void) {
    fut_thread_t *self = fut_thread_current();
    if (!self) {
        for (;;);  // Should never happen
    }

    // Mark as terminated
    self->state = FUT_THREAD_TERMINATED;

    // Remove from scheduler
    fut_sched_remove_thread(self);

    // Remove from parent task
    fut_task_remove_thread(self->task, self);

    // Schedule next thread (this never returns)
    fut_schedule();

    // Should never reach here
    for (;;);
}

/**
 * Sleep for specified milliseconds.
 */
void fut_thread_sleep(uint64_t millis) {
    if (millis == 0) {
        fut_thread_yield();
        return;
    }

    fut_thread_t *self = fut_thread_current();
    if (!self) {
        return;
    }

    // Let timer subsystem handle sleep
    fut_sleep_until(self, millis);

    // This will context switch to another thread
    fut_schedule();
}
