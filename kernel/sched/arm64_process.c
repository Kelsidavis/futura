/* arm64_process.c - ARM64 Process and Thread Management
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * ARM64 process/thread creation, scheduling, and execution.
 */

#include <platform/arm64/process.h>
#include <kernel/fut_mm.h>
#include <string.h>
#include <stdatomic.h>

/* ============================================================
 *   Global Scheduler State
 * ============================================================ */

static fut_thread_t *ready_queue = NULL;        /* Head of ready queue */
static fut_thread_t *current_thread = NULL;     /* Current running thread */
static fut_process_t *process_list = NULL;      /* Head of process list */
static _Atomic(uint32_t) next_tid = 1;
static _Atomic(uint32_t) next_pid = 1;
static fut_thread_t *idle_thread = NULL;        /* Idle thread */

/* ============================================================
 *   Stack Setup Trampolines
 * ============================================================ */

void fut_user_entry_trampoline(void (*entry)(void *), void *arg) {
    /* Enable interrupts for user space */
    fut_enable_interrupts();

    /* Call the entry point */
    entry(arg);

    /* Exit thread */
    fut_thread_exit(0);
}

void fut_kernel_entry_trampoline(void (*entry)(void *), void *arg) {
    /* Call the entry point */
    entry(arg);

    /* Exit thread */
    fut_thread_exit(0);
}

/* ============================================================
 *   Thread Creation and Management
 * ============================================================ */

fut_thread_t *fut_thread_create_kernel(void (*entry)(void *), void *arg,
                                       uint8_t priority, const char *name) {
    /* Allocate thread structure */
    fut_thread_t *thread = (fut_thread_t *)fut_malloc(sizeof(fut_thread_t));
    if (!thread) {
        return NULL;
    }

    memset(thread, 0, sizeof(fut_thread_t));

    /* Allocate kernel stack (4KB) */
    thread->kernel_stack = fut_malloc(4096);
    if (!thread->kernel_stack) {
        fut_free(thread);
        return NULL;
    }
    thread->kernel_stack_size = 4096;

    /* Initialize thread */
    thread->tid = atomic_fetch_add(&next_tid, 1);
    thread->pid = 0;  /* Kernel threads don't belong to a process */
    thread->state = FUT_THREAD_READY;
    thread->priority = priority;
    thread->flags = FUT_THREAD_KERNEL;
    thread->timeslice = 10;  /* 10ms time slice */

    /* Initialize CPU context */
    void *stack_ptr = (void *)((uint64_t)thread->kernel_stack + thread->kernel_stack_size);
    fut_init_thread_context(&thread->context, fut_kernel_entry_trampoline, (void *)entry, stack_ptr);

    /* Inject argument via context */
    thread->context.x19 = (uint64_t)arg;

    /* Use kernel VM context */
    thread->vmem = &kernel_vmem_context;

    return thread;
}

fut_thread_t *fut_thread_create_user(fut_process_t *process, void (*entry)(void *),
                                     void *arg, uint8_t priority) {
    if (!process || !process->mm) {
        return NULL;
    }

    /* Allocate thread structure */
    fut_thread_t *thread = (fut_thread_t *)fut_malloc(sizeof(fut_thread_t));
    if (!thread) {
        return NULL;
    }

    memset(thread, 0, sizeof(fut_thread_t));

    /* Allocate kernel stack for system calls and exceptions */
    thread->kernel_stack = fut_malloc(4096);
    if (!thread->kernel_stack) {
        fut_free(thread);
        return NULL;
    }
    thread->kernel_stack_size = 4096;

    /* Allocate user stack (4KB) */
    thread->user_stack = fut_malloc(4096);
    if (!thread->user_stack) {
        fut_free(thread->kernel_stack);
        fut_free(thread);
        return NULL;
    }
    thread->user_stack_size = 4096;

    /* Initialize thread */
    thread->tid = atomic_fetch_add(&next_tid, 1);
    thread->pid = process->pid;
    thread->state = FUT_THREAD_READY;
    thread->priority = priority;
    thread->flags = 0;  /* User thread */
    thread->timeslice = 10;  /* 10ms time slice */

    /* Initialize CPU context for user-space execution */
    void *stack_ptr = (void *)((uint64_t)thread->user_stack + thread->user_stack_size);

    /* Clear context */
    memset(&thread->context, 0, sizeof(fut_cpu_context_t));

    /* Set up for direct EL0 execution (no trampoline needed) */
    thread->context.x0 = (uint64_t)arg;         /* First argument */
    thread->context.sp = (uint64_t)stack_ptr;   /* User stack */
    thread->context.pc = (uint64_t)entry;       /* User entry point */
    thread->context.pstate = PSTATE_MODE_EL0t;  /* EL0 user mode */
    thread->context.x29_fp = (uint64_t)stack_ptr; /* Frame pointer */

    /* Use process's virtual memory context */
    thread->vmem = fut_mm_context(process->mm);

    return thread;
}

void fut_thread_terminate(fut_thread_t *thread) {
    if (!thread) {
        return;
    }

    /* Remove from scheduler */
    fut_scheduler_dequeue(thread);

    /* Free stacks */
    if (thread->kernel_stack) {
        fut_free(thread->kernel_stack);
    }
    if (thread->user_stack) {
        fut_free(thread->user_stack);
    }

    /* Free thread */
    fut_free(thread);
}

fut_thread_t *fut_thread_current(void) {
    return current_thread;
}

void fut_thread_yield(void) {
    /* Request reschedule */
    fut_request_reschedule();
}

void fut_thread_set_priority(fut_thread_t *thread, uint8_t priority) {
    if (!thread) {
        thread = current_thread;
    }
    if (thread) {
        thread->priority = priority;
    }
}

void fut_thread_sleep(uint32_t milliseconds) {
    fut_thread_t *thread = current_thread;
    if (!thread) {
        return;
    }

    uint32_t freq = fut_timer_get_frequency();
    uint64_t now = fut_timer_read_count();
    thread->wake_time = now + (milliseconds * freq / 1000);

    fut_scheduler_set_state(thread, FUT_THREAD_SLEEPING);
    fut_thread_yield();
}

void fut_thread_wake(fut_thread_t *thread) {
    if (!thread) {
        return;
    }

    if (thread->state == FUT_THREAD_SLEEPING) {
        fut_scheduler_set_state(thread, FUT_THREAD_READY);
        thread->wake_time = 0;
    }
}

uint32_t fut_thread_get_id(fut_thread_t *thread) {
    if (!thread) {
        thread = current_thread;
    }
    return thread ? thread->tid : 0;
}

uint32_t fut_thread_get_pid(fut_thread_t *thread) {
    if (!thread) {
        thread = current_thread;
    }
    return thread ? thread->pid : 0;
}

/* ============================================================
 *   Process Creation and Management
 * ============================================================ */

fut_process_t *fut_process_create(void (*entry)(void *), void *arg, const char *name) {
    /* Allocate process structure */
    fut_process_t *process = (fut_process_t *)fut_malloc(sizeof(fut_process_t));
    if (!process) {
        return NULL;
    }

    memset(process, 0, sizeof(fut_process_t));

    /* Create memory management context */
    process->mm = fut_mm_create();
    if (!process->mm) {
        fut_free(process);
        return NULL;
    }

    /* Initialize process */
    process->pid = atomic_fetch_add(&next_pid, 1);
    process->ppid = current_thread ? current_thread->pid : 0;
    process->state = FUT_PROCESS_CREATED;
    process->entry_point = (void *)entry;

    /* Create main thread */
    process->main_thread = fut_thread_create_user(process, entry, arg, 128);
    if (!process->main_thread) {
        fut_mm_release(process->mm);
        fut_free(process);
        return NULL;
    }

    process->threads = process->main_thread;
    process->num_threads = 1;

    /* Add to process list */
    if (process_list) {
        process->next = process_list;
        process_list->prev = process;
    }
    process_list = process;

    /* Enqueue main thread to scheduler */
    fut_scheduler_enqueue(process->main_thread);

    return process;
}

void fut_process_terminate(fut_process_t *process) {
    if (!process) {
        return;
    }

    /* Terminate all threads */
    fut_thread_t *thread = process->threads;
    while (thread) {
        fut_thread_t *next = thread->next;
        fut_thread_terminate(thread);
        thread = next;
    }

    /* Remove from process list */
    if (process->prev) {
        process->prev->next = process->next;
    } else {
        process_list = process->next;
    }
    if (process->next) {
        process->next->prev = process->prev;
    }

    /* Free memory context */
    fut_mm_release(process->mm);

    /* Free process */
    fut_free(process);
}

fut_process_t *fut_process_current(void) {
    if (!current_thread) {
        return NULL;
    }
    return fut_process_get(current_thread->pid);
}

fut_process_t *fut_process_get(uint32_t pid) {
    fut_process_t *proc = process_list;
    while (proc) {
        if (proc->pid == pid) {
            return proc;
        }
        proc = proc->next;
    }
    return NULL;
}

uint32_t fut_process_get_id(fut_process_t *process) {
    if (!process) {
        process = fut_process_current();
    }
    return process ? process->pid : 0;
}

uint32_t fut_process_get_ppid(fut_process_t *process) {
    if (!process) {
        process = fut_process_current();
    }
    return process ? process->ppid : 0;
}

/* ============================================================
 *   Scheduler Implementation
 * ============================================================ */

void fut_scheduler_init(void) {
    /* Create idle thread */
    idle_thread = fut_thread_create_kernel(NULL, NULL, 255, "idle");
    if (idle_thread) {
        fut_scheduler_enqueue(idle_thread);
    }

    /* Set idle as current */
    current_thread = idle_thread;
}

fut_thread_t *fut_scheduler_next(void) {
    if (!ready_queue) {
        return idle_thread;
    }

    /* Find highest priority ready thread */
    fut_thread_t *best = NULL;
    fut_thread_t *thread = ready_queue;

    while (thread) {
        if (thread->state == FUT_THREAD_READY) {
            if (!best || thread->priority < best->priority) {
                best = thread;
            }
        } else if (thread->state == FUT_THREAD_SLEEPING) {
            /* Check if should wake */
            uint64_t now = fut_timer_read_count();
            if (thread->wake_time && now >= thread->wake_time) {
                thread->state = FUT_THREAD_READY;
                thread->wake_time = 0;
                if (!best || thread->priority < best->priority) {
                    best = thread;
                }
            }
        }
        thread = thread->next;
    }

    return best ? best : idle_thread;
}

void fut_scheduler_enqueue(fut_thread_t *thread) {
    if (!thread) {
        return;
    }

    if (ready_queue) {
        thread->next = ready_queue;
        ready_queue->prev = thread;
    }
    ready_queue = thread;
}

void fut_scheduler_dequeue(fut_thread_t *thread) {
    if (!thread) {
        return;
    }

    if (thread->prev) {
        thread->prev->next = thread->next;
    } else {
        ready_queue = thread->next;
    }

    if (thread->next) {
        thread->next->prev = thread->prev;
    }

    thread->next = NULL;
    thread->prev = NULL;
}

void fut_scheduler_set_state(fut_thread_t *thread, uint8_t new_state) {
    if (!thread) {
        return;
    }

    thread->state = new_state;
}

bool fut_scheduler_should_preempt(void) {
    if (!current_thread) {
        return false;
    }

    fut_thread_t *next = fut_scheduler_next();
    return next && next != current_thread && next->priority < current_thread->priority;
}

void fut_scheduler_run(fut_interrupt_frame_t *frame) {
    /* Get next thread */
    fut_thread_t *next = fut_scheduler_next();
    if (!next) {
        return;
    }

    /* If same thread, no switch needed */
    if (next == current_thread) {
        return;
    }

    /* Save current thread context */
    if (current_thread && current_thread != idle_thread) {
        if (frame) {
            current_thread->int_frame = frame;
        } else {
            /* Save cooperative context */
            fut_save_context(&current_thread->context);
        }
        current_thread->state = FUT_THREAD_READY;
        fut_scheduler_enqueue(current_thread);
    }

    /* Switch to next thread */
    current_thread = next;
    current_thread->state = FUT_THREAD_RUNNING;
    fut_scheduler_dequeue(next);

    /* Switch memory context if needed */
    if (next->vmem) {
        fut_vmem_switch(next->vmem);
    }

    /* Restore context */
    if (next->int_frame) {
        /* Would return from interrupt with new context */
        // For now, this is a simplified implementation
    }
    fut_restore_context(&next->context);
}

/* ============================================================
 *   Thread Exit Handling
 * ============================================================ */

void fut_thread_exit(int exit_code) {
    if (!current_thread) {
        return;
    }

    current_thread->state = FUT_THREAD_TERMINATED;
    fut_scheduler_dequeue(current_thread);

    /* Trigger scheduler to run next thread */
    fut_scheduler_run(NULL);

    /* Should never reach here */
    while (1) {
        __asm__ volatile("wfi");
    }
}

void fut_process_exit(int exit_code) {
    if (!current_thread) {
        return;
    }

    fut_process_t *process = fut_process_get(current_thread->pid);
    if (process) {
        fut_process_terminate(process);
    }

    /* Exit current thread */
    fut_thread_exit(exit_code);
}
