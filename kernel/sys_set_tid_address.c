/* kernel/sys_set_tid_address.c - Thread ID address syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements set_tid_address for thread cleanup and futex integration.
 * Essential for NPTL (Native POSIX Thread Library) and proper thread exit.
 *
 * Phase 1 (Current): Validation and stub implementation
 * Phase 2: Store tid address in task structure
 * Phase 3: Implement clear_child_tid on thread exit
 * Phase 4: Integrate with futex wake for robust mutexes
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <stdint.h>

extern void fut_printf(const char *fmt, ...);

/**
 * set_tid_address() - Set pointer to thread ID for signal delivery
 *
 * Sets the location where the kernel should clear the thread ID and
 * wake a futex when this thread exits. This is essential for thread
 * libraries (like NPTL) to implement efficient thread joining and
 * robust mutex support.
 *
 * @param tidptr  Pointer to memory location for thread ID (in userspace)
 *
 * Returns:
 *   - Current thread ID (always succeeds)
 *
 * Usage (internal to threading library):
 *   int tid_location = 0;
 *   int tid = set_tid_address(&tid_location);
 *   // When thread exits, kernel will:
 *   // 1. Set *tidptr = 0
 *   // 2. Wake futex waiters on tidptr address
 *
 * How NPTL uses this:
 * 1. Thread library allocates per-thread data structure
 * 2. Calls set_tid_address(&thread_struct->tid)
 * 3. When thread exits, kernel clears TID and wakes waiters
 * 4. Joining threads can futex_wait on TID location
 *
 * Behavior on thread exit:
 * - Kernel writes 0 to *tidptr
 * - Kernel performs futex(tidptr, FUTEX_WAKE, 1, NULL, NULL, 0)
 * - This wakes one thread waiting on pthread_join()
 *
 * Relationship to clone():
 * - clone() with CLONE_CHILD_CLEARTID sets this automatically
 * - set_tid_address() allows changing it after clone()
 * - Used by threading libraries for dynamic thread management
 *
 * Security considerations:
 * - tidptr must be writable by the thread
 * - Kernel validates address on thread exit
 * - Invalid address causes no action (graceful failure)
 * - Per-thread setting (not inherited by children)
 *
 * Use cases:
 * - pthread_join(): Wait for thread termination efficiently
 * - Robust mutexes: Detect thread death via TID monitoring
 * - Thread cleanup: Coordinate cleanup between threads
 * - Futex-based synchronization: Efficient thread barriers
 *
 * Implementation notes:
 * - Always returns current TID (never fails)
 * - Can be called multiple times to change address
 * - NULL tidptr disables clear_child_tid behavior
 * - Address is not validated until thread exit
 *
 * Phase 1: Accept tidptr and return current TID
 * Phase 2: Store tidptr in task structure
 * Phase 3: Clear TID and wake futex on thread exit
 */
long sys_set_tid_address(int *tidptr) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        /* Should never happen, but return error if no task */
        return -ESRCH;
    }

    /* Categorize operation */
    const char *op_desc;
    if (tidptr == NULL) {
        op_desc = "disabling clear_child_tid";
    } else {
        op_desc = "setting clear_child_tid address";
    }

    /* Phase 1: Accept tidptr and return current TID */
    int current_tid = task->pid;  /* In our system, TID == PID for main thread */

    fut_printf("[SET_TID_ADDR] set_tid_address(tidptr=%p [%s], pid=%d) -> %d "
               "(Phase 1 stub - no actual futex wake on exit yet)\n",
               tidptr, op_desc, task->pid, current_tid);

    return current_tid;
}
