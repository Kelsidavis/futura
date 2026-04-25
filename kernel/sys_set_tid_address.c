/* kernel/sys_set_tid_address.c - Thread ID address syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements set_tid_address for thread cleanup and futex integration.
 * Essential for NPTL (Native POSIX Thread Library) and proper thread exit.
 *
 * Phase 1 (Completed): Validation and stub implementation
 * Phase 2 (Completed): Enhanced validation and parameter categorization with detailed logging
 * Phase 3 (Completed): Store tid address in task structure
 * Phase 4 (Completed): Implement clear_child_tid on thread exit
 */

#include <kernel/fut_task.h>
#include <kernel/fut_thread.h>
#include <kernel/errno.h>
#include <stdint.h>

#include <kernel/kprintf.h>
#include <platform/platform.h>

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
 * Phase 1 (Completed): Accept tidptr and return current TID
 * Phase 2 (Completed): Enhanced validation and categorization with detailed logging
 * Phase 3 (Completed): Store tidptr in task structure
 * Phase 4 (Completed): Clear TID and wake futex on thread exit
 */
long sys_set_tid_address(int *tidptr) {
    fut_task_t *task = fut_task_current();
    if (!task)
        return -ESRCH;

    /* Reject kernel-space pointers from userspace. The thread-exit
     * writeback in fut_thread.c does an unchecked direct write when
     * clear_child_tid >= KERNEL_VIRTUAL_BASE (intended for in-kernel
     * selftest callers); without this gate any unprivileged process
     * could call set_tid_address(kernel_addr) and get a zero-write
     * primitive at thread exit on an arbitrary kernel address.
     * NULL is preserved as the "disable cleartid" sentinel. */
#ifdef KERNEL_VIRTUAL_BASE
    if (tidptr && (uintptr_t)tidptr >= KERNEL_VIRTUAL_BASE)
        return -EFAULT;
#endif

    /* For CLONE_THREAD threads, store in the per-thread field so that only
     * THIS thread's exit clears the address (not the whole task's exit).
     * For single-threaded processes, also update task->clear_child_tid as
     * a fallback for the task_cleanup_and_exit() path. */
    fut_thread_t *thread = fut_thread_current();
    if (thread)
        thread->clear_child_tid = tidptr;
    task->clear_child_tid = tidptr;

    /* Return the calling thread's TID.  For secondary threads (CLONE_THREAD)
     * this differs from the process PID (= TGID). */
    uint64_t tid = thread ? thread->tid : (uint64_t)task->pid;
    return (long)tid;
}
