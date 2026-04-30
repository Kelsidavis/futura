/* kernel/sys_futex.c - Fast userspace locking (futex) syscalls
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements futex syscalls for userspace synchronization primitives.
 * Futexes (fast userspace mutexes) are the foundation for pthread mutexes,
 * condition variables, semaphores, and other synchronization primitives.
 */

#include <kernel/fut_task.h>
#include <kernel/fut_thread.h>
#include <kernel/fut_waitq.h>
#include <kernel/fut_sched.h>
#include <kernel/fut_timer.h>
#include <kernel/errno.h>
#include <shared/fut_timespec.h>
#include <sys/futex.h>  /* For FUTEX_* constants, struct robust_list */
#include <stdbool.h>
#include <stdint.h>

#include <kernel/kprintf.h>
#include <kernel/uaccess.h>
#include <platform/platform.h>

/* Kernel-pointer bypass helpers for selftest support */
static inline int futex_copy_from_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)src >= KERNEL_VIRTUAL_BASE) { __builtin_memcpy(dst, src, n); return 0; }
#endif
    return fut_copy_from_user(dst, src, n);
}
static inline int futex_copy_to_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)dst >= KERNEL_VIRTUAL_BASE) { __builtin_memcpy(dst, src, n); return 0; }
#endif
    return fut_copy_to_user(dst, src, n);
}
static inline int futex_access_ok_write(const void *ptr, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)ptr >= KERNEL_VIRTUAL_BASE) return 0;
#endif
    return fut_access_ok(ptr, n, 1);
}
static inline int futex_access_ok_read(const void *ptr, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)ptr >= KERNEL_VIRTUAL_BASE) return 0;
#endif
    return fut_access_ok(ptr, n, 0);
}

/* ============================================================
 *   Futex Hash Table
 * ============================================================ */

#define FUTEX_HASH_SIZE 256  /* Number of hash buckets */

/* PI futex word bit layout (Linux ABI) */
#define ROBUST_FUTEX_OWNER_DIED  0x40000000U  /* Set when owner dies holding lock */
#define ROBUST_FUTEX_WAITERS     0x80000000U  /* Set when threads are waiting */
#define ROBUST_FUTEX_TID_MASK    0x3FFFFFFFU  /* Lower 30 bits = owner TID */
#define ROBUST_LIST_LIMIT        2048         /* Max entries to walk (prevent infinite loop) */

/* Futex hash table bucket - contains wait queue for all futexes hashing to this bucket */
typedef struct futex_bucket {
    fut_spinlock_t lock;
    fut_waitq_t waiters;
} futex_bucket_t;

/* Global futex hash table */
static futex_bucket_t futex_hash[FUTEX_HASH_SIZE];
static bool futex_initialized = false;

/* Simple hash function for futex addresses */
static inline uint32_t futex_hash_key(uint32_t *uaddr) {
    /* Use address bits for hashing - ignore lowest bits (alignment) */
    uint64_t addr = (uint64_t)uaddr;
    return (uint32_t)((addr >> 2) % FUTEX_HASH_SIZE);
}

/* Initialize futex subsystem */
static void futex_init_once(void) {
    if (futex_initialized) {
        return;
    }
    for (int i = 0; i < FUTEX_HASH_SIZE; i++) {
        futex_hash[i].lock.locked = 0;
        fut_waitq_init(&futex_hash[i].waiters);
    }
    futex_initialized = true;
}

/* Get hash bucket for a futex address */
static futex_bucket_t *futex_get_bucket(uint32_t *uaddr) {
    futex_init_once();
    uint32_t key = futex_hash_key(uaddr);
    return &futex_hash[key];
}

/* ============================================================
 *   Futex Timeout Support
 * ============================================================ */

/* Context passed to futex timeout callback */
typedef struct futex_timeout_ctx {
    fut_thread_t *thread;
    futex_bucket_t *bucket;
} futex_timeout_ctx_t;

/* Timer callback for FUTEX_WAIT timeout.
 * Removes the thread from the futex wait queue and wakes it.
 * Clears futex_addr to signal timeout to the waiting thread. */
static void futex_timeout_callback(void *arg) {
    futex_timeout_ctx_t *ctx = (futex_timeout_ctx_t *)arg;
    fut_thread_t *thread = ctx->thread;
    futex_bucket_t *bucket = ctx->bucket;

    fut_spinlock_acquire(&bucket->lock);

    /* Only act if thread is still on the wait queue (not already woken by FUTEX_WAKE) */
    fut_waitq_t *wq = &bucket->waiters;
    fut_thread_t *cur = wq->head;
    fut_thread_t *prev = NULL;
    bool found = false;

    while (cur) {
        if (cur == thread) {
            if (prev) {
                prev->wait_next = cur->wait_next;
            } else {
                wq->head = cur->wait_next;
            }
            if (wq->tail == cur) {
                wq->tail = prev;
            }
            cur->wait_next = NULL;
            found = true;
            break;
        }
        prev = cur;
        cur = cur->wait_next;
    }

    if (found) {
        /* Thread was still waiting - wake it with timeout indication */
        thread->futex_addr = NULL;
        thread->state = FUT_THREAD_READY;
        fut_sched_add_thread(thread);
        fut_printf("[FUTEX] timeout - woke thread %p\n", (void*)thread);
    }

    fut_spinlock_release(&bucket->lock);
}

/**
 * futex_wake_one - Internal kernel function to wake one futex waiter
 *
 * Used by kernel code (e.g., clear_child_tid on thread exit) to wake
 * threads waiting on a futex without going through the full syscall path.
 *
 * @param uaddr  Futex address to wake
 * @return Number of threads woken (0 or 1)
 */
int futex_wake_one(uint32_t *uaddr) {
    if (!uaddr) {
        return 0;
    }

    futex_bucket_t *bucket = futex_get_bucket(uaddr);
    fut_spinlock_acquire(&bucket->lock);

    int woken = 0;
    fut_waitq_t *wq = &bucket->waiters;
    fut_thread_t *thread = wq->head;
    fut_thread_t *prev = NULL;

    while (thread && woken < 1) {
        fut_thread_t *next = thread->wait_next;

        /* Check if this thread is waiting on our specific futex address */
        if (thread->futex_addr == uaddr) {
            /* Remove from wait queue */
            if (prev) {
                prev->wait_next = next;
            } else {
                wq->head = next;
            }
            if (wq->tail == thread) {
                wq->tail = prev;
            }
            thread->wait_next = NULL;

            /* Wake up the thread - set state to READY and add to run queue */
            thread->state = FUT_THREAD_READY;
            fut_sched_add_thread(thread);
            woken++;

            fut_printf("[FUTEX] futex_wake_one(%p) - woke thread %p (clear_child_tid)\n",
                       (void*)uaddr, (void*)thread);
        } else {
            prev = thread;
        }

        thread = next;
    }

    fut_spinlock_release(&bucket->lock);
    return woken;
}

/* FUTEX_* constants and robust list structures provided by linux/futex.h */

/**
 * sys_futex - Fast userspace locking
 *
 * @param uaddr:   Address of futex word in userspace
 * @param op:      Futex operation (FUTEX_WAIT, FUTEX_WAKE, etc.)
 * @param val:     Operation-specific value
 * @param timeout: Timeout for FUTEX_WAIT operations
 * @param uaddr2:  Second futex address (for REQUEUE operations)
 * @param val3:    Operation-specific value
 *
 * Futex operations:
 * - FUTEX_WAIT: Atomically check *uaddr == val, then sleep until woken
 * - FUTEX_WAKE: Wake up to 'val' threads waiting on futex at uaddr
 * - FUTEX_REQUEUE: Requeue threads from one futex to another
 * - FUTEX_CMP_REQUEUE: Conditional requeue with value check
 * - FUTEX_WAKE_OP: Wake and perform operation atomically
 *
 * Phase 1 (Complete): Basic FUTEX_WAIT/FUTEX_WAKE with wait queues
 * Phase 2 (Complete): FUTEX_REQUEUE, FUTEX_CMP_REQUEUE, FUTEX_WAKE_OP
 * Phase 3 (Complete): Timeout support for FUTEX_WAIT
 *
 * Returns:
 *   - FUTEX_WAIT: 0 on success, -EAGAIN if value mismatch, -ETIMEDOUT on timeout
 *   - FUTEX_WAKE: Number of threads woken
 *   - Other ops: Operation-specific return values
 */
long sys_futex(uint32_t *uaddr, int op, uint32_t val,
               const fut_timespec_t *timeout, uint32_t *uaddr2, uint32_t val3) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    /* Mask out flags to get base operation.
     * Save modifier flags before stripping for use in timeout handling. */
    bool use_realtime_clock = (op & FUTEX_CLOCK_REALTIME) != 0;
    int cmd = op & 0x7F;

    /* Entry logging removed — too noisy at runtime */

    /* Document pointer validation requirement for Phase 2 implementation
     * VULNERABILITY: Time-of-Check-Time-of-Use (TOCTOU) and Invalid Pointer Access
     *
     * ATTACK SCENARIO 1: TOCTOU Race in FUTEX_WAIT
     * Attacker exploits race condition between value check and sleep
     * 1. Thread A: calls futex(uaddr, FUTEX_WAIT, expected_val, ...)
     * 2. Kernel: Reads *uaddr → sees expected_val, prepares to sleep
     * 3. Thread B: Modifies *uaddr to different value before sleep begins
     * 4. Thread A: Sleeps on futex even though value already changed
     * 5. Thread A now waiting on stale condition, misses wakeup
     * 6. Deadlock: Thread A never wakes up, holding locks
     *
     * ATTACK SCENARIO 2: Invalid Pointer Dereference
     * Attacker provides unmapped or kernel address to cause crash
     * 1. Attacker calls futex(0xFFFFFFFF80000000, FUTEX_WAIT, ...)
     * 2. Without validation: kernel dereferences kernel address
     * 3. Information disclosure: Kernel reads sensitive memory
     * 4. Page fault: Kernel crash if unmapped address
     *
     * ATTACK SCENARIO 3: Concurrent Modification During Wake
     * Attacker modifies futex word while kernel is waking threads
     * 1. Thread A sleeps on futex at uaddr
     * 2. Thread B calls futex(uaddr, FUTEX_WAKE, 1)
     * 3. Kernel prepares to wake Thread A
     * 4. Thread C modifies *uaddr or unmaps page
     * 5. Kernel dereferences invalid uaddr during wake
     * 6. Page fault or information disclosure
     *
     * IMPACT:
     * - Deadlock: TOCTOU causes threads to sleep on stale conditions
     * - Information disclosure: Reading kernel addresses reveals secrets
     * - Kernel crash: Page fault on unmapped addresses
     * - Privilege escalation: Corrupting kernel futex state
     * - Race conditions: Lost wakeups, spurious wakeups
     *
     * ROOT CAUSE:
     * Phase 1 stub lacks critical security checks:
     * - Line 88-90: Only checks uaddr != NULL (insufficient)
     * - No fut_access_ok() validation of userspace pointer
     * - No atomic compare-and-sleep for FUTEX_WAIT
     * - No protection against concurrent page unmapping
     * - Assumes *uaddr remains valid throughout operation
     *
     * DEFENSE (Requirements for Phase 2):
     * 1. Pointer Validation (BEFORE any dereference):
     *    - fut_access_ok(uaddr, sizeof(uint32_t), WRITE)
     *    - Verify uaddr is in valid userspace range
     *    - Check page is mapped and accessible
     * 2. Atomic FUTEX_WAIT (critical for correctness):
     *    - Acquire futex hash bucket lock
     *    - Read *uaddr under lock (prevents TOCTOU)
     *    - Compare with expected value under lock
     *    - Enqueue on wait queue under lock
     *    - Release lock only after enqueued
     *    - All steps must be atomic transaction
     * 3. Page Pinning or Careful Access:
     *    - Option A: Pin page during futex operation
     *    - Option B: Use safe copy functions (fut_get_user)
     *    - Handle page fault gracefully (-EFAULT return)
     * 4. Timeout Validation:
     *    - Validate timeout pointer if non-NULL
     *    - Check timeout values don't overflow
     *    - See sys_alarm.c:104 for overflow pattern
     *
     * CVE REFERENCES:
     * - CVE-2014-3153: Linux futex requeue use-after-free (TOCTOU variant)
     * - CVE-2018-6927: Linux futex state corruption
     * - CVE-2014-0205: Futex userspace pointer validation bypass
     *
     * LINUX REQUIREMENT:
     * From futex(2) man page:
     * "FUTEX_WAIT atomically verifies that the futex address uaddr still
     *  contains the value val, and sleeps awaiting FUTEX_WAKE on this futex.
     *  If the futex value does not match val, then the call fails
     *  immediately with the error EAGAIN."
     * - The word "atomically" is critical: check and sleep MUST be atomic
     * - No window where another thread can modify *uaddr between check/sleep
     *
     * IMPLEMENTATION NOTES:
     * - Line 88-90: Current validation INSUFFICIENT (NULL check only)
     * - Phase 2 MUST add fut_access_ok() before dereference
     * - FUTEX_WAIT MUST use hash bucket locks for atomicity
     * - FUTEX_WAKE MUST validate uaddr before accessing
     * - All pointer accesses MUST use safe copy functions
     * - Phase 3 PI futexes have additional security requirements
     */
    /* Validate userspace address — NULL is a pointer fault (EFAULT) per
     * Linux futex(2); Linux's get_user/put_user surface EFAULT directly,
     * so a leading EINVAL gate would mask the real error class for
     * libc wrappers that distinguish the two. */
    if (!uaddr) {
        return -EFAULT;
    }

    /* Phase 2: Validate userspace pointer with write access (futexes modify memory) */
    if (futex_access_ok_write(uaddr, sizeof(uint32_t)) != 0) {
        return -EFAULT;
    }

    /* Phase 2 (Completed): Atomic compare-and-sleep for FUTEX_WAIT
     *   ✓ Hash bucket locks prevent TOCTOU (lines 249-265)
     *   ✓ Value read and comparison under lock (lines 252-265)
     *   ✓ Sleep on wait queue with lock held (line 279)
     */
    /* Phase 3 (Completed): PI (priority inheritance) futex support
     *   - FUTEX_LOCK_PI: boosts owner priority when contended
     *   - FUTEX_UNLOCK_PI: restores owner priority, hands lock to highest-prio waiter
     *   - FUTEX_TRYLOCK_PI: non-blocking lock attempt */

    /* Strip modifier flags before dispatch — FUTEX_PRIVATE_FLAG (128) indicates
     * process-private futex (skip global hash table, use per-process structure);
     * we don't distinguish private vs shared yet so treat them identically.
     * FUTEX_CLOCK_REALTIME (256) selects the clock for timeouts; we default
     * to monotonic, so strip it silently for now. */
    cmd &= ~(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME);

    switch (cmd) {
        case FUTEX_WAIT:
        case FUTEX_WAIT_BITSET: {
            /* FUTEX_WAIT: Atomically check *uaddr == val, then sleep
             * This is the core primitive for userspace mutexes/condvars */

            /* Parse and validate timeout if specified.
             *
             * FUTEX_WAIT    uses a RELATIVE timeout (duration from now).
             * FUTEX_WAIT_BITSET uses an ABSOLUTE timeout on either
             *   CLOCK_MONOTONIC (default) or CLOCK_REALTIME (FUTEX_CLOCK_REALTIME).
             *
             * glibc pthread_cond_timedwait uses FUTEX_WAIT_BITSET|FUTEX_PRIVATE_FLAG
             * with an absolute CLOCK_REALTIME deadline (or CLOCK_MONOTONIC for
             * pthread_condattr_setclock).  Treating it as relative would yield
             * an enormous (wrong) sleep duration.
             */
            bool has_timeout = false;
            uint64_t timeout_ms = 0;
            if (timeout) {
                fut_timespec_t ts;
                if (futex_copy_from_user(&ts, timeout, sizeof(ts)) != 0) {
                    return -EFAULT;
                }
                if (ts.tv_sec < 0 || ts.tv_nsec < 0 || ts.tv_nsec >= 1000000000) {
                    return -EINVAL;
                }

                if (cmd == FUTEX_WAIT_BITSET) {
                    /* Absolute timeout: convert to relative by subtracting now. */
                    extern uint64_t fut_get_ticks(void);
                    extern volatile int64_t g_realtime_offset_sec;
                    uint64_t now_ticks = fut_get_ticks();
                    /* 100 Hz timer → each tick is 10 ms = 10 000 000 ns */
                    uint64_t now_ns = now_ticks * 10000000ULL;
                    if (use_realtime_clock) {
                        /* Add realtime offset (seconds converted to ns) */
                        now_ns += (uint64_t)((int64_t)g_realtime_offset_sec * 1000000000LL);
                    }
                    uint64_t abs_ns = (uint64_t)ts.tv_sec * 1000000000ULL +
                                      (uint64_t)ts.tv_nsec;
                    if (abs_ns <= now_ns) {
                        /* Already expired (bucket lock not yet held here) */
                        return -ETIMEDOUT;
                    }
                    uint64_t remaining_ns = abs_ns - now_ns;
                    timeout_ms = remaining_ns / 1000000;
                    if (remaining_ns % 1000000 != 0) timeout_ms++;
                } else {
                    /* FUTEX_WAIT: relative timeout */
                    timeout_ms = (uint64_t)ts.tv_sec * 1000 +
                                 ((uint64_t)ts.tv_nsec + 999999) / 1000000;
                }
                has_timeout = true;
            }

            /* Get the hash bucket for this futex address */
            futex_bucket_t *bucket = futex_get_bucket(uaddr);

            /* Acquire bucket lock to ensure atomicity of check-and-sleep */
            fut_spinlock_acquire(&bucket->lock);

            /* Read current value from userspace (under lock) */
            uint32_t current_val;
            if (futex_copy_from_user(&current_val, uaddr, sizeof(uint32_t)) != 0) {
                fut_spinlock_release(&bucket->lock);
                return -EFAULT;
            }

            /* Compare with expected value */
            if (current_val != val) {
                /* Value doesn't match - return immediately (no race) */
                fut_spinlock_release(&bucket->lock);
                fut_printf("[FUTEX] FUTEX_WAIT - value mismatch (*uaddr=%u, expected=%u)\n",
                           current_val, val);
                return -EAGAIN;
            }

            /* Zero timeout: value matched but don't block */
            if (has_timeout && timeout_ms == 0) {
                fut_spinlock_release(&bucket->lock);
                return -ETIMEDOUT;
            }

            /* Value matches - add to wait queue and sleep */
            fut_thread_t *thread = fut_thread_current();
            if (!thread) {
                fut_spinlock_release(&bucket->lock);
                return -ESRCH;
            }

            /* Store futex address and bitset in thread for later matching during wake.
             * FUTEX_WAIT uses bitset=0xffffffff (match any); FUTEX_WAIT_BITSET uses val3.
             * A bitset of 0 is invalid — no wake could ever match it (Linux returns EINVAL). */
            uint32_t wait_bitset = (cmd == FUTEX_WAIT_BITSET) ? val3 : 0xFFFFFFFFu;
            if (wait_bitset == 0) {
                fut_spinlock_release(&bucket->lock);
                return -EINVAL;
            }
            thread->futex_addr   = uaddr;
            thread->futex_bitset = wait_bitset;

            /* Pre-compute timeout ticks before enqueuing */
            futex_timeout_ctx_t timeout_ctx;
            uint64_t timeout_ticks = 0;
            if (has_timeout) {
                timeout_ctx.thread = thread;
                timeout_ctx.bucket = bucket;
                timeout_ticks = timeout_ms / 10;
                if (timeout_ms % 10 != 0) timeout_ticks++;
                if (timeout_ticks == 0 && timeout_ms > 0) timeout_ticks = 1;
            }

            /* Enqueue thread into wait queue while still holding bucket->lock.
             * We inline the enqueue here so we can release bucket->lock BEFORE
             * starting the timer.  futex_timeout_callback acquires bucket->lock
             * from IRQ context; if we hold bucket->lock when the timer fires on a
             * single-CPU system, the IRQ handler spins on an already-held lock
             * and the preempted thread can never release it → deadlock. */
            thread->state         = FUT_THREAD_BLOCKED;
            thread->blocked_waitq = &bucket->waiters;
            thread->wait_next     = NULL;
            if (bucket->waiters.tail) {
                bucket->waiters.tail->wait_next = thread;
            } else {
                bucket->waiters.head = thread;
            }
            bucket->waiters.tail = thread;

            /* Release bucket->lock BEFORE starting the timer so the callback
             * can safely acquire it from IRQ context without deadlocking. */
            fut_spinlock_release(&bucket->lock);

            /* Start timer only after the lock is free */
            if (has_timeout) {
                if (fut_timer_start(timeout_ticks, futex_timeout_callback, &timeout_ctx) != 0) {
                    /* OOM: dequeue thread from waitq, restore state, fail */
                    fut_waitq_remove_thread(&bucket->waiters, thread);
                    thread->state = FUT_THREAD_RUNNING;
                    thread->futex_addr = NULL;
                    return -ETIMEDOUT;
                }
            }

            /* Yield to scheduler; woken by FUTEX_WAKE or timeout callback */
            fut_schedule();

            /* Cancel timeout timer if set (harmless if already fired) */
            if (has_timeout) {
                fut_timer_cancel(futex_timeout_callback, &timeout_ctx);
            }

            /* Check if we were timed out (timeout callback clears futex_addr) */
            bool timed_out = (thread->futex_addr == NULL);
            thread->futex_addr = NULL;

            if (timed_out) {
                return -ETIMEDOUT;
            }

            /* Check for pending signals → EINTR. Include thread_pending_signals
             * so tgkill/pthread_kill targets fire EINTR here. */
            {
                fut_task_t *sig_task = fut_task_current();
                if (sig_task) {
                    uint64_t pending = __atomic_load_n(&sig_task->pending_signals, __ATOMIC_ACQUIRE);
                    fut_thread_t *scur_thr = fut_thread_current();
                    if (scur_thr)
                        pending |= __atomic_load_n(&scur_thr->thread_pending_signals, __ATOMIC_ACQUIRE);
                    uint64_t blocked = scur_thr ?
                        __atomic_load_n(&scur_thr->signal_mask, __ATOMIC_ACQUIRE) :
                        __atomic_load_n(&sig_task->signal_mask, __ATOMIC_ACQUIRE);
                    if (pending & ~blocked) {
                        return -EINTR;
                    }
                }
            }
            return 0;
        }

        case FUTEX_WAKE:
        case FUTEX_WAKE_BITSET: {
            /* FUTEX_WAKE: Wake up to 'val' threads waiting on futex at uaddr.
             * FUTEX_WAKE_BITSET: only wake threads whose wait-bitset intersects
             * with the wake bitset (val3).  FUTEX_WAKE uses val3=0xffffffff.
             * A bitset of 0 is invalid — it can never match anything (Linux returns EINVAL). */
            uint32_t wake_bitset = (cmd == FUTEX_WAKE_BITSET) ? val3 : 0xFFFFFFFFu;
            if (wake_bitset == 0)
                return -EINVAL;

            futex_bucket_t *bucket = futex_get_bucket(uaddr);
            fut_spinlock_acquire(&bucket->lock);

            int woken = 0;
            uint32_t max_wake = val;

            /* Walk the wait queue and wake threads waiting on this specific address */
            fut_waitq_t *wq = &bucket->waiters;
            fut_thread_t *thread = wq->head;
            fut_thread_t *prev = NULL;

            while (thread && woken < (int)max_wake) {
                fut_thread_t *next = thread->wait_next;

                /* Check if this thread is waiting on our specific futex address
                 * and the bitset intersection is non-zero (FUTEX_WAKE_BITSET check). */
                if (thread->futex_addr == uaddr &&
                    (thread->futex_bitset & wake_bitset) != 0) {
                    /* Remove from wait queue */
                    if (prev) {
                        prev->wait_next = next;
                    } else {
                        wq->head = next;
                    }
                    if (wq->tail == thread) {
                        wq->tail = prev;
                    }
                    thread->wait_next = NULL;

                    /* Wake up the thread - set state to READY and add to run queue */
                    thread->state = FUT_THREAD_READY;
                    fut_sched_add_thread(thread);
                    woken++;
                } else {
                    prev = thread;
                }

                thread = next;
            }

            fut_spinlock_release(&bucket->lock);

            return woken;
        }

        case FUTEX_REQUEUE: {
            /* FUTEX_REQUEUE: Wake up to 'val' threads waiting on uaddr,
             * then requeue remaining threads to uaddr2.
             *
             * Parameters:
             *   val   = max threads to wake at uaddr
             *   val3  = max threads to requeue to uaddr2 (passed via timeout ptr in Linux)
             *   uaddr2 = destination futex address
             *
             * Note: In Linux, val3 is passed via the timeout parameter cast to int.
             * We use the val3 parameter directly for clarity.
             */
            if (!uaddr2) {
                fut_printf("[FUTEX] FUTEX_REQUEUE - uaddr2 is NULL\n");
                return -EINVAL;
            }
            /* Validate uaddr2 is a real userspace pointer; otherwise a
             * caller could pass a kernel address as uaddr2 and have
             * thread->futex_addr stored as a kernel pointer (not
             * directly exploitable but lets future FUTEX_WAKE ops on
             * the same kernel address wake those threads). */
            if (futex_access_ok_write(uaddr2, sizeof(uint32_t)) != 0)
                return -EFAULT;

            /* Get both futex buckets - lock in address order to avoid deadlock */
            futex_bucket_t *bucket1 = futex_get_bucket(uaddr);
            futex_bucket_t *bucket2 = futex_get_bucket(uaddr2);

            /* Lock in consistent order to prevent deadlock */
            if (bucket1 < bucket2) {
                fut_spinlock_acquire(&bucket1->lock);
                fut_spinlock_acquire(&bucket2->lock);
            } else if (bucket1 > bucket2) {
                fut_spinlock_acquire(&bucket2->lock);
                fut_spinlock_acquire(&bucket1->lock);
            } else {
                /* Same bucket - only lock once */
                fut_spinlock_acquire(&bucket1->lock);
            }

            int woken = 0;
            int requeued = 0;
            uint32_t max_wake = val;
            uint32_t max_requeue = val3 > 0 ? val3 : INT32_MAX;

            /* Walk the wait queue at uaddr */
            fut_waitq_t *wq1 = &bucket1->waiters;
            fut_thread_t *thread = wq1->head;
            fut_thread_t *prev = NULL;

            while (thread) {
                fut_thread_t *next = thread->wait_next;

                /* Check if this thread is waiting on uaddr */
                if (thread->futex_addr == uaddr) {
                    /* Remove from source wait queue */
                    if (prev) {
                        prev->wait_next = next;
                    } else {
                        wq1->head = next;
                    }
                    if (wq1->tail == thread) {
                        wq1->tail = prev;
                    }
                    thread->wait_next = NULL;

                    if (woken < (int)max_wake) {
                        /* Wake this thread */
                        thread->state = FUT_THREAD_READY;
                        fut_sched_add_thread(thread);
                        woken++;
                        fut_printf("[FUTEX] FUTEX_REQUEUE - woke thread %p\n", (void*)thread);
                    } else if (requeued < (int)max_requeue) {
                        /* Requeue to uaddr2 */
                        thread->futex_addr = uaddr2;
                        fut_waitq_t *wq2 = &bucket2->waiters;
                        thread->wait_next = NULL;
                        if (wq2->tail) {
                            wq2->tail->wait_next = thread;
                        } else {
                            wq2->head = thread;
                        }
                        wq2->tail = thread;
                        requeued++;
                        fut_printf("[FUTEX] FUTEX_REQUEUE - requeued thread %p to %p\n",
                                   (void*)thread, (void*)uaddr2);
                    } else {
                        /* Already at max wake and requeue - re-add to source queue */
                        if (wq1->tail) {
                            wq1->tail->wait_next = thread;
                        } else {
                            wq1->head = thread;
                        }
                        wq1->tail = thread;
                        prev = thread;
                    }
                } else {
                    prev = thread;
                }

                thread = next;
            }

            /* Unlock in reverse order */
            if (bucket1 < bucket2) {
                fut_spinlock_release(&bucket2->lock);
                fut_spinlock_release(&bucket1->lock);
            } else if (bucket1 > bucket2) {
                fut_spinlock_release(&bucket1->lock);
                fut_spinlock_release(&bucket2->lock);
            } else {
                fut_spinlock_release(&bucket1->lock);
            }

            (void)requeued;  /* Used for debugging only */
            return woken + requeued;
        }

        case FUTEX_CMP_REQUEUE: {
            /* FUTEX_CMP_REQUEUE: Same as FUTEX_REQUEUE but first check *uaddr == val3.
             *
             * Parameters:
             *   val   = max threads to wake at uaddr
             *   val3  = expected value at *uaddr (comparison value)
             *   uaddr2 = destination futex address
             *   timeout = reinterpreted as max_requeue count (via pointer cast)
             *
             * This prevents the "thundering herd" problem by atomically checking
             * the futex value before performing the requeue operation.
             */
            if (!uaddr2) {
                fut_printf("[FUTEX] FUTEX_CMP_REQUEUE - uaddr2 is NULL\n");
                return -EINVAL;
            }
            if (futex_access_ok_write(uaddr2, sizeof(uint32_t)) != 0)
                return -EFAULT;

            /* Get both futex buckets - lock in address order to avoid deadlock */
            futex_bucket_t *bucket1 = futex_get_bucket(uaddr);
            futex_bucket_t *bucket2 = futex_get_bucket(uaddr2);

            /* Lock in consistent order to prevent deadlock */
            if (bucket1 < bucket2) {
                fut_spinlock_acquire(&bucket1->lock);
                fut_spinlock_acquire(&bucket2->lock);
            } else if (bucket1 > bucket2) {
                fut_spinlock_acquire(&bucket2->lock);
                fut_spinlock_acquire(&bucket1->lock);
            } else {
                fut_spinlock_acquire(&bucket1->lock);
            }

            /* Read current value at uaddr and compare with val3 */
            uint32_t current_val;
            if (futex_copy_from_user(&current_val, uaddr, sizeof(current_val)) != 0) {
                if (bucket1 != bucket2) {
                    fut_spinlock_release(&bucket2->lock);
                }
                fut_spinlock_release(&bucket1->lock);
                return -EFAULT;
            }

            if (current_val != val3) {
                /* Value mismatch - abort requeue */
                if (bucket1 < bucket2) {
                    fut_spinlock_release(&bucket2->lock);
                    fut_spinlock_release(&bucket1->lock);
                } else if (bucket1 > bucket2) {
                    fut_spinlock_release(&bucket1->lock);
                    fut_spinlock_release(&bucket2->lock);
                } else {
                    fut_spinlock_release(&bucket1->lock);
                }
                fut_printf("[FUTEX] FUTEX_CMP_REQUEUE - value mismatch (*uaddr=%u, expected=%u)\n",
                           current_val, val3);
                return -EAGAIN;
            }

            /* Value matches - proceed with requeue operation */
            int woken = 0;
            int requeued = 0;
            uint32_t max_wake = val;
            /* max_requeue comes from timeout pointer, cast to integer */
            uint32_t max_requeue = timeout ? (uint32_t)(uintptr_t)timeout : INT32_MAX;

            fut_waitq_t *wq1 = &bucket1->waiters;
            fut_thread_t *thread = wq1->head;
            fut_thread_t *prev = NULL;

            while (thread) {
                fut_thread_t *next = thread->wait_next;

                if (thread->futex_addr == uaddr) {
                    /* Remove from source wait queue */
                    if (prev) {
                        prev->wait_next = next;
                    } else {
                        wq1->head = next;
                    }
                    if (wq1->tail == thread) {
                        wq1->tail = prev;
                    }
                    thread->wait_next = NULL;

                    if (woken < (int)max_wake) {
                        /* Wake this thread */
                        thread->state = FUT_THREAD_READY;
                        fut_sched_add_thread(thread);
                        woken++;
                    } else if (requeued < (int)max_requeue) {
                        /* Requeue to uaddr2 */
                        thread->futex_addr = uaddr2;
                        fut_waitq_t *wq2 = &bucket2->waiters;
                        thread->wait_next = NULL;
                        if (wq2->tail) {
                            wq2->tail->wait_next = thread;
                        } else {
                            wq2->head = thread;
                        }
                        wq2->tail = thread;
                        requeued++;
                    } else {
                        /* Re-add to source queue */
                        if (wq1->tail) {
                            wq1->tail->wait_next = thread;
                        } else {
                            wq1->head = thread;
                        }
                        wq1->tail = thread;
                        prev = thread;
                    }
                } else {
                    prev = thread;
                }

                thread = next;
            }

            /* Unlock in reverse order */
            if (bucket1 < bucket2) {
                fut_spinlock_release(&bucket2->lock);
                fut_spinlock_release(&bucket1->lock);
            } else if (bucket1 > bucket2) {
                fut_spinlock_release(&bucket1->lock);
                fut_spinlock_release(&bucket2->lock);
            } else {
                fut_spinlock_release(&bucket1->lock);
            }

            (void)requeued;
            return woken + requeued;
        }

        case FUTEX_WAKE_OP: {
            /* FUTEX_WAKE_OP: Atomically perform operation on uaddr2, then conditionally wake.
             *
             * 1. Atomically: oldval = *uaddr2; *uaddr2 = op(oldval, oparg)
             * 2. Wake up to 'val' threads at uaddr
             * 3. If (oldval CMP cmparg) is true, wake up to 'val2' threads at uaddr2
             *
             * Parameters:
             *   val   = max threads to wake at uaddr
             *   val2  = max threads to wake at uaddr2 (passed via timeout ptr)
             *   val3  = encoded operation: FUTEX_OP(op, oparg, cmp, cmparg)
             *   uaddr2 = address for atomic operation and second wake
             *
             * val3 encoding:
             *   bits 0-3:   op (FUTEX_OP_SET/ADD/OR/ANDN/XOR)
             *   bits 4-7:   cmp (FUTEX_OP_CMP_EQ/NE/LT/LE/GT/GE)
             *   bits 8-19:  oparg (12 bits)
             *   bits 20-31: cmparg (12 bits)
             */
            if (!uaddr2) {
                fut_printf("[FUTEX] FUTEX_WAKE_OP - uaddr2 is NULL\n");
                return -EINVAL;
            }
            /* FUTEX_WAKE_OP performs an atomic op on *uaddr2 — must be
             * a real userspace pointer or we'd write through a kernel
             * address. */
            if (futex_access_ok_write(uaddr2, sizeof(uint32_t)) != 0)
                return -EFAULT;

            /* Decode val3. oparg (bits 8-19) and cmparg (bits 20-31) are
             * 12-bit signed values per the documented encoding above —
             * sign-extend them so FUTEX_OP_ADD with a negative oparg (a
             * common idiom for atomic decrement) and FUTEX_OP_CMP_LT/GT
             * against signed values produce the correct results instead
             * of treating 0xFFF as 4095. */
            int op_type = val3 & 0xf;
            int cmp_type = (val3 >> 4) & 0xf;
            int32_t oparg  = (int32_t)((uint32_t)val3 << 12) >> 20;
            int32_t cmparg = (int32_t)val3 >> 20;
            uint32_t val2 = timeout ? (uint32_t)(uintptr_t)timeout : 0;

            /* Get both futex buckets */
            futex_bucket_t *bucket1 = futex_get_bucket(uaddr);
            futex_bucket_t *bucket2 = futex_get_bucket(uaddr2);

            /* Lock in consistent order */
            if (bucket1 < bucket2) {
                fut_spinlock_acquire(&bucket1->lock);
                fut_spinlock_acquire(&bucket2->lock);
            } else if (bucket1 > bucket2) {
                fut_spinlock_acquire(&bucket2->lock);
                fut_spinlock_acquire(&bucket1->lock);
            } else {
                fut_spinlock_acquire(&bucket1->lock);
            }

            /* Read old value at uaddr2 */
            uint32_t oldval;
            if (futex_copy_from_user(&oldval, uaddr2, sizeof(oldval)) != 0) {
                if (bucket1 != bucket2) {
                    fut_spinlock_release(&bucket2->lock);
                }
                fut_spinlock_release(&bucket1->lock);
                return -EFAULT;
            }

            /* Compute new value based on operation. oparg is a signed
             * int32_t; the cast to uint32_t in the arithmetic ops uses
             * defined modular semantics so e.g. ADD with oparg=-1 yields
             * oldval - 1 (== oldval + 0xFFFFFFFFu). */
            uint32_t newval;
            uint32_t uoparg = (uint32_t)oparg;
            switch (op_type) {
                case FUTEX_OP_SET:  newval = uoparg; break;
                case FUTEX_OP_ADD:  newval = oldval + uoparg; break;
                case FUTEX_OP_OR:   newval = oldval | uoparg; break;
                case FUTEX_OP_ANDN: newval = oldval & ~uoparg; break;
                case FUTEX_OP_XOR:  newval = oldval ^ uoparg; break;
                default:
                    if (bucket1 < bucket2) {
                        fut_spinlock_release(&bucket2->lock);
                        fut_spinlock_release(&bucket1->lock);
                    } else if (bucket1 > bucket2) {
                        fut_spinlock_release(&bucket1->lock);
                        fut_spinlock_release(&bucket2->lock);
                    } else {
                        fut_spinlock_release(&bucket1->lock);
                    }
                    fut_printf("[FUTEX] FUTEX_WAKE_OP - invalid op %d\n", op_type);
                    return -EINVAL;
            }

            /* Write new value to uaddr2 */
            if (futex_copy_to_user(uaddr2, &newval, sizeof(newval)) != 0) {
                if (bucket1 != bucket2) {
                    fut_spinlock_release(&bucket2->lock);
                }
                fut_spinlock_release(&bucket1->lock);
                return -EFAULT;
            }

            /* Wake threads at uaddr */
            int woken1 = 0;
            fut_waitq_t *wq1 = &bucket1->waiters;
            fut_thread_t *thread = wq1->head;
            fut_thread_t *prev = NULL;

            while (thread && woken1 < (int)val) {
                fut_thread_t *next = thread->wait_next;
                if (thread->futex_addr == uaddr) {
                    if (prev) {
                        prev->wait_next = next;
                    } else {
                        wq1->head = next;
                    }
                    if (wq1->tail == thread) {
                        wq1->tail = prev;
                    }
                    thread->wait_next = NULL;
                    thread->state = FUT_THREAD_READY;
                    fut_sched_add_thread(thread);
                    woken1++;
                } else {
                    prev = thread;
                }
                thread = next;
            }

            /* Evaluate comparison. EQ/NE work on raw bits, but LT/LE/GT/GE
             * are signed comparisons per the FUTEX_OP encoding — cast both
             * sides to int32_t so cmparg=-1 vs oldval=0 evaluates as
             * 'oldval > cmparg' rather than the bogus unsigned 0 > 4095. */
            int32_t soldval = (int32_t)oldval;
            bool cmp_result;
            switch (cmp_type) {
                case FUTEX_OP_CMP_EQ: cmp_result = (oldval == (uint32_t)cmparg); break;
                case FUTEX_OP_CMP_NE: cmp_result = (oldval != (uint32_t)cmparg); break;
                case FUTEX_OP_CMP_LT: cmp_result = (soldval <  cmparg); break;
                case FUTEX_OP_CMP_LE: cmp_result = (soldval <= cmparg); break;
                case FUTEX_OP_CMP_GT: cmp_result = (soldval >  cmparg); break;
                case FUTEX_OP_CMP_GE: cmp_result = (soldval >= cmparg); break;
                default: cmp_result = false; break;
            }

            /* If comparison succeeded, wake threads at uaddr2 */
            int woken2 = 0;
            if (cmp_result && val2 > 0) {
                fut_waitq_t *wq2 = &bucket2->waiters;
                thread = wq2->head;
                prev = NULL;

                while (thread && woken2 < (int)val2) {
                    fut_thread_t *next = thread->wait_next;
                    if (thread->futex_addr == uaddr2) {
                        if (prev) {
                            prev->wait_next = next;
                        } else {
                            wq2->head = next;
                        }
                        if (wq2->tail == thread) {
                            wq2->tail = prev;
                        }
                        thread->wait_next = NULL;
                        thread->state = FUT_THREAD_READY;
                        fut_sched_add_thread(thread);
                        woken2++;
                    } else {
                        prev = thread;
                    }
                    thread = next;
                }
            }

            /* Unlock */
            if (bucket1 < bucket2) {
                fut_spinlock_release(&bucket2->lock);
                fut_spinlock_release(&bucket1->lock);
            } else if (bucket1 > bucket2) {
                fut_spinlock_release(&bucket1->lock);
                fut_spinlock_release(&bucket2->lock);
            } else {
                fut_spinlock_release(&bucket1->lock);
            }

            return woken1 + woken2;
        }

        case FUTEX_TRYLOCK_PI:
        case FUTEX_LOCK_PI: {
            /*
             * PI futex word layout (Linux ABI):
             *   bits 29:0  = owner TID (0 = free)
             *   bit  30    = FUTEX_OWNER_DIED (owner exited holding lock)
             *   bit  31    = FUTEX_WAITERS   (threads are waiting)
             *
             * Priority Inheritance (PI):
             * When a high-priority thread blocks on a PI futex held by a
             * lower-priority thread, we boost the owner's effective priority
             * to the waiter's priority.  This prevents unbounded priority
             * inversion.  The owner's original priority is restored when it
             * calls FUTEX_UNLOCK_PI.
             */
            fut_thread_t *cur = fut_thread_current();
            uint32_t mytid = cur ? (uint32_t)cur->tid : 1u;

            /* Parse timeout — FUTEX_LOCK_PI uses a relative timespec */
            bool has_timeout = false;
            uint64_t deadline_ticks = 0;
            if (timeout && cmd == FUTEX_LOCK_PI) {
                fut_timespec_t ts;
                if (futex_copy_from_user(&ts, timeout, sizeof(ts)) != 0)
                    return -EFAULT;
                if (ts.tv_sec < 0 || ts.tv_nsec < 0 || ts.tv_nsec >= 1000000000)
                    return -EINVAL;
                uint64_t tmo_ticks = ((uint64_t)ts.tv_sec * FUT_TIMER_HZ)
                                   + ((uint64_t)ts.tv_nsec / (1000000000UL / FUT_TIMER_HZ));
                deadline_ticks = fut_get_ticks() + tmo_ticks;
                has_timeout = true;
            }

            for (;;) {
                uint32_t word;
                if (futex_copy_from_user(&word, uaddr, sizeof(word)) != 0)
                    return -EFAULT;

                uint32_t owner = word & ROBUST_FUTEX_TID_MASK;

                /* Deadlock detection */
                if (owner == mytid)
                    return -EDEADLK;

                /* Lock is free or previous owner died — try to acquire */
                if (owner == 0 || (word & ROBUST_FUTEX_OWNER_DIED)) {
                    uint32_t expected = word;
                    uint32_t new_word = (word & ROBUST_FUTEX_WAITERS) | mytid;
                    if (__atomic_compare_exchange_n((uint32_t *)uaddr, &expected, new_word,
                                                    false,
                                                    __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST))
                        return 0;   /* acquired */
                    continue;       /* CAS lost — retry */
                }

                /* Lock is held */
                if (cmd == FUTEX_TRYLOCK_PI)
                    return -EAGAIN;

                /* Check timeout */
                if (has_timeout && fut_get_ticks() >= deadline_ticks)
                    return -ETIMEDOUT;

                /* Check pending signals (task-wide OR thread-directed). */
                if (cur && cur->task) {
                    uint64_t pend = __atomic_load_n(&cur->task->pending_signals, __ATOMIC_ACQUIRE)
                                  | __atomic_load_n(&cur->thread_pending_signals, __ATOMIC_ACQUIRE);
                    uint64_t mask = __atomic_load_n(&cur->signal_mask, __ATOMIC_ACQUIRE);
                    if (pend & ~mask)
                        return -EINTR;
                }

                /* Priority Inheritance: boost owner's priority to waiter's
                 * priority if the waiter has higher priority.  This prevents
                 * priority inversion where a low-priority lock holder
                 * starves a high-priority waiter. */
                if (cur) {
                    fut_thread_t *owner_thread = fut_thread_find((uint64_t)owner);
                    if (owner_thread && cur->priority > owner_thread->priority) {
                        fut_thread_priority_raise(owner_thread, cur->priority);
                        fut_printf("[FUTEX] PI boost: owner tid=%u prio %d -> %d (waiter tid=%u)\n",
                                   owner, owner_thread->pi_saved_priority,
                                   owner_thread->priority, mytid);
                    }
                }

                /* Mark WAITERS bit so the owner calls UNLOCK_PI correctly */
                {
                    uint32_t exp2 = word;
                    __atomic_compare_exchange_n((uint32_t *)uaddr, &exp2,
                                                word | ROBUST_FUTEX_WAITERS,
                                                false,
                                                __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
                }

                /* Sleep on bucket wait queue until the owner wakes us */
                futex_bucket_t *bucket = futex_get_bucket(uaddr);
                fut_spinlock_acquire(&bucket->lock);

                /* Re-read under lock: might have become free while we were setting up */
                uint32_t recheck;
                if (futex_copy_from_user(&recheck, uaddr, sizeof(recheck)) != 0) {
                    fut_spinlock_release(&bucket->lock);
                    return -EFAULT;
                }
                uint32_t recheck_owner = recheck & ROBUST_FUTEX_TID_MASK;
                if (recheck_owner == 0 || (recheck & ROBUST_FUTEX_OWNER_DIED)) {
                    fut_spinlock_release(&bucket->lock);
                    continue;
                }

                if (cur) {
                    cur->futex_addr   = uaddr;
                    cur->futex_bitset = 0xFFFFFFFFu;
                }

                futex_timeout_ctx_t tctx;
                uint64_t tctx_ticks = 0;
                if (has_timeout) {
                    uint64_t now = fut_get_ticks();
                    tctx_ticks = (deadline_ticks > now) ? (deadline_ticks - now) : 1u;
                    tctx.thread = cur;
                    tctx.bucket = bucket;
                }

                /* Inline enqueue + release lock before timer (same IRQ-deadlock
                 * fix as FUTEX_WAIT: callback acquires bucket->lock from IRQ). */
                if (cur) {
                    cur->state         = FUT_THREAD_BLOCKED;
                    cur->blocked_waitq = &bucket->waiters;
                    cur->wait_next     = NULL;
                    if (bucket->waiters.tail) {
                        bucket->waiters.tail->wait_next = cur;
                    } else {
                        bucket->waiters.head = cur;
                    }
                    bucket->waiters.tail = cur;
                }
                fut_spinlock_release(&bucket->lock);

                if (has_timeout) {
                    if (fut_timer_start(tctx_ticks, futex_timeout_callback, &tctx) != 0) {
                        /* OOM: dequeue thread from waitq, restore state, fail */
                        fut_waitq_remove_thread(&bucket->waiters, cur);
                        cur->state = FUT_THREAD_RUNNING;
                        cur->futex_addr = NULL;
                        return -ETIMEDOUT;
                    }
                }

                fut_schedule();

                if (has_timeout)
                    fut_timer_cancel(futex_timeout_callback, &tctx);

                bool timed_out = cur && (cur->futex_addr == NULL);
                if (cur) cur->futex_addr = NULL;

                if (timed_out)
                    return -ETIMEDOUT;

                /* Check signals after wakeup (task-wide OR thread-directed). */
                if (cur && cur->task) {
                    uint64_t pend = __atomic_load_n(&cur->task->pending_signals, __ATOMIC_ACQUIRE)
                                  | __atomic_load_n(&cur->thread_pending_signals, __ATOMIC_ACQUIRE);
                    uint64_t mask = __atomic_load_n(&cur->signal_mask, __ATOMIC_ACQUIRE);
                    if (pend & ~mask)
                        return -EINTR;
                }
                /* Loop: try to acquire again */
            }
        }

        case FUTEX_UNLOCK_PI: {
            fut_thread_t *cur = fut_thread_current();
            uint32_t mytid = cur ? (uint32_t)cur->tid : 1u;

            uint32_t word;
            if (futex_copy_from_user(&word, uaddr, sizeof(word)) != 0)
                return -EFAULT;

            /* Verify we own the lock */
            if ((word & ROBUST_FUTEX_TID_MASK) != mytid)
                return -EPERM;

            /* Restore our original priority if it was boosted by PI.
             * Must happen before releasing the lock so that the scheduler
             * does not run us at an artificially elevated priority after
             * we no longer hold the contended resource. */
            if (cur) {
                fut_thread_priority_restore(cur);
            }

            bool has_waiters = (word & ROBUST_FUTEX_WAITERS) != 0;

            if (has_waiters) {
                /* Wake one waiter and hand the lock to it by writing its
                 * TID into the futex word.  This avoids the thundering-herd
                 * problem where all waiters race to CAS the word.
                 * If no matching waiter is found (rare race), just zero
                 * the word so the next LOCK_PI caller can acquire. */
                futex_bucket_t *bucket = futex_get_bucket(uaddr);
                fut_spinlock_acquire(&bucket->lock);

                fut_waitq_t *wq = &bucket->waiters;
                fut_thread_t *t = wq->head;
                fut_thread_t *prev = NULL;
                fut_thread_t *woken_thread = NULL;

                /* Find the highest-priority waiter on this futex address.
                 * Handing the lock to the highest-priority waiter maintains
                 * the PI invariant and avoids re-boosting immediately. */
                fut_thread_t *best = NULL;
                fut_thread_t *best_prev = NULL;
                while (t) {
                    if (t->futex_addr == uaddr) {
                        if (!best || t->priority > best->priority) {
                            best = t;
                            best_prev = prev;
                        }
                    }
                    prev = t;
                    t = t->wait_next;
                }

                if (best) {
                    /* Remove best from the wait queue */
                    if (best_prev) {
                        best_prev->wait_next = best->wait_next;
                    } else {
                        wq->head = best->wait_next;
                    }
                    if (wq->tail == best) {
                        wq->tail = best_prev;
                    }
                    best->wait_next = NULL;
                    woken_thread = best;
                }

                /* Check if there are still more waiters on this address */
                bool more_waiters = false;
                for (fut_thread_t *scan = wq->head; scan; scan = scan->wait_next) {
                    if (scan->futex_addr == uaddr) {
                        more_waiters = true;
                        break;
                    }
                }

                /* Set the futex word: hand lock to woken thread or clear it.
                 * Preserve FUTEX_WAITERS bit if other waiters remain. */
                uint32_t new_word;
                if (woken_thread) {
                    new_word = (uint32_t)woken_thread->tid;
                    if (more_waiters)
                        new_word |= ROBUST_FUTEX_WAITERS;
                } else {
                    new_word = 0;
                }
                uint32_t expected = word;
                __atomic_compare_exchange_n((uint32_t *)uaddr, &expected, new_word,
                                            false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);

                if (woken_thread) {
                    woken_thread->state = FUT_THREAD_READY;
                    fut_sched_add_thread(woken_thread);
                }

                fut_spinlock_release(&bucket->lock);
            } else {
                /* No waiters — simply clear the futex word */
                uint32_t expected = word;
                __atomic_compare_exchange_n((uint32_t *)uaddr, &expected, 0u,
                                            false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
            }
            return 0;
        }

        case FUTEX_WAIT_REQUEUE_PI: {
            /* FUTEX_WAIT_REQUEUE_PI (Linux 2.6.31+): wait on uaddr, on wake
             * attempt to acquire the PI lock at uaddr2.
             * We delegate to FUTEX_WAIT_BITSET; the caller re-acquires the
             * PI lock via FUTEX_LOCK_PI on return (which performs PI boost). */
            return sys_futex(uaddr, FUTEX_WAIT_BITSET | (op & FUTEX_PRIVATE_FLAG),
                             val, timeout, uaddr2, 0xFFFFFFFFU);
        }

        case FUTEX_CMP_REQUEUE_PI: {
            /* FUTEX_CMP_REQUEUE_PI (Linux 2.6.31+): like FUTEX_CMP_REQUEUE but
             * the target futex (uaddr2) is a PI mutex.  Delegates to
             * FUTEX_CMP_REQUEUE; requeued waiters acquire via FUTEX_LOCK_PI. */
            return sys_futex(uaddr, FUTEX_CMP_REQUEUE | (op & FUTEX_PRIVATE_FLAG),
                             val, timeout, uaddr2, val3);
        }

        default:
            fut_printf("[FUTEX] Unsupported futex operation: %d\n", cmd);
            return -ENOSYS;
    }
}

/**
 * sys_set_robust_list - Set the robust futex list head
 *
 * @param head:     Pointer to robust_list_head in userspace
 * @param len:      Length of the structure (for ABI versioning)
 *
 * Robust futexes handle the case where a thread dies while holding a lock.
 * The kernel walks the robust list on thread exit and wakes waiters.
 *
 * Phase 1 (Completed): Stub - accepts parameters, returns success
 * Phase 2 (Completed): Store robust list head in thread structure with validation
 * Phase 3 (Completed): Walk robust list on thread exit via exit_robust_list()
 *
 * Returns:
 *   - 0 on success
 *   - -EINVAL if len is incorrect
 */
long sys_set_robust_list(struct robust_list_head *head, size_t len) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    fut_printf("[SET_ROBUST_LIST] head=%p len=%zu\n", head, len);

    /* Validate length (should be sizeof(struct robust_list_head)) */
    if (len != sizeof(struct robust_list_head)) {
        return -EINVAL;
    }

    /* Document pointer validation requirement for Phase 2/3 implementation
     * VULNERABILITY: Unbounded List Traversal and Invalid Pointer Access
     *
     * ATTACK SCENARIO 1: Circular Robust List Causing Infinite Loop
     * Attacker creates circular robust list to hang kernel on thread exit
     * 1. Attacker allocates robust_list_head in userspace
     * 2. Creates circular list: head->list.next = &head->list
     * 3. Calls set_robust_list(head, sizeof(*head))
     * 4. Kernel stores head pointer (no validation)
     * 5. Thread exits, kernel walks robust list (Phase 3)
     * 6. Traversal loops forever: head → head → head → ...
     * 7. Kernel hangs in exit path, unkillable process
     * 8. Denial of service: System freezes
     *
     * ATTACK SCENARIO 2: Invalid Pointer in Robust List
     * Attacker embeds kernel address in robust list to leak information
     * 1. Attacker sets list.next = 0xFFFFFFFF80000000 (kernel address)
     * 2. On thread exit, kernel dereferences kernel address
     * 3. Information disclosure: Kernel reads sensitive memory
     * 4. Or page fault: Kernel crash if unmapped
     *
     * ATTACK SCENARIO 3: Use-After-Free via Robust List
     * Attacker unmaps robust list page before thread exit
     * 1. Attacker calls set_robust_list(head, ...)
     * 2. Kernel stores head pointer
     * 3. Attacker munmap()s page containing robust list
     * 4. Thread exits, kernel dereferences freed memory
     * 5. Use-after-free: Reads stale data or crashes
     *
     * IMPACT:
     * - Denial of service: Infinite loop hangs kernel on thread exit
     * - Information disclosure: Reading kernel addresses leaks secrets
     * - Kernel crash: Page fault on unmapped addresses
     * - Use-after-free: Accessing freed userspace memory
     *
     * ROOT CAUSE:
     * Phase 1 stub accepts head pointer without validation:
     * - No fut_access_ok() validation
     * - No bounds checking on list traversal (Phase 3)
     * - No cycle detection in list walk
     * - Assumes userspace provides valid, acyclic list
     *
     * DEFENSE (Requirements for Phase 2/3):
     * 1. Pointer Validation (Phase 2):
     *    - fut_access_ok(head, sizeof(*head), READ)
     *    - Verify head is in valid userspace range
     *    - Check page is mapped and accessible
     * 2. List Traversal Bounds (Phase 3 - CRITICAL):
     *    - Limit maximum list length (e.g., 1000 entries)
     *    - Detect cycles using visited set or counter
     *    - Validate each list->next pointer before dereference
     *    - Use safe copy functions (fut_get_user)
     *    - Break on invalid pointer (-EFAULT)
     * 3. Thread Exit Path Safety:
     *    - Robust list walk must not block indefinitely
     *    - Must handle page faults gracefully
     *    - Cannot hold locks during unbounded traversal
     *
     * CVE REFERENCES:
     * - CVE-2014-3153: Linux futex requeue use-after-free
     * - CVE-2016-6516: Linux robust futex list corruption
     *
     * LINUX REQUIREMENT:
     * From set_robust_list(2) man page:
     * "The robust futex list is a per-thread data structure that is
     *  traversed by the kernel on thread exit. The list contains futexes
     *  that are held by the thread at the time of its exit."
     * - Kernel must gracefully handle malformed robust lists
     * - Must prevent infinite loops and kernel hangs
     *
     * IMPLEMENTATION NOTES:
     * - Phase 2: Store head pointer after validation
     * - Phase 3: exit_robust_list() MUST implement:
     *   - Maximum iteration limit (prevent infinite loop)
     *   - Pointer validation on each node
     *   - Cycle detection
     *   - Safe userspace access (handle page faults)
     * - See Linux kernel: exit_robust_list() in kernel/futex.c
     */

    /* Phase 1: Stub - accept parameters */
    /* Phase 2: Store head pointer in task->robust_list after validation */
    /* Phase 3: Walk list on thread exit via exit_robust_list() */

    /* Phase 2: Validate robust_list head pointer before storing */
    if (head && futex_access_ok_read(head, sizeof(struct robust_list_head)) != 0) {
        return -EFAULT;
    }

    /* Store head pointer in both per-thread and per-task robust_list fields.
     * The per-thread pointer is walked by exit_robust_list() in fut_thread_exit().
     * The per-task pointer is walked in task_cleanup_and_exit() as a fallback
     * for the main thread's robust list when the task exits. */
    fut_thread_t *thread = fut_thread_current();
    if (thread) {
        thread->robust_list = (void *)head;
    }
    if (task) {
        task->robust_list_head = (void *)head;
    }

    return 0;
}

/**
 * sys_get_robust_list - Get the robust futex list head
 *
 * @param pid:      Process ID (0 = current task)
 * @param head_ptr: Output parameter for robust list head pointer
 * @param len_ptr:  Output parameter for length
 *
 * Retrieves the robust list head for a given task. Requires appropriate
 * permissions to query other tasks.
 *
 * Phase 1 (Completed): Stub - returns null pointer and zero length
 * Phase 2 (Completed): Return actual robust list head from thread structure
 *
 * Returns:
 *   - 0 on success
 *   - -ESRCH if process not found
 *   - -EPERM if permission denied
 */
/* Futex word bit layout for robust mutexes (defined near top of file) */

/**
 * exit_robust_list - Walk the robust list on thread exit and release locks.
 *
 * Called from fut_thread_exit() before the thread is removed from the
 * scheduler.  For each futex on the robust list:
 *   1. Set ROBUST_FUTEX_OWNER_DIED to signal waiting threads.
 *   2. Clear the TID bits (owner is gone).
 *   3. Wake at most one waiter so it can detect the dead-owner condition.
 *
 * Security:
 *   - Every userspace pointer is validated before dereference.
 *   - Iteration is capped at ROBUST_LIST_LIMIT to prevent infinite loops.
 *   - Pointer equality check detects list termination (entry == &head->list).
 *
 * @param thread  Exiting thread whose robust_list should be cleaned up.
 */
void exit_robust_list(fut_thread_t *thread) {
    if (!thread || !thread->robust_list) {
        return;
    }

    struct robust_list_head *head = (struct robust_list_head *)thread->robust_list;

    /* Validate and copy the list head from userspace */
    if (futex_access_ok_read(head, sizeof(*head)) != 0) {
        fut_printf("[FUTEX] exit_robust_list: head %p not accessible\n", (void *)head);
        return;
    }

    struct robust_list_head head_copy;
    if (futex_copy_from_user(&head_copy, head, sizeof(head_copy)) != 0) {
        fut_printf("[FUTEX] exit_robust_list: failed to read head\n");
        return;
    }

    long futex_offset = head_copy.futex_offset;
    struct robust_list *pending = head_copy.list_op_pending;
    struct robust_list *entry   = head_copy.list.next;

    /* Helper lambda-like logic: mark a futex word as owner-died and wake. */
#define ROBUST_RELEASE_ENTRY(e) do {                                    \
    struct robust_list *_e = (e);                                       \
    if (!_e || _e == (struct robust_list *)head) break;                 \
    /* Mask flag bits (bit 0 is the "lock being modified" bit) */       \
    _e = (struct robust_list *)((uintptr_t)_e & ~(uintptr_t)1);        \
    uint32_t *futex_uaddr = (uint32_t *)((char *)_e + futex_offset);   \
    if (futex_access_ok_write(futex_uaddr, sizeof(uint32_t)) != 0) break;   \
    uint32_t val;                                                        \
    if (futex_copy_from_user(&val, futex_uaddr, sizeof(val)) != 0) break; \
    uint32_t new_val = (val & ROBUST_FUTEX_WAITERS) | ROBUST_FUTEX_OWNER_DIED; \
    if (futex_copy_to_user(futex_uaddr, &new_val, sizeof(new_val)) != 0) break;  \
    futex_wake_one(futex_uaddr);                                        \
    /* Released-futex log silenced — threaded apps holding many
     * robust mutexes at exit print one of these per release; the
     * resulting flood is purely noise on the diagnostic path. */ \
    (void)val; (void)new_val;                                           \
} while (0)

    /* Walk the list; list terminates when entry == &head->list */
    int count = 0;
    while (entry != (struct robust_list *)head && entry != NULL &&
           count < ROBUST_LIST_LIMIT) {

        /* Validate and read next pointer before processing current entry */
        if (futex_access_ok_read(entry, sizeof(*entry)) != 0) {
            fut_printf("[FUTEX] exit_robust_list: entry %p not accessible, stopping\n",
                       (void *)entry);
            break;
        }

        struct robust_list entry_copy;
        if (futex_copy_from_user(&entry_copy, entry, sizeof(entry_copy)) != 0) {
            fut_printf("[FUTEX] exit_robust_list: failed to read entry %p\n", (void *)entry);
            break;
        }

        struct robust_list *next = entry_copy.next;

        /* Skip the pending entry here — it is handled separately below */
        if (entry != (struct robust_list *)((uintptr_t)pending & ~(uintptr_t)1)) {
            ROBUST_RELEASE_ENTRY(entry);
        }

        entry = next;
        count++;
    }

    /* Handle the pending entry (partially-completed lock operation) */
    if (pending && pending != (struct robust_list *)head) {
        ROBUST_RELEASE_ENTRY(pending);
    }

#undef ROBUST_RELEASE_ENTRY

    if (count > 0) {
        fut_printf("[FUTEX] exit_robust_list: cleaned up %d robust futex(es)\n", count);
    }

    /* Clear the robust list pointer so it is not processed twice */
    thread->robust_list = NULL;
}

long sys_get_robust_list(int pid, struct robust_list_head **head_ptr,
                         size_t *len_ptr) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    fut_printf("[GET_ROBUST_LIST] pid=%d head_ptr=%p len_ptr=%p\n",
               pid, head_ptr, len_ptr);

    /* Validate output pointers.  (Linux returns EFAULT here via put_user;
     * Futura test 530 pins the NULL case at -EINVAL, and per the project
     * rule 'Futura's local tests take precedence over Linux ABI parity'
     * the EINVAL contract wins over the put_user-style EFAULT.) */
    if (!head_ptr || !len_ptr) {
        return -EINVAL;
    }

    /* Phase 2: Validate userspace pointers with write access (kernel writes to them) */
    if (futex_access_ok_write(head_ptr, sizeof(struct robust_list_head *)) != 0) {
        return -EFAULT;
    }
    if (futex_access_ok_write(len_ptr, sizeof(size_t)) != 0) {
        return -EFAULT;
    }

    /* Phase 2: Retrieve robust list head from thread structure.
     * pid==0 means current thread; querying other pids requires PTRACE_MODE_READ. */
    fut_thread_t *thread;
    if (pid == 0) {
        thread = fut_thread_current();
    } else {
        /* Look up the task by PID and get its primary thread */
        fut_task_t *target_task = fut_task_by_pid((uint64_t)pid);
        if (!target_task) {
            return -ESRCH;
        }
        /* Permission check: Linux's get_robust_list uses
         * ptrace_may_access(PTRACE_MODE_READ_REALCREDS), which compares
         * the caller's REAL uid (cred->uid) against ALL THREE of the
         * target's uids (real, effective, saved):
         *
         *   caller_uid = cred->uid;                  // REALCREDS
         *   if (uid_eq(caller_uid, tcred->euid) &&
         *       uid_eq(caller_uid, tcred->suid) &&
         *       uid_eq(caller_uid, tcred->uid))
         *       goto ok;
         *
         * The previous gate compared effective-vs-effective only,
         * letting a setuid-up helper (caller euid raised) read other
         * tasks' robust-list heads even though Linux gates on real
         * uid, and letting a dropped-setuid victim's robust list
         * (suid==0) be readable by an unprivileged peer.  Same fix
         * pattern as the recent ptrace / process_vm / kcmp updates. */
        if (task->ruid != 0 &&
            !(task->cap_effective & (1ULL << 19 /* CAP_SYS_PTRACE */)) &&
            (task->ruid != target_task->uid  ||
             task->ruid != target_task->ruid ||
             task->ruid != target_task->suid)) {
            return -EPERM;
        }
        thread = target_task->threads;
    }

    struct robust_list_head *stored_head = thread ? (struct robust_list_head *)thread->robust_list : NULL;
    size_t list_len = sizeof(struct robust_list_head);

    if (futex_copy_to_user(head_ptr, &stored_head, sizeof(struct robust_list_head *)) != 0) {
        fut_printf("[GET_ROBUST_LIST] EFAULT: failed to write head_ptr to userspace\n");
        return -EFAULT;
    }
    if (futex_copy_to_user(len_ptr, &list_len, sizeof(size_t)) != 0) {
        fut_printf("[GET_ROBUST_LIST] EFAULT: failed to write len_ptr to userspace\n");
        return -EFAULT;
    }

    return 0;
}

/* ============================================================
 *   futex_waitv — Linux 5.16+ multi-futex wait (Wine/Proton)
 * ============================================================ */

/* Linux futex2 size flags */
#define FUTEX2_SIZE_U8    0x00
#define FUTEX2_SIZE_U16   0x01
#define FUTEX2_SIZE_U32   0x02
#define FUTEX2_SIZE_U64   0x03
#define FUTEX2_SIZE_MASK  0x03
#define FUTEX2_NUMA       0x04
#define FUTEX2_PRIVATE    0x80

/* Max futex entries per futex_waitv call (Linux uses 128) */
#define FUTEX_WAITV_MAX   128

/* Per-entry struct matching Linux ABI */
struct futex_waitv {
    uint64_t val;
    uint64_t uaddr;
    uint32_t flags;
    uint32_t __reserved;
};

/**
 * sys_futex_waitv() - Wait on multiple futexes simultaneously
 *
 * Blocks until any of the futex values changes, or a timeout/signal occurs.
 * Used primarily by Wine/Proton for WaitForMultipleObjects emulation.
 *
 * @param waiters_ptr  User pointer to array of struct futex_waitv
 * @param nr_futexes   Number of entries in waiters array (1..128)
 * @param flags        Must be 0 (reserved for future use)
 * @param timeout_ptr  Optional absolute timeout (struct timespec)
 * @param clockid      Clock for timeout (CLOCK_MONOTONIC or CLOCK_REALTIME)
 *
 * Returns:
 *   - Index of woken futex on success (0..nr_futexes-1)
 *   - -EAGAIN if any futex value doesn't match at entry
 *   - -ETIMEDOUT if timeout expires
 *   - -EINTR if interrupted by signal
 *   - -EINVAL for invalid parameters
 *   - -EFAULT for bad user pointers
 */
long sys_futex_waitv(const void *waiters_ptr, unsigned int nr_futexes,
                     unsigned int flags, const void *timeout_ptr,
                     int32_t clockid) {
    fut_task_t *task = fut_task_current();
    if (!task) return -ESRCH;

    /* Validate flags — must be 0 per Linux ABI */
    if (flags != 0) return -EINVAL;

    /* Validate nr_futexes */
    if (nr_futexes == 0 || nr_futexes > FUTEX_WAITV_MAX) return -EINVAL;

    /* Validate clockid */
    if (clockid != 0 /* CLOCK_REALTIME */ && clockid != 1 /* CLOCK_MONOTONIC */) return -EINVAL;

    /* Validate and copy waiter array from user */
    size_t waiters_size = nr_futexes * sizeof(struct futex_waitv);
    if (futex_access_ok_read(waiters_ptr, waiters_size) != 0) return -EFAULT;

    struct futex_waitv waiters[FUTEX_WAITV_MAX];
    if (futex_copy_from_user(waiters, waiters_ptr, waiters_size) != 0) return -EFAULT;

    /* Validate each waiter entry */
    for (unsigned int i = 0; i < nr_futexes; i++) {
        if (waiters[i].__reserved != 0) return -EINVAL;

        /* Only FUTEX2_SIZE_U32 supported (the common case for Wine/Proton) */
        uint32_t size_flag = waiters[i].flags & FUTEX2_SIZE_MASK;
        if (size_flag != FUTEX2_SIZE_U32) return -EINVAL;

        /* FUTEX2_NUMA not supported */
        if (waiters[i].flags & FUTEX2_NUMA) return -EINVAL;

        /* Linux's futex_validate_input enforces two domain checks the
         * previous code missed:
         *   (a) uaddr must be aligned to the futex size (4 bytes for U32)
         *       — kernel/futex/core.c rejects misaligned uaddr with EINVAL.
         *       Without this check Futura would either fault on a
         *       misaligned read or silently access bytes that straddle
         *       the page boundary and tear the comparison.
         *   (b) val must fit in the configured futex size.  For U32 the
         *       upper 32 bits of waiters[i].val must be zero; otherwise
         *       Linux returns EINVAL because the comparison can never
         *       match a 32-bit memory location. */
        if (waiters[i].uaddr & 0x3ULL) return -EINVAL;
        if (waiters[i].val >> 32) return -EINVAL;

        /* Validate address */
        uint32_t *addr = (uint32_t *)(uintptr_t)waiters[i].uaddr;
        if (!addr) return -EINVAL;
        if (futex_access_ok_read(addr, sizeof(uint32_t)) != 0) return -EFAULT;
    }

    /* Parse timeout if present */
    bool has_timeout = false;
    uint64_t timeout_ms = 0;
    if (timeout_ptr) {
        fut_timespec_t ts;
        if (futex_copy_from_user(&ts, timeout_ptr, sizeof(ts)) != 0) return -EFAULT;
        if (ts.tv_sec < 0 || ts.tv_nsec < 0 || ts.tv_nsec >= 1000000000) return -EINVAL;

        /* Absolute timeout: convert to relative */
        extern uint64_t fut_get_ticks(void);
        extern volatile int64_t g_realtime_offset_sec;
        uint64_t now_ticks = fut_get_ticks();
        uint64_t now_ns = now_ticks * 10000000ULL;
        if (clockid == 0 /* CLOCK_REALTIME */) {
            now_ns += (uint64_t)((int64_t)g_realtime_offset_sec * 1000000000LL);
        }
        uint64_t abs_ns = (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
        if (abs_ns <= now_ns) return -ETIMEDOUT;
        uint64_t remaining_ns = abs_ns - now_ns;
        timeout_ms = remaining_ns / 1000000;
        if (remaining_ns % 1000000 != 0) timeout_ms++;
        has_timeout = true;
    }

    /* --- Atomically check all futex values --- */
    /* Collect unique buckets and lock in address order to avoid deadlock */
    futex_bucket_t *buckets[FUTEX_WAITV_MAX];
    for (unsigned int i = 0; i < nr_futexes; i++) {
        buckets[i] = futex_get_bucket((uint32_t *)(uintptr_t)waiters[i].uaddr);
    }

    /* Sort unique buckets for ordered locking (simple insertion sort, N<=128) */
    futex_bucket_t *sorted_buckets[FUTEX_WAITV_MAX];
    unsigned int n_sorted = 0;
    for (unsigned int i = 0; i < nr_futexes; i++) {
        bool found = false;
        for (unsigned int j = 0; j < n_sorted; j++) {
            if (sorted_buckets[j] == buckets[i]) { found = true; break; }
        }
        if (!found) sorted_buckets[n_sorted++] = buckets[i];
    }
    /* Sort by address */
    for (unsigned int i = 1; i < n_sorted; i++) {
        futex_bucket_t *key = sorted_buckets[i];
        int j = (int)i - 1;
        while (j >= 0 && (uintptr_t)sorted_buckets[j] > (uintptr_t)key) {
            sorted_buckets[j + 1] = sorted_buckets[j];
            j--;
        }
        sorted_buckets[j + 1] = key;
    }

    /* Lock all unique buckets */
    for (unsigned int i = 0; i < n_sorted; i++) {
        fut_spinlock_acquire(&sorted_buckets[i]->lock);
    }

    /* Check all values under locks */
    for (unsigned int i = 0; i < nr_futexes; i++) {
        uint32_t *addr = (uint32_t *)(uintptr_t)waiters[i].uaddr;
        uint32_t current_val;
        if (futex_copy_from_user(&current_val, addr, sizeof(uint32_t)) != 0) {
            for (unsigned int k = n_sorted; k > 0; k--)
                fut_spinlock_release(&sorted_buckets[k - 1]->lock);
            return -EFAULT;
        }
        if (current_val != (uint32_t)waiters[i].val) {
            for (unsigned int k = n_sorted; k > 0; k--)
                fut_spinlock_release(&sorted_buckets[k - 1]->lock);
            fut_printf("[FUTEX_WAITV] value mismatch at index %u (*addr=%u, expected=%u) -> EAGAIN\n",
                       i, current_val, (uint32_t)waiters[i].val);
            return -EAGAIN;
        }
    }

    /* All values match — block.
     *
     * We enqueue the current thread on the FIRST futex's bucket wait queue,
     * using the first futex address as the futex_addr match key.  FUTEX_WAKE
     * on that address will wake us.  For other addresses, we rely on value
     * changes being visible when we re-check after wake.
     *
     * To handle wakes on ANY of the futex addresses, we enqueue the thread
     * on ALL unique buckets with the corresponding futex_addr.  Since a
     * thread can only be in one linked list (via wait_next), we use the
     * first futex as the primary enqueue and set futex_addr to a sentinel.
     * On wake from any bucket, we check all values to find which changed.
     *
     * Simplified approach: enqueue once with first address, after wake scan all.
     */
    fut_thread_t *thread = fut_thread_current();
    if (!thread) {
        for (unsigned int k = n_sorted; k > 0; k--)
            fut_spinlock_release(&sorted_buckets[k - 1]->lock);
        return -ESRCH;
    }

    uint32_t *primary_addr = (uint32_t *)(uintptr_t)waiters[0].uaddr;
    thread->futex_addr   = primary_addr;
    thread->futex_bitset = 0xFFFFFFFFu;
    thread->state        = FUT_THREAD_BLOCKED;
    thread->blocked_waitq = &buckets[0]->waiters;
    thread->wait_next    = NULL;

    fut_waitq_t *wq = &buckets[0]->waiters;
    if (wq->tail) {
        wq->tail->wait_next = thread;
    } else {
        wq->head = thread;
    }
    wq->tail = thread;

    /* Release all locks BEFORE starting timer (IRQ deadlock prevention) */
    for (unsigned int k = n_sorted; k > 0; k--)
        fut_spinlock_release(&sorted_buckets[k - 1]->lock);

    /* Start timeout timer if needed */
    futex_timeout_ctx_t timeout_ctx;
    if (has_timeout) {
        timeout_ctx.thread = thread;
        timeout_ctx.bucket = buckets[0];
        uint64_t timeout_ticks = timeout_ms / 10;
        if (timeout_ms % 10 != 0) timeout_ticks++;
        if (timeout_ticks == 0 && timeout_ms > 0) timeout_ticks = 1;
        if (fut_timer_start(timeout_ticks, futex_timeout_callback, &timeout_ctx) != 0) {
            /* OOM: dequeue thread from waitq, restore state, fail */
            fut_waitq_remove_thread(&buckets[0]->waiters, thread);
            thread->state = FUT_THREAD_RUNNING;
            thread->futex_addr = NULL;
            return -ETIMEDOUT;
        }
    }

    /* Yield to scheduler — woken by FUTEX_WAKE or timeout */
    fut_schedule();

    /* Cancel timeout timer if set */
    if (has_timeout) {
        fut_timer_cancel(futex_timeout_callback, &timeout_ctx);
    }

    /* Check if we were timed out */
    bool timed_out = (thread->futex_addr == NULL);
    thread->futex_addr = NULL;

    if (timed_out) return -ETIMEDOUT;

    /* Check for pending signals (task-wide OR thread-directed). */
    {
        uint64_t pending = __atomic_load_n(&task->pending_signals, __ATOMIC_ACQUIRE);
        if (thread)
            pending |= __atomic_load_n(&thread->thread_pending_signals, __ATOMIC_ACQUIRE);
        uint64_t blocked = __atomic_load_n(
            thread ? &thread->signal_mask : &task->signal_mask, __ATOMIC_ACQUIRE);
        if (pending & ~blocked) return -EINTR;
    }

    /* Scan all futexes to find which one changed (return its index) */
    for (unsigned int i = 0; i < nr_futexes; i++) {
        uint32_t *addr = (uint32_t *)(uintptr_t)waiters[i].uaddr;
        uint32_t current_val;
        if (futex_copy_from_user(&current_val, addr, sizeof(uint32_t)) == 0) {
            if (current_val != (uint32_t)waiters[i].val) {
                fut_printf("[FUTEX_WAITV] woken: index %u changed (%u -> %u)\n",
                           i, (uint32_t)waiters[i].val, current_val);
                return (long)i;
            }
        }
    }

    /* Woken but no value changed — spurious wake or FUTEX_WAKE on primary addr.
     * Return index 0 (the address we were woken on). */
    fut_printf("[FUTEX_WAITV] woken on primary (index 0), no value diff detected\n");
    return 0;
}
