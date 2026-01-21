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

extern void fut_printf(const char *fmt, ...);
extern fut_task_t *fut_task_current(void);
extern fut_thread_t *fut_thread_current(void);
extern int fut_access_ok(const void *u_ptr, size_t len, int write);
extern int fut_copy_from_user(void *to, const void *from, size_t size);

/* ============================================================
 *   Futex Hash Table
 * ============================================================ */

#define FUTEX_HASH_SIZE 256  /* Number of hash buckets */

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

/* Futex operations */
#define FUTEX_WAIT              0
#define FUTEX_WAKE              1
#define FUTEX_FD                2
#define FUTEX_REQUEUE           3
#define FUTEX_CMP_REQUEUE       4
#define FUTEX_WAKE_OP           5
#define FUTEX_LOCK_PI           6
#define FUTEX_UNLOCK_PI         7
#define FUTEX_TRYLOCK_PI        8
#define FUTEX_WAIT_BITSET       9
#define FUTEX_WAKE_BITSET       10
#define FUTEX_WAIT_REQUEUE_PI   11
#define FUTEX_CMP_REQUEUE_PI    12

/* Futex flags */
#define FUTEX_PRIVATE_FLAG      128
#define FUTEX_CLOCK_REALTIME    256

/* Robust list structures */
struct robust_list {
    struct robust_list *next;
};

struct robust_list_head {
    struct robust_list list;
    long futex_offset;
    struct robust_list *list_op_pending;
};

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
 * Phase 1: Stub - returns success/failure without actual implementation
 * Phase 2: Implement FUTEX_WAIT/FUTEX_WAKE with wait queues
 * Phase 3: Add timeout support and advanced operations
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

    /* Mask out flags to get base operation */
    int cmd = op & 0x7F;

    fut_printf("[FUTEX] futex(uaddr=%p, op=%d, val=%u, timeout=%p, uaddr2=%p, val3=%u)\n",
               uaddr, op, val, timeout, uaddr2, val3);

    /* Phase 5: Document pointer validation requirement for Phase 2 implementation
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
     * DEFENSE (Phase 5 Requirements for Phase 2):
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
    /* Validate userspace address */
    if (!uaddr) {
        return -EINVAL;
    }

    /* Phase 2: Validate userspace pointer with write access (futexes modify memory) */
    if (fut_access_ok(uaddr, sizeof(uint32_t), 1) != 0) {
        return -EFAULT;
    }

    /* Phase 2 (Completed): Atomic compare-and-sleep for FUTEX_WAIT
     *   ✓ Hash bucket locks prevent TOCTOU (lines 249-265)
     *   ✓ Value read and comparison under lock (lines 252-265)
     *   ✓ Sleep on wait queue with lock held (line 279)
     */
    /* TODO Phase 3: Add PI (priority inheritance) futex support */

    switch (cmd) {
        case FUTEX_WAIT:
        case FUTEX_WAIT_BITSET: {
            /* FUTEX_WAIT: Atomically check *uaddr == val, then sleep
             * This is the core primitive for userspace mutexes/condvars */

            /* Get the hash bucket for this futex address */
            futex_bucket_t *bucket = futex_get_bucket(uaddr);

            /* Acquire bucket lock to ensure atomicity of check-and-sleep */
            fut_spinlock_acquire(&bucket->lock);

            /* Read current value from userspace (under lock) */
            uint32_t current_val;
            if (fut_copy_from_user(&current_val, uaddr, sizeof(uint32_t)) != 0) {
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

            /* Value matches - add to wait queue and sleep */
            fut_thread_t *thread = fut_thread_current();
            if (!thread) {
                fut_spinlock_release(&bucket->lock);
                return -ESRCH;
            }

            /* Store futex address in thread for later matching during wake */
            thread->futex_addr = uaddr;

            /* Sleep on wait queue (releases bucket lock) */
            fut_printf("[FUTEX] FUTEX_WAIT - sleeping on futex at %p\n", uaddr);
            fut_waitq_sleep_locked(&bucket->waiters, &bucket->lock, FUT_THREAD_BLOCKED);

            /* Woken up - clear futex address */
            thread->futex_addr = NULL;

            /* TODO: Handle timeout if specified */
            (void)timeout;

            fut_printf("[FUTEX] FUTEX_WAIT - woken up\n");
            return 0;
        }

        case FUTEX_WAKE:
        case FUTEX_WAKE_BITSET: {
            /* FUTEX_WAKE: Wake up to 'val' threads waiting on futex at uaddr */

            futex_bucket_t *bucket = futex_get_bucket(uaddr);
            fut_spinlock_acquire(&bucket->lock);

            int woken = 0;
            uint32_t max_wake = val;

            /* Walk the wait queue and wake threads waiting on this specific address */
            fut_waitq_t *wq = &bucket->waiters;
            fut_thread_t *thread = wq->head;
            fut_thread_t *prev = NULL;

            while (thread && woken < (int)max_wake) {
                fut_thread_t *next = thread->wq_next;

                /* Check if this thread is waiting on our specific futex address */
                if (thread->futex_addr == uaddr) {
                    /* Remove from wait queue */
                    if (prev) {
                        prev->wq_next = next;
                    } else {
                        wq->head = next;
                    }
                    if (wq->tail == thread) {
                        wq->tail = prev;
                    }
                    thread->wq_next = NULL;

                    /* Wake up the thread - set state to READY and add to run queue */
                    thread->state = FUT_THREAD_READY;
                    fut_sched_add_thread(thread);
                    woken++;

                    fut_printf("[FUTEX] FUTEX_WAKE - woke thread %p\n", (void*)thread);
                } else {
                    prev = thread;
                }

                thread = next;
            }

            fut_spinlock_release(&bucket->lock);

            fut_printf("[FUTEX] FUTEX_WAKE - woke %d threads\n", woken);
            return woken;
        }

        case FUTEX_REQUEUE:
            /* Should requeue threads from uaddr to uaddr2 */
            fut_printf("[FUTEX] FUTEX_REQUEUE - stub (returning 0)\n");
            (void)uaddr2;
            return 0;

        case FUTEX_CMP_REQUEUE:
            /* Should conditionally requeue based on value check */
            fut_printf("[FUTEX] FUTEX_CMP_REQUEUE - stub (returning 0)\n");
            (void)uaddr2;
            (void)val3;
            return 0;

        case FUTEX_WAKE_OP:
            /* Should wake and perform atomic operation */
            fut_printf("[FUTEX] FUTEX_WAKE_OP - stub (returning 0)\n");
            (void)uaddr2;
            (void)val3;
            return 0;

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
 * Phase 1: Stub - accepts parameters, returns success
 * Phase 2: Store robust list head in task structure
 * Phase 3: Walk robust list on thread exit and perform cleanup
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

    /* Phase 5: Document pointer validation requirement for Phase 2/3 implementation
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
     * DEFENSE (Phase 5 Requirements for Phase 2/3):
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

    /* Phase 2: Validate robust_list head pointer before accessing */
    if (head && fut_access_ok(head, sizeof(struct robust_list_head), 0) != 0) {
        return -EFAULT;
    }

    fut_printf("[SET_ROBUST_LIST] Stub implementation - returning success\n");
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
 * Phase 1: Stub - returns null pointer and zero length
 * Phase 2: Return actual robust list head from task structure
 *
 * Returns:
 *   - 0 on success
 *   - -ESRCH if process not found
 *   - -EPERM if permission denied
 */
long sys_get_robust_list(int pid, struct robust_list_head **head_ptr,
                         size_t *len_ptr) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    fut_printf("[GET_ROBUST_LIST] pid=%d head_ptr=%p len_ptr=%p\n",
               pid, head_ptr, len_ptr);

    /* Validate output pointers */
    if (!head_ptr || !len_ptr) {
        return -EINVAL;
    }

    /* Phase 2: Validate userspace pointers with write access (kernel writes to them) */
    if (fut_access_ok(head_ptr, sizeof(struct robust_list_head *), 1) != 0) {
        return -EFAULT;
    }
    if (fut_access_ok(len_ptr, sizeof(size_t), 1) != 0) {
        return -EFAULT;
    }

    /* Phase 1: Stub - return null pointer */
    /* Phase 2: Retrieve robust list head from task structure */
    /* Phase 3: Add permission checks for querying other tasks */

    *head_ptr = NULL;
    *len_ptr = 0;

    fut_printf("[GET_ROBUST_LIST] Stub implementation - returning null\n");
    return 0;
}
