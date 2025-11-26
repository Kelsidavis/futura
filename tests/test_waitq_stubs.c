/* test_waitq_stubs.c - Verify host wait queue stubs work correctly
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 */

#include <stdio.h>
#include <kernel/fut_waitq.h>
#include <kernel/fut_sched.h>

int main(void) {
    printf("Testing host wait queue stubs...\n");

    /* Test 1: Initialize wait queue */
    fut_waitq_t wq;
    fut_waitq_init(&wq);
    if (wq.head != NULL) {
        printf("FAIL: fut_waitq_init did not set head to NULL\n");
        return 1;
    }
    printf("PASS: fut_waitq_init works\n");

    /* Test 2: Sleep locked (should just release the lock) */
    fut_spinlock_t lock;
    fut_spinlock_init(&lock);
    fut_spinlock_acquire(&lock);
    fut_waitq_sleep_locked(&wq, &lock, THREAD_BLOCKED);
    /* If we get here, the lock was released (no-op in host build) */
    printf("PASS: fut_waitq_sleep_locked works\n");

    /* Test 3: Wake one (no-op) */
    fut_waitq_wake_one(&wq);
    printf("PASS: fut_waitq_wake_one works\n");

    printf("\nAll wait queue stub tests passed!\n");
    return 0;
}
