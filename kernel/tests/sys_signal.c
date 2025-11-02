/* sys_signal.c - Signal handling validation tests
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Tests for signal() syscall supporting inter-process event handling:
 * - Signal installation and handler registration
 * - Signal delivery and handler invocation
 * - Signal masking and blocking
 * - Multiple signal queueing
 * - Signal frame context
 */

#include <kernel/fut_task.h>
#include <kernel/fut_thread.h>
#include <kernel/errno.h>
#include <kernel/syscalls.h>
#include <kernel/signal.h>
#include "tests/test_api.h"

extern void fut_printf(const char *fmt, ...);
extern int fut_signal_set_handler(fut_task_t *task, int signum, sighandler_t handler);
extern sighandler_t fut_signal_get_handler(fut_task_t *task, int signum);
extern int fut_signal_send(fut_task_t *target, int signum);
extern int fut_signal_is_pending(fut_task_t *task, int signum);
extern int fut_signal_procmask(fut_task_t *task, int how, const sigset_t *set, sigset_t *oldset);

/* Test constants */
#define SIG_TEST_INSTALL        1
#define SIG_TEST_PENDING        2
#define SIG_TEST_MASK           3
#define SIG_TEST_MULTIPLE       4

/* Global test state for signal handler invocation */
static volatile int signal_handler_called = 0;
static volatile int last_signal_received = 0;

/* Simple signal handler for testing */
static void test_signal_handler(int signum) {
    signal_handler_called++;
    last_signal_received = signum;
    fut_printf("[SIGNAL-TEST] Handler invoked for signal %d (call count=%d)\n", signum, signal_handler_called);
}

/* Test 1: Signal installation */
static void test_signal_install(void) {
    fut_printf("[SIGNAL-TEST] Test 1: Signal installation\n");

    extern fut_task_t *fut_task_current(void);
    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_printf("[SIGNAL-TEST] ✗ No current task\n");
        fut_test_fail(SIG_TEST_INSTALL);
        return;
    }

    /* Install handler for SIGUSR1 */
    int ret = fut_signal_set_handler(task, SIGUSR1, test_signal_handler);
    if (ret < 0) {
        fut_printf("[SIGNAL-TEST] ✗ fut_signal_set_handler() returned %d\n", ret);
        fut_test_fail(SIG_TEST_INSTALL);
        return;
    }

    /* Verify handler was set */
    sighandler_t handler = fut_signal_get_handler(task, SIGUSR1);
    if (handler != test_signal_handler) {
        fut_printf("[SIGNAL-TEST] ✗ Handler not installed correctly (got %p, expected %p)\n",
                  (void *)(uintptr_t)handler, (void *)(uintptr_t)test_signal_handler);
        fut_test_fail(SIG_TEST_INSTALL);
        return;
    }

    fut_printf("[SIGNAL-TEST] ✓ Signal handler installed successfully for SIGUSR1\n");
    fut_test_pass();
}

/* Test 2: Signal pending queueing */
static void test_signal_pending(void) {
    fut_printf("[SIGNAL-TEST] Test 2: Signal pending queueing\n");

    extern fut_task_t *fut_task_current(void);
    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_printf("[SIGNAL-TEST] ✗ No current task\n");
        fut_test_fail(SIG_TEST_PENDING);
        return;
    }

    /* Clear any existing pending signals */
    task->pending_signals = 0;

    /* Send signal to self */
    int ret = fut_signal_send(task, SIGUSR2);
    if (ret < 0) {
        fut_printf("[SIGNAL-TEST] ✗ fut_signal_send() failed with %d\n", ret);
        fut_test_fail(SIG_TEST_PENDING);
        return;
    }

    /* Check that signal is now pending */
    if (!fut_signal_is_pending(task, SIGUSR2)) {
        fut_printf("[SIGNAL-TEST] ✗ Signal SIGUSR2 not marked as pending\n");
        fut_test_fail(SIG_TEST_PENDING);
        return;
    }

    fut_printf("[SIGNAL-TEST] ✓ Signal successfully queued as pending\n");
    fut_test_pass();
}

/* Test 3: Signal masking (blocking/unblocking) */
static void test_signal_mask(void) {
    fut_printf("[SIGNAL-TEST] Test 3: Signal mask blocking and unblocking\n");

    extern fut_task_t *fut_task_current(void);
    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_printf("[SIGNAL-TEST] ✗ No current task\n");
        fut_test_fail(SIG_TEST_MASK);
        return;
    }

    /* Get current mask */
    sigset_t oldset;
    int ret = fut_signal_procmask(task, SIGPROCMASK_BLOCK, NULL, &oldset);
    if (ret != 0) {
        fut_printf("[SIGNAL-TEST] ✗ sigprocmask(get) failed with %d\n", ret);
        fut_test_fail(SIG_TEST_MASK);
        return;
    }

    /* Block SIGUSR1 */
    sigset_t newset;
    newset.__mask = (1ULL << (SIGUSR1 - 1));
    ret = fut_signal_procmask(task, SIGPROCMASK_BLOCK, &newset, NULL);
    if (ret != 0) {
        fut_printf("[SIGNAL-TEST] ✗ sigprocmask(block) failed with %d\n", ret);
        fut_test_fail(SIG_TEST_MASK);
        return;
    }

    /* Verify signal is blocked */
    if (!(task->signal_mask & (1ULL << (SIGUSR1 - 1)))) {
        fut_printf("[SIGNAL-TEST] ✗ Signal SIGUSR1 not blocked in mask\n");
        fut_test_fail(SIG_TEST_MASK);
        return;
    }

    /* Unblock SIGUSR1 */
    ret = fut_signal_procmask(task, SIGPROCMASK_UNBLOCK, &newset, NULL);
    if (ret != 0) {
        fut_printf("[SIGNAL-TEST] ✗ sigprocmask(unblock) failed with %d\n", ret);
        fut_test_fail(SIG_TEST_MASK);
        return;
    }

    /* Verify signal is unblocked */
    if (task->signal_mask & (1ULL << (SIGUSR1 - 1))) {
        fut_printf("[SIGNAL-TEST] ✗ Signal SIGUSR1 still blocked after unblock\n");
        fut_test_fail(SIG_TEST_MASK);
        return;
    }

    fut_printf("[SIGNAL-TEST] ✓ Signal masking working correctly\n");
    fut_test_pass();
}

/* Test 4: Multiple signals queueing */
static void test_signal_multiple(void) {
    fut_printf("[SIGNAL-TEST] Test 4: Multiple signal queueing\n");

    extern fut_task_t *fut_task_current(void);
    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_printf("[SIGNAL-TEST] ✗ No current task\n");
        fut_test_fail(SIG_TEST_MULTIPLE);
        return;
    }

    /* Clear pending signals */
    task->pending_signals = 0;

    /* Send multiple different signals */
    int signals[] = {SIGUSR1, SIGUSR2, SIGTERM};
    for (int i = 0; i < 3; i++) {
        int ret = fut_signal_send(task, signals[i]);
        if (ret < 0) {
            fut_printf("[SIGNAL-TEST] ✗ Failed to queue signal %d\n", signals[i]);
            fut_test_fail(SIG_TEST_MULTIPLE);
            return;
        }
    }

    /* Verify all signals are pending */
    for (int i = 0; i < 3; i++) {
        if (!fut_signal_is_pending(task, signals[i])) {
            fut_printf("[SIGNAL-TEST] ✗ Signal %d not marked as pending\n", signals[i]);
            fut_test_fail(SIG_TEST_MULTIPLE);
            return;
        }
    }

    /* Verify all bits are set in pending_signals */
    uint64_t expected_mask = (1ULL << (SIGUSR1 - 1)) |
                             (1ULL << (SIGUSR2 - 1)) |
                             (1ULL << (SIGTERM - 1));
    if ((task->pending_signals & expected_mask) != expected_mask) {
        fut_printf("[SIGNAL-TEST] ✗ Pending signals bitmask incorrect (got %llx, expected %llx)\n",
                  task->pending_signals & expected_mask, expected_mask);
        fut_test_fail(SIG_TEST_MULTIPLE);
        return;
    }

    fut_printf("[SIGNAL-TEST] ✓ Multiple signals successfully queued\n");
    fut_test_pass();
}

/* Main test harness thread */
static void fut_signal_test_thread(void *arg) {
    (void)arg;

    fut_printf("[SIGNAL-TEST] ========================================\n");
    fut_printf("[SIGNAL-TEST] Signal Handling Validation Tests\n");
    fut_printf("[SIGNAL-TEST] ========================================\n");

    /* Run all tests */
    test_signal_install();
    test_signal_pending();
    test_signal_mask();
    test_signal_multiple();

    fut_printf("[SIGNAL-TEST] ========================================\n");
    fut_printf("[SIGNAL-TEST] All signal tests completed\n");
    fut_printf("[SIGNAL-TEST] ========================================\n");
}

/**
 * Schedule signal validation tests on a task.
 */
void fut_signal_selftest_schedule(fut_task_t *task) {
    fut_printf("[SIGNAL] fut_signal_selftest_schedule called with task=%p\n", (void*)task);

    if (!task) {
        fut_printf("[SIGNAL] task is NULL, returning\n");
        return;
    }

    fut_thread_t *thread = fut_thread_create(
        task,
        fut_signal_test_thread,
        NULL,
        12 * 1024,  /* 12 KB stack */
        180         /* Priority */
    );

    if (!thread) {
        fut_printf("[SIGNAL] failed to schedule test harness thread\n");
    } else {
        fut_printf("[SIGNAL] successfully created test thread\n");
    }
}
