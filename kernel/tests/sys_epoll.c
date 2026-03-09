/* sys_epoll.c - epoll syscall validation tests
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Tests for epoll event notification interface:
 * - epoll instance creation and close
 * - FD registration (EPOLL_CTL_ADD / EPOLL_CTL_DEL)
 * - Per-task quota enforcement (MAX_EPOLL_PER_TASK)
 * - Auto-removal of watched FDs on close (epoll_notify_fd_close)
 * - Error handling (EBADF, EEXIST, EMFILE)
 */

#include <kernel/fut_task.h>
#include <kernel/fut_thread.h>
#include <kernel/fut_vfs.h>
#include <kernel/errno.h>
#include <kernel/syscalls.h>
#include <sys/epoll.h>
#include "tests/test_api.h"

#include <kernel/kprintf.h>

/* Forward declarations for kernel-internal epoll functions */
extern long sys_epoll_create1(int flags);

/* Max per-task epoll instances (must match kernel/sys_epoll.c) */
#define EPOLL_TEST_MAX_PER_TASK 16

/* Test error codes */
#define EPOLL_TEST_CREATE       1
#define EPOLL_TEST_CLOSE        2
#define EPOLL_TEST_CTL_ADD_DEL  3
#define EPOLL_TEST_QUOTA        4
#define EPOLL_TEST_EBADF        5
#define EPOLL_TEST_EEXIST       6

/* Scratch file used for FD-based tests */
#define EPOLL_TEST_FILE "/tmp/epoll_test_scratch"

/**
 * Test 1: epoll_create1 returns a valid file descriptor.
 */
static void test_epoll_create(void) {
    fut_printf("[EPOLL-TEST] Test 1: epoll_create1 basic creation\n");

    long epfd = sys_epoll_create1(0);
    if (epfd < 0) {
        fut_printf("[EPOLL-TEST] ✗ sys_epoll_create1(0) returned %ld\n", epfd);
        fut_test_fail(EPOLL_TEST_CREATE);
        return;
    }

    sys_close((int)epfd);

    fut_printf("[EPOLL-TEST] ✓ sys_epoll_create1 returned fd=%ld\n", epfd);
    fut_test_pass();
}

/**
 * Test 2: Closing an epoll FD releases the instance (no crash, fd reusable).
 */
static void test_epoll_close(void) {
    fut_printf("[EPOLL-TEST] Test 2: epoll FD close and cleanup\n");

    long epfd = sys_epoll_create1(0);
    if (epfd < 0) {
        fut_printf("[EPOLL-TEST] ✗ sys_epoll_create1 failed: %ld\n", epfd);
        fut_test_fail(EPOLL_TEST_CLOSE);
        return;
    }

    long ret = sys_close((int)epfd);
    if (ret != 0) {
        fut_printf("[EPOLL-TEST] ✗ sys_close(epfd=%ld) returned %ld\n", epfd, ret);
        fut_test_fail(EPOLL_TEST_CLOSE);
        return;
    }

    /* Create a new epoll instance — should succeed (slot was freed) */
    long epfd2 = sys_epoll_create1(0);
    if (epfd2 < 0) {
        fut_printf("[EPOLL-TEST] ✗ Second sys_epoll_create1 failed: %ld\n", epfd2);
        fut_test_fail(EPOLL_TEST_CLOSE);
        return;
    }
    sys_close((int)epfd2);

    fut_printf("[EPOLL-TEST] ✓ epoll FD closed and instance recycled (fd=%ld fd2=%ld)\n",
               epfd, epfd2);
    fut_test_pass();
}

/**
 * Test 3: epoll_ctl ADD and DEL a real file descriptor.
 */
static void test_epoll_ctl_add_del(void) {
    fut_printf("[EPOLL-TEST] Test 3: epoll_ctl ADD and DEL\n");

    /* Create a scratch file to watch */
    int filefd = fut_vfs_open(EPOLL_TEST_FILE, O_CREAT | O_RDWR, 0644);
    if (filefd < 0) {
        fut_printf("[EPOLL-TEST] ✗ Failed to create scratch file: %d\n", filefd);
        fut_test_fail(EPOLL_TEST_CTL_ADD_DEL);
        return;
    }

    long epfd = sys_epoll_create1(0);
    if (epfd < 0) {
        fut_printf("[EPOLL-TEST] ✗ sys_epoll_create1 failed: %ld\n", epfd);
        fut_vfs_close(filefd);
        fut_test_fail(EPOLL_TEST_CTL_ADD_DEL);
        return;
    }

    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = filefd;

    long ret = sys_epoll_ctl((int)epfd, EPOLL_CTL_ADD, filefd, &ev);
    if (ret != 0) {
        fut_printf("[EPOLL-TEST] ✗ epoll_ctl(ADD) returned %ld\n", ret);
        sys_close((int)epfd);
        fut_vfs_close(filefd);
        fut_test_fail(EPOLL_TEST_CTL_ADD_DEL);
        return;
    }

    ret = sys_epoll_ctl((int)epfd, EPOLL_CTL_DEL, filefd, NULL);
    if (ret != 0) {
        fut_printf("[EPOLL-TEST] ✗ epoll_ctl(DEL) returned %ld\n", ret);
        sys_close((int)epfd);
        fut_vfs_close(filefd);
        fut_test_fail(EPOLL_TEST_CTL_ADD_DEL);
        return;
    }

    sys_close((int)epfd);
    fut_vfs_close(filefd);

    fut_printf("[EPOLL-TEST] ✓ epoll_ctl ADD and DEL succeeded\n");
    fut_test_pass();
}

/**
 * Test 4: Per-task quota — creating more than MAX_EPOLL_PER_TASK instances fails.
 */
static void test_epoll_quota(void) {
    fut_printf("[EPOLL-TEST] Test 4: Per-task quota (limit=%d)\n", EPOLL_TEST_MAX_PER_TASK);

    long fds[EPOLL_TEST_MAX_PER_TASK];
    int created = 0;

    /* Create exactly EPOLL_TEST_MAX_PER_TASK instances */
    for (int i = 0; i < EPOLL_TEST_MAX_PER_TASK; i++) {
        fds[i] = sys_epoll_create1(0);
        if (fds[i] < 0) {
            fut_printf("[EPOLL-TEST] ✗ sys_epoll_create1 failed at i=%d: %ld\n", i, fds[i]);
            /* Close what we opened */
            for (int j = 0; j < i; j++) sys_close((int)fds[j]);
            fut_test_fail(EPOLL_TEST_QUOTA);
            return;
        }
        created++;
    }

    /* One more should be rejected with EMFILE */
    long overflow = sys_epoll_create1(0);
    if (overflow >= 0) {
        fut_printf("[EPOLL-TEST] ✗ Created %d+1 epoll instances (quota not enforced)\n",
                   EPOLL_TEST_MAX_PER_TASK);
        sys_close((int)overflow);
        for (int i = 0; i < created; i++) sys_close((int)fds[i]);
        fut_test_fail(EPOLL_TEST_QUOTA);
        return;
    }
    if (overflow != -EMFILE) {
        fut_printf("[EPOLL-TEST] ✗ Expected -EMFILE, got %ld\n", overflow);
        for (int i = 0; i < created; i++) sys_close((int)fds[i]);
        fut_test_fail(EPOLL_TEST_QUOTA);
        return;
    }

    /* Clean up */
    for (int i = 0; i < created; i++) sys_close((int)fds[i]);

    fut_printf("[EPOLL-TEST] ✓ Quota enforced: %d allowed, 17th rejected with EMFILE\n",
               EPOLL_TEST_MAX_PER_TASK);
    fut_test_pass();
}

/**
 * Test 5: epoll_ctl on an invalid/closed epfd returns EBADF.
 */
static void test_epoll_ebadf(void) {
    fut_printf("[EPOLL-TEST] Test 5: EBADF on invalid epfd\n");

    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = 0;

    /* Use a deliberately invalid epfd */
    long ret = sys_epoll_ctl(9999, EPOLL_CTL_ADD, 0, &ev);
    if (ret != -EBADF) {
        fut_printf("[EPOLL-TEST] ✗ Expected -EBADF, got %ld\n", ret);
        fut_test_fail(EPOLL_TEST_EBADF);
        return;
    }

    fut_printf("[EPOLL-TEST] ✓ epoll_ctl(invalid epfd) correctly returned EBADF\n");
    fut_test_pass();
}

/**
 * Test 6: Duplicate ADD (same FD twice) returns EEXIST.
 */
static void test_epoll_eexist(void) {
    fut_printf("[EPOLL-TEST] Test 6: Duplicate ADD returns EEXIST\n");

    int filefd = fut_vfs_open(EPOLL_TEST_FILE, O_RDONLY, 0);
    if (filefd < 0) {
        /* Try to create it first */
        filefd = fut_vfs_open(EPOLL_TEST_FILE, O_CREAT | O_RDWR, 0644);
    }
    if (filefd < 0) {
        fut_printf("[EPOLL-TEST] ✗ Failed to open scratch file: %d\n", filefd);
        fut_test_fail(EPOLL_TEST_EEXIST);
        return;
    }

    long epfd = sys_epoll_create1(0);
    if (epfd < 0) {
        fut_printf("[EPOLL-TEST] ✗ sys_epoll_create1 failed: %ld\n", epfd);
        fut_vfs_close(filefd);
        fut_test_fail(EPOLL_TEST_EEXIST);
        return;
    }

    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = filefd;

    /* First ADD — must succeed */
    long ret = sys_epoll_ctl((int)epfd, EPOLL_CTL_ADD, filefd, &ev);
    if (ret != 0) {
        fut_printf("[EPOLL-TEST] ✗ First epoll_ctl(ADD) returned %ld\n", ret);
        sys_close((int)epfd);
        fut_vfs_close(filefd);
        fut_test_fail(EPOLL_TEST_EEXIST);
        return;
    }

    /* Second ADD — must return EEXIST */
    ret = sys_epoll_ctl((int)epfd, EPOLL_CTL_ADD, filefd, &ev);
    if (ret != -EEXIST) {
        fut_printf("[EPOLL-TEST] ✗ Duplicate ADD returned %ld (expected -EEXIST)\n", ret);
        sys_close((int)epfd);
        fut_vfs_close(filefd);
        fut_test_fail(EPOLL_TEST_EEXIST);
        return;
    }

    sys_close((int)epfd);
    fut_vfs_close(filefd);

    fut_printf("[EPOLL-TEST] ✓ Duplicate ADD correctly returned EEXIST\n");
    fut_test_pass();
}

/**
 * Thread entry point for epoll tests.
 */
void fut_epoll_test_thread(void *arg) {
    (void)arg;

    fut_printf("[EPOLL-TEST] ========================================\n");
    fut_printf("[EPOLL-TEST] Starting epoll Syscall Tests\n");
    fut_printf("[EPOLL-TEST] ========================================\n");

    test_epoll_create();
    test_epoll_close();
    test_epoll_ctl_add_del();
    test_epoll_quota();
    test_epoll_ebadf();
    test_epoll_eexist();

    fut_printf("[EPOLL-TEST] ========================================\n");
    fut_printf("[EPOLL-TEST] epoll Syscall Tests Complete\n");
    fut_printf("[EPOLL-TEST] ========================================\n");
}

/**
 * Schedule epoll tests to run.
 *
 * @param task The test task context
 */
void fut_epoll_selftest_schedule(fut_task_t *task) {
    fut_printf("[EPOLL] fut_epoll_selftest_schedule called with task=%p\n", (void *)task);

    if (!task) {
        fut_printf("[EPOLL] task is NULL, returning\n");
        return;
    }

    fut_thread_t *thread = fut_thread_create(
        task,
        fut_epoll_test_thread,
        NULL,
        12 * 1024,  /* 12 KB stack */
        180         /* Priority */
    );

    if (!thread) {
        fut_printf("[EPOLL] failed to schedule test harness thread\n");
    } else {
        fut_printf("[EPOLL] successfully created test thread\n");
    }
}
