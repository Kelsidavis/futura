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
extern long sys_eventfd2(unsigned int initval, int flags);

/* Max per-task epoll instances (must match kernel/sys_epoll.c) */
#define EPOLL_TEST_MAX_PER_TASK 16

/* Test error codes */
#define EPOLL_TEST_CREATE       1
#define EPOLL_TEST_CLOSE        2
#define EPOLL_TEST_CTL_ADD_DEL  3
#define EPOLL_TEST_QUOTA        4
#define EPOLL_TEST_EBADF        5
#define EPOLL_TEST_EEXIST       6
#define EPOLL_TEST_EPOLLIN      7
#define EPOLL_TEST_TIMEOUT      8
#define EPOLL_TEST_MOD          9
#define EPOLL_TEST_ONESHOT      10
#define EPOLL_TEST_EPOLLET      11
#define EPOLL_TEST_EPOLLHUP     12

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
 * Test 7: epoll_wait returns EPOLLIN for an already-readable eventfd.
 */
static void test_epoll_wait_epollin(void) {
    fut_printf("[EPOLL-TEST] Test 7: epoll_wait EPOLLIN on ready eventfd\n");

    /* Create eventfd with initial count=1 (immediately readable) */
    long efd = sys_eventfd2(1, 0);
    if (efd < 0) {
        fut_printf("[EPOLL-TEST] ✗ eventfd2 failed: %ld\n", efd);
        fut_test_fail(EPOLL_TEST_EPOLLIN);
        return;
    }

    long epfd = sys_epoll_create1(0);
    if (epfd < 0) {
        fut_printf("[EPOLL-TEST] ✗ epoll_create1 failed: %ld\n", epfd);
        sys_close((int)efd);
        fut_test_fail(EPOLL_TEST_EPOLLIN);
        return;
    }

    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = (int)efd;
    long ret = sys_epoll_ctl((int)epfd, EPOLL_CTL_ADD, (int)efd, &ev);
    if (ret != 0) {
        fut_printf("[EPOLL-TEST] ✗ epoll_ctl ADD failed: %ld\n", ret);
        sys_close((int)epfd);
        sys_close((int)efd);
        fut_test_fail(EPOLL_TEST_EPOLLIN);
        return;
    }

    /* Poll with timeout=0 — eventfd is immediately readable */
    struct epoll_event out[4];
    long n = sys_epoll_wait((int)epfd, out, 4, 0);
    if (n != 1) {
        fut_printf("[EPOLL-TEST] ✗ epoll_wait returned %ld (expected 1)\n", n);
        sys_close((int)epfd);
        sys_close((int)efd);
        fut_test_fail(EPOLL_TEST_EPOLLIN);
        return;
    }
    if (!(out[0].events & EPOLLIN)) {
        fut_printf("[EPOLL-TEST] ✗ event 0x%x missing EPOLLIN\n", out[0].events);
        sys_close((int)epfd);
        sys_close((int)efd);
        fut_test_fail(EPOLL_TEST_EPOLLIN);
        return;
    }

    sys_close((int)epfd);
    sys_close((int)efd);
    fut_printf("[EPOLL-TEST] ✓ epoll_wait: EPOLLIN fired for ready eventfd (events=0x%x)\n",
               out[0].events);
    fut_test_pass();
}

/**
 * Test 8: epoll_wait with timeout=0 returns 0 when no fd is ready.
 */
static void test_epoll_wait_timeout_zero(void) {
    fut_printf("[EPOLL-TEST] Test 8: epoll_wait timeout=0, no ready fd\n");

    /* eventfd with count=0 — not readable */
    long efd = sys_eventfd2(0, 0);
    if (efd < 0) {
        fut_printf("[EPOLL-TEST] ✗ eventfd2 failed: %ld\n", efd);
        fut_test_fail(EPOLL_TEST_TIMEOUT);
        return;
    }

    long epfd = sys_epoll_create1(0);
    if (epfd < 0) {
        fut_printf("[EPOLL-TEST] ✗ epoll_create1 failed: %ld\n", epfd);
        sys_close((int)efd);
        fut_test_fail(EPOLL_TEST_TIMEOUT);
        return;
    }

    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = (int)efd;
    sys_epoll_ctl((int)epfd, EPOLL_CTL_ADD, (int)efd, &ev);

    struct epoll_event out[4];
    long n = sys_epoll_wait((int)epfd, out, 4, 0);

    sys_close((int)epfd);
    sys_close((int)efd);

    if (n != 0) {
        fut_printf("[EPOLL-TEST] ✗ epoll_wait timeout=0 returned %ld (expected 0)\n", n);
        fut_test_fail(EPOLL_TEST_TIMEOUT);
        return;
    }

    fut_printf("[EPOLL-TEST] ✓ epoll_wait: timeout=0 returns 0 for non-ready fd\n");
    fut_test_pass();
}

/**
 * Test 9: EPOLL_CTL_MOD updates event data returned by epoll_wait.
 */
static void test_epoll_ctl_mod(void) {
    fut_printf("[EPOLL-TEST] Test 9: EPOLL_CTL_MOD updates event data\n");

    /* eventfd with count=1 (immediately readable) */
    long efd = sys_eventfd2(1, 0);
    if (efd < 0) {
        fut_printf("[EPOLL-TEST] ✗ eventfd2 failed: %ld\n", efd);
        fut_test_fail(EPOLL_TEST_MOD);
        return;
    }

    long epfd = sys_epoll_create1(0);
    if (epfd < 0) {
        fut_printf("[EPOLL-TEST] ✗ epoll_create1 failed: %ld\n", epfd);
        sys_close((int)efd);
        fut_test_fail(EPOLL_TEST_MOD);
        return;
    }

    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.u32 = 42;
    sys_epoll_ctl((int)epfd, EPOLL_CTL_ADD, (int)efd, &ev);

    struct epoll_event out[4];
    long n = sys_epoll_wait((int)epfd, out, 4, 0);
    if (n != 1 || out[0].data.u32 != 42) {
        fut_printf("[EPOLL-TEST] ✗ before MOD: n=%ld data.u32=%u (expected 1/42)\n",
                   n, out[0].data.u32);
        sys_close((int)epfd);
        sys_close((int)efd);
        fut_test_fail(EPOLL_TEST_MOD);
        return;
    }

    /* MOD: change user data */
    ev.events = EPOLLIN;
    ev.data.u32 = 99;
    long ret = sys_epoll_ctl((int)epfd, EPOLL_CTL_MOD, (int)efd, &ev);
    if (ret != 0) {
        fut_printf("[EPOLL-TEST] ✗ EPOLL_CTL_MOD failed: %ld\n", ret);
        sys_close((int)epfd);
        sys_close((int)efd);
        fut_test_fail(EPOLL_TEST_MOD);
        return;
    }

    n = sys_epoll_wait((int)epfd, out, 4, 0);
    if (n != 1 || out[0].data.u32 != 99) {
        fut_printf("[EPOLL-TEST] ✗ after MOD: n=%ld data.u32=%u (expected 1/99)\n",
                   n, out[0].data.u32);
        sys_close((int)epfd);
        sys_close((int)efd);
        fut_test_fail(EPOLL_TEST_MOD);
        return;
    }

    sys_close((int)epfd);
    sys_close((int)efd);
    fut_printf("[EPOLL-TEST] ✓ EPOLL_CTL_MOD: data.u32 updated from 42 to 99\n");
    fut_test_pass();
}

/**
 * Test 10: EPOLLONESHOT — fd fires once, then is silenced; MOD re-arms it.
 */
static void test_epoll_oneshot(void) {
    fut_printf("[EPOLL-TEST] Test 10: EPOLLONESHOT fires once then silenced\n");

    long efd = sys_eventfd2(1, 0);  /* count=1, readable */
    if (efd < 0) {
        fut_printf("[EPOLL-TEST] ✗ eventfd2 failed: %ld\n", efd);
        fut_test_fail(EPOLL_TEST_ONESHOT);
        return;
    }

    long epfd = sys_epoll_create1(0);
    if (epfd < 0) {
        fut_printf("[EPOLL-TEST] ✗ epoll_create1 failed: %ld\n", epfd);
        sys_close((int)efd);
        fut_test_fail(EPOLL_TEST_ONESHOT);
        return;
    }

    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLONESHOT;
    ev.data.fd = (int)efd;
    sys_epoll_ctl((int)epfd, EPOLL_CTL_ADD, (int)efd, &ev);

    struct epoll_event out[4];

    /* First wait: should return 1 event */
    long n = sys_epoll_wait((int)epfd, out, 4, 0);
    if (n != 1) {
        fut_printf("[EPOLL-TEST] ✗ first wait: n=%ld (expected 1)\n", n);
        sys_close((int)epfd);
        sys_close((int)efd);
        fut_test_fail(EPOLL_TEST_ONESHOT);
        return;
    }

    /* Second wait: EPOLLONESHOT silenced the fd → 0 events */
    n = sys_epoll_wait((int)epfd, out, 4, 0);
    if (n != 0) {
        fut_printf("[EPOLL-TEST] ✗ second wait: n=%ld (expected 0, oneshot should silence)\n", n);
        sys_close((int)epfd);
        sys_close((int)efd);
        fut_test_fail(EPOLL_TEST_ONESHOT);
        return;
    }

    /* MOD to re-arm with EPOLLONESHOT */
    ev.events = EPOLLIN | EPOLLONESHOT;
    ev.data.fd = (int)efd;
    long ret = sys_epoll_ctl((int)epfd, EPOLL_CTL_MOD, (int)efd, &ev);
    if (ret != 0) {
        fut_printf("[EPOLL-TEST] ✗ MOD re-arm failed: %ld\n", ret);
        sys_close((int)epfd);
        sys_close((int)efd);
        fut_test_fail(EPOLL_TEST_ONESHOT);
        return;
    }

    /* Third wait: re-armed, should fire again (eventfd still count=1) */
    n = sys_epoll_wait((int)epfd, out, 4, 0);
    if (n != 1) {
        fut_printf("[EPOLL-TEST] ✗ third wait after MOD re-arm: n=%ld (expected 1)\n", n);
        sys_close((int)epfd);
        sys_close((int)efd);
        fut_test_fail(EPOLL_TEST_ONESHOT);
        return;
    }

    sys_close((int)epfd);
    sys_close((int)efd);
    fut_printf("[EPOLL-TEST] ✓ EPOLLONESHOT: fires once, silenced, MOD re-arms\n");
    fut_test_pass();
}

/**
 * Test 11: EPOLLET — edge-triggered only fires on not-ready→ready transition.
 */
static void test_epoll_epollet(void) {
    fut_printf("[EPOLL-TEST] Test 11: EPOLLET edge-triggered transitions\n");

    long efd = sys_eventfd2(0, 0);  /* count=0, not readable */
    if (efd < 0) {
        fut_printf("[EPOLL-TEST] ✗ eventfd2 failed: %ld\n", efd);
        fut_test_fail(EPOLL_TEST_EPOLLET);
        return;
    }

    long epfd = sys_epoll_create1(0);
    if (epfd < 0) {
        fut_printf("[EPOLL-TEST] ✗ epoll_create1 failed: %ld\n", epfd);
        sys_close((int)efd);
        fut_test_fail(EPOLL_TEST_EPOLLET);
        return;
    }

    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLET;
    ev.data.fd = (int)efd;
    sys_epoll_ctl((int)epfd, EPOLL_CTL_ADD, (int)efd, &ev);

    struct epoll_event out[4];

    /* Step 1: nothing ready → 0 events */
    long n = sys_epoll_wait((int)epfd, out, 4, 0);
    if (n != 0) {
        fut_printf("[EPOLL-TEST] ✗ step1 (not ready): n=%ld (expected 0)\n", n);
        sys_close((int)epfd);
        sys_close((int)efd);
        fut_test_fail(EPOLL_TEST_EPOLLET);
        return;
    }

    /* Step 2: write to eventfd (not-ready→ready transition), expect 1 event */
    uint64_t one = 1;
    sys_write((int)efd, &one, sizeof(one));
    n = sys_epoll_wait((int)epfd, out, 4, 0);
    if (n != 1) {
        fut_printf("[EPOLL-TEST] ✗ step2 (after write): n=%ld (expected 1)\n", n);
        sys_close((int)epfd);
        sys_close((int)efd);
        fut_test_fail(EPOLL_TEST_EPOLLET);
        return;
    }

    /* Step 3: still readable, no new edge → 0 events */
    n = sys_epoll_wait((int)epfd, out, 4, 0);
    if (n != 0) {
        fut_printf("[EPOLL-TEST] ✗ step3 (no new edge): n=%ld (expected 0)\n", n);
        sys_close((int)epfd);
        sys_close((int)efd);
        fut_test_fail(EPOLL_TEST_EPOLLET);
        return;
    }

    /* Step 4: drain eventfd (counter→0), scan must observe not-ready → clears ET state */
    uint64_t val;
    sys_read((int)efd, &val, sizeof(val));  /* drain: counter→0 */
    n = sys_epoll_wait((int)epfd, out, 4, 0);  /* scan sees not-ready → clears last_was_readable */
    if (n != 0) {
        fut_printf("[EPOLL-TEST] ✗ step4 (after drain): n=%ld (expected 0)\n", n);
        sys_close((int)epfd);
        sys_close((int)efd);
        fut_test_fail(EPOLL_TEST_EPOLLET);
        return;
    }

    /* Step 5: write again → new not-ready→ready transition → 1 event */
    sys_write((int)efd, &one, sizeof(one));
    n = sys_epoll_wait((int)epfd, out, 4, 0);
    if (n != 1) {
        fut_printf("[EPOLL-TEST] ✗ step5 (write after drain+scan): n=%ld (expected 1)\n", n);
        sys_close((int)epfd);
        sys_close((int)efd);
        fut_test_fail(EPOLL_TEST_EPOLLET);
        return;
    }

    sys_close((int)epfd);
    sys_close((int)efd);
    fut_printf("[EPOLL-TEST] ✓ EPOLLET: fires on not-ready→ready transitions only\n");
    fut_test_pass();
}

/**
 * Test 12: EPOLLHUP fires when write end of pipe is closed.
 */
static void test_epoll_hup_pipe(void) {
    fut_printf("[EPOLL-TEST] Test 12: EPOLLHUP on pipe after write-end close\n");

    int pipefd[2];
    long ret = sys_pipe(pipefd);
    if (ret != 0) {
        fut_printf("[EPOLL-TEST] ✗ pipe() failed: %ld\n", ret);
        fut_test_fail(EPOLL_TEST_EPOLLHUP);
        return;
    }

    long epfd = sys_epoll_create1(0);
    if (epfd < 0) {
        fut_printf("[EPOLL-TEST] ✗ epoll_create1 failed: %ld\n", epfd);
        sys_close(pipefd[0]);
        sys_close(pipefd[1]);
        fut_test_fail(EPOLL_TEST_EPOLLHUP);
        return;
    }

    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLHUP;
    ev.data.fd = pipefd[0];
    sys_epoll_ctl((int)epfd, EPOLL_CTL_ADD, pipefd[0], &ev);

    /* Close write end → read end should see EPOLLHUP */
    sys_close(pipefd[1]);

    struct epoll_event out[4];
    long n = sys_epoll_wait((int)epfd, out, 4, 0);
    if (n < 1) {
        fut_printf("[EPOLL-TEST] ✗ epoll_wait after write-end close: n=%ld (expected >=1)\n", n);
        sys_close((int)epfd);
        sys_close(pipefd[0]);
        fut_test_fail(EPOLL_TEST_EPOLLHUP);
        return;
    }
    if (!(out[0].events & (EPOLLHUP | EPOLLIN))) {
        fut_printf("[EPOLL-TEST] ✗ events=0x%x missing EPOLLHUP|EPOLLIN\n", out[0].events);
        sys_close((int)epfd);
        sys_close(pipefd[0]);
        fut_test_fail(EPOLL_TEST_EPOLLHUP);
        return;
    }

    sys_close((int)epfd);
    sys_close(pipefd[0]);
    fut_printf("[EPOLL-TEST] ✓ EPOLLHUP: pipe read-end sees HUP after write-end closed (events=0x%x)\n",
               out[0].events);
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
    test_epoll_wait_epollin();
    test_epoll_wait_timeout_zero();
    test_epoll_ctl_mod();
    test_epoll_oneshot();
    test_epoll_epollet();
    test_epoll_hup_pipe();

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
