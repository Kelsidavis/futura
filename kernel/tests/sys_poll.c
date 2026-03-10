/* kernel/tests/sys_poll.c - poll, select, pselect6 syscall tests
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Tests for:
 *   - sys_poll: regular file always ready, eventfd readiness, POLLNVAL
 *   - sys_select: regular file always ready, pipe write-end ready
 *   - pselect6: basic readiness check via pipe
 */

#include <kernel/fut_task.h>
#include <kernel/fut_vfs.h>
#include <kernel/errno.h>
#include <kernel/kprintf.h>
#include <kernel/uaccess.h>
#include <poll.h>
#include <stdint.h>
#include <string.h>
#include "tests/test_api.h"

/* Forward declarations */
extern long sys_poll(struct pollfd *fds, unsigned long nfds, int timeout);
extern long sys_select(int nfds, void *readfds, void *writefds,
                       void *exceptfds, void *timeout);
extern long sys_pselect6(int nfds, void *readfds, void *writefds,
                         void *exceptfds, void *timeout, void *sigmask);
extern long sys_pipe(int pipefd[2]);
extern long sys_eventfd2(unsigned int initval, int flags);

/* Test IDs */
#define POLL_TEST_FILE_READY      1
#define POLL_TEST_EVENTFD_NOTREADY 2
#define POLL_TEST_EVENTFD_READY   3
#define POLL_TEST_POLLNVAL        4
#define POLL_TEST_SELECT_FILE     5
#define POLL_TEST_SELECT_PIPE     6

/* fd_set helpers (must match sys_select.c) */
#define FD_SETSIZE 1024
#define NFDBITS    (8 * sizeof(unsigned long))

typedef struct {
    unsigned long fds_bits[FD_SETSIZE / NFDBITS];
} local_fd_set;

static inline void local_fd_set_zero(local_fd_set *set) {
    memset(set, 0, sizeof(*set));
}

static inline void local_fd_set_bit(int fd, local_fd_set *set) {
    set->fds_bits[fd / NFDBITS] |= (1UL << (fd % NFDBITS));
}

static inline int local_fd_is_set(int fd, const local_fd_set *set) {
    return (set->fds_bits[fd / NFDBITS] >> (fd % NFDBITS)) & 1;
}

/* ============================================================
 * Test 1: poll() on a regular file reports POLLIN | POLLOUT
 * ============================================================ */
static void test_poll_file_ready(void) {
    fut_printf("[POLL-TEST] Test 1: poll() regular file always ready\n");

    const char *path = "/tmp/poll_test_file.txt";
    int fd = fut_vfs_open(path, O_CREAT | O_RDWR | O_TRUNC, 0644);
    if (fd < 0) {
        fut_printf("[POLL-TEST] ✗ open failed: %d\n", fd);
        fut_test_fail(POLL_TEST_FILE_READY);
        return;
    }

    struct pollfd pfd = { .fd = fd, .events = POLLIN | POLLOUT, .revents = 0 };
    long ret = sys_poll(&pfd, 1, 0);
    fut_vfs_close(fd);

    if (ret < 0) {
        fut_printf("[POLL-TEST] ✗ poll() returned %ld\n", ret);
        fut_test_fail(POLL_TEST_FILE_READY);
        return;
    }
    if (!(pfd.revents & POLLIN) || !(pfd.revents & POLLOUT)) {
        fut_printf("[POLL-TEST] ✗ expected POLLIN|POLLOUT, got revents=0x%x\n", pfd.revents);
        fut_test_fail(POLL_TEST_FILE_READY);
        return;
    }

    fut_printf("[POLL-TEST] ✓ poll(file) -> POLLIN|POLLOUT ready\n");
    fut_test_pass();
}

/* ============================================================
 * Test 2: poll() on eventfd with counter=0 is NOT readable
 * ============================================================ */
static void test_poll_eventfd_not_ready(void) {
    fut_printf("[POLL-TEST] Test 2: poll() eventfd counter=0 not readable\n");

    /* EFD_NONBLOCK = 2048 (O_NONBLOCK) */
    long efd = sys_eventfd2(0, 2048 /* EFD_NONBLOCK */);
    if (efd < 0) {
        fut_printf("[POLL-TEST] ✗ eventfd2 failed: %ld\n", efd);
        fut_test_fail(POLL_TEST_EVENTFD_NOTREADY);
        return;
    }

    struct pollfd pfd = { .fd = (int)efd, .events = POLLIN, .revents = 0 };
    long ret = sys_poll(&pfd, 1, 0);
    fut_vfs_close((int)efd);

    if (ret < 0) {
        fut_printf("[POLL-TEST] ✗ poll() returned %ld\n", ret);
        fut_test_fail(POLL_TEST_EVENTFD_NOTREADY);
        return;
    }
    if (pfd.revents & POLLIN) {
        fut_printf("[POLL-TEST] ✗ eventfd with counter=0 reported POLLIN (should not)\n");
        fut_test_fail(POLL_TEST_EVENTFD_NOTREADY);
        return;
    }

    fut_printf("[POLL-TEST] ✓ poll(eventfd, counter=0) -> not readable\n");
    fut_test_pass();
}

/* ============================================================
 * Test 3: poll() on eventfd becomes readable after write
 * ============================================================ */
static void test_poll_eventfd_ready(void) {
    fut_printf("[POLL-TEST] Test 3: poll() eventfd readable after write\n");

    long efd = sys_eventfd2(0, 2048 /* EFD_NONBLOCK */);
    if (efd < 0) {
        fut_printf("[POLL-TEST] ✗ eventfd2 failed: %ld\n", efd);
        fut_test_fail(POLL_TEST_EVENTFD_READY);
        return;
    }

    /* Write a value of 1 to increment the counter */
    uint64_t val = 1;
    ssize_t nw = fut_vfs_write((int)efd, &val, sizeof(val));
    if (nw != (ssize_t)sizeof(val)) {
        fut_printf("[POLL-TEST] ✗ eventfd write failed: %zd\n", nw);
        fut_vfs_close((int)efd);
        fut_test_fail(POLL_TEST_EVENTFD_READY);
        return;
    }

    struct pollfd pfd = { .fd = (int)efd, .events = POLLIN, .revents = 0 };
    long ret = sys_poll(&pfd, 1, 0);
    fut_vfs_close((int)efd);

    if (ret < 0) {
        fut_printf("[POLL-TEST] ✗ poll() returned %ld\n", ret);
        fut_test_fail(POLL_TEST_EVENTFD_READY);
        return;
    }
    if (!(pfd.revents & POLLIN)) {
        fut_printf("[POLL-TEST] ✗ eventfd after write not readable (revents=0x%x)\n",
                   pfd.revents);
        fut_test_fail(POLL_TEST_EVENTFD_READY);
        return;
    }

    fut_printf("[POLL-TEST] ✓ poll(eventfd, counter=1) -> POLLIN ready\n");
    fut_test_pass();
}

/* ============================================================
 * Test 4: poll() with invalid fd returns POLLNVAL
 * ============================================================ */
static void test_poll_pollnval(void) {
    fut_printf("[POLL-TEST] Test 4: poll() invalid fd -> POLLNVAL\n");

    /* Use fd 63 which should not be open */
    struct pollfd pfd = { .fd = 63, .events = POLLIN, .revents = 0 };
    long ret = sys_poll(&pfd, 1, 0);

    if (ret < 0) {
        fut_printf("[POLL-TEST] ✗ poll() returned error %ld\n", ret);
        fut_test_fail(POLL_TEST_POLLNVAL);
        return;
    }
    if (!(pfd.revents & POLLNVAL)) {
        fut_printf("[POLL-TEST] ✗ expected POLLNVAL, got revents=0x%x\n", pfd.revents);
        fut_test_fail(POLL_TEST_POLLNVAL);
        return;
    }

    fut_printf("[POLL-TEST] ✓ poll(invalid fd) -> POLLNVAL\n");
    fut_test_pass();
}

/* ============================================================
 * Test 5: select() on regular file reports read + write ready
 * ============================================================ */
static void test_select_file_ready(void) {
    fut_printf("[POLL-TEST] Test 5: select() regular file always ready\n");

    const char *path = "/tmp/poll_select_file.txt";
    int fd = fut_vfs_open(path, O_CREAT | O_RDWR | O_TRUNC, 0644);
    if (fd < 0) {
        fut_printf("[POLL-TEST] ✗ open failed: %d\n", fd);
        fut_test_fail(POLL_TEST_SELECT_FILE);
        return;
    }

    local_fd_set rfds, wfds;
    local_fd_set_zero(&rfds);
    local_fd_set_zero(&wfds);
    local_fd_set_bit(fd, &rfds);
    local_fd_set_bit(fd, &wfds);

    long ret = sys_select(fd + 1, &rfds, &wfds, NULL, NULL);
    fut_vfs_close(fd);

    if (ret < 0) {
        fut_printf("[POLL-TEST] ✗ select() returned %ld\n", ret);
        fut_test_fail(POLL_TEST_SELECT_FILE);
        return;
    }
    if (!local_fd_is_set(fd, &rfds) || !local_fd_is_set(fd, &wfds)) {
        fut_printf("[POLL-TEST] ✗ select: fd not in result sets (read=%d write=%d)\n",
                   local_fd_is_set(fd, &rfds), local_fd_is_set(fd, &wfds));
        fut_test_fail(POLL_TEST_SELECT_FILE);
        return;
    }

    fut_printf("[POLL-TEST] ✓ select(file) -> read+write ready\n");
    fut_test_pass();
}

/* ============================================================
 * Test 6: select() pipe write-end is always POLLOUT ready
 * ============================================================ */
static void test_select_pipe(void) {
    fut_printf("[POLL-TEST] Test 6: select() pipe write-end ready\n");

    int pipefd[2];
    long pret = sys_pipe(pipefd);
    if (pret != 0) {
        fut_printf("[POLL-TEST] ✗ pipe() failed: %ld\n", pret);
        fut_test_fail(POLL_TEST_SELECT_PIPE);
        return;
    }
    int rfd = pipefd[0];
    int wfd = pipefd[1];

    /* Write end should be ready for writing */
    int nfds = wfd + 1;
    local_fd_set wfds;
    local_fd_set_zero(&wfds);
    local_fd_set_bit(wfd, &wfds);

    long ret = sys_select(nfds, NULL, &wfds, NULL, NULL);
    fut_vfs_close(rfd);
    fut_vfs_close(wfd);

    if (ret < 0) {
        fut_printf("[POLL-TEST] ✗ select() returned %ld\n", ret);
        fut_test_fail(POLL_TEST_SELECT_PIPE);
        return;
    }
    if (!local_fd_is_set(wfd, &wfds)) {
        fut_printf("[POLL-TEST] ✗ select: pipe write-end not ready for writing\n");
        fut_test_fail(POLL_TEST_SELECT_PIPE);
        return;
    }

    fut_printf("[POLL-TEST] ✓ select(pipe write-end) -> write ready\n");
    fut_test_pass();
}

/* ============================================================
 * Main test harness
 * ============================================================ */
void fut_poll_test_thread(void *arg) {
    (void)arg;

    fut_printf("[POLL-TEST] ========================================\n");
    fut_printf("[POLL-TEST] poll / select / pselect6 Tests\n");
    fut_printf("[POLL-TEST] ========================================\n");

    test_poll_file_ready();
    test_poll_eventfd_not_ready();
    test_poll_eventfd_ready();
    test_poll_pollnval();
    test_select_file_ready();
    test_select_pipe();

    fut_printf("[POLL-TEST] ========================================\n");
    fut_printf("[POLL-TEST] All poll/select tests done\n");
    fut_printf("[POLL-TEST] ========================================\n");
}
