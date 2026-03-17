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
#include <kernel/signal.h>
#include <kernel/uaccess.h>
#include <kernel/fut_timer.h>
#include <kernel/fut_memory.h>
#include <poll.h>
#include <stdint.h>
#include <string.h>
#include <sys/timerfd.h>
#include "tests/test_api.h"

#if defined(__x86_64__)
#include <platform/x86_64/memory/paging.h>
#include <platform/x86_64/memory/pmap.h>
#endif

#ifndef SFD_NONBLOCK
#define SFD_NONBLOCK 0x0800
#endif

/* Kernel-side signalfd info layout (128 bytes). */
struct test_signalfd_siginfo {
    uint32_t ssi_signo;
    int32_t ssi_errno;
    int32_t ssi_code;
    uint32_t ssi_pid;
    uint32_t ssi_uid;
    int32_t ssi_fd;
    uint32_t ssi_tid;
    uint32_t ssi_band;
    uint32_t ssi_overrun;
    uint32_t ssi_trapno;
    int32_t ssi_status;
    int32_t ssi_int;
    uint64_t ssi_ptr;
    uint64_t ssi_utime;
    uint64_t ssi_stime;
    uint64_t ssi_addr;
    uint16_t ssi_addr_lsb;
    uint16_t __pad2;
    int32_t ssi_syscall;
    uint64_t ssi_call_addr;
    uint32_t ssi_arch;
    uint8_t __pad[28];
};

/* Forward declarations */
extern long sys_poll(struct pollfd *fds, unsigned long nfds, int timeout);
extern long sys_select(int nfds, void *readfds, void *writefds,
                       void *exceptfds, void *timeout);
extern long sys_pselect6(int nfds, void *readfds, void *writefds,
                         void *exceptfds, void *timeout, void *sigmask);
extern long sys_pipe(int pipefd[2]);
extern long sys_eventfd2(unsigned int initval, int flags);
extern long sys_signalfd4(int ufd, const void *mask, size_t sizemask, int flags);
extern long sys_timerfd_create(int clockid, int flags);
extern long sys_timerfd_settime(int ufd, int flags,
                                const struct itimerspec *new_value,
                                struct itimerspec *old_value);

/* Test IDs */
#define POLL_TEST_FILE_READY      1
#define POLL_TEST_EVENTFD_NOTREADY 2
#define POLL_TEST_EVENTFD_READY   3
#define POLL_TEST_POLLNVAL        4
#define POLL_TEST_SELECT_FILE     5
#define POLL_TEST_SELECT_PIPE     6
#define POLL_TEST_PSELECT6_PIPE   7
#define POLL_TEST_PSELECT6_SIGMASK 8
#define POLL_TEST_TIMEOUT_ONLY    9
#define POLL_TEST_TIMERFD_READY   10
#define POLL_TEST_SIGNALFD_READY  11
#define POLL_TEST_PIPE_EOF        12

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

static void *map_user_page_for_test(uintptr_t uaddr) {
#if defined(__x86_64__)
    void *page = fut_pmm_alloc_page();
    if (!page) return NULL;
    phys_addr_t phys = pmap_virt_to_phys((uintptr_t)page);
    if (pmap_map(uaddr, phys, PAGE_SIZE, PTE_PRESENT | PTE_WRITABLE | PTE_USER) != 0) {
        return NULL;
    }
    return (void *)uaddr;
#else
    (void)uaddr;
    return NULL;
#endif
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
 * Test 7: pselect6() pipe write-end is always POLLOUT ready
 * ============================================================ */
static void test_pselect6_pipe(void) {
    fut_printf("[POLL-TEST] Test 7: pselect6() pipe write-end ready\n");

    int pipefd[2];
    long pret = sys_pipe(pipefd);
    if (pret != 0) {
        fut_printf("[POLL-TEST] ✗ pipe() failed: %ld\n", pret);
        fut_test_fail(POLL_TEST_PSELECT6_PIPE);
        return;
    }
    int rfd = pipefd[0];
    int wfd = pipefd[1];

    int nfds = wfd + 1;
    local_fd_set wfds;
    local_fd_set_zero(&wfds);
    local_fd_set_bit(wfd, &wfds);

    long ret = sys_pselect6(nfds, NULL, &wfds, NULL, NULL, NULL);
    fut_vfs_close(rfd);
    fut_vfs_close(wfd);

    if (ret < 0) {
        fut_printf("[POLL-TEST] ✗ pselect6() returned %ld\n", ret);
        fut_test_fail(POLL_TEST_PSELECT6_PIPE);
        return;
    }
    if (!local_fd_is_set(wfd, &wfds)) {
        fut_printf("[POLL-TEST] ✗ pselect6: pipe write-end not ready for writing\n");
        fut_test_fail(POLL_TEST_PSELECT6_PIPE);
        return;
    }

    fut_printf("[POLL-TEST] ✓ pselect6(pipe write-end) -> write ready\n");
    fut_test_pass();
}

/* ============================================================
 * Test 8: pselect6() temporarily installs and restores signal mask
 * ============================================================ */
static void test_pselect6_sigmask_restore(void) {
    fut_printf("[POLL-TEST] Test 8: pselect6() restores signal mask\n");

    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_printf("[POLL-TEST] ✗ no current task\n");
        fut_test_fail(POLL_TEST_PSELECT6_SIGMASK);
        return;
    }

    uint64_t old_mask = __atomic_load_n(&task->signal_mask, __ATOMIC_ACQUIRE);
    sigset_t req_mask = {
        .__mask = (1ULL << (SIGUSR1 - 1)) | (1ULL << (SIGKILL - 1)),
    };

    int pipefd[2];
    long pret = sys_pipe(pipefd);
    if (pret != 0) {
        fut_printf("[POLL-TEST] ✗ pipe() failed: %ld\n", pret);
        fut_test_fail(POLL_TEST_PSELECT6_SIGMASK);
        return;
    }
    int rfd = pipefd[0];
    int wfd = pipefd[1];

    int nfds = wfd + 1;
    local_fd_set wfds;
    local_fd_set_zero(&wfds);
    local_fd_set_bit(wfd, &wfds);

    long ret = sys_pselect6(nfds, NULL, &wfds, NULL, NULL, &req_mask);
    fut_vfs_close(rfd);
    fut_vfs_close(wfd);

    if (ret != 1) {
        fut_printf("[POLL-TEST] ✗ pselect6() returned %ld\n", ret);
        fut_test_fail(POLL_TEST_PSELECT6_SIGMASK);
        return;
    }
    if (!local_fd_is_set(wfd, &wfds)) {
        fut_printf("[POLL-TEST] ✗ pselect6: pipe write-end not ready for writing\n");
        fut_test_fail(POLL_TEST_PSELECT6_SIGMASK);
        return;
    }

    uint64_t restored = __atomic_load_n(&task->signal_mask, __ATOMIC_ACQUIRE);
    if (restored != old_mask) {
        fut_printf("[POLL-TEST] ✗ signal mask not restored: old=0x%llx new=0x%llx\n",
                   (unsigned long long)old_mask, (unsigned long long)restored);
        __atomic_store_n(&task->signal_mask, old_mask, __ATOMIC_RELEASE);
        fut_test_fail(POLL_TEST_PSELECT6_SIGMASK);
        return;
    }

    fut_printf("[POLL-TEST] ✓ pselect6() temporarily applied and restored signal mask\n");
    fut_test_pass();
}

/* ============================================================
 * Test 9: poll() with nfds=0 honors finite timeout
 * ============================================================ */
static void test_poll_timeout_only(void) {
    fut_printf("[POLL-TEST] Test 9: poll() timeout-only sleep\n");

    const int timeout_ms = 25;
    uint64_t start_ns = fut_get_time_ns();
    long ret = sys_poll(NULL, 0, timeout_ms);
    uint64_t end_ns = fut_get_time_ns();
    uint64_t elapsed_ms = (end_ns - start_ns) / 1000000ULL;

    if (ret != 0) {
        fut_printf("[POLL-TEST] ✗ poll(NULL, 0, %d) returned %ld\n", timeout_ms, ret);
        fut_test_fail(POLL_TEST_TIMEOUT_ONLY);
        return;
    }

    if (elapsed_ms < 10) {
        fut_printf("[POLL-TEST] ✗ poll timeout returned too quickly: %llu ms\n",
                   (unsigned long long)elapsed_ms);
        fut_test_fail(POLL_TEST_TIMEOUT_ONLY);
        return;
    }

    fut_printf("[POLL-TEST] ✓ poll(NULL, 0, %d) delayed for %llu ms\n",
               timeout_ms, (unsigned long long)elapsed_ms);
    fut_test_pass();
}

/* ============================================================
 * Test 10: timerfd transitions to readable after expiration
 * ============================================================ */
static void test_poll_timerfd_ready(void) {
    fut_printf("[POLL-TEST] Test 10: timerfd poll/read readiness\n");

    long tfd = sys_timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    if (tfd < 0) {
        fut_printf("[POLL-TEST] ✗ timerfd_create failed: %ld\n", tfd);
        fut_test_fail(POLL_TEST_TIMERFD_READY);
        return;
    }

    struct pollfd pfd = { .fd = (int)tfd, .events = POLLIN, .revents = 0 };
    long ret = sys_poll(&pfd, 1, 0);
    if (ret < 0 || (pfd.revents & POLLIN)) {
        fut_printf("[POLL-TEST] ✗ disarmed timerfd unexpectedly readable (ret=%ld revents=0x%x)\n",
                   ret, pfd.revents);
        fut_vfs_close((int)tfd);
        fut_test_fail(POLL_TEST_TIMERFD_READY);
        return;
    }

    uintptr_t user_arm_addr = g_user_lo + 0x20000;
    struct itimerspec *u_arm = (struct itimerspec *)map_user_page_for_test(user_arm_addr);
    if (!u_arm) {
        fut_printf("[POLL-TEST] ✗ failed to map user page for timerfd_settime\n");
        fut_vfs_close((int)tfd);
        fut_test_fail(POLL_TEST_TIMERFD_READY);
        return;
    }
    struct itimerspec arm = {0};
    arm.it_value.tv_nsec = 20 * 1000 * 1000;  /* 20 ms one-shot */
    memcpy(u_arm, &arm, sizeof(arm));

    ret = sys_timerfd_settime((int)tfd, 0, u_arm, NULL);
    if (ret != 0) {
        fut_printf("[POLL-TEST] ✗ timerfd_settime failed: %ld\n", ret);
        fut_vfs_close((int)tfd);
        fut_test_fail(POLL_TEST_TIMERFD_READY);
        return;
    }

    pfd.revents = 0;
    ret = sys_poll(&pfd, 1, 100);
    if (ret <= 0 || !(pfd.revents & POLLIN)) {
        fut_printf("[POLL-TEST] ✗ armed timerfd not readable after timeout (ret=%ld revents=0x%x)\n",
                   ret, pfd.revents);
        fut_vfs_close((int)tfd);
        fut_test_fail(POLL_TEST_TIMERFD_READY);
        return;
    }

    uintptr_t user_read_addr = g_user_lo + 0x22000;
    uint64_t *u_expirations = (uint64_t *)map_user_page_for_test(user_read_addr);
    if (!u_expirations) {
        fut_printf("[POLL-TEST] ✗ failed to map user page for timerfd read\n");
        fut_vfs_close((int)tfd);
        fut_test_fail(POLL_TEST_TIMERFD_READY);
        return;
    }

    ssize_t nr = fut_vfs_read((int)tfd, u_expirations, sizeof(*u_expirations));
    uint64_t expirations = 0;
    if (nr == (ssize_t)sizeof(*u_expirations)) {
        if (fut_copy_from_user(&expirations, u_expirations, sizeof(expirations)) != 0) {
            nr = -EFAULT;
        }
    }
    if (nr != (ssize_t)sizeof(expirations) || expirations == 0) {
        fut_printf("[POLL-TEST] ✗ timerfd read failed: nr=%zd expirations=%llu\n",
                   nr, (unsigned long long)expirations);
        fut_vfs_close((int)tfd);
        fut_test_fail(POLL_TEST_TIMERFD_READY);
        return;
    }

    fut_vfs_close((int)tfd);
    fut_printf("[POLL-TEST] ✓ timerfd became readable and returned expirations=%llu\n",
               (unsigned long long)expirations);
    fut_test_pass();
}

/* ============================================================
 * Test 11: signalfd poll/read readiness on pending signal
 * ============================================================ */
static void test_poll_signalfd_ready(void) {
    fut_printf("[POLL-TEST] Test 11: signalfd poll/read readiness\n");

    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_printf("[POLL-TEST] ✗ no current task\n");
        fut_test_fail(POLL_TEST_SIGNALFD_READY);
        return;
    }

    const int test_signo = SIGUSR1;
    uint64_t sig_bit = (1ULL << (test_signo - 1));
    __atomic_fetch_and(&task->pending_signals, ~sig_bit, __ATOMIC_ACQ_REL);

    uintptr_t user_mask_addr = g_user_lo + 0x21000;
    uint64_t *u_mask = (uint64_t *)map_user_page_for_test(user_mask_addr);
    if (!u_mask) {
        fut_printf("[POLL-TEST] ✗ failed to map user page for signalfd4 mask\n");
        fut_test_fail(POLL_TEST_SIGNALFD_READY);
        return;
    }
    *u_mask = sig_bit;

    long sfd = sys_signalfd4(-1, u_mask, sizeof(*u_mask), SFD_NONBLOCK);
    if (sfd < 0) {
        fut_printf("[POLL-TEST] ✗ signalfd4 failed: %ld\n", sfd);
        fut_test_fail(POLL_TEST_SIGNALFD_READY);
        return;
    }

    struct pollfd pfd = { .fd = (int)sfd, .events = POLLIN, .revents = 0 };
    long ret = sys_poll(&pfd, 1, 0);
    if (ret < 0 || (pfd.revents & POLLIN)) {
        fut_printf("[POLL-TEST] ✗ empty signalfd unexpectedly readable (ret=%ld revents=0x%x)\n",
                   ret, pfd.revents);
        fut_vfs_close((int)sfd);
        fut_test_fail(POLL_TEST_SIGNALFD_READY);
        return;
    }

    int sret = fut_signal_send(task, test_signo);
    if (sret != 0) {
        fut_printf("[POLL-TEST] ✗ fut_signal_send(signo=%d) failed: %d\n", test_signo, sret);
        fut_vfs_close((int)sfd);
        fut_test_fail(POLL_TEST_SIGNALFD_READY);
        return;
    }

    pfd.revents = 0;
    ret = sys_poll(&pfd, 1, 0);
    if (ret <= 0 || !(pfd.revents & POLLIN)) {
        fut_printf("[POLL-TEST] ✗ signalfd not readable after queued signal (ret=%ld revents=0x%x)\n",
                   ret, pfd.revents);
        fut_vfs_close((int)sfd);
        fut_test_fail(POLL_TEST_SIGNALFD_READY);
        return;
    }

    uintptr_t user_info_addr = g_user_lo + 0x23000;
    struct test_signalfd_siginfo *u_info =
        (struct test_signalfd_siginfo *)map_user_page_for_test(user_info_addr);
    if (!u_info) {
        fut_printf("[POLL-TEST] ✗ failed to map user page for signalfd read\n");
        fut_vfs_close((int)sfd);
        fut_test_fail(POLL_TEST_SIGNALFD_READY);
        return;
    }

    struct test_signalfd_siginfo info;
    memset(&info, 0, sizeof(info));
    ssize_t nr = fut_vfs_read((int)sfd, u_info, sizeof(info));
    if (nr == (ssize_t)sizeof(info)) {
        if (fut_copy_from_user(&info, u_info, sizeof(info)) != 0) {
            nr = -EFAULT;
        }
    }
    if (nr != (ssize_t)sizeof(info) || info.ssi_signo != (uint32_t)test_signo) {
        fut_printf("[POLL-TEST] ✗ signalfd read mismatch: nr=%zd signo=%u\n",
                   nr, info.ssi_signo);
        fut_vfs_close((int)sfd);
        fut_test_fail(POLL_TEST_SIGNALFD_READY);
        return;
    }

    fut_vfs_close((int)sfd);
    fut_printf("[POLL-TEST] ✓ signalfd readable with signo=%d info\n", test_signo);
    fut_test_pass();
}

/* ============================================================
 * Test 12: pipe EOF detection via poll (EPOLLHUP + EPOLLIN)
 * ============================================================ */
static void test_poll_pipe_eof(void) {
    fut_printf("[POLL-TEST] Test 12: pipe EOF detection via poll\n");

    int pipefd[2];
    long ret = sys_pipe(pipefd);
    if (ret != 0) {
        fut_printf("[POLL-TEST] ✗ pipe() failed: %ld\n", ret);
        fut_test_fail(POLL_TEST_PIPE_EOF);
        return;
    }

    /* Close write end — read end should now report HUP + readable (EOF) */
    fut_vfs_close(pipefd[1]);

    struct pollfd pfd = { .fd = pipefd[0], .events = POLLIN, .revents = 0 };
    ret = sys_poll(&pfd, 1, 0);

    if (ret <= 0) {
        fut_printf("[POLL-TEST] ✗ poll on EOF pipe returned %ld (expected 1)\n", ret);
        fut_vfs_close(pipefd[0]);
        fut_test_fail(POLL_TEST_PIPE_EOF);
        return;
    }

    /* Should have POLLIN (EOF is readable) and POLLHUP */
    if (!(pfd.revents & POLLIN)) {
        fut_printf("[POLL-TEST] ✗ EOF pipe missing POLLIN: revents=0x%x\n", pfd.revents);
        fut_vfs_close(pipefd[0]);
        fut_test_fail(POLL_TEST_PIPE_EOF);
        return;
    }

    if (!(pfd.revents & POLLHUP)) {
        fut_printf("[POLL-TEST] ✗ EOF pipe missing POLLHUP: revents=0x%x\n", pfd.revents);
        fut_vfs_close(pipefd[0]);
        fut_test_fail(POLL_TEST_PIPE_EOF);
        return;
    }

    /* Verify read returns 0 (EOF) */
    char buf[4];
    ssize_t nr = fut_vfs_read(pipefd[0], buf, sizeof(buf));
    if (nr != 0) {
        fut_printf("[POLL-TEST] ✗ read on EOF pipe returned %zd (expected 0)\n", nr);
        fut_vfs_close(pipefd[0]);
        fut_test_fail(POLL_TEST_PIPE_EOF);
        return;
    }

    fut_vfs_close(pipefd[0]);
    fut_printf("[POLL-TEST] ✓ pipe EOF: POLLIN|POLLHUP detected, read returns 0\n");
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
    test_pselect6_pipe();
    test_pselect6_sigmask_restore();
    test_poll_timeout_only();
    test_poll_timerfd_ready();
    test_poll_signalfd_ready();
    test_poll_pipe_eof();

    fut_printf("[POLL-TEST] ========================================\n");
    fut_printf("[POLL-TEST] All poll/select tests done\n");
    fut_printf("[POLL-TEST] ========================================\n");
}
