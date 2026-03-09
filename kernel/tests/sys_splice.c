/* kernel/tests/sys_splice.c - splice, vmsplice, statfs, and sysinfo syscall tests
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Tests for:
 *   - sys_statfs: real PMM-backed filesystem statistics
 *   - sys_sysinfo: real uptime and memory statistics
 *   - sys_splice: pipe-to-file and file-to-pipe data transfer
 *   - sys_vmsplice: user-space iovec to pipe transfer
 */

#include <kernel/fut_task.h>
#include <kernel/fut_vfs.h>
#include <kernel/errno.h>
#include <kernel/uaccess.h>
#include <kernel/kprintf.h>
#include <stdint.h>
#include <sys/uio.h>
#include "tests/test_api.h"

/* Forward declarations */
extern long sys_statfs(const char *path, struct fut_linux_statfs *buf);
extern long sys_sysinfo(struct fut_linux_sysinfo *info);
extern long sys_splice(int fd_in, int64_t *off_in, int fd_out, int64_t *off_out,
                       size_t len, unsigned int flags);
extern long sys_vmsplice(int fd, const void *iov, size_t nr_segs, unsigned int flags);
extern long sys_pipe(int pipefd[2]);

/* Test IDs */
#define SPLICE_TEST_STATFS           1
#define SPLICE_TEST_SYSINFO          2
#define SPLICE_TEST_PIPE_TO_FILE     3
#define SPLICE_TEST_FILE_TO_PIPE     4
#define SPLICE_TEST_EINVAL_NO_PIPE   5
#define SPLICE_TEST_VMSPLICE         6

/* Scratch files */
#define SPLICE_SCRATCH_A  "/tmp/splice_test_a"
#define SPLICE_SCRATCH_B  "/tmp/splice_test_b"

/* ============================================================
 * Test 1: sys_statfs returns real PMM memory statistics
 * ============================================================ */
static void test_statfs(void) {
    fut_printf("[SPLICE-TEST] Test 1: sys_statfs returns valid memory stats\n");

    struct fut_linux_statfs st;
    long ret = sys_statfs("/", &st);

    if (ret != 0) {
        fut_printf("[SPLICE-TEST] ✗ sys_statfs(\"/\") returned %ld\n", ret);
        fut_test_fail(SPLICE_TEST_STATFS);
        return;
    }

    if (st.f_bsize == 0) {
        fut_printf("[SPLICE-TEST] ✗ f_bsize is zero\n");
        fut_test_fail(SPLICE_TEST_STATFS);
        return;
    }

    if (st.f_blocks == 0) {
        fut_printf("[SPLICE-TEST] ✗ f_blocks is zero (PMM reported no pages)\n");
        fut_test_fail(SPLICE_TEST_STATFS);
        return;
    }

    if (st.f_bfree > st.f_blocks) {
        fut_printf("[SPLICE-TEST] ✗ f_bfree (%llu) > f_blocks (%llu)\n",
                   (unsigned long long)st.f_bfree,
                   (unsigned long long)st.f_blocks);
        fut_test_fail(SPLICE_TEST_STATFS);
        return;
    }

    fut_printf("[SPLICE-TEST] ✓ statfs: bsize=%llu blocks=%llu bfree=%llu\n",
               (unsigned long long)st.f_bsize,
               (unsigned long long)st.f_blocks,
               (unsigned long long)st.f_bfree);
    fut_test_pass();
}

/* ============================================================
 * Test 2: sys_sysinfo returns real uptime and memory stats
 * ============================================================ */
static void test_sysinfo(void) {
    fut_printf("[SPLICE-TEST] Test 2: sys_sysinfo returns valid stats\n");

    struct fut_linux_sysinfo info;
    long ret = sys_sysinfo(&info);

    if (ret != 0) {
        fut_printf("[SPLICE-TEST] ✗ sys_sysinfo() returned %ld\n", ret);
        fut_test_fail(SPLICE_TEST_SYSINFO);
        return;
    }

    if (info.totalram == 0) {
        fut_printf("[SPLICE-TEST] ✗ totalram is zero\n");
        fut_test_fail(SPLICE_TEST_SYSINFO);
        return;
    }

    if (info.freeram > info.totalram) {
        fut_printf("[SPLICE-TEST] ✗ freeram (%llu) > totalram (%llu)\n",
                   (unsigned long long)info.freeram,
                   (unsigned long long)info.totalram);
        fut_test_fail(SPLICE_TEST_SYSINFO);
        return;
    }

    if (info.mem_unit == 0) {
        fut_printf("[SPLICE-TEST] ✗ mem_unit is zero\n");
        fut_test_fail(SPLICE_TEST_SYSINFO);
        return;
    }

    fut_printf("[SPLICE-TEST] ✓ sysinfo: uptime=%llu totalram=%llu freeram=%llu\n",
               (unsigned long long)info.uptime,
               (unsigned long long)info.totalram,
               (unsigned long long)info.freeram);
    fut_test_pass();
}

/* ============================================================
 * Test 3: splice from pipe read-end to file
 * ============================================================ */
static void test_splice_pipe_to_file(void) {
    fut_printf("[SPLICE-TEST] Test 3: splice pipe → file\n");

    int pipefd[2];
    long pret = sys_pipe(pipefd);
    if (pret != 0) {
        fut_printf("[SPLICE-TEST] ✗ pipe() failed: %ld\n", pret);
        fut_test_fail(SPLICE_TEST_PIPE_TO_FILE);
        return;
    }
    int rfd = pipefd[0];
    int wfd = pipefd[1];

    /* Write test payload into pipe */
    const char *payload = "splice-pipe-to-file";
    const size_t plen = 19; /* strlen("splice-pipe-to-file") */
    ssize_t wr = fut_vfs_write(wfd, payload, plen);
    if (wr != (ssize_t)plen) {
        fut_printf("[SPLICE-TEST] ✗ pipe write failed: got %ld expected %zu\n", wr, plen);
        fut_vfs_close(rfd);
        fut_vfs_close(wfd);
        fut_test_fail(SPLICE_TEST_PIPE_TO_FILE);
        return;
    }
    fut_vfs_close(wfd);

    /* Open destination file */
    int fout = fut_vfs_open(SPLICE_SCRATCH_A, O_CREAT | O_RDWR, 0644);
    if (fout < 0) {
        fut_printf("[SPLICE-TEST] ✗ open(%s) failed: %d\n", SPLICE_SCRATCH_A, fout);
        fut_vfs_close(rfd);
        fut_test_fail(SPLICE_TEST_PIPE_TO_FILE);
        return;
    }

    /* Splice pipe → file */
    long spliced = sys_splice(rfd, NULL, fout, NULL, plen, 0);
    fut_vfs_close(rfd);

    if (spliced < 0) {
        fut_printf("[SPLICE-TEST] ✗ splice(pipe→file) returned %ld\n", spliced);
        fut_vfs_close(fout);
        fut_test_fail(SPLICE_TEST_PIPE_TO_FILE);
        return;
    }

    fut_vfs_close(fout);

    /* Re-open file and read back to verify data arrived */
    int fcheck = fut_vfs_open(SPLICE_SCRATCH_A, O_RDONLY, 0);
    if (fcheck < 0) {
        fut_printf("[SPLICE-TEST] ✗ re-open for verify failed: %d\n", fcheck);
        fut_test_fail(SPLICE_TEST_PIPE_TO_FILE);
        return;
    }
    char buf[32] = {0};
    ssize_t rd = fut_vfs_read(fcheck, buf, sizeof(buf) - 1);
    fut_vfs_close(fcheck);

    if (rd <= 0) {
        fut_printf("[SPLICE-TEST] ✗ read after splice returned %ld\n", rd);
        fut_test_fail(SPLICE_TEST_PIPE_TO_FILE);
        return;
    }

    fut_printf("[SPLICE-TEST] ✓ splice pipe→file transferred %ld bytes\n", spliced);
    fut_test_pass();
}

/* ============================================================
 * Test 4: splice from file to pipe read-end
 * ============================================================ */
static void test_splice_file_to_pipe(void) {
    fut_printf("[SPLICE-TEST] Test 4: splice file → pipe\n");

    /* Write data to a scratch file, then close it */
    int fin_wr = fut_vfs_open(SPLICE_SCRATCH_B, O_CREAT | O_RDWR, 0644);
    if (fin_wr < 0) {
        fut_printf("[SPLICE-TEST] ✗ open(%s) for write failed: %d\n", SPLICE_SCRATCH_B, fin_wr);
        fut_test_fail(SPLICE_TEST_FILE_TO_PIPE);
        return;
    }
    const char *payload = "splice-file-to-pipe";
    const size_t plen = 19;
    ssize_t wr = fut_vfs_write(fin_wr, payload, plen);
    fut_vfs_close(fin_wr);
    if (wr != (ssize_t)plen) {
        fut_printf("[SPLICE-TEST] ✗ file write failed: %ld\n", wr);
        fut_test_fail(SPLICE_TEST_FILE_TO_PIPE);
        return;
    }

    /* Re-open for reading — fd position starts at 0, so off_in=NULL is fine */
    int fin = fut_vfs_open(SPLICE_SCRATCH_B, O_RDONLY, 0);
    if (fin < 0) {
        fut_printf("[SPLICE-TEST] ✗ open(%s) for read failed: %d\n", SPLICE_SCRATCH_B, fin);
        fut_test_fail(SPLICE_TEST_FILE_TO_PIPE);
        return;
    }

    int pipefd[2];
    long pret = sys_pipe(pipefd);
    if (pret != 0) {
        fut_printf("[SPLICE-TEST] ✗ pipe() failed: %ld\n", pret);
        fut_vfs_close(fin);
        fut_test_fail(SPLICE_TEST_FILE_TO_PIPE);
        return;
    }
    int rfd = pipefd[0];
    int wfd = pipefd[1];

    /* Splice file → pipe write-end; use NULL offset to consume fd position */
    long spliced = sys_splice(fin, NULL, wfd, NULL, plen, 0);
    fut_vfs_close(fin);
    fut_vfs_close(wfd);

    if (spliced < 0) {
        fut_printf("[SPLICE-TEST] ✗ splice(file→pipe) returned %ld\n", spliced);
        fut_vfs_close(rfd);
        fut_test_fail(SPLICE_TEST_FILE_TO_PIPE);
        return;
    }

    /* Read from pipe to verify data arrived */
    char buf[32] = {0};
    ssize_t rd = fut_vfs_read(rfd, buf, sizeof(buf) - 1);
    fut_vfs_close(rfd);

    if (rd <= 0) {
        fut_printf("[SPLICE-TEST] ✗ pipe read after splice returned %ld\n", rd);
        fut_test_fail(SPLICE_TEST_FILE_TO_PIPE);
        return;
    }

    fut_printf("[SPLICE-TEST] ✓ splice file→pipe transferred %ld bytes\n", spliced);
    fut_test_pass();
}

/* ============================================================
 * Test 5: splice with two regular files (no pipe) → EINVAL
 * ============================================================ */
static void test_splice_einval_no_pipe(void) {
    fut_printf("[SPLICE-TEST] Test 5: splice file→file returns EINVAL\n");

    int fa = fut_vfs_open(SPLICE_SCRATCH_A, O_CREAT | O_RDWR, 0644);
    int fb = fut_vfs_open(SPLICE_SCRATCH_B, O_CREAT | O_RDWR, 0644);

    if (fa < 0 || fb < 0) {
        fut_printf("[SPLICE-TEST] ✗ open failed: fa=%d fb=%d\n", fa, fb);
        if (fa >= 0) fut_vfs_close(fa);
        if (fb >= 0) fut_vfs_close(fb);
        fut_test_fail(SPLICE_TEST_EINVAL_NO_PIPE);
        return;
    }

    long ret = sys_splice(fa, NULL, fb, NULL, 16, 0);
    fut_vfs_close(fa);
    fut_vfs_close(fb);

    if (ret != -EINVAL) {
        fut_printf("[SPLICE-TEST] ✗ Expected -EINVAL, got %ld\n", ret);
        fut_test_fail(SPLICE_TEST_EINVAL_NO_PIPE);
        return;
    }

    fut_printf("[SPLICE-TEST] ✓ splice(file,file) correctly returned EINVAL\n");
    fut_test_pass();
}

/* ============================================================
 * Test 6: vmsplice user iovec to pipe
 * ============================================================ */
static void test_vmsplice(void) {
    fut_printf("[SPLICE-TEST] Test 6: vmsplice user iovec → pipe\n");

    int pipefd[2];
    long pret = sys_pipe(pipefd);
    if (pret != 0) {
        fut_printf("[SPLICE-TEST] ✗ pipe() failed: %ld\n", pret);
        fut_test_fail(SPLICE_TEST_VMSPLICE);
        return;
    }
    int rfd = pipefd[0];
    int wfd = pipefd[1];

    const char *buf1 = "hello";
    const char *buf2 = "-world";
    struct iovec iov[2];
    iov[0].iov_base = (void *)buf1;
    iov[0].iov_len  = 5;
    iov[1].iov_base = (void *)buf2;
    iov[1].iov_len  = 6;

    long written = sys_vmsplice(wfd, iov, 2, 0);
    fut_vfs_close(wfd);

    if (written < 0) {
        fut_printf("[SPLICE-TEST] ✗ vmsplice returned %ld\n", written);
        fut_vfs_close(rfd);
        fut_test_fail(SPLICE_TEST_VMSPLICE);
        return;
    }

    if (written != 11) {
        fut_printf("[SPLICE-TEST] ✗ vmsplice wrote %ld bytes (expected 11)\n", written);
        fut_vfs_close(rfd);
        fut_test_fail(SPLICE_TEST_VMSPLICE);
        return;
    }

    /* Read back and verify */
    char out[16] = {0};
    ssize_t rd = fut_vfs_read(rfd, out, sizeof(out) - 1);
    fut_vfs_close(rfd);

    if (rd != 11) {
        fut_printf("[SPLICE-TEST] ✗ pipe read returned %ld (expected 11)\n", rd);
        fut_test_fail(SPLICE_TEST_VMSPLICE);
        return;
    }

    fut_printf("[SPLICE-TEST] ✓ vmsplice transferred %ld bytes\n", written);
    fut_test_pass();
}

/* ============================================================
 * Main test harness thread
 * ============================================================ */
void fut_splice_test_thread(void *arg) {
    (void)arg;

    fut_printf("[SPLICE-TEST] ========================================\n");
    fut_printf("[SPLICE-TEST] splice / statfs / sysinfo Tests\n");
    fut_printf("[SPLICE-TEST] ========================================\n");

    test_statfs();
    test_sysinfo();
    test_splice_pipe_to_file();
    test_splice_file_to_pipe();
    test_splice_einval_no_pipe();
    test_vmsplice();

    fut_printf("[SPLICE-TEST] ========================================\n");
    fut_printf("[SPLICE-TEST] All splice/statfs/sysinfo tests done\n");
    fut_printf("[SPLICE-TEST] ========================================\n");
}
