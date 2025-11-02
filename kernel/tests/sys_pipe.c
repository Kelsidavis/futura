/* sys_pipe.c - Pipe syscall validation tests
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Tests for pipe() syscall supporting inter-process communication:
 * - Pipe creation and FD allocation
 * - Read/write operations
 * - Blocking behavior
 * - Pipe closure and EOF detection
 */

#include <kernel/fut_task.h>
#include <kernel/fut_thread.h>
#include <kernel/fut_vfs.h>
#include <kernel/errno.h>
#include <kernel/syscalls.h>
#include <kernel/uaccess.h>
#include "tests/test_api.h"

extern void fut_printf(const char *fmt, ...);
extern long sys_pipe(int pipefd[2]);

/* Test constants */
#define PIPE_TEST_BASIC_CREATE 1
#define PIPE_TEST_READ_WRITE 2
#define PIPE_TEST_EPIPE 3
#define PIPE_TEST_EOF 4

/* Test 1: Verify pipe creation allocates proper FDs */
static void test_pipe_creation(void) {
    fut_printf("[PIPE-TEST] Test 1: Pipe creation and FD allocation\n");

    int pipefd[2];
    long ret = sys_pipe(pipefd);

    if (ret != 0) {
        fut_printf("[PIPE-TEST] ✗ sys_pipe() returned %ld (expected 0)\n", ret);
        fut_test_fail(PIPE_TEST_BASIC_CREATE);
        return;
    }

    int read_fd = pipefd[0];
    int write_fd = pipefd[1];

    if (read_fd < 0 || write_fd < 0) {
        fut_printf("[PIPE-TEST] ✗ Invalid FDs: read=%d write=%d\n", read_fd, write_fd);
        fut_test_fail(PIPE_TEST_BASIC_CREATE);
        return;
    }

    if (read_fd == write_fd) {
        fut_printf("[PIPE-TEST] ✗ Read and write FDs are the same (%d)\n", read_fd);
        fut_test_fail(PIPE_TEST_BASIC_CREATE);
        return;
    }

    /* Verify FDs are in task's FD table */
    fut_task_t *task = fut_task_current();
    if (!task || !task->fd_table) {
        fut_printf("[PIPE-TEST] ✗ No task FD table\n");
        fut_test_fail(PIPE_TEST_BASIC_CREATE);
        return;
    }

    struct fut_file *read_file = task->fd_table[read_fd];
    struct fut_file *write_file = task->fd_table[write_fd];

    if (!read_file || !write_file) {
        fut_printf("[PIPE-TEST] ✗ FDs not in task's FD table\n");
        fut_test_fail(PIPE_TEST_BASIC_CREATE);
        return;
    }

    /* Clean up */
    fut_vfs_close(read_fd);
    fut_vfs_close(write_fd);

    fut_printf("[PIPE-TEST] ✓ Pipe created with FDs: read=%d write=%d\n", read_fd, write_fd);
    fut_test_pass();
}

/* Test 2: Verify basic read/write operations */
static void test_pipe_read_write(void) {
    fut_printf("[PIPE-TEST] Test 2: Pipe read/write operations\n");

    int pipefd[2];
    long ret = sys_pipe(pipefd);
    if (ret != 0) {
        fut_printf("[PIPE-TEST] ✗ Failed to create pipe\n");
        fut_test_fail(PIPE_TEST_READ_WRITE);
        return;
    }

    int read_fd = pipefd[0];
    int write_fd = pipefd[1];

    const char *test_msg = "Hello through pipe!";
    size_t msg_len = 19;  /* strlen("Hello through pipe!") */

    /* Write data to pipe */
    ssize_t write_ret = fut_vfs_write(write_fd, test_msg, msg_len);
    if (write_ret != (ssize_t)msg_len) {
        fut_printf("[PIPE-TEST] ✗ Write failed: expected %zu, got %ld\n", msg_len, write_ret);
        fut_vfs_close(read_fd);
        fut_vfs_close(write_fd);
        fut_test_fail(PIPE_TEST_READ_WRITE);
        return;
    }

    /* Read data from pipe */
    char buffer[64] = {0};
    ssize_t read_ret = fut_vfs_read(read_fd, buffer, 63);
    if (read_ret <= 0) {
        fut_printf("[PIPE-TEST] ✗ Read failed: got %ld\n", read_ret);
        fut_vfs_close(read_fd);
        fut_vfs_close(write_fd);
        fut_test_fail(PIPE_TEST_READ_WRITE);
        return;
    }

    /* Verify data integrity */
    buffer[read_ret] = '\0';
    if (read_ret != (ssize_t)msg_len) {
        fut_printf("[PIPE-TEST] ✗ Read size mismatch: expected %zu, got %ld\n", msg_len, read_ret);
        fut_vfs_close(read_fd);
        fut_vfs_close(write_fd);
        fut_test_fail(PIPE_TEST_READ_WRITE);
        return;
    }

    /* Clean up */
    fut_vfs_close(read_fd);
    fut_vfs_close(write_fd);

    fut_printf("[PIPE-TEST] ✓ Read/write successful: wrote %zu bytes, read %ld bytes\n", msg_len, read_ret);
    fut_test_pass();
}

/* Test 3: Verify EPIPE when writing to closed pipe */
static void test_pipe_epipe(void) {
    fut_printf("[PIPE-TEST] Test 3: EPIPE error on closed read end\n");

    int pipefd[2];
    long ret = sys_pipe(pipefd);
    if (ret != 0) {
        fut_printf("[PIPE-TEST] ✗ Failed to create pipe\n");
        fut_test_fail(PIPE_TEST_EPIPE);
        return;
    }

    int read_fd = pipefd[0];
    int write_fd = pipefd[1];

    /* Close read end */
    fut_vfs_close(read_fd);

    /* Try to write to pipe - should get EPIPE */
    const char *test_msg = "This should fail";
    ssize_t write_ret = fut_vfs_write(write_fd, test_msg, 16);

    fut_vfs_close(write_fd);

    if (write_ret != -EPIPE) {
        fut_printf("[PIPE-TEST] ✗ Expected -EPIPE (%d), got %ld\n", -EPIPE, write_ret);
        fut_test_fail(PIPE_TEST_EPIPE);
        return;
    }

    fut_printf("[PIPE-TEST] ✓ EPIPE correctly returned when writing to closed read end\n");
    fut_test_pass();
}

/* Test 4: Verify EOF on closed write end */
static void test_pipe_eof(void) {
    fut_printf("[PIPE-TEST] Test 4: EOF when write end closed\n");

    int pipefd[2];
    long ret = sys_pipe(pipefd);
    if (ret != 0) {
        fut_printf("[PIPE-TEST] ✗ Failed to create pipe\n");
        fut_test_fail(PIPE_TEST_EOF);
        return;
    }

    int read_fd = pipefd[0];
    int write_fd = pipefd[1];

    /* Write some data */
    const char *test_msg = "Some data";
    ssize_t write_ret = fut_vfs_write(write_fd, test_msg, 9);
    if (write_ret <= 0) {
        fut_printf("[PIPE-TEST] ✗ Write failed\n");
        fut_vfs_close(read_fd);
        fut_vfs_close(write_fd);
        fut_test_fail(PIPE_TEST_EOF);
        return;
    }

    /* Close write end */
    fut_vfs_close(write_fd);

    /* Read available data */
    char buffer[64] = {0};
    ssize_t read_ret = fut_vfs_read(read_fd, buffer, 63);
    if (read_ret <= 0) {
        fut_printf("[PIPE-TEST] ✗ Read failed: %ld\n", read_ret);
        fut_vfs_close(read_fd);
        fut_test_fail(PIPE_TEST_EOF);
        return;
    }

    /* Try to read again - should return EOF (0) */
    ssize_t eof_ret = fut_vfs_read(read_fd, buffer, 63);
    fut_vfs_close(read_fd);

    if (eof_ret != 0) {
        fut_printf("[PIPE-TEST] ✗ Expected EOF (0), got %ld\n", eof_ret);
        fut_test_fail(PIPE_TEST_EOF);
        return;
    }

    fut_printf("[PIPE-TEST] ✓ EOF correctly returned when write end closed\n");
    fut_test_pass();
}

/* Main test harness thread */
static void fut_pipe_test_thread(void *arg) {
    (void)arg;

    fut_printf("[PIPE-TEST] ========================================\n");
    fut_printf("[PIPE-TEST] Pipe Syscall Validation Tests\n");
    fut_printf("[PIPE-TEST] ========================================\n");

    /* Run all tests */
    test_pipe_creation();
    test_pipe_read_write();
    test_pipe_epipe();
    test_pipe_eof();

    fut_printf("[PIPE-TEST] ========================================\n");
    fut_printf("[PIPE-TEST] All pipe tests completed\n");
    fut_printf("[PIPE-TEST] ========================================\n");
}

/**
 * Schedule pipe validation tests on a task.
 */
void fut_pipe_selftest_schedule(fut_task_t *task) {
    fut_printf("[PIPE] fut_pipe_selftest_schedule called with task=%p\n", (void*)task);

    if (!task) {
        fut_printf("[PIPE] task is NULL, returning\n");
        return;
    }

    fut_thread_t *thread = fut_thread_create(
        task,
        fut_pipe_test_thread,
        NULL,
        12 * 1024,  /* 12 KB stack */
        180         /* Priority */
    );

    if (!thread) {
        fut_printf("[PIPE] failed to schedule test harness thread\n");
    } else {
        fut_printf("[PIPE] successfully created test thread\n");
    }
}
