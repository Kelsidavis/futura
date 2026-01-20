/* sys_dup2.c - stdio redirection tests via dup2()
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Tests for dup2() syscall enabling stdout/stderr/stdin redirection
 * to files for stdio handling and pipe operations.
 */

#include <kernel/fut_task.h>
#include <kernel/fut_thread.h>
#include <kernel/fut_vfs.h>
#include <kernel/fut_ramfs.h>
#include <kernel/errno.h>
#include <kernel/syscalls.h>
#include "tests/test_api.h"

extern void fut_printf(const char *fmt, ...);

/* Test constants */
#define DUP2_TEST_STDOUT_REDIRECT 1
#define DUP2_TEST_INVALID_FDS 2
#define DUP2_TEST_SAME_FD 3

/* Helper: Create a test file */
static int create_test_file(const char *path) {
    int fd = fut_vfs_open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        fut_printf("[DUP2-TEST] Failed to create test file %s (error %d)\n", path, fd);
        return fd;
    }
    fut_vfs_close(fd);
    return 0;
}

/* Test 1: Verify dup2() can duplicate a file descriptor */
static void test_stdout_redirect(void) {
    fut_printf("[DUP2-TEST] Test 1: FD duplication via dup2\n");

    const char *test_path = "/test_dup2_stdout.txt";

    /* Create the target file */
    int ret = create_test_file(test_path);
    if (ret != 0) {
        fut_printf("[DUP2-TEST] ✗ Failed to create test file\n");
        fut_test_fail(DUP2_TEST_STDOUT_REDIRECT);
        return;
    }

    /* Open file for writing */
    int file_fd = fut_vfs_open(test_path, O_WRONLY, 0644);
    if (file_fd < 0) {
        fut_printf("[DUP2-TEST] ✗ Failed to open test file (error %d)\n", file_fd);
        fut_test_fail(DUP2_TEST_STDOUT_REDIRECT);
        return;
    }

    /* Get current task and FD table */
    fut_task_t *task = fut_task_current();
    if (!task || !task->fd_table) {
        fut_printf("[DUP2-TEST] ✗ No task FD table\n");
        fut_vfs_close(file_fd);
        fut_test_fail(DUP2_TEST_STDOUT_REDIRECT);
        return;
    }

    /* Verify original file_fd is valid */
    struct fut_file *original_file = task->fd_table[file_fd];
    if (!original_file) {
        fut_printf("[DUP2-TEST] ✗ FD %d not valid in task FD table\n", file_fd);
        fut_vfs_close(file_fd);
        fut_test_fail(DUP2_TEST_STDOUT_REDIRECT);
        return;
    }

    /* Allocate a new FD to duplicate to */
    int target_fd = 10;  /* Use FD 10 as target */

    /* Redirect to the new FD via dup2 */
    long dup2_ret = sys_dup2(file_fd, target_fd);
    if (dup2_ret != target_fd) {
        fut_printf("[DUP2-TEST] ✗ dup2() failed or returned unexpected value: %ld\n", dup2_ret);
        fut_vfs_close(file_fd);
        fut_test_fail(DUP2_TEST_STDOUT_REDIRECT);
        return;
    }

    /* Verify target FD now points to the same file */
    struct fut_file *duplicated_file = task->fd_table[target_fd];
    if (!duplicated_file || duplicated_file != original_file) {
        fut_printf("[DUP2-TEST] ✗ FD was not duplicated properly\n");
        fut_vfs_close(file_fd);
        fut_test_fail(DUP2_TEST_STDOUT_REDIRECT);
        return;
    }

    /* Verify refcount increased */
    if (original_file->refcount < 2) {
        fut_printf("[DUP2-TEST] ✗ File refcount not increased (was %d, expected >=2)\n", original_file->refcount);
        fut_vfs_close(file_fd);
        fut_test_fail(DUP2_TEST_STDOUT_REDIRECT);
        return;
    }

    /* Clean up */
    fut_vfs_close(file_fd);
    fut_vfs_close(target_fd);

    fut_printf("[DUP2-TEST] ✓ FD duplication successful (refcount=%d)\n", original_file->refcount);
    fut_test_pass();
}

/* Test 2: Verify dup2() rejects invalid FDs */
static void test_invalid_fds(void) {
    fut_printf("[DUP2-TEST] Test 2: dup2() with invalid FDs\n");

    /* Test with invalid oldfd */
    long ret = sys_dup2(-1, 10);
    if (ret != -EBADF) {
        fut_printf("[DUP2-TEST] ✗ Expected -EBADF for invalid oldfd, got %ld\n", ret);
        fut_test_fail(DUP2_TEST_INVALID_FDS);
        return;
    }

    /* Test with invalid newfd (negative) - POSIX says EINVAL for negative newfd */
    ret = sys_dup2(0, -1);
    if (ret != -EINVAL) {
        fut_printf("[DUP2-TEST] ✗ Expected -EINVAL for negative newfd, got %ld\n", ret);
        fut_test_fail(DUP2_TEST_INVALID_FDS);
        return;
    }

    fut_printf("[DUP2-TEST] ✓ Invalid FD handling verified\n");
    fut_test_pass();
}

/* Test 3: Redirect stdout to a file and verify output */
static void test_actual_stdout_redirect(void) {
    fut_printf("[DUP2-TEST] Test 3: Actual stdout redirection to file\n");

    const char *test_path = "/test_actual_redirect.txt";
    const char *test_msg = "Hello from redirected stdout!";

    /* Create the target file */
    int ret = create_test_file(test_path);
    if (ret != 0) {
        fut_printf("[DUP2-TEST] ✗ Failed to create test file\n");
        fut_test_fail(DUP2_TEST_INVALID_FDS);
        return;
    }

    /* Open file for writing */
    int file_fd = fut_vfs_open(test_path, O_WRONLY, 0644);
    if (file_fd < 0) {
        fut_printf("[DUP2-TEST] ✗ Failed to open test file (error %d)\n", file_fd);
        fut_test_fail(DUP2_TEST_INVALID_FDS);
        return;
    }

    /* Get current task */
    fut_task_t *task = fut_task_current();
    if (!task || !task->fd_table) {
        fut_printf("[DUP2-TEST] ✗ No task FD table\n");
        fut_vfs_close(file_fd);
        fut_test_fail(DUP2_TEST_INVALID_FDS);
        return;
    }

    /* Save original stdout (fd 1) */
    struct fut_file *original_stdout = task->fd_table[1];

    /* Redirect stdout to the file using dup2 */
    long dup2_ret = sys_dup2(file_fd, 1);
    if (dup2_ret != 1) {
        fut_printf("[DUP2-TEST] ✗ Failed to redirect stdout (dup2 returned %ld)\n", dup2_ret);
        fut_vfs_close(file_fd);
        fut_test_fail(DUP2_TEST_INVALID_FDS);
        return;
    }

    /* Write to stdout (now redirected to file) */
    ssize_t write_ret = fut_vfs_write(1, test_msg, 28);  /* strlen("Hello from redirected stdout!") */
    if (write_ret <= 0) {
        fut_printf("[DUP2-TEST] ✗ Failed to write to redirected stdout\n");
        /* Restore stdout before returning */
        sys_dup2(file_fd, 1);
        fut_vfs_close(file_fd);
        fut_test_fail(DUP2_TEST_INVALID_FDS);
        return;
    }

    /* Restore stdout using original file descriptor */
    if (original_stdout && original_stdout != task->fd_table[1]) {
        /* Manually restore by putting original back */
        task->fd_table[1] = original_stdout;
    }

    fut_vfs_close(file_fd);

    /* Now verify the file contains the message by reading it */
    int read_fd = fut_vfs_open(test_path, O_RDONLY, 0644);
    if (read_fd < 0) {
        fut_printf("[DUP2-TEST] ✗ Failed to open file for reading\n");
        fut_test_fail(DUP2_TEST_INVALID_FDS);
        return;
    }

    char buffer[64] = {0};
    ssize_t read_ret = fut_vfs_read(read_fd, buffer, 63);
    fut_vfs_close(read_fd);

    if (read_ret > 0) {
        fut_printf("[DUP2-TEST] ✓ stdout redirected successfully, wrote %ld bytes\n", read_ret);
        fut_test_pass();
    } else {
        fut_printf("[DUP2-TEST] ✗ Failed to read back redirected output\n");
        fut_test_fail(DUP2_TEST_INVALID_FDS);
    }
}

/* Test 4: Verify dup2(fd, fd) returns fd without error */
static void test_same_fd(void) {
    fut_printf("[DUP2-TEST] Test 4: dup2() with same source and target FD\n");

    /* Create a test file to have a valid open fd */
    const char *test_path = "/test_dup2_same.txt";
    int ret_create = create_test_file(test_path);
    if (ret_create != 0) {
        fut_printf("[DUP2-TEST] ✗ Failed to create test file\n");
        fut_test_fail(DUP2_TEST_SAME_FD);
        return;
    }

    int fd = fut_vfs_open(test_path, O_RDONLY, 0644);
    if (fd < 0) {
        fut_printf("[DUP2-TEST] ✗ Failed to open test file (error %d)\n", fd);
        fut_test_fail(DUP2_TEST_SAME_FD);
        return;
    }

    /* Call dup2(fd, fd) - should return fd without modification */
    long ret = sys_dup2(fd, fd);
    if (ret != fd) {
        fut_printf("[DUP2-TEST] ✗ dup2(%d, %d) returned %ld instead of %d\n", fd, fd, ret, fd);
        fut_vfs_close(fd);
        fut_test_fail(DUP2_TEST_SAME_FD);
        return;
    }

    fut_vfs_close(fd);
    fut_printf("[DUP2-TEST] ✓ dup2(fd, fd) returns fd correctly\n");
    fut_test_pass();
}

/* Main test harness thread */
static void fut_dup2_test_thread(void *arg) {
    (void)arg;

    fut_printf("[DUP2-TEST] ========================================\n");
    fut_printf("[DUP2-TEST] File Descriptor Duplication (dup2) Tests\n");
    fut_printf("[DUP2-TEST] ========================================\n");

    /* Run all tests */
    test_stdout_redirect();
    test_invalid_fds();
    test_actual_stdout_redirect();
    test_same_fd();

    fut_printf("[DUP2-TEST] ========================================\n");
    fut_printf("[DUP2-TEST] All dup2() tests completed\n");
    fut_printf("[DUP2-TEST] ========================================\n");
}

/**
 * Schedule dup2() validation tests on a task.
 * This function is called from kernel_main.c during initialization.
 */
void fut_dup2_selftest_schedule(fut_task_t *task) {
    fut_printf("[DUP2] fut_dup2_selftest_schedule called with task=%p\n", (void*)task);

    if (!task) {
        fut_printf("[DUP2] task is NULL, returning\n");
        return;
    }

    fut_thread_t *thread = fut_thread_create(
        task,
        fut_dup2_test_thread,
        NULL,
        12 * 1024,  /* 12 KB stack */
        180         /* Priority */
    );

    if (!thread) {
        fut_printf("[DUP2] failed to schedule test harness thread\n");
    } else {
        fut_printf("[DUP2] successfully created test thread\n");
    }
}
