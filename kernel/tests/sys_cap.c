/* sys_cap.c - Capability syscall validation tests
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Tests for capability-based file operations:
 * - Capability handle creation (open_cap)
 * - Capability read/write operations
 * - Rights enforcement
 * - Capability cleanup (close_cap)
 */

#include <kernel/fut_task.h>
#include <kernel/fut_thread.h>
#include <kernel/fut_vfs.h>
#include <kernel/fut_object.h>
#include <kernel/fut_capability.h>
#include <kernel/errno.h>
#include <kernel/syscalls.h>
#include "tests/test_api.h"

extern void fut_printf(const char *fmt, ...);

/* VFS capability functions */
extern fut_handle_t fut_vfs_open_cap(const char *path, int flags, int mode);
extern long fut_vfs_read_cap(fut_handle_t handle, void *buffer, size_t count);
extern long fut_vfs_write_cap(fut_handle_t handle, const void *buffer, size_t count);
extern long fut_vfs_lseek_cap(fut_handle_t handle, int64_t offset, int whence);
extern int fut_vfs_close_cap(fut_handle_t handle);
extern int fut_vfs_fstat_cap(fut_handle_t handle, struct fut_stat *statbuf);

/* Test error codes */
#define CAP_TEST_OPEN       1
#define CAP_TEST_READ       2
#define CAP_TEST_WRITE      3
#define CAP_TEST_RIGHTS     4
#define CAP_TEST_CLOSE      5
#define CAP_TEST_INVALID    6
#define CAP_TEST_LSEEK      7

/* Number of tests */
#define CAP_TEST_COUNT 6

/* Test file path - use /tmp which is writable ramfs */
#define TEST_FILE_PATH "/tmp/cap_test_file"

/**
 * Test 1: Verify capability handle creation via open_cap
 */
static void test_cap_open(void) {
    fut_printf("[CAP-TEST] Test 1: Capability handle creation\n");

    /* First create a test file using regular VFS */
    int fd = fut_vfs_open(TEST_FILE_PATH, O_CREAT | O_RDWR, 0644);
    if (fd < 0) {
        fut_printf("[CAP-TEST] ✗ Failed to create test file: %d\n", fd);
        fut_test_fail(CAP_TEST_OPEN);
        return;
    }

    /* Write some test data */
    const char *test_data = "Hello Capability World!";
    long written = fut_vfs_write(fd, test_data, 23);
    fut_vfs_close(fd);

    if (written < 0) {
        fut_printf("[CAP-TEST] ✗ Failed to write test data: %ld\n", written);
        fut_test_fail(CAP_TEST_OPEN);
        return;
    }

    /* Now open with capability handle */
    fut_handle_t handle = fut_vfs_open_cap(TEST_FILE_PATH, O_RDONLY, 0);

    if (handle == FUT_INVALID_HANDLE) {
        fut_printf("[CAP-TEST] ✗ fut_vfs_open_cap() returned INVALID_HANDLE\n");
        fut_test_fail(CAP_TEST_OPEN);
        return;
    }

    /* Verify handle is valid (non-zero) */
    if (handle == 0) {
        fut_printf("[CAP-TEST] ✗ Capability handle is zero\n");
        fut_test_fail(CAP_TEST_OPEN);
        return;
    }

    /* Clean up */
    fut_vfs_close_cap(handle);

    fut_printf("[CAP-TEST] ✓ Capability handle created: 0x%lx\n", (unsigned long)handle);
    fut_test_pass();
}

/**
 * Test 2: Verify capability read operation
 */
static void test_cap_read(void) {
    fut_printf("[CAP-TEST] Test 2: Capability read operation\n");

    /* Open file with read capability */
    fut_handle_t handle = fut_vfs_open_cap(TEST_FILE_PATH, O_RDONLY, 0);
    if (handle == FUT_INVALID_HANDLE) {
        fut_printf("[CAP-TEST] ✗ Failed to open file for reading\n");
        fut_test_fail(CAP_TEST_READ);
        return;
    }

    /* Read data using capability handle */
    char buffer[64] = {0};
    long bytes_read = fut_vfs_read_cap(handle, buffer, sizeof(buffer) - 1);

    if (bytes_read < 0) {
        fut_printf("[CAP-TEST] ✗ fut_vfs_read_cap() failed: %ld\n", bytes_read);
        fut_vfs_close_cap(handle);
        fut_test_fail(CAP_TEST_READ);
        return;
    }

    if (bytes_read == 0) {
        fut_printf("[CAP-TEST] ✗ Read returned 0 bytes\n");
        fut_vfs_close_cap(handle);
        fut_test_fail(CAP_TEST_READ);
        return;
    }

    /* Verify we got the expected data */
    const char *expected = "Hello Capability World!";
    bool match = true;
    for (int i = 0; i < 23 && i < bytes_read; i++) {
        if (buffer[i] != expected[i]) {
            match = false;
            break;
        }
    }

    fut_vfs_close_cap(handle);

    if (!match) {
        fut_printf("[CAP-TEST] ✗ Data mismatch: got '%s'\n", buffer);
        fut_test_fail(CAP_TEST_READ);
        return;
    }

    fut_printf("[CAP-TEST] ✓ Read %ld bytes via capability: '%s'\n", bytes_read, buffer);
    fut_test_pass();
}

/**
 * Test 3: Verify capability write operation
 */
static void test_cap_write(void) {
    fut_printf("[CAP-TEST] Test 3: Capability write operation\n");

    /* Open file with write capability */
    fut_handle_t handle = fut_vfs_open_cap(TEST_FILE_PATH, O_WRONLY | O_TRUNC, 0);
    if (handle == FUT_INVALID_HANDLE) {
        fut_printf("[CAP-TEST] ✗ Failed to open file for writing\n");
        fut_test_fail(CAP_TEST_WRITE);
        return;
    }

    /* Write data using capability handle */
    const char *write_data = "Capability Write Test!";
    long bytes_written = fut_vfs_write_cap(handle, write_data, 22);

    if (bytes_written < 0) {
        fut_printf("[CAP-TEST] ✗ fut_vfs_write_cap() failed: %ld\n", bytes_written);
        fut_vfs_close_cap(handle);
        fut_test_fail(CAP_TEST_WRITE);
        return;
    }

    if (bytes_written != 22) {
        fut_printf("[CAP-TEST] ✗ Expected to write 22 bytes, wrote %ld\n", bytes_written);
        fut_vfs_close_cap(handle);
        fut_test_fail(CAP_TEST_WRITE);
        return;
    }

    fut_vfs_close_cap(handle);

    /* Verify by reading back */
    handle = fut_vfs_open_cap(TEST_FILE_PATH, O_RDONLY, 0);
    if (handle == FUT_INVALID_HANDLE) {
        fut_printf("[CAP-TEST] ✗ Failed to reopen file for verification\n");
        fut_test_fail(CAP_TEST_WRITE);
        return;
    }

    char buffer[64] = {0};
    long bytes_read = fut_vfs_read_cap(handle, buffer, sizeof(buffer) - 1);
    fut_vfs_close_cap(handle);

    if (bytes_read < 22) {
        fut_printf("[CAP-TEST] ✗ Verification read failed: %ld bytes\n", bytes_read);
        fut_test_fail(CAP_TEST_WRITE);
        return;
    }

    fut_printf("[CAP-TEST] ✓ Wrote %ld bytes via capability, verified: '%s'\n", bytes_written, buffer);
    fut_test_pass();
}

/**
 * Test 4: Verify rights enforcement - read-only handle cannot write
 */
static void test_cap_rights_enforcement(void) {
    fut_printf("[CAP-TEST] Test 4: Rights enforcement (read-only cannot write)\n");

    /* Open file with read-only capability */
    fut_handle_t handle = fut_vfs_open_cap(TEST_FILE_PATH, O_RDONLY, 0);
    if (handle == FUT_INVALID_HANDLE) {
        fut_printf("[CAP-TEST] ✗ Failed to open file for reading\n");
        fut_test_fail(CAP_TEST_RIGHTS);
        return;
    }

    /* Attempt to write - this should fail with -EPERM */
    const char *write_data = "Unauthorized Write!";
    long result = fut_vfs_write_cap(handle, write_data, 19);

    fut_vfs_close_cap(handle);

    if (result >= 0) {
        fut_printf("[CAP-TEST] ✗ Write succeeded on read-only handle (returned %ld)\n", result);
        fut_test_fail(CAP_TEST_RIGHTS);
        return;
    }

    if (result != -EPERM && result != -EBADF) {
        fut_printf("[CAP-TEST] ✗ Expected -EPERM or -EBADF, got %ld\n", result);
        fut_test_fail(CAP_TEST_RIGHTS);
        return;
    }

    fut_printf("[CAP-TEST] ✓ Write on read-only handle correctly denied: %ld\n", result);
    fut_test_pass();
}

/**
 * Test 5: Verify operations on invalid handle
 */
static void test_cap_invalid_handle(void) {
    fut_printf("[CAP-TEST] Test 5: Invalid handle operations\n");

    fut_handle_t invalid = FUT_INVALID_HANDLE;
    char buffer[32];

    /* Read with invalid handle */
    long result = fut_vfs_read_cap(invalid, buffer, sizeof(buffer));
    if (result >= 0) {
        fut_printf("[CAP-TEST] ✗ Read on invalid handle succeeded\n");
        fut_test_fail(CAP_TEST_INVALID);
        return;
    }

    /* Write with invalid handle */
    result = fut_vfs_write_cap(invalid, "test", 4);
    if (result >= 0) {
        fut_printf("[CAP-TEST] ✗ Write on invalid handle succeeded\n");
        fut_test_fail(CAP_TEST_INVALID);
        return;
    }

    /* Lseek with invalid handle */
    result = fut_vfs_lseek_cap(invalid, 0, 0);
    if (result >= 0) {
        fut_printf("[CAP-TEST] ✗ Lseek on invalid handle succeeded\n");
        fut_test_fail(CAP_TEST_INVALID);
        return;
    }

    /* Close invalid handle should be safe */
    (void)fut_vfs_close_cap(invalid);
    /* Close on invalid may return 0 or error, either is acceptable */

    fut_printf("[CAP-TEST] ✓ Invalid handle operations correctly rejected\n");
    fut_test_pass();
}

/**
 * Test 6: Verify capability handle cleanup
 */
static void test_cap_close(void) {
    fut_printf("[CAP-TEST] Test 6: Capability handle cleanup\n");

    /* Open file with capability */
    fut_handle_t handle = fut_vfs_open_cap(TEST_FILE_PATH, O_RDONLY, 0);
    if (handle == FUT_INVALID_HANDLE) {
        fut_printf("[CAP-TEST] ✗ Failed to open file\n");
        fut_test_fail(CAP_TEST_CLOSE);
        return;
    }

    /* Close the handle */
    int result = fut_vfs_close_cap(handle);
    if (result < 0) {
        fut_printf("[CAP-TEST] ✗ fut_vfs_close_cap() failed: %d\n", result);
        fut_test_fail(CAP_TEST_CLOSE);
        return;
    }

    /* Operations on closed handle should fail */
    char buffer[32];
    long read_result = fut_vfs_read_cap(handle, buffer, sizeof(buffer));
    if (read_result >= 0) {
        fut_printf("[CAP-TEST] ✗ Read on closed handle succeeded\n");
        fut_test_fail(CAP_TEST_CLOSE);
        return;
    }

    fut_printf("[CAP-TEST] ✓ Capability handle closed, subsequent ops rejected\n");
    fut_test_pass();
}

/**
 * Thread entry point for capability tests.
 * This runs the tests in a proper thread context after the scheduler starts.
 */
static void fut_cap_test_thread(void *arg) {
    (void)arg;

    fut_printf("[CAP-TEST] ========================================\n");
    fut_printf("[CAP-TEST] Starting Capability Syscall Tests\n");
    fut_printf("[CAP-TEST] ========================================\n");

    test_cap_open();
    test_cap_read();
    test_cap_write();
    test_cap_rights_enforcement();
    test_cap_invalid_handle();
    test_cap_close();

    fut_printf("[CAP-TEST] ========================================\n");
    fut_printf("[CAP-TEST] Capability Syscall Tests Complete\n");
    fut_printf("[CAP-TEST] ========================================\n");
}

/**
 * Schedule capability tests to run.
 *
 * Called during kernel initialization to register the capability tests.
 * Creates a thread to run the tests after the scheduler starts.
 *
 * @param task The test task context
 */
void fut_cap_selftest_schedule(fut_task_t *task) {
    fut_printf("[CAP] fut_cap_selftest_schedule called with task=%p\n", (void*)task);

    if (!task) {
        fut_printf("[CAP] task is NULL, returning\n");
        return;
    }

    fut_thread_t *thread = fut_thread_create(
        task,
        fut_cap_test_thread,
        NULL,
        12 * 1024,  /* 12 KB stack */
        180         /* Priority */
    );

    if (!thread) {
        fut_printf("[CAP] failed to schedule test harness thread\n");
    } else {
        fut_printf("[CAP] successfully created test thread\n");
    }
}
