// SPDX-License-Identifier: MPL-2.0
#include <futura/blkdev.h>
#include <kernel/errno.h>
#include <kernel/fut_memory.h>
#include <kernel/fut_task.h>
#include <kernel/fut_thread.h>

#include <string.h>

#include <subsystems/futura_fs/futfs.h>

extern void fut_printf(const char *fmt, ...);

#define FUTFS_TEST_PATH "/hello.txt"

static void fut_futfs_selftest_thread(void *arg) {
    (void)arg;

    fut_handle_t blk_cap = FUT_INVALID_HANDLE;
    fut_status_t rc = fut_blk_acquire("blk:vda",
                                      FUT_BLK_READ | FUT_BLK_WRITE | FUT_BLK_ADMIN,
                                      &blk_cap);
    if (rc != 0) {
        fut_printf("[futfs] fut_blk_acquire failed: %d\n", rc);
        return;
    }

    rc = futfs_mount(blk_cap);
    if (rc != 0) {
        fut_printf("[futfs] mount failed: %d\n", rc);
        fut_blk_close(blk_cap);
        return;
    }

    fut_handle_t file_cap = FUT_INVALID_HANDLE;
    rc = futfs_create(FUTFS_TEST_PATH, &file_cap);
    if (rc != 0) {
        fut_printf("[futfs] create failed: %d\n", rc);
        futfs_unmount();
        fut_blk_close(blk_cap);
        return;
    }

    const char payload[] = "Hello FuturaFS";
    rc = futfs_write(file_cap, payload, sizeof(payload));
    if (rc != 0) {
        fut_printf("[futfs] write failed: %d\n", rc);
        futfs_close(file_cap);
        futfs_unmount();
        fut_blk_close(blk_cap);
        return;
    }

    rc = futfs_sync(file_cap);
    if (rc != 0) {
        fut_printf("[futfs] sync failed: %d\n", rc);
        futfs_close(file_cap);
        futfs_unmount();
        fut_blk_close(blk_cap);
        return;
    }

    char buffer[64];
    size_t bytes = 0;
    memset(buffer, 0, sizeof(buffer));
    rc = futfs_read(file_cap, buffer, sizeof(payload), &bytes);
    if (rc != 0 || bytes != sizeof(payload)) {
        fut_printf("[futfs] read failed: rc=%d bytes=%zu\n", rc, bytes);
        futfs_close(file_cap);
        futfs_unmount();
        fut_blk_close(blk_cap);
        return;
    }

    if (memcmp(buffer, payload, sizeof(payload)) != 0) {
        fut_printf("[futfs] data mismatch\n");
        futfs_close(file_cap);
        futfs_unmount();
        fut_blk_close(blk_cap);
        return;
    }

    futfs_close(file_cap);
    fut_printf("FuturaFS test passed\n");
    futfs_unmount();
    fut_blk_close(blk_cap);
}

void fut_futfs_selftest_schedule(fut_task_t *task) {
    if (!task) {
        return;
    }
    fut_thread_t *thread = fut_thread_create(task,
                                             fut_futfs_selftest_thread,
                                             NULL,
                                             12 * 1024,
                                             130);
    if (!thread) {
        fut_printf("[futfs] failed to schedule selftest\n");
    }
}
