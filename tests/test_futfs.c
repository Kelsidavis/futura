// SPDX-License-Identifier: MPL-2.0
#include <futura/blkdev.h>
#include <kernel/errno.h>
#include <kernel/fut_memory.h>
#include <kernel/fut_task.h>
#include <kernel/fut_thread.h>

#include <stdbool.h>
#include <string.h>

#include <subsystems/futura_fs/futfs.h>

#include "tests/test_api.h"

extern void fut_printf(const char *fmt, ...);

#define FUTFS_TEST_PATH "/hello.txt"

static bool futfs_name_equals(const char *lhs, const char *rhs) {
    if (!lhs || !rhs) {
        return false;
    }
    while (*lhs && *rhs) {
        if (*lhs != *rhs) {
            return false;
        }
        ++lhs;
        ++rhs;
    }
    return (*lhs == '\0') && (*rhs == '\0');
}

static void fut_futfs_selftest_thread(void *arg) {
    (void)arg;
    fut_handle_t blk_cap = FUT_INVALID_HANDLE;
    fut_status_t rc = fut_blk_acquire("blk:vda",
                                      FUT_BLK_READ | FUT_BLK_WRITE | FUT_BLK_ADMIN,
                                      &blk_cap);
    if (rc != 0) {
        if (rc == -ENODEV || rc == -ENOENT) {
            fut_printf("[futfs] skipping selftest: block device unavailable (rc=%d)\n", rc);
            fut_test_pass();
        } else {
            fut_printf("[futfs] fut_blk_acquire failed: %d\n", rc);
            fut_test_fail(0xF1);
        }
        return;
    }

    rc = futfs_mount(blk_cap);
    if (rc != 0) {
        fut_printf("[futfs] mount failed: %d\n", rc);
        fut_blk_close(blk_cap);
        fut_test_fail(0xF2);
        return;
    }

    fut_handle_t file_cap = FUT_INVALID_HANDLE;
    rc = futfs_create(FUTFS_TEST_PATH, &file_cap);
    if (rc != 0) {
        fut_printf("[futfs] create failed: %d\n", rc);
        futfs_unmount();
        fut_blk_close(blk_cap);
        fut_test_fail(0xF3);
        return;
    }

    const char payload[] = "Hello FuturaFS";
    rc = futfs_write(file_cap, payload, sizeof(payload));
    if (rc != 0) {
        fut_printf("[futfs] write failed: %d\n", rc);
        futfs_close(file_cap);
        futfs_unmount();
        fut_blk_close(blk_cap);
        fut_test_fail(0xF4);
        return;
    }

    rc = futfs_sync(file_cap);
    if (rc != 0) {
        fut_printf("[futfs] sync failed: %d\n", rc);
        futfs_close(file_cap);
        futfs_unmount();
        fut_blk_close(blk_cap);
        fut_test_fail(0xF5);
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
        fut_test_fail(0xF6);
        return;
    }

    if (memcmp(buffer, payload, sizeof(payload)) != 0) {
        fut_printf("[futfs] data mismatch\n");
        futfs_close(file_cap);
        futfs_unmount();
        fut_blk_close(blk_cap);
        fut_test_fail(0xF7);
        return;
    }

    const char *file_name = FUTFS_TEST_PATH + 1;
    size_t cookie = 0;
    futfs_dirent_t dent = {0};
    bool saw_file = false;
    while (true) {
        fut_status_t rd = futfs_readdir("/", &cookie, &dent);
        if (rd <= 0) {
            break;
        }
        if (futfs_name_equals(dent.name, file_name)) {
            saw_file = true;
        }
    }
    if (!saw_file) {
        fut_printf("[futfs] readdir missing %s\n", file_name);
        futfs_close(file_cap);
        futfs_unmount();
        fut_blk_close(blk_cap);
        fut_test_fail(0xF8);
        return;
    }

    futfs_close(file_cap);
    file_cap = FUT_INVALID_HANDLE;

    rc = futfs_unlink(FUTFS_TEST_PATH);
    if (rc != 0) {
        fut_printf("[futfs] unlink failed: %d\n", rc);
        futfs_unmount();
        fut_blk_close(blk_cap);
        fut_test_fail(0xF9);
        return;
    }

    cookie = 0;
    bool still_present = false;
    while (true) {
        fut_status_t rd = futfs_readdir("/", &cookie, &dent);
        if (rd <= 0) {
            break;
        }
        if (futfs_name_equals(dent.name, file_name)) {
            still_present = true;
            break;
        }
    }
    if (still_present) {
        fut_printf("[futfs] unlink left stale entry\n");
        futfs_unmount();
        fut_blk_close(blk_cap);
        fut_test_fail(0xFA);
        return;
    }

    rc = futfs_mkdir("/tmpdir");
    if (rc != 0) {
        fut_printf("[futfs] mkdir failed: %d\n", rc);
        futfs_unmount();
        fut_blk_close(blk_cap);
        fut_test_fail(0xFB);
        return;
    }

    cookie = 0;
    bool saw_dir = false;
    while (true) {
        fut_status_t rd = futfs_readdir("/", &cookie, &dent);
        if (rd <= 0) {
            break;
        }
        if (futfs_name_equals(dent.name, "tmpdir") && dent.type == FUTFS_INODE_DIR) {
            saw_dir = true;
        }
    }
    if (!saw_dir) {
        fut_printf("[futfs] mkdir entry missing from readdir\n");
        futfs_unmount();
        fut_blk_close(blk_cap);
        fut_test_fail(0xFC);
        return;
    }

    rc = futfs_rmdir("/tmpdir");
    if (rc != 0) {
        fut_printf("[futfs] rmdir failed: %d\n", rc);
        futfs_unmount();
        fut_blk_close(blk_cap);
        fut_test_fail(0xFD);
        return;
    }

    cookie = 0;
    bool dir_present = false;
    while (true) {
        fut_status_t rd = futfs_readdir("/", &cookie, &dent);
        if (rd <= 0) {
            break;
        }
        if (futfs_name_equals(dent.name, "tmpdir")) {
            dir_present = true;
            break;
        }
    }
    if (dir_present) {
        fut_printf("[futfs] rmdir left stale entry\n");
        futfs_unmount();
        fut_blk_close(blk_cap);
        fut_test_fail(0xFE);
        return;
    }

    struct fut_statfs fs_stats_before;
    rc = futfs_statfs(&fs_stats_before);
    if (rc != 0) {
        fut_printf("[futfs] statfs failed: %d\n", rc);
        futfs_unmount();
        fut_blk_close(blk_cap);
        fut_test_fail(0xE0);
        return;
    }

    const char *gc_names[] = {
        "/gcfile0",
        "/gcfile1",
        "/gcfile2",
        "/gcfile3",
        "/gcfile4",
        "/gcfile5",
    };
    const int gc_total = (int)(sizeof(gc_names) / sizeof(gc_names[0]));
    const int gc_tomb = 3;
    fut_handle_t gc_handles[gc_total];

    for (int i = 0; i < gc_total; ++i) {
        rc = futfs_create(gc_names[i], &gc_handles[i]);
        if (rc != 0) {
            fut_printf("[futfs] gc create %s failed: %d\n", gc_names[i], rc);
            for (int j = 0; j < i; ++j) {
                futfs_close(gc_handles[j]);
            }
            futfs_unmount();
            fut_blk_close(blk_cap);
            fut_test_fail(0xE1);
            return;
        }
    }

    for (int i = 0; i < gc_total; ++i) {
        futfs_close(gc_handles[i]);
    }

    for (int i = 0; i < gc_tomb; ++i) {
        rc = futfs_unlink(gc_names[i]);
        if (rc != 0) {
            fut_printf("[futfs] gc unlink %s failed: %d\n", gc_names[i], rc);
            futfs_unmount();
            fut_blk_close(blk_cap);
            fut_test_fail(0xE2);
            return;
        }
    }

    struct fut_statfs fs_stats_mid;
    rc = futfs_statfs(&fs_stats_mid);
    if (rc != 0) {
        fut_printf("[futfs] statfs(mid) failed: %d\n", rc);
        futfs_unmount();
        fut_blk_close(blk_cap);
        fut_test_fail(0xE3);
        return;
    }

    if (fs_stats_mid.dir_tombstones < (uint64_t)gc_tomb) {
        fut_printf("[futfs] expected tombstones >= %d, saw %llu\n",
                   gc_tomb,
                   (unsigned long long)fs_stats_mid.dir_tombstones);
        futfs_unmount();
        fut_blk_close(blk_cap);
        fut_test_fail(0xE4);
        return;
    }

    struct futfs_gc_stats gc_stats;
    rc = futfs_compact_dir("/", &gc_stats);
    if (rc != 0) {
        fut_printf("[futfs] compact_dir failed: %d\n", rc);
        futfs_unmount();
        fut_blk_close(blk_cap);
        fut_test_fail(0xE5);
        return;
    }

    if (gc_stats.tombstones_after >= gc_stats.tombstones_before) {
        fut_printf("[futfs] compaction did not reduce tombstones (%llu -> %llu)\n",
                   (unsigned long long)gc_stats.tombstones_before,
                   (unsigned long long)gc_stats.tombstones_after);
        futfs_unmount();
        fut_blk_close(blk_cap);
        fut_test_fail(0xE6);
        return;
    }

    struct fut_statfs fs_stats_after;
    rc = futfs_statfs(&fs_stats_after);
    if (rc != 0) {
        fut_printf("[futfs] statfs(after) failed: %d\n", rc);
        futfs_unmount();
        fut_blk_close(blk_cap);
        fut_test_fail(0xE7);
        return;
    }

    if (fs_stats_after.dir_tombstones > fs_stats_mid.dir_tombstones) {
        fut_printf("[futfs] tombstones increased after compaction (%llu -> %llu)\n",
                   (unsigned long long)fs_stats_mid.dir_tombstones,
                   (unsigned long long)fs_stats_after.dir_tombstones);
        futfs_unmount();
        fut_blk_close(blk_cap);
        fut_test_fail(0xE8);
        return;
    }

    for (int i = gc_tomb; i < gc_total; ++i) {
        rc = futfs_unlink(gc_names[i]);
        if (rc != 0) {
            fut_printf("[futfs] cleanup unlink %s failed: %d\n", gc_names[i], rc);
            futfs_unmount();
            fut_blk_close(blk_cap);
            fut_test_fail(0xE9);
            return;
        }
    }

    rc = futfs_statfs(&fs_stats_after);
    if (rc == 0 && !(fs_stats_after.features & FUT_STATFS_FEAT_DIR_COMPACTION)) {
        fut_printf("[futfs] statfs features missing DIR_COMPACTION\n");
        futfs_unmount();
        fut_blk_close(blk_cap);
        fut_test_fail(0xEA);
        return;
    }

    fut_printf("[FUTURAFS-TEST] statfs ok (blocks=%llu free=%llu tombstones=%llu)\n",
               (unsigned long long)fs_stats_after.blocks_total,
               (unsigned long long)fs_stats_after.blocks_free,
               (unsigned long long)fs_stats_after.dir_tombstones);
    fut_printf("[FUTURAFS-TEST] gc compact ok (before=%llu after=%llu)\n",
               (unsigned long long)gc_stats.tombstones_before,
               (unsigned long long)gc_stats.tombstones_after);

    fut_printf("FuturaFS test passed\n");
    futfs_unmount();
    fut_blk_close(blk_cap);
    fut_test_pass();
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
