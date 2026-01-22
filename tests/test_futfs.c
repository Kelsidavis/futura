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
#include <kernel/kprintf.h>

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

    uint64_t blocks_used_after = (fs_stats_after.blocks_total > fs_stats_after.blocks_free)
                                     ? fs_stats_after.blocks_total - fs_stats_after.blocks_free
                                     : 0;
    uint64_t inodes_used_after = (fs_stats_after.inodes_total > fs_stats_after.inodes_free)
                                     ? fs_stats_after.inodes_total - fs_stats_after.inodes_free
                                     : 0;

    fut_printf("[FUTURAFS-TEST] statfs ok (blocks %llu/%llu inodes %llu/%llu tombstones %llu)\n",
               (unsigned long long)blocks_used_after,
               (unsigned long long)fs_stats_after.blocks_total,
               (unsigned long long)inodes_used_after,
               (unsigned long long)fs_stats_after.inodes_total,
               (unsigned long long)fs_stats_after.dir_tombstones);
    fut_printf("[FUTURAFS-TEST] gc compact ok (size from %llu -> %llu)\n",
               (unsigned long long)gc_stats.bytes_before,
               (unsigned long long)gc_stats.bytes_after);

    /* ===== NESTED PATH TESTS ===== */
    fut_printf("[FUTURAFS-TEST] Testing nested path support...\n");

    /* Test 1: Create nested directory structure */
    rc = futfs_mkdir("/a");
    if (rc != 0) {
        fut_printf("[futfs] nested mkdir /a failed: %d\n", rc);
        futfs_unmount();
        fut_blk_close(blk_cap);
        fut_test_fail(0xE10);
        return;
    }

    rc = futfs_mkdir("/a/b");
    if (rc != 0) {
        fut_printf("[futfs] nested mkdir /a/b failed: %d\n", rc);
        futfs_unmount();
        fut_blk_close(blk_cap);
        fut_test_fail(0xE11);
        return;
    }

    rc = futfs_mkdir("/a/b/c");
    if (rc != 0) {
        fut_printf("[futfs] nested mkdir /a/b/c failed: %d\n", rc);
        futfs_unmount();
        fut_blk_close(blk_cap);
        fut_test_fail(0xE12);
        return;
    }

    fut_printf("[FUTURAFS-TEST] Created nested directories /a/b/c\n");

    /* Test 2: Create file in nested directory */
    fut_handle_t nested_file = FUT_INVALID_HANDLE;
    rc = futfs_create("/a/b/c/nested.txt", &nested_file);
    if (rc != 0) {
        fut_printf("[futfs] create in nested dir failed: %d\n", rc);
        futfs_unmount();
        fut_blk_close(blk_cap);
        fut_test_fail(0xE13);
        return;
    }

    const char nested_payload[] = "Nested content";
    rc = futfs_write(nested_file, nested_payload, sizeof(nested_payload));
    if (rc != 0) {
        fut_printf("[futfs] write to nested file failed: %d\n", rc);
        futfs_close(nested_file);
        futfs_unmount();
        fut_blk_close(blk_cap);
        fut_test_fail(0xE14);
        return;
    }

    rc = futfs_sync(nested_file);
    if (rc != 0) {
        fut_printf("[futfs] sync nested file failed: %d\n", rc);
        futfs_close(nested_file);
        futfs_unmount();
        fut_blk_close(blk_cap);
        fut_test_fail(0xE15);
        return;
    }

    char nested_buffer[64];
    size_t nested_bytes = 0;
    memset(nested_buffer, 0, sizeof(nested_buffer));
    rc = futfs_read(nested_file, nested_buffer, sizeof(nested_payload), &nested_bytes);
    if (rc != 0 || nested_bytes != sizeof(nested_payload)) {
        fut_printf("[futfs] read from nested file failed: rc=%d bytes=%zu\n", rc, nested_bytes);
        futfs_close(nested_file);
        futfs_unmount();
        fut_blk_close(blk_cap);
        fut_test_fail(0xE16);
        return;
    }

    if (memcmp(nested_buffer, nested_payload, sizeof(nested_payload)) != 0) {
        fut_printf("[futfs] nested file data mismatch\n");
        futfs_close(nested_file);
        futfs_unmount();
        fut_blk_close(blk_cap);
        fut_test_fail(0xE17);
        return;
    }

    fut_printf("[FUTURAFS-TEST] Nested file create/write/read ok\n");

    /* Test 3: Create another file at different nesting level */
    fut_handle_t mid_file = FUT_INVALID_HANDLE;
    rc = futfs_create("/a/b/midlevel.txt", &mid_file);
    if (rc != 0) {
        fut_printf("[futfs] create at mid-level failed: %d\n", rc);
        futfs_close(nested_file);
        futfs_unmount();
        fut_blk_close(blk_cap);
        fut_test_fail(0xE18);
        return;
    }

    const char mid_payload[] = "Mid-level";
    rc = futfs_write(mid_file, mid_payload, sizeof(mid_payload));
    if (rc != 0) {
        fut_printf("[futfs] write to mid-level file failed: %d\n", rc);
        futfs_close(mid_file);
        futfs_close(nested_file);
        futfs_unmount();
        fut_blk_close(blk_cap);
        fut_test_fail(0xE19);
        return;
    }

    futfs_close(mid_file);
    fut_printf("[FUTURAFS-TEST] Mid-level file create/write ok\n");

    /* Test 4: Directory listing at different levels */
    cookie = 0;
    bool found_nested_txt = false;
    bool found_midlevel_txt = false;
    while (true) {
        fut_status_t rd = futfs_readdir("/a/b", &cookie, &dent);
        if (rd <= 0) {
            break;
        }
        if (futfs_name_equals(dent.name, "nested.txt")) {
            found_nested_txt = true;
        }
        if (futfs_name_equals(dent.name, "midlevel.txt")) {
            found_midlevel_txt = true;
        }
    }
    if (!found_nested_txt || !found_midlevel_txt) {
        fut_printf("[futfs] readdir /a/b missing expected files\n");
        futfs_close(nested_file);
        futfs_unmount();
        fut_blk_close(blk_cap);
        fut_test_fail(0xE1A);
        return;
    }

    fut_printf("[FUTURAFS-TEST] Nested readdir ok\n");

    /* Test 5: Error case - ENOENT on missing nested path */
    fut_handle_t bad_file = FUT_INVALID_HANDLE;
    rc = futfs_create("/nonexistent/path/file.txt", &bad_file);
    if (rc != -ENOENT) {
        fut_printf("[futfs] expected ENOENT for missing nested path, got %d\n", rc);
        if (bad_file != FUT_INVALID_HANDLE) {
            futfs_close(bad_file);
        }
        futfs_close(nested_file);
        futfs_unmount();
        fut_blk_close(blk_cap);
        fut_test_fail(0xE1B);
        return;
    }

    fut_printf("[FUTURAFS-TEST] Error handling (ENOENT) ok\n");

    /* Test 6: Error case - ENOTDIR when intermediate is a file */
    fut_handle_t root_file = FUT_INVALID_HANDLE;
    rc = futfs_create("/rootfile.txt", &root_file);
    if (rc != 0) {
        fut_printf("[futfs] create root file for ENOTDIR test failed: %d\n", rc);
        futfs_close(nested_file);
        futfs_unmount();
        fut_blk_close(blk_cap);
        fut_test_fail(0xE1C);
        return;
    }
    futfs_close(root_file);

    fut_handle_t bad_nested = FUT_INVALID_HANDLE;
    rc = futfs_create("/rootfile.txt/cannot/nest.txt", &bad_nested);
    if (rc != -ENOTDIR) {
        fut_printf("[futfs] expected ENOTDIR for file as directory, got %d\n", rc);
        if (bad_nested != FUT_INVALID_HANDLE) {
            futfs_close(bad_nested);
        }
        futfs_close(nested_file);
        futfs_unmount();
        fut_blk_close(blk_cap);
        fut_test_fail(0xE1D);
        return;
    }

    fut_printf("[FUTURAFS-TEST] Error handling (ENOTDIR) ok\n");

    /* Test 7: Unlink nested file */
    rc = futfs_unlink("/a/b/c/nested.txt");
    if (rc != 0) {
        fut_printf("[futfs] unlink nested file failed: %d\n", rc);
        futfs_close(nested_file);
        futfs_unmount();
        fut_blk_close(blk_cap);
        fut_test_fail(0xE1E);
        return;
    }

    /* Verify it's gone */
    cookie = 0;
    found_nested_txt = false;
    while (true) {
        fut_status_t rd = futfs_readdir("/a/b/c", &cookie, &dent);
        if (rd <= 0) {
            break;
        }
        if (futfs_name_equals(dent.name, "nested.txt")) {
            found_nested_txt = true;
            break;
        }
    }
    if (found_nested_txt) {
        fut_printf("[futfs] unlink nested file left stale entry\n");
        futfs_close(nested_file);
        futfs_unmount();
        fut_blk_close(blk_cap);
        fut_test_fail(0xE1F);
        return;
    }

    fut_printf("[FUTURAFS-TEST] Nested file unlink ok\n");

    /* Test 8: Remove nested directories */
    rc = futfs_rmdir("/a/b/c");
    if (rc != 0) {
        fut_printf("[futfs] rmdir /a/b/c failed: %d\n", rc);
        futfs_close(nested_file);
        futfs_unmount();
        fut_blk_close(blk_cap);
        fut_test_fail(0xE20);
        return;
    }

    rc = futfs_rmdir("/a/b");
    if (rc != 0) {
        fut_printf("[futfs] rmdir /a/b failed: %d\n", rc);
        futfs_close(nested_file);
        futfs_unmount();
        fut_blk_close(blk_cap);
        fut_test_fail(0xE21);
        return;
    }

    rc = futfs_rmdir("/a");
    if (rc != 0) {
        fut_printf("[futfs] rmdir /a failed: %d\n", rc);
        futfs_close(nested_file);
        futfs_unmount();
        fut_blk_close(blk_cap);
        fut_test_fail(0xE22);
        return;
    }

    fut_printf("[FUTURAFS-TEST] Nested directory removal ok\n");

    rc = futfs_unlink("/rootfile.txt");
    if (rc != 0) {
        fut_printf("[futfs] cleanup unlink /rootfile.txt failed: %d\n", rc);
        futfs_unmount();
        fut_blk_close(blk_cap);
        fut_test_fail(0xE23);
        return;
    }

    futfs_set_crash_compaction(false);

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
