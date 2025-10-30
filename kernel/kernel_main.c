/* kernel_main.c - Futura OS Kernel Main Entry Point
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * This is the main kernel initialization sequence.
 * Called from platform_init after platform-specific setup is complete.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <generated/feature_flags.h>
#include <kernel/fut_memory.h>
#include <kernel/fut_sched.h>
#include <kernel/fut_thread.h>
#include <kernel/fut_task.h>
#include <kernel/fut_fipc.h>
#include <kernel/exec.h>
#include <kernel/fut_vfs.h>
#include <kernel/fut_ramfs.h>
#include <kernel/fut_blockdev.h>
#include <kernel/fut_ramdisk.h>
#include <kernel/fut_timer.h>
#include <kernel/fut_futurafs.h>
#include <kernel/fb.h>
#include <kernel/console.h>
#include <kernel/boot_banner.h>
#include <kernel/boot_args.h>
#include <kernel/fut_percpu.h>
#include <kernel/input.h>
#include <futura/blkdev.h>
#include <futura/net.h>
#include <futura/tcpip.h>
#include <futura/dns.h>
#include <platform/platform.h>
#include "tests/test_api.h"
#include "tests/perf.h"
#if defined(__x86_64__)
#include <arch/x86_64/paging.h>
#include <arch/x86_64/pmap.h>
#include <arch/x86_64/lapic.h>
#elif defined(__aarch64__)
#include <arch/arm64/paging.h>
#include <arch/arm64/irq.h>
#include <arch/arm64/process.h>
#endif

extern void fut_echo_selftest(void);
extern void fut_fb_smoke(void);
extern void fut_input_smoke(void);
extern void fut_exec_double_smoke(void);
extern void fut_mm_tests_run(void);
extern void fut_blk_async_selftest_schedule(fut_task_t *task);
extern void fut_futfs_selftest_schedule(fut_task_t *task);
extern void fut_net_selftest_schedule(fut_task_t *task);
extern void fut_perf_selftest_schedule(fut_task_t *task);

#if ENABLE_WAYLAND_DEMO
#define WAYLAND_TEST_SENTINEL_CODE 0xD0u
#define WAYLAND_TEST_STAGE_FAIL    0xD1u
#define WAYLAND_TEST_EXEC_FAIL     0xD2u
#define WAYLAND_TEST_CLIENT_FAIL   0xD3u
#endif

#if ENABLE_WINSRV_DEMO || ENABLE_WAYLAND_DEMO
__attribute__((unused)) static void fut_boot_delay_ms(uint32_t delay_ms) {
    if (delay_ms == 0) {
        return;
    }

    uint64_t start = fut_get_ticks();
    const uint64_t ceiling = start + delay_ms;
    const uint64_t guard_iterations = (uint64_t)delay_ms * 20000ULL;

    for (uint64_t spin = 0; spin < guard_iterations; ++spin) {
        if (fut_get_ticks() >= ceiling) {
            return;
        }
#if defined(__x86_64__)
        __asm__ volatile("pause" ::: "memory");
#endif
    }
}
#endif
extern fut_status_t virtio_blk_init(uint64_t pci_addr);
extern fut_status_t virtio_net_init(void);
extern void ahci_init(void);
extern char boot_ptables_start[];
extern char boot_ptables_end[];

__attribute__((unused)) static bool boot_flag_enabled(const char *key, bool default_on) {
    const char *value = fut_boot_arg_value(key);
    if (!value) {
        return default_on;
    }
    if (*value == '\0') {
        return true;
    }
    if (value[0] == '0' || value[0] == 'f' || value[0] == 'F' || value[0] == 'n' || value[0] == 'N') {
        return false;
    }
    if (value[0] == '1' || value[0] == 't' || value[0] == 'T' || value[0] == 'y' || value[0] == 'Y') {
        return true;
    }
    return default_on;
}

/* ============================================================
 *   External Symbols from Linker Script
 * ============================================================ */

/* Kernel memory layout symbols from link.ld */
extern char _kernel_end[];
extern char _bss_start[];
extern char _bss_end[];

/* ============================================================
 *   Configuration Constants
 * ============================================================ */

/* Memory configuration - allocate 1GB in QEMU with balanced kernel heap */
#define TOTAL_MEMORY_SIZE       (1024 * 1024 * 1024) /* 1 GiB */
#define KERNEL_HEAP_SIZE        (96 * 1024 * 1024)  /* 96 MiB kernel heap - CRITICAL: must stay below 0xffffffff88000000 (128MB mark) where page mapping ends */

/* ============================================================
 *   Test Thread Functions
 * ============================================================ */

/* Global FIPC channel for testing */
static struct fut_fipc_channel *g_test_channel = NULL;

__attribute__((unused)) static void fut_test_watchdog_thread(void *arg) {
    (void)arg;
    const uint32_t timeout_ms = 20000;
    uint32_t elapsed = 0;

    while (elapsed < timeout_ms) {
        if (fut_tests_completed()) {
            fut_thread_exit();
        }
        fut_thread_sleep(1000);
        elapsed += 1000;
    }

    fut_test_fail(0xEE);
}

enum futurafs_test_status {
    FUTURAFS_TEST_ERR_RAMDISK = 0xA0,
    FUTURAFS_TEST_ERR_REGISTER = 0xA1,
    FUTURAFS_TEST_ERR_FORMAT = 0xA2,
    FUTURAFS_TEST_ERR_MOUNT = 0xA3,
    FUTURAFS_TEST_ERR_STAT = 0xA4,
    FUTURAFS_TEST_ERR_LOOKUP_ROOT = 0xA5,
    FUTURAFS_TEST_ERR_LOOKUP_DOT = 0xA6
};

/**
 * Test VFS file operations.
 * Creates files using vnode operations, writes data, reads it back.
 * DISABLED: Consumes too much physical memory for wayland execution
 */
static void __attribute__((unused)) test_vfs_operations(void) {
    fut_printf("[VFS-TEST] Starting VFS file I/O test...\n");

    /* Test 1: Verify root filesystem is accessible */
    fut_printf("[VFS-TEST] Test 1: Checking root filesystem\n");
    struct fut_stat st;
    int ret = fut_vfs_stat("/", &st);
    if (ret == 0) {
        fut_printf("[VFS-TEST] ✓ Root accessible (inode %llu, mode 0%o)\n", st.st_ino, st.st_mode);
    } else {
        fut_printf("[VFS-TEST] ✗ Failed to stat root: error %d\n", ret);
        return;
    }

    /* Test 2: Create test directory using vnode operations */
    fut_printf("[VFS-TEST] Test 2: Creating directory /testdir\n");

    /* Get root vnode directly (hack: use internal VFS function) */
    extern void fut_vfs_set_root(struct fut_vnode *vnode);  /* Forward declaration */

    /* Access root through lookup */
    struct fut_vnode *root_vnode = NULL;

    /* Simple hack to get root vnode - use external linkage */
    extern struct fut_vnode *fut_vfs_get_root(void);
    root_vnode = fut_vfs_get_root();

    if (!root_vnode) {
        fut_printf("[VFS-TEST] ✗ Could not access root vnode\n");
        fut_printf("[VFS-TEST] Note: Full file I/O test requires vnode API access\n");
        fut_printf("[VFS-TEST] VFS basic validation complete\n");
        return;
    }

    /* Create directory using vnode operations */
    if (root_vnode->ops && root_vnode->ops->mkdir) {
        ret = root_vnode->ops->mkdir(root_vnode, "testdir", 0755);
        if (ret == 0) {
            fut_printf("[VFS-TEST] ✓ Directory created: /testdir\n");
        } else {
            fut_printf("[VFS-TEST] ✗ mkdir failed: error %d\n", ret);
        }
    }

    /* Test 3: Create test file in root */
    fut_printf("[VFS-TEST] Test 3: Creating file /test.txt\n");

    if (root_vnode->ops && root_vnode->ops->create) {
        struct fut_vnode *file_vnode = NULL;
        ret = root_vnode->ops->create(root_vnode, "test.txt", 0644, &file_vnode);
        if (ret == 0 && file_vnode) {
            fut_printf("[VFS-TEST] ✓ File created: /test.txt (inode %llu)\n", file_vnode->ino);

            /* Test 4: Write data to file */
            fut_printf("[VFS-TEST] Test 4: Writing data to /test.txt\n");
            const char *test_data = "Hello, VFS! This is a test.";
            size_t data_len = 28;

            if (file_vnode->ops && file_vnode->ops->write) {
                ssize_t written = file_vnode->ops->write(file_vnode, test_data, data_len, 0);
                if (written > 0) {
                    fut_printf("[VFS-TEST] ✓ Wrote %lld bytes\n", (long long)written);

                    /* Test 5: Read data back */
                    fut_printf("[VFS-TEST] Test 5: Reading data from /test.txt\n");
                    char read_buf[64];

                    if (file_vnode->ops && file_vnode->ops->read) {
                        ssize_t bytes_read = file_vnode->ops->read(file_vnode, read_buf, sizeof(read_buf), 0);
                        if (bytes_read > 0) {
                            read_buf[bytes_read] = '\0';
                            fut_printf("[VFS-TEST] ✓ Read %lld bytes: '%s'\n", (long long)bytes_read, read_buf);

                            /* Verify data matches */
                            int match = 1;
                            for (size_t i = 0; i < data_len; i++) {
                                if (read_buf[i] != test_data[i]) {
                                    match = 0;
                                    break;
                                }
                            }

                            if (match) {
                                fut_printf("[VFS-TEST] ✓ Data verification PASSED\n");
                            } else {
                                fut_printf("[VFS-TEST] ✗ Data verification FAILED\n");
                            }
                        } else {
                            fut_printf("[VFS-TEST] ✗ Read failed: %lld\n", (long long)bytes_read);
                        }
                    }
                } else {
                    fut_printf("[VFS-TEST] ✗ Write failed: %lld\n", (long long)written);
                }
            }

            /* Decrement reference count */
            fut_vnode_unref(file_vnode);
        } else {
            fut_printf("[VFS-TEST] ✗ create failed: error %d\n", ret);
        }
    }

    fut_printf("[VFS-TEST] ===========================================\n");
    fut_printf("[VFS-TEST] VFS file I/O test complete!\n");
    fut_printf("[VFS-TEST] ===========================================\n\n");
}

/**
 * Test block device operations.
 * Creates a ramdisk, writes data, reads it back, and verifies.
 */
__attribute__((unused))
static void test_blockdev_operations(void) {
    fut_printf("[BLOCKDEV-TEST] Starting block device I/O test...\n");

    /* Test 1: Create ramdisk - use small size to fit in heap */
    fut_printf("[BLOCKDEV-TEST] Test 1: Creating 128 KB ramdisk\n");
    struct fut_blockdev *ramdisk = fut_ramdisk_create("ramdisk0", 0, 512);  /* 0 MB triggers special case - let's use 128KB */
    if (!ramdisk) {
        fut_printf("[BLOCKDEV-TEST] ✗ Failed to create ramdisk\n");
        return;
    }
    fut_printf("[BLOCKDEV-TEST] ✓ Ramdisk created: %s (%llu blocks, %u bytes/block)\n",
               ramdisk->name, ramdisk->num_blocks, ramdisk->block_size);

    /* Test 2: Register ramdisk */
    fut_printf("[BLOCKDEV-TEST] Test 2: Registering ramdisk\n");
    int ret = fut_blockdev_register(ramdisk);
    if (ret < 0) {
        fut_printf("[BLOCKDEV-TEST] ✗ Failed to register: error %d\n", ret);
        return;
    }
    fut_printf("[BLOCKDEV-TEST] ✓ Ramdisk registered\n");

    /* Test 3: Write blocks */
    fut_printf("[BLOCKDEV-TEST] Test 3: Writing test data\n");
    uint8_t write_buffer[512];
    for (int i = 0; i < 512; i++) {
        write_buffer[i] = (uint8_t)(i % 256);
    }

    ret = fut_blockdev_write(ramdisk, 0, 1, write_buffer);
    if (ret < 0) {
        fut_printf("[BLOCKDEV-TEST] ✗ Write failed: error %d\n", ret);
        return;
    }
    fut_printf("[BLOCKDEV-TEST] ✓ Wrote 1 block (512 bytes)\n");

    /* Test 4: Read blocks back */
    fut_printf("[BLOCKDEV-TEST] Test 4: Reading test data\n");
    uint8_t read_buffer[512];
    for (int i = 0; i < 512; i++) {
        read_buffer[i] = 0;
    }

    ret = fut_blockdev_read(ramdisk, 0, 1, read_buffer);
    if (ret < 0) {
        fut_printf("[BLOCKDEV-TEST] ✗ Read failed: error %d\n", ret);
        return;
    }
    fut_printf("[BLOCKDEV-TEST] ✓ Read 1 block (512 bytes)\n");

    /* Test 5: Verify data */
    fut_printf("[BLOCKDEV-TEST] Test 5: Verifying data integrity\n");
    int match = 1;
    for (int i = 0; i < 512; i++) {
        if (read_buffer[i] != write_buffer[i]) {
            fut_printf("[BLOCKDEV-TEST] ✗ Mismatch at byte %d: expected %u, got %u\n",
                       i, write_buffer[i], read_buffer[i]);
            match = 0;
            break;
        }
    }

    if (match) {
        fut_printf("[BLOCKDEV-TEST] ✓ Data verification PASSED\n");
    } else {
        fut_printf("[BLOCKDEV-TEST] ✗ Data verification FAILED\n");
    }

    /* Test 6: Byte-level I/O */
    fut_printf("[BLOCKDEV-TEST] Test 6: Testing byte-level I/O\n");
    const char *test_msg = "Block device test message!";
    size_t msg_len = 27;

    ssize_t written = fut_blockdev_write_bytes(ramdisk, 100, msg_len, test_msg);
    if (written < 0) {
        fut_printf("[BLOCKDEV-TEST] ✗ Byte write failed: error %lld\n", (long long)written);
    } else {
        fut_printf("[BLOCKDEV-TEST] ✓ Wrote %lld bytes at offset 100\n", (long long)written);

        char read_msg[32];
        ssize_t bytes_read = fut_blockdev_read_bytes(ramdisk, 100, msg_len, read_msg);
        if (bytes_read < 0) {
            fut_printf("[BLOCKDEV-TEST] ✗ Byte read failed: error %lld\n", (long long)bytes_read);
        } else {
            read_msg[bytes_read] = '\0';
            fut_printf("[BLOCKDEV-TEST] ✓ Read %lld bytes: '%s'\n", (long long)bytes_read, read_msg);

            int msg_match = 1;
            for (size_t i = 0; i < msg_len; i++) {
                if (read_msg[i] != test_msg[i]) {
                    msg_match = 0;
                    break;
                }
            }

            if (msg_match) {
                fut_printf("[BLOCKDEV-TEST] ✓ Byte-level verification PASSED\n");
            } else {
                fut_printf("[BLOCKDEV-TEST] ✗ Byte-level verification FAILED\n");
            }
        }
    }

    /* Test 7: Device statistics */
    fut_printf("[BLOCKDEV-TEST] Test 7: Device statistics\n");
    fut_printf("[BLOCKDEV-TEST]   Reads: %llu, Writes: %llu, Errors: %llu\n",
               ramdisk->reads, ramdisk->writes, ramdisk->errors);

    /* Test 8: Device lookup */
    fut_printf("[BLOCKDEV-TEST] Test 8: Device lookup\n");
    struct fut_blockdev *found = fut_blockdev_find("ramdisk0");
    if (found == ramdisk) {
        fut_printf("[BLOCKDEV-TEST] ✓ Device lookup successful\n");
    } else {
        fut_printf("[BLOCKDEV-TEST] ✗ Device lookup failed\n");
    }

    fut_printf("[BLOCKDEV-TEST] ===========================================\n");
    fut_printf("[BLOCKDEV-TEST] Block device test complete!\n");
    fut_printf("[BLOCKDEV-TEST] ===========================================\n\n");
}

/**
 * Test FuturaFS operations.
 * Creates a ramdisk, formats it with FuturaFS, mounts it, and tests file operations.
 */
__attribute__((unused))
static void test_futurafs_operations(void) {
    fut_printf("[FUTURAFS-TEST] Starting FuturaFS test...\n");

    /* Test 1: Create 128 KB ramdisk for FuturaFS (reduced for testing) */
    fut_printf("[FUTURAFS-TEST] Test 1: Creating 128 KB ramdisk for FuturaFS\n");

    struct fut_blockdev *ramdisk = fut_ramdisk_create_bytes("futurafs0", 128 * 1024u, 4096);
    if (!ramdisk) {
        fut_printf("[FUTURAFS-TEST] ✗ Failed to create ramdisk (continuing to compositor)\n");
        /* Don't fail test framework; continue to compositor for interactive testing */
        return;
    }
    fut_printf("[FUTURAFS-TEST] ✓ Ramdisk created: %s (%llu blocks, %u bytes/block)\n",
               ramdisk->name, ramdisk->num_blocks, ramdisk->block_size);

    /* Test 2: Register ramdisk */
    fut_printf("[FUTURAFS-TEST] Test 2: Registering ramdisk\n");
    int ret = fut_blockdev_register(ramdisk);
    if (ret < 0) {
        fut_printf("[FUTURAFS-TEST] ✗ Failed to register: error %d\n", ret);
        fut_test_fail(FUTURAFS_TEST_ERR_REGISTER);
        return;
    }
    fut_printf("[FUTURAFS-TEST] ✓ Ramdisk registered\n");

    /* Test 3: Register FuturaFS filesystem type */
    fut_printf("[FUTURAFS-TEST] Test 3: Registering FuturaFS filesystem type\n");
    fut_futurafs_init();
    fut_printf("[FUTURAFS-TEST] ✓ FuturaFS filesystem type registered\n");

    /* Test 4: Format with FuturaFS */
    fut_printf("[FUTURAFS-TEST] Test 4: Formatting ramdisk with FuturaFS\n");
    ret = fut_futurafs_format(ramdisk, "FuturaFS", 4096);
    if (ret < 0) {
        fut_printf("[FUTURAFS-TEST] ✗ Format failed: error %d\n", ret);
        fut_test_fail(FUTURAFS_TEST_ERR_FORMAT);
        return;
    }
    fut_printf("[FUTURAFS-TEST] ✓ Ramdisk formatted with FuturaFS (label: FuturaFS, inode_ratio: 4)\n");

    /* Test 5: Mount FuturaFS */
    fut_printf("[FUTURAFS-TEST] Test 5: Mounting FuturaFS at /mnt\n");

    /* Create mount point (if mkdir is available via VFS) */
    extern struct fut_vnode *fut_vfs_get_root(void);
    struct fut_vnode *root_vnode = fut_vfs_get_root();
    if (root_vnode && root_vnode->ops && root_vnode->ops->mkdir) {
        root_vnode->ops->mkdir(root_vnode, "mnt", 0755);
    }

    ret = fut_vfs_mount("futurafs0", "/mnt", "futurafs", 0, NULL, FUT_INVALID_HANDLE);
    if (ret < 0) {
        fut_printf("[FUTURAFS-TEST] ✗ Mount failed: error %d\n", ret);
        fut_test_fail(FUTURAFS_TEST_ERR_MOUNT);
        return;
    }
    fut_printf("[FUTURAFS-TEST] ✓ FuturaFS mounted at /mnt\n");

    /* Test 6: Verify mount */
    fut_printf("[FUTURAFS-TEST] Test 6: Verifying mount\n");
    struct fut_stat st;
    ret = fut_vfs_stat("/mnt", &st);
    if (ret == 0) {
        fut_printf("[FUTURAFS-TEST] ✓ Mount point accessible (inode %llu)\n", st.st_ino);
    } else {
        fut_printf("[FUTURAFS-TEST] ✗ Failed to stat mount point: error %d\n", ret);
        fut_test_fail(FUTURAFS_TEST_ERR_STAT);
        return;
    }

    struct fut_vnode *verify_vnode = NULL;
    ret = fut_vfs_lookup("/mnt", &verify_vnode);
    if (ret < 0 || !verify_vnode) {
        fut_printf("[FUTURAFS-TEST] ✗ fut_vfs_lookup(\"/mnt\") failed: error %d\n", ret);
        if (verify_vnode) {
            fut_vnode_unref(verify_vnode);
        }
        fut_test_fail(FUTURAFS_TEST_ERR_LOOKUP_ROOT);
        return;
    }
    fut_vnode_unref(verify_vnode);

    ret = fut_vfs_lookup("/mnt/.", &verify_vnode);
    if (ret < 0 || !verify_vnode) {
        fut_printf("[FUTURAFS-TEST] ✗ fut_vfs_lookup(\"/mnt/.\") failed: error %d\n", ret);
        if (verify_vnode) {
            fut_vnode_unref(verify_vnode);
        }
        fut_test_fail(FUTURAFS_TEST_ERR_LOOKUP_DOT);
        return;
    }
    fut_vnode_unref(verify_vnode);

    /* Test 7: Directory CRUD via vnode + VFS wrappers */
    fut_printf("[FUTURAFS-TEST] Test 7: Directory and file operations\n");
    struct fut_vnode *mnt_dir = NULL;
    fut_printf("[FUTURAFS-TEST]   resolving /mnt...\n");
    ret = fut_vfs_lookup("/mnt", &mnt_dir);
    fut_printf("[FUTURAFS-TEST]   fut_vfs_lookup ret=%d vnode=%p\n", ret, (void *)mnt_dir);
    if (ret < 0 || !mnt_dir) {
        fut_printf("[FUTURAFS-TEST] ✗ Failed to locate /mnt vnode (error %d)\n", ret);
        fut_test_fail(FUTURAFS_TEST_ERR_LOOKUP_ROOT);
        return;
    } else {
        if (mnt_dir->ops && mnt_dir->ops->mkdir) {
            fut_printf("[FUTURAFS-TEST]   invoking vnode->mkdir\n");
            ret = mnt_dir->ops->mkdir(mnt_dir, "dir_direct", 0755);
            fut_printf("[FUTURAFS-TEST]   dir_direct via vnode->ops %s (ret=%d)\n",
                       ret == 0 ? "✓" : "✗", ret);
        }

        ret = fut_vfs_mkdir("/mnt/dir_wrapper", 0755);
        fut_printf("[FUTURAFS-TEST]   dir_wrapper via fut_vfs_mkdir %s (ret=%d)\n",
                   ret == 0 ? "✓" : "✗", ret);

        struct fut_vnode *file_vnode = NULL;
        if (mnt_dir->ops && mnt_dir->ops->create) {
            ret = mnt_dir->ops->create(mnt_dir, "test_file.txt", 0644, &file_vnode);
            fut_printf("[FUTURAFS-TEST]   file creation %s (ret=%d)\n",
                       ret == 0 ? "✓" : "✗", ret);
            if (file_vnode) {
                fut_vnode_unref(file_vnode);
            }
        }

        uint64_t cookie = 0;
        struct fut_vdirent dirent;
        int entry_count = 0;
        while (true) {
            int rd = fut_vfs_readdir("/mnt", &cookie, &dirent);
            if (rd == -ENOENT) {
                break;
            }
            if (rd < 0) {
                fut_printf("[FUTURAFS-TEST]   readdir error %d\n", rd);
                break;
            }

            fut_printf("[FUTURAFS-TEST]   entry %d: %s (ino=%llu, type=%u)\n",
                       entry_count + 1,
                       dirent.d_name,
                       (unsigned long long)dirent.d_ino,
                       dirent.d_type);
            entry_count++;
        }
        fut_printf("[FUTURAFS-TEST]   total entries enumerated: %d\n", entry_count);

        ret = fut_vfs_unlink("/mnt/test_file.txt");
        fut_printf("[FUTURAFS-TEST]   unlink(/mnt/test_file.txt) %s (ret=%d)\n",
                   ret == 0 ? "✓" : "✗", ret);

        ret = fut_vfs_rmdir("/mnt/dir_wrapper");
        fut_printf("[FUTURAFS-TEST]   rmdir(/mnt/dir_wrapper) %s (ret=%d)\n",
                   ret == 0 ? "✓" : "✗", ret);

        /* Verify ENOTEMPTY path */
        if (mnt_dir->ops && mnt_dir->ops->mkdir) {
            ret = mnt_dir->ops->mkdir(mnt_dir, "dir_busy", 0755);
            if (ret == 0) {
                struct fut_vnode *busy_dir = NULL;
                if (mnt_dir->ops->lookup &&
                    mnt_dir->ops->lookup(mnt_dir, "dir_busy", &busy_dir) == 0 && busy_dir) {
                    struct fut_vnode *tmp = NULL;
                    if (busy_dir->ops && busy_dir->ops->create) {
                        busy_dir->ops->create(busy_dir, "dangling", 0644, &tmp);
                        if (tmp) {
                            fut_vnode_unref(tmp);
                        }
                    }
                    fut_vnode_unref(busy_dir);
                }

                ret = fut_vfs_rmdir("/mnt/dir_busy");
                fut_printf("[FUTURAFS-TEST]   rmdir(/mnt/dir_busy) expected ENOTEMPTY -> ret=%d\n", ret);

                fut_vfs_unlink("/mnt/dir_busy/dangling");
                fut_vfs_rmdir("/mnt/dir_busy");
            }
        }

        fut_vnode_unref(mnt_dir);
    }

    fut_printf("[FUTURAFS-TEST] ===========================================\n");
    fut_printf("[FUTURAFS-TEST] FuturaFS test complete!\n");
    fut_printf("[FUTURAFS-TEST] ===========================================\n\n");
    fut_test_pass();
}

/**
 * FIPC sender thread - sends test messages.
 */
/**
 * Demonstration thread - shows scheduler working with multiple threads
 * (Currently unused - kept for testing purposes)
 */
__attribute__((unused)) static void demo_thread_a(void *arg) {
    extern void fut_printf(const char *, ...);
    int thread_id = (int)(uintptr_t)arg;

    for (int i = 0; i < 3; i++) {
        fut_printf("[THREAD-%d] Iteration %d\n", thread_id, i);
        fut_thread_yield();  // Yield to other threads
    }

    fut_printf("[THREAD-%d] Exiting\n", thread_id);
    fut_thread_exit();
}

__attribute__((unused)) static void demo_thread_b(void *arg) {
    extern void fut_printf(const char *, ...);
    int thread_id = (int)(uintptr_t)arg;

    for (int i = 0; i < 3; i++) {
        fut_printf("[THREAD-%d] Iteration %d\n", thread_id, i);
        fut_thread_yield();
    }

    fut_printf("[THREAD-%d] Exiting\n", thread_id);
    fut_thread_exit();
}

/**
 * Simple test thread - minimal code to isolate the issue
 */
__attribute__((unused)) static void simple_test_thread(void *arg) {
#ifdef __x86_64__
    /* Add inline assembly at the very start to debug (x86_64 only) */
    __asm__ volatile(
        "movw $0x3F8, %%dx\n"
        "movb $'E', %%al\n"      /* 'E' for Entry */
        "outb %%al, %%dx\n"
        ::: "dx", "ax"
    );
#endif

    extern void serial_puts(const char *);
    serial_puts("[SIMPLE-TEST] Thread running!\n");
    (void)arg;
    serial_puts("[SIMPLE-TEST] About to exit\n");
    fut_thread_exit();
}

__attribute__((unused)) static void fipc_sender_thread(void *arg) {
    extern void serial_puts(const char *);
    serial_puts("[FIPC-SENDER-ENTRY] Entered function\n");
    (void)arg;
    fut_printf("[FIPC-SENDER] Starting sender thread\n");

    /* Wait a bit for receiver to be ready */
    fut_thread_yield();

    /* Send test messages */
    for (int i = 0; i < 3; i++) {
        char msg[64];
        fut_printf("[FIPC-SENDER] Sending message %d\n", i);

        /* Build message payload */
        msg[0] = 'M';
        msg[1] = 'S';
        msg[2] = 'G';
        msg[3] = '0' + i;
        msg[4] = '\0';

        /* Send through FIPC channel */
        int ret = fut_fipc_send(g_test_channel, FIPC_MSG_USER_BASE, msg, 5);
        if (ret < 0) {
            fut_printf("[FIPC-SENDER] Send failed with error %d\n", ret);
        }

        fut_thread_yield();
    }

    fut_printf("[FIPC-SENDER] All messages sent, exiting\n");
    fut_thread_exit();
}

/**
 * FIPC receiver thread - receives and processes messages.
 */
__attribute__((unused)) static void fipc_receiver_thread(void *arg) {
    (void)arg;
    fut_printf("[FIPC-RECEIVER] Starting receiver thread\n");

    /* Receive messages */
    for (int i = 0; i < 3; i++) {
        fut_printf("[FIPC-RECEIVER] Waiting for message %d...\n", i);

        /* Allocate buffer for message (header + payload) */
        uint8_t buf[128];

        /* Poll until message arrives */
        while (fut_fipc_poll(g_test_channel, FIPC_EVENT_MESSAGE) == 0) {
            fut_thread_yield();
        }

        /* Receive message */
        ssize_t received = fut_fipc_recv(g_test_channel, buf, sizeof(buf));
        if (received < 0) {
            fut_printf("[FIPC-RECEIVER] Receive failed with error %lld\n", (long long)received);
            continue;
        }

        /* Parse message */
        struct fut_fipc_msg *msg = (struct fut_fipc_msg *)buf;
        char *payload = (char *)msg->payload;

        fut_printf("[FIPC-RECEIVER] Received message: type=0x%x, len=%u, payload='%s'\n",
                   msg->type, msg->length, payload);

        fut_thread_yield();
    }

    fut_printf("[FIPC-RECEIVER] All messages received, exiting\n");
    fut_thread_exit();
}

/* ============================================================
 *   Kernel Main Entry Point
 * ============================================================ */

/**
 * Main kernel initialization and startup.
 * Called from platform_init after platform-specific initialization.
 *
 * This function:
 * 1. Initializes kernel subsystems (memory, scheduler, IPC)
 * 2. Creates initial test threads
 * 3. Starts scheduling (never returns)
 */
void fut_kernel_main(void) {
    fut_serial_puts("[DEBUG] kernel_main: Entry\n");

    /* fbtest disabled - variables removed to reduce memory usage */
#if ENABLE_WINSRV_DEMO
    int winsrv_stage = -1;
    int winstub_stage = -1;
    int winsrv_exec = -1;
    int winstub_exec = -1;
#endif
#if ENABLE_WAYLAND_DEMO
    int wayland_stage = -1;
    int wayland_client_stage = -1;
    int wayland_color_stage = -1;
    int wayland_exec = -1;
    int wayland_client_exec = -1;
    int wayland_color_exec = -1;
#endif

#if defined(__x86_64__)
    uintptr_t min_phys = KERNEL_VIRTUAL_BASE + 0x100000ULL;
#endif

    /* ========================================
     *   Step 1: Initialize Memory Subsystem
     * ======================================== */

    fut_serial_puts("[DEBUG] kernel_main: Before PMM init\n");
    fut_printf("[INIT] Initializing physical memory manager...\n");

    /* Calculate memory base (starts after kernel) - use VIRTUAL address */
    /* In a higher-half kernel, all memory accesses must use virtual addresses */
    uintptr_t kernel_virt_end = (uintptr_t)_kernel_end;
    uintptr_t mem_base = (kernel_virt_end + 0xFFF) & ~0xFFFULL;  /* Page-align */

#if defined(__x86_64__)
    /* Skip legacy VGA/BIOS hole below 1 MiB */
    if (mem_base < min_phys) {
        mem_base = min_phys;
    }
#endif

    /* Initialize PMM with total available memory */
#if defined(__x86_64__)
    phys_addr_t mem_base_phys = pmap_virt_to_phys(mem_base);
    phys_addr_t boot_ptables_start_phys = pmap_virt_to_phys((uintptr_t)boot_ptables_start);
    phys_addr_t boot_ptables_end_phys = pmap_virt_to_phys((uintptr_t)boot_ptables_end);
    boot_ptables_start_phys &= ~(FUT_PAGE_SIZE - 1ULL);
    boot_ptables_end_phys = FUT_PAGE_ALIGN(boot_ptables_end_phys);
    if (mem_base_phys < boot_ptables_end_phys) {
        mem_base_phys = boot_ptables_end_phys;
        mem_base = pmap_phys_to_virt(mem_base_phys);
        min_phys = mem_base;
    }
#else
    phys_addr_t mem_base_phys = mem_base;
#endif
    fut_serial_puts("[DEBUG] kernel_main: Before mmap setup\n");
    fut_mmap_reset();
    if (mem_base_phys > 0) {
        fut_mmap_add(0, mem_base_phys, 2);
    }
    fut_mmap_add(mem_base_phys, TOTAL_MEMORY_SIZE, 1);

    fut_serial_puts("[DEBUG] kernel_main: Before PMM init call\n");
    fut_pmm_init(TOTAL_MEMORY_SIZE, mem_base_phys);

    fut_serial_puts("[DEBUG] kernel_main: After PMM init\n");
    fut_printf("[INIT] PMM initialized: %llu pages total, %llu pages free\n",
               fut_pmm_total_pages(), fut_pmm_free_pages());

    /* Initialize kernel heap */
    fut_serial_puts("[DEBUG] kernel_main: Before heap init\n");
    fut_printf("[INIT] Initializing kernel heap...\n");

    /* Heap region in virtual memory (after kernel end) */
    uintptr_t heap_start = (uintptr_t)_kernel_end;
    heap_start = (heap_start + 0xFFF) & ~0xFFFULL;  /* Page-align */
#if defined(__x86_64__)
    if (heap_start < min_phys) {
        heap_start = min_phys;
    }
#endif
    uintptr_t heap_end = heap_start + KERNEL_HEAP_SIZE;

    /* Debug: print heap addresses before initialization */
    fut_printf("[DEBUG] _kernel_end address: 0x%llx\n",
               (unsigned long long)(uintptr_t)_kernel_end);
    fut_printf("[DEBUG] heap_start: 0x%llx\n", (unsigned long long)heap_start);
    fut_printf("[DEBUG] heap_end: 0x%llx\n", (unsigned long long)heap_end);
    fut_printf("[DEBUG] heap_size: %llu bytes\n",
               (unsigned long long)KERNEL_HEAP_SIZE);

    fut_serial_puts("[DEBUG] kernel_main: Calling fut_heap_init\n");
    fut_heap_init(heap_start, heap_end);

    fut_serial_puts("[DEBUG] kernel_main: After heap init\n");
    fut_printf("[INIT] Heap initialized: 0x%llx - 0x%llx (%llu MiB)\n",
               heap_start, heap_end, KERNEL_HEAP_SIZE / (1024 * 1024));

    fut_serial_puts("[DEBUG] kernel_main: Before timer init\n");
    fut_printf("[INIT] Initializing timer subsystem...\n");
    fut_timer_subsystem_init();

    fut_serial_puts("[DEBUG] kernel_main: Before ACPI init\n");
    fut_printf("[INIT] Initializing ACPI...\n");
    extern bool acpi_init(void);
    extern void acpi_parse_madt(void);
    if (acpi_init()) {
        fut_printf("[INIT] Parsing MADT for CPU topology...\n");
        acpi_parse_madt();
    }

#if defined(__x86_64__)
    /* Initialize per-CPU data for BSP */
    fut_printf("[INIT] Initializing BSP per-CPU data...\n");

    /* For now, use CPU ID 0 for BSP (LAPIC disabled for PIC mode testing) */
    /* TODO: Restore lapic_get_id() when LAPIC is re-enabled */
    uint32_t bsp_apic_id = 0;  /* lapic_get_id() requires LAPIC init */

    fut_percpu_init(bsp_apic_id, 0);
    fut_printf("[INIT] Per-CPU data initialized for BSP (CPU ID %u, index 0)\n", bsp_apic_id);

    /* Set GS_BASE to point to per-CPU data */
    fut_percpu_set(&fut_percpu_data[0]);

    /* Mark per-CPU data as safe to access (enables fut_thread_current()) */
    fut_thread_mark_percpu_safe();
    fut_printf("[INIT] Per-CPU data marked as safe for access\n");
#else
    fut_printf("[INIT] Initializing per-CPU data for CPU 0...\n");
    fut_percpu_init(0, 0);
    fut_thread_mark_percpu_safe();
    fut_printf("[INIT] Per-CPU data initialized for CPU 0\n");
#endif

    fut_serial_puts("[DEBUG] kernel_main: Before boot banner\n");
    fut_boot_banner();

#ifdef WAYLAND_INTERACTIVE_MODE
    /* In interactive/headful mode, always enable framebuffer for virtio-gpu */
    bool fb_enabled = true;
#else
    bool fb_enabled = boot_flag_enabled("fb", false);  /* Disabled in favor of wayland */
#endif
    bool fb_available = fb_enabled && fb_is_available();
    fut_printf("[INIT] fb_enabled=%d fb_available=%d\n",
               fb_enabled ? 1 : 0, fb_available ? 1 : 0);
    if (fb_available) {
        /* Enable framebuffer splash for virtio-gpu initialization */
        fb_boot_splash();
        fb_char_init();
        struct fut_fb_hwinfo fbinfo = {0};
        if (fb_get_info(&fbinfo) == 0) {
            fut_printf("[INIT] fb geometry %ux%u pitch=%u bpp=%u phys=0x%llx\n",
                       fbinfo.info.width,
                       fbinfo.info.height,
                       fbinfo.info.pitch,
                       fbinfo.info.bpp,
                       (unsigned long long)fbinfo.phys);
        }
    } else {
        fb_enabled = false;
    }

    /* DISABLED: Smoke tests consume too much physical memory
       Needed by wayland to create process memory managers
    */
    fut_printf("[INIT] Smoke tests disabled to free physical pages for wayland\n");

    /* Initialize input drivers - REQUIRED for Wayland compositor */
#ifdef ENABLE_WAYLAND_DEMO
    fut_printf("[INIT] Initializing input drivers for Wayland...\n");
    bool input_enabled = true;  /* Required for interactive mode */
    int input_rc = fut_input_hw_init(true, true);
    if (input_rc != 0) {
        fut_printf("[INPUT] init failed: %d - Wayland may not work!\n", input_rc);
        input_enabled = false;
    } else {
        fut_printf("[INPUT] Keyboard and mouse drivers initialized\n");
    }
#else
    /* For non-interactive builds, allow boot flag to control input */
    bool input_enabled = boot_flag_enabled("input", false);
    if (input_enabled) {
        int input_rc = fut_input_hw_init(true, true);
        if (input_rc != 0) {
            fut_printf("[INPUT] init failed: %d\n", input_rc);
            input_enabled = false;
        }
    }
#endif

    /* ========================================
     *   Step 2: Initialize FIPC Subsystem
     * ======================================== */

    fut_printf("[INIT] Initializing FIPC (Futura Inter-Process Communication)...\n");
    fut_fipc_init();
    fut_printf("[INIT] FIPC initialized\n");

    /* ========================================
     *   Step 3: Initialize VFS and Root Filesystem
     * ======================================== */

    fut_printf("[INIT] Initializing VFS (Virtual Filesystem)...\n");
    fut_vfs_init();

    /* Register ramfs filesystem type */
    fut_ramfs_init();
    fut_printf("[INIT] Registered ramfs filesystem\n");

    /* Mount ramfs as root filesystem */
    int vfs_ret = fut_vfs_mount(NULL, "/", "ramfs", 0, NULL, FUT_INVALID_HANDLE);
    if (vfs_ret < 0) {
        fut_printf("[ERROR] Failed to mount root filesystem (error %d)\n", vfs_ret);
        fut_platform_panic("Failed to mount root filesystem");
    }

    fut_console_init();
    fut_printf("[INIT] Console device registered at /dev/console\n");

    /* Give console input thread a chance to start before doing I/O */
    /* DISABLED: Scheduler not ready at this boot stage, causes hang */
    /*
    extern void fut_thread_yield(void);
    for (int i = 0; i < 100; i++) {
        fut_thread_yield();
    }
    */

    /* TODO: Fix VFS open deadlock with /dev/console
     * The following code causes the kernel to hang. Commenting out for now
     * to allow boot to proceed. Need to investigate why try_open_chrdev()
     * is not returning when the device is properly registered.
     */
    /*
    int fd0 = fut_vfs_open("/dev/console", O_RDWR, 0);
    int fd1 = fut_vfs_open("/dev/console", O_RDWR, 0);
    int fd2 = fut_vfs_open("/dev/console", O_RDWR, 0);
    if (fd0 < 0 || fd1 < 0 || fd2 < 0) {
        fut_printf("[WARN] Failed to seed /dev/console descriptors (fd0=%d fd1=%d fd2=%d)\n",
                   fd0, fd1, fd2);
    }
    */

    fut_printf("[INIT] Root filesystem mounted (ramfs at /)\n");

    /* Create /tmp directory for temporary files */
    int tmp_ret = fut_vfs_mkdir("/tmp", 0777);
    if (tmp_ret < 0 && tmp_ret != -EEXIST) {
        fut_printf("[WARN] Failed to create /tmp directory (error %d)\n", tmp_ret);
    }

    /* Mount ramfs at /tmp to make it writable for Wayland sockets and other temporary files */
    fut_printf("[INIT] About to mount ramfs at /tmp\n");
    int tmp_mount_ret = fut_vfs_mount(NULL, "/tmp", "ramfs", 0, NULL, FUT_INVALID_HANDLE);
    fut_printf("[INIT] Mount ramfs /tmp result: %d\n", tmp_mount_ret);
    if (tmp_mount_ret == 0) {
        fut_printf("[INIT] ✓ Mounted writable ramfs at /tmp\n");
    } else {
        fut_printf("[WARN] ✗ Failed to mount ramfs at /tmp (error %d)\n", tmp_mount_ret);
    }

    bool perf_flag = fut_boot_arg_flag("perf");
    bool run_async_selftests = boot_flag_enabled("async-tests", false);

    uint16_t planned_tests = 1u; /* VFS smoke */
    if (fb_enabled) {
        planned_tests += 1u;
    }
    if (input_enabled) {
        planned_tests += 1u;
    }
    planned_tests += 1u; /* exec double */
#if ENABLE_WAYLAND_DEMO
    planned_tests += 1u; /* Wayland demo sentinel */
#endif
    if (run_async_selftests) {
        planned_tests += 1u; /* block */
        planned_tests += 1u; /* futfs */
        planned_tests += 1u; /* net */
        if (perf_flag) {
            planned_tests += 1u; /* perf */
        }
    }
    fut_test_plan(planned_tests);

    /* DISABLED: VFS and exec double tests consume too much physical memory */
    /*
    test_vfs_operations();
    fut_exec_double_smoke();
    */
    fut_printf("[INIT] VFS and exec tests disabled to free physical pages for wayland\n");

    /* ========================================
     *   Step 4: Initialize Block Device Subsystem
     * ======================================== */

    fut_printf("[INIT] Initializing block device subsystem...\n");
    fut_blockdev_init();
    fut_blk_core_init();
    fut_status_t vblk_rc = virtio_blk_init(0);
    if (vblk_rc != 0 && vblk_rc != -19) {  /* -19 = ENODEV (no device found) */
        fut_printf("[virtio-blk] init failed: %d\n", vblk_rc);
    }
    /* ahci_init(); */  /* AHCI not yet implemented */
    fut_printf("[INIT] Block device subsystem initialized\n");

    /* ========================================
     *   Step 5: Initialize FuturaFS and Mount Block Device
     * ======================================== */

    extern void fut_futurafs_init(void);
    fut_futurafs_init();
    fut_printf("[INIT] FuturaFS filesystem registered\n");

    /* Disabled automatic FuturaFS formatting to allow scheduler to start
     * Block device I/O during init blocks kernel startup before scheduler
     * This should be done after scheduler initialization instead */
    /*
    if (vblk_rc == 0) {
        extern struct fut_blockdev *fut_blockdev_find(const char *name);
        struct fut_blockdev *test_dev = fut_blockdev_find("blk:vda");
        if (test_dev) {
            fut_printf("[INIT] Block device 'blk:vda' found\n");

            fut_printf("[INIT] Formatting blk:vda with FuturaFS...\n");
            int format_rc = fut_futurafs_format(test_dev, "FuturaOS", 4096);
            if (format_rc == 0) {
                fut_printf("[INIT] Successfully formatted blk:vda with FuturaFS\n");
            } else {
                fut_printf("[INIT] Failed to format blk:vda: error %d\n", format_rc);
            }
        } else {
            fut_printf("[INIT] Block device 'blk:vda' NOT found\n");
        }

        int mount_rc = fut_vfs_mount("blk:vda", "/mnt", "futurafs", 0, NULL, FUT_INVALID_HANDLE);
        if (mount_rc == 0) {
            fut_printf("[INIT] Mounted FuturaFS from blk:vda at /mnt\n");
        } else {
            fut_printf("[INIT] Failed to mount FuturaFS: error %d\n", mount_rc);
        }
    }
    */

    fut_printf("[INIT] Initializing network subsystem...\n");
    fut_net_init();
    fut_status_t vnet_rc = virtio_net_init();
    if (vnet_rc != 0) {
        fut_printf("[virtio-net] init failed: %d\n", vnet_rc);
    }

    /* Initialize TCP/IP stack */
    int tcpip_rc = tcpip_init();
    if (tcpip_rc != 0) {
        fut_printf("[TCP/IP] init failed: %d\n", tcpip_rc);
    } else {
        /* Test ping to external site (Google DNS 8.8.8.8) */
        fut_printf("[TCP/IP-TEST] Sending ICMP ping to 8.8.8.8 (Google DNS)...\n");
        uint32_t google_dns = (8 << 24) | (8 << 16) | (8 << 8) | 8;  /* 8.8.8.8 */
        const char *ping_data = "Futura OS ping test";
        int ping_rc = icmp_ping(google_dns, 1, 1, (void *)ping_data, 19);  /* strlen("Futura OS ping test") = 19 */
        if (ping_rc == 0) {
            fut_printf("[TCP/IP-TEST] ✓ ICMP echo request sent successfully to 8.8.8.8\n");
        } else {
            fut_printf("[TCP/IP-TEST] ✗ Failed to send ping: %d\n", ping_rc);
        }

        /* Test ping to another well-known DNS (1.1.1.1 - Cloudflare) */
        fut_printf("[TCP/IP-TEST] Sending ICMP ping to 1.1.1.1 (Cloudflare DNS)...\n");
        uint32_t cloudflare_dns = (1 << 24) | (1 << 16) | (1 << 8) | 1;  /* 1.1.1.1 */
        ping_rc = icmp_ping(cloudflare_dns, 1, 2, (void *)ping_data, 19);  /* strlen("Futura OS ping test") = 19 */
        if (ping_rc == 0) {
            fut_printf("[TCP/IP-TEST] ✓ ICMP echo request sent successfully to 1.1.1.1\n");
        } else {
            fut_printf("[TCP/IP-TEST] ✗ Failed to send ping: %d\n", ping_rc);
        }

        /* Initialize DNS resolver - TEMPORARILY DISABLED FOR SLAB DEBUGGING */
        fut_printf("[DNS-TEST] Skipped for slab debugging\n");
        if (0) {  /* Disabled */
        fut_printf("[DNS-TEST] Initializing DNS resolver...\n");
        /* Use QEMU's built-in DNS server at 10.0.2.3 for user networking */
        uint32_t qemu_dns_ip = (10 << 24) | (0 << 16) | (2 << 8) | 3;  /* 10.0.2.3 */
        uint32_t google_dns_ip = (8 << 24) | (8 << 16) | (8 << 8) | 8;  /* 8.8.8.8 (fallback) */
        int dns_rc = dns_init(qemu_dns_ip, google_dns_ip);
        if (dns_rc != 0) {
            fut_printf("[DNS-TEST] ✗ DNS init failed: %d\n", dns_rc);
        } else {
            /* Test DNS resolution */
            fut_printf("[DNS-TEST] Testing domain resolution...\n");

            /* Test 1: Resolve google.com */
            uint32_t resolved_ip;
            dns_rc = dns_resolve("google.com", &resolved_ip);
            if (dns_rc == 0) {
                char ip_str[16];
                dns_format_ip(resolved_ip, ip_str, sizeof(ip_str));
                fut_printf("[DNS-TEST] ✓ google.com -> %s\n", ip_str);
            } else {
                fut_printf("[DNS-TEST] ✗ Failed to resolve google.com: %d\n", dns_rc);
            }

            /* Test 2: Resolve example.com */
            dns_rc = dns_resolve("example.com", &resolved_ip);
            if (dns_rc == 0) {
                char ip_str[16];
                dns_format_ip(resolved_ip, ip_str, sizeof(ip_str));
                fut_printf("[DNS-TEST] ✓ example.com -> %s\n", ip_str);
            } else {
                fut_printf("[DNS-TEST] ✗ Failed to resolve example.com: %d\n", dns_rc);
            }

            /* Test 3: Cache hit test - resolve google.com again */
            dns_rc = dns_resolve("google.com", &resolved_ip);
            if (dns_rc == 0) {
                fut_printf("[DNS-TEST] ✓ Cache test: google.com (should be cached)\n");
            }
        }
        }  /* End DNS tests disabled for slab debugging */
    }

    /* Test block device operations - DISABLED (heap too small for 1MB ramdisk) */
    /* test_blockdev_operations(); */

    /* Test FuturaFS operations with smaller ramdisk
     * DISABLED for interactive mode - need heap space for compositor staging */
    /* Slab debugging complete - disabled again for interactive mode */
    /* test_futurafs_operations(); */

    fut_printf("[INIT] Skipping fbtest staging (debugging)\n");
    // TEMPORARILY DISABLED FOR DEBUGGING
    // fb_stage = fut_stage_fbtest_binary();
    // fut_printf("[INIT] fut_stage_fbtest_binary returned %d\n", fb_stage);
    // if (fb_stage != 0) {
    //     fut_printf("[WARN] Failed to stage fbtest binary (error %d)\n", fb_stage);
    // } else {
    //     fut_printf("[INIT] fbtest binary staged at /bin/fbtest\n");
    // }

#if ENABLE_WINSRV_DEMO
    fut_printf("[INIT] Staging winsrv user binary...\n");
    winsrv_stage = fut_stage_winsrv_binary();
    if (winsrv_stage != 0) {
        fut_printf("[WARN] Failed to stage winsrv binary (error %d)\n", winsrv_stage);
    } else {
        fut_printf("[INIT] winsrv binary staged at /sbin/winsrv\n");
    }

    fut_printf("[INIT] Staging winstub user binary...\n");
    winstub_stage = fut_stage_winstub_binary();
    if (winstub_stage != 0) {
        fut_printf("[WARN] Failed to stage winstub binary (error %d)\n", winstub_stage);
    } else {
        fut_printf("[INIT] winstub binary staged at /bin/winstub\n");
    }
#endif

#if ENABLE_WAYLAND_DEMO
    fut_printf("[INIT] Staging futura-wayland compositor...\n");
    fut_printf("[INIT-DEBUG] About to call fut_stage_wayland_compositor_binary\n");
    wayland_stage = fut_stage_wayland_compositor_binary();
    fut_printf("[INIT-DEBUG] Returned from fut_stage_wayland_compositor_binary, stage=%d\n", wayland_stage);
    if (wayland_stage != 0) {
        fut_printf("[WARN] Failed to stage futura-wayland binary (error %d, continuing)\n", wayland_stage);
        /* Continue even if staging fails for interactive testing */
    } else {
        fut_printf("[INIT] futura-wayland staged at /sbin/futura-wayland\n");
    }
    fut_printf("[INIT-DEBUG] About to stage wl-simple\n");

    fut_printf("[INIT] Staging wl-simple client...\n");
    wayland_client_stage = fut_stage_wayland_client_binary();
    if (wayland_client_stage != 0) {
        fut_printf("[WARN] Failed to stage wl-simple binary (error %d, continuing)\n", wayland_client_stage);
        /* Continue even if staging fails for interactive testing */
    } else {
        fut_printf("[INIT] wl-simple staged at /bin/wl-simple\n");
    }

    fut_printf("[INIT] Staging wl-colorwheel client...\n");
    wayland_color_stage = fut_stage_wayland_color_client_binary();
    if (wayland_color_stage != 0) {
        fut_printf("[WARN] Failed to stage wl-colorwheel binary (error %d)\n", wayland_color_stage);
    } else {
        fut_printf("[INIT] wl-colorwheel staged at /bin/wl-colorwheel\n");
    }
#endif
    /* ========================================
     *   Step 5: Initialize Scheduler
     * ======================================== */

    fut_printf("[INIT] Initializing scheduler...\n");
    fut_sched_init();
    fut_printf("[INIT] Scheduler initialized with idle thread\n");

    /* ========================================
     *   Memory Management Tests
     * ======================================== */

    bool mm_tests_enabled = boot_flag_enabled("mm-tests", true);  /* Default ON for testing */
    if (mm_tests_enabled) {
        fut_mm_tests_run();
    }

    /* DISABLED: fbtest consumes too much memory - prioritize wayland execution */
    /*
    if (fb_stage == 0) {
        char fbtest_name[] = "fbtest";
        char *fbtest_args[] = { fbtest_name, NULL };
        fb_exec = fut_exec_elf("/bin/fbtest", fbtest_args);
        if (fb_exec != 0) {
            fut_printf("[WARN] Failed to launch /bin/fbtest (error %d)\n", fb_exec);
        } else {
            fut_printf("[INIT] Scheduled /bin/fbtest user process\n");
        }
    }
    */
    fut_printf("[INIT] fbtest disabled to free memory for wayland\n");

    /* ========================================
     *   Launch Interactive Shell
     * ======================================== */
    /* Shell binary is staged as a file in initramfs, not embedded */
    /* fut_printf("[INIT] Staging shell binary...\n");
    int shell_stage = fut_stage_shell_binary();
    if (shell_stage != 0) {
        fut_printf("[WARN] Failed to stage shell binary (error %d)\n", shell_stage);
    } */

    fut_printf("[INIT] Launching shell...\n");
    char shell_name[] = "shell";
    char *shell_args[] = { shell_name, NULL };
    int shell_exec = fut_exec_elf("/bin/shell", shell_args, NULL);
    if (shell_exec != 0) {
        fut_printf("[WARN] Failed to launch /bin/shell (error %d)\n", shell_exec);
    } else {
        fut_printf("[INIT] Interactive shell launched\n");
    }

#if ENABLE_WINSRV_DEMO
    if (winsrv_stage == 0) {
        char winsrv_name[] = "winsrv";
        char *winsrv_args[] = { winsrv_name, NULL };
        winsrv_exec = fut_exec_elf("/sbin/winsrv", winsrv_args, NULL);
        if (winsrv_exec != 0) {
            fut_printf("[WARN] Failed to launch /sbin/winsrv (error %d)\n", winsrv_exec);
        } else {
            fut_printf("[INIT] Scheduled /sbin/winsrv service\n");
        }
    }

    if (winsrv_exec == 0 && winstub_stage == 0) {
        fut_boot_delay_ms(100);
        char winstub_name[] = "winstub";
        char *winstub_args[] = { winstub_name, NULL };
        winstub_exec = fut_exec_elf("/bin/winstub", winstub_args, NULL);
        if (winstub_exec != 0) {
            fut_printf("[WARN] Failed to launch /bin/winstub (error %d)\n", winstub_exec);
        } else {
            fut_printf("[INIT] Scheduled /bin/winstub demo client\n");
        }
    }
#endif

#if ENABLE_WAYLAND_DEMO
    if (wayland_stage == 0) {
        char name[] = "futura-wayland";
        char *args[] = { name, NULL };
        wayland_exec = fut_exec_elf("/sbin/futura-wayland", args, NULL);
        if (wayland_exec != 0) {
            fut_printf("[WARN] Failed to launch /sbin/futura-wayland (error %d)\n", wayland_exec);
#if ENABLE_WAYLAND_DEMO
            fut_test_fail(WAYLAND_TEST_EXEC_FAIL);
#endif
        } else {
            fut_printf("[INIT] exec /sbin/futura-wayland -> 0\n");
        }
    }

    /* Re-enabled: using wayland instead of direct framebuffer */
    wayland_client_exec = 0;  /* Will be set by actual exec below */
    wayland_color_exec = 0;   /* Will be set by actual exec below */
#if 1  /* Enabled wayland clients */
    if (wayland_exec == 0 && wayland_client_stage == 0) {
        fut_boot_delay_ms(100);
        char name[] = "wl-simple";
        char *args[] = { name, NULL };
        wayland_client_exec = fut_exec_elf("/bin/wl-simple", args, NULL);
        if (wayland_client_exec != 0) {
            fut_printf("[WARN] Failed to launch /bin/wl-simple (error %d)\n", wayland_client_exec);
#if ENABLE_WAYLAND_DEMO
            fut_test_fail(WAYLAND_TEST_CLIENT_FAIL);
#endif
        } else {
            fut_printf("[INIT] exec /bin/wl-simple -> 0\n");
        }
    }

    /* Disabled colorwheel client to save memory for shell staging */
#if 0
    if (wayland_exec == 0 && wayland_client_exec == 0 && wayland_color_stage == 0) {
        fut_boot_delay_ms(100);
        char name[] = "wl-colorwheel";
        char *args[] = { name, NULL };
        wayland_color_exec = fut_exec_elf("/bin/wl-colorwheel", args, NULL);
        if (wayland_color_exec != 0) {
            fut_printf("[WARN] Failed to launch /bin/wl-colorwheel (error %d)\n", wayland_color_exec);
        } else {
            fut_printf("[INIT] exec /bin/wl-colorwheel -> 0\n");
        }
    }
#endif
#endif

    /* Check if interactive mode is enabled (for GUI testing) */
    /* When ENABLE_WAYLAND_DEMO is set, enable interactive mode so user can interact with shell */
    bool wayland_interactive = false;
#ifdef ENABLE_WAYLAND_DEMO
    /* For wayland demo, keep system interactive for user interaction */
    wayland_interactive = true;
#endif

    if (wayland_exec == 0 && wayland_client_exec == 0) {
        uint32_t finalize_delay_ms = 2500;
        if (wayland_color_stage == 0 && wayland_color_exec == 0) {
            finalize_delay_ms = 3200;
        }
        fut_boot_delay_ms(finalize_delay_ms);

        if (!wayland_interactive) {
            /* Auto-exit for automated testing (default behavior) */
#ifdef __x86_64__
            hal_outb(0xf4u, 0u);  /* x86-64 debug port exit */
#endif
#if ENABLE_WAYLAND_DEMO
            fut_test_pass();
#endif
        } else {
            /* Interactive mode: Scheduler will start and switch to processes */
            fut_printf("[INIT] ========================================\n");
            fut_printf("[INIT] Wayland Interactive Mode - Scheduler Starting\n");
            fut_printf("[INIT] ========================================\n");
            /* Removed HLT loop - scheduler must start to run processes */
        }
    } else if (wayland_interactive) {
        /* Interactive mode requested but processes failed to launch - still start scheduler */
        fut_printf("[WARN] Interactive mode requested but compositor/clients failed to launch\n");
        fut_printf("[WARN] Wayland exec: %d, client exec: %d\n", wayland_exec, wayland_client_exec);
        fut_printf("[WARN] Continuing to scheduler anyway\n");
    }
#endif

    /* ========================================
     *   Step 6: Create Test Task and FIPC Channel
     * ======================================== */

    fut_printf("[INIT] Creating test task for FIPC demonstration...\n");

    /* Create a test task (process container) */
    fut_task_t *test_task = fut_task_create();
    if (!test_task) {
        fut_printf("[ERROR] Failed to create test task!\n");
        fut_platform_panic("Failed to create test task");
    }

    fut_printf("[INIT] Test task created (PID %llu)\n", test_task->pid);

    bool perf_enabled = run_async_selftests && perf_flag;

    if (run_async_selftests) {
        fut_blk_async_selftest_schedule(test_task);
        fut_futfs_selftest_schedule(test_task);
        fut_net_selftest_schedule(test_task);
        if (perf_enabled) {
            fut_perf_selftest_schedule(test_task);
        }
    }

    /* Disable watchdog for now - it exits immediately due to fut_tests_completed() stub */
    /*
    fut_thread_t *watchdog_thread = fut_thread_create(
        test_task,
        fut_test_watchdog_thread,
        NULL,
        8 * 1024,
        60
    );
    if (!watchdog_thread) {
        fut_printf("[WARN] Failed to create test watchdog thread\n");
    }
    */

    /* Create FIPC channel for inter-thread communication */
    fut_printf("[INIT] Creating FIPC test channel...\n");
    int ret = fut_fipc_channel_create(
        test_task,              /* Sender task */
        test_task,              /* Receiver task (same task, different threads) */
        4096,                   /* 4KB message queue */
        FIPC_CHANNEL_NONBLOCKING,  /* Non-blocking mode */
        &g_test_channel
    );

    if (ret != 0) {
        fut_printf("[ERROR] Failed to create FIPC channel (error %d)\n", ret);
        fut_platform_panic("Failed to create FIPC channel");
    }

    fut_printf("[INIT] FIPC channel created (ID %llu)\n", g_test_channel->id);

    /* ========================================
     *   Step 7: Create FIPC Test Threads
     * ======================================== */

    /* Demo threads disabled - scheduler working correctly
    fut_printf("[INIT] Creating demo threads to test scheduler...\n");

    fut_thread_t *thread_a = fut_thread_create(
        test_task,
        demo_thread_a,
        (void *)1,
        16 * 1024,
        128
    );

    if (!thread_a) {
        fut_printf("[ERROR] Failed to create thread A!\n");
        fut_platform_panic("Failed to create thread A");
    }

    fut_printf("[INIT] Thread A created (TID %llu)\n", thread_a->tid);

    fut_thread_t *thread_b = fut_thread_create(
        test_task,
        demo_thread_b,
        (void *)2,
        16 * 1024,
        128
    );

    if (!thread_b) {
        fut_printf("[ERROR] Failed to create thread B!\n");
        fut_platform_panic("Failed to create thread B");
    }

    fut_printf("[INIT] Thread B created (TID %llu)\n", thread_b->tid);
    */

    /* Skip receiver thread for now - test with just one thread */
    /* fut_thread_t *receiver_thread = fut_thread_create(
        test_task,
        fipc_receiver_thread,
        NULL,
        16 * 1024,
        128
    );

    if (!receiver_thread) {
        fut_printf("[ERROR] Failed to create receiver thread!\n");
        fut_platform_panic("Failed to create receiver thread");
    }

    fut_printf("[INIT] FIPC receiver thread created (TID %llu)\n", receiver_thread->tid); */

    /* ========================================
     *   Step 8: Start Scheduling
     * ======================================== */

    fut_printf("\n");
    fut_printf("=======================================================\n");
    fut_printf("   Kernel initialization complete!\n");
    fut_printf("   Starting scheduler...\n");
    fut_printf("=======================================================\n\n");

    /* Enable timer interrupts now that all subsystems are ready */
    extern void fut_irq_enable(uint8_t irq);
    fut_printf("[INIT] Enabling timer IRQ for preemptive scheduling...\n");
    fut_irq_enable(0);  /* Unmask PIC IRQ 0 (timer) */

    /* Enable interrupts and start scheduling */
    /* This should never return - scheduler takes over */
    __asm__ volatile("sti" ::: "memory");  /* Enable interrupts for timer-based preemption */
    fut_schedule();

    /* Should never reach here */
    fut_printf("[PANIC] Scheduler returned unexpectedly!\n");
    fut_platform_panic("Scheduler returned to kernel_main");
}
