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
#include <kernel/signal.h>
#include <kernel/fut_futurafs.h>
#include <kernel/fb.h>
#include <kernel/console.h>
#include <kernel/boot_banner.h>
#include <kernel/boot_args.h>

/* Platform-specific memory mapping */
#if defined(__x86_64__)
#include <platform/x86_64/memory/pmap.h>
#elif defined(__aarch64__)
#include <platform/arm64/memory/pmap.h>
#endif
#include <kernel/fut_percpu.h>
#include <kernel/input.h>
#include <kernel/platform_hooks.h>
#include <futura/blkdev.h>
#include <futura/net.h>
#include <futura/tcpip.h>
#include <futura/dns.h>
#include <platform/platform.h>
#include "tests/test_api.h"
#include "tests/perf.h"
#if defined(__x86_64__)
#include <platform/x86_64/memory/paging.h>
#include <platform/x86_64/memory/pmap.h>
#include <platform/x86_64/interrupt/lapic.h>
#elif defined(__aarch64__)
#include <platform/arm64/memory/paging.h>
#include <platform/arm64/interrupt/irq.h>
#include <platform/arm64/process.h>
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
extern void fut_multiprocess_selftest_schedule(fut_task_t *task);
extern void fut_dup2_selftest_schedule(fut_task_t *task);
extern void fut_pipe_selftest_schedule(fut_task_t *task);
extern void fut_signal_selftest_schedule(fut_task_t *task);

#if ENABLE_WAYLAND_DEMO
#define WAYLAND_TEST_SENTINEL_CODE 0xD0u
#define WAYLAND_TEST_STAGE_FAIL    0xD1u
#define WAYLAND_TEST_EXEC_FAIL     0xD2u
#define WAYLAND_TEST_CLIENT_FAIL   0xD3u
#endif

#if ENABLE_WAYLAND_DEMO
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
#define KERNEL_HEAP_SIZE        (96 * 1024 * 1024)   /* 96 MiB kernel heap - supports large allocations */

/* ============================================================
 *   Platform Hook Weak Symbols
 * ============================================================ */

/* Weak implementations - platforms can override these */
__attribute__((weak)) void arch_late_init(void) {
    /* Default: do nothing */
}

__attribute__((weak)) void arch_idle_loop(void) {
    /* Default: infinite loop with interrupts enabled */
    fut_printf("[KERNEL] Entering default idle loop...\n");
    while (1) {
#if defined(__x86_64__)
        __asm__ volatile("hlt");
#elif defined(__aarch64__)
        __asm__ volatile("wfi");
#else
        /* Generic: just loop */
        for (volatile int i = 0; i < 1000000; i++);
#endif
    }
}

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

    /* Core Wayland variables (production) */
    int wayland_stage = -1;
    __attribute__((unused)) int wayland_exec = -1;  /* TODO: Make compositor exec unconditional */

#if ENABLE_WAYLAND_DEMO
    /* Test client variables (optional) */
    int wayland_client_stage = -1;
    int wayland_client_exec = -1;
#endif

    /* ========================================
     *   Step 1: Initialize Memory Subsystem
     * ======================================== */

    fut_printf("[INIT] Initializing physical memory manager...\n");

    /* Get platform-specific memory layout */
    uintptr_t ram_start, ram_end;
    size_t heap_size;
    arch_memory_config(&ram_start, &ram_end, &heap_size);


    /* Initialize PMM with platform-specific memory range */
    size_t total_memory = ram_end - ram_start;
    fut_mmap_reset();
    if (ram_start > 0) {
        fut_mmap_add(0, ram_start, 2);
    }
    fut_mmap_add(ram_start, total_memory, 1);

    fut_pmm_init(total_memory, ram_start);

    fut_printf("[INIT] PMM initialized: %llu pages total, %llu pages free\n",
               fut_pmm_total_pages(), fut_pmm_free_pages());

    /* Initialize kernel heap */
    fut_printf("[INIT] Initializing kernel heap...\n");

    /* Heap region starts after PMM allocation region
     * NOTE: arch_memory_config returns physical addresses,
     * but fut_heap_init expects virtual addresses.
     * Both x86_64 and ARM64 now use high-VA kernels and need phys_to_virt.
     */
    uintptr_t heap_start = (uintptr_t)pmap_phys_to_virt(ram_start);
    uintptr_t heap_end = (uintptr_t)pmap_phys_to_virt(ram_start + heap_size);

    /* Debug: print heap addresses before initialization */

    fut_heap_init(heap_start, heap_end);

    fut_printf("[INIT] Heap initialized: 0x%llx - 0x%llx (%llu MiB)\n",
               heap_start, heap_end, heap_size / (1024 * 1024));

    /* Initialize MM subsystem (kernel page table context) */
    fut_printf("[INIT] Initializing MM subsystem...\n");
    extern void fut_mm_system_init(void);
    fut_mm_system_init();

    fut_printf("[INIT] Initializing timer subsystem...\n");
    fut_timer_subsystem_init();

    fut_printf("[INIT] Initializing signal subsystem...\n");
    fut_signal_init();

    fut_printf("[INIT] Initializing ACPI...\n");
    extern bool acpi_init(void);
#ifdef __x86_64__
    extern void acpi_parse_madt(void);
    if (acpi_init()) {
        fut_printf("[INIT] Parsing MADT for CPU topology...\n");
        acpi_parse_madt();
    }
#else
    /* ARM64: ACPI parsing not yet implemented */
    acpi_init();
#endif

#if defined(__x86_64__)
    /* Initialize per-CPU data for BSP */
    fut_printf("[INIT] Initializing BSP per-CPU data...\n");

    /* Get BSP APIC ID from hardware (LAPIC initialized in ACPI init) */
    uint32_t bsp_apic_id = lapic_get_id();

    fut_percpu_init(bsp_apic_id, 0);
    fut_printf("[INIT] Per-CPU data initialized for BSP (CPU ID %u, index 0)\n", bsp_apic_id);

    /* Set GS_BASE to point to per-CPU data */
    fut_percpu_set(&fut_percpu_data[0]);

    /* Mark per-CPU data as safe to access (enables fut_thread_current()) */
    fut_thread_mark_percpu_safe();
    fut_printf("[INIT] Per-CPU data marked as safe for access\n");
#else
    fut_serial_puts("[INIT] Initializing per-CPU data for CPU 0...\n");
    fut_percpu_init(0, 0);

    /* Set TPIDR_EL1 to point to per-CPU data (ARM64 equivalent of GS_BASE on x86_64) */
    fut_percpu_set(&fut_percpu_data[0]);

    /* Mark per-CPU data as safe to access (enables fut_thread_current()) */
    fut_thread_mark_percpu_safe();
    fut_serial_puts("[INIT] Per-CPU data initialized for CPU 0\n");
#endif

    fut_boot_banner();

    /* ARM64: Debug check for VA-to-PA mapping using known kernel symbols */
#ifdef __aarch64__
    {
        /* Use _bss_start which is already declared at the top of this file */
        uintptr_t bss_va = (uintptr_t)_bss_start;
        uint64_t bss_pa = pmap_virt_to_phys(bss_va);

        fut_printf("[VA-PA-CHECK] _bss_start VA=0x%016llx PA=0x%016llx (offset=0x%016llx)\n",
                   (unsigned long long)bss_va, (unsigned long long)bss_pa,
                   (unsigned long long)(bss_va - bss_pa));

        /* Expected offset: Virtual base 0xFFFFFF8040000000 - Physical load 0x40200000
         * (QEMU virt reserves 0x40000000-0x40200000 for DTB) */
        uint64_t expected_offset = 0xFFFFFF7FFFE00000ULL;
        uint64_t actual_offset = bss_va - bss_pa;
        if (actual_offset != expected_offset) {
            fut_printf("[VA-PA-CHECK] WARNING: Offset mismatch! Expected=0x%016llx Actual=0x%016llx Diff=0x%016llx\n",
                       (unsigned long long)expected_offset,
                       (unsigned long long)actual_offset,
                       (unsigned long long)(actual_offset - expected_offset));
        }
    }
#endif

#ifdef WAYLAND_INTERACTIVE_MODE
    /* In interactive/headful mode, always enable framebuffer for virtio-gpu */
    bool fb_enabled = true;
#elif defined(__aarch64__)
    /* ARM64: Enable framebuffer by default for display demos */
    bool fb_enabled = true;
#else
    bool fb_enabled = boot_flag_enabled("fb", false);  /* Disabled in favor of wayland */
#endif
    bool fb_available = fb_enabled && fb_is_available();
    fut_printf("[INIT] fb_enabled=%d fb_available=%d\n",
               fb_enabled ? 1 : 0, fb_available ? 1 : 0);

#ifdef WAYLAND_INTERACTIVE_MODE
    /* In headful mode, always initialize fb_char for virtio-gpu even if not detected yet */
    if (fb_enabled) {
#ifndef __aarch64__
        /* On ARM64, fb_boot_splash() was already called above */
        fb_boot_splash();
#endif
        fb_char_init();
#else
    if (fb_available) {
        /* Enable framebuffer splash for virtio-gpu initialization */
#ifndef __aarch64__
        /* On ARM64, fb_boot_splash() was already called above */
        fb_boot_splash();
#endif
        fb_char_init();
#endif
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

    /* ========================================
     *   Post-Subsystem Initialization
     * ======================================== */

    fut_serial_puts("[INIT] Smoke tests disabled\n");

    /* Diagnostic check for interrupt-driven UART on ARM64 */
#ifdef __aarch64__
    fut_serial_enable_irq_mode();
#endif

    /* Initialize input drivers - REQUIRED for Wayland compositor */
#ifdef ENABLE_WAYLAND_DEMO
    fut_serial_puts("[INIT] Initializing input drivers for Wayland...\n");
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
    extern volatile int vfs_debug_stage;
    vfs_debug_stage = 0;
    int vfs_ret = fut_vfs_mount(NULL, "/", "ramfs", 0, NULL, FUT_INVALID_HANDLE);
    if (vfs_ret < 0) {
        fut_printf("[ERROR] Failed to mount root filesystem (error %d, stage=%d)\n", vfs_ret, vfs_debug_stage);
        fut_platform_panic("Failed to mount root filesystem");
    }

    /* Create /dev directory for device files BEFORE registering devices */
    vfs_debug_stage = 0;

    /* Start mkdir in a way we can monitor */
    int dev_ret = fut_vfs_mkdir("/dev", 0755);

    /* If we get here, mkdir completed */
    if (dev_ret < 0 && dev_ret != -EEXIST) {
        fut_printf("[WARN] Failed to create /dev directory (error %d)\n", dev_ret);
    }

    fut_console_init();
    fut_printf("[INIT] Console device registered at /dev/console\n");

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
        planned_tests += 5u; /* multiprocess: fork isolation, FD inheritance, per-task isolation, cloexec, shared offset */
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

#ifdef __aarch64__
    /* On ARM64, initialize VirtIO-MMIO transport layer */
    extern void virtio_mmio_init(uint64_t dtb_ptr);
    virtio_mmio_init(0);  /* TODO: Pass actual DTB pointer once device tree parsing is implemented */
#endif

    fut_printf("[INIT] Initializing block device subsystem...\n");
    fut_blockdev_init();
    fut_blk_core_init();
    fut_status_t vblk_rc = virtio_blk_init(0);
    if (vblk_rc != 0 && vblk_rc != -19) {  /* -19 = ENODEV (no device found) */
        fut_printf("[virtio-blk] init failed: %d\n", vblk_rc);
    }
#ifdef __x86_64__
    /* ahci_init(); */  /* AHCI not yet implemented */
#endif
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

    /* Initialize network drivers (but not TCP/IP - that needs scheduler) */
    fut_printf("[INIT] Initializing network subsystem...\n");
    fut_net_init();
    fut_status_t vnet_rc = virtio_net_init();
    if (vnet_rc != 0) {
        fut_printf("[virtio-net] init failed: %d\n", vnet_rc);
    }
    fut_printf("[INIT] Network drivers initialized (TCP/IP stack will start after scheduler)\n");

    /* Test block device operations - DISABLED (heap too small for 1MB ramdisk) */
    /* test_blockdev_operations(); */

    /* Test FuturaFS operations with smaller ramdisk
     * DISABLED for interactive mode - need heap space for compositor staging */
    /* Slab debugging complete - disabled again for interactive mode */
    /* test_futurafs_operations(); */

    /* ========================================
     *   Stage Core Wayland Binaries (Production)
     * ======================================== */
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

    int wl_term_stage = fut_stage_wl_term_binary();
    if (wl_term_stage != 0) {
        fut_printf("[WARN] Failed to stage wl-term binary (error %d)\n", wl_term_stage);
    } else {
        fut_printf("[INIT] wl-term staged at /bin/wl-term\n");
    }

#if ENABLE_WAYLAND_TEST_CLIENTS
    /* ========================================
     *   Stage Test Clients (Optional)
     * ======================================== */
    fut_printf("[INIT-DEBUG] About to stage wl-simple\n");

    fut_printf("[INIT] Staging wl-simple client...\n");
    wayland_client_stage = fut_stage_wayland_client_binary();
    if (wayland_client_stage != 0) {
        fut_printf("[WARN] Failed to stage wl-simple binary (error %d, continuing)\n", wayland_client_stage);
        /* Continue even if staging fails for interactive testing */
    } else {
        fut_printf("[INIT] wl-simple staged at /bin/wl-simple\n");
    }

    fut_printf("[INIT-DEBUG] About to stage wl-colorwheel\n");
    fut_printf("[INIT] Staging wl-colorwheel client...\n");
    int wayland_color_stage = fut_stage_wayland_color_client_binary();
    if (wayland_color_stage != 0) {
        fut_printf("[WARN] Failed to stage wl-colorwheel binary (error %d, continuing)\n", wayland_color_stage);
        /* Continue even if staging fails - wl-simple is sufficient for testing */
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

#if defined(__aarch64__)
    /* ARM64: Initialize boot thread so per-CPU has a current thread */
    extern void arm64_init_boot_thread(void);
    arm64_init_boot_thread();
#endif

    /* ========================================
     *   Enable Interrupts and Start Scheduler
     * ======================================== */
    /* Enable interrupts NOW so the scheduler can run and user processes can execute */
    fut_printf("[INIT] Enabling interrupts to start scheduler...\n");
    fut_enable_interrupts();  /* Platform-neutral interrupt enable */

    /* Console input thread will be started after kernel init completes */
    fut_printf("[INIT] Scheduler running via timer IRQs\n");

    /* ========================================
     *   Seed Standard File Descriptors
     * ======================================== */
    /* Note: Console input thread will be started AFTER scheduler is running */
    int fd0 = fut_vfs_open("/dev/console", O_RDWR, 0);
    int fd1 = fut_vfs_open("/dev/console", O_RDWR, 0);
    int fd2 = fut_vfs_open("/dev/console", O_RDWR, 0);
    if (fd0 < 0 || fd1 < 0 || fd2 < 0) {
        fut_printf("[WARN] Failed to seed /dev/console descriptors (fd0=%d fd1=%d fd2=%d)\n",
                   fd0, fd1, fd2);
    } else {
        fut_printf("[INIT] Standard streams initialized (fd0=%d fd1=%d fd2=%d)\n", fd0, fd1, fd2);
    }

    /* ========================================
     *   Initialize TCP/IP Stack (requires scheduler)
     * ======================================== */
    fut_printf("[INIT] Initializing TCP/IP stack...\n");
    int tcpip_rc = tcpip_init();
    if (tcpip_rc != 0) {
        fut_printf("[TCP/IP] init failed: %d\n", tcpip_rc);
    } else {
        fut_printf("[TCP/IP] ✓ Stack initialized successfully\n");
    }

    /* ========================================
     *   Memory Management Tests
     * ======================================== */

#ifdef __x86_64__
    bool mm_tests_enabled = boot_flag_enabled("mm-tests", false);  /* Default OFF - enable with mm-tests boot flag */
    if (mm_tests_enabled) {
        fut_mm_tests_run();
    }
#endif

    /* ========================================
     *   Launch Init Process with Framebuffer Demo
     * ======================================== */
    extern int fut_stage_init_stub_binary(void);

    fut_printf("[INIT] Staging init process...\n");

    /* Stage init_stub */
    int init_stage = fut_stage_init_stub_binary();
    if (init_stage != 0) {
        fut_printf("[WARN] Failed to stage init_stub (error %d)\n", init_stage);
    }

#if ENABLE_FB_DIAGNOSTICS
    extern int fut_stage_fbtest_binary(void);
    /* Stage fbtest binary */
    int fbtest_stage = fut_stage_fbtest_binary();
    if (fbtest_stage != 0) {
        fut_printf("[WARN] Failed to stage fbtest binary (error %d)\n", fbtest_stage);
    }
#endif

    /* TEMPORARILY DISABLED: Console input thread busy-waits and prevents
     * user processes from running. Need to fix scheduler preemption first.
     * TODO: Re-enable after fixing busy-wait or implementing proper blocking. */
    // fut_printf("[INIT] Starting console input thread...\n");
    // fut_console_start_input_thread();

    /* Launch init process */
    if (init_stage == 0) {
        fut_printf("[INIT] Launching init process...\n");
        char init_name[] = "init";
        char *init_args[] = { init_name, NULL };
        int init_exec = fut_exec_elf("/sbin/init_stub", init_args, NULL);
        if (init_exec != 0) {
            fut_printf("[WARN] Failed to launch /sbin/init_stub (error %d)\n", init_exec);
        } else {
            fut_printf("[INIT] Init process launched successfully\n");
        }
    }

    /* ========================================
     *   Launch Interactive Shell
     * ======================================== */
    /* NOTE: Shell launch disabled - init_stub now launches wl-term instead */
    /* Shell binary is staged as a file in initramfs, not embedded */
    /* fut_printf("[INIT] Staging shell binary...\n");
    int shell_stage = fut_stage_shell_binary();
    if (shell_stage != 0) {
        fut_printf("[WARN] Failed to stage shell binary (error %d)\n", shell_stage);
    } else {
        fut_printf("[INIT] Launching shell...\n");
        char shell_name[] = "shell";
        char *shell_args[] = { shell_name, NULL };
        int shell_exec = fut_exec_elf("/bin/shell", shell_args, NULL);
        if (shell_exec != 0) {
            fut_printf("[WARN] Failed to launch /bin/shell (error %d)\n", shell_exec);
        } else {
            fut_printf("[INIT] Shell launched successfully\n");
        }
    } */

#if ENABLE_WAYLAND_DEMO
    if (wayland_stage == 0) {
        char name[] = "futura-wayland";
        char *args[] = { name, NULL };
        /* Environment with LD_PRELOAD for syscall routing via int 0x80 */
        char ld_preload[] = "LD_PRELOAD=/lib/libopen_wrapper.so";
        char *envp[] = { ld_preload, NULL };
        wayland_exec = fut_exec_elf("/sbin/futura-wayland", args, envp);
        if (wayland_exec != 0) {
            fut_printf("[WARN] Failed to launch /sbin/futura-wayland (error %d)\n", wayland_exec);
#if ENABLE_WAYLAND_DEMO
            fut_test_fail(WAYLAND_TEST_EXEC_FAIL);
#endif
        } else {
            fut_printf("[INIT] exec /sbin/futura-wayland -> 0\n");
        }
    }

    /* Multi-client Wayland: Launch wl-simple and optionally wl-colorwheel */
    wayland_client_exec = 0;  /* Will be set by actual exec below */
#if 1  /* Enabled: multi-client Wayland support */
    if (wayland_exec == 0 && wayland_client_stage == 0) {
        fut_boot_delay_ms(100);

        /* Launch first client: wl-simple */
        char name1[] = "wl-simple";
        char *args1[] = { name1, NULL };
        char ld_preload[] = "LD_PRELOAD=/lib/libopen_wrapper.so";
        char *envp[] = { ld_preload, NULL };
        wayland_client_exec = fut_exec_elf("/bin/wl-simple", args1, envp);
        if (wayland_client_exec != 0) {
            fut_printf("[WARN] Failed to launch /bin/wl-simple (error %d)\n", wayland_client_exec);
#if ENABLE_WAYLAND_DEMO
            fut_test_fail(WAYLAND_TEST_CLIENT_FAIL);
#endif
        } else {
            fut_printf("[INIT] exec /bin/wl-simple -> 0\n");
        }

        /* Launch second client: wl-colorwheel (if available) */
        if (wayland_color_stage == 0) {
            fut_boot_delay_ms(50);
            char name2[] = "wl-colorwheel";
            char *args2[] = { name2, NULL };
            int colorwheel_exec = fut_exec_elf("/bin/wl-colorwheel", args2, envp);
            if (colorwheel_exec != 0) {
                fut_printf("[WARN] Failed to launch /bin/wl-colorwheel (error %d), continuing with single client\n", colorwheel_exec);
            } else {
                fut_printf("[INIT] exec /bin/wl-colorwheel -> 0 (multi-client Wayland enabled!)\n");
            }
        }
    }
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
        fut_multiprocess_selftest_schedule(test_task);
        fut_dup2_selftest_schedule(test_task);
        fut_pipe_selftest_schedule(test_task);
        fut_signal_selftest_schedule(test_task);
        // fut_blk_async_selftest_schedule(test_task);
        // fut_futfs_selftest_schedule(test_task);
        // fut_net_selftest_schedule(test_task);
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
     *   Step 8: Platform Late Initialization
     * ======================================== */

    fut_printf("\n");
    fut_printf("=======================================================\n");
    fut_printf("   Kernel initialization complete!\n");
    fut_printf("   Calling platform late init...\n");
    fut_printf("=======================================================\n\n");

    /* Platform-specific late initialization (spawn init, etc.) */
    arch_late_init();

    /* ========================================
     *   Step 9: Enter Idle Loop
     * ======================================== */

    fut_printf("[INIT] Kernel init complete. Entering idle loop.\n");

#if defined(__x86_64__)
    /* Exit the boot thread to let the idle thread take over.
     * The scheduler has already been initialized with user threads in the ready queue.
     * Timer IRQs will drive scheduling between idle and user threads. */
    fut_printf("[INIT] Boot thread exiting, idle thread will take over\n");
    extern void fut_thread_exit(void) __attribute__((noreturn));
    fut_thread_exit();

    /* Should never reach here */
    fut_printf("[PANIC] Boot thread exit failed!\n");
    for (;;) {
        __asm__ volatile("hlt");
    }
#elif defined(__aarch64__)
    /* ARM64: Enable timer IRQ and start scheduling */
    /* The timer IRQ must be enabled explicitly here for alarm() delivery */
    fut_irq_enable(27);  /* Enable ARM Generic Timer virtual timer interrupt */

    /* Enable interrupts and start scheduling */
    fut_printf("[INIT] ARM64: Enabling interrupts and starting scheduler...\n");
    fut_enable_interrupts();

    /* Exit the boot thread to let the idle thread (tid=3, priority=0) take over.
     * The boot thread was causing livelock by staying in READY state in a yield loop.
     * Now only the idle thread and actual work threads will be scheduled. */
    fut_printf("[INIT] Boot thread exiting, idle thread will take over\n");
    extern void fut_thread_exit(void) __attribute__((noreturn));
    fut_thread_exit();

    /* Should never reach here */
    fut_printf("[PANIC] Boot thread exit failed!\n");
    for (;;) {
        fut_schedule();
    }
#else
    /* Other platforms: enter idle loop after late init */
    arch_idle_loop();
#endif
}
