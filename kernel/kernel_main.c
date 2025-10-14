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
#include <kernel/input.h>
#include <futura/blkdev.h>
#include <futura/net.h>
#include <platform/platform.h>
#include "tests/test_api.h"
#include "tests/perf.h"
#if defined(__x86_64__)
#include <arch/x86_64/paging.h>
#include <arch/x86_64/pmap.h>
#endif

extern void fut_echo_selftest(void);
extern void fut_fb_smoke(void);
extern void fut_input_smoke(void);
extern void fut_blk_async_selftest_schedule(fut_task_t *task);
extern void fut_futfs_selftest_schedule(fut_task_t *task);
extern void fut_net_selftest_schedule(fut_task_t *task);
extern void fut_perf_selftest_schedule(fut_task_t *task);
extern fut_status_t virtio_blk_init(uint64_t pci_addr);
extern fut_status_t virtio_net_init(void);
extern void ahci_init(void);
extern char boot_ptables_start[];
extern char boot_ptables_end[];

static bool boot_flag_enabled(const char *key, bool default_on) {
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

/* Memory configuration - for now assume 128MB available in QEMU */
#define TOTAL_MEMORY_SIZE       (128 * 1024 * 1024)  /* 128 MiB */
#define KERNEL_HEAP_SIZE        (16 * 1024 * 1024)   /* 16 MiB heap for userland bootstrap */

/* ============================================================
 *   Test Thread Functions
 * ============================================================ */

/* Global FIPC channel for testing */
static struct fut_fipc_channel *g_test_channel = NULL;

static void fut_test_watchdog_thread(void *arg) {
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
 */
static void test_vfs_operations(void) {
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
static void test_futurafs_operations(void) {
    fut_printf("[FUTURAFS-TEST] Starting FuturaFS test...\n");

    /* Test 1: Create 512 KB ramdisk for FuturaFS (reduced due to mapping limits) */
    fut_printf("[FUTURAFS-TEST] Test 1: Creating 512 KB ramdisk for FuturaFS\n");

    struct fut_blockdev *ramdisk = fut_ramdisk_create_bytes("futurafs0", 512 * 1024u, 4096);
    if (!ramdisk) {
        fut_printf("[FUTURAFS-TEST] ✗ Failed to create ramdisk\n");
        fut_test_fail(FUTURAFS_TEST_ERR_RAMDISK);
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

    ret = fut_vfs_mount("futurafs0", "/mnt", "futurafs", 0, NULL);
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
static void fipc_sender_thread(void *arg) {
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
static void fipc_receiver_thread(void *arg) {
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
    int fb_stage = -1;
    int fb_exec = -1;

#if defined(__x86_64__)
    uintptr_t min_phys = KERNEL_VIRTUAL_BASE + 0x100000ULL;
#endif

    /* ========================================
     *   Step 1: Initialize Memory Subsystem
     * ======================================== */

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
    fut_mmap_reset();
    if (mem_base_phys > 0) {
        fut_mmap_add(0, mem_base_phys, 2);
    }
    fut_mmap_add(mem_base_phys, TOTAL_MEMORY_SIZE, 1);

    fut_pmm_init(TOTAL_MEMORY_SIZE, mem_base_phys);

    fut_printf("[INIT] PMM initialized: %llu pages total, %llu pages free\n",
               fut_pmm_total_pages(), fut_pmm_free_pages());

    /* Initialize kernel heap */
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

    fut_heap_init(heap_start, heap_end);

    fut_printf("[INIT] Heap initialized: 0x%llx - 0x%llx (%llu MiB)\n",
               heap_start, heap_end, KERNEL_HEAP_SIZE / (1024 * 1024));

    fut_printf("[INIT] Initializing timer subsystem...\n");
    fut_timer_subsystem_init();

    fut_boot_banner();

    bool fb_enabled = boot_flag_enabled("fb", true);
    bool fb_available = fb_enabled && fb_is_available();
    if (fb_available) {
        fb_boot_splash();
        fb_char_init();
    } else {
        fb_enabled = false;
    }

    fut_echo_selftest();
    if (fb_enabled) {
        fut_fb_smoke();
    }

    bool input_enabled = boot_flag_enabled("input", true);
    if (input_enabled) {
        int input_rc = fut_input_hw_init(true, true);
        if (input_rc != 0) {
            fut_printf("[INPUT] init failed: %d\n", input_rc);
            input_enabled = false;
        } else {
            fut_input_smoke();
        }
    }

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
    int vfs_ret = fut_vfs_mount(NULL, "/", "ramfs", 0, NULL);
    if (vfs_ret < 0) {
        fut_printf("[ERROR] Failed to mount root filesystem (error %d)\n", vfs_ret);
        fut_platform_panic("Failed to mount root filesystem");
    }

    fut_console_init();
    fut_printf("[INIT] Console device registered at /dev/console\n");

    int fd0 = fut_vfs_open("/dev/console", O_RDWR, 0);
    int fd1 = fut_vfs_open("/dev/console", O_RDWR, 0);
    int fd2 = fut_vfs_open("/dev/console", O_RDWR, 0);
    if (fd0 < 0 || fd1 < 0 || fd2 < 0) {
        fut_printf("[WARN] Failed to seed /dev/console descriptors (fd0=%d fd1=%d fd2=%d)\n",
                   fd0, fd1, fd2);
    }

    fut_printf("[INIT] Root filesystem mounted (ramfs at /)\n");

    bool perf_enabled = fut_boot_arg_flag("perf");
    uint16_t planned_tests = 3u + (perf_enabled ? 1u : 0u);
    if (fb_enabled) {
        planned_tests += 1u;
    }
    if (input_enabled) {
        planned_tests += 1u;
    }
    fut_test_plan(planned_tests);

    /* Test VFS operations */
    test_vfs_operations();

    /* ========================================
     *   Step 4: Initialize Block Device Subsystem
     * ======================================== */

    fut_printf("[INIT] Initializing block device subsystem...\n");
    fut_blockdev_init();
    fut_printf("[INIT] Block device subsystem initialized\n");
    fut_blk_core_init();
    fut_printf("[INIT] Async block core initialized\n");
    fut_status_t vblk_rc = virtio_blk_init(0);
    if (vblk_rc != 0) {
        fut_printf("[virtio-blk] init failed: %d\n", vblk_rc);
    }
    ahci_init();

    fut_printf("[INIT] Initializing network subsystem...\n");
    fut_net_init();
    fut_status_t vnet_rc = virtio_net_init();
    if (vnet_rc != 0) {
        fut_printf("[virtio-net] init failed: %d\n", vnet_rc);
    }

    /* Test block device operations - DISABLED (heap too small for 1MB ramdisk) */
    /* test_blockdev_operations(); */

    /* Test FuturaFS operations with smaller ramdisk */
    test_futurafs_operations();

    fut_printf("[INIT] Staging fbtest user binary...\n");
    fb_stage = fut_stage_fbtest_binary();
    if (fb_stage != 0) {
        fut_printf("[WARN] Failed to stage fbtest binary (error %d)\n", fb_stage);
    } else {
        fut_printf("[INIT] fbtest binary staged at /bin/fbtest\n");
    }

    /* ========================================
     *   Step 5: Initialize Scheduler
     * ======================================== */

    fut_printf("[INIT] Initializing scheduler...\n");
    fut_sched_init();
    fut_printf("[INIT] Scheduler initialized with idle thread\n");

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

    fut_blk_async_selftest_schedule(test_task);
    fut_futfs_selftest_schedule(test_task);
    fut_net_selftest_schedule(test_task);
    if (perf_enabled) {
        fut_perf_selftest_schedule(test_task);
    }

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

    fut_printf("[INIT] Creating FIPC test threads...\n");

    /* Create sender thread */
    fut_thread_t *sender_thread = fut_thread_create(
        test_task,
        fipc_sender_thread,
        NULL,                   /* No argument needed */
        16 * 1024,              /* 16 KB stack */
        128                     /* Normal priority */
    );

    if (!sender_thread) {
        fut_printf("[ERROR] Failed to create sender thread!\n");
        fut_platform_panic("Failed to create sender thread");
    }

    fut_printf("[INIT] FIPC sender thread created (TID %llu)\n", sender_thread->tid);

    /* Create receiver thread */
    fut_thread_t *receiver_thread = fut_thread_create(
        test_task,
        fipc_receiver_thread,
        NULL,                   /* No argument needed */
        16 * 1024,              /* 16 KB stack */
        128                     /* Normal priority */
    );

    if (!receiver_thread) {
        fut_printf("[ERROR] Failed to create receiver thread!\n");
        fut_platform_panic("Failed to create receiver thread");
    }

    fut_printf("[INIT] FIPC receiver thread created (TID %llu)\n", receiver_thread->tid);

    /* ========================================
     *   Step 8: Start Scheduling
     * ======================================== */

    fut_printf("\n");
    fut_printf("=======================================================\n");
    fut_printf("   Kernel initialization complete!\n");
    fut_printf("   Starting scheduler...\n");
    fut_printf("=======================================================\n\n");

    /* Enable interrupts and start scheduling */
    /* This should never return - scheduler takes over */
    fut_schedule();

    /* Should never reach here */
    fut_printf("[PANIC] Scheduler returned unexpectedly!\n");
    fut_platform_panic("Scheduler returned to kernel_main");
}
