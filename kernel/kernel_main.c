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
#include <kernel/kprintf.h>
#include <kernel/errno.h>
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
#include <platform/platform.h>

/* Platform-specific memory mapping */
#include <platform/platform.h>
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
#include <kernel/tests/test_main.h>
/* Architecture-specific headers (non-paging; pmap via platform.h) */
#if defined(__x86_64__)
#include <platform/x86_64/interrupt/lapic.h>
#elif defined(__aarch64__)
#include <platform/arm64/interrupt/irq.h>
#include <platform/arm64/process.h>
#endif

/* Test and selftest function declarations provided by kernel/tests/test_main.h */

#if ENABLE_WAYLAND
#define WAYLAND_TEST_SENTINEL_CODE 0xD0u
#define WAYLAND_TEST_STAGE_FAIL    0xD1u
#define WAYLAND_TEST_EXEC_FAIL     0xD2u
#define WAYLAND_TEST_CLIENT_FAIL   0xD3u
#endif

#if ENABLE_WAYLAND
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

/**
 * Helper: Acquire block device capability handle for filesystem mounting.
 *
 * This function acquires a capability handle to a block device with appropriate
 * rights (READ for read-only mounts, READ+WRITE for read-write mounts).
 * The handle enforces capability-based security at the block layer.
 *
 * @param device_name Block device name (e.g., "blk:vda", "ramdisk0")
 * @param read_only   True for read-only access, false for read-write
 * @param handle_out  Pointer to store acquired handle (FUT_INVALID_HANDLE on failure)
 * @return 0 on success, negative error code on failure
 */
static int acquire_block_device_handle(const char *device_name, bool read_only, fut_handle_t *handle_out) {

    if (!device_name || !handle_out) {
        return -EINVAL;
    }

    /* Determine required rights based on mount mode */
    uint32_t rights = FUT_BLK_READ;
    if (!read_only) {
        rights |= FUT_BLK_WRITE;
    }

    /* Acquire capability handle to block device */
    fut_status_t status = fut_blk_acquire(device_name, rights, handle_out);
    if (status < 0) {
        fut_printf("[BLKCAP] Failed to acquire handle for '%s' with rights 0x%x: %d\n",
                   device_name, rights, status);
        *handle_out = FUT_INVALID_HANDLE;
        return status;
    }

    fut_printf("[BLKCAP] Acquired capability handle %llu for device '%s' (rights: %s)\n",
               (unsigned long long)*handle_out, device_name,
               read_only ? "READ" : "READ|WRITE");
    return 0;
}
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
                        ssize_t bytes_read = file_vnode->ops->read(file_vnode, read_buf, sizeof(read_buf) - 1, 0);
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

    /* Test 2: Register ramdisk with legacy blockdev subsystem */
    fut_printf("[FUTURAFS-TEST] Test 2: Registering ramdisk (legacy blockdev)\n");
    int ret = fut_blockdev_register(ramdisk);
    if (ret < 0) {
        fut_printf("[FUTURAFS-TEST] ✗ Failed to register with blockdev: error %d\n", ret);
        fut_test_fail(FUTURAFS_TEST_ERR_REGISTER);
        return;
    }
    fut_printf("[FUTURAFS-TEST] ✓ Ramdisk registered with legacy blockdev\n");

    /* Test 2b: Register ramdisk with blkcore for capability-based I/O */
    fut_printf("[FUTURAFS-TEST] Test 2b: Registering ramdisk with blkcore\n");

    /* Create blkdev descriptor for blkcore */
    fut_blkdev_t *blkdev = fut_malloc(sizeof(fut_blkdev_t));
    if (!blkdev) {
        fut_printf("[FUTURAFS-TEST] ✗ Failed to allocate blkdev descriptor\n");
        fut_test_fail(FUTURAFS_TEST_ERR_REGISTER);
        return;
    }

    /* Populate blkdev descriptor */
    blkdev->name = ramdisk->name;
    blkdev->block_size = ramdisk->block_size;
    blkdev->block_count = ramdisk->num_blocks;
    blkdev->allowed_rights = FUT_BLK_READ | FUT_BLK_WRITE | FUT_BLK_ADMIN;
    blkdev->core = NULL;  /* Will be initialized by fut_blk_register */

    /* Set up backend that bridges to legacy blockdev operations */
    static fut_blk_backend_t ramdisk_backend;
    ramdisk_backend.read = (fut_status_t (*)(void*, uint64_t, size_t, void*))ramdisk->ops->read;
    ramdisk_backend.write = (fut_status_t (*)(void*, uint64_t, size_t, const void*))ramdisk->ops->write;
    ramdisk_backend.flush = (fut_status_t (*)(void*))ramdisk->ops->flush;

    blkdev->backend = &ramdisk_backend;
    blkdev->backend_ctx = ramdisk;

    /* Register with blkcore */
    fut_status_t blk_status = fut_blk_register(blkdev);
    if (blk_status < 0) {
        fut_printf("[FUTURAFS-TEST] ✗ Failed to register with blkcore: %d\n", blk_status);
        fut_printf("[FUTURAFS-TEST] ℹ Capability-based I/O will not be available\n");
        fut_free(blkdev);
        /* Don't fail the test - continue with legacy I/O */
    } else {
        fut_printf("[FUTURAFS-TEST] ✓ Ramdisk registered with blkcore (capability-based I/O enabled)\n");
    }

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

    /* Test 5: Mount FuturaFS with capability-based block I/O */
    fut_printf("[FUTURAFS-TEST] Test 5: Mounting FuturaFS at /mnt (capability-aware)\n");

    /* Create mount point (if mkdir is available via VFS) */
    extern struct fut_vnode *fut_vfs_get_root(void);
    struct fut_vnode *root_vnode = fut_vfs_get_root();
    if (root_vnode && root_vnode->ops && root_vnode->ops->mkdir) {
        root_vnode->ops->mkdir(root_vnode, "mnt", 0755);
    }

    /* Acquire capability handle for block device (read-write access) */
    fut_handle_t blk_handle = FUT_INVALID_HANDLE;
    ret = acquire_block_device_handle("futurafs0", false, &blk_handle);
    if (ret < 0) {
        fut_printf("[FUTURAFS-TEST] ✗ Failed to acquire block device handle: error %d\n", ret);
        fut_printf("[FUTURAFS-TEST] ℹ Falling back to legacy I/O path\n");
        blk_handle = FUT_INVALID_HANDLE;
    }

    /* Mount FuturaFS with capability handle (or FUT_INVALID_HANDLE for legacy fallback) */
    ret = fut_vfs_mount("futurafs0", "/mnt", "futurafs", 0, NULL, blk_handle);
    if (ret < 0) {
        fut_printf("[FUTURAFS-TEST] ✗ Mount failed: error %d\n", ret);
        if (blk_handle != FUT_INVALID_HANDLE) {
            fut_blk_close(blk_handle);
        }
        fut_test_fail(FUTURAFS_TEST_ERR_MOUNT);
        return;
    }
    fut_printf("[FUTURAFS-TEST] ✓ FuturaFS mounted at /mnt (using %s I/O)\n",
               blk_handle != FUT_INVALID_HANDLE ? "capability-based" : "legacy");

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
    int thread_id = (int)(uintptr_t)arg;

    for (int i = 0; i < 3; i++) {
        fut_printf("[THREAD-%d] Iteration %d\n", thread_id, i);
        fut_thread_yield();  // Yield to other threads
    }

    fut_printf("[THREAD-%d] Exiting\n", thread_id);
    fut_thread_exit();
}

__attribute__((unused)) static void demo_thread_b(void *arg) {
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

    /* serial_puts provided by platform/platform.h */
    serial_puts("[SIMPLE-TEST] Thread running!\n");
    (void)arg;
    serial_puts("[SIMPLE-TEST] About to exit\n");
    fut_thread_exit();
}

__attribute__((unused)) static void fipc_sender_thread(void *arg) {
    /* serial_puts provided by platform/platform.h */
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

/* Test thread functions — run all test suites sequentially in a single
 * thread to prevent concurrent access to shared kernel state. */
extern void fut_multiprocess_test_thread(void *arg);
extern void fut_dup2_test_thread(void *arg);
extern void fut_pipe_test_thread(void *arg);
extern void fut_signal_test_thread(void *arg);
extern void fut_cap_test_thread(void *arg);
extern void fut_epoll_test_thread(void *arg);
extern void fut_splice_test_thread(void *arg);
extern void fut_clock_sched_test_thread(void *arg);
extern void fut_vfs_test_thread(void *arg);
extern void fut_poll_test_thread(void *arg);
extern void fut_misc_test_thread(void *arg);

/* Set by boot thread after all initialization is complete.
 * Test thread waits for this before starting to avoid races with init. */
static volatile int g_init_complete = 0;

static void selftest_sequential_runner(void *arg) {
    (void)arg;

    /* Wait for boot thread to finish all initialization.
     * Without this, the test thread can run while ramfs directories
     * are still being created, seeing half-initialized entries.
     * Use acquire semantics to ensure all writes by the boot thread
     * (VFS, ramfs, device setup) are visible once we see g_init_complete=1. */
    while (!__atomic_load_n(&g_init_complete, __ATOMIC_ACQUIRE)) {
        extern void fut_schedule(void);
        fut_schedule();
    }

    fut_multiprocess_test_thread(NULL);
    fut_dup2_test_thread(NULL);
    fut_pipe_test_thread(NULL);
    fut_signal_test_thread(NULL);
    fut_cap_test_thread(NULL);
    fut_epoll_test_thread(NULL);
    fut_splice_test_thread(NULL);
    fut_clock_sched_test_thread(NULL);
    fut_vfs_test_thread(NULL);
    fut_poll_test_thread(NULL);
    fut_misc_test_thread(NULL);
}

/* Bridge functions: legacy blockdev read/write → blkcore read/write */
static int blkcore_bridge_read(struct fut_blockdev *dev, uint64_t lba, uint64_t count, void *buf) {
    extern int fut_blk_read(void *ctx, uint64_t sector, uint32_t cnt, void *buffer);
    return fut_blk_read(dev->private_data, lba, (uint32_t)count, buf);
}
static int blkcore_bridge_write(struct fut_blockdev *dev, uint64_t lba, uint64_t count, const void *buf) {
    extern int fut_blk_write(void *ctx, uint64_t sector, uint32_t cnt, const void *buffer);
    return fut_blk_write(dev->private_data, lba, (uint32_t)count, buf);
}

void fut_kernel_main(void) {

    /* Core Wayland variables (production) */
#if ENABLE_WAYLAND
    int wayland_stage = -1;
    /* Note: wayland_exec removed - compositor is now launched by init */
#endif

    /* Detect interactive/headful boot mode from kernel cmdline */
#ifdef WAYLAND_INTERACTIVE_MODE
    bool wayland_interactive_boot = true;
#else
    bool wayland_interactive_boot = fut_boot_arg_flag("WAYLAND_INTERACTIVE");
#endif
    __attribute__((unused)) bool wayland_autoclose = boot_flag_enabled("wayland-autoclose", false);

#if ENABLE_WAYLAND_TEST_CLIENTS
    /* Test client variables (optional) */
    int wayland_client_stage = -1;
    int wayland_client_exec = -1;
#else
    __attribute__((unused)) int wayland_client_stage = -1;
    __attribute__((unused)) int wayland_client_exec = -1;
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

    /* Provide a bootstrap task/thread context so VFS/syscalls work before scheduler */
    fut_thread_init_bootstrap();
#else
    fut_serial_puts("[INIT] Initializing per-CPU data for CPU 0...\n");
    fut_percpu_init(0, 0);

    /* Set TPIDR_EL1 to point to per-CPU data (ARM64 equivalent of GS_BASE on x86_64) */
    fut_percpu_set(&fut_percpu_data[0]);

    /* Mark per-CPU data as safe to access (enables fut_thread_current()) */
    fut_thread_mark_percpu_safe();
    fut_serial_puts("[INIT] Per-CPU data initialized for CPU 0\n");

    /* Provide a bootstrap task/thread context so VFS/syscalls work before scheduler */
    fut_thread_init_bootstrap();
#endif

    fut_boot_banner();

#if defined(__aarch64__)
    bool fb_enabled = true;  /* Display always on for ARM64 */
#else
    /* Enable framebuffer by default when Wayland demo is enabled, since the
     * compositor needs /dev/fb0 for hardware-accelerated rendering.
     * Can be disabled via boot flag fb=0 if needed. */
    #if ENABLE_WAYLAND
    bool fb_enabled = boot_flag_enabled("fb", true);  /* Enabled by default for Wayland */
    #else
    bool fb_enabled = boot_flag_enabled("fb", false);  /* Disabled when no GUI */
    #endif
#endif
    if (wayland_interactive_boot) {
        fb_enabled = true;
    }

    bool fb_available = fb_enabled && fb_is_available();
    fut_printf("[INIT] fb_enabled=%d fb_available=%d\n",
               fb_enabled ? 1 : 0, fb_available ? 1 : 0);

    if (fb_enabled) {
        bool should_init_fb = wayland_interactive_boot || fb_available;
        if (should_init_fb) {
            /* Initialize graphics device and show boot splash */
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
    }

    /* ========================================
     *   Post-Subsystem Initialization
     * ======================================== */

    /* smoke tests disabled */

    /* Diagnostic check for interrupt-driven UART on ARM64 */
#ifdef __aarch64__
    fut_serial_enable_irq_mode();
#endif

    /* Initialize input drivers - REQUIRED for Wayland compositor */
#ifdef ENABLE_WAYLAND
    /* input init */
    __attribute__((unused)) bool input_enabled = true;  /* Required for interactive mode */
    int input_rc = fut_input_hw_init(true, true);
    if (input_rc != 0) {
        fut_printf("[INPUT] init failed: %d - Wayland may not work!\n", input_rc);
        input_enabled = false;
    } else {
        fut_printf("[INPUT] Keyboard and mouse drivers initialized\n");
    }
#else
    /* For non-interactive builds, allow boot flag to control input */
    __attribute__((unused)) bool input_enabled = boot_flag_enabled("input", false);
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

    /* Register /dev/null and /dev/zero pseudo-devices */
    extern void dev_null_init(void);
    dev_null_init();

    /* Register PTY (pseudo-terminal) subsystem: /dev/ptmx + /dev/pts/ */
    extern void pty_init(void);
    pty_init();

    /* Create /dev/stdin, /dev/stdout, /dev/stderr as device aliases.
     * Many programs and shell scripts expect these to exist.
     * On Linux these are symlinks to /proc/self/fd/N. Since we don't have
     * procfs, register them as chrdev aliases to the console device. */
    {
        extern int devfs_create_chr(const char *path, unsigned major, unsigned minor);
        devfs_create_chr("/dev/stdin",  4, 0);   /* Same as /dev/console */
        devfs_create_chr("/dev/stdout", 4, 0);
        devfs_create_chr("/dev/stderr", 4, 0);
        devfs_create_chr("/dev/tty",    4, 0);   /* Controlling terminal */
    }

    fut_printf("[INIT] Root filesystem mounted (ramfs at /)\n");

    /* Create /tmp directory for temporary files */
    int tmp_ret = fut_vfs_mkdir("/tmp", 0777);
    if (tmp_ret < 0 && tmp_ret != -EEXIST) {
        fut_printf("[WARN] Failed to create /tmp directory (error %d)\n", tmp_ret);
    }

    /* Mount ramfs at /tmp to make it writable for Wayland sockets and other temporary files */
    /* Mount /tmp */
    int tmp_mount_ret = fut_vfs_mount(NULL, "/tmp", "ramfs", 0, NULL, FUT_INVALID_HANDLE);
    (void)tmp_mount_ret;
    if (tmp_mount_ret == 0) {
        fut_printf("[INIT] ✓ Mounted writable ramfs at /tmp\n");
    } else {
        fut_printf("[WARN] ✗ Failed to mount ramfs at /tmp (error %d)\n", tmp_mount_ret);
    }

    /* Create and mount /dev/shm for POSIX shared memory (shm_open/shm_unlink use this path) */
    {
        int shm_mkdir_ret = fut_vfs_mkdir("/dev/shm", 01777);
        if (shm_mkdir_ret < 0 && shm_mkdir_ret != -EEXIST)
            fut_printf("[WARN] Failed to create /dev/shm directory (error %d)\n", shm_mkdir_ret);
        int shm_mount_ret = fut_vfs_mount(NULL, "/dev/shm", "ramfs", 0, NULL, FUT_INVALID_HANDLE);
        if (shm_mount_ret == 0)
            fut_printf("[INIT] ✓ Mounted ramfs at /dev/shm (POSIX shm_open support)\n");
        else
            fut_printf("[WARN] ✗ Failed to mount ramfs at /dev/shm (error %d)\n", shm_mount_ret);
    }

    /* Initialize and mount procfs at /proc */
    {
        extern void fut_procfs_init(void);
        fut_procfs_init();
        int proc_mkdir_ret = fut_vfs_mkdir("/proc", 0555);
        if (proc_mkdir_ret < 0 && proc_mkdir_ret != -EEXIST)
            fut_printf("[WARN] Failed to create /proc directory (error %d)\n", proc_mkdir_ret);
        int proc_mount_ret = fut_vfs_mount(NULL, "/proc", "proc", 0, NULL, FUT_INVALID_HANDLE);
        if (proc_mount_ret == 0)
            fut_printf("[INIT] ✓ Mounted procfs at /proc\n");
        else
            fut_printf("[WARN] ✗ Failed to mount procfs at /proc (error %d)\n", proc_mount_ret);
    }

    /* Initialize and mount sysfs at /sys */
    {
        extern void fut_sysfs_init(void);
        fut_sysfs_init();
        int sys_mkdir_ret = fut_vfs_mkdir("/sys", 0555);
        if (sys_mkdir_ret < 0 && sys_mkdir_ret != -EEXIST)
            fut_printf("[WARN] Failed to create /sys directory (error %d)\n", sys_mkdir_ret);
        int sys_mount_ret = fut_vfs_mount(NULL, "/sys", "sysfs", 0, NULL, FUT_INVALID_HANDLE);
        if (sys_mount_ret == 0)
            fut_printf("[INIT] ✓ Mounted sysfs at /sys\n");
        else
            fut_printf("[WARN] ✗ Failed to mount sysfs at /sys (error %d)\n", sys_mount_ret);
    }

    /* Create /etc with essential config files for Linux userspace compatibility */
    {
        int etc_mkdir_ret = fut_vfs_mkdir("/etc", 0755);
        if (etc_mkdir_ret < 0 && etc_mkdir_ret != -EEXIST)
            fut_printf("[WARN] Failed to create /etc directory (error %d)\n", etc_mkdir_ret);
        int etc_mount_ret = fut_vfs_mount(NULL, "/etc", "ramfs", 0, NULL, FUT_INVALID_HANDLE);
        if (etc_mount_ret == 0)
            fut_printf("[INIT] ✓ Mounted ramfs at /etc\n");
        else
            fut_printf("[WARN] ✗ Failed to mount ramfs at /etc (error %d)\n", etc_mount_ret);

        /* Helper: write a string to a new file */
#define ETC_WRITE(path, content) do { \
    int _fd = fut_vfs_open((path), O_WRONLY | O_CREAT | O_TRUNC, 0644); \
    if (_fd >= 0) { \
        fut_vfs_write(_fd, (content), __builtin_strlen(content)); \
        fut_vfs_close(_fd); \
    } else { \
        fut_printf("[WARN] Failed to create %s (err %d)\n", (path), _fd); \
    } \
} while (0)

        ETC_WRITE("/etc/hostname",
                  "futura\n");
        ETC_WRITE("/etc/hosts",
                  "127.0.0.1\tlocalhost\n"
                  "::1\t\tlocalhost ip6-localhost ip6-loopback\n"
                  "127.0.1.1\tfutura\n");
        ETC_WRITE("/etc/resolv.conf",
                  "nameserver 127.0.0.1\n"
                  "search local\n");
        ETC_WRITE("/etc/nsswitch.conf",
                  "passwd:   files\n"
                  "group:    files\n"
                  "shadow:   files\n"
                  "hosts:    files dns\n"
                  "networks: files\n"
                  "protocols: files\n"
                  "services: files\n");
        ETC_WRITE("/etc/passwd",
                  "root:x:0:0:root:/root:/bin/shell\n"
                  "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n");
        ETC_WRITE("/etc/group",
                  "root:x:0:\n"
                  "nobody:x:65534:\n");
        ETC_WRITE("/etc/os-release",
                  "NAME=\"Futura OS\"\n"
                  "VERSION=\"0.4.0\"\n"
                  "ID=futura\n"
                  "VERSION_ID=0.4.0\n"
                  "PRETTY_NAME=\"Futura OS 0.4.0\"\n"
                  "HOME_URL=\"https://github.com/netrunner-labs/futura\"\n");
        ETC_WRITE("/etc/profile",
                  "# Futura OS system profile\n"
                  "export PATH=/bin:/sbin:/bin/user\n"
                  "export HOME=/root\n"
                  "export TERM=vt100\n"
                  "# Common aliases\n"
                  "alias ll='ls -l'\n"
                  "alias la='ls -la'\n"
                  "alias l='ls'\n"
                  "alias ..='cd ..'\n"
                  "alias ...='cd ../..'\n"
                  "alias h='history'\n"
                  "alias q='exit'\n"
                  "# Display motd\n"
                  "cat /etc/motd\n");
        ETC_WRITE("/etc/motd",
                  "\n"
                  "  Welcome to Futura OS 0.4.0 (aarch64)\n"
                  "\n"
                  "  * 72 built-in commands — type 'help'\n"
                  "  * Glob expansion: ls *.txt, cat /etc/*\n"
                  "  * Command substitution: VAR=$(cmd), echo $(date)\n"
                  "  * Scripting: for/while/if, source, pipes, redirects\n"
                  "  * FuturaFS at /mnt — try: echo hello > /mnt/file\n"
                  "\n");
#undef ETC_WRITE

        fut_printf("[INIT] ✓ Created /etc config files\n");
    }

    /* Create /run (and /run/lock, /run/user/0) for programs that expect a writable
     * runtime directory; mount ramfs so writes from userspace work */
    {
        int run_mkdir_ret = fut_vfs_mkdir("/run", 0755);
        if (run_mkdir_ret < 0 && run_mkdir_ret != -EEXIST)
            fut_printf("[WARN] Failed to create /run (error %d)\n", run_mkdir_ret);
        int run_mount_ret = fut_vfs_mount(NULL, "/run", "ramfs", 0, NULL, FUT_INVALID_HANDLE);
        if (run_mount_ret == 0) {
            fut_printf("[INIT] ✓ Mounted ramfs at /run\n");
            fut_vfs_mkdir("/run/lock",    01777);
            fut_vfs_mkdir("/run/user",    0755);
            fut_vfs_mkdir("/run/user/0",  0700);
        } else {
            fut_printf("[WARN] ✗ Failed to mount ramfs at /run (error %d)\n", run_mount_ret);
        }
    }

    /* Create standard directory hierarchy */
    fut_vfs_mkdir("/root", 0700);
    fut_vfs_mkdir("/home", 0755);
    fut_vfs_mkdir("/var", 0755);
    fut_vfs_mkdir("/var/log", 0755);
    fut_vfs_mkdir("/var/tmp", 01777);
    fut_vfs_mkdir("/opt", 0755);

    bool run_async_selftests = boot_flag_enabled("async-tests", false);

    /* VFS and exec double tests are DISABLED (too much memory), don't count them */
    uint16_t planned_tests = 0u;
    /* FB and input tests are only for Wayland demo mode */
#if ENABLE_WAYLAND
    if (fb_enabled) {
        planned_tests += 1u;
    }
    if (input_enabled) {
        planned_tests += 1u;
    }
    planned_tests += 1u; /* Wayland demo sentinel */
#endif
    if (run_async_selftests) {
        planned_tests += 5u; /* multiprocess: fork isolation, FD inheritance, per-task isolation, cloexec, shared offset */
        planned_tests += 5u; /* dup2: basic dup, invalid FDs, stdout redirect, same FD, dup3 */
        planned_tests += 6u; /* pipe: creation, read/write, EPIPE, EOF, pipe2(O_NONBLOCK), pipe2(O_CLOEXEC) */
        planned_tests += 5u; /* signal: handler installation, pending, ignored, multiple, delivery */
        planned_tests += 6u; /* capability: open, read, write, rights, invalid, close */
        planned_tests += 12u; /* epoll: create, close, ctl add/del, quota, EBADF, EEXIST, EPOLLIN, timeout=0, MOD, ONESHOT, EPOLLET, EPOLLHUP */
        planned_tests += 8u; /* splice: statfs, sysinfo, pipe→file, file→pipe, EINVAL, vmsplice, fallocate, tee */
        planned_tests += 17u; /* clock_sched: getres, sched_param, sched_policy, itimer, rusage, times, getpriority, setpriority, getpriority(-who), setpriority(-who), unshare(0), unshare(invalid), rr_get_interval, clock_gettime, posix_timer_sigev_value, posix_timer_si_timer, itimer_virtual */
        planned_tests += 22u; /* vfs: O_TRUNC, O_APPEND, relpath, dir_mtime, readlink, hardlink, mount, renameat2, inotify, inotify_rename, inotify_attrib, inotify_close, inotify_access, inotify_modify, inotify_ftruncate, inotify_utimensat, inotify_truncate, inotify_delete, umount expire, dotdot, eisdir, chdir_dotdot */
        planned_tests += 17u; /* poll: file ready, eventfd not-ready, eventfd ready, POLLNVAL, select file, select pipe, pselect6 pipe, pselect6 sigmask restore, timeout-only sleep, timerfd readiness, signalfd readiness, pipe EOF, select pipe EOF, select timerfd wakeup, poll negative fd, POLLRDNORM, select timeout update */
        planned_tests += 1744u; /* misc(1744): ..., splice_o_append (1592-1593), sendfile_o_append (1594-1595), openat_o_directory (1596-1597), dup2_newfd_range (1598-1599), wait_flags (1600-1603), setgroups_cap (1604), setreuid_saved (1605-1613), cred_dumpable (1614-1619), setpgid_exec (1620), cap_uid_transitions (1621-1624), sigpending_mask (1625-1626), priority_neg_who (1627-1628), faccessat_eaccess (1629-1630), wnowait_stopped_cont (1631-1632), mremap_vma_boundary (1633), futex_bitset_zero (1634-1635), epoll_maxevents_cap_hup (1636-1638), mprotect_gap (1639), signalfd_fields (1640), rusage_children_nvcsw (1641), brk_rlimit_as (1642), rusage_minflt (1643), wait4_rusage (1644), vmpeak_tracking (1645), oom_score_adj (1646), procfs_io_bytes (1647), fork_cwd (1648), fork_affinity (1649), fork_cmdline (1650), fork_sigaltstack (1651), async_sigio (1652), async_f_setsig (1653), async_socket (1654), async_pipe_write_end (1655), async_socket_recv (1656), f_setown_ex (1657), f_setown_ex_pgrp (1658), rseq_tracking (1659), rseq_cpu_id (1660), fgetfl_mask (1661), fgetfl_status (1662), fioasync_set (1663), fioasync_clear (1664), pty_open_ptmx (1665), pty_tiocgptn (1666), pty_open_slave (1667), pty_master_to_slave (1668), pty_slave_to_master (1669), pty_winsize (1670), pty_fionread (1671), pty_master_close_eof (1672), pty_tcsets_independence (1673), pty_tcgets_per_pair (1674), pty_winsize_independence (1675), pty_tcsets_master_slave (1676), pty_poll_writable (1677), pty_poll_readable (1678), pty_select_readable (1679), pty_epoll_readable (1680), pty_readlink_master (1681), pty_readlink_slave (1682), pty_tty_nr (1683), pty_tty_nr_persist (1684), auxv_hwcap_nonzero (1685), auxv_clktck (1686), auxv_pagesz (1687), auxv_hwcap_fpu_sse2 (1688), pts_dir_empty (1689), pts_dir_has_slave (1690), pts_dir_removed (1691), pts_dir_two_slaves (1692), pty_refcount_double_open (1693), pty_refcount_first_close (1694), pty_refcount_last_close_eof (1695), pty_refcount_dir_persist (1696), pie_at_entry (1697), pie_at_phdr (1698), pie_entry_range (1699), pie_pagesz (1700), pty_sigwinch_master (1701), pty_sigwinch_slave (1702), pty_winsize_readback (1703), pty_sigwinch_sigign (1704), auxv_at_base (1705), auxv_at_flags (1706), status_ngid (1707), auxv_entry_count (1708), maps_stack (1709), stack_rw_p (1710), maps_heap (1711), maps_code_rxp (1712), exec_enoent (1713), exec_empty (1714), exec_bad_magic (1715), shebang_enoent (1716), chdir_getcwd_roundtrip (1717), chdir_dotdot (1718), fchdir_dirfd (1719), chdir_nested (1720), timer_abstime_past (1721), nanosleep_abstime_past (1722), nanosleep_bad_clock (1723), nanosleep_bad_nsec (1724), exec_empty_enoexec (1725), exec_bad_magic (1726), exec_handler_preserved (1727), exec_dir_error (1728), umask_file_022 (1729), umask_file_077 (1730), umask_000 (1731), umask_mkdir (1732), umask_create_file (1733), umask_openat (1734), umask_mount_point (1735), umask_return_old (1736), close_neg1 (1737), double_close (1738), read_closed (1739), dup_closed (1740), rename_write_persist (1741), rename_old_gone (1742), unlink_fd_works (1743), unlink_stat_enoent (1744) */
        // planned_tests += 1u; /* block */
        // planned_tests += 1u; /* futfs */
        // planned_tests += 1u; /* net */
        /* perf tests disabled — not included in sequential runner */
    }
    (void)planned_tests;
    fut_test_plan(planned_tests);

    /* DISABLED: VFS and exec double tests consume too much physical memory */
    /*
    test_vfs_operations();
    fut_exec_double_smoke();
    */
    /* tests disabled */

    /* ========================================
     *   Step 4: Initialize Block Device Subsystem
     * ======================================== */

#ifdef __aarch64__
    /* On ARM64, initialize VirtIO-MMIO transport layer */
    extern void virtio_mmio_init(uint64_t dtb_ptr);
    virtio_mmio_init(fut_platform_get_dtb());
#endif

    fut_printf("[INIT] Initializing block device subsystem...\n");
    fut_blockdev_init();
    fut_blk_core_init();
    fut_status_t vblk_rc = virtio_blk_init(0);
    if (vblk_rc == 0) {
        fut_printf("[INIT] VirtIO block device initialized\n");
    } else if (vblk_rc != -19 && vblk_rc != -22) {
        /* -19 = ENODEV (no device), -22 = EINVAL (empty/no-capacity disk) */
        fut_printf("[virtio-blk] init: %d\n", vblk_rc);
    }
#ifdef __x86_64__
    /* ahci_init(); */  /* AHCI not yet implemented */
#endif
    fut_printf("[INIT] Block device subsystem initialized\n");

    /* ========================================
     *   Initialize FuturaFS
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

        Acquire capability handle for block device (read-write)
        fut_handle_t blk_handle = FUT_INVALID_HANDLE;
        int acq_rc = acquire_block_device_handle("blk:vda", false, &blk_handle);
        if (acq_rc < 0) {
            fut_printf("[INIT] Warning: Failed to acquire block device handle, using legacy I/O\n");
            blk_handle = FUT_INVALID_HANDLE;
        }

        int mount_rc = fut_vfs_mount("blk:vda", "/mnt", "futurafs", 0, NULL, blk_handle);
        if (mount_rc == 0) {
            fut_printf("[INIT] Mounted FuturaFS from blk:vda at /mnt (using %s I/O)\n",
                       blk_handle != FUT_INVALID_HANDLE ? "capability-based" : "legacy");
        } else {
            fut_printf("[INIT] Failed to mount FuturaFS: error %d\n", mount_rc);
            if (blk_handle != FUT_INVALID_HANDLE) {
                fut_blk_close(blk_handle);
            }
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

#if ENABLE_WAYLAND
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

    extern int fut_stage_futura_shell_binary(void);
    int shell_stage = fut_stage_futura_shell_binary();
    if (shell_stage != 0) {
        fut_printf("[WARN] Failed to stage futura-shell binary (error %d)\n", shell_stage);
    } else {
        fut_printf("[INIT] futura-shell staged at /bin/futura-shell\n");
    }

    /* Stage CLI shell binary for use by wl-term */
    extern int fut_stage_shell_binary(void);
    int cli_shell_stage = fut_stage_shell_binary();
    if (cli_shell_stage != 0) {
        fut_printf("[WARN] Failed to stage CLI shell binary (error %d)\n", cli_shell_stage);
    } else {
        fut_printf("[INIT] CLI shell staged at /bin/shell\n");
    }
#endif

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
    /* Enable interrupts and start scheduler. Timer IRQs will now cause context switches. */
    fut_printf("[INIT] Enabling interrupts...\n");
    fut_enable_interrupts();  /* Platform-neutral interrupt enable */

    /* Start the scheduler to enable preemptive context switches */
    fut_printf("[INIT] Starting scheduler...\n");
    fut_sched_start();  /* Enable scheduling on timer IRQs */

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

    /* Memory management tests — default OFF, enable via boot flag on x86_64 */
#ifdef __x86_64__
    if (boot_flag_enabled("mm-tests", false)) {
        fut_mm_tests_run();
    }
#endif

    /* ========================================
     *   Mount FuturaFS on VirtIO Block Device
     * ======================================== */
    if (!run_async_selftests) {
        /* Skip block device I/O during automated tests — virtio-blk interrupt
         * delivery is unreliable in the CI test harness and causes timeouts. */
        /* Try legacy blockdev first, then blkcore */
        extern struct fut_blockdev *fut_blockdev_find(const char *name);
        struct fut_blockdev *vda = fut_blockdev_find("blk:vda");
        if (!vda) {
            /* Rust VirtIO driver registers with blkcore, not legacy.
             * Create a legacy wrapper so FuturaFS can use it. */
            extern void *fut_blk_find_device(const char *name);
            extern int fut_blk_read(void *ctx, uint64_t sector, uint32_t count, void *buf);
            void *blkcore_dev = fut_blk_find_device("blk:vda");
            if (blkcore_dev) {
                fut_printf("[INIT] Found blk:vda via blkcore, creating legacy wrapper\n");
                static struct fut_blockdev legacy_vda;
                static struct fut_blockdev_ops legacy_ops;
                legacy_ops.read = blkcore_bridge_read;
                legacy_ops.write = blkcore_bridge_write;
                legacy_vda.name[0] = 'b'; legacy_vda.name[1] = 'l';
                legacy_vda.name[2] = 'k'; legacy_vda.name[3] = ':';
                legacy_vda.name[4] = 'v'; legacy_vda.name[5] = 'd';
                legacy_vda.name[6] = 'a'; legacy_vda.name[7] = '\0';
                legacy_vda.block_size = 512;
                legacy_vda.num_blocks = 131072;  /* 64MB / 512 */
                legacy_vda.ops = &legacy_ops;
                legacy_vda.private_data = blkcore_dev;
                vda = &legacy_vda;
            }
        }
        /* C-side block test removed — it resets the device and destroys
         * the Rust driver's queue state. Let the Rust driver handle I/O. */

        if (vda) {
            fut_printf("[INIT] Found block device blk:vda, attempting FuturaFS mount...\n");

            /* Format if not already formatted */
            int format_rc = fut_futurafs_format(vda, "FuturaOS", 4096);
            if (format_rc == 0) {
                fut_printf("[INIT] blk:vda formatted with FuturaFS\n");
            } else {
                fut_printf("[INIT] FuturaFS format returned %d (may already be formatted)\n", format_rc);
            }

            /* Create /mnt mount point */
            extern struct fut_vnode *fut_vfs_get_root(void);
            struct fut_vnode *root_vnode = fut_vfs_get_root();
            if (root_vnode && root_vnode->ops && root_vnode->ops->mkdir) {
                root_vnode->ops->mkdir(root_vnode, "mnt", 0755);
            }

            /* Mount */
            int mount_rc = fut_vfs_mount("blk:vda", "/mnt", "futurafs", 0, NULL, FUT_INVALID_HANDLE);
            if (mount_rc == 0) {
                fut_printf("[INIT] ✓ FuturaFS mounted at /mnt (virtio-blk)\n");
            } else {
                /* VirtIO block failed — fall back to ramdisk */
                fut_printf("[INIT] VirtIO block I/O failed, using ramdisk fallback\n");
                goto try_ramdisk;
            }
        } else {
try_ramdisk: (void)0;
            /* Create a 4MB ramdisk for FuturaFS */
            extern struct fut_blockdev *fut_ramdisk_create_bytes(const char *, size_t, uint32_t);
            extern int fut_blockdev_register(struct fut_blockdev *);
            struct fut_blockdev *ramdisk = fut_ramdisk_create_bytes("ramdisk0", 1024 * 1024, 4096);
            if (ramdisk) {
                fut_blockdev_register(ramdisk);
                int fmt_rc = fut_futurafs_format(ramdisk, "FuturaOS", 4096);
                if (fmt_rc == 0) {
                    extern struct fut_vnode *fut_vfs_get_root(void);
                    struct fut_vnode *root = fut_vfs_get_root();
                    if (root && root->ops && root->ops->mkdir)
                        root->ops->mkdir(root, "mnt", 0755);
                    int mnt_rc = fut_vfs_mount("ramdisk0", "/mnt", "futurafs", 0, NULL, FUT_INVALID_HANDLE);
                    if (mnt_rc == 0) {
                        fut_printf("[INIT] ✓ FuturaFS mounted at /mnt (4MB ramdisk)\n");
                    } else {
                        fut_printf("[INIT] Ramdisk FuturaFS mount failed: %d\n", mnt_rc);
                    }
                } else {
                    fut_printf("[INIT] Ramdisk format failed: %d\n", fmt_rc);
                }
            }
        }
    } else {
        fut_printf("[INIT] Skipping FuturaFS mount (test mode)\n");
    }

#if ENABLE_WAYLAND
    /* ========================================
     *   Launch Init Process (Wayland Desktop)
     * ======================================== */
    extern int fut_stage_init_binary(void);

    fut_printf("[INIT] Staging init process...\n");

    /* Stage init */
    int init_stage = fut_stage_init_binary();
    if (init_stage != 0) {
        fut_printf("[WARN] Failed to stage init (error %d)\n", init_stage);
    }
#endif

#if ENABLE_FB_DIAGNOSTICS
    extern int fut_stage_fbtest_binary(void);
    /* Stage fbtest binary */
    int fbtest_stage = fut_stage_fbtest_binary();
    if (fbtest_stage != 0) {
        fut_printf("[WARN] Failed to stage fbtest binary (error %d)\n", fbtest_stage);
    }
#endif

    /* Start console input thread - reads from serial and feeds line discipline.
     * Now uses scheduler yield instead of busy-spinning. */
    fut_printf("[INIT] Starting console input thread...\n");
    fut_console_start_input_thread();

    /* ========================================
     *   Wayland Compositor Launch (DISABLED)
     * ======================================== */
    /* NOTE: Compositor is now launched by init via fork+exec.
     * This avoids duplicate compositor instances fighting for resources.
     * The binary is still staged at /sbin/futura-wayland for init to exec. */
#if 0 && ENABLE_WAYLAND
    /* DISABLED: init handles compositor launch now */
    if (wayland_stage == 0) {
        fut_printf("[INIT] Launching Wayland compositor...\n");
        char name[] = "futura-wayland";
        char *args[] = { name, NULL };
        /* Environment with LD_PRELOAD and runtime parameters */
        char ld_preload[] = "LD_PRELOAD=/lib/libopen_wrapper.so";
        char xdg_runtime[] = "XDG_RUNTIME_DIR=/tmp";
        char wayland_display_env[] = "WAYLAND_DISPLAY=wayland-0";
        char wayland_multi_env[] = "WAYLAND_MULTI=1";
        /* Default to single-buffered mode; allocator cannot recycle double 3 MiB slabs yet */
        char wayland_backbuffer_env[] = "WAYLAND_BACKBUFFER=0";
        char wayland_deco_env[] = "WAYLAND_DECO=1";
        char wayland_shadow_env[] = "WAYLAND_SHADOW=1";
        char wayland_resize_env[] = "WAYLAND_RESIZE=1";
        char wayland_throttle_env[] = "WAYLAND_THROTTLE=1";
        char wayland_interactive_env[] = "WAYLAND_INTERACTIVE=1";
        char *envp[] = {
            ld_preload,
            xdg_runtime,
            wayland_display_env,
            wayland_multi_env,
            wayland_backbuffer_env,
            wayland_deco_env,
            wayland_shadow_env,
            wayland_resize_env,
            wayland_throttle_env,
            wayland_interactive_env,
            NULL
        };
        wayland_exec = fut_exec_elf("/sbin/futura-wayland", args, envp);
        if (wayland_exec != 0) {
            fut_printf("[WARN] Failed to launch /sbin/futura-wayland (error %d)\n", wayland_exec);
#if ENABLE_WAYLAND
            fut_test_fail(WAYLAND_TEST_EXEC_FAIL);
#endif
        } else {
            fut_printf("[INIT] exec /sbin/futura-wayland -> 0\n");
        }
    }
#endif

#if ENABLE_WAYLAND
    /* Launch init process with environment for Wayland.
     * init will fork and exec the compositor, then launch wl-term.
     * This replaces the old direct kernel compositor launch. */
    int init_exec = -1;  /* Track init launch result for wayland_ready check */
    if (init_stage == 0) {
        fut_printf("[INIT] Launching init process...\n");
        char init_name[] = "init";
        char *init_args[] = { init_name, NULL };
        /* Pass Wayland environment to init so it can launch wl-term */
        char xdg_runtime[] = "XDG_RUNTIME_DIR=/tmp";
        char wayland_display[] = "WAYLAND_DISPLAY=wayland-0";
        char *init_envp[] = { xdg_runtime, wayland_display, NULL };
        init_exec = fut_exec_elf("/sbin/init", init_args, init_envp);
        if (init_exec != 0) {
            fut_printf("[WARN] Failed to launch /sbin/init (error %d)\n", init_exec);
        } else {
            fut_printf("[INIT] Init process launched successfully\n");
        }
    }
#endif

    /* ========================================
     *   Launch Interactive Shell (DISABLED)
     * ======================================== */
    /* NOTE: Shell launch disabled - init now launches wl-term instead */
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

    /* Multi-client Wayland test clients (DISABLED)
     * NOTE: Test client launch is now handled by init, not the kernel.
     * The compositor is launched by init via fork+exec, and test clients
     * would need to be launched after the compositor is ready.
     * This direct kernel launch approach is obsolete. */
#if 0 && ENABLE_WAYLAND_TEST_CLIENTS
    /* DISABLED: Direct kernel launch of test clients no longer works.
     * Test clients should be launched by init or the compositor. */
    wayland_client_exec = 0;
    if (wayland_client_stage == 0) {
        fut_boot_delay_ms(100);

        /* Launch first client: wl-simple */
        char name1[] = "wl-simple";
        char *args1[] = { name1, NULL };
        char ld_preload[] = "LD_PRELOAD=/lib/libopen_wrapper.so";
        char xdg_runtime[] = "XDG_RUNTIME_DIR=/tmp";
        char wayland_display_env[] = "WAYLAND_DISPLAY=wayland-0";
        char *envp[] = { ld_preload, xdg_runtime, wayland_display_env, NULL };
        wayland_client_exec = fut_exec_elf("/bin/wl-simple", args1, envp);
        if (wayland_client_exec != 0) {
            fut_printf("[WARN] Failed to launch /bin/wl-simple (error %d)\n", wayland_client_exec);
            fut_test_fail(WAYLAND_TEST_CLIENT_FAIL);
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

#if ENABLE_WAYLAND
    /* Compositor is now launched by init (which forks and execs it).
     * Check init_exec instead of the old wayland_exec variable. */
    bool wayland_ready = (init_exec == 0);

    if (wayland_ready) {
        /* Allow time for compositor and clients to initialize */
        uint32_t finalize_delay_ms = 2500;
        fut_boot_delay_ms(finalize_delay_ms);

        if (wayland_autoclose) {
            /* Auto-exit for automated testing when wayland-autoclose boot flag is set */
            fut_printf("[INIT] Wayland autoclose flag set - exiting demo after bring-up\n");
#ifdef __x86_64__
            hal_outb(0xf4u, 0u);  /* x86-64 debug port exit */
#endif
            fut_test_pass();
        } else {
            /* Interactive mode: Scheduler will start and switch to processes */
            fut_printf("[INIT] ========================================\n");
            fut_printf("[INIT] Wayland Interactive Mode - Scheduler Starting\n");
            fut_printf("[INIT] ========================================\n");
        }
    } else {
        /* Init failed to launch - still start scheduler for debugging */
        fut_printf("[WARN] Init failed to launch (init_exec: %d)\n", init_exec);
        fut_printf("[WARN] Continuing to scheduler anyway\n");
    }
#endif /* ENABLE_WAYLAND */

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

    /* Create FIPC channel BEFORE starting test thread to avoid concurrent
     * heap allocation races between the boot thread and test thread.
     * The allocator is not fully thread-safe, so all init-time allocations
     * must complete before the test thread begins its work. */
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

    if (run_async_selftests) {
        /* Run all test suites sequentially in a single thread to prevent
         * concurrent access to shared kernel state (ramfs directories,
         * task signal fields, etc.) from corrupting data structures. */
        fut_thread_t *test_thread = fut_thread_create(
            test_task,
            selftest_sequential_runner,
            NULL,
            16 * 1024,  /* 16 KB stack (enough for all test suites) */
            180         /* Priority */
        );
        if (test_thread) {
            fut_printf("[INIT] Created sequential test thread (tid=%llu)\n", test_thread->tid);
        }
    }

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
    /* calling late init */
    fut_printf("=======================================================\n\n");

    /* Platform-specific late initialization (spawn init, etc.) */
    arch_late_init();

    /* ========================================
     *   Step 9: Enter Idle Loop
     * ======================================== */

    /* idle */

    /* Signal test thread that init is done — safe to access VFS now.
     * Full memory barrier ensures all preceding writes (VFS init, directory
     * creation, device setup) are visible before the flag is seen as 1. */
    __atomic_store_n(&g_init_complete, 1, __ATOMIC_SEQ_CST);

#if defined(__x86_64__)
    /* Exit the boot thread to let the idle thread take over.
     * The scheduler has already been initialized with user threads in the ready queue.
     * Timer IRQs will drive scheduling between idle and user threads. */
    /* boot thread done */
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
    /* entering idle */
    fut_enable_interrupts();

    /* Exit the boot thread to let the idle thread (tid=3, priority=0) take over.
     * The boot thread was causing livelock by staying in READY state in a yield loop.
     * Now only the idle thread and actual work threads will be scheduled. */
    /* boot thread done */
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
