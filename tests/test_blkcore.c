// SPDX-License-Identifier: MPL-2.0
/*
 * test_blkcore.c - Asynchronous block device self-test
 *
 * Mirrors the in-kernel blkcore self-test but kept under tests/ so the
 * build system can wire it into the kernel image for boot-time coverage.
 */

#include <futura/blkdev.h>

#include <kernel/errno.h>
#include <kernel/fut_memory.h>
#include <kernel/fut_task.h>
#include <kernel/fut_thread.h>

#include <stddef.h>
#include <stdint.h>
#include <string.h>

extern void fut_printf(const char *fmt, ...);

#ifndef ETIMEDOUT
#define ETIMEDOUT 110
#endif

#ifndef ENOTSUP
#define ENOTSUP 95
#endif

#define TEST_BLOCKS      32u
#define TEST_BLOCK_SIZE  512u

#define CONTAINER_OF(ptr, type, member) \
    ((type *)((char *)(ptr) - offsetof(type, member)))

typedef struct test_backend_ctx {
    uint8_t *storage;
    size_t storage_len;
} test_backend_ctx_t;

typedef struct test_io {
    fut_bio_t bio;
    volatile bool done;
    int status;
    size_t bytes;
} test_io_t;

static uint8_t g_test_storage[TEST_BLOCKS * TEST_BLOCK_SIZE];
static test_backend_ctx_t g_test_ctx = {
    .storage = g_test_storage,
    .storage_len = sizeof(g_test_storage)
};

static int test_read(void *ctx, uint64_t lba, size_t nsectors, void *buf) {
    test_backend_ctx_t *backend = (test_backend_ctx_t *)ctx;
    size_t offset = lba * TEST_BLOCK_SIZE;
    size_t bytes = nsectors * TEST_BLOCK_SIZE;
    if (offset + bytes > backend->storage_len) {
        return -EINVAL;
    }
    memcpy(buf, backend->storage + offset, bytes);
    return 0;
}

static int test_write(void *ctx, uint64_t lba, size_t nsectors, const void *buf) {
    test_backend_ctx_t *backend = (test_backend_ctx_t *)ctx;
    size_t offset = lba * TEST_BLOCK_SIZE;
    size_t bytes = nsectors * TEST_BLOCK_SIZE;
    if (offset + bytes > backend->storage_len) {
        return -EINVAL;
    }
    memcpy(backend->storage + offset, buf, bytes);
    return 0;
}

static int test_flush(void *ctx) {
    (void)ctx;
    return 0;
}

static const fut_blk_backend_t g_test_backend = {
    .read = test_read,
    .write = test_write,
    .flush = test_flush
};

static fut_blkdev_t g_test_device = {
    .name = "blk:test0",
    .block_size = TEST_BLOCK_SIZE,
    .block_count = TEST_BLOCKS,
    .allowed_rights = FUT_BLK_READ | FUT_BLK_WRITE | FUT_BLK_ADMIN,
    .backend = &g_test_backend,
    .backend_ctx = &g_test_ctx
};

static void test_io_complete(fut_bio_t *bio, int status, size_t bytes) {
    test_io_t *req = CONTAINER_OF(bio, test_io_t, bio);
    req->status = status;
    req->bytes = bytes;
    req->done = true;
}

static void test_io_prepare(test_io_t *io, uint64_t lba, size_t nsectors, void *buf, bool write) {
    memset(io, 0, sizeof(*io));
    io->bio.lba = lba;
    io->bio.nsectors = nsectors;
    io->bio.buf = buf;
    io->bio.write = write;
    io->bio.on_complete = test_io_complete;
    io->done = false;
}

static bool test_io_wait(test_io_t *io, uint32_t retries) {
    for (uint32_t i = 0; i < retries; ++i) {
        if (io->done) {
            return true;
        }
        fut_thread_sleep(1);
    }
    return io->done;
}

static int submit_and_wait(fut_handle_t handle,
                           test_io_t *io,
                           uint32_t retries,
                           size_t expected_bytes) {
    int rc = fut_blk_submit(handle, &io->bio);
    if (rc != 0) {
        return rc;
    }
    if (!test_io_wait(io, retries)) {
        return -ETIMEDOUT;
    }
    if (expected_bytes && io->bytes != expected_bytes) {
        return -EIO;
    }
    return io->status;
}

static bool run_hw_roundtrip_test(const char *name) {
    fut_handle_t handle = FUT_INVALID_HANDLE;
    int rc = fut_blk_acquire(name, FUT_BLK_READ | FUT_BLK_WRITE | FUT_BLK_ADMIN, &handle);
    if (rc != 0) {
        fut_printf("[BLK] virtio test %s open failed: %d\n", name, rc);
        return false;
    }

    const size_t sectors = 4;
    const size_t bytes = sectors * TEST_BLOCK_SIZE;
    uint8_t *orig = fut_malloc(bytes);
    uint8_t *write_buf = fut_malloc(bytes);
    uint8_t *read_buf = fut_malloc(bytes);
    bool write_ok = false;
    bool read_ok = false;
    int flush_rc = -ENOTSUP;

    if (!orig || !write_buf || !read_buf) {
        fut_printf("[BLK] virtio test %s allocation failure\n", name);
        goto cleanup_fail;
    }

    for (size_t i = 0; i < bytes; ++i) {
        write_buf[i] = (uint8_t)((i * 37u) & 0xFFu);
    }

    test_io_t read_orig;
    test_io_prepare(&read_orig, 16, sectors, orig, false);
    rc = submit_and_wait(handle, &read_orig, 256, bytes);
    if (rc != 0) {
        fut_printf("[BLK] virtio test %s read original failed: %d\n", name, rc);
        goto cleanup_fail;
    }

    test_io_t write_req;
    test_io_prepare(&write_req, 16, sectors, write_buf, true);
    rc = submit_and_wait(handle, &write_req, 256, bytes);
    if (rc != 0) {
        fut_printf("[BLK] virtio test %s write failed: %d\n", name, rc);
        goto cleanup_restore_fail;
    }
    write_ok = true;

    flush_rc = fut_blk_flush(handle);

    test_io_t read_back;
    test_io_prepare(&read_back, 16, sectors, read_buf, false);
    rc = submit_and_wait(handle, &read_back, 256, bytes);
    if (rc != 0) {
        fut_printf("[BLK] virtio test %s readback failed: %d\n", name, rc);
        goto cleanup_restore_fail;
    }

    if (memcmp(read_buf, write_buf, bytes) == 0) {
        read_ok = true;
    }

cleanup_restore_fail:
    if (write_ok) {
        test_io_t restore_req;
        test_io_prepare(&restore_req, 16, sectors, orig, true);
        (void)submit_and_wait(handle, &restore_req, 256, bytes);
        if (flush_rc == 0) {
            (void)fut_blk_flush(handle);
        }
    }

cleanup_fail:
    if (flush_rc != 0 && flush_rc != -ENOTSUP) {
        flush_rc = -EIO;
    }

    fut_printf("[BLK] virtio %s write=%s read=%s flush=%s\n",
               name,
               write_ok ? "ok" : "fail",
               read_ok ? "ok" : "fail",
               (flush_rc == 0) ? "ok" : (flush_rc == -ENOTSUP ? "skip" : "fail"));

    if (orig) {
        fut_free(orig);
    }
    if (write_buf) {
        fut_free(write_buf);
    }
    if (read_buf) {
        fut_free(read_buf);
    }

    fut_blk_close(handle);
    return write_ok && read_ok && (flush_rc == 0 || flush_rc == -ENOTSUP);
}

static void fut_blk_async_selftest_thread(void *arg) {
    (void)arg;

    fut_blkdev_t *dev = &g_test_device;

    memset(g_test_storage, 0, sizeof(g_test_storage));

    int rc = fut_blk_register(dev);

    if (rc != 0 && rc != -EEXIST) {
        fut_printf("[BLK] selftest register failed: %d\n", rc);
        fut_thread_exit();
    }

    fut_handle_t rw_handle = FUT_INVALID_HANDLE;
    rc = fut_blk_acquire("blk:test0", FUT_BLK_READ | FUT_BLK_WRITE | FUT_BLK_ADMIN, &rw_handle);
    if (rc != 0) {
        fut_printf("[BLK] selftest open rw failed: %d\n", rc);
        fut_thread_exit();
    }

    uint8_t write_buf[TEST_BLOCK_SIZE * 2];
    for (size_t i = 0; i < sizeof(write_buf); ++i) {
        write_buf[i] = (uint8_t)(i & 0xFFu);
    }

    test_io_t write_req;
    test_io_prepare(&write_req, 0, 2, write_buf, true);
    rc = fut_blk_submit(rw_handle, &write_req.bio);
    bool write_done = (rc == 0) && test_io_wait(&write_req, 128);
    bool write_ok = write_done && (write_req.status == 0) && (write_req.bytes == sizeof(write_buf));

    uint8_t read_buf[TEST_BLOCK_SIZE * 2];
    memset(read_buf, 0, sizeof(read_buf));

    test_io_t read_req;
    test_io_prepare(&read_req, 0, 2, read_buf, false);
    rc = fut_blk_submit(rw_handle, &read_req.bio);
    bool read_done = (rc == 0) && test_io_wait(&read_req, 128);
    bool read_ok = read_done && (read_req.status == 0) &&
                   (memcmp(read_buf, write_buf, sizeof(read_buf)) == 0);

    int flush_rc = fut_blk_flush(rw_handle);
    bool flush_ok = (flush_rc == 0);

    fut_handle_t ro_handle = FUT_INVALID_HANDLE;
    rc = fut_blk_acquire("blk:test0", FUT_BLK_READ, &ro_handle);
    bool ro_open_ok = (rc == 0);

    bool rights_enforced = false;
    test_io_t deny_req;
    if (ro_open_ok) {
        test_io_prepare(&deny_req, 4, 1, write_buf, true);
        rc = fut_blk_submit(ro_handle, &deny_req.bio);
        rights_enforced = (rc == -EPERM);
    }

    if (ro_open_ok) {
        fut_blk_close(ro_handle);
    }
    fut_blk_close(rw_handle);

    fut_blk_stats_t stats = {0};
    if (dev) {
        fut_blk_get_stats(dev, &stats);
    }

    fut_printf("[BLK] selftest queued=%llu inflight=%llu completed=%llu errors=%llu "
               "write=%s read=%s flush=%s rights=%s\n",
               (unsigned long long)stats.queued,
               (unsigned long long)stats.inflight,
               (unsigned long long)stats.completed,
               (unsigned long long)stats.errors,
               write_ok ? "ok" : "fail",
               read_ok ? "ok" : "fail",
               flush_ok ? "ok" : "fail",
               rights_enforced ? "ok" : "fail");

    bool virtio_ok = run_hw_roundtrip_test("blk:vda");
    bool ahci_ok = run_hw_roundtrip_test("blk:sata0");

    bool flush_optional_ok = (flush_rc == 0) || (flush_rc == -ENOTSUP);
    bool self_ok = write_ok && read_ok && flush_optional_ok && rights_enforced;
    if (self_ok && virtio_ok && ahci_ok) {
        fut_printf("blkcore: all tests passed\n");
    } else {
        fut_printf("blkcore: failures detected (self=%s virtio=%s ahci=%s)\n",
                   self_ok ? "ok" : "fail",
                   virtio_ok ? "ok" : "fail",
                   ahci_ok ? "ok" : "fail");
    }

    fut_thread_exit();
}

void fut_blk_async_selftest_schedule(fut_task_t *task) {
    if (!task) {
        return;
    }
    fut_thread_t *thread = fut_thread_create(
        task,
        fut_blk_async_selftest_thread,
        NULL,
        12 * 1024,
        140
    );
    if (!thread) {
        fut_printf("[BLK] failed to schedule selftest thread\n");
    }
}
