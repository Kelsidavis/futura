#include "perf.h"

#include <futura/blkdev.h>

#include <kernel/errno.h>
#include <kernel/fut_blockdev.h>
#include <kernel/fut_memory.h>
#include <kernel/fut_ramdisk.h>
#include <kernel/fut_thread.h>

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#ifdef DEBUG_PERF
#define PERFDBG(...) fut_printf(__VA_ARGS__)
#else
#define PERFDBG(...) do { } while (0)
#endif

extern void fut_printf(const char *fmt, ...);

#define BLK_WARMUP 32u
#define BLK_ITERS  128u
#define BLK_BLOCK_BYTES 4096u

typedef struct {
    fut_bio_t bio;
    volatile bool done;
    int status;
    size_t bytes;
} fut_perf_blk_req_t;

static void fut_perf_blk_complete(fut_bio_t *bio, int status, size_t bytes) {
    fut_perf_blk_req_t *req = (fut_perf_blk_req_t *)bio;
    req->status = status;
    req->bytes = bytes;
    req->done = true;
}

static int fut_perf_blk_submit_wait(fut_handle_t handle,
                                    fut_perf_blk_req_t *req,
                                    uint64_t lba,
                                    size_t nsectors,
                                    void *buffer,
                                    bool write,
                                    size_t expected_bytes) {
    req->bio.lba = lba;
    req->bio.nsectors = nsectors;
    req->bio.buf = buffer;
    req->bio.write = write;
    req->bio.on_complete = fut_perf_blk_complete;
    req->done = false;
    req->status = 0;
    req->bytes = 0;

    int rc = fut_blk_submit(handle, &req->bio);
    if (rc != 0) {
        return rc;
    }

    while (!req->done) {
        fut_thread_yield();
    }

    if (expected_bytes && req->bytes != expected_bytes) {
        return -EIO;
    }
    return req->status;
}

static fut_blockdev_t *fut_perf_blk_device(void) {
    static fut_blockdev_t *cached = NULL;
    if (cached) {
        return cached;
    }

    fut_blockdev_t *existing = fut_blockdev_find("perf_ram0");
    if (!existing) {
        fut_blockdev_t *ram = fut_ramdisk_create_bytes("perf_ram0", 1 * 1024 * 1024u, BLK_BLOCK_BYTES);
        if (!ram) {
            return NULL;
        }
        ram->allowed_rights = FUT_BLK_READ | FUT_BLK_WRITE | FUT_BLK_ADMIN;
        if (fut_blk_register(ram) != 0) {
            fut_ramdisk_destroy(ram);
            return NULL;
        }
        existing = ram;
    }

    cached = existing;
    return cached;
}

int fut_perf_run_blk(struct fut_perf_stats *read_stats,
                     struct fut_perf_stats *write_stats) {
    if (!read_stats || !write_stats) {
        return -EINVAL;
    }

    fut_blockdev_t *dev = fut_perf_blk_device();
    if (!dev) {
        return -ENODEV;
    }

    fut_handle_t handle = FUT_INVALID_HANDLE;
    if (fut_blk_acquire(dev->name, FUT_BLK_READ | FUT_BLK_WRITE | FUT_BLK_ADMIN, &handle) != 0) {
        return -EIO;
    }

    const size_t block_size = fut_blk_block_size(dev);
    const size_t sectors = BLK_BLOCK_BYTES / block_size;
    const size_t bytes = sectors * block_size;
    const uint64_t base_lba = 8u;

    uint8_t *write_buf = (uint8_t *)fut_malloc(bytes);
    uint8_t *read_buf = (uint8_t *)fut_malloc(bytes);
    if (!write_buf || !read_buf) {
        fut_blk_close(handle);
        if (write_buf) fut_free(write_buf);
        if (read_buf) fut_free(read_buf);
        return -ENOMEM;
    }

    for (size_t i = 0; i < bytes; ++i) {
        write_buf[i] = (uint8_t)((i * 13u) & 0xFFu);
        read_buf[i] = 0u;
    }

    fut_perf_blk_req_t req;

    for (size_t i = 0; i < BLK_WARMUP; ++i) {
        if (fut_perf_blk_submit_wait(handle, &req, base_lba, sectors, write_buf, true, bytes) != 0) {
            fut_blk_close(handle);
            fut_free(write_buf);
            fut_free(read_buf);
            return -EIO;
        }
        if (fut_perf_blk_submit_wait(handle, &req, base_lba, sectors, read_buf, false, bytes) != 0) {
            fut_blk_close(handle);
            fut_free(write_buf);
            fut_free(read_buf);
            return -EIO;
        }
    }

    uint64_t *read_samples = (uint64_t *)fut_malloc(sizeof(uint64_t) * BLK_ITERS);
    uint64_t *write_samples = (uint64_t *)fut_malloc(sizeof(uint64_t) * BLK_ITERS);
    if (!read_samples || !write_samples) {
        if (read_samples) fut_free(read_samples);
        if (write_samples) fut_free(write_samples);
        fut_blk_close(handle);
        fut_free(write_buf);
        fut_free(read_buf);
        return -ENOMEM;
    }

    for (size_t i = 0; i < BLK_ITERS; ++i) {
        uint64_t start = fut_rdtsc();
        if (fut_perf_blk_submit_wait(handle, &req, base_lba + i, sectors, read_buf, false, bytes) != 0) {
            fut_free(read_samples);
            fut_free(write_samples);
            fut_blk_close(handle);
            fut_free(write_buf);
            fut_free(read_buf);
            return -EIO;
        }
        uint64_t end = fut_rdtsc();
        read_samples[i] = end - start;
    }

    for (size_t i = 0; i < BLK_ITERS; ++i) {
        uint64_t start = fut_rdtsc();
        if (fut_perf_blk_submit_wait(handle, &req, base_lba + 256u + i, sectors, write_buf, true, bytes) != 0) {
            fut_free(read_samples);
            fut_free(write_samples);
            fut_blk_close(handle);
            fut_free(write_buf);
            fut_free(read_buf);
            return -EIO;
        }
        uint64_t end = fut_rdtsc();
        write_samples[i] = end - start;
    }

    (void)fut_blk_flush(handle);

    fut_perf_sort(read_samples, BLK_ITERS);
    fut_perf_sort(write_samples, BLK_ITERS);
    fut_perf_compute_stats(read_samples, BLK_ITERS, read_stats);
    fut_perf_compute_stats(write_samples, BLK_ITERS, write_stats);

    fut_free(read_samples);
    fut_free(write_samples);
    fut_blk_close(handle);
    fut_free(write_buf);
    fut_free(read_buf);

    return 0;
}
