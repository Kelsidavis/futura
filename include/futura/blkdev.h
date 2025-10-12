// SPDX-License-Identifier: MPL-2.0
/*
 * blkdev.h - Asynchronous block device core interface
 *
 * Handle-gated capability model inspired by Zircon/Fuchsia. Devices register
 * backends, callers open handles with explicit rights, and asynchronous BIOs
 * complete via callbacks on a worker thread.
 */

#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <kernel/fut_object.h>

enum fut_blk_rights {
    FUT_BLK_READ  = 1u << 0,
    FUT_BLK_WRITE = 1u << 1,
    FUT_BLK_ADMIN = 1u << 2
};

typedef struct fut_bio {
    uint64_t lba;
    size_t nsectors;
    void *buf;
    bool write;
    void (*on_complete)(struct fut_bio *bio, int status, size_t bytes);
} fut_bio_t;

typedef struct fut_blkdev fut_blkdev_t;

typedef struct fut_blk_backend {
    int (*read)(void *ctx, uint64_t lba, size_t nsectors, void *buf);
    int (*write)(void *ctx, uint64_t lba, size_t nsectors, const void *buf);
    int (*flush)(void *ctx);
} fut_blk_backend_t;

typedef struct fut_blk_stats {
    uint64_t queued;
    uint64_t inflight;
    uint64_t completed;
    uint64_t errors;
} fut_blk_stats_t;

void fut_blk_core_init(void);

int fut_blk_register(const char *name,
                     uint32_t block_size,
                     uint64_t block_count,
                     uint32_t allowed_rights,
                     const fut_blk_backend_t *backend,
                     void *backend_ctx,
                     fut_blkdev_t **out_dev);

int fut_blk_open(const char *name, uint32_t rights, fut_handle_t *out_handle);
int fut_blk_submit(fut_handle_t handle, fut_bio_t *bio);
int fut_blk_flush(fut_handle_t handle);
int fut_blk_close(fut_handle_t handle);

const char *fut_blk_name(const fut_blkdev_t *dev);
uint32_t fut_blk_block_size(const fut_blkdev_t *dev);
uint64_t fut_blk_block_count(const fut_blkdev_t *dev);
void fut_blk_get_stats(const fut_blkdev_t *dev, fut_blk_stats_t *out);
