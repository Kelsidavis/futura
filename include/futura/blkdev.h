// SPDX-License-Identifier: MPL-2.0
/*
 * blkdev.h - Asynchronous block device core interface
 *
 * Handle-gated capability model inspired by Zircon/Fuchsia. Devices register
 * backends, callers acquire handles with explicit rights, and asynchronous
 * BIOs complete via callbacks dispatched from blkcore worker threads.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <kernel/fut_object.h>

typedef int fut_status_t;

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

struct fut_blkcore_state;

typedef struct fut_blk_backend {
    fut_status_t (*read)(void *ctx, uint64_t lba, size_t nsectors, void *buf);
    fut_status_t (*write)(void *ctx, uint64_t lba, size_t nsectors, const void *buf);
    fut_status_t (*flush)(void *ctx);
} fut_blk_backend_t;

typedef struct fut_blk_stats {
    uint64_t queued;
    uint64_t inflight;
    uint64_t completed;
    uint64_t errors;
} fut_blk_stats_t;

typedef struct fut_blkdev {
    const char *name;
    uint32_t block_size;
    uint64_t block_count;
    uint32_t allowed_rights;
    const fut_blk_backend_t *backend;
    void *backend_ctx;
    struct fut_blkcore_state *core; /* Internal state (zero-initialize before register). */
} fut_blkdev_t;

/// Initialize blkcore (idempotent).
void fut_blk_core_init(void);

/// Register a block device with blkcore.
fut_status_t fut_blk_register(fut_blkdev_t *dev);

/// Acquire a handle to a block device by name with specific rights.
fut_status_t fut_blk_acquire(const char *name, uint32_t rights, fut_handle_t *out_handle);

/// Resolve a block device pointer from a capability handle.
fut_status_t fut_blk_open(fut_handle_t cap, fut_blkdev_t **out);

/// Queue an asynchronous BIO on a capability-enforced handle.
fut_status_t fut_blk_submit(fut_handle_t cap, fut_bio_t *bio);

/// Flush outstanding writes for a capability-enforced handle.
fut_status_t fut_blk_flush(fut_handle_t cap);

/// Close a capability handle to a block device.
fut_status_t fut_blk_close(fut_handle_t cap);

const char *fut_blk_name(const fut_blkdev_t *dev);
uint32_t fut_blk_block_size(const fut_blkdev_t *dev);
uint64_t fut_blk_block_count(const fut_blkdev_t *dev);
void fut_blk_get_stats(const fut_blkdev_t *dev, fut_blk_stats_t *out);
