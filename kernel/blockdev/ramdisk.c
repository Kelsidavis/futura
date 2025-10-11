/* ramdisk.c - RAM-Based Block Device Driver
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Virtual block device backed by RAM.
 * Useful for testing filesystems and as a fast temporary storage.
 */

#include <kernel/fut_blockdev.h>
#include <kernel/fut_memory.h>
#include <stddef.h>

/* ============================================================
 *   Ramdisk Private Data
 * ============================================================ */

struct ramdisk_data {
    uint8_t *storage;     /* Backing storage buffer */
    size_t size;          /* Total size in bytes */
};

/* ============================================================
 *   Ramdisk Operations
 * ============================================================ */

static int ramdisk_read(struct fut_blockdev *dev, uint64_t block_num, uint64_t num_blocks, void *buffer) {
    if (!dev || !buffer) {
        return BLOCKDEV_EINVAL;
    }

    struct ramdisk_data *data = (struct ramdisk_data *)dev->private_data;
    if (!data || !data->storage) {
        return BLOCKDEV_EIO;
    }

    /* Calculate byte offset and size */
    uint64_t offset = block_num * dev->block_size;
    size_t size = num_blocks * dev->block_size;

    /* Bounds check */
    if (offset + size > data->size) {
        return BLOCKDEV_EINVAL;
    }

    /* Copy data from ramdisk to buffer */
    uint8_t *src = data->storage + offset;
    uint8_t *dst = (uint8_t *)buffer;

    for (size_t i = 0; i < size; i++) {
        dst[i] = src[i];
    }

    return 0;
}

static int ramdisk_write(struct fut_blockdev *dev, uint64_t block_num, uint64_t num_blocks, const void *buffer) {
    if (!dev || !buffer) {
        return BLOCKDEV_EINVAL;
    }

    struct ramdisk_data *data = (struct ramdisk_data *)dev->private_data;
    if (!data || !data->storage) {
        return BLOCKDEV_EIO;
    }

    /* Calculate byte offset and size */
    uint64_t offset = block_num * dev->block_size;
    size_t size = num_blocks * dev->block_size;

    /* Bounds check */
    if (offset + size > data->size) {
        return BLOCKDEV_EINVAL;
    }

    /* Copy data from buffer to ramdisk */
    uint8_t *dst = data->storage + offset;
    const uint8_t *src = (const uint8_t *)buffer;

    for (size_t i = 0; i < size; i++) {
        dst[i] = src[i];
    }

    return 0;
}

static int ramdisk_flush(struct fut_blockdev *dev) {
    (void)dev;
    /* Nothing to flush for ramdisk */
    return 0;
}

static const struct fut_blockdev_ops ramdisk_ops = {
    .read = ramdisk_read,
    .write = ramdisk_write,
    .flush = ramdisk_flush,
    .get_info = NULL
};

/* ============================================================
 *   Ramdisk Creation
 * ============================================================ */

/**
 * Create a ramdisk block device.
 *
 * @param name       Device name (e.g., "ramdisk0")
 * @param size_mb    Size in megabytes
 * @param block_size Block size in bytes (512 or 4096)
 * @return Block device on success, NULL on failure
 */
struct fut_blockdev *fut_ramdisk_create(const char *name, uint32_t size_mb, uint32_t block_size) {
    /* Validate parameters */
    if (!name || size_mb == 0) {
        return NULL;
    }

    if (block_size != 512 && block_size != 4096) {
        return NULL;  /* Only support standard block sizes */
    }

    /* Allocate ramdisk data structure */
    struct ramdisk_data *data = fut_malloc(sizeof(struct ramdisk_data));
    if (!data) {
        return NULL;
    }

    /* Calculate size in bytes */
    size_t size_bytes = (size_t)size_mb * 1024 * 1024;

    /* Allocate storage buffer */
    uint8_t *storage = fut_malloc(size_bytes);
    if (!storage) {
        fut_free(data);
        return NULL;
    }

    /* Zero initialize storage */
    for (size_t i = 0; i < size_bytes; i++) {
        storage[i] = 0;
    }

    /* Initialize ramdisk data */
    data->storage = storage;
    data->size = size_bytes;

    /* Allocate block device structure */
    struct fut_blockdev *dev = fut_malloc(sizeof(struct fut_blockdev));
    if (!dev) {
        fut_free(storage);
        fut_free(data);
        return NULL;
    }

    /* Copy device name */
    size_t i = 0;
    while (i < 31 && name[i]) {
        dev->name[i] = name[i];
        i++;
    }
    dev->name[i] = '\0';

    /* Initialize block device */
    dev->type = BLOCKDEV_RAMDISK;
    dev->num_blocks = size_bytes / block_size;
    dev->block_size = block_size;
    dev->capacity = size_bytes;
    dev->read_only = false;
    dev->flags = BLOCKDEV_FLAG_VIRTUAL;
    dev->ops = &ramdisk_ops;
    dev->private_data = data;
    dev->reads = 0;
    dev->writes = 0;
    dev->errors = 0;
    dev->next = NULL;

    return dev;
}

/**
 * Destroy a ramdisk block device.
 *
 * @param dev Ramdisk device to destroy
 */
void fut_ramdisk_destroy(struct fut_blockdev *dev) {
    if (!dev || dev->type != BLOCKDEV_RAMDISK) {
        return;
    }

    struct ramdisk_data *data = (struct ramdisk_data *)dev->private_data;
    if (data) {
        if (data->storage) {
            fut_free(data->storage);
        }
        fut_free(data);
    }

    fut_free(dev);
}
