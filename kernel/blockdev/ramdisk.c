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
#include <string.h>

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

    /* Copy data from ramdisk to buffer - use memcpy for efficiency */
    memcpy(buffer, data->storage + offset, size);

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

    /* Copy data from buffer to ramdisk - use memcpy for efficiency */
    memcpy(data->storage + offset, buffer, size);

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
static struct fut_blockdev *ramdisk_create_common(const char *name,
                                                  size_t size_bytes,
                                                  uint32_t block_size) {
    /* Allocate ramdisk data structure */
    struct ramdisk_data *data = fut_malloc(sizeof(struct ramdisk_data));
    if (!data) {
        return NULL;
    }
    data->storage = NULL;
    data->size = 0;

    /* Allocate storage buffer */
    uint8_t *storage = fut_malloc(size_bytes);
    if (!storage) {
        fut_free(data);
        return NULL;
    }

    /* Zero initialize storage - use memset for efficiency */
    memset(storage, 0, size_bytes);

    data->storage = storage;
    data->size = size_bytes;

    /* Allocate block device structure */
    struct fut_blockdev *dev = fut_malloc(sizeof(struct fut_blockdev));
    if (!dev) {
        fut_free(storage);
        fut_free(data);
        return NULL;
    }

    /* Clear structure to avoid stale data - use memset for efficiency */
    memset(dev, 0, sizeof(struct fut_blockdev));

    /* Copy device name */
    size_t i = 0;
    while (i < 31 && name[i]) {
        dev->name[i] = name[i];
        i++;
    }
    dev->name[i] = '\0';

    /* Initialize block device metadata */
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

struct fut_blockdev *fut_ramdisk_create_bytes(const char *name, size_t size_bytes, uint32_t block_size) {
    if (!name || size_bytes == 0) {
        return NULL;
    }

    if (block_size != 512 && block_size != 4096) {
        return NULL;
    }

    /* Round size up to whole blocks */
    size_t blocks = (size_bytes + block_size - 1u) / block_size;
    if (blocks == 0) {
        return NULL;
    }

    size_t aligned_size = blocks * (size_t)block_size;
    return ramdisk_create_common(name, aligned_size, block_size);
}

struct fut_blockdev *fut_ramdisk_create(const char *name, uint32_t size_mb, uint32_t block_size) {
    if (!name) {
        return NULL;
    }

    if (block_size != 512 && block_size != 4096) {
        return NULL;
    }

    if (size_mb == 0) {
        /* Preserve legacy behavior: default to 128 KiB ramdisk */
        return fut_ramdisk_create_bytes(name, 128 * 1024u, block_size);
    }

    size_t size_bytes = (size_t)size_mb * 1024u * 1024u;
    return fut_ramdisk_create_bytes(name, size_bytes, block_size);
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
