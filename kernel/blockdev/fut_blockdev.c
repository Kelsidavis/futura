/* fut_blockdev.c - Block Device Core Implementation
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Core block device management and I/O operations.
 */

#include <kernel/fut_blockdev.h>
#include <kernel/fut_memory.h>
#include <stddef.h>

/* ============================================================
 *   Global State
 * ============================================================ */

static struct fut_blockdev *device_list = NULL;

/* ============================================================
 *   String Utilities
 * ============================================================ */

static int str_cmp(const char *a, const char *b) {
    while (*a && *b && *a == *b) {
        a++;
        b++;
    }
    return *a - *b;
}

/* ============================================================
 *   Block Device Management
 * ============================================================ */

void fut_blockdev_init(void) {
    device_list = NULL;
}

int fut_blockdev_register(struct fut_blockdev *dev) {
    if (!dev) {
        return BLOCKDEV_EINVAL;
    }

    /* Check for duplicate name */
    struct fut_blockdev *existing = device_list;
    while (existing) {
        if (str_cmp(existing->name, dev->name) == 0) {
            return BLOCKDEV_EINVAL;  /* Device already exists */
        }
        existing = existing->next;
    }

    /* Calculate capacity if not set */
    if (dev->capacity == 0 && dev->num_blocks > 0 && dev->block_size > 0) {
        dev->capacity = dev->num_blocks * dev->block_size;
    }

    /* Initialize statistics */
    dev->reads = 0;
    dev->writes = 0;
    dev->errors = 0;

    /* Add to device list */
    dev->next = device_list;
    device_list = dev;

    return 0;
}

void fut_blockdev_unregister(struct fut_blockdev *dev) {
    if (!dev) {
        return;
    }

    /* Remove from device list */
    struct fut_blockdev **prev = &device_list;
    struct fut_blockdev *curr = device_list;

    while (curr) {
        if (curr == dev) {
            *prev = curr->next;
            return;
        }
        prev = &curr->next;
        curr = curr->next;
    }
}

struct fut_blockdev *fut_blockdev_find(const char *name) {
    if (!name) {
        return NULL;
    }

    struct fut_blockdev *dev = device_list;
    while (dev) {
        if (str_cmp(dev->name, name) == 0) {
            return dev;
        }
        dev = dev->next;
    }

    return NULL;
}

/* ============================================================
 *   Block I/O Operations
 * ============================================================ */

int fut_blockdev_read(struct fut_blockdev *dev, uint64_t block_num, uint64_t num_blocks, void *buffer) {
    if (!dev || !buffer || num_blocks == 0) {
        return BLOCKDEV_EINVAL;
    }

    /* Check bounds */
    if (block_num + num_blocks > dev->num_blocks) {
        return BLOCKDEV_EINVAL;
    }

    /* Check if device has read operation */
    if (!dev->ops || !dev->ops->read) {
        return BLOCKDEV_EIO;
    }

    /* Perform read */
    int ret = dev->ops->read(dev, block_num, num_blocks, buffer);

    /* Update statistics */
    if (ret == 0) {
        dev->reads++;
    } else {
        dev->errors++;
    }

    return ret;
}

int fut_blockdev_write(struct fut_blockdev *dev, uint64_t block_num, uint64_t num_blocks, const void *buffer) {
    if (!dev || !buffer || num_blocks == 0) {
        return BLOCKDEV_EINVAL;
    }

    /* Check read-only */
    if (dev->read_only) {
        return BLOCKDEV_EROFS;
    }

    /* Check bounds */
    if (block_num + num_blocks > dev->num_blocks) {
        return BLOCKDEV_EINVAL;
    }

    /* Check if device has write operation */
    if (!dev->ops || !dev->ops->write) {
        return BLOCKDEV_EIO;
    }

    /* Perform write */
    int ret = dev->ops->write(dev, block_num, num_blocks, buffer);

    /* Update statistics */
    if (ret == 0) {
        dev->writes++;
    } else {
        dev->errors++;
    }

    return ret;
}

int fut_blockdev_flush(struct fut_blockdev *dev) {
    if (!dev) {
        return BLOCKDEV_EINVAL;
    }

    /* Flush is optional */
    if (dev->ops && dev->ops->flush) {
        return dev->ops->flush(dev);
    }

    return 0;
}

/* ============================================================
 *   Byte-Level I/O (Convenience Wrappers)
 * ============================================================ */

ssize_t fut_blockdev_read_bytes(struct fut_blockdev *dev, uint64_t offset, size_t size, void *buffer) {
    if (!dev || !buffer || size == 0) {
        return BLOCKDEV_EINVAL;
    }

    /* Check for integer overflow: offset + size */
    if (offset > UINT64_MAX - (uint64_t)size) {
        return BLOCKDEV_EINVAL;  /* Overflow would occur */
    }

    /* Check bounds */
    uint64_t end_offset = offset + (uint64_t)size;
    if (end_offset > dev->capacity) {
        return BLOCKDEV_EINVAL;
    }

    uint32_t block_size = dev->block_size;
    uint64_t start_block = offset / block_size;
    uint64_t end_block = (offset + size + block_size - 1) / block_size;
    uint64_t num_blocks = end_block - start_block;

    /* Allocate temporary buffer for aligned I/O */
    void *temp_buffer = fut_malloc(num_blocks * block_size);
    if (!temp_buffer) {
        return -12;  /* ENOMEM */
    }

    /* Read blocks */
    int ret = fut_blockdev_read(dev, start_block, num_blocks, temp_buffer);
    if (ret < 0) {
        fut_free(temp_buffer);
        return ret;
    }

    /* Copy relevant portion to output buffer */
    uint64_t offset_in_block = offset % block_size;
    uint8_t *src = (uint8_t *)temp_buffer + offset_in_block;
    uint8_t *dst = (uint8_t *)buffer;

    for (size_t i = 0; i < size; i++) {
        dst[i] = src[i];
    }

    fut_free(temp_buffer);
    return (ssize_t)size;
}

ssize_t fut_blockdev_write_bytes(struct fut_blockdev *dev, uint64_t offset, size_t size, const void *buffer) {
    if (!dev || !buffer || size == 0) {
        return BLOCKDEV_EINVAL;
    }

    /* Check for integer overflow: offset + size */
    if (offset > UINT64_MAX - (uint64_t)size) {
        return BLOCKDEV_EINVAL;  /* Overflow would occur */
    }

    /* Check bounds */
    uint64_t end_offset = offset + (uint64_t)size;
    if (end_offset > dev->capacity) {
        return BLOCKDEV_EINVAL;
    }

    /* Check read-only */
    if (dev->read_only) {
        return BLOCKDEV_EROFS;
    }

    uint32_t block_size = dev->block_size;
    uint64_t start_block = offset / block_size;
    uint64_t end_block = (offset + size + block_size - 1) / block_size;
    uint64_t num_blocks = end_block - start_block;

    /* Canary pattern for detecting buffer overflows */
    #define CANARY_PATTERN 0xDEADBEEFDEADC0DEULL
    #define CANARY_SIZE 16

    /* Allocate temp buffer with canary guards (16 bytes before, 16 bytes after) */
    size_t buffer_size = num_blocks * block_size;
    size_t total_alloc = CANARY_SIZE + buffer_size + CANARY_SIZE;
    uint8_t *alloc_buffer = (uint8_t *)fut_malloc(total_alloc);
    if (!alloc_buffer) {
        return -12;  /* ENOMEM */
    }

    /* Set up canaries */
    uint64_t *pre_canary = (uint64_t *)alloc_buffer;
    uint8_t *temp_buffer = alloc_buffer + CANARY_SIZE;
    uint64_t *post_canary = (uint64_t *)(alloc_buffer + CANARY_SIZE + buffer_size);

    pre_canary[0] = CANARY_PATTERN;
    pre_canary[1] = CANARY_PATTERN;
    post_canary[0] = CANARY_PATTERN;
    post_canary[1] = CANARY_PATTERN;

    fut_printf("[BLOCKDEV-WRITE-BYTES] dev=%s offset=%llu size=%llu block_size=%u blocks=%llu\n",
               dev->name,
               (unsigned long long)offset,
               (unsigned long long)size,
               block_size,
               (unsigned long long)num_blocks);
    fut_printf("[BLOCKDEV-WRITE-BYTES] temp_buffer=%p buffer_size=%llu (with %d-byte canaries)\n",
               (void*)temp_buffer, (unsigned long long)buffer_size, CANARY_SIZE);

    /* Read existing blocks first (for partial block writes) */
    int ret = fut_blockdev_read(dev, start_block, num_blocks, temp_buffer);
    if (ret < 0) {
        fut_free(alloc_buffer);
        return ret;
    }

    /* Verify canaries after read */
    if (pre_canary[0] != CANARY_PATTERN || pre_canary[1] != CANARY_PATTERN) {
        fut_printf("[BLOCKDEV-WRITE-BYTES] ERROR: Pre-canary corrupted after read! %llx %llx\n",
                   (unsigned long long)pre_canary[0], (unsigned long long)pre_canary[1]);
        fut_free(alloc_buffer);
        return BLOCKDEV_EIO;
    }
    if (post_canary[0] != CANARY_PATTERN || post_canary[1] != CANARY_PATTERN) {
        fut_printf("[BLOCKDEV-WRITE-BYTES] ERROR: Post-canary corrupted after read! %llx %llx\n",
                   (unsigned long long)post_canary[0], (unsigned long long)post_canary[1]);
        fut_free(alloc_buffer);
        return BLOCKDEV_EIO;
    }

    /* Modify relevant portion with bounds checking */
    uint64_t offset_in_block = offset % block_size;
    uint8_t *dst = (uint8_t *)temp_buffer + offset_in_block;
    const uint8_t *src = (const uint8_t *)buffer;

    /* Verify write stays within bounds */
    if (offset_in_block + size > buffer_size) {
        fut_printf("[BLOCKDEV-WRITE-BYTES] ERROR: Write would overflow buffer! offset_in_block=%llu size=%llu buffer_size=%llu\n",
                   (unsigned long long)offset_in_block, (unsigned long long)size, (unsigned long long)buffer_size);
        fut_free(alloc_buffer);
        return BLOCKDEV_EINVAL;
    }

    for (size_t i = 0; i < size; i++) {
        dst[i] = src[i];
    }

    /* Verify canaries after modification */
    if (pre_canary[0] != CANARY_PATTERN || pre_canary[1] != CANARY_PATTERN) {
        fut_printf("[BLOCKDEV-WRITE-BYTES] ERROR: Pre-canary corrupted after modify! %llx %llx\n",
                   (unsigned long long)pre_canary[0], (unsigned long long)pre_canary[1]);
        fut_free(alloc_buffer);
        return BLOCKDEV_EIO;
    }
    if (post_canary[0] != CANARY_PATTERN || post_canary[1] != CANARY_PATTERN) {
        fut_printf("[BLOCKDEV-WRITE-BYTES] ERROR: Post-canary corrupted after modify! %llx %llx\n",
                   (unsigned long long)post_canary[0], (unsigned long long)post_canary[1]);
        fut_free(alloc_buffer);
        return BLOCKDEV_EIO;
    }

    /* Write blocks back */
    ret = fut_blockdev_write(dev, start_block, num_blocks, temp_buffer);
    if (ret < 0) {
        fut_free(alloc_buffer);
        return ret;
    }

    /* Final canary check */
    if (pre_canary[0] != CANARY_PATTERN || pre_canary[1] != CANARY_PATTERN) {
        fut_printf("[BLOCKDEV-WRITE-BYTES] ERROR: Pre-canary corrupted after write! %llx %llx\n",
                   (unsigned long long)pre_canary[0], (unsigned long long)pre_canary[1]);
        fut_free(alloc_buffer);
        return BLOCKDEV_EIO;
    }
    if (post_canary[0] != CANARY_PATTERN || post_canary[1] != CANARY_PATTERN) {
        fut_printf("[BLOCKDEV-WRITE-BYTES] ERROR: Post-canary corrupted after write! %llx %llx\n",
                   (unsigned long long)post_canary[0], (unsigned long long)post_canary[1]);
        fut_free(alloc_buffer);
        return BLOCKDEV_EIO;
    }

    fut_printf("[BLOCKDEV-WRITE-BYTES] write complete dev=%s (canaries intact)\n", dev->name);
    fut_free(alloc_buffer);
    return (ssize_t)size;
}
