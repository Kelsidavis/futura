/* fut_blockdev.h - Futura OS Block Device Abstraction
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Generic block device interface for storage devices.
 * Provides uniform access to disks, partitions, and virtual block devices.
 */

#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* Freestanding environment: define ssize_t */
#ifndef _SSIZE_T_DEFINED
#define _SSIZE_T_DEFINED
typedef long ssize_t;
#endif

/* Forward declarations */
struct fut_blockdev;
struct fut_blockdev_ops;

/* ============================================================
 *   Block Device Types
 * ============================================================ */

enum fut_blockdev_type {
    BLOCKDEV_RAMDISK = 0,    /* RAM-based virtual disk */
    BLOCKDEV_ATA,            /* ATA/SATA disk */
    BLOCKDEV_NVME,           /* NVMe SSD */
    BLOCKDEV_SCSI,           /* SCSI disk */
    BLOCKDEV_USB,            /* USB storage */
    BLOCKDEV_PARTITION       /* Disk partition */
};

/* ============================================================
 *   Block Device Structure
 * ============================================================ */

/**
 * Block device representation.
 * Represents any block-addressable storage device.
 */
struct fut_blockdev {
    char name[32];                      /* Device name (e.g., "ramdisk0", "sda1") */
    enum fut_blockdev_type type;        /* Device type */

    /* Device geometry */
    uint64_t num_blocks;                /* Total number of blocks */
    uint32_t block_size;                /* Block size in bytes (usually 512 or 4096) */
    uint64_t capacity;                  /* Total capacity in bytes */

    /* Device state */
    bool read_only;                     /* Read-only flag */
    uint32_t flags;                     /* Device flags */

    /* Operations */
    const struct fut_blockdev_ops *ops; /* Device operations */
    void *private_data;                 /* Driver-specific data */

    /* Statistics */
    uint64_t reads;                     /* Number of read operations */
    uint64_t writes;                    /* Number of write operations */
    uint64_t errors;                    /* Number of I/O errors */

    /* List linkage */
    struct fut_blockdev *next;          /* Next device in global list */
};

/* ============================================================
 *   Block Device Operations
 * ============================================================ */

/**
 * Block device operations table.
 * Implemented by each block device driver.
 */
struct fut_blockdev_ops {
    /**
     * Read blocks from device.
     *
     * @param dev        Block device
     * @param block_num  Starting block number
     * @param num_blocks Number of blocks to read
     * @param buffer     Buffer to read into (must be num_blocks * block_size)
     * @return 0 on success, negative error code on failure
     */
    int (*read)(struct fut_blockdev *dev, uint64_t block_num, uint64_t num_blocks, void *buffer);

    /**
     * Write blocks to device.
     *
     * @param dev        Block device
     * @param block_num  Starting block number
     * @param num_blocks Number of blocks to write
     * @param buffer     Buffer to write from
     * @return 0 on success, negative error code on failure
     */
    int (*write)(struct fut_blockdev *dev, uint64_t block_num, uint64_t num_blocks, const void *buffer);

    /**
     * Flush cached writes to device.
     *
     * @param dev Block device
     * @return 0 on success, negative error code on failure
     */
    int (*flush)(struct fut_blockdev *dev);

    /**
     * Get device information.
     *
     * @param dev  Block device
     * @param info Pointer to info structure to fill
     * @return 0 on success, negative error code on failure
     */
    int (*get_info)(struct fut_blockdev *dev, void *info);
};

/* Device flags */
#define BLOCKDEV_FLAG_REMOVABLE  (1 << 0)  /* Removable media */
#define BLOCKDEV_FLAG_HOTPLUG    (1 << 1)  /* Hot-pluggable */
#define BLOCKDEV_FLAG_VIRTUAL    (1 << 2)  /* Virtual device */

/* Standard block sizes */
#define BLOCKDEV_SECTOR_SIZE     512       /* Traditional sector size */
#define BLOCKDEV_4K_SIZE         4096      /* 4K sector size */

/* ============================================================
 *   Block Device API
 * ============================================================ */

/**
 * Initialize block device subsystem.
 */
void fut_blockdev_init(void);

/**
 * Register a block device.
 *
 * @param dev Block device to register
 * @return 0 on success, negative error code on failure
 */
int fut_blockdev_register(struct fut_blockdev *dev);

/**
 * Unregister a block device.
 *
 * @param dev Block device to unregister
 */
void fut_blockdev_unregister(struct fut_blockdev *dev);

/**
 * Find block device by name.
 *
 * @param name Device name (e.g., "ramdisk0")
 * @return Block device or NULL if not found
 */
struct fut_blockdev *fut_blockdev_find(const char *name);

/**
 * Read blocks from device.
 *
 * @param dev        Block device
 * @param block_num  Starting block number
 * @param num_blocks Number of blocks to read
 * @param buffer     Buffer to read into
 * @return 0 on success, negative error code on failure
 */
int fut_blockdev_read(struct fut_blockdev *dev, uint64_t block_num, uint64_t num_blocks, void *buffer);

/**
 * Write blocks to device.
 *
 * @param dev        Block device
 * @param block_num  Starting block number
 * @param num_blocks Number of blocks to write
 * @param buffer     Buffer to write from
 * @return 0 on success, negative error code on failure
 */
int fut_blockdev_write(struct fut_blockdev *dev, uint64_t block_num, uint64_t num_blocks, const void *buffer);

/**
 * Flush cached writes to device.
 *
 * @param dev Block device
 * @return 0 on success, negative error code on failure
 */
int fut_blockdev_flush(struct fut_blockdev *dev);

/**
 * Read bytes from device (convenience wrapper).
 *
 * @param dev    Block device
 * @param offset Byte offset
 * @param size   Number of bytes to read
 * @param buffer Buffer to read into
 * @return Number of bytes read, or negative error code
 */
ssize_t fut_blockdev_read_bytes(struct fut_blockdev *dev, uint64_t offset, size_t size, void *buffer);

/**
 * Write bytes to device (convenience wrapper).
 *
 * @param dev    Block device
 * @param offset Byte offset
 * @param size   Number of bytes to write
 * @param buffer Buffer to write from
 * @return Number of bytes written, or negative error code
 */
ssize_t fut_blockdev_write_bytes(struct fut_blockdev *dev, uint64_t offset, size_t size, const void *buffer);

/* Error codes */
#define BLOCKDEV_EIO     -5     /* I/O error */
#define BLOCKDEV_EINVAL  -22    /* Invalid argument */
#define BLOCKDEV_EROFS   -30    /* Read-only filesystem */
#define BLOCKDEV_ENOSPC  -28    /* No space left on device */
#define BLOCKDEV_ENODEV  -19    /* No such device */
