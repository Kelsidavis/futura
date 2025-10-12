/* fut_ramdisk.h - RAM Disk Driver
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * RAM-based block device for testing and temporary storage.
 */

#pragma once

#include <kernel/fut_blockdev.h>
#include <stddef.h>

/**
 * Create a ramdisk block device.
 *
 * @param name       Device name (e.g., "ramdisk0")
 * @param size_mb    Size in megabytes
 * @param block_size Block size in bytes (512 or 4096)
 * @return Block device on success, NULL on failure
 */
struct fut_blockdev *fut_ramdisk_create(const char *name, uint32_t size_mb, uint32_t block_size);

/**
 * Create a ramdisk block device with arbitrary size in bytes.
 *
 * @param name        Device name (e.g., "ramdisk0")
 * @param size_bytes  Desired capacity in bytes
 * @param block_size  Block size in bytes (512 or 4096)
 * @return Block device on success, NULL on failure
 *
 * Size will be rounded up to the nearest block to preserve whole blocks.
 */
struct fut_blockdev *fut_ramdisk_create_bytes(const char *name, size_t size_bytes, uint32_t block_size);

/**
 * Destroy a ramdisk block device.
 *
 * @param dev Ramdisk device to destroy
 */
void fut_ramdisk_destroy(struct fut_blockdev *dev);
