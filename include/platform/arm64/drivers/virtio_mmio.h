/* virtio_mmio.h - VirtIO MMIO Transport Layer for ARM64
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Public API for VirtIO MMIO transport layer.
 */

#ifndef __FUTURA_ARM64_VIRTIO_MMIO_H__
#define __FUTURA_ARM64_VIRTIO_MMIO_H__

#include <stdint.h>
#include <stdbool.h>

/* Forward declaration */
typedef struct virtio_mmio_device_s virtio_mmio_device_t;

/* VirtIO Device Types */
#define VIRTIO_DEV_NET      1
#define VIRTIO_DEV_BLOCK    2
#define VIRTIO_DEV_CONSOLE  3
#define VIRTIO_DEV_RNG      4
#define VIRTIO_DEV_BALLOON  5
#define VIRTIO_DEV_SCSI     8
#define VIRTIO_DEV_9P       9
#define VIRTIO_DEV_GPU      16
#define VIRTIO_DEV_INPUT    18

/* ============================================================
 *   Public API
 * ============================================================ */

/**
 * Initialize VirtIO MMIO subsystem.
 * @param dtb_ptr: Device tree blob pointer
 */
void virtio_mmio_init(uint64_t dtb_ptr);

/**
 * Find a virtio device by type.
 * @param device_type: VirtIO device type (VIRTIO_DEV_*)
 * @return: Device index, or -1 if not found
 */
int virtio_mmio_find_device(uint32_t device_type);

/**
 * Claim a virtio device for use.
 * @param device_idx: Device index from virtio_mmio_find_device()
 * @return: Device handle, or NULL on error
 */
virtio_mmio_device_t *virtio_mmio_get_device(int device_idx);

/**
 * Read 32-bit value from device configuration space.
 * @param dev: Device handle
 * @param offset: Byte offset into configuration space
 * @return: Configuration value
 */
uint32_t virtio_mmio_read_config32(virtio_mmio_device_t *dev, uint32_t offset);

/**
 * Read 64-bit value from device configuration space.
 * @param dev: Device handle
 * @param offset: Byte offset into configuration space
 * @return: Configuration value
 */
uint64_t virtio_mmio_read_config64(virtio_mmio_device_t *dev, uint32_t offset);

/**
 * Initialize a VirtIO device with standard handshake.
 * @param dev: Device handle
 * @param features: Driver feature bits to negotiate
 * @param queue_size: Virtqueue size (must be power of 2)
 * @return: 0 on success, -1 on error
 */
int virtio_mmio_setup_device(virtio_mmio_device_t *dev, uint32_t features, uint32_t queue_size);

/**
 * Notify device of new available buffers.
 * @param dev: Device handle
 * @param queue_idx: Queue index (usually 0)
 */
void virtio_mmio_notify(virtio_mmio_device_t *dev, uint32_t queue_idx);

/**
 * Check if there are used buffers to process.
 * @param dev: Device handle
 * @return: true if used buffers available
 */
bool virtio_mmio_has_used_buffers(virtio_mmio_device_t *dev);

#endif /* __FUTURA_ARM64_VIRTIO_MMIO_H__ */
