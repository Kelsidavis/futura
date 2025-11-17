/* virtio_gpu_mmio.h - VirtIO GPU driver for ARM64 (MMIO transport)
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Public API for VirtIO GPU MMIO driver (ARM64 platform).
 */

#ifndef __KERNEL_VIDEO_VIRTIO_GPU_MMIO_H__
#define __KERNEL_VIDEO_VIRTIO_GPU_MMIO_H__

#include <stdint.h>

/**
 * virtio_gpu_init_mmio() - Initialize VirtIO GPU device using MMIO transport
 * @out_fb_phys: Returns the framebuffer physical address
 * @width: Desired framebuffer width (0 = auto-detect)
 * @height: Desired framebuffer height (0 = auto-detect)
 *
 * Initializes the VirtIO GPU device via MMIO transport, creates a 2D resource,
 * attaches backing storage, and configures the scanout.
 *
 * Returns: 0 on success, negative error code on failure
 */
int virtio_gpu_init_mmio(uint64_t *out_fb_phys, uint32_t width, uint32_t height);

/**
 * virtio_gpu_flush_display_mmio() - Flush framebuffer changes to the display
 *
 * Transfers modified framebuffer contents to the host and flushes the display.
 * Call this after writing to the framebuffer to make changes visible.
 */
void virtio_gpu_flush_display_mmio(void);

#endif /* __KERNEL_VIDEO_VIRTIO_GPU_MMIO_H__ */
