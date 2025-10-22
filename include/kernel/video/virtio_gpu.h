// SPDX-License-Identifier: MPL-2.0
#ifndef __KERNEL_VIDEO_VIRTIO_GPU_H__
#define __KERNEL_VIDEO_VIRTIO_GPU_H__

#include <stdint.h>

/* Initialize virtio-gpu device and return the guest framebuffer physical address */
int virtio_gpu_init(uint64_t *out_fb_phys, uint32_t width, uint32_t height);

/* Flush framebuffer updates to the display */
void virtio_gpu_flush_display(void);

#endif /* __KERNEL_VIDEO_VIRTIO_GPU_H__ */
