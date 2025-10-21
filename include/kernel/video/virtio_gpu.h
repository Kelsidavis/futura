// SPDX-License-Identifier: MPL-2.0
#ifndef __KERNEL_VIDEO_VIRTIO_GPU_H__
#define __KERNEL_VIDEO_VIRTIO_GPU_H__

#include <stdint.h>

/* Initialize virtio-gpu device with framebuffer at given physical address */
int virtio_gpu_init(uint64_t fb_phys, uint32_t width, uint32_t height);

#endif /* __KERNEL_VIDEO_VIRTIO_GPU_H__ */
