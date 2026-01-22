/* kernel/video/virtio_gpu_mmio.c - VirtIO GPU driver for ARM64 (MMIO transport)
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements VirtIO GPU support for ARM64 using MMIO transport instead of PCI.
 * Provides framebuffer initialization and display management.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <platform/arm64/drivers/virtio_mmio.h>
#include <kernel/errno.h>

#include <kernel/kprintf.h>
extern void *fut_malloc_pages(size_t num_pages);
extern void *memset(void *, int, size_t);
extern int fut_virt_to_phys(void *ctx, const void *virt, uint64_t *phys);

/* VirtIO GPU command types */
#define VIRTIO_GPU_CMD_GET_DISPLAY_INFO      0x0100
#define VIRTIO_GPU_CMD_RESOURCE_CREATE_2D    0x0101
#define VIRTIO_GPU_CMD_RESOURCE_UNREF        0x0102
#define VIRTIO_GPU_CMD_SET_SCANOUT           0x0103
#define VIRTIO_GPU_CMD_RESOURCE_FLUSH        0x0104
#define VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D   0x0105
#define VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING 0x0106
#define VIRTIO_GPU_CMD_RESOURCE_DETACH_BACKING 0x0107

#define VIRTIO_GPU_RESP_OK_NODATA            0x1100
#define VIRTIO_GPU_RESP_OK_DISPLAY_INFO      0x1101

/* VirtIO GPU formats */
#define VIRTIO_GPU_FORMAT_B8G8R8A8_UNORM     1  /* BGRA8888 */
#define VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM     2  /* BGRX8888 */
#define VIRTIO_GPU_FORMAT_A8R8G8B8_UNORM     3  /* ARGB8888 */
#define VIRTIO_GPU_FORMAT_X8R8G8B8_UNORM     4  /* XRGB8888 */

/* VirtIO GPU command header */
struct virtio_gpu_ctrl_hdr {
    uint32_t type;
    uint32_t flags;
    uint64_t fence_id;
    uint32_t ctx_id;
    uint32_t padding;
} __attribute__((packed));

/* GET_DISPLAY_INFO command */
struct virtio_gpu_rect {
    uint32_t x;
    uint32_t y;
    uint32_t width;
    uint32_t height;
} __attribute__((packed));

struct virtio_gpu_display_one {
    struct virtio_gpu_rect r;
    uint32_t enabled;
    uint32_t flags;
} __attribute__((packed));

#define VIRTIO_GPU_MAX_SCANOUTS 16

struct virtio_gpu_resp_display_info {
    struct virtio_gpu_ctrl_hdr hdr;
    struct virtio_gpu_display_one pmodes[VIRTIO_GPU_MAX_SCANOUTS];
} __attribute__((packed));

/* RESOURCE_CREATE_2D command */
struct virtio_gpu_resource_create_2d {
    struct virtio_gpu_ctrl_hdr hdr;
    uint32_t resource_id;
    uint32_t format;
    uint32_t width;
    uint32_t height;
} __attribute__((packed));

/* RESOURCE_ATTACH_BACKING command */
struct virtio_gpu_mem_entry {
    uint64_t addr;
    uint32_t length;
    uint32_t padding;
} __attribute__((packed));

struct virtio_gpu_resource_attach_backing {
    struct virtio_gpu_ctrl_hdr hdr;
    uint32_t resource_id;
    uint32_t nr_entries;
    struct virtio_gpu_mem_entry entries[1];
} __attribute__((packed));

/* SET_SCANOUT command */
struct virtio_gpu_set_scanout {
    struct virtio_gpu_ctrl_hdr hdr;
    struct virtio_gpu_rect r;
    uint32_t scanout_id;
    uint32_t resource_id;
} __attribute__((packed));

/* TRANSFER_TO_HOST_2D command */
struct virtio_gpu_transfer_to_host_2d {
    struct virtio_gpu_ctrl_hdr hdr;
    struct virtio_gpu_rect r;
    uint64_t offset;
    uint32_t resource_id;
    uint32_t padding;
} __attribute__((packed));

/* RESOURCE_FLUSH command */
struct virtio_gpu_resource_flush {
    struct virtio_gpu_ctrl_hdr hdr;
    struct virtio_gpu_rect r;
    uint32_t resource_id;
    uint32_t padding;
} __attribute__((packed));

/* Static state */
static virtio_mmio_device_t *gpu_dev = NULL;
static uint64_t framebuffer_phys = 0;
static void *framebuffer_virt = NULL;
static uint32_t fb_width = 0;
static uint32_t fb_height = 0;
static uint32_t resource_id = 1;

/**
 * Submit a command to the VirtIO GPU device.
 * Returns 0 on success, negative errno on error.
 */
static int submit_gpu_command(const void *cmd, size_t cmd_size, void *resp, size_t resp_size) {
    if (!gpu_dev) {
        return -ENODEV;
    }

    /* Get physical addresses for command and response buffers */
    uint64_t cmd_phys, resp_phys;
    if (fut_virt_to_phys(NULL, cmd, &cmd_phys) != 0) {
        return -EFAULT;
    }
    if (fut_virt_to_phys(NULL, resp, &resp_phys) != 0) {
        return -EFAULT;
    }

    /* Setup descriptor chain:
     * desc[0] = command buffer (device-readable)
     * desc[1] = response buffer (device-writable)
     */
    gpu_dev->desc[0].addr = cmd_phys;
    gpu_dev->desc[0].len = cmd_size;
    gpu_dev->desc[0].flags = 1;  /* VIRTQ_DESC_F_NEXT */
    gpu_dev->desc[0].next = 1;

    gpu_dev->desc[1].addr = resp_phys;
    gpu_dev->desc[1].len = resp_size;
    gpu_dev->desc[1].flags = 2;  /* VIRTQ_DESC_F_WRITE */
    gpu_dev->desc[1].next = 0;

    /* Add to available ring */
    uint16_t avail_idx = gpu_dev->avail->idx;
    gpu_dev->avail->ring[avail_idx % gpu_dev->queue_size] = 0;  /* Start at desc[0] */
    __asm__ volatile("dsb sy" ::: "memory");
    gpu_dev->avail->idx = avail_idx + 1;

    /* Notify device */
    virtio_mmio_notify(gpu_dev, 0);

    /* Wait for response (simple polling) */
    int timeout = 100000;
    while (!virtio_mmio_has_used_buffers(gpu_dev) && timeout-- > 0) {
        __asm__ volatile("nop");
    }

    if (timeout <= 0) {
        fut_printf("[virtio-gpu-mmio] Command timeout\n");
        return -ETIMEDOUT;
    }

    /* Update last used index */
    gpu_dev->last_used_idx = gpu_dev->used->idx;

    return 0;
}

/**
 * Initialize VirtIO GPU device using MMIO transport.
 * Returns framebuffer physical address on success, 0 on error.
 */
int virtio_gpu_init_mmio(uint64_t *out_fb_phys, uint32_t width, uint32_t height) {
    fut_printf("[virtio-gpu-mmio] Initializing VirtIO GPU (MMIO transport)...\n");

    /* Find virtio-gpu device */
    int dev_idx = virtio_mmio_find_device(VIRTIO_DEV_GPU);
    if (dev_idx < 0) {
        fut_printf("[virtio-gpu-mmio] No virtio-gpu device found\n");
        return -ENODEV;
    }

    /* Get device handle */
    gpu_dev = virtio_mmio_get_device(dev_idx);
    if (!gpu_dev) {
        fut_printf("[virtio-gpu-mmio] Failed to get device handle\n");
        return -ENODEV;
    }

    /* Setup device with basic features (no feature bits needed for basic 2D) */
    if (virtio_mmio_setup_device(gpu_dev, 0, 64) < 0) {
        fut_printf("[virtio-gpu-mmio] Device setup failed\n");
        return -EIO;
    }

    fut_printf("[virtio-gpu-mmio] Device initialized, checking display capabilities...\n");

    /* Get display info */
    struct virtio_gpu_ctrl_hdr get_display_info_cmd = {
        .type = VIRTIO_GPU_CMD_GET_DISPLAY_INFO,
        .flags = 0,
        .fence_id = 0,
        .ctx_id = 0,
        .padding = 0
    };

    struct virtio_gpu_resp_display_info display_info = {0};

    if (submit_gpu_command(&get_display_info_cmd, sizeof(get_display_info_cmd),
                           &display_info, sizeof(display_info)) < 0) {
        fut_printf("[virtio-gpu-mmio] GET_DISPLAY_INFO command failed\n");
        return -EIO;
    }

    if (display_info.hdr.type != VIRTIO_GPU_RESP_OK_DISPLAY_INFO) {
        fut_printf("[virtio-gpu-mmio] GET_DISPLAY_INFO returned error: 0x%x\n",
                   display_info.hdr.type);
        return -EIO;
    }

    fut_printf("[virtio-gpu-mmio] Display 0: %ux%u enabled=%u\n",
               display_info.pmodes[0].r.width,
               display_info.pmodes[0].r.height,
               display_info.pmodes[0].enabled);

    /* Use requested dimensions or detected dimensions */
    fb_width = width ? width : display_info.pmodes[0].r.width;
    fb_height = height ? height : display_info.pmodes[0].r.height;

    if (fb_width == 0 || fb_height == 0) {
        fb_width = 1024;
        fb_height = 768;
        fut_printf("[virtio-gpu-mmio] Using default dimensions: %ux%u\n",
                   fb_width, fb_height);
    }

    /* Allocate framebuffer (identity mapped on ARM64) */
    size_t fb_size = fb_width * fb_height * 4;  /* 32bpp */
    size_t fb_pages = (fb_size + 4095) / 4096;

    framebuffer_virt = fut_malloc_pages(fb_pages);
    if (!framebuffer_virt) {
        fut_printf("[virtio-gpu-mmio] Failed to allocate framebuffer\n");
        return -ENOMEM;
    }

    memset(framebuffer_virt, 0, fb_size);

    if (fut_virt_to_phys(NULL, framebuffer_virt, &framebuffer_phys) != 0) {
        fut_printf("[virtio-gpu-mmio] Failed to get physical address of framebuffer\n");
        return -EIO;
    }

    fut_printf("[virtio-gpu-mmio] Framebuffer allocated: virt=%p phys=0x%llx size=%zu KB\n",
               framebuffer_virt, (unsigned long long)framebuffer_phys, fb_size / 1024);

    /* Create 2D resource */
    struct virtio_gpu_resource_create_2d create_cmd = {
        .hdr = { .type = VIRTIO_GPU_CMD_RESOURCE_CREATE_2D, .flags = 0 },
        .resource_id = resource_id,
        .format = VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM,  /* BGRX8888 */
        .width = fb_width,
        .height = fb_height
    };

    struct virtio_gpu_ctrl_hdr create_resp = {0};

    if (submit_gpu_command(&create_cmd, sizeof(create_cmd),
                           &create_resp, sizeof(create_resp)) < 0) {
        fut_printf("[virtio-gpu-mmio] RESOURCE_CREATE_2D failed\n");
        return -EIO;
    }

    if (create_resp.type != VIRTIO_GPU_RESP_OK_NODATA) {
        fut_printf("[virtio-gpu-mmio] RESOURCE_CREATE_2D returned error: 0x%x\n",
                   create_resp.type);
        return -EIO;
    }

    fut_printf("[virtio-gpu-mmio] Created 2D resource %u (%ux%u)\n",
               resource_id, fb_width, fb_height);

    /* Attach backing storage */
    struct {
        struct virtio_gpu_resource_attach_backing cmd;
    } attach_cmd = {
        .cmd = {
            .hdr = { .type = VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING, .flags = 0 },
            .resource_id = resource_id,
            .nr_entries = 1,
            .entries = {{ .addr = framebuffer_phys, .length = (uint32_t)fb_size, .padding = 0 }}
        }
    };

    struct virtio_gpu_ctrl_hdr attach_resp = {0};

    if (submit_gpu_command(&attach_cmd, sizeof(attach_cmd),
                           &attach_resp, sizeof(attach_resp)) < 0) {
        fut_printf("[virtio-gpu-mmio] RESOURCE_ATTACH_BACKING failed\n");
        return -EIO;
    }

    if (attach_resp.type != VIRTIO_GPU_RESP_OK_NODATA) {
        fut_printf("[virtio-gpu-mmio] RESOURCE_ATTACH_BACKING returned error: 0x%x\n",
                   attach_resp.type);
        return -EIO;
    }

    fut_printf("[virtio-gpu-mmio] Attached backing storage\n");

    /* Set scanout */
    struct virtio_gpu_set_scanout scanout_cmd = {
        .hdr = { .type = VIRTIO_GPU_CMD_SET_SCANOUT, .flags = 0 },
        .r = { .x = 0, .y = 0, .width = fb_width, .height = fb_height },
        .scanout_id = 0,
        .resource_id = resource_id
    };

    struct virtio_gpu_ctrl_hdr scanout_resp = {0};

    if (submit_gpu_command(&scanout_cmd, sizeof(scanout_cmd),
                           &scanout_resp, sizeof(scanout_resp)) < 0) {
        fut_printf("[virtio-gpu-mmio] SET_SCANOUT failed\n");
        return -EIO;
    }

    if (scanout_resp.type != VIRTIO_GPU_RESP_OK_NODATA) {
        fut_printf("[virtio-gpu-mmio] SET_SCANOUT returned error: 0x%x\n",
                   scanout_resp.type);
        return -EIO;
    }

    fut_printf("[virtio-gpu-mmio] Scanout configured\n");

    /* Initial transfer and flush */
    struct virtio_gpu_transfer_to_host_2d transfer_cmd = {
        .hdr = { .type = VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D, .flags = 0 },
        .r = { .x = 0, .y = 0, .width = fb_width, .height = fb_height },
        .offset = 0,
        .resource_id = resource_id,
        .padding = 0
    };

    struct virtio_gpu_ctrl_hdr transfer_resp = {0};

    if (submit_gpu_command(&transfer_cmd, sizeof(transfer_cmd),
                           &transfer_resp, sizeof(transfer_resp)) < 0) {
        fut_printf("[virtio-gpu-mmio] Initial TRANSFER_TO_HOST_2D failed\n");
    }

    struct virtio_gpu_resource_flush flush_cmd = {
        .hdr = { .type = VIRTIO_GPU_CMD_RESOURCE_FLUSH, .flags = 0 },
        .r = { .x = 0, .y = 0, .width = fb_width, .height = fb_height },
        .resource_id = resource_id,
        .padding = 0
    };

    struct virtio_gpu_ctrl_hdr flush_resp = {0};

    if (submit_gpu_command(&flush_cmd, sizeof(flush_cmd),
                           &flush_resp, sizeof(flush_resp)) < 0) {
        fut_printf("[virtio-gpu-mmio] Initial RESOURCE_FLUSH failed\n");
    }

    fut_printf("[virtio-gpu-mmio] Display initialized successfully\n");
    fut_printf("[virtio-gpu-mmio] Framebuffer: %ux%u @ 0x%llx\n",
               fb_width, fb_height, (unsigned long long)framebuffer_phys);

    if (out_fb_phys) {
        *out_fb_phys = framebuffer_phys;
    }

    return 0;
}

/**
 * Flush framebuffer changes to the display.
 */
void virtio_gpu_flush_display_mmio(void) {
    if (!gpu_dev) {
        return;
    }

    /* Cache flush on ARM64 */
    __asm__ volatile("dsb sy" ::: "memory");

    /* Transfer to host */
    struct virtio_gpu_transfer_to_host_2d transfer_cmd = {
        .hdr = { .type = VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D, .flags = 0 },
        .r = { .x = 0, .y = 0, .width = fb_width, .height = fb_height },
        .offset = 0,
        .resource_id = resource_id,
        .padding = 0
    };

    struct virtio_gpu_ctrl_hdr transfer_resp = {0};

    submit_gpu_command(&transfer_cmd, sizeof(transfer_cmd),
                       &transfer_resp, sizeof(transfer_resp));

    /* Flush resource */
    struct virtio_gpu_resource_flush flush_cmd = {
        .hdr = { .type = VIRTIO_GPU_CMD_RESOURCE_FLUSH, .flags = 0 },
        .r = { .x = 0, .y = 0, .width = fb_width, .height = fb_height },
        .resource_id = resource_id,
        .padding = 0
    };

    struct virtio_gpu_ctrl_hdr flush_resp = {0};

    submit_gpu_command(&flush_cmd, sizeof(flush_cmd),
                       &flush_resp, sizeof(flush_resp));
}
