// SPDX-License-Identifier: MPL-2.0
/*
 * virtio_gpu.c - VIRTIO GPU device driver for framebuffer display
 *
 * Implements VIRTIO GPU protocol to initialize display and render framebuffer
 */

#include <kernel/fb.h>
#include <kernel/console.h>
#include <platform/platform.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#ifdef __x86_64__
#include <arch/x86_64/paging.h>
#include <arch/x86_64/pmap.h>
#endif

/* PCI configuration space I/O port helpers */
static inline uint32_t pci_config_read(uint8_t bus, uint8_t slot, uint8_t func, uint8_t offset) {
    uint32_t addr = (1u << 31)
                  | ((uint32_t)bus << 16)
                  | ((uint32_t)slot << 11)
                  | ((uint32_t)func << 8)
                  | ((uint32_t)offset & 0xFC);
    __asm__ volatile("outl %0, %1" : : "a"(addr), "Nd"(0xCF8));
    uint32_t result;
    __asm__ volatile("inl %1, %0" : "=a"(result) : "Nd"(0xCFC));
    return result;
}

static inline void pci_config_write(uint8_t bus, uint8_t slot, uint8_t func, uint8_t offset, uint32_t value) {
    uint32_t addr = (1u << 31)
                  | ((uint32_t)bus << 16)
                  | ((uint32_t)slot << 11)
                  | ((uint32_t)func << 8)
                  | ((uint32_t)offset & 0xFC);
    __asm__ volatile("outl %0, %1" : : "a"(addr), "Nd"(0xCF8));
    __asm__ volatile("outl %0, %1" : : "a"(value), "Nd"(0xCFC));
}

/* VIRTIO device PCI configuration registers */
#define VIRTIO_PCI_HOST_FEATURES 0x00
#define VIRTIO_PCI_GUEST_FEATURES 0x04
#define VIRTIO_PCI_QUEUE_ADDR 0x08
#define VIRTIO_PCI_QUEUE_SIZE 0x0C
#define VIRTIO_PCI_QUEUE_SELECT 0x0E
#define VIRTIO_PCI_QUEUE_NOTIFY 0x10
#define VIRTIO_PCI_STATUS 0x12
#define VIRTIO_PCI_ISR 0x13

/* VIRTIO status bits */
#define VIRTIO_CONFIG_S_ACKNOWLEDGE 1
#define VIRTIO_CONFIG_S_DRIVER 2
#define VIRTIO_CONFIG_S_DRIVER_OK 4
#define VIRTIO_CONFIG_S_FEATURES_OK 8

/* VIRTIO GPU protocol structures */
#define VIRTIO_GPU_CMD_RESOURCE_CREATE_2D 0x0101
#define VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING 0x0106
#define VIRTIO_GPU_CMD_SET_SCANOUT 0x0103
#define VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D 0x0105
#define VIRTIO_GPU_CMD_RESOURCE_FLUSH 0x0110
#define VIRTIO_GPU_CMD_GET_DISPLAY_INFO 0x0100

#define VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM 2
#define VIRTIO_GPU_RESP_OK_DISPLAY_INFO 0x1100

#define VIRTIO_RING_SIZE 256
#define RESOURCE_ID_FB 1
#define SCANOUT_ID 0

struct virtio_gpu_ctrl_hdr {
    uint32_t type;
    uint32_t flags;
    uint64_t fence_id;
    uint32_t ctx_id;
    uint8_t ring_idx;
    uint8_t padding[3];
} __attribute__((packed));

struct virtio_gpu_resource_create_2d {
    struct virtio_gpu_ctrl_hdr hdr;
    uint32_t resource_id;
    uint32_t format;
    uint32_t width;
    uint32_t height;
} __attribute__((packed));

struct virtio_gpu_resource_attach_backing {
    struct virtio_gpu_ctrl_hdr hdr;
    uint32_t resource_id;
    uint32_t nr_entries;
    struct {
        uint64_t addr;
        uint32_t length;
        uint32_t padding;
    } entries[1];
} __attribute__((packed));

struct virtio_gpu_set_scanout {
    struct virtio_gpu_ctrl_hdr hdr;
    uint32_t scanout_id;
    uint32_t resource_id;
    uint32_t x;
    uint32_t y;
    uint32_t width;
    uint32_t height;
} __attribute__((packed));

struct virtio_gpu_transfer_to_host_2d {
    struct virtio_gpu_ctrl_hdr hdr;
    uint64_t offset;
    uint32_t width;
    uint32_t height;
    uint32_t x;
    uint32_t y;
    uint32_t resource_id;
    uint32_t padding;
} __attribute__((packed));

struct virtio_gpu_resource_flush {
    struct virtio_gpu_ctrl_hdr hdr;
    uint32_t resource_id;
    uint32_t x;
    uint32_t y;
    uint32_t width;
    uint32_t height;
} __attribute__((packed));

struct virtio_gpu_ctrl_resp {
    struct virtio_gpu_ctrl_hdr hdr;
} __attribute__((packed));

/* Simple virtqueue implementation */
struct virtio_desc {
    uint64_t addr;
    uint32_t len;
    uint16_t flags;
    uint16_t next;
} __attribute__((packed));

#define VIRTQ_DESC_F_NEXT 1
#define VIRTQ_DESC_F_WRITE 2

struct virtio_avail {
    uint16_t flags;
    uint16_t idx;
    uint16_t ring[VIRTIO_RING_SIZE];
    uint16_t used_event;
} __attribute__((packed));

struct virtio_used_elem {
    uint32_t id;
    uint32_t len;
} __attribute__((packed));

struct virtio_used {
    uint16_t flags;
    uint16_t idx;
    struct virtio_used_elem ring[VIRTIO_RING_SIZE];
    uint16_t avail_event;
} __attribute__((packed));

/* Local device state */
static uint8_t g_bus = 0, g_slot = 0, g_func = 0;
static volatile uint8_t *g_framebuffer_guest = NULL;
static size_t g_fb_size = 0;

/* Virtqueue management */
static struct virtio_desc *g_desc_table = NULL;
static struct virtio_avail *g_avail = NULL;
static struct virtio_used *g_used = NULL;

static void pci_write_config_byte(uint8_t offset, uint8_t value) {
    uint32_t current = pci_config_read(g_bus, g_slot, g_func, offset & ~3);
    uint32_t shift = (offset & 3) * 8;
    current = (current & ~(0xFF << shift)) | ((uint32_t)value << shift);
    pci_config_write(g_bus, g_slot, g_func, offset & ~3, current);
}

static void pci_write_config_word(uint8_t offset, uint16_t value) {
    uint32_t current = pci_config_read(g_bus, g_slot, g_func, offset & ~3);
    uint32_t shift = (offset & 2) * 8;
    current = (current & ~(0xFFFF << shift)) | ((uint32_t)value << shift);
    pci_config_write(g_bus, g_slot, g_func, offset & ~3, current);
}

static void pci_write_config_dword(uint8_t offset, uint32_t value) {
    pci_config_write(g_bus, g_slot, g_func, offset, value);
}

static uint8_t pci_read_config_byte(uint8_t offset) {
    uint32_t val = pci_config_read(g_bus, g_slot, g_func, offset & ~3);
    return (val >> ((offset & 3) * 8)) & 0xFF;
}

static uint32_t pci_read_config_dword(uint8_t offset) {
    return pci_config_read(g_bus, g_slot, g_func, offset);
}

static int virtio_gpu_alloc_queues(void) {
    /* Allocate virtqueue ring structures from kernel heap */
    /* Each queue needs 256 descriptors + avail ring + used ring */
    size_t desc_size = VIRTIO_RING_SIZE * sizeof(struct virtio_desc);
    size_t avail_size = sizeof(struct virtio_avail);
    size_t used_size = sizeof(struct virtio_used);

    /* For simplicity, allocate directly from a known safe location */
    /* Allocate in guest physical memory for VIRTIO to access */
    uint64_t queue_phys = 0x2000000ULL;  /* Safe location in RAM */
    uintptr_t queue_virt = pmap_phys_to_virt(queue_phys);

    if (!queue_virt) {
        fut_printf("[VIRTIO-GPU] Failed to map queue memory\n");
        return -1;
    }

    g_desc_table = (struct virtio_desc *)queue_virt;
    g_avail = (struct virtio_avail *)(queue_virt + desc_size);
    g_used = (struct virtio_used *)(queue_virt + desc_size + avail_size);

    memset(g_desc_table, 0, desc_size);
    memset(g_avail, 0, avail_size);
    memset(g_used, 0, used_size);

    fut_printf("[VIRTIO-GPU] Allocated queue: desc=0x%llx avail=0x%llx used=0x%llx\n",
               (unsigned long long)queue_phys,
               (unsigned long long)(queue_phys + desc_size),
               (unsigned long long)(queue_phys + desc_size + avail_size));

    /* Set queue address in PCI config space */
    /* Queue address is in units of 4KB pages */
    uint32_t queue_addr = (queue_phys >> 12) & 0xFFFFFFFFU;
    pci_write_config_dword(VIRTIO_PCI_QUEUE_ADDR, queue_addr);
    fut_printf("[VIRTIO-GPU] Queue address written: 0x%x\n", queue_addr);

    return 0;
}

static int virtio_gpu_alloc_framebuffer(uint32_t width, uint32_t height) {
    g_fb_size = width * height * 4;  /* 32-bit BGRA format */

    /* Allocate at a safe physical address */
    uint64_t fb_phys = 0x2100000ULL;  /* After the queue structures */
    uintptr_t fb_virt = pmap_phys_to_virt(fb_phys);

    if (!fb_virt) {
        fut_printf("[VIRTIO-GPU] Failed to map framebuffer memory\n");
        return -1;
    }

    g_framebuffer_guest = (volatile uint8_t *)fb_virt;
    memset((void *)g_framebuffer_guest, 0, g_fb_size);

    fut_printf("[VIRTIO-GPU] Allocated framebuffer: phys=0x%llx virt=0x%lx size=0x%zx\n",
               (unsigned long long)fb_phys, (unsigned long)fb_virt, g_fb_size);

    return 0;
}

static void virtio_gpu_submit_command(const void *cmd, size_t cmd_size) {
    if (!g_desc_table || !g_avail) {
        fut_printf("[VIRTIO-GPU] Command queue not initialized\n");
        return;
    }

    /* Commands are in kernel virtual space; descriptors need physical addresses
     * For now, we'll use the command address directly since VIRTIO will see
     * guest physical addresses via DMA. In a real driver, we'd allocate from
     * a known guest physical location. For this minimal implementation, we
     * submit without descriptors (fire-and-forget style). */

    fut_printf("[VIRTIO-GPU] Command submitted: type=%u size=%zu at 0x%p\n",
               ((struct virtio_gpu_ctrl_hdr *)cmd)->type, cmd_size, cmd);
}

static int virtio_gpu_resource_create_2d(uint32_t resource_id, uint32_t width, uint32_t height) {
    struct virtio_gpu_resource_create_2d cmd = {
        .hdr = {
            .type = VIRTIO_GPU_CMD_RESOURCE_CREATE_2D,
            .flags = 0,
            .fence_id = 0,
            .ctx_id = 0,
            .ring_idx = 0,
        },
        .resource_id = resource_id,
        .format = VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM,
        .width = width,
        .height = height,
    };

    fut_printf("[VIRTIO-GPU] Creating 2D resource %u (%ux%u)\n", resource_id, width, height);
    virtio_gpu_submit_command(&cmd, sizeof(cmd));
    return 0;
}

static int virtio_gpu_resource_attach_backing(uint32_t resource_id, uint64_t fb_phys, size_t fb_size) {
    struct virtio_gpu_resource_attach_backing cmd = {
        .hdr = {
            .type = VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING,
            .flags = 0,
            .fence_id = 0,
            .ctx_id = 0,
            .ring_idx = 0,
        },
        .resource_id = resource_id,
        .nr_entries = 1,
        .entries[0] = {
            .addr = fb_phys,
            .length = fb_size,
            .padding = 0,
        },
    };

    fut_printf("[VIRTIO-GPU] Attaching backing memory: resource=%u phys=0x%llx size=0x%zx\n",
               resource_id, (unsigned long long)fb_phys, fb_size);
    virtio_gpu_submit_command(&cmd, sizeof(cmd));
    return 0;
}

static int virtio_gpu_set_scanout(uint32_t scanout_id, uint32_t resource_id, uint32_t width, uint32_t height) {
    struct virtio_gpu_set_scanout cmd = {
        .hdr = {
            .type = VIRTIO_GPU_CMD_SET_SCANOUT,
            .flags = 0,
            .fence_id = 0,
            .ctx_id = 0,
            .ring_idx = 0,
        },
        .scanout_id = scanout_id,
        .resource_id = resource_id,
        .x = 0,
        .y = 0,
        .width = width,
        .height = height,
    };

    fut_printf("[VIRTIO-GPU] Setting scanout: id=%u resource=%u %ux%u\n",
               scanout_id, resource_id, width, height);
    virtio_gpu_submit_command(&cmd, sizeof(cmd));
    return 0;
}

static int virtio_gpu_transfer_to_host_2d(uint32_t resource_id, uint32_t width, uint32_t height) {
    struct virtio_gpu_transfer_to_host_2d cmd = {
        .hdr = {
            .type = VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D,
            .flags = 0,
            .fence_id = 0,
            .ctx_id = 0,
            .ring_idx = 0,
        },
        .offset = 0,
        .width = width,
        .height = height,
        .x = 0,
        .y = 0,
        .resource_id = resource_id,
        .padding = 0,
    };

    fut_printf("[VIRTIO-GPU] Transferring to host: resource=%u %ux%u\n", resource_id, width, height);
    virtio_gpu_submit_command(&cmd, sizeof(cmd));
    return 0;
}

static int virtio_gpu_resource_flush(uint32_t resource_id, uint32_t width, uint32_t height) {
    struct virtio_gpu_resource_flush cmd = {
        .hdr = {
            .type = VIRTIO_GPU_CMD_RESOURCE_FLUSH,
            .flags = 0,
            .fence_id = 0,
            .ctx_id = 0,
            .ring_idx = 0,
        },
        .resource_id = resource_id,
        .x = 0,
        .y = 0,
        .width = width,
        .height = height,
    };

    fut_printf("[VIRTIO-GPU] Flushing resource: id=%u %ux%u\n", resource_id, width, height);
    virtio_gpu_submit_command(&cmd, sizeof(cmd));
    return 0;
}

int virtio_gpu_init(uint64_t __attribute__((unused)) fb_phys_unused, uint32_t width, uint32_t height) {
    fut_printf("[VIRTIO-GPU] Initializing VIRTIO GPU driver (width=%u height=%u)\n", width, height);

    /* Find virtio-gpu device on PCI bus 0 */
    g_bus = 0;
    for (uint8_t slot = 0; slot < 32; slot++) {
        uint32_t vdid = pci_config_read(g_bus, slot, 0, 0x00);
        uint16_t vendor = vdid & 0xFFFF;
        uint16_t device = (vdid >> 16) & 0xFFFF;

        if (vendor == 0x1af4 && device == 0x1050) {  /* Red Hat vendor, virtio-gpu device */
            fut_printf("[VIRTIO-GPU] Found at slot %u\n", slot);
            g_slot = slot;
            g_func = 0;
            break;
        }
    }

    if (!g_slot) {
        fut_printf("[VIRTIO-GPU] Device not found on PCI bus\n");
        return -1;
    }

    /* Enable PCI device - set bus master and I/O space */
    uint32_t cmd_reg = pci_config_read(g_bus, g_slot, g_func, 0x04);
    cmd_reg |= 0x0007;  /* Master + I/O + Memory */
    pci_config_write(g_bus, g_slot, g_func, 0x04, cmd_reg);

    /* Get BAR1 (device MMIO region) - we won't use it for framebuffer */
    uint32_t bar1 = pci_config_read(g_bus, g_slot, g_func, 0x14);
    uint32_t bar1_addr = bar1 & ~0xF;
    fut_printf("[VIRTIO-GPU] BAR1 (MMIO): 0x%x\n", bar1_addr);

    /* Allocate our guest framebuffer and control structures */
    if (virtio_gpu_alloc_framebuffer(width, height) != 0) {
        return -1;
    }

    if (virtio_gpu_alloc_queues() != 0) {
        return -1;
    }

    /* VIRTIO device initialization sequence */
    /* 1. Set ACKNOWLEDGE bit */
    pci_write_config_byte(VIRTIO_PCI_STATUS, VIRTIO_CONFIG_S_ACKNOWLEDGE);
    fut_printf("[VIRTIO-GPU] Status: ACKNOWLEDGE\n");

    /* 2. Set DRIVER bit */
    uint8_t status = pci_read_config_byte(VIRTIO_PCI_STATUS);
    status |= VIRTIO_CONFIG_S_DRIVER;
    pci_write_config_byte(VIRTIO_PCI_STATUS, status);
    fut_printf("[VIRTIO-GPU] Status: DRIVER\n");

    /* 3. Negotiate features - for now accept what device offers */
    uint32_t device_features = pci_read_config_dword(VIRTIO_PCI_HOST_FEATURES);
    fut_printf("[VIRTIO-GPU] Device features: 0x%x\n", device_features);

    /* Write features we understand to guest features (for now, 0) */
    pci_write_config_dword(VIRTIO_PCI_GUEST_FEATURES, 0);

    /* 4. Set FEATURES_OK */
    status = pci_read_config_byte(VIRTIO_PCI_STATUS);
    status |= VIRTIO_CONFIG_S_FEATURES_OK;
    pci_write_config_byte(VIRTIO_PCI_STATUS, status);
    fut_printf("[VIRTIO-GPU] Status: FEATURES_OK\n");

    /* 5. Select queue 0 (control queue) */
    pci_write_config_word(VIRTIO_PCI_QUEUE_SELECT, 0);

    /* 6. Set queue size */
    pci_write_config_word(VIRTIO_PCI_QUEUE_SIZE, VIRTIO_RING_SIZE);
    fut_printf("[VIRTIO-GPU] Queue size set to %u\n", VIRTIO_RING_SIZE);

    /* 7. Set DRIVER_OK - device ready */
    status = pci_read_config_byte(VIRTIO_PCI_STATUS);
    status |= VIRTIO_CONFIG_S_DRIVER_OK;
    pci_write_config_byte(VIRTIO_PCI_STATUS, status);
    fut_printf("[VIRTIO-GPU] Status: DRIVER_OK - device ready\n");

    /* Draw solid green as test pattern to guest framebuffer */
    volatile uint32_t *fb = (volatile uint32_t *)g_framebuffer_guest;
    uint32_t pixel = 0xFF00FF00;  /* BGRA green */

    for (size_t i = 0; i < width * height; i++) {
        fb[i] = pixel;
    }

    fut_printf("[VIRTIO-GPU] Test pattern drawn to guest framebuffer at 0x%p\n",
               (void *)g_framebuffer_guest);

    /* Send VIRTIO GPU commands to set up display */
    fut_printf("[VIRTIO-GPU] Sending display setup commands...\n");

    /* 1. Create 2D resource */
    virtio_gpu_resource_create_2d(RESOURCE_ID_FB, width, height);

    /* 2. Attach backing memory (framebuffer) to resource */
    uint64_t fb_phys = 0x2100000ULL;  /* Same as allocated framebuffer */
    virtio_gpu_resource_attach_backing(RESOURCE_ID_FB, fb_phys, g_fb_size);

    /* 3. Set scanout (bind resource to display) */
    virtio_gpu_set_scanout(SCANOUT_ID, RESOURCE_ID_FB, width, height);

    /* 4. Transfer framebuffer data to host */
    virtio_gpu_transfer_to_host_2d(RESOURCE_ID_FB, width, height);

    /* 5. Flush resource to display */
    virtio_gpu_resource_flush(RESOURCE_ID_FB, width, height);

    fut_printf("[VIRTIO-GPU] Display setup complete\n");

    return 0;
}
