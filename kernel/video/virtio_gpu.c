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
#include <platform/x86_64/memory/paging.h>
#include <platform/x86_64/memory/pmap.h>
#endif

#ifdef __x86_64__
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
#endif /* __x86_64__ */

/* Virtio 1.0 PCI capability types */
#define VIRTIO_PCI_CAP_COMMON_CFG 1
#define VIRTIO_PCI_CAP_NOTIFY_CFG 2
#define VIRTIO_PCI_CAP_ISR_CFG 3
#define VIRTIO_PCI_CAP_DEVICE_CFG 4
#define VIRTIO_PCI_CAP_PCI_CFG 5

/* PCI capability ID for vendor-specific */
#define PCI_CAP_ID_VNDR 0x09

/* Legacy virtio register offsets (for fallback) */
#define VIRTIO_PCI_QUEUE_ADDR 0x08
#define VIRTIO_PCI_QUEUE_SELECT 0x0E
#define VIRTIO_PCI_QUEUE_NOTIFY 0x10
#define VIRTIO_PCI_QUEUE_SIZE 0x0C
#define VIRTIO_PCI_HOST_FEATURES 0x00
#define VIRTIO_PCI_GUEST_FEATURES 0x04

/* Virtio 1.0 common configuration structure offsets */
#define VIRTIO_PCI_COMMON_DFSELECT 0x00
#define VIRTIO_PCI_COMMON_DF 0x04
#define VIRTIO_PCI_COMMON_GFSELECT 0x08
#define VIRTIO_PCI_COMMON_GF 0x0c
#define VIRTIO_PCI_COMMON_MSIX 0x10
#define VIRTIO_PCI_COMMON_NUMQ 0x12
#define VIRTIO_PCI_COMMON_STATUS 0x14
#define VIRTIO_PCI_COMMON_CFGGENERATION 0x15
#define VIRTIO_PCI_COMMON_Q_SELECT 0x16
#define VIRTIO_PCI_COMMON_Q_SIZE 0x18
#define VIRTIO_PCI_COMMON_Q_MSIX 0x1a
#define VIRTIO_PCI_COMMON_Q_ENABLE 0x1c
#define VIRTIO_PCI_COMMON_Q_NOFF 0x1e
#define VIRTIO_PCI_COMMON_Q_DESCLO 0x20
#define VIRTIO_PCI_COMMON_Q_DESCHI 0x24
#define VIRTIO_PCI_COMMON_Q_AVAILLO 0x28
#define VIRTIO_PCI_COMMON_Q_AVAILHI 0x2c
#define VIRTIO_PCI_COMMON_Q_USEDLO 0x30
#define VIRTIO_PCI_COMMON_Q_USEDHI 0x34
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

struct virtio_gpu_rect {
    uint32_t x;
    uint32_t y;
    uint32_t width;
    uint32_t height;
} __attribute__((packed));

struct virtio_gpu_set_scanout {
    struct virtio_gpu_ctrl_hdr hdr;
    struct virtio_gpu_rect r;
    uint32_t scanout_id;
    uint32_t resource_id;
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

/* Virtio PCI capability structure */
struct virtio_pci_cap {
    uint8_t cap_vndr;    /* Generic PCI field: PCI_CAP_ID_VNDR */
    uint8_t cap_next;    /* Generic PCI field: next ptr */
    uint8_t cap_len;     /* Generic PCI field: capability length */
    uint8_t cfg_type;    /* Identifies the structure (VIRTIO_PCI_CAP_*) */
    uint8_t bar;         /* Where to find it */
    uint8_t padding[3];
    uint32_t offset;     /* Offset within bar */
    uint32_t length;     /* Length of the structure, in bytes */
} __attribute__((packed));

#ifdef __x86_64__
/* Local device state */
static uint8_t g_bus = 0, g_slot = 0, g_func = 0;
static volatile uint8_t *g_mmio_base = NULL;  /* BAR1 MMIO base (legacy fallback) */
static volatile uint8_t *g_common_cfg = NULL;  /* Common configuration region */
static volatile uint8_t *g_notify_base = NULL; /* Notification region */
static volatile uint8_t *g_isr_base = NULL;    /* ISR status region */
static volatile uint8_t *g_device_cfg = NULL;  /* Device-specific configuration */
static volatile uint8_t *g_framebuffer_guest = NULL;
static size_t g_fb_size = 0;
static uint32_t g_fb_width = 0, g_fb_height = 0;

/* Virtqueue management */
static struct virtio_desc *g_desc_table = NULL;
static struct virtio_avail *g_avail = NULL;
static struct virtio_used *g_used = NULL;
static uint16_t g_cmd_idx = 0;

/* Command buffer pool in guest physical memory (after queues and FB) */
static volatile uint8_t *g_cmd_buffer = NULL;
static uint64_t g_cmd_buffer_phys = 0;
#define CMD_BUFFER_SIZE 4096
#define CMD_BUFFER_PHYS 0x2200000ULL

/* Response buffer for command responses */
static volatile uint8_t *g_resp_buffer = NULL;
static uint64_t g_resp_buffer_phys = 0;
#define RESP_BUFFER_SIZE 4096
#define RESP_BUFFER_PHYS 0x2201000ULL
#endif /* __x86_64__ */

#ifdef __x86_64__
/* MMIO access functions for virtio device registers (via BAR1) */
static inline uint8_t virtio_read8(uint16_t offset) {
    return *(volatile uint8_t *)(g_mmio_base + offset);
}

static inline void virtio_write8(uint16_t offset, uint8_t value) {
    *(volatile uint8_t *)(g_mmio_base + offset) = value;
}

static inline uint16_t virtio_read16(uint16_t offset) {
    return *(volatile uint16_t *)(g_mmio_base + offset);
}

static inline void virtio_write16(uint16_t offset, uint16_t value) {
    *(volatile uint16_t *)(g_mmio_base + offset) = value;
}

static inline uint32_t virtio_read32(uint16_t offset) {
    return *(volatile uint32_t *)(g_mmio_base + offset);
}

static inline void virtio_write32(uint16_t offset, uint32_t value) {
    *(volatile uint32_t *)(g_mmio_base + offset) = value;
}

/* Modern virtio 1.0 common config access helpers */
static inline uint8_t virtio_common_read8(uint16_t offset) {
    if (!g_common_cfg) return 0;
    return *(volatile uint8_t *)(g_common_cfg + offset);
}

static inline void virtio_common_write8(uint16_t offset, uint8_t value) {
    if (!g_common_cfg) return;
    *(volatile uint8_t *)(g_common_cfg + offset) = value;
}

static inline uint16_t virtio_common_read16(uint16_t offset) {
    if (!g_common_cfg) return 0;
    return *(volatile uint16_t *)(g_common_cfg + offset);
}

static inline void virtio_common_write16(uint16_t offset, uint16_t value) {
    if (!g_common_cfg) return;
    *(volatile uint16_t *)(g_common_cfg + offset) = value;
}

static inline uint32_t virtio_common_read32(uint16_t offset) {
    if (!g_common_cfg) return 0;
    return *(volatile uint32_t *)(g_common_cfg + offset);
}

static inline void virtio_common_write32(uint16_t offset, uint32_t value) {
    if (!g_common_cfg) return;
    *(volatile uint32_t *)(g_common_cfg + offset) = value;
}

static inline uint64_t virtio_common_read64(uint16_t offset) {
    if (!g_common_cfg) return 0;
    return *(volatile uint64_t *)(g_common_cfg + offset);
}

static inline void virtio_common_write64(uint16_t offset, uint64_t value) {
    if (!g_common_cfg) return;
    *(volatile uint64_t *)(g_common_cfg + offset) = value;
}
/* Helper to read a single byte from PCI config space */
static uint8_t pci_config_read_byte(uint8_t bus, uint8_t slot, uint8_t func, uint8_t offset) {
    uint32_t dword = pci_config_read(bus, slot, func, offset & ~3);
    return (dword >> ((offset & 3) * 8)) & 0xFF;
}

/* Scan PCI capabilities to find virtio 1.0 structures and map them */
static int virtio_scan_capabilities(void) {
    /* Read capabilities pointer from PCI config space offset 0x34 */
    uint8_t cap_ptr = pci_config_read_byte(g_bus, g_slot, g_func, 0x34);

    if (cap_ptr == 0) {
        fut_printf("[VIRTIO-GPU] No PCI capabilities found\n");
        return -1;
    }

    fut_printf("[VIRTIO-GPU] Scanning PCI capabilities starting at offset 0x%02x\n", cap_ptr);

    /* Track which BARs we need to map */
    uint32_t bar_addrs[6] = {0};
    uint8_t bar_mapped[6] = {0};

    /* Scan the capabilities linked list */
    int cap_count = 0;
    while (cap_ptr != 0 && cap_count < 32) {  /* Safety limit */
        cap_count++;

        /* Read capability header */
        uint8_t cap_id = pci_config_read_byte(g_bus, g_slot, g_func, cap_ptr);
        uint8_t cap_next = pci_config_read_byte(g_bus, g_slot, g_func, cap_ptr + 1);

        fut_printf("[VIRTIO-GPU]   Cap %d at 0x%02x: ID=0x%02x\n", cap_count, cap_ptr, cap_id);

        /* Check if this is a vendor-specific capability */
        if (cap_id == PCI_CAP_ID_VNDR) {
            /* Read virtio capability structure */
            uint8_t cfg_type = pci_config_read_byte(g_bus, g_slot, g_func, cap_ptr + 3);
            uint8_t bar = pci_config_read_byte(g_bus, g_slot, g_func, cap_ptr + 4);

            /* Read offset and length (32-bit values at offsets +8 and +12) */
            uint32_t cap_offset = pci_config_read(g_bus, g_slot, g_func, cap_ptr + 8);
            uint32_t cap_length = pci_config_read(g_bus, g_slot, g_func, cap_ptr + 12);

            fut_printf("[VIRTIO-GPU]     Virtio cap: type=%u bar=%u offset=0x%x len=0x%x\n",
                       cfg_type, bar, cap_offset, cap_length);

            /* Ensure BAR is valid */
            if (bar >= 6) {
                fut_printf("[VIRTIO-GPU]     Invalid BAR index %u, skipping\n", bar);
                cap_ptr = cap_next;
                continue;
            }

            /* Read the BAR address if we haven't already */
            if (bar_addrs[bar] == 0) {
                uint32_t bar_offset = 0x10 + (bar * 4);
                uint32_t bar_val = pci_config_read(g_bus, g_slot, g_func, bar_offset);

                if ((bar_val & 0x1) == 0) {  /* MMIO BAR */
                    bar_addrs[bar] = bar_val & ~0xF;
                    fut_printf("[VIRTIO-GPU]     BAR%u address: 0x%x\n", bar, bar_addrs[bar]);
                }
            }

            /* Map the BAR if needed and set up the appropriate pointer */
            if (bar_addrs[bar] != 0) {
                /* Get the virtual base address (map if not already mapped) */
                uintptr_t virt_base = 0xFFFFFFFFFEC00000ULL + (bar * 0x10000);

                if (!bar_mapped[bar]) {
                    uint64_t phys_base = PAGE_ALIGN_DOWN(bar_addrs[bar]);

                    if (pmap_map(virt_base, phys_base, 0x10000,
                                 PTE_KERNEL_RW | PTE_WRITE_THROUGH | PTE_CACHE_DISABLE) != 0) {
                        fut_printf("[VIRTIO-GPU]     Failed to map BAR%u\n", bar);
                        cap_ptr = cap_next;
                        continue;
                    }
                    bar_mapped[bar] = 1;
                    fut_printf("[VIRTIO-GPU]     Mapped BAR%u: phys=0x%llx virt=0x%lx\n",
                               bar, (unsigned long long)phys_base, (unsigned long)virt_base);
                }

                /* Calculate the capability virtual address from the BAR virtual base */
                uint64_t phys_base = PAGE_ALIGN_DOWN(bar_addrs[bar]);
                uint64_t offset_in_bar = bar_addrs[bar] - phys_base;
                volatile uint8_t *cap_virt = (volatile uint8_t *)(virt_base + offset_in_bar + cap_offset);

                /* Store base pointer for this capability type */
                switch (cfg_type) {
                    case VIRTIO_PCI_CAP_COMMON_CFG:
                        g_common_cfg = cap_virt;
                        fut_printf("[VIRTIO-GPU]     Common config at virt=0x%lx\n",
                                   (unsigned long)g_common_cfg);
                        break;
                    case VIRTIO_PCI_CAP_NOTIFY_CFG:
                        g_notify_base = cap_virt;
                        fut_printf("[VIRTIO-GPU]     Notify region at virt=0x%lx\n",
                                   (unsigned long)g_notify_base);
                        break;
                    case VIRTIO_PCI_CAP_ISR_CFG:
                        g_isr_base = cap_virt;
                        fut_printf("[VIRTIO-GPU]     ISR status at virt=0x%lx\n",
                                   (unsigned long)g_isr_base);
                        break;
                    case VIRTIO_PCI_CAP_DEVICE_CFG:
                        g_device_cfg = cap_virt;
                        fut_printf("[VIRTIO-GPU]     Device config at virt=0x%lx\n",
                                   (unsigned long)g_device_cfg);
                        break;
                    default:
                        fut_printf("[VIRTIO-GPU]     Unknown capability type %u\n", cfg_type);
                        break;
                }
            }
        }

        cap_ptr = cap_next;
    }

    fut_printf("[VIRTIO-GPU] Scanned %d capabilities\n", cap_count);

    /* Verify we found the essential structures */
    if (!g_common_cfg) {
        fut_printf("[VIRTIO-GPU] ERROR: Common configuration not found\n");
        return -1;
    }

    fut_printf("[VIRTIO-GPU] Successfully mapped virtio 1.0 structures\n");
    return 0;
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

    uint64_t desc_phys = queue_phys;
    uint64_t avail_phys = queue_phys + desc_size;
    uint64_t used_phys = queue_phys + desc_size + avail_size;

    fut_printf("[VIRTIO-GPU] Allocated queue: desc=0x%llx avail=0x%llx used=0x%llx\n",
               (unsigned long long)desc_phys,
               (unsigned long long)avail_phys,
               (unsigned long long)used_phys);

    /* Modern virtio 1.0: Set descriptor, available, and used addresses separately */
    if (g_common_cfg) {
        /* Select queue 0 (control queue) */
        virtio_common_write16(VIRTIO_PCI_COMMON_Q_SELECT, 0);

        /* Set queue size */
        virtio_common_write16(VIRTIO_PCI_COMMON_Q_SIZE, VIRTIO_RING_SIZE);

        /* Set descriptor table address (64-bit) */
        virtio_common_write64(VIRTIO_PCI_COMMON_Q_DESCLO, desc_phys);

        /* Set available ring address (64-bit) */
        virtio_common_write64(VIRTIO_PCI_COMMON_Q_AVAILLO, avail_phys);

        /* Set used ring address (64-bit) */
        virtio_common_write64(VIRTIO_PCI_COMMON_Q_USEDLO, used_phys);

        /* Enable the queue */
        virtio_common_write16(VIRTIO_PCI_COMMON_Q_ENABLE, 1);

        fut_printf("[VIRTIO-GPU] Modern queue setup complete\n");
    } else {
        /* Legacy mode fallback */
        uint32_t queue_addr = (queue_phys >> 12) & 0xFFFFFFFFU;
        virtio_write32(VIRTIO_PCI_QUEUE_ADDR, queue_addr);
        fut_printf("[VIRTIO-GPU] Legacy queue address written: 0x%x\n", queue_addr);
    }

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
    if (!g_desc_table || !g_avail || !g_cmd_buffer || !g_resp_buffer) {
        fut_printf("[VIRTIO-GPU] Command queue not initialized\n");
        return;
    }

    if (cmd_size > CMD_BUFFER_SIZE) {
        fut_printf("[VIRTIO-GPU] Command too large: %zu > %u\n", cmd_size, CMD_BUFFER_SIZE);
        return;
    }

    /* Copy command to guest physical buffer */
    memcpy((void *)g_cmd_buffer, cmd, cmd_size);

    /* Clear response buffer */
    memset((void *)g_resp_buffer, 0, RESP_BUFFER_SIZE);

    /* Create descriptor chain: command -> response */
    uint16_t cmd_desc_idx = (g_cmd_idx * 2) % VIRTIO_RING_SIZE;
    uint16_t resp_desc_idx = (g_cmd_idx * 2 + 1) % VIRTIO_RING_SIZE;

    /* Command descriptor (device reads) */
    g_desc_table[cmd_desc_idx].addr = g_cmd_buffer_phys;
    g_desc_table[cmd_desc_idx].len = cmd_size;
    g_desc_table[cmd_desc_idx].flags = VIRTQ_DESC_F_NEXT;  /* Chain to response */
    g_desc_table[cmd_desc_idx].next = resp_desc_idx;

    /* Response descriptor (device writes) */
    g_desc_table[resp_desc_idx].addr = g_resp_buffer_phys;
    g_desc_table[resp_desc_idx].len = RESP_BUFFER_SIZE;
    g_desc_table[resp_desc_idx].flags = VIRTQ_DESC_F_WRITE;  /* Device writes response */
    g_desc_table[resp_desc_idx].next = 0;

    /* Add to available ring (head of chain) */
    uint16_t avail_idx = g_avail->idx % VIRTIO_RING_SIZE;
    g_avail->ring[avail_idx] = cmd_desc_idx;
    __sync_synchronize();  /* Memory barrier before incrementing idx */
    g_avail->idx++;

    /* Notify device - modern virtio 1.0 uses notify region, legacy uses register */
    if (g_notify_base) {
        /* Modern: Write queue index (0) to the notify region */
        *(volatile uint16_t *)g_notify_base = 0;
    } else {
        /* Legacy fallback */
        virtio_write16(VIRTIO_PCI_QUEUE_NOTIFY, 0);
    }

    /* Wait for response with timeout */
    uint16_t last_used_idx = g_used->idx;
    int timeout = 1000000;
    while (g_used->idx == last_used_idx && timeout > 0) {
        __sync_synchronize();
        timeout--;
    }

    if (timeout > 0) {
        /* Check response */
        struct virtio_gpu_ctrl_hdr *resp = (struct virtio_gpu_ctrl_hdr *)g_resp_buffer;
        fut_printf("[VIRTIO-GPU] Cmd type=%u: response type=0x%x (waited %d)\n",
                   ((struct virtio_gpu_ctrl_hdr *)cmd)->type, resp->type, 1000000-timeout);
    } else {
        fut_printf("[VIRTIO-GPU] Cmd type=%u: TIMEOUT waiting for response\n",
                   ((struct virtio_gpu_ctrl_hdr *)cmd)->type);
    }

    g_cmd_idx++;
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
        .r = {
            .x = 0,
            .y = 0,
            .width = width,
            .height = height,
        },
        .scanout_id = scanout_id,
        .resource_id = resource_id,
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

int virtio_gpu_init(uint64_t *out_fb_phys, uint32_t width, uint32_t height) {
    fut_printf("[VIRTIO-GPU] Initializing VIRTIO GPU driver (width=%u height=%u)\n", width, height);

    /* Store dimensions for later use */
    g_fb_width = width;
    g_fb_height = height;

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

    /* Enable PCI device - set bus master and memory space */
    uint32_t cmd_reg = pci_config_read(g_bus, g_slot, g_func, 0x04);
    cmd_reg |= 0x0006;  /* Master + Memory */
    pci_config_write(g_bus, g_slot, g_func, 0x04, cmd_reg);

    /* Scan PCI capabilities to locate virtio 1.0 structures */
    if (virtio_scan_capabilities() != 0) {
        fut_printf("[VIRTIO-GPU] Failed to scan capabilities\n");
        return -1;
    }

    /* Allocate our guest framebuffer and control structures */
    if (virtio_gpu_alloc_framebuffer(width, height) != 0) {
        return -1;
    }

    if (virtio_gpu_alloc_queues() != 0) {
        return -1;
    }

    /* Map command buffer for VIRTIO command submission */
    g_cmd_buffer_phys = CMD_BUFFER_PHYS;
    uintptr_t cmd_virt = pmap_phys_to_virt(CMD_BUFFER_PHYS);
    if (!cmd_virt) {
        fut_printf("[VIRTIO-GPU] Failed to map command buffer\n");
        return -1;
    }
    g_cmd_buffer = (volatile uint8_t *)cmd_virt;
    memset((void *)g_cmd_buffer, 0, CMD_BUFFER_SIZE);
    fut_printf("[VIRTIO-GPU] Command buffer: phys=0x%llx virt=0x%lx size=%u\n",
               (unsigned long long)g_cmd_buffer_phys, (unsigned long)g_cmd_buffer, CMD_BUFFER_SIZE);

    /* Map response buffer for VIRTIO command responses */
    g_resp_buffer_phys = RESP_BUFFER_PHYS;
    uintptr_t resp_virt = pmap_phys_to_virt(RESP_BUFFER_PHYS);
    if (!resp_virt) {
        fut_printf("[VIRTIO-GPU] Failed to map response buffer\n");
        return -1;
    }
    g_resp_buffer = (volatile uint8_t *)resp_virt;
    memset((void *)g_resp_buffer, 0, RESP_BUFFER_SIZE);
    fut_printf("[VIRTIO-GPU] Response buffer: phys=0x%llx virt=0x%lx size=%u\n",
               (unsigned long long)g_resp_buffer_phys, (unsigned long)g_resp_buffer, RESP_BUFFER_SIZE);

    /* VIRTIO device initialization sequence (using modern virtio 1.0 common config) */
    /* 1. Set ACKNOWLEDGE bit */
    virtio_common_write8(VIRTIO_PCI_COMMON_STATUS, VIRTIO_CONFIG_S_ACKNOWLEDGE);
    uint8_t status_readback = virtio_common_read8(VIRTIO_PCI_COMMON_STATUS);
    fut_printf("[VIRTIO-GPU] Status: ACKNOWLEDGE (wrote 0x%x, read 0x%x)\n",
               VIRTIO_CONFIG_S_ACKNOWLEDGE, status_readback);

    /* 2. Set DRIVER bit */
    uint8_t status = virtio_common_read8(VIRTIO_PCI_COMMON_STATUS);
    status |= VIRTIO_CONFIG_S_DRIVER;
    virtio_common_write8(VIRTIO_PCI_COMMON_STATUS, status);
    status_readback = virtio_common_read8(VIRTIO_PCI_COMMON_STATUS);
    fut_printf("[VIRTIO-GPU] Status: DRIVER (wrote 0x%x, read 0x%x)\n", status, status_readback);

    /* 3. Negotiate features - read device features */
    virtio_common_write32(VIRTIO_PCI_COMMON_DFSELECT, 0);  /* Select features bits 0-31 */
    uint32_t device_features_lo = virtio_common_read32(VIRTIO_PCI_COMMON_DF);
    virtio_common_write32(VIRTIO_PCI_COMMON_DFSELECT, 1);  /* Select features bits 32-63 */
    uint32_t device_features_hi = virtio_common_read32(VIRTIO_PCI_COMMON_DF);
    fut_printf("[VIRTIO-GPU] Device features: 0x%x%08x\n", device_features_hi, device_features_lo);

    /* Write features we understand to guest features (for now, accept all lower 32 bits) */
    virtio_common_write32(VIRTIO_PCI_COMMON_GFSELECT, 0);  /* Select guest features bits 0-31 */
    virtio_common_write32(VIRTIO_PCI_COMMON_GF, device_features_lo);
    virtio_common_write32(VIRTIO_PCI_COMMON_GFSELECT, 1);  /* Select guest features bits 32-63 */
    virtio_common_write32(VIRTIO_PCI_COMMON_GF, 0);  /* Don't enable 64-bit features for now */

    /* 4. Set FEATURES_OK */
    status = virtio_common_read8(VIRTIO_PCI_COMMON_STATUS);
    status |= VIRTIO_CONFIG_S_FEATURES_OK;
    virtio_common_write8(VIRTIO_PCI_COMMON_STATUS, status);

    /* Verify FEATURES_OK was accepted */
    status = virtio_common_read8(VIRTIO_PCI_COMMON_STATUS);
    if (!(status & VIRTIO_CONFIG_S_FEATURES_OK)) {
        fut_printf("[VIRTIO-GPU] ERROR: Device rejected our feature set\n");
        return -1;
    }
    fut_printf("[VIRTIO-GPU] Status: FEATURES_OK (status=0x%x)\n", status);

    /* 5. Set DRIVER_OK - device ready */
    status = virtio_common_read8(VIRTIO_PCI_COMMON_STATUS);
    status |= VIRTIO_CONFIG_S_DRIVER_OK;
    virtio_common_write8(VIRTIO_PCI_COMMON_STATUS, status);
    fut_printf("[VIRTIO-GPU] Status: DRIVER_OK - device ready\n");

    /* Draw solid white as test pattern to guest framebuffer */
    volatile uint32_t *fb = (volatile uint32_t *)g_framebuffer_guest;
    uint32_t pixel = 0xFFFFFFFF;  /* White - all channels max */

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

    /* Return the actual guest framebuffer address that should be used */
    if (out_fb_phys) {
        *out_fb_phys = fb_phys;
        fut_printf("[VIRTIO-GPU] Returning framebuffer address: phys=0x%llx\n",
                   (unsigned long long)fb_phys);
    }

    return 0;
}

void virtio_gpu_flush_display(void) {
    if (!g_framebuffer_guest || g_fb_width == 0 || g_fb_height == 0) {
        return;
    }

    /* Transfer framebuffer data to host and flush */
    virtio_gpu_transfer_to_host_2d(RESOURCE_ID_FB, g_fb_width, g_fb_height);
    virtio_gpu_resource_flush(RESOURCE_ID_FB, g_fb_width, g_fb_height);
}
#else /* !__x86_64__ (ARM64) */
/**
 * ARM64 VirtIO GPU implementation using PCI ECAM
 */

#include <platform/arm64/pci_ecam.h>

/* ARM64 device state */
static volatile uint8_t *g_common_cfg_arm = NULL;
static volatile uint8_t *g_notify_base_arm = NULL;
static uint32_t g_notify_off_multiplier_arm = 0;
static uint16_t g_queue_notify_off_arm = 0;
static volatile uint8_t *g_framebuffer_arm = NULL;
static struct virtio_desc *g_desc_table_arm = NULL;
static struct virtio_avail *g_avail_arm = NULL;
static struct virtio_used *g_used_arm = NULL;
static volatile uint8_t *g_cmd_buffer_arm = NULL;
static volatile uint8_t *g_resp_buffer_arm = NULL;
static uint32_t g_fb_width_arm = 0, g_fb_height_arm = 0;
static size_t g_fb_size_arm = 0;
static uint16_t g_cmd_idx_arm = 0;
static uint8_t g_virtio_bus = 0, g_virtio_slot = 0;

/* Buffer sizes for ARM64 */
#define CMD_BUFFER_SIZE 4096
#define RESP_BUFFER_SIZE 4096

/* ARM64 common config register access */
static inline uint8_t arm64_virtio_common_read8(uint16_t offset) {
    if (!g_common_cfg_arm) return 0;
    __asm__ volatile("dsb sy" ::: "memory");
    uint8_t val = *(volatile uint8_t *)(g_common_cfg_arm + offset);
    __asm__ volatile("dsb sy" ::: "memory");
    return val;
}

static inline void arm64_virtio_common_write8(uint16_t offset, uint8_t value) {
    if (!g_common_cfg_arm) return;
    __asm__ volatile("dsb sy" ::: "memory");
    *(volatile uint8_t *)(g_common_cfg_arm + offset) = value;
    __asm__ volatile("dsb sy" ::: "memory");
}

static inline uint16_t arm64_virtio_common_read16(uint16_t offset) {
    if (!g_common_cfg_arm) return 0;
    __asm__ volatile("dsb sy" ::: "memory");
    uint16_t val = *(volatile uint16_t *)(g_common_cfg_arm + offset);
    __asm__ volatile("dsb sy" ::: "memory");
    return val;
}

static inline void arm64_virtio_common_write16(uint16_t offset, uint16_t value) {
    if (!g_common_cfg_arm) return;
    __asm__ volatile("dsb sy" ::: "memory");
    *(volatile uint16_t *)(g_common_cfg_arm + offset) = value;
    __asm__ volatile("dsb sy" ::: "memory");
}

static inline uint32_t arm64_virtio_common_read32(uint16_t offset) {
    if (!g_common_cfg_arm) return 0;
    __asm__ volatile("dsb sy" ::: "memory");
    uint32_t val = *(volatile uint32_t *)(g_common_cfg_arm + offset);
    __asm__ volatile("dsb sy" ::: "memory");
    return val;
}

static inline void arm64_virtio_common_write32(uint16_t offset, uint32_t value) {
    if (!g_common_cfg_arm) return;
    __asm__ volatile("dsb sy" ::: "memory");
    *(volatile uint32_t *)(g_common_cfg_arm + offset) = value;
    __asm__ volatile("dsb sy" ::: "memory");
}

static inline void arm64_virtio_common_write64(uint16_t offset, uint64_t value) {
    if (!g_common_cfg_arm) return;
    __asm__ volatile("dsb sy" ::: "memory");
    *(volatile uint64_t *)(g_common_cfg_arm + offset) = value;
    __asm__ volatile("dsb sy" ::: "memory");
}

static void arm64_virtio_gpu_submit_command(const void *cmd, size_t cmd_size) {
    if (!g_desc_table_arm || !g_avail_arm || !g_cmd_buffer_arm || !g_resp_buffer_arm) {
        fut_printf("[VIRTIO-GPU] ARM64: Command queue not initialized\n");
        return;
    }

    if (cmd_size > CMD_BUFFER_SIZE) {
        fut_printf("[VIRTIO-GPU] ARM64: Command too large\n");
        return;
    }

    /* Copy command to buffer */
    memcpy((void *)g_cmd_buffer_arm, cmd, cmd_size);
    memset((void *)g_resp_buffer_arm, 0, RESP_BUFFER_SIZE);

    /* Create descriptor chain */
    uint16_t cmd_desc_idx = (g_cmd_idx_arm * 2) % VIRTIO_RING_SIZE;
    uint16_t resp_desc_idx = (g_cmd_idx_arm * 2 + 1) % VIRTIO_RING_SIZE;

    uint64_t cmd_phys = (uint64_t)g_cmd_buffer_arm;
    uint64_t resp_phys = (uint64_t)g_resp_buffer_arm;

    g_desc_table_arm[cmd_desc_idx].addr = cmd_phys;
    g_desc_table_arm[cmd_desc_idx].len = cmd_size;
    g_desc_table_arm[cmd_desc_idx].flags = VIRTQ_DESC_F_NEXT;
    g_desc_table_arm[cmd_desc_idx].next = resp_desc_idx;

    g_desc_table_arm[resp_desc_idx].addr = resp_phys;
    g_desc_table_arm[resp_desc_idx].len = RESP_BUFFER_SIZE;
    g_desc_table_arm[resp_desc_idx].flags = VIRTQ_DESC_F_WRITE;
    g_desc_table_arm[resp_desc_idx].next = 0;

    fut_printf("[VIRTIO-GPU] ARM64: Descriptor chain: cmd[%u]={addr=0x%llx len=%lu flags=0x%x next=%u} resp[%u]={addr=0x%llx len=%u flags=0x%x}\n",
               cmd_desc_idx, cmd_phys, (unsigned long)cmd_size, g_desc_table_arm[cmd_desc_idx].flags, g_desc_table_arm[cmd_desc_idx].next,
               resp_desc_idx, resp_phys, RESP_BUFFER_SIZE, g_desc_table_arm[resp_desc_idx].flags);

    uint16_t old_avail_idx = g_avail_arm->idx;
    uint16_t avail_idx = old_avail_idx % VIRTIO_RING_SIZE;
    g_avail_arm->ring[avail_idx] = cmd_desc_idx;
    __sync_synchronize();
    g_avail_arm->idx++;

    fut_printf("[VIRTIO-GPU] ARM64: Avail ring: old_idx=%u new_idx=%u ring[%u]=%u\n",
               old_avail_idx, g_avail_arm->idx, avail_idx, cmd_desc_idx);

    /* Notify device using VirtIO 1.0 specification:
     * notify_addr = notify_base + (queue_notify_off * notify_off_multiplier) */
    if (g_notify_base_arm) {
        volatile uint16_t *notify_addr = (volatile uint16_t *)(
            g_notify_base_arm + (g_queue_notify_off_arm * g_notify_off_multiplier_arm)
        );
        fut_printf("[VIRTIO-GPU] ARM64: Notifying at addr=0x%lx (base=0x%lx offset=%u mult=%u)\n",
                   (unsigned long)notify_addr, (unsigned long)g_notify_base_arm,
                   g_queue_notify_off_arm, g_notify_off_multiplier_arm);
        __asm__ volatile("dsb sy" ::: "memory");
        *notify_addr = 0;  /* Write queue index (control queue = 0) */
        __asm__ volatile("dsb sy" ::: "memory");
    } else {
        fut_printf("[VIRTIO-GPU] ARM64: ERROR: Cannot notify - notify_base is NULL\n");
    }

    /* Wait for response */
    uint16_t last_used_idx = g_used_arm->idx;
    fut_printf("[VIRTIO-GPU] ARM64: Waiting for response, used.idx=%u (expecting %u)\n",
               last_used_idx, (uint16_t)(last_used_idx + 1));

    int timeout = 1000000;
    while (g_used_arm->idx == last_used_idx && timeout > 0) {
        __sync_synchronize();
        timeout--;
    }

    fut_printf("[VIRTIO-GPU] ARM64: After wait: used.idx=%u (was %u), timeout_remaining=%d\n",
               g_used_arm->idx, last_used_idx, timeout);

    if (timeout > 0) {
        struct virtio_gpu_ctrl_hdr *resp = (struct virtio_gpu_ctrl_hdr *)g_resp_buffer_arm;
        fut_printf("[VIRTIO-GPU] ARM64: Cmd type=%u response=0x%x\n",
                   ((struct virtio_gpu_ctrl_hdr *)cmd)->type, resp->type);
    } else {
        fut_printf("[VIRTIO-GPU] ARM64: Cmd type=%u TIMEOUT (used ring not updated by device)\n",
                   ((struct virtio_gpu_ctrl_hdr *)cmd)->type);
    }

    g_cmd_idx_arm++;
}

static int arm64_virtio_gpu_resource_create_2d(uint32_t resource_id, uint32_t width, uint32_t height) {
    struct virtio_gpu_resource_create_2d cmd = {
        .hdr = {.type = VIRTIO_GPU_CMD_RESOURCE_CREATE_2D, .flags = 0, .fence_id = 0, .ctx_id = 0, .ring_idx = 0},
        .resource_id = resource_id,
        .format = VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM,
        .width = width,
        .height = height,
    };
    fut_printf("[VIRTIO-GPU] ARM64: Creating 2D resource %u (%ux%u)\n", resource_id, width, height);
    arm64_virtio_gpu_submit_command(&cmd, sizeof(cmd));
    return 0;
}

static int arm64_virtio_gpu_resource_attach_backing(uint32_t resource_id, uint64_t fb_phys, size_t fb_size) {
    struct virtio_gpu_resource_attach_backing cmd = {
        .hdr = {.type = VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING, .flags = 0, .fence_id = 0, .ctx_id = 0, .ring_idx = 0},
        .resource_id = resource_id,
        .nr_entries = 1,
        .entries[0] = {.addr = fb_phys, .length = fb_size, .padding = 0},
    };
    fut_printf("[VIRTIO-GPU] ARM64: Attaching backing: resource=%u phys=0x%llx size=0x%zx\n",
               resource_id, (unsigned long long)fb_phys, fb_size);
    arm64_virtio_gpu_submit_command(&cmd, sizeof(cmd));
    return 0;
}

static int arm64_virtio_gpu_set_scanout(uint32_t scanout_id, uint32_t resource_id, uint32_t width, uint32_t height) {
    struct virtio_gpu_set_scanout cmd = {
        .hdr = {.type = VIRTIO_GPU_CMD_SET_SCANOUT, .flags = 0, .fence_id = 0, .ctx_id = 0, .ring_idx = 0},
        .r = {.x = 0, .y = 0, .width = width, .height = height},
        .scanout_id = scanout_id,
        .resource_id = resource_id,
    };
    fut_printf("[VIRTIO-GPU] ARM64: Setting scanout: id=%u resource=%u %ux%u\n",
               scanout_id, resource_id, width, height);
    arm64_virtio_gpu_submit_command(&cmd, sizeof(cmd));
    return 0;
}

static int arm64_virtio_gpu_transfer_to_host_2d(uint32_t resource_id, uint32_t width, uint32_t height) {
    struct virtio_gpu_transfer_to_host_2d cmd = {
        .hdr = {.type = VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D, .flags = 0, .fence_id = 0, .ctx_id = 0, .ring_idx = 0},
        .offset = 0,
        .width = width,
        .height = height,
        .x = 0,
        .y = 0,
        .resource_id = resource_id,
        .padding = 0,
    };
    fut_printf("[VIRTIO-GPU] ARM64: Transferring to host: resource=%u %ux%u\n", resource_id, width, height);
    arm64_virtio_gpu_submit_command(&cmd, sizeof(cmd));
    return 0;
}

static int arm64_virtio_gpu_resource_flush(uint32_t resource_id, uint32_t width, uint32_t height) {
    struct virtio_gpu_resource_flush cmd = {
        .hdr = {.type = VIRTIO_GPU_CMD_RESOURCE_FLUSH, .flags = 0, .fence_id = 0, .ctx_id = 0, .ring_idx = 0},
        .resource_id = resource_id,
        .x = 0,
        .y = 0,
        .width = width,
        .height = height,
    };
    fut_printf("[VIRTIO-GPU] ARM64: Flushing resource: id=%u %ux%u\n", resource_id, width, height);
    arm64_virtio_gpu_submit_command(&cmd, sizeof(cmd));
    return 0;
}

int virtio_gpu_init_arm64_pci(uint8_t bus, uint8_t dev, uint8_t func, uint64_t *out_fb_phys, uint32_t width, uint32_t height) {
    fut_printf("[VIRTIO-GPU] ARM64: Initializing VirtIO GPU driver at PCI %u:%u.%u (%ux%u)\n",
               bus, dev, func, width, height);

    g_fb_width_arm = width;
    g_fb_height_arm = height;
    g_fb_size_arm = width * height * 4;

    /* Use provided PCI device location */
    g_virtio_bus = bus;
    g_virtio_slot = dev;

    fut_printf("[VIRTIO-GPU] ARM64: Using device at bus=%u dev=%u func=%u\n", bus, dev, func);

    /* Enable bus master and memory space */
    uint32_t cmd = arm64_pci_read32(g_virtio_bus, g_virtio_slot, 0, 0x04);
    cmd |= 0x0006;
    arm64_pci_write32(g_virtio_bus, g_virtio_slot, 0, 0x04, cmd);

    /* Scan PCI capabilities to find VirtIO 1.0 structures */
    uint8_t cap_ptr = arm64_pci_read8(g_virtio_bus, g_virtio_slot, 0, 0x34);
    fut_printf("[VIRTIO-GPU] ARM64: Scanning capabilities from offset 0x%02x\n", cap_ptr);

    while (cap_ptr != 0) {
        uint8_t cap_id = arm64_pci_read8(g_virtio_bus, g_virtio_slot, 0, cap_ptr);
        uint8_t cap_next = arm64_pci_read8(g_virtio_bus, g_virtio_slot, 0, cap_ptr + 1);

        if (cap_id == PCI_CAP_ID_VNDR) {
            uint8_t cfg_type = arm64_pci_read8(g_virtio_bus, g_virtio_slot, 0, cap_ptr + 3);
            uint8_t bar = arm64_pci_read8(g_virtio_bus, g_virtio_slot, 0, cap_ptr + 4);
            uint32_t offset = arm64_pci_read32(g_virtio_bus, g_virtio_slot, 0, cap_ptr + 8);

            fut_printf("[VIRTIO-GPU] ARM64: Found VirtIO cap: type=%u bar=%u offset=0x%x\n", cfg_type, bar, offset);

            if (bar < 6) {
                uint64_t bar_addr = arm64_pci_get_bar(g_virtio_bus, g_virtio_slot, 0, bar);
                fut_printf("[VIRTIO-GPU] ARM64:   BAR%u current address: 0x%llx\n", bar, (unsigned long long)bar_addr);

                if (bar_addr == 0) {
                    bar_addr = arm64_pci_assign_bar(g_virtio_bus, g_virtio_slot, 0, bar);
                    fut_printf("[VIRTIO-GPU] ARM64:   Assigned BAR%u address: 0x%llx\n", bar, (unsigned long long)bar_addr);
                }

                if (bar_addr != 0) {
                    volatile uint8_t *cap_addr = (volatile uint8_t *)(bar_addr + offset);
                    fut_printf("[VIRTIO-GPU] ARM64:   Final cap address: 0x%lx (BAR 0x%llx + offset 0x%x)\n",
                               (unsigned long)cap_addr, (unsigned long long)bar_addr, offset);

                    switch (cfg_type) {
                        case VIRTIO_PCI_CAP_COMMON_CFG:
                            g_common_cfg_arm = cap_addr;
                            fut_printf("[VIRTIO-GPU] ARM64: *** Common config registered at 0x%lx ***\n", (unsigned long)cap_addr);
                            break;
                        case VIRTIO_PCI_CAP_NOTIFY_CFG:
                            g_notify_base_arm = cap_addr;
                            /* Read notify_off_multiplier from capability structure (offset 16) */
                            g_notify_off_multiplier_arm = arm64_pci_read32(g_virtio_bus, g_virtio_slot, 0, cap_ptr + 16);
                            fut_printf("[VIRTIO-GPU] ARM64: *** Notify base registered at 0x%lx, multiplier=%u ***\n",
                                       (unsigned long)cap_addr, g_notify_off_multiplier_arm);
                            break;
                        default:
                            fut_printf("[VIRTIO-GPU] ARM64:   (Other capability type %u - ignoring)\n", cfg_type);
                            break;
                    }
                } else {
                    fut_printf("[VIRTIO-GPU] ARM64:   ERROR: Failed to get/assign BAR%u address\n", bar);
                }
            } else {
                fut_printf("[VIRTIO-GPU] ARM64:   WARNING: Invalid BAR number %u\n", bar);
            }
        }

        cap_ptr = cap_next;
    }

    if (!g_common_cfg_arm) {
        fut_printf("[VIRTIO-GPU] ARM64: Common config not found\n");
        return -1;
    }

    /* Verify PCI command register before MMIO access */
    uint32_t cmd_check = arm64_pci_read32(g_virtio_bus, g_virtio_slot, 0, 0x04);
    fut_printf("[VIRTIO-GPU] ARM64: PCI Command register = 0x%x (bit1=mem_space bit2=bus_master)\n", cmd_check);
    if (!(cmd_check & 0x02)) {
        fut_printf("[VIRTIO-GPU] ARM64: WARNING: Memory space access not enabled in PCI command register!\n");
    }

    /* Verify the BAR was actually written to the device by reading it back */
    uint32_t bar4_low = arm64_pci_read32(g_virtio_bus, g_virtio_slot, 0, 0x20);  /* BAR4 at offset 0x10 + (4*4) */
    uint32_t bar4_high = arm64_pci_read32(g_virtio_bus, g_virtio_slot, 0, 0x24);
    uint64_t bar4_readback = ((uint64_t)bar4_high << 32) | (bar4_low & ~0xFULL);
    fut_printf("[VIRTIO-GPU] ARM64: BAR4 readback from PCI config: 0x%llx (expected 0x10004000)\n",
               (unsigned long long)bar4_readback);

    if (bar4_readback != 0x10004000) {
        fut_printf("[VIRTIO-GPU] ARM64: ERROR: BAR4 value in PCI config doesn't match! Device may not have accepted the BAR assignment.\n");
    }

    /* Verify MMIO region is accessible by testing reads */
    fut_printf("[VIRTIO-GPU] ARM64: Testing MMIO accessibility at 0x%lx...\n", (unsigned long)g_common_cfg_arm);

    /* Raw memory test - bypass all helpers to verify the address works */
    volatile uint32_t *raw_test_ptr = (volatile uint32_t *)g_common_cfg_arm;
    __asm__ volatile("dsb sy" ::: "memory");
    uint32_t raw_value = *raw_test_ptr;
    __asm__ volatile("dsb sy" ::: "memory");
    fut_printf("[VIRTIO-GPU] ARM64: Raw 32-bit read from 0x%lx = 0x%x\n", (unsigned long)g_common_cfg_arm, raw_value);

    /* Test 1: Read device features register (should NOT be 0xFFFFFFFF) */
    arm64_virtio_common_write32(VIRTIO_PCI_COMMON_DFSELECT, 0);
    uint32_t test_features = arm64_virtio_common_read32(VIRTIO_PCI_COMMON_DF);
    fut_printf("[VIRTIO-GPU] ARM64: Test read DFSELECT=0, DF=0x%x (0xFFFFFFFF means MMIO failed)\n", test_features);

    /* Test 2: Read queue size register (should be a reasonable value like 256, not 0xFFFF) */
    arm64_virtio_common_write16(VIRTIO_PCI_COMMON_Q_SELECT, 0);
    uint16_t test_queue_size = arm64_virtio_common_read16(VIRTIO_PCI_COMMON_Q_SIZE);
    fut_printf("[VIRTIO-GPU] ARM64: Test read Q_SELECT=0, Q_SIZE=%u (0xFFFF means MMIO failed)\n", test_queue_size);

    /* Test 3: Read initial status (should be 0, not 0xFF) */
    uint8_t test_status = arm64_virtio_common_read8(VIRTIO_PCI_COMMON_STATUS);
    fut_printf("[VIRTIO-GPU] ARM64: Initial status=0x%x (0xFF means MMIO failed)\n", test_status);

    if (test_features == 0xFFFFFFFF || test_queue_size == 0xFFFF || test_status == 0xFF) {
        fut_printf("[VIRTIO-GPU] ARM64: ERROR: MMIO region not accessible - all reads return 0xFF\n");
        fut_printf("[VIRTIO-GPU] ARM64: This indicates the PCI BAR is not properly mapped\n");
        return -1;
    }

    fut_printf("[VIRTIO-GPU] ARM64: MMIO accessibility verified - proceeding with initialization\n");

    /* Allocate framebuffer and queues at safe physical addresses */
    uint64_t queue_phys = 0x42000000ULL;
    uint64_t fb_phys = 0x43000000ULL;
    uint64_t cmd_phys = 0x44000000ULL;
    uint64_t resp_phys = 0x44001000ULL;

    g_desc_table_arm = (struct virtio_desc *)queue_phys;
    g_avail_arm = (struct virtio_avail *)(queue_phys + VIRTIO_RING_SIZE * sizeof(struct virtio_desc));
    g_used_arm = (struct virtio_used *)(queue_phys + VIRTIO_RING_SIZE * sizeof(struct virtio_desc) + sizeof(struct virtio_avail));
    g_framebuffer_arm = (volatile uint8_t *)fb_phys;
    g_cmd_buffer_arm = (volatile uint8_t *)cmd_phys;
    g_resp_buffer_arm = (volatile uint8_t *)resp_phys;

    memset((void *)g_desc_table_arm, 0, VIRTIO_RING_SIZE * sizeof(struct virtio_desc));
    memset((void *)g_avail_arm, 0, sizeof(struct virtio_avail));
    memset((void *)g_used_arm, 0, sizeof(struct virtio_used));
    memset((void *)g_framebuffer_arm, 0x00, g_fb_size_arm);  /* Clear to black - userspace will draw content */

    fut_printf("[VIRTIO-GPU] ARM64: Allocated queues at 0x%llx, FB at 0x%llx\n",
               (unsigned long long)queue_phys, (unsigned long long)fb_phys);

    /* VirtIO device initialization */
    arm64_virtio_common_write8(VIRTIO_PCI_COMMON_STATUS, VIRTIO_CONFIG_S_ACKNOWLEDGE);
    arm64_virtio_common_write8(VIRTIO_PCI_COMMON_STATUS,
                                arm64_virtio_common_read8(VIRTIO_PCI_COMMON_STATUS) | VIRTIO_CONFIG_S_DRIVER);

    /* Feature negotiation */
    arm64_virtio_common_write32(VIRTIO_PCI_COMMON_DFSELECT, 0);
    uint32_t features = arm64_virtio_common_read32(VIRTIO_PCI_COMMON_DF);
    arm64_virtio_common_write32(VIRTIO_PCI_COMMON_GFSELECT, 0);
    arm64_virtio_common_write32(VIRTIO_PCI_COMMON_GF, features);

    arm64_virtio_common_write8(VIRTIO_PCI_COMMON_STATUS,
                                arm64_virtio_common_read8(VIRTIO_PCI_COMMON_STATUS) | VIRTIO_CONFIG_S_FEATURES_OK);

    /* Verify FEATURES_OK was accepted by device */
    uint8_t status = arm64_virtio_common_read8(VIRTIO_PCI_COMMON_STATUS);
    if (!(status & VIRTIO_CONFIG_S_FEATURES_OK)) {
        fut_printf("[VIRTIO-GPU] ARM64: ERROR: Device rejected feature negotiation (status=0x%x)\n", status);
        return -1;
    }
    fut_printf("[VIRTIO-GPU] ARM64: Feature negotiation accepted, status=0x%x\n", status);

    /* Setup control queue */
    arm64_virtio_common_write16(VIRTIO_PCI_COMMON_Q_SELECT, 0);
    arm64_virtio_common_write16(VIRTIO_PCI_COMMON_Q_SIZE, VIRTIO_RING_SIZE);

    /* Calculate physical addresses for ring structures */
    uint64_t avail_phys = queue_phys + VIRTIO_RING_SIZE * sizeof(struct virtio_desc);
    uint64_t used_phys = queue_phys + VIRTIO_RING_SIZE * sizeof(struct virtio_desc) + sizeof(struct virtio_avail);

    arm64_virtio_common_write64(VIRTIO_PCI_COMMON_Q_DESCLO, queue_phys);
    arm64_virtio_common_write64(VIRTIO_PCI_COMMON_Q_AVAILLO, avail_phys);
    arm64_virtio_common_write64(VIRTIO_PCI_COMMON_Q_USEDLO, used_phys);

    fut_printf("[VIRTIO-GPU] ARM64: Queue 0 addresses: desc=0x%llx avail=0x%llx used=0x%llx size=%u\n",
               (unsigned long long)queue_phys,
               (unsigned long long)avail_phys,
               (unsigned long long)used_phys,
               VIRTIO_RING_SIZE);

    arm64_virtio_common_write16(VIRTIO_PCI_COMMON_Q_ENABLE, 1);

    /* Read queue notify offset for calculating notify address */
    g_queue_notify_off_arm = arm64_virtio_common_read16(VIRTIO_PCI_COMMON_Q_NOFF);

    /* If queue_notify_off is 0xFFFF (uninitialized), use 0 for queue 0
     * This is common - queue 0's notify address is often just notify_base itself */
    if (g_queue_notify_off_arm == 0xFFFF) {
        fut_printf("[VIRTIO-GPU] ARM64: Queue notify offset uninitialized (0xFFFF), using 0 for queue 0\n");
        g_queue_notify_off_arm = 0;
    } else {
        fut_printf("[VIRTIO-GPU] ARM64: Queue notify offset=%u\n", g_queue_notify_off_arm);
    }

    /* Set DRIVER_OK */
    arm64_virtio_common_write8(VIRTIO_PCI_COMMON_STATUS,
                                arm64_virtio_common_read8(VIRTIO_PCI_COMMON_STATUS) | VIRTIO_CONFIG_S_DRIVER_OK);

    status = arm64_virtio_common_read8(VIRTIO_PCI_COMMON_STATUS);
    fut_printf("[VIRTIO-GPU] ARM64: Device initialization complete, final status=0x%x\n", status);

    /* Send VirtIO GPU display setup commands */
    fut_printf("[VIRTIO-GPU] ARM64: Sending display setup commands...\n");

    arm64_virtio_gpu_resource_create_2d(RESOURCE_ID_FB, width, height);
    arm64_virtio_gpu_resource_attach_backing(RESOURCE_ID_FB, fb_phys, g_fb_size_arm);
    arm64_virtio_gpu_set_scanout(SCANOUT_ID, RESOURCE_ID_FB, width, height);  /* CRITICAL: This tells QEMU what to display */
    arm64_virtio_gpu_transfer_to_host_2d(RESOURCE_ID_FB, width, height);
    arm64_virtio_gpu_resource_flush(RESOURCE_ID_FB, width, height);

    fut_printf("[VIRTIO-GPU] ARM64: Display setup complete\n");

    if (out_fb_phys) {
        *out_fb_phys = fb_phys;
        fut_printf("[VIRTIO-GPU] ARM64: Returning framebuffer phys=0x%llx\n", (unsigned long long)fb_phys);
    }

    return 0;
}

void virtio_gpu_flush_display(void) {
    if (!g_framebuffer_arm || g_fb_width_arm == 0 || g_fb_height_arm == 0) {
        return;
    }
    arm64_virtio_gpu_transfer_to_host_2d(RESOURCE_ID_FB, g_fb_width_arm, g_fb_height_arm);
    arm64_virtio_gpu_resource_flush(RESOURCE_ID_FB, g_fb_width_arm, g_fb_height_arm);
}
#endif /* __x86_64__ */
