/* virtio_mmio.c - VirtIO MMIO Transport Layer for ARM64
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements VirtIO 1.0 MMIO transport for ARM64 QEMU virt machine.
 * Provides block, network, and GPU device support via memory-mapped I/O.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <platform/platform.h>
#include <platform/arm64/dtb.h>
#include <platform/arm64/memory/pmap.h>

/* ============================================================
 *   VirtIO MMIO Register Offsets (VirtIO 1.0 Spec)
 * ============================================================ */

#define VIRTIO_MMIO_MAGIC_VALUE         0x000  /* 0x74726976 ('virt') */
#define VIRTIO_MMIO_VERSION             0x004  /* Must be 2 for VirtIO 1.0 */
#define VIRTIO_MMIO_DEVICE_ID           0x008  /* Device type */
#define VIRTIO_MMIO_VENDOR_ID           0x00c  /* Vendor ID */
#define VIRTIO_MMIO_DEVICE_FEATURES     0x010  /* Device features (32-bit) */
#define VIRTIO_MMIO_DEVICE_FEATURES_SEL 0x014  /* Feature selector */
#define VIRTIO_MMIO_DRIVER_FEATURES     0x020  /* Driver features */
#define VIRTIO_MMIO_DRIVER_FEATURES_SEL 0x024  /* Driver feature selector */
#define VIRTIO_MMIO_QUEUE_SEL           0x030  /* Queue selector */
#define VIRTIO_MMIO_QUEUE_NUM_MAX       0x034  /* Max queue size */
#define VIRTIO_MMIO_QUEUE_NUM           0x038  /* Current queue size */
#define VIRTIO_MMIO_QUEUE_READY         0x044  /* Queue ready flag */
#define VIRTIO_MMIO_QUEUE_NOTIFY        0x050  /* Queue notification */
#define VIRTIO_MMIO_INTERRUPT_STATUS    0x060  /* Interrupt status */
#define VIRTIO_MMIO_INTERRUPT_ACK       0x064  /* Interrupt acknowledge */
#define VIRTIO_MMIO_STATUS              0x070  /* Device status */
#define VIRTIO_MMIO_QUEUE_DESC_LOW      0x080  /* Descriptor ring PA (low 32 bits) */
#define VIRTIO_MMIO_QUEUE_DESC_HIGH     0x084  /* Descriptor ring PA (high 32 bits) */
#define VIRTIO_MMIO_QUEUE_DRIVER_LOW    0x090  /* Available ring PA (low 32 bits) */
#define VIRTIO_MMIO_QUEUE_DRIVER_HIGH   0x094  /* Available ring PA (high 32 bits) */
#define VIRTIO_MMIO_QUEUE_DEVICE_LOW    0x0a0  /* Used ring PA (low 32 bits) */
#define VIRTIO_MMIO_QUEUE_DEVICE_HIGH   0x0a4  /* Used ring PA (high 32 bits) */
#define VIRTIO_MMIO_CONFIG_GENERATION   0x0fc  /* Configuration atomicity */
#define VIRTIO_MMIO_CONFIG              0x100  /* Device-specific configuration */

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

/* VirtIO Status Bits */
#define VIRTIO_STATUS_ACKNOWLEDGE   1
#define VIRTIO_STATUS_DRIVER        2
#define VIRTIO_STATUS_DRIVER_OK     4
#define VIRTIO_STATUS_FEATURES_OK   8
#define VIRTIO_STATUS_FAILED        128

/* VirtIO Interrupt Flags */
#define VIRTIO_MMIO_INT_VRING       (1 << 0)
#define VIRTIO_MMIO_INT_CONFIG      (1 << 1)

/* Descriptor flags */
#define VIRTQ_DESC_F_NEXT       1  /* Buffer continues via next */
#define VIRTQ_DESC_F_WRITE      2  /* Buffer is write-only (device writes) */
#define VIRTQ_DESC_F_INDIRECT   4  /* Buffer contains list of descriptors */

/* Maximum queue size */
#define VIRTIO_QUEUE_MAX_SIZE   256

/* ============================================================
 *   VirtIO Data Structures (Virtqueue Split Format)
 * ============================================================ */

/* Descriptor ring entry */
struct virtq_desc {
    uint64_t addr;   /* Physical address */
    uint32_t len;    /* Length */
    uint16_t flags;  /* Flags */
    uint16_t next;   /* Next descriptor index (if VIRTQ_DESC_F_NEXT) */
} __attribute__((packed));

/* Available ring (driver -> device) */
struct virtq_avail {
    uint16_t flags;
    uint16_t idx;
    uint16_t ring[];  /* Variable length: ring[queue_size] */
    /* uint16_t used_event follows ring[] but we don't use event_idx yet */
} __attribute__((packed));

/* Used ring element */
struct virtq_used_elem {
    uint32_t id;   /* Index of descriptor chain */
    uint32_t len;  /* Total bytes written */
} __attribute__((packed));

/* Used ring (device -> driver) */
struct virtq_used {
    uint16_t flags;
    uint16_t idx;
    struct virtq_used_elem ring[];  /* Variable length: ring[queue_size] */
    /* uint16_t avail_event follows ring[] but we don't use event_idx yet */
} __attribute__((packed));

/* ============================================================
 *   VirtIO Device State
 * ============================================================ */

typedef struct {
    uint64_t base_addr;       /* MMIO base address (virtual) */
    uint32_t irq;             /* GIC IRQ number */
    uint32_t device_type;     /* VirtIO device type */
    bool in_use;              /* Device claimed */

    /* Virtqueue state (single queue for now) */
    uint32_t queue_size;
    struct virtq_desc *desc;
    struct virtq_avail *avail;
    struct virtq_used *used;
    uint16_t last_used_idx;   /* Last processed used index */
    uint16_t next_free_desc;  /* Next free descriptor */

    /* Physical addresses for queue */
    uint64_t desc_phys;
    uint64_t avail_phys;
    uint64_t used_phys;
} virtio_mmio_device_t;

#define MAX_VIRTIO_DEVICES  32

static virtio_mmio_device_t virtio_devices[MAX_VIRTIO_DEVICES];
static int virtio_device_count = 0;

/* ============================================================
 *   MMIO Register Access Helpers
 * ============================================================ */

static inline uint32_t virtio_mmio_read32(uint64_t base, uint32_t offset) {
    volatile uint32_t *reg = (volatile uint32_t *)(base + offset);
    return *reg;
}

static inline void virtio_mmio_write32(uint64_t base, uint32_t offset, uint32_t value) {
    volatile uint32_t *reg = (volatile uint32_t *)(base + offset);
    *reg = value;
    __asm__ volatile("dsb sy" ::: "memory");  /* Data sync barrier */
}

static inline void virtio_mmio_write64(uint64_t base, uint32_t offset_low, uint64_t value) {
    virtio_mmio_write32(base, offset_low, (uint32_t)(value & 0xFFFFFFFF));
    virtio_mmio_write32(base, offset_low + 4, (uint32_t)(value >> 32));
}

/* ============================================================
 *   VirtIO Device Initialization
 * ============================================================ */

/**
 * Reset a VirtIO device.
 */
static void virtio_mmio_reset(virtio_mmio_device_t *dev) {
    virtio_mmio_write32(dev->base_addr, VIRTIO_MMIO_STATUS, 0);
    __asm__ volatile("dsb sy" ::: "memory");
}

/**
 * Set device status bits.
 */
static void virtio_mmio_set_status(virtio_mmio_device_t *dev, uint8_t status) {
    uint8_t current = virtio_mmio_read32(dev->base_addr, VIRTIO_MMIO_STATUS);
    virtio_mmio_write32(dev->base_addr, VIRTIO_MMIO_STATUS, current | status);
}

/**
 * Initialize a single virtqueue.
 */
static int virtio_mmio_init_queue(virtio_mmio_device_t *dev, uint32_t queue_idx, uint32_t queue_size) {
    extern void *fut_malloc_pages(size_t num_pages);
    extern void fut_free_pages(void *ptr, size_t num_pages);
    extern phys_addr_t pmap_virt_to_phys(uintptr_t virt);
    extern void *memset(void *, int, size_t);

    /* Select queue */
    virtio_mmio_write32(dev->base_addr, VIRTIO_MMIO_QUEUE_SEL, queue_idx);

    /* Check max queue size */
    uint32_t max_size = virtio_mmio_read32(dev->base_addr, VIRTIO_MMIO_QUEUE_NUM_MAX);
    if (max_size == 0) {
        return -1;  /* Queue not available */
    }
    if (queue_size > max_size) {
        queue_size = max_size;
    }
    if (queue_size == 0) {
        return -1;  /* Queue size must be at least 1 */
    }

    /* Allocate queue memory (descriptor, available, and used rings) */
    size_t desc_size = sizeof(struct virtq_desc) * queue_size;
    size_t avail_size = sizeof(struct virtq_avail) + sizeof(uint16_t) * queue_size + sizeof(uint16_t);
    size_t used_size = sizeof(struct virtq_used) + sizeof(struct virtq_used_elem) * queue_size + sizeof(uint16_t);

    /* Allocate contiguous pages — used ring needs page alignment */
    size_t used_offset = (desc_size + avail_size + 4095) & ~4095UL;
    size_t total_size = used_offset + used_size;
    size_t total_pages = (total_size + 4095) / 4096;

    void *desc_virt = fut_malloc_pages(total_pages);
    if (!desc_virt) {
        return -1;
    }

    /* Zero the memory */
    memset(desc_virt, 0, total_pages * 4096);

    /* Convert virtual addresses to physical addresses for device.
     * CRITICAL: VirtIO MMIO requires used ring to be page-aligned (or at least
     * aligned to VIRTQ_USED_ALIGN=4 in VirtIO 1.0, but QEMU may require 4096). */
    phys_addr_t desc_phys = pmap_virt_to_phys((uintptr_t)desc_virt);
    phys_addr_t avail_phys = desc_phys + desc_size;
    /* Align used ring to page boundary for reliable MMIO operation */
    phys_addr_t used_phys = (desc_phys + desc_size + avail_size + 4095) & ~4095ULL;

    /* Setup queue pointers (virtual addresses for CPU access) */
    dev->desc = (struct virtq_desc *)desc_virt;
    dev->avail = (struct virtq_avail *)((uintptr_t)desc_virt + desc_size);
    /* Used ring: align to page boundary to match physical address alignment */
    uintptr_t used_virt_offset = (desc_size + avail_size + 4095) & ~4095UL;
    dev->used = (struct virtq_used *)((uintptr_t)desc_virt + used_virt_offset);

    /* Save physical addresses for device configuration */
    dev->desc_phys = desc_phys;
    dev->avail_phys = avail_phys;
    dev->used_phys = used_phys;

    dev->queue_size = queue_size;
    dev->last_used_idx = 0;
    dev->next_free_desc = 0;

    /* Initialize descriptor chain (all descriptors free) */
    for (uint32_t i = 0; i < queue_size - 1; i++) {
        dev->desc[i].next = i + 1;
    }
    dev->desc[queue_size - 1].next = 0;  /* Last wraps to 0 */

    /* Configure queue in device (device uses physical addresses) */
    virtio_mmio_write32(dev->base_addr, VIRTIO_MMIO_QUEUE_NUM, queue_size);
    virtio_mmio_write64(dev->base_addr, VIRTIO_MMIO_QUEUE_DESC_LOW, desc_phys);
    virtio_mmio_write64(dev->base_addr, VIRTIO_MMIO_QUEUE_DRIVER_LOW, avail_phys);
    virtio_mmio_write64(dev->base_addr, VIRTIO_MMIO_QUEUE_DEVICE_LOW, used_phys);
    virtio_mmio_write32(dev->base_addr, VIRTIO_MMIO_QUEUE_READY, 1);

    return 0;
}

/**
 * Probe a VirtIO MMIO device at a given address.
 */
static int virtio_mmio_probe_device(uint64_t phys_addr, uint32_t irq) {
    if (virtio_device_count >= MAX_VIRTIO_DEVICES) {
        return -1;
    }

    /* Map device registers to kernel virtual memory
     * ARM64 peripheral mapping: PA 0x00000000 -> VA 0xFFFFFF8000000000 */
    uint64_t virt_addr = 0xFFFFFF8000000000ULL + phys_addr;

    /* Check magic value */
    uint32_t magic = virtio_mmio_read32(virt_addr, VIRTIO_MMIO_MAGIC_VALUE);
    if (magic != 0x74726976) {  /* 'virt' */
        return -1;
    }

    /* Check version (1 = legacy 0.9.5, 2 = VirtIO 1.0) */
    uint32_t version = virtio_mmio_read32(virt_addr, VIRTIO_MMIO_VERSION);
    if (version < 1 || version > 2) {
        return -1;  /* Only support version 1 (legacy) and 2 (modern) */
    }

    /* Read device type */
    uint32_t device_id = virtio_mmio_read32(virt_addr, VIRTIO_MMIO_DEVICE_ID);
    if (device_id == 0) {
        /* Device ID 0 = not connected */
        return -1;
    }

    /* Register device */
    virtio_mmio_device_t *dev = &virtio_devices[virtio_device_count];
    dev->base_addr = virt_addr;
    dev->irq = irq;
    dev->device_type = device_id;
    dev->in_use = false;
    dev->queue_size = 0;

    virtio_device_count++;

    /* Log discovered device */
    const char *dev_name = "unknown";
    switch (device_id) {
        case VIRTIO_DEV_NET:     dev_name = "virtio-net"; break;
        case VIRTIO_DEV_BLOCK:   dev_name = "virtio-blk"; break;
        case VIRTIO_DEV_CONSOLE: dev_name = "virtio-console"; break;
        case VIRTIO_DEV_RNG:     dev_name = "virtio-rng"; break;
        case VIRTIO_DEV_GPU:     dev_name = "virtio-gpu"; break;
        case VIRTIO_DEV_INPUT:   dev_name = "virtio-input"; break;
    }

    fut_printf("[virtio-mmio] Found %s at 0x%lx (IRQ %u)\n", dev_name, phys_addr, irq);

    return 0;
}

/* ============================================================
 *   Public API
 * ============================================================ */

/**
 * Initialize VirtIO MMIO subsystem by scanning device tree.
 */
void virtio_mmio_init(uint64_t dtb_ptr) {
    fut_printf("[virtio-mmio] Initializing VirtIO MMIO subsystem...\n");

    /* Try device tree discovery first */
    bool dt_used = false;
    if (dtb_ptr && fut_dtb_validate(dtb_ptr)) {
        fut_dtb_node_t dt_nodes[MAX_VIRTIO_DEVICES];
        int dt_count = fut_dtb_find_compatible_nodes(dtb_ptr, "virtio,mmio",
                                                      dt_nodes, MAX_VIRTIO_DEVICES);

        if (dt_count > 0) {
            fut_printf("[virtio-mmio] Found %d device(s) via device tree\n", dt_count);
            dt_used = true;

            /* Probe each device found in device tree */
            for (int i = 0; i < dt_count && i < MAX_VIRTIO_DEVICES; i++) {
                virtio_mmio_probe_device(dt_nodes[i].base_addr, dt_nodes[i].irq);
            }
        }
    }

    /* Fallback to hardcoded QEMU virt addresses if device tree not available */
    if (!dt_used) {
        fut_printf("[virtio-mmio] Device tree unavailable, using hardcoded QEMU virt addresses\n");

        /* QEMU virt uses addresses 0x0a000000 + n*0x200 for up to 32 devices */
        for (int i = 0; i < 32; i++) {
            uint64_t base = 0x0a000000 + (i * 0x200);
            uint32_t irq = 16 + i;  /* IRQs 16-47 (0x10-0x2f in device tree) */

            virtio_mmio_probe_device(base, irq);
        }
    }

    fut_printf("[virtio-mmio] Discovered %d VirtIO device(s)\n", virtio_device_count);
}

/**
 * Find a virtio device by type.
 * Returns device index, or -1 if not found.
 */
int virtio_mmio_find_device(uint32_t device_type) {
    for (int i = 0; i < virtio_device_count; i++) {
        if (virtio_devices[i].device_type == device_type && !virtio_devices[i].in_use) {
            return i;
        }
    }
    return -1;
}

/* Find device regardless of in_use state (for testing) */
int virtio_mmio_find_device_any(uint32_t device_type) {
    for (int i = 0; i < virtio_device_count; i++) {
        if (virtio_devices[i].device_type == device_type) {
            return i;
        }
    }
    return -1;
}

/**
 * Claim a virtio device for use.
 */
virtio_mmio_device_t *virtio_mmio_get_device(int device_idx) {
    if (device_idx < 0 || device_idx >= virtio_device_count) {
        return NULL;
    }

    virtio_mmio_device_t *dev = &virtio_devices[device_idx];
    if (dev->in_use) {
        return NULL;
    }

    dev->in_use = true;
    return dev;
}

/**
 * Get device MMIO base address.
 */
uint64_t virtio_mmio_get_base_addr(virtio_mmio_device_t *dev) {
    return dev ? dev->base_addr : 0;
}

/**
 * Read 32-bit value from device-specific configuration space.
 */
uint32_t virtio_mmio_read_config32(virtio_mmio_device_t *dev, uint32_t offset) {
    return virtio_mmio_read32(dev->base_addr, VIRTIO_MMIO_CONFIG + offset);
}

/**
 * Read 64-bit value from device-specific configuration space.
 */
uint64_t virtio_mmio_read_config64(virtio_mmio_device_t *dev, uint32_t offset) {
    uint32_t low = virtio_mmio_read32(dev->base_addr, VIRTIO_MMIO_CONFIG + offset);
    uint32_t high = virtio_mmio_read32(dev->base_addr, VIRTIO_MMIO_CONFIG + offset + 4);
    return ((uint64_t)high << 32) | low;
}

/**
 * Initialize a VirtIO device with standard handshake.
 */
int virtio_mmio_setup_device(virtio_mmio_device_t *dev, uint32_t features, uint32_t queue_size) {
    /* Reset device */
    virtio_mmio_reset(dev);

    /* Set ACKNOWLEDGE status bit */
    virtio_mmio_set_status(dev, VIRTIO_STATUS_ACKNOWLEDGE);

    /* Set DRIVER status bit */
    virtio_mmio_set_status(dev, VIRTIO_STATUS_DRIVER);

    /* Negotiate features */
    virtio_mmio_write32(dev->base_addr, VIRTIO_MMIO_DRIVER_FEATURES_SEL, 0);
    virtio_mmio_write32(dev->base_addr, VIRTIO_MMIO_DRIVER_FEATURES, features);

    /* Set FEATURES_OK */
    virtio_mmio_set_status(dev, VIRTIO_STATUS_FEATURES_OK);

    /* Verify FEATURES_OK */
    uint8_t status = virtio_mmio_read32(dev->base_addr, VIRTIO_MMIO_STATUS);
    if (!(status & VIRTIO_STATUS_FEATURES_OK)) {
        virtio_mmio_set_status(dev, VIRTIO_STATUS_FAILED);
        return -1;
    }

    /* Initialize virtqueue */
    if (virtio_mmio_init_queue(dev, 0, queue_size) < 0) {
        virtio_mmio_set_status(dev, VIRTIO_STATUS_FAILED);
        return -1;
    }

    /* Set DRIVER_OK */
    virtio_mmio_set_status(dev, VIRTIO_STATUS_DRIVER_OK);

    return 0;
}

/**
 * Notify device of new available buffers.
 */
void virtio_mmio_notify(virtio_mmio_device_t *dev, uint32_t queue_idx) {
    virtio_mmio_write32(dev->base_addr, VIRTIO_MMIO_QUEUE_NOTIFY, queue_idx);
}

/**
 * Check if there are used buffers to process.
 */
bool virtio_mmio_has_used_buffers(virtio_mmio_device_t *dev) {
    __asm__ volatile("dsb sy" ::: "memory");
    return dev->last_used_idx != dev->used->idx;
}

/* ============================================================
 *   VirtIO Block Read (C implementation for ARM64 MMIO)
 * ============================================================ */

/* VirtIO block request header */
struct virtio_blk_req {
    uint32_t type;    /* VIRTIO_BLK_T_IN=0, VIRTIO_BLK_T_OUT=1 */
    uint32_t reserved;
    uint64_t sector;
} __attribute__((packed));

/**
 * Read sectors from a VirtIO block device using the C MMIO transport.
 * This bypasses the Rust driver for ARM64 where Rust printf is broken.
 *
 * @param dev_idx: Device index from virtio_mmio_find_device(VIRTIO_DEV_BLOCK)
 * @param sector: Starting sector (LBA)
 * @param count: Number of sectors to read
 * @param buffer: Output buffer (must be page-aligned)
 * @return: 0 on success, negative on error
 */
int virtio_mmio_blk_read(int dev_idx, uint64_t sector, uint32_t count, void *buffer) {
    extern phys_addr_t pmap_virt_to_phys(uintptr_t virt);

    if (dev_idx < 0 || dev_idx >= virtio_device_count) return -1;
    virtio_mmio_device_t *dev = &virtio_devices[dev_idx];
    if (dev->device_type != VIRTIO_DEV_BLOCK) return -1;

    /* Initialize queue if not set up (Rust driver uses its own queue) */
    if (!dev->desc) {
        fut_printf("[MMIO-BLK] Initializing C-side queue for block device\n");
        /* Reset device and do full handshake */
        virtio_mmio_reset(dev);
        virtio_mmio_set_status(dev, VIRTIO_STATUS_ACKNOWLEDGE);
        virtio_mmio_set_status(dev, VIRTIO_STATUS_DRIVER);

        /* Feature negotiation — must accept VIRTIO_F_VERSION_1 for MMIO v2 */
        virtio_mmio_write32(dev->base_addr, VIRTIO_MMIO_DEVICE_FEATURES_SEL, 0);
        uint32_t features_lo = virtio_mmio_read32(dev->base_addr, VIRTIO_MMIO_DEVICE_FEATURES);
        virtio_mmio_write32(dev->base_addr, VIRTIO_MMIO_DEVICE_FEATURES_SEL, 1);
        uint32_t features_hi = virtio_mmio_read32(dev->base_addr, VIRTIO_MMIO_DEVICE_FEATURES);
        /* Accept low features + VIRTIO_F_VERSION_1 (bit 32, in high word bit 0) */
        virtio_mmio_write32(dev->base_addr, VIRTIO_MMIO_DRIVER_FEATURES_SEL, 0);
        virtio_mmio_write32(dev->base_addr, VIRTIO_MMIO_DRIVER_FEATURES, features_lo);
        virtio_mmio_write32(dev->base_addr, VIRTIO_MMIO_DRIVER_FEATURES_SEL, 1);
        virtio_mmio_write32(dev->base_addr, VIRTIO_MMIO_DRIVER_FEATURES, features_hi | 1);
        virtio_mmio_set_status(dev, VIRTIO_STATUS_FEATURES_OK);
        (void)features_lo; (void)features_hi;

        /* Check FEATURES_OK */
        uint32_t status = virtio_mmio_read32(dev->base_addr, VIRTIO_MMIO_STATUS);
        if (!(status & VIRTIO_STATUS_FEATURES_OK)) {
            fut_printf("[MMIO-BLK] FEATURES_OK not set\n");
            return -1;
        }

        /* Setup queue */
        if (virtio_mmio_init_queue(dev, 0, 16) != 0) {
            fut_printf("[MMIO-BLK] Queue init failed\n");
            return -1;
        }

        /* Set DRIVER_OK */
        virtio_mmio_set_status(dev, VIRTIO_STATUS_DRIVER_OK);
        fut_printf("[MMIO-BLK] Device initialized, queue ready\n");
    }

    /* Allocate request header and status byte from page-aligned memory */
    static struct virtio_blk_req req __attribute__((aligned(4096)));
    static uint8_t status_byte __attribute__((aligned(4096)));

    req.type = 0;  /* VIRTIO_BLK_T_IN = read */
    req.reserved = 0;
    req.sector = sector;
    status_byte = 0xFF;

    /* Physical addresses for device DMA */
    uint64_t req_phys = pmap_virt_to_phys((uintptr_t)&req);
    uint64_t buf_phys = pmap_virt_to_phys((uintptr_t)buffer);
    uint64_t status_phys = pmap_virt_to_phys((uintptr_t)&status_byte);
    uint32_t data_len = count * 512;

    fut_printf("[MMIO-BLK] read: sector=%llu count=%u req_phys=0x%llx buf_phys=0x%llx status_phys=0x%llx\n",
               (unsigned long long)sector, count,
               (unsigned long long)req_phys, (unsigned long long)buf_phys,
               (unsigned long long)status_phys);

    /* Set up 3-descriptor chain: header → data → status */
    /* Descriptor 0: request header (device reads) */
    dev->desc[0].addr = req_phys;
    dev->desc[0].len = sizeof(struct virtio_blk_req);
    dev->desc[0].flags = VIRTQ_DESC_F_NEXT;
    dev->desc[0].next = 1;

    /* Descriptor 1: data buffer (device writes) */
    dev->desc[1].addr = buf_phys;
    dev->desc[1].len = data_len;
    dev->desc[1].flags = VIRTQ_DESC_F_WRITE | VIRTQ_DESC_F_NEXT;
    dev->desc[1].next = 2;

    /* Descriptor 2: status byte (device writes) */
    dev->desc[2].addr = status_phys;
    dev->desc[2].len = 1;
    dev->desc[2].flags = VIRTQ_DESC_F_WRITE;
    dev->desc[2].next = 0;

    /* Flush cache for DMA buffers so device sees correct data */
    __asm__ volatile("dc civac, %0" :: "r"(&req) : "memory");
    __asm__ volatile("dc civac, %0" :: "r"(&status_byte) : "memory");
    __asm__ volatile("dc civac, %0" :: "r"(buffer) : "memory");
    /* Ensure descriptors and data are visible before updating avail ring */
    __asm__ volatile("dsb sy" ::: "memory");

    /* Add to available ring */
    uint16_t avail_idx = dev->avail->idx;
    dev->avail->ring[avail_idx % dev->queue_size] = 0;  /* Descriptor chain head = 0 */
    __asm__ volatile("dsb sy" ::: "memory");
    dev->avail->idx = avail_idx + 1;
    __asm__ volatile("dsb sy" ::: "memory");

    /* Notify device — write queue index 0 to QUEUE_NOTIFY register */
    /* Verify avail ring is correct before notify */
    fut_printf("[MMIO-BLK] avail->idx=%u avail->ring[0]=%u\n",
               (unsigned)dev->avail->idx, (unsigned)dev->avail->ring[0]);
    fut_printf("[MMIO-BLK] desc[0]: addr=0x%llx len=%u flags=0x%x next=%u\n",
               (unsigned long long)dev->desc[0].addr, dev->desc[0].len,
               dev->desc[0].flags, dev->desc[0].next);

    /* Notify device */
    volatile uint32_t *notify_reg = (volatile uint32_t *)(dev->base_addr + VIRTIO_MMIO_QUEUE_NOTIFY);
    *notify_reg = 0;
    __asm__ volatile("dsb sy" ::: "memory");

    /* Read status to verify device is alive */
    uint32_t status_after = virtio_mmio_read32(dev->base_addr, VIRTIO_MMIO_STATUS);
    uint32_t isr_after = virtio_mmio_read32(dev->base_addr, VIRTIO_MMIO_INTERRUPT_STATUS);
    fut_printf("[MMIO-BLK] After notify: status=0x%x isr=0x%x\n", status_after, isr_after);

    /* Poll for completion */
    for (int i = 0; i < 1000000; i++) {
        __asm__ volatile("dsb sy" ::: "memory");
        if (dev->used->idx != dev->last_used_idx) {
            dev->last_used_idx = dev->used->idx;

            /* Check status byte */
            __asm__ volatile("dsb sy" ::: "memory");
            uint8_t final_status = *(volatile uint8_t *)&status_byte;
            fut_printf("[MMIO-BLK] completion: status=%u used_idx=%u\n",
                       (unsigned)final_status, (unsigned)dev->used->idx);

            /* Acknowledge interrupt */
            uint32_t isr = virtio_mmio_read32(dev->base_addr, VIRTIO_MMIO_INTERRUPT_STATUS);
            if (isr) {
                virtio_mmio_write32(dev->base_addr, VIRTIO_MMIO_INTERRUPT_ACK, isr);
            }

            return (final_status == 0) ? 0 : -5;
        }
        for (volatile int j = 0; j < 10; j++);
    }

    fut_printf("[MMIO-BLK] TIMEOUT: used_idx=%u last=%u\n",
               (unsigned)dev->used->idx, (unsigned)dev->last_used_idx);
    return -5;  /* Timeout */
}
