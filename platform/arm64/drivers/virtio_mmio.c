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
    extern phys_addr_t pmap_virt_to_phys(const void *virt);
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

    /* Allocate queue memory (descriptor, available, and used rings) */
    size_t desc_size = sizeof(struct virtq_desc) * queue_size;
    size_t avail_size = sizeof(struct virtq_avail) + sizeof(uint16_t) * queue_size + sizeof(uint16_t);
    size_t used_size = sizeof(struct virtq_used) + sizeof(struct virtq_used_elem) * queue_size + sizeof(uint16_t);

    /* Allocate contiguous pages (already mapped in kernel virtual address space) */
    size_t total_size = desc_size + avail_size + used_size;
    size_t total_pages = (total_size + 4095) / 4096;

    void *desc_virt = fut_malloc_pages(total_pages);
    if (!desc_virt) {
        return -1;
    }

    /* Zero the memory */
    memset(desc_virt, 0, total_pages * 4096);

    /* Convert virtual addresses to physical addresses for device */
    phys_addr_t desc_phys = pmap_virt_to_phys(desc_virt);
    phys_addr_t avail_phys = desc_phys + desc_size;
    phys_addr_t used_phys = desc_phys + desc_size + avail_size;

    /* Setup queue pointers (virtual addresses for CPU access) */
    dev->desc = (struct virtq_desc *)desc_virt;
    dev->avail = (struct virtq_avail *)((uintptr_t)desc_virt + desc_size);
    dev->used = (struct virtq_used *)((uintptr_t)desc_virt + desc_size + avail_size);

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
    (void)dtb_ptr;

    fut_printf("[virtio-mmio] Probing QEMU virt MMIO device slots...\n");

    /* Probe VirtIO MMIO devices at QEMU virt machine fixed addresses.
     * QEMU virt uses addresses 0x0a000000 + n*0x200 for up to 32 devices.
     *
     * TODO: Parse device tree to discover device addresses dynamically
     * instead of hardcoding QEMU virt addresses. This would allow:
     *   - Portable boot on other ARM64 platforms
     *   - Discovery of non-contiguous device ranges
     *   - Dynamic IRQ mapping from FDT interrupt properties
     */
    for (int i = 0; i < 32; i++) {
        uint64_t base = 0x0a000000 + (i * 0x200);
        uint32_t irq = 16 + i;  /* IRQs 16-47 (0x10-0x2f in device tree) */

        virtio_mmio_probe_device(base, irq);
        /* Continue scanning all slots - devices may not be contiguous */
    }

    fut_printf("[virtio-mmio] Found %d virtio device(s)\n", virtio_device_count);
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
