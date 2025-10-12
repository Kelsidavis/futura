// SPDX-License-Identifier: MPL-2.0
/*
 * platform/x86_64/drivers/virtio/blk.c
 *
 * Minimal virtio-blk driver wired into the async block core.
 * Targets the modern PCI (virtio 1.0) transport as implemented by QEMU.
 *
 * QEMU smoke run (512 MiB RAM, virtio-blk boot drive):
 *   qemu-system-x86_64 -serial stdio \
 *     -drive if=virtio,file=disk.img,format=raw \
 *     -m 512 -cdrom futura.iso
 *
 * References:
 *   - OASIS Virtual I/O Device (VIRTIO) Specification v1.2
 *   - Section 5.2 (Virtio Block Device)
 *   - Section 5.6 (PCI Device Discovery)
 */

#include <futura/blkdev.h>

#include <kernel/errno.h>
#include <kernel/fut_memory.h>
#include <kernel/fut_sched.h>
#include <kernel/fut_thread.h>

#include <arch/x86_64/pmap.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

extern void fut_printf(const char *fmt, ...);

#ifndef ETIMEDOUT
#define ETIMEDOUT 110
#endif

#ifndef ENOTSUP
#define ENOTSUP 95
#endif

/* -------------------------------------------------------------
 *   PCI configuration helpers (legacy I/O port mechanism)
 * ------------------------------------------------------------- */

#define PCI_CONFIG_ADDRESS 0xCF8
#define PCI_CONFIG_DATA    0xCFC

static inline void outl(uint16_t port, uint32_t value) {
    __asm__ volatile("outl %0, %1" : : "a"(value), "Nd"(port));
}

static inline uint32_t inl(uint16_t port) {
    uint32_t value;
    __asm__ volatile("inl %1, %0" : "=a"(value) : "Nd"(port));
    return value;
}

static inline void outw(uint16_t port, uint16_t value) {
    __asm__ volatile("outw %0, %1" : : "a"(value), "Nd"(port));
}

static inline uint16_t inw(uint16_t port) {
    uint16_t value;
    __asm__ volatile("inw %1, %0" : "=a"(value) : "Nd"(port));
    return value;
}

static inline void outb(uint16_t port, uint8_t value) {
    __asm__ volatile("outb %0, %1" : : "a"(value), "Nd"(port));
}

static inline uint8_t inb(uint16_t port) {
    uint8_t value;
    __asm__ volatile("inb %1, %0" : "=a"(value) : "Nd"(port));
    return value;
}

static uint32_t pci_config_read32(uint8_t bus, uint8_t device, uint8_t func, uint8_t offset) {
    uint32_t address = (uint32_t)((uint32_t)bus << 16 |
                                  (uint32_t)device << 11 |
                                  (uint32_t)func << 8 |
                                  (offset & 0xFC) |
                                  (uint32_t)0x80000000);
    outl(PCI_CONFIG_ADDRESS, address);
    return inl(PCI_CONFIG_DATA);
}

static void pci_config_write32(uint8_t bus, uint8_t device, uint8_t func, uint8_t offset, uint32_t value) {
    uint32_t address = (uint32_t)((uint32_t)bus << 16 |
                                  (uint32_t)device << 11 |
                                  (uint32_t)func << 8 |
                                  (offset & 0xFC) |
                                  (uint32_t)0x80000000);
    outl(PCI_CONFIG_ADDRESS, address);
    outl(PCI_CONFIG_DATA, value);
}

static uint16_t pci_config_read16(uint8_t bus, uint8_t device, uint8_t func, uint8_t offset) {
    uint32_t value = pci_config_read32(bus, device, func, offset);
    return (uint16_t)((value >> ((offset & 2u) * 8u)) & 0xFFFFu);
}

static void pci_config_write16(uint8_t bus, uint8_t device, uint8_t func, uint8_t offset, uint16_t value) {
    uint32_t current = pci_config_read32(bus, device, func, offset);
    uint32_t shift = (offset & 2u) * 8u;
    current &= ~(0xFFFFu << shift);
    current |= ((uint32_t)value << shift);
    pci_config_write32(bus, device, func, offset, current);
}

static uint8_t pci_config_read8(uint8_t bus, uint8_t device, uint8_t func, uint8_t offset) {
    uint32_t value = pci_config_read32(bus, device, func, offset);
    return (uint8_t)((value >> ((offset & 3u) * 8u)) & 0xFFu);
}

/* -------------------------------------------------------------
 *   Virtio PCI capability descriptors and constants
 * ------------------------------------------------------------- */

#define PCI_CAP_ID_VNDR           0x09

#define VIRTIO_PCI_CAP_COMMON_CFG 1
#define VIRTIO_PCI_CAP_NOTIFY_CFG 2
#define VIRTIO_PCI_CAP_ISR_CFG    3
#define VIRTIO_PCI_CAP_DEVICE_CFG 4

#define VIRTIO_VENDOR_ID          0x1AF4
#define VIRTIO_DEVICE_ID_BLOCK_LEGACY 0x1001
#define VIRTIO_DEVICE_ID_BLOCK_MODERN 0x1042

#define PCI_COMMAND               0x04
#define PCI_COMMAND_IO            0x1
#define PCI_COMMAND_MEMORY        0x2
#define PCI_COMMAND_BUS_MASTER    0x4

struct virtio_pci_cap {
    uint8_t cap_vndr;
    uint8_t cap_next;
    uint8_t cap_len;
    uint8_t cfg_type;
    uint8_t bar;
    uint8_t padding[3];
    uint32_t offset;
    uint32_t length;
} __attribute__((packed));

struct virtio_pci_notify_cap {
    struct virtio_pci_cap cap;
    uint32_t notify_off_multiplier;
} __attribute__((packed));

struct virtio_pci_common_cfg {
    uint32_t device_feature_select;
    uint32_t device_feature;
    uint32_t driver_feature_select;
    uint32_t driver_feature;
    uint16_t msix_config;
    uint16_t num_queues;
    uint8_t device_status;
    uint8_t config_generation;
    uint16_t queue_select;
    uint16_t queue_size;
    uint16_t queue_msix_vector;
    uint16_t queue_enable;
    uint16_t queue_notify_off;
    uint16_t queue_reserved;
    uint32_t queue_desc_lo;
    uint32_t queue_desc_hi;
    uint32_t queue_avail_lo;
    uint32_t queue_avail_hi;
    uint32_t queue_used_lo;
    uint32_t queue_used_hi;
} __attribute__((packed));

struct virtio_blk_config {
    uint64_t capacity;
    uint32_t size_max;
    uint32_t seg_max;
    uint16_t cylinders;
    uint8_t heads;
    uint8_t sectors;
    uint32_t blk_size;
    uint32_t topology;
    uint8_t writeback;
    uint8_t unused0[3];
    uint32_t max_discard_sectors;
    uint32_t max_discard_seg;
    uint32_t discard_sector_alignment;
    uint32_t max_write_zeroes_sectors;
    uint32_t max_write_zeroes_seg;
    uint8_t write_zeroes_may_unmap;
    uint8_t unused1[3];
} __attribute__((packed));

/* ----- Queue structures (virtio spec 2.6.5) ----- */

struct virtq_desc {
    uint64_t addr;
    uint32_t len;
    uint16_t flags;
    uint16_t next;
} __attribute__((packed, aligned(16)));

struct virtq_avail {
    uint16_t flags;
    uint16_t idx;
    uint16_t ring[];
} __attribute__((packed));

struct virtq_used_elem {
    uint32_t id;
    uint32_t len;
} __attribute__((packed));

struct virtq_used {
    uint16_t flags;
    uint16_t idx;
    struct virtq_used_elem ring[];
} __attribute__((packed, aligned(4)));

#define VIRTQ_DESC_F_NEXT   1
#define VIRTQ_DESC_F_WRITE  2

#define VIRTIO_STATUS_ACKNOWLEDGE 0x01
#define VIRTIO_STATUS_DRIVER      0x02
#define VIRTIO_STATUS_DRIVER_OK   0x04
#define VIRTIO_STATUS_FEATURES_OK 0x08
#define VIRTIO_STATUS_FAILED      0x80

#define VIRTIO_BLK_T_IN     0u
#define VIRTIO_BLK_T_OUT    1u
#define VIRTIO_BLK_T_FLUSH  4u

#define VIRTIO_BLK_S_OK     0u
#define VIRTIO_BLK_S_IOERR  1u
#define VIRTIO_BLK_S_UNSUPP 2u

#define VIRTIO_F_VERSION_1          32u
#define VIRTIO_BLK_F_SIZE_MAX        1u
#define VIRTIO_BLK_F_SEG_MAX         2u
#define VIRTIO_BLK_F_FLUSH           9u
#define VIRTIO_BLK_F_BLK_SIZE        6u

struct virtio_blk_req_header {
    uint32_t type;
    uint32_t reserved;
    uint64_t sector;
} __attribute__((packed));

struct virtio_blk_dma {
    struct virtio_blk_req_header header;
    uint8_t status;
    uint8_t pad[7];
} __attribute__((packed, aligned(16)));

typedef struct virtio_virtq {
    uint16_t size;
    volatile struct virtq_desc *desc;
    volatile struct virtq_avail *avail;
    volatile struct virtq_used *used;
    phys_addr_t desc_phys;
    phys_addr_t avail_phys;
    phys_addr_t used_phys;
    uint16_t next_avail;
    uint16_t last_used;
    uint16_t notify_off;
} virtio_virtq_t;

typedef struct virtio_blk_device {
    uint8_t bus;
    uint8_t device;
    uint8_t function;

    uint64_t bars[6];

    volatile struct virtio_pci_common_cfg *common;
    volatile uint8_t *isr;
    volatile struct virtio_blk_config *config;
    volatile uint8_t *notify_base;
    uint32_t notify_off_multiplier;

    virtio_virtq_t queue;

    struct virtio_blk_dma *dma;
    phys_addr_t dma_phys;

    uint64_t capacity_sectors;
    uint32_t block_size;
    uint32_t negotiated_features_low;
    uint32_t negotiated_features_high;
    bool has_flush;

    fut_blkdev_t *blk_dev;
    fut_spinlock_t io_lock;
} virtio_blk_device_t;

static virtio_blk_device_t g_vblk = {0};

/* -------------------------------------------------------------
 *   Helper routines
 * ------------------------------------------------------------- */

static phys_addr_t virt_to_phys_maybe(uintptr_t addr) {
    if (addr >= PMAP_DIRECT_VIRT_BASE) {
        return pmap_virt_to_phys(addr);
    }
    return (phys_addr_t)addr;
}

static void *map_cap_pointer(virtio_blk_device_t *dev,
                             uint8_t bar,
                             uint32_t offset,
                             uint32_t length) {
    (void)length;
    if (bar >= 6) {
        return NULL;
    }
    uint64_t base = dev->bars[bar];
    if (base == 0) {
        return NULL;
    }
    return (void *)(uintptr_t)(pmap_phys_to_virt((phys_addr_t)(base + offset)));
}

static void virtio_blk_reset(virtio_blk_device_t *dev) {
    if (!dev->common) {
        return;
    }
    dev->common->device_status = 0;
}

static void virtio_blk_set_status(virtio_blk_device_t *dev, uint8_t status) {
    dev->common->device_status |= status;
}

static bool virtio_blk_set_features(virtio_blk_device_t *dev, uint64_t features) {
    dev->common->driver_feature_select = 0;
    dev->common->driver_feature = (uint32_t)(features & 0xFFFFFFFFu);
    dev->common->driver_feature_select = 1;
    dev->common->driver_feature = (uint32_t)((features >> 32) & 0xFFFFFFFFu);

    virtio_blk_set_status(dev, VIRTIO_STATUS_FEATURES_OK);
    uint8_t status = dev->common->device_status;
    return (status & VIRTIO_STATUS_FEATURES_OK) != 0;
}

static uint64_t virtio_blk_read_device_features(virtio_blk_device_t *dev) {
    uint64_t value = 0;
    dev->common->device_feature_select = 0;
    value |= dev->common->device_feature;
    dev->common->device_feature_select = 1;
    value |= ((uint64_t)dev->common->device_feature) << 32;
    return value;
}

static void virtio_blk_notify(virtio_blk_device_t *dev) {
    if (!dev->notify_base) {
        return;
    }
    uintptr_t off = (uintptr_t)dev->queue.notify_off * (uintptr_t)dev->notify_off_multiplier;
    volatile uint16_t *notify = (volatile uint16_t *)(dev->notify_base + off);
    *notify = 0; /* queue 0 */
}

static void virtio_blk_queue_init(virtio_blk_device_t *dev, uint16_t requested_size) {
    virtio_virtq_t *q = &dev->queue;

    dev->common->queue_select = 0;
    uint16_t device_size = dev->common->queue_size;
    if (device_size == 0) {
        return;
    }

    uint16_t qsize = (requested_size < device_size) ? requested_size : device_size;
    if (qsize == 0) {
        qsize = device_size;
    }

    q->size = qsize;
    q->next_avail = 0;
    q->last_used = 0;

    void *desc = fut_pmm_alloc_page();
    void *avail = fut_pmm_alloc_page();
    void *used = fut_pmm_alloc_page();
    if (!desc || !avail || !used) {
        return;
    }

    memset(desc, 0, PAGE_SIZE);
    memset(avail, 0, PAGE_SIZE);
    memset(used, 0, PAGE_SIZE);

    q->desc = (volatile struct virtq_desc *)desc;
    q->avail = (volatile struct virtq_avail *)avail;
    q->used = (volatile struct virtq_used *)used;

    q->desc_phys = virt_to_phys_maybe((uintptr_t)desc);
    q->avail_phys = virt_to_phys_maybe((uintptr_t)avail);
    q->used_phys = virt_to_phys_maybe((uintptr_t)used);

    dev->common->queue_size = qsize;
    dev->common->queue_desc_lo = (uint32_t)(q->desc_phys & 0xFFFFFFFFu);
    dev->common->queue_desc_hi = (uint32_t)(q->desc_phys >> 32);
    dev->common->queue_avail_lo = (uint32_t)(q->avail_phys & 0xFFFFFFFFu);
    dev->common->queue_avail_hi = (uint32_t)(q->avail_phys >> 32);
    dev->common->queue_used_lo = (uint32_t)(q->used_phys & 0xFFFFFFFFu);
    dev->common->queue_used_hi = (uint32_t)(q->used_phys >> 32);

    dev->common->queue_enable = 1;
    q->notify_off = dev->common->queue_notify_off;
}

/* -------------------------------------------------------------
 *   Backend I/O helpers
 * ------------------------------------------------------------- */

static inline void blk_dma_prepare(struct virtio_blk_dma *dma,
                                   uint32_t type,
                                   uint64_t lba) {
    dma->header.type = type;
    dma->header.reserved = 0;
    dma->header.sector = lba;
    dma->status = 0xFFu;
}

static int virtio_blk_poll_completion(virtio_blk_device_t *dev, uint16_t expect) {
    virtio_virtq_t *q = &dev->queue;
    while (q->last_used == expect) {
        uint16_t used_idx = q->used->idx;
        if (used_idx != q->last_used) {
            break;
        }
        fut_thread_yield();
    }
    uint16_t used_idx = q->used->idx;
    if (used_idx == q->last_used) {
        return -ETIMEDOUT;
    }
    uint16_t slot = q->last_used % q->size;
    (void)q->used->ring[slot];
    q->last_used++;
    return 0;
}

static int virtio_blk_do_io(virtio_blk_device_t *dev,
                            fut_bio_t *bio,
                            uint32_t type) {
    if (!dev || !bio || bio->nsectors == 0) {
        return -EINVAL;
    }

    virtio_virtq_t *q = &dev->queue;
    struct virtio_blk_dma *dma = dev->dma;
    if (!q->desc || !dma) {
        return -ENODEV;
    }

    const size_t data_bytes = bio->nsectors * dev->block_size;
    void *bounce = NULL;
    phys_addr_t data_phys = 0;

    if (type == VIRTIO_BLK_T_FLUSH) {
        /* nothing */
    } else {
        uintptr_t buf_addr = (uintptr_t)bio->buf;
        if (buf_addr >= PMAP_DIRECT_VIRT_BASE) {
            data_phys = pmap_virt_to_phys(buf_addr);
        } else {
            bounce = fut_malloc(data_bytes);
            if (!bounce) {
                return -ENOMEM;
            }
            if (type == VIRTIO_BLK_T_OUT) {
                memcpy(bounce, bio->buf, data_bytes);
            }
            data_phys = virt_to_phys_maybe((uintptr_t)bounce);
        }
    }

    blk_dma_prepare(dma, type, bio->lba);

    phys_addr_t header_phys = dev->dma_phys;
    phys_addr_t status_phys = dev->dma_phys + offsetof(struct virtio_blk_dma, status);

    volatile struct virtq_desc *desc = q->desc;
    volatile struct virtq_avail *avail = q->avail;

    /* Descriptor 0: request header */
    desc[0].addr = header_phys;
    desc[0].len = sizeof(struct virtio_blk_req_header);
    desc[0].flags = VIRTQ_DESC_F_NEXT;
    desc[0].next = (type == VIRTIO_BLK_T_FLUSH) ? 2 : 1;

    if (type != VIRTIO_BLK_T_FLUSH) {
        desc[1].addr = data_phys;
        desc[1].len = data_bytes;
        desc[1].flags = VIRTQ_DESC_F_NEXT;
        if (type == VIRTIO_BLK_T_IN) {
            desc[1].flags |= VIRTQ_DESC_F_WRITE;
        }
        desc[1].next = 2;
    }

    desc[2].addr = status_phys;
    desc[2].len = 1;
    desc[2].flags = VIRTQ_DESC_F_WRITE;
    desc[2].next = 0;

    uint16_t slot = q->next_avail % q->size;
    avail->ring[slot] = 0; /* descriptor head index */
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
    avail->idx++;
    q->next_avail++;

    virtio_blk_notify(dev);

    int rc = virtio_blk_poll_completion(dev, q->last_used);
    if (rc != 0) {
        if (bounce) {
            fut_free(bounce);
        }
        return rc;
    }

    uint8_t status = dma->status;
    if (status == VIRTIO_BLK_S_OK) {
        if (type == VIRTIO_BLK_T_IN) {
            if (bounce) {
                memcpy(bio->buf, bounce, data_bytes);
            }
        }
        if (bounce) {
            fut_free(bounce);
        }
        return 0;
    }

    if (bounce) {
        if (type == VIRTIO_BLK_T_IN) {
            /* do not copy */
        }
        fut_free(bounce);
    }

    if (status == VIRTIO_BLK_S_UNSUPP) {
        return -ENOTSUP;
    }
    return -EIO;
}

/* -------------------------------------------------------------
 *   Backend hooks for blkcore
 * ------------------------------------------------------------- */

static int virtio_blk_backend_read(void *ctx, uint64_t lba, size_t nsectors, void *buf) {
    virtio_blk_device_t *dev = (virtio_blk_device_t *)ctx;
    fut_bio_t bio = {
        .lba = lba,
        .nsectors = nsectors,
        .buf = buf,
        .write = false,
        .on_complete = NULL,
    };

    fut_spinlock_acquire(&dev->io_lock);
    int rc = virtio_blk_do_io(dev, &bio, VIRTIO_BLK_T_IN);
    fut_spinlock_release(&dev->io_lock);
    return rc;
}

static int virtio_blk_backend_write(void *ctx, uint64_t lba, size_t nsectors, const void *buf) {
    virtio_blk_device_t *dev = (virtio_blk_device_t *)ctx;
    fut_bio_t bio = {
        .lba = lba,
        .nsectors = nsectors,
        .buf = (void *)buf,
        .write = true,
        .on_complete = NULL,
    };

    fut_spinlock_acquire(&dev->io_lock);
    int rc = virtio_blk_do_io(dev, &bio, VIRTIO_BLK_T_OUT);
    fut_spinlock_release(&dev->io_lock);
    return rc;
}

static int virtio_blk_backend_flush(void *ctx) {
    virtio_blk_device_t *dev = (virtio_blk_device_t *)ctx;
    if (!dev->has_flush) {
        return -ENOTSUP;
    }

    fut_bio_t bio = {
        .lba = 0,
        .nsectors = 1,
        .buf = dev->dma,
        .write = true,
        .on_complete = NULL,
    };

    fut_spinlock_acquire(&dev->io_lock);
    int rc = virtio_blk_do_io(dev, &bio, VIRTIO_BLK_T_FLUSH);
    fut_spinlock_release(&dev->io_lock);
    return rc;
}

static const fut_blk_backend_t g_vblk_backend = {
    .read = virtio_blk_backend_read,
    .write = virtio_blk_backend_write,
    .flush = virtio_blk_backend_flush,
};

/* -------------------------------------------------------------
 *   Device setup
 * ------------------------------------------------------------- */

static void virtio_blk_setup_bars(virtio_blk_device_t *dev) {
    for (uint8_t i = 0; i < 6; ++i) {
        uint8_t offset = 0x10 + (i * 4);
        uint32_t value = pci_config_read32(dev->bus, dev->device, dev->function, offset);
        if ((value & 0x1) != 0) {
            dev->bars[i] = 0;
            continue; /* I/O BAR not supported */
        }
        uint32_t type = (value >> 1) & 0x3;
        uint64_t base = value & 0xFFFFFFF0u;
        if (type == 0x2 && i + 1 < 6) {
            uint32_t hi = pci_config_read32(dev->bus, dev->device, dev->function, offset + 4);
            base |= ((uint64_t)hi << 32);
            ++i; /* consume high word */
        }
        dev->bars[i] = base;
    }
}

static bool virtio_blk_parse_capabilities(virtio_blk_device_t *dev) {
    uint8_t status = pci_config_read8(dev->bus, dev->device, dev->function, 0x06);
    if ((status & 0x10) == 0) { /* capabilities present bit */
        return false;
    }

    uint8_t cap_ptr = pci_config_read8(dev->bus, dev->device, dev->function, 0x34);
    while (cap_ptr >= 0x40) {
        struct virtio_pci_cap cap = {0};
        uint8_t cap_len = pci_config_read8(dev->bus, dev->device, dev->function, cap_ptr + 2);

        for (uint8_t i = 0; i < cap_len; i += 4) {
            uint32_t word = pci_config_read32(dev->bus, dev->device, dev->function, cap_ptr + i);
            uint8_t *dst = ((uint8_t *)&cap) + i;
            memcpy(dst, &word, (cap_len - i) >= 4 ? 4 : (cap_len - i));
        }

        if (cap.cap_vndr == PCI_CAP_ID_VNDR) {
            void *mapped = map_cap_pointer(dev, cap.bar, cap.offset, cap.length);
            if (!mapped) {
                cap_ptr = cap.cap_next;
                continue;
            }

            switch (cap.cfg_type) {
            case VIRTIO_PCI_CAP_COMMON_CFG:
                dev->common = (volatile struct virtio_pci_common_cfg *)mapped;
                break;
            case VIRTIO_PCI_CAP_DEVICE_CFG:
                dev->config = (volatile struct virtio_blk_config *)mapped;
                break;
            case VIRTIO_PCI_CAP_ISR_CFG:
                dev->isr = (volatile uint8_t *)mapped;
                break;
            case VIRTIO_PCI_CAP_NOTIFY_CFG: {
                struct virtio_pci_notify_cap notify_cap = {0};
                for (uint8_t i = 0; i < cap_len; i += 4) {
                    uint32_t word = pci_config_read32(dev->bus, dev->device, dev->function, cap_ptr + i);
                    uint8_t *dst = ((uint8_t *)&notify_cap) + i;
                    memcpy(dst, &word, (cap_len - i) >= 4 ? 4 : (cap_len - i));
                }
                dev->notify_base = (volatile uint8_t *)map_cap_pointer(dev,
                                                                       cap.bar,
                                                                       cap.offset,
                                                                       cap.length);
                dev->notify_off_multiplier = notify_cap.notify_off_multiplier;
                break;
            }
            default:
                break;
            }
        }

    cap_ptr = cap.cap_next;
    if (cap_ptr == 0) {
        break;
    }
    }

    return dev->common && dev->config && dev->notify_base;
}

static bool virtio_blk_configure_features(virtio_blk_device_t *dev) {
    uint64_t device_features = virtio_blk_read_device_features(dev);
    uint64_t driver_features = 0;

    if (device_features & (1ull << VIRTIO_F_VERSION_1)) {
        driver_features |= (1ull << VIRTIO_F_VERSION_1);
    }
    if (device_features & (1ull << VIRTIO_BLK_F_FLUSH)) {
        driver_features |= (1ull << VIRTIO_BLK_F_FLUSH);
        dev->has_flush = true;
    } else {
        dev->has_flush = false;
    }
    if (device_features & (1ull << VIRTIO_BLK_F_BLK_SIZE)) {
        driver_features |= (1ull << VIRTIO_BLK_F_BLK_SIZE);
    }

    dev->negotiated_features_low = (uint32_t)(driver_features & 0xFFFFFFFFu);
    dev->negotiated_features_high = (uint32_t)((driver_features >> 32) & 0xFFFFFFFFu);

    return virtio_blk_set_features(dev, driver_features);
}

static bool virtio_blk_init_queue_and_dma(virtio_blk_device_t *dev) {
    virtio_blk_queue_init(dev, 8);

    dev->dma = (struct virtio_blk_dma *)fut_pmm_alloc_page();
    if (!dev->dma) {
        return false;
    }
    memset(dev->dma, 0, PAGE_SIZE);
    dev->dma_phys = virt_to_phys_maybe((uintptr_t)dev->dma);
    return true;
}

static bool virtio_blk_register_device(virtio_blk_device_t *dev) {
    if (!dev->common || !dev->config) {
        return false;
    }

    uint64_t capacity = dev->config->capacity;
    dev->capacity_sectors = capacity;
    uint32_t blk_size = dev->config->blk_size;
    if (blk_size == 0) {
        blk_size = 512;
    }
    dev->block_size = blk_size;

    fut_blkdev_t *blk_dev = NULL;
    int rc = fut_blk_register("blk:vda",
                              dev->block_size,
                              dev->capacity_sectors,
                              FUT_BLK_READ | FUT_BLK_WRITE | FUT_BLK_ADMIN,
                              &g_vblk_backend,
                              dev,
                              &blk_dev);
    if (rc != 0) {
        fut_printf("[virtio-blk] fut_blk_register failed: %d\n", rc);
        return false;
    }

    dev->blk_dev = blk_dev;
    fut_spinlock_init(&dev->io_lock);
    fut_printf("[virtio-blk] registered /dev/vda (%llu sectors, %u-byte blocks)\n",
               (unsigned long long)dev->capacity_sectors,
               dev->block_size);
    return true;
}

static bool virtio_blk_setup_device(uint8_t bus, uint8_t device, uint8_t func) {
    virtio_blk_device_t *dev = &g_vblk;
    memset(dev, 0, sizeof(*dev));
    dev->bus = bus;
    dev->device = device;
    dev->function = func;

    virtio_blk_setup_bars(dev);
    if (!virtio_blk_parse_capabilities(dev)) {
        fut_printf("[virtio-blk] capability discovery failed\n");
        return false;
    }

    virtio_blk_reset(dev);
    virtio_blk_set_status(dev, VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER);

    if (!virtio_blk_configure_features(dev)) {
        fut_printf("[virtio-blk] feature negotiation failed\n");
        return false;
    }

    if (!virtio_blk_init_queue_and_dma(dev)) {
        fut_printf("[virtio-blk] queue allocation failed\n");
        return false;
    }

    virtio_blk_set_status(dev, VIRTIO_STATUS_DRIVER_OK);

    if (!virtio_blk_register_device(dev)) {
        virtio_blk_reset(dev);
        return false;
    }

    return true;
}

static bool virtio_blk_probe_pci(void) {
    for (uint8_t bus = 0; bus < 2; ++bus) {
        for (uint8_t device = 0; device < 32; ++device) {
            for (uint8_t func = 0; func < 8; ++func) {
                uint16_t vendor = pci_config_read16(bus, device, func, 0x00);
                if (vendor == 0xFFFF) {
                    continue;
                }
                uint16_t device_id = pci_config_read16(bus, device, func, 0x02);
                if (vendor != VIRTIO_VENDOR_ID) {
                    continue;
                }
                if (device_id != VIRTIO_DEVICE_ID_BLOCK_MODERN &&
                    device_id != VIRTIO_DEVICE_ID_BLOCK_LEGACY) {
                    continue;
                }

                uint16_t command = pci_config_read16(bus, device, func, PCI_COMMAND);
                command |= (PCI_COMMAND_MEMORY | PCI_COMMAND_BUS_MASTER);
                pci_config_write16(bus, device, func, PCI_COMMAND, command);

                if (virtio_blk_setup_device(bus, device, func)) {
                    return true;
                }
            }
        }
    }
    return false;
}

/* -------------------------------------------------------------
 *   Public entry point
 * ------------------------------------------------------------- */

void virtio_blk_init(void) {
    if (virtio_blk_probe_pci()) {
        fut_printf("[virtio-blk] device ready\n");
    } else {
        fut_printf("[virtio-blk] no device found\n");
    }
}
