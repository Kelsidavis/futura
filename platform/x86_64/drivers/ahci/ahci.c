// SPDX-License-Identifier: MPL-2.0
/*
 * ahci.c - Minimal AHCI SATA host controller driver
 *
 * Implements the baseline command/response flow described in the Intel
 * "Serial ATA Advanced Host Controller Interface (AHCI) Specification"
 * Revision 1.3.1.  The driver walks PCI configuration space to locate
 * a class-code 0x0106 (SATA AHCI) device, maps the HBA MMIO window,
 * detects active ports, issues IDENTIFY DEVICE to determine capacity,
 * and plumbs each disk through the async block core.
 *
 * Supported operations:
 *   - READ DMA (0xC8) / READ DMA EXT (0x25)
 *   - WRITE DMA (0xCA) / WRITE DMA EXT (0x35)
 *   - FLUSH CACHE (0xE7) / FLUSH CACHE EXT (0xEA)
 *
 * QEMU smoke run (AHCI disk + serial console):
 *   qemu-system-x86_64 -serial stdio \
 *     -drive id=disk,file=disk.img,if=none,format=raw \
 *     -device ahci,id=ahci \
 *     -device ide-hd,drive=disk,bus=ahci.0 \
 *     -m 512 -cdrom futura.iso
 *
 * The async block core performs read/write/flush tests during boot, so
 * successful initialization will be reflected in the "[BLK]" self-test
 * log lines.
 */

#include <futura/blkdev.h>

#include <kernel/errno.h>
#include <kernel/fut_memory.h>
#include <kernel/fut_sched.h>
#include <kernel/fut_thread.h>

#include <arch/x86_64/pmap.h>

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

extern void fut_printf(const char *fmt, ...);

#ifndef ETIMEDOUT
#define ETIMEDOUT 110
#endif

#ifndef ENOTSUP
#define ENOTSUP 95
#endif

/* -------------------------------------------------------------
 *   PCI helpers (legacy config mechanism)
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
    uint32_t address = (uint32_t)0x80000000u
                     | ((uint32_t)bus << 16)
                     | ((uint32_t)device << 11)
                     | ((uint32_t)func << 8)
                     | (offset & 0xFCu);
    outl(PCI_CONFIG_ADDRESS, address);
    return inl(PCI_CONFIG_DATA);
}

static void pci_config_write32(uint8_t bus, uint8_t device, uint8_t func, uint8_t offset, uint32_t value) {
    uint32_t address = (uint32_t)0x80000000u
                     | ((uint32_t)bus << 16)
                     | ((uint32_t)device << 11)
                     | ((uint32_t)func << 8)
                     | (offset & 0xFCu);
    outl(PCI_CONFIG_ADDRESS, address);
    outl(PCI_CONFIG_DATA, value);
}

static uint16_t pci_config_read16(uint8_t bus, uint8_t device, uint8_t func, uint8_t offset) {
    uint32_t data = pci_config_read32(bus, device, func, offset);
    return (uint16_t)((data >> ((offset & 2u) * 8u)) & 0xFFFFu);
}

static void pci_config_write16(uint8_t bus, uint8_t device, uint8_t func, uint8_t offset, uint16_t value) {
    uint32_t current = pci_config_read32(bus, device, func, offset);
    uint32_t shift = (offset & 2u) * 8u;
    current &= ~(0xFFFFu << shift);
    current |= ((uint32_t)value << shift);
    pci_config_write32(bus, device, func, offset, current);
}

/* -------------------------------------------------------------
 *   AHCI register structures (subset)
 * ------------------------------------------------------------- */

#define AHCI_PCI_CLASS_STORAGE       0x01
#define AHCI_PCI_SUBCLASS_SATA       0x06
#define AHCI_PCI_PROGIF_AHCI         0x01

#define AHCI_BAR_INDEX               5 /* BAR5 */

#define AHCI_CAP_NP_MASK             0x1F

#define AHCI_GHC_HR                  (1u << 0)
#define AHCI_GHC_IE                  (1u << 1)
#define AHCI_GHC_AE                  (1u << 31)

#define AHCI_PORT_CMD_ST             (1u << 0)
#define AHCI_PORT_CMD_SU             (1u << 1)
#define AHCI_PORT_CMD_FRE            (1u << 4)
#define AHCI_PORT_CMD_FR             (1u << 14)
#define AHCI_PORT_CMD_CR             (1u << 15)

#define AHCI_PORT_SSTS_DET_MASK      0x0F
#define AHCI_PORT_SSTS_DET_PRESENT   0x03
#define AHCI_PORT_SSTS_IPM_MASK      0xF0
#define AHCI_PORT_SSTS_IPM_ACTIVE    0x10

#define AHCI_PORT_TFD_ERR            0x01
#define AHCI_PORT_TFD_DRQ            0x08
#define AHCI_PORT_TFD_BSY            0x80

#define AHCI_FIS_REG_H2D             0x27
#define AHCI_FIS_REG_D2H             0x34

#define AHCI_CMD_SLOT                0 /* single outstanding command */
#define AHCI_MAX_PORTS               32
#define AHCI_MAX_DEVICES             4

#define AHCI_MAX_PRDT                8
#define AHCI_PRD_MAX_BYTES           (4 * 1024 * 1024)

typedef volatile struct {
    uint32_t clb;
    uint32_t clbu;
    uint32_t fb;
    uint32_t fbu;
    uint32_t is;
    uint32_t ie;
    uint32_t cmd;
    uint32_t reserved0;
    uint32_t tfd;
    uint32_t sig;
    uint32_t ssts;
    uint32_t sctl;
    uint32_t serr;
    uint32_t sact;
    uint32_t ci;
    uint32_t sntf;
    uint32_t fbs;
    uint32_t devslp;
    uint32_t reserved1[10];
    uint32_t vendor[4];
} hba_port_t;

typedef volatile struct {
    uint32_t cap;
    uint32_t ghc;
    uint32_t is;
    uint32_t pi;
    uint32_t vs;
    uint32_t ccc_ctl;
    uint32_t ccc_pts;
    uint32_t em_loc;
    uint32_t em_ctl;
    uint32_t cap2;
    uint32_t bohc;
    uint8_t  reserved[0xA0 - 0x2C];
    hba_port_t ports[AHCI_MAX_PORTS];
} hba_mem_t;

typedef struct {
    uint16_t flags;
    uint16_t prdtl;
    uint32_t prdbc;
    uint32_t ctba;
    uint32_t ctbau;
    uint32_t reserved[4];
} __attribute__((packed, aligned(32))) hba_cmd_header_t;

typedef struct {
    uint32_t dba;
    uint32_t dbau;
    uint32_t reserved0;
    uint32_t dbc; /* bits 0-21 byte count (n-1), bit 31 interrupt */
} __attribute__((packed)) hba_prdt_entry_t;

typedef struct {
    uint8_t cfis[64];
    uint8_t acmd[16];
    uint8_t reserved[48];
    hba_prdt_entry_t prdt[AHCI_MAX_PRDT];
} __attribute__((packed, aligned(128))) hba_cmd_table_t;

/* -------------------------------------------------------------
 *   Port context
 * ------------------------------------------------------------- */

typedef struct {
    volatile hba_port_t *port;
    hba_cmd_header_t *cmd_header;
    phys_addr_t cmd_header_phys;
    uint8_t *recv_fis;
    phys_addr_t recv_fis_phys;
    hba_cmd_table_t *cmd_table;
    phys_addr_t cmd_table_phys;
    fut_spinlock_t lock;
    uint64_t capacity_lba;
    uint32_t block_size;
    bool lba48;
    fut_blkdev_t blk_dev;
    char name[16];
} ahci_device_t;

static volatile hba_mem_t *g_hba = NULL;
static ahci_device_t g_devices[AHCI_MAX_DEVICES];
static uint32_t g_device_count = 0;

/* -------------------------------------------------------------
 *   Helper functions
 * ------------------------------------------------------------- */

static phys_addr_t virt_to_phys(uintptr_t addr) {
    if (addr >= PMAP_DIRECT_VIRT_BASE) {
        return pmap_virt_to_phys(addr);
    }
    return (phys_addr_t)addr;
}

static void ahci_port_stop(volatile hba_port_t *port) {
    uint32_t cmd = port->cmd;
    cmd &= ~(AHCI_PORT_CMD_ST | AHCI_PORT_CMD_FRE);
    port->cmd = cmd;

    /* Wait until FR and CR clear */
    while (port->cmd & (AHCI_PORT_CMD_FR | AHCI_PORT_CMD_CR)) {
        fut_thread_yield();
    }
}

static void ahci_port_start(volatile hba_port_t *port) {
    uint32_t cmd = port->cmd;
    port->cmd = cmd | AHCI_PORT_CMD_FRE;
    port->cmd |= AHCI_PORT_CMD_ST;
}

static bool ahci_port_ready(volatile hba_port_t *port) {
    uint32_t ssts = port->ssts;
    uint32_t det = ssts & AHCI_PORT_SSTS_DET_MASK;
    uint32_t ipm = ssts & AHCI_PORT_SSTS_IPM_MASK;
    return det == AHCI_PORT_SSTS_DET_PRESENT && ipm == AHCI_PORT_SSTS_IPM_ACTIVE;
}

static bool ahci_wait_port_idle(volatile hba_port_t *port) {
    uint32_t tries = 100000;
    while ((port->tfd & (AHCI_PORT_TFD_BSY | AHCI_PORT_TFD_DRQ)) != 0 && tries--) {
        fut_thread_yield();
    }
    return tries != 0;
}

static void ahci_clear_interrupts(volatile hba_port_t *port) {
    port->is = port->is;
    port->serr = port->serr;
}

/* -------------------------------------------------------------
 *   Command submission
 * ------------------------------------------------------------- */

static int ahci_issue_command(ahci_device_t *dev,
                              uint8_t ata_command,
                              uint64_t lba,
                              size_t sector_count,
                              void *buffer,
                              size_t buffer_len,
                              bool is_write) {
    volatile hba_port_t *port = dev->port;
    if (!ahci_wait_port_idle(port)) {
        return -EBUSY;
    }

    hba_cmd_header_t *header = dev->cmd_header;
    hba_cmd_table_t *table = dev->cmd_table;

    memset((void *)header, 0, sizeof(*header));
    memset(table, 0, sizeof(*table));

    uint16_t prdt_needed = 0;
    if (buffer_len > 0) {
        prdt_needed = (uint16_t)((buffer_len + AHCI_PRD_MAX_BYTES - 1) / AHCI_PRD_MAX_BYTES);
        if (prdt_needed > AHCI_MAX_PRDT) {
            return -EINVAL;
        }
    }

    header->flags = 5u; /* Command FIS length in DWORDs */
    if (is_write) {
        header->flags |= (1u << 6); /* W flag */
    }
    header->prdtl = prdt_needed;
    header->ctba = (uint32_t)(dev->cmd_table_phys & 0xFFFFFFFFu);
    header->ctbau = (uint32_t)(dev->cmd_table_phys >> 32);

    /* Command FIS (Register Host to Device) */
    uint8_t *cfis = table->cfis;
    memset(cfis, 0, 64);
    cfis[0] = AHCI_FIS_REG_H2D;
    cfis[1] = 1 << 7; /* Command */
    cfis[2] = ata_command;
    cfis[3] = 0;

    uint32_t sector_size = dev->block_size;

    uint64_t byte_count = (uint64_t)sector_count * (uint64_t)sector_size;

    /* Setup PRDT entries */
    uint8_t *cursor = (uint8_t *)buffer;
    for (uint16_t i = 0; i < prdt_needed; ++i) {
        size_t chunk = byte_count;
        if (chunk > AHCI_PRD_MAX_BYTES) {
            chunk = AHCI_PRD_MAX_BYTES;
        }
        byte_count -= chunk;

        hba_prdt_entry_t *prd = &table->prdt[i];
        phys_addr_t phys = virt_to_phys((uintptr_t)cursor);
        prd->dba = (uint32_t)(phys & 0xFFFFFFFFu);
        prd->dbau = (uint32_t)(phys >> 32);
        prd->dbc = (uint32_t)((chunk - 1) & 0x3FFFFFu);
        if (byte_count == 0) {
            prd->dbc |= (1u << 31); /* interrupt on completion */
        }
        cursor += chunk;
    }

    /* Fill CFIS fields for LBA and sector count */
    bool command_is_flush = (ata_command == 0xE7 || ata_command == 0xEA);
    bool use_lba48 = command_is_flush ? dev->lba48
                                      : (dev->lba48 && (lba > 0x0FFFFFFFu || sector_count > 0xFF));
    uint8_t command = ata_command;
    if (use_lba48) {
        if (ata_command == 0xC8) {
            command = 0x25; /* READ DMA EXT */
        } else if (ata_command == 0xCA) {
            command = 0x35; /* WRITE DMA EXT */
        } else if (ata_command == 0xE7) {
            command = 0xEA; /* FLUSH CACHE EXT */
        }
    } else {
        if (ata_command == 0x25) {
            command = 0xC8;
        } else if (ata_command == 0x35) {
            command = 0xCA;
        } else if (ata_command == 0xEA) {
            command = 0xE7;
        }
    }

    cfis[2] = command;

    if (sector_count > 0) {
        if (use_lba48) {
            cfis[3] = (uint8_t)((sector_count >> 8) & 0xFF);
            cfis[4] = (uint8_t)(lba & 0xFF);
            cfis[5] = (uint8_t)((lba >> 8) & 0xFF);
            cfis[6] = (uint8_t)((lba >> 16) & 0xFF);
            cfis[7] = 0x40;
            cfis[8] = (uint8_t)((lba >> 24) & 0xFF);
            cfis[9] = (uint8_t)((lba >> 32) & 0xFF);
            cfis[10] = (uint8_t)((lba >> 40) & 0xFF);
            cfis[12] = (uint8_t)(sector_count & 0xFF);
            cfis[13] = (uint8_t)((sector_count >> 8) & 0xFF);
        } else {
            cfis[3] = 0;
            cfis[4] = (uint8_t)(lba & 0xFF);
            cfis[5] = (uint8_t)((lba >> 8) & 0xFF);
            cfis[6] = (uint8_t)((lba >> 16) & 0xFF);
            cfis[7] = 0x40 | ((uint8_t)((lba >> 24) & 0x0F));
            cfis[12] = (uint8_t)(sector_count & 0xFF);
            cfis[13] = 0;
        }
    } else {
        cfis[7] = 0x40;
        cfis[12] = 0;
        cfis[13] = 0;
    }

    ahci_clear_interrupts(port);

    header->prdbc = 0;

    port->ci = (1u << AHCI_CMD_SLOT);

    /* Poll completion */
    uint32_t timeout = 1000000;
    while (port->ci & (1u << AHCI_CMD_SLOT)) {
        if (timeout-- == 0) {
            return -ETIMEDOUT;
        }
        fut_thread_yield();
    }

    if (port->tfd & AHCI_PORT_TFD_ERR) {
        ahci_clear_interrupts(port);
        return -EIO;
    }

    return 0;
}

/* -------------------------------------------------------------
 *   ATA helper flows
 * ------------------------------------------------------------- */

static int ahci_identify_device(ahci_device_t *dev, uint16_t *identify_out) {
    uint8_t *buffer = (uint8_t *)identify_out;
    size_t bytes = 512;
    memset(buffer, 0, bytes);

    /* IDENTIFY DEVICE returns 512 bytes */
    int rc = ahci_issue_command(dev, 0xEC, 0, 1, buffer, bytes, false);
    if (rc != 0) {
        return rc;
    }
    return 0;
}

static uint64_t ahci_parse_capacity(const uint16_t *identify, bool *supports_lba48) {
    uint16_t caps = identify[49];
    bool lba_supported = (caps & (1u << 9)) != 0;
    uint64_t sectors28 = 0;
    if (lba_supported) {
        uint32_t low = ((uint32_t)identify[60]) | ((uint32_t)identify[61] << 16);
        sectors28 = low;
    }

    uint16_t cmd_set_supported = identify[83];
    bool lba48_supported = (cmd_set_supported & (1u << 10)) != 0;
    *supports_lba48 = lba48_supported;

    if (lba48_supported) {
        uint64_t l0 = identify[100];
        uint64_t l1 = identify[101];
        uint64_t l2 = identify[102];
        uint64_t l3 = identify[103];
        uint64_t total = l0 | (l1 << 16) | (l2 << 32) | (l3 << 48);
        if (total != 0) {
            return total;
        }
    }
    return sectors28;
}

/* -------------------------------------------------------------
 *   Block backend
 * ------------------------------------------------------------- */

static int ahci_io_common(ahci_device_t *dev, bool write, uint64_t lba, size_t sectors, void *buf) {
    if (!dev->port) {
        return -ENODEV;
    }
    if (lba + sectors > dev->capacity_lba) {
        return -EINVAL;
    }

    const size_t sector_size = dev->block_size;
    const size_t max_sectors_per_prd = AHCI_PRD_MAX_BYTES / sector_size;
    const size_t max_sectors_per_cmd = max_sectors_per_prd * AHCI_MAX_PRDT;
    uint8_t *cursor = (uint8_t *)buf;

    fut_spinlock_acquire(&dev->lock);

    while (sectors > 0) {
        size_t chunk = sectors;
        if (chunk > max_sectors_per_cmd) {
            chunk = max_sectors_per_cmd;
        }
        size_t bytes = chunk * sector_size;

        void *transfer_buf = cursor;
        void *bounce = NULL;
        if ((uintptr_t)transfer_buf < PMAP_DIRECT_VIRT_BASE) {
            bounce = fut_malloc(bytes);
            if (!bounce) {
                fut_spinlock_release(&dev->lock);
                return -ENOMEM;
            }
            if (write) {
                memcpy(bounce, transfer_buf, bytes);
            }
            transfer_buf = bounce;
        }

        uint8_t command = write ? (dev->lba48 ? 0x35 : 0xCA) : (dev->lba48 ? 0x25 : 0xC8);
        int rc = ahci_issue_command(dev, command, lba, chunk, transfer_buf, bytes, write);
        if (rc != 0) {
            if (bounce) {
                fut_free(bounce);
            }
            fut_spinlock_release(&dev->lock);
            return rc;
        }

        if (!write && bounce) {
            memcpy(cursor, bounce, bytes);
        }

        if (bounce) {
            fut_free(bounce);
        }

        sectors -= chunk;
        lba += chunk;
        cursor += bytes;
    }

    fut_spinlock_release(&dev->lock);
    return 0;
}

static int ahci_backend_read(void *ctx, uint64_t lba, size_t nsectors, void *buf) {
    return ahci_io_common((ahci_device_t *)ctx, false, lba, nsectors, buf);
}

static int ahci_backend_write(void *ctx, uint64_t lba, size_t nsectors, const void *buf) {
    return ahci_io_common((ahci_device_t *)ctx, true, lba, nsectors, (void *)buf);
}

static int ahci_backend_flush(void *ctx) {
    ahci_device_t *dev = (ahci_device_t *)ctx;
    if (!dev->lba48) {
        return ahci_issue_command(dev, 0xE7, 0, 0, NULL, 0, false);
    }
    return ahci_issue_command(dev, 0xEA, 0, 0, NULL, 0, false);
}

static const fut_blk_backend_t g_ahci_backend = {
    .read = ahci_backend_read,
    .write = ahci_backend_write,
    .flush = ahci_backend_flush,
};

/* -------------------------------------------------------------
 *   Device bring-up
 * ------------------------------------------------------------- */

static bool ahci_port_configure(ahci_device_t *dev,
                                volatile hba_port_t *port,
                                uint32_t index,
                                uint32_t device_id) {
    if (!ahci_port_ready(port)) {
        return false;
    }

    memset(dev, 0, sizeof(*dev));

    ahci_port_stop(port);

    void *cmd_header_page = fut_pmm_alloc_page();
    void *recv_fis_page = fut_pmm_alloc_page();
    void *cmd_table_page = fut_pmm_alloc_page();
    if (!cmd_header_page || !recv_fis_page || !cmd_table_page) {
        goto fail_alloc;
    }

    memset(cmd_header_page, 0, PAGE_SIZE);
    memset(recv_fis_page, 0, PAGE_SIZE);
    memset(cmd_table_page, 0, PAGE_SIZE);

    dev->port = port;
    dev->cmd_header = (hba_cmd_header_t *)cmd_header_page;
    dev->cmd_header_phys = virt_to_phys((uintptr_t)cmd_header_page);
    dev->recv_fis = (uint8_t *)recv_fis_page;
    dev->recv_fis_phys = virt_to_phys((uintptr_t)recv_fis_page);
    dev->cmd_table = (hba_cmd_table_t *)cmd_table_page;
    dev->cmd_table_phys = virt_to_phys((uintptr_t)cmd_table_page);
    fut_spinlock_init(&dev->lock);

    port->clb = (uint32_t)(dev->cmd_header_phys & 0xFFFFFFFFu);
    port->clbu = (uint32_t)(dev->cmd_header_phys >> 32);
    port->fb = (uint32_t)(dev->recv_fis_phys & 0xFFFFFFFFu);
    port->fbu = (uint32_t)(dev->recv_fis_phys >> 32);

    for (uint32_t i = 0; i < 32; ++i) {
        hba_cmd_header_t *hdr = &dev->cmd_header[i];
        hdr->ctba = (uint32_t)(dev->cmd_table_phys & 0xFFFFFFFFu);
        hdr->ctbau = (uint32_t)(dev->cmd_table_phys >> 32);
    }

    ahci_clear_interrupts(port);
    ahci_port_start(port);

    uint16_t identify[256];
    int rc = ahci_identify_device(dev, identify);
    if (rc != 0) {
        fut_printf("[ahci] port %u identify failed: %d\n", index, rc);
        goto fail_ident;
    }

    bool lba48 = false;
    uint64_t capacity = ahci_parse_capacity(identify, &lba48);
    if (capacity == 0) {
        fut_printf("[ahci] port %u reported zero capacity\n", index);
        goto fail_ident;
    }

    dev->capacity_lba = capacity;
    dev->lba48 = lba48;
    dev->block_size = 512; /* logical sector size */

    char name[sizeof(dev->name)];
    memset(name, 0, sizeof(name));
    name[0] = 'b'; name[1] = 'l'; name[2] = 'k'; name[3] = ':'; name[4] = 's';
    name[5] = 'a'; name[6] = 't'; name[7] = 'a';
    name[8] = (char)('0' + (char)device_id);
    name[9] = '\0';
    memcpy(dev->name, name, sizeof(dev->name));

    dev->blk_dev.name = dev->name;
    dev->blk_dev.block_size = dev->block_size;
    dev->blk_dev.block_count = dev->capacity_lba;
    dev->blk_dev.allowed_rights = FUT_BLK_READ | FUT_BLK_WRITE | FUT_BLK_ADMIN;
    dev->blk_dev.backend = &g_ahci_backend;
    dev->blk_dev.backend_ctx = dev;

    rc = fut_blk_register(&dev->blk_dev);
    if (rc != 0) {
        fut_printf("[ahci] register %s failed: %d\n", dev->name, rc);
        goto fail_ident;
    }

    fut_printf("[ahci] port %u -> %s (%llu sectors, %s LBA48)\n",
               index,
               dev->name,
               (unsigned long long)dev->capacity_lba,
               dev->lba48 ? "with" : "no");
    return true;

fail_ident:
    ahci_port_stop(port);
fail_alloc:
    if (dev->cmd_header) {
        fut_pmm_free_page((void *)dev->cmd_header);
    } else if (cmd_header_page) {
        fut_pmm_free_page(cmd_header_page);
    }
    if (dev->recv_fis) {
        fut_pmm_free_page(dev->recv_fis);
    } else if (recv_fis_page) {
        fut_pmm_free_page(recv_fis_page);
    }
    if (dev->cmd_table) {
        fut_pmm_free_page(dev->cmd_table);
    } else if (cmd_table_page) {
        fut_pmm_free_page(cmd_table_page);
    }
    memset(dev, 0, sizeof(*dev));
    return false;
}

/* -------------------------------------------------------------
 *   PCI probe and driver entry
 * ------------------------------------------------------------- */

static bool ahci_probe_controller(uint8_t bus, uint8_t device, uint8_t func) {
    uint16_t vendor = pci_config_read16(bus, device, func, 0x00);
    if (vendor == 0xFFFF) {
        return false;
    }

    uint32_t class_reg = pci_config_read32(bus, device, func, 0x08);
    uint8_t class_code = (uint8_t)(class_reg >> 24);
    uint8_t subclass = (uint8_t)(class_reg >> 16);
    uint8_t prog_if = (uint8_t)(class_reg >> 8);

    if (class_code != AHCI_PCI_CLASS_STORAGE ||
        subclass != AHCI_PCI_SUBCLASS_SATA ||
        prog_if != AHCI_PCI_PROGIF_AHCI) {
        return false;
    }

    uint32_t bar_low = pci_config_read32(bus, device, func, 0x10 + AHCI_BAR_INDEX * 4);
    uint32_t bar_high = pci_config_read32(bus, device, func, 0x10 + AHCI_BAR_INDEX * 4 + 4);
    uint64_t bar = ((uint64_t)bar_high << 32) | (bar_low & 0xFFFFFFF0u);
    if (bar == 0) {
        return false;
    }

    uint16_t command = pci_config_read16(bus, device, func, 0x04);
    command |= (uint16_t)(0x0002u | 0x0004u); /* enable memory + bus master */
    pci_config_write16(bus, device, func, 0x04, command);

    g_hba = (volatile hba_mem_t *)pmap_phys_to_virt((phys_addr_t)bar);
    if (!g_hba) {
        return false;
    }

    g_hba->ghc |= AHCI_GHC_AE;
    g_hba->ghc |= AHCI_GHC_IE;

    uint32_t implemented = g_hba->pi;
    uint32_t ports = g_hba->cap & AHCI_CAP_NP_MASK;
    if (ports == 0) {
        ports = 1;
    }

    for (uint32_t port_id = 0; port_id < ports; ++port_id) {
        if ((implemented & (1u << port_id)) == 0) {
            continue;
        }
        if (g_device_count >= AHCI_MAX_DEVICES) {
            fut_printf("[ahci] maximum managed devices reached\n");
            break;
        }
        ahci_device_t *dev = &g_devices[g_device_count];
        if (ahci_port_configure(dev, &g_hba->ports[port_id], port_id, g_device_count)) {
            g_device_count++;
        }
    }

    return g_device_count > 0;
}

void ahci_init(void) {
    bool found = false;
    for (uint8_t bus = 0; bus < 8 && !found; ++bus) {
        for (uint8_t device = 0; device < 32 && !found; ++device) {
            for (uint8_t func = 0; func < 8 && !found; ++func) {
                if (ahci_probe_controller(bus, device, func)) {
                    found = true;
                }
            }
        }
    }

    if (found) {
        fut_printf("[ahci] controller initialized (%u device(s))\n", g_device_count);
    } else {
        fut_printf("[ahci] controller not found\n");
    }
}
