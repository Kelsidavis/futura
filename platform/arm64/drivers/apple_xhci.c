/* apple_xhci.c - Apple Silicon USB xHCI Controller Driver
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * USB support via PCIe-attached xHCI controller on Apple Silicon.
 * Depends on the Apple PCIe root complex driver for BAR discovery.
 */

#include <platform/arm64/apple_xhci.h>
#include <platform/arm64/apple_pcie.h>
#include <platform/platform.h>
#include <kernel/fut_memory.h>
#include <string.h>

/* xHCI TRB types */
#define TRB_NORMAL       1
#define TRB_SETUP        2
#define TRB_DATA         3
#define TRB_STATUS       4
#define TRB_LINK         6
#define TRB_ENABLE_SLOT  9
#define TRB_ADDRESS_DEV  11
#define TRB_CMD_COMPLETE 33
#define TRB_PORT_STATUS  34

/* TRB flags */
#define TRB_FLAG_CYCLE   (1 << 0)
#define TRB_FLAG_IOC     (1 << 5)

/* PCI class code for xHCI */
#define PCI_CLASS_USB_XHCI  0x0C0330

/* Ring sizes */
#define CMD_RING_SIZE     64
#define EVT_RING_SIZE     64
#define TRB_SIZE          16

/* Transfer Request Block */
typedef struct {
    uint64_t param;
    uint32_t status;
    uint32_t control;
} __attribute__((packed)) xhci_trb_t;

/* Static controller */
static xhci_ctrl_t g_xhci;

/* ============================================================
 *   Register Access
 * ============================================================ */

#define XHCI_READ32(base, off) \
    (*((volatile uint32_t *)((base) + (off))))

#define XHCI_WRITE32(base, off, val) \
    (*((volatile uint32_t *)((base) + (off))) = (val))

#define XHCI_READ64(base, off) \
    (*((volatile uint64_t *)((base) + (off))))

#define XHCI_WRITE64(base, off, val) \
    (*((volatile uint64_t *)((base) + (off))) = (val))

/* ============================================================
 *   Controller Initialization
 * ============================================================ */

static bool xhci_reset(xhci_ctrl_t *ctrl) {
    /* Stop controller */
    uint32_t cmd = XHCI_READ32(ctrl->op_base, XHCI_USBCMD);
    XHCI_WRITE32(ctrl->op_base, XHCI_USBCMD, cmd & ~XHCI_CMD_RUN);

    /* Wait for halt */
    for (int i = 0; i < 100000; i++) {
        if (XHCI_READ32(ctrl->op_base, XHCI_USBSTS) & XHCI_STS_HCH)
            break;
    }

    /* Reset */
    XHCI_WRITE32(ctrl->op_base, XHCI_USBCMD, XHCI_CMD_HCRST);

    /* Wait for reset complete */
    for (int i = 0; i < 100000; i++) {
        uint32_t sts = XHCI_READ32(ctrl->op_base, XHCI_USBCMD);
        if (!(sts & XHCI_CMD_HCRST))
            break;
    }

    /* Wait for controller ready */
    for (int i = 0; i < 100000; i++) {
        if (!(XHCI_READ32(ctrl->op_base, XHCI_USBSTS) & XHCI_STS_CNR))
            return true;
    }

    return false;
}

static bool xhci_setup_rings(xhci_ctrl_t *ctrl) {
    /* Allocate command ring */
    ctrl->cmd_ring = fut_malloc_pages(1);
    if (!ctrl->cmd_ring) return false;
    memset(ctrl->cmd_ring, 0, 4096);
    ctrl->cmd_ring_enqueue = 0;
    ctrl->cmd_ring_cycle = 1;

    /* Allocate event ring segment */
    ctrl->evt_ring = fut_malloc_pages(1);
    if (!ctrl->evt_ring) return false;
    memset(ctrl->evt_ring, 0, 4096);
    ctrl->evt_ring_dequeue = 0;
    ctrl->evt_ring_cycle = 1;

    /* Allocate DCBAA (Device Context Base Address Array) */
    ctrl->dcbaa = fut_malloc_pages(1);
    if (!ctrl->dcbaa) return false;
    memset(ctrl->dcbaa, 0, 4096);

    return true;
}

static bool xhci_start(xhci_ctrl_t *ctrl) {
    /* Set max device slots */
    uint32_t slots = ctrl->max_slots < XHCI_MAX_SLOTS ? ctrl->max_slots : XHCI_MAX_SLOTS;
    XHCI_WRITE32(ctrl->op_base, XHCI_CONFIG, slots);

    /* Set DCBAAP */
    XHCI_WRITE64(ctrl->op_base, XHCI_DCBAAP, (uint64_t)(uintptr_t)ctrl->dcbaa);

    /* Set command ring pointer */
    uint64_t crcr = (uint64_t)(uintptr_t)ctrl->cmd_ring | ctrl->cmd_ring_cycle;
    XHCI_WRITE64(ctrl->op_base, XHCI_CRCR, crcr);

    /* Start controller */
    uint32_t cmd = XHCI_READ32(ctrl->op_base, XHCI_USBCMD);
    XHCI_WRITE32(ctrl->op_base, XHCI_USBCMD, cmd | XHCI_CMD_RUN | XHCI_CMD_INTE);

    /* Wait for running */
    for (int i = 0; i < 100000; i++) {
        if (!(XHCI_READ32(ctrl->op_base, XHCI_USBSTS) & XHCI_STS_HCH))
            return true;
    }

    return false;
}

/* ============================================================
 *   USB Device Enumeration
 * ============================================================ */

static void xhci_ring_cmd_doorbell(xhci_ctrl_t *ctrl) {
    XHCI_WRITE32(ctrl->db_base, 0, 0);
}

static xhci_trb_t *xhci_poll_event(xhci_ctrl_t *ctrl) {
    xhci_trb_t *evt_ring = (xhci_trb_t *)ctrl->evt_ring;
    xhci_trb_t *trb = &evt_ring[ctrl->evt_ring_dequeue];

    for (int i = 0; i < 100000; i++) {
        uint32_t cycle = trb->control & TRB_FLAG_CYCLE;
        if ((cycle != 0) == (ctrl->evt_ring_cycle != 0)) {
            ctrl->evt_ring_dequeue++;
            if (ctrl->evt_ring_dequeue >= EVT_RING_SIZE) {
                ctrl->evt_ring_dequeue = 0;
                ctrl->evt_ring_cycle ^= 1;
            }
            return trb;
        }
        for (volatile int j = 0; j < 100; j++);
    }

    return NULL;
}

/* ============================================================
 *   Public API
 * ============================================================ */

int apple_xhci_init(const fut_platform_info_t *info) {
    if (!info) return -1;

    memset(&g_xhci, 0, sizeof(g_xhci));

    /* Initialize PCIe first */
    if (info->pcie_base == 0 || info->pcie_cfg_base == 0) {
        fut_printf("[xHCI] PCIe not available\n");
        return -1;
    }

    ApplePcie *pcie = rust_apple_pcie_init(info->pcie_base,
                                            info->pcie_num_ports,
                                            info->pcie_cfg_base);
    if (!pcie) {
        fut_printf("[xHCI] Failed to initialize PCIe\n");
        return -1;
    }

    /* Scan for xHCI controller on PCIe bus */
    uint64_t xhci_bar = 0;
    for (uint32_t port = 0; port < info->pcie_num_ports; port++) {
        if (!rust_apple_pcie_port_link_up(pcie, port)) continue;

        uint8_t bus = port + 1;
        uint32_t class_rev = rust_apple_pcie_cfg_read32(pcie, bus, 0, 0, 0x08);
        uint32_t class_code = class_rev >> 8;

        if (class_code == PCI_CLASS_USB_XHCI) {
            /* Found xHCI controller - read BAR0 */
            uint32_t bar0_lo = rust_apple_pcie_cfg_read32(pcie, bus, 0, 0, 0x10);
            uint32_t bar0_hi = rust_apple_pcie_cfg_read32(pcie, bus, 0, 0, 0x14);
            xhci_bar = ((uint64_t)bar0_hi << 32) | (bar0_lo & ~0xFULL);

            /* Enable bus mastering and memory space */
            uint16_t cmd = rust_apple_pcie_cfg_read16(pcie, bus, 0, 0, 0x04);
            rust_apple_pcie_cfg_write32(pcie, bus, 0, 0, 0x04,
                                         (uint32_t)(cmd | 0x06));  /* MEM + BM */

            fut_printf("[xHCI] Found xHCI controller at bus %u, BAR=0x%lx\n",
                       bus, (unsigned long)xhci_bar);
            break;
        }
    }

    if (xhci_bar == 0) {
        fut_printf("[xHCI] No xHCI controller found on PCIe\n");
        return -1;
    }

    /* Map xHCI registers */
    g_xhci.cap_base = (volatile uint8_t *)xhci_bar;

    uint8_t cap_length = *(volatile uint8_t *)g_xhci.cap_base;
    g_xhci.op_base = g_xhci.cap_base + cap_length;

    uint32_t rtsoff = XHCI_READ32(g_xhci.cap_base, XHCI_RTSOFF) & ~0x1F;
    g_xhci.rt_base = g_xhci.cap_base + rtsoff;

    uint32_t dboff = XHCI_READ32(g_xhci.cap_base, XHCI_DBOFF) & ~0x3;
    g_xhci.db_base = g_xhci.cap_base + dboff;

    /* Read capabilities */
    uint32_t hcsparams1 = XHCI_READ32(g_xhci.cap_base, XHCI_HCSPARAMS1);
    g_xhci.max_slots = (hcsparams1 >> 0) & 0xFF;
    g_xhci.max_ports = (hcsparams1 >> 24) & 0xFF;

    fut_printf("[xHCI] Max slots: %u, Max ports: %u\n",
               g_xhci.max_slots, g_xhci.max_ports);

    /* Reset and initialize */
    if (!xhci_reset(&g_xhci)) {
        fut_printf("[xHCI] Controller reset failed\n");
        return -1;
    }

    if (!xhci_setup_rings(&g_xhci)) {
        fut_printf("[xHCI] Ring allocation failed\n");
        return -1;
    }

    if (!xhci_start(&g_xhci)) {
        fut_printf("[xHCI] Controller start failed\n");
        return -1;
    }

    g_xhci.initialized = true;
    fut_printf("[xHCI] Controller initialized\n");
    return 0;
}

int apple_xhci_enumerate(void) {
    if (!g_xhci.initialized) return -1;

    /* Check each port for connected devices */
    int found = 0;
    for (uint32_t port = 0; port < g_xhci.max_ports && port < XHCI_MAX_PORTS; port++) {
        /* Read port status/control register */
        uint32_t portsc_off = 0x400 + (port * 0x10);
        uint32_t portsc = XHCI_READ32(g_xhci.op_base, portsc_off);

        bool connected = (portsc & 0x01) != 0;  /* CCS bit */
        bool enabled = (portsc & 0x02) != 0;     /* PED bit */

        if (connected && enabled) {
            /* Issue Enable Slot command */
            xhci_trb_t *cmd_ring = (xhci_trb_t *)g_xhci.cmd_ring;
            xhci_trb_t *trb = &cmd_ring[g_xhci.cmd_ring_enqueue];
            memset(trb, 0, sizeof(*trb));
            trb->control = (TRB_ENABLE_SLOT << 10) |
                           (g_xhci.cmd_ring_cycle ? TRB_FLAG_CYCLE : 0);

            g_xhci.cmd_ring_enqueue++;
            xhci_ring_cmd_doorbell(&g_xhci);

            /* Wait for completion */
            xhci_trb_t *evt = xhci_poll_event(&g_xhci);
            if (evt && ((evt->control >> 10) & 0x3F) == TRB_CMD_COMPLETE) {
                uint8_t slot_id = (evt->control >> 24) & 0xFF;
                uint8_t comp_code = (evt->status >> 24) & 0xFF;

                if (comp_code == 1 && slot_id > 0) {  /* Success */
                    g_xhci.devices[found].slot_id = slot_id;
                    g_xhci.devices[found].port = port;
                    g_xhci.devices[found].present = true;
                    found++;
                    fut_printf("[xHCI] Device on port %u, slot %u\n", port, slot_id);
                }
            }
        }
    }

    g_xhci.num_devices = found;
    fut_printf("[xHCI] Enumerated %d USB device(s)\n", found);
    return found;
}

bool apple_xhci_get_device(uint32_t idx, xhci_usb_device_t *dev) {
    if (!g_xhci.initialized || idx >= g_xhci.num_devices || !dev) return false;
    *dev = g_xhci.devices[idx];
    return true;
}

int apple_xhci_control_transfer(uint8_t slot_id, uint8_t bmRequestType,
                                 uint8_t bRequest, uint16_t wValue,
                                 uint16_t wIndex, void *data, uint16_t wLength) {
    if (!g_xhci.initialized || slot_id == 0) return -1;

    /* Build Setup TRB */
    xhci_trb_t *cmd_ring = (xhci_trb_t *)g_xhci.cmd_ring;
    xhci_trb_t *setup = &cmd_ring[g_xhci.cmd_ring_enqueue++];
    setup->param = (uint64_t)bmRequestType |
                   ((uint64_t)bRequest << 8) |
                   ((uint64_t)wValue << 16) |
                   ((uint64_t)wIndex << 32) |
                   ((uint64_t)wLength << 48);
    setup->status = 8;  /* TRB transfer length = 8 (setup packet) */
    setup->control = (TRB_SETUP << 10) |
                     (g_xhci.cmd_ring_cycle ? TRB_FLAG_CYCLE : 0) |
                     (3 << 16);  /* IDT */

    /* Data TRB if needed */
    if (wLength > 0 && data) {
        xhci_trb_t *data_trb = &cmd_ring[g_xhci.cmd_ring_enqueue++];
        data_trb->param = (uint64_t)(uintptr_t)data;
        data_trb->status = wLength;
        data_trb->control = (TRB_DATA << 10) |
                            (g_xhci.cmd_ring_cycle ? TRB_FLAG_CYCLE : 0) |
                            ((bmRequestType & 0x80) ? (1 << 16) : 0);  /* DIR */
    }

    /* Status TRB */
    xhci_trb_t *status = &cmd_ring[g_xhci.cmd_ring_enqueue++];
    status->param = 0;
    status->status = 0;
    status->control = (TRB_STATUS << 10) |
                      TRB_FLAG_IOC |
                      (g_xhci.cmd_ring_cycle ? TRB_FLAG_CYCLE : 0) |
                      ((bmRequestType & 0x80) ? 0 : (1 << 16));

    /* Ring doorbell for slot */
    XHCI_WRITE32(g_xhci.db_base, slot_id * 4, 1);  /* EP 0 */

    /* Poll for completion */
    xhci_trb_t *evt = xhci_poll_event(&g_xhci);
    if (!evt) return -1;

    uint8_t comp_code = (evt->status >> 24) & 0xFF;
    if (comp_code == 1) {  /* Success */
        return wLength;
    }

    return -1;
}

int apple_xhci_bulk_transfer(uint8_t slot_id, uint8_t endpoint,
                              void *data, uint32_t length) {
    if (!g_xhci.initialized || slot_id == 0 || !data || length == 0) return -1;

    xhci_trb_t *cmd_ring = (xhci_trb_t *)g_xhci.cmd_ring;
    xhci_trb_t *trb = &cmd_ring[g_xhci.cmd_ring_enqueue++];

    trb->param = (uint64_t)(uintptr_t)data;
    trb->status = length;
    trb->control = (TRB_NORMAL << 10) |
                   TRB_FLAG_IOC |
                   (g_xhci.cmd_ring_cycle ? TRB_FLAG_CYCLE : 0);

    /* Ring doorbell: endpoint DCI = (ep_num * 2) + direction */
    uint8_t ep_num = endpoint & 0x0F;
    uint8_t dir = (endpoint & 0x80) ? 1 : 0;
    uint32_t dci = (ep_num * 2) + dir;
    XHCI_WRITE32(g_xhci.db_base, slot_id * 4, dci);

    xhci_trb_t *evt = xhci_poll_event(&g_xhci);
    if (!evt) return -1;

    uint8_t comp_code = (evt->status >> 24) & 0xFF;
    uint32_t residual = evt->status & 0xFFFFFF;

    if (comp_code == 1 || comp_code == 13) {  /* Success or Short Packet */
        return (int)(length - residual);
    }

    return -1;
}

int apple_xhci_platform_init(const fut_platform_info_t *info) {
    if (!info) return -1;

    if (info->type != PLATFORM_APPLE_M1 &&
        info->type != PLATFORM_APPLE_M2 &&
        info->type != PLATFORM_APPLE_M3 &&
        info->type != PLATFORM_APPLE_M4) {
        return 0;
    }

    if (info->pcie_base == 0) {
        return 0;  /* No PCIe available */
    }

    int ret = apple_xhci_init(info);
    if (ret == 0) {
        apple_xhci_enumerate();
    }
    return ret;
}
