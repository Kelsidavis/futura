/* apple_xhci.c - Apple Silicon xHCI — Rust-backed wrapper
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * USB on Apple Silicon is xHCI hanging off the Apple PCIe root
 * complex.  All controller bring-up — reset, ring management,
 * doorbell writes, port enumeration, control/bulk transfers — lives
 * in the Rust apple_xhci crate under drivers/rust/apple_xhci.  This
 * C file is the thin glue layer that:
 *
 *   1. Walks the Apple PCIe ECAM via rust_apple_pcie_cfg_read32()
 *      looking for a class-code 0x0C0330 device, reads its BAR0,
 *      and enables MEM + bus mastering through the same path.
 *   2. Allocates the command ring, event ring, and DCBAA pages from
 *      the kernel page allocator (these are the only buffers Rust
 *      cannot allocate itself in no_std).
 *   3. Hands those resources to rust_apple_xhci_new() and stores the
 *      singleton handle.
 *   4. Forwards the legacy public API (apple_xhci_*) to the Rust
 *      side, preserving usb_cdc_ecm.c's existing call sites unchanged.
 *
 * Compat note: apple_xhci_platform_init() gates on
 * info->type == PLATFORM_APPLE_M[1-4] so RPi and QEMU virt boots
 * never reach the Rust driver.
 */

#include <platform/arm64/apple_xhci.h>
#include <platform/arm64/apple_pcie.h>
#include <platform/platform.h>
#include <kernel/fut_memory.h>
#include <string.h>

/* PCI class code for xHCI (USB 3.0 host controller) */
#define PCI_CLASS_USB_XHCI  0x0C0330

/* Ring buffer sizing — must match the Rust crate's CMD_RING_SIZE /
 * EVT_RING_SIZE.  One 4 KiB page comfortably holds 64 × 16-byte TRBs
 * plus the link TRB slack. */
#define XHCI_RING_PAGE_COUNT  1

/* Public-API state holder — keeps the discovered USB devices visible
 * via apple_xhci_get_device() and provides a place to stash the Rust
 * handle. */
static struct {
    AppleXhci *rust_ctrl;
    xhci_usb_device_t devices[XHCI_MAX_SLOTS];
    uint32_t num_devices;
    bool initialized;
} g_xhci;

/* ============================================================
 *   Public API
 * ============================================================ */

int apple_xhci_init(const fut_platform_info_t *info) {
    if (!info) return -1;

    memset(&g_xhci, 0, sizeof(g_xhci));

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

        uint8_t bus = (uint8_t)(port + 1);
        uint32_t class_rev = rust_apple_pcie_cfg_read32(pcie, bus, 0, 0, 0x08);
        uint32_t class_code = class_rev >> 8;

        if (class_code == PCI_CLASS_USB_XHCI) {
            uint32_t bar0_lo = rust_apple_pcie_cfg_read32(pcie, bus, 0, 0, 0x10);
            uint32_t bar0_hi = rust_apple_pcie_cfg_read32(pcie, bus, 0, 0, 0x14);
            xhci_bar = ((uint64_t)bar0_hi << 32) | (bar0_lo & ~0xFULL);

            /* Enable MEM + Bus Mastering */
            uint16_t cmd = rust_apple_pcie_cfg_read16(pcie, bus, 0, 0, 0x04);
            rust_apple_pcie_cfg_write32(pcie, bus, 0, 0, 0x04,
                                         (uint32_t)(cmd | 0x06));

            fut_printf("[xHCI] Found xHCI controller at bus %u, BAR=0x%lx\n",
                       bus, (unsigned long)xhci_bar);
            break;
        }
    }

    if (xhci_bar == 0) {
        fut_printf("[xHCI] No xHCI controller found on PCIe\n");
        return -1;
    }

    /* Allocate the three buffers Rust needs.  Pages are guaranteed
     * 4 KiB aligned and physically contiguous in the kernel's
     * identity-mapped region, so vaddr == paddr from the controller's
     * point of view. */
    uint8_t *cmd_ring = fut_malloc_pages(XHCI_RING_PAGE_COUNT);
    uint8_t *evt_ring = fut_malloc_pages(XHCI_RING_PAGE_COUNT);
    uint8_t *dcbaa    = fut_malloc_pages(XHCI_RING_PAGE_COUNT);
    if (!cmd_ring || !evt_ring || !dcbaa) {
        fut_printf("[xHCI] Ring allocation failed\n");
        return -1;
    }
    memset(cmd_ring, 0, XHCI_RING_PAGE_COUNT * 4096);
    memset(evt_ring, 0, XHCI_RING_PAGE_COUNT * 4096);
    memset(dcbaa,    0, XHCI_RING_PAGE_COUNT * 4096);

    g_xhci.rust_ctrl = rust_apple_xhci_new(xhci_bar, cmd_ring, evt_ring, dcbaa);
    if (!g_xhci.rust_ctrl) {
        fut_printf("[xHCI] rust_apple_xhci_new failed\n");
        return -1;
    }

    int rc = rust_apple_xhci_reset_and_start(g_xhci.rust_ctrl);
    if (rc != 0) {
        fut_printf("[xHCI] Controller reset/start failed (rc=%d)\n", rc);
        return -1;
    }

    fut_printf("[xHCI] Controller running: %u slots, %u ports\n",
               rust_apple_xhci_max_slots(g_xhci.rust_ctrl),
               rust_apple_xhci_max_ports(g_xhci.rust_ctrl));

    g_xhci.initialized = true;
    return 0;
}

int apple_xhci_enumerate(void) {
    if (!g_xhci.initialized || !g_xhci.rust_ctrl) return -1;

    uint8_t ports[XHCI_MAX_SLOTS];
    uint8_t slots[XHCI_MAX_SLOTS];
    int32_t found = rust_apple_xhci_enumerate(g_xhci.rust_ctrl,
                                               ports, slots,
                                               XHCI_MAX_SLOTS);
    if (found < 0) {
        fut_printf("[xHCI] Enumerate failed (%d)\n", found);
        return found;
    }

    for (int32_t i = 0; i < found; i++) {
        g_xhci.devices[i].slot_id = slots[i];
        g_xhci.devices[i].port    = ports[i];
        g_xhci.devices[i].present = true;
        fut_printf("[xHCI] Device on port %u, slot %u\n",
                   ports[i], slots[i]);
    }
    g_xhci.num_devices = (uint32_t)found;
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
    if (!g_xhci.initialized || !g_xhci.rust_ctrl) return -1;
    return rust_apple_xhci_control_transfer(g_xhci.rust_ctrl, slot_id,
                                             bmRequestType, bRequest,
                                             wValue, wIndex,
                                             (uint8_t *)data, wLength);
}

int apple_xhci_bulk_transfer(uint8_t slot_id, uint8_t endpoint,
                              void *data, uint32_t length) {
    if (!g_xhci.initialized || !g_xhci.rust_ctrl) return -1;
    return rust_apple_xhci_bulk_transfer(g_xhci.rust_ctrl, slot_id, endpoint,
                                          (uint8_t *)data, length);
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
        return 0;
    }

    int ret = apple_xhci_init(info);
    if (ret == 0) {
        apple_xhci_enumerate();
    }
    return ret;
}
