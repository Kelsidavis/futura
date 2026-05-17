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
#include <platform/arm64/apple_pmgr.h>
#include <platform/arm64/memory/pmap.h>
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

    /* PA→VA via the kernel peripheral mapping window — Rust crates do
     * raw MMIO via the value as a pointer.  The xHCI BAR read out of
     * PCIe config below also gets converted before passing to the
     * xHCI Rust driver. */
    uint64_t pcie_va     = fut_kernel_peripheral_va(info->pcie_base);
    uint64_t pcie_cfg_va = fut_kernel_peripheral_va(info->pcie_cfg_base);
    ApplePcie *pcie = rust_apple_pcie_init(pcie_va,
                                            info->pcie_num_ports,
                                            pcie_cfg_va);
    if (!pcie) {
        fut_printf("[xHCI] Failed to initialize PCIe (PA pcie=0x%lx cfg=0x%lx)\n",
                   (unsigned long)info->pcie_base,
                   (unsigned long)info->pcie_cfg_base);
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

    /* Allocate the three buffers Rust needs.  fut_malloc_pages
     * returns a kernel VA in the high-half mapping; the xHCI
     * controller DMAs the rings + DCBAA directly without going
     * through the CPU page tables, so we have to also compute the
     * physical address for each and hand BOTH to Rust. */
    uint8_t *cmd_ring = fut_malloc_pages(XHCI_RING_PAGE_COUNT);
    uint8_t *evt_ring = fut_malloc_pages(XHCI_RING_PAGE_COUNT);
    uint8_t *dcbaa    = fut_malloc_pages(XHCI_RING_PAGE_COUNT);
    if (!cmd_ring || !evt_ring || !dcbaa) {
        fut_printf("[xHCI] Ring allocation failed\n");
        /* Free whichever sub-allocations succeeded; without this any
         * partial-success scenario leaks pages that the PMM can't
         * recover. */
        if (cmd_ring) fut_free_pages(cmd_ring, XHCI_RING_PAGE_COUNT);
        if (evt_ring) fut_free_pages(evt_ring, XHCI_RING_PAGE_COUNT);
        if (dcbaa)    fut_free_pages(dcbaa,    XHCI_RING_PAGE_COUNT);
        return -1;
    }
    memset(cmd_ring, 0, XHCI_RING_PAGE_COUNT * 4096);
    memset(evt_ring, 0, XHCI_RING_PAGE_COUNT * 4096);
    memset(dcbaa,    0, XHCI_RING_PAGE_COUNT * 4096);

    uint64_t cmd_ring_pa = pmap_virt_to_phys((uintptr_t)cmd_ring);
    uint64_t evt_ring_pa = pmap_virt_to_phys((uintptr_t)evt_ring);
    uint64_t dcbaa_pa    = pmap_virt_to_phys((uintptr_t)dcbaa);

    /* The xHCI controller's BAR0 is also a PA — convert to kernel VA
     * through the peripheral mapping window before handing to Rust. */
    uint64_t xhci_bar_va = fut_kernel_peripheral_va(xhci_bar);
    g_xhci.rust_ctrl = rust_apple_xhci_new(xhci_bar_va,
                                            cmd_ring, cmd_ring_pa,
                                            evt_ring, evt_ring_pa,
                                            dcbaa,    dcbaa_pa);
    if (!g_xhci.rust_ctrl) {
        fut_printf("[xHCI] rust_apple_xhci_new failed (PA BAR 0x%lx VA 0x%lx)\n",
                   (unsigned long)xhci_bar, (unsigned long)xhci_bar_va);
        fut_free_pages(cmd_ring, XHCI_RING_PAGE_COUNT);
        fut_free_pages(evt_ring, XHCI_RING_PAGE_COUNT);
        fut_free_pages(dcbaa,    XHCI_RING_PAGE_COUNT);
        return -1;
    }

    int rc = rust_apple_xhci_reset_and_start(g_xhci.rust_ctrl);
    if (rc != 0) {
        fut_printf("[xHCI] Controller reset/start failed (rc=%d)\n", rc);
        /* The Rust ctrl now holds references to the rings; rather
         * than free them here and risk a UAF if Rust tries to touch
         * them again on a future call, leave them allocated and
         * leak.  The kernel doesn't unload drivers anyway, so this
         * is a permanent leak only if init runs more than once,
         * which apple_xhci_platform_init guards against. */
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

    /* Defensive cap: rust_apple_xhci_enumerate is told the buffer
     * size and shouldn't return more, but a misbehaving controller
     * + future Rust crate revision could violate that contract.
     * Bound at the array size we declared. */
    if (found > XHCI_MAX_SLOTS) {
        fut_printf("[xHCI] Enumerate returned %d > %d, capping\n",
                   found, XHCI_MAX_SLOTS);
        found = XHCI_MAX_SLOTS;
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
    /* slot_id 0 is reserved (xHCI assigns slots starting at 1). */
    if (slot_id == 0) return -1;
    /* A caller passing data==NULL with wLength>0 would otherwise let
     * us program a TRB pointing at physical address 0 — Rust forwards
     * data_pa to the controller verbatim, and PA 0 is reserved RAM on
     * every supported platform.  Reject the obvious caller bug rather
     * than DMA into the trap. */
    if (!data && wLength > 0) return -1;
    /* Convert the caller's kernel-VA buffer to a physical address —
     * xHCI DMAs the data stage directly via TRB.param. */
    uint64_t data_pa = (data && wLength > 0)
                         ? pmap_virt_to_phys((uintptr_t)data) : 0;
    return rust_apple_xhci_control_transfer(g_xhci.rust_ctrl, slot_id,
                                             bmRequestType, bRequest,
                                             wValue, wIndex,
                                             data_pa, wLength);
}

int apple_xhci_bulk_transfer(uint8_t slot_id, uint8_t endpoint,
                              void *data, uint32_t length) {
    if (!g_xhci.initialized || !g_xhci.rust_ctrl) return -1;
    if (slot_id == 0) return -1;
    /* Same NULL+nonzero-length reject as control_transfer. */
    if (!data && length > 0) return -1;
    /* Same VA→PA conversion as control_transfer — TRB.param is a
     * physical address for the controller's DMA engine. */
    uint64_t data_pa = data ? pmap_virt_to_phys((uintptr_t)data) : 0;
    return rust_apple_xhci_bulk_transfer(g_xhci.rust_ctrl, slot_id, endpoint,
                                          data_pa, length);
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

    /* Bring up pmgr power domains for the PCIe root complex (the
     * xHCI controller hangs off PCIe).  Without this on cold boot
     * the PCIe link won't train and BAR reads return 0xFFFF.  m1n1
     * may have done it; this is idempotent. */
    extern uint64_t fut_platform_get_dtb(void);
    static const char *const pcie_paths[] = {
        "/soc/pcie@690000000",
        "/soc/pcie",
        "/arm-io/pcie",
        "/arm-io/pciec0",
        NULL,
    };
    int pcie_pmgr = apple_pmgr_enable_domains_any(fut_platform_get_dtb(),
                                                   pcie_paths);
    if (pcie_pmgr > 0) {
        fut_printf("[xHCI] pmgr: %d PCIe domains enabled\n", pcie_pmgr);
    }

    int ret = apple_xhci_init(info);
    if (ret == 0) {
        apple_xhci_enumerate();
    }
    return ret;
}
