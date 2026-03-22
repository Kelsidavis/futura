/* usb_cdc_ecm.c - USB CDC-ECM Ethernet Adapter Driver
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Network connectivity via USB Ethernet adapters (CDC-ECM class).
 * Depends on the xHCI driver for USB transport.
 */

#include <platform/arm64/usb_cdc_ecm.h>
#include <platform/arm64/apple_xhci.h>
#include <platform/platform.h>
#include <string.h>

/* USB CDC class requests */
#define CDC_SET_ETH_MULTICAST_FILTERS  0x40
#define CDC_SET_ETH_PM_PATTERN_FILTER  0x41
#define CDC_GET_ETH_PM_PATTERN_FILTER  0x42
#define CDC_SET_ETH_PACKET_FILTER      0x43
#define CDC_GET_ETH_STATISTIC          0x44

/* Packet filter bits */
#define CDC_PACKET_TYPE_PROMISCUOUS    (1 << 0)
#define CDC_PACKET_TYPE_ALL_MULTICAST  (1 << 1)
#define CDC_PACKET_TYPE_DIRECTED       (1 << 2)
#define CDC_PACKET_TYPE_BROADCAST      (1 << 3)
#define CDC_PACKET_TYPE_MULTICAST      (1 << 4)

static usb_cdc_ecm_ctx_t g_ecm;

int usb_cdc_ecm_init(void) {
    memset(&g_ecm, 0, sizeof(g_ecm));

    /* Scan enumerated USB devices for CDC-ECM class */
    xhci_usb_device_t dev;
    bool found = false;

    for (uint32_t i = 0; ; i++) {
        if (!apple_xhci_get_device(i, &dev)) break;
        if (!dev.present) continue;

        /* Read device descriptor to check class */
        usb_device_descriptor_t desc;
        int ret = apple_xhci_control_transfer(
            dev.slot_id,
            0x80,       /* bmRequestType: Device-to-Host, Standard, Device */
            0x06,       /* GET_DESCRIPTOR */
            0x0100,     /* Device descriptor */
            0,
            &desc,
            sizeof(desc)
        );

        if (ret < 0) continue;

        /* Check for CDC class (bDeviceClass=0x02) or interface-level CDC */
        if (desc.bDeviceClass == USB_CLASS_CDC ||
            desc.bDeviceClass == 0xEF) {  /* Misc class (composite) */

            g_ecm.slot_id = dev.slot_id;

            /* Default endpoint assignments for CDC-ECM:
             * Bulk IN: EP 1 IN (0x81)
             * Bulk OUT: EP 2 OUT (0x02)
             * Interrupt: EP 3 IN (0x83)
             */
            g_ecm.bulk_in_ep = 0x81;
            g_ecm.bulk_out_ep = 0x02;
            g_ecm.int_ep = 0x83;

            /* Get MAC address from string descriptor (index from functional descriptor) */
            /* Fallback: use a locally-administered MAC */
            g_ecm.mac_addr[0] = 0x02;  /* Locally administered */
            g_ecm.mac_addr[1] = 0xFU;
            g_ecm.mac_addr[2] = 0x00;
            g_ecm.mac_addr[3] = 0x00;
            g_ecm.mac_addr[4] = 0x00;
            g_ecm.mac_addr[5] = dev.slot_id;

            /* Set packet filter to accept directed + broadcast */
            uint16_t filter = CDC_PACKET_TYPE_DIRECTED | CDC_PACKET_TYPE_BROADCAST;
            apple_xhci_control_transfer(
                dev.slot_id,
                0x21,       /* bmRequestType: Host-to-Device, Class, Interface */
                CDC_SET_ETH_PACKET_FILTER,
                filter,
                0,          /* Interface 0 */
                NULL,
                0
            );

            found = true;
            g_ecm.link_up = true;
            g_ecm.initialized = true;

            fut_printf("[CDC-ECM] USB Ethernet adapter found on slot %u\n",
                       dev.slot_id);
            fut_printf("[CDC-ECM] MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                       g_ecm.mac_addr[0], g_ecm.mac_addr[1], g_ecm.mac_addr[2],
                       g_ecm.mac_addr[3], g_ecm.mac_addr[4], g_ecm.mac_addr[5]);
            break;
        }
    }

    if (!found) {
        fut_printf("[CDC-ECM] No USB Ethernet adapter found\n");
        return -1;
    }

    return 0;
}

int usb_cdc_ecm_send(const void *data, uint32_t len) {
    if (!g_ecm.initialized || !data || len == 0 || len > ETH_FRAME_MAX) {
        return -1;
    }

    int ret = apple_xhci_bulk_transfer(g_ecm.slot_id, g_ecm.bulk_out_ep,
                                        (void *)data, len);
    if (ret > 0) {
        g_ecm.tx_packets++;
    } else {
        g_ecm.tx_errors++;
    }

    return ret;
}

int usb_cdc_ecm_recv(void *buf, uint32_t max_len) {
    if (!g_ecm.initialized || !buf || max_len == 0) {
        return -1;
    }

    int ret = apple_xhci_bulk_transfer(g_ecm.slot_id, g_ecm.bulk_in_ep,
                                        buf, max_len);
    if (ret > 0) {
        g_ecm.rx_packets++;
    } else if (ret < 0) {
        g_ecm.rx_errors++;
    }

    return ret;
}

bool usb_cdc_ecm_get_mac(uint8_t *mac_out) {
    if (!g_ecm.initialized || !mac_out) return false;
    memcpy(mac_out, g_ecm.mac_addr, ETH_ADDR_LEN);
    return true;
}

bool usb_cdc_ecm_link_up(void) {
    return g_ecm.initialized && g_ecm.link_up;
}
