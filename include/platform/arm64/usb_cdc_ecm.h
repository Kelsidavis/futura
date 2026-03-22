/* usb_cdc_ecm.h - USB CDC-ECM Ethernet Adapter Driver Header
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Provides network connectivity via USB Ethernet adapters (CDC-ECM class).
 */

#ifndef __FUTURA_USB_CDC_ECM_H__
#define __FUTURA_USB_CDC_ECM_H__

#include <stdint.h>
#include <stdbool.h>

/* Ethernet frame limits */
#define ETH_MTU         1500
#define ETH_FRAME_MAX   1518  /* MTU + 14 header + 4 FCS */
#define ETH_ADDR_LEN    6

/* CDC-ECM subclass/protocol */
#define CDC_SUBCLASS_ECM 0x06
#define CDC_PROTO_NONE   0x00

typedef struct {
    uint8_t  mac_addr[ETH_ADDR_LEN];
    uint8_t  slot_id;        /* USB device slot */
    uint8_t  bulk_in_ep;     /* Bulk IN endpoint */
    uint8_t  bulk_out_ep;    /* Bulk OUT endpoint */
    uint8_t  int_ep;         /* Interrupt endpoint */
    bool     link_up;
    bool     initialized;
    uint64_t rx_packets;
    uint64_t tx_packets;
    uint64_t rx_errors;
    uint64_t tx_errors;
} usb_cdc_ecm_ctx_t;

/**
 * Initialize USB CDC-ECM driver.
 * Scans enumerated USB devices for CDC-ECM adapters.
 * @return: 0 on success, negative on failure
 */
int usb_cdc_ecm_init(void);

/**
 * Send an Ethernet frame.
 * @param data: Frame data (including Ethernet header)
 * @param len: Frame length
 * @return: Bytes sent, or negative error
 */
int usb_cdc_ecm_send(const void *data, uint32_t len);

/**
 * Receive an Ethernet frame.
 * @param buf: Buffer for received frame
 * @param max_len: Maximum buffer length
 * @return: Bytes received, 0 if no data, negative error
 */
int usb_cdc_ecm_recv(void *buf, uint32_t max_len);

/**
 * Get the MAC address of the adapter.
 * @param mac_out: 6-byte output buffer
 * @return: true if available
 */
bool usb_cdc_ecm_get_mac(uint8_t *mac_out);

/**
 * Check if link is up.
 */
bool usb_cdc_ecm_link_up(void);

#endif /* __FUTURA_USB_CDC_ECM_H__ */
