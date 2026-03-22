/* apple_xhci.h - Apple Silicon USB xHCI Controller Header
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * USB support via PCIe-attached xHCI controller on Apple Silicon.
 */

#ifndef __FUTURA_APPLE_XHCI_H__
#define __FUTURA_APPLE_XHCI_H__

#include <stdint.h>
#include <stdbool.h>
#include <platform/arm64/dtb.h>

/* USB device class codes */
#define USB_CLASS_HID          0x03
#define USB_CLASS_MASS_STORAGE 0x08
#define USB_CLASS_CDC          0x02
#define USB_CLASS_CDC_DATA     0x0A
#define USB_CLASS_HUB          0x09

/* xHCI capability register offsets */
#define XHCI_CAPLENGTH      0x00
#define XHCI_HCSPARAMS1     0x04
#define XHCI_HCSPARAMS2     0x08
#define XHCI_HCSPARAMS3     0x0C
#define XHCI_HCCPARAMS1     0x10
#define XHCI_DBOFF          0x14
#define XHCI_RTSOFF         0x18

/* xHCI operational register offsets (relative to op_base) */
#define XHCI_USBCMD         0x00
#define XHCI_USBSTS         0x04
#define XHCI_PAGESIZE       0x08
#define XHCI_DNCTRL         0x14
#define XHCI_CRCR           0x18
#define XHCI_DCBAAP          0x30
#define XHCI_CONFIG          0x38

/* USBCMD bits */
#define XHCI_CMD_RUN         (1 << 0)
#define XHCI_CMD_HCRST       (1 << 1)
#define XHCI_CMD_INTE        (1 << 2)

/* USBSTS bits */
#define XHCI_STS_HCH        (1 << 0)  /* HC halted */
#define XHCI_STS_EINT       (1 << 3)  /* Event interrupt */
#define XHCI_STS_CNR        (1 << 11) /* Controller not ready */

/* Maximum supported USB devices */
#define XHCI_MAX_SLOTS       32
#define XHCI_MAX_PORTS       8

/* USB device descriptor */
typedef struct {
    uint8_t  bLength;
    uint8_t  bDescriptorType;
    uint16_t bcdUSB;
    uint8_t  bDeviceClass;
    uint8_t  bDeviceSubClass;
    uint8_t  bDeviceProtocol;
    uint8_t  bMaxPacketSize0;
    uint16_t idVendor;
    uint16_t idProduct;
    uint16_t bcdDevice;
    uint8_t  iManufacturer;
    uint8_t  iProduct;
    uint8_t  iSerialNumber;
    uint8_t  bNumConfigurations;
} __attribute__((packed)) usb_device_descriptor_t;

/* Discovered USB device */
typedef struct {
    uint8_t  slot_id;
    uint8_t  port;
    uint8_t  dev_class;
    uint8_t  dev_subclass;
    uint16_t vendor_id;
    uint16_t product_id;
    bool     present;
} xhci_usb_device_t;

/* xHCI controller context */
typedef struct {
    /* MMIO bases */
    volatile uint8_t *cap_base;     /* Capability registers */
    volatile uint8_t *op_base;      /* Operational registers */
    volatile uint8_t *rt_base;      /* Runtime registers */
    volatile uint8_t *db_base;      /* Doorbell array */

    /* Ring buffers (page-aligned) */
    void *cmd_ring;                 /* Command ring */
    void *evt_ring;                 /* Event ring segment */
    void *dcbaa;                    /* Device Context Base Address Array */

    /* State */
    uint32_t max_slots;
    uint32_t max_ports;
    uint32_t cmd_ring_enqueue;
    uint32_t evt_ring_dequeue;
    uint8_t  cmd_ring_cycle;
    uint8_t  evt_ring_cycle;

    /* Discovered devices */
    xhci_usb_device_t devices[XHCI_MAX_SLOTS];
    uint32_t num_devices;

    bool initialized;
} xhci_ctrl_t;

/**
 * Initialize xHCI controller found on the Apple PCIe bus.
 * @param info: Platform information
 * @return: 0 on success, negative on failure
 */
int apple_xhci_init(const fut_platform_info_t *info);

/**
 * Enumerate USB devices on the bus.
 * @return: Number of devices found
 */
int apple_xhci_enumerate(void);

/**
 * Get discovered USB device by index.
 * @param idx: Device index (0-based)
 * @param dev: Output device info
 * @return: true if device exists at index
 */
bool apple_xhci_get_device(uint32_t idx, xhci_usb_device_t *dev);

/**
 * Perform a USB control transfer.
 * @param slot_id: Device slot
 * @param bmRequestType: Request type
 * @param bRequest: Request code
 * @param wValue: Value
 * @param wIndex: Index
 * @param data: Data buffer
 * @param wLength: Data length
 * @return: Bytes transferred, or negative error
 */
int apple_xhci_control_transfer(uint8_t slot_id, uint8_t bmRequestType,
                                 uint8_t bRequest, uint16_t wValue,
                                 uint16_t wIndex, void *data, uint16_t wLength);

/**
 * Perform a USB bulk transfer.
 * @param slot_id: Device slot
 * @param endpoint: Endpoint address
 * @param data: Data buffer
 * @param length: Transfer length
 * @return: Bytes transferred, or negative error
 */
int apple_xhci_bulk_transfer(uint8_t slot_id, uint8_t endpoint,
                              void *data, uint32_t length);

/**
 * Platform integration entry point.
 */
int apple_xhci_platform_init(const fut_platform_info_t *info);

#endif /* __FUTURA_APPLE_XHCI_H__ */
