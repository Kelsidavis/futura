// SPDX-License-Identifier: MPL-2.0
#pragma once

#include <stdint.h>

/* ARM64 PCI ECAM functions */
void arm64_pci_init(void);
uint32_t arm64_pci_read32(uint8_t bus, uint8_t dev, uint8_t fn, uint16_t reg);
void arm64_pci_write32(uint8_t bus, uint8_t dev, uint8_t fn, uint16_t reg, uint32_t value);
uint16_t arm64_pci_read16(uint8_t bus, uint8_t dev, uint8_t fn, uint16_t reg);
void arm64_pci_write16(uint8_t bus, uint8_t dev, uint8_t fn, uint16_t reg, uint16_t value);
uint8_t arm64_pci_read8(uint8_t bus, uint8_t dev, uint8_t fn, uint16_t reg);
int arm64_pci_scan_device(uint8_t bus, uint8_t dev, uint8_t fn,
                           uint16_t *vendor_id, uint16_t *device_id,
                           uint8_t *class_code, uint8_t *subclass);
uint64_t arm64_pci_get_bar(uint8_t bus, uint8_t dev, uint8_t fn, uint8_t bar_num);
uint64_t arm64_pci_assign_bar(uint8_t bus, uint8_t dev, uint8_t fn, uint8_t bar_num);

/* PCI vendor/device IDs */
#define PCI_VENDOR_REDHAT_QUMRANET  0x1AF4
#define PCI_DEVICE_VIRTIO_GPU        0x1050

/* PCI class codes */
#define PCI_CLASS_DISPLAY            0x03
