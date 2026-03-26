/* kernel/pci.h - PCI bus enumeration
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 */

#ifndef KERNEL_PCI_H
#define KERNEL_PCI_H

#include <stdint.h>

#define PCI_MAX_DEVICES 64

struct pci_device {
    uint8_t  bus;
    uint8_t  dev;
    uint8_t  func;
    uint16_t vendor_id;
    uint16_t device_id;
    uint8_t  class_code;     /* PCI class */
    uint8_t  subclass;       /* PCI subclass */
    uint8_t  prog_if;        /* programming interface */
    uint8_t  revision;
    uint8_t  header_type;
    uint16_t subsys_vendor;
    uint16_t subsys_id;
    uint8_t  irq_line;
};

void pci_enumerate(void);
int  pci_device_count(void);
const struct pci_device *pci_get_device(int index);

#endif /* KERNEL_PCI_H */
