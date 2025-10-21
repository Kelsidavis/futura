// SPDX-License-Identifier: MPL-2.0
/*
 * pci_vga.h - PCI VGA Device Discovery Header
 */

#ifndef KERNEL_VIDEO_PCI_VGA_H
#define KERNEL_VIDEO_PCI_VGA_H

#include <stdint.h>

/**
 * Scan PCI bus for VGA devices and discover framebuffer address
 * @return Physical address of framebuffer, or 0 if not found
 */
uint64_t pci_find_vga_framebuffer(void);

/**
 * Probe for VGA device and initialize framebuffer from PCI discovery
 * @return 0 on success, -1 if no VGA device found
 */
int fb_probe_pci_vga(void);

#endif /* KERNEL_VIDEO_PCI_VGA_H */
