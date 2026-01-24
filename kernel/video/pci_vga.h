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

/**
 * Initialize bochs VGA device to specified resolution and bit depth
 * This is needed for QEMU's stdvga (bochs VGA) to properly display output
 *
 * @param width Display width in pixels
 * @param height Display height in pixels
 * @param bpp Bits per pixel (typically 32)
 * @return 0 on success, -1 on failure
 */
int bochs_vga_init(uint16_t width, uint16_t height, uint16_t bpp);

#endif /* KERNEL_VIDEO_PCI_VGA_H */
