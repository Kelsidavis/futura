// SPDX-License-Identifier: MPL-2.0
/*
 * cirrus_vga.h - Cirrus Logic VGA Device Driver
 */

#ifndef KERNEL_VIDEO_CIRRUS_VGA_H
#define KERNEL_VIDEO_CIRRUS_VGA_H

/**
 * Initialize Cirrus VGA device for linear framebuffer mode
 *
 * @return 0 on success, -1 on failure
 */
int cirrus_vga_init(void);

#endif /* KERNEL_VIDEO_CIRRUS_VGA_H */
