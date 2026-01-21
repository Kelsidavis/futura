// SPDX-License-Identifier: MPL-2.0
/*
 * fb.h - Framebuffer interface definitions
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Provides framebuffer initialization and information retrieval for
 * graphical output. Supports multiple discovery methods:
 *   - Multiboot2 framebuffer tag (GRUB)
 *   - VirtIO GPU (QEMU)
 *   - PCI VGA BAR discovery
 *   - Device tree (ARM64)
 *
 * The framebuffer provides a linear memory region that can be
 * directly written to display pixels on screen.
 */

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <futura/fb_ioctl.h>

/**
 * Hardware framebuffer information.
 *
 * Contains physical address and geometry needed to access and
 * map the framebuffer for display output.
 */
struct fut_fb_hwinfo {
    uint64_t phys;              /**< Physical base address of framebuffer */
    uint64_t length;            /**< Total bytes in framebuffer region */
    struct fut_fb_info info;    /**< Public geometry (width, height, pitch, bpp) */
};

/**
 * Probe framebuffer from multiboot2 information.
 *
 * Extracts framebuffer configuration from multiboot2 tags provided
 * by GRUB or compatible bootloaders.
 *
 * @param mb_info  Pointer to multiboot2 information structure
 * @return 0 on success, -1 if no framebuffer tag found
 */
int fb_probe_from_multiboot(const void *mb_info);

/**
 * Get current framebuffer hardware information.
 *
 * @param out  Output structure to fill with framebuffer info
 * @return 0 on success, -1 if no framebuffer available
 */
int fb_get_info(struct fut_fb_hwinfo *out);

/**
 * Check if a framebuffer is available.
 *
 * @return true if framebuffer was successfully initialized
 */
bool fb_is_available(void);

/**
 * Initialize framebuffer and display boot splash.
 *
 * Discovers and initializes the framebuffer through available
 * methods (multiboot, VirtIO, PCI), then displays the boot logo.
 * Must be called early in boot.
 */
void fb_boot_splash(void);

/**
 * Initialize character rendering for framebuffer console.
 *
 * Loads the bitmap font and prepares for text output.
 * Called after fb_boot_splash().
 */
void fb_char_init(void);
