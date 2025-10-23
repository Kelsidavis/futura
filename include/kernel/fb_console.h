// SPDX-License-Identifier: MPL-2.0
/*
 * fb_console.h - Framebuffer-based console driver for ARM64 and x86_64
 *
 * Provides text output directly to framebuffer memory without requiring
 * a serial console. Useful for embedded systems and headless QEMU.
 */

#ifndef KERNEL_FB_CONSOLE_H
#define KERNEL_FB_CONSOLE_H

#include <stdint.h>
#include <stddef.h>

/* Initialize framebuffer console with discovered framebuffer */
int fb_console_init(void);

/* Write a string to the framebuffer console */
void fb_console_write(const char *str, size_t len);

/* Write a single character */
void fb_console_putc(char c);

/* Put character at specific position (for debugging) */
void fb_console_putc_at(int x, int y, char c);

/* Clear the framebuffer console */
void fb_console_clear(void);

/* Get console dimensions */
void fb_console_get_dimensions(int *width, int *height);

#endif /* KERNEL_FB_CONSOLE_H */
