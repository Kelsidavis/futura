// SPDX-License-Identifier: MPL-2.0
/*
 * fb_console.h - Framebuffer-based console driver
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Provides text output directly to framebuffer memory for ARM64 and x86_64,
 * without requiring a serial console. Useful for embedded systems, headless
 * QEMU, and early boot before serial is initialized.
 *
 * Features:
 *   - Built-in bitmap font (8x16 pixels per character)
 *   - Automatic line wrapping and scrolling
 *   - Supports newline, carriage return, tab
 *   - Works with any linear framebuffer (32-bit ARGB)
 *
 * The console uses the framebuffer discovered by fb_boot_splash() or
 * configured via multiboot/device tree information.
 */

#ifndef KERNEL_FB_CONSOLE_H
#define KERNEL_FB_CONSOLE_H

#include <stdint.h>
#include <stddef.h>

/**
 * Initialize the framebuffer console.
 *
 * Must be called after framebuffer initialization (fb_boot_splash).
 * Sets up the console with default colors and clears the screen.
 *
 * @return 0 on success, -1 if framebuffer not available
 */
int fb_console_init(void);

/**
 * Write a string to the framebuffer console.
 *
 * Handles special characters (newline, carriage return, tab).
 * Automatically wraps at end of line and scrolls at bottom.
 *
 * @param str  String to write (does not need to be null-terminated)
 * @param len  Number of characters to write
 */
void fb_console_write(const char *str, size_t len);

/**
 * Write a single character to the console.
 *
 * @param c  Character to write
 */
void fb_console_putc(char c);

/**
 * Write a character at a specific screen position.
 *
 * Useful for status displays or debugging overlays. Does not
 * update the cursor position.
 *
 * @param x  Column (0 to width-1)
 * @param y  Row (0 to height-1)
 * @param c  Character to write
 */
void fb_console_putc_at(int x, int y, char c);

/**
 * Clear the entire console screen.
 *
 * Fills with background color and resets cursor to top-left.
 */
void fb_console_clear(void);

/**
 * Get console dimensions in characters.
 *
 * @param width   Output: number of columns (may be NULL)
 * @param height  Output: number of rows (may be NULL)
 */
void fb_console_get_dimensions(int *width, int *height);

#endif /* KERNEL_FB_CONSOLE_H */
