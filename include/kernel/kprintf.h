/* kernel/kprintf.h - Kernel printf declaration
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Minimal header providing fut_printf() declaration for kernel code.
 * This replaces scattered 'extern void fut_printf(...)' declarations
 * throughout the kernel with a single authoritative header.
 *
 * Usage:
 *   #include <kernel/kprintf.h>
 *   fut_printf("[SUBSYS] message: %d\n", value);
 *
 * Implementation is in platform-specific code (serial/UART output).
 */

#pragma once

/**
 * fut_printf - Formatted kernel output
 *
 * @param fmt Format string (printf-style)
 * @param ... Variable arguments
 *
 * Outputs formatted text to the kernel console (typically serial port).
 * Safe to call from any kernel context including interrupt handlers.
 *
 * Supported format specifiers:
 *   %d, %i  - Signed decimal integer
 *   %u      - Unsigned decimal integer
 *   %x, %X  - Hexadecimal (lowercase/uppercase)
 *   %p      - Pointer (prints as 0x...)
 *   %s      - Null-terminated string
 *   %c      - Character
 *   %lld    - Long long signed
 *   %llu    - Long long unsigned
 *   %llx    - Long long hexadecimal
 *   %zu     - size_t
 *   %%      - Literal percent sign
 *
 * Width and precision modifiers are supported (e.g., %08x, %.2f).
 */
void fut_printf(const char *fmt, ...);
