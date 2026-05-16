/* apple_uart.c - Apple Silicon UART (s5l) — Rust-backed wrapper
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Samsung S5L-style UART used by Apple M1/M2/M3/M4 SoCs.  This file
 * is a thin C bridge over the Rust driver under
 * `drivers/rust/apple_uart` (Asahi-Linux-derived).  Per the project's
 * Rust-only-drivers policy the register-level work lives in Rust;
 * the C API below preserves the call-site signatures the rest of
 * the arm64 platform code targets so nothing else has to change.
 *
 * The previous hand-rolled C body had the right semantics but was
 * gradually drifting from the Rust port — keep one driver, not two.
 * The C wrapper caches the UART base populated by
 * fut_apple_uart_init() and forwards every subsequent call into the
 * Rust FFI, which is safe to call concurrently with the Rust UART's
 * own interrupt path.
 *
 * Compatibility note: the wrapper functions are no-ops until
 * fut_apple_uart_init() has cached a non-zero base — RPi / QEMU virt
 * builds never reach fut_apple_uart_init (which requires
 * info->uart_base from the Apple DTB), so this code is dormant on
 * those platforms.
 */

#include <platform/arm64/apple_uart.h>
#include <platform/platform.h>
#include <string.h>
#include <stddef.h>

/* Cached UART base populated by fut_apple_uart_init.  0 until then,
 * which the Rust FFI checks for and treats as "driver not ready". */
static uint64_t s5l_uart_base = 0;

/* Forward decl — installed as the serial-putc backend by init. */
void fut_apple_uart_putc_thunk(char ch);

/* ============================================================
 *   UART Initialization
 * ============================================================ */

bool fut_apple_uart_init(const fut_platform_info_t *info, uint32_t baudrate) {
    if (!info || info->uart_base == 0) {
        fut_printf("[UART] Error: Invalid platform info or missing UART base\n");
        return false;
    }
    if (baudrate == 0) {
        fut_printf("[UART] Error: Invalid baud rate (cannot be zero)\n");
        return false;
    }

    fut_printf("[UART] Initializing Apple s5l-uart (Rust driver)\n");
    fut_printf("[UART] Base address: 0x%016llx\n", info->uart_base);
    fut_printf("[UART] Baud rate: %u\n", baudrate);

    if (!rust_apple_uart_init(info->uart_base, baudrate)) {
        fut_printf("[UART] Error: rust_apple_uart_init failed\n");
        return false;
    }

    s5l_uart_base = info->uart_base;

    /* Hook into the platform-agnostic serial console.  After this
     * point, every fut_serial_putc() (and therefore every fut_printf)
     * delegates to the s5l-uart instead of the QEMU-virt PL011 MMIO
     * path.  The thunk adapts the public Apple UART API signature
     * (which used to take a fut_platform_info_t *) to the
     * platform-agnostic `void (*)(char)` shape. */
    extern void fut_serial_set_putc_backend(void (*fn)(char c));
    fut_serial_set_putc_backend(fut_apple_uart_putc_thunk);

    fut_printf("[UART] Apple s5l-uart initialized successfully\n");
    return true;
}

/* ============================================================
 *   Character I/O (C API wrappers)
 * ============================================================ */

void fut_apple_uart_putc(const fut_platform_info_t *info, char ch) {
    (void)info;
    if (s5l_uart_base == 0) {
        return;
    }
    rust_apple_uart_putc(s5l_uart_base, (uint8_t)ch);
    if (ch == '\n') {
        /* Rust putc already expands \n to \r\n; nothing extra needed. */
    }
}

int fut_apple_uart_getc(const fut_platform_info_t *info) {
    (void)info;
    if (s5l_uart_base == 0) {
        return -1;
    }
    return rust_apple_uart_getc(s5l_uart_base);
}

void fut_apple_uart_puts(const fut_platform_info_t *info, const char *str) {
    (void)info;
    if (s5l_uart_base == 0 || !str) {
        return;
    }
    rust_apple_uart_puts(s5l_uart_base, (const uint8_t *)str);
}

/* ============================================================
 *   Platform Integration
 * ============================================================ */

void fut_apple_uart_platform_init(const fut_platform_info_t *info) {
    if (!info || !info->uart_base) {
        fut_printf("[APPLE] Error: Cannot initialize UART - missing base address\n");
        return;
    }

    fut_printf("[APPLE] Initializing Apple Silicon UART subsystem\n");

    if (!fut_apple_uart_init(info, APPLE_UART_BAUDRATE)) {
        fut_printf("[APPLE] Error: Failed to initialize Apple UART\n");
        return;
    }

    /* Test UART output */
    fut_apple_uart_puts(info, "[APPLE] UART console ready\n");

    fut_printf("[APPLE] Apple UART subsystem initialized successfully\n");
}

/* Thin trampoline so platform.h's `void (*)(char)` backend signature
 * matches the public Apple UART API which takes a platform_info ptr. */
void fut_apple_uart_putc_thunk(char ch) {
    fut_apple_uart_putc(NULL, ch);
}
