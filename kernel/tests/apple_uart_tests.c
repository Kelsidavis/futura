/* apple_uart_tests.c - base=0 guard tests for apple_uart Rust FFI
 *
 * Copyright (c) 2026 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * apple_uart drives the Apple Silicon s5l-style UART used as the
 * primary console.  Every function checks `base == 0` before
 * dereferencing the MMIO pointer — these tests assert those guards
 * (since the kernel test harness doesn't have a real Apple UART).
 */

#ifdef __aarch64__

#include <platform/arm64/apple_uart.h>
#include <kernel/kprintf.h>
#include <stdint.h>
#include <stddef.h>

extern void fut_test_pass(void);
extern void fut_test_fail(uint16_t code);

#define UART_PASS(name) \
    do { \
        fut_printf("[UART-TEST] PASS: %s\n", name); \
        fut_test_pass(); \
    } while (0)

#define UART_FAIL(name, code) \
    do { \
        fut_printf("[UART-TEST] FAIL: %s (code=%u)\n", name, (unsigned)(code)); \
        fut_test_fail((uint16_t)(code)); \
    } while (0)

void fut_apple_uart_test_thread(void *arg)
{
    (void)arg;
    fut_printf("[UART-TEST] starting apple_uart base=0 guard tests\n");

    /* T1: init(0, 115200) → 0 (refuses zero base) */
    {
        if (rust_apple_uart_init(0, 115200) == 0) UART_PASS("init(base=0)");
        else { UART_FAIL("init(base=0)", 1); return; }
    }

    /* T2: init(0x1000, 0) → 0 (refuses zero baudrate) */
    {
        if (rust_apple_uart_init(0x1000, 0) == 0) UART_PASS("init(baud=0)");
        else { UART_FAIL("init(baud=0)", 2); return; }
    }

    /* T3: putc(0, ...) → no-op (no crash) */
    {
        rust_apple_uart_putc(0, 'X');
        UART_PASS("putc(base=0) no-op");
    }

    /* T4: getc(0) → -1 */
    {
        if (rust_apple_uart_getc(0) == -1) UART_PASS("getc(base=0) → -1");
        else { UART_FAIL("getc(base=0)", 4); return; }
    }

    /* T5: tx_ready(0) → 0 */
    {
        if (rust_apple_uart_tx_ready(0) == 0) UART_PASS("tx_ready(base=0)");
        else { UART_FAIL("tx_ready(base=0)", 5); return; }
    }

    /* T6: rx_ready(0) → 0 */
    {
        if (rust_apple_uart_rx_ready(0) == 0) UART_PASS("rx_ready(base=0)");
        else { UART_FAIL("rx_ready(base=0)", 6); return; }
    }

    /* T7: write(0, NULL, 0) → no-op */
    {
        rust_apple_uart_write(0, NULL, 0);
        UART_PASS("write(base=0) no-op");
    }

    /* T8: puts(0, NULL) → no-op */
    {
        rust_apple_uart_puts(0, NULL);
        UART_PASS("puts(base=0) no-op");
    }

    fut_printf("[UART-TEST] all apple_uart guard tests passed\n");
}

#else /* !__aarch64__ */

void fut_apple_uart_test_thread(void *arg) { (void)arg; }

#endif /* __aarch64__ */
