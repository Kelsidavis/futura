/* apple_uart.c - Apple Silicon UART Driver Implementation
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Samsung S5L-style UART driver for Apple M1/M2/M3 SoCs.
 * Provides console I/O for early boot and debugging.
 */

#include <platform/arm64/apple_uart.h>
#include <platform/platform.h>
#include <string.h>
#include <stddef.h>

/* ============================================================
 *   UART Register Access
 * ============================================================ */

/* Base address of UART registers (set during init) */
static volatile uint8_t *uart_base = NULL;

/* Helper macros for register access */
#define UART_READ32(offset)      (*((volatile uint32_t *)(uart_base + (offset))))
#define UART_WRITE32(offset, val) (*((volatile uint32_t *)(uart_base + (offset))) = (val))

/* ============================================================
 *   UART Initialization
 * ============================================================ */

bool fut_apple_uart_init(const fut_platform_info_t *info, uint32_t baudrate) {
    if (!info || info->uart_base == 0) {
        fut_printf("[UART] Error: Invalid platform info or missing UART base\n");
        return false;
    }

    /* Map UART base address */
    uart_base = (volatile uint8_t *)info->uart_base;

    fut_printf("[UART] Initializing Apple s5l-uart\n");
    fut_printf("[UART] Base address: 0x%016llx\n", info->uart_base);
    fut_printf("[UART] Baud rate: %u\n", baudrate);

    /* Disable UART during configuration */
    UART_WRITE32(UCON, 0);

    /* Configure line control: 8N1 (8 data bits, no parity, 1 stop bit) */
    UART_WRITE32(ULCON, ULCON_WORD_LEN_8 | ULCON_PARITY_NONE);

    /* Configure FIFO: Enable FIFO, reset TX/RX, set trigger levels */
    UART_WRITE32(UFCON, UFCON_FIFO_ENABLE | UFCON_RX_FIFO_RST |
                        UFCON_TX_FIFO_RST | UFCON_RX_TRIGGER_8 |
                        UFCON_TX_TRIGGER_8);

    /* Calculate baud rate divisor
     * Baud rate formula: UART_CLOCK / (16 * baudrate)
     * For fractional baud rate: UFRACVAL = (remainder * 16) / divisor
     */
    uint32_t div = APPLE_UART_CLOCK / (16 * baudrate);
    uint32_t remainder = APPLE_UART_CLOCK % (16 * baudrate);
    uint32_t frac = (remainder * 16) / (16 * baudrate);

    UART_WRITE32(UBRDIV, div);
    UART_WRITE32(UFRACVAL, frac);

    /* Clear all interrupts */
    UART_WRITE32(UINTP, 0xF);  /* Clear all pending interrupts */
    UART_WRITE32(UINTM, 0xF);  /* Mask all interrupts initially */

    /* Enable UART: RX interrupt mode, TX interrupt mode */
    UART_WRITE32(UCON, UCON_RX_MODE_INT | UCON_TX_MODE_INT | UCON_RX_TIMEOUT);

    fut_printf("[UART] Apple s5l-uart initialized successfully\n");

    return true;
}

/* ============================================================
 *   Character I/O
 * ============================================================ */

void fut_apple_uart_putc(const fut_platform_info_t *info, char ch) {
    if (!uart_base) {
        return;
    }

    (void)info;  /* Unused - uart_base is cached */

    /* Wait for TX FIFO to have space */
    while (!(UART_READ32(UTRSTAT) & UTRSTAT_TX_EMPTY)) {
        /* Spin-wait */
    }

    /* Write character to transmit buffer */
    UART_WRITE32(UTXH, (uint32_t)ch);

    /* Handle line endings: convert \n to \r\n for terminal compatibility */
    if (ch == '\n') {
        /* Wait again for TX ready */
        while (!(UART_READ32(UTRSTAT) & UTRSTAT_TX_EMPTY)) {
            /* Spin-wait */
        }
        UART_WRITE32(UTXH, '\r');
    }
}

int fut_apple_uart_getc(const fut_platform_info_t *info) {
    if (!uart_base) {
        return -1;
    }

    (void)info;  /* Unused - uart_base is cached */

    /* Check if RX FIFO has data */
    if (!(UART_READ32(UTRSTAT) & UTRSTAT_RX_READY)) {
        return -1;  /* No data available */
    }

    /* Read character from receive buffer */
    uint32_t data = UART_READ32(URXH);

    return (int)(data & 0xFF);
}

bool fut_apple_uart_tx_ready(const fut_platform_info_t *info) {
    if (!uart_base) {
        return false;
    }

    (void)info;  /* Unused */

    return (UART_READ32(UTRSTAT) & UTRSTAT_TX_EMPTY) != 0;
}

bool fut_apple_uart_rx_ready(const fut_platform_info_t *info) {
    if (!uart_base) {
        return false;
    }

    (void)info;  /* Unused */

    return (UART_READ32(UTRSTAT) & UTRSTAT_RX_READY) != 0;
}

/* ============================================================
 *   Interrupt Management
 * ============================================================ */

void fut_apple_uart_enable_rx_interrupt(const fut_platform_info_t *info) {
    if (!uart_base) {
        return;
    }

    (void)info;  /* Unused */

    /* Unmask RX interrupt */
    uint32_t mask = UART_READ32(UINTM);
    mask &= ~UINT_RXD;
    UART_WRITE32(UINTM, mask);
}

void fut_apple_uart_enable_tx_interrupt(const fut_platform_info_t *info) {
    if (!uart_base) {
        return;
    }

    (void)info;  /* Unused */

    /* Unmask TX interrupt */
    uint32_t mask = UART_READ32(UINTM);
    mask &= ~UINT_TXD;
    UART_WRITE32(UINTM, mask);
}

void fut_apple_uart_disable_tx_interrupt(const fut_platform_info_t *info) {
    if (!uart_base) {
        return;
    }

    (void)info;  /* Unused */

    /* Mask TX interrupt */
    uint32_t mask = UART_READ32(UINTM);
    mask |= UINT_TXD;
    UART_WRITE32(UINTM, mask);
}

uint32_t fut_apple_uart_get_intp(const fut_platform_info_t *info) {
    if (!uart_base) {
        return 0;
    }

    (void)info;  /* Unused */

    return UART_READ32(UINTP);
}

void fut_apple_uart_clear_interrupts(const fut_platform_info_t *info, uint32_t mask) {
    if (!uart_base) {
        return;
    }

    (void)info;  /* Unused */

    /* Write 1 to clear pending interrupts */
    UART_WRITE32(UINTP, mask);
}

/* ============================================================
 *   String Output
 * ============================================================ */

void fut_apple_uart_puts(const fut_platform_info_t *info, const char *str) {
    if (!str) {
        return;
    }

    while (*str) {
        fut_apple_uart_putc(info, *str++);
    }
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
