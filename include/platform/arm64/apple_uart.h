/* apple_uart.h - Apple Silicon UART Driver
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Apple s5l-uart (Samsung-style UART) driver for M1/M2/M3 SoCs.
 * Based on Asahi Linux implementation.
 */

#ifndef __FUTURA_ARM64_APPLE_UART_H__
#define __FUTURA_ARM64_APPLE_UART_H__

#include <stdint.h>
#include <stdbool.h>
#include <platform/arm64/dtb.h>

/* ============================================================
 *   Apple UART Register Offsets
 * ============================================================ */

/* Samsung S5L UART register layout (used by Apple) */
#define ULCON       0x00    /* Line control */
#define UCON        0x04    /* Control */
#define UFCON       0x08    /* FIFO control */
#define UMCON       0x0C    /* Modem control */
#define UTRSTAT     0x10    /* TX/RX status */
#define UERSTAT     0x14    /* Error status */
#define UFSTAT      0x18    /* FIFO status */
#define UMSTAT      0x1C    /* Modem status */
#define UTXH        0x20    /* Transmit buffer */
#define URXH        0x24    /* Receive buffer */
#define UBRDIV      0x28    /* Baud rate divisor */
#define UFRACVAL    0x2C    /* Fractional baud rate */
#define UINTP       0x30    /* Interrupt pending */
#define UINTS       0x34    /* Interrupt source */
#define UINTM       0x38    /* Interrupt mask */

/* ============================================================
 *   Register Bit Definitions
 * ============================================================ */

/* ULCON - Line Control Register */
#define ULCON_WORD_LEN_5    0x0
#define ULCON_WORD_LEN_6    0x1
#define ULCON_WORD_LEN_7    0x2
#define ULCON_WORD_LEN_8    0x3
#define ULCON_STOP_BIT      (1 << 2)    /* 0=1 stop bit, 1=2 stop bits */
#define ULCON_PARITY_NONE   (0 << 3)
#define ULCON_PARITY_ODD    (4 << 3)
#define ULCON_PARITY_EVEN   (5 << 3)

/* UCON - Control Register */
#define UCON_RX_MODE_INT    (1 << 0)    /* Receive interrupt mode */
#define UCON_TX_MODE_INT    (1 << 2)    /* Transmit interrupt mode */
#define UCON_RX_TIMEOUT     (1 << 7)    /* Receive timeout enable */
#define UCON_RX_INT_TYPE    (1 << 8)    /* RX interrupt type (pulse) */
#define UCON_TX_INT_TYPE    (1 << 9)    /* TX interrupt type (pulse) */

/* UFCON - FIFO Control Register */
#define UFCON_FIFO_ENABLE   (1 << 0)    /* Enable FIFO */
#define UFCON_RX_FIFO_RST   (1 << 1)    /* Reset RX FIFO */
#define UFCON_TX_FIFO_RST   (1 << 2)    /* Reset TX FIFO */
#define UFCON_RX_TRIGGER_8  (1 << 4)    /* RX FIFO trigger: 8 bytes */
#define UFCON_TX_TRIGGER_8  (1 << 6)    /* TX FIFO trigger: 8 bytes */

/* UTRSTAT - TX/RX Status Register */
#define UTRSTAT_RX_READY    (1 << 0)    /* Receive buffer has data */
#define UTRSTAT_TX_EMPTY    (1 << 1)    /* Transmit buffer empty */
#define UTRSTAT_TX_DONE     (1 << 2)    /* Transmitter idle */

/* UFSTAT - FIFO Status Register */
#define UFSTAT_RX_FULL      (1 << 8)    /* RX FIFO full */
#define UFSTAT_TX_FULL      (1 << 24)   /* TX FIFO full */
#define UFSTAT_RX_COUNT(x)  ((x) & 0xFF)        /* RX FIFO count */
#define UFSTAT_TX_COUNT(x)  (((x) >> 16) & 0xFF) /* TX FIFO count */

/* Interrupt bits (UINTP, UINTS, UINTM) */
#define UINT_RXD            (1 << 0)    /* Receive interrupt */
#define UINT_TXD            (1 << 2)    /* Transmit interrupt */
#define UINT_ERR            (1 << 1)    /* Error interrupt */
#define UINT_MODEM          (1 << 3)    /* Modem status interrupt */

/* ============================================================
 *   UART Configuration
 * ============================================================ */

/* Default baud rate for Apple Silicon UART */
#define APPLE_UART_BAUDRATE     115200

/* UART clock frequency (from device tree, typically 24 MHz) */
#define APPLE_UART_CLOCK        24000000

/* ============================================================
 *   Apple UART Functions
 * ============================================================ */

/**
 * Initialize Apple UART.
 * Sets up line control, baud rate, and enables TX/RX.
 * @param info: Platform information with uart_base address
 * @param baudrate: Desired baud rate (typically 115200)
 * @return: true on success, false on failure
 */
bool fut_apple_uart_init(const fut_platform_info_t *info, uint32_t baudrate);

/**
 * Write a character to UART (blocking).
 * Waits for TX FIFO to have space before writing.
 * @param info: Platform information
 * @param ch: Character to write
 */
void fut_apple_uart_putc(const fut_platform_info_t *info, char ch);

/**
 * Read a character from UART (non-blocking).
 * Returns -1 if no data available.
 * @param info: Platform information
 * @return: Character read, or -1 if no data
 */
int fut_apple_uart_getc(const fut_platform_info_t *info);

/**
 * Check if TX FIFO is ready for data.
 * @param info: Platform information
 * @return: true if ready, false if full
 */
bool fut_apple_uart_tx_ready(const fut_platform_info_t *info);

/**
 * Check if RX FIFO has data available.
 * @param info: Platform information
 * @return: true if data available, false otherwise
 */
bool fut_apple_uart_rx_ready(const fut_platform_info_t *info);

/**
 * Enable UART receive interrupt.
 * @param info: Platform information
 */
void fut_apple_uart_enable_rx_interrupt(const fut_platform_info_t *info);

/**
 * Enable UART transmit interrupt.
 * @param info: Platform information
 */
void fut_apple_uart_enable_tx_interrupt(const fut_platform_info_t *info);

/**
 * Disable UART transmit interrupt.
 * @param info: Platform information
 */
void fut_apple_uart_disable_tx_interrupt(const fut_platform_info_t *info);

/**
 * Get UART interrupt status.
 * @param info: Platform information
 * @return: Interrupt pending register value
 */
uint32_t fut_apple_uart_get_intp(const fut_platform_info_t *info);

/**
 * Clear UART interrupt flags.
 * @param info: Platform information
 * @param mask: Bitmask of interrupts to clear
 */
void fut_apple_uart_clear_interrupts(const fut_platform_info_t *info, uint32_t mask);

/**
 * Write a null-terminated string to UART.
 * @param info: Platform information
 * @param str: String to write
 */
void fut_apple_uart_puts(const fut_platform_info_t *info, const char *str);

/**
 * Platform integration: Initialize Apple Silicon UART.
 * High-level entry point called from platform init.
 * @param info: Platform information
 */
void fut_apple_uart_platform_init(const fut_platform_info_t *info);

#endif /* __FUTURA_ARM64_APPLE_UART_H__ */
