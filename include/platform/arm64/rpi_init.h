/* rpi_init.h - Raspberry Pi Platform Initialization
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Platform-specific initialization for Raspberry Pi 3, 4, and 5.
 * Integrates with DTB parser for hardware detection and configuration.
 */

#ifndef __FUTURA_ARM64_RPI_INIT_H__
#define __FUTURA_ARM64_RPI_INIT_H__

#include <platform/arm64/dtb.h>
#include <stdint.h>
#include <stdbool.h>

/* ============================================================
 *   RPi UART Controller (PL011)
 * ============================================================ */

typedef struct {
    volatile uint32_t dr;           /* 0x00: Data Register */
    volatile uint32_t rsrecr;       /* 0x04: Receive Status/Error Clear */
    uint32_t _reserved1[4];
    volatile uint32_t fr;           /* 0x18: Flag Register */
    uint32_t _reserved2[1];
    volatile uint32_t ilpr;         /* 0x20: IrDA Low-Power Counter */
    volatile uint32_t ibrd;         /* 0x24: Integer Baud Rate Divisor */
    volatile uint32_t fbrd;         /* 0x28: Fractional Baud Rate Divisor */
    volatile uint32_t lcrh;         /* 0x2C: Line Control Register (High) */
    volatile uint32_t cr;           /* 0x30: Control Register */
    volatile uint32_t ifls;         /* 0x34: Interrupt FIFO Level Select */
    volatile uint32_t imsc;         /* 0x38: Interrupt Mask Set/Clear */
    volatile uint32_t ris;          /* 0x3C: Raw Interrupt Status */
    volatile uint32_t mis;          /* 0x40: Masked Interrupt Status */
    volatile uint32_t icr;          /* 0x44: Interrupt Clear Register */
    volatile uint32_t dmacr;        /* 0x48: DMA Control Register */
} pl011_uart_t;

/* UART Flag Register bits */
#define UART_FR_CTS     (1 << 0)    /* Clear to send */
#define UART_FR_DSR     (1 << 1)    /* Data set ready */
#define UART_FR_DCD     (1 << 2)    /* Data carrier detect */
#define UART_FR_BUSY    (1 << 3)    /* UART busy */
#define UART_FR_RXFE    (1 << 4)    /* Receive FIFO empty */
#define UART_FR_TXFF    (1 << 5)    /* Transmit FIFO full */
#define UART_FR_RXFF    (1 << 6)    /* Receive FIFO full */
#define UART_FR_TXFE    (1 << 7)    /* Transmit FIFO empty */

/* UART Control Register bits */
#define UART_CR_UARTEN  (1 << 0)    /* UART enable */
#define UART_CR_TXE     (1 << 8)    /* Transmit enable */
#define UART_CR_RXE     (1 << 9)    /* Receive enable */

/* UART Line Control Register bits */
#define UART_LCRH_WLEN_5    (0 << 5)
#define UART_LCRH_WLEN_6    (1 << 5)
#define UART_LCRH_WLEN_7    (2 << 5)
#define UART_LCRH_WLEN_8    (3 << 5)
#define UART_LCRH_FEN       (1 << 4)   /* FIFO enable */
#define UART_LCRH_STP2      (1 << 3)   /* Two stop bits */
#define UART_LCRH_EPS       (1 << 2)   /* Even parity select */
#define UART_LCRH_PEN       (1 << 1)   /* Parity enable */

/* ============================================================
 *   RPi Clock Manager (simplified)
 * ============================================================ */

typedef struct {
    uint32_t cntfrq;        /* ARM Generic Timer frequency */
    uint32_t uart_clock;    /* UART base clock */
    uint32_t gpio_clock;    /* GPIO clock (if needed) */
} rpi_clock_t;

/* ============================================================
 *   RPi GPIO (simplified - just for LED control)
 * ============================================================ */

typedef struct {
    volatile uint32_t gpfsel[6];    /* GPIO Function Select */
    volatile uint32_t gpset[2];     /* GPIO Pin Output Set */
    volatile uint32_t gpclr[2];     /* GPIO Pin Output Clear */
    volatile uint32_t gplev[2];     /* GPIO Pin Level */
    volatile uint32_t gppud;        /* GPIO Pull-up/down Enable */
    volatile uint32_t gppudclk[2];  /* GPIO Pull-up/down Enable Clock */
} rpi_gpio_t;

/* GPFSEL field width: 3 bits per pin */
#define GPIO_FSEL_INPUT     0
#define GPIO_FSEL_OUTPUT    1

/* ============================================================
 *   Platform Initialization Functions
 * ============================================================ */

/**
 * Initialize platform based on detected RPi variant.
 * @param info: Platform information from DTB parser
 */
void fut_rpi_platform_init(const fut_platform_info_t *info);

/**
 * Initialize PL011 UART for the platform.
 * @param info: Platform information
 * @param baudrate: Desired baud rate (typically 115200)
 */
void fut_rpi_uart_init(const fut_platform_info_t *info, uint32_t baudrate);

/**
 * Write a character to UART.
 * @param info: Platform information
 * @param ch: Character to write
 */
void fut_rpi_uart_putc(const fut_platform_info_t *info, char ch);

/**
 * Read a character from UART (blocking).
 * @param info: Platform information
 * @return: Character read from UART
 */
char fut_rpi_uart_getc(const fut_platform_info_t *info);

/**
 * Enable receive interrupt on PL011 UART.
 * Called after UART is initialized to enable interrupt-driven RX.
 * @param info: Platform information
 */
void fut_rpi_uart_enable_rx_interrupt(const fut_platform_info_t *info);

/**
 * Enable transmit interrupt on PL011 UART.
 * Called when data is ready to send to trigger TX via interrupt.
 * @param info: Platform information
 */
void fut_rpi_uart_enable_tx_interrupt(const fut_platform_info_t *info);

/**
 * Disable transmit interrupt on PL011 UART.
 * Called when TX FIFO is full to prevent interrupt flooding.
 * @param info: Platform information
 */
void fut_rpi_uart_disable_tx_interrupt(const fut_platform_info_t *info);

/**
 * Get masked interrupt status from UART.
 * Returns which interrupts are pending and enabled.
 * @param info: Platform information
 * @return: Masked interrupt status register value
 */
uint32_t fut_rpi_uart_get_mis(const fut_platform_info_t *info);

/**
 * Clear UART interrupt flags.
 * @param info: Platform information
 * @param mask: Bitmask of interrupt flags to clear
 */
void fut_rpi_uart_clear_interrupts(const fut_platform_info_t *info, uint32_t mask);

/**
 * Initialize interrupt controller for the platform.
 * RPi3 uses legacy interrupts, RPi4/5 use GICv2.
 * @param info: Platform information
 */
void fut_rpi_irq_init(const fut_platform_info_t *info);

/**
 * Initialize GPIO for the platform.
 * Useful for LED status indicators during boot.
 * @param info: Platform information
 */
void fut_rpi_gpio_init(const fut_platform_info_t *info);

/**
 * Set GPIO pin output level.
 * @param info: Platform information
 * @param pin: GPIO pin number
 * @param level: 0 for low, 1 for high
 */
void fut_rpi_gpio_set(const fut_platform_info_t *info, uint32_t pin, uint32_t level);

/**
 * Get GPIO pin input level.
 * @param info: Platform information
 * @param pin: GPIO pin number
 * @return: 0 for low, 1 for high
 */
uint32_t fut_rpi_gpio_get(const fut_platform_info_t *info, uint32_t pin);

/**
 * Initialize system timer/clock for the platform.
 * @param info: Platform information
 */
void fut_rpi_timer_init(const fut_platform_info_t *info);

/**
 * Get current timer count from ARM Generic Timer or System Timer.
 * @param info: Platform information
 * @return: Current timer count
 */
uint64_t fut_rpi_timer_read(const fut_platform_info_t *info);

/**
 * Set timer timeout/compare value.
 * @param info: Platform information
 * @param timeout: Target timer count value
 */
void fut_rpi_timer_set_timeout(const fut_platform_info_t *info, uint64_t timeout);

/* ============================================================
 *   Boot Integration
 * ============================================================ */

/**
 * Main RPi platform initialization called from kernel_main.
 * Detects platform, parses DTB, and initializes all subsystems.
 * @param dtb_ptr: Physical address of device tree blob (passed in X0 at boot)
 */
void fut_rpi_boot_init(uint64_t dtb_ptr);

#endif /* __FUTURA_ARM64_RPI_INIT_H__ */
