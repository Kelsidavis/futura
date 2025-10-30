/* rpi_init.c - Raspberry Pi Platform Initialization Implementation
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Platform-specific initialization routines for RPi3, RPi4, and RPi5.
 */

#include <platform/arm64/rpi_init.h>
#include <platform/arm64/dtb.h>
#include <platform/arm64/interrupt/irq.h>
#include <platform/platform.h>
#include <string.h>

/* ============================================================
 *   UART Initialization and Output
 * ============================================================ */

/**
 * Calculate UART baud rate divisors for PL011 controller.
 * IBRD = UART_CLK / (16 * BAUD)
 * FBRD = (UART_CLK % (16 * BAUD)) * 64 / (16 * BAUD)
 */
static void fut_rpi_uart_calc_divisors(uint32_t uart_clock, uint32_t baudrate,
                                       uint32_t *ibrd, uint32_t *fbrd) {
    uint32_t divisor = uart_clock / (16 * baudrate);
    uint32_t remainder = uart_clock % (16 * baudrate);

    *ibrd = divisor;
    *fbrd = (remainder * 64 + 8 * baudrate) / (16 * baudrate);

    /* Mask FBRD to 6 bits */
    *fbrd &= 0x3F;
}

void fut_rpi_uart_init(const fut_platform_info_t *info, uint32_t baudrate) {
    if (!info || !info->uart_base) {
        return;
    }

    pl011_uart_t *uart = (pl011_uart_t *)info->uart_base;
    uint32_t ibrd, fbrd;

    /* Disable UART during configuration */
    uart->cr = 0;

    /* Calculate and set baud rate divisors */
    fut_rpi_uart_calc_divisors(3000000, baudrate, &ibrd, &fbrd);  /* 3MHz for all RPi */
    uart->ibrd = ibrd;
    uart->fbrd = fbrd;

    /* Set line control: 8 bits, no parity, 1 stop bit, FIFO enabled */
    uart->lcrh = UART_LCRH_WLEN_8 | UART_LCRH_FEN;

    /* Enable UART: transmit, receive, and UART itself */
    uart->cr = UART_CR_UARTEN | UART_CR_TXE | UART_CR_RXE;

    /* Print initialization message */
    fut_printf("[INIT] UART initialized at 0x%016llx (baudrate %u)\n",
               info->uart_base, baudrate);
}

void fut_rpi_uart_putc(const fut_platform_info_t *info, char ch) {
    if (!info || !info->uart_base) {
        return;
    }

    pl011_uart_t *uart = (pl011_uart_t *)info->uart_base;

    /* Wait for transmit FIFO to have space */
    while (uart->fr & UART_FR_TXFF) {
        /* Busy wait */
    }

    /* Send character */
    uart->dr = (uint32_t)ch;

    /* For newlines, also send carriage return */
    if (ch == '\n') {
        while (uart->fr & UART_FR_TXFF) {
            /* Busy wait */
        }
        uart->dr = '\r';
    }
}

char fut_rpi_uart_getc(const fut_platform_info_t *info) {
    if (!info || !info->uart_base) {
        return '\0';
    }

    pl011_uart_t *uart = (pl011_uart_t *)info->uart_base;

    /* Wait for receive FIFO to have data */
    while (uart->fr & UART_FR_RXFE) {
        /* Busy wait */
    }

    /* Read character */
    return (char)(uart->dr & 0xFF);
}

/* ============================================================
 *   Interrupt Controller Initialization
 * ============================================================ */

void fut_rpi_irq_init(const fut_platform_info_t *info) {
    if (!info) {
        return;
    }

    if (info->has_gic) {
        /* RPi4/5 with GICv2 */
        fut_printf("[INIT] Initializing GICv2 for RPi (%s)\n", info->name);
        fut_gic_init();  /* Use existing GIC initialization from arm64_irq.c */
    } else {
        /* RPi3 with legacy interrupt controller */
        fut_printf("[INIT] RPi3 legacy interrupt controller (not fully implemented)\n");
        /* TODO: Implement RPi3 legacy interrupt controller setup */
    }
}

/* ============================================================
 *   GPIO Initialization (simplified)
 * ============================================================ */

void fut_rpi_gpio_init(const fut_platform_info_t *info) {
    if (!info || !info->gpio_base) {
        return;
    }

    fut_printf("[INIT] GPIO controller at 0x%016llx\n", info->gpio_base);
    /* GPIO initialization would go here for LED control, etc. */
}

void fut_rpi_gpio_set(const fut_platform_info_t *info, uint32_t pin, uint32_t level) {
    if (!info || !info->gpio_base || pin >= 54) {
        return;
    }

    rpi_gpio_t *gpio = (rpi_gpio_t *)info->gpio_base;
    uint32_t bank = pin / 32;
    uint32_t bit = pin % 32;

    if (level) {
        gpio->gpset[bank] = 1U << bit;
    } else {
        gpio->gpclr[bank] = 1U << bit;
    }
}

uint32_t fut_rpi_gpio_get(const fut_platform_info_t *info, uint32_t pin) {
    if (!info || !info->gpio_base || pin >= 54) {
        return 0;
    }

    rpi_gpio_t *gpio = (rpi_gpio_t *)info->gpio_base;
    uint32_t bank = pin / 32;
    uint32_t bit = pin % 32;

    return (gpio->gplev[bank] >> bit) & 1;
}

/* ============================================================
 *   Timer Initialization
 * ============================================================ */

void fut_rpi_timer_init(const fut_platform_info_t *info) {
    if (!info) {
        return;
    }

    if (info->has_generic_timer) {
        fut_printf("[INIT] ARM Generic Timer (CNTFRQ=%u Hz)\n", info->cpu_freq);
        fut_timer_init(info->cpu_freq);  /* Use existing ARM Generic Timer init */
    } else {
        fut_printf("[INIT] RPi3 System Timer (not fully implemented)\n");
        /* TODO: Implement RPi3 system timer if needed */
    }
}

uint64_t fut_rpi_timer_read(const fut_platform_info_t *info) {
    if (!info) {
        return 0;
    }

    if (info->has_generic_timer) {
        return fut_timer_read_count();
    }

    return 0;  /* TODO: RPi3 system timer read */
}

void fut_rpi_timer_set_timeout(const fut_platform_info_t *info, uint64_t timeout) {
    if (!info) {
        return;
    }

    if (info->has_generic_timer) {
        fut_timer_set_timeout(timeout);
    }
    /* TODO: RPi3 system timer setup */
}

/* ============================================================
 *   Platform Main Initialization
 * ============================================================ */

void fut_rpi_platform_init(const fut_platform_info_t *info) {
    if (!info) {
        return;
    }

    fut_printf("========================================================\n");
    fut_printf("   Raspberry Pi Platform Initialization\n");
    fut_printf("========================================================\n");
    fut_printf("[INIT] Platform: %s\n", info->name);
    fut_printf("[INIT] CPU Frequency: %u MHz\n", info->cpu_freq / 1000000);

    /* Initialize UART first for debug output */
    fut_rpi_uart_init(info, 115200);

    /* Initialize interrupt controller */
    fut_rpi_irq_init(info);

    /* Initialize GPIO (optional) */
    fut_rpi_gpio_init(info);

    /* Initialize timer */
    fut_rpi_timer_init(info);

    fut_printf("========================================================\n");
    fut_printf("   RPi Platform Initialization Complete\n");
    fut_printf("========================================================\n");
}

/* ============================================================
 *   Boot Integration Point
 * ============================================================ */

void fut_rpi_boot_init(uint64_t dtb_ptr) {
    /* Parse device tree to detect platform */
    fut_platform_info_t info = fut_dtb_parse(dtb_ptr);

    /* Initialize platform-specific subsystems */
    fut_rpi_platform_init(&info);

    /* The kernel_main should then call the generic ARM64 init */
    /* This provides platform detection before scheduler/paging setup */
}

/* ============================================================
 *   Override fut_serial_putc for platform-specific output
 * ============================================================ */

/* We can override the default serial output if needed */
void fut_rpi_serial_putc(char ch __attribute__((unused))) {
    /* This would be called by fut_printf if the global platform is set */
    /* For now, we rely on the existing platform initialization */
}
