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
 *   RPi3 Legacy Interrupt Controller
 * ============================================================ */

/* RPi3 ARM legacy interrupt controller registers
 * Based on BCM2835 ARM Peripherals documentation
 * Base address: 0x3F00B000 for RPi3 (peripheral bus address)
 * This is mapped to 0xFFFFFFFF8xxxxxxxwhen using higher-half kernel addressing
 */

#define RPI3_IRQ_BASIC_PENDING      0x00
#define RPI3_IRQ_PENDING1           0x04
#define RPI3_IRQ_PENDING2           0x08
#define RPI3_IRQ_FIQ_CONTROL        0x0C
#define RPI3_IRQ_ENABLE1            0x10
#define RPI3_IRQ_ENABLE2            0x14
#define RPI3_IRQ_ENABLE_BASIC       0x18
#define RPI3_IRQ_DISABLE1           0x1C
#define RPI3_IRQ_DISABLE2           0x20
#define RPI3_IRQ_DISABLE_BASIC      0x24

/* ARM Core Interrupt bits (in BASIC register) */
#define RPI3_IRQ_TIMER_IRQ          (1 << 0)
#define RPI3_IRQ_MAILBOX_IRQ        (1 << 1)
#define RPI3_IRQ_DOORBELL_0         (1 << 2)
#define RPI3_IRQ_DOORBELL_1         (1 << 3)
#define RPI3_IRQ_GPU_HALTED         (1 << 4)
#define RPI3_IRQ_PMU                (1 << 5)
#define RPI3_IRQ_CNTPS              (1 << 6)
#define RPI3_IRQ_CNTPNS             (1 << 7)

/* Standard device interrupts (in PENDING1/2 registers) */
#define RPI3_IRQ_UART               57      /* IRQ 57 for UART (in PENDING2) */
#define RPI3_IRQ_TIMER              64      /* IRQ 64-67 for ARM timer (in PENDING2) */

typedef struct {
    volatile uint32_t basic_pending;
    volatile uint32_t pending1;
    volatile uint32_t pending2;
    volatile uint32_t fiq_control;
    volatile uint32_t enable1;
    volatile uint32_t enable2;
    volatile uint32_t enable_basic;
    volatile uint32_t disable1;
    volatile uint32_t disable2;
    volatile uint32_t disable_basic;
} rpi3_irq_controller_t;

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

    /* Clear any pending interrupts */
    uart->icr = 0x7FF;  /* Clear all interrupt flags */

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

/**
 * Enable receive interrupt on PL011 UART.
 * Called after UART is initialized to enable interrupt-driven RX.
 */
void fut_rpi_uart_enable_rx_interrupt(const fut_platform_info_t *info) {
    if (!info || !info->uart_base) {
        return;
    }

    pl011_uart_t *uart = (pl011_uart_t *)info->uart_base;

    /* Enable receive interrupt (RXIM) and RX timeout interrupt (RTIM) */
    /* Bit 4: RXIM (Receive Interrupt Mask)
     * Bit 6: RTIM (Receive Timeout Interrupt Mask) */
    uart->imsc |= (1 << 4) | (1 << 6);

    fut_printf("[UART] RX interrupts enabled\n");
}

/**
 * Enable transmit interrupt on PL011 UART.
 * Called when data is ready to send to trigger TX via interrupt.
 */
void fut_rpi_uart_enable_tx_interrupt(const fut_platform_info_t *info) {
    if (!info || !info->uart_base) {
        return;
    }

    pl011_uart_t *uart = (pl011_uart_t *)info->uart_base;

    /* Enable transmit interrupt (TXIM)
     * Bit 5: TXIM (Transmit Interrupt Mask) */
    uart->imsc |= (1 << 5);
}

/**
 * Disable transmit interrupt on PL011 UART.
 * Called when TX FIFO is full to prevent interrupt flooding.
 */
void fut_rpi_uart_disable_tx_interrupt(const fut_platform_info_t *info) {
    if (!info || !info->uart_base) {
        return;
    }

    pl011_uart_t *uart = (pl011_uart_t *)info->uart_base;

    /* Disable transmit interrupt (TXIM) */
    uart->imsc &= ~(1 << 5);
}

/**
 * Get masked interrupt status from UART.
 * Returns which interrupts are pending and enabled.
 */
uint32_t fut_rpi_uart_get_mis(const fut_platform_info_t *info) {
    if (!info || !info->uart_base) {
        return 0;
    }

    pl011_uart_t *uart = (pl011_uart_t *)info->uart_base;
    return uart->mis;
}

/**
 * Clear UART interrupt flags.
 * @param mask: Bitmask of interrupt flags to clear
 */
void fut_rpi_uart_clear_interrupts(const fut_platform_info_t *info, uint32_t mask) {
    if (!info || !info->uart_base) {
        return;
    }

    pl011_uart_t *uart = (pl011_uart_t *)info->uart_base;
    uart->icr = mask;  /* Writing 1 to ICR clears the interrupt */
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
        fut_printf("[INIT] Initializing RPi3 legacy interrupt controller\n");

        /* RPi3 interrupt controller base address (BCM2835 peripheral base)
         * For RPi3, this is typically at 0x3F000000 (bus address)
         * The bootloader/firmware has already done device tree parsing
         * The kernel should use the mapped address from DTB if available
         */

        /* Get the interrupt controller base address from platform info
         * For now, use a reasonable default for RPi3 if not in DTB */
        uint64_t irq_base = info->gic_dist_base;
        if (!irq_base) {
            /* Fallback: RPi3 standard address (in kernel virtual space)
             * The actual physical address 0x3F00B000 must be mapped
             * during kernel initialization */
            irq_base = 0x3F00B000;
            fut_printf("[INIT] Warning: using fallback IRQ controller address 0x%016llx\n", irq_base);
        }

        rpi3_irq_controller_t *irq_ctrl = (rpi3_irq_controller_t *)irq_base;

        /* Disable all device interrupts initially */
        irq_ctrl->disable1 = 0xFFFFFFFF;
        irq_ctrl->disable2 = 0xFFFFFFFF;
        irq_ctrl->disable_basic = 0xFF;

        /* Clear all pending interrupts by reading status */
        (void)irq_ctrl->basic_pending;
        (void)irq_ctrl->pending1;
        (void)irq_ctrl->pending2;

        /* Set all interrupts to normal priority (not FIQ) */
        irq_ctrl->fiq_control = 0;

        fut_printf("[INIT] RPi3 legacy interrupt controller initialized\n");
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
        /* RPi3 uses ARM Generic Timer when running in 64-bit mode (ARMv8)
         * The system timer (based on BCM2835) is primarily used in 32-bit mode.
         * For 64-bit ARM64 systems, we rely on the ARM Generic Timer (CNTPCT_EL0).
         * If the DTB indicates no generic timer support, we would use the system timer,
         * but this is unlikely for RPi3 in 64-bit mode. */
        fut_printf("[INIT] RPi3 detected: Using ARM Generic Timer (ARMv8)\n");

        /* Most RPi3 64-bit systems support ARM Generic Timer through device tree.
         * If this code path is reached, use a reasonable default frequency. */
        if (info->cpu_freq > 0) {
            fut_timer_init(info->cpu_freq);
        } else {
            /* Fallback frequency for RPi3: ~1GHz typical */
            fut_printf("[INIT] Using default frequency: 1000000000 Hz\n");
            fut_timer_init(1000000000);
        }
    }
}

uint64_t fut_rpi_timer_read(const fut_platform_info_t *info) {
    if (!info) {
        return 0;
    }

    if (info->has_generic_timer) {
        return fut_timer_read_count();
    }

    /* RPi3 in 64-bit mode should have ARM Generic Timer.
     * If not, fall back to reading from generic timer anyway. */
    return fut_timer_read_count();
}

void fut_rpi_timer_set_timeout(const fut_platform_info_t *info, uint64_t timeout) {
    if (!info) {
        return;
    }

    if (info->has_generic_timer) {
        fut_timer_set_timeout(timeout);
    } else {
        /* RPi3 in 64-bit mode should use ARM Generic Timer */
        fut_timer_set_timeout(timeout);
    }
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
