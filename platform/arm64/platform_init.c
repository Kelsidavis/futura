/*
 * Futura OS - ARM64 Platform Initialization
 * Copyright (C) 2025 Futura OS Project
 *
 * Platform-specific initialization for ARM64 (AArch64) architecture.
 * Supports QEMU virt machine with GICv2 and PL011 UART.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdbool.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#include <arch/arm64/regs.h>
#pragma GCC diagnostic pop
#include <arch/arm64/irq.h>
#include <platform/platform.h>
#include <config/futura_config.h>

/* Note: IRQ handler types and functions (fut_register_irq_handler, fut_irq_enable, etc.)
 * are now properly declared in <arch/arm64/irq.h> and implemented in kernel/irq/arm64_irq.c.
 * Removed duplicate implementations from this file to avoid handler table conflicts. */

/* ============================================================
 *   MMIO Helper Functions
 * ============================================================ */

uint32_t mmio_read32(volatile void *addr) {
    uint32_t value = *(volatile uint32_t *)addr;
    dmb();
    return value;
}

void mmio_write32(volatile void *addr, uint32_t value) {
    dmb();
    *(volatile uint32_t *)addr = value;
    dmb();
}

uint64_t mmio_read64(volatile void *addr) {
    uint64_t value = *(volatile uint64_t *)addr;
    dmb();
    return value;
}

void mmio_write64(volatile void *addr, uint64_t value) {
    dmb();
    *(volatile uint64_t *)addr = value;
    dmb();
}

/* ============================================================
 *   PL011 UART Implementation
 * ============================================================ */

/* UART TX ring buffer */
#define UART_TX_BUFFER_SIZE 4096
static volatile char uart_tx_buffer[UART_TX_BUFFER_SIZE];
static volatile uint32_t uart_tx_head = 0;  /* Write position */
static volatile uint32_t uart_tx_tail = 0;  /* Read position */
static volatile _Bool uart_irq_mode = 0;    /* false = polling, true = interrupt */

/* UART RX ring buffer */
#define UART_RX_BUFFER_SIZE 4096
static volatile char uart_rx_buffer[UART_RX_BUFFER_SIZE];
static volatile uint32_t uart_rx_head = 0;  /* Write position (filled by ISR) */
static volatile uint32_t uart_rx_tail = 0;  /* Read position (consumed by getc) */

/* UART TX interrupt handler - drains ring buffer into hardware FIFO */
static void uart_tx_irq_handler(int irq_num, fut_interrupt_frame_t *frame) {
    (void)irq_num;
    (void)frame;
    volatile uint8_t *uart = (volatile uint8_t *)UART0_BASE;

    /* Drain ring buffer into UART FIFO */
    while (uart_tx_head != uart_tx_tail) {
        /* Check if TX FIFO is full */
        if (mmio_read32((volatile void *)(uart + UART_FR)) & UART_FR_TXFF) {
            break;  /* FIFO full, wait for next interrupt */
        }

        /* Send next character from ring buffer */
        mmio_write32((volatile void *)(uart + UART_DR), (uint32_t)uart_tx_buffer[uart_tx_tail]);
        uart_tx_tail = (uart_tx_tail + 1) % UART_TX_BUFFER_SIZE;
    }

    /* If buffer is empty, disable TX interrupt to avoid spurious interrupts */
    if (uart_tx_head == uart_tx_tail) {
        uint32_t imsc = mmio_read32((volatile void *)(uart + UART_IMSC));
        imsc &= ~UART_INT_TX;
        mmio_write32((volatile void *)(uart + UART_IMSC), imsc);
    }

    /* Clear TX interrupt */
    mmio_write32((volatile void *)(uart + UART_ICR), UART_INT_TX);
}

/* UART RX interrupt handler - fills ring buffer from hardware FIFO */
static void uart_rx_irq_handler(int irq_num, fut_interrupt_frame_t *frame) {
    (void)irq_num;
    (void)frame;
    volatile uint8_t *uart = (volatile uint8_t *)UART0_BASE;

    /* Drain hardware FIFO into ring buffer */
    while (!(mmio_read32((volatile void *)(uart + UART_FR)) & UART_FR_RXFE)) {
        /* Read character from UART data register */
        uint32_t data = mmio_read32((volatile void *)(uart + UART_DR));

        /* Check for error flags in upper byte */
        if (data & (UART_INT_FE | UART_INT_PE | UART_INT_BE | UART_INT_OE)) {
            /* Skip characters with errors for now */
            continue;
        }

        /* Extract character from lower byte */
        char c = (char)(data & 0xFF);

        /* Check if buffer has space */
        uint32_t next_head = (uart_rx_head + 1) % UART_RX_BUFFER_SIZE;
        if (next_head == uart_rx_tail) {
            /* Buffer full - drop character (could add overflow counter here) */
            break;
        }

        /* Add character to ring buffer */
        uart_rx_buffer[uart_rx_head] = c;
        uart_rx_head = next_head;
    }

    /* Clear RX and RX timeout interrupts */
    mmio_write32((volatile void *)(uart + UART_ICR), UART_INT_RX | UART_INT_RT);
}

void fut_serial_init(void) {
    volatile uint8_t *uart = (volatile uint8_t *)UART0_BASE;

    /* Disable UART */
    mmio_write32((volatile void *)(uart + UART_CR), 0);

    /* Clear all interrupts */
    mmio_write32((volatile void *)(uart + UART_ICR), 0x7FF);

    /* Set baud rate to 115200 (assuming 24MHz UART clock)
     * IBRD = 24000000 / (16 * 115200) = 13
     * FBRD = (0.020833... * 64) + 0.5 = 2
     */
    mmio_write32((volatile void *)(uart + UART_IBRD), 13);
    mmio_write32((volatile void *)(uart + UART_FBRD), 2);

    /* Set line control: 8 bits, no parity, 1 stop bit, FIFOs enabled */
    mmio_write32((volatile void *)(uart + UART_LCR), (1 << 4) | (1 << 5) | (1 << 6));

    /* Enable RX interrupt and RX timeout interrupt for serial input */
    /* UART_INT_RX fires on FIFO threshold, UART_INT_RT fires after timeout of no chars */
    mmio_write32((volatile void *)(uart + UART_IMSC), UART_INT_RX | UART_INT_RT);

    /* Enable UART: TXE, RXE, UARTEN */
    mmio_write32((volatile void *)(uart + UART_CR), (1 << 0) | (1 << 8) | (1 << 9));

    /* Register RX interrupt handler and enable IRQ 33 (PL011 UART) */
    fut_register_irq_handler(33, uart_rx_irq_handler);
    fut_irq_enable(33);
}

void fut_serial_putc(char c) {
    volatile uint8_t *uart = (volatile uint8_t *)UART0_BASE;

    if (!uart_irq_mode) {
        /* Polling mode: direct write to UART with timeout */
        volatile int timeout = 100000;
        while ((mmio_read32((volatile void *)(uart + UART_FR)) & UART_FR_TXFF) && timeout > 0) {
            timeout--;
        }

        /* Write character if FIFO has space (or timeout expired) */
        if (timeout > 0) {
            mmio_write32((volatile void *)(uart + UART_DR), (uint32_t)c);
        }
    } else {
        /* Interrupt mode: queue into ring buffer */
        uint32_t next_head = (uart_tx_head + 1) % UART_TX_BUFFER_SIZE;

        /* Wait if buffer is full (with timeout to avoid deadlock) */
        volatile int timeout = 100000;
        while (next_head == uart_tx_tail && timeout > 0) {
            timeout--;
        }

        if (timeout > 0) {
            /* Add character to ring buffer */
            uart_tx_buffer[uart_tx_head] = c;
            uart_tx_head = next_head;

            /* Enable TX interrupt to start draining buffer */
            uint32_t imsc = mmio_read32((volatile void *)(uart + UART_IMSC));
            imsc |= UART_INT_TX;
            mmio_write32((volatile void *)(uart + UART_IMSC), imsc);
        }
    }
}

void fut_serial_puts(const char *str) {
    while (*str) {
        if (*str == '\n')
            fut_serial_putc('\r');
        fut_serial_putc(*str++);
    }

    /* Small delay to let UART buffer drain */
    for (volatile int i = 0; i < 1000; i++)
        ;
}

/* Alias for compatibility */
void serial_puts(const char *str) {
    fut_serial_puts(str);
}

/* Printf implementation with format string support */
static void print_num(uint64_t num, int base, int uppercase, int sign, int width) {
    char buf[32];
    const char *digits = uppercase ? "0123456789ABCDEF" : "0123456789abcdef";
    int i = 0;
    int negative = 0;

    /* Handle signed numbers */
    if (sign && (int64_t)num < 0) {
        negative = 1;
        num = -(int64_t)num;
    }

    /* Convert to string (reverse order) */
    if (num == 0) {
        buf[i++] = '0';
    } else {
        while (num > 0) {
            buf[i++] = digits[num % base];
            num /= base;
        }
    }

    /* Add sign */
    if (negative) {
        buf[i++] = '-';
    }

    /* Pad with spaces if needed */
    while (i < width) {
        buf[i++] = ' ';
    }

    /* Print in correct order */
    while (i > 0) {
        fut_serial_putc(buf[--i]);
    }
}

void fut_printf(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);

    while (*fmt) {
        if (*fmt == '%') {
            fmt++;

            /* Parse width */
            int width = 0;
            while (*fmt >= '0' && *fmt <= '9') {
                width = width * 10 + (*fmt - '0');
                fmt++;
            }

            /* Parse length modifiers */
            int is_long = 0;
            int is_longlong = 0;
            if (*fmt == 'l') {
                fmt++;
                is_long = 1;
                if (*fmt == 'l') {
                    fmt++;
                    is_longlong = 1;
                }
            }

            /* Process format specifier */
            switch (*fmt) {
                case 'd':
                case 'i': {
                    int64_t val;
                    if (is_longlong) {
                        val = va_arg(args, int64_t);
                    } else if (is_long) {
                        val = va_arg(args, long);
                    } else {
                        val = va_arg(args, int);
                    }
                    print_num((uint64_t)val, 10, 0, 1, width);
                    break;
                }
                case 'u': {
                    uint64_t val;
                    if (is_longlong) {
                        val = va_arg(args, uint64_t);
                    } else if (is_long) {
                        val = va_arg(args, unsigned long);
                    } else {
                        val = va_arg(args, unsigned int);
                    }
                    print_num(val, 10, 0, 0, width);
                    break;
                }
                case 'x': {
                    uint64_t val;
                    if (is_longlong) {
                        val = va_arg(args, uint64_t);
                    } else if (is_long) {
                        val = va_arg(args, unsigned long);
                    } else {
                        val = va_arg(args, unsigned int);
                    }
                    print_num(val, 16, 0, 0, width);
                    break;
                }
                case 'X': {
                    uint64_t val;
                    if (is_longlong) {
                        val = va_arg(args, uint64_t);
                    } else if (is_long) {
                        val = va_arg(args, unsigned long);
                    } else {
                        val = va_arg(args, unsigned int);
                    }
                    print_num(val, 16, 1, 0, width);
                    break;
                }
                case 'p': {
                    void *ptr = va_arg(args, void *);
                    fut_serial_puts("0x");
                    print_num((uint64_t)ptr, 16, 0, 0, 16);
                    break;
                }
                case 's': {
                    const char *str = va_arg(args, const char *);
                    if (str) {
                        fut_serial_puts(str);
                    } else {
                        fut_serial_puts("(null)");
                    }
                    break;
                }
                case 'c': {
                    char c = (char)va_arg(args, int);
                    fut_serial_putc(c);
                    break;
                }
                case '%': {
                    fut_serial_putc('%');
                    break;
                }
                default: {
                    fut_serial_putc('%');
                    fut_serial_putc(*fmt);
                    break;
                }
            }
            fmt++;
        } else {
            fut_serial_putc(*fmt);
            fmt++;
        }
    }

    va_end(args);
}

/* ============================================================
 *   GICv2 Interrupt Controller
 * ============================================================ */

static volatile uint32_t *gicd = (volatile uint32_t *)GICD_BASE;
static volatile uint32_t *gicc = (volatile uint32_t *)GICC_BASE;

static void fut_gic_init(void) {
    /* Disable distributor */
    mmio_write32(&gicd[GICD_CTLR / 4], 0);

    /* Get number of interrupt lines */
    uint32_t typer = mmio_read32(&gicd[4 / 4]);
    uint32_t num_irqs = ((typer & 0x1F) + 1) * 32;

    /* Disable all interrupts */
    for (uint32_t i = 0; i < num_irqs / 32; i++) {
        mmio_write32(&gicd[(GICD_ICENABLER + i * 4) / 4], 0xFFFFFFFF);
    }

    /* Clear all pending interrupts */
    for (uint32_t i = 0; i < num_irqs / 32; i++) {
        mmio_write32(&gicd[(GICD_ICPENDR + i * 4) / 4], 0xFFFFFFFF);
    }

    /* Set all interrupts to lowest priority */
    for (uint32_t i = 0; i < num_irqs; i++) {
        mmio_write32(&gicd[(GICD_IPRIORITYR + i * 4) / 4], 0xA0A0A0A0);
    }

    /* Route all interrupts to CPU 0 */
    for (uint32_t i = 32 / 4; i < num_irqs / 4; i++) {
        mmio_write32(&gicd[(GICD_ITARGETSR + i * 4) / 4], 0x01010101);
    }

    /* Enable distributor */
    mmio_write32(&gicd[GICD_CTLR / 4], 1);

    /* Configure CPU interface */
    mmio_write32(&gicc[GICC_PMR / 4], 0xF0);     /* Priority mask */
    mmio_write32(&gicc[GICC_CTLR / 4], 1);       /* Enable CPU interface */
}

void fut_irq_enable(uint8_t irq) {
    uint32_t reg = irq / 32;
    uint32_t bit = irq % 32;
    mmio_write32(&gicd[(GICD_ISENABLER + reg * 4) / 4], 1U << bit);
}

void fut_irq_disable(uint8_t irq) {
    uint32_t reg = irq / 32;
    uint32_t bit = irq % 32;
    mmio_write32(&gicd[(GICD_ICENABLER + reg * 4) / 4], 1U << bit);
}

void fut_irq_send_eoi(uint8_t irq) {
    (void)irq;  /* IRQ number from IAR */
    /* End of interrupt - write to GICC_EOIR */
    mmio_write32(&gicc[GICC_EOIR / 4], irq);
}

/* Get pending interrupt number */
int fut_irq_acknowledge(void) {
    uint32_t intack = mmio_read32(&gicc[GICC_IAR / 4]);
    int irq = intack & 0x3FF;

    /* Check for spurious interrupt */
    if (irq == 1023) {
        return -1;  /* Spurious interrupt */
    }

    return irq;
}

/* ============================================================
 *   ARM Generic Timer
 * ============================================================ */

static uint32_t timer_frequency = 0;
static uint64_t timer_ticks = 0;

void fut_timer_init(uint32_t frequency) {
    /* Read timer frequency from system register */
    timer_frequency = read_sysreg(cntfrq_el0);

    fut_serial_puts("[TIMER] ARM Generic Timer frequency: ");
    fut_serial_puts("\n");

    /* Calculate timer value for desired frequency */
    uint32_t timer_interval = timer_frequency / frequency;

    /* Set timer compare value */
    write_sysreg(cntp_tval_el0, timer_interval);

    /* Enable timer: ENABLE=1, IMASK=0 */
    write_sysreg(cntp_ctl_el0, CNTP_CTL_ENABLE);

    /* Enable timer interrupt (IRQ 30 on QEMU virt) */
    fut_irq_enable(30);
}

uint64_t fut_timer_get_ticks(void) {
    return timer_ticks;
}

uint32_t fut_timer_get_frequency(void) {
    return timer_frequency;
}

void fut_timer_irq_handler(void) {
    /* Call common timer tick handler (updates system time, wakes threads, etc.) */
    extern void fut_timer_tick(void);
    fut_timer_tick();

    timer_ticks++;

    /* Reset timer for next interrupt */
    uint32_t timer_interval = timer_frequency / CONFIG_TIMER_HZ;
    write_sysreg(cntp_tval_el0, timer_interval);
}

/* ============================================================
 *   Interrupt Enable/Disable
 * ============================================================ */

void fut_enable_interrupts(void) {
    __asm__ volatile("msr daifclr, #2" ::: "memory");  /* Clear I bit */
}

void fut_disable_interrupts(void) {
    __asm__ volatile("msr daifset, #2" ::: "memory");  /* Set I bit */
}

uint64_t fut_save_and_disable_interrupts(void) {
    uint64_t pstate = read_sysreg(CurrentEL);
    fut_disable_interrupts();
    return pstate;
}

void fut_restore_interrupts(uint64_t state) {
    if (!(state & PSTATE_I_BIT)) {
        fut_enable_interrupts();
    }
}

/* ============================================================
 *   CPU Management
 * ============================================================ */

uint32_t fut_platform_get_cpu_id(void) {
    return 0;  /* Single core for Phase 2 */
}

uint32_t fut_platform_get_cpu_count(void) {
    return 1;  /* Single core for Phase 2 */
}

void fut_platform_cpu_halt(void) {
    __asm__ volatile("wfi");  /* Wait for interrupt */
}

void fut_platform_udelay(uint32_t usec) {
    /* Simple delay loop (not precise) */
    uint64_t start = read_sysreg(cntpct_el0);
    uint64_t delta = (timer_frequency * usec) / 1000000;
    while ((read_sysreg(cntpct_el0) - start) < delta)
        ;
}

/* ============================================================
 *   Memory Management
 * ============================================================ */

void fut_platform_mem_init(uint64_t mem_lower, uint64_t mem_upper) {
    (void)mem_lower;
    (void)mem_upper;
    /* Phase 2: Basic identity mapping, no paging yet */
    fut_serial_puts("[MEM] ARM64 memory management stub\n");
}

uint64_t fut_platform_get_mem_size(void) {
    /* Phase 2: Return fixed size, should read from device tree */
    return 128 * 1024 * 1024;  /* 128 MB */
}

void fut_platform_tlb_flush(void) {
    __asm__ volatile("tlbi vmalle1" ::: "memory");
    dsb();
    isb();
}

void fut_platform_tlb_flush_page(uint64_t vaddr) {
    __asm__ volatile("tlbi vae1, %0" :: "r"(vaddr >> 12) : "memory");
    dsb();
    isb();
}

/* ============================================================
 *   Platform Information
 * ============================================================ */

const char *fut_platform_get_name(void) {
    return "ARM64";
}

uint64_t fut_platform_get_features(void) {
    return PLATFORM_FEATURE_MMU |
           PLATFORM_FEATURE_FPU |
           PLATFORM_FEATURE_SIMD |
           PLATFORM_FEATURE_TIMER |
           PLATFORM_FEATURE_UART;
}

/* ============================================================
 *   Panic Handler
 * ============================================================ */

[[noreturn]] void fut_platform_panic(const char *message) {
    fut_disable_interrupts();
    fut_serial_puts("\n[PANIC] ");
    fut_serial_puts(message);
    fut_serial_puts("\n");

    /* Halt CPU */
    while (1) {
        __asm__ volatile("wfi");
    }
}

/* ============================================================
 *   Debugging Support
 * ============================================================ */

void fut_platform_dump_registers(struct fut_interrupt_frame *frame) {
    fut_serial_puts("[REGS] ARM64 register dump:\n");
    if (frame) {
        fut_serial_puts("  PC=");
        fut_serial_puts("\n");
        fut_serial_puts("  SP=");
        fut_serial_puts("\n");
    }
}

void fut_platform_stack_trace(int max_frames) {
    fut_serial_puts("[TRACE] ARM64 stack trace not implemented\n");
    (void)max_frames;
}

/* ============================================================
 *   Deferred Reschedule Tracking
 * ============================================================ */

static _Bool reschedule_pending = 0;

_Bool fut_reschedule_pending(void) {
    return reschedule_pending;
}

void fut_clear_reschedule(void) {
    reschedule_pending = 0;
}

void fut_request_reschedule(void) {
    reschedule_pending = 1;
}

/* ============================================================
 *   Platform Initialization Entry Points
 * ============================================================ */

/* External kernel main */
extern void fut_kernel_main(void);

void fut_platform_early_init(uint32_t boot_magic, void *boot_info) {
    (void)boot_magic;
    (void)boot_info;

    /* Initialize serial console first */
    fut_serial_init();
    fut_serial_puts("\nFutura OS ARM64 Platform Initialization\n");
    fut_serial_puts("========================================\n\n");

    /* Initialize GIC */
    fut_serial_puts("[INIT] Initializing GICv2...\n");
    fut_gic_init();

    /* Initialize timer */
    fut_serial_puts("[INIT] Initializing ARM Generic Timer...\n");
    fut_timer_init(CONFIG_TIMER_HZ);

    /* Enable interrupts */
    fut_serial_puts("[INIT] Enabling interrupts...\n");
    fut_enable_interrupts();

    /* Register UART TX interrupt handler - but stay in polling mode for now */
    fut_serial_puts("[DEBUG] Registering UART TX IRQ handler (IRQ 33)...\n");
    int result = fut_register_irq_handler(33, uart_tx_irq_handler);
    if (result == 0) {
        fut_serial_puts("[DEBUG] UART IRQ handler registered successfully\n");
        fut_irq_enable(33);
        fut_serial_puts("[DEBUG] UART IRQ 33 enabled in GIC\n");

        /* Switch to interrupt-driven mode now that IRQ handler registration is fixed */
        uart_irq_mode = 1;
        fut_serial_puts("[DEBUG] UART switched to interrupt-driven mode\n");
    } else {
        fut_serial_puts("[DEBUG] UART IRQ handler registration failed, staying in polling mode\n");
    }
}

void fut_platform_late_init(void) {
    /* Late initialization placeholder (currently unused) */
    fut_serial_puts("[INIT] ARM64 platform late initialization complete\n\n");
}

/* Main platform entry point (called from boot.S) */
void fut_platform_init(uint32_t boot_magic, void *boot_info) {
    /* Early initialization */
    fut_platform_early_init(boot_magic, boot_info);

    /* Call kernel main */
    fut_serial_puts("[INIT] Jumping to kernel main...\n\n");
    fut_kernel_main();

    /* Should never reach here */
    fut_platform_panic("Kernel main returned!");
}

/* Weak symbol stubs */
void __attribute__((weak)) fut_kernel_main(void) {
    fut_serial_puts("[KERNEL] ARM64 kernel main not implemented!\n");
    while (1) {
        __asm__ volatile("wfi");
    }
}
