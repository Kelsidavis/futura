/* platform/arm64/rpi_entry.c - Raspberry Pi C-level kernel entry
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Called by rpi_boot.S after EL1 setup and cache enable.
 * Initializes UART for early output, detects the platform via DTB,
 * sets up the mailbox, and then transitions to the main kernel.
 *
 * This file is only compiled for the RPi boot target, not the
 * QEMU virt target.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <drivers/rpi_periph.h>

/* PL011 UART register offsets */
#define UART_DR     0x00
#define UART_FR     0x18
#define UART_IBRD   0x24
#define UART_FBRD   0x28
#define UART_LCRH   0x2C
#define UART_CR     0x30
#define UART_ICR    0x44

/* UART flags */
#define UART_FR_TXFF    (1 << 5)
#define UART_FR_RXFE    (1 << 4)

static volatile uint32_t *uart_base = NULL;

/* ── Early UART output (before kprintf is available) ── */

static void early_uart_putc(char c) {
    if (!uart_base) return;
    /* Wait for TX FIFO to have space */
    while (uart_base[UART_FR / 4] & UART_FR_TXFF)
        __asm__ volatile("yield");
    uart_base[UART_DR / 4] = (uint32_t)c;
}

static void early_uart_puts(const char *s) {
    while (*s) {
        if (*s == '\n') early_uart_putc('\r');
        early_uart_putc(*s++);
    }
}

static void early_uart_hex(uint64_t val) {
    const char hex[] = "0123456789abcdef";
    early_uart_puts("0x");
    for (int i = 60; i >= 0; i -= 4)
        early_uart_putc(hex[(val >> i) & 0xF]);
}

/* ── PL011 UART initialization ── */

static void early_uart_init(uint64_t base, uint32_t clock_hz, uint32_t baud) {
    uart_base = (volatile uint32_t *)(uintptr_t)base;

    /* Disable UART */
    uart_base[UART_CR / 4] = 0;

    /* Clear pending interrupts */
    uart_base[UART_ICR / 4] = 0x7FF;

    /* Set baud rate: divisor = clock / (16 * baud) */
    uint32_t div = clock_hz / (16 * baud);
    uint32_t frac = ((clock_hz % (16 * baud)) * 64 + (8 * baud)) / (16 * baud);
    uart_base[UART_IBRD / 4] = div;
    uart_base[UART_FBRD / 4] = frac;

    /* 8N1, FIFO enabled */
    uart_base[UART_LCRH / 4] = (3 << 5) | (1 << 4); /* WLEN=8, FEN=1 */

    /* Enable UART, TX, RX */
    uart_base[UART_CR / 4] = (1 << 0) | (1 << 8) | (1 << 9); /* UARTEN, TXE, RXE */
}

/* ── DTB minimal parsing (just get compatible string) ── */

static uint32_t dtb_read32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  | (uint32_t)p[3];
}

static bool dtb_is_rpi5(uint64_t dtb_addr) {
    const uint8_t *dtb = (const uint8_t *)(uintptr_t)dtb_addr;
    if (dtb_read32(dtb) != 0xD00DFEED) return false;

    uint32_t total_size = dtb_read32(dtb + 4);
    uint32_t struct_off = dtb_read32(dtb + 8);
    uint32_t strings_off = dtb_read32(dtb + 12);

    /* Search for "raspberrypi,5" in strings block */
    const char *strings = (const char *)(dtb + strings_off);
    const uint8_t *structs = dtb + struct_off;

    /* Walk FDT structure to find compatible property */
    uint32_t pos = 0;
    while (pos < total_size - struct_off) {
        uint32_t token = dtb_read32(structs + pos);
        pos += 4;
        if (token == 0x00000003) { /* FDT_PROP */
            uint32_t len = dtb_read32(structs + pos);
            uint32_t nameoff = dtb_read32(structs + pos + 4);
            pos += 8;
            const char *propname = strings + nameoff;
            if (propname[0] == 'c' && propname[1] == 'o' && propname[2] == 'm') {
                /* Check if compatible value contains "5-model-b" */
                const char *val = (const char *)(structs + pos);
                for (uint32_t i = 0; i + 9 < len; i++) {
                    if (val[i] == '5' && val[i+1] == '-' && val[i+2] == 'm')
                        return true;
                }
            }
            pos = (pos + len + 3) & ~3; /* Align to 4 bytes */
        } else if (token == 0x00000001) { /* FDT_BEGIN_NODE */
            while (structs[pos] != 0) pos++;
            pos = (pos + 4) & ~3;
        } else if (token == 0x00000002) { /* FDT_END_NODE */
            /* continue */
        } else if (token == 0x00000009) { /* FDT_END */
            break;
        }
    }
    return false;
}

/* ── Main C entry point ── */

void rpi_kernel_entry(uint64_t dtb_addr) {
    /* Detect Pi4 vs Pi5 from DTB */
    bool is_pi5 = dtb_is_rpi5(dtb_addr);

    /* Initialize UART for early debug output */
    if (is_pi5) {
        /* Pi5 (BCM2712): UART at different base, 44.2 MHz clock */
        early_uart_init(0x107C040000ULL, 44236800, 115200);
    } else {
        /* Pi4 (BCM2711): PL011 UART0 at 0xFE201000, 48 MHz clock */
        early_uart_init(0xFE201000ULL, 48000000, 115200);
    }

    early_uart_puts("\n\n");
    early_uart_puts("========================================\n");
    early_uart_puts("  Futura OS - Raspberry Pi Boot\n");
    early_uart_puts("========================================\n");
    early_uart_puts("DTB address: ");
    early_uart_hex(dtb_addr);
    early_uart_puts("\n");
    early_uart_puts("Platform: ");
    early_uart_puts(is_pi5 ? "Raspberry Pi 5 (BCM2712)\n" : "Raspberry Pi 4 (BCM2711)\n");

    /* Initialize mailbox */
    uint64_t periph = is_pi5 ? BCM2712_PERIPH_BASE : BCM2711_PERIPH_BASE;
    rpi_mailbox_init(periph);

    /* Query board info via mailbox */
    uint32_t rev = rpi_mbox_get_board_revision();
    early_uart_puts("Board revision: ");
    early_uart_hex(rev);
    early_uart_puts("\n");

    uint32_t temp = rpi_mbox_get_temperature();
    early_uart_puts("SoC temperature: ");
    /* Simple decimal print */
    uint32_t deg = temp / 1000;
    char tbuf[4] = { '0' + (char)(deg / 10), '0' + (char)(deg % 10), 'C', '\0' };
    early_uart_puts(tbuf);
    early_uart_puts("\n");

    /* Get ARM memory */
    uint32_t mem_base = 0, mem_size = 0;
    rpi_mbox_get_arm_memory(&mem_base, &mem_size);
    early_uart_puts("ARM memory: ");
    early_uart_hex(mem_size);
    early_uart_puts(" bytes\n");

    /* Get UART clock rate */
    uint32_t uart_clk = rpi_mbox_get_clock_rate(2 /* CLOCK_ID_UART */);
    early_uart_puts("UART clock: ");
    early_uart_hex(uart_clk);
    early_uart_puts(" Hz\n");

    early_uart_puts("\n");
    early_uart_puts("Futura OS kernel starting...\n");
    early_uart_puts("========================================\n\n");

    /* TODO: Set up MMU with RPi-specific memory map, then jump to kernel_main.
     * For now, the kernel needs to be linked for flat physical addressing
     * (using boot/rpi.ld instead of platform/arm64/link.ld). */

    /* Call the main RPi initialization path */
    extern void fut_rpi_boot_init(uint64_t dtb_ptr);
    fut_rpi_boot_init(dtb_addr);

    /* Halt — kernel_main should take over from here */
    early_uart_puts("[RPi] Boot init complete, entering idle\n");
    while (1) __asm__ volatile("wfe");
}
