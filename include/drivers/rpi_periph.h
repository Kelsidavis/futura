/* rpi_periph.h - Raspberry Pi 4/5 Peripheral Base Addresses
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Memory-mapped I/O register base addresses for BCM2711 (Pi4) and
 * BCM2712 (Pi5). Used by all RPi drivers for MMIO access.
 *
 * RPi4 (BCM2711): ARM peripherals at 0xFE000000 (low peripheral mode)
 * RPi5 (BCM2712): ARM peripherals at 0x107C000000 (new SoC layout)
 */

#ifndef __FUTURA_RPI_PERIPH_H__
#define __FUTURA_RPI_PERIPH_H__

#include <stdint.h>
#include <stdbool.h>

/* ── BCM2711 (Raspberry Pi 4) ── */

#define BCM2711_PERIPH_BASE     0xFE000000ULL
#define BCM2711_PERIPH_SIZE     0x01800000  /* 24 MB */

/* Core peripherals */
#define BCM2711_GPIO_BASE       (BCM2711_PERIPH_BASE + 0x200000)
#define BCM2711_UART0_BASE      (BCM2711_PERIPH_BASE + 0x201000)  /* PL011 */
#define BCM2711_UART2_BASE      (BCM2711_PERIPH_BASE + 0x201400)  /* PL011 */
#define BCM2711_UART3_BASE      (BCM2711_PERIPH_BASE + 0x201600)  /* PL011 */
#define BCM2711_UART4_BASE      (BCM2711_PERIPH_BASE + 0x201800)  /* PL011 */
#define BCM2711_UART5_BASE      (BCM2711_PERIPH_BASE + 0x201A00)  /* PL011 */
#define BCM2711_AUX_BASE        (BCM2711_PERIPH_BASE + 0x215000)  /* Mini UART + SPI1/2 */
#define BCM2711_MINIUART_BASE   (BCM2711_PERIPH_BASE + 0x215040)  /* Mini UART */
#define BCM2711_MAILBOX_BASE    (BCM2711_PERIPH_BASE + 0x00B880)
#define BCM2711_WATCHDOG_BASE   (BCM2711_PERIPH_BASE + 0x100000)
#define BCM2711_RNG_BASE        (BCM2711_PERIPH_BASE + 0x104000)  /* HW RNG */
#define BCM2711_I2C0_BASE       (BCM2711_PERIPH_BASE + 0x205000)
#define BCM2711_I2C1_BASE       (BCM2711_PERIPH_BASE + 0x804000)
#define BCM2711_SPI0_BASE       (BCM2711_PERIPH_BASE + 0x204000)
#define BCM2711_PWM_BASE        (BCM2711_PERIPH_BASE + 0x20C000)
#define BCM2711_EMMC_BASE       (BCM2711_PERIPH_BASE + 0x300000)  /* SD host */
#define BCM2711_EMMC2_BASE      (BCM2711_PERIPH_BASE + 0x340000)  /* eMMC2 (SD card) */

/* Interrupt controller — GIC-400 */
#define BCM2711_GIC_DIST_BASE   0xFF841000ULL   /* GIC Distributor */
#define BCM2711_GIC_CPU_BASE    0xFF842000ULL   /* GIC CPU Interface */

/* PCIe (for USB 3.0 via VL805 xHCI) */
#define BCM2711_PCIE_BASE       0xFD500000ULL
#define BCM2711_XHCI_BASE       0x600000000ULL  /* USB 3.0 after PCIe init */

/* Ethernet — GENET (Gigabit Ethernet) */
#define BCM2711_GENET_BASE      (BCM2711_PERIPH_BASE + 0x580000) /* GENET v5 */

/* HDMI */
#define BCM2711_HDMI0_BASE      0xFEF00700ULL
#define BCM2711_HDMI1_BASE      0xFEF05700ULL
#define BCM2711_PIXEL_VALVE0    (BCM2711_PERIPH_BASE + 0x206000)

/* ARM local peripherals */
#define BCM2711_ARM_LOCAL_BASE  0xFF800000ULL

/* ── BCM2712 (Raspberry Pi 5) ── */

#define BCM2712_PERIPH_BASE     0x107C000000ULL
#define BCM2712_PERIPH_SIZE     0x04000000  /* 64 MB */

/* Core peripherals (offsets differ from Pi4) */
#define BCM2712_GPIO_BASE       (BCM2712_PERIPH_BASE + 0xD0000)
#define BCM2712_UART0_BASE      (BCM2712_PERIPH_BASE + 0x40000)   /* PL011 UART10 */
#define BCM2712_UART1_BASE      (BCM2712_PERIPH_BASE + 0x44000)   /* PL011 */
#define BCM2712_UART2_BASE      (BCM2712_PERIPH_BASE + 0x48000)   /* PL011 */
#define BCM2712_MAILBOX_BASE    (BCM2712_PERIPH_BASE + 0x13880)
#define BCM2712_I2C0_BASE       (BCM2712_PERIPH_BASE + 0x70000)
#define BCM2712_I2C1_BASE       (BCM2712_PERIPH_BASE + 0x74000)
#define BCM2712_SPI0_BASE       (BCM2712_PERIPH_BASE + 0x50000)
#define BCM2712_WATCHDOG_BASE   (BCM2712_PERIPH_BASE + 0x100000)
#define BCM2712_RNG_BASE        (BCM2712_PERIPH_BASE + 0x104000)
#define BCM2712_EMMC2_BASE      (BCM2712_PERIPH_BASE + 0x340000)

/* Interrupt controller — GIC-400 (same as Pi4) */
#define BCM2712_GIC_DIST_BASE   0x107FFF9000ULL
#define BCM2712_GIC_CPU_BASE    0x107FFFA000ULL

/* RP1 south bridge (new in Pi5 — handles most I/O) */
#define BCM2712_RP1_BAR         0x1F00000000ULL  /* PCIe BAR for RP1 */
#define BCM2712_RP1_GPIO_BASE   (BCM2712_RP1_BAR + 0xD0000)
#define BCM2712_RP1_UART0_BASE  (BCM2712_RP1_BAR + 0x30000)
#define BCM2712_RP1_I2C0_BASE   (BCM2712_RP1_BAR + 0x70000)
#define BCM2712_RP1_SPI0_BASE   (BCM2712_RP1_BAR + 0x50000)
#define BCM2712_RP1_ETH_BASE    (BCM2712_RP1_BAR + 0x100000)

/* PCIe gen3 (native, no VL805) */
#define BCM2712_PCIE_BASE       0x1000120000ULL

/* HDMI */
#define BCM2712_HDMI0_BASE      0x107C700700ULL

/* ── Common platform detection ── */

typedef enum {
    RPI_MODEL_UNKNOWN = 0,
    RPI_MODEL_3B,
    RPI_MODEL_3B_PLUS,
    RPI_MODEL_4B,
    RPI_MODEL_400,
    RPI_MODEL_CM4,
    RPI_MODEL_5,
} rpi_model_t;

typedef struct {
    rpi_model_t model;
    const char *name;
    uint64_t periph_base;
    uint64_t uart_base;
    uint64_t gpio_base;
    uint64_t mailbox_base;
    uint64_t gic_dist_base;
    uint64_t gic_cpu_base;
    uint64_t emmc2_base;
    uint32_t ram_mb;
    bool has_gic;
    bool has_pcie;
    bool has_genet;
    bool has_rp1;
} rpi_hw_info_t;

/* Get hardware info from board revision code */
static inline rpi_hw_info_t rpi_detect_model(uint32_t board_rev) {
    rpi_hw_info_t hw = {0};

    /* New-style revision codes (bit 23 set) */
    if (board_rev & (1 << 23)) {
        uint32_t type = (board_rev >> 4) & 0xFF;
        uint32_t ram  = (board_rev >> 20) & 0x7;
        uint32_t ram_sizes[] = { 256, 512, 1024, 2048, 4096, 8192 };
        hw.ram_mb = (ram < 6) ? ram_sizes[ram] : 0;

        switch (type) {
        case 0x04: /* Pi 2B */
        case 0x08: /* Pi 3B */
            hw.model = RPI_MODEL_3B;
            hw.name = "Raspberry Pi 3B";
            hw.periph_base = 0x3F000000ULL;
            hw.has_gic = false;
            break;
        case 0x0D: /* Pi 3B+ */
            hw.model = RPI_MODEL_3B_PLUS;
            hw.name = "Raspberry Pi 3B+";
            hw.periph_base = 0x3F000000ULL;
            hw.has_gic = false;
            break;
        case 0x11: /* Pi 4B */
            hw.model = RPI_MODEL_4B;
            hw.name = "Raspberry Pi 4B";
            hw.periph_base = BCM2711_PERIPH_BASE;
            hw.uart_base = BCM2711_UART0_BASE;
            hw.gpio_base = BCM2711_GPIO_BASE;
            hw.mailbox_base = BCM2711_MAILBOX_BASE;
            hw.gic_dist_base = BCM2711_GIC_DIST_BASE;
            hw.gic_cpu_base = BCM2711_GIC_CPU_BASE;
            hw.emmc2_base = BCM2711_EMMC2_BASE;
            hw.has_gic = true;
            hw.has_pcie = true;
            hw.has_genet = true;
            break;
        case 0x13: /* Pi 400 */
            hw.model = RPI_MODEL_400;
            hw.name = "Raspberry Pi 400";
            hw.periph_base = BCM2711_PERIPH_BASE;
            hw.uart_base = BCM2711_UART0_BASE;
            hw.gpio_base = BCM2711_GPIO_BASE;
            hw.mailbox_base = BCM2711_MAILBOX_BASE;
            hw.gic_dist_base = BCM2711_GIC_DIST_BASE;
            hw.gic_cpu_base = BCM2711_GIC_CPU_BASE;
            hw.has_gic = true;
            hw.has_pcie = true;
            hw.has_genet = true;
            break;
        case 0x14: /* CM4 */
            hw.model = RPI_MODEL_CM4;
            hw.name = "Raspberry Pi CM4";
            hw.periph_base = BCM2711_PERIPH_BASE;
            hw.uart_base = BCM2711_UART0_BASE;
            hw.gpio_base = BCM2711_GPIO_BASE;
            hw.mailbox_base = BCM2711_MAILBOX_BASE;
            hw.gic_dist_base = BCM2711_GIC_DIST_BASE;
            hw.gic_cpu_base = BCM2711_GIC_CPU_BASE;
            hw.has_gic = true;
            hw.has_pcie = true;
            break;
        case 0x17: /* Pi 5 */
            hw.model = RPI_MODEL_5;
            hw.name = "Raspberry Pi 5";
            hw.periph_base = BCM2712_PERIPH_BASE;
            hw.uart_base = BCM2712_UART0_BASE;
            hw.gpio_base = BCM2712_GPIO_BASE;
            hw.mailbox_base = BCM2712_MAILBOX_BASE;
            hw.gic_dist_base = BCM2712_GIC_DIST_BASE;
            hw.gic_cpu_base = BCM2712_GIC_CPU_BASE;
            hw.emmc2_base = BCM2712_EMMC2_BASE;
            hw.has_gic = true;
            hw.has_pcie = true;
            hw.has_rp1 = true;
            break;
        default:
            hw.model = RPI_MODEL_UNKNOWN;
            hw.name = "Unknown Raspberry Pi";
            break;
        }
    }

    return hw;
}

/* ── Mailbox API (implemented in rpi_mailbox.c) ── */

void     rpi_mailbox_init(uint64_t periph_base);
uint32_t rpi_mbox_get_board_revision(void);
uint64_t rpi_mbox_get_board_serial(void);
void     rpi_mbox_get_arm_memory(uint32_t *base, uint32_t *size);
uint32_t rpi_mbox_get_clock_rate(uint32_t clock_id);
uint32_t rpi_mbox_set_clock_rate(uint32_t clock_id, uint32_t rate_hz);
bool     rpi_mbox_set_power_state(uint32_t device_id, bool on);
uint32_t rpi_mbox_get_temperature(void);
bool     rpi_mbox_alloc_framebuffer(uint32_t width, uint32_t height, uint32_t depth,
                                     uint32_t *fb_addr, uint32_t *fb_size, uint32_t *pitch);

#endif /* __FUTURA_RPI_PERIPH_H__ */
