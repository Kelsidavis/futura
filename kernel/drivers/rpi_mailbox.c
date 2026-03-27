/* kernel/drivers/rpi_mailbox.c - Raspberry Pi VideoCore Mailbox Driver
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements the VideoCore mailbox interface for Raspberry Pi 4 (BCM2711)
 * and Raspberry Pi 5 (BCM2712). The mailbox is the primary communication
 * channel between the ARM cores and the VideoCore GPU firmware.
 *
 * Used for:
 *   - Clock configuration (UART, EMMC, core, arm)
 *   - Power domain management (USB, HDMI, I2C, SPI)
 *   - Framebuffer allocation and configuration
 *   - Board revision and serial number queries
 *   - GPIO expander control (active LED, power LED)
 *   - Temperature and voltage monitoring
 *   - Memory split configuration
 *
 * Mailbox protocol:
 *   Channel 8 (ARM→VC property interface):
 *     1. Write buffer physical address | channel to WRITE register
 *     2. Poll READ register until channel matches
 *     3. Response overwrites buffer in-place
 *
 * RPi4 (BCM2711) peripheral base: 0xFE000000
 * RPi5 (BCM2712) peripheral base: 0x107C000000 (differs from Pi4!)
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

/* ── Mailbox register offsets ── */

#define MBOX_READ       0x00    /* Read register */
#define MBOX_STATUS     0x18    /* Status register */
#define MBOX_WRITE      0x20    /* Write register */

#define MBOX_FULL       0x80000000  /* Status: write mailbox full */
#define MBOX_EMPTY      0x40000000  /* Status: read mailbox empty */

#define MBOX_CHANNEL_PROP  8    /* ARM→VC property channel */

/* ── Property tag IDs ── */

/* VideoCore */
#define TAG_GET_FIRMWARE_REV    0x00000001

/* Board */
#define TAG_GET_BOARD_MODEL     0x00010001
#define TAG_GET_BOARD_REV       0x00010002
#define TAG_GET_BOARD_MAC       0x00010003
#define TAG_GET_BOARD_SERIAL    0x00010004
#define TAG_GET_ARM_MEMORY      0x00010005
#define TAG_GET_VC_MEMORY       0x00010006

/* Clocks */
#define TAG_GET_CLOCK_RATE      0x00030002
#define TAG_SET_CLOCK_RATE      0x00038002
#define TAG_GET_MAX_CLOCK_RATE  0x00030004
#define TAG_GET_MIN_CLOCK_RATE  0x00030007

/* Power */
#define TAG_GET_POWER_STATE     0x00020001
#define TAG_SET_POWER_STATE     0x00028001

/* Temperature */
#define TAG_GET_TEMPERATURE     0x00030006
#define TAG_GET_MAX_TEMPERATURE 0x0003000A

/* Framebuffer */
#define TAG_ALLOCATE_BUFFER     0x00040001
#define TAG_RELEASE_BUFFER      0x00048001
#define TAG_SET_PHYSICAL_SIZE   0x00048003
#define TAG_SET_VIRTUAL_SIZE    0x00048004
#define TAG_SET_DEPTH           0x00048005
#define TAG_SET_PIXEL_ORDER     0x00048006
#define TAG_GET_PITCH           0x00040008
#define TAG_SET_VIRTUAL_OFFSET  0x00048009

/* GPIO (virtual — via firmware) */
#define TAG_GET_GPIO_STATE      0x00030041
#define TAG_SET_GPIO_STATE      0x00038041

/* Clock IDs */
#define CLOCK_ID_EMMC   1
#define CLOCK_ID_UART   2
#define CLOCK_ID_ARM    3
#define CLOCK_ID_CORE   4
#define CLOCK_ID_V3D    5
#define CLOCK_ID_H264   6
#define CLOCK_ID_ISP    7
#define CLOCK_ID_SDRAM  8
#define CLOCK_ID_PIXEL  9
#define CLOCK_ID_PWM    10
#define CLOCK_ID_HEVC   11
#define CLOCK_ID_EMMC2  12

/* Power domain IDs */
#define POWER_ID_SD     0
#define POWER_ID_UART0  1
#define POWER_ID_UART1  2
#define POWER_ID_USB    3
#define POWER_ID_I2C0   4
#define POWER_ID_I2C1   5
#define POWER_ID_I2C2   6
#define POWER_ID_SPI    7
#define POWER_ID_CCP2TX 8

/* ── Mailbox buffer (must be 16-byte aligned) ── */

static uint32_t __attribute__((aligned(16))) mbox_buffer[256];

/* ── Platform state ── */

static volatile uint32_t *mbox_base = NULL;
static uint64_t peripheral_base = 0;

/* ── MMIO helpers ── */

static inline uint32_t mmio_read(volatile uint32_t *addr) {
    uint32_t val;
    __asm__ volatile("ldr %w0, [%1]" : "=r"(val) : "r"(addr) : "memory");
    return val;
}

static inline void mmio_write(volatile uint32_t *addr, uint32_t val) {
    __asm__ volatile("str %w0, [%1]" :: "r"(val), "r"(addr) : "memory");
}

/* ── Mailbox communication ── */

/**
 * rpi_mbox_call() — Send a property tag buffer to VideoCore and wait for reply.
 * @channel: Mailbox channel (usually MBOX_CHANNEL_PROP = 8)
 * Returns: true on success (response code 0x80000000), false on failure.
 */
static bool rpi_mbox_call(uint8_t channel) {
    if (!mbox_base) return false;

    /* Get physical address of buffer (identity-mapped at boot) */
    uint64_t buf_addr = (uint64_t)(uintptr_t)mbox_buffer;
    /* For kernel virtual addresses, convert to physical */
    if (buf_addr >= 0xFFFFFF8000000000ULL) {
        buf_addr = buf_addr - 0xFFFFFF8040000000ULL + 0x40000000ULL;
    }

    uint32_t msg = ((uint32_t)(buf_addr & 0xFFFFFFF0)) | (channel & 0xF);

    /* Wait until mailbox is not full */
    volatile uint32_t *status = (volatile uint32_t *)((uintptr_t)mbox_base + MBOX_STATUS);
    volatile uint32_t *write_reg = (volatile uint32_t *)((uintptr_t)mbox_base + MBOX_WRITE);
    volatile uint32_t *read_reg = (volatile uint32_t *)((uintptr_t)mbox_base + MBOX_READ);

    int timeout = 1000000;
    while ((mmio_read(status) & MBOX_FULL) && --timeout > 0)
        __asm__ volatile("yield");
    if (timeout <= 0) return false;

    /* Write message */
    mmio_write(write_reg, msg);

    /* Wait for response */
    timeout = 1000000;
    while (--timeout > 0) {
        while ((mmio_read(status) & MBOX_EMPTY) && --timeout > 0)
            __asm__ volatile("yield");
        if (timeout <= 0) return false;

        uint32_t response = mmio_read(read_reg);
        if ((response & 0xF) == channel) {
            /* Check response code */
            return mbox_buffer[1] == 0x80000000; /* Request successful */
        }
    }
    return false;
}

/* ── Public API ── */

/**
 * rpi_mailbox_init() — Initialize the mailbox driver.
 * @periph_base: Physical base address of peripherals
 *               RPi4: 0xFE000000, RPi5: 0x107C000000
 */
void rpi_mailbox_init(uint64_t periph_base) {
    peripheral_base = periph_base;
    /* Mailbox is at peripheral_base + 0xB880 */
    mbox_base = (volatile uint32_t *)(uintptr_t)(periph_base + 0xB880);
}

/**
 * rpi_mbox_get_board_revision() — Get the board revision number.
 * Identifies exact Pi model, memory, manufacturer.
 */
uint32_t rpi_mbox_get_board_revision(void) {
    mbox_buffer[0] = 7 * 4;         /* Buffer size */
    mbox_buffer[1] = 0;             /* Request */
    mbox_buffer[2] = TAG_GET_BOARD_REV;
    mbox_buffer[3] = 4;             /* Value buffer size */
    mbox_buffer[4] = 0;             /* Request/response indicator */
    mbox_buffer[5] = 0;             /* Value (filled by VC) */
    mbox_buffer[6] = 0;             /* End tag */

    if (rpi_mbox_call(MBOX_CHANNEL_PROP))
        return mbox_buffer[5];
    return 0;
}

/**
 * rpi_mbox_get_board_serial() — Get the 64-bit board serial number.
 */
uint64_t rpi_mbox_get_board_serial(void) {
    mbox_buffer[0] = 8 * 4;
    mbox_buffer[1] = 0;
    mbox_buffer[2] = TAG_GET_BOARD_SERIAL;
    mbox_buffer[3] = 8;
    mbox_buffer[4] = 0;
    mbox_buffer[5] = 0;
    mbox_buffer[6] = 0;
    mbox_buffer[7] = 0;

    if (rpi_mbox_call(MBOX_CHANNEL_PROP))
        return ((uint64_t)mbox_buffer[6] << 32) | mbox_buffer[5];
    return 0;
}

/**
 * rpi_mbox_get_arm_memory() — Get ARM-accessible memory base and size.
 */
void rpi_mbox_get_arm_memory(uint32_t *base, uint32_t *size) {
    mbox_buffer[0] = 8 * 4;
    mbox_buffer[1] = 0;
    mbox_buffer[2] = TAG_GET_ARM_MEMORY;
    mbox_buffer[3] = 8;
    mbox_buffer[4] = 0;
    mbox_buffer[5] = 0;
    mbox_buffer[6] = 0;
    mbox_buffer[7] = 0;

    if (rpi_mbox_call(MBOX_CHANNEL_PROP)) {
        if (base) *base = mbox_buffer[5];
        if (size) *size = mbox_buffer[6];
    }
}

/**
 * rpi_mbox_get_clock_rate() — Get current clock rate for a clock ID.
 */
uint32_t rpi_mbox_get_clock_rate(uint32_t clock_id) {
    mbox_buffer[0] = 8 * 4;
    mbox_buffer[1] = 0;
    mbox_buffer[2] = TAG_GET_CLOCK_RATE;
    mbox_buffer[3] = 8;
    mbox_buffer[4] = 0;
    mbox_buffer[5] = clock_id;
    mbox_buffer[6] = 0;
    mbox_buffer[7] = 0;

    if (rpi_mbox_call(MBOX_CHANNEL_PROP))
        return mbox_buffer[6];
    return 0;
}

/**
 * rpi_mbox_set_clock_rate() — Set clock rate for a clock ID.
 */
uint32_t rpi_mbox_set_clock_rate(uint32_t clock_id, uint32_t rate_hz) {
    mbox_buffer[0] = 9 * 4;
    mbox_buffer[1] = 0;
    mbox_buffer[2] = TAG_SET_CLOCK_RATE;
    mbox_buffer[3] = 12;
    mbox_buffer[4] = 0;
    mbox_buffer[5] = clock_id;
    mbox_buffer[6] = rate_hz;
    mbox_buffer[7] = 0;    /* Skip setting turbo */
    mbox_buffer[8] = 0;

    if (rpi_mbox_call(MBOX_CHANNEL_PROP))
        return mbox_buffer[6];
    return 0;
}

/**
 * rpi_mbox_set_power_state() — Enable/disable a power domain.
 */
bool rpi_mbox_set_power_state(uint32_t device_id, bool on) {
    mbox_buffer[0] = 8 * 4;
    mbox_buffer[1] = 0;
    mbox_buffer[2] = TAG_SET_POWER_STATE;
    mbox_buffer[3] = 8;
    mbox_buffer[4] = 0;
    mbox_buffer[5] = device_id;
    mbox_buffer[6] = on ? 3 : 0;   /* bit 0 = on, bit 1 = wait */
    mbox_buffer[7] = 0;

    if (rpi_mbox_call(MBOX_CHANNEL_PROP))
        return (mbox_buffer[6] & 0x3) == (on ? 1 : 0);
    return false;
}

/**
 * rpi_mbox_get_temperature() — Get SoC temperature in millidegrees C.
 */
uint32_t rpi_mbox_get_temperature(void) {
    mbox_buffer[0] = 8 * 4;
    mbox_buffer[1] = 0;
    mbox_buffer[2] = TAG_GET_TEMPERATURE;
    mbox_buffer[3] = 8;
    mbox_buffer[4] = 0;
    mbox_buffer[5] = 0;    /* Temperature ID (0 = SoC) */
    mbox_buffer[6] = 0;
    mbox_buffer[7] = 0;

    if (rpi_mbox_call(MBOX_CHANNEL_PROP))
        return mbox_buffer[6];  /* Temperature in milli-degrees C */
    return 0;
}

/**
 * rpi_mbox_alloc_framebuffer() — Allocate GPU framebuffer.
 * @width, @height: Requested resolution
 * @depth: Bits per pixel (16, 24, or 32)
 * @fb_addr: Output — physical address of framebuffer
 * @fb_size: Output — size of framebuffer in bytes
 * @pitch: Output — bytes per row
 * Returns: true on success
 */
bool rpi_mbox_alloc_framebuffer(uint32_t width, uint32_t height, uint32_t depth,
                                 uint32_t *fb_addr, uint32_t *fb_size, uint32_t *pitch) {
    /* Build multi-tag request */
    int i = 0;
    mbox_buffer[i++] = 0;  /* Total size (filled at end) */
    mbox_buffer[i++] = 0;  /* Request */

    /* Set physical size */
    mbox_buffer[i++] = TAG_SET_PHYSICAL_SIZE;
    mbox_buffer[i++] = 8;
    mbox_buffer[i++] = 0;
    mbox_buffer[i++] = width;
    mbox_buffer[i++] = height;

    /* Set virtual size (same as physical, no scrolling) */
    mbox_buffer[i++] = TAG_SET_VIRTUAL_SIZE;
    mbox_buffer[i++] = 8;
    mbox_buffer[i++] = 0;
    mbox_buffer[i++] = width;
    mbox_buffer[i++] = height;

    /* Set virtual offset (0,0) */
    mbox_buffer[i++] = TAG_SET_VIRTUAL_OFFSET;
    mbox_buffer[i++] = 8;
    mbox_buffer[i++] = 0;
    mbox_buffer[i++] = 0;
    mbox_buffer[i++] = 0;

    /* Set depth */
    mbox_buffer[i++] = TAG_SET_DEPTH;
    mbox_buffer[i++] = 4;
    mbox_buffer[i++] = 0;
    mbox_buffer[i++] = depth;

    /* Set pixel order (0 = BGR, 1 = RGB) */
    mbox_buffer[i++] = TAG_SET_PIXEL_ORDER;
    mbox_buffer[i++] = 4;
    mbox_buffer[i++] = 0;
    mbox_buffer[i++] = 1;  /* RGB */

    /* Allocate buffer */
    mbox_buffer[i++] = TAG_ALLOCATE_BUFFER;
    mbox_buffer[i++] = 8;
    mbox_buffer[i++] = 0;
    mbox_buffer[i++] = 4096;   /* Alignment */
    mbox_buffer[i++] = 0;

    /* Get pitch */
    mbox_buffer[i++] = TAG_GET_PITCH;
    mbox_buffer[i++] = 4;
    mbox_buffer[i++] = 0;
    mbox_buffer[i++] = 0;

    /* End tag */
    mbox_buffer[i++] = 0;

    /* Set total buffer size */
    mbox_buffer[0] = (uint32_t)(i * 4);

    if (!rpi_mbox_call(MBOX_CHANNEL_PROP))
        return false;

    /* Extract results — walk buffer looking for tag responses */
    /* Allocate buffer response is at a known offset based on our layout */
    /* Tags: phys_size(7), virt_size(7), virt_offset(7), depth(5), pixel_order(5), alloc_buf(7), pitch(5) */
    int alloc_idx = 2 + 5 + 5 + 5 + 3 + 3 + 2; /* = 25 */
    int pitch_idx = alloc_idx + 5; /* = 30 */

    if (fb_addr) *fb_addr = mbox_buffer[alloc_idx + 3] & 0x3FFFFFFF; /* Mask bus address bits */
    if (fb_size) *fb_size = mbox_buffer[alloc_idx + 4];
    if (pitch)   *pitch   = mbox_buffer[pitch_idx + 3];

    return true;
}
