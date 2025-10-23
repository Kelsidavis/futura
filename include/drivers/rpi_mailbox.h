/*
 * Broadcom Mailbox Protocol for Raspberry Pi GPU Communication
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * This header defines the mailbox protocol used for communication between
 * the ARM CPU and VideoCore GPU on Raspberry Pi platforms.
 *
 * References:
 * - https://github.com/raspberrypi/firmware/wiki/Mailboxes
 * - https://github.com/raspberrypi/firmware/wiki/Mailbox-property-interface
 */

#ifndef __FUTURA_DRIVERS_RPI_MAILBOX_H__
#define __FUTURA_DRIVERS_RPI_MAILBOX_H__

#include <stdint.h>
#include <stddef.h>

/* ============================================================
 *   Mailbox Hardware Addresses
 * ============================================================
 *
 * Physical addresses for mailbox registers on Raspberry Pi
 * (offset from BCM2835/BCM2711 peripheral base address)
 */

/* Mailbox base addresses (relative to BCM base) */
#define MBOX_BASE_OFFSET 0xB880
#define MBOX_ARM_TO_VC 1        /* ARM writes to VC, VC reads */
#define MBOX_VC_TO_ARM 0        /* VC writes to ARM, ARM reads */

/* ============================================================
 *   Mailbox Register Offsets
 * ============================================================ */

#define MBOX_READ(mb)      ((mb) * 0x20 + 0x00)
#define MBOX_WRITE(mb)     ((mb) * 0x20 + 0x04)
#define MBOX_PEEK(mb)      ((mb) * 0x20 + 0x10)
#define MBOX_SENDER(mb)    ((mb) * 0x20 + 0x14)
#define MBOX_STATUS(mb)    ((mb) * 0x20 + 0x18)
#define MBOX_CONFIG(mb)    ((mb) * 0x20 + 0x1C)

/* Status register bits */
#define MBOX_STATUS_EMPTY  0x40000000
#define MBOX_STATUS_FULL   0x80000000

/* ============================================================
 *   Mailbox Channels
 * ============================================================
 *
 * Each mailbox supports multiple channels for different functions.
 * The channel is encoded in the lower 4 bits of the message.
 */

#define MBOX_CHANNEL_POWER      0   /* Power management */
#define MBOX_CHANNEL_FB         1   /* Framebuffer */
#define MBOX_CHANNEL_VCHIQ      3   /* VCHIQ interface */
#define MBOX_CHANNEL_LEDS       4   /* LED control */
#define MBOX_CHANNEL_BUTTONS    5   /* Button input */
#define MBOX_CHANNEL_TOUCH      6   /* Touchscreen */
#define MBOX_CHANNEL_COUNT      7   /* Property tags (main interface) */
#define MBOX_CHANNEL_GPU_MEM    8   /* GPU memory access */
#define MBOX_CHANNEL_EXCEPTION  9   /* Exception handling */

/* ============================================================
 *   Property Tags Interface (Channel 8)
 * ============================================================
 *
 * The property tags interface is the primary way to communicate with
 * the GPU firmware for device configuration.
 *
 * Message format:
 * - u32: total message size (including this field)
 * - u32: request/response code (0x00000000 = request, 0x80000000 = response)
 * - [tags...]
 * - u32: 0 (end tag)
 */

#define MBOX_REQUEST_CODE       0x00000000
#define MBOX_RESPONSE_CODE      0x80000000
#define MBOX_TAG_END            0x00000000

/* Property tag structure
 *
 * Each tag format:
 * - u32: tag ID
 * - u32: value buffer size (in bytes)
 * - u32: request/response size (in bytes)
 * - [value data...]
 */

/* Common property tags */
#define MBOX_TAG_GET_BOARD_REVISION     0x00010002
#define MBOX_TAG_GET_BOARD_SERIAL       0x00010004
#define MBOX_TAG_GET_ARM_MEMORY         0x00010005
#define MBOX_TAG_GET_VC_MEMORY          0x00010006
#define MBOX_TAG_GET_CLOCKS             0x00010007
#define MBOX_TAG_GET_POWER_STATE        0x00020001
#define MBOX_TAG_SET_POWER_STATE        0x00028001
#define MBOX_TAG_GET_CLOCK_RATE         0x00030002
#define MBOX_TAG_SET_CLOCK_RATE         0x00038002
#define MBOX_TAG_GET_MAX_CLOCK_RATE     0x00030004
#define MBOX_TAG_GET_MIN_CLOCK_RATE     0x00030007
#define MBOX_TAG_GET_TEMPERATURE        0x00030006
#define MBOX_TAG_GET_MAX_TEMPERATURE    0x0003000A
#define MBOX_TAG_GET_EDID_BLOCK         0x00030020

/* Framebuffer tags */
#define MBOX_TAG_ALLOCATE_FRAMEBUFFER   0x00040001
#define MBOX_TAG_BLANK_FRAMEBUFFER      0x00040002
#define MBOX_TAG_GET_PHYSICAL_SIZE      0x00040003
#define MBOX_TAG_TEST_PHYSICAL_SIZE     0x00044003
#define MBOX_TAG_SET_PHYSICAL_SIZE      0x00048003
#define MBOX_TAG_GET_VIRTUAL_SIZE       0x00040004
#define MBOX_TAG_TEST_VIRTUAL_SIZE      0x00044004
#define MBOX_TAG_SET_VIRTUAL_SIZE       0x00048004
#define MBOX_TAG_GET_DEPTH              0x00040005
#define MBOX_TAG_TEST_DEPTH             0x00044005
#define MBOX_TAG_SET_DEPTH              0x00048005
#define MBOX_TAG_GET_PIXEL_ORDER        0x00040006
#define MBOX_TAG_TEST_PIXEL_ORDER       0x00044006
#define MBOX_TAG_SET_PIXEL_ORDER        0x00048006
#define MBOX_TAG_GET_ALPHA_MODE         0x00040007
#define MBOX_TAG_TEST_ALPHA_MODE        0x00044007
#define MBOX_TAG_SET_ALPHA_MODE         0x00048007
#define MBOX_TAG_GET_PITCH              0x00040008
#define MBOX_TAG_GET_OFFSET             0x00040009
#define MBOX_TAG_SET_OFFSET             0x00048009

/* Power domain IDs (for MBOX_TAG_SET_POWER_STATE) */
#define MBOX_POWER_DOMAIN_UART          0
#define MBOX_POWER_DOMAIN_USB           3
#define MBOX_POWER_DOMAIN_HVS           1
#define MBOX_POWER_DOMAIN_HDMI          2
#define MBOX_POWER_DOMAIN_VPU           4
#define MBOX_POWER_DOMAIN_SDRAM_C       5
#define MBOX_POWER_DOMAIN_SDRAM_I       6
#define MBOX_POWER_DOMAIN_SDRAM_P       7
#define MBOX_POWER_DOMAIN_GPU           8

/* Clock IDs (for MBOX_TAG_GET_CLOCK_RATE, etc.) */
#define MBOX_CLOCK_EMMC                 1
#define MBOX_CLOCK_UART                 2
#define MBOX_CLOCK_ARM                  3
#define MBOX_CLOCK_CORE                 4
#define MBOX_CLOCK_V3D                  5
#define MBOX_CLOCK_H264                 6
#define MBOX_CLOCK_ISP                  7
#define MBOX_CLOCK_SDRAM                8
#define MBOX_CLOCK_PIXEL                9
#define MBOX_CLOCK_PWM                  10
#define MBOX_CLOCK_HEVC                 11
#define MBOX_CLOCK_EMMC2                12
#define MBOX_CLOCK_M2MC                 13
#define MBOX_CLOCK_PIXEL_BVB            14

/* Pixel formats for framebuffer */
#define MBOX_PIXEL_RGB565               0
#define MBOX_PIXEL_RGB888               1
#define MBOX_PIXEL_RGBA8888             2
#define MBOX_PIXEL_RGBX8888             3

/* Pixel order */
#define MBOX_PIXEL_ORDER_BGR            0
#define MBOX_PIXEL_ORDER_RGB            1

/* ============================================================
 *   Mailbox Message Structures
 * ============================================================ */

/* Basic mailbox message header */
typedef struct {
    uint32_t size;          /* Total message size including this field */
    uint32_t code;          /* Request/response code */
    /* followed by tags and end marker */
} mbox_message_t;

/* Property tag header */
typedef struct {
    uint32_t tag_id;
    uint32_t value_size;
    uint32_t value_length;
    /* followed by value buffer */
} mbox_tag_t;

/* Framebuffer allocation response structure */
typedef struct {
    uint32_t fb_address;    /* Physical address of framebuffer (in VC address space) */
    uint32_t fb_size;       /* Size of framebuffer in bytes */
} mbox_fb_allocate_response_t;

/* ============================================================
 *   DMA Memory Allocation (CMA - Contiguous Memory Allocator)
 * ============================================================
 *
 * The GPU requires contiguous memory blocks for DMA operations.
 * These are allocated via the mailbox interface.
 */

/* CMA allocation flags */
#define MBOX_MEM_FLAG_DIRECT            (1 << 2)    /* Allocate from direct area */
#define MBOX_MEM_FLAG_COHERENT          (1 << 3)    /* Cache coherent memory */
#define MBOX_MEM_FLAG_L1_NONALLOCATING  (1 << 5)    /* L1 cache non-allocating */
#define MBOX_MEM_FLAG_ZERO              (1 << 4)    /* Pre-zero memory */

/* VC memory address space
 *
 * VideoCore uses a different physical address space:
 * - 0xC0000000 - 0xDFFFFFFF: L2 cached ARM access (0x00000000-0x1FFFFFFF maps to here)
 * - 0x40000000 - 0x7FFFFFFF: Uncached ARM access to VC memory
 * - 0x00000000 - 0x3FFFFFFF: VC direct access to SDRAM
 *
 * To convert ARM physical address to VC address: add 0x40000000 if uncached,
 * or use 0xC0000000 base for cached access.
 */

#define VC_MEM_ARM_TO_VC_UNCACHED(addr)  ((addr) | 0x40000000)
#define VC_MEM_ARM_TO_VC_CACHED(addr)    (0xC0000000 + ((addr) & 0x1FFFFFFF))
#define VC_MEM_VC_TO_ARM(addr)           ((addr) & 0x3FFFFFFF)

/* ============================================================
 *   Mailbox Driver Interface
 * ============================================================ */

/* Function declarations for mailbox driver implementation */

/* Initialize mailbox interface */
void mailbox_init(uint64_t mbox_base);

/* Send message to GPU and wait for response */
int mailbox_property_call(uint32_t *buffer);

/* Raw mailbox operations */
void mailbox_write(int mbox, uint32_t value);
uint32_t mailbox_read(int mbox);

/* Utility functions */
uint32_t mailbox_get_board_revision(void);
uint32_t mailbox_get_arm_memory(void);
uint32_t mailbox_get_vc_memory(void);
int mailbox_set_power_state(uint32_t domain, uint32_t state);
int mailbox_get_clock_rate(uint32_t clock, uint32_t *rate);
int mailbox_set_clock_rate(uint32_t clock, uint32_t rate);

#endif /* __FUTURA_DRIVERS_RPI_MAILBOX_H__ */
