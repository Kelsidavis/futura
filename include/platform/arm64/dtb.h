/* dtb.h - Device Tree Blob Parsing for ARM64 RPi
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Device tree blob (DTB) parsing for Raspberry Pi support.
 */

#ifndef __FUTURA_ARM64_DTB_H__
#define __FUTURA_ARM64_DTB_H__

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* ============================================================
 *   DTB Header Structures
 * ============================================================ */

typedef struct {
    uint32_t magic;          /* Must be 0xd00dfeed */
    uint32_t totalsize;      /* Total size of DTB in bytes */
    uint32_t off_dt_struct;  /* Offset to struct block */
    uint32_t off_dt_strings; /* Offset to strings block */
    uint32_t off_mem_rsvmap; /* Offset to memory reservation block */
    uint32_t version;        /* DTB version */
    uint32_t last_comp_version; /* Last compatible version */
    uint32_t boot_cpuid_phys; /* Boot CPU physical ID */
    uint32_t size_dt_strings; /* Size of strings block */
    uint32_t size_dt_struct;  /* Size of struct block */
} dtb_header_t;

/* Device tree node property */
typedef struct {
    uint32_t len;        /* Property value length */
    uint32_t nameoff;    /* Offset into string block */
} dtb_prop_t;

/* DTB Token Types */
#define FDT_BEGIN_NODE    0x00000001
#define FDT_END_NODE      0x00000002
#define FDT_PROP          0x00000003
#define FDT_NOP           0x00000004
#define FDT_END           0x00000009

/* ============================================================
 *   Platform Detection
 * ============================================================ */

typedef enum {
    PLATFORM_UNKNOWN = 0,
    PLATFORM_RPI3 = 1,
    PLATFORM_RPI4 = 2,
    PLATFORM_RPI5 = 3,
    PLATFORM_QEMU_VIRT = 4
} fut_platform_type_t;

typedef struct {
    fut_platform_type_t type;
    const char *name;
    uint32_t cpu_freq;           /* CNTFRQ value */
    uint64_t uart_base;          /* UART0 base address */
    uint64_t gpio_base;          /* GPIO base address */
    uint64_t gic_dist_base;      /* GIC distributor base (or 0 if N/A) */
    uint64_t gic_cpu_base;       /* GIC CPU interface base (or 0 if N/A) */
    bool has_gic;                /* Has GICv2 support */
    bool has_generic_timer;      /* Has ARM generic timer */
    uint32_t total_memory;       /* Total RAM in bytes */
} fut_platform_info_t;

/* ============================================================
 *   DTB Parsing Functions
 * ============================================================ */

/**
 * Parse DTB and extract platform information.
 * @param dtb_ptr: Physical address of DTB (passed in X0 at boot)
 * @return: Platform information structure
 */
fut_platform_info_t fut_dtb_parse(uint64_t dtb_ptr);

/**
 * Detect platform type from DTB compatible property.
 * @param dtb_ptr: Physical address of DTB
 * @return: Detected platform type
 */
fut_platform_type_t fut_dtb_detect_platform(uint64_t dtb_ptr);

/**
 * Get property value from DTB node.
 * @param dtb_ptr: Physical address of DTB
 * @param node_name: Full path to node (e.g., "/soc/serial@fe201000")
 * @param prop_name: Property name (e.g., "reg", "compatible")
 * @param value_out: Pointer to output buffer
 * @param max_len: Maximum length to read
 * @return: Actual property length, or 0 if not found
 */
size_t fut_dtb_get_property(uint64_t dtb_ptr, const char *node_name,
                            const char *prop_name, void *value_out, size_t max_len);

/**
 * Get string property value.
 * @param dtb_ptr: Physical address of DTB
 * @param node_name: Full path to node
 * @param prop_name: Property name
 * @param str_out: Pointer to string output buffer
 * @param max_len: Maximum string length
 * @return: Actual string length, or 0 if not found
 */
size_t fut_dtb_get_string_property(uint64_t dtb_ptr, const char *node_name,
                                   const char *prop_name, char *str_out, size_t max_len);

/**
 * Get 32-bit integer property.
 * @param dtb_ptr: Physical address of DTB
 * @param node_name: Full path to node
 * @param prop_name: Property name
 * @param value_out: Pointer to uint32_t output
 * @return: true if found, false otherwise
 */
bool fut_dtb_get_u32_property(uint64_t dtb_ptr, const char *node_name,
                              const char *prop_name, uint32_t *value_out);

/**
 * Get 64-bit integer property.
 * @param dtb_ptr: Physical address of DTB
 * @param node_name: Full path to node
 * @param prop_name: Property name
 * @param value_out: Pointer to uint64_t output
 * @return: true if found, false otherwise
 */
bool fut_dtb_get_u64_property(uint64_t dtb_ptr, const char *node_name,
                              const char *prop_name, uint64_t *value_out);

/**
 * Get memory size from device tree.
 * @param dtb_ptr: Physical address of DTB
 * @return: Total RAM size in bytes
 */
uint64_t fut_dtb_get_memory_size(uint64_t dtb_ptr);

/**
 * Validate DTB header.
 * @param dtb_ptr: Physical address of DTB
 * @return: true if valid, false otherwise
 */
bool fut_dtb_validate(uint64_t dtb_ptr);

/* ============================================================
 *   Platform-Specific Initialization
 * ============================================================ */

/**
 * Initialize platform based on detected type.
 * @param info: Platform information
 */
void fut_platform_init_rpi(const fut_platform_info_t *info);

/**
 * Initialize UART for the platform.
 * @param info: Platform information
 */
void fut_platform_uart_init(const fut_platform_info_t *info);

/**
 * Initialize GIC or legacy interrupt controller.
 * @param info: Platform information
 */
void fut_platform_irq_init(const fut_platform_info_t *info);

/**
 * Set up timer for the platform.
 * @param info: Platform information
 */
void fut_platform_timer_init(const fut_platform_info_t *info);

#endif /* __FUTURA_ARM64_DTB_H__ */
