/* arm64_dtb.c - Device Tree Blob Parsing for ARM64 RPi
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Parses device tree blobs passed by bootloader for RPi3/4/5.
 */

#include <arch/arm64/dtb.h>
#include <string.h>
#include <platform/platform.h>

/* ============================================================
 *   DTB Validation
 * ============================================================ */

bool fut_dtb_validate(uint64_t dtb_ptr) {
    if (!dtb_ptr) {
        return false;
    }

    dtb_header_t *header = (dtb_header_t *)dtb_ptr;

    /* Validate magic number (big-endian) */
    if (header->magic != 0xd00dfeed) {
        return false;
    }

    /* Validate version is reasonable */
    if (header->version < 1 || header->version > 17) {
        return false;
    }

    /* Validate offsets are within bounds */
    if (header->off_dt_struct >= header->totalsize ||
        header->off_dt_strings >= header->totalsize) {
        return false;
    }

    return true;
}

/* ============================================================
 *   Helper Functions for DTB Traversal
 * ============================================================ */

/**
 * Read big-endian 32-bit value.
 */
static inline uint32_t be32_to_cpu(uint32_t value) {
    return ((value & 0xFF000000) >> 24) |
           ((value & 0x00FF0000) >> 8) |
           ((value & 0x0000FF00) << 8) |
           ((value & 0x000000FF) << 24);
}

/**
 * Read big-endian 64-bit value.
 */
static inline uint64_t be64_to_cpu(uint64_t value) {
    return ((value & 0xFF00000000000000ULL) >> 56) |
           ((value & 0x00FF000000000000ULL) >> 40) |
           ((value & 0x0000FF0000000000ULL) >> 24) |
           ((value & 0x000000FF00000000ULL) >> 8) |
           ((value & 0x00000000FF000000ULL) << 8) |
           ((value & 0x0000000000FF0000ULL) << 24) |
           ((value & 0x000000000000FF00ULL) << 40) |
           ((value & 0x00000000000000FFULL) << 56);
}

/**
 * Align offset to 4-byte boundary.
 */
static inline size_t align_offset(size_t offset) {
    return (offset + 3) & ~3;
}

/* ============================================================
 *   Platform Detection
 * ============================================================ */

fut_platform_type_t fut_dtb_detect_platform(uint64_t dtb_ptr) {
    if (!fut_dtb_validate(dtb_ptr)) {
        return PLATFORM_UNKNOWN;
    }

    /* Try to read compatible property from /node */
    char compatible[256] = {0};
    size_t len = fut_dtb_get_string_property(dtb_ptr, "", "compatible",
                                             compatible, sizeof(compatible) - 1);

    if (len == 0) {
        /* Try root node compatible */
        dtb_header_t *header = (dtb_header_t *)dtb_ptr;
        uint32_t *struct_ptr = (uint32_t *)(dtb_ptr + be32_to_cpu(header->off_dt_struct));

        /* Skip to first property of root node */
        if (be32_to_cpu(struct_ptr[0]) == FDT_BEGIN_NODE) {
            /* Look for compatible in root */
            uint32_t *prop_ptr = struct_ptr + 2; /* Skip token and node name length */

            while (be32_to_cpu(prop_ptr[0]) == FDT_PROP) {
                dtb_prop_t *prop = (dtb_prop_t *)&prop_ptr[1];
                uint32_t prop_len = be32_to_cpu(prop->len);
                uint32_t name_off = be32_to_cpu(prop->nameoff);

                char *strings_base = (char *)(dtb_ptr + be32_to_cpu(header->off_dt_strings));
                const char *prop_name = strings_base + name_off;

                if (strcmp(prop_name, "compatible") == 0 && prop_len < sizeof(compatible)) {
                    memcpy(compatible, &prop[1], prop_len);
                    compatible[prop_len] = '\0';
                    break;
                }

                /* Move to next property */
                uint32_t skip = sizeof(dtb_prop_t) + prop_len;
                prop_ptr = (uint32_t *)((char *)prop_ptr + skip);
                prop_ptr = (uint32_t *)align_offset((size_t)prop_ptr);
            }
        }
    }

    /* Detect platform from compatible string */
    if (strstr(compatible, "raspberrypi,3-model-b") != NULL) {
        return PLATFORM_RPI3;
    }
    if (strstr(compatible, "raspberrypi,4-model-b") != NULL) {
        return PLATFORM_RPI4;
    }
    if (strstr(compatible, "raspberrypi,5-model-b") != NULL) {
        return PLATFORM_RPI5;
    }
    if (strstr(compatible, "qemu,virt") != NULL) {
        return PLATFORM_QEMU_VIRT;
    }

    return PLATFORM_UNKNOWN;
}

/* ============================================================
 *   Property Extraction
 * ============================================================ */

size_t fut_dtb_get_property(uint64_t dtb_ptr, const char *node_name __attribute__((unused)),
                            const char *prop_name, void *value_out, size_t max_len) {
    if (!fut_dtb_validate(dtb_ptr) || !prop_name || !value_out) {
        return 0;
    }

    /* Simplified implementation: search through all nodes */
    dtb_header_t *header = (dtb_header_t *)dtb_ptr;
    char *strings_base = (char *)(dtb_ptr + be32_to_cpu(header->off_dt_strings));
    uint32_t *struct_ptr = (uint32_t *)(dtb_ptr + be32_to_cpu(header->off_dt_struct));

    /* Skip to end of root node and look for properties */
    uint32_t *p = struct_ptr;

    while (be32_to_cpu(p[0]) != FDT_END) {
        uint32_t token = be32_to_cpu(p[0]);

        if (token == FDT_PROP) {
            dtb_prop_t *prop = (dtb_prop_t *)&p[1];
            uint32_t prop_len = be32_to_cpu(prop->len);
            uint32_t name_off = be32_to_cpu(prop->nameoff);
            const char *name = strings_base + name_off;

            if (strcmp(name, prop_name) == 0) {
                size_t copy_len = (prop_len < max_len) ? prop_len : max_len;
                memcpy(value_out, &prop[1], copy_len);
                return prop_len;
            }

            /* Move to next entry */
            p = (uint32_t *)((char *)p + sizeof(uint32_t) + sizeof(dtb_prop_t) + prop_len);
            p = (uint32_t *)align_offset((size_t)p);
        } else if (token == FDT_BEGIN_NODE || token == FDT_END_NODE || token == FDT_NOP) {
            p += 1;
        } else {
            break;
        }
    }

    return 0;
}

size_t fut_dtb_get_string_property(uint64_t dtb_ptr, const char *node_name,
                                   const char *prop_name, char *str_out, size_t max_len) {
    char buffer[256];
    size_t len = fut_dtb_get_property(dtb_ptr, node_name, prop_name, buffer, sizeof(buffer));

    if (len == 0) {
        if (max_len > 0) str_out[0] = '\0';
        return 0;
    }

    size_t copy_len = (len < max_len) ? len : (max_len - 1);
    memcpy(str_out, buffer, copy_len);
    if (max_len > 0) {
        str_out[copy_len] = '\0';
    }

    return len;
}

bool fut_dtb_get_u32_property(uint64_t dtb_ptr, const char *node_name,
                              const char *prop_name, uint32_t *value_out) {
    uint32_t value;
    size_t len = fut_dtb_get_property(dtb_ptr, node_name, prop_name, &value, sizeof(uint32_t));

    if (len < sizeof(uint32_t)) {
        return false;
    }

    *value_out = be32_to_cpu(value);
    return true;
}

bool fut_dtb_get_u64_property(uint64_t dtb_ptr, const char *node_name,
                              const char *prop_name, uint64_t *value_out) {
    uint64_t value;
    size_t len = fut_dtb_get_property(dtb_ptr, node_name, prop_name, &value, sizeof(uint64_t));

    if (len < sizeof(uint64_t)) {
        return false;
    }

    *value_out = be64_to_cpu(value);
    return true;
}

/* ============================================================
 *   Memory and Platform Info
 * ============================================================ */

uint64_t fut_dtb_get_memory_size(uint64_t dtb_ptr) {
    if (!fut_dtb_validate(dtb_ptr)) {
        return 0;
    }

    /* For now, return a reasonable default based on platform */
    fut_platform_type_t platform = fut_dtb_detect_platform(dtb_ptr);

    switch (platform) {
        case PLATFORM_RPI3:
            return 1024ULL * 1024 * 1024;  /* 1GB */
        case PLATFORM_RPI4:
            return 2ULL * 1024 * 1024 * 1024;  /* 2GB (could be more) */
        case PLATFORM_RPI5:
            return 4ULL * 1024 * 1024 * 1024;  /* 4GB (could be more) */
        default:
            return 2ULL * 1024 * 1024 * 1024;  /* Default 2GB */
    }
}

fut_platform_info_t fut_dtb_parse(uint64_t dtb_ptr) {
    fut_platform_info_t info = {
        .type = PLATFORM_UNKNOWN,
        .name = "Unknown",
        .cpu_freq = 1000000,  /* Default 1MHz */
        .uart_base = 0,
        .gpio_base = 0,
        .gic_dist_base = 0,
        .gic_cpu_base = 0,
        .has_gic = false,
        .has_generic_timer = false,
        .total_memory = 2ULL * 1024 * 1024 * 1024
    };

    if (!fut_dtb_validate(dtb_ptr)) {
        return info;
    }

    info.type = fut_dtb_detect_platform(dtb_ptr);
    info.total_memory = fut_dtb_get_memory_size(dtb_ptr);

    /* Set platform-specific values */
    switch (info.type) {
        case PLATFORM_RPI3:
            info.name = "Raspberry Pi 3";
            info.cpu_freq = 19200000;  /* 19.2 MHz */
            info.uart_base = 0x3F201000;  /* PL011 UART0 */
            info.gpio_base = 0x3F200000;
            info.has_gic = false;
            info.has_generic_timer = false;  /* RPi3 uses system timer */
            break;

        case PLATFORM_RPI4:
            info.name = "Raspberry Pi 4";
            info.cpu_freq = 54000000;  /* 54 MHz */
            info.uart_base = 0xFE201000;  /* PL011 UART0 */
            info.gpio_base = 0xFE200000;
            info.gic_dist_base = 0xFF841000;  /* GICv2 */
            info.gic_cpu_base = 0xFF842000;
            info.has_gic = true;
            info.has_generic_timer = true;
            break;

        case PLATFORM_RPI5:
            info.name = "Raspberry Pi 5";
            info.cpu_freq = 54000000;  /* 54 MHz */
            info.uart_base = 0xFE201000;  /* PL011 UART0 */
            info.gpio_base = 0xFE200000;
            info.gic_dist_base = 0xFF841000;  /* GICv2 */
            info.gic_cpu_base = 0xFF842000;
            info.has_gic = true;
            info.has_generic_timer = true;
            break;

        case PLATFORM_QEMU_VIRT:
            info.name = "QEMU virt (ARM64)";
            info.cpu_freq = 62500000;  /* QEMU default */
            info.uart_base = 0x09000000;  /* PL011 @ virt offset */
            info.gpio_base = 0;
            info.gic_dist_base = 0x08000000;
            info.gic_cpu_base = 0x08010000;
            info.has_gic = true;
            info.has_generic_timer = true;
            break;

        default:
            break;
    }

    return info;
}

/* ============================================================
 *   Platform Initialization Stubs
 * ============================================================ */

void fut_platform_init_rpi(const fut_platform_info_t *info) {
    if (!info) return;

    fut_printf("[INIT] Detected platform: %s\n", info->name);
    fut_printf("[INIT] CPU Frequency: %u MHz\n", info->cpu_freq / 1000000);
    fut_printf("[INIT] UART Base: 0x%016llx\n", info->uart_base);
    fut_printf("[INIT] GPIO Base: 0x%016llx\n", info->gpio_base);

    if (info->has_gic) {
        fut_printf("[INIT] GIC Distributor: 0x%016llx\n", info->gic_dist_base);
        fut_printf("[INIT] GIC CPU Interface: 0x%016llx\n", info->gic_cpu_base);
    }
}

void fut_platform_uart_init(const fut_platform_info_t *info) {
    if (!info || !info->uart_base) return;

    fut_printf("[INIT] Initializing UART at 0x%016llx\n", info->uart_base);
    /* UART initialization will be implemented in UART driver */
}

void fut_platform_irq_init(const fut_platform_info_t *info) {
    if (!info) return;

    if (info->has_gic) {
        fut_printf("[INIT] Initializing GICv2...\n");
        /* GIC init already called, but could add RPi-specific setup */
    } else {
        fut_printf("[INIT] Using legacy interrupt controller\n");
        /* RPi3 legacy interrupt setup would go here */
    }
}

void fut_platform_timer_init(const fut_platform_info_t *info) {
    if (!info) return;

    if (info->has_generic_timer) {
        fut_printf("[INIT] Using ARM Generic Timer (CNTFRQ=%u MHz)\n",
                   info->cpu_freq / 1000000);
    } else {
        fut_printf("[INIT] Using System Timer\n");
        /* RPi3 system timer setup would go here */
    }
}
