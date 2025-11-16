/* arm64_dtb.c - Device Tree Blob Parsing for ARM64 RPi
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Parses device tree blobs passed by bootloader for RPi3/4/5.
 */

#include <platform/arm64/dtb.h>
#include <string.h>
#include <platform/platform.h>

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
 *   DTB Validation
 * ============================================================ */

bool fut_dtb_validate(uint64_t dtb_ptr) {
    if (!dtb_ptr) {
        fut_printf("[DTB] Validation failed: NULL pointer\n");
        return false;
    }

    dtb_header_t *header = (dtb_header_t *)dtb_ptr;

    /* Validate magic number (big-endian) */
    uint32_t magic = be32_to_cpu(header->magic);
    if (magic != 0xd00dfeed) {
        fut_printf("[DTB] Validation failed: bad magic 0x%08x (expected 0xd00dfeed)\n", magic);
        return false;
    }

    /* Validate version is reasonable */
    uint32_t version = be32_to_cpu(header->version);
    if (version < 1 || version > 17) {
        fut_printf("[DTB] Validation failed: bad version %u\n", version);
        return false;
    }

    /* Validate offsets are within bounds */
    uint32_t off_dt_struct = be32_to_cpu(header->off_dt_struct);
    uint32_t off_dt_strings = be32_to_cpu(header->off_dt_strings);
    uint32_t totalsize = be32_to_cpu(header->totalsize);
    if (off_dt_struct >= totalsize || off_dt_strings >= totalsize) {
        fut_printf("[DTB] Validation failed: bad offsets (struct=%u strings=%u total=%u)\n",
                   off_dt_struct, off_dt_strings, totalsize);
        return false;
    }

    fut_printf("[DTB] Validation passed! (magic=0x%08x version=%u size=%u)\n",
               magic, version, totalsize);
    return true;
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

    /* Apple Silicon detection */
    if (strstr(compatible, "apple,t8103") != NULL || /* M1 */
        strstr(compatible, "apple,j274") != NULL) {   /* Mac mini M1 */
        return PLATFORM_APPLE_M1;
    }
    if (strstr(compatible, "apple,t8112") != NULL || /* M2 */
        strstr(compatible, "apple,j413") != NULL ||   /* MacBook Air M2 */
        strstr(compatible, "apple,j493") != NULL) {   /* MacBook Pro 13" M2 (A2338) */
        return PLATFORM_APPLE_M2;
    }
    if (strstr(compatible, "apple,t8103") != NULL) { /* M3 */
        return PLATFORM_APPLE_M3;
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

bool fut_dtb_get_reg(uint64_t dtb_ptr, const char *node_name,
                     uint64_t *base_out, uint64_t *size_out) {
    if (!fut_dtb_validate(dtb_ptr) || !base_out) {
        return false;
    }

    /* Read "reg" property - contains (address, size) pairs
     * On ARM64, typically 64-bit address + 64-bit size = 16 bytes per entry
     */
    uint64_t reg_data[4];  /* Allow for 2 address/size pairs */
    size_t len = fut_dtb_get_property(dtb_ptr, node_name, "reg", reg_data, sizeof(reg_data));

    if (len < 16) {  /* Need at least 16 bytes for one 64-bit address/size pair */
        return false;
    }

    /* Extract base address (first 64 bits) */
    *base_out = be64_to_cpu(reg_data[0]);

    /* Extract size if requested (second 64 bits) */
    if (size_out && len >= 16) {
        *size_out = be64_to_cpu(reg_data[1]);
    }

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
        .aic_base = 0,
        .ans_mailbox_base = 0,
        .ans_nvme_base = 0,
        .has_gic = false,
        .has_aic = false,
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

        case PLATFORM_APPLE_M1:
            info.name = "Apple M1";
            info.cpu_freq = 24000000;  /* 24 MHz timer frequency */
            info.uart_base = 0x235200000;  /* Apple s5l-uart (hardcoded - TODO: DT parse) */
            info.gpio_base = 0;  /* GPIO controller varies by device */
            info.aic_base = 0x23B100000;  /* Apple Interrupt Controller (hardcoded - TODO: DT parse) */
            info.has_gic = false;
            info.has_aic = true;
            info.has_generic_timer = true;  /* ARM Generic Timer present */

            /* Parse Apple-specific device tree nodes for ANS/mailbox */
            /* Note: These node paths are examples - actual paths vary by device */
            /* Real implementation would search for compatible="apple,nvme-ans2" */
            uint64_t ans_mailbox, ans_nvme;
            if (fut_dtb_get_reg(dtb_ptr, "/arm-io/ans", &ans_nvme, NULL)) {
                info.ans_nvme_base = ans_nvme;
            }
            if (fut_dtb_get_reg(dtb_ptr, "/arm-io/ans/mailbox", &ans_mailbox, NULL)) {
                info.ans_mailbox_base = ans_mailbox;
            }
            break;

        case PLATFORM_APPLE_M2:
            info.name = "Apple M2";
            info.cpu_freq = 24000000;  /* 24 MHz timer frequency */
            info.uart_base = 0x235200000;  /* Apple s5l-uart (hardcoded - TODO: DT parse) */
            info.gpio_base = 0;  /* GPIO controller varies by device */
            info.aic_base = 0x23B100000;  /* Apple Interrupt Controller (hardcoded - TODO: DT parse) */
            info.has_gic = false;
            info.has_aic = true;
            info.has_generic_timer = true;

            /* Parse Apple-specific device tree nodes for ANS/mailbox */
            uint64_t ans_mailbox_m2, ans_nvme_m2;
            if (fut_dtb_get_reg(dtb_ptr, "/arm-io/ans", &ans_nvme_m2, NULL)) {
                info.ans_nvme_base = ans_nvme_m2;
            }
            if (fut_dtb_get_reg(dtb_ptr, "/arm-io/ans/mailbox", &ans_mailbox_m2, NULL)) {
                info.ans_mailbox_base = ans_mailbox_m2;
            }
            break;

        case PLATFORM_APPLE_M3:
            info.name = "Apple M3";
            info.cpu_freq = 24000000;  /* 24 MHz timer frequency */
            info.uart_base = 0x235200000;  /* Apple s5l-uart (hardcoded - TODO: DT parse) */
            info.gpio_base = 0;  /* GPIO controller varies by device */
            info.aic_base = 0x23B100000;  /* Apple Interrupt Controller (hardcoded - TODO: DT parse) */
            info.has_gic = false;
            info.has_aic = true;
            info.has_generic_timer = true;

            /* Parse Apple-specific device tree nodes for ANS/mailbox */
            uint64_t ans_mailbox_m3, ans_nvme_m3;
            if (fut_dtb_get_reg(dtb_ptr, "/arm-io/ans", &ans_nvme_m3, NULL)) {
                info.ans_nvme_base = ans_nvme_m3;
            }
            if (fut_dtb_get_reg(dtb_ptr, "/arm-io/ans/mailbox", &ans_mailbox_m3, NULL)) {
                info.ans_mailbox_base = ans_mailbox_m3;
            }
            break;

        default:
            break;
    }

    return info;
}

/* ============================================================
 *   Device Tree Node Discovery
 * ============================================================ */

bool fut_dtb_get_interrupt(uint64_t dtb_ptr, const char *node_name, uint32_t *irq_out) {
    if (!fut_dtb_validate(dtb_ptr) || !node_name || !irq_out) {
        return false;
    }

    /* Read "interrupts" property - contains (type, number, flags) triplets
     * Format: <type, number, flags>
     *   type: 0=SPI (Shared Peripheral Interrupt), 1=PPI (Private Peripheral Interrupt)
     *   number: Interrupt number
     *   flags: Trigger type (bit 0: edge=1, level=0)
     */
    uint32_t int_data[3];  /* One interrupt triplet */
    size_t len = fut_dtb_get_property(dtb_ptr, node_name, "interrupts", int_data, sizeof(int_data));

    if (len < 12) {  /* Need at least 12 bytes for one triplet */
        return false;
    }

    /* Extract interrupt number (second cell) */
    uint32_t int_type = be32_to_cpu(int_data[0]);
    uint32_t int_num = be32_to_cpu(int_data[1]);
    uint32_t int_flags = be32_to_cpu(int_data[2]);

    /* For SPI interrupts (type 0), the interrupt number is used directly.
     * The GIC driver handles the offset internally (SPI starts at 32).
     * For PPI interrupts (type 1), the number is also used directly.
     */
    (void)int_type;   /* Type not currently used */
    (void)int_flags;  /* Flags not currently used */

    *irq_out = int_num;
    return true;
}

int fut_dtb_find_compatible_nodes(uint64_t dtb_ptr, const char *compatible,
                                   fut_dtb_node_t *nodes_out, int max_nodes) {
    if (!fut_dtb_validate(dtb_ptr) || !compatible || !nodes_out || max_nodes <= 0) {
        fut_printf("[DTB-SEARCH] Invalid parameters or validation failed\n");
        return 0;
    }

    fut_printf("[DTB-SEARCH] Searching for compatible=\"%s\", max_nodes=%d\n", compatible, max_nodes);

    dtb_header_t *header = (dtb_header_t *)dtb_ptr;
    char *strings_base = (char *)(dtb_ptr + be32_to_cpu(header->off_dt_strings));
    uint32_t *struct_ptr = (uint32_t *)(dtb_ptr + be32_to_cpu(header->off_dt_struct));
    uint32_t *p = struct_ptr;

    int found_count = 0;
    int node_count = 0;
    char current_node_name[64] = {0};
    bool in_matching_node = false;
    uint64_t current_base = 0;
    uint64_t current_size = 0;
    uint32_t current_irq = 0;

    /* Iterate through device tree structure */
    while (be32_to_cpu(p[0]) != FDT_END) {
        uint32_t token = be32_to_cpu(p[0]);

        if (token == FDT_BEGIN_NODE) {
            /* Extract node name (null-terminated string after token) */
            const char *node_name_ptr = (const char *)&p[1];
            size_t name_len = strlen(node_name_ptr);

            node_count++;

            /* Copy node name for tracking */
            if (name_len > 0 && name_len < sizeof(current_node_name)) {
                memcpy(current_node_name, node_name_ptr, name_len);
                current_node_name[name_len] = '\0';
                if (node_count < 20) {  /* Limit debug spam */
                    fut_printf("[DTB-SEARCH] Node #%d: '%s'\n", node_count, current_node_name);
                }
            } else {
                current_node_name[0] = '\0';
            }

            /* Reset matching state for new node */
            in_matching_node = false;
            current_base = 0;
            current_size = 0;
            current_irq = 0;

            /* Move past node name (aligned to 4 bytes) */
            size_t aligned_name_len = align_offset(name_len + 1);
            p = (uint32_t *)((char *)&p[1] + aligned_name_len);

        } else if (token == FDT_PROP) {
            dtb_prop_t *prop = (dtb_prop_t *)&p[1];
            uint32_t prop_len = be32_to_cpu(prop->len);
            uint32_t name_off = be32_to_cpu(prop->nameoff);
            const char *prop_name = strings_base + name_off;
            void *prop_value = (void *)&prop[1];

            /* Always extract reg and interrupts for every node (property order is not guaranteed) */
            if (strcmp(prop_name, "reg") == 0 && prop_len >= 16) {
                /* Extract 64-bit base and size */
                uint64_t *reg_data = (uint64_t *)prop_value;
                current_base = be64_to_cpu(reg_data[0]);
                current_size = be64_to_cpu(reg_data[1]);
            }

            if (strcmp(prop_name, "interrupts") == 0 && prop_len >= 12) {
                /* Extract interrupt number from 3-cell format */
                uint32_t *int_data = (uint32_t *)prop_value;
                current_irq = be32_to_cpu(int_data[1]);  /* Second cell is interrupt number */
            }

            /* Check if this is a compatible property matching our search */
            if (strcmp(prop_name, "compatible") == 0 && prop_len > 0) {
                /* Compatible strings are null-terminated, possibly multiple */
                const char *compat_str = (const char *)prop_value;
                if (strstr(compat_str, compatible) != NULL) {
                    in_matching_node = true;
                }
            }

            /* Move to next property */
            p = (uint32_t *)((char *)p + sizeof(uint32_t) + sizeof(dtb_prop_t) + prop_len);
            p = (uint32_t *)align_offset((size_t)p);

        } else if (token == FDT_END_NODE) {
            /* If we found a matching node with all required properties, add it */
            if (in_matching_node && current_base != 0) {
                if (found_count < max_nodes) {
                    /* Copy node info to output array */
                    size_t name_len = strlen(current_node_name);
                    if (name_len >= sizeof(nodes_out[found_count].name)) {
                        name_len = sizeof(nodes_out[found_count].name) - 1;
                    }
                    memcpy(nodes_out[found_count].name, current_node_name, name_len);
                    nodes_out[found_count].name[name_len] = '\0';

                    nodes_out[found_count].base_addr = current_base;
                    nodes_out[found_count].size = current_size;
                    nodes_out[found_count].irq = current_irq;
                }
                found_count++;
            }

            /* Reset for next node */
            in_matching_node = false;
            current_node_name[0] = '\0';
            p += 1;

        } else if (token == FDT_NOP) {
            p += 1;
        } else {
            /* Unknown token, stop */
            break;
        }
    }

    fut_printf("[DTB-SEARCH] Search complete: found %d matching nodes (searched %d total nodes)\n",
               found_count, node_count);
    return found_count;
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
