/* arm64_dtb.c - Device Tree Blob Parsing for ARM64 RPi
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Parses device tree blobs passed by bootloader for RPi3/4/5.
 */

#include <platform/arm64/dtb.h>
#include <kernel/kprintf.h>
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

/* ============================================================
 *   DTB Validation
 * ============================================================ */

bool fut_dtb_validate(uint64_t dtb_ptr) {
    if (!dtb_ptr) {
        return false;
    }

    dtb_header_t *header = (dtb_header_t *)dtb_ptr;

    /* Validate magic number.  The DTB stores 0xd00dfeed in *big-endian*
     * byte order on disk (bytes d0 0d fe ed).  On little-endian ARM64
     * a direct uint32_t read gives the host-native value 0xedfe0dd0;
     * comparing that against the literal 0xd00dfeed never matched, so
     * every call to fut_dtb_validate() silently returned false and
     * fut_dtb_parse() handed back default values (PLATFORM_UNKNOWN,
     * no /chosen/bootargs, no real reg values).  Byte-swap the magic
     * before comparing so the DTB is actually validated. */
    if (be32_to_cpu(header->magic) != 0xd00dfeed) {
        return false;
    }

    /* All DTB header fields are big-endian; byte-swap for comparison */
    uint32_t totalsize = be32_to_cpu(header->totalsize);
    uint32_t version = be32_to_cpu(header->version);
    uint32_t off_struct = be32_to_cpu(header->off_dt_struct);
    uint32_t off_strings = be32_to_cpu(header->off_dt_strings);

    /* Validate version is reasonable */
    if (version < 1 || version > 17) {
        return false;
    }

    /* Sanity check: totalsize must be large enough for the header */
    if (totalsize < sizeof(dtb_header_t)) {
        return false;
    }

    /* Validate offsets are within bounds */
    if (off_struct >= totalsize || off_strings >= totalsize) {
        return false;
    }

    return true;
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
        uint32_t totalsize = be32_to_cpu(header->totalsize);
        uint32_t off_struct = be32_to_cpu(header->off_dt_struct);
        uint32_t off_strings = be32_to_cpu(header->off_dt_strings);

        if (off_struct >= totalsize || off_strings >= totalsize) {
            return PLATFORM_UNKNOWN;
        }

        uint32_t *struct_ptr = (uint32_t *)(dtb_ptr + off_struct);
        uint32_t *struct_end = (uint32_t *)(dtb_ptr + totalsize);
        char *strings_base = (char *)(dtb_ptr + off_strings);
        uint32_t strings_size = totalsize - off_strings;

        /* Skip to first property of root node */
        if (struct_ptr < struct_end && be32_to_cpu(struct_ptr[0]) == FDT_BEGIN_NODE) {
            /* Look for compatible in root */
            uint32_t *prop_ptr = struct_ptr + 2; /* Skip token and node name length */

            while (prop_ptr < struct_end && be32_to_cpu(prop_ptr[0]) == FDT_PROP) {
                dtb_prop_t *prop = (dtb_prop_t *)&prop_ptr[1];
                uint32_t prop_len = be32_to_cpu(prop->len);
                uint32_t name_off = be32_to_cpu(prop->nameoff);

                /* Validate string offset is within strings block */
                if (name_off >= strings_size) {
                    break;
                }
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
    if (strstr(compatible, "apple,t8122") != NULL) { /* M3 */
        return PLATFORM_APPLE_M3;
    }
    if (strstr(compatible, "apple,t6031") != NULL || /* M4 */
        strstr(compatible, "apple,t6030") != NULL) {  /* M4 Pro */
        return PLATFORM_APPLE_M4;
    }

    return PLATFORM_UNKNOWN;
}

/* ============================================================
 *   Property Extraction
 * ============================================================ */

/* True if @actual matches @target, treating an Asahi/U-Boot unit-address
 * suffix on @actual as optional.  "uart0" matches "uart0@235200000" and
 * vice-versa; "ans/mailbox" matches "ans/mailbox@..." too. */
static bool dtb_node_name_matches(const char *actual, const char *target) {
    while (*target != '\0') {
        if (*actual == '\0' || *actual != *target) {
            return false;
        }
        actual++;
        target++;
    }
    /* Target exhausted — accept either exact end or unit-address suffix. */
    return *actual == '\0' || *actual == '@';
}

size_t fut_dtb_get_property(uint64_t dtb_ptr, const char *node_name,
                            const char *prop_name, void *value_out, size_t max_len) {
    if (!fut_dtb_validate(dtb_ptr) || !prop_name || !value_out) {
        return 0;
    }

    dtb_header_t *header = (dtb_header_t *)dtb_ptr;
    uint32_t totalsize    = be32_to_cpu(header->totalsize);
    uint32_t off_struct   = be32_to_cpu(header->off_dt_struct);
    uint32_t off_strings  = be32_to_cpu(header->off_dt_strings);
    uint32_t size_strings = be32_to_cpu(header->size_dt_strings);

    if (off_struct >= totalsize || off_strings >= totalsize) {
        return 0;
    }

    const char *strings_base = (const char *)(dtb_ptr + off_strings);
    uint32_t   *p            = (uint32_t *)(dtb_ptr + off_struct);
    uint32_t   *struct_end   = (uint32_t *)(dtb_ptr + totalsize);

    /* Parse the target path into per-depth components.  An empty or
     * NULL node_name matches the root node (depth 0).  Paths with a
     * leading '/' are anchored; a relative path like "memory" is
     * equivalent to "/memory".  Each component is a pointer + length
     * into the caller's string; we don't copy because the path
     * outlives the walk. */
    #define MAX_DEPTH 16
    const char *comp_ptr[MAX_DEPTH] = {0};
    size_t      comp_len[MAX_DEPTH] = {0};
    int         target_depth        = 0;

    if (node_name && *node_name != '\0') {
        const char *s = node_name;
        if (*s == '/') s++;
        while (*s != '\0' && target_depth < MAX_DEPTH) {
            comp_ptr[target_depth] = s;
            size_t len = 0;
            while (s[len] != '\0' && s[len] != '/') len++;
            comp_len[target_depth] = len;
            target_depth++;
            s += len;
            if (*s == '/') s++;
        }
    }

    /* Walk tokens.  is_match[d] is true if every ancestor from depth 1
     * through d matched its path component.  is_match[0] is always
     * true (root).  When depth == target_depth AND is_match[depth] is
     * true we're inside the target node and look at every FDT_PROP. */
    bool is_match[MAX_DEPTH + 1] = {0};
    is_match[0] = true;
    int  depth  = 0;

    while (p < struct_end) {
        uint32_t token = be32_to_cpu(p[0]);

        if (token == FDT_END) {
            break;
        } else if (token == FDT_BEGIN_NODE) {
            const char *name = (const char *)&p[1];
            /* Bound the strlen to the remaining DTB so a malformed
             * blob can't run us past struct_end. */
            size_t max_name = (size_t)((char *)struct_end - name);
            size_t name_len = 0;
            while (name_len < max_name && name[name_len] != '\0') {
                name_len++;
            }
            depth++;
            if (depth <= MAX_DEPTH) {
                if (depth <= target_depth && is_match[depth - 1]) {
                    /* Compare this node name to the matching path
                     * component.  Build a temporary NUL-terminated
                     * copy of just the component to use the unit-
                     * address-tolerant matcher. */
                    char target_buf[64];
                    size_t tlen = comp_len[depth - 1];
                    if (tlen >= sizeof(target_buf)) tlen = sizeof(target_buf) - 1;
                    memcpy(target_buf, comp_ptr[depth - 1], tlen);
                    target_buf[tlen] = '\0';
                    is_match[depth] = dtb_node_name_matches(name, target_buf);
                } else {
                    is_match[depth] = false;
                }
            }
            /* Advance past the variable-length name (NUL-terminated,
             * padded to 4 bytes).  This is the bit the old walker
             * got wrong — it just did p += 1 and desync'd inside
             * any non-root subtree. */
            size_t aligned = align_offset(name_len + 1);
            p = (uint32_t *)((char *)&p[1] + aligned);
        } else if (token == FDT_END_NODE) {
            if (depth <= MAX_DEPTH) {
                is_match[depth] = false;
            }
            depth--;
            p += 1;
        } else if (token == FDT_NOP) {
            p += 1;
        } else if (token == FDT_PROP) {
            dtb_prop_t *prop  = (dtb_prop_t *)&p[1];
            uint32_t prop_len = be32_to_cpu(prop->len);
            uint32_t name_off = be32_to_cpu(prop->nameoff);
            if (name_off >= size_strings) {
                break;
            }
            const char *name = strings_base + name_off;

            bool in_target = (depth == target_depth) &&
                             (depth <= MAX_DEPTH) &&
                             is_match[depth];
            if (in_target && strcmp(name, prop_name) == 0) {
                size_t copy_len = (prop_len < max_len) ? prop_len : max_len;
                memcpy(value_out, &prop[1], copy_len);
                return prop_len;
            }

            size_t advance = sizeof(uint32_t) + sizeof(dtb_prop_t) + prop_len;
            p = (uint32_t *)((char *)p + advance);
            p = (uint32_t *)align_offset((size_t)p);
        } else {
            /* Unknown token — abort rather than walking into garbage. */
            break;
        }
    }

    return 0;
    #undef MAX_DEPTH
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
        case PLATFORM_APPLE_M2:
        case PLATFORM_APPLE_M3:
        case PLATFORM_APPLE_M4: {
            /* Shared Apple Silicon initialization */
            static const char *apple_names[] = {
                [PLATFORM_APPLE_M1] = "Apple M1",
                [PLATFORM_APPLE_M2] = "Apple M2",
                [PLATFORM_APPLE_M3] = "Apple M3",
                [PLATFORM_APPLE_M4] = "Apple M4",
            };
            info.name = apple_names[info.type];
            info.cpu_freq = 24000000;  /* 24 MHz timer frequency */
            info.uart_base = 0x235200000;  /* Apple s5l-uart (default fallback) */
            info.gpio_base = 0;
            info.aic_base = 0x23B100000;  /* Apple Interrupt Controller (default fallback) */
            info.has_gic = false;
            info.has_aic = true;
            info.has_generic_timer = true;

            /* Parse Apple-specific device tree nodes.
             *
             * Path conventions differ across DT sources: Asahi Linux
             * (and m1n1's exported FDT) name peripherals under /soc/
             * with the MMIO base as the unit-address suffix
             * (e.g. /soc/serial@235200000), while some older custom
             * DTs and the historical Futura test fixtures used
             * /arm-io/ paths.  Walk both — the path-aware walker in
             * fut_dtb_get_property short-circuits on the first
             * match.  Hardcoded fallbacks above (uart_base,
             * aic_base) keep the kernel limping along even if the
             * DTB is unrecognisable. */
            uint64_t tmp_addr;

            /* UART (s5l-uart) */
            if (fut_dtb_get_reg(dtb_ptr, "/soc/serial@235200000", &tmp_addr, NULL) ||
                fut_dtb_get_reg(dtb_ptr, "/soc/serial",           &tmp_addr, NULL) ||
                fut_dtb_get_reg(dtb_ptr, "/arm-io/uart0",         &tmp_addr, NULL)) {
                info.uart_base = tmp_addr;
            }

            /* AIC (Apple Interrupt Controller) — Asahi labels it
             * /soc/interrupt-controller@..., older trees use /soc/aic. */
            if (fut_dtb_get_reg(dtb_ptr, "/soc/interrupt-controller@23b100000", &tmp_addr, NULL) ||
                fut_dtb_get_reg(dtb_ptr, "/soc/aic@23b100000",                 &tmp_addr, NULL) ||
                fut_dtb_get_reg(dtb_ptr, "/soc/aic",                           &tmp_addr, NULL) ||
                fut_dtb_get_reg(dtb_ptr, "/arm-io/aic",                        &tmp_addr, NULL)) {
                info.aic_base = tmp_addr;
            }

            /* ANS2 NVMe — Asahi has split MMIO + mailbox nodes
             * (nvme@277400000 + mailbox@277408000), older trees
             * nest as /arm-io/ans + /arm-io/ans/mailbox. */
            if (fut_dtb_get_reg(dtb_ptr, "/soc/nvme@277400000", &tmp_addr, NULL) ||
                fut_dtb_get_reg(dtb_ptr, "/soc/nvme",           &tmp_addr, NULL) ||
                fut_dtb_get_reg(dtb_ptr, "/arm-io/ans",         &tmp_addr, NULL)) {
                info.ans_nvme_base = tmp_addr;
            }
            if (fut_dtb_get_reg(dtb_ptr, "/soc/mailbox@277408000", &tmp_addr, NULL) ||
                fut_dtb_get_reg(dtb_ptr, "/arm-io/ans/mailbox",    &tmp_addr, NULL)) {
                info.ans_mailbox_base = tmp_addr;
            }

            /* DCP (Display Co-Processor) — Asahi: display-pipe + mailbox. */
            if (fut_dtb_get_reg(dtb_ptr, "/soc/display-pipe@28200000", &tmp_addr, NULL) ||
                fut_dtb_get_reg(dtb_ptr, "/soc/dcp@28200000",          &tmp_addr, NULL) ||
                fut_dtb_get_reg(dtb_ptr, "/soc/dcp",                   &tmp_addr, NULL) ||
                fut_dtb_get_reg(dtb_ptr, "/arm-io/dcp",                &tmp_addr, NULL)) {
                info.dcp_base = tmp_addr;
                info.has_dcp = true;
            }
            if (fut_dtb_get_reg(dtb_ptr, "/soc/mailbox@28e408000", &tmp_addr, NULL) ||
                fut_dtb_get_reg(dtb_ptr, "/arm-io/dcp/mailbox",    &tmp_addr, NULL)) {
                info.dcp_mailbox_base = tmp_addr;
            }

            /* DART IOMMU for DCP — Asahi uses /soc/iommu@<base>. */
            if (fut_dtb_get_reg(dtb_ptr, "/soc/iommu@381000000", &tmp_addr, NULL) ||
                fut_dtb_get_reg(dtb_ptr, "/soc/dart-dcp",        &tmp_addr, NULL) ||
                fut_dtb_get_reg(dtb_ptr, "/arm-io/dart-dcp",     &tmp_addr, NULL)) {
                info.dart_base = tmp_addr;
            }

            /* SMC (System Management Controller) */
            if (fut_dtb_get_reg(dtb_ptr, "/soc/smc@23e400000",  &tmp_addr, NULL) ||
                fut_dtb_get_reg(dtb_ptr, "/soc/smc",            &tmp_addr, NULL) ||
                fut_dtb_get_reg(dtb_ptr, "/arm-io/smc",         &tmp_addr, NULL) ||
                fut_dtb_get_reg(dtb_ptr, "/arm-io/smc/mailbox", &tmp_addr, NULL)) {
                info.smc_base = tmp_addr;
            }

            /* GPIO / pinctrl */
            if (fut_dtb_get_reg(dtb_ptr, "/soc/pinctrl@23c100000", &tmp_addr, NULL) ||
                fut_dtb_get_reg(dtb_ptr, "/soc/pinctrl",           &tmp_addr, NULL) ||
                fut_dtb_get_reg(dtb_ptr, "/arm-io/gpio",           &tmp_addr, NULL) ||
                fut_dtb_get_reg(dtb_ptr, "/arm-io/pinctrl",        &tmp_addr, NULL)) {
                info.gpio_base_apple = tmp_addr;
            }

            /* SPI0 (keyboard HID) */
            if (fut_dtb_get_reg(dtb_ptr, "/soc/spi@23510c000", &tmp_addr, NULL) ||
                fut_dtb_get_reg(dtb_ptr, "/soc/spi0",          &tmp_addr, NULL) ||
                fut_dtb_get_reg(dtb_ptr, "/arm-io/spi0",       &tmp_addr, NULL)) {
                info.spi0_base = tmp_addr;
            }

            /* I2C0 (trackpad HID) */
            if (fut_dtb_get_reg(dtb_ptr, "/soc/i2c@235010000", &tmp_addr, NULL) ||
                fut_dtb_get_reg(dtb_ptr, "/soc/i2c0",          &tmp_addr, NULL) ||
                fut_dtb_get_reg(dtb_ptr, "/arm-io/i2c0",       &tmp_addr, NULL)) {
                info.i2c0_base = tmp_addr;
            }

            /* PCIe root complex */
            if (fut_dtb_get_reg(dtb_ptr, "/soc/pcie@690000000", &tmp_addr, NULL) ||
                fut_dtb_get_reg(dtb_ptr, "/soc/pcie",           &tmp_addr, NULL) ||
                fut_dtb_get_reg(dtb_ptr, "/arm-io/pcie",        &tmp_addr, NULL) ||
                fut_dtb_get_reg(dtb_ptr, "/arm-io/pciec0",      &tmp_addr, NULL)) {
                info.pcie_base = tmp_addr;
                info.pcie_num_ports = 3;  /* Default: 3 ports on M1/M2 */
            }
            if (fut_dtb_get_reg(dtb_ptr, "/soc/pcie/ecam",     &tmp_addr, NULL) ||
                fut_dtb_get_reg(dtb_ptr, "/arm-io/pcie/ecam",  &tmp_addr, NULL)) {
                info.pcie_cfg_base = tmp_addr;
            }

            /* MCA (Multi-Channel Audio) I2S controller.  Asahi DT
             * names the node /soc/mca@<base> with base 0x2D5200000
             * on M1; cluster count is 1 on M1 / M2 base SKUs (only
             * the internal speakers wired up) and grows to 6 on M1
             * Pro / Max where additional analog outputs are routed.
             * We default to 1 here and let the audio driver clamp. */
            if (fut_dtb_get_reg(dtb_ptr, "/soc/mca@2d5200000", &tmp_addr, NULL) ||
                fut_dtb_get_reg(dtb_ptr, "/soc/mca",           &tmp_addr, NULL) ||
                fut_dtb_get_reg(dtb_ptr, "/arm-io/mca",        &tmp_addr, NULL)) {
                info.mca_base = tmp_addr;
                info.mca_num_clusters = 1;
            }

            /* Panel geometry from /chosen/framebuffer (Simple FB node
             * that m1n1 populates with the firmware's chosen mode).
             * apple_dcp uses this to skip the EDID + DCP-control
             * round-trip on first boot and just paint into the
             * already-running framebuffer surface. */
            fut_dtb_get_chosen_framebuffer(dtb_ptr,
                                            &info.display_width,
                                            &info.display_height,
                                            NULL);

            break;
        }

        default:
            break;
    }

    return info;
}

/* ============================================================
 *   Boot-arguments extraction
 * ============================================================ */

/* Walk the flattened device tree looking for /chosen/bootargs and copy
 * its value (a NUL-terminated string) into out.  Returns the number of
 * bytes written (excluding the terminator), or 0 if the property was
 * not found.
 *
 * Implemented as a focused walker rather than going through
 * fut_dtb_get_property() because that helper doesn't advance past
 * FDT_BEGIN_NODE's variable-length name correctly and silently misses
 * nested properties — symptom on QEMU virt was that `-append "X=Y"`
 * landed in /chosen/bootargs but the kernel saw no cmdline at all. */
size_t fut_dtb_get_bootargs(uint64_t dtb_ptr, char *out, size_t max_len) {
    if (!fut_dtb_validate(dtb_ptr) || !out || max_len == 0) {
        return 0;
    }

    dtb_header_t *header = (dtb_header_t *)dtb_ptr;
    uint32_t totalsize    = be32_to_cpu(header->totalsize);
    uint32_t off_struct   = be32_to_cpu(header->off_dt_struct);
    uint32_t off_strings  = be32_to_cpu(header->off_dt_strings);
    uint32_t size_strings = be32_to_cpu(header->size_dt_strings);

    if (off_struct >= totalsize || off_strings >= totalsize) {
        return 0;
    }

    const char *strings_base = (const char *)(dtb_ptr + off_strings);
    uint32_t *p              = (uint32_t *)(dtb_ptr + off_struct);
    uint32_t *struct_end     = (uint32_t *)(dtb_ptr + totalsize);

    /* Track whether we are currently inside the "chosen" node.  We bump
     * a depth counter on each FDT_BEGIN_NODE and decrement on
     * FDT_END_NODE so we can correctly detect leaving the chosen node
     * even when it contains its own children. */
    bool   in_chosen      = false;
    int    chosen_depth   = 0;
    int    depth          = 0;

    while (p < struct_end) {
        uint32_t token = be32_to_cpu(p[0]);

        if (token == FDT_END) {
            break;
        } else if (token == FDT_BEGIN_NODE) {
            const char *node_name = (const char *)&p[1];
            size_t max_name = (size_t)((char *)struct_end - node_name);
            size_t name_len = 0;
            while (name_len < max_name && node_name[name_len] != '\0') {
                name_len++;
            }
            depth++;
            if (!in_chosen && strcmp(node_name, "chosen") == 0) {
                in_chosen    = true;
                chosen_depth = depth;
            }
            size_t aligned = align_offset(name_len + 1);
            p = (uint32_t *)((char *)&p[1] + aligned);
        } else if (token == FDT_END_NODE) {
            if (in_chosen && depth == chosen_depth) {
                in_chosen = false;
            }
            depth--;
            p += 1;
        } else if (token == FDT_NOP) {
            p += 1;
        } else if (token == FDT_PROP) {
            dtb_prop_t *prop  = (dtb_prop_t *)&p[1];
            uint32_t prop_len = be32_to_cpu(prop->len);
            uint32_t name_off = be32_to_cpu(prop->nameoff);
            if (name_off >= size_strings) {
                break;
            }
            const char *prop_name = strings_base + name_off;
            if (in_chosen && strcmp(prop_name, "bootargs") == 0) {
                size_t copy_len = (prop_len < max_len - 1) ? prop_len : (max_len - 1);
                memcpy(out, &prop[1], copy_len);
                /* The FDT stores bootargs as a NUL-terminated C string;
                 * strip any trailing NUL inside the property length so
                 * the caller sees just the payload. */
                while (copy_len > 0 && out[copy_len - 1] == '\0') {
                    copy_len--;
                }
                out[copy_len] = '\0';
                return copy_len;
            }
            size_t advance = sizeof(uint32_t) + sizeof(dtb_prop_t) + prop_len;
            p = (uint32_t *)((char *)p + advance);
            p = (uint32_t *)align_offset((size_t)p);
        } else {
            /* Unknown token — abort to avoid running off into garbage. */
            break;
        }
    }

    out[0] = '\0';
    return 0;
}

/* Walk the flattened device tree looking for /chosen/framebuffer's
 * width / height / stride properties.  m1n1 (Asahi Linux's
 * bootloader) and U-Boot both publish the panel geometry the
 * firmware has already brought up here, as a Linux Simple
 * Framebuffer subnode.  Used by fut_dtb_parse on Apple Silicon to
 * surface a default mode for apple_dcp without having to wait for
 * EDID + a full DCP control conversation.
 *
 * Implemented as a focused walker for the same reason as
 * fut_dtb_get_bootargs: the generic fut_dtb_get_property helper does
 * not advance past FDT_BEGIN_NODE's variable-length name correctly
 * and silently misses properties on nested nodes.
 *
 * Returns true if /chosen/framebuffer was found and at least width
 * + height were read; *_out pointers may be NULL and are not
 * updated unless the corresponding property was present. */
bool fut_dtb_get_chosen_framebuffer(uint64_t dtb_ptr,
                                    uint32_t *width_out,
                                    uint32_t *height_out,
                                    uint32_t *stride_out) {
    if (!fut_dtb_validate(dtb_ptr)) {
        return false;
    }

    dtb_header_t *header = (dtb_header_t *)dtb_ptr;
    uint32_t totalsize    = be32_to_cpu(header->totalsize);
    uint32_t off_struct   = be32_to_cpu(header->off_dt_struct);
    uint32_t off_strings  = be32_to_cpu(header->off_dt_strings);
    uint32_t size_strings = be32_to_cpu(header->size_dt_strings);

    if (off_struct >= totalsize || off_strings >= totalsize) {
        return false;
    }

    const char *strings_base = (const char *)(dtb_ptr + off_strings);
    uint32_t *p              = (uint32_t *)(dtb_ptr + off_struct);
    uint32_t *struct_end     = (uint32_t *)(dtb_ptr + totalsize);

    /* Track our position relative to /chosen and /chosen/framebuffer.
     * Same depth-counter approach as fut_dtb_get_bootargs so nested
     * children inside chosen don't fool the in_chosen state. */
    bool in_chosen    = false;
    bool in_fb        = false;
    int  chosen_depth = 0;
    int  fb_depth     = 0;
    int  depth        = 0;
    bool got_width    = false;
    bool got_height   = false;

    while (p < struct_end) {
        uint32_t token = be32_to_cpu(p[0]);

        if (token == FDT_END) {
            break;
        } else if (token == FDT_BEGIN_NODE) {
            const char *node_name = (const char *)&p[1];
            size_t max_name = (size_t)((char *)struct_end - node_name);
            size_t name_len = 0;
            while (name_len < max_name && node_name[name_len] != '\0') {
                name_len++;
            }
            depth++;
            if (!in_chosen && strcmp(node_name, "chosen") == 0) {
                in_chosen    = true;
                chosen_depth = depth;
            } else if (in_chosen && !in_fb &&
                       /* Match "framebuffer" or "framebuffer@<addr>" — the
                        * Simple Framebuffer node name often carries the
                        * MMIO base as a unit address. */
                       (strcmp(node_name, "framebuffer") == 0 ||
                        (name_len >= 12 &&
                         strncmp(node_name, "framebuffer@", 12) == 0))) {
                in_fb    = true;
                fb_depth = depth;
            }
            size_t aligned = align_offset(name_len + 1);
            p = (uint32_t *)((char *)&p[1] + aligned);
        } else if (token == FDT_END_NODE) {
            if (in_fb && depth == fb_depth) {
                in_fb = false;
            }
            if (in_chosen && depth == chosen_depth) {
                in_chosen = false;
            }
            depth--;
            p += 1;
        } else if (token == FDT_NOP) {
            p += 1;
        } else if (token == FDT_PROP) {
            dtb_prop_t *prop  = (dtb_prop_t *)&p[1];
            uint32_t prop_len = be32_to_cpu(prop->len);
            uint32_t name_off = be32_to_cpu(prop->nameoff);
            if (name_off >= size_strings) {
                break;
            }
            const char *prop_name = strings_base + name_off;
            if (in_fb && prop_len == sizeof(uint32_t)) {
                uint32_t raw;
                memcpy(&raw, &prop[1], sizeof(raw));
                uint32_t val = be32_to_cpu(raw);
                if (strcmp(prop_name, "width") == 0) {
                    if (width_out) { *width_out = val; }
                    got_width = true;
                } else if (strcmp(prop_name, "height") == 0) {
                    if (height_out) { *height_out = val; }
                    got_height = true;
                } else if (strcmp(prop_name, "stride") == 0) {
                    if (stride_out) { *stride_out = val; }
                }
            }
            size_t advance = sizeof(uint32_t) + sizeof(dtb_prop_t) + prop_len;
            p = (uint32_t *)((char *)p + advance);
            p = (uint32_t *)align_offset((size_t)p);
        } else {
            break;
        }
    }

    return got_width && got_height;
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
        return 0;
    }

    dtb_header_t *header = (dtb_header_t *)dtb_ptr;
    uint32_t totalsize = be32_to_cpu(header->totalsize);
    uint32_t off_struct = be32_to_cpu(header->off_dt_struct);
    uint32_t off_strings = be32_to_cpu(header->off_dt_strings);

    if (off_struct >= totalsize || off_strings >= totalsize) {
        return 0;
    }

    char *strings_base = (char *)(dtb_ptr + off_strings);
    uint32_t strings_size = totalsize - off_strings;
    uint32_t *struct_ptr = (uint32_t *)(dtb_ptr + off_struct);
    uint32_t *struct_end = (uint32_t *)(dtb_ptr + totalsize);
    uint32_t *p = struct_ptr;

    int found_count = 0;
    char current_node_name[64] = {0};
    bool in_matching_node = false;
    uint64_t current_base = 0;
    uint64_t current_size = 0;
    uint32_t current_irq = 0;

    /* Iterate through device tree structure */
    while (p < struct_end && be32_to_cpu(p[0]) != FDT_END) {
        uint32_t token = be32_to_cpu(p[0]);

        if (token == FDT_BEGIN_NODE) {
            /* Extract node name (null-terminated string after token) */
            const char *node_name_ptr = (const char *)&p[1];
            /* Bound the strlen to remaining DTB size to avoid reading past end */
            size_t max_name = (size_t)((char *)struct_end - node_name_ptr);
            size_t name_len = 0;
            while (name_len < max_name && node_name_ptr[name_len] != '\0') {
                name_len++;
            }

            /* Copy node name for tracking */
            if (name_len > 0 && name_len < sizeof(current_node_name)) {
                memcpy(current_node_name, node_name_ptr, name_len);
                current_node_name[name_len] = '\0';
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

            /* Validate string offset is within strings block */
            if (name_off >= strings_size) {
                break;
            }
            const char *prop_name = strings_base + name_off;
            void *prop_value = (void *)&prop[1];

            /* Check if this is a compatible property matching our search */
            if (strcmp(prop_name, "compatible") == 0 && prop_len > 0) {
                /* Compatible strings are null-terminated, possibly multiple */
                const char *compat_str = (const char *)prop_value;
                if (strstr(compat_str, compatible) != NULL) {
                    in_matching_node = true;
                }
            }

            /* If we're in a matching node, extract reg and interrupts */
            if (in_matching_node) {
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
