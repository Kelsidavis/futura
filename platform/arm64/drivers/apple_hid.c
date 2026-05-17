/* apple_hid.c - Apple SPI/I2C HID Input — Rust-backed wrapper
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Keyboard (SPI) and trackpad (SPI/I2C) input for Apple Silicon
 * MacBooks.  The byte-level protocol parsing (US-layout HID scancode
 * → ASCII tables, key edge detection, ring buffer) lives in the
 * Rust apple_hid crate under drivers/rust/apple_hid.  This C file is
 * a thin glue layer that:
 *
 *   1. Owns the AppleHidParser instance (allocated by the Rust
 *      driver's `rust_apple_hid_new`).
 *   2. Drives the SPI/I2C transfers via the existing rust_spi /
 *      rust_i2c FFI, then feeds the received bytes into the parser.
 *   3. Adapts the legacy C callbacks (apple_hid_key_callback_t,
 *      apple_hid_touch_callback_t) so existing call-sites keep
 *      working unchanged.
 *
 * Compat note: apple_hid_platform_init() guards on
 * info->type == PLATFORM_APPLE_M[1-4] so RPi and QEMU virt boots
 * never reach the Rust parser.
 */

#include <platform/arm64/apple_hid.h>
#include <platform/arm64/apple_spi.h>
#include <platform/arm64/apple_i2c.h>
#include <platform/arm64/apple_pmgr.h>
#include <platform/arm64/memory/pmap.h>
#include <platform/platform.h>
#include <string.h>

/* Apple SPI HID constants */
#define SPI_HID_PKT_SIZE     256
#define SPI_HID_PCLK_HZ     125000000  /* 125 MHz peripheral clock */
#define SPI_HID_SCLK_HZ     8000000    /* 8 MHz SPI clock */

/* Global HID context — kept here (not in the parser) because it
 * holds the SPI/I2C handles and the legacy-shaped C callbacks. */
static apple_hid_ctx_t g_hid;
static AppleHidParser *g_parser = NULL;

/* Adapter: Rust → C touchpad callback.  The Rust side passes a
 * raw byte slice; the public C API took a typed report struct.
 * Cast through the same struct definition. */
static void touch_adapter(const uint8_t *ptr, size_t len) {
    if (!g_hid.touch_cb || !ptr || len < sizeof(apple_hid_touchpad_report_t)) {
        return;
    }
    g_hid.touch_cb((const apple_hid_touchpad_report_t *)ptr);
}

/* Adapter: Rust → C keyboard edge callback.  Signatures already
 * match (scancode, modifiers, pressed) — just relay. */
static void key_adapter(uint8_t scancode, uint8_t modifiers, bool pressed) {
    if (g_hid.key_cb) {
        g_hid.key_cb(scancode, modifiers, pressed);
    }
}

/* ============================================================
 *   Public API
 * ============================================================ */

int apple_hid_init(const fut_platform_info_t *info) {
    if (!info) return -1;

    memset(&g_hid, 0, sizeof(g_hid));

    /* Initialize SPI for keyboard.  Peripheral PA → kernel VA via the
     * boot.S peripheral mapping window so the Rust crate's raw MMIO
     * reads land on a mapped address. */
    if (info->spi0_base != 0) {
        uint64_t spi_va = fut_kernel_peripheral_va(info->spi0_base);
        g_hid.spi = rust_spi_init(spi_va, SPI_HID_PCLK_HZ, 0, SPI_HID_SCLK_HZ);
        if (!g_hid.spi) {
            fut_printf("[HID] Failed to initialize SPI\n");
            return -1;
        }
        g_hid.spi_cs = 0;
        fut_printf("[HID] SPI keyboard initialized at PA 0x%lx (VA 0x%lx)\n",
                   (unsigned long)info->spi0_base, (unsigned long)spi_va);
    }

    /* Initialize I2C for trackpad (if separate from SPI) */
    if (info->i2c0_base != 0) {
        uint64_t i2c_va = fut_kernel_peripheral_va(info->i2c0_base);
        g_hid.i2c = rust_i2c_init(i2c_va);
        if (g_hid.i2c) {
            g_hid.i2c_addr = 0x49;  /* Common Apple trackpad I2C address */
            fut_printf("[HID] I2C trackpad initialized at PA 0x%lx (VA 0x%lx)\n",
                       (unsigned long)info->i2c0_base, (unsigned long)i2c_va);
        }
    }

    /* Allocate the Rust parser. */
    g_parser = rust_apple_hid_new();
    if (!g_parser) {
        fut_printf("[HID] Failed to allocate parser\n");
        /* I2C controller handle from rust_i2c_init is heap-allocated,
         * so release it here.  SPI uses a global static (G_SPI) and
         * is idempotent — nothing to free. */
        if (g_hid.i2c) {
            extern void rust_i2c_free(AppleI2c *i2c);
            rust_i2c_free((AppleI2c *)g_hid.i2c);
            g_hid.i2c = NULL;
        }
        return -1;
    }
    rust_apple_hid_set_key_cb(g_parser, key_adapter);
    rust_apple_hid_set_touch_cb(g_parser, touch_adapter);

    g_hid.initialized = true;
    fut_printf("[HID] Apple HID input initialized (Rust parser)\n");
    return 0;
}

void apple_hid_poll(void) {
    if (!g_hid.initialized || !g_parser) return;

    /* Poll SPI for keyboard/trackpad data */
    if (g_hid.spi) {
        uint8_t rx_buf[SPI_HID_PKT_SIZE];
        memset(rx_buf, 0, sizeof(rx_buf));

        rust_spi_cs_assert((AppleSpi *)g_hid.spi, g_hid.spi_cs);
        int ret = rust_spi_read((AppleSpi *)g_hid.spi, rx_buf, SPI_HID_PKT_SIZE);
        rust_spi_cs_deassert((AppleSpi *)g_hid.spi, g_hid.spi_cs);

        if (ret == 0) {
            /* Skip frames that are all 0x00 or all 0xFF — those are
             * idle-line probe results, not real packets. */
            bool valid = false;
            for (int i = 0; i < 8; i++) {
                if (rx_buf[i] != 0x00 && rx_buf[i] != 0xFF) {
                    valid = true;
                    break;
                }
            }
            if (valid) {
                rust_apple_hid_feed_spi_packet(g_parser, rx_buf, SPI_HID_PKT_SIZE);
            }
        }
    }

    /* Poll I2C for trackpad data (if using I2C trackpad) */
    if (g_hid.i2c) {
        uint8_t rx_buf[64];
        int ret = rust_i2c_read((AppleI2c *)g_hid.i2c, g_hid.i2c_addr,
                                 rx_buf, sizeof(rx_buf));
        if (ret == 0 && rx_buf[0] != 0) {
            rust_apple_hid_feed_touchpad(g_parser, rx_buf, sizeof(rx_buf));
        }
    }
}

char apple_hid_getchar(void) {
    if (!g_parser) return 0;
    int c = rust_apple_hid_getchar(g_parser);
    return (c < 0) ? 0 : (char)c;
}

bool apple_hid_has_key(void) {
    if (!g_parser) return false;
    return rust_apple_hid_has_key(g_parser) != 0;
}

void apple_hid_register_key_callback(apple_hid_key_callback_t cb) {
    g_hid.key_cb = cb;
}

void apple_hid_register_touch_callback(apple_hid_touch_callback_t cb) {
    g_hid.touch_cb = cb;
}

int apple_hid_platform_init(const fut_platform_info_t *info) {
    if (!info) return -1;

    /* Only initialize on Apple Silicon — keeps RPi / QEMU virt
     * boots out of this code path entirely. */
    if (info->type != PLATFORM_APPLE_M1 &&
        info->type != PLATFORM_APPLE_M2 &&
        info->type != PLATFORM_APPLE_M3 &&
        info->type != PLATFORM_APPLE_M4) {
        return 0;
    }

    if (info->spi0_base == 0 && info->i2c0_base == 0) {
        return 0;  /* No HID hardware found in DTB */
    }

    extern uint64_t fut_platform_get_dtb(void);
    uint64_t dtb = fut_platform_get_dtb();

    if (info->spi0_base != 0) {
        static const char *const spi_paths[] = {
            "/soc/spi@23510c000",
            "/soc/spi0",
            "/arm-io/spi0",
            NULL,
        };
        int n = apple_pmgr_enable_domains_any(dtb, spi_paths);
        if (n > 0) fut_printf("[HID] pmgr: %d SPI0 domains enabled\n", n);
    }
    if (info->i2c0_base != 0) {
        static const char *const i2c_paths[] = {
            "/soc/i2c@235010000",
            "/soc/i2c0",
            "/arm-io/i2c0",
            NULL,
        };
        int n = apple_pmgr_enable_domains_any(dtb, i2c_paths);
        if (n > 0) fut_printf("[HID] pmgr: %d I2C0 domains enabled\n", n);
    }

    return apple_hid_init(info);
}
