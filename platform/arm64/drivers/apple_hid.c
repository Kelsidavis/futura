/* apple_hid.c - Apple SPI/I2C HID Input Driver
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Keyboard (SPI) and trackpad (SPI/I2C) input for Apple Silicon MacBooks.
 */

#include <platform/arm64/apple_hid.h>
#include <platform/arm64/apple_spi.h>
#include <platform/arm64/apple_i2c.h>
#include <platform/platform.h>
#include <string.h>

/* Apple SPI HID constants */
#define SPI_HID_PKT_SIZE     256
#define SPI_HID_PCLK_HZ     125000000  /* 125 MHz peripheral clock */
#define SPI_HID_SCLK_HZ     8000000    /* 8 MHz SPI clock */

/* HID scancode to ASCII lookup (US layout, unshifted) */
static const char hid_to_ascii[128] = {
    [0x04] = 'a', [0x05] = 'b', [0x06] = 'c', [0x07] = 'd',
    [0x08] = 'e', [0x09] = 'f', [0x0A] = 'g', [0x0B] = 'h',
    [0x0C] = 'i', [0x0D] = 'j', [0x0E] = 'k', [0x0F] = 'l',
    [0x10] = 'm', [0x11] = 'n', [0x12] = 'o', [0x13] = 'p',
    [0x14] = 'q', [0x15] = 'r', [0x16] = 's', [0x17] = 't',
    [0x18] = 'u', [0x19] = 'v', [0x1A] = 'w', [0x1B] = 'x',
    [0x1C] = 'y', [0x1D] = 'z', [0x1E] = '1', [0x1F] = '2',
    [0x20] = '3', [0x21] = '4', [0x22] = '5', [0x23] = '6',
    [0x24] = '7', [0x25] = '8', [0x26] = '9', [0x27] = '0',
    [0x28] = '\n', [0x29] = 0x1B, /* Enter, Escape */
    [0x2A] = '\b', [0x2B] = '\t', [0x2C] = ' ',
    [0x2D] = '-', [0x2E] = '=', [0x2F] = '[', [0x30] = ']',
    [0x31] = '\\', [0x33] = ';', [0x34] = '\'', [0x35] = '`',
    [0x36] = ',', [0x37] = '.', [0x38] = '/',
};

/* Shifted ASCII lookup */
static const char hid_to_ascii_shift[128] = {
    [0x04] = 'A', [0x05] = 'B', [0x06] = 'C', [0x07] = 'D',
    [0x08] = 'E', [0x09] = 'F', [0x0A] = 'G', [0x0B] = 'H',
    [0x0C] = 'I', [0x0D] = 'J', [0x0E] = 'K', [0x0F] = 'L',
    [0x10] = 'M', [0x11] = 'N', [0x12] = 'O', [0x13] = 'P',
    [0x14] = 'Q', [0x15] = 'R', [0x16] = 'S', [0x17] = 'T',
    [0x18] = 'U', [0x19] = 'V', [0x1A] = 'W', [0x1B] = 'X',
    [0x1C] = 'Y', [0x1D] = 'Z', [0x1E] = '!', [0x1F] = '@',
    [0x20] = '#', [0x21] = '$', [0x22] = '%', [0x23] = '^',
    [0x24] = '&', [0x25] = '*', [0x26] = '(', [0x27] = ')',
    [0x28] = '\n', [0x29] = 0x1B,
    [0x2A] = '\b', [0x2B] = '\t', [0x2C] = ' ',
    [0x2D] = '_', [0x2E] = '+', [0x2F] = '{', [0x30] = '}',
    [0x31] = '|', [0x33] = ':', [0x34] = '"', [0x35] = '~',
    [0x36] = '<', [0x37] = '>', [0x38] = '?',
};

/* Global HID context */
static apple_hid_ctx_t g_hid;

/* Key buffer (simple ring buffer) */
#define KEY_BUF_SIZE  64
static char g_key_buf[KEY_BUF_SIZE];
static volatile uint32_t g_key_head = 0;
static volatile uint32_t g_key_tail = 0;

static void key_buf_push(char c) {
    uint32_t next = (g_key_head + 1) % KEY_BUF_SIZE;
    if (next != g_key_tail) {
        g_key_buf[g_key_head] = c;
        g_key_head = next;
    }
}

/* ============================================================
 *   SPI HID Protocol
 * ============================================================ */

static void apple_hid_process_keyboard(const uint8_t *data, uint16_t len) {
    if (len < 8) return;

    apple_hid_keyboard_report_t *report = (apple_hid_keyboard_report_t *)data;
    bool shift = (report->modifiers & (HID_MOD_LSHIFT | HID_MOD_RSHIFT)) != 0;

    /* Detect new key presses (keys in current report but not in last) */
    for (int i = 0; i < 6; i++) {
        uint8_t kc = report->keycodes[i];
        if (kc == 0) continue;

        /* Check if this key was already held */
        bool was_held = false;
        for (int j = 0; j < 6; j++) {
            if (g_hid.last_keys[j] == kc) {
                was_held = true;
                break;
            }
        }

        if (!was_held) {
            /* New key press */
            if (g_hid.key_cb) {
                g_hid.key_cb(kc, report->modifiers, true);
            }

            /* Convert to ASCII and buffer */
            if (kc < 128) {
                char c = shift ? hid_to_ascii_shift[kc] : hid_to_ascii[kc];
                if (c != 0) {
                    key_buf_push(c);
                }
            }
        }
    }

    /* Detect released keys */
    if (g_hid.key_cb) {
        for (int i = 0; i < 6; i++) {
            uint8_t kc = g_hid.last_keys[i];
            if (kc == 0) continue;
            bool still_held = false;
            for (int j = 0; j < 6; j++) {
                if (report->keycodes[j] == kc) {
                    still_held = true;
                    break;
                }
            }
            if (!still_held) {
                g_hid.key_cb(kc, report->modifiers, false);
            }
        }
    }

    /* Save current state */
    memcpy(g_hid.last_keys, report->keycodes, 6);
    g_hid.last_modifiers = report->modifiers;
}

static void apple_hid_process_touchpad(const uint8_t *data, uint16_t len) {
    if (len < sizeof(apple_hid_touchpad_report_t)) return;

    if (g_hid.touch_cb) {
        g_hid.touch_cb((const apple_hid_touchpad_report_t *)data);
    }
}

static void apple_hid_process_spi_packet(const uint8_t *pkt, size_t len) {
    if (len < sizeof(apple_hid_msg_header_t)) return;

    apple_hid_msg_header_t *hdr = (apple_hid_msg_header_t *)pkt;
    const uint8_t *payload = pkt + sizeof(apple_hid_msg_header_t);
    uint16_t payload_len = hdr->length;

    if (sizeof(apple_hid_msg_header_t) + payload_len > len) return;

    switch (hdr->type) {
        case APPLE_HID_REPORT_KEYBOARD:
            apple_hid_process_keyboard(payload, payload_len);
            break;
        case APPLE_HID_REPORT_TOUCHPAD:
            apple_hid_process_touchpad(payload, payload_len);
            break;
        default:
            break;
    }
}

/* ============================================================
 *   Public API
 * ============================================================ */

int apple_hid_init(const fut_platform_info_t *info) {
    if (!info) return -1;

    memset(&g_hid, 0, sizeof(g_hid));

    /* Initialize SPI for keyboard */
    if (info->spi0_base != 0) {
        g_hid.spi = rust_spi_init(info->spi0_base, SPI_HID_PCLK_HZ, 0, SPI_HID_SCLK_HZ);
        if (!g_hid.spi) {
            fut_printf("[HID] Failed to initialize SPI\n");
            return -1;
        }
        g_hid.spi_cs = 0;
        fut_printf("[HID] SPI keyboard initialized at 0x%lx\n",
                   (unsigned long)info->spi0_base);
    }

    /* Initialize I2C for trackpad (if separate from SPI) */
    if (info->i2c0_base != 0) {
        g_hid.i2c = rust_i2c_init(info->i2c0_base);
        if (g_hid.i2c) {
            g_hid.i2c_addr = 0x49;  /* Common Apple trackpad I2C address */
            fut_printf("[HID] I2C trackpad initialized at 0x%lx\n",
                       (unsigned long)info->i2c0_base);
        }
    }

    g_hid.initialized = true;
    fut_printf("[HID] Apple HID input initialized\n");
    return 0;
}

void apple_hid_poll(void) {
    if (!g_hid.initialized) return;

    /* Poll SPI for keyboard/trackpad data */
    if (g_hid.spi) {
        uint8_t rx_buf[SPI_HID_PKT_SIZE];
        memset(rx_buf, 0, sizeof(rx_buf));

        rust_spi_cs_assert((AppleSpi *)g_hid.spi, g_hid.spi_cs);
        int ret = rust_spi_read((AppleSpi *)g_hid.spi, rx_buf, SPI_HID_PKT_SIZE);
        rust_spi_cs_deassert((AppleSpi *)g_hid.spi, g_hid.spi_cs);

        if (ret == 0) {
            /* Check if packet is valid (not all zeros/0xFF) */
            bool valid = false;
            for (int i = 0; i < 8; i++) {
                if (rx_buf[i] != 0x00 && rx_buf[i] != 0xFF) {
                    valid = true;
                    break;
                }
            }
            if (valid) {
                apple_hid_process_spi_packet(rx_buf, SPI_HID_PKT_SIZE);
            }
        }
    }

    /* Poll I2C for trackpad data (if using I2C trackpad) */
    if (g_hid.i2c) {
        uint8_t rx_buf[64];
        int ret = rust_i2c_read((AppleI2c *)g_hid.i2c, g_hid.i2c_addr,
                                 rx_buf, sizeof(rx_buf));
        if (ret == 0 && rx_buf[0] != 0) {
            apple_hid_process_touchpad(rx_buf, sizeof(rx_buf));
        }
    }
}

char apple_hid_getchar(void) {
    if (g_key_head == g_key_tail) return 0;
    char c = g_key_buf[g_key_tail];
    g_key_tail = (g_key_tail + 1) % KEY_BUF_SIZE;
    return c;
}

bool apple_hid_has_key(void) {
    return g_key_head != g_key_tail;
}

void apple_hid_register_key_callback(apple_hid_key_callback_t cb) {
    g_hid.key_cb = cb;
}

void apple_hid_register_touch_callback(apple_hid_touch_callback_t cb) {
    g_hid.touch_cb = cb;
}

int apple_hid_platform_init(const fut_platform_info_t *info) {
    if (!info) return -1;

    /* Only initialize on Apple Silicon */
    if (info->type != PLATFORM_APPLE_M1 &&
        info->type != PLATFORM_APPLE_M2 &&
        info->type != PLATFORM_APPLE_M3 &&
        info->type != PLATFORM_APPLE_M4) {
        return 0;
    }

    if (info->spi0_base == 0 && info->i2c0_base == 0) {
        return 0;  /* No HID hardware found in DTB */
    }

    return apple_hid_init(info);
}
