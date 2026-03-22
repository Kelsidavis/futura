/* apple_hid.h - Apple SPI/I2C HID Input Driver Header
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Keyboard and trackpad input for Apple Silicon MacBooks.
 * Keyboard uses SPI, trackpad uses SPI or I2C depending on model.
 */

#ifndef __FUTURA_APPLE_HID_H__
#define __FUTURA_APPLE_HID_H__

#include <stdint.h>
#include <stdbool.h>
#include <platform/arm64/dtb.h>

/* HID report types */
#define APPLE_HID_REPORT_KEYBOARD   0x01
#define APPLE_HID_REPORT_TOUCHPAD   0x02

/* SPI HID message header (Apple-specific framing) */
typedef struct {
    uint8_t  type;       /* Report type */
    uint8_t  device;     /* Device ID (0=keyboard, 1=touchpad) */
    uint16_t length;     /* Payload length */
    uint8_t  flags;      /* Message flags */
    uint8_t  seq;        /* Sequence number */
    uint16_t reserved;
} __attribute__((packed)) apple_hid_msg_header_t;

/* Standard USB HID keyboard report (8 bytes) */
typedef struct {
    uint8_t modifiers;     /* Modifier keys bitmask */
    uint8_t reserved;
    uint8_t keycodes[6];   /* Up to 6 simultaneous key presses */
} __attribute__((packed)) apple_hid_keyboard_report_t;

/* Modifier key bits */
#define HID_MOD_LCTRL   (1 << 0)
#define HID_MOD_LSHIFT  (1 << 1)
#define HID_MOD_LALT    (1 << 2)
#define HID_MOD_LGUI    (1 << 3)
#define HID_MOD_RCTRL   (1 << 4)
#define HID_MOD_RSHIFT  (1 << 5)
#define HID_MOD_RALT    (1 << 6)
#define HID_MOD_RGUI    (1 << 7)

/* Touchpad finger tracking */
#define APPLE_HID_MAX_FINGERS  5

typedef struct {
    uint16_t x;
    uint16_t y;
    uint16_t pressure;
    uint8_t  id;         /* Finger tracking ID */
    uint8_t  state;      /* 0=released, 1=touching, 2=hovering */
} apple_hid_touch_point_t;

typedef struct {
    uint8_t  num_fingers;
    uint8_t  button;       /* Physical button state */
    apple_hid_touch_point_t fingers[APPLE_HID_MAX_FINGERS];
} apple_hid_touchpad_report_t;

/* Input event callback types */
typedef void (*apple_hid_key_callback_t)(uint8_t keycode, uint8_t modifiers, bool pressed);
typedef void (*apple_hid_touch_callback_t)(const apple_hid_touchpad_report_t *report);

/* HID controller context */
typedef struct {
    /* SPI handle for keyboard */
    void *spi;
    uint8_t spi_cs;

    /* I2C handle for trackpad (NULL if trackpad is on SPI) */
    void *i2c;
    uint8_t i2c_addr;

    /* State */
    bool initialized;
    uint8_t last_keys[6];
    uint8_t last_modifiers;

    /* Callbacks */
    apple_hid_key_callback_t key_cb;
    apple_hid_touch_callback_t touch_cb;
} apple_hid_ctx_t;

/**
 * Initialize Apple HID input subsystem.
 * @param info: Platform information with SPI/I2C base addresses
 * @return: 0 on success, negative on failure
 */
int apple_hid_init(const fut_platform_info_t *info);

/**
 * Poll for HID input events.
 * Should be called periodically from the kernel main loop or timer IRQ.
 */
void apple_hid_poll(void);

/**
 * Get the last pressed key as an ASCII character.
 * @return: ASCII character, or 0 if no key pressed
 */
char apple_hid_getchar(void);

/**
 * Check if a key is available.
 * @return: true if a key is ready to be read
 */
bool apple_hid_has_key(void);

/**
 * Register keyboard event callback.
 */
void apple_hid_register_key_callback(apple_hid_key_callback_t cb);

/**
 * Register touchpad event callback.
 */
void apple_hid_register_touch_callback(apple_hid_touch_callback_t cb);

/**
 * Platform integration entry point.
 */
int apple_hid_platform_init(const fut_platform_info_t *info);

#endif /* __FUTURA_APPLE_HID_H__ */
