// SPDX-License-Identifier: MPL-2.0
/*
 * input_event.h - Userspace input event ABI
 *
 * The layout is intentionally simple and fixed-size so events can be
 * recorded directly into user buffers without additional marshaling.
 */

#pragma once

#include <stdint.h>

/* Event types */
#define FUT_EV_KEY            1u
#define FUT_EV_MOUSE_MOVE     2u
#define FUT_EV_MOUSE_BTN      3u

/* Relative axes */
#define FUT_REL_X             0
#define FUT_REL_Y             1

/* Mouse buttons */
#define FUT_BTN_LEFT          0x110
#define FUT_BTN_RIGHT         0x111
#define FUT_BTN_MIDDLE        0x112

/* Selected keyboard scancodes (set 1 encoding) */
#define FUT_KEY_ESC           0x01
#define FUT_KEY_1             0x02
#define FUT_KEY_2             0x03
#define FUT_KEY_3             0x04
#define FUT_KEY_4             0x05
#define FUT_KEY_5             0x06
#define FUT_KEY_6             0x07
#define FUT_KEY_7             0x08
#define FUT_KEY_8             0x09
#define FUT_KEY_9             0x0A
#define FUT_KEY_0             0x0B
#define FUT_KEY_MINUS         0x0C
#define FUT_KEY_EQUAL         0x0D
#define FUT_KEY_BACKSPACE     0x0E
#define FUT_KEY_TAB           0x0F
#define FUT_KEY_Q             0x10
#define FUT_KEY_W             0x11
#define FUT_KEY_E             0x12
#define FUT_KEY_R             0x13
#define FUT_KEY_T             0x14
#define FUT_KEY_Y             0x15
#define FUT_KEY_U             0x16
#define FUT_KEY_I             0x17
#define FUT_KEY_O             0x18
#define FUT_KEY_P             0x19
#define FUT_KEY_LEFTBRACE     0x1A
#define FUT_KEY_RIGHTBRACE    0x1B
#define FUT_KEY_ENTER         0x1C
#define FUT_KEY_LEFTCTRL      0x1D
#define FUT_KEY_A             0x1E
#define FUT_KEY_S             0x1F
#define FUT_KEY_D             0x20
#define FUT_KEY_F             0x21
#define FUT_KEY_G             0x22
#define FUT_KEY_H             0x23
#define FUT_KEY_J             0x24
#define FUT_KEY_K             0x25
#define FUT_KEY_L             0x26
#define FUT_KEY_SEMICOLON     0x27
#define FUT_KEY_APOSTROPHE    0x28
#define FUT_KEY_GRAVE         0x29
#define FUT_KEY_LEFTSHIFT     0x2A
#define FUT_KEY_BACKSLASH     0x2B
#define FUT_KEY_Z             0x2C
#define FUT_KEY_X             0x2D
#define FUT_KEY_C             0x2E
#define FUT_KEY_V             0x2F
#define FUT_KEY_B             0x30
#define FUT_KEY_N             0x31
#define FUT_KEY_M             0x32
#define FUT_KEY_COMMA         0x33
#define FUT_KEY_DOT           0x34
#define FUT_KEY_SLASH         0x35
#define FUT_KEY_RIGHTSHIFT    0x36
#define FUT_KEY_KP_ASTERISK   0x37
#define FUT_KEY_LEFTALT       0x38
#define FUT_KEY_SPACE         0x39
#define FUT_KEY_CAPSLOCK      0x3A
#define FUT_KEY_F1            0x3B
#define FUT_KEY_F2            0x3C
#define FUT_KEY_F3            0x3D
#define FUT_KEY_F4            0x3E
#define FUT_KEY_F5            0x3F
#define FUT_KEY_F6            0x40
#define FUT_KEY_F7            0x41
#define FUT_KEY_F8            0x42
#define FUT_KEY_F9            0x43
#define FUT_KEY_F10           0x44
#define FUT_KEY_NUMLOCK       0x45
#define FUT_KEY_SCROLLLOCK    0x46
#define FUT_KEY_F11           0x57
#define FUT_KEY_F12           0x58

/* Extended keys (E0 prefix) */
#define FUT_KEY_RIGHTCTRL     0x1D
#define FUT_KEY_RIGHTALT      0x38
#define FUT_KEY_LEFTMETA      0x5B
#define FUT_KEY_RIGHTMETA     0x5C

struct fut_input_event {
    uint64_t ts_ns;   /* Monotonic timestamp */
    uint16_t type;    /* FUT_EV_* */
    int16_t  code;    /* Key/button/axis code */
    int32_t  value;   /* 1=press, 0=release, delta for move */
};

