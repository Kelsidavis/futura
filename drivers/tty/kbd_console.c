// SPDX-License-Identifier: MPL-2.0
/*
 * kbd_console.c - Keyboard to console integration
 *
 * Converts PS/2 scancodes to ASCII characters and feeds them
 * to the console line discipline.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <futura/input_event.h>
#include <kernel/tty.h>

extern void fut_printf(const char *fmt, ...);
extern tty_ldisc_t *kbd_console_get_ldisc(void);

/* Modifier key state */
static struct {
    bool left_shift;
    bool right_shift;
    bool left_ctrl;
    bool right_ctrl;
    bool left_alt;
    bool right_alt;
    bool caps_lock;
    bool num_lock;
} g_modifiers = {0};

/* US QWERTY keymap - scancode to ASCII (unshifted) */
static const char keymap_normal[128] = {
    [0x00] = 0,
    [FUT_KEY_ESC] = 0x1B,       /* Escape */
    [FUT_KEY_1] = '1',
    [FUT_KEY_2] = '2',
    [FUT_KEY_3] = '3',
    [FUT_KEY_4] = '4',
    [FUT_KEY_5] = '5',
    [FUT_KEY_6] = '6',
    [FUT_KEY_7] = '7',
    [FUT_KEY_8] = '8',
    [FUT_KEY_9] = '9',
    [FUT_KEY_0] = '0',
    [FUT_KEY_MINUS] = '-',
    [FUT_KEY_EQUAL] = '=',
    [FUT_KEY_BACKSPACE] = 0x7F, /* DEL */
    [FUT_KEY_TAB] = '\t',
    [FUT_KEY_Q] = 'q',
    [FUT_KEY_W] = 'w',
    [FUT_KEY_E] = 'e',
    [FUT_KEY_R] = 'r',
    [FUT_KEY_T] = 't',
    [FUT_KEY_Y] = 'y',
    [FUT_KEY_U] = 'u',
    [FUT_KEY_I] = 'i',
    [FUT_KEY_O] = 'o',
    [FUT_KEY_P] = 'p',
    [FUT_KEY_LEFTBRACE] = '[',
    [FUT_KEY_RIGHTBRACE] = ']',
    [FUT_KEY_ENTER] = '\n',
    [FUT_KEY_LEFTCTRL] = 0,     /* Modifier */
    [FUT_KEY_A] = 'a',
    [FUT_KEY_S] = 's',
    [FUT_KEY_D] = 'd',
    [FUT_KEY_F] = 'f',
    [FUT_KEY_G] = 'g',
    [FUT_KEY_H] = 'h',
    [FUT_KEY_J] = 'j',
    [FUT_KEY_K] = 'k',
    [FUT_KEY_L] = 'l',
    [FUT_KEY_SEMICOLON] = ';',
    [FUT_KEY_APOSTROPHE] = '\'',
    [FUT_KEY_GRAVE] = '`',
    [FUT_KEY_LEFTSHIFT] = 0,    /* Modifier */
    [FUT_KEY_BACKSLASH] = '\\',
    [FUT_KEY_Z] = 'z',
    [FUT_KEY_X] = 'x',
    [FUT_KEY_C] = 'c',
    [FUT_KEY_V] = 'v',
    [FUT_KEY_B] = 'b',
    [FUT_KEY_N] = 'n',
    [FUT_KEY_M] = 'm',
    [FUT_KEY_COMMA] = ',',
    [FUT_KEY_DOT] = '.',
    [FUT_KEY_SLASH] = '/',
    [FUT_KEY_RIGHTSHIFT] = 0,   /* Modifier */
    [FUT_KEY_KP_ASTERISK] = '*',
    [FUT_KEY_LEFTALT] = 0,      /* Modifier */
    [FUT_KEY_SPACE] = ' ',
    [FUT_KEY_CAPSLOCK] = 0,     /* Toggle */
};

/* US QWERTY keymap - scancode to ASCII (shifted) */
static const char keymap_shifted[128] = {
    [0x00] = 0,
    [FUT_KEY_ESC] = 0x1B,
    [FUT_KEY_1] = '!',
    [FUT_KEY_2] = '@',
    [FUT_KEY_3] = '#',
    [FUT_KEY_4] = '$',
    [FUT_KEY_5] = '%',
    [FUT_KEY_6] = '^',
    [FUT_KEY_7] = '&',
    [FUT_KEY_8] = '*',
    [FUT_KEY_9] = '(',
    [FUT_KEY_0] = ')',
    [FUT_KEY_MINUS] = '_',
    [FUT_KEY_EQUAL] = '+',
    [FUT_KEY_BACKSPACE] = 0x7F,
    [FUT_KEY_TAB] = '\t',
    [FUT_KEY_Q] = 'Q',
    [FUT_KEY_W] = 'W',
    [FUT_KEY_E] = 'E',
    [FUT_KEY_R] = 'R',
    [FUT_KEY_T] = 'T',
    [FUT_KEY_Y] = 'Y',
    [FUT_KEY_U] = 'U',
    [FUT_KEY_I] = 'I',
    [FUT_KEY_O] = 'O',
    [FUT_KEY_P] = 'P',
    [FUT_KEY_LEFTBRACE] = '{',
    [FUT_KEY_RIGHTBRACE] = '}',
    [FUT_KEY_ENTER] = '\n',
    [FUT_KEY_LEFTCTRL] = 0,
    [FUT_KEY_A] = 'A',
    [FUT_KEY_S] = 'S',
    [FUT_KEY_D] = 'D',
    [FUT_KEY_F] = 'F',
    [FUT_KEY_G] = 'G',
    [FUT_KEY_H] = 'H',
    [FUT_KEY_J] = 'J',
    [FUT_KEY_K] = 'K',
    [FUT_KEY_L] = 'L',
    [FUT_KEY_SEMICOLON] = ':',
    [FUT_KEY_APOSTROPHE] = '"',
    [FUT_KEY_GRAVE] = '~',
    [FUT_KEY_LEFTSHIFT] = 0,
    [FUT_KEY_BACKSLASH] = '|',
    [FUT_KEY_Z] = 'Z',
    [FUT_KEY_X] = 'X',
    [FUT_KEY_C] = 'C',
    [FUT_KEY_V] = 'V',
    [FUT_KEY_B] = 'B',
    [FUT_KEY_N] = 'N',
    [FUT_KEY_M] = 'M',
    [FUT_KEY_COMMA] = '<',
    [FUT_KEY_DOT] = '>',
    [FUT_KEY_SLASH] = '?',
    [FUT_KEY_RIGHTSHIFT] = 0,
    [FUT_KEY_KP_ASTERISK] = '*',
    [FUT_KEY_LEFTALT] = 0,
    [FUT_KEY_SPACE] = ' ',
    [FUT_KEY_CAPSLOCK] = 0,
};

/**
 * Check if shift is active (either shift key or caps lock for letters).
 */
static bool is_shifted(void) {
    return g_modifiers.left_shift || g_modifiers.right_shift;
}

/**
 * Check if ctrl is active.
 */
static bool is_ctrl(void) {
    return g_modifiers.left_ctrl || g_modifiers.right_ctrl;
}

/**
 * Check if a character should be uppercased due to caps lock.
 */
static bool caps_affects(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

/**
 * Convert a scancode to an ASCII character.
 *
 * @param scancode PS/2 set 1 scancode
 * @param pressed true if key pressed, false if released
 * @return ASCII character, or 0 if no character (modifier key, etc.)
 */
static char scancode_to_char(uint16_t scancode, bool pressed) {
    /* Handle modifier keys */
    switch (scancode) {
        case FUT_KEY_LEFTSHIFT:
            g_modifiers.left_shift = pressed;
            return 0;
        case FUT_KEY_RIGHTSHIFT:
            g_modifiers.right_shift = pressed;
            return 0;
        case FUT_KEY_LEFTCTRL:
            g_modifiers.left_ctrl = pressed;
            return 0;
        case FUT_KEY_LEFTALT:
            g_modifiers.left_alt = pressed;
            return 0;
        case FUT_KEY_CAPSLOCK:
            if (pressed) {
                g_modifiers.caps_lock = !g_modifiers.caps_lock;
            }
            return 0;
        case FUT_KEY_NUMLOCK:
            if (pressed) {
                g_modifiers.num_lock = !g_modifiers.num_lock;
            }
            return 0;
    }

    /* Only generate characters on key press, not release */
    if (!pressed) {
        return 0;
    }

    /* Bounds check */
    if (scancode >= 128) {
        return 0;
    }

    /* Get base character from keymap */
    char c;
    if (is_shifted()) {
        c = keymap_shifted[scancode];
    } else {
        c = keymap_normal[scancode];
    }

    /* Apply caps lock to letters */
    if (g_modifiers.caps_lock && caps_affects(c)) {
        if (c >= 'a' && c <= 'z') {
            c = c - 'a' + 'A';
        } else if (c >= 'A' && c <= 'Z') {
            c = c - 'A' + 'a';
        }
    }

    /* Handle Ctrl+key combinations */
    if (is_ctrl() && c != 0) {
        if (c >= 'a' && c <= 'z') {
            /* Ctrl+a = 0x01, Ctrl+z = 0x1A */
            c = c - 'a' + 1;
        } else if (c >= 'A' && c <= 'Z') {
            c = c - 'A' + 1;
        } else if (c == '[') {
            c = 0x1B;  /* Escape */
        } else if (c == '\\') {
            c = 0x1C;  /* FS */
        } else if (c == ']') {
            c = 0x1D;  /* GS */
        } else if (c == '^' || c == '6') {
            c = 0x1E;  /* RS */
        } else if (c == '_' || c == '-') {
            c = 0x1F;  /* US */
        } else if (c == ' ' || c == '@' || c == '2') {
            c = 0x00;  /* NUL */
        }
    }

    return c;
}

/**
 * Process a keyboard event and feed it to the console.
 * Called from the keyboard driver's interrupt handler.
 *
 * @param scancode PS/2 set 1 scancode
 * @param pressed true if key pressed, false if released
 */
void kbd_console_handle_key(uint16_t scancode, bool pressed) {
    char c = scancode_to_char(scancode, pressed);

    if (c != 0) {
        tty_ldisc_t *ldisc = kbd_console_get_ldisc();
        if (ldisc) {
            tty_ldisc_input(ldisc, c);
        }
    }
}

/**
 * Initialize keyboard-to-console integration.
 */
void kbd_console_init(void) {
    /* Reset modifier state */
    g_modifiers.left_shift = false;
    g_modifiers.right_shift = false;
    g_modifiers.left_ctrl = false;
    g_modifiers.right_ctrl = false;
    g_modifiers.left_alt = false;
    g_modifiers.right_alt = false;
    g_modifiers.caps_lock = false;
    g_modifiers.num_lock = false;

    fut_printf("[KBD-CONSOLE] Keyboard-to-console integration initialized\n");
}
