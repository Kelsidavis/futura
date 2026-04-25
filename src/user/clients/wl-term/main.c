/* main.c - Wayland terminal emulator
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * A simple terminal emulator that displays a shell in a Wayland window.
 * Uses fork/exec to spawn the shell and pipes for I/O.
 */

#include "terminal.h"
#include "font.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <errno.h>
#include <futura/compat/posix_shm.h>
#include <user/stdio.h>
#include <user/signal.h>
#include <user/sys.h>

#include <wayland-client-core.h>
#include <wayland-client-protocol.h>
#include "xdg-shell-client-protocol.h"

/* Set to 1 to enable verbose wl-term debug logging */
#define WLTERM_DEBUG 0
#if WLTERM_DEBUG
#define WLTERM_LOG(...) printf(__VA_ARGS__)
#else
#define WLTERM_LOG(...) ((void)0)
#endif

/* Inner padding around terminal content (px) */
#define TERM_PAD_X  6
#define TERM_PAD_Y  4

/* Initial terminal window size (80x25 chars + padding) */
#define TERM_WIDTH  (TERM_COLS * FONT_WIDTH + 2 * TERM_PAD_X)
#define TERM_HEIGHT (TERM_ROWS * FONT_HEIGHT + 2 * TERM_PAD_Y)
/* Maximum buffer size (matches TERM_MAX dimensions + padding) */
#define TERM_MAX_WIDTH  (TERM_MAX_COLS * FONT_WIDTH + 2 * TERM_PAD_X)
#define TERM_MAX_HEIGHT (TERM_MAX_ROWS * FONT_HEIGHT + 2 * TERM_PAD_Y)

#define O_RDWR      0x0002
#define O_CREAT     0x0040
#define O_TRUNC     0x0200
#define PROT_READ   0x0001
#define PROT_WRITE  0x0002
#define MAP_SHARED  0x0001

/* Client state */
struct client_state {
    /* Wayland objects */
    struct wl_display *display;
    struct wl_registry *registry;
    struct wl_compositor *compositor;
    struct wl_shm *shm;
    struct xdg_wm_base *xdg_wm_base;
    struct wl_seat *seat;
    struct wl_keyboard *keyboard;
    struct wl_pointer *pointer;
    struct wl_surface *surface;
    struct xdg_surface *xdg_surface;
    struct xdg_toplevel *toplevel;

    /* Configuration state */
    bool configured;
    uint32_t configure_serial;

    /* Frame tracking */
    struct wl_callback *frame_cb;
    bool frame_done;
    bool needs_redraw;

    /* Buffer management */
    void *shm_data;
    size_t shm_size;
    int shm_fd;
    struct wl_shm_pool *pool;
    struct wl_buffer *buffer;

    /* Current pixel dimensions (derived from term cols/rows) */
    int32_t pixel_width;
    int32_t pixel_height;

    /* Terminal emulator */
    struct terminal term;

    /* Running state */
    bool running;
};

/* XDG WM Base listener */
static void handle_ping(void *data, struct xdg_wm_base *wm_base, uint32_t serial) {
    (void)data;
    xdg_wm_base_pong(wm_base, serial);
}

static const struct xdg_wm_base_listener wm_base_listener = {
    .ping = handle_ping,
};

/* XDG Surface listener */
static void xdg_surface_configure(void *data, struct xdg_surface *surface, uint32_t serial) {
    (void)surface;
    struct client_state *state = data;
    state->configure_serial = serial;
    state->configured = true;
}

static const struct xdg_surface_listener xdg_surface_listener = {
    .configure = xdg_surface_configure,
};

/* Recreate wl_buffer at current pixel dimensions from the existing pool */
static void recreate_buffer(struct client_state *state) {
    if (state->buffer) {
        wl_buffer_destroy(state->buffer);
        state->buffer = NULL;
    }
    if (!state->pool) return;

    state->buffer = wl_shm_pool_create_buffer(
        state->pool, 0,
        state->pixel_width, state->pixel_height,
        state->pixel_width * 4, WL_SHM_FORMAT_ARGB8888);
}

/* XDG Toplevel listener */
static void xdg_toplevel_configure(void *data, struct xdg_toplevel *toplevel,
                                   int32_t width, int32_t height, struct wl_array *states) {
    (void)toplevel; (void)states;
    struct client_state *state = data;

    if (width <= 0 || height <= 0) {
        /* 0,0 means "client decides" — keep current size */
        return;
    }

    /* Compute new grid dimensions from pixel size (subtract padding) */
    int new_cols = (width - 2 * TERM_PAD_X) / FONT_WIDTH;
    int new_rows = (height - 2 * TERM_PAD_Y) / FONT_HEIGHT;
    if (new_cols < 1) new_cols = 1;
    if (new_rows < 1) new_rows = 1;
    if (new_cols > TERM_MAX_COLS) new_cols = TERM_MAX_COLS;
    if (new_rows > TERM_MAX_ROWS) new_rows = TERM_MAX_ROWS;

    if (new_cols == state->term.cols && new_rows == state->term.rows) {
        state->needs_redraw = true;
        return;
    }

    /* Resize the terminal grid */
    term_resize(&state->term, new_cols, new_rows);

    /* Update pixel dimensions to match grid (snap to char boundaries + padding) */
    state->pixel_width = new_cols * FONT_WIDTH + 2 * TERM_PAD_X;
    state->pixel_height = new_rows * FONT_HEIGHT + 2 * TERM_PAD_Y;

    /* Recreate buffer at new size */
    recreate_buffer(state);

    /* Update PTY window size so shell knows about new dimensions */
    if (state->term.shell_stdin_fd >= 0) {
        struct { unsigned short ws_row, ws_col, ws_xpixel, ws_ypixel; } wsz;
        wsz.ws_row = (unsigned short)new_rows;
        wsz.ws_col = (unsigned short)new_cols;
        wsz.ws_xpixel = (unsigned short)state->pixel_width;
        wsz.ws_ypixel = (unsigned short)state->pixel_height;
        sys_ioctl(state->term.shell_stdin_fd, 0x5414 /* TIOCSWINSZ */, (long)&wsz);
    }

    state->needs_redraw = true;
}

static void xdg_toplevel_close(void *data, struct xdg_toplevel *toplevel) {
    (void)toplevel;
    struct client_state *state = data;
    state->running = false;
}

static const struct xdg_toplevel_listener xdg_toplevel_listener = {
    .configure = xdg_toplevel_configure,
    .close = xdg_toplevel_close,
};

/* Keyboard listener */
static void keyboard_keymap(void *data, struct wl_keyboard *keyboard,
                           uint32_t format, int32_t fd, uint32_t size) {
    (void)data; (void)keyboard; (void)format; (void)size;
    if (fd >= 0) {
        sys_close(fd);
    }
}

static void keyboard_enter(void *data, struct wl_keyboard *keyboard, uint32_t serial,
                          struct wl_surface *surface, struct wl_array *keys) {
    (void)data; (void)keyboard; (void)serial; (void)surface; (void)keys;
}

static uint32_t repeat_key;  /* forward decl — defined with repeat state below */

static void keyboard_leave(void *data, struct wl_keyboard *keyboard, uint32_t serial,
                          struct wl_surface *surface) {
    (void)data; (void)keyboard; (void)serial; (void)surface;
    /* Stop key repeat when focus is lost — otherwise a held key
     * would keep repeating when focus returns. */
    repeat_key = 0;
}

/* Simple keycode to ASCII mapping (US keyboard layout) */
static char keycode_to_ascii(uint32_t key, bool shift) {
    /* Evdev keycodes - simplified mapping */
    if (key >= 2 && key <= 11) {  /* Number row */
        if (!shift) {
            const char nums[] = "1234567890";
            return nums[key - 2];
        } else {
            const char syms[] = "!@#$%^&*()";
            return syms[key - 2];
        }
    }

    if (key >= 16 && key <= 25) {  /* QWERTYUIOP */
        const char keys[] = "qwertyuiop";
        char ch = keys[key - 16];
        return shift ? (ch - 32) : ch;
    }

    if (key >= 30 && key <= 38) {  /* ASDFGHJKL */
        const char keys[] = "asdfghjkl";
        char ch = keys[key - 30];
        return shift ? (ch - 32) : ch;
    }

    if (key >= 44 && key <= 50) {  /* ZXCVBNM */
        const char keys[] = "zxcvbnm";
        char ch = keys[key - 44];
        return shift ? (ch - 32) : ch;
    }

    switch (key) {
        case 28: return '\n';       /* Enter */
        case 57: return ' ';        /* Space */
        case 14: return '\b';       /* Backspace */
        case 15: return '\t';       /* Tab */
        case 12: return shift ? '_' : '-';  /* Minus */
        case 13: return shift ? '+' : '=';  /* Equals */
        case 26: return shift ? '{' : '[';  /* Left bracket */
        case 27: return shift ? '}' : ']';  /* Right bracket */
        case 39: return shift ? ':' : ';';  /* Semicolon */
        case 40: return shift ? '"' : '\''; /* Quote */
        case 41: return shift ? '~' : '`';  /* Backtick */
        case 43: return shift ? '|' : '\\'; /* Backslash */
        case 51: return shift ? '<' : ',';  /* Comma */
        case 52: return shift ? '>' : '.';  /* Period */
        case 53: return shift ? '?' : '/';  /* Slash */
        default: return 0;
    }
}

static uint32_t kbd_mods_depressed = 0;  /* Track modifier state */
static uint64_t tick_ms = 0;             /* Monotonic tick counter (~10ms per iteration) */

/* Key repeat state */
static uint32_t repeat_key = 0;          /* Currently held key (0 = none) */
static uint64_t repeat_deadline_ms = 0;  /* When next repeat fires */
static uint64_t repeat_start_ms = 0;     /* When current repeat started */
#define REPEAT_DELAY_MS   500
#define REPEAT_INTERVAL_MS 33  /* ~30 chars/sec */
#define REPEAT_MAX_MS     2000 /* Safety: auto-clear repeat after 2s */

/* Forward declaration — processes a single keypress */
static void process_key(struct client_state *state, uint32_t key);

static void keyboard_key(void *data, struct wl_keyboard *keyboard, uint32_t serial,
                        uint32_t time, uint32_t key, uint32_t key_state) {
    (void)keyboard; (void)serial; (void)time;

    struct client_state *state = data;
    if (!state) return;

    if (key_state == WL_KEYBOARD_KEY_STATE_RELEASED) {
        if (key == repeat_key) repeat_key = 0;  /* Stop repeating */
        return;
    }

    /* Key pressed — process it and start repeat timer */
    process_key(state, key);

    /* Modifier keys (shift, ctrl, alt) don't repeat. Also skip repeat when
     * ctrl/alt is held: otherwise releasing the modifier while still holding
     * the key would re-fire process_key without it (e.g. Ctrl+C → literal 'c'
     * spam to the shell once Ctrl is released). */
    bool ctrl_or_alt = (kbd_mods_depressed & 0xCu) != 0;
    if (ctrl_or_alt ||
        key == 42 || key == 54 || key == 29 || key == 97 ||
        key == 56 || key == 100) {
        repeat_key = 0;
    } else {
        repeat_key = key;
        repeat_deadline_ms = tick_ms + REPEAT_DELAY_MS;
        repeat_start_ms = tick_ms;
    }
}

static void process_key(struct client_state *state, uint32_t key) {
    bool shift = (kbd_mods_depressed & 1) != 0;

    /* Shift+PageUp/PageDown: scroll through scrollback history.
     * These are the only keys that should *not* return the user to the
     * live view, since they're how the user navigates scrollback. */
    if (shift && key == 104) {  /* PageUp (evdev keycode) */
        term_scroll_view(&state->term, 5);
        state->needs_redraw = true;
        return;
    }
    if (shift && key == 109) {  /* PageDown */
        term_scroll_view(&state->term, -5);
        state->needs_redraw = true;
        return;
    }

    /* Any other keypress sends input to the shell — pop back to the live
     * view first so the user can see what they're typing. Previously the
     * arrow / Home / End / Delete / Ctrl handlers below all returned
     * before the scroll reset, so typing in scrollback view stayed in
     * scrollback and the user typed blind. */
    term_scroll_to_bottom(&state->term);

    /* Arrow keys: send VT100 escape sequences to shell */
    if (key == 103) { term_send_key(&state->term, '\033'); term_send_key(&state->term, '['); term_send_key(&state->term, 'A'); state->needs_redraw = true; return; } /* Up */
    if (key == 108) { term_send_key(&state->term, '\033'); term_send_key(&state->term, '['); term_send_key(&state->term, 'B'); state->needs_redraw = true; return; } /* Down */
    if (key == 106) { term_send_key(&state->term, '\033'); term_send_key(&state->term, '['); term_send_key(&state->term, 'C'); state->needs_redraw = true; return; } /* Right */
    if (key == 105) { term_send_key(&state->term, '\033'); term_send_key(&state->term, '['); term_send_key(&state->term, 'D'); state->needs_redraw = true; return; } /* Left */
    /* Home/End */
    if (key == 102) { term_send_key(&state->term, '\033'); term_send_key(&state->term, '['); term_send_key(&state->term, 'H'); state->needs_redraw = true; return; }
    if (key == 107) { term_send_key(&state->term, '\033'); term_send_key(&state->term, '['); term_send_key(&state->term, 'F'); state->needs_redraw = true; return; }
    /* Insert / Delete */
    if (key == 110) { term_send_key(&state->term, '\033'); term_send_key(&state->term, '['); term_send_key(&state->term, '2'); term_send_key(&state->term, '~'); state->needs_redraw = true; return; }
    if (key == 111) { term_send_key(&state->term, '\033'); term_send_key(&state->term, '['); term_send_key(&state->term, '3'); term_send_key(&state->term, '~'); state->needs_redraw = true; return; }
    /* PageUp / PageDown — Shift+PgUp/PgDn is consumed above for scrollback;
     * plain PgUp/PgDn forwards the xterm escape so less, vim, etc. can
     * page through their own buffers. Without these wl-term silently
     * dropped the keys. */
    if (key == 104) { term_send_key(&state->term, '\033'); term_send_key(&state->term, '['); term_send_key(&state->term, '5'); term_send_key(&state->term, '~'); state->needs_redraw = true; return; }
    if (key == 109) { term_send_key(&state->term, '\033'); term_send_key(&state->term, '['); term_send_key(&state->term, '6'); term_send_key(&state->term, '~'); state->needs_redraw = true; return; }

    /* F1-F12 — xterm convention. F11 is intercepted by the compositor
     * for fullscreen toggle, so it never reaches us; the rest are
     * forwarded. F1-F4 use the SS3 form (ESC O <letter>); F5-F12 use
     * the CSI form (ESC [ <n> ~). */
    {
        const char *seq = NULL;
        switch (key) {
            case 59: seq = "\033OP";   break; /* F1 */
            case 60: seq = "\033OQ";   break; /* F2 */
            case 61: seq = "\033OR";   break; /* F3 */
            case 62: seq = "\033OS";   break; /* F4 */
            case 63: seq = "\033[15~"; break; /* F5 */
            case 64: seq = "\033[17~"; break; /* F6 */
            case 65: seq = "\033[18~"; break; /* F7 */
            case 66: seq = "\033[19~"; break; /* F8 */
            case 67: seq = "\033[20~"; break; /* F9 */
            case 68: seq = "\033[21~"; break; /* F10 */
            case 88: seq = "\033[24~"; break; /* F12 */
            default: break;
        }
        if (seq) {
            for (const char *p = seq; *p; p++) term_send_key(&state->term, *p);
            state->needs_redraw = true;
            return;
        }
    }

    bool ctrl = (kbd_mods_depressed & 4) != 0;  /* Ctrl modifier */

    /* Ctrl+key: send control characters (Ctrl+C=0x03, Ctrl+D=0x04, etc.)
     * The PTY line discipline converts these to signals (SIGINT, EOF, etc.) */
    if (ctrl) {
        char ch = keycode_to_ascii(key, false);
        if (ch >= 'a' && ch <= 'z') {
            term_send_key(&state->term, (char)(ch - 'a' + 1));
            state->needs_redraw = true;
            return;
        }
        /* Ctrl+[ = ESC (0x1B), Ctrl+\ = 0x1C (SIGQUIT) */
        if (key == 26) { term_send_key(&state->term, 0x1B); state->needs_redraw = true; return; }  /* [ */
        if (key == 43) { term_send_key(&state->term, 0x1C); state->needs_redraw = true; return; }  /* \ */
    }

    /* Tab key — Shift+Tab sends the back-tab sequence ESC[Z that
     * readline / less / fzf / emacs use for reverse completion. Plain
     * Tab still sends a literal '\t'. */
    if (key == 15) {
        if (shift) {
            term_send_key(&state->term, '\033');
            term_send_key(&state->term, '[');
            term_send_key(&state->term, 'Z');
        } else {
            term_send_key(&state->term, '\t');
        }
        state->needs_redraw = true;
        return;
    }
    /* Backspace */
    if (key == 14) { term_send_key(&state->term, 0x7F); state->needs_redraw = true; return; }
    /* Escape */
    if (key == 1) { term_send_key(&state->term, 0x1B); state->needs_redraw = true; return; }

    /* Convert keycode to ASCII */
    char ch = keycode_to_ascii(key, shift);
    if (ch != 0) {
        /* Alt+letter is the ESC+letter convention used by readline,
         * vim, emacs, and friends (Alt+b for word-back, Alt+. etc.).
         * Without this, Alt-modified keystrokes were silently dropped. */
        bool alt = (kbd_mods_depressed & 8) != 0;
        if (alt) {
            term_send_key(&state->term, 0x1B);
        }
        term_send_key(&state->term, ch);
        state->needs_redraw = true;
    }
}

static void keyboard_modifiers(void *data, struct wl_keyboard *keyboard, uint32_t serial,
                              uint32_t mods_depressed, uint32_t mods_latched,
                              uint32_t mods_locked, uint32_t group) {
    (void)data; (void)keyboard; (void)serial;
    (void)mods_latched; (void)mods_locked; (void)group;
    kbd_mods_depressed = mods_depressed;
}

static void keyboard_repeat(void *data, struct wl_keyboard *keyboard,
                           int32_t rate, int32_t delay) {
    (void)data; (void)keyboard; (void)rate; (void)delay;
}

static const struct wl_keyboard_listener keyboard_listener = {
    .keymap = keyboard_keymap,
    .enter = keyboard_enter,
    .leave = keyboard_leave,
    .key = keyboard_key,
    .modifiers = keyboard_modifiers,
    .repeat_info = keyboard_repeat,
};

/* Pointer (mouse) listener — used for scroll wheel scrollback */
static void pointer_enter(void *data, struct wl_pointer *pointer, uint32_t serial,
                         struct wl_surface *surface, wl_fixed_t sx, wl_fixed_t sy) {
    (void)data; (void)pointer; (void)serial; (void)surface; (void)sx; (void)sy;
}

static void pointer_leave(void *data, struct wl_pointer *pointer, uint32_t serial,
                         struct wl_surface *surface) {
    (void)data; (void)pointer; (void)serial; (void)surface;
}

static void pointer_motion(void *data, struct wl_pointer *pointer, uint32_t time,
                          wl_fixed_t sx, wl_fixed_t sy) {
    (void)data; (void)pointer; (void)time; (void)sx; (void)sy;
}

static void pointer_button(void *data, struct wl_pointer *pointer, uint32_t serial,
                          uint32_t time, uint32_t button, uint32_t button_state) {
    (void)data; (void)pointer; (void)serial; (void)time; (void)button; (void)button_state;
}

static void pointer_axis(void *data, struct wl_pointer *pointer, uint32_t time,
                        uint32_t axis, wl_fixed_t value) {
    (void)pointer; (void)time;
    struct client_state *state = data;
    if (!state) return;

    /* axis 0 = vertical scroll.  Positive value = scroll down, negative = scroll up.
     * wl_fixed_t is 24.8 fixed point; divide by 256 to get integer pixels,
     * then convert to lines (each scroll notch is typically +-10.0 = 2560). */
    if (axis == 0) {
        int scroll_pixels = wl_fixed_to_int(value);
        /* Each "notch" of the scroll wheel is about 10 pixels worth.
         * Scroll 3 lines per notch for comfortable reading. */
        int lines = 0;
        if (scroll_pixels < 0) {
            lines = 3;   /* Scroll wheel up: view older history */
        } else if (scroll_pixels > 0) {
            lines = -3;  /* Scroll wheel down: view newer content */
        }
        if (lines != 0) {
            term_scroll_view(&state->term, lines);
            state->needs_redraw = true;
        }
    }
}

static void pointer_frame(void *data, struct wl_pointer *pointer) {
    (void)data; (void)pointer;
}

static void pointer_axis_source(void *data, struct wl_pointer *pointer, uint32_t axis_source) {
    (void)data; (void)pointer; (void)axis_source;
}

static void pointer_axis_stop(void *data, struct wl_pointer *pointer,
                              uint32_t time, uint32_t axis) {
    (void)data; (void)pointer; (void)time; (void)axis;
}

static void pointer_axis_discrete(void *data, struct wl_pointer *pointer,
                                  uint32_t axis, int32_t discrete) {
    (void)data; (void)pointer; (void)axis; (void)discrete;
}

static const struct wl_pointer_listener pointer_listener = {
    .enter = pointer_enter,
    .leave = pointer_leave,
    .motion = pointer_motion,
    .button = pointer_button,
    .axis = pointer_axis,
    .frame = pointer_frame,
    .axis_source = pointer_axis_source,
    .axis_stop = pointer_axis_stop,
    .axis_discrete = pointer_axis_discrete,
};

/* Seat listener */
static void seat_capabilities(void *data, struct wl_seat *seat, uint32_t capabilities) {
    struct client_state *state = data;
    if (!state) {
        return;
    }

    bool want_keyboard = (capabilities & WL_SEAT_CAPABILITY_KEYBOARD) != 0;
    if (want_keyboard && !state->keyboard) {
        state->keyboard = wl_seat_get_keyboard(seat);
        if (state->keyboard) {
            wl_keyboard_add_listener(state->keyboard, &keyboard_listener, state);
        }
    } else if (!want_keyboard && state->keyboard) {
        wl_keyboard_destroy(state->keyboard);
        state->keyboard = NULL;
    }

    bool want_pointer = (capabilities & WL_SEAT_CAPABILITY_POINTER) != 0;
    if (want_pointer && !state->pointer) {
        state->pointer = wl_seat_get_pointer(seat);
        if (state->pointer) {
            wl_pointer_add_listener(state->pointer, &pointer_listener, state);
        }
    } else if (!want_pointer && state->pointer) {
        wl_pointer_destroy(state->pointer);
        state->pointer = NULL;
    }
}

static void seat_name(void *data, struct wl_seat *seat, const char *name) {
    (void)data; (void)seat; (void)name;
}

static const struct wl_seat_listener seat_listener = {
    .capabilities = seat_capabilities,
    .name = seat_name,
};

/* Registry listener */
static void registry_global(void *data, struct wl_registry *registry, uint32_t name,
                           const char *interface, uint32_t version) {
    struct client_state *state = data;

    WLTERM_LOG("[WL-TERM-REGISTRY] Global advertised: name=%u interface=%s version=%u\n",
               name, interface, version);

    if (strcmp(interface, wl_compositor_interface.name) == 0) {
        uint32_t ver = version < 4 ? version : 4;
        state->compositor = wl_registry_bind(registry, name, &wl_compositor_interface, ver);
        WLTERM_LOG("[WL-TERM-REGISTRY] Bound wl_compositor: %p\n", state->compositor);
    } else if (strcmp(interface, wl_shm_interface.name) == 0) {
        state->shm = wl_registry_bind(registry, name, &wl_shm_interface, 1);
        WLTERM_LOG("[WL-TERM-REGISTRY] Bound wl_shm: %p\n", state->shm);
    } else if (strcmp(interface, xdg_wm_base_interface.name) == 0) {
        uint32_t ver = version < 2 ? version : 2;
        state->xdg_wm_base = wl_registry_bind(registry, name, &xdg_wm_base_interface, ver);
        WLTERM_LOG("[WL-TERM-REGISTRY] Bound xdg_wm_base: %p\n", state->xdg_wm_base);
        xdg_wm_base_add_listener(state->xdg_wm_base, &wm_base_listener, state);
    } else if (strcmp(interface, wl_seat_interface.name) == 0) {
        uint32_t ver = version < 7 ? version : 7;
        state->seat = wl_registry_bind(registry, name, &wl_seat_interface, ver);
        if (state->seat) {
            wl_seat_add_listener(state->seat, &seat_listener, state);
        }
        WLTERM_LOG("[WL-TERM-REGISTRY] Bound wl_seat: %p\n", state->seat);
    } else {
        WLTERM_LOG("[WL-TERM-REGISTRY] Unknown global: %s\n", interface);
    }
}

static void registry_global_remove(void *data, struct wl_registry *registry, uint32_t name) {
    (void)data; (void)registry; (void)name;
}

static const struct wl_registry_listener registry_listener = {
    .global = registry_global,
    .global_remove = registry_global_remove,
};

/* Frame callback */
static void frame_done(void *data, struct wl_callback *callback, uint32_t time) {
    (void)time;
    struct client_state *state = data;
    state->frame_done = true;
    /* Only destroy if this is still our current callback.  If the timeout
     * already superseded it (frame_cb == NULL or points to a newer cb),
     * the callback was either already destroyed or will be cleaned up
     * in the next redraw(). */
    if (state->frame_cb == callback) {
        wl_callback_destroy(callback);
        state->frame_cb = NULL;
    }
}

static const struct wl_callback_listener frame_listener = {
    .done = frame_done,
};

/* Spawn shell process connected to terminal via PTY.
 * Uses /dev/ptmx (Unix98 PTY) so the shell sees a real terminal:
 * - isatty() returns true
 * - Terminal line discipline (Ctrl+C → SIGINT, Ctrl+Z → SIGTSTP)
 * - TIOCGWINSZ reports terminal dimensions
 * - Job control works (fg, bg, jobs)
 */
static int spawn_shell(struct terminal *term) {
    term->shell_stdin_fd = -1;
    term->shell_stdout_fd = -1;
    term->shell_pid = -1;

    /* Open PTY master */
    int master_fd = sys_open("/dev/ptmx", 2 /* O_RDWR */, 0);
    if (master_fd < 0) {
        /* Fallback: try pipes if PTY not available */
        const char *msg = "Welcome to Futura OS Terminal\n"
                          "[PTY unavailable, using pipes]\n";
        while (*msg) { term_putchar(term, (unsigned char)*msg); msg++; }

        int stdin_pipe[2] = { -1, -1 }, stdout_pipe[2] = { -1, -1 };
        if (sys_pipe_call(stdin_pipe) < 0) return -1;
        if (sys_pipe_call(stdout_pipe) < 0) {
            sys_close(stdin_pipe[0]); sys_close(stdin_pipe[1]);
            return -1;
        }
        long pid = sys_fork_call();
        if (pid < 0) {
            sys_close(stdin_pipe[0]); sys_close(stdin_pipe[1]);
            sys_close(stdout_pipe[0]); sys_close(stdout_pipe[1]);
            return -1;
        }
        if (pid == 0) {
            sys_close(stdin_pipe[1]); sys_close(stdout_pipe[0]);
            sys_close(0); sys_close(1); sys_close(2);
            sys_dup2_call(stdin_pipe[0], 0);
            sys_dup2_call(stdout_pipe[1], 1);
            sys_dup2_call(stdout_pipe[1], 2);
            sys_close(stdin_pipe[0]); sys_close(stdout_pipe[1]);
            char *argv[] = { "/bin/shell", (void*)0 };
            sys_execve_call("/bin/shell", argv, (void*)0);
            sys_exit(127);
        }
        sys_close(stdin_pipe[0]); sys_close(stdout_pipe[1]);
        term->shell_stdin_fd = stdin_pipe[1];
        term->shell_stdout_fd = stdout_pipe[0];
        sys_fcntl_call(stdout_pipe[0], 4, 0x0800);
        term->shell_pid = (int)pid;
        return 0;
    }

    /* Unlock slave PTY */
    int unlock_val = 0;
    sys_ioctl(master_fd, 0x40045431 /* TIOCSPTLCK */, (long)&unlock_val);

    /* Get slave PTY number */
    int slave_num = -1;
    if (sys_ioctl(master_fd, 0x80045430 /* TIOCGPTN */, (long)&slave_num) < 0 ||
        slave_num < 0) {
        /* TIOCGPTN failed (or returned a bogus number). Without a valid
         * slave path the spawn would build "/dev/pts//" or worse. Close
         * the master and let the caller fall back to pipes. */
        sys_close(master_fd);
        return -1;
    }

    /* Build slave path: /dev/pts/<n>. Handle any number of digits — the
     * old chain stopped at hundreds, so a slave_num of 1234 produced
     * "/dev/pts/234". */
    char slave_path[32];
    slave_path[0]='/'; slave_path[1]='d'; slave_path[2]='e'; slave_path[3]='v';
    slave_path[4]='/'; slave_path[5]='p'; slave_path[6]='t'; slave_path[7]='s';
    slave_path[8]='/';
    int sp = 9;
    {
        char digits[12];
        int nd = 0;
        int n = slave_num;
        if (n == 0) { digits[nd++] = '0'; }
        else { while (n > 0 && nd < (int)sizeof(digits)) { digits[nd++] = '0' + (char)(n % 10); n /= 10; } }
        for (int i = nd - 1; i >= 0 && sp < (int)sizeof(slave_path) - 1; i--) {
            slave_path[sp++] = digits[i];
        }
    }
    slave_path[sp] = '\0';

    /* Enable ECHO and line-editing flags for the terminal.
     * Default termios has ECHO off to avoid test pollution; real terminals
     * need it so keystrokes are displayed. */
    {
        char tios[60];
        if (sys_ioctl(master_fd, 0x5401 /* TCGETS */, (long)tios) == 0) {
            unsigned int lf;
            for (int i = 0; i < 4; i++) ((char*)&lf)[i] = tios[12+i];
            lf |= 0x0008 | 0x0010 | 0x0020 | 0x0200 | 0x0800;
            /* ECHO | ECHOE | ECHOK | ECHOCTL | ECHOKE */
            for (int i = 0; i < 4; i++) tios[12+i] = ((char*)&lf)[i];
            sys_ioctl(master_fd, 0x5402 /* TCSETS */, (long)tios);
        }
    }

    /* Set terminal size on PTY */
    struct { unsigned short ws_row, ws_col, ws_xpixel, ws_ypixel; } wsz;
    wsz.ws_row = TERM_ROWS;
    wsz.ws_col = TERM_COLS;
    wsz.ws_xpixel = TERM_COLS * 8;
    wsz.ws_ypixel = TERM_ROWS * 16;
    sys_ioctl(master_fd, 0x5414 /* TIOCSWINSZ */, (long)&wsz);

    long pid = sys_fork_call();
    if (pid < 0) {
        sys_close(master_fd);
        return -1;
    }

    if (pid == 0) {
        /* Child: open slave PTY as stdin/stdout/stderr */
        sys_close(master_fd);

        /* Create new session so child becomes session leader */
        sys_call1(112 /* setsid */, 0);

        int slave_fd = sys_open(slave_path, 2 /* O_RDWR */, 0);
        if (slave_fd < 0) sys_exit(126);

        /* Set controlling terminal */
        sys_ioctl(slave_fd, 0x540E /* TIOCSCTTY */, 0);

        /* Redirect stdio to slave PTY */
        sys_close(0); sys_close(1); sys_close(2);
        sys_dup2_call(slave_fd, 0);
        sys_dup2_call(slave_fd, 1);
        sys_dup2_call(slave_fd, 2);
        if (slave_fd > 2) sys_close(slave_fd);

        /* Set TERM environment variable */
        char *argv[] = { "/bin/shell", (void*)0 };
        char *envp[] = { "TERM=xterm-256color", "HOME=/", (void*)0 };
        sys_execve_call("/bin/shell", argv, envp);
        sys_exit(127);
    }

    /* Parent: master fd is our I/O endpoint */
    term->shell_stdin_fd = master_fd;    /* Write to master → appears on slave stdin */
    term->shell_stdout_fd = master_fd;   /* Read from master ← slave stdout output */

    /* Set master to non-blocking */
    sys_fcntl_call(master_fd, 4 /*F_SETFL*/, 0x0800 /*O_NONBLOCK*/);
    term->shell_pid = (int)pid;

    return 0;
}

/* Render terminal to buffer and request frame */
static void redraw(struct client_state *state) {
    if (!state->buffer || !state->shm_data) {
        return;
    }

    /* Defensive check: reject suspiciously low pointer values (likely corruption) */
    if ((uintptr_t)state->shm_data < 0x10000) {
        return;
    }

    /* Render terminal to pixel buffer */
    uint32_t *pixels = (uint32_t *)state->shm_data;
    term_render(&state->term, pixels, state->pixel_width, state->pixel_height, state->pixel_width,
                TERM_PAD_X, TERM_PAD_Y);

    /* Destroy any old frame callback that was superseded by timeout */
    if (state->frame_cb) {
        wl_callback_destroy(state->frame_cb);
        state->frame_cb = NULL;
    }

    /* Request frame callback */
    state->frame_done = false;
    state->frame_cb = wl_surface_frame(state->surface);
    if (!state->frame_cb) {
        /* Allocation failure — render without callback, retry next tick */
        state->frame_done = true;
    } else {
        wl_callback_add_listener(state->frame_cb, &frame_listener, state);
    }

    /* Commit surface */
    wl_surface_attach(state->surface, state->buffer, 0, 0);
    wl_surface_damage_buffer(state->surface, 0, 0, state->pixel_width, state->pixel_height);
    wl_surface_commit(state->surface);
    wl_display_flush(state->display);

    state->needs_redraw = false;
}

/* Frame callback timeout: if the compositor stops sending frame callbacks
 * (e.g., surface not in damage region), force a redraw to prevent freeze. */
static int frame_wait_ticks = 0;
#define FRAME_TIMEOUT_TICKS 50  /* ~500ms at 10ms/iteration */

/* Main loop iteration */
static bool main_loop_iteration(struct client_state *state) {
    tick_ms += 10;  /* Each iteration is ~10ms (matches nanosleep below) */

    /* Drain all available shell output before rendering.
     * Reading in a loop avoids thousands of render cycles when the shell
     * dumps large output (e.g., "help" with 620+ commands).  Cap at 16
     * reads (~4KB) per iteration to keep the main loop responsive. */
    {
        int total = 0, reads = 0;
        const int max_reads = 16;
        while (reads < max_reads) {
            int n = term_read_shell(&state->term);
            if (n > 0) {
                total += n;
                reads++;
            } else if (n < 0) {
                WLTERM_LOG("[WL-TERM] Shell exited\n");
                return false;
            } else {
                break;  /* No more data available */
            }
        }
        if (total > 0) {
            state->needs_redraw = true;
            state->term.cursor_blink_on = true;
            state->term.cursor_blink_time = tick_ms;
        }
    }

    /* Update cursor blink */
    if (term_update_blink(&state->term, tick_ms)) {
        state->needs_redraw = true;
    }

    /* Key repeat: if a key is held, re-fire it after delay.
     * Safety: auto-clear repeat after REPEAT_MAX_MS to prevent stuck keys
     * (e.g., if a key release event is lost over the Wayland connection). */
    if (repeat_key != 0) {
        if (tick_ms - repeat_start_ms > REPEAT_MAX_MS) {
            repeat_key = 0;  /* Safety timeout — stop repeating */
        } else if (tick_ms >= repeat_deadline_ms) {
            process_key(state, repeat_key);
            repeat_deadline_ms = tick_ms + REPEAT_INTERVAL_MS;
        }
    }

    /* Ack any pending configure from the compositor (fullscreen, maximize, etc.) */
    if (state->configured && state->configure_serial != 0) {
        xdg_surface_ack_configure(state->xdg_surface, state->configure_serial);
        state->configured = false;
        state->needs_redraw = true;
    }

    /* Check if shell set a new window title via OSC 0/2 */
    if (state->term.title_changed && state->toplevel) {
        xdg_toplevel_set_title(state->toplevel, term_get_title(&state->term));
        state->term.title_changed = false;
        wl_surface_commit(state->surface);
    }

    /* Frame callback timeout: if compositor hasn't sent frame done in
     * FRAME_TIMEOUT_TICKS iterations, force it so we don't freeze.
     * Do NOT destroy frame_cb here — the done event may still arrive
     * later and calling wl_callback_destroy twice is undefined behavior.
     * The old callback will be cleaned up in the next redraw(). */
    if (!state->frame_done) {
        frame_wait_ticks++;
        if (frame_wait_ticks >= FRAME_TIMEOUT_TICKS) {
            state->frame_done = true;
            frame_wait_ticks = 0;
        }
    } else {
        frame_wait_ticks = 0;
    }

    /* Redraw if needed and frame is ready */
    if (state->needs_redraw && state->frame_done) {
        redraw(state);
    }

    /* Process Wayland events.
     *
     * Futura poll() is a stub, so we use non-blocking I/O with
     * prepare_read/read_events instead of blocking dispatch.
     *
     * Error handling: treat ALL errors as transient and retry.
     * Futura's socket implementation can produce transient errors
     * (e.g., buffer contention, scheduler timing) that don't mean
     * the connection is truly dead.  Only exit on persistent failure
     * (wl_display_get_error reports a protocol error). */
    wl_display_flush(state->display);
    {
        int prep_retries = 0;
        while (wl_display_prepare_read(state->display) != 0) {
            wl_display_dispatch_pending(state->display);
            if (++prep_retries > 1000) break;
        }
        if (prep_retries <= 1000) {
            wl_display_read_events(state->display);
        }
    }
    wl_display_dispatch_pending(state->display);

    return state->running;
}

int main(void) {
    /* Ignore SIGPIPE so broken pipes return errors instead of killing us */
    {
        struct sigaction sa = {0};
        sa.sa_handler = SIG_IGN;
        sigaction(SIGPIPE, &sa, NULL);
        (void)sa;
    }

    WLTERM_LOG("[WL-TERM] Starting...\n");
    struct client_state state = {0};
    state.running = true;
    state.frame_done = true;

    WLTERM_LOG("[WL-TERM] Initializing terminal...\n");
    /* Initialize terminal */
    term_init(&state.term);

    WLTERM_LOG("[WL-TERM] Connecting to Wayland display...\n");
    /* Connect to Wayland display */
    state.display = wl_display_connect(NULL);
    if (!state.display) {
        WLTERM_LOG("[WL-TERM] Failed to connect to Wayland\n");
        return -1;
    }
    WLTERM_LOG("[WL-TERM] Connected to Wayland!\n");

    /* Get registry and bind globals (blocking roundtrip — standard Wayland init) */
    WLTERM_LOG("[WL-TERM] Getting registry...\n");
    state.registry = wl_display_get_registry(state.display);
    wl_registry_add_listener(state.registry, &registry_listener, &state);
    wl_display_roundtrip(state.display);
    WLTERM_LOG("[WL-TERM] After roundtrip: compositor=%p shm=%p xdg_wm_base=%p\n",
           state.compositor, state.shm, state.xdg_wm_base);

    if (!state.compositor || !state.shm || !state.xdg_wm_base) {
        WLTERM_LOG("[WL-TERM] Missing required Wayland globals\n");
        wl_display_disconnect(state.display);
        return -1;
    }

    /* Create surface */
    state.surface = wl_compositor_create_surface(state.compositor);
    if (!state.surface) {
        WLTERM_LOG("[WL-TERM] Failed to create surface\n");
        wl_display_disconnect(state.display);
        return -1;
    }

    /* Create XDG surface and toplevel */
    state.xdg_surface = xdg_wm_base_get_xdg_surface(state.xdg_wm_base, state.surface);
    xdg_surface_add_listener(state.xdg_surface, &xdg_surface_listener, &state);

    state.toplevel = xdg_surface_get_toplevel(state.xdg_surface);
    xdg_toplevel_add_listener(state.toplevel, &xdg_toplevel_listener, &state);
    xdg_toplevel_set_title(state.toplevel, "Futura Terminal");
    wl_surface_commit(state.surface);

    /* Wait for configure (blocking roundtrip — compositor will respond).
     * Bail out after ~2 seconds to prevent hanging if compositor is stuck. */
    {
        int config_attempts = 0;
        while (!state.configured && config_attempts < 200) {
            wl_display_roundtrip(state.display);
            config_attempts++;
        }
        if (!state.configured) {
            WLTERM_LOG("[WL-TERM] Timed out waiting for configure\n");
            wl_display_disconnect(state.display);
            return -1;
        }
    }
    xdg_surface_ack_configure(state.xdg_surface, state.configure_serial);
    /* Same fix as wl-edit/wl-sysmon: clear the latch so the main loop
     * (state->configured = false at line 830) actually has something to
     * skip; without this we re-ack the same serial on the next configure
     * arrival because state->configure_serial is stale. */
    state.configured = false;
    state.configure_serial = 0;

    /* Set pixel dimensions from terminal grid (may have been resized by configure) */
    state.pixel_width = state.term.cols * FONT_WIDTH + 2 * TERM_PAD_X;
    state.pixel_height = state.term.rows * FONT_HEIGHT + 2 * TERM_PAD_Y;

    /* Create shared memory buffer (unique per instance via PID).
     * Allocate at MAX size so we can resize without re-mmap. */
    state.shm_size = (size_t)TERM_MAX_WIDTH * TERM_MAX_HEIGHT * 4u;
    char shm_name[32];
    {
        long pid = sys_call1(39 /* getpid */, 0);
        int si = 0;
        shm_name[si++] = '/';
        shm_name[si++] = 'w';
        shm_name[si++] = 'l';
        shm_name[si++] = '-';
        shm_name[si++] = 't';
        shm_name[si++] = 'e';
        shm_name[si++] = 'r';
        shm_name[si++] = 'm';
        shm_name[si++] = '-';
        /* Append PID digits */
        if (pid < 0) pid = 0;
        char digits[12];
        int nd = 0;
        long tmp = pid;
        do { digits[nd++] = '0' + (char)(tmp % 10); tmp /= 10; } while (tmp > 0);
        for (int d = nd - 1; d >= 0; d--) shm_name[si++] = digits[d];
        shm_name[si] = '\0';
    }
    state.shm_fd = fut_shm_create(shm_name, state.shm_size, O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (state.shm_fd < 0) {
        WLTERM_LOG("[WL-TERM] Failed to create shm\n");
        wl_display_disconnect(state.display);
        return -1;
    }

    state.shm_data = (void *)sys_mmap(NULL, (long)state.shm_size,
                                      PROT_READ | PROT_WRITE, MAP_SHARED,
                                      state.shm_fd, 0);
    WLTERM_LOG("[WL-TERM] mmap returned: %p (size=%lu)\n", state.shm_data, (unsigned long)state.shm_size);
    /* Check for mmap errors: returns negative on error or NULL on failure */
    if (state.shm_data == NULL || (long)state.shm_data < 0 ||
        (uintptr_t)state.shm_data < 0x10000) {
        WLTERM_LOG("[WL-TERM] mmap failed: %p\n", state.shm_data);
        sys_close(state.shm_fd);
        wl_display_disconnect(state.display);
        return -1;
    }
    WLTERM_LOG("[WL-TERM] shm_data verified: %p\n", state.shm_data);

    /* Initialize buffer to background color.
     * Use a volatile pointer to force re-read from memory each iteration.
     * Without volatile, the compiler keeps the base pointer in a register
     * (RAX) across the entire loop.  If a timer interrupt triggers a
     * context switch mid-loop, the register can be corrupted by the
     * scheduler (INT 0x80 saves the return value in R11, but cooperative
     * context switching doesn't preserve caller-saved registers), causing
     * a page fault on an invalid address. */
    volatile uint32_t *pixels = (volatile uint32_t *)state.shm_data;
    for (size_t i = 0; i < state.shm_size / 4; i++) {
        pixels[i] = 0xFF1A1B26u;  /* Match terminal background */
    }

    state.pool = wl_shm_create_pool(state.shm, state.shm_fd,
                                     (int32_t)state.shm_size);
    if (!state.pool) {
        WLTERM_LOG("[WL-TERM] wl_shm_create_pool failed\n");
        sys_close(state.shm_fd);
        wl_display_disconnect(state.display);
        return -1;
    }
    state.buffer = wl_shm_pool_create_buffer(state.pool, 0,
                                             state.pixel_width, state.pixel_height,
                                             state.pixel_width * 4, WL_SHM_FORMAT_ARGB8888);
    if (!state.buffer) {
        WLTERM_LOG("[WL-TERM] wl_shm_pool_create_buffer failed\n");
        sys_close(state.shm_fd);
        wl_display_disconnect(state.display);
        return -1;
    }

    /* Initial draw BEFORE spawning shell — spawn_shell() can block on PTY
     * device open/ioctl during early boot, preventing the window from
     * becoming visible.  Drawing first ensures the surface is committed. */
    redraw(&state);

    /* Spawn shell process (non-fatal if fork fails) */
    if (spawn_shell(&state.term) < 0) {
        WLTERM_LOG("[WL-TERM] Shell spawn failed, continuing as display-only terminal\n");
    }

    /* Set Wayland socket to non-blocking for the main loop.
     * Futura's poll() is a stub that always returns POLLIN,
     * so blocking wl_display_dispatch doesn't work reliably.
     * We use non-blocking dispatch + 10ms sleep instead. */
    {
        int wl_fd = wl_display_get_fd(state.display);
        if (wl_fd >= 0) {
            sys_fcntl_call(wl_fd, 4 /*F_SETFL*/, 0x0800 /*O_NONBLOCK*/);
        }
    }

    /* Main event loop */
    while (state.running) {
        if (!main_loop_iteration(&state)) {
            break;
        }

        /* Yield to compositor between iterations.  On a single-CPU
         * system, the compositor needs CPU time to process our
         * Wayland requests and send back events (keyboard, frame
         * callbacks).  Without an explicit yield, the nanosleep
         * busy-yields but may starve the compositor. */
        sys_sched_yield();

        /* Small delay to avoid busy-wait */
        struct fut_timespec ts = { .tv_sec = 0, .tv_nsec = 10000000 };  /* 10ms */
        sys_nanosleep_call(&ts, NULL);
    }

    /* Cleanup */
    WLTERM_LOG("[WL-TERM] Shutting down\n");

    /* In PTY mode shell_stdin_fd and shell_stdout_fd are the same master_fd;
     * close once. In pipe-fallback mode they're separate. */
    if (state.term.shell_stdin_fd >= 0) {
        sys_close(state.term.shell_stdin_fd);
        if (state.term.shell_stdout_fd == state.term.shell_stdin_fd) {
            state.term.shell_stdout_fd = -1;
        }
        state.term.shell_stdin_fd = -1;
    }
    if (state.term.shell_stdout_fd >= 0) {
        sys_close(state.term.shell_stdout_fd);
        state.term.shell_stdout_fd = -1;
    }
    term_destroy(&state.term);

    if (state.frame_cb) {
        wl_callback_destroy(state.frame_cb);
    }
    if (state.buffer) {
        wl_buffer_destroy(state.buffer);
    }
    if (state.pool) {
        wl_shm_pool_destroy(state.pool);
    }
    if (state.shm_data) {
        sys_munmap_call(state.shm_data, (long)state.shm_size);
    }
    if (state.shm_fd >= 0) {
        sys_close(state.shm_fd);
        fut_shm_unlink(shm_name);
    }

    if (state.pointer) {
        wl_pointer_destroy(state.pointer);
    }
    if (state.keyboard) {
        wl_keyboard_destroy(state.keyboard);
    }
    if (state.seat) {
        wl_seat_destroy(state.seat);
    }
    if (state.toplevel) {
        xdg_toplevel_destroy(state.toplevel);
    }
    if (state.xdg_surface) {
        xdg_surface_destroy(state.xdg_surface);
    }
    if (state.surface) {
        wl_surface_destroy(state.surface);
    }
    if (state.xdg_wm_base) {
        xdg_wm_base_destroy(state.xdg_wm_base);
    }
    wl_display_disconnect(state.display);

    return 0;
}
