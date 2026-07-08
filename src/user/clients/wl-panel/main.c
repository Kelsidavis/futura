/* wl-panel - Minimal desktop panel for Futura OS
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Provides a top panel with launcher, clock, and system info.
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <futura/compat/posix_shm.h>
#include <user/signal.h>
#include <user/stdio.h>
#include <user/sys.h>
#include <user/time.h>

#include <wayland-client-core.h>
#include <wayland-client-protocol.h>
#include "xdg-shell-client-protocol.h"

#define PANEL_HEIGHT    28
#define PANEL_WIDTH     1024
#define PANEL_COLOR_TOP 0xFF222230  /* Dark panel top */
#define PANEL_COLOR_BOT 0xFF1A1A28  /* Darker panel bottom */
#define TEXT_COLOR      0xFFE0E0E8  /* Soft white text */
#define TEXT_DIM        0xFF909098  /* Dimmed text */
#define ACCENT_COLOR    0xFF6A8FD8  /* Softer blue accent */
#define SEPARATOR_COLOR 0xFF3A3A48  /* Subtle separator */

#define O_RDWR      0x0002
#define O_CREAT     0x0040
#define O_TRUNC     0x0200
#define PROT_READ   0x0001
#define PROT_WRITE  0x0002
#define MAP_SHARED  0x0001

struct panel_state {
    struct wl_display *display;
    struct wl_registry *registry;
    struct wl_compositor *compositor;
    struct wl_shm *shm;
    struct xdg_wm_base *xdg_wm_base;
    struct wl_seat *seat;
    struct wl_pointer *pointer;

    struct wl_surface *surface;
    struct xdg_surface *xdg_surface;
    struct xdg_toplevel *toplevel;

    struct wl_buffer *buffer;
    uint32_t *shm_data;
    size_t shm_size;

    bool configured;
    uint32_t configure_serial;

    struct wl_callback *frame_cb;
    bool running;

    uint32_t pointer_x;
    uint32_t pointer_y;
    int hovered_launcher;   /* index into launchers[], -1 = none */
};

/* Launcher buttons across the panel's left edge. Each button is
 * label_len*6 + 2*LB_PAD_X wide; positions are computed on the fly
 * so the table is the single source of truth. */
struct launcher_def {
    const char *label;
    const char *path;
};
static const struct launcher_def launchers[] = {
    { "TERM",  "/bin/wl-term" },
    { "FILES", "/bin/wl-files" },
    { "EDIT",  "/bin/wl-edit" },
    { "TASKS", "/bin/wl-sysmon" },
    { "SETUP", "/bin/wl-settings" },
};
#define N_LAUNCHERS ((int)(sizeof(launchers) / sizeof(launchers[0])))
#define LB_X0     6   /* first button left edge */
#define LB_Y      4
#define LB_H      20
#define LB_PAD_X  8   /* label inset inside a button */
#define LB_GAP    5   /* spacing between buttons */

static int launcher_label_len(int idx) {
    int n = 0;
    while (launchers[idx].label[n]) n++;
    return n;
}

static int launcher_width(int idx) {
    return launcher_label_len(idx) * 6 + 2 * LB_PAD_X;
}

static int launcher_x(int idx) {
    int x = LB_X0;
    for (int i = 0; i < idx; i++) x += launcher_width(i) + LB_GAP;
    return x;
}

/* Panel-relative pointer position → launcher index, or -1. */
static int launcher_hit(uint32_t px, uint32_t py) {
    if (py < LB_Y || py >= LB_Y + LB_H) return -1;
    for (int i = 0; i < N_LAUNCHERS; i++) {
        int x = launcher_x(i);
        if ((int)px >= x && (int)px < x + launcher_width(i)) return i;
    }
    return -1;
}

/* Draw a simple 5x7 font character — extended with uppercase letters */
static void draw_char(uint32_t *framebuffer, int fb_width, int x, int y, char c, uint32_t color) {
    static const uint8_t font_digits[11][5] = {
        /* 0 */ {0x1F, 0x11, 0x11, 0x11, 0x1F},
        /* 1 */ {0x08, 0x0C, 0x08, 0x08, 0x1C},
        /* 2 */ {0x1F, 0x01, 0x1F, 0x10, 0x1F},
        /* 3 */ {0x1F, 0x01, 0x1F, 0x01, 0x1F},
        /* 4 */ {0x11, 0x11, 0x1F, 0x01, 0x01},
        /* 5 */ {0x1F, 0x10, 0x1F, 0x01, 0x1F},
        /* 6 */ {0x1F, 0x10, 0x1F, 0x11, 0x1F},
        /* 7 */ {0x1F, 0x01, 0x02, 0x04, 0x08},
        /* 8 */ {0x1F, 0x11, 0x1F, 0x11, 0x1F},
        /* 9 */ {0x1F, 0x11, 0x1F, 0x01, 0x1F},
        /* : */ {0x00, 0x0C, 0x00, 0x0C, 0x00},
    };
    /* Minimal uppercase letter bitmaps (5x5 grid) */
    static const uint8_t font_alpha[26][5] = {
        /* A */ {0x0E, 0x11, 0x1F, 0x11, 0x11},
        /* B */ {0x1E, 0x11, 0x1E, 0x11, 0x1E},
        /* C */ {0x0F, 0x10, 0x10, 0x10, 0x0F},
        /* D */ {0x1E, 0x11, 0x11, 0x11, 0x1E},
        /* E */ {0x1F, 0x10, 0x1E, 0x10, 0x1F},
        /* F */ {0x1F, 0x10, 0x1E, 0x10, 0x10},
        /* G */ {0x0F, 0x10, 0x17, 0x11, 0x0F},
        /* H */ {0x11, 0x11, 0x1F, 0x11, 0x11},
        /* I */ {0x1F, 0x04, 0x04, 0x04, 0x1F},
        /* J */ {0x1F, 0x02, 0x02, 0x12, 0x0C},
        /* K */ {0x11, 0x12, 0x1C, 0x12, 0x11},
        /* L */ {0x10, 0x10, 0x10, 0x10, 0x1F},
        /* M */ {0x11, 0x1B, 0x15, 0x11, 0x11},
        /* N */ {0x11, 0x19, 0x15, 0x13, 0x11},
        /* O */ {0x0E, 0x11, 0x11, 0x11, 0x0E},
        /* P */ {0x1E, 0x11, 0x1E, 0x10, 0x10},
        /* Q */ {0x0E, 0x11, 0x15, 0x12, 0x0D},
        /* R */ {0x1E, 0x11, 0x1E, 0x12, 0x11},
        /* S */ {0x0F, 0x10, 0x0E, 0x01, 0x1E},
        /* T */ {0x1F, 0x04, 0x04, 0x04, 0x04},
        /* U */ {0x11, 0x11, 0x11, 0x11, 0x0E},
        /* V */ {0x11, 0x11, 0x11, 0x0A, 0x04},
        /* W */ {0x11, 0x11, 0x15, 0x1B, 0x11},
        /* X */ {0x11, 0x0A, 0x04, 0x0A, 0x11},
        /* Y */ {0x11, 0x0A, 0x04, 0x04, 0x04},
        /* Z */ {0x1F, 0x02, 0x04, 0x08, 0x1F},
    };

    static const uint8_t glyph_pct[5] = {0x19, 0x1A, 0x04, 0x0B, 0x13}; /* % */
    const uint8_t *glyph = NULL;
    if (c >= '0' && c <= '9') glyph = font_digits[c - '0'];
    else if (c == ':') glyph = font_digits[10];
    else if (c == '%') glyph = glyph_pct;
    else if (c >= 'A' && c <= 'Z') glyph = font_alpha[c - 'A'];
    else if (c >= 'a' && c <= 'z') glyph = font_alpha[c - 'a'];
    else return;

    for (int row = 0; row < 5; row++) {
        uint8_t bits = glyph[row];
        for (int col = 0; col < 5; col++) {
            if (bits & (1 << (4 - col))) {
                int px = x + col;
                int py = y + row;
                if (px >= 0 && px < fb_width && py >= 0 && py < PANEL_HEIGHT) {
                    framebuffer[py * fb_width + px] = color;
                }
            }
        }
    }
}

/* Draw text string */
static void draw_text(uint32_t *framebuffer, int fb_width, int x, int y, const char *text, uint32_t color) {
    int offset = 0;
    for (const char *p = text; *p; p++) {
        draw_char(framebuffer, fb_width, x + offset, y, *p, color);
        offset += 6;  /* 5 pixels + 1 space */
    }
}

/* Draw filled rectangle */
static void draw_rect(uint32_t *framebuffer, int fb_width, int x, int y, int w, int h, uint32_t color) {
    for (int row = 0; row < h; row++) {
        for (int col = 0; col < w; col++) {
            int px = x + col;
            int py = y + row;
            if (px >= 0 && px < fb_width && py >= 0 && py < PANEL_HEIGHT) {
                framebuffer[py * fb_width + px] = color;
            }
        }
    }
}

/* Read TZ_OFFSET_SEC env var (signed integer) once on first call.
 * Inherited from the spawner so the panel matches the compositor's
 * wall-clock display instead of showing UTC. */
static long panel_tz_offset_sec(void) {
    static long cached = 0;
    static int initialized = 0;
    if (!initialized) {
        const char *tz = getenv("TZ_OFFSET_SEC");
        long v = 0;
        int neg = 0;
        if (tz && *tz) {
            const char *p = tz;
            if (*p == '-') { neg = 1; p++; }
            else if (*p == '+') { p++; }
            while (*p >= '0' && *p <= '9') {
                v = v * 10 + (*p - '0');
                p++;
            }
            if (neg) v = -v;
        }
        cached = v;
        initialized = 1;
    }
    return cached;
}

/* Civil-from-days (Howard Hinnant). Converts days since 1970-01-01
 * to (year, month, day). Same algorithm rust-date uses. */
static void civil_from_days(long z, int *yo, int *mo, int *do_) {
    long zz = z + 719468;
    long era = (zz >= 0 ? zz : zz - 146096) / 146097;
    unsigned long doe = (unsigned long)(zz - era * 146097);          /* [0, 146096] */
    unsigned long yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    long y = (long)yoe + era * 400;
    unsigned long doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    unsigned long mp  = (5 * doy + 2) / 153;
    unsigned long d   = doy - (153 * mp + 2) / 5 + 1;
    unsigned long m   = (mp < 10 ? mp + 3 : mp - 9);
    if (m <= 2) y++;
    *yo = (int)y; *mo = (int)m; *do_ = (int)d;
}

/* Get current date+time as "MMM DD  HH:MM" (13 chars + NUL). */
static void get_clock_string(char *buf) {
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) == 0) {
        long seconds = ts.tv_sec + panel_tz_offset_sec();
        long day_secs = seconds % 86400;
        long days = seconds / 86400;
        if (day_secs < 0) { day_secs += 86400; days -= 1; }
        long hours = day_secs / 3600;
        long minutes = (day_secs % 3600) / 60;

        int y = 0, mo = 0, d = 0;
        civil_from_days(days, &y, &mo, &d);
        static const char *MON[13] = {
            "???", "Jan", "Feb", "Mar", "Apr", "May", "Jun",
            "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
        };
        const char *mp = MON[(mo >= 1 && mo <= 12) ? mo : 0];
        buf[0] = mp[0]; buf[1] = mp[1]; buf[2] = mp[2];
        buf[3] = ' ';
        buf[4] = (char)('0' + (d / 10));
        buf[5] = (char)('0' + (d % 10));
        buf[6] = ' ';
        buf[7] = ' ';
        buf[8]  = (char)('0' + (hours / 10));
        buf[9]  = (char)('0' + (hours % 10));
        buf[10] = ':';
        buf[11] = (char)('0' + (minutes / 10));
        buf[12] = (char)('0' + (minutes % 10));
        buf[13] = '\0';
    } else {
        const char *fb = "--- -- --:--";
        for (int i = 0; i < 13; i++) buf[i] = fb[i];
        buf[13] = '\0';
    }
}

/* Read battery percentage from sysfs. Returns -1 if no battery. */
static int get_battery_pct(void) {
    int fd = sys_open("/sys/class/power_supply/BAT0/capacity", 0 /*O_RDONLY*/, 0);
    if (fd < 0) return -1;
    char buf[8];
    ssize_t n = sys_read(fd, buf, sizeof(buf) - 1);
    sys_close(fd);
    if (n <= 0) return -1;
    buf[n] = '\0';
    int pct = 0;
    for (int i = 0; i < n && buf[i] >= '0' && buf[i] <= '9'; i++)
        pct = pct * 10 + (buf[i] - '0');
    return (pct >= 0 && pct <= 100) ? pct : -1;
}

/* Read battery charge status from sysfs. */
static bool get_battery_charging(void) {
    int fd = sys_open("/sys/class/power_supply/BAT0/status", 0, 0);
    if (fd < 0) return false;
    char buf[16];
    ssize_t n = sys_read(fd, buf, sizeof(buf) - 1);
    sys_close(fd);
    if (n <= 0) return false;
    buf[n] = '\0';
    return (buf[0] == 'C'); /* "Charging" starts with C */
}

/* Format battery string: "BAT 73%" or "CHG 73%" or empty. */
static int get_battery_string(char *buf, int bufsz) {
    int pct = get_battery_pct();
    if (pct < 0) return 0;
    bool charging = get_battery_charging();
    const char *prefix = charging ? "CHG " : "BAT ";
    int i = 0;
    while (*prefix && i < bufsz - 1) buf[i++] = *prefix++;
    if (pct >= 100) { buf[i++] = '1'; buf[i++] = '0'; buf[i++] = '0'; }
    else if (pct >= 10) { buf[i++] = (char)('0' + pct / 10); buf[i++] = (char)('0' + pct % 10); }
    else { buf[i++] = (char)('0' + pct); }
    if (i < bufsz - 1) buf[i++] = '%';
    buf[i] = '\0';
    return i;
}

static void panel_draw(struct panel_state *state) {
    /* Gradient background: subtle vertical gradient for depth */
    for (int y = 0; y < PANEL_HEIGHT; y++) {
        int t = y * 255 / (PANEL_HEIGHT > 1 ? PANEL_HEIGHT - 1 : 1);
        uint32_t r = 0x22 + (0x1A - 0x22) * t / 255;
        uint32_t g = 0x22 + (0x1A - 0x22) * t / 255;
        uint32_t b = 0x30 + (0x28 - 0x30) * t / 255;
        uint32_t color = 0xFF000000u | (r << 16) | (g << 8) | b;
        for (int x = 0; x < PANEL_WIDTH; x++) {
            state->shm_data[y * PANEL_WIDTH + x] = color;
        }
    }

    /* 1px bottom separator line */
    for (int x = 0; x < PANEL_WIDTH; x++) {
        state->shm_data[(PANEL_HEIGHT - 1) * PANEL_WIDTH + x] = SEPARATOR_COLOR;
    }

    /* Launcher buttons across the left edge; the hovered one lights
     * up with the accent color. Labels are vertically centered in the
     * 20px-tall buttons (glyphs are 5px tall → y = 4 + (20-5)/2 ≈ 11). */
    for (int i = 0; i < N_LAUNCHERS; i++) {
        int x = launcher_x(i);
        int wdt = launcher_width(i);
        uint32_t bg = (i == state->hovered_launcher) ? ACCENT_COLOR : 0xFF333340;
        draw_rect(state->shm_data, PANEL_WIDTH, x, LB_Y, wdt, LB_H, bg);
        draw_text(state->shm_data, PANEL_WIDTH, x + LB_PAD_X, 11,
                  launchers[i].label, TEXT_COLOR);
    }

    /* Branding: "FUTURA" right of the launcher row */
    {
        int brand_x = launcher_x(N_LAUNCHERS - 1) +
                      launcher_width(N_LAUNCHERS - 1) + 18;
        draw_text(state->shm_data, PANEL_WIDTH, brand_x, 11, "FUTURA", ACCENT_COLOR);
    }

    /* Battery indicator (right side, left of clock). */
    char bat_str[12];
    int bat_len = get_battery_string(bat_str, sizeof(bat_str));
    int bat_width = bat_len * 6;
    /* Clock position and battery position are both right-aligned. Clock
     * is 13 chars = 78px + 12px margin. Battery sits to its left with
     * a 12px gap. */
    int clock_x = PANEL_WIDTH - 90;
    if (bat_len > 0) {
        int bat_x = clock_x - bat_width - 12;
        int pct = get_battery_pct();
        uint32_t bat_color = TEXT_DIM;
        if (pct >= 0 && pct <= 20) bat_color = 0xFFE06060;       /* red */
        else if (pct >= 0 && pct <= 40) bat_color = 0xFFE0A040;  /* orange */
        else if (pct > 80) bat_color = 0xFF60C060;                /* green */
        draw_text(state->shm_data, PANEL_WIDTH, bat_x, 11, bat_str, bat_color);
    }

    /* Draw "MMM DD  HH:MM" (right side). 13 chars × 6px stride = 78px,
     * + ~12px right margin = position at PANEL_WIDTH - 90. */
    char clock_str[14];
    get_clock_string(clock_str);
    draw_text(state->shm_data, PANEL_WIDTH, clock_x, 11, clock_str, TEXT_COLOR);

    wl_surface_attach(state->surface, state->buffer, 0, 0);
    wl_surface_damage_buffer(state->surface, 0, 0, PANEL_WIDTH, PANEL_HEIGHT);
    wl_surface_commit(state->surface);
}

static void frame_callback(void *data, struct wl_callback *callback, uint32_t time);

static const struct wl_callback_listener frame_listener = {
    .done = frame_callback,
};

static void frame_callback(void *data, struct wl_callback *callback, uint32_t time) {
    struct panel_state *state = data;
    (void)time;  /* Unused but required by Wayland API */

    if (callback) {
        wl_callback_destroy(callback);
    }

    /* Only redraw when something visible actually changed: clock minute
     * tick or hover state. The previous unconditional redraw was
     * hammering the CPU at the compositor's frame rate (~60 fps) just
     * to repaint a panel whose contents change once a minute. Hover
     * transitions already trigger an out-of-band panel_draw() from
     * pointer_motion(), so we just need to catch the minute roll. */
    static char last_time_str[14] = {0};
    static int last_bat_pct = -2;
    char now_time_str[14];
    get_clock_string(now_time_str);
    bool changed = false;
    for (int i = 0; i < 14; i++) {
        if (last_time_str[i] != now_time_str[i]) { changed = true; break; }
    }
    int cur_bat = get_battery_pct();
    if (cur_bat != last_bat_pct) { changed = true; last_bat_pct = cur_bat; }
    if (changed) {
        for (int i = 0; i < 14; i++) last_time_str[i] = now_time_str[i];
        panel_draw(state);
    }

    /* Request next frame. wl_surface_frame is part of the next commit;
     * the wl_surface_commit below submits the frame request. (When
     * changed==true panel_draw also committed a buffer above; the
     * commit here is the one that arms the frame callback.) */
    state->frame_cb = wl_surface_frame(state->surface);
    wl_callback_add_listener(state->frame_cb, &frame_listener, state);
    wl_surface_commit(state->surface);
}

static void pointer_enter(void *data, struct wl_pointer *pointer, uint32_t serial,
                         struct wl_surface *surface, wl_fixed_t sx, wl_fixed_t sy) {
    (void)data; (void)pointer; (void)serial; (void)surface; (void)sx; (void)sy;
    /* Pointer entered panel */
}

static void pointer_leave(void *data, struct wl_pointer *pointer, uint32_t serial,
                         struct wl_surface *surface) {
    struct panel_state *state = data;
    (void)pointer; (void)serial; (void)surface;
    /* Pointer left the panel — clear the hover highlight and redraw,
     * otherwise the button stays "lit" until the next minute tick. */
    if (state->hovered_launcher >= 0) {
        state->hovered_launcher = -1;
        panel_draw(state);
    }
}

static void pointer_motion(void *data, struct wl_pointer *pointer, uint32_t time,
                          wl_fixed_t sx, wl_fixed_t sy) {
    struct panel_state *state = data;
    (void)pointer; (void)time;
    state->pointer_x = wl_fixed_to_int(sx);
    state->pointer_y = wl_fixed_to_int(sy);

    /* Track which launcher button (if any) the pointer is over */
    int was_hovered = state->hovered_launcher;
    state->hovered_launcher = launcher_hit(state->pointer_x, state->pointer_y);

    if (was_hovered != state->hovered_launcher) {
        panel_draw(state);
    }
}

static void pointer_button(void *data, struct wl_pointer *pointer, uint32_t serial,
                          uint32_t time, uint32_t button, uint32_t button_state) {
    struct panel_state *state = data;
    (void)pointer; (void)serial; (void)time;

    /* Linux BTN_LEFT (0x110) — only left-clicks launch. Without this
     * check, right- or middle-clicking a launcher also forked a child,
     * which felt like a stuck launcher. */
    if (button == 0x110 &&
        button_state == WL_POINTER_BUTTON_STATE_PRESSED &&
        state->hovered_launcher >= 0) {
        const char *path = launchers[state->hovered_launcher].path;
        printf("[PANEL] Launching %s\n", path);

        /* Fork and exec the client. The child must inherit the wayland
         * envvars or it can't connect to the compositor — launching
         * with envp={NULL} produced children that silently exited with
         * wl_display_connect() == NULL. Mirror the cli_envp set up by
         * the spawner thread in platform_init, and forward
         * TZ_OFFSET_SEC so clock-rendering children agree with the
         * panel's own timezone. */
        long pid = sys_fork_call();
        if (pid == 0) {
            const char *argv[] = {path, NULL};
            const char *tz = getenv("TZ_OFFSET_SEC");
            char tz_kv[32] = "TZ_OFFSET_SEC=";
            if (tz && *tz) {
                int kpos = 14;
                int ti = 0;
                while (tz[ti] && kpos + 1 < (int)sizeof(tz_kv)) {
                    tz_kv[kpos++] = tz[ti++];
                }
                tz_kv[kpos] = '\0';
            } else {
                tz_kv[0] = '\0';  /* skip slot */
            }
            const char *envp[] = {
                "PATH=/bin:/sbin",
                "HOME=/root",
                "TERM=xterm-256color",
                "USER=root",
                "HOSTNAME=futura",
                "WAYLAND_DISPLAY=wayland-0",
                "XDG_RUNTIME_DIR=/run",
                tz_kv[0] ? tz_kv : NULL,
                NULL,
            };
            sys_execve_call(path, (char *const *)argv, (char *const *)envp);
            printf("[PANEL] Failed to launch %s\n", path);
            sys_exit(1);
        } else if (pid > 0) {
            printf("[PANEL] Launched %s with PID %ld\n", path, pid);
        } else {
            printf("[PANEL] Fork failed: %ld\n", pid);
        }
    }
}

static void pointer_axis(void *data, struct wl_pointer *pointer, uint32_t time,
                        uint32_t axis, wl_fixed_t value) {
    (void)data; (void)pointer; (void)time; (void)axis; (void)value;
    /* Scroll events */
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

static void seat_capabilities(void *data, struct wl_seat *seat, uint32_t caps) {
    struct panel_state *state = data;

    if (caps & WL_SEAT_CAPABILITY_POINTER) {
        state->pointer = wl_seat_get_pointer(seat);
        wl_pointer_add_listener(state->pointer, &pointer_listener, state);
    }
}

static void seat_name(void *data, struct wl_seat *seat, const char *name) {
    (void)data; (void)seat; (void)name;
    /* Seat name received */
}

static const struct wl_seat_listener seat_listener = {
    .capabilities = seat_capabilities,
    .name = seat_name,
};

static void xdg_surface_configure(void *data, struct xdg_surface *xdg_surface, uint32_t serial) {
    struct panel_state *state = data;
    xdg_surface_ack_configure(xdg_surface, serial);

    if (!state->configured) {
        state->configured = true;
        state->configure_serial = serial;

        /* Start frame callback */
        state->frame_cb = wl_surface_frame(state->surface);
        wl_callback_add_listener(state->frame_cb, &frame_listener, state);
        panel_draw(state);
    }
}

static const struct xdg_surface_listener xdg_surface_listener = {
    .configure = xdg_surface_configure,
};

static void xdg_toplevel_configure(void *data, struct xdg_toplevel *toplevel,
                                  int32_t width, int32_t height, struct wl_array *states) {
    (void)data; (void)toplevel; (void)width; (void)height; (void)states;
    /* Panel stays fixed size */
}

static void xdg_toplevel_close(void *data, struct xdg_toplevel *toplevel) {
    struct panel_state *state = data;
    (void)toplevel;
    state->running = false;
}

static const struct xdg_toplevel_listener toplevel_listener = {
    .configure = xdg_toplevel_configure,
    .close = xdg_toplevel_close,
};

static void xdg_wm_base_ping(void *data, struct xdg_wm_base *xdg_wm_base, uint32_t serial) {
    (void)data;
    xdg_wm_base_pong(xdg_wm_base, serial);
}

static const struct xdg_wm_base_listener xdg_wm_base_listener = {
    .ping = xdg_wm_base_ping,
};

static void registry_global(void *data, struct wl_registry *registry,
                           uint32_t name, const char *interface, uint32_t version) {
    struct panel_state *state = data;
    (void)version;

    if (strcmp(interface, wl_compositor_interface.name) == 0) {
        state->compositor = wl_registry_bind(registry, name, &wl_compositor_interface, 4);
    } else if (strcmp(interface, wl_shm_interface.name) == 0) {
        state->shm = wl_registry_bind(registry, name, &wl_shm_interface, 1);
    } else if (strcmp(interface, xdg_wm_base_interface.name) == 0) {
        state->xdg_wm_base = wl_registry_bind(registry, name, &xdg_wm_base_interface, 1);
        xdg_wm_base_add_listener(state->xdg_wm_base, &xdg_wm_base_listener, state);
    } else if (strcmp(interface, wl_seat_interface.name) == 0) {
        state->seat = wl_registry_bind(registry, name, &wl_seat_interface, 1);
        wl_seat_add_listener(state->seat, &seat_listener, state);
    }
}

static void registry_global_remove(void *data, struct wl_registry *registry, uint32_t name) {
    (void)data; (void)registry; (void)name;
    /* Global removed */
}

static const struct wl_registry_listener registry_listener = {
    .global = registry_global,
    .global_remove = registry_global_remove,
};

int main(void) {
    printf("[PANEL] Starting Futura desktop panel\n");

    /* Auto-reap children so each launcher click doesn't leave a
     * zombie behind. SIG_IGN on SIGCHLD asks the kernel to reap
     * exited children — Linux POSIX behavior. */
    {
        struct sigaction sa = {0};
        sa.sa_handler = SIG_IGN;
        sigaction(SIGCHLD, &sa, NULL);
    }

    struct panel_state state = {0};
    state.running = true;
    state.hovered_launcher = -1;

    /* Connect to Wayland display */
    state.display = wl_display_connect(NULL);
    if (!state.display) {
        printf("[PANEL] Failed to connect to Wayland display\n");
        return 1;
    }

    /* Get registry */
    state.registry = wl_display_get_registry(state.display);
    wl_registry_add_listener(state.registry, &registry_listener, &state);
    wl_display_roundtrip(state.display);

    if (!state.compositor || !state.shm || !state.xdg_wm_base) {
        printf("[PANEL] Missing required Wayland interfaces\n");
        return 1;
    }

    /* Create shared memory buffer */
    state.shm_size = PANEL_WIDTH * PANEL_HEIGHT * 4;
    const char shm_name[] = "/wl-panel-shm";
    int fd = fut_shm_create(shm_name, state.shm_size, O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        printf("[PANEL] Failed to create shared memory\n");
        return 1;
    }

    state.shm_data = (uint32_t *)sys_mmap(NULL, (long)state.shm_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    /* mmap can fail with NULL or a low/garbage pointer, not only a negative
     * value; the bare "< 0" check let a NULL through to be dereferenced in
     * panel_draw. Match the guard the other wl-* clients use. */
    if (state.shm_data == NULL || (long)state.shm_data < 0 ||
        (uintptr_t)state.shm_data < 0x10000) {
        printf("[PANEL] Failed to mmap shared memory\n");
        sys_close(fd);
        fut_shm_unlink(shm_name);
        return 1;
    }

    struct wl_shm_pool *pool = wl_shm_create_pool(state.shm, fd, (int32_t)state.shm_size);
    state.buffer = wl_shm_pool_create_buffer(pool, 0, PANEL_WIDTH, PANEL_HEIGHT,
                                             PANEL_WIDTH * 4, WL_SHM_FORMAT_ARGB8888);
    wl_shm_pool_destroy(pool);
    sys_close(fd);

    /* Create surface */
    state.surface = wl_compositor_create_surface(state.compositor);
    state.xdg_surface = xdg_wm_base_get_xdg_surface(state.xdg_wm_base, state.surface);
    xdg_surface_add_listener(state.xdg_surface, &xdg_surface_listener, &state);

    state.toplevel = xdg_surface_get_toplevel(state.xdg_surface);
    xdg_toplevel_add_listener(state.toplevel, &toplevel_listener, &state);
    xdg_toplevel_set_title(state.toplevel, "Futura Panel");
    xdg_toplevel_set_app_id(state.toplevel, "org.futura.panel");

    wl_surface_commit(state.surface);
    wl_display_roundtrip(state.display);

    printf("[PANEL] Panel initialized, entering event loop\n");

    /* Event loop */
    while (state.running && wl_display_dispatch(state.display) != -1) {
        /* Process events */
    }

    /* Cleanup */
    if (state.frame_cb) wl_callback_destroy(state.frame_cb);
    if (state.buffer) wl_buffer_destroy(state.buffer);
    if (state.toplevel) xdg_toplevel_destroy(state.toplevel);
    if (state.xdg_surface) xdg_surface_destroy(state.xdg_surface);
    if (state.surface) wl_surface_destroy(state.surface);
    if (state.pointer) wl_pointer_destroy(state.pointer);
    if (state.seat) wl_seat_destroy(state.seat);
    if (state.xdg_wm_base) xdg_wm_base_destroy(state.xdg_wm_base);
    if (state.shm) wl_shm_destroy(state.shm);
    if (state.compositor) wl_compositor_destroy(state.compositor);
    if (state.registry) wl_registry_destroy(state.registry);
    if (state.shm_data) sys_munmap_call(state.shm_data, (long)state.shm_size);
    fut_shm_unlink(shm_name);
    wl_display_disconnect(state.display);

    printf("[PANEL] Panel exited\n");
    return 0;
}
