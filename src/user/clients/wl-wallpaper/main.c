/* wl-wallpaper - Horizon DE wallpaper picker
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Lists a handful of named wallpaper presets and shows a colour swatch
 * next to each.  Pressing Enter writes the selected preset name to
 * /etc/wallpaper.conf (or /run/wallpaper.conf if /etc isn't writable).
 * The compositor polls the file ~once a second and remaps the desktop
 * gradient endpoints to match — no compositor restart is needed.
 *
 * Controls:
 *   Up/Down       Move selection
 *   Enter         Apply selected preset
 *   r             Re-read config
 *   Esc / Ctrl+Q  Close
 */

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <errno.h>
#include <futura/compat/posix_shm.h>
#include <user/stdio.h>
#include <user/signal.h>
#include <user/sys.h>
#include <user/sysnums.h>
#include <shared/fut_timespec.h>

#include <wayland-client-core.h>
#include <wayland-client-protocol.h>
#include "xdg-shell-client-protocol.h"
#include "font.h"

#define O_RDONLY    0x0000
#define O_RDWR      0x0002
#define O_CREAT     0x0040
#define O_TRUNC     0x0200
#define PROT_READ   0x0001
#define PROT_WRITE  0x0002
#define MAP_SHARED  0x0001

/* Layout */
#define SM_PAD        10
#define SM_HEADER_H   24
#define SM_ROW_H      18
#define SM_VIS_ROWS   18
#define SM_WIDTH      560
#define SM_HEIGHT     (SM_PAD * 2 + SM_HEADER_H + (SM_VIS_ROWS + 1) * SM_ROW_H)

/* Colors */
#define COL_BG        0xFF1A1B26u
#define COL_HEADER_BG 0xFF24273Au
#define COL_HEADER_FG 0xFF89B4FAu
#define COL_ROW_A     0xFF1E1F2Du
#define COL_ROW_B     0xFF22233Au
#define COL_TEXT      0xFFCDD6F4u
#define COL_DIM       0xFF7F849Cu
#define COL_ACCENT    0xFFA6E3A1u
#define COL_WARN      0xFFF9E2AFu

/* Wallpaper preset table */
#define SM_MAX_PROCS 16

struct proc_info {
    int pid;            /* unused                                  */
    char state[4];      /* unused                                  */
    char name[32];      /* preset display name                     */
    long rss_kb;        /* unused                                  */
    char value[24];     /* preset key written to /etc/wallpaper.conf */
    uint32_t color;     /* swatch colour (ARGB)                    */
};

static int selected = 0;
static int applied = -1;  /* index of last-applied preset, or -1 */

static struct proc_info procs[SM_MAX_PROCS];
static int proc_count = 0;
static int scroll_off = 0;
static uint64_t last_refresh_ms = 0;

/* Client */
struct client_state {
    struct wl_display *display;
    struct wl_registry *registry;
    struct wl_compositor *compositor;
    struct wl_shm *shm;
    struct xdg_wm_base *xdg_wm_base;
    struct wl_seat *seat;
    struct wl_keyboard *keyboard;
    struct wl_surface *surface;
    struct xdg_surface *xdg_surface;
    struct xdg_toplevel *toplevel;

    bool configured;
    uint32_t configure_serial;
    struct wl_callback *frame_cb;
    bool frame_done;
    bool needs_redraw;

    void *shm_data;
    size_t shm_size;
    int shm_fd;
    struct wl_shm_pool *pool;
    struct wl_buffer *buffer;
    int32_t pixel_width;
    int32_t pixel_height;

    bool running;
};

/* Copy at most n-1 chars from src into dst and NUL-terminate. */
static void s_copy(char *dst, const char *src, size_t n) {
    if (n == 0) return;
    size_t i = 0;
    while (i + 1 < n && src[i]) { dst[i] = src[i]; i++; }
    dst[i] = '\0';
}

static void add_preset(const char *label, const char *key, uint32_t color) {
    if (proc_count >= SM_MAX_PROCS) return;
    struct proc_info *p = &procs[proc_count++];
    p->pid = 0;
    p->state[0] = '\0';
    p->rss_kb = 0;
    p->color = color;
    s_copy(p->name, label, sizeof(p->name));
    s_copy(p->value, key, sizeof(p->value));
}

static void refresh_procs(void) {
    proc_count = 0;

    /* Bundled wallpaper presets. The compositor currently hard-codes
     * a starfield + moon scene; future work will read the chosen key
     * from /etc/wallpaper.conf and dispatch on it. */
    add_preset("Night Sky (default)", "nightsky",  0xFF0B132Bu);
    add_preset("Deep Ocean",          "ocean",     0xFF003049u);
    add_preset("Forest Dawn",         "forest",    0xFF1B4332u);
    add_preset("Sunset Dunes",        "sunset",    0xFFD62828u);
    add_preset("Lavender Dusk",       "lavender",  0xFF6B5B95u);
    add_preset("Slate Studio",        "slate",     0xFF2B2B2Bu);
    add_preset("Solarized Light",     "solarl",    0xFFFDF6E3u);
    add_preset("Solarized Dark",      "solard",    0xFF002B36u);

    /* Clamp selection */
    if (selected >= proc_count) selected = proc_count - 1;
    if (selected < 0) selected = 0;

    /* Keep selection visible */
    if (selected < scroll_off) scroll_off = selected;
    if (selected >= scroll_off + SM_VIS_ROWS) scroll_off = selected - SM_VIS_ROWS + 1;
    int max_scroll = proc_count - SM_VIS_ROWS;
    if (max_scroll < 0) max_scroll = 0;
    if (scroll_off > max_scroll) scroll_off = max_scroll;
    if (scroll_off < 0) scroll_off = 0;
}

/* Write the selected preset key to /etc/wallpaper.conf so the
 * compositor's once-per-second poller picks up the change. */
static void apply_preset(int idx) {
    if (idx < 0 || idx >= proc_count) return;
    int fd = sys_open("/etc/wallpaper.conf",
                      O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        /* /etc may not exist on the ramfs — try /run instead. */
        fd = sys_open("/run/wallpaper.conf",
                      O_RDWR | O_CREAT | O_TRUNC, 0644);
    }
    if (fd < 0) return;

    char buf[64];
    int n = 0;
    const char *k = procs[idx].value;
    while (*k && n < (int)sizeof(buf) - 1) buf[n++] = *k++;
    buf[n++] = '\n';
    /* Loop past short writes — a partial write would leave the file
     * with a truncated key and the compositor's poll would parse
     * something like "ocea" instead of "ocean". */
    int off = 0;
    bool ok = true;
    while (off < n) {
        long w = sys_write(fd, buf + off, n - off);
        if (w <= 0) { ok = false; break; }
        off += (int)w;
    }
    sys_close(fd);
    if (ok) applied = idx;
}

/* ─── Rendering helpers ─── */

/* Clip rect against negative origin and stride width so callers passing
 * over-wide rects (the row strip uses w - 2*(SM_PAD-2), the track at
 * the right edge, etc.) can't run off the row. */
static void fill_rect(uint32_t *px, int stride, int x0, int y0, int w, int h, uint32_t color) {
    if (w <= 0 || h <= 0) return;
    int x1 = x0 + w;
    int y1 = y0 + h;
    if (x0 < 0) x0 = 0;
    if (y0 < 0) y0 = 0;
    if (x1 > stride) x1 = stride;
    if (x1 <= x0 || y1 <= y0) return;
    for (int y = y0; y < y1; y++) {
        uint32_t *row = px + y * stride;
        for (int x = x0; x < x1; x++) row[x] = color;
    }
}

static void draw_text(uint32_t *px, int32_t w, int32_t h, int32_t stride,
                      int x, int y, const char *s, int len,
                      uint32_t fg, uint32_t bg) {
    for (int i = 0; i < len; i++) {
        font_render_char(s[i], px, x + i * FONT_WIDTH, y, stride, w, h, fg, bg);
    }
}

static void redraw_all(struct client_state *state) {
    if (!state->buffer || !state->shm_data) return;
    if ((uintptr_t)state->shm_data < 0x10000) return;

    uint32_t *px = (uint32_t *)state->shm_data;
    int32_t w = state->pixel_width;
    int32_t h = state->pixel_height;
    int32_t stride = w;

    fill_rect(px, stride, 0, 0, w, h, COL_BG);

    /* Header bar */
    fill_rect(px, stride, 0, 0, w, SM_HEADER_H, COL_HEADER_BG);

    /* Title + selection hint */
    {
        const char *title = "Wallpaper";
        int tl = (int)strlen(title);
        int ty = (SM_HEADER_H - FONT_HEIGHT) / 2;
        draw_text(px, w, h, stride, SM_PAD, ty, title, tl,
                  COL_HEADER_FG, COL_HEADER_BG);

        /* ASCII-only — the bitmap font renders one glyph per byte,
         * so a UTF-8 bullet (• = E2 80 A2) shows as three garbage
         * glyphs. Use a plain dot separator instead. */
        const char *hint = "Enter to apply  -  Up/Down to choose";
        int hl = (int)strlen(hint);
        int hx = w - SM_PAD - hl * FONT_WIDTH;
        draw_text(px, w, h, stride, hx, ty, hint, hl, COL_DIM, COL_HEADER_BG);
    }

    /* Column header */
    int col_y = SM_HEADER_H + 4;
    {
        int cy = col_y + (SM_ROW_H - FONT_HEIGHT) / 2;
        int x = SM_PAD;
        draw_text(px, w, h, stride, x, cy, "  ", 2, COL_DIM, COL_BG);  /* swatch col */
        x += 6 * FONT_WIDTH;
        draw_text(px, w, h, stride, x, cy, "PRESET", 6, COL_DIM, COL_BG);
        /* Underline */
        fill_rect(px, stride, SM_PAD, col_y + SM_ROW_H - 2, w - 2 * SM_PAD, 1, 0xFF313244u);
    }

    /* Rows */
    for (int vi = 0; vi < SM_VIS_ROWS; vi++) {
        int pi = scroll_off + vi;
        int ry = col_y + (vi + 1) * SM_ROW_H;
        uint32_t row_bg = (vi & 1) ? COL_ROW_A : COL_ROW_B;
        bool is_sel = (pi == selected) && (pi < proc_count);
        if (is_sel) row_bg = 0xFF313A55u;
        fill_rect(px, stride, SM_PAD - 2, ry, w - 2 * (SM_PAD - 2), SM_ROW_H, row_bg);
        if (pi >= proc_count) continue;
        struct proc_info *p = &procs[pi];

        int cy = ry + (SM_ROW_H - FONT_HEIGHT) / 2;
        int x = SM_PAD;

        /* Colour swatch — a 4×N rectangle inset slightly */
        fill_rect(px, stride, x, ry + 3, 5 * FONT_WIDTH - 4, SM_ROW_H - 6, p->color);
        x += 6 * FONT_WIDTH;

        /* Preset label */
        int nlen = (int)strlen(p->name);
        int maxn = (w - SM_PAD - x - 12 * FONT_WIDTH) / FONT_WIDTH;
        if (nlen > maxn) nlen = maxn;
        if (nlen > 0) {
            uint32_t name_col = is_sel ? COL_HEADER_FG : COL_TEXT;
            draw_text(px, w, h, stride, x, cy, p->name, nlen, name_col, row_bg);
        }

        /* "ACTIVE" tag at the right for the applied preset */
        if (pi == applied) {
            const char *tag = "ACTIVE";
            int tl2 = (int)strlen(tag);
            int tx = w - SM_PAD - tl2 * FONT_WIDTH;
            draw_text(px, w, h, stride, tx, cy, tag, tl2, COL_ACCENT, row_bg);
        }
    }

    /* Scroll indicator on right edge */
    if (proc_count > SM_VIS_ROWS) {
        int track_x = w - 4;
        int track_y = col_y + SM_ROW_H + 2;
        int track_h = SM_VIS_ROWS * SM_ROW_H - 4;
        fill_rect(px, stride, track_x, track_y, 2, track_h, 0xFF313244u);
        int thumb_h = (track_h * SM_VIS_ROWS) / proc_count;
        if (thumb_h < 8) thumb_h = 8;
        int thumb_y = track_y + (track_h - thumb_h) * scroll_off / (proc_count - SM_VIS_ROWS);
        fill_rect(px, stride, track_x, thumb_y, 2, thumb_h, COL_DIM);
    }

    /* Present */
    if (state->frame_cb) {
        wl_callback_destroy(state->frame_cb);
        state->frame_cb = NULL;
    }
    state->frame_done = false;
    state->frame_cb = wl_surface_frame(state->surface);
    if (!state->frame_cb) state->frame_done = true;

    wl_surface_attach(state->surface, state->buffer, 0, 0);
    wl_surface_damage_buffer(state->surface, 0, 0, w, h);
    wl_surface_commit(state->surface);
    wl_display_flush(state->display);
    state->needs_redraw = false;
}

static void frame_done_cb(void *data, struct wl_callback *cb, uint32_t time) {
    (void)time;
    struct client_state *s = data;
    s->frame_done = true;
    if (s->frame_cb == cb) {
        wl_callback_destroy(cb);
        s->frame_cb = NULL;
    }
}
static const struct wl_callback_listener frame_listener = { .done = frame_done_cb };

/* ─── Wayland plumbing ─── */

static void handle_ping(void *d, struct xdg_wm_base *b, uint32_t s) {
    (void)d; xdg_wm_base_pong(b, s);
}
static const struct xdg_wm_base_listener wm_base_listener = { .ping = handle_ping };

static void xdg_surface_configure(void *d, struct xdg_surface *xs, uint32_t serial) {
    (void)xs;
    struct client_state *s = d;
    s->configure_serial = serial;
    s->configured = true;
}
static const struct xdg_surface_listener xdg_surface_listener = {
    .configure = xdg_surface_configure,
};

static void xdg_toplevel_configure(void *d, struct xdg_toplevel *t,
                                   int32_t w, int32_t h, struct wl_array *a) {
    (void)d; (void)t; (void)w; (void)h; (void)a;
}
static void xdg_toplevel_close(void *d, struct xdg_toplevel *t) {
    (void)t;
    struct client_state *s = d;
    s->running = false;
}
static const struct xdg_toplevel_listener xdg_toplevel_listener = {
    .configure = xdg_toplevel_configure,
    .close = xdg_toplevel_close,
};

/* Keyboard */
static uint32_t kbd_mods = 0;
static uint64_t tick_ms = 0;
static uint32_t repeat_key = 0;
static uint64_t repeat_deadline_ms = 0;
static uint64_t repeat_start_ms = 0;
#define REPEAT_DELAY_MS    400
#define REPEAT_INTERVAL_MS 60
#define REPEAT_MAX_MS      2000

static void process_key(struct client_state *s, uint32_t key) {
    bool ctrl = (kbd_mods & 4) != 0;
    /* Up/Down: move selection (and scroll the viewport with it) */
    if (key == 103) {
        if (selected > 0) selected--;
        if (selected < scroll_off) scroll_off = selected;
        s->needs_redraw = true; return;
    }
    if (key == 108) {
        if (selected + 1 < proc_count) selected++;
        if (selected >= scroll_off + SM_VIS_ROWS)
            scroll_off = selected - SM_VIS_ROWS + 1;
        s->needs_redraw = true; return;
    }
    if (key == 102) { selected = 0; scroll_off = 0; s->needs_redraw = true; return; } /* Home */
    if (key == 107) { /* End */
        selected = proc_count - 1;
        int m = proc_count - SM_VIS_ROWS; if (m < 0) m = 0;
        scroll_off = m; s->needs_redraw = true; return;
    }
    if (key == 28 /* Enter */) {
        apply_preset(selected);
        s->needs_redraw = true; return;
    }
    if (ctrl && key == 16 /* q */) { s->running = false; return; }
    if (key == 1 /* Escape */) { s->running = false; return; }
    if (key == 19 /* r */) {
        refresh_procs();
        last_refresh_ms = tick_ms;
        s->needs_redraw = true; return;
    }
}

static void kb_keymap(void *d, struct wl_keyboard *k, uint32_t f, int32_t fd, uint32_t sz) {
    (void)d; (void)k; (void)f; (void)sz;
    if (fd >= 0) sys_close(fd);
}
static void kb_enter(void *d, struct wl_keyboard *k, uint32_t s,
                     struct wl_surface *sf, struct wl_array *a) {
    (void)d; (void)k; (void)s; (void)sf; (void)a;
}
static void kb_leave(void *d, struct wl_keyboard *k, uint32_t s, struct wl_surface *sf) {
    (void)d; (void)k; (void)s; (void)sf;
    repeat_key = 0;
}
static void kb_key(void *d, struct wl_keyboard *k, uint32_t ser, uint32_t t,
                   uint32_t key, uint32_t ks) {
    (void)k; (void)ser; (void)t;
    struct client_state *s = d;
    if (!s) return;
    if (ks == WL_KEYBOARD_KEY_STATE_RELEASED) {
        if (key == repeat_key) repeat_key = 0;
        return;
    }
    process_key(s, key);
    /* Don't auto-repeat modifier keys, ctrl/alt-modified keys, or
     * keys with non-idempotent / expensive side effects:
     *   Enter (28)        writes /etc/wallpaper.conf
     *   r (19)            re-reads the config and rebuilds the list
     * Plain Up/Down/Home/End still repeat. */
    bool ctrl_or_alt = (kbd_mods & 0xCu) != 0;
    if (ctrl_or_alt ||
        key == 28 /* Enter */ ||
        key == 19 /* r refresh */ ||
        key == 42 || key == 54 || key == 29 || key == 97 ||
        key == 56 || key == 100) {
        repeat_key = 0;
    } else {
        repeat_key = key;
        repeat_deadline_ms = tick_ms + REPEAT_DELAY_MS;
        repeat_start_ms = tick_ms;
    }
}
static void kb_mods(void *d, struct wl_keyboard *k, uint32_t s,
                    uint32_t md, uint32_t ml, uint32_t mlk, uint32_t g) {
    (void)d; (void)k; (void)s; (void)ml; (void)mlk; (void)g;
    kbd_mods = md;
}
static void kb_repeat(void *d, struct wl_keyboard *k, int32_t r, int32_t dl) {
    (void)d; (void)k; (void)r; (void)dl;
}
static const struct wl_keyboard_listener keyboard_listener = {
    .keymap = kb_keymap,
    .enter = kb_enter,
    .leave = kb_leave,
    .key = kb_key,
    .modifiers = kb_mods,
    .repeat_info = kb_repeat,
};

static void seat_caps(void *d, struct wl_seat *s, uint32_t caps) {
    struct client_state *st = d;
    if (!st) return;
    bool wk = (caps & WL_SEAT_CAPABILITY_KEYBOARD) != 0;
    if (wk && !st->keyboard) {
        st->keyboard = wl_seat_get_keyboard(s);
        if (st->keyboard) wl_keyboard_add_listener(st->keyboard, &keyboard_listener, st);
    } else if (!wk && st->keyboard) {
        wl_keyboard_destroy(st->keyboard);
        st->keyboard = NULL;
    }
}
static void seat_name(void *d, struct wl_seat *s, const char *n) {
    (void)d; (void)s; (void)n;
}
static const struct wl_seat_listener seat_listener = {
    .capabilities = seat_caps,
    .name = seat_name,
};

static void reg_global(void *d, struct wl_registry *r, uint32_t name,
                       const char *iface, uint32_t ver) {
    struct client_state *s = d;
    if (strcmp(iface, wl_compositor_interface.name) == 0) {
        uint32_t v = ver < 4 ? ver : 4;
        s->compositor = wl_registry_bind(r, name, &wl_compositor_interface, v);
    } else if (strcmp(iface, wl_shm_interface.name) == 0) {
        s->shm = wl_registry_bind(r, name, &wl_shm_interface, 1);
    } else if (strcmp(iface, xdg_wm_base_interface.name) == 0) {
        uint32_t v = ver < 2 ? ver : 2;
        s->xdg_wm_base = wl_registry_bind(r, name, &xdg_wm_base_interface, v);
        xdg_wm_base_add_listener(s->xdg_wm_base, &wm_base_listener, s);
    } else if (strcmp(iface, wl_seat_interface.name) == 0) {
        uint32_t v = ver < 7 ? ver : 7;
        s->seat = wl_registry_bind(r, name, &wl_seat_interface, v);
        if (s->seat) wl_seat_add_listener(s->seat, &seat_listener, s);
    }
}
static void reg_global_remove(void *d, struct wl_registry *r, uint32_t n) {
    (void)d; (void)r; (void)n;
}
static const struct wl_registry_listener registry_listener = {
    .global = reg_global,
    .global_remove = reg_global_remove,
};

int main(void) {
    {
        struct sigaction sa = {0};
        sa.sa_handler = SIG_IGN;
        sigaction(SIGPIPE, &sa, NULL);
        (void)sa;
    }

    refresh_procs();

    /* Read the currently-active preset from /etc/wallpaper.conf so
     * the picker opens with the right row pre-selected and shows
     * "ACTIVE" next to it from the start. */
    {
        int wfd = sys_open("/etc/wallpaper.conf", O_RDONLY, 0);
        if (wfd < 0) wfd = sys_open("/run/wallpaper.conf", O_RDONLY, 0);
        if (wfd >= 0) {
            char buf[24];
            long n = sys_read(wfd, buf, sizeof(buf) - 1);
            sys_close(wfd);
            while (n > 0 && (buf[n-1] == '\n' || buf[n-1] == '\r' ||
                             buf[n-1] == ' ' || buf[n-1] == '\t')) {
                n--;
            }
            if (n > 0 && n < (long)sizeof(buf)) {
                buf[n] = '\0';
                for (int i = 0; i < proc_count; i++) {
                    int eq = 1;
                    for (long j = 0; j <= n; j++) {
                        if (procs[i].value[j] != buf[j]) { eq = 0; break; }
                    }
                    if (eq) {
                        applied = i;
                        selected = i;
                        break;
                    }
                }
            }
        }
    }

    struct client_state state = {0};
    state.running = true;
    state.frame_done = true;

    state.display = wl_display_connect(NULL);
    if (!state.display) return -1;
    state.registry = wl_display_get_registry(state.display);
    wl_registry_add_listener(state.registry, &registry_listener, &state);
    wl_display_roundtrip(state.display);

    if (!state.compositor || !state.shm || !state.xdg_wm_base) {
        wl_display_disconnect(state.display);
        return -1;
    }

    state.surface = wl_compositor_create_surface(state.compositor);
    state.xdg_surface = xdg_wm_base_get_xdg_surface(state.xdg_wm_base, state.surface);
    xdg_surface_add_listener(state.xdg_surface, &xdg_surface_listener, &state);
    state.toplevel = xdg_surface_get_toplevel(state.xdg_surface);
    xdg_toplevel_add_listener(state.toplevel, &xdg_toplevel_listener, &state);
    xdg_toplevel_set_title(state.toplevel, "Wallpaper");
    xdg_toplevel_set_app_id(state.toplevel, "wl-wallpaper");
    /* Fixed-size: don't handle resize. Pin min == max so the compositor
     * doesn't expose resize handles. */
    xdg_toplevel_set_min_size(state.toplevel, SM_WIDTH, SM_HEIGHT);
    xdg_toplevel_set_max_size(state.toplevel, SM_WIDTH, SM_HEIGHT);
    wl_surface_commit(state.surface);

    int waited = 0;
    while (!state.configured && waited < 200) {
        wl_display_roundtrip(state.display);
        waited++;
    }
    if (!state.configured) {
        wl_display_disconnect(state.display);
        return -1;
    }
    xdg_surface_ack_configure(state.xdg_surface, state.configure_serial);
    /* Same fix as wl-edit: clear the latch so the main loop's ack-pending
     * branch doesn't re-ack the same serial on its first iteration. */
    state.configured = false;
    state.configure_serial = 0;

    state.pixel_width = SM_WIDTH;
    state.pixel_height = SM_HEIGHT;
    state.shm_size = (size_t)SM_WIDTH * SM_HEIGHT * 4u;

    char shm_name[32];
    {
        long pid = sys_getpid_call();
        int si = 0;
        const char *pfx = "/wl-wallpaper-";
        while (*pfx) shm_name[si++] = *pfx++;
        if (pid < 0) pid = 0;
        char dg[12]; int nd = 0; long t = pid;
        do { dg[nd++] = '0' + (char)(t % 10); t /= 10; } while (t > 0);
        for (int d = nd - 1; d >= 0; d--) shm_name[si++] = dg[d];
        shm_name[si] = '\0';
    }
    state.shm_fd = fut_shm_create(shm_name, state.shm_size, O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (state.shm_fd < 0) { wl_display_disconnect(state.display); return -1; }
    state.shm_data = (void *)sys_mmap(NULL, (long)state.shm_size,
                                      PROT_READ | PROT_WRITE, MAP_SHARED,
                                      state.shm_fd, 0);
    if (state.shm_data == NULL || (long)state.shm_data < 0 ||
        (uintptr_t)state.shm_data < 0x10000) {
        sys_close(state.shm_fd);
        wl_display_disconnect(state.display);
        return -1;
    }
    {
        volatile uint32_t *p = (volatile uint32_t *)state.shm_data;
        for (size_t i = 0; i < state.shm_size / 4; i++) p[i] = COL_BG;
    }

    state.pool = wl_shm_create_pool(state.shm, state.shm_fd, (int32_t)state.shm_size);
    state.buffer = wl_shm_pool_create_buffer(state.pool, 0,
                                             state.pixel_width, state.pixel_height,
                                             state.pixel_width * 4, WL_SHM_FORMAT_ARGB8888);
    if (!state.pool || !state.buffer) {
        wl_display_disconnect(state.display);
        return -1;
    }

    state.needs_redraw = true;
    redraw_all(&state);
    if (state.frame_cb)
        wl_callback_add_listener(state.frame_cb, &frame_listener, &state);

    {
        int wfd = wl_display_get_fd(state.display);
        if (wfd >= 0) sys_fcntl_call(wfd, 4, 0x0800);
    }

    /* Refresh interval */
    /* Preset list is static; refreshing every 2s is wasteful. 60s. */
    const uint64_t REFRESH_MS = 60000;
    last_refresh_ms = 0;

    while (state.running) {
        tick_ms += 10;

        if (state.configured && state.configure_serial != 0) {
            xdg_surface_ack_configure(state.xdg_surface, state.configure_serial);
            state.configured = false;
            state.needs_redraw = true;
        }

        /* Auto-refresh */
        if (tick_ms - last_refresh_ms >= REFRESH_MS) {
            refresh_procs();
            last_refresh_ms = tick_ms;
            state.needs_redraw = true;
        }

        if (repeat_key != 0) {
            if (tick_ms - repeat_start_ms > REPEAT_MAX_MS) {
                repeat_key = 0;
            } else if (tick_ms >= repeat_deadline_ms) {
                process_key(&state, repeat_key);
                repeat_deadline_ms = tick_ms + REPEAT_INTERVAL_MS;
            }
        }

        /* Frame-callback timeout: if the compositor stops sending
         * frame.done, force frame_done so a refresh isn't blocked
         * indefinitely. ~500ms threshold (50 ticks @ ~10ms). */
        static int sm_frame_wait = 0;
        if (!state.frame_done) {
            if (++sm_frame_wait >= 50) {
                state.frame_done = true;
                sm_frame_wait = 0;
            }
        } else {
            sm_frame_wait = 0;
        }

        if (state.needs_redraw && state.frame_done) {
            redraw_all(&state);
            if (state.frame_cb)
                wl_callback_add_listener(state.frame_cb, &frame_listener, &state);
        }

        wl_display_flush(state.display);
        {
            int tries = 0;
            while (wl_display_prepare_read(state.display) != 0) {
                wl_display_dispatch_pending(state.display);
                if (++tries > 1000) break;
            }
            if (tries <= 1000) wl_display_read_events(state.display);
        }
        wl_display_dispatch_pending(state.display);

        sys_sched_yield();
        struct fut_timespec ts = { .tv_sec = 0, .tv_nsec = 10000000 };
        sys_nanosleep_call(&ts, NULL);
    }

    if (state.frame_cb) wl_callback_destroy(state.frame_cb);
    if (state.buffer) wl_buffer_destroy(state.buffer);
    if (state.pool) wl_shm_pool_destroy(state.pool);
    if (state.shm_data) sys_munmap_call(state.shm_data, (long)state.shm_size);
    if (state.shm_fd >= 0) { sys_close(state.shm_fd); fut_shm_unlink(shm_name); }
    if (state.keyboard) wl_keyboard_destroy(state.keyboard);
    if (state.seat) wl_seat_destroy(state.seat);
    if (state.toplevel) xdg_toplevel_destroy(state.toplevel);
    if (state.xdg_surface) xdg_surface_destroy(state.xdg_surface);
    if (state.surface) wl_surface_destroy(state.surface);
    if (state.xdg_wm_base) xdg_wm_base_destroy(state.xdg_wm_base);
    wl_display_disconnect(state.display);
    return 0;
}
