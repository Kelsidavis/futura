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
    bool launcher_hovered;
};

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

    const uint8_t *glyph = NULL;
    if (c >= '0' && c <= '9') glyph = font_digits[c - '0'];
    else if (c == ':') glyph = font_digits[10];
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

/* Get current time as HH:MM string */
static void get_time_string(char *buf) {
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) == 0) {
        long seconds = ts.tv_sec + panel_tz_offset_sec();
        /* Modulo with wrap-around in case TZ offset pushes us negative
         * (e.g. just-after-midnight UTC for a negative offset zone). */
        long hours = (((seconds / 3600) % 24) + 24) % 24;
        long minutes = (((seconds / 60) % 60) + 60) % 60;

        buf[0] = (char)('0' + (hours / 10));
        buf[1] = (char)('0' + (hours % 10));
        buf[2] = ':';
        buf[3] = (char)('0' + (minutes / 10));
        buf[4] = (char)('0' + (minutes % 10));
        buf[5] = '\0';
    } else {
        /* Fallback if clock_gettime fails */
        buf[0] = '-'; buf[1] = '-'; buf[2] = ':';
        buf[3] = '-'; buf[4] = '-'; buf[5] = '\0';
    }
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

    /* Draw launcher button (left side) with rounded-look highlight */
    uint32_t launcher_color = state->launcher_hovered ? ACCENT_COLOR : 0xFF333340;
    draw_rect(state->shm_data, PANEL_WIDTH, 6, 4, 72, 20, launcher_color);
    /* Centre "APPS" inside the 72×20 button rather than nailing it to
     * x=14 / y=8 (which left a noticeable left/top weight when the
     * button hovered). 4 chars × 6px stride = 24px wide, glyphs are
     * 5px tall. Button origin (6, 4); centre = (6 + (72-24)/2,
     * 4 + (20-5)/2) ≈ (30, 11). */
    draw_text(state->shm_data, PANEL_WIDTH, 30, 11, "APPS", TEXT_COLOR);

    /* Branding: "FUTURA" left of center */
    draw_text(state->shm_data, PANEL_WIDTH, 90, 11, "FUTURA", ACCENT_COLOR);

    /* Draw clock and date (right side) */
    char time_str[6];
    get_time_string(time_str);
    draw_text(state->shm_data, PANEL_WIDTH, PANEL_WIDTH - 48, 11, time_str, TEXT_COLOR);

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
    static char last_time_str[6] = {0};
    char now_time_str[6];
    get_time_string(now_time_str);
    bool changed = false;
    for (int i = 0; i < 6; i++) {
        if (last_time_str[i] != now_time_str[i]) { changed = true; break; }
    }
    if (changed) {
        for (int i = 0; i < 6; i++) last_time_str[i] = now_time_str[i];
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
    state->launcher_hovered = false;
}

static void pointer_motion(void *data, struct wl_pointer *pointer, uint32_t time,
                          wl_fixed_t sx, wl_fixed_t sy) {
    struct panel_state *state = data;
    (void)pointer; (void)time;
    state->pointer_x = wl_fixed_to_int(sx);
    state->pointer_y = wl_fixed_to_int(sy);

    /* Check if hovering over launcher button */
    bool was_hovered = state->launcher_hovered;
    state->launcher_hovered = (state->pointer_x >= 6 && state->pointer_x < 78 &&
                              state->pointer_y >= 4 && state->pointer_y < 24);

    if (was_hovered != state->launcher_hovered) {
        panel_draw(state);
    }
}

static void pointer_button(void *data, struct wl_pointer *pointer, uint32_t serial,
                          uint32_t time, uint32_t button, uint32_t button_state) {
    struct panel_state *state = data;
    (void)pointer; (void)serial; (void)time; (void)button;

    if (button_state == WL_POINTER_BUTTON_STATE_PRESSED && state->launcher_hovered) {
        printf("[PANEL] Launcher button clicked - attempting to launch terminal\n");

        /* Fork and exec a terminal application. The child must inherit
         * the wayland envvars or it can't connect to the compositor —
         * launching with envp={NULL} produced terminal processes that
         * silently exited with wl_display_connect() == NULL. Mirror the
         * cli_envp set up by the spawner thread in platform_init. */
        long pid = sys_fork_call();
        if (pid == 0) {
            /* Child process - launch terminal */
            const char *argv[] = {"/bin/wl-term", NULL};
            const char *envp[] = {
                "PATH=/bin:/sbin",
                "HOME=/",
                "TERM=vt100",
                "USER=root",
                "HOSTNAME=futura",
                "WAYLAND_DISPLAY=wayland-0",
                "XDG_RUNTIME_DIR=/run",
                NULL,
            };
            sys_execve_call("/bin/wl-term", (char *const *)argv, (char *const *)envp);

            /* If execve fails, try futura-shell as fallback */
            const char *shell_argv[] = {"/bin/futura-shell", NULL};
            sys_execve_call("/bin/futura-shell", (char *const *)shell_argv, (char *const *)envp);

            /* If both fail, exit */
            printf("[PANEL] Failed to launch application\n");
            sys_exit(1);
        } else if (pid > 0) {
            printf("[PANEL] Launched application with PID %ld\n", pid);
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

    struct panel_state state = {0};
    state.running = true;

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
    if ((long)state.shm_data < 0) {
        printf("[PANEL] Failed to mmap shared memory\n");
        sys_close(fd);
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
    wl_display_disconnect(state.display);

    printf("[PANEL] Panel exited\n");
    return 0;
}
