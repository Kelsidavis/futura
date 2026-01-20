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

#define PANEL_HEIGHT    32
#define PANEL_WIDTH     1024
#define PANEL_COLOR     0xFF2A2A2A  /* Dark gray panel */
#define TEXT_COLOR      0xFFFFFFFF  /* White text */
#define ACCENT_COLOR    0xFF4A90E2  /* Blue accent */

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

/* Draw a simple 5x7 font character */
static void draw_char(uint32_t *framebuffer, int fb_width, int x, int y, char c, uint32_t color) {
    /* Simple 5x7 bitmap font for digits and : */
    static const uint8_t font[11][7] = {
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

    int idx = -1;
    if (c >= '0' && c <= '9') {
        idx = c - '0';
    } else if (c == ':') {
        idx = 10;
    }

    if (idx < 0) return;

    for (int row = 0; row < 5; row++) {
        uint8_t bits = font[idx][row];
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

/* Get current time as HH:MM string */
static void get_time_string(char *buf) {
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) == 0) {
        /* Convert seconds since epoch to hours:minutes (UTC) */
        long seconds = ts.tv_sec;
        long hours = (seconds / 3600) % 24;
        long minutes = (seconds / 60) % 60;

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
    /* Clear panel */
    for (size_t i = 0; i < PANEL_WIDTH * PANEL_HEIGHT; i++) {
        state->shm_data[i] = PANEL_COLOR;
    }

    /* Draw launcher button (left side) */
    uint32_t launcher_color = state->launcher_hovered ? ACCENT_COLOR : 0xFF3A3A3A;
    draw_rect(state->shm_data, PANEL_WIDTH, 4, 4, 80, 24, launcher_color);
    draw_text(state->shm_data, PANEL_WIDTH, 12, 10, "APPS", TEXT_COLOR);

    /* Draw clock (center-right) */
    char time_str[6];
    get_time_string(time_str);
    draw_text(state->shm_data, PANEL_WIDTH, PANEL_WIDTH - 150, 12, time_str, TEXT_COLOR);

    /* Draw system info (right side) */
    draw_text(state->shm_data, PANEL_WIDTH, PANEL_WIDTH - 80, 12, "FUTURA", ACCENT_COLOR);

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

    panel_draw(state);

    /* Request next frame */
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
    state->launcher_hovered = (state->pointer_x >= 4 && state->pointer_x < 84 &&
                              state->pointer_y >= 4 && state->pointer_y < 28);

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

        /* Fork and exec a terminal application */
        long pid = sys_fork();
        if (pid == 0) {
            /* Child process - launch terminal */
            const char *argv[] = {"/bin/wl-term", NULL};
            const char *envp[] = {NULL};
            sys_execve("/bin/wl-term", (char *const *)argv, (char *const *)envp);

            /* If execve fails, try futura-shell as fallback */
            const char *shell_argv[] = {"/bin/futura-shell", NULL};
            sys_execve("/bin/futura-shell", (char *const *)shell_argv, (char *const *)envp);

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

static const struct wl_pointer_listener pointer_listener = {
    .enter = pointer_enter,
    .leave = pointer_leave,
    .motion = pointer_motion,
    .button = pointer_button,
    .axis = pointer_axis,
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
