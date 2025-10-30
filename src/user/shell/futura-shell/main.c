/*
 * futura-shell - Lightweight Wayland desktop shell
 * Features: Sidebar with app launcher, top panel, window management
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <futura/compat/posix_shm.h>
#include <user/stdio.h>
#include <user/stdlib.h>
#include <user/string.h>
#include <user/sys.h>

#include <wayland-client-core.h>
#include <wayland-client-protocol.h>
#include "xdg-shell-client-protocol.h"

/* Linux input event codes */
#define BTN_LEFT 0x110

/* UI Layout Constants */
#define SCREEN_WIDTH    1024
#define SCREEN_HEIGHT   768
#define SIDEBAR_WIDTH   80
#define TOPBAR_HEIGHT   40
#define ICON_SIZE       48
#define ICON_PADDING    16
#define WORKSPACE_COUNT 4

/* File I/O Flags */
#define O_RDWR      0x0002
#define O_CREAT     0x0040
#define O_TRUNC     0x0200
#define PROT_READ   0x0001
#define PROT_WRITE  0x0002
#define MAP_SHARED  0x0001

/* Application definitions */
#define APP_COUNT 3
struct app_info {
    const char *name;
    const char *label;
    const char *path;
    uint32_t color;
};

static const struct app_info apps[APP_COUNT] = {
    {"colorwheel", "Gallery", "/bin/wl-colorwheel", 0xFF4CAF50u},
    {"simple",     "Canvas",  "/bin/wl-simple",     0xFF2196F3u},
    {"terminal",   "Shell",   "/bin/sh",            0xFF9C27B0u},
};

/* Shell state */
struct shell_state {
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
    bool configured;
    uint32_t configure_serial;

    uint32_t *pixels;
    size_t buffer_size;
    int shm_fd;

    uint32_t current_workspace;
    int32_t mouse_x;
    int32_t mouse_y;
    bool mouse_pressed;
};

/* Rendering functions */
static void fill_rect(uint32_t *pixels, int32_t width, int32_t height, int32_t stride_bytes,
                      int32_t x, int32_t y, int32_t w, int32_t h, uint32_t color) {
    int32_t stride = stride_bytes / 4;
    for (int32_t row = 0; row < h; row++) {
        int32_t py = y + row;
        if (py < 0 || py >= height) continue;
        for (int32_t col = 0; col < w; col++) {
            int32_t px = x + col;
            if (px < 0 || px >= width) continue;
            pixels[py * stride + px] = color;
        }
    }
}

static void render_ui(uint32_t *pixels, int32_t width, int32_t height, int32_t stride_bytes) {
    /* Clear background */
    fill_rect(pixels, width, height, stride_bytes, 0, 0, width, height, 0xFF1a1a1au);

    /* Draw top panel */
    fill_rect(pixels, width, height, stride_bytes, 0, 0, width, TOPBAR_HEIGHT, 0xFF2a2a2au);

    /* Draw sidebar */
    fill_rect(pixels, width, height, stride_bytes, 0, TOPBAR_HEIGHT,
              SIDEBAR_WIDTH, height - TOPBAR_HEIGHT, 0xFF333333u);

    /* Draw app icons in sidebar */
    for (int i = 0; i < APP_COUNT; i++) {
        int32_t icon_y = TOPBAR_HEIGHT + ICON_PADDING + i * (ICON_SIZE + ICON_PADDING);
        if (icon_y + ICON_SIZE > height) break;

        /* Icon background */
        fill_rect(pixels, width, height, stride_bytes,
                  (SIDEBAR_WIDTH - ICON_SIZE) / 2, icon_y, ICON_SIZE, ICON_SIZE, apps[i].color);

        /* Simple text label (draw a dot for now) */
        fill_rect(pixels, width, height, stride_bytes,
                  SIDEBAR_WIDTH / 2 - 3, icon_y + ICON_SIZE / 2 - 3, 6, 6, 0xFFFFFFFFu);
    }

    /* Draw status text in top panel */
    /* (We'd need a font renderer for actual text) */
    fill_rect(pixels, width, height, stride_bytes, 10, 10, 20, 20, 0xFF4CAF50u);
}

/* Wayland callbacks */
static void pointer_enter(void *data, struct wl_pointer *pointer,
                          uint32_t serial, struct wl_surface *surface,
                          wl_fixed_t x, wl_fixed_t y) {
    (void)pointer; (void)serial; (void)surface;
    struct shell_state *state = data;
    if (!state) return;
    state->mouse_x = wl_fixed_to_int(x);
    state->mouse_y = wl_fixed_to_int(y);
}

static void pointer_leave(void *data __attribute__((unused)), struct wl_pointer *pointer __attribute__((unused)),
                          uint32_t serial, struct wl_surface *surface) {
    (void)pointer; (void)serial; (void)surface;
}

static void pointer_motion(void *data, struct wl_pointer *pointer,
                           uint32_t time, wl_fixed_t x, wl_fixed_t y) {
    (void)pointer; (void)time;
    struct shell_state *state = data;
    if (!state) return;
    state->mouse_x = wl_fixed_to_int(x);
    state->mouse_y = wl_fixed_to_int(y);
}

static void pointer_button(void *data, struct wl_pointer *pointer,
                           uint32_t serial, uint32_t time, uint32_t button,
                           uint32_t button_state) {
    (void)pointer; (void)serial; (void)time;
    struct shell_state *state = data;
    if (!state) return;

    if (button == BTN_LEFT && button_state == WL_POINTER_BUTTON_STATE_PRESSED) {
        state->mouse_pressed = true;

        /* Check if click is in sidebar (app launcher area) */
        if (state->mouse_x < SIDEBAR_WIDTH && state->mouse_y > TOPBAR_HEIGHT) {
            int32_t icon_index = (state->mouse_y - TOPBAR_HEIGHT - ICON_PADDING) /
                                 (ICON_SIZE + ICON_PADDING);
            if (icon_index >= 0 && icon_index < APP_COUNT) {
                printf("[SHELL] Launching app: %s\n", apps[icon_index].path);
                /* In a real implementation, we'd fork/exec the app */
            }
        }
    } else if (button == BTN_LEFT && button_state == WL_POINTER_BUTTON_STATE_RELEASED) {
        state->mouse_pressed = false;
    }
}

static void pointer_axis(void *data, struct wl_pointer *pointer,
                         uint32_t time, uint32_t axis, wl_fixed_t value) {
    (void)data; (void)pointer; (void)time; (void)axis; (void)value;
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

static void seat_capabilities(void *data, struct wl_seat *seat, uint32_t capabilities) {
    struct shell_state *state = data;
    if (!state) return;

    if ((capabilities & WL_SEAT_CAPABILITY_POINTER) && !state->pointer) {
        state->pointer = wl_seat_get_pointer(seat);
        if (state->pointer) {
            wl_pointer_add_listener(state->pointer, &pointer_listener, state);
        }
    }
}

static void seat_name(void *data, struct wl_seat *seat, const char *name) {
    (void)data; (void)seat; (void)name;
}

static const struct wl_seat_listener seat_listener = {
    .capabilities = seat_capabilities,
    .name = seat_name,
};

static void handle_ping(void *data, struct xdg_wm_base *wm_base, uint32_t serial) {
    (void)data;
    xdg_wm_base_pong(wm_base, serial);
}

static const struct xdg_wm_base_listener wm_base_listener = {
    .ping = handle_ping,
};

static void xdg_surface_configure(void *data, struct xdg_surface *surface, uint32_t serial) {
    (void)surface;
    struct shell_state *state = data;
    state->configure_serial = serial;
    state->configured = true;
}

static const struct xdg_surface_listener xdg_surface_listener = {
    .configure = xdg_surface_configure,
};

static void xdg_toplevel_configure(void *data, struct xdg_toplevel *toplevel,
                                   int32_t width, int32_t height, struct wl_array *states) {
    (void)data; (void)toplevel; (void)width; (void)height; (void)states;
}

static void xdg_toplevel_close(void *data, struct xdg_toplevel *toplevel) {
    (void)data; (void)toplevel;
}

static const struct xdg_toplevel_listener xdg_toplevel_listener = {
    .configure = xdg_toplevel_configure,
    .close = xdg_toplevel_close,
};

static void registry_global(void *data, struct wl_registry *registry,
                            uint32_t name, const char *interface, uint32_t version) {
    struct shell_state *state = data;

    if (strcmp(interface, wl_compositor_interface.name) == 0) {
        uint32_t ver = version < 4 ? version : 4;
        state->compositor = wl_registry_bind(registry, name, &wl_compositor_interface, ver);
    } else if (strcmp(interface, wl_shm_interface.name) == 0) {
        state->shm = wl_registry_bind(registry, name, &wl_shm_interface, 1);
    } else if (strcmp(interface, xdg_wm_base_interface.name) == 0) {
        uint32_t ver = version < 2 ? version : 2;
        state->xdg_wm_base = wl_registry_bind(registry, name, &xdg_wm_base_interface, ver);
        xdg_wm_base_add_listener(state->xdg_wm_base, &wm_base_listener, state);
    } else if (strcmp(interface, wl_seat_interface.name) == 0) {
        uint32_t ver = version < 7 ? version : 7;
        state->seat = wl_registry_bind(registry, name, &wl_seat_interface, ver);
        if (state->seat) {
            wl_seat_add_listener(state->seat, &seat_listener, state);
        }
    }
}

static void registry_global_remove(void *data, struct wl_registry *registry, uint32_t name) {
    (void)data; (void)registry; (void)name;
}

static const struct wl_registry_listener registry_listener = {
    .global = registry_global,
    .global_remove = registry_global_remove,
};

int main(void) {
    struct shell_state state = {0};

    /* Connect to Wayland */
    state.display = wl_display_connect(NULL);
    if (!state.display) {
        printf("[SHELL] failed to connect to Wayland\n");
        return -1;
    }
    printf("[SHELL] Connected to Wayland\n");

    /* Get registry */
    state.registry = wl_display_get_registry(state.display);
    wl_registry_add_listener(state.registry, &registry_listener, &state);
    wl_display_roundtrip(state.display);

    if (!state.compositor || !state.shm || !state.xdg_wm_base) {
        printf("[SHELL] missing required globals\n");
        wl_display_disconnect(state.display);
        return -1;
    }
    printf("[SHELL] Got required Wayland globals\n");

    /* Create surface and shell surface */
    state.surface = wl_compositor_create_surface(state.compositor);
    if (!state.surface) {
        printf("[SHELL] failed to create surface\n");
        wl_display_disconnect(state.display);
        return -1;
    }

    state.xdg_surface = xdg_wm_base_get_xdg_surface(state.xdg_wm_base, state.surface);
    xdg_surface_add_listener(state.xdg_surface, &xdg_surface_listener, &state);

    state.toplevel = xdg_surface_get_toplevel(state.xdg_surface);
    xdg_toplevel_add_listener(state.toplevel, &xdg_toplevel_listener, &state);
    wl_surface_commit(state.surface);

    while (!state.configured) {
        wl_display_roundtrip(state.display);
    }
    xdg_surface_ack_configure(state.xdg_surface, state.configure_serial);
    printf("[SHELL] Surface configured\n");

    /* Create shared memory buffer */
    state.buffer_size = (size_t)SCREEN_WIDTH * SCREEN_HEIGHT * 4u;
    const char shm_name[] = "/futura-shell-shm";
    state.shm_fd = fut_shm_create(shm_name, state.buffer_size, O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (state.shm_fd < 0) {
        printf("[SHELL] failed to create shm buffer\n");
        wl_display_disconnect(state.display);
        return -1;
    }

    void *map = (void *)sys_mmap(NULL, (long)state.buffer_size, PROT_READ | PROT_WRITE, MAP_SHARED, state.shm_fd, 0);
    if ((long)map < 0) {
        printf("[SHELL] mmap failed\n");
        sys_close(state.shm_fd);
        wl_display_disconnect(state.display);
        return -1;
    }
    state.pixels = (uint32_t *)map;
    printf("[SHELL] Created shared memory buffer\n");

    /* Create Wayland buffer */
    struct wl_shm_pool *pool = wl_shm_create_pool(state.shm, state.shm_fd, (int32_t)state.buffer_size);
    struct wl_buffer *buffer = wl_shm_pool_create_buffer(pool, 0, SCREEN_WIDTH, SCREEN_HEIGHT,
                                                          SCREEN_WIDTH * 4, WL_SHM_FORMAT_ARGB8888);
    wl_shm_pool_destroy(pool);

    /* Render initial UI */
    render_ui(state.pixels, SCREEN_WIDTH, SCREEN_HEIGHT, SCREEN_WIDTH * 4);

    /* Commit first frame */
    wl_surface_attach(state.surface, buffer, 0, 0);
    wl_surface_damage_buffer(state.surface, 0, 0, SCREEN_WIDTH, SCREEN_HEIGHT);
    wl_surface_commit(state.surface);
    wl_display_flush(state.display);

    printf("[SHELL] Desktop shell ready (1024x768)\n");
    printf("[SHELL] Sidebar: left | Top panel: 40px | Apps: 3 available\n");

    /* Main event loop */
    while (wl_display_dispatch(state.display) != -1) {
        /* Re-render UI if needed */
        render_ui(state.pixels, SCREEN_WIDTH, SCREEN_HEIGHT, SCREEN_WIDTH * 4);

        wl_surface_attach(state.surface, buffer, 0, 0);
        wl_surface_damage_buffer(state.surface, 0, 0, SCREEN_WIDTH, SCREEN_HEIGHT);
        wl_surface_commit(state.surface);
        wl_display_flush(state.display);
    }

    /* Cleanup */
    wl_buffer_destroy(buffer);
    sys_munmap_call(map, (long)state.buffer_size);
    fut_shm_unlink(shm_name);
    sys_close(state.shm_fd);

    if (state.pointer) {
        wl_pointer_destroy(state.pointer);
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
    printf("[SHELL] Shutdown complete\n");
    return 0;
}
