#include "log.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <futura/compat/posix_shm.h>
#include <shared/fut_timespec.h>
#include <user/stdio.h>
#include <user/sys.h>

#include <wayland-client-core.h>
#include <wayland-client-protocol.h>
#include "xdg-shell-client-protocol.h"

#define SURFACE_WIDTH   320
#define SURFACE_HEIGHT  200
#define RECT_SIZE       64
#define TARGET_FRAMES   120

#define O_RDWR      0x0002
#define O_CREAT     0x0040
#define O_TRUNC     0x0200
#define PROT_READ   0x0001
#define PROT_WRITE  0x0002
#define MAP_SHARED  0x0001

struct client_state {
    struct wl_display *display;
    struct wl_registry *registry;
    struct wl_compositor *compositor;
    struct wl_shm *shm;
    struct xdg_wm_base *xdg_wm_base;
    struct wl_surface *surface;
    struct xdg_surface *xdg_surface;
    struct xdg_toplevel *toplevel;
    bool configured;
    uint32_t configure_serial;
};

static void handle_ping(void *data, struct xdg_wm_base *wm_base, uint32_t serial) {
    (void)data;
    xdg_wm_base_pong(wm_base, serial);
}

static const struct xdg_wm_base_listener wm_base_listener = {
    .ping = handle_ping,
};

static void xdg_surface_configure(void *data,
                                  struct xdg_surface *surface,
                                  uint32_t serial) {
    (void)surface;
    struct client_state *state = data;
    state->configure_serial = serial;
    state->configured = true;
}

static const struct xdg_surface_listener xdg_surface_listener = {
    .configure = xdg_surface_configure,
};

static void xdg_toplevel_configure(void *data,
                                   struct xdg_toplevel *toplevel,
                                   int32_t width,
                                   int32_t height,
                                   struct wl_array *states) {
    (void)data;
    (void)toplevel;
    (void)width;
    (void)height;
    (void)states;
}

static void xdg_toplevel_close(void *data, struct xdg_toplevel *toplevel) {
    (void)data;
    (void)toplevel;
}

static const struct xdg_toplevel_listener xdg_toplevel_listener = {
    .configure = xdg_toplevel_configure,
    .close = xdg_toplevel_close,
};

static void registry_global(void *data,
                            struct wl_registry *registry,
                            uint32_t name,
                            const char *interface,
                            uint32_t version) {
    struct client_state *state = data;

    if (strcmp(interface, wl_compositor_interface.name) == 0) {
        uint32_t ver = version < 4 ? version : 4;
        state->compositor = wl_registry_bind(registry, name, &wl_compositor_interface, ver);
    } else if (strcmp(interface, wl_shm_interface.name) == 0) {
        state->shm = wl_registry_bind(registry, name, &wl_shm_interface, 1);
    } else if (strcmp(interface, xdg_wm_base_interface.name) == 0) {
        uint32_t ver = version < 2 ? version : 2;
        state->xdg_wm_base = wl_registry_bind(registry, name, &xdg_wm_base_interface, ver);
        xdg_wm_base_add_listener(state->xdg_wm_base, &wm_base_listener, state);
    }
}

static void registry_global_remove(void *data,
                                   struct wl_registry *registry,
                                   uint32_t name) {
    (void)data;
    (void)registry;
    (void)name;
}

static const struct wl_registry_listener registry_listener = {
    .global = registry_global,
    .global_remove = registry_global_remove,
};

static void nanosleep_ms(uint32_t ms) {
    struct fut_timespec req = {
        .tv_sec = (long)(ms / 1000u),
        .tv_nsec = (long)((ms % 1000u) * 1000000u),
    };
    sys_nanosleep_call(&req, NULL);
}

static void fill_gradient(uint32_t *pixels, int32_t width, int32_t height, int32_t stride_bytes) {
    int32_t stride = stride_bytes / 4;
    for (int32_t y = 0; y < height; ++y) {
        for (int32_t x = 0; x < width; ++x) {
            uint8_t r = (uint8_t)((x * 255) / width);
            uint8_t g = (uint8_t)((y * 255) / height);
            uint8_t b = 128;
            pixels[y * stride + x] = (0xFFu << 24) | (r << 16) | (g << 8) | b;
        }
    }
}

static void draw_rect(uint32_t *pixels,
                      int32_t stride_bytes,
                      int32_t origin_x,
                      int32_t origin_y,
                      int32_t size,
                      uint32_t color) {
    int32_t stride = stride_bytes / 4;
    for (int32_t y = 0; y < size; ++y) {
        int32_t dst_y = origin_y + y;
        if (dst_y < 0 || dst_y >= SURFACE_HEIGHT) {
            continue;
        }
        uint32_t *row = pixels + dst_y * stride;
        for (int32_t x = 0; x < size; ++x) {
            int32_t dst_x = origin_x + x;
            if (dst_x < 0 || dst_x >= SURFACE_WIDTH) {
                continue;
            }
            row[dst_x] = color;
        }
    }
}

int main(void) {
    struct client_state state = {0};

    state.display = wl_display_connect(NULL);
    if (!state.display) {
        printf("[WL-SIMPLE] failed to connect\n");
        return -1;
    }

    state.registry = wl_display_get_registry(state.display);
    wl_registry_add_listener(state.registry, &registry_listener, &state);
    wl_display_roundtrip(state.display);

    if (!state.compositor || !state.shm || !state.xdg_wm_base) {
        printf("[WL-SIMPLE] missing globals\n");
        wl_display_disconnect(state.display);
        return -1;
    }

    state.surface = wl_compositor_create_surface(state.compositor);
    if (!state.surface) {
        printf("[WL-SIMPLE] failed to create surface\n");
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

    size_t buffer_size = (size_t)SURFACE_WIDTH * SURFACE_HEIGHT * 4u;
    const char shm_name[] = "/wl-simple-shm";
    int fd = fut_shm_create(shm_name, buffer_size, O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        printf("[WL-SIMPLE] failed to create shm pool\n");
        wl_display_disconnect(state.display);
        return -1;
    }

    void *map = (void *)sys_mmap(NULL, (long)buffer_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if ((long)map < 0) {
        printf("[WL-SIMPLE] mmap failed\n");
        sys_close(fd);
        wl_display_disconnect(state.display);
        return -1;
    }

    uint32_t *pixels = (uint32_t *)map;
    uint32_t *base = malloc(buffer_size);
    if (!base) {
        printf("[WL-SIMPLE] malloc failed\n");
        sys_munmap_call(map, (long)buffer_size);
        sys_close(fd);
        wl_display_disconnect(state.display);
        return -1;
    }

    fill_gradient(base, SURFACE_WIDTH, SURFACE_HEIGHT, SURFACE_WIDTH * 4);
    memcpy(pixels, base, buffer_size);

    struct wl_shm_pool *pool = wl_shm_create_pool(state.shm, fd, (int32_t)buffer_size);
    struct wl_buffer *buffer = wl_shm_pool_create_buffer(pool,
                                                         0,
                                                         SURFACE_WIDTH,
                                                         SURFACE_HEIGHT,
                                                         SURFACE_WIDTH * 4,
                                                         WL_SHM_FORMAT_ARGB8888);
    wl_shm_pool_destroy(pool);

    wl_surface_attach(state.surface, buffer, 0, 0);
    wl_surface_damage_buffer(state.surface, 0, 0, SURFACE_WIDTH, SURFACE_HEIGHT);
    wl_surface_commit(state.surface);
    wl_display_flush(state.display);

    int32_t rect_x = 0;
    int32_t rect_y = 0;
    int32_t rect_dx = 4;
    int32_t rect_dy = 3;
    uint32_t frames = 0;
    uint32_t frame_delay_ms = 16u;

    while (frames < TARGET_FRAMES) {
        memcpy(pixels, base, buffer_size);

        rect_x += rect_dx;
        rect_y += rect_dy;
        if (rect_x < 0 || rect_x + RECT_SIZE >= SURFACE_WIDTH) {
            rect_dx = -rect_dx;
            rect_x += rect_dx;
        }
        if (rect_y < 0 || rect_y + RECT_SIZE >= SURFACE_HEIGHT) {
            rect_dy = -rect_dy;
            rect_y += rect_dy;
        }

        draw_rect(pixels, SURFACE_WIDTH * 4, rect_x, rect_y, RECT_SIZE, 0xFFFF6600u);

        wl_surface_attach(state.surface, buffer, 0, 0);
        wl_surface_damage_buffer(state.surface, 0, 0, SURFACE_WIDTH, SURFACE_HEIGHT);
        wl_surface_commit(state.surface);

        wl_display_flush(state.display);
        wl_display_dispatch_pending(state.display);

        nanosleep_ms(frame_delay_ms);
        ++frames;
    }

    char done_buf[64];
    int done_len = snprintf(done_buf, sizeof(done_buf),
                             "[WL-SIMPLE] frames=%u ok\n", frames);
    if (done_len > 0) {
        sys_write(1, done_buf, (long)done_len);
        sys_write(2, done_buf, (long)done_len);
    }

    wl_buffer_destroy(buffer);
    sys_munmap_call(map, (long)buffer_size);
    free(base);
    fut_shm_unlink(shm_name);
    sys_close(fd);

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
