#include "log.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <futura/compat/posix_shm.h>
#include <user/stdio.h>
#include <user/sys.h>

#include <wayland-client-core.h>
#include <wayland-client-protocol.h>
#include "xdg-shell-client-protocol.h"

#define SURFACE_WIDTH   320
#define SURFACE_HEIGHT  200
#define RECT_SIZE       64
#define TARGET_FRAMES   120
#define CLIPBOARD_MIME  "text/plain;charset=utf-8"
#define KEY_C            46u

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
    struct wl_seat *seat;
    struct wl_keyboard *keyboard;
    struct wl_data_device_manager *data_device_manager;
    struct wl_data_device *data_device;
    struct wl_data_source *data_source;
    struct wl_surface *surface;
    struct xdg_surface *xdg_surface;
    struct xdg_toplevel *toplevel;
    bool configured;
    uint32_t configure_serial;
    struct wl_callback *frame_cb;
    bool frame_done;
    uint32_t last_serial;
    bool have_copy;
    char copy_text[64];
};

static void ensure_data_interfaces(struct client_state *state);

static void data_source_target(void *data, struct wl_data_source *source, const char *mime_type) {
    (void)data;
    (void)source;
    (void)mime_type;
}

static void data_source_send(void *data,
                             struct wl_data_source *source,
                             const char *mime_type,
                             int32_t fd) {
    (void)source;
    struct client_state *state = data;
    if (!state || fd < 0) {
        if (fd >= 0) {
            sys_close(fd);
        }
        return;
    }

    if (!state->have_copy || strcmp(mime_type, CLIPBOARD_MIME) != 0) {
        sys_close(fd);
        return;
    }

    size_t len = strlen(state->copy_text) + 1;
    sys_write(fd, state->copy_text, (long)len);
    sys_close(fd);

#ifdef DEBUG_WAYLAND
    printf("[WL-SIMPLE] copy send %s\n", state->copy_text);
#endif
}

static void data_source_cancelled(void *data, struct wl_data_source *source) {
    (void)source;
    struct client_state *state = data;
    if (state) {
        state->have_copy = false;
    }
}

static const struct wl_data_source_listener data_source_listener = {
    .target = data_source_target,
    .send = data_source_send,
    .cancelled = data_source_cancelled,
};

static void data_device_data_offer(void *data,
                                   struct wl_data_device *device,
                                   struct wl_data_offer *offer) {
    (void)data;
    (void)device;
    if (offer) {
        wl_data_offer_destroy(offer);
    }
}

static void data_device_enter(void *data,
                              struct wl_data_device *device,
                              uint32_t serial,
                              struct wl_surface *surface,
                              wl_fixed_t x,
                              wl_fixed_t y,
                              struct wl_data_offer *offer) {
    (void)data; (void)device; (void)serial; (void)surface; (void)x; (void)y;
    if (offer) {
        wl_data_offer_destroy(offer);
    }
}

static void data_device_leave(void *data, struct wl_data_device *device) {
    (void)data;
    (void)device;
}

static void data_device_motion(void *data,
                               struct wl_data_device *device,
                               uint32_t time,
                               wl_fixed_t x,
                               wl_fixed_t y) {
    (void)data; (void)device; (void)time; (void)x; (void)y;
}

static void data_device_drop(void *data, struct wl_data_device *device) {
    (void)data;
    (void)device;
}

static void data_device_selection(void *data,
                                  struct wl_data_device *device,
                                  struct wl_data_offer *offer) {
    (void)device;
    struct client_state *state = data;
    if (offer) {
        wl_data_offer_destroy(offer);
    } else if (state) {
        state->have_copy = false;
    }
}

static const struct wl_data_device_listener data_device_listener = {
    .data_offer = data_device_data_offer,
    .enter = data_device_enter,
    .leave = data_device_leave,
    .motion = data_device_motion,
    .drop = data_device_drop,
    .selection = data_device_selection,
};

static void ensure_data_interfaces(struct client_state *state) {
    if (!state || !state->data_device_manager) {
        return;
    }

    if (!state->data_source) {
        state->data_source = wl_data_device_manager_create_data_source(state->data_device_manager);
        if (state->data_source) {
            wl_data_source_add_listener(state->data_source, &data_source_listener, state);
        }
    }

    if (state->seat && !state->data_device) {
        state->data_device = wl_data_device_manager_get_data_device(state->data_device_manager, state->seat);
        if (state->data_device) {
            wl_data_device_add_listener(state->data_device, &data_device_listener, state);
        }
    }
}

static void perform_copy(struct client_state *state) {
    if (!state || !state->last_serial) {
        return;
    }

    ensure_data_interfaces(state);
    if (!state->data_device || !state->data_source) {
        return;
    }

    const char *payload = "Hello from wl-simple";
    strncpy(state->copy_text, payload, sizeof(state->copy_text) - 1);
    state->copy_text[sizeof(state->copy_text) - 1] = '\0';

    wl_data_source_offer(state->data_source, CLIPBOARD_MIME);
    wl_data_device_set_selection(state->data_device, state->data_source, state->last_serial);
    state->have_copy = true;

#ifdef DEBUG_WAYLAND
    printf("[WL-SIMPLE] copy set_selection \"%s\"\n", state->copy_text);
#endif
}

static void keyboard_keymap(void *data,
                            struct wl_keyboard *keyboard,
                            uint32_t format,
                            int32_t fd,
                            uint32_t size) {
    (void)data;
    (void)keyboard;
    (void)format;
    (void)size;
    if (fd >= 0) {
        sys_close(fd);
    }
}

static void keyboard_enter(void *data,
                           struct wl_keyboard *keyboard,
                           uint32_t serial,
                           struct wl_surface *surface,
                           struct wl_array *keys) {
    (void)data; (void)keyboard; (void)serial; (void)surface; (void)keys;
}

static void keyboard_leave(void *data,
                           struct wl_keyboard *keyboard,
                           uint32_t serial,
                           struct wl_surface *surface) {
    (void)data; (void)keyboard; (void)serial; (void)surface;
}

static void keyboard_key(void *data,
                         struct wl_keyboard *keyboard,
                         uint32_t serial,
                         uint32_t time,
                         uint32_t key,
                         uint32_t key_state) {
    (void)keyboard;
    (void)time;
    struct client_state *state = data;
    if (!state) {
        return;
    }
    if (key_state == WL_KEYBOARD_KEY_STATE_PRESSED) {
        state->last_serial = serial;
        if (key == KEY_C) {
            perform_copy(state);
        }
    }
}

static void keyboard_modifiers(void *data,
                               struct wl_keyboard *keyboard,
                               uint32_t serial,
                               uint32_t mods_depressed,
                               uint32_t mods_latched,
                               uint32_t mods_locked,
                               uint32_t group) {
    (void)data; (void)keyboard; (void)serial;
    (void)mods_depressed; (void)mods_latched; (void)mods_locked; (void)group;
}

static void keyboard_repeat(void *data,
                            struct wl_keyboard *keyboard,
                            int32_t rate,
                            int32_t delay) {
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

static void seat_capabilities(void *data,
                              struct wl_seat *seat,
                              uint32_t capabilities) {
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

    ensure_data_interfaces(state);
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
    } else if (strcmp(interface, wl_seat_interface.name) == 0) {
        uint32_t ver = version < 7 ? version : 7;
        state->seat = wl_registry_bind(registry, name, &wl_seat_interface, ver);
        if (state->seat) {
            wl_seat_add_listener(state->seat, &seat_listener, state);
        }
        ensure_data_interfaces(state);
    } else if (strcmp(interface, wl_data_device_manager_interface.name) == 0) {
        uint32_t ver = version < 1 ? version : 1;
        state->data_device_manager = wl_registry_bind(registry, name, &wl_data_device_manager_interface, ver);
        ensure_data_interfaces(state);
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

static void frame_done(void *data, struct wl_callback *callback, uint32_t time) {
    (void)time;
    struct client_state *state = data;
    state->frame_done = true;
    if (state->frame_cb == callback) {
        state->frame_cb = NULL;
    }
    wl_callback_destroy(callback);
}

static const struct wl_callback_listener frame_listener = {
    .done = frame_done,
};

static void request_frame(struct client_state *state) {
    if (!state || !state->surface) {
        return;
    }
    state->frame_done = false;
    state->frame_cb = wl_surface_frame(state->surface);
    wl_callback_add_listener(state->frame_cb, &frame_listener, state);
}

static bool wait_for_frame(struct client_state *state) {
    if (!state || !state->display) {
        return false;
    }
    while (!state->frame_done) {
        if (wl_display_dispatch(state->display) < 0) {
            return false;
        }
    }
    return true;
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

    request_frame(&state);
    wl_surface_attach(state.surface, buffer, 0, 0);
    wl_surface_damage_buffer(state.surface, 0, 0, SURFACE_WIDTH, SURFACE_HEIGHT);
    wl_surface_commit(state.surface);
    wl_display_flush(state.display);
    bool keep_running = true;
    if (!wait_for_frame(&state)) {
        printf("[WL-SIMPLE] failed to receive initial frame callback\n");
        keep_running = false;
    }

    int32_t rect_x = 0;
    int32_t rect_y = 0;
    int32_t rect_dx = 4;
    int32_t rect_dy = 3;
    uint32_t frames = 0;

    while (keep_running && frames < TARGET_FRAMES) {
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

        request_frame(&state);
        wl_surface_attach(state.surface, buffer, 0, 0);
        wl_surface_damage_buffer(state.surface, 0, 0, SURFACE_WIDTH, SURFACE_HEIGHT);
        wl_surface_commit(state.surface);
        wl_display_flush(state.display);
        if (!wait_for_frame(&state)) {
            printf("[WL-SIMPLE] dispatch error; stopping animation\n");
            keep_running = false;
            break;
        }
        ++frames;
    }

    if (state.frame_cb) {
        wl_callback_destroy(state.frame_cb);
        state.frame_cb = NULL;
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

    if (state.data_device) {
        wl_data_device_destroy(state.data_device);
    }
    if (state.data_source) {
        wl_data_source_destroy(state.data_source);
    }
    if (state.keyboard) {
        wl_keyboard_destroy(state.keyboard);
    }
    if (state.seat) {
        wl_seat_destroy(state.seat);
    }
    if (state.data_device_manager) {
        wl_data_device_manager_destroy(state.data_device_manager);
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
