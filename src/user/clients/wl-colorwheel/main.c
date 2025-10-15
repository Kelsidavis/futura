#include "log.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <futura/compat/posix_shm.h>
#include <shared/fut_timespec.h>
#include <user/stdio.h>
#include <user/stdlib.h>
#include <user/string.h>
#include <user/sys.h>

#include <wayland-client-core.h>
#include <wayland-client-protocol.h>
#include "xdg-shell-client-protocol.h"

#define SURFACE_WIDTH   320
#define SURFACE_HEIGHT  240
#define TARGET_FRAMES   120u
#define CLIPBOARD_MIME  "text/plain;charset=utf-8"
#define KEY_V            47u

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
    struct wl_data_offer *selection_offer;
    struct wl_data_offer *pending_offer;
    bool pending_offer_has_mime;
    bool selection_has_mime;
    uint32_t paste_counter;
    struct wl_surface *surface;
    struct xdg_surface *xdg_surface;
    struct xdg_toplevel *toplevel;
    bool configured;
    uint32_t configure_serial;
};

static void ensure_data_interfaces(struct client_state *state);
static void perform_paste(struct client_state *state);

static void data_offer_offer(void *data,
                             struct wl_data_offer *offer,
                             const char *mime_type) {
    struct client_state *state = data;
    if (!state || !offer || !mime_type) {
        return;
    }
    if (strcmp(mime_type, CLIPBOARD_MIME) == 0 && state->pending_offer == offer) {
        state->pending_offer_has_mime = true;
    }
}

static const struct wl_data_offer_listener data_offer_listener = {
    .offer = data_offer_offer,
};

static void data_device_data_offer(void *data,
                                   struct wl_data_device *device,
                                   struct wl_data_offer *offer) {
    (void)device;
    struct client_state *state = data;
    if (!state) {
        wl_data_offer_destroy(offer);
        return;
    }
    if (state->pending_offer && state->pending_offer != offer) {
        wl_data_offer_destroy(state->pending_offer);
    }
    state->pending_offer = offer;
    state->pending_offer_has_mime = false;
    wl_data_offer_add_listener(offer, &data_offer_listener, state);
}

static void data_device_selection(void *data,
                                  struct wl_data_device *device,
                                  struct wl_data_offer *offer) {
    (void)device;
    struct client_state *state = data;
    if (!state) {
        if (offer) {
            wl_data_offer_destroy(offer);
        }
        return;
    }

    if (state->selection_offer && state->selection_offer != offer) {
        wl_data_offer_destroy(state->selection_offer);
    }

    if (!offer) {
        state->selection_offer = NULL;
        state->selection_has_mime = false;
        return;
    }

    state->selection_offer = offer;
    if (state->pending_offer == offer) {
        state->selection_has_mime = state->pending_offer_has_mime;
        state->pending_offer = NULL;
        state->pending_offer_has_mime = false;
    } else {
        state->selection_has_mime = false;
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
    (void)data; (void)device;
}

static void data_device_motion(void *data,
                               struct wl_data_device *device,
                               uint32_t time,
                               wl_fixed_t x,
                               wl_fixed_t y) {
    (void)data; (void)device; (void)time; (void)x; (void)y;
}

static void data_device_drop(void *data, struct wl_data_device *device) {
    (void)data; (void)device;
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
    if (!state || !state->data_device_manager || !state->seat) {
        return;
    }
    if (!state->data_device) {
        state->data_device = wl_data_device_manager_get_data_device(state->data_device_manager, state->seat);
        if (state->data_device) {
            wl_data_device_add_listener(state->data_device, &data_device_listener, state);
        }
    }
}

static void keyboard_keymap(void *data,
                            struct wl_keyboard *keyboard,
                            uint32_t format,
                            int32_t fd,
                            uint32_t size) {
    (void)data; (void)keyboard; (void)format; (void)size;
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
                         uint32_t state_value) {
    (void)keyboard; (void)serial; (void)time;
    struct client_state *state = data;
    if (!state) {
        return;
    }
    if (state_value == WL_KEYBOARD_KEY_STATE_PRESSED && key == KEY_V) {
        perform_paste(state);
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

static void perform_paste(struct client_state *state) {
    if (!state || !state->selection_offer || !state->selection_has_mime) {
        return;
    }

    ensure_data_interfaces(state);
    if (!state->data_device) {
        return;
    }

    char shm_name[64];
    state->paste_counter++;
    int name_len = snprintf(shm_name, sizeof(shm_name), "/wl-colorwheel-clip-%u", state->paste_counter);
    if (name_len <= 0) {
        return;
    }

    size_t clip_size = 256;
    int fd = fut_shm_create(shm_name, clip_size, O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        printf("[WL-COLOR] paste: failed to allocate shm\n");
        return;
    }

    wl_data_offer_receive(state->selection_offer, CLIPBOARD_MIME, fd);
    wl_display_flush(state->display);
    wl_display_roundtrip(state->display);

    void *map = (void *)sys_mmap(NULL, (long)clip_size, PROT_READ, MAP_SHARED, fd, 0);
    if ((long)map >= 0) {
        const char *text = (const char *)map;
        printf("[WL-COLOR] paste: \"%s\"\n", text);
        sys_munmap_call(map, (long)clip_size);
    } else {
        printf("[WL-COLOR] paste: mmap failed\n");
    }

    sys_close(fd);
    fut_shm_unlink(shm_name);
}

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

static void nanosleep_ms(uint32_t ms) {
    struct fut_timespec req = {
        .tv_sec = (long)(ms / 1000u),
        .tv_nsec = (long)((ms % 1000u) * 1000000u),
    };
    sys_nanosleep_call(&req, NULL);
}

static uint32_t hsv_to_argb(uint8_t h, uint8_t s, uint8_t v) {
    uint8_t region = (uint8_t)(h / 43);
    uint8_t remainder = (uint8_t)((h - region * 43u) * 6u);

    uint32_t p = ((uint32_t)v * (255u - (uint32_t)s)) / 255u;
    uint32_t q = ((uint32_t)v * (255u - ((uint32_t)s * remainder) / 255u)) / 255u;
    uint32_t t = ((uint32_t)v * (255u - ((uint32_t)s * (255u - remainder)) / 255u)) / 255u;

    uint32_t r = v;
    uint32_t g = t;
    uint32_t b = p;

    switch (region) {
    case 0:
        r = v; g = t; b = p;
        break;
    case 1:
        r = q; g = v; b = p;
        break;
    case 2:
        r = p; g = v; b = t;
        break;
    case 3:
        r = p; g = q; b = v;
        break;
    case 4:
        r = t; g = p; b = v;
        break;
    default:
        r = v; g = p; b = q;
        break;
    }
    return (0xFFu << 24) | ((uint32_t)r << 16) | ((uint32_t)g << 8) | (uint32_t)b;
}

static uint8_t clamp_u8(int32_t value) {
    if (value < 0) {
        return 0;
    }
    if (value > 255) {
        return 255;
    }
    return (uint8_t)value;
}

static void render_colorwheel(uint32_t *pixels,
                              int32_t stride_bytes,
                              uint32_t frame_tick) {
    int32_t stride = stride_bytes / 4;
    int32_t cx = SURFACE_WIDTH / 2;
    int32_t cy = SURFACE_HEIGHT / 2;
    int32_t max_radius = (SURFACE_WIDTH < SURFACE_HEIGHT ? SURFACE_WIDTH : SURFACE_HEIGHT) / 2;

    for (int32_t y = 0; y < SURFACE_HEIGHT; ++y) {
        for (int32_t x = 0; x < SURFACE_WIDTH; ++x) {
            int32_t dx = x - cx;
            int32_t dy = y - cy;
            int32_t abs_dx = dx < 0 ? -dx : dx;
            int32_t abs_dy = dy < 0 ? -dy : dy;
            int32_t radius = abs_dx > abs_dy ? abs_dx : abs_dy;

            if (radius > max_radius) {
                pixels[y * stride + x] = 0xFF101010u;
                continue;
            }

            int32_t hue_base = (dx * 6) - (dy * 6);
            uint8_t hue = (uint8_t)((hue_base + (int32_t)(frame_tick * 4u)) & 0xFF);
            uint8_t sat = clamp_u8(255 - (radius * 255) / (max_radius ? max_radius : 1));
            uint8_t val = (uint8_t)(200 + (radius * 55) / (max_radius ? max_radius : 1));

            pixels[y * stride + x] = hsv_to_argb(hue, sat, val);
        }
    }
}

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

int main(void) {
    struct client_state state = {0};

    state.display = wl_display_connect(NULL);
    if (!state.display) {
        printf("[WL-COLOR] failed to connect\n");
        return -1;
    }

    state.registry = wl_display_get_registry(state.display);
    wl_registry_add_listener(state.registry, &registry_listener, &state);
    wl_display_roundtrip(state.display);

    if (!state.compositor || !state.shm || !state.xdg_wm_base) {
        printf("[WL-COLOR] missing globals\n");
        wl_display_disconnect(state.display);
        return -1;
    }

    state.surface = wl_compositor_create_surface(state.compositor);
    if (!state.surface) {
        printf("[WL-COLOR] failed to create surface\n");
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
    const char shm_name[] = "/wl-colorwheel-shm";
    int fd = fut_shm_create(shm_name, buffer_size, O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        printf("[WL-COLOR] failed to create shm pool\n");
        wl_display_disconnect(state.display);
        return -1;
    }

    void *map = (void *)sys_mmap(NULL, (long)buffer_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if ((long)map < 0) {
        printf("[WL-COLOR] mmap failed\n");
        sys_close(fd);
        wl_display_disconnect(state.display);
        return -1;
    }

    uint32_t *pixels = (uint32_t *)map;
    struct wl_shm_pool *pool = wl_shm_create_pool(state.shm, fd, (int32_t)buffer_size);
    struct wl_buffer *buffer = wl_shm_pool_create_buffer(pool,
                                                         0,
                                                         SURFACE_WIDTH,
                                                         SURFACE_HEIGHT,
                                                         SURFACE_WIDTH * 4,
                                                         WL_SHM_FORMAT_ARGB8888);
    wl_shm_pool_destroy(pool);

    uint32_t frame_delay_ms = 16u;
    uint32_t frames = 0;

    while (frames < TARGET_FRAMES) {
        render_colorwheel(pixels, SURFACE_WIDTH * 4, frames);

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
                             "[WL-COLOR] frames=%u ok\n", frames);
    if (done_len > 0) {
        sys_write(1, done_buf, (long)done_len);
        sys_write(2, done_buf, (long)done_len);
    }

    wl_buffer_destroy(buffer);
    sys_munmap_call(map, (long)buffer_size);
    fut_shm_unlink(shm_name);
    sys_close(fd);

    if (state.selection_offer) {
        wl_data_offer_destroy(state.selection_offer);
        state.selection_offer = NULL;
    }
    if (state.pending_offer) {
        wl_data_offer_destroy(state.pending_offer);
        state.pending_offer = NULL;
    }
    if (state.data_device) {
        wl_data_device_destroy(state.data_device);
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
