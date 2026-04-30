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
#include <user/time.h>

#include <wayland-client-core.h>
#include <wayland-client-protocol.h>
#include "xdg-shell-client-protocol.h"
#include "font.h"

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
#define APP_COUNT 7
struct app_info {
    const char *name;
    const char *label;
    const char *path;
    uint32_t color;
};

/* Apps that are actually staged into ramfs by the spawner. wl-colorwheel
 * / wl-simple were listed before but never built into the ARM64 image,
 * so the corresponding sidebar slots silently failed when clicked. */
static const struct app_info apps[APP_COUNT] = {
    {"terminal", "Term",      "/bin/wl-term",      0xFF9C27B0u},
    {"editor",   "Edit",      "/bin/wl-edit",      0xFF4CAF50u},
    {"files",    "Files",     "/bin/wl-files",     0xFF00BCD4u},
    {"wallp",    "Wallpaper", "/bin/wl-wallpaper", 0xFF6B5B95u},
    {"sysmon",   "Tasks",     "/bin/wl-sysmon",    0xFF2196F3u},
    {"settings", "Settings",  "/bin/wl-settings",  0xFFFF9800u},
    {"shell",    "Shell",     "/bin/shell",        0xFFE91E63u},
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

/* Brighten a 0xAARRGGBB colour by adding `delta` to each RGB channel.
 * Used so the hovered icon visibly lifts without needing a separate
 * highlight texture. */
static uint32_t brighten(uint32_t c, int delta) {
    int a = (c >> 24) & 0xFF;
    int r = (c >> 16) & 0xFF; r += delta; if (r > 255) r = 255;
    int g = (c >>  8) & 0xFF; g += delta; if (g > 255) g = 255;
    int b = (c      ) & 0xFF; b += delta; if (b > 255) b = 255;
    return ((uint32_t)a << 24) | ((uint32_t)r << 16) |
           ((uint32_t)g <<  8) |  (uint32_t)b;
}

static void render_ui(struct shell_state *state,
                      uint32_t *pixels, int32_t width, int32_t height,
                      int32_t stride_bytes) {
    /* Clear background */
    fill_rect(pixels, width, height, stride_bytes, 0, 0, width, height, 0xFF1a1a1au);

    /* Draw top panel */
    fill_rect(pixels, width, height, stride_bytes, 0, 0, width, TOPBAR_HEIGHT, 0xFF2a2a2au);

    /* Draw sidebar */
    fill_rect(pixels, width, height, stride_bytes, 0, TOPBAR_HEIGHT,
              SIDEBAR_WIDTH, height - TOPBAR_HEIGHT, 0xFF333333u);

    /* Hover detection: which icon is the pointer over? */
    int hover_idx = -1;
    if (state) {
        int32_t mx = state->mouse_x, my = state->mouse_y;
        if (mx >= 0 && mx < SIDEBAR_WIDTH && my > TOPBAR_HEIGHT) {
            int32_t off = my - TOPBAR_HEIGHT - ICON_PADDING;
            int32_t cell = ICON_SIZE + ICON_PADDING;
            if (off >= 0) {
                int32_t idx = off / cell;
                int32_t within = off - idx * cell;
                if (idx >= 0 && idx < APP_COUNT && within < ICON_SIZE) {
                    hover_idx = (int)idx;
                }
            }
        }
    }

    /* Draw app icons in sidebar */
    for (int i = 0; i < APP_COUNT; i++) {
        int32_t icon_y = TOPBAR_HEIGHT + ICON_PADDING + i * (ICON_SIZE + ICON_PADDING);
        if (icon_y + ICON_SIZE > height) break;

        int32_t icon_x = (SIDEBAR_WIDTH - ICON_SIZE) / 2;
        bool is_hover = (i == hover_idx);
        uint32_t icon_color = is_hover ? brighten(apps[i].color, 30) : apps[i].color;

        /* Icon background — accented colour, brightened on hover */
        fill_rect(pixels, width, height, stride_bytes,
                  icon_x, icon_y, ICON_SIZE, ICON_SIZE, icon_color);

        /* 1-px white rim on hover for clear feedback */
        if (is_hover) {
            fill_rect(pixels, width, height, stride_bytes,
                      icon_x, icon_y, ICON_SIZE, 1, 0xFFFFFFFFu);
            fill_rect(pixels, width, height, stride_bytes,
                      icon_x, icon_y + ICON_SIZE - 1, ICON_SIZE, 1, 0xFFFFFFFFu);
            fill_rect(pixels, width, height, stride_bytes,
                      icon_x, icon_y, 1, ICON_SIZE, 0xFFFFFFFFu);
            fill_rect(pixels, width, height, stride_bytes,
                      icon_x + ICON_SIZE - 1, icon_y, 1, ICON_SIZE, 0xFFFFFFFFu);
        }

        /* Icon label: short text from apps[].label, centred inside the
         * icon. Truncated to whatever fits at the current font width. */
        const char *label = apps[i].label ? apps[i].label : "";
        int label_len = 0;
        while (label[label_len]) label_len++;
        int max_glyphs = ICON_SIZE / FONT_WIDTH;
        if (label_len > max_glyphs) label_len = max_glyphs;
        int32_t text_w = label_len * FONT_WIDTH;
        int32_t tx = icon_x + (ICON_SIZE - text_w) / 2;
        int32_t ty = icon_y + (ICON_SIZE - FONT_HEIGHT) / 2;
        for (int ci = 0; ci < label_len; ci++) {
            font_render_char(label[ci], pixels,
                             tx + ci * FONT_WIDTH, ty,
                             stride_bytes / 4, width, height,
                             0xFFFFFFFFu, icon_color);
        }
    }

    /* Top panel: brand on the left, clock on the right. Both use the
     * shared bitmap font now that it's linked into futura-shell. */
    {
        int32_t topbar_text_y = (TOPBAR_HEIGHT - FONT_HEIGHT) / 2;
        const char *brand = "FUTURA";
        for (int i = 0; brand[i]; i++) {
            font_render_char(brand[i], pixels,
                             10 + i * FONT_WIDTH, topbar_text_y,
                             stride_bytes / 4, width, height,
                             0xFF8BB4FFu, 0xFF2a2a2au);
        }

        /* Clock — read CLOCK_REALTIME, apply TZ_OFFSET_SEC if set, render
         * "HH:MM" right-aligned on the top panel. Cached TZ value: we
         * read getenv() once across the process lifetime since the env
         * doesn't mutate. */
        struct timespec ts = {0};
        if (clock_gettime(CLOCK_REALTIME, &ts) == 0) {
            static long tz_off = 0;
            static int tz_init = 0;
            if (!tz_init) {
                const char *tz = getenv("TZ_OFFSET_SEC");
                long v = 0;
                int neg = 0;
                if (tz && *tz) {
                    const char *p = tz;
                    if (*p == '-') { neg = 1; p++; }
                    else if (*p == '+') { p++; }
                    while (*p >= '0' && *p <= '9') {
                        v = v * 10 + (*p - '0'); p++;
                    }
                    if (neg) v = -v;
                }
                tz_off = v;
                tz_init = 1;
            }
            long s = ts.tv_sec + tz_off;
            long hr = (((s / 3600) % 24) + 24) % 24;
            long mn = (((s / 60) % 60) + 60) % 60;
            char tbuf[6] = { (char)('0' + (hr / 10)),
                             (char)('0' + (hr % 10)),
                             ':',
                             (char)('0' + (mn / 10)),
                             (char)('0' + (mn % 10)),
                             '\0' };
            int tlen = 5;
            int32_t tx = width - 10 - tlen * FONT_WIDTH;
            for (int i = 0; i < tlen; i++) {
                font_render_char(tbuf[i], pixels,
                                 tx + i * FONT_WIDTH, topbar_text_y,
                                 stride_bytes / 4, width, height,
                                 0xFFE0E0E0u, 0xFF2a2a2au);
            }
        }
    }
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
                long pid = sys_fork_call();
                if (pid == 0) {
                    /* Child: exec the app with wayland envvars so it can
                     * connect to the compositor at /run/wayland-0. */
                    const char *argv[] = { apps[icon_index].path, NULL };
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
                    sys_execve_call(apps[icon_index].path,
                                    (char *const *)argv,
                                    (char *const *)envp);
                    sys_exit(127);
                }
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

    /* Initialize standard streams */
    int console_fd = sys_open("/dev/console", O_RDWR, 0);
    if (console_fd < 0) {
        /* Can't print error - no stdout yet! Just exit. */
        return -1;
    }
    /* console_fd should be 0 (stdin). Dup to stdout and stderr. */
    if (console_fd != 0) {
        sys_close(0);
        sys_dup2_call(console_fd, 0);
        sys_close(console_fd);
    }
    sys_dup2_call(0, 1);  /* stdout */
    sys_dup2_call(0, 2);  /* stderr */

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
    render_ui(&state, state.pixels, SCREEN_WIDTH, SCREEN_HEIGHT, SCREEN_WIDTH * 4);

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
        render_ui(&state, state.pixels, SCREEN_WIDTH, SCREEN_HEIGHT, SCREEN_WIDTH * 4);

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
