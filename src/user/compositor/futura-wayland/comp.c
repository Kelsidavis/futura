#include "comp.h"
#include "cursor.h"
#include "log.h"
#include "seat.h"
#include "shm_backend.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <wayland-server-protocol.h>

#include <user/libfutura.h>
#include <user/stdio.h>
#include <user/sys.h>

#define O_RDWR      0x0002
#define PROT_READ   0x0001
#define PROT_WRITE  0x0002
#define MAP_SHARED  0x0001

static inline uint32_t clamp_u32(uint32_t value, uint32_t max) {
    return value > max ? max : value;
}

static inline int32_t clamp_i32(int32_t value, int32_t min, int32_t max) {
    if (value < min) {
        return min;
    }
    if (value > max) {
        return max;
    }
    return value;
}

static void comp_damage_union(struct compositor_state *comp,
                              const struct comp_damage *damage) {
    if (!comp || !damage || !damage->valid ||
        damage->width <= 0 || damage->height <= 0) {
        return;
    }

    if (!comp->pending_damage.valid) {
        comp->pending_damage = *damage;
    } else {
        int32_t x1 = comp->pending_damage.x;
        int32_t y1 = comp->pending_damage.y;
        int32_t x2 = x1 + comp->pending_damage.width;
        int32_t y2 = y1 + comp->pending_damage.height;

        int32_t nx1 = damage->x;
        int32_t ny1 = damage->y;
        int32_t nx2 = nx1 + damage->width;
        int32_t ny2 = ny1 + damage->height;

        if (nx1 < x1) x1 = nx1;
        if (ny1 < y1) y1 = ny1;
        if (nx2 > x2) x2 = nx2;
        if (ny2 > y2) y2 = ny2;

        comp->pending_damage.x = x1;
        comp->pending_damage.y = y1;
        comp->pending_damage.width = x2 - x1;
        comp->pending_damage.height = y2 - y1;
    }
    comp->pending_damage.valid = true;
    comp->needs_repaint = true;
}

const struct fut_fb_info *comp_get_fb_info(const struct compositor_state *comp) {
    return comp ? &comp->fb_info : NULL;
}

int comp_state_init(struct compositor_state *comp) {
    if (!comp) {
        return -1;
    }

    memset(comp, 0, sizeof(*comp));
    comp->fb_fd = -1;

    int fd = (int)sys_open("/dev/fb0", O_RDWR, 0);
    if (fd < 0) {
        printf("[WAYLAND] failed to open /dev/fb0 (err=%d)\n", fd);
        return -1;
    }

    struct fut_fb_info info = {0};
    if (sys_ioctl(fd, FBIOGET_INFO, (long)&info) < 0) {
        printf("[WAYLAND] FBIOGET_INFO failed\n");
        sys_close(fd);
        return -1;
    }

    if (info.bpp != 32) {
        printf("[WAYLAND] unsupported framebuffer format (bpp=%u)\n", info.bpp);
        sys_close(fd);
        return -1;
    }

    size_t map_size = (size_t)info.pitch * info.height;
    void *map = (void *)sys_mmap(NULL,
                                 (long)map_size,
                                 PROT_READ | PROT_WRITE,
                                 MAP_SHARED,
                                 fd,
                                 0);
    if ((long)map < 0) {
        printf("[WAYLAND] mmap framebuffer failed\n");
        sys_close(fd);
        return -1;
    }

    comp->fb_fd = fd;
    comp->fb_map = (uint8_t *)map;
    comp->fb_map_size = map_size;
    comp->fb_info = info;
    comp->running = true;
    comp->frame_delay_ms = 16u;
    comp->pointer_x = (int32_t)info.width / 2;
    comp->pointer_y = (int32_t)info.height / 2;
    comp->cursor = cursor_create();
    if (!comp->cursor) {
        printf("[WAYLAND] failed to create cursor state\n");
        comp_state_finish(comp);
        return -1;
    }
    cursor_set_position(comp->cursor, comp->pointer_x, comp->pointer_y);
    return 0;
}

void comp_state_finish(struct compositor_state *comp) {
    if (!comp) {
        return;
    }

    comp->running = false;

    if (comp->cursor) {
        cursor_destroy(comp->cursor);
        comp->cursor = NULL;
    }

    if (comp->fb_map && comp->fb_map_size) {
        sys_munmap_call(comp->fb_map, (long)comp->fb_map_size);
        comp->fb_map = NULL;
        comp->fb_map_size = 0;
    }
    if (comp->fb_fd >= 0) {
        sys_close(comp->fb_fd);
        comp->fb_fd = -1;
    }
}

static void comp_clear_framebuffer(struct compositor_state *comp) {
    if (!comp || !comp->fb_map) {
        return;
    }
    for (uint32_t row = 0; row < comp->fb_info.height; ++row) {
        uint8_t *dst_row = comp->fb_map + (size_t)row * comp->fb_info.pitch;
        memset(dst_row, 0, comp->fb_info.pitch);
    }
}

void comp_present_buffer(struct compositor_state *comp,
                         int32_t dst_x,
                         int32_t dst_y,
                         struct comp_buffer *buffer,
                         const struct comp_damage *damage) {
    if (!comp || !buffer || !buffer->data || !comp->fb_map) {
        return;
    }

    int32_t src_width = buffer->width;
    int32_t src_height = buffer->height;
    int32_t src_stride = buffer->stride;
    if (src_width <= 0 || src_height <= 0 || src_stride <= 0) {
        return;
    }

    int32_t copy_x = 0;
    int32_t copy_y = 0;
    int32_t copy_w = src_width;
    int32_t copy_h = src_height;

    if (damage && damage->valid) {
        copy_x = damage->x;
        copy_y = damage->y;
        copy_w = damage->width;
        copy_h = damage->height;
    }

    if (copy_x < 0) {
        copy_w += copy_x;
        copy_x = 0;
    }
    if (copy_y < 0) {
        copy_h += copy_y;
        copy_y = 0;
    }

    if (copy_w <= 0 || copy_h <= 0) {
        return;
    }

    uint32_t dst_w = comp->fb_info.width;
    uint32_t dst_h = comp->fb_info.height;

    if (copy_x >= src_width || copy_y >= src_height) {
        return;
    }

    int32_t max_w_src = src_width - copy_x;
    int32_t max_h_src = src_height - copy_y;
    if (copy_w > max_w_src) {
        copy_w = max_w_src;
    }
    if (copy_h > max_h_src) {
        copy_h = max_h_src;
    }

    int32_t dst_start_x = dst_x + copy_x;
    int32_t dst_start_y = dst_y + copy_y;
    int32_t dst_end_x = dst_start_x + copy_w;
    int32_t dst_end_y = dst_start_y + copy_h;

    if (dst_end_x <= 0 || dst_end_y <= 0 ||
        dst_start_x >= (int32_t)dst_w || dst_start_y >= (int32_t)dst_h) {
        return;
    }

    if (dst_start_x < 0) {
        int32_t delta = -dst_start_x;
        copy_w -= delta;
        copy_x += delta;
        dst_start_x = 0;
    }
    if (dst_start_y < 0) {
        int32_t delta = -dst_start_y;
        copy_h -= delta;
        copy_y += delta;
        dst_start_y = 0;
    }

    if (dst_end_x > (int32_t)dst_w) {
        copy_w -= dst_end_x - (int32_t)dst_w;
        dst_end_x = (int32_t)dst_w;
    }
    if (dst_end_y > (int32_t)dst_h) {
        copy_h -= dst_end_y - (int32_t)dst_h;
        dst_end_y = (int32_t)dst_h;
    }

    if (copy_w <= 0 || copy_h <= 0) {
        return;
    }

    uint8_t *dst = comp->fb_map + (size_t)dst_start_y * comp->fb_info.pitch + (size_t)dst_start_x * 4;
    const uint8_t *src = (const uint8_t *)buffer->data + (size_t)copy_y * src_stride + (size_t)copy_x * 4;
    uint32_t row_bytes = (uint32_t)copy_w * 4u;

    for (int32_t y = 0; y < copy_h; ++y) {
        memcpy(dst + (size_t)y * comp->fb_info.pitch,
               src + (size_t)y * src_stride,
               row_bytes);
    }
}

struct comp_surface *comp_surface_create(struct compositor_state *comp,
                                         struct wl_resource *surface_resource) {
    struct comp_surface *surface = malloc(sizeof(*surface));
    if (!surface) {
        return NULL;
    }
    memset(surface, 0, sizeof(*surface));
    surface->comp = comp;
    surface->surface_resource = surface_resource;
    wl_list_init(&surface->frame_callbacks);
    surface->pending_damage.valid = false;
    surface->has_pending_buffer = false;
    surface->surface_id = ++comp->next_surface_id;
    if (!comp->active_surface) {
        comp->active_surface = surface;
    }
    return surface;
}

void comp_surface_destroy(struct comp_surface *surface) {
    if (!surface) {
        return;
    }

    struct comp_frame_callback *cb, *tmp;
    wl_list_for_each_safe(cb, tmp, &surface->frame_callbacks, link) {
        wl_resource_destroy(cb->resource);
        free(cb);
    }

    if (surface->backing) {
        free(surface->backing);
    }

    struct compositor_state *comp = surface->comp;
    if (comp) {
        if (surface->has_backing) {
            struct comp_damage dmg = {
                .x = comp->window_x,
                .y = comp->window_y,
                .width = surface->width,
                .height = surface->height,
                .valid = true,
            };
            comp_request_repaint(comp, &dmg);
        }
        if (comp->active_surface == surface) {
            comp->active_surface = NULL;
        }
        if (comp->focused_surface == surface) {
            comp->focused_surface = NULL;
        }
        if (comp->seat) {
            seat_surface_destroyed(comp->seat, surface);
        }
    }

    free(surface);
}

void comp_surface_attach(struct comp_surface *surface,
                         struct wl_resource *buffer_resource) {
    if (!surface) {
        return;
    }
    surface->pending_buffer_resource = buffer_resource;
    surface->has_pending_buffer = (buffer_resource != NULL);
}

void comp_surface_damage(struct comp_surface *surface,
                         int32_t x, int32_t y,
                         int32_t width, int32_t height) {
    if (!surface) {
        return;
    }

    surface->pending_damage.x = x;
    surface->pending_damage.y = y;
    surface->pending_damage.width = width;
    surface->pending_damage.height = height;
    surface->pending_damage.valid = true;
}

static uint32_t comp_now_msec(void) {
    return (uint32_t)sys_time_millis_call();
}

static void frame_callback_resource_destroy(struct wl_resource *resource) {
    struct comp_frame_callback *cb = wl_resource_get_user_data(resource);
    if (!cb) {
        return;
    }
    wl_list_remove(&cb->link);
    free(cb);
}

void comp_surface_commit(struct comp_surface *surface) {
    if (!surface) {
        return;
    }

    if (surface->has_pending_buffer && surface->pending_buffer_resource) {
        struct comp_buffer buffer = {0};
        if (shm_buffer_import(surface->pending_buffer_resource, &buffer) == 0) {
            size_t required = (size_t)buffer.stride * (size_t)buffer.height;
            if (required == 0) {
                required = (size_t)buffer.width * 4u;
            }
            if (surface->backing_size < required) {
                uint8_t *new_mem = realloc(surface->backing, required);
                if (!new_mem) {
                    shm_buffer_release(&buffer);
                    surface->pending_buffer_resource = NULL;
                    surface->has_pending_buffer = false;
                    return;
                }
                surface->backing = new_mem;
                surface->backing_size = required;
            }
            for (int32_t row = 0; row < buffer.height; ++row) {
                const uint8_t *src_row = (const uint8_t *)buffer.data + (size_t)row * buffer.stride;
                uint8_t *dst_row = surface->backing + (size_t)row * buffer.stride;
                memcpy(dst_row, src_row, (size_t)buffer.width * 4u);
            }

            surface->width = buffer.width;
            surface->height = buffer.height;
            surface->stride = buffer.stride;
            surface->has_backing = true;
            surface->comp->active_surface = surface;

            if (!surface->comp->window_pos_initialised) {
                int32_t cx = ((int32_t)surface->comp->fb_info.width - surface->width) / 2;
                int32_t cy = ((int32_t)surface->comp->fb_info.height - surface->height) / 2;
                int32_t max_x = (int32_t)surface->comp->fb_info.width - surface->width;
                int32_t max_y = (int32_t)surface->comp->fb_info.height - surface->height;
                if (max_x < 0) max_x = 0;
                if (max_y < 0) max_y = 0;
                surface->comp->window_x = clamp_i32(cx, 0, max_x);
                surface->comp->window_y = clamp_i32(cy, 0, max_y);
                surface->comp->window_pos_initialised = true;
            }

            struct comp_damage dmg = {
                .x = surface->comp->window_x,
                .y = surface->comp->window_y,
                .width = surface->width,
                .height = surface->height,
                .valid = true,
            };
            comp_damage_union(surface->comp, &dmg);

            shm_buffer_release(&buffer);
        } else {
            wl_buffer_send_release(surface->pending_buffer_resource);
        }
        surface->pending_buffer_resource = NULL;
        surface->has_pending_buffer = false;
        surface->pending_damage.valid = false;
    }

    uint32_t now = comp_now_msec();
    struct comp_frame_callback *cb, *tmp;
    wl_list_for_each_safe(cb, tmp, &surface->frame_callbacks, link) {
        wl_callback_send_done(cb->resource, now);
        wl_resource_destroy(cb->resource);
        wl_list_remove(&cb->link);
        free(cb);
    }
}

void comp_surface_frame(struct comp_surface *surface,
                        struct wl_resource *callback_resource) {
    if (!surface || !callback_resource) {
        return;
    }

    struct comp_frame_callback *cb = malloc(sizeof(*cb));
    if (!cb) {
        wl_resource_destroy(callback_resource);
        return;
    }
    cb->resource = callback_resource;
    wl_list_insert(surface->frame_callbacks.prev, &cb->link);
    wl_resource_set_user_data(callback_resource, cb);
    wl_resource_set_destructor(callback_resource, frame_callback_resource_destroy);
}

static void comp_draw_surface(struct compositor_state *comp,
                              struct comp_surface *surface) {
    if (!comp || !surface || !surface->has_backing) {
        return;
    }

    struct comp_buffer buf = {
        .data = surface->backing,
        .width = surface->width,
        .height = surface->height,
        .stride = surface->stride,
        .format = WL_SHM_FORMAT_ARGB8888,
    };
    comp_present_buffer(comp, comp->window_x, comp->window_y, &buf, NULL);
}

static void comp_render(struct compositor_state *comp) {
    if (!comp || !comp->fb_map) {
        return;
    }

    comp_clear_framebuffer(comp);
    comp_draw_surface(comp, comp->active_surface);

    if (comp->cursor) {
        cursor_draw(comp->cursor, comp->fb_map, &comp->fb_info);
    }

    comp->needs_repaint = false;
    comp->pending_damage.valid = false;
}

int comp_run(struct compositor_state *comp) {
    if (!comp || !comp->display || !comp->loop) {
        return -1;
    }

    while (comp->running) {
        wl_display_flush_clients(comp->display);

        int timeout = comp->needs_repaint ? 0 : (int)comp->frame_delay_ms;
        int rc = wl_event_loop_dispatch(comp->loop, timeout);
        if (rc < 0 && errno != EINTR) {
            break;
        }

        if (comp->needs_repaint) {
            comp_render(comp);
        }
    }

    return 0;
}

void comp_request_repaint(struct compositor_state *comp, const struct comp_damage *damage) {
    if (!comp) {
        return;
    }
    if (damage) {
        comp_damage_union(comp, damage);
    } else if (!comp->pending_damage.valid) {
        struct comp_damage full = {
            .x = 0,
            .y = 0,
            .width = (int32_t)comp->fb_info.width,
            .height = (int32_t)comp->fb_info.height,
            .valid = true,
        };
        comp_damage_union(comp, &full);
    } else {
        comp->needs_repaint = true;
    }
}

bool comp_pointer_inside_surface(const struct compositor_state *comp,
                                 const struct comp_surface *surface,
                                 int32_t px,
                                 int32_t py,
                                 int32_t *out_sx,
                                 int32_t *out_sy) {
    if (!comp || !surface || !surface->has_backing) {
        return false;
    }

    int32_t sx = px - comp->window_x;
    int32_t sy = py - comp->window_y;
    if (sx < 0 || sy < 0 ||
        sx >= surface->width || sy >= surface->height) {
        return false;
    }
    if (out_sx) {
        *out_sx = sx;
    }
    if (out_sy) {
        *out_sy = sy;
    }
    return true;
}

static void comp_cursor_damage(struct compositor_state *comp,
                               int32_t x,
                               int32_t y,
                               int32_t w,
                               int32_t h) {
    struct comp_damage dmg = {
        .x = x,
        .y = y,
        .width = w,
        .height = h,
        .valid = true,
    };
    comp_damage_union(comp, &dmg);
}

void comp_pointer_motion(struct compositor_state *comp, int32_t new_x, int32_t new_y) {
    if (!comp || !comp->cursor) {
        return;
    }

    int32_t cursor_w = cursor_get_width(comp->cursor);
    int32_t cursor_h = cursor_get_height(comp->cursor);
    int32_t max_x = (int32_t)comp->fb_info.width - cursor_w;
    int32_t max_y = (int32_t)comp->fb_info.height - cursor_h;
    if (max_x < 0) {
        max_x = 0;
    }
    if (max_y < 0) {
        max_y = 0;
    }

    int32_t clamped_x = clamp_i32(new_x, 0, max_x);
    int32_t clamped_y = clamp_i32(new_y, 0, max_y);

    if (clamped_x == comp->pointer_x && clamped_y == comp->pointer_y) {
        if (comp->dragging) {
            comp_update_drag(comp);
        }
        return;
    }

    comp_cursor_damage(comp, comp->pointer_x, comp->pointer_y, cursor_w, cursor_h);

    comp->pointer_x = clamped_x;
    comp->pointer_y = clamped_y;
    cursor_set_position(comp->cursor, comp->pointer_x, comp->pointer_y);

    comp_cursor_damage(comp, comp->pointer_x, comp->pointer_y, cursor_w, cursor_h);
    comp->needs_repaint = true;

    comp_update_drag(comp);
}

void comp_start_drag(struct compositor_state *comp) {
    if (!comp || comp->dragging || !comp->active_surface || !comp->active_surface->has_backing) {
        return;
    }
    comp->dragging = true;
    comp->drag_offset_x = comp->pointer_x - comp->window_x;
    comp->drag_offset_y = comp->pointer_y - comp->window_y;
}

void comp_end_drag(struct compositor_state *comp) {
    if (!comp) {
        return;
    }
    comp->dragging = false;
}

void comp_update_window_position(struct compositor_state *comp, int32_t new_x, int32_t new_y) {
    if (!comp || !comp->active_surface || !comp->active_surface->has_backing) {
        return;
    }

    int32_t width = comp->active_surface->width;
    int32_t height = comp->active_surface->height;
    int32_t max_x = (int32_t)comp->fb_info.width - width;
    int32_t max_y = (int32_t)comp->fb_info.height - height;
    if (max_x < 0) {
        max_x = 0;
    }
    if (max_y < 0) {
        max_y = 0;
    }

    int32_t clamped_x = clamp_i32(new_x, 0, max_x);
    int32_t clamped_y = clamp_i32(new_y, 0, max_y);
    if (clamped_x == comp->window_x && clamped_y == comp->window_y) {
        return;
    }

    struct comp_damage old_rect = {
        .x = comp->window_x,
        .y = comp->window_y,
        .width = width,
        .height = height,
        .valid = true,
    };
    struct comp_damage new_rect = {
        .x = clamped_x,
        .y = clamped_y,
        .width = width,
        .height = height,
        .valid = true,
    };
    comp_damage_union(comp, &old_rect);
    comp_damage_union(comp, &new_rect);

    comp->window_x = clamped_x;
    comp->window_y = clamped_y;
    comp->needs_repaint = true;
    if (comp->active_surface) {
        WLOG("[WAYLAND] move id=%u -> x=%d y=%d\n",
             comp->active_surface->surface_id,
             clamped_x,
             clamped_y);
    }
}

void comp_update_drag(struct compositor_state *comp) {
    if (!comp || !comp->dragging) {
        return;
    }
    int32_t new_x = comp->pointer_x - comp->drag_offset_x;
    int32_t new_y = comp->pointer_y - comp->drag_offset_y;
    comp_update_window_position(comp, new_x, new_y);
}
