#include "comp.h"
#include "cursor.h"
#include "log.h"
#include "seat.h"
#include "shm_backend.h"

#include <errno.h>
#include <stddef.h>

#include <wayland-server-protocol.h>
#include <wayland-util.h>

#include <user/sys.h>

void *malloc(size_t size);
void *realloc(void *ptr, size_t size);
void free(void *ptr);
void *memcpy(void *dest, const void *src, size_t n);
void *memset(void *dest, int c, size_t n);

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

static fut_rect_t rect_clip_to_fb(const struct fut_fb_info *info, fut_rect_t rect, bool *out_valid) {
    fut_rect_t clipped = rect;
    if (clipped.w <= 0 || clipped.h <= 0) {
        if (out_valid) {
            *out_valid = false;
        }
        return clipped;
    }

    int32_t fb_w = (int32_t)info->width;
    int32_t fb_h = (int32_t)info->height;

    if (clipped.x < 0) {
        clipped.w += clipped.x;
        clipped.x = 0;
    }
    if (clipped.y < 0) {
        clipped.h += clipped.y;
        clipped.y = 0;
    }

    if (clipped.x + clipped.w > fb_w) {
        clipped.w = fb_w - clipped.x;
    }
    if (clipped.y + clipped.h > fb_h) {
        clipped.h = fb_h - clipped.y;
    }

    if (clipped.w <= 0 || clipped.h <= 0) {
        if (out_valid) {
            *out_valid = false;
        }
        return clipped;
    }

    if (out_valid) {
        *out_valid = true;
    }
    return clipped;
}

static fut_rect_t rect_union(fut_rect_t a, fut_rect_t b) {
    int32_t ax2 = a.x + a.w;
    int32_t ay2 = a.y + a.h;
    int32_t bx2 = b.x + b.w;
    int32_t by2 = b.y + b.h;

    fut_rect_t out;
    out.x = a.x < b.x ? a.x : b.x;
    out.y = a.y < b.y ? a.y : b.y;
    out.w = (ax2 > bx2 ? ax2 : bx2) - out.x;
    out.h = (ay2 > by2 ? ay2 : by2) - out.y;
    return out;
}

static bool rect_intersection(fut_rect_t a, fut_rect_t b, fut_rect_t *out) {
    int32_t ax2 = a.x + a.w;
    int32_t ay2 = a.y + a.h;
    int32_t bx2 = b.x + b.w;
    int32_t by2 = b.y + b.h;

    int32_t rx1 = a.x > b.x ? a.x : b.x;
    int32_t ry1 = a.y > b.y ? a.y : b.y;
    int32_t rx2 = ax2 < bx2 ? ax2 : bx2;
    int32_t ry2 = ay2 < by2 ? ay2 : by2;

    if (rx2 <= rx1 || ry2 <= ry1) {
        return false;
    }
    if (out) {
        out->x = rx1;
        out->y = ry1;
        out->w = rx2 - rx1;
        out->h = ry2 - ry1;
    }
    return true;
}

static bool rects_overlap_or_touch(fut_rect_t a, fut_rect_t b) {
    int32_t ax2 = a.x + a.w;
    int32_t ay2 = a.y + a.h;
    int32_t bx2 = b.x + b.w;
    int32_t by2 = b.y + b.h;

    return (a.x <= bx2 + 1 && bx2 >= a.x - 1 &&
            b.x <= ax2 + 1 && ax2 >= b.x - 1 &&
            a.y <= by2 + 1 && by2 >= a.y - 1 &&
            b.y <= ay2 + 1 && ay2 >= b.y - 1);
}

static void damage_coalesce(struct damage_accum *dmg) {
    if (!dmg) {
        return;
    }

    bool merged;
    do {
        merged = false;
        for (int i = 0; i < dmg->count && !merged; ++i) {
            for (int j = i + 1; j < dmg->count; ++j) {
                if (rects_overlap_or_touch(dmg->rects[i], dmg->rects[j])) {
                    dmg->rects[i] = rect_union(dmg->rects[i], dmg->rects[j]);
                    for (int k = j; k < dmg->count - 1; ++k) {
                        dmg->rects[k] = dmg->rects[k + 1];
                    }
                    --dmg->count;
                    merged = true;
                    break;
                }
            }
        }
    } while (merged);
}

static int bb_create(struct backbuffer *bb, int width, int height, int pitch) {
    if (!bb || width <= 0 || height <= 0 || pitch <= 0) {
        return -1;
    }
    size_t size = (size_t)pitch * (size_t)height;
    uint32_t *mem = malloc(size);
    if (!mem) {
        return -1;
    }
    bb->px = mem;
    bb->width = width;
    bb->height = height;
    bb->pitch = pitch;
    bb->owns = true;
    memset(mem, 0, size);
    return 0;
}

static void bb_destroy(struct backbuffer *bb) {
    if (!bb) {
        return;
    }
    if (bb->owns && bb->px) {
        free(bb->px);
    }
    bb->px = NULL;
    bb->width = 0;
    bb->height = 0;
    bb->pitch = 0;
    bb->owns = false;
}

static void bb_fill_rect(struct backbuffer *bb, fut_rect_t rect, uint32_t argb) {
    if (!bb || !bb->px) {
        return;
    }
    uint8_t *base = (uint8_t *)bb->px;
    for (int32_t y = 0; y < rect.h; ++y) {
        uint8_t *dst = base + (size_t)(rect.y + y) * bb->pitch + (size_t)rect.x * 4u;
        uint32_t *dst_px = (uint32_t *)dst;
        for (int32_t x = 0; x < rect.w; ++x) {
            dst_px[x] = argb;
        }
    }
}

static void blit_argb(const uint8_t *src_base,
                      int src_pitch,
                      uint8_t *dst_base,
                      int dst_pitch,
                      int width,
                      int height) {
    size_t row_bytes = (size_t)width * 4u;
    const uint8_t *src = src_base;
    uint8_t *dst = dst_base;
    for (int y = 0; y < height; ++y) {
        memcpy(dst, src, row_bytes);
        src += src_pitch;
        dst += dst_pitch;
    }
}

static int comp_configure_backbuffers(struct compositor_state *comp);
static uint64_t comp_now_ns(void);

static void comp_surface_link_tail(struct compositor_state *comp, struct comp_surface *surface) {
    if (!comp || !surface || surface->in_zlist) {
        return;
    }
    wl_list_insert(comp->surfaces.prev, &surface->link);
    surface->in_zlist = true;
}

static void comp_surface_unlink(struct comp_surface *surface) {
    if (!surface || !surface->in_zlist) {
        return;
    }
    wl_list_remove(&surface->link);
    surface->in_zlist = false;
}

void comp_damage_add_rect(struct compositor_state *comp, fut_rect_t rect) {
    if (!comp) {
        return;
    }

    bool valid = false;
    fut_rect_t clipped = rect_clip_to_fb(&comp->fb_info, rect, &valid);
    if (!valid) {
        return;
    }

    struct damage_accum *dmg = &comp->frame_damage;
    if (dmg->count >= MAX_DAMAGE) {
        comp_damage_add_full(comp);
        return;
    }

    dmg->rects[dmg->count++] = clipped;
    damage_coalesce(dmg);
    comp->needs_repaint = true;
}

void comp_damage_add_full(struct compositor_state *comp) {
    if (!comp) {
        return;
    }
    struct damage_accum *dmg = &comp->frame_damage;
    dmg->count = 1;
    dmg->rects[0].x = 0;
    dmg->rects[0].y = 0;
    dmg->rects[0].w = (int32_t)comp->fb_info.width;
    dmg->rects[0].h = (int32_t)comp->fb_info.height;
    comp->needs_repaint = true;
}

int comp_set_backbuffer_enabled(struct compositor_state *comp, bool enabled) {
    if (!comp) {
        return -1;
    }
    comp->backbuffer_enabled = enabled;
    return comp_configure_backbuffers(comp);
}

const struct fut_fb_info *comp_get_fb_info(const struct compositor_state *comp) {
    return comp ? &comp->fb_info : NULL;
}

int comp_state_init(struct compositor_state *comp) {
    if (!comp) {
        return -1;
    }

    memset(comp, 0, sizeof(*comp));
    comp->multi_enabled = (WAYLAND_MULTI_BUILD != 0);
    wl_list_init(&comp->surfaces);
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
    comp->target_ms = 16u;
    comp->last_present_ns = 0;
    comp->frame_damage.count = 0;
    comp->bb_index = 0;
    comp->backbuffer_enabled = (WAYLAND_BACKBUFFER_BUILD != 0);
    comp->pointer_x = (int32_t)info.width / 2;
    comp->pointer_y = (int32_t)info.height / 2;
    comp->cursor = cursor_create();
    if (!comp->cursor) {
        printf("[WAYLAND] failed to create cursor state\n");
        comp_state_finish(comp);
        return -1;
    }
    cursor_set_position(comp->cursor, comp->pointer_x, comp->pointer_y);
    if (comp_configure_backbuffers(comp) != 0) {
        printf("[WAYLAND] failed to allocate backbuffer\n");
        comp_state_finish(comp);
        return -1;
    }
    comp->last_present_ns = comp_now_ns() - (uint64_t)comp->target_ms * 1000000ULL;
    return 0;
}

void comp_state_finish(struct compositor_state *comp) {
    if (!comp) {
        return;
    }

    comp->running = false;

    for (int i = 0; i < 2; ++i) {
        bb_destroy(&comp->bb[i]);
    }

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

static int comp_configure_backbuffers(struct compositor_state *comp) {
    if (!comp) {
        return -1;
    }

    for (int i = 0; i < 2; ++i) {
        bb_destroy(&comp->bb[i]);
    }
    comp->bb_index = 0;

    if (!comp->backbuffer_enabled) {
        comp->bb[0].px = (uint32_t *)comp->fb_map;
        comp->bb[0].width = (int)comp->fb_info.width;
        comp->bb[0].height = (int)comp->fb_info.height;
        comp->bb[0].pitch = (int)comp->fb_info.pitch;
        comp->bb[0].owns = false;
        comp->bb[1].px = NULL;
        comp->bb[1].width = 0;
        comp->bb[1].height = 0;
        comp->bb[1].pitch = 0;
        comp->bb[1].owns = false;
        return 0;
    }

    int width = (int)comp->fb_info.width;
    int height = (int)comp->fb_info.height;
    int pitch = (int)comp->fb_info.pitch;

    if (bb_create(&comp->bb[0], width, height, pitch) != 0) {
        return -1;
    }
    if (bb_create(&comp->bb[1], width, height, pitch) != 0) {
        bb_destroy(&comp->bb[0]);
        return -1;
    }
    return 0;
}

struct comp_surface *comp_surface_create(struct compositor_state *comp,
                                         struct wl_resource *surface_resource) {
    struct comp_surface *surface = malloc(sizeof(*surface));
    if (!surface) {
        return NULL;
    }
    memset(surface, 0, sizeof(*surface));
    surface->comp = comp;
    surface->x = 0;
    surface->y = 0;
    surface->pos_initialised = false;
    surface->in_zlist = false;
    surface->surface_resource = surface_resource;
    wl_list_init(&surface->frame_callbacks);
    surface->has_pending_damage = false;
    surface->has_pending_buffer = false;
    surface->surface_id = ++comp->next_surface_id;
    comp_surface_link_tail(comp, surface);
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
        comp_surface_unlink(surface);
        if (surface->has_backing) {
            fut_rect_t rect = {
                .x = surface->x,
                .y = surface->y,
                .w = surface->width,
                .h = surface->height,
            };
            comp_damage_add_rect(comp, rect);
        }
        if (comp->active_surface == surface) {
            if (!wl_list_empty(&comp->surfaces)) {
                struct wl_list *tail_link = comp->surfaces.prev;
                comp->active_surface = wl_container_of(tail_link, surface, link);
            } else {
                comp->active_surface = NULL;
            }
        }
        if (comp->focused_surface == surface) {
            comp->focused_surface = NULL;
        }
        if (comp->drag_surface == surface) {
            comp->drag_surface = NULL;
            comp->dragging = false;
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
    surface->pending_damage.w = width;
    surface->pending_damage.h = height;
    surface->has_pending_damage = true;
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
            bool first_buffer = !surface->has_backing;
            for (int32_t row = 0; row < buffer.height; ++row) {
                const uint8_t *src_row = (const uint8_t *)buffer.data + (size_t)row * buffer.stride;
                uint8_t *dst_row = surface->backing + (size_t)row * buffer.stride;
                memcpy(dst_row, src_row, (size_t)buffer.width * 4u);
            }

            surface->width = buffer.width;
            surface->height = buffer.height;
            surface->stride = buffer.stride;
            surface->has_backing = true;
            comp_surface_raise(surface->comp, surface);

            if (!surface->pos_initialised) {
                int32_t cx = ((int32_t)surface->comp->fb_info.width - surface->width) / 2;
                int32_t cy = ((int32_t)surface->comp->fb_info.height - surface->height) / 2;
                int32_t max_x = (int32_t)surface->comp->fb_info.width - surface->width;
                int32_t max_y = (int32_t)surface->comp->fb_info.height - surface->height;
                if (max_x < 0) max_x = 0;
                if (max_y < 0) max_y = 0;
                surface->x = clamp_i32(cx, 0, max_x);
                surface->y = clamp_i32(cy, 0, max_y);
                surface->pos_initialised = true;
            }

            fut_rect_t full = {
                .x = surface->x,
                .y = surface->y,
                .w = surface->width,
                .h = surface->height,
            };
            comp_damage_add_rect(surface->comp, full);

            shm_buffer_release(&buffer);
            if (first_buffer) {
                WLOG("[WAYLAND] window create win=%p size=%dx%d z=top\n",
                     (void *)surface,
                     surface->width,
                     surface->height);
            }
        } else {
            wl_buffer_send_release(surface->pending_buffer_resource);
        }
        surface->pending_buffer_resource = NULL;
        surface->has_pending_buffer = false;
    }

    if (surface->has_pending_damage && surface->has_backing) {
        fut_rect_t local = surface->pending_damage;
        fut_rect_t global = {
            .x = surface->x + local.x,
            .y = surface->y + local.y,
            .w = local.w,
            .h = local.h,
        };
        comp_damage_add_rect(surface->comp, global);
        surface->has_pending_damage = false;
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

static uint64_t comp_now_ns(void) {
    return (uint64_t)sys_time_millis_call() * 1000000ULL;
}

static void present_damage(struct compositor_state *comp, const struct damage_accum *damage) {
    if (!comp || !damage || !comp->fb_map) {
        return;
    }

    const struct backbuffer *src = &comp->bb[comp->bb_index];
    if (!src->px) {
        return;
    }

    for (int i = 0; i < damage->count; ++i) {
        fut_rect_t rect = damage->rects[i];
        const uint8_t *src_base = (const uint8_t *)src->px + (size_t)rect.y * src->pitch + (size_t)rect.x * 4u;
        uint8_t *dst_base = comp->fb_map + (size_t)rect.y * comp->fb_info.pitch + (size_t)rect.x * 4u;
        blit_argb(src_base, src->pitch, dst_base, comp->fb_info.pitch, rect.w, rect.h);
    }
}

static void render_one_frame(struct compositor_state *comp) {
    if (!comp) {
        return;
    }

    struct damage_accum *damage = &comp->frame_damage;
    if (damage->count == 0) {
        comp->needs_repaint = false;
        return;
    }

    damage_coalesce(damage);
    int region_count = damage->count;

    int render_index = comp->backbuffer_enabled ? (comp->bb_index ^ 1) : 0;
    struct backbuffer *dst = &comp->bb[render_index];
    if (!dst->px) {
        comp_damage_add_full(comp);
        damage = &comp->frame_damage;
        damage_coalesce(damage);
        region_count = damage->count;
        dst = &comp->bb[render_index];
        if (!dst->px) {
            comp->needs_repaint = false;
            damage->count = 0;
            return;
        }
    }

    for (int i = 0; i < damage->count; ++i) {
        bb_fill_rect(dst, damage->rects[i], 0x00000000u);
    }

    struct comp_surface *surface;
    wl_list_for_each(surface, &comp->surfaces, link) {
        if (!surface->has_backing) {
            continue;
        }
        fut_rect_t surf_rect = {
            .x = surface->x,
            .y = surface->y,
            .w = surface->width,
            .h = surface->height,
        };

        for (int i = 0; i < damage->count; ++i) {
            fut_rect_t inter;
            if (!rect_intersection(damage->rects[i], surf_rect, &inter)) {
                continue;
            }
            const uint8_t *src_ptr = surface->backing +
                (size_t)(inter.y - surface->y) * surface->stride +
                (size_t)(inter.x - surface->x) * 4u;
            uint8_t *dst_ptr = (uint8_t *)dst->px +
                (size_t)inter.y * dst->pitch +
                (size_t)inter.x * 4u;
            blit_argb(src_ptr, surface->stride, dst_ptr, dst->pitch, inter.w, inter.h);
        }
    }

    if (comp->cursor) {
        struct fut_fb_info info = comp->fb_info;
        info.pitch = (uint32_t)dst->pitch;
        cursor_draw(comp->cursor, (uint8_t *)dst->px, &info);
    }

    if (comp->backbuffer_enabled) {
        comp->bb_index = render_index;
        present_damage(comp, damage);
    }

#ifdef DEBUG_WAYLAND
    WLOG("[WAYLAND] present bb=%d regions=%d\n", comp->bb_index, region_count);
#endif

    comp->frame_damage.count = 0;
    comp->needs_repaint = false;
    comp->last_present_ns = comp_now_ns();
}

int comp_run(struct compositor_state *comp) {
    if (!comp || !comp->display || !comp->loop) {
        return -1;
    }

    while (comp->running) {
        wl_display_flush_clients(comp->display);

        uint64_t target_ns = (uint64_t)comp->target_ms * 1000000ULL;
        uint64_t now_ns = comp_now_ns();
        uint64_t elapsed_ns = now_ns - comp->last_present_ns;
        int timeout_ms = comp->target_ms;

        if (comp->frame_damage.count > 0) {
            if (elapsed_ns >= target_ns) {
                timeout_ms = 0;
            } else {
                uint64_t remaining_ns = target_ns - elapsed_ns;
                timeout_ms = (int)(remaining_ns / 1000000ULL);
                if (timeout_ms < 0) {
                    timeout_ms = 0;
                }
            }
        }

        int rc = wl_event_loop_dispatch(comp->loop, timeout_ms);
        if (rc < 0 && errno != EINTR) {
            break;
        }

        now_ns = comp_now_ns();
        if (comp->frame_damage.count > 0 && now_ns - comp->last_present_ns >= target_ns) {
            render_one_frame(comp);
        }
    }

    return 0;
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

    int32_t sx = px - surface->x;
    int32_t sy = py - surface->y;
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

struct comp_surface *comp_surface_at(struct compositor_state *comp,
                                     int32_t px,
                                     int32_t py,
                                     int32_t *out_sx,
                                     int32_t *out_sy) {
    if (!comp) {
        return NULL;
    }
    struct comp_surface *surface;
    wl_list_for_each_reverse(surface, &comp->surfaces, link) {
        if (!surface->has_backing) {
            continue;
        }
        int32_t sx = px - surface->x;
        int32_t sy = py - surface->y;
        if (sx < 0 || sy < 0 ||
            sx >= surface->width || sy >= surface->height) {
            continue;
        }
        if (out_sx) {
            *out_sx = sx;
        }
        if (out_sy) {
            *out_sy = sy;
        }
        return surface;
    }
    return NULL;
}

void comp_surface_raise(struct compositor_state *comp, struct comp_surface *surface) {
    if (!comp || !surface) {
        return;
    }

    if (!surface->in_zlist) {
        comp_surface_link_tail(comp, surface);
    } else if (comp->multi_enabled) {
        wl_list_remove(&surface->link);
        wl_list_insert(comp->surfaces.prev, &surface->link);
    }
    surface->in_zlist = true;
    comp->active_surface = surface;
    if (surface->has_backing) {
        fut_rect_t rect = {
            .x = surface->x,
            .y = surface->y,
            .w = surface->width,
            .h = surface->height,
        };
        comp_damage_add_rect(comp, rect);
    }
}

static void comp_cursor_damage(struct compositor_state *comp,
                               int32_t x,
                               int32_t y,
                               int32_t w,
                                int32_t h) {
    fut_rect_t rect = {
        .x = x,
        .y = y,
        .w = w,
        .h = h,
    };
    comp_damage_add_rect(comp, rect);
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

void comp_start_drag(struct compositor_state *comp, struct comp_surface *surface) {
    if (!comp || comp->dragging || !surface || !surface->has_backing) {
        return;
    }
    comp->dragging = true;
    comp->drag_surface = surface;
    comp->drag_offset_x = comp->pointer_x - surface->x;
    comp->drag_offset_y = comp->pointer_y - surface->y;
}

void comp_end_drag(struct compositor_state *comp) {
    if (!comp) {
        return;
    }
    comp->dragging = false;
    comp->drag_surface = NULL;
}

void comp_update_surface_position(struct compositor_state *comp,
                                  struct comp_surface *surface,
                                  int32_t new_x,
                                  int32_t new_y) {
    if (!comp || !surface || !surface->has_backing) {
        return;
    }

    int32_t width = surface->width;
    int32_t height = surface->height;
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
    if (clamped_x == surface->x && clamped_y == surface->y) {
        return;
    }

    fut_rect_t old_rect = {
        .x = surface->x,
        .y = surface->y,
        .w = width,
        .h = height,
    };
    fut_rect_t new_rect = {
        .x = clamped_x,
        .y = clamped_y,
        .w = width,
        .h = height,
    };
    comp_damage_add_rect(comp, old_rect);
    comp_damage_add_rect(comp, new_rect);

    surface->x = clamped_x;
    surface->y = clamped_y;
    comp->needs_repaint = true;
    if (surface == comp->active_surface) {
        WLOG("[WAYLAND] move win=%p -> x=%d y=%d\n",
             (void *)surface,
             clamped_x,
             clamped_y);
    }
}

void comp_update_drag(struct compositor_state *comp) {
    if (!comp || !comp->dragging || !comp->drag_surface) {
        return;
    }
    struct comp_surface *surface = comp->drag_surface;
    int32_t new_x = comp->pointer_x - comp->drag_offset_x;
    int32_t new_y = comp->pointer_y - comp->drag_offset_y;
    comp_update_surface_position(comp, surface, new_x, new_y);
}
