// SPDX-License-Identifier: MPL-2.0
#pragma once

#include <stdbool.h>
#include <stdint.h>

#include <futura/fb_ioctl.h>
#include <wayland-server-core.h>

#ifndef WAYLAND_MULTI_BUILD
#define WAYLAND_MULTI_BUILD 1
#endif

#ifndef WAYLAND_BACKBUFFER_BUILD
#define WAYLAND_BACKBUFFER_BUILD 1
#endif

#ifndef WAYLAND_DECO_BUILD
#define WAYLAND_DECO_BUILD 1
#endif

#ifndef WAYLAND_SHADOW_BUILD
#define WAYLAND_SHADOW_BUILD 1
#endif

#ifndef WAYLAND_RESIZE_BUILD
#define WAYLAND_RESIZE_BUILD 1
#endif

#define XDG_CFG_STATE_RESIZING   (1u << 0)
#define XDG_CFG_STATE_MAXIMIZED  (1u << 1)

#define WINDOW_BAR_HEIGHT 24
#define WINDOW_BTN_WIDTH 16
#define WINDOW_BTN_HEIGHT 16
#define WINDOW_BTN_PADDING 4
#define WINDOW_TITLE_MAX 128
#define WINDOW_SHADOW_DEFAULT 10

struct seat_state;
struct cursor_state;
struct wl_event_source;

typedef struct comp_selection {
    struct wl_resource *source;
    char mime[64];
    uint32_t serial;
} comp_selection_t;

typedef struct fut_rect {
    int32_t x;
    int32_t y;
    int32_t w;
    int32_t h;
} fut_rect_t;

#define MAX_DAMAGE 64

struct damage_accum {
    fut_rect_t rects[MAX_DAMAGE];
    int count;
};

struct backbuffer {
    uint32_t *px;
    int width;
    int height;
    int pitch;     /* bytes */
    bool owns;
};

typedef enum resize_edge {
    RSZ_NONE        = 0,
    RSZ_LEFT        = 1 << 0,
    RSZ_RIGHT       = 1 << 1,
    RSZ_TOP         = 1 << 2,
    RSZ_BOTTOM      = 1 << 3,
    RSZ_TOPLEFT     = RSZ_TOP | RSZ_LEFT,
    RSZ_TOPRIGHT    = RSZ_TOP | RSZ_RIGHT,
    RSZ_BOTTOMLEFT  = RSZ_BOTTOM | RSZ_LEFT,
    RSZ_BOTTOMRIGHT = RSZ_BOTTOM | RSZ_RIGHT,
} resize_edge_t;

typedef enum hit_role {
    HIT_NONE = 0,
    HIT_BAR,
    HIT_MINIMIZE,
    HIT_CLOSE,
    HIT_CONTENT,
    HIT_RESIZE,
} hit_role_t;

struct comp_buffer {
    struct wl_resource *resource;
    struct wl_shm_buffer *shm;
    void *data;
    int32_t width;
    int32_t height;
    int32_t stride;
    uint32_t format;
};

struct comp_frame_callback {
    struct wl_resource *resource;
    struct wl_list link;
};

struct compositor_state {
    struct wl_display *display;
    struct wl_event_loop *loop;
    int fb_fd;
    struct fut_fb_info fb_info;
    uint8_t *fb_map;
    size_t fb_map_size;
    bool running;
    struct wl_list surfaces; /* back = topmost */
    struct comp_surface *active_surface;
    struct comp_surface *focused_surface;
    struct comp_surface *drag_surface;
    struct seat_state *seat;
    struct cursor_state *cursor;
    int32_t pointer_x;
    int32_t pointer_y;
    bool dragging;
    int32_t drag_offset_x;
    int32_t drag_offset_y;
    bool needs_repaint;
    uint32_t next_surface_id;
    bool multi_enabled;
    bool backbuffer_enabled;
    bool deco_enabled;
    bool shadow_enabled;
    int32_t shadow_radius;
    bool resize_enabled;
    bool throttle_enabled;
    struct backbuffer bb[2];
    int bb_index;
    struct damage_accum frame_damage;
    uint64_t last_present_ns;
    uint32_t target_ms;
    uint32_t vsync_hint_ms;
    int timerfd;
    struct wl_event_source *timer_source;
    uint64_t next_tick_ms;
    struct comp_surface *resize_surface;
};

struct comp_surface {
    struct compositor_state *comp;
    struct wl_list link;
    struct wl_resource *surface_resource;
    struct wl_resource *pending_buffer_resource;
    fut_rect_t pending_damage;
    bool has_pending_damage;
    struct wl_list frame_callbacks;
    bool has_pending_buffer;
    uint8_t *backing;
    size_t backing_size;
    bool had_new_buffer;
    bool composed_this_tick;
    bool damage_since_present;
    int32_t width;
    int32_t height;
    int32_t content_height;
    int32_t stride;
    bool has_backing;
    uint32_t surface_id;
    int32_t x;
    int32_t y;
    bool pos_initialised;
    bool in_zlist;
    int32_t bar_height;
    int32_t min_btn_x;
    int32_t min_btn_y;
    int32_t min_btn_w;
    int32_t min_btn_h;
    bool min_btn_hover;
    bool min_btn_pressed;
    int32_t btn_x;
    int32_t btn_y;
    int32_t btn_w;
    int32_t btn_h;
    bool btn_hover;
    bool btn_pressed;
    bool minimized;
    struct wl_resource *xdg_toplevel;
    uint32_t cfg_serial_last;
    uint32_t cfg_serial_pending;
    int32_t pend_w;
    int32_t pend_h;
    bool have_pending_size;
    int32_t pend_x;
    int32_t pend_y;
    bool have_pending_pos;
    int32_t shadow_px;
    int32_t min_w;
    int32_t min_h;
    int32_t max_w;
    int32_t max_h;
    bool maximized;
    resize_edge_t resizing;
    int32_t resize_dx;
    int32_t resize_dy;
    int32_t base_x;
    int32_t base_y;
    int32_t base_w;
    int32_t base_h;
    int32_t base_total_h;
    int32_t saved_x;
    int32_t saved_y;
    int32_t saved_w;
    int32_t saved_h;
    bool have_saved_geom;
    char title[WINDOW_TITLE_MAX];
    bool title_dirty;
};

int comp_state_init(struct compositor_state *comp);
void comp_state_finish(struct compositor_state *comp);

const struct fut_fb_info *comp_get_fb_info(const struct compositor_state *comp);

struct comp_surface *comp_surface_create(struct compositor_state *comp,
                                         struct wl_resource *surface_resource);
void comp_surface_destroy(struct comp_surface *surface);
void comp_surface_attach(struct comp_surface *surface,
                         struct wl_resource *buffer_resource);
void comp_surface_damage(struct comp_surface *surface,
                         int32_t x, int32_t y,
                         int32_t width, int32_t height);
void comp_surface_commit(struct comp_surface *surface);
void comp_surface_frame(struct comp_surface *surface,
                        struct wl_resource *callback_resource);

int comp_run(struct compositor_state *comp);
int comp_scheduler_start(struct compositor_state *comp);
void comp_scheduler_stop(struct compositor_state *comp);

bool comp_pointer_inside_surface(const struct compositor_state *comp,
                                 const struct comp_surface *surface,
                                 int32_t px,
                                 int32_t py,
                                 int32_t *out_sx,
                                 int32_t *out_sy);
void comp_pointer_motion(struct compositor_state *comp, int32_t new_x, int32_t new_y);
void comp_start_drag(struct compositor_state *comp, struct comp_surface *surface);
void comp_end_drag(struct compositor_state *comp);
void comp_update_drag(struct compositor_state *comp);
void comp_update_surface_position(struct compositor_state *comp,
                                  struct comp_surface *surface,
                                  int32_t new_x,
                                  int32_t new_y);
void comp_start_resize(struct compositor_state *comp,
                       struct comp_surface *surface,
                       resize_edge_t edge);
void comp_update_resize(struct compositor_state *comp);
void comp_end_resize(struct compositor_state *comp, struct comp_surface *surface);
void comp_surface_set_maximized(struct comp_surface *surface, bool maximized);
void comp_surface_toggle_maximize(struct comp_surface *surface);
void comp_surface_set_minimized(struct comp_surface *surface, bool minimized);
void comp_surface_toggle_minimize(struct comp_surface *surface);

struct comp_surface *comp_surface_at(struct compositor_state *comp,
                                     int32_t px,
                                     int32_t py,
                                     int32_t *out_sx,
                                     int32_t *out_sy);
void comp_surface_raise(struct compositor_state *comp, struct comp_surface *surface);
static inline bool comp_multi_enabled(const struct compositor_state *comp) {
    return comp && comp->multi_enabled;
}

void comp_surface_mark_damage(struct comp_surface *surface);

void comp_damage_add_rect(struct compositor_state *comp, fut_rect_t rect);
void comp_damage_add_full(struct compositor_state *comp);
int comp_set_backbuffer_enabled(struct compositor_state *comp, bool enabled);
hit_role_t comp_hit_test(struct compositor_state *comp,
                         int32_t px,
                         int32_t py,
                         struct comp_surface **out_surface,
                         resize_edge_t *out_edge);
void comp_surface_request_close(struct comp_surface *surface);
void comp_surface_update_decorations(struct comp_surface *surface);
static inline fut_rect_t comp_window_rect(const struct comp_surface *surface) {
    fut_rect_t r = {
        .x = surface->x,
        .y = surface->y,
        .w = surface->width,
        .h = surface->height,
    };
    if (r.w < 0) {
        r.w = 0;
    }
    if (r.h < 0) {
        r.h = 0;
    }
    return r;
}

static inline fut_rect_t comp_bar_rect(const struct comp_surface *surface) {
    fut_rect_t r = comp_window_rect(surface);
    if (surface->bar_height <= 0) {
        r.h = 0;
        return r;
    }
    r.h = surface->bar_height;
    return r;
}

static inline fut_rect_t comp_min_btn_rect(const struct comp_surface *surface) {
    fut_rect_t r = {
        .x = surface->min_btn_x,
        .y = surface->min_btn_y,
        .w = surface->min_btn_w,
        .h = surface->min_btn_h,
    };
    return r;
}

static inline fut_rect_t comp_btn_rect(const struct comp_surface *surface) {
    fut_rect_t r = {
        .x = surface->btn_x,
        .y = surface->btn_y,
        .w = surface->btn_w,
        .h = surface->btn_h,
    };
    return r;
}

static inline fut_rect_t comp_content_rect(const struct comp_surface *surface) {
    fut_rect_t r = {
        .x = surface->x,
        .y = surface->y + surface->bar_height,
        .w = surface->width,
        .h = surface->height - surface->bar_height,
    };
    if (r.h < 0) {
        r.h = 0;
    }
    return r;
}

static inline fut_rect_t comp_frame_rect(const struct comp_surface *surface) {
    fut_rect_t r = comp_window_rect(surface);
    int32_t shadow = surface->shadow_px;
    if (shadow > 0) {
        r.x -= shadow;
        r.y -= shadow;
        r.w += shadow * 2;
        r.h += shadow * 2;
    }
    return r;
}

static inline bool rect_contains(const fut_rect_t *rect, int32_t px, int32_t py) {
    return px >= rect->x && py >= rect->y &&
           px < rect->x + rect->w && py < rect->y + rect->h;
}

static inline uint32_t comp_surface_state_flags(const struct comp_surface *surface) {
    uint32_t flags = 0;
    if (!surface) {
        return flags;
    }
    if (surface->maximized) {
        flags |= XDG_CFG_STATE_MAXIMIZED;
    }
    if (surface->resizing != RSZ_NONE) {
        flags |= XDG_CFG_STATE_RESIZING;
    }
    return flags;
}
