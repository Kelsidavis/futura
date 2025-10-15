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

struct seat_state;
struct cursor_state;

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
    struct backbuffer bb[2];
    int bb_index;
    struct damage_accum frame_damage;
    uint64_t last_present_ns;
    uint32_t target_ms;
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
    int32_t width;
    int32_t height;
    int32_t stride;
    bool has_backing;
    uint32_t surface_id;
    int32_t x;
    int32_t y;
    bool pos_initialised;
    bool in_zlist;
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

struct comp_surface *comp_surface_at(struct compositor_state *comp,
                                     int32_t px,
                                     int32_t py,
                                     int32_t *out_sx,
                                     int32_t *out_sy);
void comp_surface_raise(struct compositor_state *comp, struct comp_surface *surface);
static inline bool comp_multi_enabled(const struct compositor_state *comp) {
    return comp && comp->multi_enabled;
}

void comp_damage_add_rect(struct compositor_state *comp, fut_rect_t rect);
void comp_damage_add_full(struct compositor_state *comp);
int comp_set_backbuffer_enabled(struct compositor_state *comp, bool enabled);
