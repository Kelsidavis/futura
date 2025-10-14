// SPDX-License-Identifier: MPL-2.0
#pragma once

#include <stdbool.h>
#include <stdint.h>

#include <futura/fb_ioctl.h>
#include <wayland-server-core.h>

struct comp_damage {
    int32_t x;
    int32_t y;
    int32_t width;
    int32_t height;
    bool valid;
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
    uint32_t frame_delay_ms;
};

struct comp_surface {
    struct compositor_state *comp;
    struct wl_resource *surface_resource;
    struct wl_resource *pending_buffer_resource;
    struct comp_damage pending_damage;
    struct wl_list frame_callbacks;
    bool has_pending_buffer;
};

int comp_state_init(struct compositor_state *comp);
void comp_state_finish(struct compositor_state *comp);

void comp_present_buffer(struct compositor_state *comp,
                         struct comp_buffer *buffer,
                         const struct comp_damage *damage);

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
