/* futurawayd.c - Futuraway compositor (M2: multi-surface, damage-aware)
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 */

#define _POSIX_C_SOURCE 200809L

#include "futurawayd.h"

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#include <kernel/fut_fipc.h>
#include <kernel/fut_fipc_sys.h>
#include <kernel/fut_timer.h>

#include <user/futuraway_proto.h>

#include "../svc_registryd/registry_client.h"
#include "../sys/fipc_sys.h"

#include "fb_host.h"

#define FUTURAWAY_MAX_SURFACES   64u
#define FUTURAWAY_MAX_DAMAGE     64u
#define FUTURAWAY_BG_COLOR       0xFF20252Eu

struct futuraway_damage_entry {
    struct fw_surface_damage rect;
    bool in_use;
};

struct futuraway_surface {
    bool in_use;
    uint64_t id;
    uint32_t width;
    uint32_t height;
    uint32_t stride_bytes;
    uint32_t z_index;
    bool premultiplied;
    bool full_dirty;
    uint8_t *pixels;
    size_t pixels_size;
    struct futuraway_damage_entry damages[FUTURAWAY_MAX_DAMAGE];
};

struct futuraway_state {
    struct futurawayd_config cfg;
    struct fut_fipc_channel *listen;
    struct fw_framebuffer fb;
    struct futuraway_surface surfaces[FUTURAWAY_MAX_SURFACES];
    uint32_t frames_presented;
};

static int ensure_parent_directory(const char *path) {
    if (!path || *path == '\0') {
        return -EINVAL;
    }

    char *copy = strdup(path);
    if (!copy) {
        return -ENOMEM;
    }

    char *slash = strrchr(copy, '/');
    if (!slash) {
        free(copy);
        return 0;
    }
    *slash = '\0';
    if (*copy == '\0') {
        free(copy);
        return 0;
    }

    int rc = 0;
    size_t len = strlen(copy);
    for (size_t i = 1; i < len; ++i) {
        if (copy[i] != '/' && copy[i] != '\0') {
            continue;
        }
        char saved = copy[i];
        copy[i] = '\0';
        if (strlen(copy) > 0) {
            if (mkdir(copy, 0755) != 0 && errno != EEXIST) {
                rc = -errno;
                copy[i] = saved;
                break;
            }
        }
        copy[i] = saved;
    }

    if (rc == 0) {
        if (mkdir(copy, 0755) != 0 && errno != EEXIST) {
            rc = -errno;
        }
    }

    free(copy);
    return rc;
}

static struct fut_fipc_channel *ensure_system_channel(void) {
    struct fut_fipc_channel *channel = fut_fipc_channel_lookup(FIPC_SYS_CHANNEL_ID);
    if (channel) {
        return channel;
    }
    if (fut_fipc_channel_create(NULL,
                                NULL,
                                4096,
                                FIPC_CHANNEL_NONBLOCKING,
                                &channel) != 0 || !channel) {
        return NULL;
    }
    channel->id = FIPC_SYS_CHANNEL_ID;
    channel->type = FIPC_CHANNEL_SYSTEM;
    return channel;
}

static void publish_surface_commit(uint64_t surface_id) {
    uint64_t t_start = fut_get_ticks();
    uint64_t t_end = t_start + 1;
    (void)fipc_sys_fway_surface_commit(surface_id, 0, t_start, t_end);
}

static struct futuraway_surface *surface_lookup(struct futuraway_state *state, uint64_t surface_id) {
    for (size_t i = 0; i < FUTURAWAY_MAX_SURFACES; ++i) {
        if (state->surfaces[i].in_use && state->surfaces[i].id == surface_id) {
            return &state->surfaces[i];
        }
    }
    return NULL;
}

static struct futuraway_surface *surface_alloc(struct futuraway_state *state, uint64_t surface_id) {
    struct futuraway_surface *slot = surface_lookup(state, surface_id);
    if (slot) {
        return slot;
    }
    for (size_t i = 0; i < FUTURAWAY_MAX_SURFACES; ++i) {
        if (!state->surfaces[i].in_use) {
            memset(&state->surfaces[i], 0, sizeof(state->surfaces[i]));
            state->surfaces[i].in_use = true;
            state->surfaces[i].id = surface_id;
            return &state->surfaces[i];
        }
    }
    return NULL;
}

static void surface_reset(struct futuraway_surface *surface) {
    if (!surface) {
        return;
    }
    free(surface->pixels);
    memset(surface, 0, sizeof(*surface));
}

static struct fw_surface_damage clip_damage(const struct futuraway_surface *surface,
                                            const struct fw_surface_damage *rect) {
    struct fw_surface_damage out = *rect;
    if (out.x >= surface->width || out.y >= surface->height) {
        out.width = 0;
        out.height = 0;
        return out;
    }

    uint64_t max_w = surface->width - out.x;
    uint64_t max_h = surface->height - out.y;
    if (out.width > max_w) {
        out.width = (uint32_t)max_w;
    }
    if (out.height > max_h) {
        out.height = (uint32_t)max_h;
    }
    return out;
}

static bool damage_intersects(const struct fw_surface_damage *a,
                              const struct fw_surface_damage *b) {
    uint64_t ax2 = (uint64_t)a->x + a->width;
    uint64_t ay2 = (uint64_t)a->y + a->height;
    uint64_t bx2 = (uint64_t)b->x + b->width;
    uint64_t by2 = (uint64_t)b->y + b->height;
    return !(ax2 <= b->x || bx2 <= a->x || ay2 <= b->y || by2 <= a->y);
}

static struct fw_surface_damage damage_union(const struct fw_surface_damage *a,
                                             const struct fw_surface_damage *b) {
    uint64_t x1 = a->x < b->x ? a->x : b->x;
    uint64_t y1 = a->y < b->y ? a->y : b->y;
    uint64_t x2 = ((uint64_t)a->x + a->width) > ((uint64_t)b->x + b->width)
                      ? ((uint64_t)a->x + a->width)
                      : ((uint64_t)b->x + b->width);
    uint64_t y2 = ((uint64_t)a->y + a->height) > ((uint64_t)b->y + b->height)
                      ? ((uint64_t)a->y + a->height)
                      : ((uint64_t)b->y + b->height);
    struct fw_surface_damage result = {
        .x = (uint32_t)x1,
        .y = (uint32_t)y1,
        .width = (uint32_t)(x2 - x1),
        .height = (uint32_t)(y2 - y1),
    };
    return result;
}

static void surface_add_damage(struct futuraway_surface *surface,
                               const struct fw_surface_damage *rect) {
    if (!surface || !rect) {
        return;
    }
    struct fw_surface_damage clipped = clip_damage(surface, rect);
    if (clipped.width == 0 || clipped.height == 0) {
        return;
    }

    for (size_t i = 0; i < FUTURAWAY_MAX_DAMAGE; ++i) {
        if (!surface->damages[i].in_use) {
            continue;
        }
        struct fw_surface_damage *existing = &surface->damages[i].rect;
        if (damage_intersects(existing, &clipped)) {
            *existing = damage_union(existing, &clipped);
            return;
        }
        if (clipped.x >= existing->x &&
            clipped.y >= existing->y &&
            (clipped.x + clipped.width) <= (existing->x + existing->width) &&
            (clipped.y + clipped.height) <= (existing->y + existing->height)) {
            return;
        }
    }

    for (size_t i = 0; i < FUTURAWAY_MAX_DAMAGE; ++i) {
        if (!surface->damages[i].in_use) {
            surface->damages[i].rect = clipped;
            surface->damages[i].in_use = true;
            return;
        }
    }

    surface->full_dirty = true;
    for (size_t i = 0; i < FUTURAWAY_MAX_DAMAGE; ++i) {
        surface->damages[i].in_use = false;
    }
}

static size_t surface_snapshot_damage(const struct futuraway_surface *surface,
                                      struct fw_surface_damage *out,
                                      size_t max_out,
                                      bool *full_region) {
    if (!surface || !out || max_out == 0) {
        if (full_region) {
            *full_region = false;
        }
        return 0;
    }

    if (surface->full_dirty) {
        if (full_region) {
            *full_region = true;
        }
        out[0] = (struct fw_surface_damage){
            .x = 0,
            .y = 0,
            .width = surface->width,
            .height = surface->height,
        };
        return 1;
    }

    size_t count = 0;
    for (size_t i = 0; i < FUTURAWAY_MAX_DAMAGE && count < max_out; ++i) {
        if (surface->damages[i].in_use) {
            out[count++] = surface->damages[i].rect;
        }
    }

    if (count == 0) {
        if (full_region) {
            *full_region = true;
        }
        out[0] = (struct fw_surface_damage){
            .x = 0,
            .y = 0,
            .width = surface->width,
            .height = surface->height,
        };
        return 1;
    }

    if (full_region) {
        *full_region = false;
    }
    return count;
}

static void surface_clear_damage(struct futuraway_surface *surface) {
    if (!surface) {
        return;
    }
    surface->full_dirty = false;
    for (size_t i = 0; i < FUTURAWAY_MAX_DAMAGE; ++i) {
        surface->damages[i].in_use = false;
    }
}

static inline uint32_t premultiply_pixel(uint32_t pixel) {
    uint32_t a = (pixel >> 24) & 0xFFu;
    if (a == 0u || a == 255u) {
        return ((a & 0xFFu) << 24) | (pixel & 0x00FFFFFFu);
    }
    uint32_t r = (pixel >> 16) & 0xFFu;
    uint32_t g = (pixel >> 8) & 0xFFu;
    uint32_t b = pixel & 0xFFu;
    r = (r * a + 127u) / 255u;
    g = (g * a + 127u) / 255u;
    b = (b * a + 127u) / 255u;
    return (a << 24) | (r << 16) | (g << 8) | b;
}

static inline uint32_t clamp_u32(uint32_t value) {
    return value > 255u ? 255u : value;
}

static inline uint32_t blend_premult(uint32_t dst, uint32_t src) {
    uint32_t src_a = (src >> 24) & 0xFFu;
    if (src_a == 0u) {
        return dst;
    }
    if (src_a == 255u) {
        return src;
    }

    uint32_t dst_a = (dst >> 24) & 0xFFu;
    uint32_t inv = 255u - src_a;

    uint32_t dst_r = (dst >> 16) & 0xFFu;
    uint32_t dst_g = (dst >> 8) & 0xFFu;
    uint32_t dst_b = dst & 0xFFu;

    uint32_t src_r = (src >> 16) & 0xFFu;
    uint32_t src_g = (src >> 8) & 0xFFu;
    uint32_t src_b = src & 0xFFu;

    uint32_t out_r = src_r + ((dst_r * inv) + 127u) / 255u;
    uint32_t out_g = src_g + ((dst_g * inv) + 127u) / 255u;
    uint32_t out_b = src_b + ((dst_b * inv) + 127u) / 255u;
    uint32_t out_a = src_a + ((dst_a * inv) + 127u) / 255u;

    return (clamp_u32(out_a) << 24) |
           (clamp_u32(out_r) << 16) |
           (clamp_u32(out_g) << 8) |
           clamp_u32(out_b);
}

static size_t gather_surfaces_by_z(const struct futuraway_state *state,
                                   const struct futuraway_surface **out,
                                   size_t max_out) {
    size_t count = 0;
    for (size_t i = 0; i < FUTURAWAY_MAX_SURFACES && count < max_out; ++i) {
        if (state->surfaces[i].in_use && state->surfaces[i].pixels) {
            out[count++] = &state->surfaces[i];
        }
    }

    for (size_t i = 1; i < count; ++i) {
        const struct futuraway_surface *key = out[i];
        size_t j = i;
        while (j > 0 && out[j - 1]->z_index > key->z_index) {
            out[j] = out[j - 1];
            --j;
        }
        out[j] = key;
    }

    return count;
}

static void composite_rect(struct futuraway_state *state,
                           const struct futuraway_surface **ordered,
                           size_t surface_count,
                           const struct fw_surface_damage *rect) {
    if (!rect || rect->width == 0 || rect->height == 0) {
        return;
    }
    uint32_t fb_w = state->fb.width;
    uint32_t fb_h = state->fb.height;

    uint32_t x0 = rect->x;
    uint32_t y0 = rect->y;
    uint32_t x1 = rect->x + rect->width;
    uint32_t y1 = rect->y + rect->height;

    if (x0 >= fb_w || y0 >= fb_h) {
        return;
    }

    if (x1 > fb_w) {
        x1 = fb_w;
    }
    if (y1 > fb_h) {
        y1 = fb_h;
    }

    uint32_t stride_pixels = state->fb.stride_bytes / 4u;
    uint32_t *fb_pixels = (uint32_t *)state->fb.pixels;

    for (uint32_t y = y0; y < y1; ++y) {
        for (uint32_t x = x0; x < x1; ++x) {
            uint32_t color = FUTURAWAY_BG_COLOR;
            for (size_t s = 0; s < surface_count; ++s) {
                const struct futuraway_surface *surf = ordered[s];
                if (x >= surf->width || y >= surf->height) {
                    continue;
                }
                const uint32_t *surface_pixels = (const uint32_t *)surf->pixels;
                uint32_t surface_stride = surf->stride_bytes / 4u;
                uint32_t src = surface_pixels[(size_t)y * surface_stride + x];
                color = blend_premult(color, src);
            }
            fb_pixels[(size_t)y * stride_pixels + x] = color;
        }
    }
}

static void composite_regions(struct futuraway_state *state,
                              struct futuraway_surface *surface,
                              const struct fw_surface_damage *rects,
                              size_t rect_count) {
    (void)surface;
    if (rect_count == 0) {
        return;
    }
    const struct futuraway_surface *ordered[FUTURAWAY_MAX_SURFACES];
    size_t surface_count = gather_surfaces_by_z(state, ordered, FUTURAWAY_MAX_SURFACES);

    for (size_t i = 0; i < rect_count; ++i) {
        composite_rect(state, ordered, surface_count, &rects[i]);
    }
}

static int surface_ensure_pixels(struct futuraway_surface *surface,
                                 size_t bytes,
                                 bool premult) {
    if (!surface) {
        return -EINVAL;
    }
    if (surface->pixels_size < bytes) {
        uint8_t *mem = (uint8_t *)realloc(surface->pixels, bytes);
        if (!mem) {
            return -ENOMEM;
        }
        surface->pixels = mem;
        surface->pixels_size = bytes;
    }
    surface->premultiplied = premult;
    return 0;
}

static void premultiply_rectangles(uint32_t *pixels,
                                   uint32_t stride_pixels,
                                   const struct fw_surface_damage *rects,
                                   size_t rect_count) {
    if (!pixels || !rects) {
        return;
    }
    for (size_t i = 0; i < rect_count; ++i) {
        const struct fw_surface_damage *r = &rects[i];
        for (uint32_t y = 0; y < r->height; ++y) {
            uint32_t *row = pixels + (size_t)(r->y + y) * stride_pixels + r->x;
            for (uint32_t x = 0; x < r->width; ++x) {
                row[x] = premultiply_pixel(row[x]);
            }
        }
    }
}

static int surface_update_pixels(struct futuraway_surface *surface,
                                 const struct fw_surface_commit_req *req,
                                 const uint8_t *payload,
                                 const struct fw_surface_damage *rects,
                                 size_t rect_count,
                                 bool full_region) {
    size_t required = (size_t)req->stride_bytes * (size_t)req->height;
    int rc = surface_ensure_pixels(surface, required, surface->premultiplied);
    if (rc != 0) {
        return rc;
    }

    if (full_region) {
        memcpy(surface->pixels, payload, required);
        if (!surface->premultiplied) {
            uint32_t *pixels = (uint32_t *)surface->pixels;
            size_t count = ((size_t)req->stride_bytes / 4u) * req->height;
            for (size_t i = 0; i < count; ++i) {
                pixels[i] = premultiply_pixel(pixels[i]);
            }
            surface->premultiplied = true;
        }
        return 0;
    }

    uint32_t stride_pixels = req->stride_bytes / 4u;
    for (size_t i = 0; i < rect_count; ++i) {
        struct fw_surface_damage rect = rects[i];
        if (rect.width == 0 || rect.height == 0) {
            continue;
        }
        size_t copy_bytes = (size_t)rect.width * 4u;
        for (uint32_t row = 0; row < rect.height; ++row) {
            const uint8_t *src = payload + ((size_t)(rect.y + row) * req->stride_bytes) + rect.x * 4u;
            uint8_t *dst = surface->pixels + ((size_t)(rect.y + row) * req->stride_bytes) + rect.x * 4u;
            memcpy(dst, src, copy_bytes);
        }
    }

    if (!surface->premultiplied) {
        uint32_t *pixels = (uint32_t *)surface->pixels;
        premultiply_rectangles(pixels, stride_pixels, rects, rect_count);
        surface->premultiplied = true;
    }

    return 0;
}

static int handle_surface_create2(struct futuraway_state *state,
                                  const struct fw_surface_create2_req *req) {
    if (!req) {
        return -EINVAL;
    }
    if (req->format != FW_FORMAT_ARGB32) {
        return -EINVAL;
    }
    if (req->width == 0 || req->height == 0 ||
        req->width > state->fb.width || req->height > state->fb.height) {
        return -EINVAL;
    }

    struct futuraway_surface *surface = surface_alloc(state, req->surface_id);
    if (!surface) {
        return -ENOMEM;
    }

    surface->width = req->width;
    surface->height = req->height;
    surface->stride_bytes = req->width * 4u;
    surface->z_index = req->z_index;
    surface->premultiplied = req->alpha_premultiplied != 0;
    surface->full_dirty = true;

    if (req->shm_bytes != 0 && req->shm_bytes < surface->stride_bytes * (uint64_t)req->height) {
        surface->pixels_size = (size_t)req->shm_bytes;
    }

    return 0;
}

static int handle_surface_create(struct futuraway_state *state,
                                 const struct fw_surface_create_req *req) {
    if (!req) {
        return -EINVAL;
    }
    struct fw_surface_create2_req up = {
        .width = req->width,
        .height = req->height,
        .format = req->format,
        .flags = req->flags,
        .surface_id = req->surface_id,
        .z_index = 0,
        .alpha_premultiplied = 1,
        .shm_bytes = 0,
    };
    return handle_surface_create2(state, &up);
}

static int handle_surface_set_z(struct futuraway_state *state,
                                const struct fw_surface_set_z_req *req) {
    if (!req) {
        return -EINVAL;
    }
    struct futuraway_surface *surface = surface_lookup(state, req->surface_id);
    if (!surface) {
        return -ENOENT;
    }
    surface->z_index = req->z_index;
    surface->full_dirty = true;
    return 0;
}

static int handle_surface_damage(struct futuraway_state *state,
                                 const struct fw_surface_damage_req *req) {
    if (!req) {
        return -EINVAL;
    }
    struct futuraway_surface *surface = surface_lookup(state, req->surface_id);
    if (!surface) {
        return -ENOENT;
    }
    surface_add_damage(surface, &req->rect);
    return 0;
}

static int handle_surface_commit(struct futuraway_state *state,
                                 const struct fut_fipc_msg *msg) {
    if (!msg || msg->length < sizeof(struct fw_surface_commit_req)) {
        return -EINVAL;
    }
    const struct fw_surface_commit_req *req =
        (const struct fw_surface_commit_req *)msg->payload;

    struct futuraway_surface *surface = surface_lookup(state, req->surface_id);
    if (!surface) {
        return -ENOENT;
    }
    if (req->width != surface->width ||
        req->height != surface->height ||
        req->stride_bytes != surface->stride_bytes) {
        return -EINVAL;
    }

    size_t pixel_bytes = (size_t)req->stride_bytes * (size_t)req->height;
    if (msg->length != sizeof(*req) + pixel_bytes) {
        return -EINVAL;
    }

    struct fw_surface_damage rects[FUTURAWAY_MAX_DAMAGE + 1];
    bool full_region = false;
    size_t rect_count = surface_snapshot_damage(surface,
                                                rects,
                                                FUTURAWAY_MAX_DAMAGE + 1,
                                                &full_region);
    if (rect_count == 0) {
        rects[0] = (struct fw_surface_damage){
            .x = 0,
            .y = 0,
            .width = surface->width,
            .height = surface->height,
        };
        rect_count = 1;
        full_region = true;
    }

    int rc = surface_update_pixels(surface,
                                   req,
                                   msg->payload + sizeof(*req),
                                   rects,
                                   rect_count,
                                   full_region);
    if (rc != 0) {
        return rc;
    }

    composite_regions(state, surface, rects, rect_count);
    surface_clear_damage(surface);
    publish_surface_commit(surface->id);
    state->frames_presented++;
    return 0;
}

static void handle_message(struct futuraway_state *state,
                           const struct fut_fipc_msg *msg) {
    switch (msg->type) {
    case FW_OP_SURFACE_CREATE:
        (void)handle_surface_create(state,
                                    (const struct fw_surface_create_req *)msg->payload);
        break;
    case FW_OP_SURFACE_CREATE2:
        (void)handle_surface_create2(state,
                                     (const struct fw_surface_create2_req *)msg->payload);
        break;
    case FW_OP_SURFACE_SET_Z:
        (void)handle_surface_set_z(state,
                                   (const struct fw_surface_set_z_req *)msg->payload);
        break;
    case FW_OP_SURFACE_DAMAGE:
        (void)handle_surface_damage(state,
                                    (const struct fw_surface_damage_req *)msg->payload);
        break;
    case FW_OP_SURFACE_COMMIT:
        (void)handle_surface_commit(state, msg);
        break;
    case FW_OP_SURFACE_BUFFER:
        if (msg->length >= sizeof(struct fw_surface_buffer)) {
            (void)*(const struct fw_surface_buffer *)msg->payload;
        }
        break;
    case FW_OP_PRESENT:
        if (msg->length >= sizeof(struct fw_present)) {
            const struct fw_present *req = (const struct fw_present *)msg->payload;
            size_t count = (size_t)req->damage_count;
            size_t extra = 0;
            bool valid = true;
            if (count != 0) {
                if (count > (SIZE_MAX - sizeof(struct fw_present)) / sizeof(struct fw_surface_damage)) {
                    valid = false;
                } else {
                    extra = count * sizeof(struct fw_surface_damage);
                }
            }
            if (valid && msg->length >= sizeof(struct fw_present) + extra) {
                /* consume payload to keep parser aligned; no state yet */
            }
        }
        break;
    case FW_OP_INPUT_FOCUS:
        if (msg->length >= sizeof(uint64_t)) {
            (void)*(const uint64_t *)msg->payload;
        }
        break;
    case FW_OP_INPUT_POINTER:
        if (msg->length >= sizeof(uint32_t) * 2u) {
            (void)((const uint32_t *)msg->payload)[0];
            (void)((const uint32_t *)msg->payload)[1];
        }
        break;
    case FW_OP_INPUT_EVENT:
    default:
        break;
    }
}

static void futuraway_state_init(struct futuraway_state *state,
                                 const struct futurawayd_config *config) {
    memset(state, 0, sizeof(*state));
    state->cfg = *config;
    if (state->cfg.width == 0) {
        state->cfg.width = 800;
    }
    if (state->cfg.height == 0) {
        state->cfg.height = 600;
    }
    if (!state->cfg.service_name) {
        state->cfg.service_name = "futurawayd";
    }
    if (!state->cfg.registry_host) {
        state->cfg.registry_host = "127.0.0.1";
    }
}

static void futuraway_state_shutdown(struct futuraway_state *state) {
    if (!state) {
        return;
    }
    for (size_t i = 0; i < FUTURAWAY_MAX_SURFACES; ++i) {
        if (state->surfaces[i].in_use) {
            surface_reset(&state->surfaces[i]);
        }
    }
    fw_framebuffer_destroy(&state->fb);
    if (state->listen) {
        fut_fipc_channel_destroy(state->listen);
        state->listen = NULL;
    }
}

int futurawayd_run(const struct futurawayd_config *config) {
    if (!config) {
        return -EINVAL;
    }

    struct futuraway_state state;
    futuraway_state_init(&state, config);

    if (!ensure_system_channel()) {
        return -EIO;
    }

    if (fw_framebuffer_create(state.cfg.width, state.cfg.height, &state.fb) != 0) {
        return -ENOMEM;
    }
    fw_framebuffer_clear(&state.fb, FUTURAWAY_BG_COLOR);

    if (fut_fipc_channel_create(NULL,
                                NULL,
                                8u * 1024u * 1024u,
                                FIPC_CHANNEL_NONBLOCKING,
                                &state.listen) != 0 ||
        !state.listen) {
        futuraway_state_shutdown(&state);
        return -EIO;
    }

    if (state.cfg.registry_port != 0) {
        if (registry_client_register(state.cfg.registry_host,
                                     state.cfg.registry_port,
                                     state.cfg.service_name,
                                     state.listen->id) != 0) {
            futuraway_state_shutdown(&state);
            return -EIO;
        }
    }

    size_t max_payload = sizeof(struct fut_fipc_msg) +
                         sizeof(struct fw_surface_commit_req) +
                         ((size_t)state.cfg.width * (size_t)state.cfg.height * 4u);
    uint8_t *buffer = (uint8_t *)malloc(max_payload);
    if (!buffer) {
        futuraway_state_shutdown(&state);
        return -ENOMEM;
    }

    bool running = true;
    while (running) {
        ssize_t rc = fut_fipc_recv(state.listen, buffer, max_payload);
        if (rc > 0) {
            struct fut_fipc_msg *msg = (struct fut_fipc_msg *)buffer;
            if ((size_t)rc >= sizeof(*msg) && msg->length <= (size_t)rc - sizeof(*msg)) {
                handle_message(&state, msg);
            }
        } else if (rc == FIPC_EAGAIN) {
            struct timespec ts = { .tv_sec = 0, .tv_nsec = 1 * 1000 * 1000 };
            nanosleep(&ts, NULL);
        } else {
            break;
        }

        if (state.cfg.frame_limit != 0 &&
            state.frames_presented >= state.cfg.frame_limit) {
            running = false;
        }
    }

    if (state.cfg.dump_path && *state.cfg.dump_path) {
        if (ensure_parent_directory(state.cfg.dump_path) == 0) {
            (void)fw_framebuffer_dump_ppm(&state.fb, state.cfg.dump_path);
        }
    }

    free(buffer);
    futuraway_state_shutdown(&state);
    return 0;
}
