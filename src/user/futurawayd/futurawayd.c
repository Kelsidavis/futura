/* futurawayd.c - Minimal FuturaWay compositor (software, single surface)
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
#include <user/futura_way.h>

#include "../svc_registryd/registry_client.h"
#include "../sys/fipc_sys.h"

#include "fb_host.h"

#define FUTURAWAY_DEFAULT_SERVICE "futurawayd"
#define FUTURAWAY_DEFAULT_HOST    "127.0.0.1"
#define FUTURAWAY_SURFACE_MAX     1u

struct futuraway_surface {
    bool in_use;
    uint64_t id;
    uint32_t width;
    uint32_t height;
    uint32_t stride_bytes;
    uint8_t *pixels;
};

struct futuraway_state {
    struct futurawayd_config cfg;
    struct fut_fipc_channel *listen;
    struct fw_framebuffer fb;
    struct futuraway_surface surface;
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

static void surface_reset(struct futuraway_surface *surface) {
    if (!surface) {
        return;
    }
    free(surface->pixels);
    memset(surface, 0, sizeof(*surface));
}

static int surface_prepare(struct futuraway_surface *surface,
                           uint64_t surface_id,
                           uint32_t width,
                           uint32_t height,
                           uint32_t stride) {
    if (!surface || width == 0 || height == 0 || stride == 0) {
        return -EINVAL;
    }

    size_t needed = (size_t)stride * (size_t)height;
    uint8_t *buffer = (uint8_t *)calloc(1, needed);
    if (!buffer) {
        return -ENOMEM;
    }

    surface_reset(surface);
    surface->pixels = buffer;
    surface->id = surface_id;
    surface->width = width;
    surface->height = height;
    surface->stride_bytes = stride;
    surface->in_use = true;
    return 0;
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

static void publish_surface_commit(const struct futuraway_state *state, uint64_t surface_id) {
    (void)state;
    uint64_t t_start = fut_get_ticks();
    uint64_t t_end = t_start + 1;
    (void)fipc_sys_fway_surface_commit(surface_id, 0, t_start, t_end);
}

static void blit_to_framebuffer(struct futuraway_state *state) {
    if (!state || !state->surface.in_use || !state->fb.pixels) {
        return;
    }

    const uint8_t *src = state->surface.pixels;
    uint8_t *dst = state->fb.pixels;
    uint32_t copy_stride = state->surface.stride_bytes;
    uint32_t fb_stride = state->fb.stride_bytes;

    uint32_t height = state->surface.height;
    for (uint32_t row = 0; row < height; ++row) {
        memcpy(dst + (size_t)row * fb_stride,
               src + (size_t)row * copy_stride,
               copy_stride);
    }
}

static void handle_create(struct futuraway_state *state, const struct fut_fipc_msg *msg) {
    if (!state || !msg || msg->length < sizeof(struct fw_surface_create_req)) {
        return;
    }
    const struct fw_surface_create_req *req =
        (const struct fw_surface_create_req *)msg->payload;
    if (req->format != FW_FORMAT_ARGB32) {
        fprintf(stderr, "[futurawayd] unsupported format %u\n", req->format);
        return;
    }
    if (req->width != state->fb.width || req->height != state->fb.height) {
        fprintf(stderr,
                "[futurawayd] surface %ux%u does not match framebuffer %ux%u\n",
                req->width,
                req->height,
                state->fb.width,
                state->fb.height);
        return;
    }

    if (surface_prepare(&state->surface,
                        req->surface_id,
                        req->width,
                        req->height,
                        req->width * 4u) != 0) {
        fprintf(stderr, "[futurawayd] failed to prepare surface\n");
    }
}

static void handle_commit(struct futuraway_state *state, const struct fut_fipc_msg *msg) {
    if (!state || !msg || msg->length < sizeof(struct fw_surface_commit_req)) {
        return;
    }
    if (!state->surface.in_use) {
        fprintf(stderr, "[futurawayd] commit before surface create ignored\n");
        return;
    }

    const struct fw_surface_commit_req *req =
        (const struct fw_surface_commit_req *)msg->payload;
    size_t pixel_bytes = (size_t)req->height * (size_t)req->stride_bytes;
    size_t expected = sizeof(*req) + pixel_bytes;
    if (req->surface_id != state->surface.id ||
        req->width != state->surface.width ||
        req->height != state->surface.height ||
        req->stride_bytes != state->surface.stride_bytes ||
        msg->length != expected) {
        fprintf(stderr, "[futurawayd] commit mismatch (id=%llu len=%zu exp=%zu)\n",
                (unsigned long long)req->surface_id,
                (size_t)msg->length,
                expected);
        return;
    }

    memcpy(state->surface.pixels, req + 1, pixel_bytes);
    blit_to_framebuffer(state);
    state->frames_presented++;
    publish_surface_commit(state, req->surface_id);
}

static void handle_message(struct futuraway_state *state, const struct fut_fipc_msg *msg) {
    if (!state || !msg) {
        return;
    }
    switch (msg->type) {
    case FWAY_MSG_CREATE_SURFACE:
        handle_create(state, msg);
        break;
    case FWAY_MSG_COMMIT:
        handle_commit(state, msg);
        break;
    case FWAY_MSG_INPUT_EVENT:
        /* Input handling placeholder */
        break;
    default:
        break;
    }
}

static void apply_defaults(struct futuraway_state *state, const struct futurawayd_config *config) {
    memset(state, 0, sizeof(*state));
    state->cfg = *config;
    if (state->cfg.width == 0) {
        state->cfg.width = 800;
    }
    if (state->cfg.height == 0) {
        state->cfg.height = 600;
    }
    if (!state->cfg.service_name) {
        state->cfg.service_name = FUTURAWAY_DEFAULT_SERVICE;
    }
    if (!state->cfg.registry_host) {
        state->cfg.registry_host = FUTURAWAY_DEFAULT_HOST;
    }
}

int futurawayd_run(const struct futurawayd_config *config) {
    if (!config) {
        return -EINVAL;
    }

    struct futuraway_state state;
    apply_defaults(&state, config);

    if (!ensure_system_channel()) {
        fprintf(stderr, "[futurawayd] failed to prepare system channel\n");
        return -EIO;
    }

    if (fw_framebuffer_create(state.cfg.width, state.cfg.height, &state.fb) != 0) {
        fprintf(stderr, "[futurawayd] framebuffer allocation failed\n");
        return -ENOMEM;
    }

    if (fut_fipc_channel_create(NULL,
                                NULL,
                                2u * 1024u * 1024u,
                                FIPC_CHANNEL_NONBLOCKING,
                                &state.listen) != 0 ||
        !state.listen) {
        fprintf(stderr, "[futurawayd] channel creation failed\n");
        fw_framebuffer_destroy(&state.fb);
        return -EIO;
    }

    if (state.cfg.registry_port != 0) {
        if (registry_client_register(state.cfg.registry_host,
                                     state.cfg.registry_port,
                                     state.cfg.service_name,
                                     state.listen->id) != 0) {
            fprintf(stderr, "[futurawayd] registry registration failed\n");
            fut_fipc_channel_destroy(state.listen);
            fw_framebuffer_destroy(&state.fb);
            return -EIO;
        }
    }

    size_t max_payload = sizeof(struct fut_fipc_msg) +
                         sizeof(struct fw_surface_commit_req) +
                         ((size_t)state.cfg.width * (size_t)state.cfg.height * 4u);
    uint8_t *buffer = (uint8_t *)malloc(max_payload);
    if (!buffer) {
        fprintf(stderr, "[futurawayd] buffer allocation failed\n");
        fut_fipc_channel_destroy(state.listen);
        fw_framebuffer_destroy(&state.fb);
        return -ENOMEM;
    }

    fw_framebuffer_clear(&state.fb, 0xFF20252Eu);

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
            running = false;
        }

        if (state.cfg.frame_limit > 0 &&
            state.frames_presented >= state.cfg.frame_limit) {
            running = false;
        }
    }

    if (state.cfg.dump_path && *state.cfg.dump_path) {
        if (ensure_parent_directory(state.cfg.dump_path) == 0) {
            (void)fw_framebuffer_dump_ppm(&state.fb, state.cfg.dump_path);
        } else {
            fprintf(stderr,
                    "[futurawayd] failed to prepare dump path '%s'\n",
                    state.cfg.dump_path);
        }
    }

    free(buffer);
    surface_reset(&state.surface);
    fw_framebuffer_destroy(&state.fb);
    fut_fipc_channel_destroy(state.listen);
    return 0;
}
