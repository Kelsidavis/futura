// SPDX-License-Identifier: MPL-2.0
//
// main.c - Minimal window server prototype

#include <stdbool.h>
#include <futura/fb_ioctl.h>
#include <futura/ipc_ids.h>
#include <futura/ipc_win.h>
#include <kernel/errno.h>
#include <kernel/fut_fipc.h>
#include <user/futura_posix.h>
#include <user/libfutura.h>
#include <user/stdio.h>
#include <user/sys.h>

#include "compositor.h"
#include "win_log.h"
#include "win_proto.h"

#define O_RDWR      0x0002
#define PROT_READ   0x0001
#define PROT_WRITE  0x0002
#define MAP_SHARED  0x0001

struct winsrv_state {
    int fb_fd;
    uint8_t *fb_base;
    size_t fb_size;
    uint32_t fb_width;
    uint32_t fb_height;
    uint32_t fb_pitch;
    uint32_t fb_bpp;
    struct fut_fipc_channel *channel;
    struct ui_surface *surface;
    uint32_t client_version;
};

static int winsrv_init_fb(struct winsrv_state *state) {
    state->fb_fd = (int)sys_open("/dev/fb0", O_RDWR, 0);
    if (state->fb_fd < 0) {
        return -ENODEV;
    }

    struct fut_fb_info info = {0};
    if (sys_ioctl(state->fb_fd, FBIOGET_INFO, (long)&info) < 0) {
        sys_close(state->fb_fd);
        state->fb_fd = -1;
        return -EINVAL;
    }

    size_t fb_size = (size_t)info.pitch * info.height;
    void *map = (void *)sys_mmap(NULL,
                                 (long)fb_size,
                                 PROT_READ | PROT_WRITE,
                                 MAP_SHARED,
                                 state->fb_fd,
                                 0);
    if ((long)map < 0) {
        sys_close(state->fb_fd);
        state->fb_fd = -1;
        return -ENOMEM;
    }

    state->fb_base = (uint8_t *)map;
    state->fb_size = fb_size;
    state->fb_width = info.width;
    state->fb_height = info.height;
    state->fb_pitch = info.pitch;
    state->fb_bpp = info.bpp;
    return 0;
}

static struct fut_fipc_channel *winsrv_bind_channel(void) {
    struct fut_fipc_channel *chan = fut_fipc_channel_lookup(FIPC_CHAN_WINSRV);
    if (chan) {
        return chan;
    }

    if (fut_fipc_channel_create(NULL,
                                NULL,
                                4096,
                                FIPC_CHANNEL_BLOCKING,
                                &chan) != 0 || !chan) {
        return NULL;
    }

    chan->id = FIPC_CHAN_WINSRV;
    chan->type = FIPC_CHANNEL_LOCAL;
    return chan;
}

static void winsrv_surface_reset(struct winsrv_state *state) {
    if (state->surface) {
        compositor_surface_destroy(state->surface);
        state->surface = NULL;
    }
}

int main(void) {
    struct winsrv_state state = {
        .fb_fd = -1,
        .fb_base = NULL,
        .fb_size = 0,
        .fb_width = 0,
        .fb_height = 0,
        .fb_pitch = 0,
        .fb_bpp = 0,
        .channel = NULL,
        .surface = NULL,
        .client_version = 0,
    };

    if (winsrv_init_fb(&state) != 0) {
        sys_exit(-1);
    }

    state.channel = winsrv_bind_channel();
    if (!state.channel) {
        sys_exit(-1);
    }

    struct win_msg_ready ready = {
        .fb_w = state.fb_width,
        .fb_h = state.fb_height,
        .fb_bpp = state.fb_bpp
    };
    (void)win_proto_send(state.channel,
                         WIN_MSG_READY,
                         &ready,
                         sizeof(ready));
    WLOG_READY(state.fb_width, state.fb_height, state.fb_bpp);

    struct win_proto_message msg = {0};
    bool running = true;

    while (running) {
        int rc = win_proto_recv(state.channel, &msg);
        if (rc < 0) {
            continue;
        }

        switch (msg.header.id) {
        case WIN_MSG_HELLO: {
            if (msg.payload_size == sizeof(struct win_msg_hello)) {
                const struct win_msg_hello *hello =
                    (const struct win_msg_hello *)msg.payload;
                state.client_version = hello->version;
            }
            break;
        }

        case WIN_MSG_CREATE: {
            if (msg.payload_size != sizeof(struct win_msg_create)) {
                break;
            }
            const struct win_msg_create *create =
                (const struct win_msg_create *)msg.payload;
            winsrv_surface_reset(&state);
            state.surface = compositor_surface_create(create->width, create->height);
            if (!state.surface) {
                break;
            }

            struct win_msg_created created = {
                .surface_id = WIN_SURFACE_ID_PRIMARY,
                .width = state.surface->width,
                .height = state.surface->height,
                .pitch = state.surface->pitch,
                .format = WIN_FORMAT_ARGB8888
            };
            (void)win_proto_send(state.channel,
                                 WIN_MSG_CREATED,
                                 &created,
                                 sizeof(created));
            WLOG_CREATE(state.surface->width, state.surface->height, created.surface_id);
            break;
        }

        case WIN_MSG_DAMAGE_RECT: {
            if (msg.payload_size != sizeof(struct win_msg_damage) || !state.surface) {
                break;
            }
            const struct win_msg_damage *damage =
                (const struct win_msg_damage *)msg.payload;
            if (damage->surface_id != WIN_SURFACE_ID_PRIMARY) {
                break;
            }

            compositor_fill_rect(state.surface,
                                 damage->x,
                                 damage->y,
                                 damage->width,
                                 damage->height,
                                 damage->argb);
            compositor_blit_to_fb(state.surface,
                                  state.fb_base,
                                  state.fb_pitch,
                                  state.fb_width,
                                  state.fb_height,
                                  damage->x,
                                  damage->y,
                                  damage->width,
                                  damage->height);
            WLOG_DAMAGE(damage->surface_id,
                        damage->x,
                        damage->y,
                        damage->width,
                        damage->height);
            break;
        }

        case WIN_MSG_CLOSE: {
            winsrv_surface_reset(&state);
            running = false;
            break;
        }

        default:
            break;
        }
    }

    winsrv_surface_reset(&state);
    if (state.channel) {
        fut_fipc_channel_destroy(state.channel);
        state.channel = NULL;
    }
    if (state.fb_fd >= 0) {
        sys_close(state.fb_fd);
    }
    if (state.fb_base && state.fb_size > 0) {
        sys_munmap_call(state.fb_base, (long)state.fb_size);
    }
    sys_exit(0);
    return 0;
}
