// SPDX-License-Identifier: MPL-2.0
//
// main.c - Window protocol stub client

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <futura/ipc_ids.h>
#include <futura/ipc_win.h>
#include <kernel/errno.h>
#include <kernel/fut_fipc.h>
#include <user/futura_posix.h>
#include <user/libfutura.h>
#include <shared/fut_timespec.h>
#include <user/stdio.h>
#include <user/sys.h>

#include "../../services/winsrv/win_proto.h"

static void sleep_ms(uint32_t ms) {
    fut_timespec_t ts = {
        .tv_sec = (long)(ms / 1000u),
        .tv_nsec = (long)((ms % 1000u) * 1000000u)
    };
    sys_nanosleep_call(&ts, NULL);
}

static struct fut_fipc_channel *wait_for_channel(void) {
    const uint32_t attempts = 50;
    for (uint32_t i = 0; i < attempts; ++i) {
        struct fut_fipc_channel *chan = fut_fipc_channel_lookup(FIPC_CHAN_WINSRV);
        if (chan) {
            return chan;
        }
        sleep_ms(10);
    }
    return NULL;
}

int main(void) {
    struct fut_fipc_channel *channel = wait_for_channel();
    if (!channel) {
        sys_exit(-1);
    }

    const struct win_msg_hello hello = { .version = WIN_PROTO_VERSION };
    (void)win_proto_send(channel, WIN_MSG_HELLO, &hello, sizeof(hello));

    struct win_proto_message msg = {0};
    bool got_ready = false;
    bool running = true;

    while (running && !got_ready) {
        int rc = win_proto_recv(channel, &msg);
        if (rc < 0) {
            sys_exit(-1);
        }
        if (msg.header.id == WIN_MSG_READY) {
            got_ready = true;
            break;
        }
    }

    if (!got_ready) {
        sys_exit(-1);
    }

    struct win_msg_create create = {
        .width = 320,
        .height = 200,
    };
    memset(create.title, 0, sizeof(create.title));
    const char title[] = "winstub";
    strncpy(create.title, title, sizeof(create.title) - 1u);

    (void)win_proto_send(channel, WIN_MSG_CREATE, &create, sizeof(create));

    uint32_t surface_width = 0;
    uint32_t surface_height = 0;
    bool surface_ready = false;

    while (!surface_ready) {
        int rc = win_proto_recv(channel, &msg);
        if (rc < 0) {
            sys_exit(-1);
        }
        if (msg.header.id == WIN_MSG_CREATED &&
            msg.payload_size == sizeof(struct win_msg_created)) {
            const struct win_msg_created *created =
                (const struct win_msg_created *)msg.payload;
            if (created->surface_id == WIN_SURFACE_ID_PRIMARY) {
                surface_width = created->width;
                surface_height = created->height;
                surface_ready = true;
                printf("[WINSTUB] connected; created surface %u (%ux%u)\n",
                       created->surface_id,
                       surface_width,
                       surface_height);
            }
        }
    }

    struct win_msg_damage damage = {
        .surface_id = WIN_SURFACE_ID_PRIMARY,
        .x = 0,
        .y = 0,
        .width = surface_width,
        .height = surface_height,
        .argb = 0xFF2030FFu /* blue-ish */
    };
    (void)win_proto_send(channel, WIN_MSG_DAMAGE_RECT, &damage, sizeof(damage));
    sleep_ms(200);

    damage.x = (surface_width > 100u) ? (surface_width - 100u) / 2u : 0u;
    damage.y = (surface_height > 60u) ? (surface_height - 60u) / 2u : 0u;
    damage.width = surface_width < 100u ? surface_width : 100u;
    damage.height = surface_height < 60u ? surface_height : 60u;
    damage.argb = 0xFFFF3040u; /* red */
    (void)win_proto_send(channel, WIN_MSG_DAMAGE_RECT, &damage, sizeof(damage));
    sleep_ms(200);

    const uint32_t stripe_w = surface_width < 24u ? surface_width : 24u;
    const uint32_t stripe_h = surface_height < 24u ? surface_height : 24u;
    uint32_t stripe_x = surface_width / 3u;
    uint32_t stripe_y = surface_height / 4u;
    if (stripe_x + stripe_w > surface_width) {
        stripe_x = surface_width > stripe_w ? surface_width - stripe_w : 0u;
    }
    if (stripe_y + stripe_h > surface_height) {
        stripe_y = surface_height > stripe_h ? surface_height - stripe_h : 0u;
    }
    struct win_msg_damage stripe = {
        .surface_id = WIN_SURFACE_ID_PRIMARY,
        .x = stripe_x,
        .y = stripe_y,
        .width = stripe_w,
        .height = stripe_h,
        .argb = 0xFF30FF60u /* green */
    };
    (void)win_proto_send(channel, WIN_MSG_DAMAGE_RECT, &stripe, sizeof(stripe));
    sleep_ms(200);

    (void)win_proto_send(channel, WIN_MSG_CLOSE, NULL, 0);

    printf("[WINSTUB] drew 3 rects; bye\n");
    sys_exit(0);
    return 0;
}
