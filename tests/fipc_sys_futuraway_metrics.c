// SPDX-License-Identifier: MPL-2.0
// Validate that FuturaWay compositor telemetry publishes IDL-v0 records.

#define _POSIX_C_SOURCE 200809L

#include <stdint.h>
#include <stdio.h>
#include <time.h>

#include <kernel/fut_fipc.h>
#include <kernel/fut_fipc_sys.h>

#include "../src/user/sys/fipc_sys.h"
#include "../src/user/sys/fipc_idlv0_codegen.h"

#define FIPC_FWAY_TABLE(M)            \
    M(FIPC_FWAY_EVT, evt)             \
    M(FIPC_FWAY_SURF_ID, surface_id)  \
    M(FIPC_FWAY_CLIENT_PID, client)   \
    M(FIPC_FWAY_T_START, t_start)     \
    M(FIPC_FWAY_T_END, t_end)         \
    M(FIPC_FWAY_DUR_MS, duration)

FIPC_IDL_DEF_STRUCT(fway_view, FIPC_FWAY_TABLE)
FIPC_IDL_DEF_DECODE_BOUNDED(fway_view,
                            FIPC_FWAY_TABLE,
                            FIPC_FWAY_BEGIN,
                            FIPC_FWAY_END)

static int recv_once(struct fut_fipc_channel *channel,
                     uint8_t *buffer,
                     size_t capacity) {
    for (int i = 0; i < 256; ++i) {
        ssize_t rc = fut_fipc_recv(channel, buffer, capacity);
        if (rc > 0) {
            return (int)rc;
        }
        if (rc < 0 && rc != FIPC_EAGAIN) {
            return -1;
        }
        struct timespec ts = { .tv_sec = 0, .tv_nsec = 1 * 1000 * 1000 };
        nanosleep(&ts, NULL);
    }
    return -1;
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

int main(void) {
    fut_fipc_init();

    struct fut_fipc_channel *sys_channel = ensure_system_channel();
    if (!sys_channel) {
        fprintf(stderr, "[FWAY] failed to prepare system channel\n");
        return 1;
    }

    const uint64_t surface_id = 42;
    const uint64_t client_pid = 1001;
    const uint64_t t0 = 10;
    const uint64_t t1 = 25;

    if (!fipc_sys_fway_surface_create(surface_id, client_pid, t0, t0 + 1)) {
        fprintf(stderr, "[FWAY] surface_create publish failed\n");
        return 1;
    }

    if (!fipc_sys_fway_surface_commit(surface_id, client_pid, t0 + 5, t1)) {
        fprintf(stderr, "[FWAY] surface_commit publish failed\n");
        return 1;
    }

    uint8_t buffer[256];

    /* First frame should be the create event; skip after sanity. */
    int bytes = recv_once(sys_channel, buffer, sizeof(buffer));
    if (bytes <= 0) {
        fprintf(stderr, "[FWAY] missing create frame\n");
        return 1;
    }

    bytes = recv_once(sys_channel, buffer, sizeof(buffer));
    if (bytes <= 0) {
        fprintf(stderr, "[FWAY] missing commit frame\n");
        return 1;
    }

    struct fut_fipc_msg *msg = (struct fut_fipc_msg *)buffer;
    if (msg->type != FIPC_SYS_MSG_FWAY_METRICS) {
        fprintf(stderr, "[FWAY] unexpected message type 0x%x\n", msg->type);
        return 1;
    }

    fway_view view;
    if (fway_view_decode(msg->payload, msg->length, &view) != 0) {
        fprintf(stderr, "[FWAY] decode failed\n");
        return 1;
    }

    if (view.evt != FIPC_FWAY_SURFACE_COMMIT ||
        view.surface_id != surface_id ||
        view.client != client_pid ||
        view.duration == 0) {
        fprintf(stderr, "[FWAY] decoded values not plausible\n");
        return 1;
    }

    printf("[FWAY] compositor metrics decoded — PASS\n");
    return 0;
}
