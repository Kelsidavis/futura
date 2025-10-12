/* fipc_sys_pub_futuraway.c - Publish FuturaWay compositor telemetry
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 */

#include "fipc_sys.h"

#include <kernel/fut_fipc.h>
#include <kernel/fut_fipc_sys.h>

static struct fut_fipc_channel *fipc_sys_get_channel(void) {
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

static bool fipc_sys_fway_emit(uint64_t event,
                               uint64_t surface_id,
                               uint64_t client_pid,
                               uint64_t t_start,
                               uint64_t t_end) {
    struct fut_fipc_channel *channel = fipc_sys_get_channel();
    if (!channel) {
        return false;
    }

    uint8_t buffer[160];
    uint8_t *cursor = buffer;
    const uint8_t *const end = buffer + sizeof(buffer);

    if (cursor >= end) {
        return false;
    }
    *cursor++ = FIPC_FWAY_BEGIN;

#define FIPC_SYS_WRITE(tag, value)                                      \
    do {                                                                \
        if ((size_t)(end - cursor) < 11) {                              \
            return false;                                               \
        }                                                               \
        *cursor++ = (uint8_t)(tag);                                     \
        cursor = fipc_sys_varint_u64(cursor, (uint64_t)(value));        \
        if (cursor > end) {                                             \
            return false;                                               \
        }                                                               \
    } while (0)

    FIPC_SYS_WRITE(FIPC_FWAY_EVT, event);
    FIPC_SYS_WRITE(FIPC_FWAY_SURF_ID, surface_id);
    FIPC_SYS_WRITE(FIPC_FWAY_CLIENT_PID, client_pid);
    FIPC_SYS_WRITE(FIPC_FWAY_T_START, t_start);
    FIPC_SYS_WRITE(FIPC_FWAY_T_END, t_end);

    uint64_t duration = (t_end > t_start) ? (t_end - t_start) : 0;
    FIPC_SYS_WRITE(FIPC_FWAY_DUR_MS, duration);

#undef FIPC_SYS_WRITE

    if (cursor >= end) {
        return false;
    }
    *cursor++ = FIPC_FWAY_END;

    size_t payload_len = (size_t)(cursor - buffer);
    return fut_fipc_channel_inject(channel,
                                   FIPC_SYS_MSG_FWAY_METRICS,
                                   buffer,
                                   payload_len,
                                   0,
                                   0,
                                   0) == 0;
}

bool fipc_sys_fway_surface_create(uint64_t surface_id,
                                  uint64_t client_pid,
                                  uint64_t t_start,
                                  uint64_t t_end) {
    return fipc_sys_fway_emit(FIPC_FWAY_SURFACE_CREATE,
                              surface_id,
                              client_pid,
                              t_start,
                              t_end);
}

bool fipc_sys_fway_surface_commit(uint64_t surface_id,
                                  uint64_t client_pid,
                                  uint64_t t_start,
                                  uint64_t t_end) {
    return fipc_sys_fway_emit(FIPC_FWAY_SURFACE_COMMIT,
                              surface_id,
                              client_pid,
                              t_start,
                              t_end);
}

bool fipc_sys_fway_input_event(uint64_t surface_id,
                               uint64_t client_pid,
                               uint64_t t_start,
                               uint64_t t_end) {
    return fipc_sys_fway_emit(FIPC_FWAY_INPUT_EVENT,
                              surface_id,
                              client_pid,
                              t_start,
                              t_end);
}
