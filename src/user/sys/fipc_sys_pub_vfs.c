/* fipc_sys_pub_vfs.c - Publish VFS/FS telemetry over the system channel
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 */

#include "fipc_sys.h"

#include <stdbool.h>
#include <stdint.h>

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

static uint64_t fipc_sys_path_hash(const char *path) {
    const uint64_t offset_basis = 1469598103934665603ull;
    const uint64_t prime = 1099511628211ull;

    uint64_t hash = offset_basis;
    if (!path) {
        return hash;
    }
    while (*path) {
        hash ^= (uint8_t)*path++;
        hash *= prime;
    }
    return hash;
}

static bool fipc_sys_vfs_emit(uint64_t event,
                              const char *path,
                              uint64_t bytes,
                              uint64_t result,
                              uint64_t t_start,
                              uint64_t t_end) {
    struct fut_fipc_channel *channel = fipc_sys_get_channel();
    if (!channel) {
        return false;
    }

    uint8_t buffer[192];
    uint8_t *cursor = buffer;
    const uint8_t *const end = buffer + sizeof(buffer);

    if (cursor >= end) {
        return false;
    }
    *cursor++ = FIPC_VFS_BEGIN;

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

    FIPC_SYS_WRITE(FIPC_VFS_EVT, event);
    FIPC_SYS_WRITE(FIPC_VFS_PATH_HASH, fipc_sys_path_hash(path));
    FIPC_SYS_WRITE(FIPC_VFS_BYTES, bytes);
    FIPC_SYS_WRITE(FIPC_VFS_RESULT, result);
    FIPC_SYS_WRITE(FIPC_VFS_T_START, t_start);
    FIPC_SYS_WRITE(FIPC_VFS_T_END, t_end);

    uint64_t duration = (t_end > t_start) ? (t_end - t_start) : 0;
    FIPC_SYS_WRITE(FIPC_VFS_DUR_MS, duration);

#undef FIPC_SYS_WRITE

    if (cursor >= end) {
        return false;
    }
    *cursor++ = FIPC_VFS_END;

    size_t payload_len = (size_t)(cursor - buffer);
    return fut_fipc_channel_inject(channel,
                                   FIPC_SYS_MSG_VFS_METRICS,
                                   buffer,
                                   payload_len,
                                   0,
                                   0,
                                   0) == 0;
}

bool fipc_sys_vfs_open(const char *path,
                       uint64_t result,
                       uint64_t t_start,
                       uint64_t t_end) {
    return fipc_sys_vfs_emit(FIPC_VFS_OPEN, path, 0, result, t_start, t_end);
}

bool fipc_sys_vfs_read(const char *path,
                       uint64_t bytes,
                       uint64_t result,
                       uint64_t t_start,
                       uint64_t t_end) {
    return fipc_sys_vfs_emit(FIPC_VFS_READ, path, bytes, result, t_start, t_end);
}

bool fipc_sys_vfs_write(const char *path,
                        uint64_t bytes,
                        uint64_t result,
                        uint64_t t_start,
                        uint64_t t_end) {
    return fipc_sys_vfs_emit(FIPC_VFS_WRITE, path, bytes, result, t_start, t_end);
}

bool fipc_sys_vfs_close(const char *path,
                        uint64_t result,
                        uint64_t t_start,
                        uint64_t t_end) {
    return fipc_sys_vfs_emit(FIPC_VFS_CLOSE, path, 0, result, t_start, t_end);
}
