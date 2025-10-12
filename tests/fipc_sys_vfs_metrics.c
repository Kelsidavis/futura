// SPDX-License-Identifier: MPL-2.0
// Validate VFS telemetry publishing and decoding.

#define _POSIX_C_SOURCE 200809L

#include <stdint.h>
#include <stdio.h>
#include <time.h>

#include <kernel/fut_fipc.h>
#include <kernel/fut_fipc_sys.h>

#include "../src/user/sys/fipc_sys.h"
#include "../src/user/sys/fipc_idlv0_codegen.h"

#define FIPC_VFS_TABLE(M)            \
    M(FIPC_VFS_EVT, evt)             \
    M(FIPC_VFS_PATH_HASH, path_hash) \
    M(FIPC_VFS_BYTES, bytes)         \
    M(FIPC_VFS_RESULT, result)       \
    M(FIPC_VFS_T_START, t_start)     \
    M(FIPC_VFS_T_END, t_end)         \
    M(FIPC_VFS_DUR_MS, duration)

FIPC_IDL_DEF_STRUCT(vfs_view, FIPC_VFS_TABLE)
FIPC_IDL_DEF_DECODE_BOUNDED(vfs_view,
                            FIPC_VFS_TABLE,
                            FIPC_VFS_BEGIN,
                            FIPC_VFS_END)

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
        fprintf(stderr, "[VFS] failed to prepare system channel\n");
        return 1;
    }

    const char *path = "/tmp/test.dat";
    const uint64_t t0 = 100;
    const uint64_t t1 = 140;

    (void)fipc_sys_vfs_open(path, 0, t0, t0 + 1);
    (void)fipc_sys_vfs_write(path, 4096, 0, t0 + 2, t0 + 10);
    (void)fipc_sys_vfs_read(path, 4096, 0, t0 + 12, t1);
    (void)fipc_sys_vfs_close(path, 0, t1, t1 + 1);

    uint8_t buffer[256];

    int bytes = recv_once(sys_channel, buffer, sizeof(buffer));
    if (bytes <= 0) {
        fprintf(stderr, "[VFS] missing open frame\n");
        return 1;
    }

    bytes = recv_once(sys_channel, buffer, sizeof(buffer));
    if (bytes <= 0) {
        fprintf(stderr, "[VFS] missing write frame\n");
        return 1;
    }

    struct fut_fipc_msg *msg = (struct fut_fipc_msg *)buffer;
    if (msg->type != FIPC_SYS_MSG_VFS_METRICS) {
        fprintf(stderr, "[VFS] unexpected message type 0x%x\n", msg->type);
        return 1;
    }

    vfs_view view;
    if (vfs_view_decode(msg->payload, msg->length, &view) != 0) {
        fprintf(stderr, "[VFS] decode failed\n");
        return 1;
    }

    if (view.evt != FIPC_VFS_WRITE ||
        view.bytes != 4096 ||
        view.duration == 0) {
        fprintf(stderr, "[VFS] decoded values not plausible\n");
        return 1;
    }

    printf("[VFS] vfs metrics decoded — PASS\n");
    return 0;
}
