/* syswatch.c - simple monitor for system metrics channel
 *
 * SPDX-License-Identifier: MPL-2.0
 */

#define _POSIX_C_SOURCE 200809L

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <kernel/fut_fipc.h>
#include <kernel/fut_fipc_sys.h>

#include "../src/user/netd/netd_core.h"
#include "../src/user/sys/fipc_sys.h"

static int recv_once(struct fut_fipc_channel *channel,
                     uint8_t *buffer,
                     size_t capacity,
                     int polls) {
    for (int i = 0; i < polls; ++i) {
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
    return 0;
}

static const char *msg_type_name(uint32_t type) {
    switch (type) {
        case FIPC_SYS_MSG_SYSTEM_METRICS: return "SYSM";
        case FIPC_SYS_MSG_KERNEL_METRICS: return "KMET";
        case FIPC_SYS_MSG_FWAY_METRICS:   return "FWAY";
        case FIPC_SYS_MSG_VFS_METRICS:    return "VFSM";
        default:                          return "????";
    }
}

int main(int argc, char **argv) {
    bool once = false;
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--once") == 0) {
            once = true;
        }
    }

    fut_fipc_init();

    struct fut_fipc_channel *sys_channel = fut_fipc_channel_lookup(FIPC_SYS_CHANNEL_ID);
    if (!sys_channel) {
        if (fut_fipc_channel_create(NULL,
                                    NULL,
                                    4096,
                                    FIPC_CHANNEL_NONBLOCKING,
                                    &sys_channel) != 0 || !sys_channel) {
            fprintf(stderr, "[syswatch] failed to create system channel\n");
            return 1;
        }
        sys_channel->id = FIPC_SYS_CHANNEL_ID;
        sys_channel->type = FIPC_CHANNEL_SYSTEM;
    }

    uint8_t buffer[1024];

    for (;;) {
        int r = recv_once(sys_channel, buffer, sizeof(buffer), 256);
        if (r < 0) {
            fprintf(stderr, "[syswatch] receive error\n");
            return 1;
        }
        if (r == 0) {
            if (once) {
                break;
            }
            continue;
        }

        struct fut_fipc_msg *msg = (struct fut_fipc_msg *)buffer;
        printf("[%s] payload=%u bytes\n", msg_type_name(msg->type), (unsigned)msg->length);

        if (msg->type == FIPC_SYS_MSG_SYSTEM_METRICS) {
            struct netd_metrics metrics = {0};
            if (fipc_sys_decode_metrics(msg->payload, msg->length, &metrics)) {
                printf("  lookup_attempts=%llu hits=%llu miss=%llu eagain=%llu tx=%llu auth_fail=%llu replay=%llu\n",
                       (unsigned long long)metrics.lookup_attempts,
                       (unsigned long long)metrics.lookup_hits,
                       (unsigned long long)metrics.lookup_miss,
                       (unsigned long long)metrics.send_eagain,
                       (unsigned long long)metrics.tx_frames,
                       (unsigned long long)metrics.auth_fail,
                       (unsigned long long)metrics.replay_drop);
            }
        }

        if (once) {
            break;
        }
    }

    return 0;
}
