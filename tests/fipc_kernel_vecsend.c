// SPDX-License-Identifier: MPL-2.0
// fipc_kernel_vecsend.c - Validate vector send batching and counters

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <string.h>
#include <kernel/fut_fipc.h>

static int drain_channel(struct fut_fipc_channel *ch, size_t max_msgs) {
    size_t removed = fut_fipc_dequeue_bounded(ch, max_msgs);
    return (removed > 0) ? 0 : 0;
}

int main(void) {
    fut_fipc_init();

    struct fut_fipc_channel *ch = NULL;
    if (fut_fipc_channel_create(NULL, NULL, 4096, FIPC_CHANNEL_NONBLOCKING, &ch) != 0 || !ch) {
        fprintf(stderr, "[VEC] channel create failed\n");
        return 1;
    }

    struct fut_fipc_cap cap = {
        .rights = FIPC_CAP_R_SEND | FIPC_CAP_R_RECV,
        .max_msgs = 0,
        .max_bytes = 0,
        .expiry_tick = 0
    };
    (void)fut_fipc_cap_bind(ch, &cap);

    const char *seg1 = "A";
    const char *seg2 = "BC";
    const char *seg3 = "DEF";
    struct fipc_iovec iov[3] = {
        { seg1, strlen(seg1) },
        { seg2, strlen(seg2) },
        { seg3, strlen(seg3) }
    };

    uint64_t total = iov[0].len + iov[1].len + iov[2].len;

    if (fut_fipc_sendv(ch, 0xE001u, iov, 3) != 0) {
        fprintf(stderr, "[VEC] sendv failed\n");
        return 1;
    }
    if (ch->msgs_sent != 1 || ch->bytes_sent != total) {
        fprintf(stderr, "[VEC] counters mismatch after sendv (msgs=%llu bytes=%llu)\n",
                (unsigned long long)ch->msgs_sent,
                (unsigned long long)ch->bytes_sent);
        return 1;
    }

    drain_channel(ch, 8);

    uint64_t baseline_msgs = ch->msgs_sent;
    uint64_t baseline_bytes = ch->bytes_sent;

    for (size_t i = 0; i < 3; ++i) {
        if (fut_fipc_send(ch, 0xE002u + (uint32_t)i, iov[i].base, iov[i].len) != 0) {
            fprintf(stderr, "[VEC] scalar send %zu failed\n", i);
            return 1;
        }
    }

    if (ch->msgs_sent != baseline_msgs + 3 || ch->bytes_sent != baseline_bytes + total) {
        fprintf(stderr, "[VEC] counters mismatch after scalar sends\n");
        return 1;
    }

    drain_channel(ch, 8);

    printf("[VEC] vector send batching — PASS\n");
    return 0;
}
