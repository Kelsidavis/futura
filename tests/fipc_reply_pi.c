// SPDX-License-Identifier: MPL-2.0
// fipc_reply_pi.c - Reply-chain priority inheritance smoke test

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <kernel/fut_fipc.h>
#include <kernel/fut_thread.h>

static void setup_thread(fut_thread_t *thread, uint64_t tid, int priority) {
    if (!thread) return;
    *thread = (fut_thread_t){0};
    thread->tid = tid;
    thread->priority = priority;
    thread->base_priority = priority;
    thread->pi_saved_priority = priority;
    thread->pi_boosted = false;
    thread->deadline_tick = 0;
}

int main(void) {
    fut_fipc_init();

    struct fut_fipc_channel *ch = NULL;
    if (fut_fipc_channel_create(NULL, NULL, 2048, FIPC_CHANNEL_NONBLOCKING, &ch) != 0 || !ch) {
        fprintf(stderr, "[PI] channel create failed\n");
        return 1;
    }

    fut_thread_t server;
    fut_thread_t client;
    setup_thread(&server, 2u, 10);
    setup_thread(&client, 1u, 80);

    fut_thread_set_current(&server);
    ch->owner_tid = server.tid;
    ch->owner_original_priority = server.priority;
    ch->owner_pi_active = false;

    fut_thread_set_current(&client);
    if (fut_fipc_send(ch, 0xAB01u, "REQ", 3) != 0) {
        fprintf(stderr, "[PI] client send failed\n");
        return 1;
    }

    if (!ch->owner_pi_active || server.priority != client.priority) {
        fprintf(stderr, "[PI] priority inheritance not applied\n");
        return 1;
    }

    fut_thread_set_current(&server);
    if (fut_fipc_send(ch, 0xAB02u, "REP", 3) != 0) {
        fprintf(stderr, "[PI] server reply failed\n");
        return 1;
    }

    if (server.priority != server.base_priority || ch->owner_pi_active) {
        fprintf(stderr, "[PI] priority not restored\n");
        return 1;
    }
    if (ch->pi_applied == 0 || ch->pi_restored == 0) {
        fprintf(stderr, "[PI] PI metrics not updated\n");
        return 1;
    }

    printf("[PI] reply-chain PI — PASS\n");
    return 0;
}
