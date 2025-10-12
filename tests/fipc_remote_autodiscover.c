// SPDX-License-Identifier: MPL-2.0
// tests/fipc_remote_autodiscover.c - lazy registry lookup on first send

#define _POSIX_C_SOURCE 200809L

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <kernel/fut_fipc.h>

#include "../src/user/netd/netd_core.h"
#include "../src/user/svc_registryd/registry_client.h"
#include "../src/user/svc_registryd/registry_server.h"

struct registry_poll_ctx {
    struct registryd *rd;
    bool running;
};

static void *registry_poll_thread(void *arg) {
    struct registry_poll_ctx *ctx = (struct registry_poll_ctx *)arg;
    while (ctx->running) {
        (void)registryd_poll_once(ctx->rd, 10);
        struct timespec ts = {0, 1000000};
        nanosleep(&ts, NULL);
    }
    return NULL;
}

static int drain_channel(struct netd *nd,
                         struct registryd *rd,
                         struct fut_fipc_channel *channel,
                         uint8_t *buffer,
                         size_t buffer_cap,
                         struct fut_fipc_msg **msg_out,
                         int max_polls) {
    if (msg_out) {
        *msg_out = NULL;
    }

    for (int i = 0; i < max_polls; i++) {
        (void)netd_poll_once(nd, 0);
        (void)registryd_poll_once(rd, 0);
        ssize_t got = fut_fipc_recv(channel, buffer, buffer_cap);
        if (got > 0) {
            if (msg_out) {
                *msg_out = (struct fut_fipc_msg *)buffer;
            }
            return 0;
        }
        if (got < 0 && got != FIPC_EAGAIN) {
            return -1;
        }
        struct timespec ts = {0, 1000000};
        nanosleep(&ts, NULL);
    }

    return -1;
}

static void cleanup_channels(struct fut_fipc_channel **list, size_t count) {
    for (size_t i = 0; i < count; i++) {
        if (list[i]) {
            fut_fipc_channel_destroy(list[i]);
        }
    }
}

int main(int argc, char **argv) {
    const char *host = "127.0.0.1";
    uint16_t net_port = 27500;
    uint16_t reg_port = 27499;

    for (int i = 1; i < argc; i++) {
        if (strncmp(argv[i], "--net=", 6) == 0) {
            net_port = (uint16_t)atoi(argv[i] + 6);
        } else if (strncmp(argv[i], "--registry=", 11) == 0) {
            reg_port = (uint16_t)atoi(argv[i] + 11);
        }
    }

    fut_fipc_init();

    struct netd *nd = netd_bootstrap(host, net_port);
    if (!nd) {
        fprintf(stderr, "[FIPC-AUTO] netd bootstrap failed\n");
        return 1;
    }

    struct registryd *rd = registryd_start(reg_port);
    if (!rd) {
        fprintf(stderr, "[FIPC-AUTO] registry start failed\n");
        netd_shutdown(nd);
        return 1;
    }

    struct registry_poll_ctx poll_ctx = { .rd = rd, .running = true };
    pthread_t poll_thread;
    if (pthread_create(&poll_thread, NULL, registry_poll_thread, &poll_ctx) != 0) {
        fprintf(stderr, "[FIPC-AUTO] failed to spawn registry thread\n");
        registryd_stop(rd);
        netd_shutdown(nd);
        return 1;
    }

    struct fut_fipc_channel *channels[4] = {0};
    for (size_t i = 0; i < 4; i++) {
        if (fut_fipc_channel_create(NULL, NULL, 8192, FIPC_CHANNEL_NONBLOCKING, &channels[i]) != 0) {
            fprintf(stderr, "[FIPC-AUTO] channel creation failed\n");
            poll_ctx.running = false;
            pthread_join(poll_thread, NULL);
            cleanup_channels(channels, 4);
            registryd_stop(rd);
            netd_shutdown(nd);
            return 1;
        }
    }

    struct fut_fipc_channel *a = channels[0];
    struct fut_fipc_channel *b = channels[1];
    struct fut_fipc_channel *a2 = channels[2];
    struct fut_fipc_channel *c = channels[3];

    const char *svc_ok = "svc.auto1";
    const char *svc_late = "svc.auto2";

    if (registry_client_register(host, reg_port, svc_ok, b->id) != 0) {
        fprintf(stderr, "[FIPC-AUTO] registry register svc_ok failed\n");
        poll_ctx.running = false;
        pthread_join(poll_thread, NULL);
        cleanup_channels(channels, 4);
        registryd_stop(rd);
        netd_shutdown(nd);
        return 1;
    }

    struct fut_fipc_remote_endpoint ep = { .node_id = net_port, .channel_id = 0, .mtu = 8192, .flags = 0 };
    (void)fut_fipc_register_remote(a->id, &ep);
    (void)netd_bind_service(nd, a->id, svc_ok, host, reg_port);

    const char *payload_ok = "auto-discovery hello";
    if (fut_fipc_send(a, 0xA001u, payload_ok, strlen(payload_ok)) != 0) {
        fprintf(stderr, "[FIPC-AUTO] send to svc_ok failed\n");
        poll_ctx.running = false;
        pthread_join(poll_thread, NULL);
        cleanup_channels(channels, 4);
        registryd_stop(rd);
        netd_shutdown(nd);
        return 1;
    }

    uint8_t buffer[4096];
    struct fut_fipc_msg *msg = NULL;
    if (drain_channel(nd, rd, b, buffer, sizeof(buffer), &msg, 512) != 0 || !msg ||
        msg->length != strlen(payload_ok) || memcmp(msg->payload, payload_ok, msg->length) != 0) {
        fprintf(stderr, "[FIPC-AUTO] expected payload not received on B\n");
        poll_ctx.running = false;
        pthread_join(poll_thread, NULL);
        cleanup_channels(channels, 4);
        registryd_stop(rd);
        netd_shutdown(nd);
        return 1;
    }

    struct fut_fipc_remote_endpoint ep2 = { .node_id = net_port, .channel_id = 0, .mtu = 8192, .flags = 0 };
    (void)fut_fipc_register_remote(a2->id, &ep2);
    (void)netd_bind_service(nd, a2->id, svc_late, host, reg_port);

    const char *payload_late = "late-binding hi";
    if (fut_fipc_send(a2, 0xA002u, payload_late, strlen(payload_late)) == 0) {
        fprintf(stderr, "[FIPC-AUTO] expected EAGAIN before registry entry\n");
        poll_ctx.running = false;
        pthread_join(poll_thread, NULL);
        cleanup_channels(channels, 4);
        registryd_stop(rd);
        netd_shutdown(nd);
        return 1;
    }

    if (registry_client_register(host, reg_port, svc_late, c->id) != 0) {
        fprintf(stderr, "[FIPC-AUTO] registry register svc_late failed\n");
        poll_ctx.running = false;
        pthread_join(poll_thread, NULL);
        cleanup_channels(channels, 4);
        registryd_stop(rd);
        netd_shutdown(nd);
        return 1;
    }

    if (fut_fipc_send(a2, 0xA003u, payload_late, strlen(payload_late)) != 0) {
        fprintf(stderr, "[FIPC-AUTO] send retry to svc_late failed\n");
        poll_ctx.running = false;
        pthread_join(poll_thread, NULL);
        cleanup_channels(channels, 4);
        registryd_stop(rd);
        netd_shutdown(nd);
        return 1;
    }

    msg = NULL;
    if (drain_channel(nd, rd, c, buffer, sizeof(buffer), &msg, 512) != 0 || !msg ||
        msg->length != strlen(payload_late) || memcmp(msg->payload, payload_late, msg->length) != 0) {
        fprintf(stderr, "[FIPC-AUTO] expected payload not received on C\n");
        poll_ctx.running = false;
        pthread_join(poll_thread, NULL);
        cleanup_channels(channels, 4);
        registryd_stop(rd);
        netd_shutdown(nd);
        return 1;
    }

    printf("[FIPC-AUTO] first-send lookup + retry path — PASS\n");

    poll_ctx.running = false;
    pthread_join(poll_thread, NULL);
    cleanup_channels(channels, 4);
    registryd_stop(rd);
    netd_shutdown(nd);
    return 0;
}
