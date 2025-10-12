// SPDX-License-Identifier: MPL-2.0
// tests/fipc_remote_header_v1.c - exercise header v1 sequence path

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
#include "../src/user/svc_registryd/registry_server.h"
#include "../src/user/svc_registryd/registry_client.h"

struct registry_poll_ctx {
    struct registryd *rd;
    bool running;
};

static void *registry_poll_thread(void *arg) {
    struct registry_poll_ctx *ctx = (struct registry_poll_ctx *)arg;
    while (ctx->running) {
        (void)registryd_poll_once(ctx->rd, 5);
        struct timespec ts = {0, 1000000};
        nanosleep(&ts, NULL);
    }
    return NULL;
}

static void cleanup_channels(struct fut_fipc_channel **list, size_t count) {
    for (size_t i = 0; i < count; i++) {
        if (list[i]) {
            fut_fipc_channel_destroy(list[i]);
        }
    }
}

static int recv_poll(struct netd *nd, struct fut_fipc_channel *ch, int polls) {
    uint8_t buffer[512];
    for (int i = 0; i < polls; i++) {
        (void)netd_poll_once(nd, 0);
        ssize_t r = fut_fipc_recv(ch, buffer, sizeof(buffer));
        if (r > 0) {
            return 0;
        }
        if (r < 0 && r != FIPC_EAGAIN) {
            return -1;
        }
        struct timespec ts = {0, 1000000};
        nanosleep(&ts, NULL);
    }
    return -1;
}

int main(int argc, char **argv) {
    const char *host = "127.0.0.1";
    uint16_t net_port = 29000;
    uint16_t reg_port = 28999;

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
        fprintf(stderr, "[HDRV1] netd bootstrap failed\n");
        return 1;
    }

    struct registryd *rd = registryd_start(reg_port);
    if (!rd) {
        fprintf(stderr, "[HDRV1] registry start failed\n");
        netd_shutdown(nd);
        return 1;
    }

    struct registry_poll_ctx poll_ctx = { .rd = rd, .running = true };
    pthread_t poll_thread;
    pthread_create(&poll_thread, NULL, registry_poll_thread, &poll_ctx);

    struct fut_fipc_channel *channels[2] = {0};
    if (fut_fipc_channel_create(NULL, NULL, 8192, FIPC_CHANNEL_NONBLOCKING, &channels[0]) != 0 ||
        fut_fipc_channel_create(NULL, NULL, 8192, FIPC_CHANNEL_NONBLOCKING, &channels[1]) != 0) {
        fprintf(stderr, "[HDRV1] channel creation failed\n");
        poll_ctx.running = false;
        pthread_join(poll_thread, NULL);
        registryd_stop(rd);
        netd_shutdown(nd);
        return 1;
    }

    struct fut_fipc_channel *A = channels[0];
    struct fut_fipc_channel *B = channels[1];

    const char *svc_name = "svc.hdrv1";
    if (registry_client_register(host, reg_port, svc_name, B->id) != 0) {
        fprintf(stderr, "[HDRV1] registry register failed\n");
        cleanup_channels(channels, 2);
        poll_ctx.running = false;
        pthread_join(poll_thread, NULL);
        registryd_stop(rd);
        netd_shutdown(nd);
        return 1;
    }

    struct fut_fipc_remote_endpoint ep = {
        .node_id = net_port,
        .channel_id = 0,
        .mtu = 8192,
        .flags = 0
    };
    (void)fut_fipc_register_remote(A->id, &ep);
    if (!netd_bind_service(nd, A->id, svc_name, host, reg_port)) {
        fprintf(stderr, "[HDRV1] netd_bind_service failed\n");
        cleanup_channels(channels, 2);
        poll_ctx.running = false;
        pthread_join(poll_thread, NULL);
        registryd_stop(rd);
        netd_shutdown(nd);
        return 1;
    }

    int rc_send = fut_fipc_send(A, 0xB001u, "one", 3);
    if (rc_send != 0) {
        fprintf(stderr, "[HDRV1] send 1 failed (rc=%d)\n", rc_send);
        cleanup_channels(channels, 2);
        poll_ctx.running = false;
        pthread_join(poll_thread, NULL);
        registryd_stop(rd);
        netd_shutdown(nd);
        return 1;
    }
    if (recv_poll(nd, B, 256) != 0) {
        fprintf(stderr, "[HDRV1] recv 1 failed\n");
        cleanup_channels(channels, 2);
        poll_ctx.running = false;
        pthread_join(poll_thread, NULL);
        registryd_stop(rd);
        netd_shutdown(nd);
        return 1;
    }

    rc_send = fut_fipc_send(A, 0xB002u, "two", 3);
    if (rc_send != 0) {
        fprintf(stderr, "[HDRV1] send 2 failed (rc=%d)\n", rc_send);
        cleanup_channels(channels, 2);
        poll_ctx.running = false;
        pthread_join(poll_thread, NULL);
        registryd_stop(rd);
        netd_shutdown(nd);
        return 1;
    }
    if (recv_poll(nd, B, 256) != 0) {
        fprintf(stderr, "[HDRV1] recv 2 failed\n");
        cleanup_channels(channels, 2);
        poll_ctx.running = false;
        pthread_join(poll_thread, NULL);
        registryd_stop(rd);
        netd_shutdown(nd);
        return 1;
    }

    struct netd_metrics m;
    if (!netd_metrics_snapshot(nd, &m)) {
        fprintf(stderr, "[HDRV1] metrics snapshot failed\n");
        cleanup_channels(channels, 2);
        poll_ctx.running = false;
        pthread_join(poll_thread, NULL);
        registryd_stop(rd);
        netd_shutdown(nd);
        return 1;
    }

    if (!(m.lookup_attempts >= 1 && m.lookup_hits >= 1 && m.tx_frames >= 2)) {
        fprintf(stderr, "[HDRV1] metrics not advanced (att=%llu hits=%llu tx=%llu)\n",
                (unsigned long long)m.lookup_attempts,
                (unsigned long long)m.lookup_hits,
                (unsigned long long)m.tx_frames);
        cleanup_channels(channels, 2);
        poll_ctx.running = false;
        pthread_join(poll_thread, NULL);
        registryd_stop(rd);
        netd_shutdown(nd);
        return 1;
    }

    cleanup_channels(channels, 2);
    poll_ctx.running = false;
    pthread_join(poll_thread, NULL);
    registryd_stop(rd);
    netd_shutdown(nd);
    printf("[HDRV1] header v1 seq path exercised (metrics checked) — PASS\n");
    return 0;
}
