// SPDX-License-Identifier: MPL-2.0
// tests/fipc_remote_metrics.c - verify netd counters and publish API

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

static int drain_metrics(struct netd *nd,
                         struct fut_fipc_channel *sink,
                         uint8_t *buffer,
                         size_t cap,
                         struct fut_fipc_msg **out_msg) {
    if (out_msg) {
        *out_msg = NULL;
    }

    for (int i = 0; i < 256; i++) {
        (void)netd_poll_once(nd, 0);
        ssize_t r = fut_fipc_recv(sink, buffer, cap);
        if (r > 0) {
            if (out_msg) {
                *out_msg = (struct fut_fipc_msg *)buffer;
            }
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

static void cleanup_channels(struct fut_fipc_channel **list, size_t count) {
    for (size_t i = 0; i < count; i++) {
        if (list[i]) {
            fut_fipc_channel_destroy(list[i]);
        }
    }
}

int main(int argc, char **argv) {
    const char *host = "127.0.0.1";
    uint16_t net_port = 28600;
    uint16_t reg_port = 28599;

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
        fprintf(stderr, "[FIPC-MET] netd bootstrap failed\n");
        return 1;
    }

    struct registryd *rd = registryd_start(reg_port);
    if (!rd) {
        fprintf(stderr, "[FIPC-MET] registry start failed\n");
        netd_shutdown(nd);
        return 1;
    }

    struct registry_poll_ctx ctx = { .rd = rd, .running = true };
    pthread_t poll_thread;
    pthread_create(&poll_thread, NULL, registry_poll_thread, &ctx);

    struct fut_fipc_channel *channels[3] = {0};
    for (size_t i = 0; i < 3; i++) {
        if (fut_fipc_channel_create(NULL, NULL, 8192, FIPC_CHANNEL_NONBLOCKING, &channels[i]) != 0) {
            fprintf(stderr, "[FIPC-MET] channel creation failed\n");
            cleanup_channels(channels, 3);
            ctx.running = false;
            pthread_join(poll_thread, NULL);
            registryd_stop(rd);
            netd_shutdown(nd);
            return 1;
        }
    }

    struct fut_fipc_channel *A = channels[0];
    struct fut_fipc_channel *B = channels[1];
    struct fut_fipc_channel *S = channels[2];

    const char *service_name = "svc.metrics";

    struct fut_fipc_remote_endpoint ep = { .node_id = net_port, .channel_id = 0, .mtu = 8192, .flags = 0 };
    (void)fut_fipc_register_remote(A->id, &ep);
    (void)netd_bind_service(nd, A->id, service_name, host, reg_port);

    int rc = fut_fipc_send(A, 0xA100u, "probe", 5);
    if (rc == 0) {
        fprintf(stderr, "[FIPC-MET] expected EAGAIN before registry entry\n");
        cleanup_channels(channels, 3);
        ctx.running = false;
        pthread_join(poll_thread, NULL);
        registryd_stop(rd);
        netd_shutdown(nd);
        return 1;
    }

    if (registry_client_register(host, reg_port, service_name, B->id) != 0) {
        fprintf(stderr, "[FIPC-MET] registry register failed\n");
        cleanup_channels(channels, 3);
        ctx.running = false;
        pthread_join(poll_thread, NULL);
        registryd_stop(rd);
        netd_shutdown(nd);
        return 1;
    }

    if (fut_fipc_send(A, 0xA101u, "hello", 5) != 0) {
        fprintf(stderr, "[FIPC-MET] send after registration failed\n");
        cleanup_channels(channels, 3);
        ctx.running = false;
        pthread_join(poll_thread, NULL);
        registryd_stop(rd);
        netd_shutdown(nd);
        return 1;
    }

    struct netd_metrics metrics;
    if (!netd_metrics_snapshot(nd, &metrics)) {
        fprintf(stderr, "[FIPC-MET] metrics snapshot failed\n");
        cleanup_channels(channels, 3);
        ctx.running = false;
        pthread_join(poll_thread, NULL);
        registryd_stop(rd);
        netd_shutdown(nd);
        return 1;
    }

    if (!(metrics.lookup_attempts >= 1 && metrics.lookup_miss >= 1 && metrics.lookup_hits >= 1)) {
        fprintf(stderr, "[FIPC-MET] counters not advanced: attempts=%llu hits=%llu miss=%llu eagain=%llu\n",
                (unsigned long long)metrics.lookup_attempts,
                (unsigned long long)metrics.lookup_hits,
                (unsigned long long)metrics.lookup_miss,
                (unsigned long long)metrics.send_eagain);
        cleanup_channels(channels, 3);
        ctx.running = false;
        pthread_join(poll_thread, NULL);
        registryd_stop(rd);
        netd_shutdown(nd);
        return 1;
    }

    if (!netd_metrics_publish(nd, S)) {
        fprintf(stderr, "[FIPC-MET] metrics publish failed\n");
        cleanup_channels(channels, 3);
        ctx.running = false;
        pthread_join(poll_thread, NULL);
        registryd_stop(rd);
        netd_shutdown(nd);
        return 1;
    }

    uint8_t buffer[512];
    struct fut_fipc_msg *msg = NULL;
    if (drain_metrics(nd, S, buffer, sizeof(buffer), &msg) != 0 || !msg) {
        fprintf(stderr, "[FIPC-MET] metrics message not received\n");
        cleanup_channels(channels, 3);
        ctx.running = false;
        pthread_join(poll_thread, NULL);
        registryd_stop(rd);
        netd_shutdown(nd);
        return 1;
    }

    if (msg->length == 0 || !strstr((const char *)msg->payload, "lookup_attempts=") ||
        !strstr((const char *)msg->payload, "lookup_hits=")) {
        fprintf(stderr, "[FIPC-MET] metrics payload malformed: %.*s\n",
                (int)msg->length, msg->payload);
        cleanup_channels(channels, 3);
        ctx.running = false;
        pthread_join(poll_thread, NULL);
        registryd_stop(rd);
        netd_shutdown(nd);
        return 1;
    }

    printf("[FIPC-MET] counters advanced and publish delivered — PASS\n");

    cleanup_channels(channels, 3);
    ctx.running = false;
    pthread_join(poll_thread, NULL);
    registryd_stop(rd);
    netd_shutdown(nd);
    return 0;
}
