// SPDX-License-Identifier: MPL-2.0
// fipc_remote_discovery.c - registry-backed remote channel discovery test

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

        ssize_t received = fut_fipc_recv(channel, buffer, buffer_cap);
        if (received > 0) {
            if (msg_out) {
                *msg_out = (struct fut_fipc_msg *)buffer;
            }
            return 0;
        }

        if (received == FIPC_EAGAIN) {
            continue;
        }

        break;
    }

    return -1;
}

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

static void usage(const char *prog) {
    fprintf(stderr,
            "Usage: %s [--net=<port>] [--registry=<port>] [--name=<service>]\n",
            prog);
}

int main(int argc, char **argv) {
    const char *host = "127.0.0.1";
    uint16_t net_port = 27000;
    uint16_t reg_port = 26999;
    const char *service_name = "svc.echo";

    for (int i = 1; i < argc; i++) {
        if (strncmp(argv[i], "--net=", 6) == 0) {
            net_port = (uint16_t)atoi(argv[i] + 6);
        } else if (strncmp(argv[i], "--registry=", 11) == 0) {
            reg_port = (uint16_t)atoi(argv[i] + 11);
        } else if (strncmp(argv[i], "--name=", 7) == 0) {
            service_name = argv[i] + 7;
        } else if (strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        }
    }

    fut_fipc_init();

    struct netd *nd = netd_bootstrap(host, net_port);
    if (!nd) {
        fprintf(stderr, "[FIPC-DISCOVERY] netd bootstrap failed\n");
        return 1;
    }

    struct registryd *rd = registryd_start(reg_port);
    if (!rd) {
        fprintf(stderr, "[FIPC-DISCOVERY] registry bootstrap failed\n");
        netd_shutdown(nd);
        return 1;
    }

    struct registry_poll_ctx poll_ctx = {
        .rd = rd,
        .running = true
    };
    pthread_t poll_thread;
    if (pthread_create(&poll_thread, NULL, registry_poll_thread, &poll_ctx) != 0) {
        fprintf(stderr, "[FIPC-DISCOVERY] failed to start registry poll thread\n");
        registryd_stop(rd);
        netd_shutdown(nd);
        return 1;
    }

    struct fut_fipc_channel *channel_a = NULL;
    struct fut_fipc_channel *channel_b = NULL;

    if (fut_fipc_channel_create(NULL, NULL, 8192, FIPC_CHANNEL_NONBLOCKING, &channel_a) != 0 ||
        fut_fipc_channel_create(NULL, NULL, 8192, FIPC_CHANNEL_NONBLOCKING, &channel_b) != 0) {
        fprintf(stderr, "[FIPC-DISCOVERY] channel creation failed\n");
        if (channel_a) {
            fut_fipc_channel_destroy(channel_a);
        }
        if (channel_b) {
            fut_fipc_channel_destroy(channel_b);
        }
        registryd_stop(rd);
        netd_shutdown(nd);
        return 1;
    }

    if (registry_client_register(host, reg_port, service_name, channel_b->id) != 0) {
        fprintf(stderr, "[FIPC-DISCOVERY] registry registration failed\n");
        poll_ctx.running = false;
        pthread_join(poll_thread, NULL);
        fut_fipc_channel_destroy(channel_a);
        fut_fipc_channel_destroy(channel_b);
        registryd_stop(rd);
        netd_shutdown(nd);
        return 1;
    }

    struct fut_fipc_remote_endpoint remote_ab = {
        .node_id = net_port,
        .channel_id = 0,
        .mtu = 8192,
        .flags = 0
    };

    if (fut_fipc_register_remote(channel_a->id, &remote_ab) != 0) {
        fprintf(stderr, "[FIPC-DISCOVERY] remote registration failed\n");
        fut_fipc_channel_destroy(channel_a);
        fut_fipc_channel_destroy(channel_b);
        registryd_stop(rd);
        netd_shutdown(nd);
        return 1;
    }

    uint64_t discovered_id = 0;
    if (registry_client_lookup(host, reg_port, service_name, &discovered_id) != 0 || discovered_id == 0) {
        fprintf(stderr, "[FIPC-DISCOVERY] lookup failed for '%s'\n", service_name);
        poll_ctx.running = false;
        pthread_join(poll_thread, NULL);
        fut_fipc_channel_destroy(channel_a);
        fut_fipc_channel_destroy(channel_b);
        registryd_stop(rd);
        netd_shutdown(nd);
        return 1;
    }

    remote_ab.channel_id = discovered_id;
    (void)fut_fipc_register_remote(channel_a->id, &remote_ab);

    const char *payload = "discovery: hello → world";
    if (fut_fipc_send(channel_a, 0xD15Cu, payload, strlen(payload)) != 0) {
        fprintf(stderr, "[FIPC-DISCOVERY] send failed\n");
        fut_fipc_channel_destroy(channel_a);
        fut_fipc_channel_destroy(channel_b);
        registryd_stop(rd);
        netd_shutdown(nd);
        return 1;
    }

    uint8_t buffer[4096];
    struct fut_fipc_msg *msg = NULL;
    if (drain_channel(nd, rd, channel_b, buffer, sizeof(buffer), &msg, 256) != 0 || !msg) {
        fprintf(stderr, "[FIPC-DISCOVERY] no message received\n");
        poll_ctx.running = false;
        pthread_join(poll_thread, NULL);
        fut_fipc_channel_destroy(channel_a);
        fut_fipc_channel_destroy(channel_b);
        registryd_stop(rd);
        netd_shutdown(nd);
        return 1;
    }

    if (msg->length != strlen(payload) || memcmp(msg->payload, payload, msg->length) != 0) {
        fprintf(stderr, "[FIPC-DISCOVERY] payload mismatch\n");
        poll_ctx.running = false;
        pthread_join(poll_thread, NULL);
        fut_fipc_channel_destroy(channel_a);
        fut_fipc_channel_destroy(channel_b);
        registryd_stop(rd);
        netd_shutdown(nd);
        return 1;
    }

    poll_ctx.running = false;
    pthread_join(poll_thread, NULL);

    printf("[FIPC-DISCOVERY] name '%s' lookup → channel_id=%llu, PASS\n",
           service_name,
           (unsigned long long)discovered_id);

    fut_fipc_channel_destroy(channel_a);
    fut_fipc_channel_destroy(channel_b);
    registryd_stop(rd);
    netd_shutdown(nd);
    return 0;
}
