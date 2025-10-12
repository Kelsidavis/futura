// SPDX-License-Identifier: MPL-2.0
// tests/fipc_remote_capability.c - capability mismatch drop / match deliver test

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

static int poll_once(struct netd *nd,
                     struct registryd *rd,
                     struct fut_fipc_channel *ch,
                     uint8_t *buffer,
                     size_t buf_len) {
    (void)netd_poll_once(nd, 0);
    (void)registryd_poll_once(rd, 0);
    return (int)fut_fipc_recv(ch, buffer, buf_len);
}

static int wait_for_message(struct netd *nd,
                            struct registryd *rd,
                            struct fut_fipc_channel *ch,
                            int polls) {
    uint8_t tmp[4096];
    for (int i = 0; i < polls; i++) {
        int rc = poll_once(nd, rd, ch, tmp, sizeof(tmp));
        if (rc > 0) {
            return 0;
        }
        if (rc < 0 && rc != FIPC_EAGAIN) {
            return -1;
        }
        struct timespec ts = {0, 1000000};
        nanosleep(&ts, NULL);
    }
    return -1;
}

static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s [--net=<port>] [--registry=<port>]\n", prog);
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

int main(int argc, char **argv) {
    const char *host = "127.0.0.1";
    uint16_t net_port = 28000;
    uint16_t reg_port = 27999;

    for (int i = 1; i < argc; i++) {
        if (strncmp(argv[i], "--net=", 6) == 0) {
            net_port = (uint16_t)atoi(argv[i] + 6);
        } else if (strncmp(argv[i], "--registry=", 11) == 0) {
            reg_port = (uint16_t)atoi(argv[i] + 11);
        } else if (strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        }
    }

    fut_fipc_init();

    struct netd *nd = netd_bootstrap(host, net_port);
    if (!nd) {
        fprintf(stderr, "[FIPC-CAP] netd bootstrap failed\n");
        return 1;
    }

    struct registryd *rd = registryd_start(reg_port);
    if (!rd) {
        fprintf(stderr, "[FIPC-CAP] registry bootstrap failed\n");
        netd_shutdown(nd);
        return 1;
    }

    struct registry_poll_ctx poll_ctx = { .rd = rd, .running = true };
    pthread_t poll_thread;
    if (pthread_create(&poll_thread, NULL, registry_poll_thread, &poll_ctx) != 0) {
        fprintf(stderr, "[FIPC-CAP] failed to start registry poll thread\n");
        registryd_stop(rd);
        netd_shutdown(nd);
        return 1;
    }

    struct fut_fipc_channel *channel_a = NULL;
    struct fut_fipc_channel *channel_b = NULL;

    if (fut_fipc_channel_create(NULL, NULL, 8192, FIPC_CHANNEL_NONBLOCKING, &channel_a) != 0 ||
        fut_fipc_channel_create(NULL, NULL, 8192, FIPC_CHANNEL_NONBLOCKING, &channel_b) != 0) {
        fprintf(stderr, "[FIPC-CAP] channel creation failed\n");
        if (channel_a) fut_fipc_channel_destroy(channel_a);
        if (channel_b) fut_fipc_channel_destroy(channel_b);
        registryd_stop(rd);
        netd_shutdown(nd);
        return 1;
    }

    const char *service_name = "svc.capcheck";
    if (registry_client_register(host, reg_port, service_name, channel_b->id) != 0) {
        fprintf(stderr, "[FIPC-CAP] registry registration failed\n");
        fut_fipc_channel_destroy(channel_a);
        fut_fipc_channel_destroy(channel_b);
        poll_ctx.running = false;
        pthread_join(poll_thread, NULL);
        registryd_stop(rd);
        netd_shutdown(nd);
        return 1;
    }

    struct fut_fipc_remote_endpoint endpoint = {
        .node_id = net_port,
        .channel_id = 0,
        .mtu = 8192,
        .flags = 0
    };

    if (fut_fipc_register_remote(channel_a->id, &endpoint) != 0) {
        fprintf(stderr, "[FIPC-CAP] register_remote failed\n");
        fut_fipc_channel_destroy(channel_a);
        fut_fipc_channel_destroy(channel_b);
        registryd_stop(rd);
        netd_shutdown(nd);
        return 1;
    }

    uint64_t remote_id = 0;
    if (registry_client_lookup(host, reg_port, service_name, &remote_id) != 0 || remote_id == 0) {
        fprintf(stderr, "[FIPC-CAP] registry lookup failed\n");
        fut_fipc_channel_destroy(channel_a);
        fut_fipc_channel_destroy(channel_b);
        poll_ctx.running = false;
        pthread_join(poll_thread, NULL);
        registryd_stop(rd);
        netd_shutdown(nd);
        return 1;
    }

    endpoint.channel_id = remote_id;
    (void)fut_fipc_register_remote(channel_a->id, &endpoint);

    const char *payload = "capability test";

    fut_fipc_bind_capability(channel_b, 0xC0FFEEu);
    fut_fipc_bind_capability(channel_a, 0xDEADBEEFu);

    if (fut_fipc_send(channel_a, 0xCAFEu, payload, strlen(payload)) != 0) {
        fprintf(stderr, "[FIPC-CAP] send (mismatch) failed\n");
        fut_fipc_channel_destroy(channel_a);
        fut_fipc_channel_destroy(channel_b);
        poll_ctx.running = false;
        pthread_join(poll_thread, NULL);
        registryd_stop(rd);
        netd_shutdown(nd);
        return 1;
    }

    if (wait_for_message(nd, rd, channel_b, 256) == 0) {
        fprintf(stderr, "[FIPC-CAP] mismatch should have been dropped\n");
        fut_fipc_channel_destroy(channel_a);
        fut_fipc_channel_destroy(channel_b);
        poll_ctx.running = false;
        pthread_join(poll_thread, NULL);
        registryd_stop(rd);
        netd_shutdown(nd);
        return 1;
    }

    fut_fipc_bind_capability(channel_a, 0xC0FFEEu);

    if (fut_fipc_send(channel_a, 0xCAFEu, payload, strlen(payload)) != 0) {
        fprintf(stderr, "[FIPC-CAP] send (match) failed\n");
        fut_fipc_channel_destroy(channel_a);
        fut_fipc_channel_destroy(channel_b);
        poll_ctx.running = false;
        pthread_join(poll_thread, NULL);
        registryd_stop(rd);
        netd_shutdown(nd);
        return 1;
    }

    if (wait_for_message(nd, rd, channel_b, 256) != 0) {
        fprintf(stderr, "[FIPC-CAP] expected delivery on capability match\n");
        fut_fipc_channel_destroy(channel_a);
        fut_fipc_channel_destroy(channel_b);
        poll_ctx.running = false;
        pthread_join(poll_thread, NULL);
        registryd_stop(rd);
        netd_shutdown(nd);
        return 1;
    }

    printf("[FIPC-CAP] mismatch dropped, match delivered — PASS\n");

    fut_fipc_channel_destroy(channel_a);
    fut_fipc_channel_destroy(channel_b);
    poll_ctx.running = false;
    pthread_join(poll_thread, NULL);
    registryd_stop(rd);
    netd_shutdown(nd);
    return 0;
}
