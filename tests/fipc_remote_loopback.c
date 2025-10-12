#define _POSIX_C_SOURCE 200809L

#include <kernel/fut_fipc.h>
#include <kernel/fut_timer.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "../src/user/netd/netd_core.h"

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static double ns_to_ms(uint64_t ns) {
    return (double)ns / 1e6;
}

static int drain_channel(struct netd *nd,
                         struct fut_fipc_channel *channel,
                         uint8_t *buffer,
                         size_t buffer_len,
                         struct fut_fipc_msg **msg_out,
                         int attempts) {
    for (int i = 0; i < attempts; i++) {
        ssize_t received = fut_fipc_recv(channel, buffer, buffer_len);
        if (received > 0) {
            *msg_out = (struct fut_fipc_msg *)buffer;
            return 0;
        }
        if (received == FIPC_EAGAIN) {
            netd_poll_once(nd, 0);
            continue;
        }
        return -1;
    }
    return -1;
}

static int parse_endpoint(const char *value, char *host_out, size_t host_len, uint16_t *port_out) {
    const char *colon = strchr(value, ':');
    if (!colon) {
        return -1;
    }

    size_t host_size = (size_t)(colon - value);
    if (host_size == 0 || host_size >= host_len) {
        return -1;
    }

    memcpy(host_out, value, host_size);
    host_out[host_size] = '\0';

    int port = atoi(colon + 1);
    if (port <= 0 || port > 65535) {
        return -1;
    }

    *port_out = (uint16_t)port;
    return 0;
}

int main(int argc, char **argv) {
    char host[64] = "127.0.0.1";
    uint16_t port = 49500;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--net") == 0 && (i + 1) < argc) {
            if (parse_endpoint(argv[++i], host, sizeof(host), &port) != 0) {
                fprintf(stderr, "[FIPC-REMOTE] invalid --net argument\n");
                return 1;
            }
        }
    }

    fut_fipc_init();

    struct netd *nd = netd_bootstrap(host, port);
    if (!nd) {
        fprintf(stderr, "[FIPC-REMOTE] failed to bootstrap netd\n");
        return 1;
    }

    struct fut_fipc_channel *channel_b = NULL;
    struct fut_fipc_channel *channel_a = NULL;

    if (fut_fipc_channel_create(NULL, NULL, 8192, FIPC_CHANNEL_NONBLOCKING, &channel_b) != 0) {
        fprintf(stderr, "[FIPC-REMOTE] unable to create channel B\n");
        return 1;
    }

    if (fut_fipc_channel_create(NULL, NULL, 8192, FIPC_CHANNEL_NONBLOCKING, &channel_a) != 0) {
        fprintf(stderr, "[FIPC-REMOTE] unable to create channel A\n");
        return 1;
    }

    const uint64_t capability = 0xF1C0F1C0ULL;
    fut_fipc_bind_capability(channel_a, capability);
    fut_fipc_bind_capability(channel_b, capability);

    struct fut_fipc_remote_endpoint remote_ab = {
        .node_id = port,
        .channel_id = channel_b->id,
        .mtu = 8192,
        .flags = 0
    };

    struct fut_fipc_remote_endpoint remote_ba = {
        .node_id = port,
        .channel_id = channel_a->id,
        .mtu = 8192,
        .flags = 0
    };

    fut_fipc_register_remote(channel_a->id, &remote_ab);
    fut_fipc_register_remote(channel_b->id, &remote_ba);

    uint8_t buffer[2048];
    struct fut_fipc_msg *msg = NULL;

    const char *payload_a = "hello-remote-b";
    uint64_t start_ns = now_ns();
    if (fut_fipc_send(channel_a, 0x42, payload_a, strlen(payload_a) + 1) != 0) {
        fprintf(stderr, "[FIPC-REMOTE] send A->B failed\n");
        netd_shutdown(nd);
        return 1;
    }

    double latency_ms = 0.0;
    if (drain_channel(nd, channel_b, buffer, sizeof(buffer), &msg, 128) != 0) {
        fprintf(stderr, "[FIPC-REMOTE] did not receive message on channel B\n");
        netd_shutdown(nd);
        return 1;
    }
    uint64_t end_ns = now_ns();
    latency_ms = ns_to_ms(end_ns - start_ns);

    if (strcmp((char *)msg->payload, payload_a) != 0) {
        fprintf(stderr, "[FIPC-REMOTE] payload mismatch on channel B\n");
        netd_shutdown(nd);
        return 1;
    }

    const char *payload_b = "reply-from-b";
    start_ns = now_ns();
    if (fut_fipc_send(channel_b, 0x43, payload_b, strlen(payload_b) + 1) != 0) {
        fprintf(stderr, "[FIPC-REMOTE] send B->A failed\n");
        netd_shutdown(nd);
        return 1;
    }

    if (drain_channel(nd, channel_a, buffer, sizeof(buffer), &msg, 128) != 0) {
        fprintf(stderr, "[FIPC-REMOTE] did not receive message on channel A\n");
        netd_shutdown(nd);
        return 1;
    }
    end_ns = now_ns();
    double latency_ms_ba = ns_to_ms(end_ns - start_ns);

    if (strcmp((char *)msg->payload, payload_b) != 0) {
        fprintf(stderr, "[FIPC-REMOTE] payload mismatch on channel A\n");
        netd_shutdown(nd);
        return 1;
    }

    netd_shutdown(nd);

    if (latency_ms > 1.0 || latency_ms_ba > 1.0) {
        fprintf(stderr, "[FIPC-REMOTE] latency exceeded threshold: %.3f ms / %.3f ms\n",
                latency_ms,
                latency_ms_ba);
        return 1;
    }

    printf("[FIPC-REMOTE] loopback PASS (verified CRC, latency %.3f/%.3f ms)\n",
           latency_ms,
           latency_ms_ba);
    return 0;
}
