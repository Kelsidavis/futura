// SPDX-License-Identifier: MPL-2.0
// registry_client.c - UDP client helpers for service registry tests

#define _POSIX_C_SOURCE 200809L

#include "registry_client.h"

#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <kernel/fut_hmac.h>

extern uint64_t fut_get_ticks(void);

static uint8_t g_key_current[SRG_KEY_LEN] = SRG_KEY_DEFAULT_CURRENT_INIT;
static uint8_t g_key_previous[SRG_KEY_LEN] = SRG_KEY_DEFAULT_PREVIOUS_INIT;
static uint64_t g_prev_valid_until_ms = 0;

static uint64_t next_nonce(void) {
    static uint64_t state = 0x9e3779b97f4a7c15ULL;
    state ^= state << 7;
    state ^= state >> 9;
    state ^= state << 8;
    return state;
}

static void write_le64(uint8_t *dst, uint64_t value) {
    for (size_t i = 0; i < 8; ++i) {
        dst[i] = (uint8_t)((value >> (i * 8)) & 0xFFu);
    }
}

void registry_client_set_keys(const uint8_t current[SRG_KEY_LEN],
                              const uint8_t previous[SRG_KEY_LEN],
                              uint64_t grace_ms) {
    if (current) {
        memcpy(g_key_current, current, SRG_KEY_LEN);
    }
    if (previous) {
        memcpy(g_key_previous, previous, SRG_KEY_LEN);
        g_prev_valid_until_ms = fut_get_ticks() + grace_ms;
    } else {
        memset(g_key_previous, 0, sizeof(g_key_previous));
        g_prev_valid_until_ms = 0;
    }
}

static int send_and_wait(const char *host,
                         uint16_t port,
                         const uint8_t *buf,
                         size_t len,
                         struct srg_hdr *resp_out) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        return -1;
    }

    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &dst.sin_addr) != 1) {
        close(sock);
        return -1;
    }

    ssize_t sent = sendto(sock, buf, len, 0, (struct sockaddr *)&dst, sizeof(dst));
    if (sent != (ssize_t)len) {
        close(sock);
        return -1;
    }

    struct pollfd pfd = {
        .fd = sock,
        .events = POLLIN,
        .revents = 0
    };

    int pr = poll(&pfd, 1, 500);
    if (pr <= 0 || !(pfd.revents & POLLIN)) {
        close(sock);
        return -1;
    }

    struct srg_hdr resp;
    ssize_t received = recvfrom(sock, &resp, sizeof(resp), 0, NULL, NULL);
    close(sock);
    if (received != (ssize_t)sizeof(resp)) {
        return -1;
    }
    if (ntohl(resp.magic) != SRG_MAGIC) {
        return -1;
    }

    *resp_out = resp;
    return 0;
}

static int registry_client_send_with_key(const char *host,
                                         uint16_t port,
                                         uint16_t msg_type,
                                         const char *name,
                                         uint64_t channel_id,
                                         const uint8_t *key,
                                         struct srg_hdr *resp_out) {
    if (!host || !name) {
        return -1;
    }

    size_t name_len = strlen(name);
    if (name_len == 0 || name_len > 63) {
        return -1;
    }

    uint64_t timestamp = fut_get_ticks();
    uint64_t nonce = next_nonce();

    size_t total = sizeof(struct srg_hdr) + name_len;
    size_t hmac_offset = total;
    if (key) {
        total += SRG_HMAC_LEN;
    }

    uint8_t *buf = (uint8_t *)malloc(total);
    if (!buf) {
        return -1;
    }

    struct srg_hdr hdr = {
        .magic = htonl(SRG_MAGIC),
        .type = htons(msg_type),
        .name_len = htons((uint16_t)name_len),
        .channel_id = srg_htonll(channel_id),
        .nonce = srg_htonll(nonce),
        .timestamp_ms = srg_htonll(timestamp),
    };

    memcpy(buf, &hdr, sizeof(hdr));
    memcpy(buf + sizeof(hdr), name, name_len);

    if (key) {
        uint8_t material[63 + 16];
        uint8_t *m = material;
        memcpy(m, name, name_len);
        m += name_len;
        write_le64(m, timestamp);
        m += 8;
        write_le64(m, nonce);
        size_t material_len = name_len + 16;
        uint8_t digest[SRG_HMAC_LEN];
        fut_hmac_sha256(key, SRG_KEY_LEN, material, material_len, digest);
        memcpy(buf + hmac_offset, digest, SRG_HMAC_LEN);
    }

    struct srg_hdr resp;
    int rc = send_and_wait(host, port, buf, total, &resp);
    free(buf);

    if (rc != 0) {
        return -1;
    }

    if (ntohs(resp.type) == SRG_ERROR) {
        return -1;
    }

    if (msg_type == SRG_LOOKUP && ntohs(resp.type) != SRG_LOOKUP_RESP) {
        return -1;
    }

    if (resp_out) {
        *resp_out = resp;
    }

    return 0;
}

int registry_client_register_with_key(const char *host,
                                      uint16_t port,
                                      const char *name,
                                      uint64_t channel_id,
                                      const uint8_t key[SRG_KEY_LEN]) {
    return registry_client_send_with_key(host, port, SRG_REG, name, channel_id, key, NULL);
}

int registry_client_register(const char *host,
                             uint16_t port,
                             const char *name,
                             uint64_t channel_id) {
    if (registry_client_register_with_key(host, port, name, channel_id, g_key_current) == 0) {
        return 0;
    }
    uint64_t now = fut_get_ticks();
    if (g_prev_valid_until_ms != 0 && now <= g_prev_valid_until_ms) {
        if (registry_client_register_with_key(host, port, name, channel_id, g_key_previous) == 0) {
            return 0;
        }
    }
    return -1;
}

int registry_client_lookup_with_key(const char *host,
                                    uint16_t port,
                                    const char *name,
                                    uint64_t *out_channel_id,
                                    const uint8_t key[SRG_KEY_LEN]) {
    if (!out_channel_id) {
        return -1;
    }

    struct srg_hdr reply;
    if (registry_client_send_with_key(host, port, SRG_LOOKUP, name, 0, key, &reply) != 0) {
        return -1;
    }

    *out_channel_id = srg_ntohll(reply.channel_id);
    return 0;
}

int registry_client_lookup(const char *host,
                           uint16_t port,
                           const char *name,
                           uint64_t *out_channel_id) {
    if (registry_client_lookup_with_key(host, port, name, out_channel_id, g_key_current) == 0) {
        return 0;
    }
    uint64_t now = fut_get_ticks();
    if (g_prev_valid_until_ms != 0 && now <= g_prev_valid_until_ms) {
        if (registry_client_lookup_with_key(host, port, name, out_channel_id, g_key_previous) == 0) {
            return 0;
        }
    }
    return -1;
}
