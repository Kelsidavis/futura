// SPDX-License-Identifier: MPL-2.0
// registry_client.c - UDP client helpers for service registry tests

#define _POSIX_C_SOURCE 200809L

#include "registry_client.h"
#include "registry_common.h"

#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

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

int registry_client_register(const char *host,
                             uint16_t port,
                             const char *name,
                             uint64_t channel_id) {
    if (!host || !name) {
        return -1;
    }

    size_t nlen = strlen(name);
    if (nlen == 0 || nlen > 63) {
        return -1;
    }

    size_t total = sizeof(struct srg_hdr) + nlen;
    uint8_t *buf = (uint8_t *)malloc(total);
    if (!buf) {
        return -1;
    }

    struct srg_hdr hdr = {
        .magic = htonl(SRG_MAGIC),
        .type = htons(SRG_REG),
        .name_len = htons((uint16_t)nlen),
        .channel_id = srg_htonll(channel_id),
    };

    memcpy(buf, &hdr, sizeof(hdr));
    memcpy(buf + sizeof(hdr), name, nlen);

    struct srg_hdr resp;
    int rc = send_and_wait(host, port, buf, total, &resp);
    free(buf);

    if (rc != 0) {
        return -1;
    }

    if (ntohs(resp.type) == SRG_ERROR) {
        return -1;
    }

    return 0;
}

int registry_client_lookup(const char *host,
                           uint16_t port,
                           const char *name,
                           uint64_t *out_channel_id) {
    if (!host || !name || !out_channel_id) {
        return -1;
    }

    size_t nlen = strlen(name);
    if (nlen == 0 || nlen > 63) {
        return -1;
    }

    size_t total = sizeof(struct srg_hdr) + nlen;
    uint8_t *buf = (uint8_t *)malloc(total);
    if (!buf) {
        return -1;
    }

    struct srg_hdr hdr = {
        .magic = htonl(SRG_MAGIC),
        .type = htons(SRG_LOOKUP),
        .name_len = htons((uint16_t)nlen),
        .channel_id = srg_htonll(0),
    };

    memcpy(buf, &hdr, sizeof(hdr));
    memcpy(buf + sizeof(hdr), name, nlen);

    struct srg_hdr resp;
    int rc = send_and_wait(host, port, buf, total, &resp);
    free(buf);

    if (rc != 0) {
        return -1;
    }

    if (ntohs(resp.type) != SRG_LOOKUP_RESP) {
        return -1;
    }

    *out_channel_id = srg_ntohll(resp.channel_id);
    return 0;
}
