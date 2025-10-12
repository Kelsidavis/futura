// SPDX-License-Identifier: MPL-2.0
// registry_server.c - minimal UDP registry server for tests

#define _POSIX_C_SOURCE 200809L

#include "registry_common.h"
#include "registry_server.h"

#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

struct registry_entry {
    char     name[64];
    uint64_t chan;
};

struct registryd {
    int                sock;
    struct sockaddr_in bind_addr;
    bool               running;
    struct registry_entry table[64];
    size_t             nentries;
};

struct registryd *registryd_start(uint16_t port) {
    struct registryd *rd = (struct registryd *)calloc(1, sizeof(*rd));
    if (!rd) {
        return NULL;
    }

    rd->sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (rd->sock < 0) {
        free(rd);
        return NULL;
    }

    memset(&rd->bind_addr, 0, sizeof(rd->bind_addr));
    rd->bind_addr.sin_family = AF_INET;
    rd->bind_addr.sin_port = htons(port);
    rd->bind_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    int opt = 1;
    (void)setsockopt(rd->sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    if (bind(rd->sock, (struct sockaddr *)&rd->bind_addr, sizeof(rd->bind_addr)) < 0) {
        close(rd->sock);
        free(rd);
        return NULL;
    }

    rd->running = true;
    return rd;
}

void registryd_stop(struct registryd *rd) {
    if (!rd) {
        return;
    }

    rd->running = false;
    if (rd->sock >= 0) {
        close(rd->sock);
    }
    free(rd);
}

static void respond_error(int sock, const struct sockaddr_in *dst, socklen_t dlen, uint32_t err) {
    struct srg_hdr h = {
        .magic = htonl(SRG_MAGIC),
        .type = htons(SRG_ERROR),
        .name_len = htons(0),
        .channel_id = srg_htonll((uint64_t)err),
    };
    (void)sendto(sock, &h, sizeof(h), 0, (const struct sockaddr *)dst, dlen);
}

static void handle_reg(struct registryd *rd,
                       const struct srg_hdr *h,
                       const char *name,
                       const struct sockaddr_in *src,
                       socklen_t slen) {
    if (!rd || !h || !name) {
        return;
    }

    size_t nlen = ntohs(h->name_len);
    if (nlen == 0 || nlen >= sizeof(rd->table[0].name)) {
        respond_error(rd->sock, src, slen, 2);
        return;
    }

    for (size_t i = 0; i < rd->nentries; i++) {
        if (strncmp(rd->table[i].name, name, sizeof(rd->table[i].name)) == 0) {
            rd->table[i].chan = srg_ntohll(h->channel_id);
            goto send_ack;
        }
    }

    if (rd->nentries < (sizeof(rd->table) / sizeof(rd->table[0]))) {
        size_t copy_len = nlen < sizeof(rd->table[0].name) - 1 ? nlen : sizeof(rd->table[0].name) - 1;
        memcpy(rd->table[rd->nentries].name, name, copy_len);
        rd->table[rd->nentries].name[copy_len] = '\0';
        rd->table[rd->nentries].chan = srg_ntohll(h->channel_id);
        rd->nentries++;
    } else {
        respond_error(rd->sock, src, slen, 2);
        return;
    }

send_ack: {
        struct srg_hdr resp = {
            .magic = htonl(SRG_MAGIC),
            .type = htons(SRG_LOOKUP_RESP),
            .name_len = htons(0),
            .channel_id = h->channel_id,
        };
        (void)sendto(rd->sock, &resp, sizeof(resp), 0, (const struct sockaddr *)src, slen);
    }
}

static void handle_lookup(struct registryd *rd,
                          const struct srg_hdr *h,
                          const char *name,
                          const struct sockaddr_in *src,
                          socklen_t slen) {
    if (!rd || !h || !name) {
        return;
    }

    size_t nlen = ntohs(h->name_len);
    if (nlen == 0 || nlen >= sizeof(rd->table[0].name)) {
        respond_error(rd->sock, src, slen, 2);
        return;
    }

    for (size_t i = 0; i < rd->nentries; i++) {
        if (strncmp(rd->table[i].name, name, sizeof(rd->table[i].name)) == 0) {
            struct srg_hdr resp = {
                .magic = htonl(SRG_MAGIC),
                .type = htons(SRG_LOOKUP_RESP),
                .name_len = htons(0),
                .channel_id = srg_htonll(rd->table[i].chan),
            };
            (void)sendto(rd->sock, &resp, sizeof(resp), 0, (const struct sockaddr *)src, slen);
            return;
        }
    }

    respond_error(rd->sock, src, slen, 1);
}

bool registryd_poll_once(struct registryd *rd, uint32_t timeout_ms) {
    if (!rd || !rd->running) {
        return false;
    }

    struct pollfd pfd = {
        .fd = rd->sock,
        .events = POLLIN,
        .revents = 0
    };

    int pr = poll(&pfd, 1, (int)timeout_ms);
    if (pr < 0) {
        if (errno == EINTR) {
            return true;
        }
        rd->running = false;
        return false;
    }

    if (pr == 0 || !(pfd.revents & POLLIN)) {
        return true;
    }

    uint8_t buffer[2048];
    struct sockaddr_in src;
    socklen_t slen = sizeof(src);
    ssize_t n = recvfrom(rd->sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&src, &slen);
    if (n < (ssize_t)sizeof(struct srg_hdr)) {
        return true;
    }

    struct srg_hdr h;
    memcpy(&h, buffer, sizeof(h));
    if (ntohl(h.magic) != SRG_MAGIC) {
        return true;
    }

    char name[64] = {0};
    size_t nlen = ntohs(h.name_len);
    if (nlen > 0) {
        if ((size_t)n < sizeof(h) + nlen) {
            return true;
        }
        size_t copy_len = nlen < sizeof(name) - 1 ? nlen : sizeof(name) - 1;
        memcpy(name, buffer + sizeof(h), copy_len);
        name[copy_len] = '\0';
    }

    switch (ntohs(h.type)) {
    case SRG_REG:
        handle_reg(rd, &h, name, &src, slen);
        break;
    case SRG_LOOKUP:
        handle_lookup(rd, &h, name, &src, slen);
        break;
    default:
        respond_error(rd->sock, &src, slen, 2);
        break;
    }

    return true;
}
