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
#include <kernel/fut_hmac.h>

extern uint64_t fut_get_ticks(void);

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
    uint8_t            key_current[SRG_KEY_LEN];
    uint8_t            key_previous[SRG_KEY_LEN];
    uint64_t           prev_valid_until_ms;
    struct {
        uint64_t nonce;
        uint64_t expires_at;
    } nonce_cache[SRG_NONCE_CACHE];
    size_t             nonce_cursor;
};

static void registryd_nonce_record(struct registryd *rd, uint64_t nonce, uint64_t now) {
    rd->nonce_cache[rd->nonce_cursor].nonce = nonce;
    rd->nonce_cache[rd->nonce_cursor].expires_at = now + SRG_TS_TOLERANCE_MS;
    rd->nonce_cursor = (rd->nonce_cursor + 1) % SRG_NONCE_CACHE;
}

static bool registryd_nonce_seen(struct registryd *rd, uint64_t nonce, uint64_t now) {
    for (size_t i = 0; i < SRG_NONCE_CACHE; ++i) {
        if (rd->nonce_cache[i].expires_at > now && rd->nonce_cache[i].nonce == nonce) {
            return true;
        }
    }
    return false;
}

static bool registryd_check_hmac(struct registryd *rd,
                                 const char *name,
                                 size_t name_len,
                                 uint64_t timestamp,
                                 uint64_t nonce,
                                 const uint8_t *candidate,
                                 size_t candidate_len,
                                 uint64_t now) {
    if (!candidate || candidate_len != SRG_HMAC_LEN) {
        return false;
    }

    uint8_t material[63 + 16];
    uint8_t *m = material;
    memcpy(m, name, name_len);
    m += name_len;
    for (size_t i = 0; i < 8; ++i) {
        material[name_len + i] = (uint8_t)((timestamp >> (i * 8)) & 0xFFu);
        material[name_len + 8 + i] = (uint8_t)((nonce >> (i * 8)) & 0xFFu);
    }
    size_t material_len = name_len + 16;

    uint8_t digest[SRG_HMAC_LEN];
    fut_hmac_sha256(rd->key_current, SRG_KEY_LEN, material, material_len, digest);
    if (memcmp(digest, candidate, SRG_HMAC_LEN) == 0) {
        return true;
    }

    if (rd->prev_valid_until_ms != 0 && now <= rd->prev_valid_until_ms) {
        fut_hmac_sha256(rd->key_previous, SRG_KEY_LEN, material, material_len, digest);
        if (memcmp(digest, candidate, SRG_HMAC_LEN) == 0) {
            return true;
        }
    }
    return false;
}

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
    memcpy(rd->key_current, (uint8_t[])SRG_KEY_DEFAULT_CURRENT_INIT, SRG_KEY_LEN);
    memcpy(rd->key_previous, (uint8_t[])SRG_KEY_DEFAULT_PREVIOUS_INIT, SRG_KEY_LEN);
    rd->prev_valid_until_ms = 0;
    memset(rd->nonce_cache, 0, sizeof(rd->nonce_cache));
    rd->nonce_cursor = 0;
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

int registryd_set_keys(struct registryd *rd,
                       const uint8_t current[SRG_KEY_LEN],
                       const uint8_t previous[SRG_KEY_LEN],
                       uint64_t grace_ms) {
    if (!rd || !current) {
        return -1;
    }
    memcpy(rd->key_current, current, SRG_KEY_LEN);
    if (previous) {
        memcpy(rd->key_previous, previous, SRG_KEY_LEN);
        rd->prev_valid_until_ms = fut_get_ticks() + grace_ms;
    } else {
        memset(rd->key_previous, 0, SRG_KEY_LEN);
        rd->prev_valid_until_ms = 0;
    }
    return 0;
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
        respond_error(rd->sock, src, slen, SRG_ERR_MALFORMED);
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
        respond_error(rd->sock, src, slen, SRG_ERR_MALFORMED);
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
        respond_error(rd->sock, src, slen, SRG_ERR_MALFORMED);
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

    respond_error(rd->sock, src, slen, SRG_ERR_NOT_FOUND);
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

    size_t auth_offset = sizeof(h) + nlen;
    if ((size_t)n < auth_offset + SRG_HMAC_LEN) {
        respond_error(rd->sock, &src, slen, SRG_ERR_AUTH);
        return true;
    }

    uint64_t timestamp = srg_ntohll(h.timestamp_ms);
    uint64_t nonce = srg_ntohll(h.nonce);
    const uint8_t *hmac = buffer + auth_offset;
    uint64_t now = fut_get_ticks();
    uint64_t diff = (timestamp > now) ? (timestamp - now) : (now - timestamp);
    if (diff > SRG_TS_TOLERANCE_MS) {
        respond_error(rd->sock, &src, slen, SRG_ERR_AUTH);
        return true;
    }
    if (registryd_nonce_seen(rd, nonce, now)) {
        respond_error(rd->sock, &src, slen, SRG_ERR_AUTH);
        return true;
    }
    if (!registryd_check_hmac(rd, name, nlen, timestamp, nonce, hmac, SRG_HMAC_LEN, now)) {
        respond_error(rd->sock, &src, slen, SRG_ERR_AUTH);
        return true;
    }
    registryd_nonce_record(rd, nonce, now);

    switch (ntohs(h.type)) {
    case SRG_REG:
        handle_reg(rd, &h, name, &src, slen);
        break;
    case SRG_LOOKUP:
        handle_lookup(rd, &h, name, &src, slen);
        break;
    default:
        respond_error(rd->sock, &src, slen, SRG_ERR_MALFORMED);
        break;
    }

    return true;
}
