// SPDX-License-Identifier: MPL-2.0
// registry_common.h - shared definitions for service registry test harness

#ifndef FUTA_REGISTRY_COMMON_H
#define FUTA_REGISTRY_COMMON_H

#include <arpa/inet.h>
#include <stddef.h>
#include <stdint.h>

#define SRG_MAGIC 0x31524753u /* 'SRG1' little-endian */
#define SRG_KEY_LEN 32u
#define SRG_HMAC_LEN 32u
#define SRG_DEFAULT_GRACE_MS 300000u /* 5 minutes */
#define SRG_TS_TOLERANCE_MS 300000u  /* accept timestamps within ±5 minutes */
#define SRG_NONCE_CACHE 64u

#define SRG_KEY_DEFAULT_CURRENT_INIT \
    { 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, \
      0x11, 0x33, 0x55, 0x77, 0x99, 0xbb, 0xdd, 0xff, \
      0x20, 0x31, 0x42, 0x53, 0x64, 0x75, 0x86, 0x97, \
      0xa8, 0xb9, 0xca, 0xdb, 0xec, 0xfd, 0x0e, 0x1f }

#define SRG_KEY_DEFAULT_PREVIOUS_INIT SRG_KEY_DEFAULT_CURRENT_INIT

enum srg_msg_type {
    SRG_REG = 1,          /* payload: name bytes + uint64_t channel_id */
    SRG_LOOKUP = 2,       /* payload: name bytes */
    SRG_LOOKUP_RESP = 3,  /* payload: uint64_t channel_id */
    SRG_ERROR = 255       /* payload: uint32_t err (0=ok,1=notfound,2=malformed,3=auth) */
};

#define SRG_ERR_NOT_FOUND 1u
#define SRG_ERR_MALFORMED 2u
#define SRG_ERR_AUTH      3u

struct srg_hdr {
    uint32_t magic;     /* SRG_MAGIC */
    uint16_t type;      /* srg_msg_type */
    uint16_t name_len;  /* bytes following header for name (can be 0) */
    uint64_t channel_id;/* valid for REG (send) and LOOKUP_RESP (recv) */
    uint64_t nonce;      /* client-provided nonce for replay protection */
    uint64_t timestamp_ms; /* fut_get_ticks() value from client */
} __attribute__((packed));

static inline uint64_t srg_htonll(uint64_t v) {
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    return v;
#else
    uint32_t hi = (uint32_t)(v >> 32);
    uint32_t lo = (uint32_t)(v & 0xFFFFFFFFu);
    return ((uint64_t)htonl(lo) << 32) | ((uint64_t)htonl(hi));
#endif
}

static inline uint64_t srg_ntohll(uint64_t v) {
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    return v;
#else
    uint32_t lo = ntohl((uint32_t)(v >> 32));
    uint32_t hi = ntohl((uint32_t)(v & 0xFFFFFFFFu));
    return ((uint64_t)hi << 32) | lo;
#endif
}

#endif /* FUTA_REGISTRY_COMMON_H */
