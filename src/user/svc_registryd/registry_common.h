// SPDX-License-Identifier: MPL-2.0
// registry_common.h - shared definitions for service registry test harness

#ifndef FUTA_REGISTRY_COMMON_H
#define FUTA_REGISTRY_COMMON_H

#include <arpa/inet.h>
#include <stddef.h>
#include <stdint.h>

#define SRG_MAGIC 0x31524753u /* 'SRG1' little-endian */

enum srg_msg_type {
    SRG_REG = 1,          /* payload: name bytes + uint64_t channel_id */
    SRG_LOOKUP = 2,       /* payload: name bytes */
    SRG_LOOKUP_RESP = 3,  /* payload: uint64_t channel_id */
    SRG_ERROR = 255       /* payload: uint32_t err (0=ok,1=notfound,2=malformed) */
};

struct srg_hdr {
    uint32_t magic;     /* SRG_MAGIC */
    uint16_t type;      /* srg_msg_type */
    uint16_t name_len;  /* bytes following header for name (can be 0) */
    uint64_t channel_id;/* valid for REG (send) and LOOKUP_RESP (recv) */
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
