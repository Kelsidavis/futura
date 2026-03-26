/* kernel/net/ipsec.c - IPsec Security Associations and policy database
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements IPsec Security Association (SA) and Security Policy (SP)
 * management for ESP and AH packet processing. SAs define encryption
 * and authentication parameters; SPs define which traffic to protect.
 *
 * Supports:
 *   - SA add/delete/flush via XFRM-compatible ioctls
 *   - SP add/delete for tunnel and transport mode
 *   - /proc/net/xfrm_stat for IPsec statistics
 *   - ip xfrm state/policy shell commands
 */

#include <kernel/kprintf.h>
#include <kernel/errno.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#define IPSEC_SA_MAX        64
#define IPSEC_SP_MAX        32

/* IPsec protocols */
#define IPSEC_PROTO_ESP     50
#define IPSEC_PROTO_AH      51

/* IPsec modes */
#define IPSEC_MODE_TRANSPORT 0
#define IPSEC_MODE_TUNNEL    1

/* Security Association */
struct ipsec_sa {
    bool        active;
    uint32_t    spi;            /* Security Parameter Index */
    uint32_t    src_ip;         /* Source IP (host byte order) */
    uint32_t    dst_ip;         /* Destination IP */
    uint8_t     proto;          /* ESP (50) or AH (51) */
    uint8_t     mode;           /* Transport or Tunnel */
    uint8_t     auth_algo;      /* 0=none, 1=HMAC-SHA256, 2=HMAC-SHA1 */
    uint8_t     enc_algo;       /* 0=none, 1=AES-CBC-128, 2=AES-CBC-256 */
    uint64_t    bytes;          /* Bytes processed */
    uint64_t    packets;        /* Packets processed */
    uint32_t    lifetime_sec;   /* SA lifetime in seconds (0 = infinite) */
};

/* Security Policy */
struct ipsec_sp {
    bool        active;
    uint32_t    src_net;        /* Source network */
    uint32_t    src_mask;       /* Source mask */
    uint32_t    dst_net;        /* Destination network */
    uint32_t    dst_mask;       /* Destination mask */
    uint8_t     direction;      /* 0=in, 1=out, 2=fwd */
    uint8_t     action;         /* 0=allow, 1=ipsec, 2=discard */
    uint32_t    spi;            /* SA SPI to use (for action=ipsec) */
};

static struct ipsec_sa g_sas[IPSEC_SA_MAX];
static struct ipsec_sp g_sps[IPSEC_SP_MAX];

/* Statistics */
static struct {
    uint64_t in_pkts;
    uint64_t out_pkts;
    uint64_t in_bytes;
    uint64_t out_bytes;
    uint64_t errors;
    uint64_t no_sa;             /* Packets without matching SA */
} g_ipsec_stats;

void ipsec_init(void) {
    memset(g_sas, 0, sizeof(g_sas));
    memset(g_sps, 0, sizeof(g_sps));
    memset(&g_ipsec_stats, 0, sizeof(g_ipsec_stats));
    fut_printf("[IPSEC] IPsec subsystem initialized (SA=%d, SP=%d)\n",
               IPSEC_SA_MAX, IPSEC_SP_MAX);
}

int ipsec_sa_add(uint32_t spi, uint32_t src, uint32_t dst, uint8_t proto,
                 uint8_t mode, uint8_t auth_algo, uint8_t enc_algo) {
    /* Check for duplicate SPI */
    for (int i = 0; i < IPSEC_SA_MAX; i++) {
        if (g_sas[i].active && g_sas[i].spi == spi && g_sas[i].dst_ip == dst)
            return -EEXIST;
    }
    int slot = -1;
    for (int i = 0; i < IPSEC_SA_MAX; i++) {
        if (!g_sas[i].active) { slot = i; break; }
    }
    if (slot < 0) return -ENOSPC;

    struct ipsec_sa *sa = &g_sas[slot];
    sa->active = true;
    sa->spi = spi;
    sa->src_ip = src;
    sa->dst_ip = dst;
    sa->proto = proto;
    sa->mode = mode;
    sa->auth_algo = auth_algo;
    sa->enc_algo = enc_algo;

    const char *pname = proto == IPSEC_PROTO_ESP ? "esp" : "ah";
    fut_printf("[IPSEC] SA added: spi=0x%x %s %u.%u.%u.%u → %u.%u.%u.%u\n",
               spi, pname,
               (src >> 24) & 0xFF, (src >> 16) & 0xFF, (src >> 8) & 0xFF, src & 0xFF,
               (dst >> 24) & 0xFF, (dst >> 16) & 0xFF, (dst >> 8) & 0xFF, dst & 0xFF);
    return 0;
}

int ipsec_sa_delete(uint32_t spi, uint32_t dst) {
    for (int i = 0; i < IPSEC_SA_MAX; i++) {
        if (g_sas[i].active && g_sas[i].spi == spi && g_sas[i].dst_ip == dst) {
            g_sas[i].active = false;
            return 0;
        }
    }
    return -ESRCH;
}

int ipsec_sp_add(uint32_t src_net, uint32_t src_mask, uint32_t dst_net,
                 uint32_t dst_mask, uint8_t direction, uint8_t action, uint32_t spi) {
    int slot = -1;
    for (int i = 0; i < IPSEC_SP_MAX; i++) {
        if (!g_sps[i].active) { slot = i; break; }
    }
    if (slot < 0) return -ENOSPC;

    struct ipsec_sp *sp = &g_sps[slot];
    sp->active = true;
    sp->src_net = src_net;
    sp->src_mask = src_mask;
    sp->dst_net = dst_net;
    sp->dst_mask = dst_mask;
    sp->direction = direction;
    sp->action = action;
    sp->spi = spi;

    fut_printf("[IPSEC] SP added: %s action=%s\n",
               direction == 0 ? "in" : direction == 1 ? "out" : "fwd",
               action == 0 ? "allow" : action == 1 ? "ipsec" : "discard");
    return 0;
}

int ipsec_sa_count(void) {
    int c = 0;
    for (int i = 0; i < IPSEC_SA_MAX; i++) if (g_sas[i].active) c++;
    return c;
}

int ipsec_sp_count(void) {
    int c = 0;
    for (int i = 0; i < IPSEC_SP_MAX; i++) if (g_sps[i].active) c++;
    return c;
}
