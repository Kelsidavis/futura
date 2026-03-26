/* kernel/net/gre.c - GRE tunnel interface support
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements GRE (Generic Routing Encapsulation, RFC 2784) tunnel
 * interfaces for IP-in-IP encapsulation. GRE tunnels appear as
 * regular net_iface entries with point-to-point semantics.
 *
 * Used for: VPN tunnels, overlay networks, GRE/IPIP encapsulation.
 */

#include <futura/netif.h>
#include <kernel/kprintf.h>
#include <kernel/errno.h>
#include <string.h>

#define GRE_MAX_TUNNELS     16
#define GRE_PROTOCOL        47      /* IP protocol number for GRE */

struct gre_tunnel {
    bool        active;
    int         iface_idx;          /* Tunnel interface index */
    char        name[NET_IFNAME_MAX];
    uint32_t    local_ip;           /* Tunnel source IP (host byte order) */
    uint32_t    remote_ip;          /* Tunnel destination IP (host byte order) */
    uint32_t    key;                /* GRE key (0 = no key) */
    uint16_t    flags;              /* GRE header flags */
    uint8_t     ttl;                /* TTL for outer IP header (0 = inherit) */
    uint8_t     tos;                /* TOS for outer IP header (0 = inherit) */
};

static struct gre_tunnel g_gre_tunnels[GRE_MAX_TUNNELS];

static int gre_transmit(struct net_iface *iface, const void *pkt, size_t len) {
    (void)iface; (void)pkt; (void)len;
    /* In a real implementation, this would:
     * 1. Add GRE header (4-8 bytes)
     * 2. Wrap in outer IP header with local/remote IPs
     * 3. Route the outer packet via ip_send_packet() */
    return 0;
}

int gre_tunnel_create(const char *name, uint32_t local_ip, uint32_t remote_ip,
                      uint32_t key) {
    if (!name || name[0] == '\0') return -EINVAL;

    /* Check for duplicate */
    for (int i = 0; i < GRE_MAX_TUNNELS; i++) {
        if (!g_gre_tunnels[i].active) continue;
        const char *a = g_gre_tunnels[i].name;
        const char *b = name;
        while (*a && *b && *a == *b) { a++; b++; }
        if (*a == '\0' && *b == '\0') return -EEXIST;
    }

    /* Find free slot */
    int slot = -1;
    for (int i = 0; i < GRE_MAX_TUNNELS; i++) {
        if (!g_gre_tunnels[i].active) { slot = i; break; }
    }
    if (slot < 0) return -ENOSPC;

    /* Register as point-to-point interface */
    eth_addr_t gre_mac = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};  /* No L2 for tunnels */
    int idx = netif_register(name, gre_mac, 1476, gre_transmit);  /* MTU = 1500 - 20 (IP) - 4 (GRE) */
    if (idx < 0) return idx;

    struct net_iface *iface = netif_by_index(idx);
    if (iface) {
        iface->flags = IFF_UP | IFF_POINTOPOINT | IFF_RUNNING;
    }

    struct gre_tunnel *tun = &g_gre_tunnels[slot];
    memset(tun, 0, sizeof(*tun));
    tun->active = true;
    tun->iface_idx = idx;
    tun->local_ip = local_ip;
    tun->remote_ip = remote_ip;
    tun->key = key;
    tun->ttl = 64;

    size_t nlen = 0;
    while (name[nlen] && nlen < NET_IFNAME_MAX - 1) nlen++;
    memcpy(tun->name, name, nlen);
    tun->name[nlen] = '\0';

    fut_printf("[GRE] Created tunnel '%s' local=%u.%u.%u.%u remote=%u.%u.%u.%u\n",
               name,
               (local_ip >> 24) & 0xFF, (local_ip >> 16) & 0xFF,
               (local_ip >> 8) & 0xFF, local_ip & 0xFF,
               (remote_ip >> 24) & 0xFF, (remote_ip >> 16) & 0xFF,
               (remote_ip >> 8) & 0xFF, remote_ip & 0xFF);
    return idx;
}

int gre_tunnel_count(void) {
    int count = 0;
    for (int i = 0; i < GRE_MAX_TUNNELS; i++)
        if (g_gre_tunnels[i].active) count++;
    return count;
}

const struct gre_tunnel *gre_tunnel_get(int index) {
    if (index < 0 || index >= GRE_MAX_TUNNELS) return NULL;
    return g_gre_tunnels[index].active ? &g_gre_tunnels[index] : NULL;
}
