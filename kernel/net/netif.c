/* kernel/net/netif.c - Network interface and routing table
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Multi-interface networking for router OS support:
 * - Interface registry with per-interface IP/MAC/MTU/stats
 * - Routing table with longest-prefix-match
 * - IP forwarding between interfaces
 * - Loopback interface (lo) auto-created
 */

#include <futura/netif.h>
#include <futura/tcpip.h>
#include <kernel/fut_memory.h>
#include <kernel/fut_sched.h>
#include <kernel/kprintf.h>
#include <kernel/errno.h>
#include <string.h>
#include <stdbool.h>

/* ============================================================
 *   Global State
 * ============================================================ */

static struct net_iface g_ifaces[NET_IFACE_MAX];
static struct net_route g_routes[NET_ROUTE_MAX];
static int g_next_ifindex = 1;
static fut_spinlock_t g_netif_lock;
static fut_spinlock_t g_route_lock;

bool g_ip_forward_enabled = false;

/* ============================================================
 *   Loopback transmit (delivers to self)
 * ============================================================ */

static int lo_transmit(struct net_iface *iface, const void *pkt, size_t len) {
    (void)iface; (void)pkt; (void)len;
    /* Loopback: packet is already delivered internally */
    iface->tx_packets++;
    iface->tx_bytes += len;
    iface->rx_packets++;
    iface->rx_bytes += len;
    return 0;
}

/* ============================================================
 *   Interface Management
 * ============================================================ */

void netif_init(void) {
    memset(g_ifaces, 0, sizeof(g_ifaces));
    memset(g_routes, 0, sizeof(g_routes));
    fut_spinlock_init(&g_netif_lock);
    fut_spinlock_init(&g_route_lock);
    g_next_ifindex = 1;

    /* Create loopback interface */
    eth_addr_t lo_mac = {0, 0, 0, 0, 0, 0};
    int lo_idx = netif_register("lo", lo_mac, 65536, lo_transmit);
    if (lo_idx >= 0) {
        netif_set_addr(lo_idx, 0x7F000001 /* 127.0.0.1 */,
                       0xFF000000 /* 255.0.0.0 */, 0x7FFFFFFF);
        netif_set_flags(lo_idx, IFF_UP | IFF_LOOPBACK | IFF_RUNNING);
        /* Add loopback route: 127.0.0.0/8 → lo */
        route_add(0x7F000000, 0xFF000000, 0, lo_idx, 0);
    }

    fut_printf("[NETIF] Network interface subsystem initialized (lo=%d)\n", lo_idx);
}

int netif_register(const char *name, const eth_addr_t mac, uint32_t mtu,
                   int (*transmit)(struct net_iface *, const void *, size_t)) {
    if (!name) return -EINVAL;

    fut_spinlock_acquire(&g_netif_lock);
    int slot = -1;
    for (int i = 0; i < NET_IFACE_MAX; i++) {
        if (!g_ifaces[i].active) { slot = i; break; }
    }
    if (slot < 0) {
        fut_spinlock_release(&g_netif_lock);
        return -ENOSPC;
    }

    struct net_iface *iface = &g_ifaces[slot];
    memset(iface, 0, sizeof(*iface));
    iface->active = true;
    iface->index = g_next_ifindex++;
    iface->mtu = mtu ? mtu : 1500;
    iface->transmit = transmit;
    memcpy(iface->mac, mac, ETH_ADDR_LEN);

    /* Copy name safely */
    size_t nlen = 0;
    while (name[nlen] && nlen < NET_IFNAME_MAX - 1) nlen++;
    memcpy(iface->name, name, nlen);
    iface->name[nlen] = '\0';

    fut_spinlock_release(&g_netif_lock);

    fut_printf("[NETIF] Registered interface '%s' (idx=%d, mtu=%u)\n",
               iface->name, iface->index, iface->mtu);
    return iface->index;
}

struct net_iface *netif_by_name(const char *name) {
    if (!name) return NULL;
    for (int i = 0; i < NET_IFACE_MAX; i++) {
        if (g_ifaces[i].active) {
            const char *a = g_ifaces[i].name;
            const char *b = name;
            while (*a && *b && *a == *b) { a++; b++; }
            if (*a == '\0' && *b == '\0') return &g_ifaces[i];
        }
    }
    return NULL;
}

struct net_iface *netif_by_index(int index) {
    for (int i = 0; i < NET_IFACE_MAX; i++) {
        if (g_ifaces[i].active && g_ifaces[i].index == index)
            return &g_ifaces[i];
    }
    return NULL;
}

int netif_set_addr(int index, uint32_t ip, uint32_t mask, uint32_t broadcast) {
    struct net_iface *iface = netif_by_index(index);
    if (!iface) return -ENODEV;
    iface->ip_addr = ip;
    iface->netmask = mask;
    iface->broadcast = broadcast;
    return 0;
}

int netif_set_flags(int index, uint32_t flags) {
    struct net_iface *iface = netif_by_index(index);
    if (!iface) return -ENODEV;
    iface->flags = flags;
    return 0;
}

int netif_count(void) {
    int count = 0;
    for (int i = 0; i < NET_IFACE_MAX; i++)
        if (g_ifaces[i].active) count++;
    return count;
}

void netif_foreach(netif_iter_fn fn, void *ctx) {
    if (!fn) return;
    for (int i = 0; i < NET_IFACE_MAX; i++)
        if (g_ifaces[i].active) fn(&g_ifaces[i], ctx);
}

/* ============================================================
 *   Routing Table
 * ============================================================ */

int route_add(uint32_t dest, uint32_t mask, uint32_t gateway,
              int iface_idx, uint32_t metric) {
    fut_spinlock_acquire(&g_route_lock);
    int slot = -1;
    for (int i = 0; i < NET_ROUTE_MAX; i++) {
        if (!g_routes[i].active) { slot = i; break; }
    }
    if (slot < 0) {
        fut_spinlock_release(&g_route_lock);
        return -ENOSPC;
    }

    struct net_route *rt = &g_routes[slot];
    rt->active = true;
    rt->dest = dest;
    rt->netmask = mask;
    rt->gateway = gateway;
    rt->iface_idx = iface_idx;
    rt->metric = metric;
    rt->flags = RTF_UP;
    if (gateway) rt->flags |= RTF_GATEWAY;
    if (mask == 0xFFFFFFFF) rt->flags |= RTF_HOST;

    fut_spinlock_release(&g_route_lock);
    return 0;
}

int route_del(uint32_t dest, uint32_t mask) {
    fut_spinlock_acquire(&g_route_lock);
    for (int i = 0; i < NET_ROUTE_MAX; i++) {
        if (g_routes[i].active && g_routes[i].dest == dest &&
            g_routes[i].netmask == mask) {
            g_routes[i].active = false;
            fut_spinlock_release(&g_route_lock);
            return 0;
        }
    }
    fut_spinlock_release(&g_route_lock);
    return -ESRCH;
}

const struct net_route *route_lookup(uint32_t dest_ip) {
    /* Longest prefix match: find the route with the most specific
     * (longest) netmask that matches the destination. */
    const struct net_route *best = NULL;
    uint32_t best_mask = 0;
    uint32_t best_metric = UINT32_MAX;

    for (int i = 0; i < NET_ROUTE_MAX; i++) {
        if (!g_routes[i].active) continue;
        if ((dest_ip & g_routes[i].netmask) == g_routes[i].dest) {
            /* This route matches. Prefer longer mask, then lower metric. */
            uint32_t mask = g_routes[i].netmask;
            if (mask > best_mask ||
                (mask == best_mask && g_routes[i].metric < best_metric)) {
                best = &g_routes[i];
                best_mask = mask;
                best_metric = g_routes[i].metric;
            }
        }
    }
    return best;
}

int route_count(void) {
    int count = 0;
    for (int i = 0; i < NET_ROUTE_MAX; i++)
        if (g_routes[i].active) count++;
    return count;
}

void route_foreach(route_iter_fn fn, void *ctx) {
    if (!fn) return;
    for (int i = 0; i < NET_ROUTE_MAX; i++)
        if (g_routes[i].active) fn(&g_routes[i], ctx);
}

/* ============================================================
 *   IP Forwarding
 * ============================================================ */

int ip_forward(const void *ip_packet, size_t len, struct net_iface *in_iface) {
    if (!g_ip_forward_enabled)
        return -EPERM;

    if (!ip_packet || len < 20)
        return -EINVAL;

    const uint8_t *pkt = (const uint8_t *)ip_packet;

    /* Extract destination IP from IP header (offset 16, 4 bytes) */
    uint32_t dest_ip = ((uint32_t)pkt[16] << 24) | ((uint32_t)pkt[17] << 16) |
                       ((uint32_t)pkt[18] << 8)  | (uint32_t)pkt[19];

    /* Decrement TTL */
    uint8_t ttl = pkt[8];
    if (ttl <= 1) {
        /* TTL expired — should send ICMP Time Exceeded, for now drop */
        if (in_iface) in_iface->rx_dropped++;
        return -ETIMEDOUT;
    }

    /* Look up route */
    const struct net_route *route = route_lookup(dest_ip);
    if (!route) {
        /* No route to host */
        if (in_iface) in_iface->rx_dropped++;
        return -ENETUNREACH;
    }

    struct net_iface *out_iface = netif_by_index(route->iface_idx);
    if (!out_iface || !(out_iface->flags & IFF_UP)) {
        return -ENETUNREACH;
    }

    /* FORWARD chain: filter the packet before forwarding */
    {
        extern int firewall_eval(int chain, const uint8_t *pkt, size_t len, int in_idx, int out_idx);
        int verdict = firewall_eval(1 /* FW_CHAIN_FORWARD */, pkt, len,
                                     in_iface ? in_iface->index : 0,
                                     out_iface->index);
        if (verdict != 0 /* FW_ACCEPT */) {
            if (in_iface) in_iface->rx_dropped++;
            return -EPERM;  /* Packet dropped by firewall */
        }
    }

    /* Check packet size vs MTU */
    if (len > out_iface->mtu) {
        /* Would need fragmentation — not implemented yet */
        return -EMSGSIZE;
    }

    /* Create forwarded packet (modify TTL and recompute checksum) */
    uint8_t fwd_pkt[2048];
    if (len > sizeof(fwd_pkt)) return -EMSGSIZE;
    memcpy(fwd_pkt, pkt, len);

    fwd_pkt[8] = ttl - 1;  /* Decrement TTL */

    /* Recompute IP header checksum */
    size_t hdr_len = (fwd_pkt[0] & 0x0F) * 4;
    fwd_pkt[10] = 0; fwd_pkt[11] = 0;  /* Clear checksum */
    uint32_t sum = 0;
    for (size_t i = 0; i < hdr_len; i += 2) {
        sum += ((uint32_t)fwd_pkt[i] << 8) | fwd_pkt[i + 1];
    }
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    uint16_t cksum = ~(uint16_t)sum;
    fwd_pkt[10] = (uint8_t)(cksum >> 8);
    fwd_pkt[11] = (uint8_t)(cksum & 0xFF);

    /* Apply NAT/masquerade if enabled for the output interface */
    {
        extern int nat_masquerade_out(uint8_t *pkt, size_t len, struct net_iface *out);
        nat_masquerade_out(fwd_pkt, len, out_iface);
    }

    /* Transmit on output interface */
    if (out_iface->transmit) {
        int ret = out_iface->transmit(out_iface, fwd_pkt, len);
        if (ret == 0) {
            out_iface->tx_packets++;
            out_iface->tx_bytes += len;
            if (in_iface) {
                in_iface->rx_packets++;
                in_iface->rx_bytes += len;
            }
        }
        return ret;
    }

    return -EIO;
}
