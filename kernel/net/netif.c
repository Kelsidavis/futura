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

/* Global IP/ICMP/TCP/UDP statistics for /proc/net/snmp */
struct net_snmp_stats {
    /* IP */
    uint64_t ip_in_receives;
    uint64_t ip_in_delivers;
    uint64_t ip_out_requests;
    uint64_t ip_forwarded;
    uint64_t ip_in_discards;
    uint64_t ip_out_discards;
    uint64_t ip_in_no_routes;
    /* ICMP */
    uint64_t icmp_in_msgs;
    uint64_t icmp_in_errors;
    uint64_t icmp_out_msgs;
    uint64_t icmp_out_errors;
    uint64_t icmp_in_echo;
    uint64_t icmp_in_echo_reply;
    uint64_t icmp_out_echo;
    uint64_t icmp_out_echo_reply;
    uint64_t icmp_out_time_exceeded;
    uint64_t icmp_out_dest_unreachable;
};

struct net_snmp_stats g_net_stats;

/* Writable network sysctls with Linux-compatible defaults */
struct net_sysctl g_net_sysctl = {
    .somaxconn          = 4096,
    .rmem_max           = 16777216,
    .wmem_max           = 16777216,
    .rmem_default       = 212992,
    .wmem_default       = 212992,
    .port_range_min     = 32768,  /* ip_local_port_range min (ephemeral) */
    .port_range_max     = 60999,  /* ip_local_port_range max */
    .tcp_fin_timeout    = 60,
    .tcp_syncookies     = 1,
    .tcp_keepalive_time = 7200,
    .tcp_keepalive_intvl= 75,
    .tcp_keepalive_probes=9,
    .ip_default_ttl     = 64,
    .ip_unpriv_port_start = 1024,
};

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

int netif_create_vlan(int parent_idx, uint16_t vlan_id) {
    if (vlan_id == 0 || vlan_id > 4094) return -EINVAL;

    struct net_iface *parent = netif_by_index(parent_idx);
    if (!parent) return -ENODEV;

    /* Build name: "eth0.100" */
    char vname[NET_IFNAME_MAX];
    int pos = 0;
    const char *p = parent->name;
    while (*p && pos < NET_IFNAME_MAX - 6) vname[pos++] = *p++;
    vname[pos++] = '.';
    if (vlan_id >= 1000) vname[pos++] = (char)('0' + vlan_id / 1000);
    if (vlan_id >= 100)  vname[pos++] = (char)('0' + (vlan_id / 100) % 10);
    if (vlan_id >= 10)   vname[pos++] = (char)('0' + (vlan_id / 10) % 10);
    vname[pos++] = (char)('0' + vlan_id % 10);
    vname[pos] = '\0';

    /* Check for duplicate */
    if (netif_by_name(vname)) return -EEXIST;

    /* Register with parent's MAC, parent's MTU minus 4 (VLAN tag overhead) */
    uint32_t vlan_mtu = parent->mtu > 4 ? parent->mtu - 4 : parent->mtu;
    int idx = netif_register(vname, parent->mac, vlan_mtu, parent->transmit);
    if (idx < 0) return idx;

    struct net_iface *viface = netif_by_index(idx);
    if (viface) {
        viface->vlan_id = vlan_id;
        viface->parent_idx = parent_idx;
        viface->flags = IFF_UP | IFF_BROADCAST | IFF_RUNNING;
    }

    fut_printf("[NETIF] Created VLAN interface '%s' (vid=%u, parent=%s)\n",
               vname, vlan_id, parent->name);
    return idx;
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
    rt->table_id = RT_TABLE_MAIN;

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

int route_add_table(uint32_t dest, uint32_t mask, uint32_t gateway,
                    int iface_idx, uint32_t metric, uint8_t table_id) {
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
    rt->table_id = table_id;
    fut_spinlock_release(&g_route_lock);
    return 0;
}

const struct net_route *route_lookup_table(uint32_t dest_ip, uint8_t table_id) {
    const struct net_route *best = NULL;
    uint32_t best_mask = 0;
    uint32_t best_metric = UINT32_MAX;
    for (int i = 0; i < NET_ROUTE_MAX; i++) {
        if (!g_routes[i].active) continue;
        if (g_routes[i].table_id != table_id) continue;
        if ((dest_ip & g_routes[i].netmask) == g_routes[i].dest) {
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

/* ============================================================
 *   Policy Routing Rules
 * ============================================================ */

static struct net_rule g_rules[NET_RULE_MAX];
static fut_spinlock_t g_rule_lock;

int rule_add(uint32_t priority, uint32_t src, uint32_t src_mask,
             uint8_t table_id, int iface_idx) {
    fut_spinlock_acquire(&g_rule_lock);
    /* Check for duplicate priority */
    for (int i = 0; i < NET_RULE_MAX; i++) {
        if (g_rules[i].active && g_rules[i].priority == priority) {
            fut_spinlock_release(&g_rule_lock);
            return -EEXIST;
        }
    }
    int slot = -1;
    for (int i = 0; i < NET_RULE_MAX; i++) {
        if (!g_rules[i].active) { slot = i; break; }
    }
    if (slot < 0) {
        fut_spinlock_release(&g_rule_lock);
        return -ENOSPC;
    }
    struct net_rule *r = &g_rules[slot];
    r->active = true;
    r->priority = priority;
    r->src = src;
    r->src_mask = src_mask;
    r->table_id = table_id;
    r->iface_idx = iface_idx;
    fut_spinlock_release(&g_rule_lock);
    fut_printf("[RULE] Added rule prio=%u src=%u.%u.%u.%u/%u table=%u\n",
               priority,
               (src >> 24) & 0xFF, (src >> 16) & 0xFF,
               (src >> 8) & 0xFF, src & 0xFF,
               src_mask ? __builtin_popcount(src_mask) : 0,
               table_id);
    return 0;
}

int rule_del(uint32_t priority) {
    fut_spinlock_acquire(&g_rule_lock);
    for (int i = 0; i < NET_RULE_MAX; i++) {
        if (g_rules[i].active && g_rules[i].priority == priority) {
            g_rules[i].active = false;
            fut_spinlock_release(&g_rule_lock);
            return 0;
        }
    }
    fut_spinlock_release(&g_rule_lock);
    return -ESRCH;
}

uint8_t rule_lookup(uint32_t src_ip) {
    /* Walk rules in priority order (lowest priority value first) */
    uint32_t best_prio = UINT32_MAX;
    uint8_t best_table = RT_TABLE_MAIN;
    for (int i = 0; i < NET_RULE_MAX; i++) {
        if (!g_rules[i].active) continue;
        if (g_rules[i].priority >= best_prio) continue;
        /* Match source IP */
        if (g_rules[i].src_mask == 0 ||
            (src_ip & g_rules[i].src_mask) == g_rules[i].src) {
            best_prio = g_rules[i].priority;
            best_table = g_rules[i].table_id;
        }
    }
    return best_table;
}

int rule_count(void) {
    int count = 0;
    for (int i = 0; i < NET_RULE_MAX; i++)
        if (g_rules[i].active) count++;
    return count;
}

void rule_foreach(rule_iter_fn fn, void *ctx) {
    if (!fn) return;
    for (int i = 0; i < NET_RULE_MAX; i++)
        if (g_rules[i].active) fn(&g_rules[i], ctx);
}

/* ============================================================
 *   IP Forwarding
 * ============================================================ */

/* Send ICMP error message (Time Exceeded or Dest Unreachable).
 * Per RFC 792: ICMP error contains IP header + first 8 bytes of original datagram. */
static void send_icmp_error(uint8_t icmp_type, uint8_t icmp_code,
                            const uint8_t *orig_pkt, size_t orig_len,
                            struct net_iface *out_iface) {
    if (!out_iface || out_iface->ip_addr == 0) return;
    /* Don't send ICMP errors for ICMP errors (avoid loops) */
    if (orig_len >= 20 && orig_pkt[9] == 1 /* ICMP */) {
        /* Check if original is already an ICMP error (type != 0 and type != 8) */
        size_t ihl = (orig_pkt[0] & 0x0F) * 4;
        if (orig_len > ihl) {
            uint8_t orig_icmp_type = orig_pkt[ihl];
            if (orig_icmp_type != 0 && orig_icmp_type != 8) return;
        }
    }

    /* Extract source IP from original packet (who we're replying to) */
    uint32_t src_ip = ((uint32_t)orig_pkt[12] << 24) | ((uint32_t)orig_pkt[13] << 16) |
                      ((uint32_t)orig_pkt[14] << 8) | (uint32_t)orig_pkt[15];

    /* Build ICMP error: IP header (20) + ICMP header (8) + orig IP header + 8 bytes */
    size_t orig_ihl = (orig_pkt[0] & 0x0F) * 4;
    size_t copy_len = orig_ihl + 8;
    if (copy_len > orig_len) copy_len = orig_len;
    size_t total = 20 + 8 + copy_len; /* IP + ICMP + payload */

    uint8_t buf[128];
    if (total > sizeof(buf)) return;
    memset(buf, 0, total);

    /* IP header */
    buf[0] = 0x45;  /* IPv4, IHL=5 */
    buf[1] = 0xC0;  /* TOS: CS6 (network control) */
    buf[2] = (uint8_t)(total >> 8); buf[3] = (uint8_t)(total & 0xFF);
    buf[6] = 0x40;  /* Don't Fragment */
    buf[8] = (uint8_t)g_net_sysctl.ip_default_ttl;  /* TTL from sysctl */
    buf[9] = 1;     /* Protocol: ICMP */
    /* Source: our interface IP */
    buf[12] = (uint8_t)(out_iface->ip_addr >> 24);
    buf[13] = (uint8_t)(out_iface->ip_addr >> 16);
    buf[14] = (uint8_t)(out_iface->ip_addr >> 8);
    buf[15] = (uint8_t)(out_iface->ip_addr);
    /* Dest: original packet's source */
    buf[16] = (uint8_t)(src_ip >> 24);
    buf[17] = (uint8_t)(src_ip >> 16);
    buf[18] = (uint8_t)(src_ip >> 8);
    buf[19] = (uint8_t)(src_ip);
    /* IP checksum */
    uint32_t sum = 0;
    for (int i = 0; i < 20; i += 2)
        sum += ((uint32_t)buf[i] << 8) | buf[i + 1];
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    uint16_t ck = ~(uint16_t)sum;
    buf[10] = (uint8_t)(ck >> 8); buf[11] = (uint8_t)(ck & 0xFF);

    /* ICMP header at offset 20 */
    buf[20] = icmp_type;
    buf[21] = icmp_code;
    /* buf[22..23] = checksum (computed below) */
    /* buf[24..27] = unused (zero for Time Exceeded/Dest Unreachable) */

    /* Copy original IP header + 8 bytes of payload */
    memcpy(buf + 28, orig_pkt, copy_len);

    /* ICMP checksum (over ICMP header + data) */
    size_t icmp_len = 8 + copy_len;
    sum = 0;
    for (size_t i = 0; i < icmp_len; i += 2) {
        uint16_t word = (uint16_t)buf[20 + i] << 8;
        if (i + 1 < icmp_len) word |= buf[20 + i + 1];
        sum += word;
    }
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    ck = ~(uint16_t)sum;
    buf[22] = (uint8_t)(ck >> 8); buf[23] = (uint8_t)(ck & 0xFF);

    /* Transmit via the interface (if it has a transmit callback) */
    if (out_iface->transmit)
        out_iface->transmit(out_iface, buf, total);
}

int ip_forward(const void *ip_packet, size_t len, struct net_iface *in_iface) {
    if (!g_ip_forward_enabled)
        return -EPERM;

    if (!ip_packet || len < 20)
        return -EINVAL;

    const uint8_t *pkt = (const uint8_t *)ip_packet;

    /* Extract destination IP from IP header (offset 16, 4 bytes) */
    uint32_t dest_ip = ((uint32_t)pkt[16] << 24) | ((uint32_t)pkt[17] << 16) |
                       ((uint32_t)pkt[18] << 8)  | (uint32_t)pkt[19];

    g_net_stats.ip_in_receives++;

    /* Decrement TTL */
    uint8_t ttl = pkt[8];
    if (ttl <= 1) {
        /* TTL expired — send ICMP Time Exceeded (type 11, code 0) */
        if (in_iface)
            send_icmp_error(11 /* TIME_EXCEEDED */, 0, pkt, len, in_iface);
        g_net_stats.icmp_out_time_exceeded++;
        g_net_stats.icmp_out_msgs++;
        g_net_stats.ip_in_discards++;
        if (in_iface) in_iface->rx_dropped++;
        return -ETIMEDOUT;
    }

    /* Look up route */
    const struct net_route *route = route_lookup(dest_ip);
    if (!route) {
        /* No route to host — send ICMP Destination Unreachable (type 3, code 0) */
        if (in_iface)
            send_icmp_error(3 /* DEST_UNREACHABLE */, 0 /* net unreachable */, pkt, len, in_iface);
        g_net_stats.icmp_out_dest_unreachable++;
        g_net_stats.icmp_out_msgs++;
        g_net_stats.ip_in_no_routes++;
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
            g_net_stats.ip_forwarded++;
            g_net_stats.ip_out_requests++;
            out_iface->tx_packets++;
            out_iface->tx_bytes += len;
            if (in_iface) {
                in_iface->rx_packets++;
                in_iface->rx_bytes += len;
            }
        } else {
            g_net_stats.ip_out_discards++;
        }
        return ret;
    }

    return -EIO;
}
