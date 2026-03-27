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
#include <kernel/fut_task.h>
#include <kernel/kprintf.h>
#include <kernel/errno.h>
#include <string.h>
#include <stdbool.h>

/* ============================================================
 *   Global State
 * ============================================================ */

extern struct net_namespace *netns_get_init(void);
static struct net_rule g_rules[NET_RULE_MAX];
static fut_spinlock_t g_rule_lock;

bool g_ip_forward_enabled = false;

/* Global IP/ICMP/TCP/UDP statistics — struct defined in include/futura/netif.h */
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

static struct net_namespace *netif_current_ns(void) {
    fut_task_t *task = fut_task_current();
    if (task && task->net_ns) {
        return task->net_ns;
    }
    return netns_get_init();
}

static struct net_namespace *netif_ns_or_init(struct net_namespace *ns) {
    return ns ? ns : netns_get_init();
}

static struct net_iface *netif_by_name_ns(struct net_namespace *ns, const char *name) {
    if (!name) return NULL;
    ns = netif_ns_or_init(ns);
    if (!ns->ifaces) return NULL;
    for (int i = 0; i < NET_IFACE_MAX; i++) {
        if (ns->ifaces[i].active) {
            const char *a = ns->ifaces[i].name;
            const char *b = name;
            while (*a && *b && *a == *b) { a++; b++; }
            if (*a == '\0' && *b == '\0') return &ns->ifaces[i];
        }
    }
    return NULL;
}

static struct net_iface *netif_by_index_ns(struct net_namespace *ns, int index) {
    ns = netif_ns_or_init(ns);
    if (!ns->ifaces) return NULL;
    for (int i = 0; i < NET_IFACE_MAX; i++) {
        if (ns->ifaces[i].active && ns->ifaces[i].index == index) {
            return &ns->ifaces[i];
        }
    }
    return NULL;
}

static int netif_register_ns(struct net_namespace *ns, const char *name, const eth_addr_t mac,
                             uint32_t mtu, int (*transmit)(struct net_iface *, const void *, size_t)) {
    if (!name) return -EINVAL;
    ns = netif_ns_or_init(ns);
    if (!ns->ifaces) return -ENODEV;

    fut_spinlock_acquire(&ns->netif_lock);
    int slot = -1;
    for (int i = 0; i < NET_IFACE_MAX; i++) {
        if (!ns->ifaces[i].active) { slot = i; break; }
    }
    if (slot < 0) {
        fut_spinlock_release(&ns->netif_lock);
        return -ENOSPC;
    }

    struct net_iface *iface = &ns->ifaces[slot];
    memset(iface, 0, sizeof(*iface));
    iface->active = true;
    iface->index = ns->next_ifindex++;
    iface->mtu = mtu ? mtu : 1500;
    iface->transmit = transmit;
    memcpy(iface->mac, mac, ETH_ADDR_LEN);

    size_t nlen = 0;
    while (name[nlen] && nlen < NET_IFNAME_MAX - 1) nlen++;
    memcpy(iface->name, name, nlen);
    iface->name[nlen] = '\0';

    fut_spinlock_release(&ns->netif_lock);
    fut_printf("[NETIF] Registered interface '%s' (ns=%llu idx=%d, mtu=%u)\n",
               iface->name, (unsigned long long)ns->id, iface->index, iface->mtu);
    return iface->index;
}

int netif_netns_init(struct net_namespace *ns) {
    ns = netif_ns_or_init(ns);
    if (!ns->ifaces) {
        ns->ifaces = fut_malloc(sizeof(struct net_iface) * NET_IFACE_MAX);
        if (!ns->ifaces) return -ENOMEM;
    }
    if (!ns->routes) {
        ns->routes = fut_malloc(sizeof(struct net_route) * NET_ROUTE_MAX);
        if (!ns->routes) return -ENOMEM;
    }
    memset(ns->ifaces, 0, sizeof(struct net_iface) * NET_IFACE_MAX);
    memset(ns->routes, 0, sizeof(struct net_route) * NET_ROUTE_MAX);
    fut_spinlock_init(&ns->netif_lock);
    fut_spinlock_init(&ns->route_lock);
    ns->next_ifindex = 1;

    eth_addr_t lo_mac = {0, 0, 0, 0, 0, 0};
    int lo_idx = netif_register_ns(ns, "lo", lo_mac, 65536, lo_transmit);
    if (lo_idx < 0) {
        return lo_idx;
    }

    struct net_iface *lo = netif_by_index_ns(ns, lo_idx);
    if (!lo) {
        return -EIO;
    }
    lo->ip_addr = 0x7F000001;
    lo->netmask = 0xFF000000;
    lo->broadcast = 0x7FFFFFFF;
    lo->flags = IFF_UP | IFF_LOOPBACK | IFF_RUNNING;

    fut_spinlock_acquire(&ns->route_lock);
    ns->routes[0] = (struct net_route){
        .active = true,
        .dest = 0x7F000000,
        .netmask = 0xFF000000,
        .gateway = 0,
        .iface_idx = lo_idx,
        .metric = 0,
        .flags = RTF_UP,
        .table_id = RT_TABLE_MAIN,
    };
    fut_spinlock_release(&ns->route_lock);
    return 0;
}

/* ============================================================
 *   Interface Management
 * ============================================================ */

void netif_init(void) {
    memset(g_rules, 0, sizeof(g_rules));
    fut_spinlock_init(&g_rule_lock);

    struct net_namespace *init_ns = netns_get_init();
    int rc = netif_netns_init(init_ns);
    fut_printf("[NETIF] Network interface subsystem initialized (init-ns=%llu lo-rc=%d)\n",
               (unsigned long long)init_ns->id, rc);
}

int netif_register(const char *name, const eth_addr_t mac, uint32_t mtu,
                   int (*transmit)(struct net_iface *, const void *, size_t)) {
    return netif_register_ns(netif_current_ns(), name, mac, mtu, transmit);
}

struct net_iface *netif_by_name(const char *name) {
    return netif_by_name_ns(netif_current_ns(), name);
}

struct net_iface *netif_by_index(int index) {
    return netif_by_index_ns(netif_current_ns(), index);
}

int netif_set_addr(int index, uint32_t ip, uint32_t mask, uint32_t broadcast) {
    struct net_iface *iface = netif_by_index_ns(netif_current_ns(), index);
    if (!iface) return -ENODEV;
    iface->ip_addr = ip;
    iface->netmask = mask;
    iface->broadcast = broadcast;
    return 0;
}

int netif_set_flags(int index, uint32_t flags) {
    struct net_iface *iface = netif_by_index_ns(netif_current_ns(), index);
    if (!iface) return -ENODEV;
    iface->flags = flags;
    return 0;
}

int netif_create_vlan(int parent_idx, uint16_t vlan_id) {
    if (vlan_id == 0 || vlan_id > 4094) return -EINVAL;
    struct net_namespace *ns = netif_current_ns();

    struct net_iface *parent = netif_by_index_ns(ns, parent_idx);
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
    if (netif_by_name_ns(ns, vname)) return -EEXIST;

    /* Register with parent's MAC, parent's MTU minus 4 (VLAN tag overhead) */
    uint32_t vlan_mtu = parent->mtu > 4 ? parent->mtu - 4 : parent->mtu;
    int idx = netif_register_ns(ns, vname, parent->mac, vlan_mtu, parent->transmit);
    if (idx < 0) return idx;

    struct net_iface *viface = netif_by_index_ns(ns, idx);
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
    struct net_namespace *ns = netif_current_ns();
    if (!ns->ifaces) return 0;
    int count = 0;
    for (int i = 0; i < NET_IFACE_MAX; i++)
        if (ns->ifaces[i].active) count++;
    return count;
}

void netif_foreach(netif_iter_fn fn, void *ctx) {
    struct net_namespace *ns = netif_current_ns();
    if (!fn) return;
    if (!ns->ifaces) return;
    for (int i = 0; i < NET_IFACE_MAX; i++)
        if (ns->ifaces[i].active) fn(&ns->ifaces[i], ctx);
}

/* ============================================================
 *   Routing Table
 * ============================================================ */

int route_add(uint32_t dest, uint32_t mask, uint32_t gateway,
              int iface_idx, uint32_t metric) {
    struct net_namespace *ns = netif_current_ns();
    if (!ns->routes) return -ENODEV;
    fut_spinlock_acquire(&ns->route_lock);
    int slot = -1;
    for (int i = 0; i < NET_ROUTE_MAX; i++) {
        if (!ns->routes[i].active) { slot = i; break; }
    }
    if (slot < 0) {
        fut_spinlock_release(&ns->route_lock);
        return -ENOSPC;
    }

    struct net_route *rt = &ns->routes[slot];
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

    fut_spinlock_release(&ns->route_lock);
    return 0;
}

int route_del(uint32_t dest, uint32_t mask) {
    struct net_namespace *ns = netif_current_ns();
    if (!ns->routes) return -ESRCH;
    fut_spinlock_acquire(&ns->route_lock);
    for (int i = 0; i < NET_ROUTE_MAX; i++) {
        if (ns->routes[i].active && ns->routes[i].dest == dest &&
            ns->routes[i].netmask == mask) {
            ns->routes[i].active = false;
            fut_spinlock_release(&ns->route_lock);
            return 0;
        }
    }
    fut_spinlock_release(&ns->route_lock);
    return -ESRCH;
}

const struct net_route *route_lookup(uint32_t dest_ip) {
    struct net_namespace *ns = netif_current_ns();
    if (!ns->routes) return NULL;
    /* Longest prefix match: find the route with the most specific
     * (longest) netmask that matches the destination. */
    const struct net_route *best = NULL;
    uint32_t best_mask = 0;
    uint32_t best_metric = UINT32_MAX;

    for (int i = 0; i < NET_ROUTE_MAX; i++) {
        if (!ns->routes[i].active) continue;
        if ((dest_ip & ns->routes[i].netmask) == ns->routes[i].dest) {
            /* This route matches. Prefer longer mask, then lower metric. */
            uint32_t mask = ns->routes[i].netmask;
            if (mask > best_mask ||
                (mask == best_mask && ns->routes[i].metric < best_metric)) {
                best = &ns->routes[i];
                best_mask = mask;
                best_metric = ns->routes[i].metric;
            }
        }
    }
    return best;
}

int route_count(void) {
    struct net_namespace *ns = netif_current_ns();
    if (!ns->routes) return 0;
    int count = 0;
    for (int i = 0; i < NET_ROUTE_MAX; i++)
        if (ns->routes[i].active) count++;
    return count;
}

void route_foreach(route_iter_fn fn, void *ctx) {
    struct net_namespace *ns = netif_current_ns();
    if (!fn) return;
    if (!ns->routes) return;
    for (int i = 0; i < NET_ROUTE_MAX; i++)
        if (ns->routes[i].active) fn(&ns->routes[i], ctx);
}

int route_add_table(uint32_t dest, uint32_t mask, uint32_t gateway,
                    int iface_idx, uint32_t metric, uint8_t table_id) {
    struct net_namespace *ns = netif_current_ns();
    if (!ns->routes) return -ENODEV;
    fut_spinlock_acquire(&ns->route_lock);
    int slot = -1;
    for (int i = 0; i < NET_ROUTE_MAX; i++) {
        if (!ns->routes[i].active) { slot = i; break; }
    }
    if (slot < 0) {
        fut_spinlock_release(&ns->route_lock);
        return -ENOSPC;
    }
    struct net_route *rt = &ns->routes[slot];
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
    fut_spinlock_release(&ns->route_lock);
    return 0;
}

const struct net_route *route_lookup_table(uint32_t dest_ip, uint8_t table_id) {
    struct net_namespace *ns = netif_current_ns();
    if (!ns->routes) return NULL;
    const struct net_route *best = NULL;
    uint32_t best_mask = 0;
    uint32_t best_metric = UINT32_MAX;
    for (int i = 0; i < NET_ROUTE_MAX; i++) {
        if (!ns->routes[i].active) continue;
        if (ns->routes[i].table_id != table_id) continue;
        if ((dest_ip & ns->routes[i].netmask) == ns->routes[i].dest) {
            uint32_t mask = ns->routes[i].netmask;
            if (mask > best_mask ||
                (mask == best_mask && ns->routes[i].metric < best_metric)) {
                best = &ns->routes[i];
                best_mask = mask;
                best_metric = ns->routes[i].metric;
            }
        }
    }
    return best;
}

/* ============================================================
 *   Policy Routing Rules
 * ============================================================ */

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

    /* Decrement TTL before fragmentation or forwarding */
    uint8_t new_ttl = ttl - 1;

    /* IP header length in bytes */
    size_t ip_hdr_len = (pkt[0] & 0x0F) * 4;

    /* Helper: recompute IP header checksum in-place */
    #define RECOMPUTE_IP_CKSUM(buf, hlen) do { \
        (buf)[10] = 0; (buf)[11] = 0; \
        uint32_t _s = 0; \
        for (size_t _i = 0; _i < (hlen); _i += 2) \
            _s += ((uint32_t)(buf)[_i] << 8) | (buf)[_i + 1]; \
        while (_s >> 16) _s = (_s & 0xFFFF) + (_s >> 16); \
        uint16_t _c = ~(uint16_t)_s; \
        (buf)[10] = (uint8_t)(_c >> 8); (buf)[11] = (uint8_t)(_c & 0xFF); \
    } while (0)

    /* Check packet size vs MTU — fragment if necessary */
    if (len > out_iface->mtu) {
        /* Check Don't Fragment flag (bit 14 of flags_fragment field) */
        uint16_t flags_frag = ((uint16_t)pkt[6] << 8) | pkt[7];
        if (flags_frag & 0x4000) {
            /* DF set — send ICMP "fragmentation needed" and drop */
            g_net_stats.ip_out_discards++;
            return -EMSGSIZE;
        }

        /* Fragment the packet.
         * Each fragment gets the original IP header (with modified flags/offset/length)
         * plus a chunk of payload. Payload chunks must be 8-byte aligned (except last). */
        size_t payload_len = len - ip_hdr_len;
        size_t max_payload = (out_iface->mtu - ip_hdr_len) & ~7u;  /* 8-byte aligned */
        if (max_payload == 0) return -EMSGSIZE;

        uint16_t orig_id = ((uint16_t)pkt[4] << 8) | pkt[5];
        uint16_t orig_frag_off = flags_frag & 0x1FFF;  /* original fragment offset */
        int orig_mf = (flags_frag & 0x2000) != 0;  /* original More Fragments flag */
        (void)orig_id;

        uint8_t frag_pkt[2048];
        size_t offset = 0;
        int frag_count = 0;

        while (offset < payload_len) {
            size_t chunk = payload_len - offset;
            int is_last = 1;
            if (chunk > max_payload) {
                chunk = max_payload;
                is_last = 0;
            }

            /* Build fragment: copy IP header + payload chunk */
            size_t frag_total = ip_hdr_len + chunk;
            if (frag_total > sizeof(frag_pkt)) return -EMSGSIZE;

            memcpy(frag_pkt, pkt, ip_hdr_len);
            memcpy(frag_pkt + ip_hdr_len, pkt + ip_hdr_len + offset, chunk);

            /* Update TTL */
            frag_pkt[8] = new_ttl;

            /* Update total length */
            frag_pkt[2] = (uint8_t)(frag_total >> 8);
            frag_pkt[3] = (uint8_t)(frag_total & 0xFF);

            /* Update fragment offset and flags.
             * Fragment offset is in 8-byte units.
             * MF (More Fragments) = 0x2000 if not last fragment. */
            uint16_t frag_off = orig_frag_off + (uint16_t)(offset / 8);
            uint16_t frag_flags = 0;
            if (!is_last || orig_mf)
                frag_flags |= 0x2000;  /* MF flag */
            frag_pkt[6] = (uint8_t)((frag_flags | frag_off) >> 8);
            frag_pkt[7] = (uint8_t)((frag_flags | frag_off) & 0xFF);

            /* Recompute IP header checksum */
            RECOMPUTE_IP_CKSUM(frag_pkt, ip_hdr_len);

            /* Apply NAT if needed */
            {
                extern int nat_masquerade_out(uint8_t *p, size_t l, struct net_iface *o);
                nat_masquerade_out(frag_pkt, frag_total, out_iface);
            }

            /* Transmit fragment */
            if (out_iface->transmit) {
                int ret = out_iface->transmit(out_iface, frag_pkt, frag_total);
                if (ret != 0) {
                    g_net_stats.ip_out_discards++;
                    return ret;
                }
                out_iface->tx_packets++;
                out_iface->tx_bytes += frag_total;
            }

            offset += chunk;
            frag_count++;
        }

        g_net_stats.ip_forwarded++;
        g_net_stats.ip_out_requests += (uint64_t)frag_count;
        if (in_iface) {
            in_iface->rx_packets++;
            in_iface->rx_bytes += len;
        }
        return 0;
    }

    /* Packet fits in MTU — forward without fragmentation */
    uint8_t fwd_pkt[2048];
    if (len > sizeof(fwd_pkt)) return -EMSGSIZE;
    memcpy(fwd_pkt, pkt, len);

    fwd_pkt[8] = new_ttl;  /* Decrement TTL */

    /* Recompute IP header checksum */
    RECOMPUTE_IP_CKSUM(fwd_pkt, ip_hdr_len);

    #undef RECOMPUTE_IP_CKSUM

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
