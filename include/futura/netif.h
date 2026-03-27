/* futura/netif.h - Network interface and routing table for Futura OS
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Provides multi-interface networking support:
 * - Network interface abstraction (struct net_iface)
 * - Interface registry (add/remove/lookup)
 * - Routing table with longest-prefix-match
 * - IP forwarding control (sysctl net.ipv4.ip_forward)
 */

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <futura/tcpip.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Maximum number of network interfaces */
#define NET_IFACE_MAX       16
/* Maximum number of routing table entries */
#define NET_ROUTE_MAX       64
/* Interface name max length */
#define NET_IFNAME_MAX      16

/* Interface flags (matches Linux IFF_*) */
#define IFF_UP              0x0001
#define IFF_BROADCAST       0x0002
#define IFF_LOOPBACK        0x0008
#define IFF_POINTOPOINT     0x0010
#define IFF_RUNNING         0x0040
#define IFF_PROMISC         0x0100
#define IFF_MULTICAST       0x1000

/* Route flags */
#define RTF_UP              0x0001
#define RTF_GATEWAY         0x0002
#define RTF_HOST            0x0004

/* Network interface */
struct net_iface {
    char        name[NET_IFNAME_MAX];   /* e.g., "eth0", "lo", "wlan0" */
    int         index;                  /* Interface index (ifindex) */
    bool        active;
    uint32_t    flags;                  /* IFF_* flags */
    uint32_t    mtu;                    /* Maximum transmission unit */

    /* L2 (link layer) */
    eth_addr_t  mac;                    /* Hardware address */

    /* L3 (network layer) */
    uint32_t    ip_addr;                /* IPv4 address (network byte order) */
    uint32_t    netmask;                /* Subnet mask */
    uint32_t    broadcast;              /* Broadcast address */

    /* Statistics */
    uint64_t    rx_packets;
    uint64_t    tx_packets;
    uint64_t    rx_bytes;
    uint64_t    tx_bytes;
    uint64_t    rx_errors;
    uint64_t    tx_errors;
    uint64_t    rx_dropped;
    uint64_t    tx_dropped;

    /* VLAN (802.1Q) */
    uint16_t    vlan_id;                /* 0 = not a VLAN interface */
    int         parent_idx;             /* Parent interface index (for VLAN sub-ifs) */

    /* Driver callback: transmit a packet on this interface */
    int (*transmit)(struct net_iface *iface, const void *pkt, size_t len);
};

/* Routing table IDs (Linux compatible) */
#define RT_TABLE_UNSPEC     0
#define RT_TABLE_DEFAULT    253
#define RT_TABLE_MAIN       254
#define RT_TABLE_LOCAL      255

/* Routing table entry */
struct net_route {
    bool        active;
    uint32_t    dest;           /* Destination network (host byte order) */
    uint32_t    netmask;        /* Subnet mask */
    uint32_t    gateway;        /* Next-hop gateway (0 = directly connected) */
    int         iface_idx;      /* Output interface index */
    uint32_t    metric;         /* Route metric (lower = preferred) */
    uint32_t    flags;          /* RTF_* flags */
    uint8_t     table_id;       /* Routing table (RT_TABLE_MAIN default) */
};

/* Policy routing rule */
#define NET_RULE_MAX        32
struct net_rule {
    bool        active;
    uint32_t    priority;       /* Rule priority (lower = checked first) */
    uint32_t    src;            /* Source IP to match (0 = any) */
    uint32_t    src_mask;       /* Source netmask */
    uint8_t     table_id;       /* Routing table to use */
    int         iface_idx;      /* Input interface (-1 = any) */
};

/* ---- Interface management ---- */

/* Initialize the networking subsystem */
void netif_init(void);

/* Register a new interface. Returns interface index or negative error. */
int netif_register(const char *name, const eth_addr_t mac, uint32_t mtu,
                   int (*transmit)(struct net_iface *, const void *, size_t));

/* Look up interface by name or index */
struct net_iface *netif_by_name(const char *name);
struct net_iface *netif_by_index(int index);

/* Configure interface IP */
int netif_set_addr(int index, uint32_t ip, uint32_t mask, uint32_t broadcast);

/* Set interface flags (up/down) */
int netif_set_flags(int index, uint32_t flags);

/* Get number of registered interfaces */
int netif_count(void);

/* Iterate all interfaces (for /proc/net/dev) */
typedef void (*netif_iter_fn)(const struct net_iface *iface, void *ctx);
void netif_foreach(netif_iter_fn fn, void *ctx);

/* Create a VLAN sub-interface on parent.
 * Creates "parent.vlan_id" interface that inherits parent MAC.
 * Returns interface index or negative error. */
int netif_create_vlan(int parent_idx, uint16_t vlan_id);

/* ---- Routing table ---- */

/* Add a route. Returns 0 on success. */
int route_add(uint32_t dest, uint32_t mask, uint32_t gateway,
              int iface_idx, uint32_t metric);

/* Delete a route */
int route_del(uint32_t dest, uint32_t mask);

/* Look up route for destination IP (longest prefix match).
 * Returns the matching route or NULL if no route. */
const struct net_route *route_lookup(uint32_t dest_ip);

/* Get number of routes */
int route_count(void);

/* Iterate all routes (for /proc/net/route) */
typedef void (*route_iter_fn)(const struct net_route *route, void *ctx);
void route_foreach(route_iter_fn fn, void *ctx);

/* Add route to a specific table. Returns 0 on success. */
int route_add_table(uint32_t dest, uint32_t mask, uint32_t gateway,
                    int iface_idx, uint32_t metric, uint8_t table_id);

/* Look up route in a specific table */
const struct net_route *route_lookup_table(uint32_t dest_ip, uint8_t table_id);

/* ---- Policy routing rules ---- */

/* Add a policy routing rule. */
int rule_add(uint32_t priority, uint32_t src, uint32_t src_mask,
             uint8_t table_id, int iface_idx);

/* Delete a policy routing rule by priority. */
int rule_del(uint32_t priority);

/* Look up which routing table to use for a given source IP. */
uint8_t rule_lookup(uint32_t src_ip);

/* Get rule count */
int rule_count(void);

/* Iterate rules */
typedef void (*rule_iter_fn)(const struct net_rule *rule, void *ctx);
void rule_foreach(rule_iter_fn fn, void *ctx);

/* ---- IP forwarding ---- */

/* Global forwarding enable (sysctl net.ipv4.ip_forward) */
extern bool g_ip_forward_enabled;

/* Forward an IP packet to the next hop.
 * Called from the IP receive path when dest != local address.
 * Returns 0 on success, negative error on failure. */
int ip_forward(const void *ip_packet, size_t len, struct net_iface *in_iface);

/* ---- SNMP statistics ---- */

/* Global IP/ICMP/TCP/UDP statistics for /proc/net/snmp */
struct net_snmp_stats {
    uint64_t ip_in_receives;
    uint64_t ip_in_delivers;
    uint64_t ip_out_requests;
    uint64_t ip_forwarded;
    uint64_t ip_in_discards;
    uint64_t ip_out_discards;
    uint64_t ip_in_no_routes;
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
    /* TCP counters (RFC 4022 / /proc/net/snmp) */
    uint64_t tcp_active_opens;
    uint64_t tcp_passive_opens;
    uint64_t tcp_attempt_fails;
    uint64_t tcp_estab_resets;
    uint64_t tcp_curr_estab;
    uint64_t tcp_in_segs;
    uint64_t tcp_out_segs;
    uint64_t tcp_retrans_segs;
    uint64_t tcp_in_errs;
    uint64_t tcp_out_rsts;
    /* UDP counters (RFC 4113 / /proc/net/snmp) */
    uint64_t udp_in_datagrams;
    uint64_t udp_no_ports;
    uint64_t udp_in_errors;
    uint64_t udp_out_datagrams;
};

extern struct net_snmp_stats g_net_stats;

/* ---- Network sysctls (tunable via /proc/sys/net/) ---- */

struct net_sysctl {
    uint32_t somaxconn;           /* /proc/sys/net/core/somaxconn (default 4096) */
    uint32_t rmem_max;            /* /proc/sys/net/core/rmem_max (default 16MB) */
    uint32_t wmem_max;            /* /proc/sys/net/core/wmem_max (default 16MB) */
    uint32_t rmem_default;        /* /proc/sys/net/core/rmem_default (default 212992) */
    uint32_t wmem_default;        /* /proc/sys/net/core/wmem_default (default 212992) */
    uint16_t port_range_min;      /* /proc/sys/net/ipv4/ip_local_port_range (min) */
    uint16_t port_range_max;      /* /proc/sys/net/ipv4/ip_local_port_range (max) */
    uint32_t tcp_fin_timeout;     /* /proc/sys/net/ipv4/tcp_fin_timeout (seconds) */
    uint32_t tcp_syncookies;      /* /proc/sys/net/ipv4/tcp_syncookies (0/1/2) */
    uint32_t tcp_keepalive_time;  /* /proc/sys/net/ipv4/tcp_keepalive_time (seconds) */
    uint32_t tcp_keepalive_intvl; /* /proc/sys/net/ipv4/tcp_keepalive_intvl (seconds) */
    uint32_t tcp_keepalive_probes;/* /proc/sys/net/ipv4/tcp_keepalive_probes */
    uint32_t ip_default_ttl;      /* /proc/sys/net/ipv4/ip_default_ttl */
    uint32_t ip_unpriv_port_start;/* /proc/sys/net/ipv4/ip_unprivileged_port_start (default 1024) */
};

extern struct net_sysctl g_net_sysctl;

#ifdef __cplusplus
}
#endif
