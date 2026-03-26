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

    /* Driver callback: transmit a packet on this interface */
    int (*transmit)(struct net_iface *iface, const void *pkt, size_t len);
};

/* Routing table entry */
struct net_route {
    bool        active;
    uint32_t    dest;           /* Destination network (host byte order) */
    uint32_t    netmask;        /* Subnet mask */
    uint32_t    gateway;        /* Next-hop gateway (0 = directly connected) */
    int         iface_idx;      /* Output interface index */
    uint32_t    metric;         /* Route metric (lower = preferred) */
    uint32_t    flags;          /* RTF_* flags */
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
};

extern struct net_snmp_stats g_net_stats;

#ifdef __cplusplus
}
#endif
