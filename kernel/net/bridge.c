/* kernel/net/bridge.c - L2 bridge interface support
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements software L2 bridges that connect multiple network interfaces
 * at the data link layer. Bridge interfaces appear as regular net_iface
 * entries and can be assigned IP addresses for management.
 */

#include <futura/netif.h>
#include <kernel/kprintf.h>
#include <kernel/errno.h>
#include <string.h>

/* Maximum number of bridges and ports per bridge */
#define BRIDGE_MAX          8
#define BRIDGE_PORTS_MAX    8

struct bridge_port {
    int     iface_idx;      /* Slave interface index (0 = empty) */
    bool    active;
};

struct bridge {
    bool                active;
    int                 br_iface_idx;   /* Bridge's own interface index */
    char                name[NET_IFNAME_MAX];
    struct bridge_port  ports[BRIDGE_PORTS_MAX];
    int                 port_count;
    bool                stp_enabled;    /* Spanning Tree Protocol */
    uint32_t            ageing_time;    /* MAC learning timer (seconds) */
};

static struct bridge g_bridges[BRIDGE_MAX];

/* Dummy transmit for bridge interface (no real packet path) */
static int bridge_transmit(struct net_iface *iface, const void *pkt, size_t len) {
    (void)iface; (void)pkt; (void)len;
    return 0;
}

int bridge_create(const char *name) {
    if (!name || name[0] == '\0') return -EINVAL;

    /* Check for duplicate */
    for (int i = 0; i < BRIDGE_MAX; i++) {
        if (g_bridges[i].active) {
            const char *a = g_bridges[i].name;
            const char *b = name;
            while (*a && *b && *a == *b) { a++; b++; }
            if (*a == '\0' && *b == '\0') return -EEXIST;
        }
    }

    /* Find free slot */
    int slot = -1;
    for (int i = 0; i < BRIDGE_MAX; i++) {
        if (!g_bridges[i].active) { slot = i; break; }
    }
    if (slot < 0) return -ENOSPC;

    /* Register as a network interface */
    eth_addr_t br_mac = {0x02, 0x42, 0xBB, 0x00, 0x00, (uint8_t)(slot + 1)};
    int idx = netif_register(name, br_mac, 1500, bridge_transmit);
    if (idx < 0) return idx;

    struct net_iface *iface = netif_by_index(idx);
    if (iface) {
        iface->flags = IFF_UP | IFF_BROADCAST | IFF_RUNNING | IFF_MULTICAST;
    }

    struct bridge *br = &g_bridges[slot];
    memset(br, 0, sizeof(*br));
    br->active = true;
    br->br_iface_idx = idx;
    br->ageing_time = 300;  /* Default: 5 minutes */

    size_t nlen = 0;
    while (name[nlen] && nlen < NET_IFNAME_MAX - 1) nlen++;
    memcpy(br->name, name, nlen);
    br->name[nlen] = '\0';

    fut_printf("[BRIDGE] Created bridge '%s' (idx=%d)\n", name, idx);
    return idx;
}

int bridge_add_port(const char *br_name, const char *port_name) {
    if (!br_name || !port_name) return -EINVAL;

    /* Find bridge */
    struct bridge *br = NULL;
    for (int i = 0; i < BRIDGE_MAX; i++) {
        if (g_bridges[i].active) {
            const char *a = g_bridges[i].name;
            const char *b = br_name;
            while (*a && *b && *a == *b) { a++; b++; }
            if (*a == '\0' && *b == '\0') { br = &g_bridges[i]; break; }
        }
    }
    if (!br) return -ENODEV;

    /* Find port interface */
    struct net_iface *port = netif_by_name(port_name);
    if (!port) return -ENODEV;

    /* Check if already a port of this bridge */
    for (int i = 0; i < BRIDGE_PORTS_MAX; i++) {
        if (br->ports[i].active && br->ports[i].iface_idx == port->index)
            return -EBUSY;
    }

    /* Find free port slot */
    int pslot = -1;
    for (int i = 0; i < BRIDGE_PORTS_MAX; i++) {
        if (!br->ports[i].active) { pslot = i; break; }
    }
    if (pslot < 0) return -ENOSPC;

    br->ports[pslot].active = true;
    br->ports[pslot].iface_idx = port->index;
    br->port_count++;

    fut_printf("[BRIDGE] Added port '%s' to bridge '%s'\n", port_name, br_name);
    return 0;
}

int bridge_del_port(const char *br_name, const char *port_name) {
    if (!br_name || !port_name) return -EINVAL;

    struct bridge *br = NULL;
    for (int i = 0; i < BRIDGE_MAX; i++) {
        if (g_bridges[i].active) {
            const char *a = g_bridges[i].name;
            const char *b = br_name;
            while (*a && *b && *a == *b) { a++; b++; }
            if (*a == '\0' && *b == '\0') { br = &g_bridges[i]; break; }
        }
    }
    if (!br) return -ENODEV;

    struct net_iface *port = netif_by_name(port_name);
    if (!port) return -ENODEV;

    for (int i = 0; i < BRIDGE_PORTS_MAX; i++) {
        if (br->ports[i].active && br->ports[i].iface_idx == port->index) {
            br->ports[i].active = false;
            br->ports[i].iface_idx = 0;
            br->port_count--;
            fut_printf("[BRIDGE] Removed port '%s' from bridge '%s'\n", port_name, br_name);
            return 0;
        }
    }
    return -ENOENT;
}

/* Iterate bridges for /proc/net/bridge */
int bridge_count(void) {
    int count = 0;
    for (int i = 0; i < BRIDGE_MAX; i++)
        if (g_bridges[i].active) count++;
    return count;
}

/* Generate /proc/net/bridge content */
int bridge_show(char *buf, int cap) {
    int pos = 0;
    for (int i = 0; i < BRIDGE_MAX && pos < cap - 1; i++) {
        if (!g_bridges[i].active) continue;
        struct bridge *br = &g_bridges[i];
        /* Bridge name */
        const char *n = br->name;
        while (*n && pos < cap - 1) buf[pos++] = *n++;
        /* STP and ports */
        const char *stp = br->stp_enabled ? " yes " : " no  ";
        while (*stp && pos < cap - 1) buf[pos++] = *stp++;
        /* List ports */
        for (int j = 0; j < BRIDGE_PORTS_MAX; j++) {
            if (!br->ports[j].active) continue;
            struct net_iface *pif = netif_by_index(br->ports[j].iface_idx);
            if (pif) {
                const char *pn = pif->name;
                while (*pn && pos < cap - 1) buf[pos++] = *pn++;
                if (pos < cap - 1) buf[pos++] = ' ';
            }
        }
        if (pos < cap - 1) buf[pos++] = '\n';
    }
    return pos;
}
