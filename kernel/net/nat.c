/* kernel/net/nat.c - Network Address Translation (NAT/masquerade)
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements source NAT (SNAT/masquerade) for router OS:
 * - Outbound: rewrite source IP to the outgoing interface's IP,
 *   allocate a unique port, and track the connection in a NAT table.
 * - Inbound: reverse the translation using the NAT table, restoring
 *   the original source IP and port.
 *
 * Supports TCP and UDP. ICMP uses query ID for mapping.
 * NAT entries expire after a configurable timeout.
 */

#include <futura/netif.h>
#include <kernel/fut_memory.h>
#include <kernel/fut_sched.h>
#include <kernel/fut_timer.h>
#include <kernel/kprintf.h>
#include <kernel/errno.h>
#include <string.h>
#include <stdbool.h>

/* NAT table size and timeouts */
#define NAT_TABLE_SIZE      1024
#define NAT_TCP_TIMEOUT_MS  (300 * 1000)   /* 5 minutes for TCP */
#define NAT_UDP_TIMEOUT_MS  (30 * 1000)    /* 30 seconds for UDP */
#define NAT_ICMP_TIMEOUT_MS (30 * 1000)    /* 30 seconds for ICMP */

/* Port allocation range for masqueraded connections */
#define NAT_PORT_MIN        49152
#define NAT_PORT_MAX        65535

/* NAT connection tracking entry */
struct nat_entry {
    bool        active;
    uint8_t     protocol;       /* IP_PROTO_TCP=6, UDP=17, ICMP=1 */
    uint32_t    orig_src_ip;    /* Original source (private) IP */
    uint16_t    orig_src_port;  /* Original source port */
    uint32_t    orig_dst_ip;    /* Original destination IP */
    uint16_t    orig_dst_port;  /* Original destination port */
    uint32_t    nat_ip;         /* Translated (public) IP */
    uint16_t    nat_port;       /* Translated port */
    int         out_iface_idx;  /* Outgoing interface */
    uint64_t    last_seen_ms;   /* Timestamp for expiry */
    uint64_t    packets;        /* Packet counter */
    uint64_t    bytes;          /* Byte counter */
};

static struct nat_entry g_nat_table[NAT_TABLE_SIZE];
static fut_spinlock_t   g_nat_lock;
static uint16_t         g_nat_port_next = NAT_PORT_MIN;

/* Global masquerade control: set to an interface index to enable SNAT
 * on all traffic forwarded out that interface. 0 = disabled. */
int g_masquerade_iface = 0;

/* ============================================================
 *   NAT Table Management
 * ============================================================ */

void nat_init(void) {
    memset(g_nat_table, 0, sizeof(g_nat_table));
    fut_spinlock_init(&g_nat_lock);
    g_nat_port_next = NAT_PORT_MIN;
    fut_printf("[NAT] NAT/masquerade subsystem initialized (%d entries)\n", NAT_TABLE_SIZE);
}

/* Allocate a unique NAT port */
static uint16_t nat_alloc_port(void) {
    uint16_t port = g_nat_port_next;
    if (g_nat_port_next == NAT_PORT_MAX)
        g_nat_port_next = NAT_PORT_MIN;
    else
        g_nat_port_next++;
    return port;
}

/* Find an existing NAT entry for an outbound packet */
static struct nat_entry *nat_find_outbound(uint8_t proto,
                                            uint32_t src_ip, uint16_t src_port,
                                            uint32_t dst_ip, uint16_t dst_port) {
    for (int i = 0; i < NAT_TABLE_SIZE; i++) {
        struct nat_entry *e = &g_nat_table[i];
        if (e->active && e->protocol == proto &&
            e->orig_src_ip == src_ip && e->orig_src_port == src_port &&
            e->orig_dst_ip == dst_ip && e->orig_dst_port == dst_port)
            return e;
    }
    return NULL;
}

/* Find a NAT entry for an inbound (reply) packet */
static struct nat_entry *nat_find_inbound(uint8_t proto,
                                           uint32_t src_ip, uint16_t src_port,
                                           uint32_t dst_ip, uint16_t dst_port) {
    for (int i = 0; i < NAT_TABLE_SIZE; i++) {
        struct nat_entry *e = &g_nat_table[i];
        if (e->active && e->protocol == proto &&
            e->orig_dst_ip == src_ip && e->orig_dst_port == src_port &&
            e->nat_ip == dst_ip && e->nat_port == dst_port)
            return e;
    }
    return NULL;
}

/* Create a new NAT entry */
static struct nat_entry *nat_create(uint8_t proto,
                                     uint32_t src_ip, uint16_t src_port,
                                     uint32_t dst_ip, uint16_t dst_port,
                                     uint32_t nat_ip, int out_idx) {
    /* Expire old entries first */
    uint64_t now = fut_get_ticks() * 10;  /* Convert ticks to ms */
    for (int i = 0; i < NAT_TABLE_SIZE; i++) {
        if (!g_nat_table[i].active) continue;
        uint64_t timeout = (g_nat_table[i].protocol == 6) ? NAT_TCP_TIMEOUT_MS :
                           (g_nat_table[i].protocol == 17) ? NAT_UDP_TIMEOUT_MS :
                           NAT_ICMP_TIMEOUT_MS;
        if (now - g_nat_table[i].last_seen_ms > timeout)
            g_nat_table[i].active = false;
    }

    /* Find free slot */
    for (int i = 0; i < NAT_TABLE_SIZE; i++) {
        if (!g_nat_table[i].active) {
            struct nat_entry *e = &g_nat_table[i];
            e->active = true;
            e->protocol = proto;
            e->orig_src_ip = src_ip;
            e->orig_src_port = src_port;
            e->orig_dst_ip = dst_ip;
            e->orig_dst_port = dst_port;
            e->nat_ip = nat_ip;
            e->nat_port = nat_alloc_port();
            e->out_iface_idx = out_idx;
            e->last_seen_ms = now;
            e->packets = 0;
            e->bytes = 0;
            return e;
        }
    }
    return NULL;  /* Table full */
}

/* ============================================================
 *   IP/TCP/UDP Checksum Helpers
 * ============================================================ */

__attribute__((unused))
static uint16_t ip_checksum(const void *data, size_t len) {
    const uint8_t *p = (const uint8_t *)data;
    uint32_t sum = 0;
    for (size_t i = 0; i < len; i += 2) {
        if (i + 1 < len)
            sum += ((uint32_t)p[i] << 8) | p[i + 1];
        else
            sum += (uint32_t)p[i] << 8;
    }
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

/* Incremental checksum update when changing a 32-bit field (RFC 1624) */
static void checksum_update_ip(uint8_t *cksum_ptr, uint32_t old_val, uint32_t new_val) {
    uint32_t sum = ((uint32_t)cksum_ptr[0] << 8) | cksum_ptr[1];
    sum = ~sum & 0xFFFF;
    /* Subtract old, add new (16-bit words) */
    sum -= (old_val >> 16) & 0xFFFF; if (sum >> 31) sum--; sum &= 0xFFFF;
    sum -= old_val & 0xFFFF;         if (sum >> 31) sum--; sum &= 0xFFFF;
    sum += (new_val >> 16) & 0xFFFF; if (sum > 0xFFFF) { sum -= 0xFFFF; }
    sum += new_val & 0xFFFF;         if (sum > 0xFFFF) { sum -= 0xFFFF; }
    sum = ~sum & 0xFFFF;
    cksum_ptr[0] = (uint8_t)(sum >> 8);
    cksum_ptr[1] = (uint8_t)(sum & 0xFF);
}

/* Iterate active NAT entries for /proc/net/nf_conntrack */
typedef void (*nat_foreach_fn)(uint8_t proto, uint32_t orig_src, uint16_t orig_sport,
                               uint32_t orig_dst, uint16_t orig_dport,
                               uint32_t nat_ip, uint16_t nat_port,
                               uint64_t packets, uint64_t bytes, void *ctx);

int nat_foreach(nat_foreach_fn cb, void *ctx) {
    int count = 0;
    fut_spinlock_acquire(&g_nat_lock);
    for (int i = 0; i < NAT_TABLE_SIZE; i++) {
        if (g_nat_table[i].active) {
            cb(g_nat_table[i].protocol,
               g_nat_table[i].orig_src_ip, g_nat_table[i].orig_src_port,
               g_nat_table[i].orig_dst_ip, g_nat_table[i].orig_dst_port,
               g_nat_table[i].nat_ip, g_nat_table[i].nat_port,
               g_nat_table[i].packets, g_nat_table[i].bytes, ctx);
            count++;
        }
    }
    fut_spinlock_release(&g_nat_lock);
    return count;
}

/* ============================================================
 *   NAT Packet Rewriting
 * ============================================================ */

/* Apply SNAT (masquerade) to an outbound forwarded packet.
 * Returns 0 if NAT was applied, -1 if not applicable. */
int nat_masquerade_out(uint8_t *pkt, size_t len, struct net_iface *out_iface) {
    if (!out_iface || !pkt || len < 20) return -1;
    if (g_masquerade_iface == 0 || out_iface->index != g_masquerade_iface)
        return -1;  /* Masquerade not enabled for this interface */

    uint8_t ihl = (pkt[0] & 0x0F) * 4;
    uint8_t proto = pkt[9];
    uint32_t src_ip = ((uint32_t)pkt[12] << 24) | ((uint32_t)pkt[13] << 16) |
                      ((uint32_t)pkt[14] << 8)  | (uint32_t)pkt[15];

    uint16_t src_port = 0, dst_port = 0;
    if ((proto == 6 || proto == 17) && len >= (size_t)ihl + 4) {
        src_port = ((uint16_t)pkt[ihl] << 8) | pkt[ihl + 1];
        dst_port = ((uint16_t)pkt[ihl + 2] << 8) | pkt[ihl + 3];
    } else if (proto == 1 && len >= (size_t)ihl + 4) {
        /* ICMP: use ID as "port" */
        src_port = ((uint16_t)pkt[ihl + 4] << 8) | pkt[ihl + 5];
        dst_port = 0;
    }

    uint32_t dst_ip = ((uint32_t)pkt[16] << 24) | ((uint32_t)pkt[17] << 16) |
                      ((uint32_t)pkt[18] << 8)  | (uint32_t)pkt[19];

    fut_spinlock_acquire(&g_nat_lock);

    /* Find or create NAT entry */
    struct nat_entry *entry = nat_find_outbound(proto, src_ip, src_port, dst_ip, dst_port);
    if (!entry) {
        entry = nat_create(proto, src_ip, src_port, dst_ip, dst_port,
                          out_iface->ip_addr, out_iface->index);
    }

    if (!entry) {
        fut_spinlock_release(&g_nat_lock);
        return -1;  /* NAT table full */
    }

    entry->last_seen_ms = fut_get_ticks() * 10;
    entry->packets++;
    entry->bytes += len;

    uint32_t new_src_ip = entry->nat_ip;
    uint16_t new_src_port = entry->nat_port;

    fut_spinlock_release(&g_nat_lock);

    /* Rewrite source IP in IP header */
    uint32_t old_src = ((uint32_t)pkt[12] << 24) | ((uint32_t)pkt[13] << 16) |
                       ((uint32_t)pkt[14] << 8)  | pkt[15];
    pkt[12] = (uint8_t)(new_src_ip >> 24);
    pkt[13] = (uint8_t)(new_src_ip >> 16);
    pkt[14] = (uint8_t)(new_src_ip >> 8);
    pkt[15] = (uint8_t)(new_src_ip);

    /* Update IP header checksum incrementally */
    checksum_update_ip(&pkt[10], old_src, new_src_ip);

    /* Rewrite source port in TCP/UDP header */
    if ((proto == 6 || proto == 17) && len >= (size_t)ihl + 4) {
        pkt[ihl]     = (uint8_t)(new_src_port >> 8);
        pkt[ihl + 1] = (uint8_t)(new_src_port);
        /* Clear L4 checksum (simplified — full recalc needed for production) */
        if (proto == 6 && len >= (size_t)ihl + 18) {
            pkt[ihl + 16] = 0; pkt[ihl + 17] = 0;
        } else if (proto == 17 && len >= (size_t)ihl + 8) {
            pkt[ihl + 6] = 0; pkt[ihl + 7] = 0;  /* UDP checksum optional */
        }
    }

    return 0;
}

/* Apply reverse NAT (de-masquerade) to an inbound reply packet.
 * Returns 0 if NAT was applied, -1 if no matching entry. */
int nat_demasquerade_in(uint8_t *pkt, size_t len) {
    if (!pkt || len < 20) return -1;

    uint8_t ihl = (pkt[0] & 0x0F) * 4;
    uint8_t proto = pkt[9];
    uint32_t src_ip = ((uint32_t)pkt[12] << 24) | ((uint32_t)pkt[13] << 16) |
                      ((uint32_t)pkt[14] << 8)  | (uint32_t)pkt[15];
    uint32_t dst_ip = ((uint32_t)pkt[16] << 24) | ((uint32_t)pkt[17] << 16) |
                      ((uint32_t)pkt[18] << 8)  | (uint32_t)pkt[19];

    uint16_t src_port = 0, dst_port = 0;
    if ((proto == 6 || proto == 17) && len >= (size_t)ihl + 4) {
        src_port = ((uint16_t)pkt[ihl] << 8) | pkt[ihl + 1];
        dst_port = ((uint16_t)pkt[ihl + 2] << 8) | pkt[ihl + 3];
    }

    fut_spinlock_acquire(&g_nat_lock);
    struct nat_entry *entry = nat_find_inbound(proto, src_ip, src_port, dst_ip, dst_port);
    if (!entry) {
        fut_spinlock_release(&g_nat_lock);
        return -1;
    }

    entry->last_seen_ms = fut_get_ticks() * 10;
    entry->packets++;
    entry->bytes += len;

    uint32_t orig_dst_ip = entry->orig_src_ip;
    uint16_t orig_dst_port = entry->orig_src_port;

    fut_spinlock_release(&g_nat_lock);

    /* Rewrite destination IP back to original private IP */
    pkt[16] = (uint8_t)(orig_dst_ip >> 24);
    pkt[17] = (uint8_t)(orig_dst_ip >> 16);
    pkt[18] = (uint8_t)(orig_dst_ip >> 8);
    pkt[19] = (uint8_t)(orig_dst_ip);

    /* Update IP header checksum */
    checksum_update_ip(&pkt[10], dst_ip, orig_dst_ip);

    /* Rewrite destination port */
    if ((proto == 6 || proto == 17) && len >= (size_t)ihl + 4) {
        pkt[ihl + 2] = (uint8_t)(orig_dst_port >> 8);
        pkt[ihl + 3] = (uint8_t)(orig_dst_port);
        if (proto == 17 && len >= (size_t)ihl + 8) {
            pkt[ihl + 6] = 0; pkt[ihl + 7] = 0;
        }
    }

    return 0;
}

/* Get NAT table statistics */
int nat_active_count(void) {
    int count = 0;
    for (int i = 0; i < NAT_TABLE_SIZE; i++)
        if (g_nat_table[i].active) count++;
    return count;
}
