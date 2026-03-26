/* kernel/net/filter.c - Packet filtering (firewall) for Futura OS
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Simple iptables-like packet filter with three chains:
 * - INPUT:   packets destined for this host
 * - FORWARD: packets being routed through this host
 * - OUTPUT:  packets originating from this host
 *
 * Each chain has a default policy (ACCEPT/DROP) and a list of rules.
 * Rules match on: protocol, source/dest IP+mask, source/dest port, interface.
 * Actions: ACCEPT, DROP, REJECT (send ICMP unreachable).
 */

#include <futura/netif.h>
#include <kernel/fut_memory.h>
#include <kernel/fut_sched.h>
#include <kernel/kprintf.h>
#include <kernel/errno.h>
#include <string.h>
#include <stdbool.h>

/* Filter actions */
#define FW_ACCEPT   0
#define FW_DROP     1
#define FW_REJECT   2

/* Filter chains */
#define FW_CHAIN_INPUT    0
#define FW_CHAIN_FORWARD  1
#define FW_CHAIN_OUTPUT   2
#define FW_CHAIN_COUNT    3

/* Maximum rules per chain */
#define FW_RULES_MAX  64

/* A single firewall rule */
struct fw_rule {
    bool        active;
    uint8_t     action;         /* FW_ACCEPT, FW_DROP, FW_REJECT */
    uint8_t     protocol;       /* 0=any, 6=TCP, 17=UDP, 1=ICMP */
    uint32_t    src_ip;         /* Source IP (0 = any) */
    uint32_t    src_mask;       /* Source mask */
    uint32_t    dst_ip;         /* Destination IP (0 = any) */
    uint32_t    dst_mask;       /* Destination mask */
    uint16_t    src_port_min;   /* Source port range min (0 = any) */
    uint16_t    src_port_max;
    uint16_t    dst_port_min;   /* Destination port range (0 = any) */
    uint16_t    dst_port_max;
    int         in_iface;       /* Input interface index (0 = any) */
    int         out_iface;      /* Output interface index (0 = any) */
    uint64_t    packets;        /* Match counter */
    uint64_t    bytes;
};

/* A filter chain */
struct fw_chain {
    uint8_t         default_policy;  /* FW_ACCEPT or FW_DROP */
    struct fw_rule  rules[FW_RULES_MAX];
    int             rule_count;
};

static struct fw_chain g_chains[FW_CHAIN_COUNT];
static fut_spinlock_t  g_fw_lock;

/* ============================================================
 *   Initialization
 * ============================================================ */

void firewall_init(void) {
    memset(g_chains, 0, sizeof(g_chains));
    fut_spinlock_init(&g_fw_lock);

    /* Default policies: ACCEPT everything (permissive by default) */
    g_chains[FW_CHAIN_INPUT].default_policy = FW_ACCEPT;
    g_chains[FW_CHAIN_FORWARD].default_policy = FW_ACCEPT;
    g_chains[FW_CHAIN_OUTPUT].default_policy = FW_ACCEPT;

    fut_printf("[FIREWALL] Packet filter initialized (3 chains, %d rules/chain)\n",
               FW_RULES_MAX);
}

/* ============================================================
 *   Rule Management
 * ============================================================ */

/* Add a rule to a chain. Returns rule index or negative error. */
int firewall_add_rule(int chain, uint8_t action, uint8_t protocol,
                      uint32_t src_ip, uint32_t src_mask,
                      uint32_t dst_ip, uint32_t dst_mask,
                      uint16_t dst_port_min, uint16_t dst_port_max) {
    if (chain < 0 || chain >= FW_CHAIN_COUNT) return -EINVAL;
    if (action > FW_REJECT) return -EINVAL;

    fut_spinlock_acquire(&g_fw_lock);
    struct fw_chain *c = &g_chains[chain];
    if (c->rule_count >= FW_RULES_MAX) {
        fut_spinlock_release(&g_fw_lock);
        return -ENOSPC;
    }

    int slot = c->rule_count++;
    struct fw_rule *r = &c->rules[slot];
    memset(r, 0, sizeof(*r));
    r->active = true;
    r->action = action;
    r->protocol = protocol;
    r->src_ip = src_ip;
    r->src_mask = src_mask;
    r->dst_ip = dst_ip;
    r->dst_mask = dst_mask;
    r->dst_port_min = dst_port_min;
    r->dst_port_max = dst_port_max;

    fut_spinlock_release(&g_fw_lock);
    return slot;
}

/* Set the default policy for a chain */
int firewall_set_policy(int chain, uint8_t policy) {
    if (chain < 0 || chain >= FW_CHAIN_COUNT) return -EINVAL;
    if (policy > FW_DROP) return -EINVAL;
    g_chains[chain].default_policy = policy;
    return 0;
}

/* Flush all rules from a chain */
int firewall_flush(int chain) {
    if (chain < 0 || chain >= FW_CHAIN_COUNT) return -EINVAL;
    fut_spinlock_acquire(&g_fw_lock);
    g_chains[chain].rule_count = 0;
    memset(g_chains[chain].rules, 0, sizeof(g_chains[chain].rules));
    fut_spinlock_release(&g_fw_lock);
    return 0;
}

/* ============================================================
 *   Packet Matching
 * ============================================================ */

/* Check if a packet matches a rule */
static bool rule_matches(const struct fw_rule *r,
                         uint8_t proto, uint32_t src_ip, uint32_t dst_ip,
                         uint16_t src_port, uint16_t dst_port,
                         int in_idx, int out_idx) {
    /* Protocol match */
    if (r->protocol != 0 && r->protocol != proto)
        return false;

    /* Source IP match */
    if (r->src_ip != 0 && (src_ip & r->src_mask) != (r->src_ip & r->src_mask))
        return false;

    /* Destination IP match */
    if (r->dst_ip != 0 && (dst_ip & r->dst_mask) != (r->dst_ip & r->dst_mask))
        return false;

    /* Destination port match */
    if (r->dst_port_min != 0 || r->dst_port_max != 0) {
        if (dst_port < r->dst_port_min || dst_port > r->dst_port_max)
            return false;
    }

    /* Source port match */
    if (r->src_port_min != 0 || r->src_port_max != 0) {
        if (src_port < r->src_port_min || src_port > r->src_port_max)
            return false;
    }

    /* Interface match */
    if (r->in_iface != 0 && r->in_iface != in_idx)
        return false;
    if (r->out_iface != 0 && r->out_iface != out_idx)
        return false;

    return true;
}

/* Evaluate a packet against a chain. Returns FW_ACCEPT or FW_DROP. */
int firewall_eval(int chain, const uint8_t *pkt, size_t len,
                  int in_iface_idx, int out_iface_idx) {
    if (chain < 0 || chain >= FW_CHAIN_COUNT || !pkt || len < 20)
        return FW_ACCEPT;

    /* Extract fields from IP header */
    uint8_t proto = pkt[9];
    uint32_t src_ip = ((uint32_t)pkt[12] << 24) | ((uint32_t)pkt[13] << 16) |
                      ((uint32_t)pkt[14] << 8)  | (uint32_t)pkt[15];
    uint32_t dst_ip = ((uint32_t)pkt[16] << 24) | ((uint32_t)pkt[17] << 16) |
                      ((uint32_t)pkt[18] << 8)  | (uint32_t)pkt[19];

    uint8_t ihl = (pkt[0] & 0x0F) * 4;
    uint16_t src_port = 0, dst_port = 0;
    if ((proto == 6 || proto == 17) && len >= (size_t)ihl + 4) {
        src_port = ((uint16_t)pkt[ihl] << 8) | pkt[ihl + 1];
        dst_port = ((uint16_t)pkt[ihl + 2] << 8) | pkt[ihl + 3];
    }

    struct fw_chain *c = &g_chains[chain];

    /* Check rules in order (first match wins) */
    for (int i = 0; i < c->rule_count; i++) {
        struct fw_rule *r = &c->rules[i];
        if (!r->active) continue;

        if (rule_matches(r, proto, src_ip, dst_ip, src_port, dst_port,
                        in_iface_idx, out_iface_idx)) {
            r->packets++;
            r->bytes += len;
            return r->action;
        }
    }

    /* No rule matched — use chain default policy */
    return c->default_policy;
}

/* Get rule count for a chain */
int firewall_rule_count(int chain) {
    if (chain < 0 || chain >= FW_CHAIN_COUNT) return 0;
    return g_chains[chain].rule_count;
}

/* Get default policy for a chain */
int firewall_get_policy(int chain) {
    if (chain < 0 || chain >= FW_CHAIN_COUNT) return FW_ACCEPT;
    return g_chains[chain].default_policy;
}
