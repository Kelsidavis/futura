/* kernel/net/tc.c - Traffic control / QoS subsystem
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements per-interface traffic shaping with token bucket rate limiting
 * and priority queuing. Supports `tc qdisc` and `tc class` configuration
 * via ioctls, compatible with the `tc` shell command.
 *
 * QoS model:
 *   - Each interface has a root qdisc (queuing discipline)
 *   - Default: pfifo_fast (3-band priority FIFO)
 *   - Optional: tbf (token bucket filter) for rate limiting
 *   - Optional: htb (hierarchical token bucket) for class-based shaping
 */

#include <futura/netif.h>
#include <kernel/kprintf.h>
#include <kernel/errno.h>
#include <string.h>

#define TC_MAX_IFACES   16
#define TC_MAX_CLASSES   8

/* Qdisc types */
#define TC_QDISC_PFIFO   0  /* Default priority FIFO */
#define TC_QDISC_TBF     1  /* Token bucket filter */
#define TC_QDISC_HTB     2  /* Hierarchical token bucket */

struct tc_class {
    bool     active;
    uint32_t classid;       /* Major:minor class ID */
    uint64_t rate_bps;      /* Guaranteed rate (bytes/sec) */
    uint64_t ceil_bps;      /* Maximum rate (bytes/sec) */
    uint32_t prio;          /* Priority (lower = higher priority) */
    uint64_t bytes_sent;    /* Statistics: bytes sent through this class */
    uint64_t packets_sent;  /* Statistics: packets sent */
};

struct tc_qdisc {
    bool     active;
    int      iface_idx;     /* Interface index */
    uint8_t  type;          /* TC_QDISC_* */
    uint64_t rate_bps;      /* For TBF: rate in bytes/sec */
    uint64_t burst;         /* For TBF: burst size in bytes */
    uint32_t limit;         /* Queue limit in packets */
    struct tc_class classes[TC_MAX_CLASSES];
    int      class_count;
};

static struct tc_qdisc g_qdiscs[TC_MAX_IFACES];

void tc_init(void) {
    memset(g_qdiscs, 0, sizeof(g_qdiscs));
    fut_printf("[TC] Traffic control subsystem initialized\n");
}

int tc_qdisc_add(int iface_idx, uint8_t type, uint64_t rate_bps, uint64_t burst) {
    if (iface_idx < 0 || iface_idx >= TC_MAX_IFACES)
        return -EINVAL;

    struct net_iface *iface = netif_by_index(iface_idx);
    if (!iface) return -ENODEV;

    /* Find or create qdisc for this interface */
    int slot = -1;
    for (int i = 0; i < TC_MAX_IFACES; i++) {
        if (g_qdiscs[i].active && g_qdiscs[i].iface_idx == iface_idx)
            { slot = i; break; }
    }
    if (slot < 0) {
        for (int i = 0; i < TC_MAX_IFACES; i++) {
            if (!g_qdiscs[i].active) { slot = i; break; }
        }
    }
    if (slot < 0) return -ENOSPC;

    struct tc_qdisc *q = &g_qdiscs[slot];
    q->active = true;
    q->iface_idx = iface_idx;
    q->type = type;
    q->rate_bps = rate_bps;
    q->burst = burst;
    q->limit = 1000;  /* Default packet limit */

    const char *type_name = "pfifo_fast";
    if (type == TC_QDISC_TBF) type_name = "tbf";
    else if (type == TC_QDISC_HTB) type_name = "htb";

    fut_printf("[TC] qdisc %s added to %s (rate=%llu bps)\n",
               type_name, iface->name, (unsigned long long)rate_bps);
    return 0;
}

int tc_class_add(int iface_idx, uint32_t classid, uint64_t rate_bps,
                 uint64_t ceil_bps, uint32_t prio) {
    /* Find qdisc for this interface */
    struct tc_qdisc *q = NULL;
    for (int i = 0; i < TC_MAX_IFACES; i++) {
        if (g_qdiscs[i].active && g_qdiscs[i].iface_idx == iface_idx)
            { q = &g_qdiscs[i]; break; }
    }
    if (!q) return -ENOENT;  /* No qdisc on this interface */
    if (q->class_count >= TC_MAX_CLASSES) return -ENOSPC;

    struct tc_class *c = &q->classes[q->class_count];
    c->active = true;
    c->classid = classid;
    c->rate_bps = rate_bps;
    c->ceil_bps = ceil_bps ? ceil_bps : rate_bps;
    c->prio = prio;
    c->bytes_sent = 0;
    c->packets_sent = 0;
    q->class_count++;

    fut_printf("[TC] class %u:%u added (rate=%llu ceil=%llu prio=%u)\n",
               classid >> 16, classid & 0xFFFF,
               (unsigned long long)rate_bps, (unsigned long long)ceil_bps, prio);
    return 0;
}

int tc_qdisc_show(char *buf, int cap) {
    int pos = 0;
    for (int i = 0; i < TC_MAX_IFACES && pos < cap - 1; i++) {
        if (!g_qdiscs[i].active) continue;
        struct tc_qdisc *q = &g_qdiscs[i];
        struct net_iface *iface = netif_by_index(q->iface_idx);
        const char *tn = q->type == TC_QDISC_TBF ? "tbf" :
                         q->type == TC_QDISC_HTB ? "htb" : "pfifo_fast";
        /* "qdisc <type> dev <name> rate <rate>" */
        const char *s = "qdisc ";
        while (*s && pos < cap-1) buf[pos++] = *s++;
        s = tn;
        while (*s && pos < cap-1) buf[pos++] = *s++;
        s = " dev ";
        while (*s && pos < cap-1) buf[pos++] = *s++;
        if (iface) {
            s = iface->name;
            while (*s && pos < cap-1) buf[pos++] = *s++;
        }
        if (q->rate_bps > 0) {
            s = " rate ";
            while (*s && pos < cap-1) buf[pos++] = *s++;
            /* Format rate */
            uint64_t kbps = q->rate_bps / 1000;
            char num[16]; int ni = 0;
            if (kbps == 0) { num[ni++] = '0'; }
            else { char tmp[16]; int ti = 0;
                while (kbps) { tmp[ti++] = '0' + (int)(kbps % 10); kbps /= 10; }
                for (int j = ti-1; j >= 0; j--) num[ni++] = tmp[j]; }
            s = "Kbit";
            for (int j = 0; j < ni && pos < cap-1; j++) buf[pos++] = num[j];
            while (*s && pos < cap-1) buf[pos++] = *s++;
        }
        if (pos < cap-1) buf[pos++] = '\n';
    }
    return pos;
}
