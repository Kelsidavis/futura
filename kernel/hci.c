/* hci.c - Bluetooth Host Controller Interface (HCI) core
 *
 * Copyright (c) 2026 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implementation of include/kernel/hci.h.  Holds a fixed-size table
 * of registered HCI transports.  No locking inside the registry
 * yet — callers are expected to register / unregister during
 * platform init, and concurrent send_cmd / dispatch_event are
 * serialised by the transport's own locking (which any real
 * Bluetooth controller needs internally regardless).
 */

#include <kernel/hci.h>
#include <kernel/errno.h>
#include <kernel/kprintf.h>
#include <string.h>

static fut_hci_dev_t g_hci_devs[FUT_HCI_MAX_DEVICES];
static bool          g_hci_slot_used[FUT_HCI_MAX_DEVICES];

static bool slot_valid(int idx)
{
    return idx >= 0 && idx < FUT_HCI_MAX_DEVICES && g_hci_slot_used[idx];
}

int fut_hci_register(const char *name,
                     fut_hci_dev_type_t type,
                     const fut_hci_ops_t *ops,
                     void *cookie)
{
    if (!name || !ops) return -EINVAL;
    if (!ops->send_cmd || !ops->open || !ops->close) return -EINVAL;

    for (int i = 0; i < FUT_HCI_MAX_DEVICES; i++) {
        if (g_hci_slot_used[i]) continue;

        fut_hci_dev_t *d = &g_hci_devs[i];
        memset(d, 0, sizeof(*d));

        size_t n = 0;
        while (n < FUT_HCI_NAME_MAX - 1 && name[n] != '\0') {
            d->name[n] = name[n];
            n++;
        }
        d->name[n] = '\0';

        d->type        = type;
        d->ops         = ops;
        d->cookie      = cookie;
        d->open        = false;
        d->event_sink  = NULL;
        d->sink_cookie = NULL;

        g_hci_slot_used[i] = true;
        return i;
    }
    return -ENOMEM;
}

int fut_hci_unregister(int dev_index)
{
    if (dev_index < 0 || dev_index >= FUT_HCI_MAX_DEVICES) return -EINVAL;
    if (!g_hci_slot_used[dev_index]) return 0; /* idempotent */

    fut_hci_dev_t *d = &g_hci_devs[dev_index];
    if (d->open && d->ops && d->ops->close) {
        d->ops->close(d->cookie);
    }
    memset(d, 0, sizeof(*d));
    g_hci_slot_used[dev_index] = false;
    return 0;
}

int fut_hci_dev_count(void)
{
    int n = 0;
    for (int i = 0; i < FUT_HCI_MAX_DEVICES; i++) {
        if (g_hci_slot_used[i]) n++;
    }
    return n;
}

const fut_hci_dev_t *fut_hci_dev_get(int dev_index)
{
    if (!slot_valid(dev_index)) return NULL;
    return &g_hci_devs[dev_index];
}

int fut_hci_dev_find(const char *name)
{
    if (!name) return -EINVAL;
    for (int i = 0; i < FUT_HCI_MAX_DEVICES; i++) {
        if (!g_hci_slot_used[i]) continue;
        if (strncmp(g_hci_devs[i].name, name, FUT_HCI_NAME_MAX) == 0) {
            return i;
        }
    }
    return -ENODEV;
}

int fut_hci_dev_open(int dev_index)
{
    if (!slot_valid(dev_index)) return -ENODEV;
    fut_hci_dev_t *d = &g_hci_devs[dev_index];
    if (d->open) return 0;
    int rc = d->ops->open(d->cookie);
    if (rc == 0) d->open = true;
    return rc;
}

int fut_hci_dev_close(int dev_index)
{
    if (!slot_valid(dev_index)) return -ENODEV;
    fut_hci_dev_t *d = &g_hci_devs[dev_index];
    if (!d->open) return 0;
    d->ops->close(d->cookie);
    d->open = false;
    return 0;
}

int fut_hci_send_cmd(int dev_index, const uint8_t *pkt, size_t len)
{
    if (!pkt || len == 0 || len > FUT_HCI_CMD_PKT_MAX) return -EINVAL;
    if (!slot_valid(dev_index)) return -ENODEV;
    fut_hci_dev_t *d = &g_hci_devs[dev_index];
    if (!d->open) return -ENODEV;
    return d->ops->send_cmd(d->cookie, pkt, len);
}

int fut_hci_set_event_sink(int dev_index,
                           fut_hci_event_sink_t sink,
                           void *sink_cookie)
{
    if (!slot_valid(dev_index)) return -ENODEV;
    g_hci_devs[dev_index].event_sink  = sink;
    g_hci_devs[dev_index].sink_cookie = sink_cookie;
    return 0;
}

int fut_hci_dispatch_event(int dev_index,
                           uint8_t pkt_type,
                           const uint8_t *pkt,
                           size_t len)
{
    if (!slot_valid(dev_index)) return -ENODEV;
    if (!pkt || len == 0) return -EINVAL;
    /* HCI Bluetooth Core Specification §5.4: only packet indicators
     * 0x01-0x05 are valid (CMD, ACL, SCO, EVT, ISO).  A malformed
     * indicator from a flaky transport gets rejected here rather
     * than confusing the sink. */
    if (pkt_type < FUT_HCI_CMD_PKT || pkt_type > FUT_HCI_ISO_PKT) {
        return -EINVAL;
    }

    fut_hci_dev_t *d = &g_hci_devs[dev_index];
    if (!d->event_sink) return 0;  /* silently dropped — no sink */
    return d->event_sink(d->sink_cookie, pkt_type, pkt, len);
}

void fut_hci_reset(void)
{
    for (int i = 0; i < FUT_HCI_MAX_DEVICES; i++) {
        if (g_hci_slot_used[i]) {
            fut_hci_dev_t *d = &g_hci_devs[i];
            if (d->open && d->ops && d->ops->close) {
                d->ops->close(d->cookie);
            }
        }
        memset(&g_hci_devs[i], 0, sizeof(g_hci_devs[i]));
        g_hci_slot_used[i] = false;
    }
}

void fut_hci_open_all(void)
{
    int total = 0, opened = 0, pending = 0;
    for (int i = 0; i < FUT_HCI_MAX_DEVICES; i++) {
        if (!g_hci_slot_used[i]) continue;
        total++;
        int rc = fut_hci_dev_open(i);
        if (rc == 0) {
            opened++;
            fut_printf("[hci%d] %s opened (type=%d)\n",
                       i, g_hci_devs[i].name, (int)g_hci_devs[i].type);
        } else if (rc == -ENOSYS) {
            pending++;
            fut_printf("[hci%d] %s registered, transport pending "
                       "implementation\n", i, g_hci_devs[i].name);
        } else {
            fut_printf("[hci%d] %s open failed: rc=%d\n",
                       i, g_hci_devs[i].name, rc);
        }
    }
    if (total == 0) {
        /* Quiet path — nothing to log when no transports exist. */
        return;
    }
    fut_printf("[hci] %d registered, %d opened, %d pending\n",
               total, opened, pending);
}

void fut_hci_close_all(void)
{
    int closed = 0;
    for (int i = 0; i < FUT_HCI_MAX_DEVICES; i++) {
        if (!g_hci_slot_used[i]) continue;
        if (!g_hci_devs[i].open) continue;
        fut_hci_dev_close(i);
        closed++;
    }
    if (closed > 0) {
        fut_printf("[hci] %d transports closed\n", closed);
    }
}

int fut_hci_build_cmd(uint16_t opcode,
                      const uint8_t *params,
                      uint8_t param_len,
                      uint8_t *out_buf,
                      size_t out_cap)
{
    if (!out_buf) return -EINVAL;
    size_t needed = 3u + param_len;
    if (out_cap < needed) return -EINVAL;
    if (param_len > 0 && !params) return -EINVAL;

    out_buf[0] = (uint8_t)(opcode & 0xFFu);
    out_buf[1] = (uint8_t)((opcode >> 8) & 0xFFu);
    out_buf[2] = param_len;
    if (param_len > 0) {
        memcpy(out_buf + 3, params, param_len);
    }
    return (int)needed;
}

int fut_hci_event_decode_cmd_complete(const uint8_t *pkt,
                                      size_t len,
                                      uint16_t *opcode_out)
{
    if (!pkt || !opcode_out) return 0;
    if (len < 5) return 0;
    if (pkt[0] != FUT_HCI_EVT_CMD_COMPLETE) return 0;
    if (pkt[1] < 3) return 0;  /* param_len must cover num_pkts + opcode */
    *opcode_out = (uint16_t)pkt[3] | ((uint16_t)pkt[4] << 8);
    return 1;
}
