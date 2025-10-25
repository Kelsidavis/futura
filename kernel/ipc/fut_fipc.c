/* fut_fipc.c - Futura IPC Implementation
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Shared memory regions and event channels for inter-process communication.
 */

#include <kernel/fut_fipc.h>
#include <kernel/fut_fipc_sys.h>
#include <kernel/fut_memory.h>
#include <kernel/fut_timer.h>
#include <kernel/fut_hmac.h>
#include <stddef.h>
#include <string.h>
#include <stdatomic.h>
#include <stdbool.h>

#if FIPC_DEBUG
#ifdef FIPC_HOST_BUILD
#include <stdio.h>
#include <stdlib.h>
#else
extern void fut_printf(const char *fmt, ...);
__attribute__((noreturn)) void fut_platform_panic(const char *message);
#endif
#endif

/* ============================================================
 *   FIPC State
 * ============================================================ */

static struct fut_fipc_region *region_list = NULL;
static struct fut_fipc_channel *channel_list = NULL;
static uint64_t next_region_id = 1;
static uint64_t next_channel_id = 1;

struct fut_fipc_transport_state {
    const struct fut_fipc_transport_ops *ops;
    void *context;
};

static struct fut_fipc_transport_state transport_state = {0};

/* ARM64: Disable atomics for single-core configuration */
#ifdef __aarch64__
static uint64_t next_cap_lease = 1;
#define FIPC_ATOMIC_FETCH_ADD(var, val) ({ uint64_t _old = (var); (var) += (val); _old; })
#define FIPC_ATOMIC_LOAD(var) (var)
#define FIPC_ATOMIC_CAS(var, expected_ptr, new_val) \
    ({ \
        uint64_t old = (var); \
        if (old == *(expected_ptr)) { \
            (var) = (new_val); \
        } else { \
            *(expected_ptr) = old; \
        } \
        (old == *(expected_ptr)); \
    })
#else
static _Atomic uint64_t next_cap_lease = 1;
#define FIPC_ATOMIC_FETCH_ADD(var, val) atomic_fetch_add_explicit(&(var), (val), memory_order_relaxed)
#define FIPC_ATOMIC_LOAD(var) atomic_load_explicit(&(var), memory_order_relaxed)
#define FIPC_ATOMIC_CAS(var, expected_ptr, new_val) \
    atomic_compare_exchange_weak_explicit(&(var), (expected_ptr), (new_val), \
                                          memory_order_relaxed, memory_order_relaxed)
#endif
static void fut_fipc_refill_tokens(struct fut_fipc_channel *channel, uint64_t now);
static int fut_fipc_admin_handle(struct fut_fipc_channel *channel,
                                 const uint8_t *payload,
                                 size_t size);
static uint8_t admin_token_current[FIPC_ADMIN_TOKEN_LEN] = FIPC_ADMIN_TOKEN_DEFAULT_INIT;
static uint8_t admin_hmac_key_current[FIPC_ADMIN_HMAC_KEY_LEN] = FIPC_ADMIN_HMAC_KEY_DEFAULT_INIT;

#define FIPC_STAGE_FLAG_CONSUME_CREDIT 0x01u
#define FIPC_STAGE_FLAG_CONSUME_TOKEN  0x02u
#define FIPC_STAGE_FLAG_VALID          0x80u

static size_t fipc_ring_copy_out(uint8_t *dst,
                                 const uint8_t *ring,
                                 size_t ring_size,
                                 size_t pos,
                                 size_t len) {
    if (len == 0) {
        return pos;
    }
    size_t headroom = ring_size - pos;
    if (len <= headroom) {
        memcpy(dst, ring + pos, len);
        pos += len;
        if (pos == ring_size) {
            pos = 0;
        }
        return pos;
    }
    memcpy(dst, ring + pos, headroom);
    size_t remaining = len - headroom;
    memcpy(dst + headroom, ring, remaining);
    return remaining % ring_size;
}

#if FIPC_DEBUG
void fut_fipc_assert_fail(const char *expr, const char *file, int line) {
#ifdef FIPC_HOST_BUILD
    fprintf(stderr, "[FIPC-ASSERT] %s:%d: %s\n", file, line, expr);
    abort();
#else
    fut_printf("[FIPC-ASSERT] %s:%d: %s\n", file, line, expr);
    fut_platform_panic("FIPC assertion failure");
#endif
}

static inline void fipc_ring_check(struct fut_fipc_channel *ch) {
    if (!ch) {
        return;
    }
    size_t Q = ch->queue_size;
    FIPC_ASSERT(Q > 1);
    size_t h = ch->queue_head % Q;
    size_t t = ch->queue_tail % Q;
    FIPC_ASSERT(h < Q && t < Q);
    size_t used = (h + Q - t) % Q;
    FIPC_ASSERT(used <= Q - 1);
    if (used == 0) {
        FIPC_ASSERT(h == t);
    } else if (used == Q - 1) {
        FIPC_ASSERT(((h + 1) % Q) == t);
    } else {
        FIPC_ASSERT(((h + 1) % Q) != t);
    }
}
#else
void fut_fipc_assert_fail(const char *expr, const char *file, int line) {
    (void)expr;
    (void)file;
    (void)line;
}
static inline void fipc_ring_check(struct fut_fipc_channel *ch) {
    (void)ch;
}
#endif

int fut_fipc_set_transport_ops(const struct fut_fipc_transport_ops *ops, void *context) {
    if (!ops) {
        transport_state.ops = NULL;
        transport_state.context = NULL;
        return 0;
    }

    if (!ops->send) {
        return FIPC_EINVAL;
    }

    transport_state.ops = ops;
    transport_state.context = context;
    return 0;
}

static int fut_fipc_enqueue_message(struct fut_fipc_channel *channel,
                                    uint32_t type,
                                    const void *data,
                                    size_t size,
                                    uint32_t src_pid,
                                    uint32_t dst_pid,
                                    uint64_t capability) {
    if (!channel || (!data && size > 0)) {
        return FIPC_EINVAL;
    }

    fipc_ring_check(channel);

    size_t total_size = sizeof(struct fut_fipc_msg) + size;
    FIPC_ASSERT(channel->queue_size > 0);

    size_t queue_used = (channel->queue_head - channel->queue_tail + channel->queue_size) % channel->queue_size;
    size_t queue_free = channel->queue_size - queue_used - 1;

    if (total_size > queue_free) {
        if (channel->flags & FIPC_CHANNEL_NONBLOCKING) {
            return FIPC_EAGAIN;
        }
        return FIPC_EBUSY;
    }

    struct fut_fipc_msg msg_hdr;
    msg_hdr.type = type;
    msg_hdr.length = size;
    msg_hdr.timestamp = fut_get_ticks();
    msg_hdr.src_pid = src_pid;
    msg_hdr.dst_pid = dst_pid;
    msg_hdr.capability = capability;

    uint8_t *queue_buf = (uint8_t *)channel->msg_queue;
    size_t head = channel->queue_head;

    for (size_t i = 0; i < sizeof(msg_hdr); i++) {
        queue_buf[head] = ((uint8_t *)&msg_hdr)[i];
        head = (head + 1) % channel->queue_size;
    }

    const uint8_t *data_buf = (const uint8_t *)data;
    for (size_t i = 0; i < size; i++) {
        queue_buf[head] = data_buf[i];
        head = (head + 1) % channel->queue_size;
    }

    channel->queue_head = head;
    channel->pending = true;
    channel->event_mask |= FIPC_EVENT_MESSAGE;
    fipc_ring_check(channel);
    return 0;
}

/* ============================================================
 *   FIPC Initialization
 * ============================================================ */

void fut_fipc_init(void) {
    region_list = NULL;
    channel_list = NULL;
    next_region_id = 1;
    next_channel_id = 1;

    struct fut_fipc_channel *sys_channel = NULL;
    if (fut_fipc_channel_create(NULL,
                                NULL,
                                4096,
                                FIPC_CHANNEL_NONBLOCKING,
                                &sys_channel) == 0 && sys_channel) {
        sys_channel->id = FIPC_SYS_CHANNEL_ID;
        sys_channel->type = FIPC_CHANNEL_SYSTEM;
        sys_channel->cap_ledger.rights = FIPC_CAP_R_SEND | FIPC_CAP_R_RECV | FIPC_CAP_R_ADMIN;
        sys_channel->cap_ledger.lease_id = FIPC_ATOMIC_FETCH_ADD(next_cap_lease, 1);
    }

    struct fut_fipc_channel *ctl_channel = NULL;
    if (fut_fipc_channel_create(NULL,
                                NULL,
                                4096,
                                FIPC_CHANNEL_NONBLOCKING,
                                &ctl_channel) == 0 && ctl_channel) {
        ctl_channel->id = FIPC_CTL_CHANNEL_ID;
        ctl_channel->type = FIPC_CHANNEL_SYSTEM;
        ctl_channel->cap_ledger.rights = FIPC_CAP_R_SEND | FIPC_CAP_R_RECV | FIPC_CAP_R_ADMIN;
        ctl_channel->cap_ledger.lease_id = FIPC_ATOMIC_FETCH_ADD(next_cap_lease, 1);
    }
}

/* ============================================================
 *   Shared Memory Regions
 * ============================================================ */

int fut_fipc_region_create(size_t size, uint32_t flags, struct fut_fipc_region **region_out) {
    if (!region_out) {
        return FIPC_EINVAL;
    }

    /* Allocate region structure */
    struct fut_fipc_region *region = fut_malloc(sizeof(struct fut_fipc_region));
    if (!region) {
        return FIPC_ENOMEM;
    }

    /* Allocate backing memory (should be page-aligned) */
    void *base = fut_malloc(size);
    if (!base) {
        fut_free(region);
        return FIPC_ENOMEM;
    }

    /* Initialize region */
    region->id = next_region_id++;
    region->base = base;
    region->size = size;
    region->flags = flags;
    region->refcount = 1;
    region->owner = NULL;  /* Set by caller */
    region->permissions = FIPC_REGION_READ | FIPC_REGION_WRITE;

    /* Add to region list */
    region->next = region_list;
    region_list = region;

    *region_out = region;
    return 0;
}

void fut_fipc_region_destroy(struct fut_fipc_region *region) {
    if (!region) {
        return;
    }

    /* Decrement reference count */
    if (region->refcount > 0) {
        region->refcount--;
    }

    if (region->refcount == 0) {
        /* Remove from region list */
        struct fut_fipc_region **prev = &region_list;
        struct fut_fipc_region *curr = region_list;

        while (curr) {
            if (curr == region) {
                *prev = curr->next;
                break;
            }
            prev = &curr->next;
            curr = curr->next;
        }

        /* Free backing memory */
        if (region->base) {
            fut_free(region->base);
        }

        /* Free region structure */
        fut_free(region);
    }
}

void *fut_fipc_region_map(struct fut_task *task, struct fut_fipc_region *region, void *addr) {
    /* Phase 2: Stub implementation */
    /* Full implementation would:
     * 1. Allocate virtual address range in task's address space
     * 2. Map physical pages to virtual address
     * 3. Set page table entries with appropriate permissions
     */
    (void)task;
    (void)addr;

    if (region) {
        region->refcount++;
        return region->base;  /* Return kernel virtual address */
    }

    return NULL;
}

void fut_fipc_region_unmap(struct fut_task *task, struct fut_fipc_region *region) {
    /* Phase 2: Stub implementation */
    /* Full implementation would:
     * 1. Remove page table mappings
     * 2. Flush TLB
     * 3. Decrement region reference count
     */
    (void)task;

    if (region && region->refcount > 0) {
        region->refcount--;
    }
}

/* ============================================================
 *   Event Channels
 * ============================================================ */

int fut_fipc_channel_create(struct fut_task *sender, struct fut_task *receiver,
                             size_t queue_size, uint32_t flags,
                             struct fut_fipc_channel **channel_out) {
    if (!channel_out) {
        return FIPC_EINVAL;
    }

    /* Allocate channel structure */
    struct fut_fipc_channel *channel = fut_malloc(sizeof(struct fut_fipc_channel));
    if (!channel) {
        return FIPC_ENOMEM;
    }

    /* Allocate message queue */
    void *queue = fut_malloc(queue_size);
    if (!queue) {
        fut_free(channel);
        return FIPC_ENOMEM;
    }

    /* Initialize channel */
    channel->id = next_channel_id++;
    channel->sender = sender;
    channel->receiver = receiver;
    channel->msg_queue = queue;
    channel->queue_size = queue_size;
    channel->queue_head = 0;
    channel->queue_tail = 0;
    channel->pending = false;
    channel->event_mask = 0;
    channel->flags = flags;
    channel->type = FIPC_CHANNEL_LOCAL;
    channel->capability = 0;
    channel->remote.node_id = 0;
    channel->remote.channel_id = 0;
    channel->remote.mtu = 0;
    channel->remote.flags = 0;
    memset(&channel->cap_ledger, 0, sizeof(channel->cap_ledger));
    channel->tx_credits = 0;
    channel->credit_refill = 0;
    channel->credits_enabled = false;
    channel->drops_backpressure = 0;
    channel->drops_deadline = 0;
    channel->pi_applied = 0;
    channel->pi_restored = 0;
    channel->rl_rate_per_ms = 0;
    channel->rl_burst = 0;
    channel->rl_tokens = 0;
    channel->rl_last_tick = 0;
    channel->drops_ratelimit = 0;
    channel->msgs_sent = 0;
    channel->bytes_sent = 0;
    channel->msgs_injected = 0;
    channel->bytes_injected = 0;
    channel->owner_tid = 0;
    channel->owner_original_priority = 0;
    channel->owner_pi_active = false;
    channel->pi_client_tid = 0;

    /* Add to channel list */
    channel->next = channel_list;
    channel_list = channel;

    fipc_ring_check(channel);

    *channel_out = channel;
    return 0;
}

struct fut_fipc_channel *fut_fipc_channel_lookup(uint64_t id) {
    struct fut_fipc_channel *curr = channel_list;
    while (curr) {
        if (curr->id == id) {
            return curr;
        }
        curr = curr->next;
    }
    return NULL;
}

uint64_t fut_fipc_channel_count(void) {
    uint64_t count = 0;
    struct fut_fipc_channel *curr = channel_list;
    while (curr) {
        ++count;
        curr = curr->next;
    }
    return count;
}

int fut_fipc_register_remote(uint64_t channel_id,
                             const struct fut_fipc_remote_endpoint *remote) {
    struct fut_fipc_channel *channel = fut_fipc_channel_lookup(channel_id);
    if (!channel || !remote) {
        return FIPC_EINVAL;
    }

    channel->type = FIPC_CHANNEL_REMOTE;
    channel->remote = *remote;
    return 0;
}

int fut_fipc_bind_capability(struct fut_fipc_channel *channel, uint64_t capability) {
    if (!channel) {
        return FIPC_EINVAL;
    }
    channel->capability = capability;
    return 0;
}

int fut_fipc_cap_bind(struct fut_fipc_channel *channel, const struct fut_fipc_cap *cap) {
    if (!channel || !cap) {
        return FIPC_EINVAL;
    }
    struct fut_fipc_cap new_cap = *cap;
    new_cap.revoke_flags = 0;
    if (new_cap.lease_id == 0) {
        new_cap.lease_id = FIPC_ATOMIC_FETCH_ADD(next_cap_lease, 1);
    } else {
        uint64_t current = FIPC_ATOMIC_LOAD(next_cap_lease);
        while (current <= new_cap.lease_id) {
            uint64_t desired = new_cap.lease_id + 1;
            if (FIPC_ATOMIC_CAS(next_cap_lease, &current, desired)) {
                break;
            }
        }
    }
    channel->cap_ledger = new_cap;
    return 0;
}

int fut_fipc_cap_unbind(struct fut_fipc_channel *channel) {
    if (!channel) {
        return FIPC_EINVAL;
    }
    memset(&channel->cap_ledger, 0, sizeof(channel->cap_ledger));
    channel->credits_enabled = false;
    channel->tx_credits = 0;
    channel->credit_refill = 0;
    return 0;
}

int fut_fipc_cap_revoke(struct fut_fipc_channel *channel, uint32_t revoke_flags) {
    if (!channel) {
        return FIPC_EINVAL;
    }
    channel->cap_ledger.revoke_flags |= revoke_flags;
    return 0;
}

int fut_fipc_set_credits(struct fut_fipc_channel *channel, uint32_t initial, uint32_t refill) {
    if (!channel) {
        return FIPC_EINVAL;
    }
    if (initial == 0 && refill == 0) {
        channel->credits_enabled = false;
        channel->tx_credits = 0;
        channel->credit_refill = 0;
        return 0;
    }
    channel->credits_enabled = true;
    channel->credit_refill = refill;
    channel->tx_credits = initial ? initial : refill;
    return 0;
}

int fut_fipc_refill_credits(struct fut_fipc_channel *channel, uint32_t add) {
    if (!channel) {
        return FIPC_EINVAL;
    }
    if (!channel->credits_enabled) {
        return 0;
    }
    uint64_t current = channel->tx_credits;
    current += add;
    if (channel->credit_refill != 0 && current > channel->credit_refill) {
        current = channel->credit_refill;
    }
    channel->tx_credits = (uint32_t)current;
    return 0;
}

int fut_fipc_set_rate(struct fut_fipc_channel *channel, uint32_t rate_per_ms, uint32_t burst) {
    if (!channel) {
        return FIPC_EINVAL;
    }
    channel->rl_rate_per_ms = rate_per_ms;
    channel->rl_burst = burst;
    if (rate_per_ms == 0 || burst == 0) {
        channel->rl_tokens = 0;
        channel->rl_last_tick = fut_get_ticks();
    } else {
        channel->rl_tokens = burst;
        channel->rl_last_tick = fut_get_ticks();
    }
    return 0;
}

void fut_fipc_channel_destroy(struct fut_fipc_channel *channel) {
    if (!channel) {
        return;
    }

    /* Remove from channel list */
    struct fut_fipc_channel **prev = &channel_list;
    struct fut_fipc_channel *curr = channel_list;

    while (curr) {
        if (curr == channel) {
            *prev = curr->next;
            break;
        }
        prev = &curr->next;
        curr = curr->next;
    }

    /* Free message queue */
    if (channel->msg_queue) {
        fut_free(channel->msg_queue);
    }

    /* Free channel structure */
    fut_free(channel);
}

/* ============================================================
 *   Message Passing
 * ============================================================ */

int fut_fipc_send(struct fut_fipc_channel *channel, uint32_t type,
                  const void *data, size_t size) {
    if (!channel || (!data && size > 0)) {
        return FIPC_EINVAL;
    }

    fut_thread_t *self = fut_thread_current();
    uint64_t now = fut_get_ticks();
    if (self) {
        uint64_t deadline = fut_thread_get_deadline();
        if (deadline && now > deadline) {
            channel->drops_deadline++;
            return FIPC_EAGAIN;
        }
    }

    const struct fut_fipc_cap *cap = &channel->cap_ledger;
    if (cap->revoke_flags & FIPC_CAP_REVOKE_SEND) {
        return FIPC_EPERM;
    }
    if (cap->rights && !(cap->rights & FIPC_CAP_R_SEND)) {
        return FIPC_EPERM;
    }
    if (cap->expiry_tick && now > cap->expiry_tick) {
        return FIPC_EPERM;
    }
    if (cap->max_msgs && channel->msgs_sent >= cap->max_msgs) {
        return FIPC_ENOSPC;
    }
    if (cap->max_bytes && (channel->bytes_sent + size) > cap->max_bytes) {
        return FIPC_ENOSPC;
    }

    if (channel->credits_enabled) {
        if (channel->tx_credits == 0) {
            channel->drops_backpressure++;
            return FIPC_EAGAIN;
        }
    }

    if (channel->rl_rate_per_ms > 0 && channel->rl_burst > 0) {
        fut_fipc_refill_tokens(channel, now);
        if (channel->rl_tokens == 0) {
            channel->drops_ratelimit++;
            return FIPC_EAGAIN;
        }
    }

    if (self && channel->owner_tid && channel->owner_tid != self->tid && !channel->owner_pi_active) {
        fut_thread_t *owner = fut_thread_find(channel->owner_tid);
        if (owner && self->priority > owner->priority) {
            channel->owner_original_priority = owner->priority;
            fut_thread_priority_raise(owner, self->priority);
            channel->owner_pi_active = true;
            channel->pi_client_tid = self->tid;
            channel->pi_applied++;
        }
    }

    if (channel->id == FIPC_CTL_CHANNEL_ID && type == FIPC_SYS_MSG_ADMIN_OP) {
        const uint8_t *payload = (const uint8_t *)data;
        int rc = fut_fipc_admin_handle(channel, payload, size);
        if (rc == 0) {
            if (channel->credits_enabled && channel->tx_credits > 0) {
                channel->tx_credits--;
            }
            if (channel->rl_rate_per_ms > 0 && channel->rl_burst > 0 && channel->rl_tokens > 0) {
                channel->rl_tokens--;
            }
            channel->msgs_sent++;
            channel->bytes_sent += size;
            if (channel->owner_pi_active && self && self->tid == channel->owner_tid) {
                fut_thread_t *owner = fut_thread_find(channel->owner_tid);
                if (owner) {
                    fut_thread_priority_restore(owner);
                }
                channel->owner_pi_active = false;
                channel->pi_restored++;
            }
        }
        return rc;
    }

    if (channel->type == FIPC_CHANNEL_REMOTE) {
        if (!transport_state.ops || !transport_state.ops->send) {
            return FIPC_ENOTSUP;
        }

        size_t total = sizeof(struct fut_fipc_msg) + size;
        if (total == 0 || total > UINT32_MAX) {
            return FIPC_EINVAL;
        }

        if (channel->remote.mtu && total > channel->remote.mtu) {
            return FIPC_EINVAL;
        }

        struct fut_fipc_msg *msg = (struct fut_fipc_msg *)fut_malloc(total);
        if (!msg) {
            return FIPC_ENOMEM;
        }

        msg->type = type;
        msg->length = (uint32_t)size;
        msg->timestamp = fut_get_ticks();
        msg->src_pid = 0;
        msg->dst_pid = 0;
        msg->capability = channel->capability;

        uint8_t *dst = msg->payload;
        const uint8_t *src = (const uint8_t *)data;
        for (size_t i = 0; i < size; i++) {
            dst[i] = src[i];
        }

        struct fut_fipc_net_hdr net_hdr;
        net_hdr.magic = FIPC_NET_MAGIC;
        net_hdr.version = FIPC_NET_V1;
        net_hdr.flags = FIPC_NET_F_NONE;
        net_hdr.reserved = 0;
        net_hdr.seq = 0;
        net_hdr.credits = 0;
        net_hdr.channel_id = channel->remote.channel_id ? channel->remote.channel_id : channel->id;
        net_hdr.payload_len = (uint32_t)total;
        net_hdr.crc = 0;

        int rc = transport_state.ops->send(&channel->remote,
                                           &net_hdr,
                                           (const uint8_t *)msg,
                                           total,
                                           transport_state.context);
        if (rc == 0) {
            if (channel->credits_enabled && channel->tx_credits > 0) {
                channel->tx_credits--;
            }
            if (channel->rl_rate_per_ms > 0 && channel->rl_burst > 0 && channel->rl_tokens > 0) {
                channel->rl_tokens--;
            }
            channel->msgs_sent++;
            channel->bytes_sent += size;
            if (channel->owner_pi_active && self && self->tid == channel->owner_tid) {
                fut_thread_t *owner = fut_thread_find(channel->owner_tid);
                if (owner) {
                    fut_thread_priority_restore(owner);
                }
                channel->owner_pi_active = false;
                channel->pi_restored++;
            }
        }
        fut_free(msg);
        return rc;
    }

    int rc = fut_fipc_enqueue_message(channel, type, data, size, 0, 0, channel->capability);
    if (rc == 0) {
        if (channel->credits_enabled && channel->tx_credits > 0) {
            channel->tx_credits--;
        }
        if (channel->rl_rate_per_ms > 0 && channel->rl_burst > 0 && channel->rl_tokens > 0) {
            channel->rl_tokens--;
        }
        channel->msgs_sent++;
        channel->bytes_sent += size;
        if (channel->owner_pi_active && self && self->tid == channel->owner_tid) {
            fut_thread_t *owner = fut_thread_find(channel->owner_tid);
            if (owner) {
                fut_thread_priority_restore(owner);
            }
            channel->owner_pi_active = false;
            channel->pi_restored++;
        }
    }
    return rc;
}

int fut_fipc_stage_begin(struct fut_fipc_channel *channel,
                         uint32_t type,
                         size_t payload_len,
                         uint8_t **payload_out,
                         struct fut_fipc_stage *stage) {
    if (!channel || !payload_out || !stage) {
        return FIPC_EINVAL;
    }

    fipc_ring_check(channel);

    size_t total_size = sizeof(struct fut_fipc_msg) + payload_len;
    if (total_size >= channel->queue_size) {
        return FIPC_EINVAL;
    }

    uint64_t now = fut_get_ticks();
    const struct fut_fipc_cap *cap = &channel->cap_ledger;

    if (cap->revoke_flags & FIPC_CAP_REVOKE_SEND) {
        return FIPC_EPERM;
    }
    if (cap->rights && !(cap->rights & FIPC_CAP_R_SEND)) {
        return FIPC_EPERM;
    }
    if (cap->expiry_tick && now > cap->expiry_tick) {
        return FIPC_EPERM;
    }
    if (cap->max_msgs && channel->msgs_sent >= cap->max_msgs) {
        return FIPC_ENOSPC;
    }
    if (cap->max_bytes && (channel->bytes_sent + payload_len) > cap->max_bytes) {
        return FIPC_ENOSPC;
    }

    if (channel->credits_enabled && channel->tx_credits == 0) {
        return (channel->flags & FIPC_CHANNEL_NONBLOCKING) ? FIPC_EAGAIN : FIPC_EBUSY;
    }

    if (channel->rl_rate_per_ms > 0 && channel->rl_burst > 0) {
        fut_fipc_refill_tokens(channel, now);
        if (channel->rl_tokens == 0) {
            return FIPC_EAGAIN;
        }
    }

    size_t Q = channel->queue_size;
    size_t head = channel->queue_head;
    size_t tail = channel->queue_tail;
    size_t used = (head + Q - tail) % Q;
    size_t free_bytes = Q - used - 1;
    if (total_size > free_bytes) {
        return (channel->flags & FIPC_CHANNEL_NONBLOCKING) ? FIPC_EAGAIN : FIPC_EBUSY;
    }
    if (head + total_size > Q) {
        return FIPC_EAGAIN;
    }

    struct fut_fipc_msg msg_hdr;
    msg_hdr.type = type;
    msg_hdr.length = (uint32_t)payload_len;
    msg_hdr.timestamp = now;
    msg_hdr.src_pid = 0;
    msg_hdr.dst_pid = 0;
    msg_hdr.capability = channel->capability;

    uint8_t *queue_buf = (uint8_t *)channel->msg_queue;
    memcpy(queue_buf + head, &msg_hdr, sizeof(msg_hdr));
    *payload_out = queue_buf + head + sizeof(msg_hdr);

    stage->type = type;
    stage->payload_len = payload_len;
    stage->ring_pos = head;
    stage->total_size = total_size;
    stage->flags = FIPC_STAGE_FLAG_VALID;
    if (channel->credits_enabled && channel->tx_credits > 0) {
        stage->flags |= FIPC_STAGE_FLAG_CONSUME_CREDIT;
    }
    if (channel->rl_rate_per_ms > 0 && channel->rl_burst > 0 && channel->rl_tokens > 0) {
        stage->flags |= FIPC_STAGE_FLAG_CONSUME_TOKEN;
    }

    return 0;
}

int fut_fipc_stage_commit(struct fut_fipc_channel *channel,
                          struct fut_fipc_stage *stage) {
    if (!channel || !stage || !(stage->flags & FIPC_STAGE_FLAG_VALID)) {
        return FIPC_EINVAL;
    }

    fipc_ring_check(channel);

    size_t Q = channel->queue_size;
    size_t new_head = stage->ring_pos + stage->total_size;
    if (new_head >= Q) {
        new_head -= Q;
    }

    fut_thread_t *self = fut_thread_current();
    if (self && channel->owner_tid && channel->owner_tid != self->tid && !channel->owner_pi_active) {
        fut_thread_t *owner = fut_thread_find(channel->owner_tid);
        if (owner && self->priority > owner->priority) {
            channel->owner_original_priority = owner->priority;
            fut_thread_priority_raise(owner, self->priority);
            channel->owner_pi_active = true;
            channel->pi_client_tid = self->tid;
            channel->pi_applied++;
        }
    }

    channel->queue_head = new_head;
    channel->pending = true;
    channel->event_mask |= FIPC_EVENT_MESSAGE;

    if ((stage->flags & FIPC_STAGE_FLAG_CONSUME_CREDIT) && channel->credits_enabled && channel->tx_credits > 0) {
        channel->tx_credits--;
    }
    if ((stage->flags & FIPC_STAGE_FLAG_CONSUME_TOKEN) && channel->rl_rate_per_ms > 0 && channel->rl_burst > 0 && channel->rl_tokens > 0) {
        channel->rl_tokens--;
    }

    channel->msgs_sent++;
    channel->bytes_sent += stage->payload_len;

    if (channel->owner_pi_active && self && self->tid == channel->owner_tid) {
        fut_thread_t *owner = fut_thread_find(channel->owner_tid);
        if (owner) {
            fut_thread_priority_restore(owner);
        }
        channel->owner_pi_active = false;
        channel->pi_restored++;
    }

    stage->flags = 0;
    stage->total_size = 0;

    fipc_ring_check(channel);
    return 0;
}

int fut_fipc_sendv(struct fut_fipc_channel *channel,
                   uint32_t type,
                   const struct fipc_iovec *iov,
                   size_t iovcnt) {
    if (!channel || (iovcnt == 0 && iov != NULL)) {
        return FIPC_EINVAL;
    }
    if (iovcnt == 0) {
        return fut_fipc_send(channel, type, NULL, 0);
    }
    if (!iov) {
        return FIPC_EINVAL;
    }

    uint64_t total = 0;
    for (size_t i = 0; i < iovcnt; ++i) {
        if (!iov[i].base && iov[i].len > 0) {
            return FIPC_EINVAL;
        }
        total += iov[i].len;
        if (total > SIZE_MAX) {
            return FIPC_EINVAL;
        }
    }

    if (total == 0) {
        return fut_fipc_send(channel, type, NULL, 0);
    }

    uint8_t *buffer = (uint8_t *)fut_malloc((size_t)total);
    if (!buffer) {
        return FIPC_ENOMEM;
    }

    size_t offset = 0;
    for (size_t i = 0; i < iovcnt; ++i) {
        if (iov[i].len == 0) {
            continue;
        }
        memcpy(buffer + offset, iov[i].base, iov[i].len);
        offset += iov[i].len;
    }

    int rc = fut_fipc_send(channel, type, buffer, (size_t)total);
    fut_free(buffer);
    return rc;
}

int fut_fipc_channel_inject(struct fut_fipc_channel *channel,
                            uint32_t type,
                            const void *data,
                            size_t size,
                            uint32_t src_pid,
                            uint32_t dst_pid,
                            uint64_t capability) {
    if (!channel || (!data && size > 0)) {
        return FIPC_EINVAL;
    }

    if (channel->id == FIPC_CTL_CHANNEL_ID && type == FIPC_SYS_MSG_ADMIN_OP) {
        return fut_fipc_admin_handle(channel, (const uint8_t *)data, size);
    }

    const struct fut_fipc_cap *cap = &channel->cap_ledger;
    uint64_t now = fut_get_ticks();
    if (cap->revoke_flags & FIPC_CAP_REVOKE_RECV) {
        return FIPC_EPERM;
    }
    if (cap->rights && !(cap->rights & FIPC_CAP_R_RECV)) {
        return FIPC_EPERM;
    }
    if (cap->expiry_tick && now > cap->expiry_tick) {
        return FIPC_EPERM;
    }
    if (cap->max_msgs && channel->msgs_injected >= cap->max_msgs) {
        return FIPC_ENOSPC;
    }
    if (cap->max_bytes && (channel->bytes_injected + size) > cap->max_bytes) {
        return FIPC_ENOSPC;
    }

    int rc = fut_fipc_enqueue_message(channel, type, data, size, src_pid, dst_pid, capability);
    if (rc == 0) {
        channel->msgs_injected++;
        channel->bytes_injected += size;
    }
    return rc;
}

static uint8_t *fipc_kernel_write_u64(uint8_t *cursor, uint8_t *end, uint8_t tag, uint64_t value) {
    if (cursor >= end) {
        return end;
    }
    *cursor++ = tag;
    cursor = fipc_sys_varint_u64(cursor, value);
    if (cursor > end) {
        return end;
    }
    return cursor;
}

static void fut_fipc_refill_tokens(struct fut_fipc_channel *channel, uint64_t now) {
    if (!channel || channel->rl_rate_per_ms == 0 || channel->rl_burst == 0) {
        return;
    }
    if (channel->rl_last_tick == 0) {
        channel->rl_last_tick = now;
        return;
    }
    uint64_t elapsed = (now > channel->rl_last_tick) ? (now - channel->rl_last_tick) : 0;
    if (elapsed == 0) {
        return;
    }
    uint64_t add = (uint64_t)channel->rl_rate_per_ms * elapsed;
    uint64_t tokens = channel->rl_tokens + add;
    if (tokens > channel->rl_burst) {
        tokens = channel->rl_burst;
    }
    channel->rl_tokens = tokens;
    channel->rl_last_tick = now;
}

static const uint8_t *fipc_admin_read_u64(const uint8_t *cursor,
                                          const uint8_t *end,
                                          uint64_t *out_value) {
    uint64_t value = 0;
    uint32_t shift = 0;
    while (cursor < end) {
        uint8_t byte = *cursor++;
        value |= (uint64_t)(byte & 0x7Fu) << shift;
        if ((byte & 0x80u) == 0) {
            if (out_value) {
                *out_value = value;
            }
            return cursor;
        }
        shift += 7;
        if (shift >= 64) {
            break;
        }
    }
    return NULL;
}

static const uint8_t *fipc_admin_read_bytes(const uint8_t *cursor,
                                            const uint8_t *end,
                                            uint8_t *dest,
                                            size_t dest_cap,
                                            size_t *out_len) {
    uint64_t length = 0;
    cursor = fipc_admin_read_u64(cursor, end, &length);
    if (!cursor) {
        return NULL;
    }
    if (length > dest_cap) {
        return NULL;
    }
    if ((size_t)(end - cursor) < (size_t)length) {
        return NULL;
    }
    if (dest && length > 0) {
        memcpy(dest, cursor, (size_t)length);
    }
    if (out_len) {
        *out_len = (size_t)length;
    }
    return cursor + length;
}

static void fipc_write_le64(uint8_t *dst, uint64_t value) {
    for (size_t i = 0; i < 8; ++i) {
        dst[i] = (uint8_t)((value >> (i * 8)) & 0xFFu);
    }
}

static int fut_fipc_admin_handle(struct fut_fipc_channel *channel,
                                 const uint8_t *payload,
                                 size_t size) {
    if (!channel || (!payload && size > 0)) {
        return FIPC_EINVAL;
    }

    if (!(channel->cap_ledger.rights & FIPC_CAP_R_ADMIN)) {
        return FIPC_EPERM;
    }

    const uint8_t *cursor = payload;
    const uint8_t *end = payload + size;
    if (cursor >= end || *cursor++ != FIPC_ADM_BEGIN) {
        return FIPC_EINVAL;
    }

    struct {
        uint64_t op;
        uint64_t target;
        uint64_t rights;
        uint64_t max_msgs;
        uint64_t max_bytes;
        uint64_t expiry_tick;
        uint64_t revoke;
        uint64_t rate;
        uint64_t burst;
        bool has_op;
        bool has_target;
        bool has_rights;
        bool has_max_msgs;
        bool has_max_bytes;
        bool has_expiry;
        bool has_revoke;
        bool has_rate;
        bool has_burst;
        uint8_t token[FIPC_ADMIN_TOKEN_LEN];
        size_t token_len;
        bool has_token;
        uint64_t lease_id;
        bool has_lease;
        uint8_t hmac[FUT_SHA256_DIGEST_LEN];
        size_t hmac_len;
        bool has_hmac;
    } cmd = {0};

    while (cursor < end) {
        uint8_t tag = *cursor++;
        if (tag == FIPC_ADM_END) {
            break;
        }

        if (tag == FIPC_ADM_TOKEN || tag == FIPC_ADM_HMAC) {
            uint8_t *dest = (tag == FIPC_ADM_TOKEN) ? cmd.token : cmd.hmac;
            size_t cap = (tag == FIPC_ADM_TOKEN) ? sizeof(cmd.token) : sizeof(cmd.hmac);
            size_t len = 0;
            cursor = fipc_admin_read_bytes(cursor, end, dest, cap, &len);
            if (!cursor) {
                return FIPC_EINVAL;
            }
            if (tag == FIPC_ADM_TOKEN) {
                cmd.token_len = len;
                cmd.has_token = true;
            } else {
                cmd.hmac_len = len;
                cmd.has_hmac = true;
            }
            continue;
        }

        uint64_t value = 0;
        cursor = fipc_admin_read_u64(cursor, end, &value);
        if (!cursor) {
            return FIPC_EINVAL;
        }

        switch (tag) {
            case FIPC_ADM_OP:
                cmd.op = value;
                cmd.has_op = true;
                break;
            case FIPC_ADM_TARGET:
                cmd.target = value;
                cmd.has_target = true;
                break;
            case FIPC_ADM_RIGHTS:
                cmd.rights = value;
                cmd.has_rights = true;
                break;
            case FIPC_ADM_MAX_MSGS:
                cmd.max_msgs = value;
                cmd.has_max_msgs = true;
                break;
            case FIPC_ADM_MAX_BYTES:
                cmd.max_bytes = value;
                cmd.has_max_bytes = true;
                break;
            case FIPC_ADM_EXP_TICK:
                cmd.expiry_tick = value;
                cmd.has_expiry = true;
                break;
            case FIPC_ADM_REVOKE:
                cmd.revoke = value;
                cmd.has_revoke = true;
                break;
            case FIPC_ADM_RATE:
                cmd.rate = value;
                cmd.has_rate = true;
                break;
            case FIPC_ADM_BURST:
                cmd.burst = value;
                cmd.has_burst = true;
                break;
            case FIPC_ADM_LEASE:
                cmd.lease_id = value;
                cmd.has_lease = true;
                break;
            default:
                /* Ignore unknown varint tags */
                break;
        }
    }

    if (cursor == NULL || (cursor > payload + size)) {
        return FIPC_EINVAL;
    }

    int rc = 0;
    if (!cmd.has_op || !cmd.has_target) {
        rc = FIPC_EINVAL;
    } else if (!cmd.has_token || cmd.token_len != FIPC_ADMIN_TOKEN_LEN ||
               memcmp(cmd.token, admin_token_current, FIPC_ADMIN_TOKEN_LEN) != 0) {
        rc = FIPC_EPERM;
    } else {
        struct fut_fipc_channel *target = fut_fipc_channel_lookup(cmd.target);
        if (!target) {
            rc = FIPC_EINVAL;
        } else {
            switch ((int)cmd.op) {
            case FIPC_ADM_CAP_BIND: {
                    if (!cmd.has_rights) {
                        rc = FIPC_EINVAL;
                        break;
                    }
                    if (!cmd.has_lease) {
                        rc = FIPC_EINVAL;
                        break;
                    }
                    if (!cmd.has_hmac || cmd.hmac_len != FUT_SHA256_DIGEST_LEN) {
                        rc = FIPC_EPERM;
                        break;
                    }
                    uint8_t material[40];
                    uint8_t *mat = material;
                    fipc_write_le64(mat, cmd.lease_id);
                    mat += 8;
                    fipc_write_le64(mat, cmd.rights);
                    mat += 8;
                    fipc_write_le64(mat, cmd.has_max_msgs ? cmd.max_msgs : 0);
                    mat += 8;
                    fipc_write_le64(mat, cmd.has_max_bytes ? cmd.max_bytes : 0);
                    mat += 8;
                    fipc_write_le64(mat, cmd.has_expiry ? cmd.expiry_tick : 0);

                    uint8_t expected[FUT_SHA256_DIGEST_LEN];
                    fut_hmac_sha256(admin_hmac_key_current,
                                    FIPC_ADMIN_HMAC_KEY_LEN,
                                    material,
                                    sizeof(material),
                                    expected);
                    if (memcmp(expected, cmd.hmac, FUT_SHA256_DIGEST_LEN) != 0) {
                        rc = FIPC_EPERM;
                        break;
                    }

                    struct fut_fipc_cap new_cap = {
                        .rights = (uint32_t)cmd.rights,
                        .revoke_flags = 0,
                        .max_msgs = cmd.has_max_msgs ? cmd.max_msgs : 0,
                        .max_bytes = cmd.has_max_bytes ? cmd.max_bytes : 0,
                        .expiry_tick = cmd.has_expiry ? cmd.expiry_tick : 0,
                        .lease_id = cmd.lease_id,
                    };
                    rc = fut_fipc_cap_bind(target, &new_cap);
                    break;
                }
                case FIPC_ADM_CAP_UNBIND:
                    rc = fut_fipc_cap_unbind(target);
                    break;
                case FIPC_ADM_CAP_REVOKE:
                    if (!cmd.has_revoke) {
                        rc = FIPC_EINVAL;
                        break;
                    }
                    rc = fut_fipc_cap_revoke(target, (uint32_t)cmd.revoke);
                    break;
                case FIPC_ADM_RATE_SET:
                    if (!cmd.has_rate || !cmd.has_burst) {
                        rc = FIPC_EINVAL;
                        break;
                    }
                    rc = fut_fipc_set_rate(target, (uint32_t)cmd.rate, (uint32_t)cmd.burst);
                    break;
                default:
                    rc = FIPC_ENOTSUP;
                    break;
            }
        }
    }

    uint64_t reply_code = (rc < 0) ? (uint64_t)(-rc) : (uint64_t)rc;

    uint8_t reply[64];
    uint8_t *w = reply;
    uint8_t *const reply_end = reply + sizeof(reply);
    if (w < reply_end) {
        *w++ = FIPC_ADM_RP_BEGIN;
        if (w < reply_end) {
            *w++ = FIPC_ADM_RP_CODE;
            w = fipc_sys_varint_u64(w, reply_code);
        }
        if (w < reply_end) {
            *w++ = FIPC_ADM_RP_END;
        }
    }

    size_t reply_len = (size_t)(w - reply);
    int reply_rc = fut_fipc_enqueue_message(channel,
                                            FIPC_SYS_MSG_ADMIN_RP,
                                            reply,
                                            reply_len,
                                            0,
                                            0,
                                            0);
    if (rc == 0 && reply_rc != 0) {
        return reply_rc;
    }
    return rc;
}

size_t fut_fipc_dequeue_bounded(struct fut_fipc_channel *channel, size_t max_msgs) {
    if (!channel || max_msgs == 0) {
        return 0;
    }
    if (channel->queue_size == 0) {
        return 0;
    }
    uint8_t *scratch = (uint8_t *)fut_malloc(channel->queue_size);
    if (!scratch) {
        return 0;
    }
    size_t drained = 0;
    while (drained < max_msgs) {
        ssize_t r = fut_fipc_recv(channel, scratch, channel->queue_size);
        if (r <= 0) {
            if (r == FIPC_EAGAIN) {
                break;
            }
            break;
        }
        drained++;
    }
    fut_free(scratch);
    return drained;
}

int fut_fipc_publish_kernel_metrics(void) {
    struct fut_fipc_channel *sys = fut_fipc_channel_lookup(FIPC_SYS_CHANNEL_ID);
    if (!sys) {
        return FIPC_EINVAL;
    }

    uint64_t channel_count = 0;
    uint64_t msgs_sent = 0;
    uint64_t bytes_sent = 0;
    uint64_t msgs_injected = 0;
    uint64_t bytes_injected = 0;
    uint64_t total_tx_credits = 0;
    uint64_t drops_backpressure = 0;
    uint64_t drops_deadline = 0;
    uint64_t pi_applied = 0;
    uint64_t pi_restored = 0;
    uint64_t total_rl_tokens = 0;
    uint64_t drops_ratelimit = 0;

    for (struct fut_fipc_channel *c = channel_list; c; c = c->next) {
        channel_count++;
        msgs_sent += c->msgs_sent;
        bytes_sent += c->bytes_sent;
        msgs_injected += c->msgs_injected;
        bytes_injected += c->bytes_injected;
        if (c->credits_enabled) {
            total_tx_credits += c->tx_credits;
        }
        drops_backpressure += c->drops_backpressure;
        drops_deadline += c->drops_deadline;
        pi_applied += c->pi_applied;
        pi_restored += c->pi_restored;
        if (c->rl_rate_per_ms > 0 && c->rl_burst > 0) {
            total_rl_tokens += c->rl_tokens;
        }
        drops_ratelimit += c->drops_ratelimit;
    }

    uint64_t pmm_total = fut_pmm_total_pages();
    uint64_t pmm_free = fut_pmm_free_pages();

    uint8_t buffer[192];
    uint8_t *cursor = buffer;
    uint8_t *const end = buffer + sizeof(buffer);

    if (cursor >= end) {
        return FIPC_EIO;
    }
    *cursor++ = FIPC_SYS_K_METRIC_BEGIN;

    cursor = fipc_kernel_write_u64(cursor, end, FIPC_SYS_K_PMM_TOTAL, pmm_total);
    cursor = fipc_kernel_write_u64(cursor, end, FIPC_SYS_K_PMM_FREE, pmm_free);
    cursor = fipc_kernel_write_u64(cursor, end, FIPC_SYS_K_FIPC_CHANNELS, channel_count);
    cursor = fipc_kernel_write_u64(cursor, end, FIPC_SYS_K_TX_CREDITS, total_tx_credits);
    cursor = fipc_kernel_write_u64(cursor, end, FIPC_SYS_K_DROPS_BP, drops_backpressure);
    cursor = fipc_kernel_write_u64(cursor, end, FIPC_SYS_K_DROPS_DEADLINE, drops_deadline);
    cursor = fipc_kernel_write_u64(cursor, end, FIPC_SYS_K_PI_APPLIED, pi_applied);
    cursor = fipc_kernel_write_u64(cursor, end, FIPC_SYS_K_PI_RESTORED, pi_restored);
    cursor = fipc_kernel_write_u64(cursor, end, FIPC_SYS_K_RL_TOKENS, total_rl_tokens);
    cursor = fipc_kernel_write_u64(cursor, end, FIPC_SYS_K_DROPS_RL, drops_ratelimit);

    if (cursor >= end) {
        return FIPC_EIO;
    }
    *cursor++ = FIPC_SYS_K_METRIC_END;

    size_t payload_len = (size_t)(cursor - buffer);
    int rc = fut_fipc_channel_inject(sys,
                                     FIPC_SYS_MSG_KERNEL_METRICS,
                                     buffer,
                                     payload_len,
                                     0,
                                     0,
                                     0);
    if (rc != 0) {
        return rc;
    }

    (void)msgs_sent;
    (void)bytes_sent;
    (void)msgs_injected;
    (void)bytes_injected;

    return 0;
}

ssize_t fut_fipc_recv(struct fut_fipc_channel *channel, void *buf, size_t buf_size) {
    if (!channel || !buf) {
        return FIPC_EINVAL;
    }

    fipc_ring_check(channel);

    /* Check if queue is empty */
    if (channel->queue_head == channel->queue_tail) {
        if (channel->flags & FIPC_CHANNEL_NONBLOCKING) {
            return FIPC_EAGAIN;
        }
        /* For blocking channels, would wait here */
        return 0;
    }

    /* Read message header */
    uint8_t *queue_buf = (uint8_t *)channel->msg_queue;
    size_t tail = channel->queue_tail;

    struct fut_fipc_msg msg_hdr;
    for (size_t i = 0; i < sizeof(msg_hdr); i++) {
        ((uint8_t *)&msg_hdr)[i] = queue_buf[tail];
        tail = (tail + 1) % channel->queue_size;
    }

    /* Check if buffer is large enough */
    size_t total_size = sizeof(msg_hdr) + msg_hdr.length;
    if (total_size > buf_size) {
        return FIPC_EINVAL;
    }

    /* Copy header to buffer */
    uint8_t *dest_buf = (uint8_t *)buf;
    for (size_t i = 0; i < sizeof(msg_hdr); i++) {
        dest_buf[i] = ((uint8_t *)&msg_hdr)[i];
    }

    /* Copy payload to buffer */
    for (size_t i = 0; i < msg_hdr.length; i++) {
        dest_buf[sizeof(msg_hdr) + i] = queue_buf[tail];
        tail = (tail + 1) % channel->queue_size;
    }

    /* Update queue tail */
    channel->queue_tail = tail;

    /* Clear pending flag if queue is now empty */
    if (channel->queue_head == channel->queue_tail) {
        channel->pending = false;
        channel->event_mask &= ~FIPC_EVENT_MESSAGE;
    }
    fipc_ring_check(channel);

    fut_thread_t *receiver = fut_thread_current();
    if (receiver) {
        channel->owner_tid = receiver->tid;
        channel->owner_original_priority = receiver->priority;
        channel->owner_pi_active = false;
        channel->pi_client_tid = 0;
    }

    return (ssize_t)total_size;
}

int fut_fipc_recv_batch(struct fut_fipc_channel *channel,
                        uint8_t *buf,
                        size_t buf_cap,
                        size_t *out_offsets,
                        size_t *out_lengths,
                        size_t max_msgs) {
    if (!channel || !buf || !out_offsets || !out_lengths || max_msgs == 0) {
        return FIPC_EINVAL;
    }

    fipc_ring_check(channel);

    if (channel->queue_head == channel->queue_tail) {
        return FIPC_EAGAIN;
    }

    size_t Q = channel->queue_size;
    uint8_t *queue_buf = (uint8_t *)channel->msg_queue;
    size_t tail = channel->queue_tail;
    size_t consumed = 0;
    size_t count = 0;

    while (count < max_msgs && tail != channel->queue_head) {
        size_t tail_tmp = tail;
        struct fut_fipc_msg msg_hdr;
        tail_tmp = fipc_ring_copy_out((uint8_t *)&msg_hdr, queue_buf, Q, tail_tmp, sizeof(msg_hdr));

        size_t total_size = sizeof(msg_hdr) + msg_hdr.length;
        if (total_size > buf_cap - consumed) {
            break;
        }

        memcpy(buf + consumed, &msg_hdr, sizeof(msg_hdr));
        if (msg_hdr.length > 0) {
            tail_tmp = fipc_ring_copy_out(buf + consumed + sizeof(msg_hdr),
                                          queue_buf,
                                          Q,
                                          tail_tmp,
                                          msg_hdr.length);
        }

        out_offsets[count] = consumed;
        out_lengths[count] = total_size;
        consumed += total_size;
        count++;
        tail = tail_tmp;
    }

    if (count == 0) {
        return FIPC_EAGAIN;
    }

    channel->queue_tail = tail;
    if (channel->queue_head == channel->queue_tail) {
        channel->pending = false;
        channel->event_mask &= ~FIPC_EVENT_MESSAGE;
    }

    fipc_ring_check(channel);
    return (int)count;
}

uint32_t fut_fipc_poll(struct fut_fipc_channel *channel, uint32_t mask) {
    if (!channel) {
        return FIPC_EVENT_NONE;
    }

    /* Return pending events matching mask */
    return channel->event_mask & mask;
}
