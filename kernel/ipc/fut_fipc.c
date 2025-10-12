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
#include <stddef.h>

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

    size_t total_size = sizeof(struct fut_fipc_msg) + size;

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

    /* Add to channel list */
    channel->next = channel_list;
    channel_list = channel;

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
    if (!channel || !data) {
        return FIPC_EINVAL;
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
        fut_free(msg);
        return rc;
    }

    return fut_fipc_enqueue_message(channel, type, data, size, 0, 0, channel->capability);
}

int fut_fipc_channel_inject(struct fut_fipc_channel *channel,
                            uint32_t type,
                            const void *data,
                            size_t size,
                            uint32_t src_pid,
                            uint32_t dst_pid,
                            uint64_t capability) {
    return fut_fipc_enqueue_message(channel, type, data, size, src_pid, dst_pid, capability);
}

ssize_t fut_fipc_recv(struct fut_fipc_channel *channel, void *buf, size_t buf_size) {
    if (!channel || !buf) {
        return FIPC_EINVAL;
    }

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

    return (ssize_t)total_size;
}

uint32_t fut_fipc_poll(struct fut_fipc_channel *channel, uint32_t mask) {
    if (!channel) {
        return FIPC_EVENT_NONE;
    }

    /* Return pending events matching mask */
    return channel->event_mask & mask;
}
