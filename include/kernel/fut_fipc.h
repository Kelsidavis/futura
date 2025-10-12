/* fut_fipc.h - Futura Inter-Process Communication (FIPC)
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Shared memory channels and event-driven IPC for FuturaWay and userland services.
 */

#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* Freestanding environment: define ssize_t */
#ifndef _SSIZE_T_DEFINED
#define _SSIZE_T_DEFINED
typedef long ssize_t;
#endif

/* Forward declarations */
struct fut_task;
struct fut_fipc_channel;
struct fut_fipc_region;

/* ============================================================
 *   Shared Memory Region
 * ============================================================ */

/**
 * FIPC shared memory region.
 * Allows processes to share memory for zero-copy communication.
 */
struct fut_fipc_region {
    uint64_t id;                    /* Unique region ID */
    void *base;                     /* Base address (kernel virtual) */
    size_t size;                    /* Size in bytes */
    uint32_t flags;                 /* Region flags */
    uint32_t refcount;              /* Reference count */

    /* Access control */
    struct fut_task *owner;         /* Owning task */
    uint32_t permissions;           /* Access permissions */

    struct fut_fipc_region *next;   /* Next in region list */
};

/* Region flags */
#define FIPC_REGION_READ        (1 << 0)
#define FIPC_REGION_WRITE       (1 << 1)
#define FIPC_REGION_EXEC        (1 << 2)
#define FIPC_REGION_SHARED      (1 << 3)
#define FIPC_REGION_DEVICE      (1 << 4)

/* ============================================================
 *   Event Channel
 * ============================================================ */

/**
 * FIPC event channel.
 * Allows processes to send asynchronous events and messages.
 */
enum fut_fipc_channel_type {
    FIPC_CHANNEL_LOCAL = 0,
    FIPC_CHANNEL_REMOTE = 1,
    FIPC_CHANNEL_SYSTEM = 2
};

struct fut_fipc_remote_endpoint {
    uint64_t node_id;
    uint64_t channel_id;
    uint32_t mtu;
    uint32_t flags;
};

#define FIPC_CAP_R_SEND   (1u << 0)
#define FIPC_CAP_R_RECV   (1u << 1)
#define FIPC_CAP_R_SYS    (1u << 2)
#define FIPC_CAP_R_ADMIN  (1u << 3)

struct fut_fipc_cap {
    uint32_t rights;
    uint32_t revoke_flags;
    uint64_t max_msgs;
    uint64_t max_bytes;
    uint64_t expiry_tick;
    uint64_t lease_id;
};

/**
 * Header framing for remote FIPC transport packets.
 * Serialized ahead of the canonical fut_fipc_msg payload.
 */
#define FIPC_NET_MAGIC  0x31435046u /* 'FPC1' little-endian */
#define FIPC_NET_V1     1
#define FIPC_NET_F_NONE 0u
#define FIPC_NET_F_ACK  1u
#define FIPC_NET_F_CRED 2u

struct fut_fipc_net_hdr {
    uint32_t magic;
    uint8_t  version;
    uint8_t  flags;
    uint16_t reserved;
    uint32_t seq;
    uint32_t credits;
    uint64_t channel_id;
    uint32_t payload_len;
    uint32_t crc;
};

/**
 * Remote transport backend hooks supplied by networking stack.
 * Implementations must provide a send function that emits framed packets.
 */
struct fut_fipc_transport_ops {
    int (*send)(const struct fut_fipc_remote_endpoint *remote,
                const struct fut_fipc_net_hdr *hdr,
                const uint8_t *payload,
                size_t payload_len,
                void *context);
};

/* Capability revoke flags */
#define FIPC_CAP_REVOKE_SEND  (1u << 0)
#define FIPC_CAP_REVOKE_RECV  (1u << 1)

struct fut_fipc_channel {
    uint64_t id;                    /* Unique channel ID */

    /* Endpoints */
    struct fut_task *sender;        /* Sending task */
    struct fut_task *receiver;      /* Receiving task */

    /* Message queue */
    void *msg_queue;                /* Circular message buffer */
    size_t queue_size;              /* Queue size in bytes */
    size_t queue_head;              /* Queue head (write index) */
    size_t queue_tail;              /* Queue tail (read index) */

    /* Event notification */
    bool pending;                   /* Events pending */
    uint32_t event_mask;            /* Event type mask */

    uint32_t flags;                 /* Channel flags */
    enum fut_fipc_channel_type type;/* Transport classification */
    uint64_t capability;            /* Capability token */
    struct fut_fipc_remote_endpoint remote; /* Remote metadata */
    struct fut_fipc_cap cap_ledger; /* Capability + quota descriptor */
    uint32_t tx_credits;            /* Remaining transmit credits (0 = unlimited) */
    uint32_t credit_refill;         /* Window refill size (0 = unlimited) */
    bool credits_enabled;           /* Credits enforced when true */
    uint8_t _pad_credit[3];         /* align */
    uint64_t drops_backpressure;    /* Count of send rejections due to credits */
    uint64_t drops_deadline;        /* Deadline miss counter */
    uint64_t pi_applied;            /* Priority inheritance applied count */
    uint64_t pi_restored;           /* Priority inheritance restored count */
    uint32_t rl_rate_per_ms;        /* Token bucket rate (msgs/ms) */
    uint32_t rl_burst;              /* Token bucket burst capacity */
    uint64_t rl_tokens;             /* Current tokens */
    uint64_t rl_last_tick;          /* Last refill tick */
    uint64_t drops_ratelimit;       /* Rate limit rejections */
    uint64_t msgs_sent;
    uint64_t bytes_sent;
    uint64_t msgs_injected;
    uint64_t bytes_injected;
    uint64_t owner_tid;             /* Last thread to receive from channel */
    int owner_original_priority;    /* Saved priority for restoration */
    bool owner_pi_active;
    uint8_t _pad_owner[3];
    uint64_t pi_client_tid;
    struct fut_fipc_channel *next;  /* Next in channel list */
};

/* Channel flags */
#define FIPC_CHANNEL_BLOCKING       (1 << 0)
#define FIPC_CHANNEL_NONBLOCKING    (1 << 1)
#define FIPC_CHANNEL_ASYNC          (1 << 2)

/* Event types */
#define FIPC_EVENT_NONE             0
#define FIPC_EVENT_MESSAGE          (1 << 0)
#define FIPC_EVENT_DISCONNECT       (1 << 1)
#define FIPC_EVENT_ERROR            (1 << 2)

/* ============================================================
 *   Message Format
 * ============================================================ */

/**
 * FIPC message header.
 * Prepended to all messages sent through channels.
 * Aligned with FIPC_SPEC.md specification.
 */
struct fut_fipc_msg {
    uint32_t type;                  /* Message type (SYS, FS, UI, NET, USER, etc.) */
    uint32_t length;                /* Payload length in bytes */
    uint64_t timestamp;             /* Timestamp (kernel tick counter) */
    uint32_t src_pid;               /* Source process ID */
    uint32_t dst_pid;               /* Destination process ID */
    uint64_t capability;            /* Channel or permission token */

    /* Message payload follows this header */
    uint8_t payload[];
};

/* Message types */
#define FIPC_MSG_USER_BASE      0x1000
#define FIPC_MSG_SYSTEM         0x0001
#define FIPC_MSG_SIGNAL         0x0002
#define FIPC_MSG_SURFACE_CREATE 0x1001
#define FIPC_MSG_SURFACE_DESTROY 0x1002
#define FIPC_MSG_SURFACE_UPDATE 0x1003

/* ============================================================
 *   FIPC API - Shared Memory Regions
 * ============================================================ */

/**
 * Create a new shared memory region.
 *
 * @param size       Size in bytes (must be page-aligned)
 * @param flags      Region flags (FIPC_REGION_*)
 * @param region_out Pointer to store created region
 * @return 0 on success, negative error code on failure
 */
int fut_fipc_region_create(size_t size, uint32_t flags, struct fut_fipc_region **region_out);

/**
 * Destroy a shared memory region.
 *
 * @param region Region to destroy
 */
void fut_fipc_region_destroy(struct fut_fipc_region *region);

/**
 * Map a shared memory region into a task's address space.
 *
 * @param task   Task to map region into
 * @param region Region to map
 * @param addr   Desired virtual address (or 0 for automatic)
 * @return Virtual address on success, NULL on failure
 */
void *fut_fipc_region_map(struct fut_task *task, struct fut_fipc_region *region, void *addr);

/**
 * Unmap a shared memory region from a task's address space.
 *
 * @param task   Task to unmap from
 * @param region Region to unmap
 */
void fut_fipc_region_unmap(struct fut_task *task, struct fut_fipc_region *region);

/* ============================================================
 *   FIPC API - Event Channels
 * ============================================================ */

/**
 * Create a new event channel between two tasks.
 *
 * @param sender      Sending task
 * @param receiver    Receiving task
 * @param queue_size  Message queue size in bytes
 * @param flags       Channel flags
 * @param channel_out Pointer to store created channel
 * @return 0 on success, negative error code on failure
 */
int fut_fipc_channel_create(struct fut_task *sender, struct fut_task *receiver,
                             size_t queue_size, uint32_t flags,
                             struct fut_fipc_channel **channel_out);

struct fut_fipc_channel *fut_fipc_channel_lookup(uint64_t id);
uint64_t fut_fipc_channel_count(void);
int fut_fipc_register_remote(uint64_t channel_id,
                             const struct fut_fipc_remote_endpoint *remote);
int fut_fipc_bind_capability(struct fut_fipc_channel *channel, uint64_t capability);
int fut_fipc_cap_bind(struct fut_fipc_channel *channel, const struct fut_fipc_cap *cap);
int fut_fipc_cap_unbind(struct fut_fipc_channel *channel);
int fut_fipc_cap_revoke(struct fut_fipc_channel *channel, uint32_t revoke_flags);
int fut_fipc_set_credits(struct fut_fipc_channel *channel, uint32_t initial, uint32_t refill);
int fut_fipc_refill_credits(struct fut_fipc_channel *channel, uint32_t add);
int fut_fipc_set_rate(struct fut_fipc_channel *channel, uint32_t rate_per_ms, uint32_t burst);
int fut_fipc_channel_inject(struct fut_fipc_channel *channel,
                            uint32_t type,
                            const void *data,
                            size_t size,
                            uint32_t src_pid,
                            uint32_t dst_pid,
                            uint64_t capability);
int fut_fipc_set_transport_ops(const struct fut_fipc_transport_ops *ops, void *context);
int fut_fipc_publish_kernel_metrics(void);
struct fipc_iovec {
    const void *base;
    size_t len;
};
int fut_fipc_sendv(struct fut_fipc_channel *channel,
                   uint32_t type,
                   const struct fipc_iovec *iov,
                   size_t iovcnt);
size_t fut_fipc_dequeue_bounded(struct fut_fipc_channel *channel, size_t max_msgs);

/**
 * Destroy an event channel.
 *
 * @param channel Channel to destroy
 */
void fut_fipc_channel_destroy(struct fut_fipc_channel *channel);

/**
 * Send a message through a channel.
 *
 * @param channel Channel to send through
 * @param type    Message type
 * @param data    Message payload
 * @param size    Payload size in bytes
 * @return 0 on success, negative error code on failure
 */
int fut_fipc_send(struct fut_fipc_channel *channel, uint32_t type,
                  const void *data, size_t size);

/**
 * Receive a message from a channel.
 *
 * @param channel   Channel to receive from
 * @param buf       Buffer to store message (including header)
 * @param buf_size  Buffer size in bytes
 * @return Number of bytes received, or negative error code
 */
ssize_t fut_fipc_recv(struct fut_fipc_channel *channel, void *buf, size_t buf_size);

/**
 * Poll a channel for pending events.
 *
 * @param channel Channel to poll
 * @param mask    Event mask to check for
 * @return Pending events matching mask
 */
uint32_t fut_fipc_poll(struct fut_fipc_channel *channel, uint32_t mask);

/* ============================================================
 *   FIPC Initialization
 * ============================================================ */

/**
 * Initialize FIPC subsystem.
 */
void fut_fipc_init(void);

/* ============================================================
 *   FuturaWay Surface Sharing (Example Usage)
 * ============================================================ */

/**
 * Surface descriptor for FuturaWay.
 * Shared between compositor and clients.
 */
struct fut_surface {
    uint64_t id;                    /* Surface ID */
    uint32_t width;                 /* Width in pixels */
    uint32_t height;                /* Height in pixels */
    uint32_t format;                /* Pixel format (RGBA, etc.) */
    struct fut_fipc_region *buffer; /* Shared framebuffer region */
    uint32_t flags;                 /* Surface flags */
};

/* Surface pixel formats */
#define SURFACE_FORMAT_RGBA8888     0x01
#define SURFACE_FORMAT_RGB888       0x02
#define SURFACE_FORMAT_RGB565       0x03

/* Surface flags */
#define SURFACE_FLAG_VISIBLE        (1 << 0)
#define SURFACE_FLAG_FULLSCREEN     (1 << 1)
#define SURFACE_FLAG_TRANSPARENT    (1 << 2)

/* Error codes */
#define FIPC_EPERM      (-1)        /* Operation not permitted */
#define FIPC_EIO        (-5)        /* I/O error */
#define FIPC_ENOMEM     (-12)       /* Out of memory */
#define FIPC_EINVAL     (-22)       /* Invalid argument */
#define FIPC_EBUSY      (-16)       /* Resource busy */
#define FIPC_EAGAIN     (-11)       /* Try again */
#define FIPC_EPIPE      (-32)       /* Broken pipe */
#define FIPC_ENOSPC     (-28)       /* No space left */
#define FIPC_ENOTSUP    (-95)       /* Operation not supported */
