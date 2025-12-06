/* sys_fipc.c - FIPC System Call Implementations
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * System call interface for Futura Inter-Process Communication (FIPC).
 * Allows userspace daemons to create channels and exchange messages.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <errno.h>
#include <kernel/fut_fipc.h>
#include <kernel/fut_task.h>
#include <kernel/fut_memory.h>
#include <kernel/uaccess.h>

/* Maximum number of channels a single process can own */
#define FIPC_MAX_CHANNELS_PER_TASK 64

/* Default queue size for new channels */
#define FIPC_DEFAULT_QUEUE_SIZE 8192

/**
 * sys_fipc_create - Create a new FIPC channel
 *
 * @flags: Channel flags (FIPC_CHANNEL_BLOCKING, FIPC_CHANNEL_NONBLOCKING)
 * @queue_size: Size of the message queue in bytes (0 for default)
 *
 * Returns: Channel ID on success, negative errno on failure
 *
 * The created channel is owned by the calling task and can be used
 * for bidirectional communication. Other tasks can connect to this
 * channel if they know its ID.
 */
long sys_fipc_create(uint32_t flags, size_t queue_size)
{
    fut_task_t *current = fut_task_current();
    if (!current) {
        return -ESRCH;
    }

    /* Use default queue size if not specified */
    if (queue_size == 0) {
        queue_size = FIPC_DEFAULT_QUEUE_SIZE;
    }

    /* Validate queue size */
    if (queue_size < 256 || queue_size > (1024 * 1024)) {
        return -EINVAL;
    }

    /* Validate flags */
    uint32_t valid_flags = FIPC_CHANNEL_BLOCKING | FIPC_CHANNEL_NONBLOCKING;
    if (flags & ~valid_flags) {
        return -EINVAL;
    }

    /* Create the channel */
    struct fut_fipc_channel *channel = NULL;
    int ret = fut_fipc_channel_create(
        current,    /* sender */
        current,    /* receiver - same task owns both ends initially */
        queue_size,
        flags,
        &channel
    );

    if (ret < 0) {
        return ret;
    }

    if (!channel) {
        return -ENOMEM;
    }

    /* Set up default capability - owner has full access */
    struct fut_fipc_cap cap = {
        .rights = FIPC_CAP_R_SEND | FIPC_CAP_R_RECV,
        .revoke_flags = 0,
        .max_msgs = 0,      /* unlimited */
        .max_bytes = 0,     /* unlimited */
        .expiry_tick = 0,   /* no expiry */
        .lease_id = 0,      /* auto-assigned */
    };
    fut_fipc_cap_bind(channel, &cap);

    return (long)channel->id;
}

/**
 * sys_fipc_send - Send a message through a channel
 *
 * @channel_id: ID of the channel to send through
 * @type: Message type (application-defined)
 * @data: Pointer to message payload in userspace
 * @size: Size of the payload in bytes
 *
 * Returns: 0 on success, negative errno on failure
 *
 * The message is copied from userspace and queued for delivery.
 * If the channel is full and blocking is enabled, the caller blocks.
 */
long sys_fipc_send(uint64_t channel_id, uint32_t type, const void *u_data, size_t size)
{
    fut_task_t *current = fut_task_current();
    if (!current) {
        return -ESRCH;
    }

    /* Validate size */
    if (size > 65536) {  /* 64KB max message size */
        return -EINVAL;
    }

    /* Look up the channel */
    struct fut_fipc_channel *channel = fut_fipc_channel_lookup(channel_id);
    if (!channel) {
        return -ENOENT;
    }

    /* Copy data from userspace if provided */
    uint8_t *kdata = NULL;
    if (size > 0 && u_data) {
        kdata = fut_malloc(size);
        if (!kdata) {
            return -ENOMEM;
        }

        if (fut_copy_from_user(kdata, u_data, size) != 0) {
            fut_free(kdata);
            return -EFAULT;
        }
    }

    /* Send the message */
    int ret = fut_fipc_send(channel, type, kdata, size);

    /* Free temporary buffer */
    if (kdata) {
        fut_free(kdata);
    }

    return ret;
}

/**
 * sys_fipc_recv - Receive a message from a channel
 *
 * @channel_id: ID of the channel to receive from
 * @u_buf: Userspace buffer to store the message (including header)
 * @buf_size: Size of the buffer in bytes
 *
 * Returns: Number of bytes received on success, negative errno on failure
 *
 * The message (including fut_fipc_msg header) is copied to userspace.
 * If no message is available and blocking is enabled, the caller blocks.
 */
long sys_fipc_recv(uint64_t channel_id, void *u_buf, size_t buf_size)
{
    fut_task_t *current = fut_task_current();
    if (!current) {
        return -ESRCH;
    }

    /* Validate buffer */
    if (!u_buf || buf_size < sizeof(struct fut_fipc_msg)) {
        return -EINVAL;
    }

    /* Look up the channel */
    struct fut_fipc_channel *channel = fut_fipc_channel_lookup(channel_id);
    if (!channel) {
        return -ENOENT;
    }

    /* Allocate kernel buffer for receive */
    uint8_t *kbuf = fut_malloc(buf_size);
    if (!kbuf) {
        return -ENOMEM;
    }

    /* Receive the message */
    ssize_t ret = fut_fipc_recv(channel, kbuf, buf_size);

    if (ret > 0) {
        /* Copy to userspace */
        if (fut_copy_to_user(u_buf, kbuf, ret) != 0) {
            fut_free(kbuf);
            return -EFAULT;
        }
    }

    fut_free(kbuf);
    return ret;
}

/**
 * sys_fipc_close - Close/destroy an FIPC channel
 *
 * @channel_id: ID of the channel to close
 *
 * Returns: 0 on success, negative errno on failure
 *
 * Only the channel owner can close it. Pending messages are discarded.
 */
long sys_fipc_close(uint64_t channel_id)
{
    fut_task_t *current = fut_task_current();
    if (!current) {
        return -ESRCH;
    }

    /* Look up the channel */
    struct fut_fipc_channel *channel = fut_fipc_channel_lookup(channel_id);
    if (!channel) {
        return -ENOENT;
    }

    /* Verify ownership - sender or receiver must be current task */
    if (channel->sender != current && channel->receiver != current) {
        return -EPERM;
    }

    /* Destroy the channel */
    fut_fipc_channel_destroy(channel);

    return 0;
}

/**
 * sys_fipc_poll - Poll a channel for events
 *
 * @channel_id: ID of the channel to poll
 * @event_mask: Events to check for (FIPC_EVENT_MESSAGE, etc.)
 *
 * Returns: Pending events matching mask, or negative errno on failure
 */
long sys_fipc_poll(uint64_t channel_id, uint32_t event_mask)
{
    /* Look up the channel */
    struct fut_fipc_channel *channel = fut_fipc_channel_lookup(channel_id);
    if (!channel) {
        return -ENOENT;
    }

    return (long)fut_fipc_poll(channel, event_mask);
}

/**
 * sys_fipc_connect - Connect to an existing channel by ID
 *
 * @channel_id: ID of the channel to connect to
 *
 * Returns: 0 on success, negative errno on failure
 *
 * This allows a task to become a sender on an existing channel.
 * The channel owner must have created it for multi-client use.
 */
long sys_fipc_connect(uint64_t channel_id)
{
    fut_task_t *current = fut_task_current();
    if (!current) {
        return -ESRCH;
    }

    /* Look up the channel */
    struct fut_fipc_channel *channel = fut_fipc_channel_lookup(channel_id);
    if (!channel) {
        return -ENOENT;
    }

    /* For now, just verify the channel exists and return success
     * In a full implementation, this would:
     * 1. Check if multi-client mode is enabled
     * 2. Add the task to the list of connected clients
     * 3. Set up per-client state
     */

    return 0;
}
