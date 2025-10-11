/* fipc.c - FIPC Wrapper Functions for Userland
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * User-space wrappers for FIPC operations.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <kernel/fut_fipc.h>

/**
 * Connect to a named FIPC service.
 * Phase 3: Implement service discovery mechanism.
 */
struct fut_fipc_channel *fipc_connect(const char *service_name) {
    (void)service_name;

    /* Phase 3: Would:
     * 1. Look up service in registry (via init or special daemon)
     * 2. Request channel creation from kernel
     * 3. Return channel handle
     */

    return NULL;
}

/**
 * Disconnect from FIPC service.
 */
void fipc_disconnect(struct fut_fipc_channel *channel) {
    if (!channel) return;

    /* Phase 3: Would:
     * 1. Send disconnect message
     * 2. Close channel
     * 3. Release resources
     */

    fut_fipc_channel_destroy(channel);
}

/**
 * Send message via FIPC channel.
 */
int fipc_send_message(struct fut_fipc_channel *channel, uint32_t type,
                      const void *data, size_t size) {
    if (!channel) {
        return -1;
    }

    return fut_fipc_send(channel, type, data, size);
}

/**
 * Receive message via FIPC channel.
 */
int fipc_recv_message(struct fut_fipc_channel *channel, struct fut_fipc_msg *msg,
                      size_t max_size) {
    if (!channel || !msg) {
        return -1;
    }

    ssize_t ret = fut_fipc_recv(channel, msg, max_size);
    return (int)ret;
}

/**
 * Wait for message with timeout.
 * Phase 3: Implement with proper event loop integration.
 */
int fipc_wait(struct fut_fipc_channel *channel, uint32_t timeout_ms) {
    if (!channel) {
        return -1;
    }

    /* Phase 3: Would use proper event waiting mechanism */
    uint32_t events = fut_fipc_poll(channel, FIPC_EVENT_MESSAGE);
    (void)timeout_ms;

    return (events & FIPC_EVENT_MESSAGE) ? 1 : 0;
}

/**
 * Create shared memory region for zero-copy transfers.
 */
int fipc_create_shared_region(size_t size, struct fut_fipc_region **region_out) {
    if (!region_out) {
        return -1;
    }

    return fut_fipc_region_create(size, FIPC_REGION_READ | FIPC_REGION_WRITE, region_out);
}

/**
 * Map shared memory region into process address space.
 */
void *fipc_map_region(struct fut_fipc_region *region) {
    if (!region) {
        return NULL;
    }

    /* Phase 3: Would properly map into user address space */
    return fut_fipc_region_map(NULL, region, NULL);
}

/**
 * Unmap shared memory region.
 */
void fipc_unmap_region(struct fut_fipc_region *region) {
    if (!region) {
        return;
    }

    fut_fipc_region_unmap(NULL, region);
}

/**
 * Destroy shared memory region.
 */
void fipc_destroy_region(struct fut_fipc_region *region) {
    if (!region) {
        return;
    }

    fut_fipc_region_destroy(region);
}
