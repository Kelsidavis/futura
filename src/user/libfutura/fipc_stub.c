// SPDX-License-Identifier: MPL-2.0
// Stubs for kernel FIPC entry points when running fully in userland.

#include <errno.h>
#include <stddef.h>

#include <kernel/fut_fipc.h>

int fut_fipc_send(struct fut_fipc_channel *channel, uint32_t type,
                  const void *payload, size_t size) {
    (void)channel;
    (void)type;
    (void)payload;
    (void)size;
    errno = ENOSYS;
    return -1;
}

ssize_t fut_fipc_recv(struct fut_fipc_channel *channel, void *buf, size_t buf_size) {
    (void)channel;
    (void)buf;
    (void)buf_size;
    errno = ENOSYS;
    return -1;
}

uint32_t fut_fipc_poll(struct fut_fipc_channel *channel, uint32_t mask) {
    (void)channel;
    (void)mask;
    return 0;
}

void fut_fipc_channel_destroy(struct fut_fipc_channel *channel) {
    (void)channel;
}

int fut_fipc_region_create(size_t size, uint32_t flags, struct fut_fipc_region **region_out) {
    (void)size;
    (void)flags;
    if (region_out) {
        *region_out = NULL;
    }
    errno = ENOSYS;
    return -1;
}

void *fut_fipc_region_map(struct fut_task *task, struct fut_fipc_region *region, void *addr) {
    (void)task;
    (void)region;
    (void)addr;
    errno = ENOSYS;
    return NULL;
}

void fut_fipc_region_unmap(struct fut_task *task, struct fut_fipc_region *region) {
    (void)task;
    (void)region;
}

void fut_fipc_region_destroy(struct fut_fipc_region *region) {
    (void)region;
}
