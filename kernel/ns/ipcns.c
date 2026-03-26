/* kernel/ns/ipcns.c - IPC namespace support
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Per-container System V IPC isolation (shm, sem, msg).
 */

#include <kernel/fut_task.h>
#include <kernel/fut_memory.h>
#include <kernel/kprintf.h>
#include <kernel/errno.h>
#include <string.h>

struct ipc_namespace {
    uint64_t id;
    int refcount;
};

static struct ipc_namespace g_init_ipcns = { .id = 0x4026531839ULL, .refcount = 1 };
static uint64_t g_next_ipcns_id = 0x4026531840ULL;

struct ipc_namespace *ipcns_create(struct ipc_namespace *parent) {
    (void)parent;
    struct ipc_namespace *ns = fut_malloc(sizeof(*ns));
    if (!ns) return NULL;
    ns->id = g_next_ipcns_id++;
    ns->refcount = 1;
    return ns;
}

struct ipc_namespace *ipcns_get_init(void) { return &g_init_ipcns; }
