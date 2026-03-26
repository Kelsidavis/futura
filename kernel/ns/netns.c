/* kernel/ns/netns.c - Network namespace foundation
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Foundation for per-container network isolation. Currently provides
 * namespace tracking and ID assignment; full per-namespace network
 * state (interfaces, routes, sockets) requires deeper refactoring.
 */

#include <kernel/fut_task.h>
#include <kernel/fut_memory.h>
#include <kernel/kprintf.h>
#include <kernel/errno.h>
#include <string.h>

static struct net_namespace g_init_netns = {
    .id = 0x4026531992ULL,
    .refcount = 1,
};

static uint64_t g_next_netns_id = 0x4026531993ULL;

struct net_namespace *netns_get_init(void) {
    return &g_init_netns;
}

struct net_namespace *netns_create(struct net_namespace *parent) {
    if (!parent) parent = &g_init_netns;
    struct net_namespace *ns = fut_malloc(sizeof(struct net_namespace));
    if (!ns) return NULL;
    memset(ns, 0, sizeof(*ns));
    ns->id = g_next_netns_id++;
    ns->refcount = 1;
    parent->refcount++;
    fut_printf("[NETNS] Created network namespace id=%llu\n",
               (unsigned long long)ns->id);
    return ns;
}

void netns_ref(struct net_namespace *ns) {
    if (ns && ns != &g_init_netns) ns->refcount++;
}

void netns_unref(struct net_namespace *ns) {
    if (!ns || ns == &g_init_netns) return;
    if (--ns->refcount <= 0) fut_free(ns);
}
