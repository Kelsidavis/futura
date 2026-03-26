/* kernel/ns/pidns.c - PID namespace support
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements PID namespaces for process isolation. Each namespace
 * has its own PID number space: PID 1 in a child namespace maps
 * to a different PID in the parent namespace.
 *
 * Key behaviors:
 *   - getpid() returns the namespace-local PID
 *   - Processes in a child namespace can't see/signal processes
 *     outside their namespace
 *   - When PID 1 in a namespace exits, all processes in that
 *     namespace are killed (like init dying)
 */

#include <kernel/fut_task.h>
#include <kernel/fut_memory.h>
#include <kernel/kprintf.h>
#include <kernel/errno.h>
#include <string.h>

/* The initial (root) PID namespace */
static struct pid_namespace g_init_pidns = {
    .id = 0x4026531836ULL,  /* Matches Linux /proc/self/ns/pid inode */
    .next_pid = 1,
    .init_task = NULL,
    .parent = NULL,
    .level = 0,
    .refcount = 1,
};

static uint64_t g_next_ns_id = 0x4026531837ULL;

struct pid_namespace *pidns_init(void) {
    return &g_init_pidns;
}

struct pid_namespace *pidns_create(struct pid_namespace *parent) {
    if (!parent) parent = &g_init_pidns;

    struct pid_namespace *ns = fut_malloc(sizeof(struct pid_namespace));
    if (!ns) return NULL;
    memset(ns, 0, sizeof(*ns));

    ns->id = g_next_ns_id++;
    ns->next_pid = 1;
    ns->parent = parent;
    ns->level = parent->level + 1;
    ns->refcount = 1;
    parent->refcount++;

    fut_printf("[PIDNS] Created namespace id=%llu level=%d\n",
               (unsigned long long)ns->id, ns->level);
    return ns;
}

uint64_t pidns_alloc_pid(struct pid_namespace *ns) {
    if (!ns) ns = &g_init_pidns;
    return ns->next_pid++;
}

void pidns_ref(struct pid_namespace *ns) {
    if (ns && ns != &g_init_pidns) ns->refcount++;
}

void pidns_unref(struct pid_namespace *ns) {
    if (!ns || ns == &g_init_pidns) return;
    ns->refcount--;
    if (ns->refcount <= 0) {
        if (ns->parent) pidns_unref(ns->parent);
        fut_free(ns);
    }
}

/* Get the PID visible to the caller's namespace.
 * If target is in a child namespace, return the target's PID in the
 * caller's namespace. If in a different branch, return 0 (invisible). */
uint64_t pidns_translate_pid(struct fut_task *target, struct pid_namespace *viewer_ns) {
    if (!target || !viewer_ns) return target ? target->pid : 0;

    /* Same namespace? Return ns_pid */
    if (target->pid_ns == viewer_ns) return target->ns_pid;

    /* Target is in init namespace and viewer is also init? Return real pid */
    if (!target->pid_ns && !viewer_ns->parent) return target->pid;

    /* Target in child namespace of viewer? Return real pid */
    struct pid_namespace *ns = target->pid_ns;
    while (ns) {
        if (ns == viewer_ns) return target->pid;
        ns = ns->parent;
    }

    /* Not visible */
    return 0;
}

/* Check if target is visible from viewer's namespace */
int pidns_is_visible(struct fut_task *target, struct pid_namespace *viewer_ns) {
    return pidns_translate_pid(target, viewer_ns) != 0;
}
