/* kernel/ns/mntns.c - Mount namespace support
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements mount namespaces for per-container filesystem views.
 * Each namespace has its own mount list; unshare(CLONE_NEWNS) clones
 * the parent's mount list into a new namespace.
 */

#include <kernel/fut_task.h>
#include <kernel/fut_vfs.h>
#include <kernel/fut_memory.h>
#include <kernel/kprintf.h>
#include <kernel/errno.h>
#include <string.h>

/* The initial mount namespace — shared by all tasks until unshare */
static struct mount_namespace g_init_mntns = {
    .id = 0x4026531840ULL,  /* Matches Linux /proc/self/ns/mnt */
    .refcount = 1,
    .mount_list = NULL,     /* Set during VFS init */
};

static uint64_t g_next_mntns_id = 0x4026531841ULL;

struct mount_namespace *mntns_init(void) {
    return &g_init_mntns;
}

/* Set the init namespace's mount list (called from VFS after root mount) */
void mntns_set_mount_list(struct fut_mount *list) {
    g_init_mntns.mount_list = list;
}

struct mount_namespace *mntns_create(struct mount_namespace *parent) {
    if (!parent) parent = &g_init_mntns;

    struct mount_namespace *ns = fut_malloc(sizeof(struct mount_namespace));
    if (!ns) return NULL;
    memset(ns, 0, sizeof(*ns));

    ns->id = g_next_mntns_id++;
    ns->refcount = 1;

    /* Clone the parent's mount list (shallow copy — shared mount structures) */
    ns->mount_list = parent->mount_list;

    parent->refcount++;

    fut_printf("[MNTNS] Created mount namespace id=%llu\n",
               (unsigned long long)ns->id);
    return ns;
}

void mntns_ref(struct mount_namespace *ns) {
    if (ns && ns != &g_init_mntns) ns->refcount++;
}

void mntns_unref(struct mount_namespace *ns) {
    if (!ns || ns == &g_init_mntns) return;
    ns->refcount--;
    if (ns->refcount <= 0) {
        fut_free(ns);
    }
}

struct mount_namespace *mntns_get_init(void) {
    return &g_init_mntns;
}
