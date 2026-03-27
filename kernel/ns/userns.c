/* kernel/ns/userns.c - User namespace support
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Enables unprivileged containers by mapping UIDs/GIDs between
 * namespaces. Container root (UID 0) maps to an unprivileged
 * UID on the host, preventing privilege escalation.
 *
 * /proc/<pid>/uid_map and /proc/<pid>/gid_map control the mapping.
 */

#include <kernel/fut_task.h>
#include <kernel/fut_memory.h>
#include <kernel/kprintf.h>
#include <kernel/errno.h>
#include <kernel/userns.h>
#include <string.h>

#define USERNS_MAP_MAX 5  /* Max UID/GID map entries per namespace */

static struct user_namespace g_init_userns = {
    .id = 0x4026531837ULL,
    .refcount = 1,
    .uid_map_count = 1,
    .gid_map_count = 1,
    .uid_map = {{ .ns_id = 0, .host_id = 0, .count = 4294967295U }},
    .gid_map = {{ .ns_id = 0, .host_id = 0, .count = 4294967295U }},
};

static uint64_t g_next_userns_id = 0x4026531838ULL;

struct user_namespace *userns_get_init(void) {
    return &g_init_userns;
}

struct user_namespace *userns_create(struct user_namespace *parent) {
    if (!parent) parent = &g_init_userns;
    struct user_namespace *ns = fut_malloc(sizeof(struct user_namespace));
    if (!ns) return NULL;
    memset(ns, 0, sizeof(*ns));
    ns->id = g_next_userns_id++;
    ns->parent = parent;
    ns->refcount = 1;
    /* Default: identity mapping (filled in by writing /proc/pid/uid_map) */
    ns->uid_map_count = 0;
    ns->gid_map_count = 0;
    parent->refcount++;
    fut_printf("[USERNS] Created user namespace id=%llu\n", (unsigned long long)ns->id);
    return ns;
}

void userns_ref(struct user_namespace *ns) {
    if (ns && ns != &g_init_userns) ns->refcount++;
}

void userns_unref(struct user_namespace *ns) {
    if (!ns || ns == &g_init_userns) return;
    if (--ns->refcount <= 0) {
        if (ns->parent) userns_unref(ns->parent);
        fut_free(ns);
    }
}

/* Set UID mapping: "ns_first host_first count" */
int userns_set_uid_map(struct user_namespace *ns, uint32_t ns_first,
                       uint32_t host_first, uint32_t count) {
    if (!ns || ns == &g_init_userns) return -EPERM;
    if (ns->uid_map_count >= USERNS_MAP_MAX) return -EINVAL;
    int i = ns->uid_map_count;
    ns->uid_map[i].ns_id = ns_first;
    ns->uid_map[i].host_id = host_first;
    ns->uid_map[i].count = count;
    ns->uid_map_count++;
    return 0;
}

int userns_set_gid_map(struct user_namespace *ns, uint32_t ns_first,
                       uint32_t host_first, uint32_t count) {
    if (!ns || ns == &g_init_userns) return -EPERM;
    if (ns->gid_map_count >= USERNS_MAP_MAX) return -EINVAL;
    int i = ns->gid_map_count;
    ns->gid_map[i].ns_id = ns_first;
    ns->gid_map[i].host_id = host_first;
    ns->gid_map[i].count = count;
    ns->gid_map_count++;
    return 0;
}

/* Translate namespace UID to host UID */
uint32_t userns_ns_to_host_uid(struct user_namespace *ns, uint32_t ns_uid) {
    if (!ns || ns == &g_init_userns) return ns_uid;
    for (int i = 0; i < ns->uid_map_count; i++) {
        if (ns_uid >= ns->uid_map[i].ns_id &&
            ns_uid < ns->uid_map[i].ns_id + ns->uid_map[i].count) {
            return ns->uid_map[i].host_id + (ns_uid - ns->uid_map[i].ns_id);
        }
    }
    return USERNS_OVERFLOW_ID;  /* nobody — unmapped */
}

uint32_t userns_ns_to_host_gid(struct user_namespace *ns, uint32_t ns_gid) {
    if (!ns || ns == &g_init_userns) return ns_gid;
    for (int i = 0; i < ns->gid_map_count; i++) {
        if (ns_gid >= ns->gid_map[i].ns_id &&
            ns_gid < ns->gid_map[i].ns_id + ns->gid_map[i].count) {
            return ns->gid_map[i].host_id + (ns_gid - ns->gid_map[i].ns_id);
        }
    }
    return USERNS_OVERFLOW_ID;
}

uint32_t userns_host_to_ns_uid(struct user_namespace *ns, uint32_t host_uid) {
    if (!ns || ns == &g_init_userns) return host_uid;
    for (int i = 0; i < ns->uid_map_count; i++) {
        if (host_uid >= ns->uid_map[i].host_id &&
            host_uid < ns->uid_map[i].host_id + ns->uid_map[i].count) {
            return ns->uid_map[i].ns_id + (host_uid - ns->uid_map[i].host_id);
        }
    }
    return USERNS_OVERFLOW_ID;
}

uint32_t userns_host_to_ns_gid(struct user_namespace *ns, uint32_t host_gid) {
    if (!ns || ns == &g_init_userns) return host_gid;
    for (int i = 0; i < ns->gid_map_count; i++) {
        if (host_gid >= ns->gid_map[i].host_id &&
            host_gid < ns->gid_map[i].host_id + ns->gid_map[i].count) {
            return ns->gid_map[i].ns_id + (host_gid - ns->gid_map[i].host_id);
        }
    }
    return USERNS_OVERFLOW_ID;
}
