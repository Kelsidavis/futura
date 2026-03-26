/* kernel/ns/utsns.c - UTS namespace support
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Per-container hostname and domainname via UTS namespaces.
 * unshare(CLONE_NEWUTS) gives the process its own hostname.
 */

#include <kernel/fut_task.h>
#include <kernel/fut_memory.h>
#include <kernel/kprintf.h>
#include <kernel/errno.h>
#include <string.h>

static struct uts_namespace g_init_utsns = {
    .id = 0x4026531838ULL,
    .refcount = 1,
    .nodename = "futura",
    .domainname = "(none)",
};

static uint64_t g_next_utsns_id = 0x4026531839ULL;

struct uts_namespace *utsns_get_init(void) {
    return &g_init_utsns;
}

struct uts_namespace *utsns_create(struct uts_namespace *parent) {
    if (!parent) parent = &g_init_utsns;
    struct uts_namespace *ns = fut_malloc(sizeof(struct uts_namespace));
    if (!ns) return NULL;
    *ns = *parent;  /* Copy hostname/domainname */
    ns->id = g_next_utsns_id++;
    ns->refcount = 1;
    parent->refcount++;
    fut_printf("[UTSNS] Created UTS namespace id=%llu\n", (unsigned long long)ns->id);
    return ns;
}

void utsns_ref(struct uts_namespace *ns) {
    if (ns && ns != &g_init_utsns) ns->refcount++;
}

void utsns_unref(struct uts_namespace *ns) {
    if (!ns || ns == &g_init_utsns) return;
    if (--ns->refcount <= 0) fut_free(ns);
}

const char *utsns_get_hostname(struct uts_namespace *ns) {
    return ns ? ns->nodename : g_init_utsns.nodename;
}

int utsns_set_hostname(struct uts_namespace *ns, const char *name, size_t len) {
    if (!ns) ns = &g_init_utsns;
    if (len >= sizeof(ns->nodename)) len = sizeof(ns->nodename) - 1;
    memcpy(ns->nodename, name, len);
    ns->nodename[len] = '\0';
    return 0;
}
