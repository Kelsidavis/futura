/* kernel/vfs/devfs.c - Minimal character device registry
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Provides minimal character device node registration and lookup for /dev.
 */

#include <kernel/devfs.h>
#include <kernel/errno.h>
#include <kernel/fut_memory.h>

#include <stddef.h>

#include <kernel/kprintf.h>

/* Maximum number of device nodes that can be registered */
#define DEVFS_MAX_NODES 64

typedef struct {
    char *path;
    unsigned major;
    unsigned minor;
} dev_node_t;

static dev_node_t g_dev_nodes[DEVFS_MAX_NODES];
static size_t g_dev_count = 0;

static int devfs_path_equal(const char *a, const char *b) {
    if (!a || !b) {
        return 0;
    }
    while (*a && *b && *a == *b) {
        ++a;
        ++b;
    }
    return (*a == *b);
}

int devfs_create_chr(const char *path, unsigned major, unsigned minor) {
    if (!path) {
        return -EINVAL;
    }

    size_t len = 0;
    while (path[len]) {
        ++len;
    }

    char *stored = fut_malloc(len + 1);
    if (!stored) {
        return -ENOMEM;
    }

    for (size_t i = 0; i <= len; ++i) {
        stored[i] = path[i];
    }

    /* CAS-loop reservation so concurrent devfs_create_chr calls don't
     * both pick the same g_dev_nodes index. See
     * project_slot_claim_pattern.md. */
    size_t idx;
    {
        size_t cur, next;
        do {
            cur = __atomic_load_n(&g_dev_count, __ATOMIC_ACQUIRE);
            if (cur >= DEVFS_MAX_NODES) {
                fut_free(stored);
                return -ENOSPC;
            }
            next = cur + 1;
        } while (!__atomic_compare_exchange_n(&g_dev_count, &cur, next,
                                              false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE));
        idx = cur;
    }

    g_dev_nodes[idx] = (dev_node_t){
        .path = stored,
        .major = major,
        .minor = minor,
    };

    return 0;
}

int devfs_lookup_chr(const char *path, unsigned *major, unsigned *minor) {
    if (!path) {
        return -EINVAL;
    }

    /* Acquire-load matches the release-CAS in devfs_create_chr. */
    size_t count = __atomic_load_n(&g_dev_count, __ATOMIC_ACQUIRE);
    for (size_t i = 0; i < count; ++i) {
        if (devfs_path_equal(g_dev_nodes[i].path, path)) {
            if (major) {
                *major = g_dev_nodes[i].major;
            }
            if (minor) {
                *minor = g_dev_nodes[i].minor;
            }
            return 0;
        }
    }

    return -ENOENT;
}
