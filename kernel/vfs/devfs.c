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

extern void fut_printf(const char *fmt, ...);

typedef struct {
    char *path;
    unsigned major;
    unsigned minor;
} dev_node_t;

static dev_node_t g_dev_nodes[64];
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
    if (g_dev_count >= (sizeof(g_dev_nodes) / sizeof(g_dev_nodes[0]))) {
        return -ENOSPC;
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

    g_dev_nodes[g_dev_count++] = (dev_node_t){
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

    for (size_t i = 0; i < g_dev_count; ++i) {
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
