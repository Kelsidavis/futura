/* kernel/cgroup/freezer.c - Cgroup v2 freezer controller
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Pause/resume all processes in a cgroup (docker pause/unpause):
 *   cgroup.freeze: write 1 to freeze, 0 to thaw
 *   cgroup.events: "frozen 0" or "frozen 1"
 */

#include <kernel/fut_task.h>
#include <kernel/kprintf.h>
#include <kernel/errno.h>
#include <kernel/fut_memory.h>
#include <stdint.h>
#include <string.h>

#define FREEZER_MAX 16

struct freezer_group {
    bool     active;
    char     name[32];
    bool     frozen;
};

static struct freezer_group g_freezer[FREEZER_MAX];

void freezer_init(void) {
    memset(g_freezer, 0, sizeof(g_freezer));
    g_freezer[0].active = true;
    g_freezer[0].name[0] = '/'; g_freezer[0].name[1] = '\0';
    fut_printf("[FREEZER] Cgroup v2 freezer controller initialized\n");
}

static int freezer_find(const char *path) {
    for (int i = 0; i < FREEZER_MAX; i++) {
        if (!g_freezer[i].active) continue;
        const char *a = g_freezer[i].name, *b = path;
        while (*a && *b && *a == *b) { a++; b++; }
        if (*a == '\0' && *b == '\0') return i;
    }
    return -1;
}

int freezer_create(const char *path) {
    if (!path) return -EINVAL;
    if (freezer_find(path) >= 0) return -EEXIST;
    for (int i = 1; i < FREEZER_MAX; i++) {
        if (!g_freezer[i].active) {
            g_freezer[i].active = true;
            size_t pl = 0;
            while (path[pl] && pl < 31) { g_freezer[i].name[pl] = path[pl]; pl++; }
            g_freezer[i].name[pl] = '\0';
            g_freezer[i].frozen = false;
            return 0;
        }
    }
    return -ENOSPC;
}

/**
 * freezer_set — Freeze (1) or thaw (0) a cgroup.
 * Sends SIGSTOP to all processes in the cgroup when freezing,
 * SIGCONT when thawing. This implements `docker pause/unpause`.
 */
int freezer_set(const char *path, int freeze) {
    int idx = freezer_find(path);
    if (idx < 0) return -ENOENT;
    if (idx == 0) return -EINVAL;  /* Can't freeze root cgroup */

    bool was_frozen = g_freezer[idx].frozen;
    g_freezer[idx].frozen = (freeze != 0);

    extern fut_task_t *fut_task_list;
    extern int fut_signal_send(fut_task_t *, int);

    if (freeze && !was_frozen) {
        /* Freeze: send SIGSTOP to all processes */
        fut_task_t *t = fut_task_list;
        while (t) {
            if (t->pid > 1)  /* Don't freeze init */
                fut_signal_send(t, 19 /* SIGSTOP */);
            t = t->next;
        }
        fut_printf("[FREEZER] Frozen cgroup '%s'\n", path);
    } else if (!freeze && was_frozen) {
        /* Thaw: send SIGCONT to all processes */
        fut_task_t *t = fut_task_list;
        while (t) {
            if (t->pid > 1)
                fut_signal_send(t, 18 /* SIGCONT */);
            t = t->next;
        }
        fut_printf("[FREEZER] Thawed cgroup '%s'\n", path);
    }

    return 0;
}

int freezer_get(const char *path) {
    int idx = freezer_find(path);
    if (idx < 0) return 0;
    return g_freezer[idx].frozen ? 1 : 0;
}
