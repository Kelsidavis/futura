/* kernel/cgroup/pidcg.c - Cgroup v2 PID controller
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Limits the number of processes per cgroup (fork bomb prevention):
 *   pids.max: maximum number of processes (default: unlimited)
 *   pids.current: current process count
 */

#include <kernel/fut_task.h>
#include <kernel/kprintf.h>
#include <kernel/errno.h>
#include <kernel/fut_memory.h>
#include <stdint.h>
#include <string.h>

#define PIDCG_MAX 16

struct pidcg_group {
    bool     active;
    char     name[32];
    uint32_t pids_max;      /* 0 = unlimited */
    uint32_t pids_current;
};

static struct pidcg_group g_pidcg[PIDCG_MAX];

void pidcg_init(void) {
    memset(g_pidcg, 0, sizeof(g_pidcg));
    g_pidcg[0].active = true;
    g_pidcg[0].name[0] = '/'; g_pidcg[0].name[1] = '\0';
    fut_printf("[PIDCG] Cgroup v2 PID controller initialized\n");
}

static int pidcg_find(const char *path) {
    for (int i = 0; i < PIDCG_MAX; i++) {
        if (!g_pidcg[i].active) continue;
        const char *a = g_pidcg[i].name, *b = path;
        while (*a && *b && *a == *b) { a++; b++; }
        if (*a == '\0' && *b == '\0') return i;
    }
    return -1;
}

int pidcg_create(const char *path) {
    if (!path) return -EINVAL;
    if (pidcg_find(path) >= 0) return -EEXIST;
    for (int i = 1; i < PIDCG_MAX; i++) {
        if (!g_pidcg[i].active) {
            g_pidcg[i].active = true;
            size_t pl = 0;
            while (path[pl] && pl < 31) { g_pidcg[i].name[pl] = path[pl]; pl++; }
            g_pidcg[i].name[pl] = '\0';
            g_pidcg[i].pids_max = 0;
            g_pidcg[i].pids_current = 0;
            return 0;
        }
    }
    return -ENOSPC;
}

int pidcg_set_max(const char *path, uint32_t max_pids) {
    int idx = pidcg_find(path);
    if (idx < 0) return -ENOENT;
    g_pidcg[idx].pids_max = max_pids;
    fut_printf("[PIDCG] Set pids.max=%u for '%s'\n", max_pids, path);
    return 0;
}

uint32_t pidcg_get_current(const char *path) {
    int idx = pidcg_find(path);
    if (idx < 0) return 0;
    /* Count processes by scanning task list for this cgroup */
    extern struct fut_task *fut_task_list;
    uint32_t count = 0;
    struct fut_task *t = fut_task_list;
    while (t) { count++; t = t->next; }
    /* For non-root cgroups, this would need per-cgroup tracking.
     * Root cgroup "/" reports total system process count. */
    if (idx == 0) return count;
    return g_pidcg[idx].pids_current;
}

uint32_t pidcg_get_max(const char *path) {
    int idx = pidcg_find(path);
    if (idx < 0) return 0;
    return g_pidcg[idx].pids_max;
}

/**
 * pidcg_check_fork — Called before fork to enforce pids.max.
 * Returns 0 if fork is allowed, -EAGAIN if PID limit reached.
 */
int pidcg_check_fork(int parent_pid) {
    /* Check all non-root cgroups for PID limits */
    for (int i = 1; i < PIDCG_MAX; i++) {
        if (!g_pidcg[i].active || g_pidcg[i].pids_max == 0)
            continue;
        /* In a real implementation, check if parent_pid is in this cgroup.
         * For now, enforce limits on any non-root cgroup with a limit set. */
        if (g_pidcg[i].pids_current >= g_pidcg[i].pids_max) {
            fut_printf("[PIDCG] Fork denied: cgroup '%s' at pids.max=%u\n",
                       g_pidcg[i].name, g_pidcg[i].pids_max);
            return -EAGAIN;
        }
    }
    (void)parent_pid;
    return 0;
}

/**
 * pidcg_fork_notify — Called after successful fork to update counters.
 */
void pidcg_fork_notify(void) {
    for (int i = 1; i < PIDCG_MAX; i++) {
        if (g_pidcg[i].active && g_pidcg[i].pids_max > 0)
            g_pidcg[i].pids_current++;
    }
}

/**
 * pidcg_exit_notify — Called on process exit to update counters.
 */
void pidcg_exit_notify(void) {
    for (int i = 1; i < PIDCG_MAX; i++) {
        if (g_pidcg[i].active && g_pidcg[i].pids_current > 0)
            g_pidcg[i].pids_current--;
    }
}
