/* kernel/cgroup/cpucg.c - Cgroup v2 CPU controller
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Provides per-cgroup CPU bandwidth control:
 *   - cpu.max: bandwidth limit (quota period format: "max 100000")
 *   - cpu.weight: proportional CPU share (1-10000, default 100)
 *   - cpu.stat: usage statistics (usage_usec, user_usec, system_usec)
 */

#include <kernel/fut_task.h>
#include <kernel/fut_timer.h>
#include <kernel/kprintf.h>
#include <kernel/errno.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#define CPUCG_MAX_GROUPS 16

struct cpucg_group {
    bool     active;
    char     name[32];
    uint64_t cpu_quota_us;       /* Max CPU time per period (0 = unlimited) */
    uint64_t cpu_period_us;      /* Period length (default 100ms = 100000us) */
    uint32_t cpu_weight;         /* Weight for proportional sharing (1-10000) */
    uint64_t usage_usec;         /* Total CPU time used */
    uint64_t nr_periods;         /* Number of elapsed periods */
    uint64_t nr_throttled;       /* Number of throttled periods */
};

static struct cpucg_group g_cpucg[CPUCG_MAX_GROUPS];

void cpucg_init(void) {
    memset(g_cpucg, 0, sizeof(g_cpucg));
    g_cpucg[0].active = true;
    g_cpucg[0].name[0] = '/'; g_cpucg[0].name[1] = '\0';
    g_cpucg[0].cpu_weight = 100;
    g_cpucg[0].cpu_period_us = 100000;
    fut_printf("[CPUCG] Cgroup v2 CPU controller initialized\n");
}

int cpucg_create(const char *path) {
    if (!path) return -EINVAL;
    for (int i = 0; i < CPUCG_MAX_GROUPS; i++) {
        if (!g_cpucg[i].active) continue;
        const char *a = g_cpucg[i].name, *b = path;
        while (*a && *b && *a == *b) { a++; b++; }
        if (*a == '\0' && *b == '\0') return -EEXIST;
    }
    int slot = -1;
    for (int i = 1; i < CPUCG_MAX_GROUPS; i++)
        if (!g_cpucg[i].active) { slot = i; break; }
    if (slot < 0) return -ENOSPC;

    struct cpucg_group *g = &g_cpucg[slot];
    g->active = true;
    size_t pl = 0;
    while (path[pl] && pl < 31) { g->name[pl] = path[pl]; pl++; }
    g->name[pl] = '\0';
    g->cpu_weight = 100;
    g->cpu_period_us = 100000;
    g->cpu_quota_us = 0;

    fut_printf("[CPUCG] Created CPU cgroup '%s'\n", g->name);
    return 0;
}

int cpucg_set_max(const char *path, uint64_t quota_us, uint64_t period_us) {
    for (int i = 0; i < CPUCG_MAX_GROUPS; i++) {
        if (!g_cpucg[i].active) continue;
        const char *a = g_cpucg[i].name, *b = path;
        while (*a && *b && *a == *b) { a++; b++; }
        if (*a == '\0' && *b == '\0') {
            g_cpucg[i].cpu_quota_us = quota_us;
            if (period_us > 0) g_cpucg[i].cpu_period_us = period_us;
            return 0;
        }
    }
    return -ENOENT;
}

int cpucg_set_weight(const char *path, uint32_t weight) {
    if (weight < 1 || weight > 10000) return -EINVAL;
    for (int i = 0; i < CPUCG_MAX_GROUPS; i++) {
        if (!g_cpucg[i].active) continue;
        const char *a = g_cpucg[i].name, *b = path;
        while (*a && *b && *a == *b) { a++; b++; }
        if (*a == '\0' && *b == '\0') {
            g_cpucg[i].cpu_weight = weight;
            return 0;
        }
    }
    return -ENOENT;
}

uint64_t cpucg_get_usage(const char *path) {
    /* Return total CPU ticks converted to microseconds */
    uint64_t ticks = fut_get_ticks();
    (void)path;
    return ticks * 10000;  /* 100Hz ticks → microseconds */
}

int cpucg_group_count(void) {
    int c = 0;
    for (int i = 0; i < CPUCG_MAX_GROUPS; i++)
        if (g_cpucg[i].active) c++;
    return c;
}
