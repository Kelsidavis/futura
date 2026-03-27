/* kernel/cgroup/memcg.c - Cgroup v2 memory controller
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Minimal cgroup v2 memory controller providing:
 *   - memory.max: memory limit in bytes (writable)
 *   - memory.current: current memory usage
 *   - memory.high: high watermark threshold
 *   - cgroup.procs: list of PIDs in this cgroup
 *
 * The root cgroup "/" encompasses all processes. Child cgroups
 * can be created by mkdir in the cgroup filesystem.
 */

#include <kernel/fut_task.h>
#include <kernel/fut_memory.h>
#include <kernel/kprintf.h>
#include <kernel/errno.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#define MEMCG_MAX_GROUPS    16

struct memcg_group {
    bool     active;
    char     name[32];              /* Cgroup path relative to root */
    uint64_t memory_max;            /* Memory limit (0 = unlimited) */
    uint64_t memory_high;           /* High watermark */
    uint64_t memory_current;        /* Current usage (tracked lazily) */
    int      pids[64];              /* PIDs assigned to this group */
    int      pid_count;
};

static struct memcg_group g_memcg[MEMCG_MAX_GROUPS];

void memcg_init(void) {
    memset(g_memcg, 0, sizeof(g_memcg));
    /* Root cgroup is always active */
    g_memcg[0].active = true;
    g_memcg[0].name[0] = '/';
    g_memcg[0].name[1] = '\0';
    g_memcg[0].memory_max = 0;  /* Unlimited */
    fut_printf("[MEMCG] Cgroup v2 memory controller initialized (%d groups)\n",
               MEMCG_MAX_GROUPS);
}

int memcg_create(const char *path) {
    if (!path || !path[0]) return -EINVAL;
    /* Check for duplicate */
    for (int i = 0; i < MEMCG_MAX_GROUPS; i++) {
        if (g_memcg[i].active) {
            const char *a = g_memcg[i].name, *b = path;
            while (*a && *b && *a == *b) { a++; b++; }
            if (*a == '\0' && *b == '\0') return -EEXIST;
        }
    }
    int slot = -1;
    for (int i = 1; i < MEMCG_MAX_GROUPS; i++) {
        if (!g_memcg[i].active) { slot = i; break; }
    }
    if (slot < 0) return -ENOSPC;

    struct memcg_group *g = &g_memcg[slot];
    g->active = true;
    size_t pl = 0;
    while (path[pl] && pl < 31) { g->name[pl] = path[pl]; pl++; }
    g->name[pl] = '\0';
    g->memory_max = 0;
    g->pid_count = 0;

    fut_printf("[MEMCG] Created cgroup '%s'\n", g->name);
    return 0;
}

int memcg_set_limit(const char *path, uint64_t limit_bytes) {
    for (int i = 0; i < MEMCG_MAX_GROUPS; i++) {
        if (!g_memcg[i].active) continue;
        const char *a = g_memcg[i].name, *b = path;
        while (*a && *b && *a == *b) { a++; b++; }
        if (*a == '\0' && *b == '\0') {
            g_memcg[i].memory_max = limit_bytes;
            fut_printf("[MEMCG] Set memory.max=%llu for '%s'\n",
                       (unsigned long long)limit_bytes, path);
            return 0;
        }
    }
    return -ENOENT;
}

int memcg_add_pid(const char *path, int pid) {
    for (int i = 0; i < MEMCG_MAX_GROUPS; i++) {
        if (!g_memcg[i].active) continue;
        const char *a = g_memcg[i].name, *b = path;
        while (*a && *b && *a == *b) { a++; b++; }
        if (*a == '\0' && *b == '\0') {
            if (g_memcg[i].pid_count >= 64) return -ENOSPC;
            g_memcg[i].pids[g_memcg[i].pid_count++] = pid;
            return 0;
        }
    }
    return -ENOENT;
}

uint64_t memcg_get_current(const char *path) {
    /* Compute current memory usage from PMM stats */
    uint64_t total_pages = fut_pmm_total_pages();
    uint64_t free_pages = fut_pmm_free_pages();
    uint64_t used_bytes = (total_pages - free_pages) * 4096;
    (void)path;  /* Root cgroup = all system memory */
    return used_bytes;
}

/**
 * memcg_check_limit — Check if a task's cgroup has exceeded memory.max.
 * Called from the page allocator when memory is tight.
 * Returns the PID to OOM-kill, or 0 if no limit exceeded.
 */
int memcg_check_limit(int pid) {
    for (int i = 1; i < MEMCG_MAX_GROUPS; i++) {
        if (!g_memcg[i].active || g_memcg[i].memory_max == 0)
            continue;
        /* Check if this PID is in this cgroup */
        int found = 0;
        for (int p = 0; p < g_memcg[i].pid_count; p++) {
            if (g_memcg[i].pids[p] == pid) { found = 1; break; }
        }
        if (!found) continue;

        /* Check if cgroup memory usage exceeds limit */
        uint64_t current = memcg_get_current(g_memcg[i].name);
        if (current > g_memcg[i].memory_max) {
            fut_printf("[MEMCG] OOM: cgroup '%s' usage %llu > limit %llu — killing PID %d\n",
                       g_memcg[i].name,
                       (unsigned long long)current,
                       (unsigned long long)g_memcg[i].memory_max, pid);
            return pid;  /* This PID should be OOM-killed */
        }
    }
    return 0;  /* No limit exceeded */
}

/**
 * memcg_get_limit — Get the memory.max for a cgroup by path.
 * Returns 0 if unlimited or not found.
 */
uint64_t memcg_get_limit(const char *path) {
    for (int i = 0; i < MEMCG_MAX_GROUPS; i++) {
        if (!g_memcg[i].active) continue;
        const char *a = g_memcg[i].name, *b = path;
        while (*a && *b && *a == *b) { a++; b++; }
        if (*a == '\0' && *b == '\0')
            return g_memcg[i].memory_max;
    }
    return 0;
}

int memcg_group_count(void) {
    int c = 0;
    for (int i = 0; i < MEMCG_MAX_GROUPS; i++)
        if (g_memcg[i].active) c++;
    return c;
}
