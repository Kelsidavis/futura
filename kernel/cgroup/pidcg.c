/* kernel/cgroup/pidcg.c - Cgroup v2 PID controller
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Limits the number of processes per cgroup (fork bomb prevention):
 *   pids.max: maximum number of processes (default: unlimited)
 *   pids.current: current process count
 */

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
