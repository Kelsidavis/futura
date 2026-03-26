/* kernel/cgroup/freezer.c - Cgroup v2 freezer controller
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Pause/resume all processes in a cgroup (docker pause/unpause):
 *   cgroup.freeze: write 1 to freeze, 0 to thaw
 *   cgroup.events: "frozen 0" or "frozen 1"
 */

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
