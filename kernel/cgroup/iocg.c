/* kernel/cgroup/iocg.c - Cgroup v2 I/O controller
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Per-cgroup block I/O bandwidth limits:
 *   io.max: "MAJ:MIN rbps=N wbps=N riops=N wiops=N"
 *   io.stat: per-device I/O statistics
 */

#include <kernel/kprintf.h>
#include <kernel/errno.h>
#include <kernel/fut_memory.h>
#include <stdint.h>
#include <string.h>

#define IOCG_MAX 16

struct iocg_group {
    bool     active;
    char     name[32];
    uint64_t rbps_max;      /* Read bytes/sec limit (0 = unlimited) */
    uint64_t wbps_max;      /* Write bytes/sec limit */
    uint64_t riops_max;     /* Read IOPS limit */
    uint64_t wiops_max;     /* Write IOPS limit */
    uint64_t bytes_read;
    uint64_t bytes_written;
};

static struct iocg_group g_iocg[IOCG_MAX];

void iocg_init(void) {
    memset(g_iocg, 0, sizeof(g_iocg));
    g_iocg[0].active = true;
    g_iocg[0].name[0] = '/'; g_iocg[0].name[1] = '\0';
    fut_printf("[IOCG] Cgroup v2 I/O controller initialized\n");
}
