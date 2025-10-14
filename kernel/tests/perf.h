// SPDX-License-Identifier: MPL-2.0

#pragma once

#include <stddef.h>
#include <stdint.h>

#include <kernel/perf_clock.h>

struct fut_task;

int fut_perf_run_ipc(struct fut_perf_stats *out);
int fut_perf_run_ctx_switch(struct fut_perf_stats *out);
int fut_perf_run_blk(struct fut_perf_stats *read_stats,
                     struct fut_perf_stats *write_stats);
int fut_perf_run_net(struct fut_perf_stats *small_stats,
                     struct fut_perf_stats *mtu_stats);

void fut_perf_selftest_schedule(struct fut_task *task);
