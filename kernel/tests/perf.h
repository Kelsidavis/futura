// SPDX-License-Identifier: MPL-2.0

#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include <kernel/perf_clock.h>

struct fut_task;

/* Safety limits to prevent runaway thread creation */
#define PERF_MAX_THREADS        10u
#define PERF_BENCHMARK_TIMEOUT_MS 30000u  /* 30 seconds per benchmark */

int fut_perf_run_ipc(struct fut_perf_stats *out);
int fut_perf_run_ctx_switch(struct fut_perf_stats *out);
int fut_perf_run_blk(struct fut_perf_stats *read_stats,
                     struct fut_perf_stats *write_stats);
int fut_perf_run_net(struct fut_perf_stats *small_stats,
                     struct fut_perf_stats *mtu_stats);

void fut_perf_selftest_schedule(struct fut_task *task);

/* Thread count tracking */
bool fut_perf_can_create_thread(void);
void fut_perf_thread_created(void);
void fut_perf_thread_destroyed(void);
uint32_t fut_perf_get_thread_count(void);
