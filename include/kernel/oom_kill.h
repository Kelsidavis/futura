/* oom_kill.h - OOM (Out-of-Memory) Killer
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * When the system runs critically low on physical memory, the OOM killer
 * selects and kills the process with the highest OOM score to reclaim pages.
 *
 * OOM score calculation (Linux-compatible):
 *   base_score = (process_rss / total_ram) * 1000
 *   score = base_score + oom_score_adj + nice_adjustment
 *   clamped to [0, 1000]
 *
 * Processes with oom_score_adj == -1000 (OOM_SCORE_ADJ_MIN) are immune.
 * PID 1 (init) is always immune.
 * Kernel threads (no mm) are always immune.
 */

#pragma once

#include <stdint.h>

/* OOM score adjustment range (matches Linux) */
#define OOM_SCORE_ADJ_MIN  (-1000)
#define OOM_SCORE_ADJ_MAX  1000

/* OOM threshold: trigger when free pages fall below this fraction of total.
 * Default: 1% of total physical memory. */
#define OOM_FREE_THRESHOLD_PERCENT  1

/**
 * Try to free memory by killing the highest-scoring process.
 *
 * Called from the PMM when a page allocation fails and free memory is
 * critically low (below OOM_FREE_THRESHOLD_PERCENT of total).
 *
 * @return 1 if a process was killed (caller should retry allocation),
 *         0 if no suitable victim was found (allocation must fail).
 */
int oom_kill_process(void);

/**
 * Calculate the OOM score for a given task.
 *
 * @param task  Task to score (must not be NULL)
 * @return OOM score in range [0, 1000], or 0 if task is immune
 */
long oom_score_for_task(const void *task);
