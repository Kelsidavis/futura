/* oom_kill.c - OOM (Out-of-Memory) Killer Implementation
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * When the PMM cannot allocate a page and free memory is critically low,
 * the OOM killer selects the process with the highest OOM score and sends
 * it SIGKILL.  This reclaims the victim's address space and allows the
 * system to continue operating.
 *
 * Score formula (Linux-compatible):
 *   1. base = (RSS_pages / total_pages) * 1000
 *   2. base += oom_score_adj                   (-1000 .. +1000)
 *   3. base += (nice_value * 1000) / 40        (nice -20..+19 → -500..+475)
 *      Higher nice = more likely to be killed (same as Linux badness heuristic)
 *   4. Clamp to [0, 1000]
 *
 * Immune processes (score forced to 0, never selected):
 *   - PID 1 (init)
 *   - oom_score_adj == -1000  (OOM_SCORE_ADJ_MIN)
 *   - Kernel threads (task->mm == NULL)
 */

#include "../../include/kernel/oom_kill.h"
#include "../../include/kernel/fut_task.h"
#include "../../include/kernel/fut_mm.h"
#include "../../include/kernel/fut_memory.h"
#include <kernel/signal.h>
#include <kernel/kprintf.h>

/**
 * oom_score_for_task - Compute the OOM badness score for a process.
 *
 * Returns a value in [0, 1000].  0 means "immune -- never kill".
 */
long oom_score_for_task(const void *opaque_task) {
    const fut_task_t *task = (const fut_task_t *)opaque_task;
    if (!task)
        return 0;

    /* PID 1 (init) is always immune */
    if (task->pid == 1)
        return 0;

    /* Zombie processes have no memory to reclaim */
    if (task->state == FUT_TASK_ZOMBIE)
        return 0;

    /* Kernel threads (no address space) are immune */
    if (!task->mm)
        return 0;

    /* oom_score_adj == -1000 means "never kill this process" */
    int adj = task->oom_score_adj;
    if (adj == OOM_SCORE_ADJ_MIN)
        return 0;

    /* Compute RSS in pages by summing VMA sizes.
     * (Same logic used by /proc/<pid>/oom_score in procfs.c) */
    uint64_t rss_pages = 0;
    struct fut_vma *v = task->mm->vma_list;
    while (v) {
        rss_pages += (v->end - v->start) / FUT_PAGE_SIZE;
        v = v->next;
    }

    uint64_t total_pages = fut_pmm_total_pages();
    if (total_pages == 0)
        return 0;

    /* base = (RSS / total) * 1000 */
    long score = (long)((rss_pages * 1000ULL) / total_pages);

    /* Add the per-process OOM score adjustment (-1000 .. +1000) */
    score += adj;

    /* Factor in nice value: higher nice = more likely to be killed.
     * nice ranges from -20 (highest priority) to +19 (lowest priority).
     * We map this linearly: nice * 1000 / 40 = range -500..+475.
     * This matches the Linux heuristic where low-priority tasks are
     * preferred OOM victims. */
    score += ((long)task->nice * 1000L) / 40L;

    /* Clamp to [0, 1000] */
    if (score < 0) score = 0;
    if (score > 1000) score = 1000;

    return score;
}

/* OOM killer state: prevent re-entrant invocations and log storms */
static volatile int oom_killer_active = 0;

/* Context passed through the task iterator callback */
struct oom_scan_ctx {
    fut_task_t *victim;
    long best_score;
    uint64_t victim_rss_pages;
};

/* Callback for fut_task_foreach_all: evaluate each task as a potential victim */
static void oom_scan_cb(fut_task_t *task, void *data) {
    struct oom_scan_ctx *c = (struct oom_scan_ctx *)data;
    long s = oom_score_for_task(task);
    if (s > c->best_score) {
        c->best_score = s;
        c->victim = task;
        /* Compute RSS for the log message */
        uint64_t rss = 0;
        if (task->mm) {
            struct fut_vma *v = task->mm->vma_list;
            while (v) { rss += (v->end - v->start) / FUT_PAGE_SIZE; v = v->next; }
        }
        c->victim_rss_pages = rss;
    }
}

/**
 * oom_kill_process - Select and kill the highest-scoring process.
 *
 * Iterates the global task list under the task list lock, picks the
 * process with the highest OOM score, and sends it SIGKILL.
 *
 * Returns 1 if a victim was killed, 0 if no suitable victim exists.
 */
int oom_kill_process(void) {
    /* Prevent re-entrant OOM kills (e.g. if SIGKILL delivery allocates) */
    if (__atomic_exchange_n(&oom_killer_active, 1, __ATOMIC_ACQ_REL))
        return 0;

    uint64_t free_pages = fut_pmm_free_pages();
    uint64_t total_pages = fut_pmm_total_pages();

    /* Only trigger if we are actually below the threshold */
    uint64_t threshold = total_pages / 100;  /* 1% */
    if (threshold == 0) threshold = 1;

    if (free_pages > threshold) {
        __atomic_store_n(&oom_killer_active, 0, __ATOMIC_RELEASE);
        return 0;
    }

    fut_printf("[OOM] Free memory critically low: %llu/%llu pages (%llu%% free)\n",
               (unsigned long long)free_pages,
               (unsigned long long)total_pages,
               total_pages ? (unsigned long long)(free_pages * 100 / total_pages) : 0ULL);

    /* Walk the task list to find the best victim.
     * fut_task_foreach_all iterates under the task list lock,
     * skipping PID 1 and zombies automatically. */
    struct oom_scan_ctx ctx = { .victim = nullptr, .best_score = 0, .victim_rss_pages = 0 };

    /* Exclude PID 0 (idle) -- fut_task_foreach_all already skips PID 1 and zombies */
    fut_task_foreach_all(0, oom_scan_cb, &ctx);

    if (!ctx.victim) {
        fut_printf("[OOM] No eligible victim found -- cannot reclaim memory\n");
        __atomic_store_n(&oom_killer_active, 0, __ATOMIC_RELEASE);
        return 0;
    }

    /* Log the kill */
    uint64_t rss_kb = ctx.victim_rss_pages * (FUT_PAGE_SIZE / 1024);
    fut_printf("[OOM] Killing pid %llu (%s), score %ld, RSS %llu kB\n",
               (unsigned long long)ctx.victim->pid,
               ctx.victim->comm[0] ? ctx.victim->comm : "<unknown>",
               ctx.best_score,
               (unsigned long long)rss_kb);

    /* Send SIGKILL -- uncatchable, will terminate the process */
    fut_signal_send(ctx.victim, SIGKILL);

    __atomic_store_n(&oom_killer_active, 0, __ATOMIC_RELEASE);
    return 1;
}
