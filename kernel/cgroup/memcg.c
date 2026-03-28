/* kernel/cgroup/memcg.c - Cgroup v2 memory controller
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Cgroup v2 memory controller providing:
 *   - memory.current  — actual RSS of member tasks (bytes)
 *   - memory.max      — hard memory limit (writable; "max" = unlimited)
 *   - memory.high     — high watermark for memory pressure (writable)
 *   - memory.low      — minimum memory guarantee (writable)
 *   - memory.stat     — detailed memory statistics per cgroup
 *   - memory.swap.current — current swap usage (always 0, no swap)
 *
 * The root cgroup "/" encompasses all processes. Child cgroups
 * can be created by mkdir in the cgroup filesystem.
 */

#include <kernel/fut_task.h>
#include <kernel/fut_memory.h>
#include <kernel/fut_mm.h>
#include <kernel/kprintf.h>
#include <kernel/errno.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

/* Protection flags for VMA classification (from sys/mman.h) */
#ifndef PROT_EXEC
#define PROT_EXEC 0x4
#endif

#define MEMCG_MAX_GROUPS    16

struct memcg_group {
    bool     active;
    char     name[32];              /* Cgroup path relative to root */
    uint64_t memory_max;            /* Memory limit in bytes (0 = unlimited / "max") */
    uint64_t memory_high;           /* High watermark in bytes (0 = "max") */
    uint64_t memory_low;            /* Minimum guarantee in bytes (0 = no guarantee) */
    int      pids[64];              /* PIDs assigned to this group */
    int      pid_count;
    /* Cumulative page fault counters for this cgroup */
    uint64_t pgfault;               /* Total page faults (minor) */
    uint64_t pgmajfault;            /* Total major page faults */
};

static struct memcg_group g_memcg[MEMCG_MAX_GROUPS];

/* ── Helper: string compare ── */
static bool memcg_streq(const char *a, const char *b) {
    while (*a && *b && *a == *b) { a++; b++; }
    return *a == '\0' && *b == '\0';
}

/* ── Helper: find group by path ── */
static struct memcg_group *memcg_find(const char *path) {
    for (int i = 0; i < MEMCG_MAX_GROUPS; i++) {
        if (g_memcg[i].active && memcg_streq(g_memcg[i].name, path))
            return &g_memcg[i];
    }
    return NULL;
}

void memcg_init(void) {
    memset(g_memcg, 0, sizeof(g_memcg));
    /* Root cgroup is always active */
    g_memcg[0].active = true;
    g_memcg[0].name[0] = '/';
    g_memcg[0].name[1] = '\0';
    g_memcg[0].memory_max = 0;   /* Unlimited */
    g_memcg[0].memory_high = 0;  /* Unlimited */
    g_memcg[0].memory_low = 0;   /* No guarantee */
    fut_printf("[MEMCG] Cgroup v2 memory controller initialized (%d groups)\n",
               MEMCG_MAX_GROUPS);
}

int memcg_create(const char *path) {
    if (!path || !path[0]) return -EINVAL;
    /* Check for duplicate */
    if (memcg_find(path)) return -EEXIST;

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
    g->memory_max = 0;   /* Unlimited */
    g->memory_high = 0;  /* Unlimited */
    g->memory_low = 0;   /* No guarantee */
    g->pid_count = 0;
    g->pgfault = 0;
    g->pgmajfault = 0;

    fut_printf("[MEMCG] Created cgroup '%s'\n", g->name);
    return 0;
}

int memcg_set_limit(const char *path, uint64_t limit_bytes) {
    struct memcg_group *g = memcg_find(path);
    if (!g) return -ENOENT;
    g->memory_max = limit_bytes;
    fut_printf("[MEMCG] Set memory.max=%llu for '%s'\n",
               (unsigned long long)limit_bytes, path);
    return 0;
}

int memcg_set_high(const char *path, uint64_t high_bytes) {
    struct memcg_group *g = memcg_find(path);
    if (!g) return -ENOENT;
    g->memory_high = high_bytes;
    return 0;
}

int memcg_set_low(const char *path, uint64_t low_bytes) {
    struct memcg_group *g = memcg_find(path);
    if (!g) return -ENOENT;
    g->memory_low = low_bytes;
    return 0;
}

int memcg_add_pid(const char *path, int pid) {
    struct memcg_group *g = memcg_find(path);
    if (!g) return -ENOENT;
    if (g->pid_count >= 64) return -ENOSPC;
    g->pids[g->pid_count++] = pid;
    return 0;
}

/* ── Memory statistics per cgroup ── */

struct memcg_stat {
    uint64_t anon;              /* Anonymous memory (private, non-file) in bytes */
    uint64_t file;              /* File-backed (page cache) memory in bytes */
    uint64_t kernel;            /* Kernel memory (page tables, slab overhead) */
    uint64_t slab;              /* Slab allocator memory */
    uint64_t sock;              /* Network socket buffers */
    uint64_t shmem;             /* Shared anonymous (tmpfs/shmem) in bytes */
    uint64_t zswap;             /* Compressed swap cache (0, no zswap) */
    uint64_t zswapped;          /* Original size of zswap pages (0) */
    uint64_t file_mapped;       /* File pages mapped into page tables */
    uint64_t file_dirty;        /* File pages pending writeback */
    uint64_t file_writeback;    /* File pages under active writeback */
    uint64_t pgfault;           /* Total page faults */
    uint64_t pgmajfault;        /* Major page faults */
    uint64_t rss_total;         /* Total RSS (anon + file + shmem) */
};

/**
 * memcg_compute_task_rss — Walk a single task's VMA list and accumulate
 * memory statistics into the provided stat structure.
 */
static void memcg_accumulate_task(fut_task_t *task, struct memcg_stat *st) {
    if (!task || !task->mm) return;

    struct fut_vma *vma = task->mm->vma_list;
    while (vma) {
        uint64_t sz = vma->end - vma->start;

        if (vma->vnode) {
            /* File-backed mapping */
            st->file += sz;
            st->file_mapped += sz;
        } else if (vma->flags & VMA_SHARED) {
            /* Shared anonymous (shmem/tmpfs) */
            st->shmem += sz;
        } else {
            /* Private anonymous: heap, stack, mmap */
            st->anon += sz;
        }
        vma = vma->next;
    }

    /* Accumulate per-task page fault counters */
    st->pgfault += task->minflt;
    st->pgmajfault += task->majflt;
}

/**
 * memcg_get_current — Compute actual memory usage for a cgroup.
 *
 * For the root cgroup (empty name or "/"), sums VmRSS of all tasks.
 * For child cgroups, sums VmRSS of tasks assigned to that group.
 */
uint64_t memcg_get_current(const char *path) {
    struct memcg_stat st;
    memset(&st, 0, sizeof(st));

    /* Root cgroup: iterate all tasks system-wide */
    bool is_root = (!path || path[0] == '\0' || (path[0] == '/' && path[1] == '\0'));

    if (is_root) {
        for (uint64_t pid = 1; pid <= 64; pid++) {
            fut_task_t *t = fut_task_by_pid(pid);
            if (t) memcg_accumulate_task(t, &st);
        }
    } else {
        /* Child cgroup: iterate only member PIDs */
        struct memcg_group *g = memcg_find(path);
        if (g) {
            for (int p = 0; p < g->pid_count; p++) {
                fut_task_t *t = fut_task_by_pid((uint64_t)g->pids[p]);
                if (t) memcg_accumulate_task(t, &st);
            }
        }
    }

    return st.anon + st.file + st.shmem;
}

/**
 * memcg_get_stat — Compute detailed memory statistics for a cgroup.
 * Fills the provided memcg_stat structure.
 */
void memcg_get_stat(const char *path, struct memcg_stat *st) {
    memset(st, 0, sizeof(*st));

    bool is_root = (!path || path[0] == '\0' || (path[0] == '/' && path[1] == '\0'));

    if (is_root) {
        for (uint64_t pid = 1; pid <= 64; pid++) {
            fut_task_t *t = fut_task_by_pid(pid);
            if (t) memcg_accumulate_task(t, st);
        }
    } else {
        struct memcg_group *g = memcg_find(path);
        if (g) {
            for (int p = 0; p < g->pid_count; p++) {
                fut_task_t *t = fut_task_by_pid((uint64_t)g->pids[p]);
                if (t) memcg_accumulate_task(t, st);
            }
            /* Add cgroup-level fault counters accumulated from exited tasks */
            st->pgfault += g->pgfault;
            st->pgmajfault += g->pgmajfault;
        }
    }

    st->rss_total = st->anon + st->file + st->shmem;

    /* Estimate kernel overhead: page table entries (~8 bytes per 4KB page) */
    uint64_t total_pages = st->rss_total / 4096;
    st->kernel = total_pages * 8;  /* PTE overhead */
    st->slab = st->kernel / 4;    /* Rough slab estimate */
}

/**
 * memcg_format_stat — Format memory.stat output into a buffer.
 * Returns the number of bytes written, or negative errno.
 */
int memcg_format_stat(const char *path, char *buf, size_t bufsz) {
    struct memcg_stat st;
    memcg_get_stat(path, &st);

    /* Manual formatting — no snprintf in kernel */
    int pos = 0;

    /* Helper macro: append "key value\n" to buf */
#define STAT_LINE(key, val) do {                                        \
        const char *_k = (key);                                         \
        while (*_k && pos < (int)bufsz - 1) buf[pos++] = *_k++;        \
        if (pos < (int)bufsz - 1) buf[pos++] = ' ';                    \
        uint64_t _v = (val);                                            \
        if (_v == 0) {                                                  \
            if (pos < (int)bufsz - 1) buf[pos++] = '0';                \
        } else {                                                        \
            char _rev[20]; int _rp = 0;                                 \
            while (_v > 0) { _rev[_rp++] = '0' + (char)(_v % 10); _v /= 10; } \
            while (_rp > 0 && pos < (int)bufsz - 1) buf[pos++] = _rev[--_rp]; \
        }                                                               \
        if (pos < (int)bufsz - 1) buf[pos++] = '\n';                   \
    } while (0)

    STAT_LINE("anon", st.anon);
    STAT_LINE("file", st.file);
    STAT_LINE("kernel", st.kernel);
    STAT_LINE("slab", st.slab);
    STAT_LINE("sock", st.sock);
    STAT_LINE("shmem", st.shmem);
    STAT_LINE("zswap", st.zswap);
    STAT_LINE("zswapped", st.zswapped);
    STAT_LINE("file_mapped", st.file_mapped);
    STAT_LINE("file_dirty", st.file_dirty);
    STAT_LINE("file_writeback", st.file_writeback);
    STAT_LINE("pgfault", st.pgfault);
    STAT_LINE("pgmajfault", st.pgmajfault);

#undef STAT_LINE

    if (pos < (int)bufsz) buf[pos] = '\0';
    return pos;
}

/**
 * memcg_get_max — Get memory.max for a cgroup by path.
 * Returns 0 if unlimited or not found.
 */
uint64_t memcg_get_max(const char *path) {
    struct memcg_group *g = memcg_find(path);
    return g ? g->memory_max : 0;
}

/**
 * memcg_get_high — Get memory.high for a cgroup by path.
 * Returns 0 if unlimited or not found.
 */
uint64_t memcg_get_high(const char *path) {
    struct memcg_group *g = memcg_find(path);
    return g ? g->memory_high : 0;
}

/**
 * memcg_get_low — Get memory.low for a cgroup by path.
 * Returns 0 if no guarantee or not found.
 */
uint64_t memcg_get_low(const char *path) {
    struct memcg_group *g = memcg_find(path);
    return g ? g->memory_low : 0;
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
    return memcg_get_max(path);
}

int memcg_group_count(void) {
    int c = 0;
    for (int i = 0; i < MEMCG_MAX_GROUPS; i++)
        if (g_memcg[i].active) c++;
    return c;
}
