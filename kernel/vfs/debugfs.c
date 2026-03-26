/* kernel/vfs/debugfs.c - debugfs virtual filesystem
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Provides /sys/kernel/debug/ (debugfs) with diagnostic information
 * for kernel debugging and performance analysis tools.
 *
 * Entries:
 *   /sys/kernel/debug/gpio          — GPIO pin state
 *   /sys/kernel/debug/sleep_time    — total sleep time (ns)
 *   /sys/kernel/debug/suspend_stats — suspend/resume statistics
 *   /sys/kernel/debug/wakeup_sources — wakeup source statistics
 *   /sys/kernel/debug/fault_around_bytes — page fault readahead
 *   /sys/kernel/debug/sched_features — scheduler feature flags
 *   /sys/kernel/debug/sched_debug  — scheduler debug output
 *   /sys/kernel/debug/tracing/     — ftrace tracing interface (stub)
 *
 * Used by perf, trace-cmd, bcc/bpftrace, powertop, systemd-analyze.
 */

#include <kernel/fut_vfs.h>
#include <kernel/fut_task.h>
#include <kernel/kprintf.h>
#include <kernel/errno.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

/* ── Node types ── */

enum debugfs_kind {
    DBGFS_ROOT = 0,
    DBGFS_GPIO,
    DBGFS_SLEEP_TIME,
    DBGFS_SUSPEND_STATS,
    DBGFS_WAKEUP_SOURCES,
    DBGFS_FAULT_AROUND,
    DBGFS_SCHED_FEATURES,
    DBGFS_SCHED_DEBUG,
    DBGFS_TRACING_DIR,
    DBGFS_TRACING_AVAIL_TRACERS,
    DBGFS_TRACING_CURRENT_TRACER,
    DBGFS_TRACING_TRACE,
    DBGFS_TRACING_TRACE_PIPE,
    DBGFS_TRACING_TRACING_ON,
    DBGFS_TRACING_BUFFER_SIZE,
};

typedef struct {
    enum debugfs_kind kind;
} debugfs_node_t;

/* ── Forward declarations ── */

static int dbgfs_open(struct fut_vnode *v, int f) { (void)v; (void)f; return 0; }
static int dbgfs_close(struct fut_vnode *v) { (void)v; return 0; }
static ssize_t dbgfs_dir_read(struct fut_vnode *v, void *b, size_t s, uint64_t o) {
    (void)v; (void)b; (void)s; (void)o; return -EISDIR; }
static ssize_t dbgfs_dir_write(struct fut_vnode *v, const void *b, size_t s, uint64_t o) {
    (void)v; (void)b; (void)s; (void)o; return -EISDIR; }
static int dbgfs_readdir(struct fut_vnode *dir, uint64_t *cookie, struct fut_vdirent *de);
static int dbgfs_lookup(struct fut_vnode *dir, const char *name, struct fut_vnode **result);
static ssize_t dbgfs_file_read(struct fut_vnode *v, void *buf, size_t size, uint64_t offset);
static ssize_t dbgfs_file_write(struct fut_vnode *v, const void *buf, size_t size, uint64_t offset);

static const struct fut_vnode_ops dbgfs_dir_ops = {
    .open = dbgfs_open, .close = dbgfs_close,
    .read = dbgfs_dir_read, .write = dbgfs_dir_write,
    .readdir = dbgfs_readdir, .lookup = dbgfs_lookup,
};
static const struct fut_vnode_ops dbgfs_file_ops = {
    .open = dbgfs_open, .close = dbgfs_close,
    .read = dbgfs_file_read, .write = dbgfs_file_write,
};

/* ── Vnode allocation ── */

#define DBGFS_INO_BASE 20000ULL

static struct fut_vnode *dbgfs_alloc(struct fut_mount *mnt, int type, uint64_t ino,
                                      int mode, enum debugfs_kind kind) {
    extern void *fut_malloc(size_t);
    struct fut_vnode *vn = (struct fut_vnode *)fut_malloc(sizeof(struct fut_vnode));
    if (!vn) return NULL;
    memset(vn, 0, sizeof(*vn));
    vn->type = type;
    vn->ino = ino;
    vn->mode = (uint32_t)mode;
    vn->nlinks = (type == 2) ? 2 : 1;
    vn->refcount = 1;
    vn->mount = mnt;
    vn->ops = (type == 2) ? &dbgfs_dir_ops : &dbgfs_file_ops;

    debugfs_node_t *nd = (debugfs_node_t *)fut_malloc(sizeof(debugfs_node_t));
    if (!nd) { extern void fut_free(void *); fut_free(vn); return NULL; }
    nd->kind = kind;
    vn->fs_data = nd;
    return vn;
}

/* ── Directory entries ── */

static const struct { const char *name; enum debugfs_kind kind; int is_dir; } root_files[] = {
    { "gpio",             DBGFS_GPIO,            0 },
    { "sleep_time",       DBGFS_SLEEP_TIME,      0 },
    { "suspend_stats",    DBGFS_SUSPEND_STATS,   0 },
    { "wakeup_sources",   DBGFS_WAKEUP_SOURCES,  0 },
    { "fault_around_bytes", DBGFS_FAULT_AROUND,  0 },
    { "sched_features",   DBGFS_SCHED_FEATURES,  0 },
    { "sched_debug",      DBGFS_SCHED_DEBUG,     0 },
    { "tracing",          DBGFS_TRACING_DIR,     1 },
};
#define ROOT_FILES_N (sizeof(root_files) / sizeof(root_files[0]))

static const struct { const char *name; enum debugfs_kind kind; } tracing_files[] = {
    { "available_tracers",  DBGFS_TRACING_AVAIL_TRACERS },
    { "current_tracer",     DBGFS_TRACING_CURRENT_TRACER },
    { "trace",              DBGFS_TRACING_TRACE },
    { "trace_pipe",         DBGFS_TRACING_TRACE_PIPE },
    { "tracing_on",         DBGFS_TRACING_TRACING_ON },
    { "buffer_size_kb",     DBGFS_TRACING_BUFFER_SIZE },
};
#define TRACING_FILES_N (sizeof(tracing_files) / sizeof(tracing_files[0]))

/* ── Readdir ── */

static int dbgfs_readdir(struct fut_vnode *dir, uint64_t *cookie, struct fut_vdirent *de) {
    debugfs_node_t *nd = (debugfs_node_t *)dir->fs_data;
    if (!nd || !cookie || !de) return 0;
    uint64_t pos = *cookie;
    uint64_t idx = 0;

    if (nd->kind == DBGFS_ROOT) {
        if (pos <= idx) { de->d_ino = DBGFS_INO_BASE; de->d_type = 4;
            de->d_name[0] = '.'; de->d_name[1] = '\0'; *cookie = idx+1; return 1; }
        idx++;
        if (pos <= idx) { de->d_ino = DBGFS_INO_BASE; de->d_type = 4;
            de->d_name[0] = '.'; de->d_name[1] = '.'; de->d_name[2] = '\0'; *cookie = idx+1; return 1; }
        idx++;
        for (size_t f = 0; f < ROOT_FILES_N; f++) {
            if (pos <= idx) {
                de->d_ino = DBGFS_INO_BASE + f + 1;
                de->d_type = root_files[f].is_dir ? 4 : 8;
                size_t nl = 0;
                while (root_files[f].name[nl] && nl < 254) { de->d_name[nl] = root_files[f].name[nl]; nl++; }
                de->d_name[nl] = '\0';
                *cookie = idx + 1; return 1;
            }
            idx++;
        }
    } else if (nd->kind == DBGFS_TRACING_DIR) {
        if (pos <= idx) { de->d_ino = DBGFS_INO_BASE + 100; de->d_type = 4;
            de->d_name[0] = '.'; de->d_name[1] = '\0'; *cookie = idx+1; return 1; }
        idx++;
        if (pos <= idx) { de->d_ino = DBGFS_INO_BASE; de->d_type = 4;
            de->d_name[0] = '.'; de->d_name[1] = '.'; de->d_name[2] = '\0'; *cookie = idx+1; return 1; }
        idx++;
        for (size_t f = 0; f < TRACING_FILES_N; f++) {
            if (pos <= idx) {
                de->d_ino = DBGFS_INO_BASE + 100 + f + 1;
                de->d_type = 8;
                size_t nl = 0;
                while (tracing_files[f].name[nl] && nl < 254) { de->d_name[nl] = tracing_files[f].name[nl]; nl++; }
                de->d_name[nl] = '\0';
                *cookie = idx + 1; return 1;
            }
            idx++;
        }
    }
    return 0;
}

/* ── Lookup ── */

static int dbgfs_lookup(struct fut_vnode *dir, const char *name, struct fut_vnode **result) {
    debugfs_node_t *nd = (debugfs_node_t *)dir->fs_data;
    if (!nd) return -ENOTDIR;

    if (nd->kind == DBGFS_ROOT) {
        for (size_t f = 0; f < ROOT_FILES_N; f++) {
            if (strcmp(name, root_files[f].name) == 0) {
                int type = root_files[f].is_dir ? 2 : 1;
                int mode = root_files[f].is_dir ? 0040555 : 0100444;
                *result = dbgfs_alloc(dir->mount, type, DBGFS_INO_BASE + f + 1,
                                       mode, root_files[f].kind);
                return *result ? 0 : -ENOMEM;
            }
        }
    } else if (nd->kind == DBGFS_TRACING_DIR) {
        for (size_t f = 0; f < TRACING_FILES_N; f++) {
            if (strcmp(name, tracing_files[f].name) == 0) {
                *result = dbgfs_alloc(dir->mount, 1, DBGFS_INO_BASE + 100 + f + 1,
                                       0100644, tracing_files[f].kind);
                return *result ? 0 : -ENOMEM;
            }
        }
    }
    return -ENOENT;
}

/* ── File read ── */

static ssize_t dbgfs_file_read(struct fut_vnode *v, void *buf, size_t size, uint64_t offset) {
    debugfs_node_t *nd = (debugfs_node_t *)v->fs_data;
    if (!nd) return -EINVAL;

    char tmp[512];
    size_t total = 0;

    extern uint64_t fut_get_ticks(void);

    switch (nd->kind) {
    case DBGFS_GPIO:
        total = 5;
        memcpy(tmp, "none\n", 5);
        break;
    case DBGFS_SLEEP_TIME: {
        uint64_t ns = fut_get_ticks() * 10000000ULL;
        int pos = 0;
        char nbuf[20]; int np = 0;
        uint64_t v2 = ns;
        if (v2 == 0) { nbuf[np++] = '0'; }
        else { char rev[20]; int rp = 0;
            while (v2 > 0) { rev[rp++] = '0' + (char)(v2 % 10); v2 /= 10; }
            while (rp > 0) nbuf[np++] = rev[--rp]; }
        for (int i = 0; i < np; i++) tmp[pos++] = nbuf[i];
        tmp[pos++] = '\n'; tmp[pos] = '\0';
        total = (size_t)pos;
        break;
    }
    case DBGFS_SUSPEND_STATS: {
        const char *s = "success: 0\nfail: 0\nfailed_freeze: 0\nfailed_prepare: 0\n"
                        "failed_suspend: 0\nfailed_suspend_late: 0\n"
                        "failed_suspend_noirq: 0\nfailed_resume: 0\n"
                        "failed_resume_early: 0\nfailed_resume_noirq: 0\n"
                        "last_failed_dev:\nlast_failed_errno: 0\nlast_failed_step:\n";
        total = 0;
        while (s[total]) { tmp[total] = s[total]; total++; }
        break;
    }
    case DBGFS_WAKEUP_SOURCES: {
        const char *s = "name\t\tactive_count\tevent_count\twakeup_count\t"
                        "expire_count\tactive_since\ttotal_time\tmax_time\t"
                        "last_change\tprevent_suspend_time\n";
        total = 0;
        while (s[total]) { tmp[total] = s[total]; total++; }
        break;
    }
    case DBGFS_FAULT_AROUND:
        memcpy(tmp, "65536\n", 6); total = 6;
        break;
    case DBGFS_SCHED_FEATURES: {
        const char *s = "GENTLE_FAIR_SLEEPERS START_DEBIT NO_NEXT_BUDDY "
                        "LAST_BUDDY CACHE_HOT_BUDDY WAKEUP_PREEMPTION "
                        "NO_HRTICK NO_DOUBLE_TICK NONTASK_CAPACITY "
                        "TTWU_QUEUE NO_SIS_PROP\n";
        total = 0;
        while (s[total]) { tmp[total] = s[total]; total++; }
        break;
    }
    case DBGFS_SCHED_DEBUG: {
        const char *hdr = "Sched Debug Version: v0.11, futura 6.8.0-futura\n\n"
                          "sysctl_sched\n  .sysctl_sched_latency        : 6.000000\n"
                          "  .sysctl_sched_min_granularity : 0.750000\n"
                          "  .sysctl_sched_wakeup_granularity : 1.000000\n"
                          "  .sysctl_sched_child_runs_first : 0\n\n";
        total = 0;
        while (hdr[total]) { tmp[total] = hdr[total]; total++; }
        break;
    }
    case DBGFS_TRACING_AVAIL_TRACERS:
        memcpy(tmp, "nop\n", 4); total = 4;
        break;
    case DBGFS_TRACING_CURRENT_TRACER:
        memcpy(tmp, "nop\n", 4); total = 4;
        break;
    case DBGFS_TRACING_TRACE:
        /* Empty trace buffer */
        memcpy(tmp, "# tracer: nop\n#\n", 16); total = 16;
        break;
    case DBGFS_TRACING_TRACE_PIPE:
        return 0; /* No data available */
    case DBGFS_TRACING_TRACING_ON:
        memcpy(tmp, "0\n", 2); total = 2;
        break;
    case DBGFS_TRACING_BUFFER_SIZE:
        memcpy(tmp, "1408\n", 5); total = 5;
        break;
    default:
        return -EINVAL;
    }

    if (offset >= total) return 0;
    size_t avail = total - (size_t)offset;
    size_t copy = avail < size ? avail : size;
    memcpy(buf, tmp + offset, copy);
    return (ssize_t)copy;
}

static ssize_t dbgfs_file_write(struct fut_vnode *v, const void *buf, size_t size, uint64_t offset) {
    (void)v; (void)buf; (void)offset;
    /* Accept writes to writable files (tracing_on, current_tracer, etc.) */
    return (ssize_t)size;
}

/* ── Filesystem type ── */

static int dbgfs_mount(const char *device, int flags, void *data,
                        uint64_t bdev, struct fut_mount **mount_out) {
    (void)device; (void)flags; (void)data; (void)bdev;
    extern void *fut_malloc(size_t);
    struct fut_mount *mnt = (struct fut_mount *)fut_malloc(sizeof(struct fut_mount));
    if (!mnt) return -ENOMEM;
    memset(mnt, 0, sizeof(*mnt));
    mnt->root = dbgfs_alloc(mnt, 2, DBGFS_INO_BASE, 0040555, DBGFS_ROOT);
    if (!mnt->root) { extern void fut_free(void *); fut_free(mnt); return -ENOMEM; }
    *mount_out = mnt;
    return 0;
}

static int dbgfs_unmount(struct fut_mount *mnt) { (void)mnt; return 0; }

static const struct fut_fs_type debugfs_type = {
    .name = "debugfs",
    .mount = dbgfs_mount,
    .unmount = dbgfs_unmount,
};

/* Also register as tracefs for /sys/kernel/tracing mounts */
static const struct fut_fs_type tracefs_type = {
    .name = "tracefs",
    .mount = dbgfs_mount,
    .unmount = dbgfs_unmount,
};

void debugfs_init(void) {
    extern int fut_vfs_register_fs(const struct fut_fs_type *fs);
    fut_vfs_register_fs(&debugfs_type);
    fut_vfs_register_fs(&tracefs_type);
    fut_printf("[DEBUGFS] debugfs + tracefs filesystem types registered\n");
}
