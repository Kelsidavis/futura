/* kernel/cgroup/cgroupfs.c - Cgroup v2 unified hierarchy filesystem
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements a mountable cgroup2 filesystem that exposes the unified
 * hierarchy at /sys/fs/cgroup/. Provides the standard interface files:
 *
 *   cgroup.controllers     — available controllers (cpuset cpu io memory pids)
 *   cgroup.subtree_control — enabled controllers for children
 *   cgroup.procs           — list of PIDs in this cgroup
 *   cgroup.type            — "domain" or "threaded"
 *   cgroup.events          — populated/frozen state
 *   cgroup.stat            — nr_descendants, nr_dying_descendants
 *   memory.current         — current memory usage
 *   memory.max             — memory limit
 *   memory.high            — high watermark
 *   cpu.max                — CPU bandwidth limit
 *   cpu.weight             — CPU weight (1-10000)
 *   pids.max               — PID limit
 *   pids.current           — current PID count
 *   io.max                 — I/O bandwidth limit
 *   io.stat                — per-device I/O statistics
 *   cgroup.freeze          — freeze state (0/1)
 *   cpuset.cpus            — allowed CPU set (e.g., "0-3")
 *   cpuset.cpus.effective  — effective CPU set
 *   cpuset.mems            — allowed memory nodes (e.g., "0")
 *   cpuset.mems.effective  — effective memory nodes
 *   cpuset.cpus.partition  — partition type (member/root/isolated)
 *
 * Used by systemd, Docker, Kubernetes, containerd, and all modern
 * container runtimes that require cgroup v2 support.
 */

#include <kernel/fut_vfs.h>
#include <kernel/fut_task.h>
#include <kernel/fut_memory.h>
#include <kernel/kprintf.h>
#include <kernel/errno.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

/* ── Cgroup node types ── */

enum cgroupfs_file {
    CGFS_DIR = 0,
    CGFS_CONTROLLERS,
    CGFS_SUBTREE_CONTROL,
    CGFS_PROCS,
    CGFS_TYPE,
    CGFS_EVENTS,
    CGFS_STAT,
    CGFS_MEM_CURRENT,
    CGFS_MEM_MAX,
    CGFS_MEM_HIGH,
    CGFS_MEM_LOW,
    CGFS_MEM_STAT,
    CGFS_MEM_SWAP_CURRENT,
    CGFS_MEM_SWAP_MAX,
    CGFS_CPU_MAX,
    CGFS_CPU_WEIGHT,
    CGFS_CPU_STAT,
    CGFS_PIDS_MAX,
    CGFS_PIDS_CURRENT,
    CGFS_IO_MAX,
    CGFS_IO_STAT,
    CGFS_FREEZE,
    CGFS_CPUSET_CPUS,
    CGFS_CPUSET_CPUS_EFF,
    CGFS_CPUSET_MEMS,
    CGFS_CPUSET_MEMS_EFF,
    CGFS_CPUSET_PARTITION,
};

typedef struct {
    enum cgroupfs_file ftype;
    int cgroup_idx;     /* Index into cgroup group arrays (0 = root) */
} cgroupfs_node_t;

/* Forward declarations */
int cgfs_readdir(struct fut_vnode *dir, uint64_t *cookie, struct fut_vdirent *de);
int cgfs_lookup(struct fut_vnode *dir, const char *name, struct fut_vnode **result);
int cgfs_mkdir(struct fut_vnode *dir, const char *name, uint32_t mode);
int cgfs_dir_open(struct fut_vnode *vnode, int flags);
int cgfs_dir_close(struct fut_vnode *vnode);
ssize_t cgfs_dir_read(struct fut_vnode *v, void *b, size_t s, uint64_t o);
ssize_t cgfs_dir_write(struct fut_vnode *v, const void *b, size_t s, uint64_t o);
int cgfs_file_open(struct fut_vnode *vnode, int flags);
ssize_t cgfs_file_read(struct fut_vnode *vnode, void *buf, size_t size, uint64_t offset);
ssize_t cgfs_file_write(struct fut_vnode *vnode, const void *buf, size_t size, uint64_t offset);

/* ── VFS operations ── */

static const struct fut_vnode_ops cgfs_dir_ops = {
    .open    = cgfs_dir_open,
    .close   = cgfs_dir_close,
    .read    = cgfs_dir_read,
    .write   = cgfs_dir_write,
    .readdir = cgfs_readdir,
    .lookup  = cgfs_lookup,
    .mkdir   = cgfs_mkdir,
};

static const struct fut_vnode_ops cgfs_file_ops = {
    .open  = cgfs_file_open,
    .close = cgfs_dir_close,
    .read  = cgfs_file_read,
    .write = cgfs_file_write,
};

/* ── Cgroup hierarchy state ── */

#define MAX_CGROUPS     16
#define MAX_CG_NAME     64
#define CGFS_INO_BASE   10000ULL

struct cgroup_node {
    bool    active;
    char    name[MAX_CG_NAME];     /* Relative path from root (e.g., "docker/abc") */
    int     parent;                /* Parent index (-1 for root) */
    int     nr_children;
};

static struct cgroup_node g_cgroups[MAX_CGROUPS];
static bool g_cgfs_initialized = false;

static void cgfs_ensure_init(void) {
    if (g_cgfs_initialized) return;
    memset(g_cgroups, 0, sizeof(g_cgroups));
    g_cgroups[0].active = true;
    g_cgroups[0].name[0] = '\0'; /* Root cgroup */
    g_cgroups[0].parent = -1;
    g_cgfs_initialized = true;
}

/* ── Vnode allocation ── */

static struct fut_vnode *cgfs_alloc_vnode(struct fut_mount *mnt, int type,
                                           uint64_t ino, int mode,
                                           enum cgroupfs_file ftype, int cg_idx) {
    extern void *fut_malloc(size_t);
    struct fut_vnode *vn = (struct fut_vnode *)fut_malloc(sizeof(struct fut_vnode));
    if (!vn) return NULL;
    memset(vn, 0, sizeof(*vn));

    vn->type = type;
    vn->ino = ino;
    vn->mode = (uint32_t)mode;
    vn->uid = 0;
    vn->gid = 0;
    vn->size = 0;
    vn->nlinks = (type == 2 /*VN_DIR*/) ? 2 : 1;
    vn->refcount = 1;
    vn->mount = mnt;
    vn->ops = (type == 2) ? &cgfs_dir_ops : &cgfs_file_ops;

    cgroupfs_node_t *nd = (cgroupfs_node_t *)fut_malloc(sizeof(cgroupfs_node_t));
    if (!nd) { extern void fut_free(void *); fut_free(vn); return NULL; }
    nd->ftype = ftype;
    nd->cgroup_idx = cg_idx;
    vn->fs_data = nd;

    return vn;
}

/* ── Directory operations ── */

int cgfs_dir_open(struct fut_vnode *vnode, int flags) {
    (void)vnode; (void)flags; return 0;
}
int cgfs_dir_close(struct fut_vnode *vnode) {
    (void)vnode; return 0;
}
ssize_t cgfs_dir_read(struct fut_vnode *v, void *b, size_t s, uint64_t o) {
    (void)v; (void)b; (void)s; (void)o; return -EISDIR;
}
ssize_t cgfs_dir_write(struct fut_vnode *v, const void *b, size_t s, uint64_t o) {
    (void)v; (void)b; (void)s; (void)o; return -EISDIR;
}

/* Standard cgroup interface files for each cgroup directory */
static const struct {
    const char *name;
    enum cgroupfs_file ftype;
    int mode;
} cg_files[] = {
    { "cgroup.controllers",     CGFS_CONTROLLERS,     0100444 },
    { "cgroup.subtree_control", CGFS_SUBTREE_CONTROL, 0100644 },
    { "cgroup.procs",           CGFS_PROCS,           0100644 },
    { "cgroup.type",            CGFS_TYPE,            0100644 },
    { "cgroup.events",          CGFS_EVENTS,          0100444 },
    { "cgroup.stat",            CGFS_STAT,            0100444 },
    { "cgroup.freeze",          CGFS_FREEZE,          0100644 },
    { "memory.current",         CGFS_MEM_CURRENT,     0100444 },
    { "memory.max",             CGFS_MEM_MAX,         0100644 },
    { "memory.high",            CGFS_MEM_HIGH,        0100644 },
    { "memory.low",             CGFS_MEM_LOW,         0100644 },
    { "memory.stat",            CGFS_MEM_STAT,        0100444 },
    { "memory.swap.current",    CGFS_MEM_SWAP_CURRENT,0100444 },
    { "memory.swap.max",        CGFS_MEM_SWAP_MAX,    0100644 },
    { "cpu.max",                CGFS_CPU_MAX,         0100644 },
    { "cpu.weight",             CGFS_CPU_WEIGHT,      0100644 },
    { "cpu.stat",               CGFS_CPU_STAT,        0100444 },
    { "pids.max",               CGFS_PIDS_MAX,        0100644 },
    { "pids.current",           CGFS_PIDS_CURRENT,    0100444 },
    { "io.max",                 CGFS_IO_MAX,          0100644 },
    { "io.stat",                CGFS_IO_STAT,         0100444 },
    { "cpuset.cpus",            CGFS_CPUSET_CPUS,     0100644 },
    { "cpuset.cpus.effective",  CGFS_CPUSET_CPUS_EFF, 0100444 },
    { "cpuset.mems",            CGFS_CPUSET_MEMS,     0100644 },
    { "cpuset.mems.effective",  CGFS_CPUSET_MEMS_EFF, 0100444 },
    { "cpuset.cpus.partition",  CGFS_CPUSET_PARTITION,0100644 },
};
#define CG_NUM_FILES (sizeof(cg_files) / sizeof(cg_files[0]))

static bool cgfs_tok_eq(const char *tok, size_t tok_len, const char *lit) {
    size_t i = 0;
    while (i < tok_len && lit[i] && tok[i] == lit[i]) i++;
    return i == tok_len && lit[i] == '\0';
}

static int cgfs_parse_u64_token(const char *tok, size_t tok_len, uint64_t *out) {
    if (cgfs_tok_eq(tok, tok_len, "max")) {
        *out = 0;
        return 0;
    }

    if (tok_len == 0) return -EINVAL;
    uint64_t v = 0;
    for (size_t i = 0; i < tok_len; i++) {
        if (tok[i] < '0' || tok[i] > '9') return -EINVAL;
        v = v * 10 + (uint64_t)(tok[i] - '0');
    }
    *out = v;
    return 0;
}

static int cgfs_parse_iomax_line(const char *buf, size_t size, uint64_t *rbps,
                                 uint64_t *wbps, uint64_t *riops, uint64_t *wiops) {
    uint64_t new_rbps = 0, new_wbps = 0, new_riops = 0, new_wiops = 0;
    size_t i = 0;

    while (i < size) {
        while (i < size && (buf[i] == ' ' || buf[i] == '\t' || buf[i] == '\n' || buf[i] == '\r')) i++;
        if (i >= size) break;

        size_t start = i;
        while (i < size && buf[i] != ' ' && buf[i] != '\t' && buf[i] != '\n' && buf[i] != '\r') i++;
        size_t len = i - start;
        if (len == 0) continue;

        size_t eq = 0;
        while (eq < len && buf[start + eq] != '=') eq++;
        if (eq == len || eq == 0 || eq + 1 >= len) continue; /* Device token or malformed token */

        const char *key = buf + start;
        const char *val = buf + start + eq + 1;
        size_t key_len = eq;
        size_t val_len = len - eq - 1;
        uint64_t parsed = 0;

        if (cgfs_tok_eq(key, key_len, "rbps")) {
            if (cgfs_parse_u64_token(val, val_len, &parsed) < 0) return -EINVAL;
            new_rbps = parsed;
        } else if (cgfs_tok_eq(key, key_len, "wbps")) {
            if (cgfs_parse_u64_token(val, val_len, &parsed) < 0) return -EINVAL;
            new_wbps = parsed;
        } else if (cgfs_tok_eq(key, key_len, "riops")) {
            if (cgfs_parse_u64_token(val, val_len, &parsed) < 0) return -EINVAL;
            new_riops = parsed;
        } else if (cgfs_tok_eq(key, key_len, "wiops")) {
            if (cgfs_parse_u64_token(val, val_len, &parsed) < 0) return -EINVAL;
            new_wiops = parsed;
        }
    }

    *rbps = new_rbps;
    *wbps = new_wbps;
    *riops = new_riops;
    *wiops = new_wiops;
    return 0;
}

int cgfs_readdir(struct fut_vnode *dir, uint64_t *cookie, struct fut_vdirent *de) {
    cgroupfs_node_t *nd = (cgroupfs_node_t *)dir->fs_data;
    if (!nd || nd->ftype != CGFS_DIR || !cookie || !de) return 0;
    cgfs_ensure_init();

    int cg_idx = nd->cgroup_idx;
    uint64_t pos = *cookie;
    uint64_t idx = 0;

    /* "." */
    if (pos <= idx) {
        de->d_ino = CGFS_INO_BASE + (uint64_t)cg_idx * 100;
        de->d_type = 4; /* DT_DIR */
        de->d_name[0] = '.'; de->d_name[1] = '\0';
        *cookie = idx + 1;
        return 1;
    }
    idx++;

    /* ".." */
    if (pos <= idx) {
        de->d_ino = CGFS_INO_BASE;
        de->d_type = 4;
        de->d_name[0] = '.'; de->d_name[1] = '.'; de->d_name[2] = '\0';
        *cookie = idx + 1;
        return 1;
    }
    idx++;

    /* Interface files */
    for (size_t f = 0; f < CG_NUM_FILES; f++) {
        if (pos <= idx) {
            de->d_ino = CGFS_INO_BASE + (uint64_t)cg_idx * 100 + f + 1;
            de->d_type = 8; /* DT_REG */
            size_t nl = 0;
            while (cg_files[f].name[nl] && nl < 254) {
                de->d_name[nl] = cg_files[f].name[nl]; nl++;
            }
            de->d_name[nl] = '\0';
            *cookie = idx + 1;
            return 1;
        }
        idx++;
    }

    /* Child cgroup directories */
    for (int i = 0; i < MAX_CGROUPS; i++) {
        if (!g_cgroups[i].active || g_cgroups[i].parent != cg_idx) continue;
        if (pos <= idx) {
            de->d_ino = CGFS_INO_BASE + (uint64_t)i * 100;
            de->d_type = 4;
            const char *n = g_cgroups[i].name;
            const char *last = n;
            while (*n) { if (*n == '/') last = n + 1; n++; }
            size_t nl = 0;
            while (last[nl] && nl < 254) { de->d_name[nl] = last[nl]; nl++; }
            de->d_name[nl] = '\0';
            *cookie = idx + 1;
            return 1;
        }
        idx++;
    }

    return 0; /* No more entries */
}

int cgfs_lookup(struct fut_vnode *dir, const char *name,
                        struct fut_vnode **result) {
    cgroupfs_node_t *nd = (cgroupfs_node_t *)dir->fs_data;
    if (!nd || nd->ftype != CGFS_DIR) return -ENOTDIR;
    cgfs_ensure_init();

    int cg_idx = nd->cgroup_idx;

    /* Check interface files */
    for (size_t f = 0; f < CG_NUM_FILES; f++) {
        if (strcmp(name, cg_files[f].name) == 0) {
            *result = cgfs_alloc_vnode(dir->mount, 1 /*VN_REG*/,
                                        CGFS_INO_BASE + (uint64_t)cg_idx * 100 + f + 1,
                                        cg_files[f].mode, cg_files[f].ftype, cg_idx);
            return *result ? 0 : -ENOMEM;
        }
    }

    /* Check child cgroups */
    for (int i = 0; i < MAX_CGROUPS; i++) {
        if (!g_cgroups[i].active || g_cgroups[i].parent != cg_idx) continue;
        const char *n = g_cgroups[i].name;
        const char *last = n;
        while (*n) { if (*n == '/') last = n + 1; n++; }
        if (strcmp(name, last) == 0) {
            *result = cgfs_alloc_vnode(dir->mount, 2 /*VN_DIR*/,
                                        CGFS_INO_BASE + (uint64_t)i * 100,
                                        0040755, CGFS_DIR, i);
            return *result ? 0 : -ENOMEM;
        }
    }

    return -ENOENT;
}

int cgfs_mkdir(struct fut_vnode *dir, const char *name, uint32_t mode) {
    (void)mode;
    cgroupfs_node_t *nd = (cgroupfs_node_t *)dir->fs_data;
    if (!nd || nd->ftype != CGFS_DIR) return -ENOTDIR;
    cgfs_ensure_init();

    int parent = nd->cgroup_idx;

    /* Find free slot */
    int slot = -1;
    for (int i = 1; i < MAX_CGROUPS; i++) {
        if (!g_cgroups[i].active) { slot = i; break; }
    }
    if (slot < 0) return -ENOSPC;

    /* Build path */
    g_cgroups[slot].active = true;
    g_cgroups[slot].parent = parent;
    g_cgroups[slot].nr_children = 0;

    if (g_cgroups[parent].name[0] == '\0') {
        /* Parent is root */
        size_t nl = 0;
        while (name[nl] && nl < MAX_CG_NAME - 1) {
            g_cgroups[slot].name[nl] = name[nl]; nl++;
        }
        g_cgroups[slot].name[nl] = '\0';
    } else {
        /* Parent is non-root */
        int pos = 0;
        const char *p = g_cgroups[parent].name;
        while (*p && pos < MAX_CG_NAME - 2) g_cgroups[slot].name[pos++] = *p++;
        g_cgroups[slot].name[pos++] = '/';
        while (*name && pos < MAX_CG_NAME - 1) g_cgroups[slot].name[pos++] = *name++;
        g_cgroups[slot].name[pos] = '\0';
    }

    g_cgroups[parent].nr_children++;

    /* Notify controllers */
    extern int memcg_create(const char *);
    extern int iocg_create(const char *);
    memcg_create(g_cgroups[slot].name);
    iocg_create(g_cgroups[slot].name);

    fut_printf("[CGROUPFS] Created cgroup '%s' (slot %d, parent %d)\n",
               g_cgroups[slot].name, slot, parent);
    return 0;
}

/* ── File read operations ── */

int cgfs_file_open(struct fut_vnode *vnode, int flags) {
    (void)vnode; (void)flags; return 0;
}

ssize_t cgfs_file_read(struct fut_vnode *vnode, void *buf, size_t size, uint64_t offset) {
    cgroupfs_node_t *nd = (cgroupfs_node_t *)vnode->fs_data;
    if (!nd) return -EINVAL;

    char tmp[1024];
    size_t total = 0;

    extern uint64_t memcg_get_current(const char *);
    extern uint64_t memcg_get_max(const char *);
    extern uint64_t memcg_get_high(const char *);
    extern uint64_t memcg_get_low(const char *);
    extern int memcg_format_stat(const char *, char *, size_t);
    extern int memcg_set_limit(const char *, uint64_t);
    extern int memcg_set_high(const char *, uint64_t);
    extern int memcg_set_low(const char *, uint64_t);

    const char *cg_name = (nd->cgroup_idx < MAX_CGROUPS && g_cgroups[nd->cgroup_idx].active)
                          ? g_cgroups[nd->cgroup_idx].name : "";

    switch (nd->ftype) {
    case CGFS_CONTROLLERS: {
        const char *s = "cpuset cpu io memory pids\n";
        total = 0;
        while (s[total]) { tmp[total] = s[total]; total++; }
        break;
    }
    case CGFS_SUBTREE_CONTROL: {
        const char *s = "cpuset cpu io memory pids\n";
        total = 0;
        while (s[total]) { tmp[total] = s[total]; total++; }
        break;
    }
    case CGFS_PROCS: {
        /* List PIDs — enumerate by scanning PID range */
        int pos = 0;
        for (uint64_t pid = 1; pid <= 64 && pos < 480; pid++) {
            fut_task_t *t = fut_task_by_pid(pid);
            if (!t) continue;
            char nbuf[16]; int np = 0;
            uint64_t p = pid;
            if (p == 0) { nbuf[np++] = '0'; }
            else {
                char rev[16]; int rp = 0;
                while (p > 0) { rev[rp++] = '0' + (char)(p % 10); p /= 10; }
                while (rp > 0) nbuf[np++] = rev[--rp];
            }
            for (int i = 0; i < np && pos < 500; i++) tmp[pos++] = nbuf[i];
            tmp[pos++] = '\n';
        }
        tmp[pos] = '\0';
        total = (size_t)pos;
        break;
    }
    case CGFS_TYPE: {
        const char *s = "domain\n";
        total = 0;
        while (s[total]) { tmp[total] = s[total]; total++; }
        break;
    }
    case CGFS_EVENTS: {
        const char *s = "populated 1\nfrozen 0\n";
        total = 0;
        while (s[total]) { tmp[total] = s[total]; total++; }
        break;
    }
    case CGFS_STAT: {
        const char *s = "nr_descendants 0\nnr_dying_descendants 0\n";
        total = 0;
        while (s[total]) { tmp[total] = s[total]; total++; }
        break;
    }
    case CGFS_MEM_CURRENT: {
        uint64_t cur = memcg_get_current(cg_name);
        int pos = 0;
        char nbuf[20]; int np = 0;
        if (cur == 0) { nbuf[np++] = '0'; }
        else {
            char rev[20]; int rp = 0;
            while (cur > 0) { rev[rp++] = '0' + (char)(cur % 10); cur /= 10; }
            while (rp > 0) nbuf[np++] = rev[--rp];
        }
        for (int i = 0; i < np; i++) tmp[pos++] = nbuf[i];
        tmp[pos++] = '\n'; tmp[pos] = '\0';
        total = (size_t)pos;
        break;
    }
    case CGFS_MEM_MAX: {
        uint64_t limit = memcg_get_max(cg_name);
        int pos = 0;
        if (limit == 0) {
            /* Unlimited */
            tmp[pos++] = 'm'; tmp[pos++] = 'a'; tmp[pos++] = 'x';
        } else {
            char nbuf[20]; int np = 0;
            char rev[20]; int rp = 0;
            while (limit > 0) { rev[rp++] = '0' + (char)(limit % 10); limit /= 10; }
            while (rp > 0) nbuf[np++] = rev[--rp];
            for (int i = 0; i < np; i++) tmp[pos++] = nbuf[i];
        }
        tmp[pos++] = '\n'; tmp[pos] = '\0';
        total = (size_t)pos;
        break;
    }
    case CGFS_MEM_HIGH: {
        uint64_t high = memcg_get_high(cg_name);
        int pos = 0;
        if (high == 0) {
            tmp[pos++] = 'm'; tmp[pos++] = 'a'; tmp[pos++] = 'x';
        } else {
            char nbuf[20]; int np = 0;
            char rev[20]; int rp = 0;
            while (high > 0) { rev[rp++] = '0' + (char)(high % 10); high /= 10; }
            while (rp > 0) nbuf[np++] = rev[--rp];
            for (int i = 0; i < np; i++) tmp[pos++] = nbuf[i];
        }
        tmp[pos++] = '\n'; tmp[pos] = '\0';
        total = (size_t)pos;
        break;
    }
    case CGFS_MEM_LOW: {
        uint64_t low = memcg_get_low(cg_name);
        int pos = 0;
        if (low == 0) {
            tmp[pos++] = '0';
        } else {
            char nbuf[20]; int np = 0;
            char rev[20]; int rp = 0;
            while (low > 0) { rev[rp++] = '0' + (char)(low % 10); low /= 10; }
            while (rp > 0) nbuf[np++] = rev[--rp];
            for (int i = 0; i < np; i++) tmp[pos++] = nbuf[i];
        }
        tmp[pos++] = '\n'; tmp[pos] = '\0';
        total = (size_t)pos;
        break;
    }
    case CGFS_MEM_STAT: {
        int len = memcg_format_stat(cg_name, tmp, sizeof(tmp));
        if (len < 0) return len;
        total = (size_t)len;
        break;
    }
    case CGFS_MEM_SWAP_CURRENT: {
        /* No swap support — always report 0 */
        tmp[0] = '0'; tmp[1] = '\n'; tmp[2] = '\0';
        total = 2;
        break;
    }
    case CGFS_MEM_SWAP_MAX: {
        const char *s = "max\n";
        total = 0;
        while (s[total]) { tmp[total] = s[total]; total++; }
        break;
    }
    case CGFS_CPU_MAX: {
        const char *s = "max 100000\n";
        total = 0;
        while (s[total]) { tmp[total] = s[total]; total++; }
        break;
    }
    case CGFS_CPU_WEIGHT: {
        const char *s = "100\n";
        total = 0;
        while (s[total]) { tmp[total] = s[total]; total++; }
        break;
    }
    case CGFS_CPU_STAT: {
        const char *s = "usage_usec 0\nuser_usec 0\nsystem_usec 0\n"
                        "nr_periods 0\nnr_throttled 0\nthrottled_usec 0\n";
        total = 0;
        while (s[total]) { tmp[total] = s[total]; total++; }
        break;
    }
    case CGFS_PIDS_MAX: {
        const char *s = "max\n";
        total = 0;
        while (s[total]) { tmp[total] = s[total]; total++; }
        break;
    }
    case CGFS_PIDS_CURRENT: {
        /* Count active tasks by scanning PID range */
        int count = 0;
        for (uint64_t pid = 1; pid <= 64; pid++) {
            if (fut_task_by_pid(pid)) count++;
        }
        int pos = 0;
        char nbuf[16]; int np = 0;
        if (count == 0) { nbuf[np++] = '0'; }
        else {
            char rev[16]; int rp = 0;
            while (count > 0) { rev[rp++] = '0' + (char)(count % 10); count /= 10; }
            while (rp > 0) nbuf[np++] = rev[--rp];
        }
        for (int i = 0; i < np; i++) tmp[pos++] = nbuf[i];
        tmp[pos++] = '\n'; tmp[pos] = '\0';
        total = (size_t)pos;
        break;
    }
    case CGFS_IO_MAX: {
        extern int iocg_get_max(const char *, char *, size_t);
        int len = iocg_get_max(cg_name, tmp, sizeof(tmp));
        if (len < 0) return len;
        total = (size_t)len;
        break;
    }
    case CGFS_IO_STAT: {
        extern int iocg_get_stat(const char *, char *, size_t);
        int len = iocg_get_stat(cg_name, tmp, sizeof(tmp));
        if (len < 0) return len;
        total = (size_t)len;
        break;
    }
    case CGFS_FREEZE: {
        extern int freezer_get(const char *);
        int frozen = freezer_get(cg_name);
        tmp[0] = frozen ? '1' : '0'; tmp[1] = '\n'; tmp[2] = '\0'; total = 2;
        break;
    }
    case CGFS_CPUSET_CPUS:
    case CGFS_CPUSET_CPUS_EFF: {
        /* Report available CPUs as "0-N" where N = nproc-1.
         * Use the platform SMP count if available, else default to 1. */
#if defined(__aarch64__)
        extern uint32_t fut_platform_get_cpu_count(void);
        uint32_t ncpu = fut_platform_get_cpu_count();
#elif defined(__x86_64__)
        extern uint32_t smp_get_cpu_count(void);
        uint32_t ncpu = smp_get_cpu_count();
#else
        uint32_t ncpu = 1;
#endif
        if (ncpu == 0) ncpu = 1;
        int pos = 0;
        if (ncpu == 1) {
            tmp[pos++] = '0';
        } else {
            tmp[pos++] = '0'; tmp[pos++] = '-';
            uint32_t maxcpu = ncpu - 1;
            char rev[12]; int rp = 0;
            while (maxcpu > 0) { rev[rp++] = '0' + (char)(maxcpu % 10); maxcpu /= 10; }
            while (rp > 0) tmp[pos++] = rev[--rp];
        }
        tmp[pos++] = '\n'; tmp[pos] = '\0';
        total = (size_t)pos;
        break;
    }
    case CGFS_CPUSET_MEMS:
    case CGFS_CPUSET_MEMS_EFF: {
        /* Single NUMA node: always "0" */
        tmp[0] = '0'; tmp[1] = '\n'; tmp[2] = '\0'; total = 2;
        break;
    }
    case CGFS_CPUSET_PARTITION: {
        const char *s = "member\n";
        total = 0;
        while (s[total]) { tmp[total] = s[total]; total++; }
        break;
    }
    default:
        return -EINVAL;
    }

    if (offset >= total) return 0;
    size_t avail = total - (size_t)offset;
    size_t copy = avail < size ? avail : size;
    memcpy(buf, tmp + offset, copy);
    return (ssize_t)copy;
}

ssize_t cgfs_file_write(struct fut_vnode *vnode, const void *buf, size_t size, uint64_t offset) {
    (void)offset;
    cgroupfs_node_t *nd = (cgroupfs_node_t *)vnode->fs_data;
    if (!nd) return -EINVAL;

    /* Get cgroup name for controller operations */
    const char *cg_name = (nd->cgroup_idx < MAX_CGROUPS && g_cgroups[nd->cgroup_idx].active)
                          ? g_cgroups[nd->cgroup_idx].name : "/";

    /* Accept writes to writable files — parse and apply */

    /* Helper: parse "max" or decimal byte value from buffer.
     * Sets *out = 0 for "max", otherwise the parsed uint64. */
    const char *cbuf = (const char *)buf;

    switch (nd->ftype) {
    case CGFS_MEM_MAX: {
        extern int memcg_set_limit(const char *, uint64_t);
        /* Accept "max" (unlimited) or a decimal byte value */
        if (size >= 3 && cbuf[0] == 'm' && cbuf[1] == 'a' && cbuf[2] == 'x') {
            memcg_set_limit(cg_name, 0);
        } else {
            uint64_t val = 0;
            for (size_t i = 0; i < size && cbuf[i] >= '0' && cbuf[i] <= '9'; i++)
                val = val * 10 + (uint64_t)(cbuf[i] - '0');
            memcg_set_limit(cg_name, val);
        }
        return (ssize_t)size;
    }
    case CGFS_MEM_HIGH: {
        extern int memcg_set_high(const char *, uint64_t);
        if (size >= 3 && cbuf[0] == 'm' && cbuf[1] == 'a' && cbuf[2] == 'x') {
            memcg_set_high(cg_name, 0);
        } else {
            uint64_t val = 0;
            for (size_t i = 0; i < size && cbuf[i] >= '0' && cbuf[i] <= '9'; i++)
                val = val * 10 + (uint64_t)(cbuf[i] - '0');
            memcg_set_high(cg_name, val);
        }
        return (ssize_t)size;
    }
    case CGFS_MEM_LOW: {
        extern int memcg_set_low(const char *, uint64_t);
        if (size >= 3 && cbuf[0] == 'm' && cbuf[1] == 'a' && cbuf[2] == 'x') {
            memcg_set_low(cg_name, 0);
        } else {
            uint64_t val = 0;
            for (size_t i = 0; i < size && cbuf[i] >= '0' && cbuf[i] <= '9'; i++)
                val = val * 10 + (uint64_t)(cbuf[i] - '0');
            memcg_set_low(cg_name, val);
        }
        return (ssize_t)size;
    }
    case CGFS_SUBTREE_CONTROL:
    case CGFS_PROCS:
    case CGFS_MEM_SWAP_MAX:
    case CGFS_CPU_MAX:
    case CGFS_CPU_WEIGHT:
    case CGFS_PIDS_MAX: {
        /* Parse and enforce PID limit */
        extern int pidcg_set_max(const char *, uint32_t);
        uint32_t max_pids = 0;
        for (size_t i = 0; i < size && cbuf[i] >= '0' && cbuf[i] <= '9'; i++)
            max_pids = max_pids * 10 + (uint32_t)(cbuf[i] - '0');
        if (max_pids > 0) pidcg_set_max(cg_name, max_pids);
        return (ssize_t)size;
    }
    case CGFS_TYPE:
        /* Accept the write silently */
        return (ssize_t)size;
    case CGFS_IO_MAX: {
        extern int iocg_set_max(const char *, uint64_t, uint64_t, uint64_t, uint64_t);
        uint64_t rbps = 0, wbps = 0, riops = 0, wiops = 0;
        int prc = cgfs_parse_iomax_line((const char *)buf, size, &rbps, &wbps, &riops, &wiops);
        if (prc < 0) return prc;
        int rc = iocg_set_max(cg_name, rbps, wbps, riops, wiops);
        if (rc < 0) return rc;
        return (ssize_t)size;
    }
    case CGFS_FREEZE: {
        /* Freeze (1) or thaw (0) the cgroup */
        extern int freezer_set(const char *, int);
        int freeze = (size > 0 && ((const char *)buf)[0] == '1') ? 1 : 0;
        freezer_set(cg_name, freeze);
        return (ssize_t)size;
    }
    default:
        return -EPERM;
    }
}

/* ── Filesystem type registration ── */

int cgfs_mount(const char *device, int flags, void *data,
                       uint64_t block_dev_handle, struct fut_mount **mount_out) {
    (void)device; (void)flags; (void)data; (void)block_dev_handle;
    cgfs_ensure_init();

    extern void *fut_malloc(size_t);
    struct fut_mount *mnt = (struct fut_mount *)fut_malloc(sizeof(struct fut_mount));
    if (!mnt) return -ENOMEM;
    memset(mnt, 0, sizeof(*mnt));

    mnt->root = cgfs_alloc_vnode(mnt, 2 /*VN_DIR*/, CGFS_INO_BASE,
                                  0040755, CGFS_DIR, 0);
    if (!mnt->root) {
        extern void fut_free(void *);
        fut_free(mnt);
        return -ENOMEM;
    }

    *mount_out = mnt;
    fut_printf("[CGROUPFS] Cgroup v2 filesystem mounted\n");
    return 0;
}

int cgfs_unmount(struct fut_mount *mnt) {
    (void)mnt;
    return 0;
}

static const struct fut_fs_type cgfs_type = {
    .name    = "cgroup2",
    .mount   = cgfs_mount,
    .unmount = cgfs_unmount,
};

void cgroupfs_init(void) {
    cgfs_ensure_init();
    extern int fut_vfs_register_fs(const struct fut_fs_type *fs);
    fut_vfs_register_fs(&cgfs_type);

    /* Also register as "cgroup" for v1 compat probes */
    static const struct fut_fs_type cgfs_v1_type = {
        .name    = "cgroup",
        .mount   = cgfs_mount,
        .unmount = cgfs_unmount,
    };
    fut_vfs_register_fs(&cgfs_v1_type);

    fut_printf("[CGROUPFS] cgroup2 filesystem type registered\n");
}
