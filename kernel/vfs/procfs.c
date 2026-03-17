/* kernel/vfs/procfs.c - Process Filesystem (/proc)
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements a synthetic /proc filesystem providing runtime process and
 * system information, compatible with Linux /proc conventions.
 *
 * Supported entries:
 *   /proc/self            -> symlink to /proc/<current-pid>
 *   /proc/meminfo         -> system memory statistics
 *   /proc/version         -> kernel version string
 *   /proc/uptime          -> system uptime in seconds
 *   /proc/<pid>/          -> per-process directory
 *   /proc/<pid>/status    -> process status (Name, Pid, State, VmRSS, etc.)
 *   /proc/<pid>/maps      -> memory map
 *   /proc/<pid>/cmdline   -> process command line (null-separated)
 *   /proc/<pid>/fd/       -> open file descriptor directory
 *   /proc/<pid>/fd/<n>    -> symlinks (currently ENOENT for unresolved paths)
 */

#include <kernel/fut_vfs.h>
#include <kernel/fut_task.h>
#include <kernel/fut_mm.h>
#include <kernel/fut_memory.h>
#include <kernel/fut_timer.h>
#include <kernel/fut_lock.h>
#include <kernel/vfs_credentials.h>
#include <kernel/errno.h>
#include <kernel/kprintf.h>
#include <sys/mman.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* ============================================================
 *   Procfs Node Kind (stored in fs_data)
 * ============================================================ */

enum procfs_kind {
    PROC_ROOT,       /* /proc directory */
    PROC_SELF,       /* /proc/self symlink */
    PROC_MEMINFO,    /* /proc/meminfo */
    PROC_VERSION,    /* /proc/version */
    PROC_UPTIME,     /* /proc/uptime */
    PROC_PID_DIR,    /* /proc/<pid>/ */
    PROC_STATUS,     /* /proc/<pid>/status */
    PROC_MAPS,       /* /proc/<pid>/maps */
    PROC_CMDLINE,    /* /proc/<pid>/cmdline */
    PROC_FD_DIR,     /* /proc/<pid>/fd/ */
    PROC_FD_ENTRY,   /* /proc/<pid>/fd/<n> symlink */
};

typedef struct {
    enum procfs_kind kind;
    uint64_t pid;   /* relevant PID (0 for global nodes) */
    int fd;         /* fd index for PROC_FD_ENTRY */
} procfs_node_t;

/* ============================================================
 *   Inode Number Scheme
 * ============================================================ */

#define PROC_INO_ROOT     1ULL
#define PROC_INO_SELF     2ULL
#define PROC_INO_MEMINFO  3ULL
#define PROC_INO_VERSION  4ULL
#define PROC_INO_UPTIME   5ULL

/* Per-PID: pid * 100 + offset */
#define PROC_INO_PID_DIR(p)    (1000ULL + (uint64_t)(p) * 100 + 0)
#define PROC_INO_PID_STATUS(p) (1000ULL + (uint64_t)(p) * 100 + 1)
#define PROC_INO_PID_MAPS(p)   (1000ULL + (uint64_t)(p) * 100 + 2)
#define PROC_INO_PID_CMDLINE(p)(1000ULL + (uint64_t)(p) * 100 + 3)
#define PROC_INO_PID_FD(p)     (1000ULL + (uint64_t)(p) * 100 + 4)
/* fd entries: use high range to avoid collision */
#define PROC_INO_FD_ENTRY(p,n) (100000000ULL + (uint64_t)(p) * 1000 + (uint64_t)(n))

/* ============================================================
 *   Simple Buffer Writer (no libc snprintf needed)
 * ============================================================ */

struct pbuf {
    char   *data;
    size_t  pos;
    size_t  cap;
};

static void pb_char(struct pbuf *b, char c) {
    if (b->pos < b->cap) b->data[b->pos] = c;
    b->pos++;
}

static void pb_str(struct pbuf *b, const char *s) {
    while (*s) pb_char(b, *s++);
}

static void pb_u64(struct pbuf *b, uint64_t v) {
    if (v == 0) { pb_char(b, '0'); return; }
    char tmp[20]; int n = 0;
    while (v) { tmp[n++] = '0' + (v % 10); v /= 10; }
    for (int i = n - 1; i >= 0; i--) pb_char(b, tmp[i]);
}

static void pb_hex16(struct pbuf *b, uint64_t v) {
    /* Print 16 hex digits (padded) */
    static const char hex[] = "0123456789abcdef";
    for (int i = 60; i >= 0; i -= 4)
        pb_char(b, hex[(v >> i) & 0xf]);
}

static void pb_hex(struct pbuf *b, uint64_t v) {
    /* Print minimum hex digits */
    if (v == 0) { pb_char(b, '0'); return; }
    static const char hex[] = "0123456789abcdef";
    char tmp[16]; int n = 0;
    while (v) { tmp[n++] = hex[v & 0xf]; v >>= 4; }
    for (int i = n - 1; i >= 0; i--) pb_char(b, tmp[i]);
}

/* ============================================================
 *   Forward Declarations
 * ============================================================ */

static const struct fut_vnode_ops procfs_dir_ops;
static const struct fut_vnode_ops procfs_file_ops;
static const struct fut_vnode_ops procfs_link_ops;

/* ============================================================
 *   Vnode Allocation
 * ============================================================ */

static struct fut_vnode *procfs_alloc_vnode(struct fut_mount *mount,
                                             enum fut_vnode_type type,
                                             uint64_t ino, uint32_t mode,
                                             enum procfs_kind kind,
                                             uint64_t pid, int fd) {
    struct fut_vnode *v = fut_malloc(sizeof(struct fut_vnode));
    if (!v) return NULL;

    procfs_node_t *n = fut_malloc(sizeof(procfs_node_t));
    if (!n) { fut_free(v); return NULL; }

    n->kind = kind;
    n->pid  = pid;
    n->fd   = fd;

    v->type     = type;
    v->ino      = ino;
    v->mode     = mode;
    v->uid      = 0;
    v->gid      = 0;
    v->size     = 0;
    v->nlinks   = (type == VN_DIR) ? 2 : 1;
    v->mount    = mount;
    v->fs_data  = n;
    v->refcount = 1;
    v->parent   = NULL;
    v->name     = NULL;

    const struct fut_vnode_ops *ops;
    switch (type) {
        case VN_DIR: ops = &procfs_dir_ops;  break;
        case VN_LNK: ops = &procfs_link_ops; break;
        default:     ops = &procfs_file_ops; break;
    }
    v->ops = ops;

    fut_vnode_lock_init(v);
    return v;
}

/* ============================================================
 *   Content Generators
 * ============================================================ */

static size_t gen_meminfo(char *buf, size_t cap) {
    uint64_t total_pages = fut_pmm_total_pages();
    uint64_t free_pages  = fut_pmm_free_pages();
    uint64_t page_size   = 4096;
    uint64_t total_kb    = (total_pages * page_size) / 1024;
    uint64_t free_kb     = (free_pages  * page_size) / 1024;
    uint64_t used_kb     = total_kb - free_kb;
    uint64_t avail_kb    = free_kb;

    struct pbuf b = { buf, 0, cap };
    pb_str(&b, "MemTotal:       "); pb_u64(&b, total_kb); pb_str(&b, " kB\n");
    pb_str(&b, "MemFree:        "); pb_u64(&b, free_kb);  pb_str(&b, " kB\n");
    pb_str(&b, "MemAvailable:   "); pb_u64(&b, avail_kb); pb_str(&b, " kB\n");
    pb_str(&b, "Buffers:        0 kB\n");
    pb_str(&b, "Cached:         "); pb_u64(&b, used_kb);  pb_str(&b, " kB\n");
    pb_str(&b, "SwapTotal:      0 kB\n");
    pb_str(&b, "SwapFree:       0 kB\n");
    pb_str(&b, "Dirty:          0 kB\n");
    pb_str(&b, "Writeback:      0 kB\n");
    pb_str(&b, "AnonPages:      "); pb_u64(&b, used_kb);  pb_str(&b, " kB\n");
    pb_str(&b, "Mapped:         0 kB\n");
    pb_str(&b, "Shmem:          0 kB\n");
    return b.pos;
}

static size_t gen_version(char *buf, size_t cap) {
    struct pbuf b = { buf, 0, cap };
    pb_str(&b, "Linux version 6.1.0-futura (futura@kernel) "
               "(gcc version 14.0.0) #1 SMP PREEMPT\n");
    return b.pos;
}

static size_t gen_uptime(char *buf, size_t cap) {
    uint64_t ticks = fut_get_ticks();
    uint64_t secs  = ticks / FUT_TIMER_HZ;
    uint64_t frac  = (ticks % FUT_TIMER_HZ) * 100 / FUT_TIMER_HZ;  /* centiseconds */
    struct pbuf b = { buf, 0, cap };
    pb_u64(&b, secs); pb_char(&b, '.');
    if (frac < 10) pb_char(&b, '0');
    pb_u64(&b, frac);
    pb_str(&b, " 0.00\n");  /* idle time (not tracked) */
    return b.pos;
}

static size_t gen_status(char *buf, size_t cap, fut_task_t *task) {
    if (!task) return 0;

    const char *state_str;
    switch (task->state) {
        case FUT_TASK_RUNNING: state_str = "R (running)";  break;
        case FUT_TASK_ZOMBIE:  state_str = "Z (zombie)";   break;
        case FUT_TASK_STOPPED: state_str = "T (stopped)";  break;
        default:               state_str = "S (sleeping)"; break;
    }

    /* VmRSS: total bytes from VMA list */
    uint64_t rss_kb = 0;
    if (task->mm) {
        struct fut_vma *vma = task->mm->vma_list;
        uint64_t bytes = 0;
        while (vma) { bytes += vma->end - vma->start; vma = vma->next; }
        rss_kb = bytes / 1024;
    }

    uint64_t ppid = task->parent ? task->parent->pid : 0;

    struct pbuf b = { buf, 0, cap };
    pb_str(&b, "Name:\t");    pb_str(&b, task->comm[0] ? task->comm : "?"); pb_char(&b, '\n');
    pb_str(&b, "State:\t");   pb_str(&b, state_str); pb_char(&b, '\n');
    pb_str(&b, "Tgid:\t");    pb_u64(&b, task->pid); pb_char(&b, '\n');
    pb_str(&b, "Pid:\t");     pb_u64(&b, task->pid); pb_char(&b, '\n');
    pb_str(&b, "PPid:\t");    pb_u64(&b, ppid);       pb_char(&b, '\n');
    pb_str(&b, "Uid:\t");     pb_u64(&b, task->ruid); pb_char(&b, '\t');
                               pb_u64(&b, task->uid);  pb_char(&b, '\t');
                               pb_u64(&b, task->suid); pb_char(&b, '\t');
                               pb_u64(&b, task->uid);  pb_char(&b, '\n');
    pb_str(&b, "Gid:\t");     pb_u64(&b, task->rgid); pb_char(&b, '\t');
                               pb_u64(&b, task->gid);  pb_char(&b, '\t');
                               pb_u64(&b, task->sgid); pb_char(&b, '\t');
                               pb_u64(&b, task->gid);  pb_char(&b, '\n');
    pb_str(&b, "Threads:\t"); pb_u64(&b, task->thread_count); pb_char(&b, '\n');
    pb_str(&b, "VmRSS:\t");   pb_u64(&b, rss_kb); pb_str(&b, " kB\n");
    pb_str(&b, "VmSize:\t");  pb_u64(&b, rss_kb); pb_str(&b, " kB\n");
    pb_str(&b, "SigPnd:\t");  pb_hex16(&b, task->pending_signals); pb_char(&b, '\n');
    pb_str(&b, "SigBlk:\t");  pb_hex16(&b, task->signal_mask);     pb_char(&b, '\n');
    return b.pos;
}

static size_t gen_maps(char *buf, size_t cap, fut_task_t *task) {
    if (!task || !task->mm) return 0;

    struct pbuf b = { buf, 0, cap };
    struct fut_vma *vma = task->mm->vma_list;
    while (vma) {
        /* address range */
        pb_hex(&b, vma->start); pb_char(&b, '-');
        pb_hex(&b, vma->end);   pb_char(&b, ' ');
        /* permissions */
        pb_char(&b, (vma->prot & PROT_READ)  ? 'r' : '-');
        pb_char(&b, (vma->prot & PROT_WRITE) ? 'w' : '-');
        pb_char(&b, (vma->prot & PROT_EXEC)  ? 'x' : '-');
        pb_char(&b, 'p');  /* private (simplified) */
        pb_char(&b, ' ');
        /* offset */
        pb_hex16(&b, vma->file_offset); pb_char(&b, ' ');
        /* dev 00:00, inode 0 */
        pb_str(&b, "00:00 0 ");
        /* pathname */
        if (vma->vnode && vma->vnode->name)
            pb_str(&b, vma->vnode->name);
        pb_char(&b, '\n');
        vma = vma->next;
    }
    return b.pos;
}

static size_t gen_cmdline(char *buf, size_t cap, fut_task_t *task) {
    if (!task) return 0;
    const char *name = task->comm[0] ? task->comm : "?";
    size_t n = 0;
    while (name[n]) n++;
    if (n > cap) n = cap;
    __builtin_memcpy(buf, name, n);
    if (n < cap) buf[n] = '\0';  /* null terminator (cmdline format) */
    return n + 1;
}

/* ============================================================
 *   File Operations
 * ============================================================ */

static ssize_t procfs_file_read(struct fut_vnode *vnode, void *buf, size_t size, uint64_t offset) {
    if (!vnode || !buf) return -EINVAL;
    procfs_node_t *n = (procfs_node_t *)vnode->fs_data;
    if (!n) return -EIO;

    /* Generate content into a temporary 8KB buffer */
    const size_t GEN_BUF = 8192;
    char *tmp = fut_malloc(GEN_BUF);
    if (!tmp) return -ENOMEM;

    size_t total = 0;
    switch (n->kind) {
        case PROC_MEMINFO: total = gen_meminfo(tmp, GEN_BUF); break;
        case PROC_VERSION: total = gen_version(tmp, GEN_BUF); break;
        case PROC_UPTIME:  total = gen_uptime(tmp, GEN_BUF);  break;
        case PROC_STATUS: {
            fut_task_t *task = fut_task_by_pid(n->pid);
            total = task ? gen_status(tmp, GEN_BUF, task) : 0;
            break;
        }
        case PROC_MAPS: {
            fut_task_t *task = fut_task_by_pid(n->pid);
            total = task ? gen_maps(tmp, GEN_BUF, task) : 0;
            break;
        }
        case PROC_CMDLINE: {
            fut_task_t *task = fut_task_by_pid(n->pid);
            total = task ? gen_cmdline(tmp, GEN_BUF, task) : 0;
            break;
        }
        default:
            fut_free(tmp);
            return -EINVAL;
    }

    /* Serve slice at offset */
    ssize_t ret = 0;
    if (offset < total) {
        size_t avail = total - (size_t)offset;
        ret = (ssize_t)(avail < size ? avail : size);
        __builtin_memcpy(buf, tmp + offset, (size_t)ret);
    }
    fut_free(tmp);
    return ret;
}

static int procfs_file_getattr(struct fut_vnode *vnode, struct fut_stat *st) {
    if (!vnode || !st) return -EINVAL;
    __builtin_memset(st, 0, sizeof(*st));
    st->st_ino   = vnode->ino;
    st->st_mode  = 0100444;  /* r--r--r-- regular file */
    st->st_nlink = 1;
    st->st_uid   = 0;
    st->st_gid   = 0;
    st->st_size  = 0;  /* unknown size — reads return actual content */
    st->st_blksize = 4096;
    return 0;
}

/* ============================================================
 *   Symlink Operations
 * ============================================================ */

static ssize_t procfs_link_readlink(struct fut_vnode *vnode, char *buf, size_t size) {
    if (!vnode || !buf) return -EINVAL;
    procfs_node_t *n = (procfs_node_t *)vnode->fs_data;
    if (!n) return -EIO;

    char tmp[64];
    size_t len = 0;

    if (n->kind == PROC_SELF) {
        /* Resolve to /proc/<current_pid> */
        fut_task_t *cur = fut_task_current();
        uint64_t cpid = cur ? cur->pid : 1;
        struct pbuf b = { tmp, 0, sizeof(tmp) };
        pb_str(&b, "/proc/");
        pb_u64(&b, cpid);
        len = b.pos;
    } else if (n->kind == PROC_FD_ENTRY) {
        /* /proc/<pid>/fd/<n>: stub — just return the fd number as path */
        struct pbuf b = { tmp, 0, sizeof(tmp) };
        pb_str(&b, "/dev/fd/");
        pb_u64(&b, (uint64_t)n->fd);
        len = b.pos;
    } else {
        return -EINVAL;
    }

    if (len > size) len = size;
    __builtin_memcpy(buf, tmp, len);
    return (ssize_t)len;
}

static int procfs_link_getattr(struct fut_vnode *vnode, struct fut_stat *st) {
    if (!vnode || !st) return -EINVAL;
    __builtin_memset(st, 0, sizeof(*st));
    st->st_ino   = vnode->ino;
    st->st_mode  = 0120777;  /* lrwxrwxrwx */
    st->st_nlink = 1;
    st->st_size  = 0;
    return 0;
}

/* Parse decimal string to uint64_t; returns (uint64_t)-1 on failure */
static uint64_t parse_dec(const char *s) {
    if (!s || !*s) return (uint64_t)-1;
    uint64_t v = 0;
    while (*s) {
        if (*s < '0' || *s > '9') return (uint64_t)-1;
        v = v * 10 + (uint64_t)(*s - '0');
        s++;
    }
    return v;
}

/* ============================================================
 *   Directory Operations
 * ============================================================ */

static int procfs_dir_lookup(struct fut_vnode *dir, const char *name,
                              struct fut_vnode **result) {
    if (!dir || !name || !result) return -EINVAL;
    procfs_node_t *dn = (procfs_node_t *)dir->fs_data;
    if (!dn) return -EIO;

    struct fut_mount *mnt = dir->mount;

    #define STREQ(a, b) (__builtin_strcmp((a), (b)) == 0)

    if (dn->kind == PROC_ROOT) {
        if (STREQ(name, "self")) {
            *result = procfs_alloc_vnode(mnt, VN_LNK, PROC_INO_SELF,
                                          0120777, PROC_SELF, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "meminfo")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_MEMINFO,
                                          0100444, PROC_MEMINFO, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "version")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_VERSION,
                                          0100444, PROC_VERSION, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "uptime")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_UPTIME,
                                          0100444, PROC_UPTIME, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        /* Try numeric PID */
        uint64_t pid = parse_dec(name);
        if (pid != (uint64_t)-1 && pid > 0) {
            fut_task_t *task = fut_task_by_pid(pid);
            if (!task) return -ENOENT;
            *result = procfs_alloc_vnode(mnt, VN_DIR, PROC_INO_PID_DIR(pid),
                                          0040555, PROC_PID_DIR, pid, 0);
            return *result ? 0 : -ENOMEM;
        }
        return -ENOENT;
    }

    if (dn->kind == PROC_PID_DIR) {
        uint64_t pid = dn->pid;
        if (STREQ(name, "status")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_PID_STATUS(pid),
                                          0100444, PROC_STATUS, pid, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "maps")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_PID_MAPS(pid),
                                          0100444, PROC_MAPS, pid, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "cmdline")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_PID_CMDLINE(pid),
                                          0100444, PROC_CMDLINE, pid, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "fd")) {
            *result = procfs_alloc_vnode(mnt, VN_DIR, PROC_INO_PID_FD(pid),
                                          0040500, PROC_FD_DIR, pid, 0);
            return *result ? 0 : -ENOMEM;
        }
        return -ENOENT;
    }

    if (dn->kind == PROC_FD_DIR) {
        uint64_t pid = dn->pid;
        uint64_t fd  = parse_dec(name);
        if (fd == (uint64_t)-1) return -ENOENT;
        fut_task_t *task = fut_task_by_pid(pid);
        if (!task) return -ENOENT;
        if ((int)fd >= task->max_fds || !task->fd_table[(int)fd]) return -ENOENT;
        *result = procfs_alloc_vnode(mnt, VN_LNK,
                                      PROC_INO_FD_ENTRY(pid, (int)fd),
                                      0120777, PROC_FD_ENTRY, pid, (int)fd);
        return *result ? 0 : -ENOMEM;
    }

    #undef STREQ
    return -ENOTDIR;
}

static int procfs_dir_readdir(struct fut_vnode *dir, uint64_t *cookie,
                               struct fut_vdirent *de) {
    if (!dir || !cookie || !de) return -EINVAL;
    procfs_node_t *dn = (procfs_node_t *)dir->fs_data;
    if (!dn) return -EIO;

    uint64_t idx = *cookie;

    if (dn->kind == PROC_ROOT) {
        /* Fixed entries: ., .., self, meminfo, version, uptime */
        static const char *fixed[] = { ".", "..", "self", "meminfo", "version", "uptime" };
        static const uint8_t fixed_type[] = {
            FUT_VDIR_TYPE_DIR, FUT_VDIR_TYPE_DIR,
            FUT_VDIR_TYPE_SYMLINK,
            FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG
        };
        static const uint64_t fixed_ino[] = {
            PROC_INO_ROOT, PROC_INO_ROOT,
            PROC_INO_SELF, PROC_INO_MEMINFO, PROC_INO_VERSION, PROC_INO_UPTIME
        };
        if (idx < 6) {
            de->d_ino    = fixed_ino[idx];
            de->d_off    = idx + 1;
            de->d_type   = fixed_type[idx];
            de->d_reclen = sizeof(*de);
            size_t nl = 0;
            while (fixed[idx][nl]) nl++;
            if (nl > FUT_VFS_NAME_MAX) nl = FUT_VFS_NAME_MAX;
            __builtin_memcpy(de->d_name, fixed[idx], nl);
            de->d_name[nl] = '\0';
            *cookie = idx + 1;
            return 0;
        }
        /* Then iterate live PIDs — not implemented as full iteration here,
         * but let the loop fall through to end-of-directory. */
        return -ENOENT;  /* end of directory */
    }

    if (dn->kind == PROC_PID_DIR) {
        static const char *entries[] = { ".", "..", "status", "maps", "cmdline", "fd" };
        static const uint8_t etypes[] = {
            FUT_VDIR_TYPE_DIR, FUT_VDIR_TYPE_DIR,
            FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG,
            FUT_VDIR_TYPE_DIR
        };
        uint64_t pid = dn->pid;
        if (idx < 6) {
            uint64_t ino;
            switch (idx) {
                case 0: ino = PROC_INO_PID_DIR(pid); break;
                case 1: ino = PROC_INO_ROOT; break;
                case 2: ino = PROC_INO_PID_STATUS(pid); break;
                case 3: ino = PROC_INO_PID_MAPS(pid); break;
                case 4: ino = PROC_INO_PID_CMDLINE(pid); break;
                case 5: ino = PROC_INO_PID_FD(pid); break;
                default: ino = 0; break;
            }
            de->d_ino    = ino;
            de->d_off    = idx + 1;
            de->d_type   = etypes[idx];
            de->d_reclen = sizeof(*de);
            const char *nm = entries[idx];
            size_t nl = 0; while (nm[nl]) nl++;
            if (nl > FUT_VFS_NAME_MAX) nl = FUT_VFS_NAME_MAX;
            __builtin_memcpy(de->d_name, nm, nl);
            de->d_name[nl] = '\0';
            *cookie = idx + 1;
            return 0;
        }
        return -ENOENT;
    }

    if (dn->kind == PROC_FD_DIR) {
        uint64_t pid = dn->pid;
        fut_task_t *task = fut_task_by_pid(pid);
        if (!task) return -ENOENT;

        /* Entries: ., .., then open fds */
        if (idx == 0) {
            de->d_ino    = PROC_INO_PID_FD(pid);
            de->d_off    = 1;
            de->d_type   = FUT_VDIR_TYPE_DIR;
            de->d_reclen = sizeof(*de);
            de->d_name[0] = '.'; de->d_name[1] = '\0';
            *cookie = 1;
            return 0;
        }
        if (idx == 1) {
            de->d_ino    = PROC_INO_PID_DIR(pid);
            de->d_off    = 2;
            de->d_type   = FUT_VDIR_TYPE_DIR;
            de->d_reclen = sizeof(*de);
            de->d_name[0] = '.'; de->d_name[1] = '.'; de->d_name[2] = '\0';
            *cookie = 2;
            return 0;
        }
        /* Scan for open fds starting at fd_scan = idx - 2 */
        int scan = (int)(idx - 2);
        while (scan < task->max_fds) {
            if (task->fd_table[scan]) break;
            scan++;
        }
        if (scan >= task->max_fds) return -ENOENT;
        /* Format fd number as name */
        char tmp[12]; int tn = 0;
        int v = scan;
        if (v == 0) { tmp[tn++] = '0'; }
        else {
            char rev[10]; int rn = 0;
            while (v) { rev[rn++] = '0' + (v % 10); v /= 10; }
            for (int i = rn - 1; i >= 0; i--) tmp[tn++] = rev[i];
        }
        tmp[tn] = '\0';
        de->d_ino    = PROC_INO_FD_ENTRY(pid, scan);
        de->d_off    = idx + 1;
        de->d_type   = FUT_VDIR_TYPE_SYMLINK;
        de->d_reclen = sizeof(*de);
        __builtin_memcpy(de->d_name, tmp, tn + 1);
        *cookie = (uint64_t)(scan + 2 + 1);
        return 0;
    }

    return -ENOTDIR;
}

static int procfs_dir_getattr(struct fut_vnode *vnode, struct fut_stat *st) {
    if (!vnode || !st) return -EINVAL;
    __builtin_memset(st, 0, sizeof(*st));
    st->st_ino   = vnode->ino;
    st->st_mode  = 0040555;
    st->st_nlink = 2;
    st->st_uid   = 0;
    st->st_gid   = 0;
    st->st_size  = 0;
    st->st_blksize = 4096;
    return 0;
}

/* ============================================================
 *   VNode Ops Tables
 * ============================================================ */

static const struct fut_vnode_ops procfs_file_ops = {
    .read    = procfs_file_read,
    .getattr = procfs_file_getattr,
};

static const struct fut_vnode_ops procfs_link_ops = {
    .readlink = procfs_link_readlink,
    .getattr  = procfs_link_getattr,
};

static const struct fut_vnode_ops procfs_dir_ops = {
    .lookup  = procfs_dir_lookup,
    .readdir = procfs_dir_readdir,
    .getattr = procfs_dir_getattr,
};

/* ============================================================
 *   Mount / Unmount
 * ============================================================ */

static int procfs_mount(const char *device, int flags, void *data,
                        fut_handle_t block_device_handle,
                        struct fut_mount **mount_out) {
    (void)device; (void)flags; (void)data; (void)block_device_handle;

    struct fut_mount *mount = fut_malloc(sizeof(struct fut_mount));
    if (!mount) return -ENOMEM;

    struct fut_vnode *root = procfs_alloc_vnode(mount, VN_DIR,
                                                  PROC_INO_ROOT, 0040555,
                                                  PROC_ROOT, 0, 0);
    if (!root) { fut_free(mount); return -ENOMEM; }
    root->mount = mount;

    mount->device               = NULL;
    mount->mountpoint           = NULL;
    mount->fs                   = NULL;
    mount->root                 = root;
    mount->flags                = flags;
    mount->fs_data              = NULL;
    mount->next                 = NULL;
    mount->block_device_handle  = block_device_handle;

    *mount_out = mount;
    return 0;
}

static int procfs_unmount(struct fut_mount *mount) {
    if (!mount) return -EINVAL;
    if (mount->root) {
        procfs_node_t *n = (procfs_node_t *)mount->root->fs_data;
        if (n) fut_free(n);
        fut_free(mount->root);
    }
    fut_free(mount);
    return 0;
}

/* ============================================================
 *   Registration
 * ============================================================ */

static struct fut_fs_type procfs_type;

void fut_procfs_init(void) {
    procfs_type.name    = "proc";
    procfs_type.mount   = procfs_mount;
    procfs_type.unmount = procfs_unmount;
    fut_vfs_register_fs(&procfs_type);
}
