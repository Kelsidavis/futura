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
 *   /proc/<pid>/stat      -> machine-readable process statistics (ps/top format)
 *   /proc/<pid>/statm     -> memory statistics (size resident shared text lib data dt)
 *   /proc/cpuinfo         -> CPU model/features
 */

#include <kernel/fut_vfs.h>
#include <kernel/fut_task.h>
#include <kernel/fut_mm.h>
#include <kernel/fut_memory.h>
#include <kernel/fut_timer.h>
#include <kernel/fut_stats.h>
#include <kernel/fut_lock.h>
#include <kernel/vfs_credentials.h>
#include <kernel/errno.h>
#include <kernel/kprintf.h>
#include <sys/mman.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* Global task list (defined in kernel/threading/fut_task.c) */
extern fut_task_t *fut_task_list;

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
    PROC_EXE,        /* /proc/<pid>/exe symlink */
    PROC_CWD,        /* /proc/<pid>/cwd symlink */
    PROC_STAT,       /* /proc/<pid>/stat */
    PROC_STATM,      /* /proc/<pid>/statm */
    PROC_CPUINFO,    /* /proc/cpuinfo */
    PROC_LOADAVG,    /* /proc/loadavg */
    PROC_MOUNTS,     /* /proc/mounts */
    PROC_COMM,       /* /proc/<pid>/comm */
    /* /proc/sys/ subtree */
    PROC_SYS_DIR,          /* /proc/sys/ */
    PROC_SYS_KERNEL_DIR,   /* /proc/sys/kernel/ */
    PROC_SYS_VM_DIR,       /* /proc/sys/vm/ */
    PROC_SYS_FS_DIR,       /* /proc/sys/fs/ */
    PROC_SYS_OSTYPE,       /* /proc/sys/kernel/ostype */
    PROC_SYS_OSRELEASE,    /* /proc/sys/kernel/osrelease */
    PROC_SYS_HOSTNAME,     /* /proc/sys/kernel/hostname */
    PROC_SYS_PID_MAX,      /* /proc/sys/kernel/pid_max */
    PROC_SYS_OVERCOMMIT,   /* /proc/sys/vm/overcommit_memory */
    PROC_SYS_FILE_MAX,     /* /proc/sys/fs/file-max */
    PROC_TASK_DIR,         /* /proc/<pid>/task/ */
    PROC_TID_DIR,          /* /proc/<pid>/task/<tid>/ */
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
#define PROC_INO_CPUINFO  6ULL
#define PROC_INO_LOADAVG  7ULL
#define PROC_INO_MOUNTS   8ULL
/* /proc/sys/ inode range: 200-299 */
#define PROC_INO_SYS_DIR        200ULL
#define PROC_INO_SYS_KERNEL_DIR 201ULL
#define PROC_INO_SYS_VM_DIR     202ULL
#define PROC_INO_SYS_FS_DIR     203ULL
#define PROC_INO_SYS_OSTYPE     210ULL
#define PROC_INO_SYS_OSRELEASE  211ULL
#define PROC_INO_SYS_HOSTNAME   212ULL
#define PROC_INO_SYS_PID_MAX    213ULL
#define PROC_INO_SYS_OVERCOMMIT 220ULL
#define PROC_INO_SYS_FILE_MAX   230ULL

/* Per-PID: pid * 100 + offset */
#define PROC_INO_PID_DIR(p)    (1000ULL + (uint64_t)(p) * 100 + 0)
#define PROC_INO_PID_STATUS(p) (1000ULL + (uint64_t)(p) * 100 + 1)
#define PROC_INO_PID_MAPS(p)   (1000ULL + (uint64_t)(p) * 100 + 2)
#define PROC_INO_PID_CMDLINE(p)(1000ULL + (uint64_t)(p) * 100 + 3)
#define PROC_INO_PID_FD(p)     (1000ULL + (uint64_t)(p) * 100 + 4)
#define PROC_INO_PID_EXE(p)    (1000ULL + (uint64_t)(p) * 100 + 5)
#define PROC_INO_PID_CWD(p)    (1000ULL + (uint64_t)(p) * 100 + 6)
#define PROC_INO_PID_STAT(p)   (1000ULL + (uint64_t)(p) * 100 + 7)
#define PROC_INO_PID_STATM(p)  (1000ULL + (uint64_t)(p) * 100 + 8)
#define PROC_INO_PID_COMM(p)   (1000ULL + (uint64_t)(p) * 100 + 9)
#define PROC_INO_PID_TASK(p)   (1000ULL + (uint64_t)(p) * 100 + 10)
/* fd entries: use high range to avoid collision */
#define PROC_INO_FD_ENTRY(p,n) (100000000ULL + (uint64_t)(p) * 1000 + (uint64_t)(n))
/* task/<tid> entries: separate high range */
#define PROC_INO_TID_DIR(p,t)  (200000000ULL + (uint64_t)(p) * 10000 + (uint64_t)(t))

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

/*
 * gen_stat() — /proc/<pid>/stat
 *
 * Fields follow Linux /proc/<pid>/stat layout (man 5 proc).
 * Only the fields that can be derived from kernel state are accurate;
 * the rest are zeroed as permitted by the spec.
 *
 * Key fields consumed by ps/top/glibc:
 *   1=pid, 2=(comm), 3=state, 4=ppid, 5=pgrp, 6=session,
 *   13/14=utime/stime (USER_HZ=100 ticks), 17=priority, 18=nice,
 *   19=num_threads, 21=starttime, 22=vsize (bytes), 23=rss (pages)
 */
static size_t gen_stat(char *buf, size_t cap, fut_task_t *task) {
    if (!task) return 0;

    /* State character */
    char state_c;
    switch (task->state) {
        case FUT_TASK_RUNNING: state_c = 'R'; break;
        case FUT_TASK_ZOMBIE:  state_c = 'Z'; break;
        case FUT_TASK_STOPPED: state_c = 'T'; break;
        default:               state_c = 'S'; break;
    }

    uint64_t ppid = task->parent ? task->parent->pid : 0;
    uint64_t pgrp = task->pgid;
    uint64_t session = task->sid;

    /* CPU time in USER_HZ (100 Hz) ticks — sum all threads */
    uint64_t utime = 0, stime = 0;
    if (task->threads) {
        /* Accumulate cpu_ticks across all threads of this task */
        fut_thread_t *t = task->threads;
        while (t) {
            utime += t->stats.cpu_ticks;
            t = t->next;
        }
    }
    /* Accumulated child times */
    uint64_t cutime = task->child_cpu_ticks;
    uint64_t cstime = 0;

    /* Priority in Linux terms: priority = 20 - nice (range 1..40 for SCHED_OTHER) */
    int nice = task->nice;
    long priority = (long)(20 - nice);  /* maps nice -20..19 → priority 40..1 */

    /* Virtual memory size in bytes; RSS in pages */
    uint64_t vsize = 0, rss_pages = 0;
    if (task->mm) {
        struct fut_vma *vma = task->mm->vma_list;
        while (vma) { vsize += vma->end - vma->start; vma = vma->next; }
        rss_pages = vsize / 4096;
    }

    /* Starttime: ticks since boot at task creation — not stored, approximate as 0 */
    uint64_t starttime = 0;

    struct pbuf b = { buf, 0, cap };

    /* Field 1: pid */
    pb_u64(&b, task->pid); pb_char(&b, ' ');
    /* Field 2: comm in parens */
    pb_char(&b, '(');
    pb_str(&b, task->comm[0] ? task->comm : "?");
    pb_char(&b, ')'); pb_char(&b, ' ');
    /* Field 3: state */
    pb_char(&b, state_c); pb_char(&b, ' ');
    /* Field 4: ppid */
    pb_u64(&b, ppid); pb_char(&b, ' ');
    /* Field 5: pgrp */
    pb_u64(&b, pgrp); pb_char(&b, ' ');
    /* Field 6: session */
    pb_u64(&b, session); pb_char(&b, ' ');
    /* Field 7: tty_nr (0 = no controlling terminal) */
    pb_char(&b, '0'); pb_char(&b, ' ');
    /* Field 8: tpgid (-1 = no terminal foreground group) */
    pb_char(&b, '-'); pb_char(&b, '1'); pb_char(&b, ' ');
    /* Field 9: flags */
    pb_char(&b, '0'); pb_char(&b, ' ');
    /* Fields 10-12: minflt cminflt majflt cmajflt (0) */
    pb_char(&b, '0'); pb_char(&b, ' ');
    pb_char(&b, '0'); pb_char(&b, ' ');
    pb_char(&b, '0'); pb_char(&b, ' ');
    pb_char(&b, '0'); pb_char(&b, ' ');
    /* Fields 13-16: utime stime cutime cstime */
    pb_u64(&b, utime);  pb_char(&b, ' ');
    pb_u64(&b, stime);  pb_char(&b, ' ');
    pb_u64(&b, cutime); pb_char(&b, ' ');
    pb_u64(&b, cstime); pb_char(&b, ' ');
    /* Field 17: priority */
    if (priority < 0) { pb_char(&b, '-'); pb_u64(&b, (uint64_t)(-priority)); }
    else pb_u64(&b, (uint64_t)priority);
    pb_char(&b, ' ');
    /* Field 18: nice */
    if (nice < 0) { pb_char(&b, '-'); pb_u64(&b, (uint64_t)(-nice)); }
    else pb_u64(&b, (uint64_t)nice);
    pb_char(&b, ' ');
    /* Field 19: num_threads */
    pb_u64(&b, task->thread_count ? task->thread_count : 1); pb_char(&b, ' ');
    /* Field 20: itrealvalue (obsolete, 0) */
    pb_char(&b, '0'); pb_char(&b, ' ');
    /* Field 21: starttime */
    pb_u64(&b, starttime); pb_char(&b, ' ');
    /* Field 22: vsize */
    pb_u64(&b, vsize); pb_char(&b, ' ');
    /* Field 23: rss */
    pb_u64(&b, rss_pages); pb_char(&b, ' ');
    /* Field 24: rsslim (RLIM_INFINITY) */
    pb_str(&b, "4294967295"); pb_char(&b, ' ');
    /* Fields 25-28: startcode endcode startstack kstkesp (0) */
    pb_char(&b, '0'); pb_char(&b, ' ');
    pb_char(&b, '0'); pb_char(&b, ' ');
    pb_char(&b, '0'); pb_char(&b, ' ');
    pb_char(&b, '0'); pb_char(&b, ' ');
    /* Field 29: kstkeip (0) */
    pb_char(&b, '0'); pb_char(&b, ' ');
    /* Fields 30-34: signal blocked sigignore sigcatch wchan (0) */
    pb_char(&b, '0'); pb_char(&b, ' ');
    pb_char(&b, '0'); pb_char(&b, ' ');
    pb_char(&b, '0'); pb_char(&b, ' ');
    pb_char(&b, '0'); pb_char(&b, ' ');
    pb_char(&b, '0'); pb_char(&b, ' ');
    /* Fields 35-37: nswap cnswap exit_signal */
    pb_char(&b, '0'); pb_char(&b, ' ');
    pb_char(&b, '0'); pb_char(&b, ' ');
    pb_str(&b, "17");  pb_char(&b, ' '); /* SIGCHLD = 17 */
    /* Field 39: processor (CPU 0) */
    pb_char(&b, '0'); pb_char(&b, ' ');
    /* Fields 40-41: rt_priority policy */
    pb_char(&b, '0'); pb_char(&b, ' ');
    pb_char(&b, '0'); pb_char(&b, '\n');

    return b.pos;
}

/*
 * gen_statm() — /proc/<pid>/statm
 *
 * Seven space-separated values in pages:
 *   size resident shared text 0 data 0
 */
static size_t gen_statm(char *buf, size_t cap, fut_task_t *task) {
    if (!task) return 0;

    uint64_t size = 0, resident = 0;
    if (task->mm) {
        struct fut_vma *vma = task->mm->vma_list;
        while (vma) { size += vma->end - vma->start; vma = vma->next; }
        resident = size;  /* simplified: all mapped pages resident */
    }
    uint64_t size_pg = size / 4096;
    uint64_t res_pg  = resident / 4096;

    struct pbuf b = { buf, 0, cap };
    pb_u64(&b, size_pg); pb_char(&b, ' ');  /* size */
    pb_u64(&b, res_pg);  pb_char(&b, ' ');  /* resident */
    pb_char(&b, '0');    pb_char(&b, ' ');  /* shared */
    pb_char(&b, '0');    pb_char(&b, ' ');  /* text */
    pb_char(&b, '0');    pb_char(&b, ' ');  /* lib (always 0) */
    pb_u64(&b, size_pg); pb_char(&b, ' ');  /* data */
    pb_char(&b, '0');    pb_char(&b, '\n'); /* dt (dirty) */
    return b.pos;
}

/*
 * gen_cpuinfo() — /proc/cpuinfo
 *
 * Provides minimal CPU info compatible with Linux /proc/cpuinfo.
 * Architecture is detected at compile time.
 */
static size_t gen_cpuinfo(char *buf, size_t cap) {
    struct pbuf b = { buf, 0, cap };
    pb_str(&b, "processor\t: 0\n");
#ifdef __x86_64__
    pb_str(&b, "vendor_id\t: GenuineIntel\n");
    pb_str(&b, "cpu family\t: 6\n");
    pb_str(&b, "model\t\t: 142\n");
    pb_str(&b, "model name\t: Futura Virtual Processor (x86_64)\n");
    pb_str(&b, "stepping\t: 10\n");
    pb_str(&b, "microcode\t: 0x0\n");
    pb_str(&b, "cpu MHz\t\t: 2400.000\n");
    pb_str(&b, "cache size\t: 4096 KB\n");
    pb_str(&b, "physical id\t: 0\n");
    pb_str(&b, "siblings\t: 1\n");
    pb_str(&b, "core id\t\t: 0\n");
    pb_str(&b, "cpu cores\t: 1\n");
    pb_str(&b, "apicid\t\t: 0\n");
    pb_str(&b, "initial apicid\t: 0\n");
    pb_str(&b, "fpu\t\t: yes\n");
    pb_str(&b, "fpu_exception\t: yes\n");
    pb_str(&b, "cpuid level\t: 22\n");
    pb_str(&b, "wp\t\t: yes\n");
    pb_str(&b, "flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr "
               "pge mca cmov pat pse36 clflush mmx fxsr sse sse2 syscall nx "
               "lm rep_good nopl xtopology cpuid pni pclmulqdq ssse3 cx16 "
               "pcid sse4_1 sse4_2 x2apic movbe popcnt tsc_deadline_timer "
               "aes xsave avx f16c rdrand hypervisor lahf_lm abm 3dnowprefetch\n");
    pb_str(&b, "bugs\t\t:\n");
    pb_str(&b, "bogomips\t: 4800.00\n");
    pb_str(&b, "clflush size\t: 64\n");
    pb_str(&b, "cache_alignment\t: 64\n");
    pb_str(&b, "address sizes\t: 39 bits physical, 48 bits virtual\n");
#elif defined(__aarch64__)
    pb_str(&b, "CPU implementer\t: 0x41\n");
    pb_str(&b, "CPU architecture: 8\n");
    pb_str(&b, "CPU variant\t: 0x0\n");
    pb_str(&b, "CPU part\t: 0xd08\n");
    pb_str(&b, "CPU revision\t: 3\n");
    pb_str(&b, "Features\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 "
               "atomics fphp asimdhp cpuid asimdrdm lrcpc dcpop asimddp\n");
    pb_str(&b, "BogoMIPS\t: 125.00\n");
#else
    pb_str(&b, "model name\t: Futura Virtual Processor\n");
#endif
    pb_char(&b, '\n');
    return b.pos;
}

/*
 * gen_loadavg() — /proc/loadavg
 *
 * Format: "1.00 5.00 15.00 R/T last_pid\n"
 * R = running threads, T = total threads, last_pid = newest PID.
 * Load averages are in 16.16 fixed-point from fut_get_load_avg().
 */
static size_t gen_loadavg(char *buf, size_t cap) {
    unsigned long loads[3] = {0, 0, 0};
    fut_get_load_avg(loads);

    /* Convert 16.16 fixed-point to integer + two decimal places */
    struct pbuf b = { buf, 0, cap };
    for (int i = 0; i < 3; i++) {
        uint64_t v = (uint64_t)loads[i];
        uint64_t int_part  = v >> 16;
        uint64_t frac_100  = ((v & 0xFFFFULL) * 100ULL) >> 16;
        pb_u64(&b, int_part);
        pb_char(&b, '.');
        if (frac_100 < 10) pb_char(&b, '0');
        pb_u64(&b, frac_100);
        pb_char(&b, (i < 2) ? ' ' : ' ');
    }
    /* running/total threads */
    uint64_t running = 0, total = 0;
    fut_task_t *t = fut_task_list;
    while (t) {
        total++;
        if (t->state == FUT_TASK_RUNNING) running++;
        t = t->next;
    }
    pb_u64(&b, running ? running : 1); pb_char(&b, '/');
    pb_u64(&b, total ? total : 1); pb_char(&b, ' ');
    /* last pid: find max pid */
    uint64_t last_pid = 0;
    t = fut_task_list;
    while (t) { if (t->pid > last_pid) last_pid = t->pid; t = t->next; }
    pb_u64(&b, last_pid);
    pb_char(&b, '\n');
    return b.pos;
}

/*
 * gen_mounts() — /proc/mounts (== /proc/self/mounts)
 *
 * One line per mount:
 *   device mountpoint fstype options 0 0
 */
static size_t gen_mounts(char *buf, size_t cap) {
    struct pbuf b = { buf, 0, cap };
    struct fut_mount *m = fut_vfs_first_mount();
    while (m) {
        const char *dev = (m->device && m->device[0]) ? m->device : "none";
        const char *mp  = (m->mountpoint && m->mountpoint[0]) ? m->mountpoint : "/";
        const char *fs  = (m->fs && m->fs->name) ? m->fs->name : "unknown";
        pb_str(&b, dev); pb_char(&b, ' ');
        pb_str(&b, mp);  pb_char(&b, ' ');
        pb_str(&b, fs);  pb_str(&b, " rw,relatime 0 0\n");
        m = m->next;
    }
    if (b.pos == 0) {
        /* Fallback: at least show rootfs */
        pb_str(&b, "rootfs / rootfs rw 0 0\n");
    }
    return b.pos;
}

/*
 * gen_comm() — /proc/<pid>/comm
 *
 * Single line: process name + newline.
 */
static size_t gen_comm(char *buf, size_t cap, fut_task_t *task) {
    if (!task) return 0;
    const char *name = task->comm[0] ? task->comm : "?";
    struct pbuf b = { buf, 0, cap };
    pb_str(&b, name);
    pb_char(&b, '\n');
    return b.pos;
}

/* /proc/sys/kernel/ and /proc/sys/vm/ file generators */
static size_t gen_sysctl_str(char *buf, size_t cap, const char *value) {
    struct pbuf b = { buf, 0, cap };
    pb_str(&b, value);
    pb_char(&b, '\n');
    return b.pos;
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
        case PROC_STAT: {
            fut_task_t *task = fut_task_by_pid(n->pid);
            total = task ? gen_stat(tmp, GEN_BUF, task) : 0;
            break;
        }
        case PROC_STATM: {
            fut_task_t *task = fut_task_by_pid(n->pid);
            total = task ? gen_statm(tmp, GEN_BUF, task) : 0;
            break;
        }
        case PROC_CPUINFO:
            total = gen_cpuinfo(tmp, GEN_BUF);
            break;
        case PROC_LOADAVG:
            total = gen_loadavg(tmp, GEN_BUF);
            break;
        case PROC_MOUNTS:
            total = gen_mounts(tmp, GEN_BUF);
            break;
        case PROC_COMM: {
            fut_task_t *task = fut_task_by_pid(n->pid);
            total = task ? gen_comm(tmp, GEN_BUF, task) : 0;
            break;
        }
        case PROC_SYS_OSTYPE:
            total = gen_sysctl_str(tmp, GEN_BUF, "Linux");
            break;
        case PROC_SYS_OSRELEASE:
            total = gen_sysctl_str(tmp, GEN_BUF, "6.1.0-futura");
            break;
        case PROC_SYS_HOSTNAME:
            total = gen_sysctl_str(tmp, GEN_BUF, "futura");
            break;
        case PROC_SYS_PID_MAX:
            total = gen_sysctl_str(tmp, GEN_BUF, "32768");
            break;
        case PROC_SYS_OVERCOMMIT:
            total = gen_sysctl_str(tmp, GEN_BUF, "0");
            break;
        case PROC_SYS_FILE_MAX:
            total = gen_sysctl_str(tmp, GEN_BUF, "1048576");
            break;
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

    char tmp[256];
    size_t len = 0;

    switch (n->kind) {
        case PROC_SELF: {
            /* Resolve to /proc/<current_pid> */
            fut_task_t *cur = fut_task_current();
            uint64_t cpid = cur ? cur->pid : 1;
            struct pbuf b = { tmp, 0, sizeof(tmp) };
            pb_str(&b, "/proc/");
            pb_u64(&b, cpid);
            len = b.pos;
            break;
        }
        case PROC_EXE: {
            /* Executable path stored at exec time */
            fut_task_t *task = fut_task_by_pid(n->pid);
            if (!task) return -ESRCH;
            const char *ep = task->exe_path[0] ? task->exe_path : "(deleted)";
            while (ep[len] && len < sizeof(tmp) - 1) { tmp[len] = ep[len]; len++; }
            break;
        }
        case PROC_CWD: {
            /* Current working directory */
            fut_task_t *task = fut_task_by_pid(n->pid);
            if (!task) return -ESRCH;
            const char *cwd = (task->cwd_cache && task->cwd_cache[0]) ?
                               task->cwd_cache : "/";
            while (cwd[len] && len < sizeof(tmp) - 1) { tmp[len] = cwd[len]; len++; }
            break;
        }
        case PROC_FD_ENTRY: {
            /* Use file->path if available, else vnode path, else /dev/fd/<n> */
            fut_task_t *task = fut_task_by_pid(n->pid);
            if (!task) return -ESRCH;
            if (n->fd >= 0 && n->fd < task->max_fds && task->fd_table[n->fd]) {
                struct fut_file *file = task->fd_table[n->fd];
                const char *fpath = NULL;
                if (file->path && file->path[0]) {
                    fpath = file->path;
                } else if (file->vnode) {
                    /* Build path from vnode chain */
                    char *built = fut_vnode_build_path(file->vnode, tmp, sizeof(tmp));
                    if (built) {
                        len = 0;
                        while (tmp[len] && len < sizeof(tmp) - 1) len++;
                        break;
                    }
                }
                if (fpath) {
                    while (fpath[len] && len < sizeof(tmp) - 1)
                        { tmp[len] = fpath[len]; len++; }
                    break;
                }
            }
            /* Fallback */
            struct pbuf b = { tmp, 0, sizeof(tmp) };
            pb_str(&b, "/dev/fd/");
            pb_u64(&b, (uint64_t)n->fd);
            len = b.pos;
            break;
        }
        default:
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
        if (STREQ(name, "cpuinfo")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_CPUINFO,
                                          0100444, PROC_CPUINFO, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "loadavg")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_LOADAVG,
                                          0100444, PROC_LOADAVG, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "mounts")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_MOUNTS,
                                          0100444, PROC_MOUNTS, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "sys")) {
            *result = procfs_alloc_vnode(mnt, VN_DIR, PROC_INO_SYS_DIR,
                                          0040555, PROC_SYS_DIR, 0, 0);
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
        if (STREQ(name, "exe")) {
            *result = procfs_alloc_vnode(mnt, VN_LNK, PROC_INO_PID_EXE(pid),
                                          0120777, PROC_EXE, pid, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "cwd")) {
            *result = procfs_alloc_vnode(mnt, VN_LNK, PROC_INO_PID_CWD(pid),
                                          0120777, PROC_CWD, pid, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "stat")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_PID_STAT(pid),
                                          0100444, PROC_STAT, pid, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "statm")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_PID_STATM(pid),
                                          0100444, PROC_STATM, pid, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "comm")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_PID_COMM(pid),
                                          0100644, PROC_COMM, pid, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "task")) {
            *result = procfs_alloc_vnode(mnt, VN_DIR, PROC_INO_PID_TASK(pid),
                                          0040555, PROC_TASK_DIR, pid, 0);
            return *result ? 0 : -ENOMEM;
        }
        return -ENOENT;
    }

    if (dn->kind == PROC_TASK_DIR) {
        /* Lookup a TID sub-directory under /proc/<pid>/task/<tid>/ */
        uint64_t pid = dn->pid;
        /* Parse TID from name */
        uint64_t tid = 0;
        const char *p = name;
        if (!*p) return -ENOENT;
        while (*p >= '0' && *p <= '9') { tid = tid * 10 + (*p - '0'); p++; }
        if (*p != '\0' || tid == 0) return -ENOENT;
        /* Validate that this TID belongs to this task */
        fut_task_t *task = fut_task_by_pid(pid);
        if (!task) return -ENOENT;
        bool found = false;
        for (fut_thread_t *t = task->threads; t; t = t->next) {
            if (t->tid == tid) { found = true; break; }
        }
        if (!found) return -ENOENT;
        *result = procfs_alloc_vnode(mnt, VN_DIR, PROC_INO_TID_DIR(pid, tid),
                                      0040555, PROC_TID_DIR, pid, (int)tid);
        return *result ? 0 : -ENOMEM;
    }

    if (dn->kind == PROC_TID_DIR) {
        /* /proc/<pid>/task/<tid>/ exposes the same files as /proc/<pid>/ */
        uint64_t pid = dn->pid;
        if (STREQ(name, "status"))
            { *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_PID_STATUS(pid), 0100444, PROC_STATUS, pid, 0); return *result ? 0 : -ENOMEM; }
        if (STREQ(name, "maps"))
            { *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_PID_MAPS(pid),   0100444, PROC_MAPS,   pid, 0); return *result ? 0 : -ENOMEM; }
        if (STREQ(name, "cmdline"))
            { *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_PID_CMDLINE(pid),0100444, PROC_CMDLINE,pid, 0); return *result ? 0 : -ENOMEM; }
        if (STREQ(name, "fd"))
            { *result = procfs_alloc_vnode(mnt, VN_DIR, PROC_INO_PID_FD(pid),     0040500, PROC_FD_DIR, pid, 0); return *result ? 0 : -ENOMEM; }
        if (STREQ(name, "exe"))
            { *result = procfs_alloc_vnode(mnt, VN_LNK, PROC_INO_PID_EXE(pid),    0120777, PROC_EXE,    pid, 0); return *result ? 0 : -ENOMEM; }
        if (STREQ(name, "cwd"))
            { *result = procfs_alloc_vnode(mnt, VN_LNK, PROC_INO_PID_CWD(pid),    0120777, PROC_CWD,    pid, 0); return *result ? 0 : -ENOMEM; }
        if (STREQ(name, "stat"))
            { *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_PID_STAT(pid),   0100444, PROC_STAT,   pid, 0); return *result ? 0 : -ENOMEM; }
        if (STREQ(name, "statm"))
            { *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_PID_STATM(pid),  0100444, PROC_STATM,  pid, 0); return *result ? 0 : -ENOMEM; }
        if (STREQ(name, "comm"))
            { *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_PID_COMM(pid),   0100644, PROC_COMM,   pid, 0); return *result ? 0 : -ENOMEM; }
        if (STREQ(name, "task"))
            { *result = procfs_alloc_vnode(mnt, VN_DIR, PROC_INO_PID_TASK(pid),   0040555, PROC_TASK_DIR,pid,0); return *result ? 0 : -ENOMEM; }
        return -ENOENT;
    }

    if (dn->kind == PROC_SYS_DIR) {
        if (STREQ(name, "kernel")) {
            *result = procfs_alloc_vnode(mnt, VN_DIR, PROC_INO_SYS_KERNEL_DIR,
                                          0040555, PROC_SYS_KERNEL_DIR, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "vm")) {
            *result = procfs_alloc_vnode(mnt, VN_DIR, PROC_INO_SYS_VM_DIR,
                                          0040555, PROC_SYS_VM_DIR, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "fs")) {
            *result = procfs_alloc_vnode(mnt, VN_DIR, PROC_INO_SYS_FS_DIR,
                                          0040555, PROC_SYS_FS_DIR, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        return -ENOENT;
    }

    if (dn->kind == PROC_SYS_KERNEL_DIR) {
        if (STREQ(name, "ostype")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_OSTYPE,
                                          0100444, PROC_SYS_OSTYPE, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "osrelease")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_OSRELEASE,
                                          0100444, PROC_SYS_OSRELEASE, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "hostname")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_HOSTNAME,
                                          0100644, PROC_SYS_HOSTNAME, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "pid_max")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_PID_MAX,
                                          0100644, PROC_SYS_PID_MAX, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        return -ENOENT;
    }

    if (dn->kind == PROC_SYS_VM_DIR) {
        if (STREQ(name, "overcommit_memory")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_OVERCOMMIT,
                                          0100644, PROC_SYS_OVERCOMMIT, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        return -ENOENT;
    }

    if (dn->kind == PROC_SYS_FS_DIR) {
        if (STREQ(name, "file-max")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_FILE_MAX,
                                          0100644, PROC_SYS_FILE_MAX, 0, 0);
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
        /* Fixed entries: ., .., self, meminfo, version, uptime, cpuinfo, loadavg, mounts, sys */
        static const char *fixed[] = {
            ".", "..", "self", "meminfo", "version", "uptime", "cpuinfo",
            "loadavg", "mounts", "sys"
        };
        static const uint8_t fixed_type[] = {
            FUT_VDIR_TYPE_DIR, FUT_VDIR_TYPE_DIR,
            FUT_VDIR_TYPE_SYMLINK,
            FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG,
            FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG,
            FUT_VDIR_TYPE_DIR
        };
        static const uint64_t fixed_ino[] = {
            PROC_INO_ROOT, PROC_INO_ROOT,
            PROC_INO_SELF, PROC_INO_MEMINFO, PROC_INO_VERSION, PROC_INO_UPTIME,
            PROC_INO_CPUINFO, PROC_INO_LOADAVG, PROC_INO_MOUNTS, PROC_INO_SYS_DIR
        };
        if (idx < 10) {
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

        /*
         * PID enumeration: cookie >= 7 means "find the first task with
         * pid > (cookie - 7)".  After returning a PID entry we set
         * cookie = 7 + that_pid, so the next call resumes after it.
         *
         * This is stable as long as PIDs are unique and monotonically
         * increasing; newly-forked tasks will appear if their PID is
         * greater than the last-seen PID.
         */
        uint64_t min_pid = idx - 10;  /* start scanning for pid > min_pid */
        fut_task_t *best = NULL;
        uint64_t   best_pid = (uint64_t)-1;
        fut_task_t *t = fut_task_list;
        while (t) {
            if (t->pid > min_pid && t->pid < best_pid) {
                best = t;
                best_pid = t->pid;
            }
            t = t->next;
        }
        if (!best) return -ENOENT;  /* no more tasks */

        /* Format pid as decimal name */
        char pidname[20]; int pn = 0;
        uint64_t pv = best->pid;
        if (pv == 0) { pidname[pn++] = '0'; }
        else {
            char rev[20]; int rn = 0;
            while (pv) { rev[rn++] = '0' + (int)(pv % 10); pv /= 10; }
            for (int i = rn - 1; i >= 0; i--) pidname[pn++] = rev[i];
        }
        pidname[pn] = '\0';

        de->d_ino    = PROC_INO_PID_DIR(best->pid);
        de->d_off    = 10 + best->pid + 1;
        de->d_type   = FUT_VDIR_TYPE_DIR;
        de->d_reclen = sizeof(*de);
        size_t nl = (size_t)pn;
        if (nl > FUT_VFS_NAME_MAX) nl = FUT_VFS_NAME_MAX;
        __builtin_memcpy(de->d_name, pidname, nl);
        de->d_name[nl] = '\0';
        *cookie = 10 + best->pid + 1;  /* resume after this pid */
        return 0;
    }

    if (dn->kind == PROC_PID_DIR || dn->kind == PROC_TID_DIR) {
        static const char *entries[] = {
            ".", "..", "status", "maps", "cmdline", "fd", "exe", "cwd",
            "stat", "statm", "comm", "task"
        };
        static const uint8_t etypes[] = {
            FUT_VDIR_TYPE_DIR, FUT_VDIR_TYPE_DIR,
            FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG,
            FUT_VDIR_TYPE_DIR,
            FUT_VDIR_TYPE_SYMLINK, FUT_VDIR_TYPE_SYMLINK,
            FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG,
            FUT_VDIR_TYPE_DIR
        };
        uint64_t pid = dn->pid;
        if (idx < 12) {
            uint64_t ino;
            switch (idx) {
                case 0:  ino = PROC_INO_PID_DIR(pid);     break;
                case 1:  ino = PROC_INO_ROOT;              break;
                case 2:  ino = PROC_INO_PID_STATUS(pid);  break;
                case 3:  ino = PROC_INO_PID_MAPS(pid);    break;
                case 4:  ino = PROC_INO_PID_CMDLINE(pid); break;
                case 5:  ino = PROC_INO_PID_FD(pid);      break;
                case 6:  ino = PROC_INO_PID_EXE(pid);     break;
                case 7:  ino = PROC_INO_PID_CWD(pid);     break;
                case 8:  ino = PROC_INO_PID_STAT(pid);    break;
                case 9:  ino = PROC_INO_PID_STATM(pid);   break;
                case 10: ino = PROC_INO_PID_COMM(pid);    break;
                case 11: ino = PROC_INO_PID_TASK(pid);    break;
                default: ino = 0; break;
            }
            de->d_ino    = ino;
            de->d_off    = (uint64_t)(idx + 1);
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

    if (dn->kind == PROC_TASK_DIR) {
        /* Enumerate threads: . and .. first, then TID entries */
        uint64_t pid = dn->pid;
        if (idx == 0) {
            de->d_ino = PROC_INO_PID_TASK(pid);
            de->d_off = 1; de->d_type = FUT_VDIR_TYPE_DIR;
            de->d_reclen = sizeof(*de);
            de->d_name[0] = '.'; de->d_name[1] = '\0';
            *cookie = 1; return 0;
        }
        if (idx == 1) {
            de->d_ino = PROC_INO_PID_DIR(pid);
            de->d_off = 2; de->d_type = FUT_VDIR_TYPE_DIR;
            de->d_reclen = sizeof(*de);
            de->d_name[0] = '.'; de->d_name[1] = '.'; de->d_name[2] = '\0';
            *cookie = 2; return 0;
        }
        /* TID enumeration: cookie >= 2 → find thread at position idx-2 */
        fut_task_t *task = fut_task_by_pid(pid);
        if (!task) return -ENOENT;
        fut_thread_t *t = task->threads;
        uint64_t pos = 0;
        uint64_t target = (uint64_t)idx - 2;
        while (t && pos < target) { t = t->next; pos++; }
        if (!t) return -ENOENT;
        /* Build TID string */
        char tidname[21];
        uint64_t v = t->tid; int n = 0;
        if (v == 0) { tidname[n++] = '0'; }
        else { char tmp[20]; int k = 0; while (v) { tmp[k++] = '0' + (v % 10); v /= 10; } for (int i = k-1; i >= 0; i--) tidname[n++] = tmp[i]; }
        tidname[n] = '\0';
        de->d_ino = PROC_INO_TID_DIR(pid, t->tid);
        de->d_off = idx + 1; de->d_type = FUT_VDIR_TYPE_DIR;
        de->d_reclen = sizeof(*de);
        size_t nl = (size_t)n;
        if (nl > FUT_VFS_NAME_MAX) nl = FUT_VFS_NAME_MAX;
        __builtin_memcpy(de->d_name, tidname, nl);
        de->d_name[nl] = '\0';
        *cookie = idx + 1;
        return 0;
    }

    /* Generic readdir helper for small fixed-entry directories */
#define SYS_DIR_ENTRY(nm, tp, ino)  do { \
    de->d_ino = (ino); de->d_off = idx + 1; de->d_type = (tp); \
    de->d_reclen = sizeof(*de); \
    size_t _nl = 0; while ((nm)[_nl]) _nl++; \
    if (_nl > FUT_VFS_NAME_MAX) _nl = FUT_VFS_NAME_MAX; \
    __builtin_memcpy(de->d_name, (nm), _nl); de->d_name[_nl] = '\0'; \
    *cookie = idx + 1; return 0; \
} while (0)

    if (dn->kind == PROC_SYS_DIR) {
        static const char *e[] = { ".", "..", "kernel", "vm", "fs" };
        static const uint8_t t[] = { FUT_VDIR_TYPE_DIR, FUT_VDIR_TYPE_DIR,
                                     FUT_VDIR_TYPE_DIR, FUT_VDIR_TYPE_DIR, FUT_VDIR_TYPE_DIR };
        static const uint64_t i[] = { PROC_INO_SYS_DIR, PROC_INO_ROOT,
                                      PROC_INO_SYS_KERNEL_DIR, PROC_INO_SYS_VM_DIR,
                                      PROC_INO_SYS_FS_DIR };
        if (idx < 5) SYS_DIR_ENTRY(e[idx], t[idx], i[idx]);
        return -ENOENT;
    }

    if (dn->kind == PROC_SYS_KERNEL_DIR) {
        static const char *e[] = { ".", "..", "ostype", "osrelease", "hostname", "pid_max" };
        static const uint8_t t[] = { FUT_VDIR_TYPE_DIR, FUT_VDIR_TYPE_DIR,
                                     FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG,
                                     FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG };
        static const uint64_t i[] = { PROC_INO_SYS_KERNEL_DIR, PROC_INO_SYS_DIR,
                                      PROC_INO_SYS_OSTYPE, PROC_INO_SYS_OSRELEASE,
                                      PROC_INO_SYS_HOSTNAME, PROC_INO_SYS_PID_MAX };
        if (idx < 6) SYS_DIR_ENTRY(e[idx], t[idx], i[idx]);
        return -ENOENT;
    }

    if (dn->kind == PROC_SYS_VM_DIR) {
        static const char *e[] = { ".", "..", "overcommit_memory" };
        static const uint8_t t[] = { FUT_VDIR_TYPE_DIR, FUT_VDIR_TYPE_DIR, FUT_VDIR_TYPE_REG };
        static const uint64_t i[] = { PROC_INO_SYS_VM_DIR, PROC_INO_SYS_DIR,
                                      PROC_INO_SYS_OVERCOMMIT };
        if (idx < 3) SYS_DIR_ENTRY(e[idx], t[idx], i[idx]);
        return -ENOENT;
    }

    if (dn->kind == PROC_SYS_FS_DIR) {
        static const char *e[] = { ".", "..", "file-max" };
        static const uint8_t t[] = { FUT_VDIR_TYPE_DIR, FUT_VDIR_TYPE_DIR, FUT_VDIR_TYPE_REG };
        static const uint64_t i[] = { PROC_INO_SYS_FS_DIR, PROC_INO_SYS_DIR,
                                      PROC_INO_SYS_FILE_MAX };
        if (idx < 3) SYS_DIR_ENTRY(e[idx], t[idx], i[idx]);
        return -ENOENT;
    }

#undef SYS_DIR_ENTRY

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
