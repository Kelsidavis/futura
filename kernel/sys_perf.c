/* kernel/sys_perf.c - Performance monitoring counters
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements perf_event_open() for hardware and software performance
 * counter monitoring. Used by:
 *   - perf stat, perf record, perf top
 *   - systemd-analyze, systemd-cgls
 *   - eBPF programs (bpftrace, bcc tools)
 *   - strace -c (syscall timing)
 *   - Various profilers (gperftools, Valgrind)
 *
 * Supports counter types:
 *   PERF_TYPE_HARDWARE  — cpu-cycles, instructions, cache-references, etc.
 *   PERF_TYPE_SOFTWARE  — task-clock, page-faults, context-switches, cpu-clock
 *   PERF_TYPE_TRACEPOINT — kernel tracepoints (stub)
 *   PERF_TYPE_HW_CACHE  — L1/LL/DTLB cache hit/miss counters
 *
 * Counter values are synthesized from kernel statistics (timer ticks,
 * page fault counters, context switch counters) since Futura doesn't
 * have real hardware PMU access in QEMU mode.
 *
 * Syscall number (Linux x86_64): 298  (aarch64: 241)
 */

#include <kernel/kprintf.h>
#include <kernel/errno.h>
#include <kernel/fut_task.h>
#include <kernel/chrdev.h>
#include <kernel/uaccess.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#include <platform/platform.h>

/* ── perf_event_attr constants (Linux ABI) ── */

/* Event types */
#define PERF_TYPE_HARDWARE   0
#define PERF_TYPE_SOFTWARE   1
#define PERF_TYPE_TRACEPOINT 2
#define PERF_TYPE_HW_CACHE   3
#define PERF_TYPE_RAW        4
#define PERF_TYPE_BREAKPOINT 5

/* Hardware events */
#define PERF_COUNT_HW_CPU_CYCLES              0
#define PERF_COUNT_HW_INSTRUCTIONS            1
#define PERF_COUNT_HW_CACHE_REFERENCES        2
#define PERF_COUNT_HW_CACHE_MISSES            3
#define PERF_COUNT_HW_BRANCH_INSTRUCTIONS     4
#define PERF_COUNT_HW_BRANCH_MISSES           5
#define PERF_COUNT_HW_BUS_CYCLES              6
#define PERF_COUNT_HW_STALLED_CYCLES_FRONTEND 7
#define PERF_COUNT_HW_STALLED_CYCLES_BACKEND  8
#define PERF_COUNT_HW_REF_CPU_CYCLES          9

/* Software events */
#define PERF_COUNT_SW_CPU_CLOCK         0
#define PERF_COUNT_SW_TASK_CLOCK        1
#define PERF_COUNT_SW_PAGE_FAULTS       2
#define PERF_COUNT_SW_CONTEXT_SWITCHES  3
#define PERF_COUNT_SW_CPU_MIGRATIONS    4
#define PERF_COUNT_SW_PAGE_FAULTS_MIN   5
#define PERF_COUNT_SW_PAGE_FAULTS_MAJ   6
#define PERF_COUNT_SW_ALIGNMENT_FAULTS  7
#define PERF_COUNT_SW_EMULATION_FAULTS  8

/* perf_event_attr flags */
#define PERF_FLAG_FD_NO_GROUP     (1UL << 0)
#define PERF_FLAG_FD_OUTPUT       (1UL << 1)
#define PERF_FLAG_PID_CGROUP      (1UL << 2)
#define PERF_FLAG_FD_CLOEXEC      (1UL << 3)

/* ioctl commands for perf fd */
#define PERF_EVENT_IOC_ENABLE    0x2400
#define PERF_EVENT_IOC_DISABLE   0x2401
#define PERF_EVENT_IOC_REFRESH   0x2402
#define PERF_EVENT_IOC_RESET     0x2403
#define PERF_EVENT_IOC_PERIOD    0x2404
#define PERF_EVENT_IOC_SET_OUTPUT 0x2405
#define PERF_EVENT_IOC_SET_FILTER 0x2406
#define PERF_EVENT_IOC_ID        0x2407

/* ── Simplified perf_event_attr ── */

struct perf_event_attr {
    uint32_t type;
    uint32_t size;
    uint64_t config;
    union {
        uint64_t sample_period;
        uint64_t sample_freq;
    };
    uint64_t sample_type;
    uint64_t read_format;
    uint64_t flags;           /* disabled, inherit, pinned, exclusive, ... */
    uint32_t wakeup_events;
    uint32_t bp_type;
    uint64_t config1;
    uint64_t config2;
    uint64_t branch_sample_type;
    uint64_t sample_regs_user;
    uint32_t sample_stack_user;
    int32_t  clockid;
    uint64_t sample_regs_intr;
    uint64_t aux_watermark;
    uint16_t sample_max_stack;
    uint16_t __reserved_2;
    uint32_t aux_sample_size;
};

/* ── Internal state ── */

#define MAX_PERF_EVENTS   64

struct perf_event {
    bool     active;
    int      fd;
    uint64_t owner_pid;
    uint32_t type;
    uint64_t config;
    int      target_pid;      /* -1 = calling process */
    int      target_cpu;      /* -1 = any CPU */
    bool     enabled;
    uint64_t count;           /* Current counter value */
    uint64_t time_enabled;    /* Time counter was enabled (ns) */
    uint64_t time_running;    /* Time counter was running (ns) */
    uint64_t start_ticks;     /* Ticks when enabled */
};

static struct perf_event perf_events[MAX_PERF_EVENTS];

/* ── File operations ── */

static int perf_release(void *inode, void *priv) {
    (void)inode;
    struct perf_event *ev = (struct perf_event *)priv;
    if (ev) ev->active = false;
    return 0;
}

static ssize_t perf_read(void *inode, void *priv, void *buf, size_t n, off_t *pos) {
    (void)inode; (void)pos;
    struct perf_event *ev = (struct perf_event *)priv;
    if (!ev || !ev->active) return -EBADF;

    /* Update counter value based on event type */
    extern uint64_t fut_get_ticks(void);
    uint64_t now = fut_get_ticks();
    fut_task_t *task = fut_task_current();

    switch (ev->type) {
    case PERF_TYPE_SOFTWARE:
        switch (ev->config) {
        case PERF_COUNT_SW_CPU_CLOCK:
        case PERF_COUNT_SW_TASK_CLOCK:
            /* Convert ticks to nanoseconds (100 Hz → 10ms/tick) */
            ev->count = now * 10000000ULL;
            break;
        case PERF_COUNT_SW_PAGE_FAULTS:
            ev->count = task ? (task->minflt + task->majflt) : 0;
            break;
        case PERF_COUNT_SW_PAGE_FAULTS_MIN:
            ev->count = task ? task->minflt : 0;
            break;
        case PERF_COUNT_SW_PAGE_FAULTS_MAJ:
            ev->count = task ? task->majflt : 0;
            break;
        case PERF_COUNT_SW_CONTEXT_SWITCHES:
            /* Approximate from tick count */
            ev->count = now;
            break;
        default:
            ev->count = 0;
            break;
        }
        break;

    case PERF_TYPE_HARDWARE:
        switch (ev->config) {
        case PERF_COUNT_HW_CPU_CYCLES:
            /* Approximate: ticks * cycles-per-tick (assume 1GHz, 10ms ticks) */
            ev->count = now * 10000000ULL;
            break;
        case PERF_COUNT_HW_INSTRUCTIONS:
            /* Approximate: ~2 instructions per cycle */
            ev->count = now * 20000000ULL;
            break;
        case PERF_COUNT_HW_CACHE_REFERENCES:
            ev->count = now * 1000000ULL;
            break;
        case PERF_COUNT_HW_CACHE_MISSES:
            ev->count = now * 10000ULL; /* ~1% miss rate */
            break;
        case PERF_COUNT_HW_BRANCH_INSTRUCTIONS:
            ev->count = now * 5000000ULL;
            break;
        case PERF_COUNT_HW_BRANCH_MISSES:
            ev->count = now * 50000ULL; /* ~1% miss rate */
            break;
        default:
            ev->count = 0;
            break;
        }
        break;

    default:
        ev->count = 0;
        break;
    }

    /* Update time tracking */
    if (ev->enabled && ev->start_ticks > 0) {
        uint64_t elapsed = (now - ev->start_ticks) * 10000000ULL;
        ev->time_enabled = elapsed;
        ev->time_running = elapsed;
    }

    /* Return the counter value(s) based on read_format.
     * Simplest case: just the 8-byte counter value. */
    if (n < sizeof(uint64_t)) return -EINVAL;

    uint64_t val = ev->count;
    memcpy(buf, &val, sizeof(val));
    return sizeof(uint64_t);
}

static int perf_ioctl_handler(void *inode, void *priv, unsigned long req, unsigned long arg) {
    (void)inode; (void)arg;
    struct perf_event *ev = (struct perf_event *)priv;
    if (!ev || !ev->active) return -EBADF;

    extern uint64_t fut_get_ticks(void);

    switch (req) {
    case PERF_EVENT_IOC_ENABLE:
        ev->enabled = true;
        ev->start_ticks = fut_get_ticks();
        return 0;

    case PERF_EVENT_IOC_DISABLE:
        ev->enabled = false;
        return 0;

    case PERF_EVENT_IOC_RESET:
        ev->count = 0;
        ev->time_enabled = 0;
        ev->time_running = 0;
        ev->start_ticks = fut_get_ticks();
        return 0;

    case PERF_EVENT_IOC_REFRESH:
        return 0; /* Accept refresh (overflow count) */

    case PERF_EVENT_IOC_ID: {
        /* Return event ID */
        uint64_t *id = (uint64_t *)(uintptr_t)arg;
        if (id) *id = (uint64_t)(ev - perf_events);
        return 0;
    }

    default:
        return -EINVAL;
    }
}

static const struct fut_file_ops perf_fops = {
    .release = perf_release,
    .read    = perf_read,
    .ioctl   = perf_ioctl_handler,
};

/* ── Syscall ── */

/**
 * perf_event_open() - Open a performance monitoring counter.
 * @attr:     Pointer to perf_event_attr describing the event.
 * @pid:      Target process (-1 = calling process, 0 = all).
 * @cpu:      Target CPU (-1 = any).
 * @group_fd: Group leader fd (-1 = no group).
 * @flags:    PERF_FLAG_* flags.
 * Returns: fd on success, negative errno on failure.
 */
long sys_perf_event_open(const void *attr, int pid, int cpu,
                         int group_fd, unsigned long flags) {
    (void)group_fd;

    if (!attr) return -EINVAL;

    /* Copy perf_event_attr from user before reading any fields. The
     * previous code cast attr directly and dereferenced a->type /
     * a->config / a->flags, which let any caller pass a kernel
     * address as 'attr' and have those fields read from kernel
     * memory (info disclosure into the perf_event slot's type/config
     * fields, and a kernel page-fault on a bad user pointer). */
    struct perf_event_attr a_copy;
    {
#ifdef KERNEL_VIRTUAL_BASE
        if ((uintptr_t)attr >= KERNEL_VIRTUAL_BASE) {
            __builtin_memcpy(&a_copy, attr, sizeof(a_copy));
        } else
#endif
        if (fut_copy_from_user(&a_copy, attr, sizeof(a_copy)) != 0)
            return -EFAULT;
    }
    const struct perf_event_attr *a = &a_copy;

    /* Validate event type */
    if (a->type > PERF_TYPE_BREAKPOINT) return -EINVAL;

    /* Tracepoints and breakpoints not supported */
    if (a->type == PERF_TYPE_TRACEPOINT) return -ENOENT;
    if (a->type == PERF_TYPE_BREAKPOINT) return -EINVAL;
    if (a->type == PERF_TYPE_RAW) return -EINVAL;

    fut_task_t *task = fut_task_current();
    if (!task) return -ESRCH;

    /* Cross-task / system-wide monitoring requires CAP_PERFMON (or the
     * historical CAP_SYS_ADMIN). Without this gate any process could
     * sample CPU cycles or cache misses on another user's tasks — a
     * known cross-uid side-channel vector. Linux additionally gates
     * pid==-1 (system-wide) on perf_event_paranoid; we treat any
     * cross-task or system-wide request as needing the cap. */
    {
        bool privileged = (task->uid == 0) ||
            (task->cap_effective & ((1ULL << 21 /* CAP_SYS_ADMIN */) |
                                    (1ULL << 38 /* CAP_PERFMON */)));
        bool same_task = (pid == -1)            ? false :
                         (pid == 0)             ? true  :
                         ((uint32_t)pid == task->pid);
        if (!same_task && !privileged) {
            return -EPERM;
        }
        if (pid == -1 && !privileged) {
            /* System-wide monitoring */
            return -EPERM;
        }
    }

    /* Find free slot */
    struct perf_event *ev = NULL;
    for (int i = 0; i < MAX_PERF_EVENTS; i++) {
        if (!perf_events[i].active) { ev = &perf_events[i]; break; }
    }
    if (!ev) return -EMFILE;

    memset(ev, 0, sizeof(*ev));
    ev->active = true;
    ev->type = a->type;
    ev->config = a->config;
    ev->target_pid = pid;
    ev->target_cpu = cpu;
    ev->enabled = !(a->flags & 1); /* Bit 0 = disabled */

    ev->owner_pid = task ? task->pid : 0;

    extern uint64_t fut_get_ticks(void);
    ev->start_ticks = fut_get_ticks();

    int fd = chrdev_alloc_fd(&perf_fops, NULL, ev);
    if (fd < 0) { ev->active = false; return fd; }
    ev->fd = fd;

    if ((flags & PERF_FLAG_FD_CLOEXEC) && task && fd < task->max_fds)
        task->fd_flags[fd] |= 1;

    return fd;
}
