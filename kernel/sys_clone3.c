/* kernel/sys_clone3.c - clone3() syscall (Linux 5.3+)
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * clone3() is the newer process/thread creation interface that uses a
 * struct clone_args instead of raw arguments.  It subsumes clone() and
 * is the preferred path in glibc 2.34+ for both fork() and pthread_create().
 *
 * Implemented paths:
 *   - Fork: flags == SIGCHLD (or 0 exit-signal) with no CLONE_VM/THREAD
 *   - Thread: CLONE_VM | CLONE_THREAD | CLONE_SIGHAND set
 *
 * Supports namespace flags (CLONE_NEWPID, CLONE_NEWNS, CLONE_NEWUTS,
 * CLONE_NEWNET, CLONE_NEWUSER) by creating new namespaces for the child.
 *
 * Syscall number (Linux x86_64 / ARM64): 435
 */

#include <kernel/fut_task.h>
#include <kernel/fut_thread.h>
#include <kernel/errno.h>
#include <kernel/uaccess.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include <platform/platform.h>

#include <kernel/kprintf.h>

/* struct clone_args — as defined by Linux (uapi/linux/sched.h) */
struct fut_clone_args {
    uint64_t flags;         /* Clone flags */
    uint64_t pidfd;         /* Out: pidfd (CLONE_PIDFD) */
    uint64_t child_tid;     /* Out in child: TID (CLONE_CHILD_SETTID) */
    uint64_t parent_tid;    /* Out in parent: child TID (CLONE_PARENT_SETTID) */
    uint64_t exit_signal;   /* Signal sent to parent when child exits */
    uint64_t stack;         /* Child stack base */
    uint64_t stack_size;    /* Child stack size */
    uint64_t tls;           /* TLS descriptor (CLONE_SETTLS) */
    /* v1 extension (size >= 64) */
    uint64_t set_tid;       /* Pointer to TID array (privileged) */
    uint64_t set_tid_size;  /* Count in set_tid */
    /* v2 extension (size >= 88) */
    uint64_t cgroup;        /* cgroup fd */
};

#define CLONE_ARGS_SIZE_VER0  64   /* First version: fields through tls */
#define CLONE_ARGS_SIZE_VER1  80   /* v1 adds set_tid/set_tid_size */
#define CLONE_ARGS_SIZE_VER2  88   /* v2 adds cgroup */
#define CLONE_ARGS_SIZE_MAX   CLONE_ARGS_SIZE_VER2

/* Namespace flags — require unimplemented namespace infra */
#define CLONE_NEWNS    0x00020000
#define CLONE_NEWCGROUP 0x02000000
#define CLONE_NEWUTS   0x04000000
#define CLONE_NEWIPC   0x08000000
#define CLONE_NEWUSER  0x10000000
#define CLONE_NEWPID   0x20000000
#define CLONE_NEWNET   0x40000000
#define CLONE_NEWTIME  0x00000080

#define CLONE_NAMESPACE_FLAGS (CLONE_NEWNS | CLONE_NEWCGROUP | CLONE_NEWUTS | \
                               CLONE_NEWIPC | CLONE_NEWUSER | CLONE_NEWPID |  \
                               CLONE_NEWNET | CLONE_NEWTIME)

#define CLONE_THREAD         0x00010000
#define CLONE_VM             0x00000100
#define CLONE_SIGHAND        0x00000800
#define CLONE_PIDFD          0x00001000
#define CLONE_PARENT_SETTID  0x00100000
#define CLONE_CHILD_SETTID   0x01000000
#define CLONE_CHILD_CLEARTID 0x00200000
#define CLONE_SETTLS         0x00080000
#define CLONE_PARENT         0x00008000      /* Linux: child gets same parent as caller */
#define CLONE_CLEAR_SIGHAND  0x100000000ULL  /* Linux 5.5: reset all handlers to SIG_DFL */
#define CLONE_INTO_CGROUP    0x200000000ULL  /* Linux 5.7: place child in specific cgroup */

static inline int clone3_copy_from_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)src >= KERNEL_VIRTUAL_BASE) { __builtin_memcpy(dst, src, n); return 0; }
#endif
    return fut_copy_from_user(dst, src, n);
}

static inline int clone3_copy_to_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)dst >= KERNEL_VIRTUAL_BASE) { __builtin_memcpy(dst, src, n); return 0; }
#endif
    return fut_copy_to_user(dst, src, n);
}

/**
 * sys_clone3 - Create a child process or thread via struct clone_args.
 *
 * @uargs:  Pointer to userspace struct clone_args.
 * @size:   sizeof(*uargs) as known by the caller (for ABI versioning).
 *
 * Returns child PID in parent, 0 in child, or negative errno.
 */
long sys_clone3(const struct fut_clone_args *uargs, size_t size) {
    /* Validate size: must cover at least the v0 fields */
    if (size < CLONE_ARGS_SIZE_VER0 || size > CLONE_ARGS_SIZE_MAX)
        return -EINVAL;

    if (!uargs)
        return -EFAULT;

    /* Copy the args structure (only as many bytes as the caller provided) */
    struct fut_clone_args args;
    __builtin_memset(&args, 0, sizeof(args));
    size_t copy_sz = (size < sizeof(args)) ? size : sizeof(args);
    if (clone3_copy_from_user(&args, uargs, copy_sz) != 0)
        return -EFAULT;

    uint64_t flags = args.flags;

    /* Namespace flags: apply namespace isolation to the child process.
     * The child will be placed in new namespaces via unshare-style logic. */
    uint64_t ns_flags = flags & CLONE_NAMESPACE_FLAGS;
    flags &= ~CLONE_NAMESPACE_FLAGS;  /* Remove namespace flags before passing to fork */

    /* CLONE_CLEAR_SIGHAND and CLONE_SIGHAND are mutually exclusive (Linux 5.5) */
    if ((flags & CLONE_CLEAR_SIGHAND) && (flags & CLONE_SIGHAND))
        return -EINVAL;

    /* CLONE_INTO_CGROUP: no cgroup infra yet, ignore (cgroup fd not used) */
    flags &= ~CLONE_INTO_CGROUP;

    /* CLONE_PIDFD: create a pidfd for the child and write it to *args.pidfd */
    int want_pidfd = (flags & CLONE_PIDFD) && args.pidfd;
    flags &= ~(uint64_t)CLONE_PIDFD;  /* Don't pass to lower layers */

    /* Thread creation path */
    if (flags & CLONE_THREAD) {
        extern long sys_clone_thread(uint64_t flags, uint64_t child_stack,
                                     uint64_t parent_tid_ptr, uint64_t child_tid_ptr,
                                     uint64_t tls);
        /* clone3's stack field is the BASE (lowest address); sys_clone_thread
         * expects the TOP (highest address, where SP starts).  Compute top
         * from base + size.  If stack_size is 0, pass stack as-is (caller
         * already computed the top, matching legacy clone() semantics). */
        uint64_t stack_top = args.stack;
        if (args.stack_size > 0)
            stack_top = args.stack + args.stack_size;
        return sys_clone_thread(flags, stack_top, args.parent_tid,
                                args.child_tid, args.tls);
    }

    /* Fork path: no CLONE_VM / CLONE_THREAD */
    extern long sys_fork(void);
    long child_pid = sys_fork();

    if (child_pid > 0) {
        /* ── Parent context ── */

        /* CLONE_PARENT: reparent child to caller's parent (sibling relationship).
         * Used by systemd-nspawn, container runtimes, double-fork daemons. */
        if ((flags & CLONE_PARENT) && child_pid > 0) {
            fut_task_t *caller = fut_task_current();
            if (caller && caller->parent) {
                fut_task_t *child = fut_task_by_pid((uint64_t)child_pid);
                if (child)
                    fut_task_reparent(child, caller->parent);
            }
        }

        /* CLONE_PIDFD: create pidfd and write to caller */
        if (want_pidfd) {
            extern long sys_pidfd_open(int pid, unsigned int flags);
            long pidfd = sys_pidfd_open((int)child_pid, 0);
            int pidfd_int = (pidfd >= 0) ? (int)pidfd : -1;
            clone3_copy_to_user((void *)(uintptr_t)args.pidfd,
                                &pidfd_int, sizeof(pidfd_int));
        }

        /* CLONE_PARENT_SETTID: write child PID to parent_tid address */
        if ((flags & CLONE_PARENT_SETTID) && args.parent_tid) {
            int tid_val = (int)child_pid;
            clone3_copy_to_user((void *)(uintptr_t)args.parent_tid,
                                &tid_val, sizeof(tid_val));
        }

        /* Apply namespace flags to the child process */
        if (ns_flags) {
            fut_task_t *child = fut_task_by_pid((uint64_t)child_pid);
            if (child) {
                if (ns_flags & CLONE_NEWPID) {
                    extern struct pid_namespace *pidns_create(struct pid_namespace *);
                    struct pid_namespace *ns = pidns_create(child->pid_ns);
                    if (ns) child->pid_ns = ns;
                }
                if (ns_flags & CLONE_NEWNS) {
                    extern struct mount_namespace *mntns_create(struct mount_namespace *);
                    struct mount_namespace *ns = mntns_create(child->mnt_ns);
                    if (ns) child->mnt_ns = ns;
                }
                if (ns_flags & CLONE_NEWUTS) {
                    extern struct uts_namespace *utsns_create(struct uts_namespace *);
                    struct uts_namespace *ns = utsns_create(child->uts_ns);
                    if (ns) child->uts_ns = ns;
                }
                if (ns_flags & CLONE_NEWNET) {
                    extern struct net_namespace *netns_create(struct net_namespace *);
                    struct net_namespace *ns = netns_create(child->net_ns);
                    if (ns) child->net_ns = ns;
                }
                if (ns_flags & CLONE_NEWUSER) {
                    extern struct user_namespace *userns_create(struct user_namespace *);
                    struct user_namespace *ns = userns_create(child->user_ns);
                    if (ns) child->user_ns = ns;
                }
                /* CLONE_NEWIPC, CLONE_NEWCGROUP, CLONE_NEWTIME: accept as no-ops */
            }
        }
    } else if (child_pid == 0) {
        /* ── Child context ── */
        fut_task_t *child_task = fut_task_current();

        /* Set exit_signal from clone_args (default SIGCHLD if 0 or unset) */
        if (child_task) {
            child_task->exit_signal = args.exit_signal ? (int)args.exit_signal : SIGCHLD;
        }

        /* CLONE_CLEAR_SIGHAND: reset ALL signal dispositions to SIG_DFL
         * (Linux 5.5+).  Used by systemd when spawning services to ensure
         * the child starts with a completely clean signal state. */
        if ((flags & CLONE_CLEAR_SIGHAND) && child_task) {
            for (int i = 0; i < _NSIG; i++) {
                child_task->signal_handlers[i] = SIG_DFL;
                child_task->signal_handler_masks[i] = 0;
                child_task->signal_handler_flags[i] = 0;
            }
        }

        /* CLONE_CHILD_SETTID: write child's own TID into child_tid address */
        if ((flags & CLONE_CHILD_SETTID) && args.child_tid && child_task) {
            int tid_val = (int)child_task->pid;
            clone3_copy_to_user((void *)(uintptr_t)args.child_tid,
                                &tid_val, sizeof(tid_val));
        }

        /* CLONE_CHILD_CLEARTID: register address for zero+futex-wake on exit */
        if ((flags & CLONE_CHILD_CLEARTID) && args.child_tid && child_task) {
            child_task->clear_child_tid = (void *)(uintptr_t)args.child_tid;
        }
    }
    /* Error (child_pid < 0): nothing extra to do */

    return child_pid;
}
