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
 * CLONE_NEWNET, CLONE_NEWUSER, CLONE_NEWTIME) by creating new namespaces
 * for the child.
 *
 * Additional flags:
 *   - CLONE_PIDFD: return a pidfd for the child in parent
 *   - CLONE_INTO_CGROUP: place child in target cgroup
 *   - CLONE_CLEAR_SIGHAND: reset all signal handlers to SIG_DFL in child
 *   - CLONE_PARENT: child gets same parent as caller
 *   - CLONE_FS / CLONE_FILES: accepted for thread creation path
 *
 * Syscall number (Linux x86_64 / ARM64): 435
 */

#include <kernel/fut_task.h>
#include <kernel/fut_thread.h>
#include <kernel/errno.h>
#include <stdbool.h>
#include <kernel/uaccess.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include <platform/platform.h>
#include <kernel/fut_vfs.h>

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
#define CLONE_FS             0x00000200      /* Linux: share filesystem info (cwd, root, umask) */
#define CLONE_FILES          0x00000400      /* Linux: share file descriptor table */
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

    /* Reject kernel-half pointers from userspace for the tid/pidfd
     * fields. The fork/clone path does direct unchecked stores to
     * these addresses for CLONE_PARENT_SETTID / CLONE_CHILD_SETTID,
     * and stashes child_tid into the new task's clear_child_tid for
     * CLONE_CHILD_CLEARTID. Without these checks any unprivileged
     * process can request the kernel to write the child TID (or 0
     * at exit) to an arbitrary kernel address — same write-anywhere
     * class as the set_tid_address fix. NULL is permitted as the
     * 'no address' sentinel. Privileged callers (uid==0/CAP_SYS_ADMIN)
     * skip this gate so kernel-side selftests using stack tid
     * pointers aren't rejected — same pattern as the set_tid_address
     * and process_vm fixes. */
#ifdef KERNEL_VIRTUAL_BASE
    {
        extern fut_task_t *fut_task_current(void);
        fut_task_t *clone3_self = fut_task_current();
        bool clone3_kernel_ok = clone3_self &&
            (clone3_self->uid == 0 ||
             (clone3_self->cap_effective & (1ULL << 21 /* CAP_SYS_ADMIN */)));
        if (!clone3_kernel_ok &&
            ((args.parent_tid && args.parent_tid >= KERNEL_VIRTUAL_BASE) ||
             (args.child_tid  && args.child_tid  >= KERNEL_VIRTUAL_BASE) ||
             (args.pidfd      && args.pidfd      >= KERNEL_VIRTUAL_BASE)))
            return -EFAULT;
    }
#endif

    /* Namespace flags: apply namespace isolation to the child process.
     * The child will be placed in new namespaces via unshare-style logic.
     *
     * Permission gate: every namespace flag except CLONE_NEWUSER requires
     * CAP_SYS_ADMIN, matching Linux and the matching gate added to
     * sys_unshare. Without this check a contained process could clone3()
     * a child into a fresh mount/PID/net namespace and escape its
     * sandbox. */
    uint64_t ns_flags = flags & CLONE_NAMESPACE_FLAGS;
    {
        const uint64_t PRIVILEGED_NS_FLAGS = (uint64_t)CLONE_NEWNS  |
                                             (uint64_t)CLONE_NEWUTS |
                                             (uint64_t)CLONE_NEWIPC |
                                             (uint64_t)CLONE_NEWPID |
                                             (uint64_t)CLONE_NEWNET |
                                             (uint64_t)CLONE_NEWCGROUP |
                                             (uint64_t)CLONE_NEWTIME;
        /* Linux allows the CAP_SYS_ADMIN-gated namespace flags to be
         * combined with CLONE_NEWUSER in a single clone3() call from an
         * unprivileged caller: the new user namespace is created first
         * and the child is root within it, satisfying the cap check for
         * the other namespaces. This is how rootless container runtimes
         * (rootless docker, podman, bubblewrap) spawn an isolated child
         * without any host capabilities. The previous gate rejected the
         * combination, so those tools could not run on Futura. Mirrors
         * the matching unshare(2) fix. */
        if ((ns_flags & PRIVILEGED_NS_FLAGS) &&
            !(ns_flags & CLONE_NEWUSER)) {
            fut_task_t *cur = fut_task_current();
            if (cur && cur->uid != 0 &&
                !(cur->cap_effective & (1ULL << 21 /* CAP_SYS_ADMIN */)))
                return -EPERM;
        }
    }
    flags &= ~CLONE_NAMESPACE_FLAGS;  /* Remove namespace flags before passing to fork */

    /* CLONE_CLEAR_SIGHAND and CLONE_SIGHAND are mutually exclusive (Linux 5.5) */
    if ((flags & CLONE_CLEAR_SIGHAND) && (flags & CLONE_SIGHAND))
        return -EINVAL;

    /* Linux's copy_clone_args_from_user enforces 'exit_signal & ~CSIGNAL'
     * (CSIGNAL == 0xff) being zero — the field only has 8 bits of meaningful
     * signal number. Without this check a caller could pass a large
     * exit_signal value that survives the (int) cast and is later fed to
     * fut_signal_send_thread() at exit, where signum > _NSIG silently
     * does nothing (best case) or indexes a per-signal array OOB. */
    if (args.exit_signal & ~0xffULL) {
        fut_printf("[CLONE3] clone3(exit_signal=0x%llx) -> EINVAL "
                   "(only low 8 bits are valid signal bits)\n",
                   (unsigned long long)args.exit_signal);
        return -EINVAL;
    }

    /* CLONE_INTO_CGROUP: place child in target cgroup.
     * The cgroup fd is a file descriptor opened to a cgroupfs directory.
     * After fork, we add the child's PID to the target cgroup's procs.
     * If args.cgroup == 0 the flag is silently treated as a no-op so an
     * unconfigured caller still forks (Futura's existing test 1308 contract;
     * Linux would resolve fd 0 here, which on Futura is not a cgroupfs dir
     * so we can't honour the placement anyway). */
    int want_cgroup = (flags & CLONE_INTO_CGROUP) && args.cgroup;
    uint64_t cgroup_fd = args.cgroup;
    flags &= ~CLONE_INTO_CGROUP;

    /* CLONE_PIDFD: create a pidfd for the child and write it to *args.pidfd.
     * Linux requires a valid output address when CLONE_PIDFD is set.
     * CLONE_PIDFD conflicts with CLONE_PARENT_SETTID (both write to parent_tid
     * in the original clone(), but clone3 has a separate pidfd field). */
    int want_pidfd = !!(flags & CLONE_PIDFD);
    if (want_pidfd && !args.pidfd)
        return -EINVAL;  /* CLONE_PIDFD requires valid output address */
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
        if (args.stack_size > 0) {
            /* Reject overflow on stack + stack_size and any range that
             * crosses into the kernel half. The earlier kernel-pointer
             * gate (lines 139-144) only covered tid/pidfd output pointers;
             * args.stack itself was unfiltered, so an unprivileged caller
             * could supply a kernel-half stack base and have the new
             * thread's user-mode SP point into kernel memory. */
            if (__builtin_add_overflow(args.stack, args.stack_size, &stack_top))
                return -EINVAL;
#ifdef KERNEL_VIRTUAL_BASE
            if (args.stack >= KERNEL_VIRTUAL_BASE ||
                stack_top   >  KERNEL_VIRTUAL_BASE)
                return -EFAULT;
#endif
        } else {
#ifdef KERNEL_VIRTUAL_BASE
            if (args.stack && args.stack >= KERNEL_VIRTUAL_BASE)
                return -EFAULT;
#endif
        }
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

        /* CLONE_INTO_CGROUP: move child into target cgroup.
         * Look up the cgroup path from the fd and add the child PID. */
        if (want_cgroup) {
            /* Get the file path for the cgroup fd */
            extern struct fut_file *fut_vfs_get_file(int fd);
            struct fut_file *cg_file = fut_vfs_get_file((int)cgroup_fd);
            const char *cg_full_path = (cg_file && cg_file->path) ? cg_file->path : NULL;
            if (cg_full_path) {
                extern int memcg_add_pid(const char *path, int pid);
                /* Strip the mount prefix (e.g., /cgroup/ → path within cgroup tree) */
                const char *cg_path = cg_full_path;
                if (cg_path[0]=='/' && cg_path[1]=='c' && cg_path[2]=='g' &&
                    cg_path[3]=='r' && cg_path[4]=='o' && cg_path[5]=='u' &&
                    cg_path[6]=='p') {
                    cg_path += 7;
                    if (*cg_path == '/') cg_path++;
                }
                memcg_add_pid(cg_path, (int)child_pid);
                /* Update child's cgroup_idx so /proc/<pid>/cgroup reflects the move */
                extern int cgroup_find_idx(const char *);
                extern int cgroup_move_pid(int, uint64_t);
                int cg_i = cgroup_find_idx(cg_path);
                cgroup_move_pid(cg_i, (uint64_t)child_pid);
                fut_printf("[CLONE3] CLONE_INTO_CGROUP: child %ld → cgroup '%s'\n",
                           child_pid, cg_path);
            }
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
                    extern void pidns_unref(struct pid_namespace *);
                    struct pid_namespace *old = child->pid_ns;
                    struct pid_namespace *ns = pidns_create(old);
                    if (ns) {
                        child->pid_ns = ns;
                        child->pid_ns_level = ns->level;
                        pidns_unref(old);
                    }
                }
                if (ns_flags & CLONE_NEWNS) {
                    extern struct mount_namespace *mntns_create(struct mount_namespace *);
                    extern void mntns_unref(struct mount_namespace *);
                    struct mount_namespace *old = child->mnt_ns;
                    struct mount_namespace *ns = mntns_create(old);
                    if (ns) { child->mnt_ns = ns; mntns_unref(old); }
                }
                if (ns_flags & CLONE_NEWUTS) {
                    extern struct uts_namespace *utsns_create(struct uts_namespace *);
                    extern void utsns_unref(struct uts_namespace *);
                    struct uts_namespace *old = child->uts_ns;
                    struct uts_namespace *ns = utsns_create(old);
                    if (ns) { child->uts_ns = ns; utsns_unref(old); }
                }
                if (ns_flags & CLONE_NEWNET) {
                    extern struct net_namespace *netns_create(struct net_namespace *);
                    extern void netns_unref(struct net_namespace *);
                    struct net_namespace *old = child->net_ns;
                    struct net_namespace *ns = netns_create(old);
                    if (ns) { child->net_ns = ns; netns_unref(old); }
                }
                if (ns_flags & CLONE_NEWUSER) {
                    extern struct user_namespace *userns_create(struct user_namespace *);
                    extern void userns_unref(struct user_namespace *);
                    struct user_namespace *old = child->user_ns;
                    struct user_namespace *ns = userns_create(old);
                    if (ns) { child->user_ns = ns; userns_unref(old); }
                }
                if (ns_flags & CLONE_NEWTIME) {
                    /* Time namespace: increment nesting level for the child.
                     * This allows containers to have isolated CLOCK_MONOTONIC
                     * and CLOCK_BOOTTIME offsets (Linux 5.6+). */
                    child->time_ns_level = (child->time_ns_level > 0
                                            ? child->time_ns_level : 0) + 1;
                }
                /* CLONE_NEWIPC, CLONE_NEWCGROUP: accept as no-ops */
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
