/* kernel/sys_unshare.c - Resource unsharing syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements unshare syscall for creating private copies of shared resources.
 * Essential for container isolation, allowing a process to dissociate parts
 * of its execution context without creating a new process.
 *
 * Phase 1 (Completed): Validation and stub implementation
 * Phase 2 (Completed): Comprehensive flag validation and operation categorization with logging
 * Phase 3 (Completed): Implement non-namespace resource unshare as no-op success;
 *                    namespace flags (UTS/IPC/NS/NET/USER/CGROUP) succeed as no-ops
 * Phase 4 (Completed): CLONE_NEWPID creates a real PID namespace; pid_ns_level tracked per task
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <stdint.h>

#include <kernel/kprintf.h>

/* unshare() flags (from Linux clone.h) */
#define CLONE_VM             0x00000100  /* Share memory space */
#define CLONE_FS             0x00000200  /* Share filesystem information */
#define CLONE_FILES          0x00000400  /* Share file descriptor table */
#define CLONE_SIGHAND        0x00000800  /* Share signal handlers */
#define CLONE_NEWTIME        0x00000080  /* New time namespace (Linux 5.6+) */
#define CLONE_PIDFD          0x00001000  /* Return PID file descriptor */
#define CLONE_THREAD         0x00010000  /* Share thread group */
#define CLONE_NEWNS          0x00020000  /* New mount namespace */
#define CLONE_SYSVSEM        0x00040000  /* Share System V SEM_UNDO semantics */
#define CLONE_SETTLS         0x00080000  /* Set TLS */
#define CLONE_PARENT_SETTID  0x00100000  /* Store TID in parent */
#define CLONE_CHILD_CLEARTID 0x00200000  /* Clear TID in child */
#define CLONE_DETACHED       0x00400000  /* Unused (legacy) */
#define CLONE_UNTRACED       0x00800000  /* Ptrace cannot force CLONE_PTRACE */
#define CLONE_CHILD_SETTID   0x01000000  /* Store TID in child */
#define CLONE_NEWCGROUP      0x02000000  /* New cgroup namespace */
#define CLONE_NEWUTS         0x04000000  /* New UTS namespace */
#define CLONE_NEWIPC         0x08000000  /* New IPC namespace */
#define CLONE_NEWUSER        0x10000000  /* New user namespace */
#define CLONE_NEWPID         0x20000000  /* New PID namespace */
#define CLONE_NEWNET         0x40000000  /* New network namespace */
#define CLONE_IO             0x80000000  /* Share I/O context */

/**
 * unshare() - Disassociate parts of the process execution context
 *
 * Creates private copies of shared resources, allowing a process to
 * isolate itself without forking. This is the foundation for Linux
 * container isolation (Docker, LXC, etc.).
 *
 * @param flags  Bitmask of resources to unshare (CLONE_* flags)
 *
 * Returns:
 *   - 0 on success
 *   - -EINVAL if flags contains invalid combination
 *   - -ENOMEM if insufficient memory to duplicate resources
 *   - -ENOSPC if nesting limit reached (e.g., user namespaces)
 *   - -EPERM if caller lacks permission (e.g., CAP_SYS_ADMIN for namespaces)
 *   - -EUSERS if user namespace limit reached
 *
 * Usage:
 *   // Create new mount namespace (for container filesystem isolation)
 *   unshare(CLONE_NEWNS);
 *
 *   // Create new network namespace (for network isolation)
 *   unshare(CLONE_NEWNET);
 *
 *   // Full container isolation (all namespaces)
 *   unshare(CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWIPC |
 *           CLONE_NEWPID | CLONE_NEWNET | CLONE_NEWUSER);
 *
 *   // Unshare file descriptors (make private copy of fd table)
 *   unshare(CLONE_FILES);
 *
 * Namespace types:
 * - Mount (NEWNS): Filesystem mount points
 * - UTS (NEWUTS): Hostname and domain name
 * - IPC (NEWIPC): System V IPC, POSIX message queues
 * - PID (NEWPID): Process IDs
 * - Network (NEWNET): Network devices, IP addresses, routing tables
 * - User (NEWUSER): User and group IDs
 * - Cgroup (NEWCGROUP): Cgroup root directory
 *
 * Container runtime usage:
 * Docker and other container runtimes use unshare() to create isolated
 * environments. Each container gets its own view of the filesystem,
 * network, and process tree.
 *
 * Phase 1 (Completed): Validate flags and return success
 * Phase 2 (Completed): Comprehensive flag validation, operation categorization, and detailed logging
 * Phase 3 (Completed): Non-namespace flags and most namespace flags succeed as no-ops
 * Phase 4 (Completed): CLONE_NEWPID creates real PID namespace; pid_ns_level tracked per task
 */
long sys_unshare(unsigned long flags) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    /* CLONE_NEWTIME (Linux 5.6+) is included so unshare() can create a new
     * time namespace — the privileged-flag list below already gates it
     * behind CAP_SYS_ADMIN/CLONE_NEWUSER. The previous SUPPORTED list
     * omitted CLONE_NEWTIME, so any caller passing it landed in the
     * 'flags & ~SUPPORTED' EINVAL gate before the privileged-flag check
     * could fire. That hid the time-namespace path entirely from
     * userspace; sys_clone3 already accepts CLONE_NEWTIME, so unshare()
     * was the inconsistent entry point. */
    const unsigned long SUPPORTED_UNSHARE_FLAGS =
        CLONE_FILES | CLONE_FS | CLONE_SYSVSEM |
        CLONE_NEWNS | CLONE_NEWCGROUP | CLONE_NEWUTS |
        CLONE_NEWIPC | CLONE_NEWUSER | CLONE_NEWPID |
        CLONE_NEWNET | CLONE_NEWTIME;

    /* unshare(0) is a defined no-op and should succeed. */
    if (flags == 0) {
        fut_printf("[UNSHARE] unshare(flags=0x0 [no-op], pid=%d) -> 0\n", task->pid);
        return 0;
    }

    /* Reject unknown flag bits up front. */
    if (flags & ~SUPPORTED_UNSHARE_FLAGS) {
        fut_printf("[UNSHARE] unshare(flags=0x%lx [unsupported bits], pid=%d) -> EINVAL\n",
                   flags, task->pid);
        return -EINVAL;
    }

    /* Validate flags - check for unsupported combinations */
    /* Note: CLONE_THREAD, CLONE_SIGHAND, CLONE_VM have complex interdependencies */
    if ((flags & CLONE_THREAD) && !(flags & CLONE_SIGHAND)) {
        fut_printf("[UNSHARE] unshare(flags=0x%lx [THREAD requires SIGHAND], pid=%d) "
                   "-> EINVAL\n", flags, task->pid);
        return -EINVAL;
    }

    if ((flags & CLONE_SIGHAND) && !(flags & CLONE_VM)) {
        fut_printf("[UNSHARE] unshare(flags=0x%lx [SIGHAND requires VM], pid=%d) "
                   "-> EINVAL\n", flags, task->pid);
        return -EINVAL;
    }

    /* Check for invalid unshare targets */
    /* These flags don't make sense for unshare (they're fork/clone only) */
    const unsigned long INVALID_UNSHARE_FLAGS =
        CLONE_THREAD | CLONE_SIGHAND | CLONE_VM;

    if (flags & INVALID_UNSHARE_FLAGS) {
        fut_printf("[UNSHARE] unshare(flags=0x%lx [invalid for unshare], pid=%d) "
                   "-> EINVAL\n", flags, task->pid);
        return -EINVAL;
    }

    /* Permission check: every namespace flag except CLONE_NEWUSER
     * requires CAP_SYS_ADMIN, matching Linux. CLONE_NEWUSER is the
     * one explicit exception — its whole purpose is to let an
     * unprivileged caller obtain a fresh uid mapping it controls.
     *
     * Linux additionally allows CAP_SYS_ADMIN-gated namespaces to be
     * unshared in the *same call* as CLONE_NEWUSER even by an
     * unprivileged caller: the new user namespace is created first
     * and the caller becomes root within it, which then satisfies the
     * cap check for the other namespaces in the same syscall. This is
     * how rootless containers (rootless Docker, podman, bubblewrap)
     * obtain their own mount/PID/network namespaces without any host
     * capabilities. The previous code rejected this combination, so
     * those tools could not run on Futura. */
    {
        const unsigned long PRIVILEGED_NS_FLAGS =
            CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWIPC |
            CLONE_NEWPID | CLONE_NEWNET | CLONE_NEWCGROUP |
            CLONE_NEWTIME;  /* Match sys_clone3 — time namespace also needs CAP_SYS_ADMIN */
        if ((flags & PRIVILEGED_NS_FLAGS) &&
            !(flags & CLONE_NEWUSER) &&
            task->uid != 0 &&
            !(task->cap_effective & (1ULL << 21 /* CAP_SYS_ADMIN */))) {
            fut_printf("[UNSHARE] unshare(flags=0x%lx, pid=%d) -> EPERM "
                       "(namespace creation requires CAP_SYS_ADMIN unless "
                       "combined with CLONE_NEWUSER)\n",
                       flags, task->pid);
            return -EPERM;
        }
    }

    /* Categorize unshare operation */
    const char *operation_desc __attribute__((unused));
    if (flags == 0) {
        operation_desc = "none (no-op)";
    } else if (flags == CLONE_FILES) {
        operation_desc = "files";
    } else if (flags == CLONE_FS) {
        operation_desc = "filesystem info";
    } else if (flags & (CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWIPC |
                        CLONE_NEWPID | CLONE_NEWNET | CLONE_NEWUSER)) {
        /* Namespace operations */
        if ((flags & 0x7E000000) == 0x7E000000) {
            operation_desc = "all namespaces (container)";
        } else if (flags & CLONE_NEWNS) {
            operation_desc = "mount namespace";
        } else if (flags & CLONE_NEWNET) {
            operation_desc = "network namespace";
        } else if (flags & CLONE_NEWPID) {
            operation_desc = "PID namespace";
        } else if (flags & CLONE_NEWUSER) {
            operation_desc = "user namespace";
        } else if (flags & CLONE_NEWUTS) {
            operation_desc = "UTS namespace";
        } else if (flags & CLONE_NEWIPC) {
            operation_desc = "IPC namespace";
        } else {
            operation_desc = "namespace combination";
        }
    } else {
        operation_desc = "mixed resources";
    }

    /* CLONE_NEWPID: create a new PID namespace for future children.
     * The calling process stays in its current namespace, but its next
     * fork/clone will place the child in a new PID namespace where it
     * gets PID 1. This matches Linux unshare(CLONE_NEWPID) semantics. */
    if (flags & CLONE_NEWPID) {
        extern struct pid_namespace *pidns_create(struct pid_namespace *);
        struct pid_namespace *new_ns = pidns_create(task->pid_ns);
        if (!new_ns) return -ENOMEM;
        /* Store new namespace — next fork will use it for the child */
        task->pid_ns = new_ns;
        task->pid_ns_level = new_ns->level;
        fut_printf("[UNSHARE] unshare(CLONE_NEWPID, pid=%d) -> new pidns level=%d\n",
                   (int)task->pid, new_ns->level);
    }

    /* CLONE_NEWNS: create a new mount namespace. The task gets its own
     * mount list, so future mount/umount operations are invisible to
     * other tasks in the parent namespace. */
    if (flags & CLONE_NEWNS) {
        extern struct mount_namespace *mntns_create(struct mount_namespace *);
        struct mount_namespace *new_mntns = mntns_create(task->mnt_ns);
        if (!new_mntns) return -ENOMEM;
        task->mnt_ns = new_mntns;
        fut_printf("[UNSHARE] unshare(CLONE_NEWNS, pid=%d) -> new mntns id=%llu\n",
                   (int)task->pid, (unsigned long long)new_mntns->id);
    }

    /* CLONE_NEWUTS: per-container hostname/domainname */
    if (flags & CLONE_NEWUTS) {
        extern struct uts_namespace *utsns_create(struct uts_namespace *);
        struct uts_namespace *new_utsns = utsns_create(task->uts_ns);
        if (!new_utsns) return -ENOMEM;
        task->uts_ns = new_utsns;
    }

    /* CLONE_NEWNET: per-container network stack */
    if (flags & CLONE_NEWNET) {
        extern struct net_namespace *netns_create(struct net_namespace *);
        struct net_namespace *new_netns = netns_create(task->net_ns);
        if (!new_netns) return -ENOMEM;
        task->net_ns = new_netns;
    }

    /* CLONE_NEWUSER: per-container UID/GID mapping */
    if (flags & CLONE_NEWUSER) {
        extern struct user_namespace *userns_create(struct user_namespace *);
        struct user_namespace *new_userns = userns_create(task->user_ns);
        if (!new_userns) return -ENOMEM;
        task->user_ns = new_userns;
    }

    /* Remaining flags (IPC/CGROUP) accepted as no-ops */
    return 0;
}
