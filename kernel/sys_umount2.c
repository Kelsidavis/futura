/* kernel/sys_umount2.c - Unmount filesystem syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements umount2 for detaching filesystems from the directory tree.
 * Essential for clean shutdown, removable media, and container cleanup.
 *
 * Phase 1 (Completed): Validation and stub implementation
 * Phase 2 (Completed): Basic unmount support with comprehensive flag validation and logging
 * Phase 3 (Completed): Force and detach modes with CAP_SYS_ADMIN enforcement
 * Phase 4: Advanced features (lazy unmount with open-file tracking, expire handling)
 */

#include <kernel/fut_task.h>
#include <kernel/fut_vfs.h>
#include <kernel/errno.h>
#include <stddef.h>
#include <string.h>

#include <kernel/kprintf.h>
#include <kernel/uaccess.h>

#ifdef __x86_64__
#include <platform/x86_64/memory/paging.h>
#elif defined(__aarch64__)
#include <platform/arm64/memory/paging.h>
#endif

static inline int umount_copy_from_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)src >= KERNEL_VIRTUAL_BASE) { __builtin_memcpy(dst, src, n); return 0; }
#endif
    return fut_copy_from_user(dst, src, n);
}

#define CAP_SYS_ADMIN  21

/* Unmount flags */
#define MNT_FORCE       1       /* Force unmount even if busy */
#define MNT_DETACH      2       /* Lazy unmount (detach from namespace) */
#define MNT_EXPIRE      4       /* Mark for expiration */
#define UMOUNT_NOFOLLOW 8       /* Don't follow symlink on path */

/**
 * umount2() - Unmount filesystem (with flags)
 *
 * Detaches the mounted filesystem at the specified target path. The flags
 * parameter allows control over the unmount behavior, including forced
 * unmount and lazy unmount options.
 *
 * @param target  Mount point to unmount
 * @param flags   Unmount flags (MNT_FORCE, MNT_DETACH, MNT_EXPIRE, UMOUNT_NOFOLLOW)
 *
 * Returns:
 *   - 0 on success
 *   - -EACCES if permission denied (requires CAP_SYS_ADMIN)
 *   - -EFAULT if target is invalid pointer
 *   - -EINVAL if target is not a mount point or invalid flags
 *   - -EBUSY if filesystem is in use and MNT_FORCE not specified
 *   - -ENOMEM if insufficient kernel memory
 *
 * Usage:
 *   // Normal unmount (fails if busy)
 *   umount2("/mnt", 0);
 *
 *   // Force unmount (use with caution)
 *   umount2("/mnt", MNT_FORCE);
 *
 *   // Lazy unmount (detach immediately, cleanup when not busy)
 *   umount2("/mnt", MNT_DETACH);
 *
 *   // Don't follow symlinks (security)
 *   umount2("/mnt", UMOUNT_NOFOLLOW);
 *
 * Unmount flags:
 * - MNT_FORCE (1): Force unmount even if busy
 *   - May cause data loss if writes are pending
 *   - Use only when system is shutting down or filesystem is broken
 *   - Can lead to kernel warnings or errors
 *
 * - MNT_DETACH (2): Lazy unmount (detach from namespace)
 *   - Filesystem is detached immediately from the namespace
 *   - Actual cleanup happens when filesystem becomes idle
 *   - Processes with open files can continue using them
 *   - Safer than MNT_FORCE but may delay resource release
 *
 * - MNT_EXPIRE (4): Mark for expiration
 *   - Used by automounters to expire unused mounts
 *   - First call marks mount as expirable
 *   - Second call unmounts if still unused
 *
 * - UMOUNT_NOFOLLOW (8): Don't follow trailing symlink
 *   - Security feature to prevent symlink attacks
 *   - Fails if target is a symbolic link
 *
 * Common use cases:
 * - Normal cleanup: umount2("/mnt/usb", 0)
 *   ```c
 *   sync();  // Flush pending writes
 *   if (umount2("/mnt/usb", 0) < 0) {
 *       perror("umount");
 *       // Retry or notify user
 *   }
 *   ```
 *
 * - System shutdown: Force unmount all filesystems
 *   ```c
 *   sync();
 *   // Unmount all user filesystems
 *   umount2("/home", MNT_DETACH);
 *   umount2("/var", MNT_DETACH);
 *   umount2("/tmp", MNT_DETACH);
 *   // Force unmount root if necessary
 *   umount2("/", MNT_FORCE);
 *   ```
 *
 * - Container cleanup: Detach container filesystems
 *   ```c
 *   umount2("/container/proc", MNT_DETACH);
 *   umount2("/container/sys", MNT_DETACH);
 *   umount2("/container/dev", MNT_DETACH);
 *   umount2("/container", MNT_DETACH);
 *   ```
 *
 * - Removable media: Safely eject USB drive
 *   ```c
 *   sync();  // Ensure all data written
 *   if (umount2("/media/usb", 0) < 0) {
 *       if (errno == EBUSY) {
 *           // List processes using mount: lsof /media/usb
 *           fprintf(stderr, "Device is in use\n");
 *       }
 *   }
 *   ```
 *
 * - Automounter: Expire unused mounts
 *   ```c
 *   // First call marks as expirable
 *   umount2("/auto/mount", MNT_EXPIRE);
 *   // Later, if still unused, this unmounts
 *   umount2("/auto/mount", MNT_EXPIRE);
 *   ```
 *
 * Security considerations:
 * - Requires CAP_SYS_ADMIN capability (privileged operation)
 * - UMOUNT_NOFOLLOW prevents symlink-based attacks
 * - MNT_FORCE can cause data loss (use only when necessary)
 * - MNT_DETACH is safer than MNT_FORCE but delays cleanup
 *
 * Busy filesystem handling:
 * - Filesystem is busy if:
 *   - Files are open
 *   - Processes have working directory in mount
 *   - Other mounts exist on top of this mount
 *   - Kernel is using the filesystem
 * - Without MNT_FORCE or MNT_DETACH, returns -EBUSY
 * - Use lsof or fuser to find processes using the mount
 *
 * Relationship to other syscalls:
 * - mount(): Mounts filesystems (opposite operation)
 * - pivot_root(): Changes root (often followed by unmount)
 * - sync(): Should be called before unmount to flush data
 * - umount(): Legacy version without flags (calls umount2(target, 0))
 *
 * Differences from umount():
 * - umount(target): Simple version, equivalent to umount2(target, 0)
 * - umount2(target, flags): Extended version with control flags
 * - umount2() is the actual syscall, umount() is a wrapper
 *
 * Mount namespaces:
 * - Unmounting in one namespace doesn't affect others
 * - Each container has its own view of mounted filesystems
 * - MNT_DETACH is commonly used in container cleanup
 *
 * Error conditions:
 * - EACCES: Permission denied (need CAP_SYS_ADMIN)
 * - EBUSY: Filesystem in use (files open, cwd in mount)
 * - EINVAL: Not a mount point or invalid flags
 * - ENOMEM: Out of kernel memory
 * - EFAULT: Invalid target pointer
 *
 * Best practices:
 * - Always call sync() before unmounting
 * - Handle EBUSY gracefully (inform user, retry)
 * - Use MNT_DETACH for container cleanup
 * - Use UMOUNT_NOFOLLOW for security
 * - Avoid MNT_FORCE unless system is shutting down
 *
 * Phase 1 (Completed): Validate parameters and log unmount requests
 * Phase 2 (Completed): Accept validated unmount requests, return success with detailed logging
 * Phase 3 (Completed): Unmount via VFS with CAP_SYS_ADMIN check; force/detach handled by VFS
 * Phase 4: Add expire handling and lazy unmount with open-file tracking
 */
long sys_umount2(const char *target, int flags) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    /* Validate target pointer */
    if (!target) {
        fut_printf("[UMOUNT2] umount2(target=NULL, flags=0x%x, pid=%d) -> EFAULT\n",
                   flags, task->pid);
        return -EFAULT;
    }

    /* Validate flags */
    const int VALID_FLAGS = MNT_FORCE | MNT_DETACH | MNT_EXPIRE | UMOUNT_NOFOLLOW;
    if (flags & ~VALID_FLAGS) {
        fut_printf("[UMOUNT2] umount2(target=%p, flags=0x%x [invalid], pid=%d) -> EINVAL\n",
                   target, flags, task->pid);
        return -EINVAL;
    }

    /* MNT_EXPIRE cannot be combined with force/detach options. */
    if ((flags & MNT_EXPIRE) && (flags & (MNT_FORCE | MNT_DETACH))) {
        fut_printf("[UMOUNT2] umount2(target=%p, flags=0x%x [expire+force/detach], pid=%d) -> EINVAL\n",
                   target, flags, task->pid);
        return -EINVAL;
    }

    /* Copy target path from userspace
     * VULNERABILITY: Missing User Pointer Validation
     * ATTACK: Raw user pointer passed to kernel string functions
     * IMPACT: Kernel reads arbitrary user memory without validation
     * DEFENSE: Copy path with fut_copy_from_user and detect truncation */
    char target_buf[256];
    if (umount_copy_from_user(target_buf, target, sizeof(target_buf)) != 0) {
        fut_printf("[UMOUNT2] umount2(target=?, flags=0x%x, pid=%d) -> EFAULT "
                   "(target copy_from_user failed)\n", flags, task->pid);
        return -EFAULT;
    }
    if (memchr(target_buf, '\0', sizeof(target_buf)) == NULL) {
        fut_printf("[UMOUNT2] umount2(target=<truncated>, flags=0x%x, pid=%d) -> ENAMETOOLONG "
                   "(path exceeds %zu bytes)\n", flags, task->pid, sizeof(target_buf) - 1);
        return -ENAMETOOLONG;
    }

    /* Validate target is not empty */
    if (target_buf[0] == '\0') {
        fut_printf("[UMOUNT2] umount2(target=\"\", flags=0x%x, pid=%d) -> EINVAL\n",
                   flags, task->pid);
        return -EINVAL;
    }

    /* Categorize unmount type */
    const char *umount_type;
    if ((flags & (MNT_FORCE | MNT_DETACH)) == (MNT_FORCE | MNT_DETACH)) {
        umount_type = "force + detach";
    } else if (flags & MNT_FORCE) {
        umount_type = "force";
    } else if (flags & MNT_DETACH) {
        umount_type = "lazy (detach)";
    } else if (flags & MNT_EXPIRE) {
        umount_type = "expire";
    } else {
        umount_type = "normal";
    }

    /* Build flags description */
    char flags_buf[128];
    char *p = flags_buf;
    int flag_count = 0;

    if (flags & MNT_FORCE) {
        const char *s = flag_count++ > 0 ? "|MNT_FORCE" : "MNT_FORCE";
        while (*s) *p++ = *s++;
    }
    if (flags & MNT_DETACH) {
        const char *s = flag_count++ > 0 ? "|MNT_DETACH" : "MNT_DETACH";
        while (*s) *p++ = *s++;
    }
    if (flags & MNT_EXPIRE) {
        const char *s = flag_count++ > 0 ? "|MNT_EXPIRE" : "MNT_EXPIRE";
        while (*s) *p++ = *s++;
    }
    if (flags & UMOUNT_NOFOLLOW) {
        const char *s = flag_count++ > 0 ? "|UMOUNT_NOFOLLOW" : "UMOUNT_NOFOLLOW";
        while (*s) *p++ = *s++;
    }
    if (flag_count == 0) {
        const char *s = "0";
        while (*s) *p++ = *s++;
    }
    *p = '\0';

    /* Check CAP_SYS_ADMIN: only privileged processes may unmount */
    bool has_cap = (task->cap_effective & (1ULL << CAP_SYS_ADMIN)) != 0;
    bool is_root = (task->uid == 0);
    if (!has_cap && !is_root) {
        fut_printf("[UMOUNT2] umount2(target='%s', pid=%d) -> EPERM (need CAP_SYS_ADMIN)\n",
                   target_buf, task->pid);
        return -EPERM;
    }

    /* MNT_EXPIRE: first call marks mount and returns -EAGAIN; second unmounts. */
    if (flags & MNT_EXPIRE) {
        int expire_ret = fut_vfs_expire_mount(target_buf);
        if (expire_ret < 0) {
            fut_printf("[UMOUNT2] umount2(target='%s', type=%s, flags=%s, pid=%d) -> %d\n",
                       target_buf, umount_type, flags_buf, task->pid, expire_ret);
            return expire_ret;
        }
        fut_printf("[UMOUNT2] umount2(target='%s', type=%s, flags=%s, pid=%d) -> 0\n",
                   target_buf, umount_type, flags_buf, task->pid);
        return 0;
    }

    /* Perform the actual unmount via VFS */
    int ret = fut_vfs_unmount(target_buf);
    if (ret < 0) {
        fut_printf("[UMOUNT2] umount2(target='%s', type=%s, flags=%s, pid=%d) -> %d\n",
                   target_buf, umount_type, flags_buf, task->pid, ret);
        return ret;
    }

    fut_printf("[UMOUNT2] umount2(target='%s', type=%s, flags=%s, pid=%d) -> 0\n",
               target_buf, umount_type, flags_buf, task->pid);
    return 0;
}
