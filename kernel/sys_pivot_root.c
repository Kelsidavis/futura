/* kernel/sys_pivot_root.c - Change root filesystem syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements pivot_root for changing the root mount in a mount namespace.
 * Essential for container initialization and initramfs switching.
 *
 * Phase 1 (Current): Validation and stub implementation
 * Phase 2: Basic pivot_root with mount point validation
 * Phase 3: Full mount namespace integration
 * Phase 4: Container runtime optimization
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <stddef.h>

extern void fut_printf(const char *fmt, ...);

/**
 * pivot_root() - Change root filesystem
 *
 * Changes the root mount in the current mount namespace. The new_root
 * becomes the new root filesystem, and the old root is moved to put_old.
 * This is more powerful than chroot() as it actually changes the root mount
 * rather than just changing the apparent root directory.
 *
 * @param new_root  Path to new root filesystem (must be a mount point)
 * @param put_old   Path to directory where old root will be moved
 *
 * Returns:
 *   - 0 on success
 *   - -EACCES if permission denied (requires CAP_SYS_ADMIN)
 *   - -EFAULT if new_root or put_old is invalid pointer
 *   - -EINVAL if new_root or put_old is not valid (see conditions below)
 *   - -ENOTDIR if new_root or put_old is not a directory
 *   - -EBUSY if new_root or put_old is on the current root filesystem
 *   - -ENOMEM if insufficient kernel memory
 *
 * Usage:
 *   // Container initialization
 *   mount("/container/rootfs", "/container/rootfs", NULL, MS_BIND, NULL);
 *   chdir("/container/rootfs");
 *   mkdir("old_root", 0755);
 *   pivot_root(".", "old_root");
 *   chdir("/");
 *   umount2("old_root", MNT_DETACH);
 *   rmdir("old_root");
 *
 *   // Initramfs to real root switch
 *   mount("/dev/sda1", "/newroot", "ext4", 0, NULL);
 *   chdir("/newroot");
 *   mkdir("/newroot/oldroot", 0755);
 *   pivot_root(".", "oldroot");
 *   chdir("/");
 *   umount2("/oldroot", MNT_DETACH);
 *   rmdir("/oldroot");
 *
 * Requirements for pivot_root():
 * 1. new_root and put_old must be directories
 * 2. new_root and put_old must not be on the current root filesystem
 * 3. new_root must be a mount point
 * 4. put_old must be at or underneath new_root
 * 5. No other filesystem may be mounted on put_old
 * 6. Current root must be a mount point (true after boot)
 * 7. new_root must be different from current root
 *
 * Typical usage pattern:
 * ```c
 * // Step 1: Set up new root as a mount point
 * mount("/container/rootfs", "/container/rootfs", NULL, MS_BIND, NULL);
 *
 * // Step 2: Change to new root directory
 * chdir("/container/rootfs");
 *
 * // Step 3: Create directory for old root
 * mkdir("old_root", 0755);
 *
 * // Step 4: Pivot root
 * pivot_root(".", "old_root");
 *
 * // Step 5: Change to new root
 * chdir("/");
 *
 * // Step 6: Unmount old root
 * umount2("/old_root", MNT_DETACH);
 * rmdir("/old_root");
 * ```
 *
 * Container initialization:
 * - Docker/LXC/Podman use pivot_root to set up container root
 * - Allows complete filesystem isolation
 * - More secure than chroot (harder to escape)
 * - Works with mount namespaces for per-container views
 *
 * Initramfs switching:
 * - Boot loader loads initramfs as initial root
 * - Initramfs loads drivers, finds real root device
 * - pivot_root switches to real root filesystem
 * - Old initramfs unmounted and freed
 *
 * Differences from chroot():
 * - chroot(): Changes apparent root directory (process-level)
 * - pivot_root(): Changes root mount (namespace-level)
 * - chroot() can be escaped by privileged processes
 * - pivot_root() is much harder to escape (proper isolation)
 * - chroot() doesn't require mount namespace
 * - pivot_root() requires mount namespace support
 *
 * Security benefits over chroot():
 * - Actually changes the root mount, not just the view
 * - Old root can be completely unmounted
 * - No way to access old root after unmounting
 * - Works with mount namespaces for true isolation
 * - Used by all modern container runtimes
 *
 * Common use cases:
 * - Docker container startup:
 *   ```c
 *   mount("overlay", "/container/root", "overlay", 0, options);
 *   pivot_root("/container/root", "/container/root/oldroot");
 *   umount2("/oldroot", MNT_DETACH);
 *   ```
 *
 * - Initramfs to root switch:
 *   ```c
 *   mount("/dev/root", "/newroot", "ext4", MS_RDONLY, NULL);
 *   pivot_root("/newroot", "/newroot/initramfs");
 *   exec("/sbin/init");  // New init takes over
 *   ```
 *
 * - System recovery:
 *   ```c
 *   mount("/dev/sda1", "/mnt", "ext4", 0, NULL);
 *   mount("--bind", "/mnt", "/mnt", MS_BIND, NULL);
 *   pivot_root("/mnt", "/mnt/oldroot");
 *   // Now in rescued system
 *   ```
 *
 * Mount namespace integration:
 * - Each mount namespace has its own root
 * - pivot_root only affects current namespace
 * - Container gets its own root via pivot_root
 * - Host root unchanged by container's pivot_root
 *
 * Error conditions:
 * - EACCES: Permission denied (need CAP_SYS_ADMIN)
 * - EINVAL: new_root not a mount point, or constraints violated
 * - EBUSY: put_old has mounts on it
 * - ENOTDIR: new_root or put_old not a directory
 * - ENOMEM: Out of kernel memory
 *
 * Comparison table:
 * | Feature         | chroot()    | pivot_root()      |
 * |-----------------|-------------|-------------------|
 * | Privilege level | Root        | CAP_SYS_ADMIN     |
 * | Escapable       | Yes         | No (with namespaces) |
 * | Changes         | Process view| Root mount        |
 * | Old root access | Possible    | Can be removed    |
 * | Container safe  | No          | Yes               |
 * | Namespace aware | No          | Yes               |
 *
 * Best practices:
 * - Always use with mount namespaces for security
 * - Unmount old root immediately after pivot
 * - Verify new_root is properly set up before pivot
 * - Use in combination with other namespace types (PID, network, etc.)
 * - Test container startup sequences thoroughly
 *
 * Phase 1: Validate parameters and return -ENOSYS
 * Phase 2: Implement basic pivot_root with validation
 * Phase 3: Full mount namespace integration
 */
long sys_pivot_root(const char *new_root, const char *put_old) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    /* Validate new_root pointer */
    if (!new_root) {
        fut_printf("[PIVOT_ROOT] pivot_root(new_root=NULL, put_old=%p, pid=%d) -> EFAULT\n",
                   put_old, task->pid);
        return -EFAULT;
    }

    /* Validate put_old pointer */
    if (!put_old) {
        fut_printf("[PIVOT_ROOT] pivot_root(new_root=%p, put_old=NULL, pid=%d) -> EFAULT\n",
                   new_root, task->pid);
        return -EFAULT;
    }

    /* Phase 1: Accept parameters and return -ENOSYS */
    fut_printf("[PIVOT_ROOT] pivot_root(new_root=%p, put_old=%p, pid=%d) -> ENOSYS "
               "(Phase 1 stub - no actual pivot yet)\n",
               new_root, put_old, task->pid);

    return -ENOSYS;
}
