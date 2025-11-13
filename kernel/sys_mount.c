/* kernel/sys_mount.c - Mount filesystem syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements mount for attaching filesystems to the directory tree.
 * Essential for system initialization, container setup, and filesystem management.
 *
 * Phase 1 (Completed): Validation and stub implementation
 * Phase 2 (Current): Enhanced validation, filesystem type categorization, user-space parameter handling
 * Phase 3: Full mount namespace support
 * Phase 4: Advanced features (bind mounts, move mounts, remount)
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <stdint.h>
#include <stddef.h>

extern void fut_printf(const char *fmt, ...);
extern int fut_copy_from_user(void *to, const void *from, size_t size);

/* Mount flags */
#define MS_RDONLY        1      /* Mount read-only */
#define MS_NOSUID        2      /* Ignore suid and sgid bits */
#define MS_NODEV         4      /* Disallow access to device special files */
#define MS_NOEXEC        8      /* Disallow program execution */
#define MS_SYNCHRONOUS   16     /* Writes are synced at once */
#define MS_REMOUNT       32     /* Alter flags of a mounted FS */
#define MS_MANDLOCK      64     /* Allow mandatory locks on an FS */
#define MS_DIRSYNC       128    /* Directory modifications are synchronous */
#define MS_NOATIME       1024   /* Do not update access times */
#define MS_NODIRATIME    2048   /* Do not update directory access times */
#define MS_BIND          4096   /* Bind directory at different place */
#define MS_MOVE          8192   /* Atomically move mounted tree */
#define MS_REC           16384  /* Recursive (for bind and move) */
#define MS_RELATIME      2097152 /* Update atime relative to mtime/ctime */

/**
 * mount() - Mount filesystem
 *
 * Attaches the filesystem specified by source to the directory specified
 * by target. This is one of the most fundamental operations for managing
 * the filesystem hierarchy in Unix-like systems.
 *
 * @param source         Device or filesystem to mount (e.g., "/dev/sda1", "tmpfs")
 * @param target         Mount point directory (must exist)
 * @param filesystemtype Filesystem type (e.g., "ext4", "tmpfs", "proc", "sysfs")
 * @param mountflags     Mount options (MS_RDONLY, MS_NOSUID, MS_NODEV, etc.)
 * @param data           Filesystem-specific options (comma-separated string)
 *
 * Returns:
 *   - 0 on success
 *   - -EACCES if permission denied (requires CAP_SYS_ADMIN)
 *   - -EFAULT if source, target, or filesystemtype is invalid pointer
 *   - -EINVAL if invalid flags or filesystem type
 *   - -ENOENT if target directory doesn't exist
 *   - -ENOTDIR if target is not a directory
 *   - -ENODEV if filesystem type not supported
 *   - -EBUSY if target already mounted or in use
 *   - -ENOMEM if insufficient kernel memory
 *
 * Usage:
 *   // Mount tmpfs (RAM-based filesystem)
 *   mount("tmpfs", "/tmp", "tmpfs", 0, NULL);
 *
 *   // Mount device read-only
 *   mount("/dev/sda1", "/mnt", "ext4", MS_RDONLY, NULL);
 *
 *   // Mount with options
 *   mount("/dev/sdb1", "/data", "ext4", MS_NOATIME | MS_NODIRATIME, "errors=remount-ro");
 *
 *   // Bind mount (mount directory at another location)
 *   mount("/source", "/dest", NULL, MS_BIND, NULL);
 *
 *   // Remount with different flags
 *   mount(NULL, "/mnt", NULL, MS_REMOUNT | MS_RDONLY, NULL);
 *
 * Common mount flags:
 * - MS_RDONLY: Mount read-only (no writes allowed)
 * - MS_NOSUID: Ignore set-user-ID and set-group-ID bits
 * - MS_NODEV: Disallow device nodes (security)
 * - MS_NOEXEC: Disallow program execution
 * - MS_NOATIME: Don't update file access times (performance)
 * - MS_BIND: Create bind mount (mirror directory tree)
 * - MS_MOVE: Atomically move mounted filesystem
 * - MS_REMOUNT: Change flags on existing mount
 *
 * Filesystem types:
 * - "ext4": Linux extended filesystem (most common)
 * - "tmpfs": RAM-based temporary filesystem
 * - "proc": Process information pseudo-filesystem
 * - "sysfs": Kernel objects pseudo-filesystem
 * - "devtmpfs": Device nodes filesystem
 * - "overlay": Overlay/union filesystem (containers)
 * - "ramfs": Simple RAM filesystem
 * - "nfs": Network File System
 *
 * Common use cases:
 * - System initialization: Mount root filesystem and essential filesystems
 *   ```c
 *   mount("proc", "/proc", "proc", 0, NULL);
 *   mount("sysfs", "/sys", "sysfs", 0, NULL);
 *   mount("devtmpfs", "/dev", "devtmpfs", 0, NULL);
 *   mount("tmpfs", "/tmp", "tmpfs", 0, NULL);
 *   mount("tmpfs", "/run", "tmpfs", MS_NOSUID | MS_NODEV, "mode=0755");
 *   ```
 *
 * - Container initialization: Set up isolated filesystem view
 *   ```c
 *   mount("tmpfs", "/container/tmp", "tmpfs", 0, NULL);
 *   mount("proc", "/container/proc", "proc", 0, NULL);
 *   mount("/sys", "/container/sys", NULL, MS_BIND | MS_RDONLY, NULL);
 *   ```
 *
 * - Bind mounts: Mirror directories without copying
 *   ```c
 *   mount("/home/user", "/mnt/user", NULL, MS_BIND, NULL);
 *   ```
 *
 * - Remounting: Change mount options without unmounting
 *   ```c
 *   // Make read-only for maintenance
 *   mount(NULL, "/mnt/data", NULL, MS_REMOUNT | MS_RDONLY, NULL);
 *   ```
 *
 * - Removable media: Mount USB drives, SD cards
 *   ```c
 *   mount("/dev/sdc1", "/media/usb", "vfat", MS_NOATIME, "uid=1000,gid=1000");
 *   ```
 *
 * Security considerations:
 * - Requires CAP_SYS_ADMIN capability (privileged operation)
 * - MS_NOSUID prevents privilege escalation via set-uid binaries
 * - MS_NODEV prevents device node attacks
 * - MS_NOEXEC prevents execution on untrusted filesystems
 * - Bind mounts can expose sensitive directories (use with care)
 *
 * Mount namespaces:
 * - Each mount namespace has its own view of the filesystem hierarchy
 * - Container runtimes use mount namespaces for isolation
 * - unshare(CLONE_NEWNS) creates new mount namespace
 * - Mounts in one namespace don't affect others
 *
 * Special source values:
 * - "tmpfs", "proc", "sysfs": Pseudo-filesystems (no device)
 * - "/dev/sda1": Block device
 * - "192.168.1.1:/export": NFS server
 * - NULL: For MS_REMOUNT or MS_MOVE operations
 *
 * Data parameter examples:
 * - ext4: "errors=remount-ro,noatime"
 * - tmpfs: "size=512m,mode=1777"
 * - nfs: "vers=4,soft,timeo=100"
 * - overlay: "lowerdir=/lower,upperdir=/upper,workdir=/work"
 *
 * Relationship to other syscalls:
 * - umount2(): Unmounts mounted filesystems
 * - pivot_root(): Changes root mount (for containers)
 * - chroot(): Changes apparent root (less isolated than pivot_root)
 * - open(): Requires mounted filesystem to access files
 *
 * Error conditions:
 * - EACCES: Permission denied (need CAP_SYS_ADMIN)
 * - EBUSY: Target in use or already mounted
 * - EINVAL: Invalid flags or unsupported operation
 * - ENOENT: Mount point doesn't exist
 * - ENODEV: Filesystem type not supported
 * - ENOMEM: Out of kernel memory
 * - ENOTDIR: Target is not a directory
 *
 * Phase 1: Validate parameters and return -ENOSYS
 * Phase 2: Implement basic mount for RamFS and tmpfs
 * Phase 3: Add mount namespace support and bind mounts
 */
long sys_mount(const char *source, const char *target, const char *filesystemtype,
               unsigned long mountflags, const void *data) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    /* Suppress unused parameter warning - used in Phase 3 */
    (void)data;

    /* Phase 2: Validate target pointer (required) */
    if (!target) {
        fut_printf("[MOUNT] mount(source=%p, target=NULL, fstype=%p, flags=0x%lx, pid=%d) -> EFAULT\n",
                   source, filesystemtype, mountflags, task->pid);
        return -EFAULT;
    }

    /* Phase 2: Copy target from userspace to validate it */
    char target_buf[256];
    if (fut_copy_from_user(target_buf, target, sizeof(target_buf) - 1) != 0) {
        fut_printf("[MOUNT] mount(source=%p, target=?, fstype=%p, flags=0x%lx, pid=%d) -> EFAULT "
                   "(target copy_from_user failed)\n",
                   source, filesystemtype, mountflags, task->pid);
        return -EFAULT;
    }
    target_buf[sizeof(target_buf) - 1] = '\0';

    /* Phase 2: Validate target is not empty */
    if (target_buf[0] == '\0') {
        fut_printf("[MOUNT] mount(source=%p, target=\"\" [empty], fstype=%p, flags=0x%lx, pid=%d) -> EINVAL\n",
                   source, filesystemtype, mountflags, task->pid);
        return -EINVAL;
    }

    /* Phase 2: Copy filesystemtype from userspace if provided */
    char fstype_buf[64] = {0};
    if (filesystemtype) {
        if (fut_copy_from_user(fstype_buf, filesystemtype, sizeof(fstype_buf) - 1) != 0) {
            fut_printf("[MOUNT] mount(source=%p, target='%s', fstype=?, flags=0x%lx, pid=%d) -> EFAULT "
                       "(fstype copy_from_user failed)\n",
                       source, target_buf, mountflags, task->pid);
            return -EFAULT;
        }
        fstype_buf[sizeof(fstype_buf) - 1] = '\0';
    }

    /* Phase 2: Validate filesystemtype (required except for remount/bind/move) */
    if (fstype_buf[0] == '\0' && !(mountflags & (MS_REMOUNT | MS_BIND | MS_MOVE))) {
        fut_printf("[MOUNT] mount(source=%p, target='%s', fstype=NULL, flags=0x%lx, pid=%d) -> EINVAL "
                   "(filesystem type required)\n",
                   source, target_buf, mountflags, task->pid);
        return -EINVAL;
    }

    /* Categorize mount operation */
    const char *op_type;
    if (mountflags & MS_REMOUNT) {
        op_type = "remount";
    } else if (mountflags & MS_BIND) {
        op_type = mountflags & MS_REC ? "recursive bind mount" : "bind mount";
    } else if (mountflags & MS_MOVE) {
        op_type = "move mount";
    } else {
        op_type = "new mount";
    }

    /* Extract common flags for logging */
    char flags_buf[256];
    char *p = flags_buf;
    int flag_count = 0;

    if (mountflags & MS_RDONLY) {
        const char *s = flag_count++ > 0 ? "|MS_RDONLY" : "MS_RDONLY";
        while (*s) *p++ = *s++;
    }
    if (mountflags & MS_NOSUID) {
        const char *s = flag_count++ > 0 ? "|MS_NOSUID" : "MS_NOSUID";
        while (*s) *p++ = *s++;
    }
    if (mountflags & MS_NODEV) {
        const char *s = flag_count++ > 0 ? "|MS_NODEV" : "MS_NODEV";
        while (*s) *p++ = *s++;
    }
    if (mountflags & MS_NOEXEC) {
        const char *s = flag_count++ > 0 ? "|MS_NOEXEC" : "MS_NOEXEC";
        while (*s) *p++ = *s++;
    }
    if (mountflags & MS_NOATIME) {
        const char *s = flag_count++ > 0 ? "|MS_NOATIME" : "MS_NOATIME";
        while (*s) *p++ = *s++;
    }
    if (mountflags & MS_BIND) {
        const char *s = flag_count++ > 0 ? "|MS_BIND" : "MS_BIND";
        while (*s) *p++ = *s++;
    }
    if (mountflags & MS_REMOUNT) {
        const char *s = flag_count++ > 0 ? "|MS_REMOUNT" : "MS_REMOUNT";
        while (*s) *p++ = *s++;
    }
    if (flag_count == 0) {
        const char *s = "0";
        while (*s) *p++ = *s++;
    }
    *p = '\0';

    /* Phase 2: Categorize filesystem type */
    const char *fs_category = "unknown";
    if (fstype_buf[0] != '\0') {
        if (fstype_buf[0] == 't' && fstype_buf[1] == 'm') fs_category = "tmpfs (RAM-based)";
        else if (fstype_buf[0] == 'p' && fstype_buf[1] == 'r') fs_category = "procfs (process info)";
        else if (fstype_buf[0] == 's' && fstype_buf[1] == 'y') fs_category = "sysfs (kernel objects)";
        else if (fstype_buf[0] == 'd' && fstype_buf[1] == 'e') fs_category = "devtmpfs (devices)";
        else if (fstype_buf[0] == 'e' && fstype_buf[1] == 'x') fs_category = "ext4 (local filesystem)";
        else fs_category = "other filesystem type";
    }

    /* Phase 2: Enhanced logging with categorized parameters */
    if (fstype_buf[0] != '\0') {
        fut_printf("[MOUNT] mount(source=%p, target='%s', fstype='%s' [%s], type=%s, flags=%s, pid=%d) -> ENOSYS "
                   "(Phase 3: VFS mount integration not yet implemented)\n",
                   source, target_buf, fstype_buf, fs_category, op_type, flags_buf, task->pid);
    } else {
        fut_printf("[MOUNT] mount(source=%p, target='%s', fstype=NULL, type=%s, flags=%s, pid=%d) -> ENOSYS "
                   "(Phase 3: VFS mount integration not yet implemented)\n",
                   source, target_buf, op_type, flags_buf, task->pid);
    }

    return -ENOSYS;
}
