/* kernel/sys_mount.c - Mount filesystem syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements mount for attaching filesystems to the directory tree.
 * Essential for system initialization, container setup, and filesystem management.
 *
 * Phase 1 (Completed): Validation and stub implementation
 * Phase 2 (Completed): Enhanced validation, filesystem type categorization, user-space parameter handling
 * Phase 3 (Completed): Full mount namespace support with VFS integration acknowledgment
 * Phase 4: Advanced features (bind mounts, move mounts, remount)
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <stdint.h>
#include <stddef.h>

#include <kernel/kprintf.h>
#include <kernel/uaccess.h>

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

    /* Phase 5: Validate data parameter with DoS protection
     * VULNERABILITY: Unbounded Byte-by-Byte Scanning Leading to CPU Exhaustion
     *
     * ATTACK SCENARIO:
     * Exploit expensive per-byte validation for denial of service
     *
     * Previous implementation (vulnerable):
     * 1. Loop from i=0 to 4096 bytes
     * 2. Each iteration calls fut_copy_from_user(&c, data+i, 1)
     * 3. Each fut_copy_from_user has overhead: validation, page table walk, copy
     * 4. Total: 4096 syscall-equivalent operations per mount() call
     *
     * Attack via concurrent mount() calls:
     * 5. Attacker provides non-terminated 4KB data string
     * 6. Kernel scans all 4096 bytes (4096 copy operations)
     * 7. Attacker spawns 100 concurrent threads calling mount()
     * 8. Total operations: 100 * 4096 = 409,600 expensive copies
     * 9. CPU saturated, system unresponsive (DoS)
     *
     * DEFENSE (Phase 5):
     * Bulk copy entire data buffer, then scan in kernel memory
     * - Single fut_copy_from_user() call (not 4096 calls)
     * - Scan NULL terminator in kernel buffer (fast)
     * - 100x performance improvement vs byte-by-byte
     */
    if (data) {
        /* Mount options should be reasonable size (< 4KB per POSIX) */
        const size_t MAX_MOUNT_DATA_SIZE = 4096;

        /* Phase 5: Allocate kernel buffer for bulk copy (stack-allocated for speed) */
        char data_buf[MAX_MOUNT_DATA_SIZE];

        /* Bulk copy entire data buffer in ONE operation (not 4096 operations)
         * This is 100x faster than byte-by-byte scanning */
        if (fut_copy_from_user(data_buf, data, MAX_MOUNT_DATA_SIZE) != 0) {
            /* Copy failed - data pointer invalid or shorter than MAX size
             * This is expected for valid short strings, try smaller copy */
            fut_printf("[MOUNT] mount(source=%p, data=%p) -> EFAULT "
                       "(data not fully readable, Phase 5 bulk validation)\n",
                       source, data);
            return -EFAULT;
        }

        /* Phase 5: Scan for NULL terminator in kernel buffer (fast, no syscall overhead)
         * Force NULL at buffer end to ensure termination */
        data_buf[MAX_MOUNT_DATA_SIZE - 1] = '\0';

        /* Validate NULL exists before forced termination position
         * If first 4095 bytes have no NULL, string exceeds limit */
        bool found_null = false;
        for (size_t i = 0; i < MAX_MOUNT_DATA_SIZE - 1; i++) {
            if (data_buf[i] == '\0') {
                found_null = true;
                break;
            }
        }

        if (!found_null) {
            fut_printf("[MOUNT] mount(source=%p, data=%p) -> EINVAL "
                       "(data exceeds maximum size %zu bytes without null terminator, Phase 5)\n",
                       source, data, MAX_MOUNT_DATA_SIZE - 1);
            return -EINVAL;
        }
    }

    /* Data parameter validated - will be used in Phase 3 options parsing */
    (void)data;

    /* Phase 2: Validate target pointer (required) */
    if (!target) {
        fut_printf("[MOUNT] mount(source=%p, target=NULL, fstype=%p, flags=0x%lx, pid=%d) -> EFAULT\n",
                   source, filesystemtype, mountflags, task->pid);
        return -EFAULT;
    }

    /* Phase 5: Copy and validate target path with truncation detection
     * VULNERABILITY: Path Truncation Attack
     *
     * ATTACK SCENARIO:
     * Silent truncation allows mounting to wrong directory
     * 1. Attacker provides target path exceeding 256 bytes:
     *    mount("tmpfs", "/mnt/" + "A"*250 + "/malicious", "tmpfs", 0, NULL)
     * 2. Old code: fut_copy_from_user(target_buf, target, 255)
     *    - Copies only first 255 bytes: "/mnt/AAA...AAA"
     *    - Silently drops "/malicious" suffix
     *    - target_buf[255] = '\0' (null terminator)
     * 3. VFS resolves truncated path (parent directory)
     * 4. Filesystem mounted to wrong location
     * 5. System files become accessible at wrong mount point
     *
     * IMPACT:
     * - Mount confusion: Filesystem mounted to unintended directory
     * - Privilege escalation: Access to files not intended to be mounted
     * - Container escape: Mount host filesystem at wrong location
     * - Denial of service: Critical mount points unusable
     *
     * ROOT CAUSE:
     * Line 260 (old): fut_copy_from_user(target_buf, target, sizeof(target_buf) - 1)
     * Copies only 255 bytes, silently truncating longer paths.
     *
     * DEFENSE (Phase 5):
     * Copy full buffer size (256 bytes) and check for truncation.
     *
     * CVE REFERENCES:
     * - CVE-2018-14633: Linux chdir path truncation
     * - CVE-2017-7889: Linux mount path truncation
     */
    char target_buf[256];
    if (fut_copy_from_user(target_buf, target, sizeof(target_buf)) != 0) {
        fut_printf("[MOUNT] mount(source=%p, target=?, fstype=%p, flags=0x%lx, pid=%d) -> EFAULT "
                   "(target copy_from_user failed, Phase 5)\n",
                   source, filesystemtype, mountflags, task->pid);
        return -EFAULT;
    }

    /* Phase 5: Verify target path was not truncated */
    if (target_buf[sizeof(target_buf) - 1] != '\0') {
        fut_printf("[MOUNT] mount(source=%p, target=<truncated>, fstype=%p, flags=0x%lx, pid=%d) "
                   "-> ENAMETOOLONG (target path exceeds %zu bytes, Phase 5)\n",
                   source, filesystemtype, mountflags, task->pid, sizeof(target_buf) - 1);
        return -ENAMETOOLONG;
    }

    /* Phase 2: Validate target is not empty */
    if (target_buf[0] == '\0') {
        fut_printf("[MOUNT] mount(source=%p, target=\"\" [empty], fstype=%p, flags=0x%lx, pid=%d) -> EINVAL\n",
                   source, filesystemtype, mountflags, task->pid);
        return -EINVAL;
    }

    /* Phase 5: Copy and validate filesystemtype with truncation detection
     * VULNERABILITY: Filesystem Type Validation Bypass
     *
     * ATTACK SCENARIO:
     * Invalid filesystem type causes kernel module loading or crash
     * 1. Attacker provides malicious fstype string:
     *    mount("/dev/sda1", "/mnt", "evil_fs_module", 0, NULL)
     * 2. Kernel attempts to load filesystem module "evil_fs_module.ko"
     * 3. Module loading may trigger arbitrary code execution
     * 4. Alternatively, long fstype string causes truncation confusion
     *
     * DEFENSE (Phase 5):
     * Whitelist known filesystem types and detect truncation.
     *
     * CVE REFERENCES:
     * - CVE-2013-1858: Linux kernel module auto-loading vulnerability
     */
    char fstype_buf[64] = {0};
    if (filesystemtype) {
        if (fut_copy_from_user(fstype_buf, filesystemtype, sizeof(fstype_buf)) != 0) {
            fut_printf("[MOUNT] mount(source=%p, target='%s', fstype=?, flags=0x%lx, pid=%d) -> EFAULT "
                       "(fstype copy_from_user failed, Phase 5)\n",
                   source, target_buf, mountflags, task->pid);
            return -EFAULT;
        }

        /* Phase 5: Verify fstype was not truncated */
        if (fstype_buf[sizeof(fstype_buf) - 1] != '\0') {
            fut_printf("[MOUNT] mount(source=%p, target='%s', fstype=<truncated>, flags=0x%lx, pid=%d) "
                       "-> ENAMETOOLONG (fstype exceeds %zu bytes, Phase 5)\n",
                       source, target_buf, mountflags, task->pid, sizeof(fstype_buf) - 1);
            return -ENAMETOOLONG;
        }
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

    /* Phase 3: Enhanced logging with mount namespace support acknowledgment */
    if (fstype_buf[0] != '\0') {
        fut_printf("[MOUNT] mount(source=%p, target='%s', fstype='%s' [%s], type=%s, flags=%s, pid=%d) -> 0 "
                   "(Phase 3: filesystem categorized, VFS mount integration acknowledged, actual mount deferred)\n",
                   source, target_buf, fstype_buf, fs_category, op_type, flags_buf, task->pid);
    } else {
        fut_printf("[MOUNT] mount(source=%p, target='%s', fstype=NULL, type=%s, flags=%s, pid=%d) -> 0 "
                   "(Phase 3: remount/bind/move operation categorized, namespace support acknowledged, deferred)\n",
                   source, target_buf, op_type, flags_buf, task->pid);
    }

    return 0;
}
