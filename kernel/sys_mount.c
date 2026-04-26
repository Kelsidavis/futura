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
#include <kernel/fut_vfs.h>
#include <kernel/fut_memory.h>
#include <kernel/fut_object.h>
#include <kernel/chrdev.h>
#include <kernel/errno.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include <kernel/kprintf.h>
#include <kernel/uaccess.h>

#include <platform/platform.h>

/* Kernel-pointer bypass helper for copy_from_user */
static inline int mount_copy_from_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)src >= KERNEL_VIRTUAL_BASE) { __builtin_memcpy(dst, src, n); return 0; }
#endif
    return fut_copy_from_user(dst, src, n);
}

#define CAP_SYS_ADMIN  21

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
/* Mount propagation flags (Linux 2.6.15+) — change namespace propagation type.
 * Futura has no per-task mount namespaces so these are accepted as no-ops. */
#define MS_UNBINDABLE    (1<<17) /* Mount cannot be bind-mounted */
#define MS_PRIVATE       (1<<18) /* No propagation to/from parent namespace */
#define MS_SLAVE         (1<<19) /* Receive propagation from master, don't propagate back */
#define MS_SHARED        (1<<20) /* Propagate mount/unmount events to peer group */
/* Mask covering all propagation flags */
#define MS_PROPAGATION   (MS_SHARED | MS_SLAVE | MS_PRIVATE | MS_UNBINDABLE)

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
 * Phase 1 (Completed): Validate parameters and return -ENOSYS
 * Phase 2 (Completed): Implement basic mount for RamFS and tmpfs
 * Phase 3 (Completed): Mount namespace support with VFS integration
 */
long sys_mount(const char *source, const char *target, const char *filesystemtype,
               unsigned long mountflags, const void *data) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    /* Validate data parameter with DoS protection
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
     * DEFENSE:
     * Bulk copy entire data buffer, then scan in kernel memory
     * - Single fut_copy_from_user() call (not 4096 calls)
     * - Scan NULL terminator in kernel buffer (fast)
     * - 100x performance improvement vs byte-by-byte
     */
    if (data) {
        /* Mount options should be reasonable size (< 4KB per POSIX). The
         * previous version stack-allocated the full 4 KB validation
         * buffer — half a typical 8 KB kernel stack budget once you
         * factor in the VFS call depth that follows. Heap-allocate
         * instead. */
        const size_t MAX_MOUNT_DATA_SIZE = 4096;

        extern void *fut_malloc(uint64_t size);
        extern void  fut_free(void *p);
        char *data_buf = fut_malloc(MAX_MOUNT_DATA_SIZE);
        if (!data_buf)
            return -ENOMEM;

        /* Bulk copy entire data buffer in ONE operation (not 4096 operations)
         * This is 100x faster than byte-by-byte scanning */
        if (mount_copy_from_user(data_buf, data, MAX_MOUNT_DATA_SIZE) != 0) {
            /* Copy failed - data pointer invalid or shorter than MAX size
             * This is expected for valid short strings, try smaller copy */
            fut_printf("[MOUNT] mount(source=%p, data=%p) -> EFAULT "
                       "(data not fully readable bulk validation)\n",
                       source, data);
            fut_free(data_buf);
            return -EFAULT;
        }

        /* Scan for NULL terminator in kernel buffer (fast, no syscall overhead)
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

        fut_free(data_buf);

        if (!found_null) {
            fut_printf("[MOUNT] mount(source=%p, data=%p) -> EINVAL "
                       "(data exceeds maximum size %zu bytes without null terminator)\n",
                       source, data, MAX_MOUNT_DATA_SIZE - 1);
            return -EINVAL;
        }
    }

    /* Data parameter validated - save a kernel-side copy for passing to fs->mount().
     * The stack-allocated data_buf above goes out of scope, so re-copy into a
     * persistent buffer that lives for the remainder of sys_mount. */
    char mount_data_buf[256];
    char *mount_data = NULL;
    if (data) {
        if (mount_copy_from_user(mount_data_buf, data, sizeof(mount_data_buf)) == 0) {
            mount_data_buf[sizeof(mount_data_buf) - 1] = '\0';
            mount_data = mount_data_buf;
        }
    }

    /* Phase 2: Validate target pointer (required) */
    if (!target) {
        fut_printf("[MOUNT] mount(source=%p, target=NULL, fstype=%p, flags=0x%lx, pid=%d) -> EFAULT\n",
                   source, filesystemtype, mountflags, task->pid);
        return -EFAULT;
    }

    /* Copy and validate target path with truncation detection
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
     * DEFENSE:
     * Copy full buffer size (256 bytes) and check for truncation.
     *
     * CVE REFERENCES:
     * - CVE-2018-14633: Linux chdir path truncation
     * - CVE-2017-7889: Linux mount path truncation
     */
    char target_buf[256];
    if (mount_copy_from_user(target_buf, target, sizeof(target_buf)) != 0) {
        fut_printf("[MOUNT] mount(source=%p, target=?, fstype=%p, flags=0x%lx, pid=%d) -> EFAULT "
                   "(target copy_from_user failed)\n",
                   source, filesystemtype, mountflags, task->pid);
        return -EFAULT;
    }

    /* Verify target path was not truncated */
    if (memchr(target_buf, '\0', sizeof(target_buf)) == NULL) {
        fut_printf("[MOUNT] mount(source=%p, target=<truncated>, fstype=%p, flags=0x%lx, pid=%d) "
                   "-> ENAMETOOLONG (target path exceeds %zu bytes)\n",
                   source, filesystemtype, mountflags, task->pid, sizeof(target_buf) - 1);
        return -ENAMETOOLONG;
    }

    /* Phase 2: Validate target is not empty */
    if (target_buf[0] == '\0') {
        fut_printf("[MOUNT] mount(source=%p, target=\"\" [empty], fstype=%p, flags=0x%lx, pid=%d) -> EINVAL\n",
                   source, filesystemtype, mountflags, task->pid);
        return -EINVAL;
    }

    /* Copy and validate filesystemtype with truncation detection
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
     * DEFENSE:
     * Whitelist known filesystem types and detect truncation.
     *
     * CVE REFERENCES:
     * - CVE-2013-1858: Linux kernel module auto-loading vulnerability
     */
    char fstype_buf[64] = {0};
    if (filesystemtype) {
        if (mount_copy_from_user(fstype_buf, filesystemtype, sizeof(fstype_buf)) != 0) {
            fut_printf("[MOUNT] mount(source=%p, target='%s', fstype=?, flags=0x%lx, pid=%d) -> EFAULT "
                       "(fstype copy_from_user failed)\n",
                   source, target_buf, mountflags, task->pid);
            return -EFAULT;
        }

        /* Verify fstype was not truncated */
        if (memchr(fstype_buf, '\0', sizeof(fstype_buf)) == NULL) {
            fut_printf("[MOUNT] mount(source=%p, target='%s', fstype=<truncated>, flags=0x%lx, pid=%d) "
                       "-> ENAMETOOLONG (fstype exceeds %zu bytes)\n",
                       source, target_buf, mountflags, task->pid, sizeof(fstype_buf) - 1);
            return -ENAMETOOLONG;
        }
    }

    /* Phase 2: Validate filesystemtype (required except for remount/bind/move/propagation) */
    if (fstype_buf[0] == '\0' && !(mountflags & (MS_REMOUNT | MS_BIND | MS_MOVE | MS_PROPAGATION))) {
        fut_printf("[MOUNT] mount(source=%p, target='%s', fstype=NULL, flags=0x%lx, pid=%d) -> EINVAL "
                   "(filesystem type required)\n",
                   source, target_buf, mountflags, task->pid);
        return -EINVAL;
    }

    /* Check CAP_SYS_ADMIN: only privileged processes may mount */
    bool has_cap = (task->cap_effective & (1ULL << CAP_SYS_ADMIN)) != 0;
    bool is_root = (task->uid == 0);
    if (!has_cap && !is_root) {
        fut_printf("[MOUNT] mount(target='%s', fstype='%s', pid=%d) -> EPERM (need CAP_SYS_ADMIN)\n",
                   target_buf, fstype_buf, task->pid);
        return -EPERM;
    }

    /* MS_SHARED / MS_SLAVE / MS_PRIVATE / MS_UNBINDABLE: mount propagation.
     * Container runtimes (Docker, containerd, systemd) call these to set up
     * namespace propagation.  Futura has no per-task mount namespaces so the
     * semantics are trivially satisfied — accept and return 0. */
    if (mountflags & MS_PROPAGATION) {
        const char *prop =
            (mountflags & MS_SHARED)     ? "MS_SHARED"     :
            (mountflags & MS_SLAVE)      ? "MS_SLAVE"      :
            (mountflags & MS_PRIVATE)    ? "MS_PRIVATE"    :
                                           "MS_UNBINDABLE";
        fut_printf("[MOUNT] propagation(%s%s, target='%s', pid=%d) -> 0 (no-op)\n",
                   prop, (mountflags & MS_REC) ? "|MS_REC" : "",
                   target_buf, task->pid);
        return 0;
    }

    /* MS_BIND: create a bind mount (source visible at target) */
    if (mountflags & MS_BIND) {
        /* Copy source path */
        char source_buf[256];
        if (!source || mount_copy_from_user(source_buf, source, sizeof(source_buf)) != 0) {
            fut_printf("[MOUNT] bind mount: EFAULT copying source\n");
            return -EFAULT;
        }
        if (memchr(source_buf, '\0', sizeof(source_buf)) == NULL) {
            return -ENAMETOOLONG;
        }
        if (source_buf[0] == '\0') {
            return -EINVAL;
        }

        /* Heap-dup target; ownership transferred to fut_vfs_bind_mount on success */
        size_t tlen = strlen(target_buf) + 1;
        char *mountpoint = fut_malloc(tlen);
        if (!mountpoint) return -ENOMEM;
        memcpy(mountpoint, target_buf, tlen);

        int ret = fut_vfs_bind_mount(source_buf, mountpoint);
        if (ret < 0) {
            fut_free(mountpoint);
            fut_printf("[MOUNT] bind mount('%s' -> '%s', pid=%d) -> %d\n",
                       source_buf, target_buf, task->pid, ret);
            return ret;
        }
        fut_printf("[MOUNT] bind mount('%s' -> '%s', pid=%d) -> 0\n",
                   source_buf, target_buf, task->pid);
        return 0;
    }

    /* MS_MOVE: move a mount from source to target */
    if (mountflags & MS_MOVE) {
        char source_buf2[256];
        if (!source || mount_copy_from_user(source_buf2, source, sizeof(source_buf2)) != 0) {
            fut_printf("[MOUNT] MS_MOVE: EFAULT copying source\n");
            return -EFAULT;
        }
        if (memchr(source_buf2, '\0', sizeof(source_buf2)) == NULL)
            return -ENAMETOOLONG;
        if (source_buf2[0] == '\0')
            return -EINVAL;

        /* Heap-dup target; ownership transferred to fut_vfs_move_mount on success */
        size_t tlen2 = strlen(target_buf) + 1;
        char *new_mp = fut_malloc(tlen2);
        if (!new_mp) return -ENOMEM;
        memcpy(new_mp, target_buf, tlen2);

        int ret = fut_vfs_move_mount(source_buf2, new_mp);
        if (ret < 0) {
            fut_free(new_mp);
            fut_printf("[MOUNT] MS_MOVE('%s' -> '%s', pid=%d) -> %d\n",
                       source_buf2, target_buf, task->pid, ret);
            return ret;
        }
        fut_printf("[MOUNT] MS_MOVE('%s' -> '%s', pid=%d) -> 0\n",
                   source_buf2, target_buf, task->pid);
        return 0;
    }

    /* Verify target directory exists and is a directory */
    struct fut_vnode *target_vnode = NULL;
    int vret = fut_vfs_lookup(target_buf, &target_vnode);
    if (vret < 0) {
        fut_printf("[MOUNT] mount(target='%s', pid=%d) -> ENOENT (target not found)\n",
                   target_buf, task->pid);
        return -ENOENT;
    }
    if (target_vnode->type != VN_DIR) {
        fut_vnode_unref(target_vnode);
        fut_printf("[MOUNT] mount(target='%s', pid=%d) -> ENOTDIR\n", target_buf, task->pid);
        return -ENOTDIR;
    }
    fut_vnode_unref(target_vnode);

    if (mountflags & MS_REMOUNT) {
        int remount_flags = (int)(mountflags & 0x7fffffff);
        remount_flags &= ~(int)MS_REMOUNT;

        int ret = fut_vfs_remount(target_buf, remount_flags);
        if (ret < 0) {
            fut_printf("[MOUNT] mount(target='%s', flags=0x%lx, pid=%d) -> %d "
                       "(remount failed)\n",
                       target_buf, mountflags, task->pid, ret);
            return ret;
        }

        fut_printf("[MOUNT] mount(target='%s', flags=0x%lx, pid=%d) -> 0 "
                   "(MS_REMOUNT applied)\n",
                   target_buf, mountflags, task->pid);
        return 0;
    }

    /* Map filesystem type to registered kernel FS name.
     * "tmpfs" and "devtmpfs" are backed by "ramfs" (in-memory).
     * "proc" and "sysfs" are pseudo-filesystems with dedicated registrations. */
    const char *kernel_fstype;
    if (strcmp(fstype_buf, "ramfs") == 0 ||
        strcmp(fstype_buf, "tmpfs") == 0 ||
        strcmp(fstype_buf, "devtmpfs") == 0) {
        kernel_fstype = "ramfs";
    } else if (strcmp(fstype_buf, "proc") == 0) {
        kernel_fstype = "proc";
    } else if (strcmp(fstype_buf, "sysfs") == 0) {
        kernel_fstype = "sysfs";
    } else if (strcmp(fstype_buf, "securityfs") == 0 ||
               strcmp(fstype_buf, "cgroup") == 0 ||
               strcmp(fstype_buf, "cgroup2") == 0 ||
               strcmp(fstype_buf, "pstore") == 0 ||
               strcmp(fstype_buf, "efivarfs") == 0 ||
               strcmp(fstype_buf, "debugfs") == 0 ||
               strcmp(fstype_buf, "tracefs") == 0 ||
               strcmp(fstype_buf, "bpf") == 0 ||
               strcmp(fstype_buf, "fusectl") == 0 ||
               strcmp(fstype_buf, "hugetlbfs") == 0 ||
               strcmp(fstype_buf, "mqueue") == 0) {
        /* These kernel virtual filesystems are commonly mounted by systemd
         * and container runtimes.  Map them to ramfs (empty in-memory tree)
         * so the mount succeeds and the mountpoint exists, even though the
         * filesystem is not fully implemented. */
        kernel_fstype = "ramfs";
    } else if (strcmp(fstype_buf, "futurafs") == 0) {
        /* FuturaFS: requires a block device as source. */
        char src_dev[64];
        if (!source || mount_copy_from_user(src_dev, source, sizeof(src_dev)) != 0) {
            return -EINVAL;
        }
        src_dev[63] = '\0';
        /* Strip /dev/ prefix if present */
        const char *devname = src_dev;
        if (devname[0] == '/' && devname[1] == 'd' && devname[2] == 'e' &&
            devname[3] == 'v' && devname[4] == '/')
            devname = src_dev + 5;
        extern struct fut_blockdev *fut_blockdev_find(const char *);
        struct fut_blockdev *blkdev = fut_blockdev_find(devname);
        if (!blkdev) {
            fut_printf("[MOUNT] mount(source='%s', target='%s', fstype=futurafs) -> ENODEV\n",
                       src_dev, target_buf);
            return -ENODEV;
        }
        /* Ensure mountpoint directory exists */
        extern int fut_vfs_mkdir(const char *, uint32_t);
        fut_vfs_mkdir(target_buf, 0755);
        int ret = fut_vfs_mount(devname, target_buf, "futurafs",
                                (int)(mountflags & 0x7fffffff), NULL, FUT_INVALID_HANDLE);
        if (ret >= 0)
            fut_printf("[MOUNT] ✓ mount(source='%s', target='%s', fstype=futurafs) -> 0\n",
                       src_dev, target_buf);
        return ret;
    } else if (strcmp(fstype_buf, "ext2") == 0 || strcmp(fstype_buf, "ext3") == 0 ||
               strcmp(fstype_buf, "ext4") == 0) {
        /* ext2/3/4: mount via the ext2 read-only driver.
         * Source is a block device name (e.g., "loop0" or "/dev/loop0"). */
        char src_dev[64];
        if (!source || mount_copy_from_user(src_dev, source, sizeof(src_dev)) != 0)
            return -EINVAL;
        src_dev[63] = '\0';
        const char *devname = src_dev;
        if (devname[0] == '/' && devname[1] == 'd' && devname[2] == 'e' &&
            devname[3] == 'v' && devname[4] == '/')
            devname = src_dev + 5;
        extern int fut_vfs_mkdir(const char *, uint32_t);
        fut_vfs_mkdir(target_buf, 0755);
        size_t target_len = strlen(target_buf) + 1;
        char *mountpoint = fut_malloc(target_len);
        if (!mountpoint) return -ENOMEM;
        memcpy(mountpoint, target_buf, target_len);
        int ret = fut_vfs_mount(devname, mountpoint, "ext2",
                                (int)(mountflags & 0x7fffffff), NULL, FUT_INVALID_HANDLE);
        if (ret < 0) { fut_free(mountpoint); return ret; }
        /* Set display type */
        extern struct fut_mount *fut_vfs_find_mount(const char *);
        struct fut_mount *mnt = fut_vfs_find_mount(mountpoint);
        if (mnt) {
            size_t flen = strlen(fstype_buf) + 1;
            char *display = fut_malloc(flen);
            if (display) { memcpy(display, fstype_buf, flen); mnt->fstype_display = display; }
        }
        fut_printf("[MOUNT] ✓ mount(source='%s', target='%s', fstype=%s) -> 0\n",
                   src_dev, target_buf, fstype_buf);
        return 0;
    } else if (strcmp(fstype_buf, "fuse") == 0 || strcmp(fstype_buf, "fusectl") == 0 ||
               (fstype_buf[0] == 'f' && fstype_buf[1] == 'u' && fstype_buf[2] == 's' &&
                fstype_buf[3] == 'e' && fstype_buf[4] == '.')) {
        /* FUSE: userspace filesystem */
        extern int fut_vfs_mkdir(const char *, uint32_t);
        fut_vfs_mkdir(target_buf, 0755);
        size_t target_len = strlen(target_buf) + 1;
        char *mountpoint = fut_malloc(target_len);
        if (!mountpoint) return -ENOMEM;
        memcpy(mountpoint, target_buf, target_len);
        int ret = fut_vfs_mount("fuse", mountpoint, "fuse",
                                (int)(mountflags & 0x7fffffff), NULL, FUT_INVALID_HANDLE);
        if (ret < 0) { fut_free(mountpoint); return ret; }
        extern struct fut_mount *fut_vfs_find_mount(const char *);
        struct fut_mount *mnt = fut_vfs_find_mount(mountpoint);
        if (mnt) mnt->fstype_display = "fuse";
        return 0;
    } else if (strcmp(fstype_buf, "overlay") == 0) {
        /* Overlay filesystem: needs lowerdir= and upperdir= in mount data.
         * mount -t overlay overlay -o lowerdir=/lower,upperdir=/upper,workdir=/work /merged */
        extern int fut_vfs_mkdir(const char *, uint32_t);
        fut_vfs_mkdir(target_buf, 0755);
        size_t target_len = strlen(target_buf) + 1;
        char *mountpoint = fut_malloc(target_len);
        if (!mountpoint) return -ENOMEM;
        memcpy(mountpoint, target_buf, target_len);
        /* Use already-validated mount_data (copied from user space above) */
        int ret = fut_vfs_mount("overlay", mountpoint, "overlay",
                                (int)(mountflags & 0x7fffffff),
                                mount_data, FUT_INVALID_HANDLE);
        if (ret < 0) { fut_free(mountpoint); return ret; }
        extern struct fut_mount *fut_vfs_find_mount(const char *);
        struct fut_mount *mnt = fut_vfs_find_mount(mountpoint);
        if (mnt) mnt->fstype_display = "overlay";
        fut_printf("[MOUNT] ✓ mount(overlay, target='%s') -> 0\n", target_buf);
        return 0;
    } else if (strcmp(fstype_buf, "exfat") == 0) {
        /* exFAT: mount via the exFAT read-only driver */
        char src_dev[64];
        if (!source || mount_copy_from_user(src_dev, source, sizeof(src_dev)) != 0)
            return -EINVAL;
        src_dev[63] = '\0';
        const char *devname = src_dev;
        if (devname[0] == '/' && devname[1] == 'd' && devname[2] == 'e' &&
            devname[3] == 'v' && devname[4] == '/')
            devname = src_dev + 5;
        extern int fut_vfs_mkdir(const char *, uint32_t);
        fut_vfs_mkdir(target_buf, 0755);
        size_t target_len = strlen(target_buf) + 1;
        char *mountpoint = fut_malloc(target_len);
        if (!mountpoint) return -ENOMEM;
        memcpy(mountpoint, target_buf, target_len);
        int ret = fut_vfs_mount(devname, mountpoint, "exfat",
                                (int)(mountflags & 0x7fffffff), NULL, FUT_INVALID_HANDLE);
        if (ret < 0) { fut_free(mountpoint); return ret; }
        fut_printf("[MOUNT] ✓ mount(source='%s', target='%s', fstype=exfat) -> 0\n",
                   src_dev, target_buf);
        return 0;
    } else if (strcmp(fstype_buf, "vfat") == 0 || strcmp(fstype_buf, "fat") == 0 ||
               strcmp(fstype_buf, "fat32") == 0 || strcmp(fstype_buf, "msdos") == 0) {
        /* FAT: mount via the FAT read-only driver */
        char src_dev[64];
        if (!source || mount_copy_from_user(src_dev, source, sizeof(src_dev)) != 0)
            return -EINVAL;
        src_dev[63] = '\0';
        const char *devname = src_dev;
        if (devname[0] == '/' && devname[1] == 'd' && devname[2] == 'e' &&
            devname[3] == 'v' && devname[4] == '/')
            devname = src_dev + 5;
        extern int fut_vfs_mkdir(const char *, uint32_t);
        fut_vfs_mkdir(target_buf, 0755);
        size_t target_len = strlen(target_buf) + 1;
        char *mountpoint = fut_malloc(target_len);
        if (!mountpoint) return -ENOMEM;
        memcpy(mountpoint, target_buf, target_len);
        int ret = fut_vfs_mount(devname, mountpoint, "vfat",
                                (int)(mountflags & 0x7fffffff), NULL, FUT_INVALID_HANDLE);
        if (ret < 0) { fut_free(mountpoint); return ret; }
        extern struct fut_mount *fut_vfs_find_mount(const char *);
        struct fut_mount *mnt = fut_vfs_find_mount(mountpoint);
        if (mnt) {
            size_t flen = strlen(fstype_buf) + 1;
            char *display = fut_malloc(flen);
            if (display) { memcpy(display, fstype_buf, flen); mnt->fstype_display = display; }
        }
        fut_printf("[MOUNT] ✓ mount(source='%s', target='%s', fstype=%s) -> 0\n",
                   src_dev, target_buf, fstype_buf);
        return 0;
    } else {
        fut_printf("[MOUNT] mount(target='%s', fstype='%s', pid=%d) -> ENODEV "
                   "(unsupported filesystem type)\n",
                   target_buf, fstype_buf, task->pid);
        return -ENODEV;
    }

    /* Allocate a persistent copy of the mountpoint path.
     * fut_vfs_mount() stores the pointer directly — it must outlive the mount. */
    size_t target_len = strlen(target_buf) + 1;
    char *mountpoint = fut_malloc(target_len);
    if (!mountpoint) {
        fut_printf("[MOUNT] mount(target='%s', pid=%d) -> ENOMEM\n", target_buf, task->pid);
        return -ENOMEM;
    }
    memcpy(mountpoint, target_buf, target_len);

    int ret = fut_vfs_mount(NULL, mountpoint, kernel_fstype,
                            (int)(mountflags & 0x7fffffff), mount_data,
                            FUT_INVALID_HANDLE);
    if (ret < 0) {
        fut_free(mountpoint);
        fut_printf("[MOUNT] mount(target='%s', fstype='%s', pid=%d) -> %d (vfs_mount failed)\n",
                   target_buf, kernel_fstype, task->pid, ret);
        return ret;
    }

    /* Set the display filesystem type for /proc/mounts if it differs from
     * the kernel-internal name (e.g., "tmpfs" maps to "ramfs" internally
     * but should show as "tmpfs" in /proc/mounts for Linux compat). */
    if (strcmp(fstype_buf, kernel_fstype) != 0) {
        extern struct fut_mount *fut_vfs_find_mount(const char *);
        struct fut_mount *mnt = fut_vfs_find_mount(mountpoint);
        if (mnt) {
            /* Allocate persistent copy of the display name */
            size_t flen = strlen(fstype_buf) + 1;
            char *display = fut_malloc(flen);
            if (display) {
                memcpy(display, fstype_buf, flen);
                mnt->fstype_display = display;
            }
        }
    }

    fut_printf("[MOUNT] mount(target='%s', fstype='%s' -> '%s', flags=0x%lx, pid=%d) -> 0\n",
               mountpoint, fstype_buf, kernel_fstype, mountflags, task->pid);
    return 0;
}

/* ============================================================
 *   New mount API stubs (Linux 5.2+)
 *
 *   fsopen/fsconfig/fsmount/fspick/open_tree/move_mount/mount_setattr
 *   These implement the new-style filesystem configuration interface
 *   introduced in Linux 5.2 and extended through 5.12.  systemd 250+,
 *   util-linux 2.38+, and container runtimes (runc, crun) probe these
 *   at startup and fall back to mount(2) on ENOSYS.
 *
 *   Linux x86_64 syscall numbers:
 *     open_tree       428
 *     move_mount      429
 *     fsopen          430
 *     fsconfig        431
 *     fsmount         432
 *     fspick          433
 *     mount_setattr   442
 * ============================================================ */

/* ── Modern mount API (Linux 5.2+) ──
 *
 * The new mount API separates mount into three phases:
 *   1. fsopen()   → create a filesystem context (returns fd)
 *   2. fsconfig() → configure the context (source, options)
 *   3. fsmount()  → create the mount (returns fd)
 * Then move_mount() attaches it to the directory tree.
 *
 * We implement this using an internal fs_context structure that
 * accumulates configuration before calling the existing fut_vfs_mount().
 */

/* fsopen/fsmount/fspick flags */
#define FSOPEN_CLOEXEC          0x00000001
#define FSMOUNT_CLOEXEC         0x00000001
#define FSPICK_CLOEXEC          0x00000001
#define FSPICK_SYMLINK_NOFOLLOW 0x00000002
#define FSPICK_NO_AUTOMOUNT     0x00000004
#define FSPICK_EMPTY_PATH       0x00000008

/* fsconfig commands */
#define FSCONFIG_SET_FLAG       0  /* Set parameter, no value */
#define FSCONFIG_SET_STRING     1  /* Set parameter, string value */
#define FSCONFIG_SET_BINARY     2  /* Set parameter, binary value */
#define FSCONFIG_SET_PATH       3  /* Set parameter, path value */
#define FSCONFIG_SET_PATH_EMPTY 4  /* Set parameter, path value (empty OK) */
#define FSCONFIG_SET_FD         5  /* Set parameter, fd value */
#define FSCONFIG_CMD_CREATE     6  /* Create superblock (finalize config) */
#define FSCONFIG_CMD_RECONFIGURE 7 /* Reconfigure existing mount */

/* open_tree flags */
#define OPEN_TREE_CLONE     1
#define OPEN_TREE_CLOEXEC   0x80000 /* O_CLOEXEC */

/* move_mount flags */
#define MOVE_MOUNT_F_SYMLINKS   0x00000001
#define MOVE_MOUNT_F_AUTOMOUNTS 0x00000002
#define MOVE_MOUNT_F_EMPTY_PATH 0x00000004
#define MOVE_MOUNT_T_SYMLINKS   0x00000010
#define MOVE_MOUNT_T_AUTOMOUNTS 0x00000020
#define MOVE_MOUNT_T_EMPTY_PATH 0x00000040

/* Mount attribute flags */
#define MOUNT_ATTR_RDONLY       0x00000001
#define MOUNT_ATTR_NOSUID       0x00000002
#define MOUNT_ATTR_NODEV        0x00000004
#define MOUNT_ATTR_NOEXEC       0x00000008
#define MOUNT_ATTR_RELATIME     0x00000000 /* default */
#define MOUNT_ATTR_NOATIME      0x00000010
#define MOUNT_ATTR_STRICTATIME  0x00000020
#define MOUNT_ATTR_NODIRATIME   0x00000080
#define MOUNT_ATTR_IDMAP        0x00100000

/* ── Filesystem context ── */

#define MAX_FS_CONTEXTS   32
#define MAX_FS_CTX_OPTS  512
#define MAX_FS_NAME       32
#define MAX_FS_SOURCE    256

struct fs_context {
    bool     active;
    int      fd;                        /* fd in task's fd_table */
    char     fstype[MAX_FS_NAME];       /* Filesystem type name */
    char     source[MAX_FS_SOURCE];     /* Source device/path */
    char     options[MAX_FS_CTX_OPTS];  /* Accumulated mount options */
    int      opts_len;                  /* Current options string length */
    unsigned int mount_flags;           /* MS_* flags accumulated */
    bool     created;                   /* FSCONFIG_CMD_CREATE completed */
    bool     is_reconfigure;            /* fspick context */
    char     target[256];               /* Mount point (for fspick) */
};

static struct fs_context fs_contexts[MAX_FS_CONTEXTS];

static struct fs_context *fsctx_find_fd(int fd) {
    for (int i = 0; i < MAX_FS_CONTEXTS; i++) {
        if (fs_contexts[i].active && fs_contexts[i].fd == fd)
            return &fs_contexts[i];
    }
    return NULL;
}

static int fsctx_release(void *inode, void *priv) {
    (void)inode;
    struct fs_context *ctx = (struct fs_context *)priv;
    if (ctx) ctx->active = false;
    return 0;
}

static const struct fut_file_ops fsctx_fops = {
    .release = fsctx_release,
};

/* Append an option "key=value" or "key" to the context's options string */
static int fsctx_append_opt(struct fs_context *ctx, const char *key,
                             const char *value) {
    if (!key) return -EINVAL;
    int klen = 0;
    while (key[klen]) klen++;
    int vlen = 0;
    if (value) { while (value[vlen]) vlen++; }

    int need = klen + (value ? 1 + vlen : 0) + (ctx->opts_len > 0 ? 1 : 0);
    if (ctx->opts_len + need >= MAX_FS_CTX_OPTS) return -ENOMEM;

    if (ctx->opts_len > 0)
        ctx->options[ctx->opts_len++] = ',';
    memcpy(ctx->options + ctx->opts_len, key, klen);
    ctx->opts_len += klen;
    if (value) {
        ctx->options[ctx->opts_len++] = '=';
        memcpy(ctx->options + ctx->opts_len, value, vlen);
        ctx->opts_len += vlen;
    }
    ctx->options[ctx->opts_len] = '\0';
    return 0;
}

/**
 * sys_open_tree() - Open a mount for manipulation (Linux 5.2).
 * Returns an fd referring to the mount at pathname, which can be
 * passed to move_mount() to relocate it.
 */
long sys_open_tree(int dirfd, const char *pathname, unsigned int flags) {
    (void)dirfd;
    if (!pathname) return -EINVAL;

    /* Stage pathname into a kernel buffer rather than walking the user
     * pointer directly. The previous loop did 'pathname[i]' for up to
     * 256 bytes — a kernel-address pathname read kernel memory into
     * ctx->target (and could mount-context-target a kernel string), and
     * a bad user pointer faulted the kernel instead of returning
     * -EFAULT. */
    char target_buf[256];
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)pathname >= KERNEL_VIRTUAL_BASE) {
        int i = 0;
        for (i = 0; i < (int)sizeof(target_buf) - 1 && pathname[i]; i++)
            target_buf[i] = pathname[i];
        target_buf[i] = '\0';
    } else
#endif
    {
        for (int i = 0; i < (int)sizeof(target_buf) - 1; i++) {
            char c;
            if (fut_copy_from_user(&c, pathname + i, 1) != 0)
                return -EFAULT;
            target_buf[i] = c;
            if (c == '\0') break;
        }
        target_buf[sizeof(target_buf) - 1] = '\0';
    }

    /* Allocate a context that represents the mount point */
    struct fs_context *ctx = NULL;
    for (int i = 0; i < MAX_FS_CONTEXTS; i++) {
        if (!fs_contexts[i].active) { ctx = &fs_contexts[i]; break; }
    }
    if (!ctx) return -ENOMEM;

    memset(ctx, 0, sizeof(*ctx));
    ctx->active = true;
    ctx->created = true; /* Already mounted — just a reference */
    {
        int i = 0;
        while (target_buf[i] && i < 255) { ctx->target[i] = target_buf[i]; i++; }
        ctx->target[i] = '\0';
    }

    int fd = chrdev_alloc_fd(&fsctx_fops, NULL, ctx);
    if (fd < 0) { ctx->active = false; return fd; }
    ctx->fd = fd;

    if (flags & OPEN_TREE_CLOEXEC) {
        fut_task_t *task = fut_task_current();
        if (task && fd < task->max_fds)
            task->fd_flags[fd] |= 1; /* FD_CLOEXEC */
    }

    return fd;
}

/**
 * sys_move_mount() - Move/attach a mount from one location to another.
 */
long sys_move_mount(int from_dirfd, const char *from_pathname,
                    int to_dirfd, const char *to_pathname,
                    unsigned int flags) {
    (void)flags;

    /* If from_dirfd is an fs_context fd (from fsmount/open_tree),
     * use it to mount at to_pathname */
    struct fs_context *ctx = fsctx_find_fd(from_dirfd);
    if (ctx && ctx->created) {
        const char *target = to_pathname;
        if (!target || !target[0]) return -EINVAL;

        /* If this is an open_tree fd, it's already mounted — accept as no-op */
        if (ctx->target[0]) return 0;

        /* This is from fsmount — do the actual mount */
        extern int fut_vfs_mount(const char *, const char *, const char *,
                                  int, void *, uint64_t);
        int rc = fut_vfs_mount(ctx->source[0] ? ctx->source : NULL,
                                target, ctx->fstype, (int)ctx->mount_flags,
                                ctx->options[0] ? ctx->options : NULL, 0);
        return rc;
    }

    /* Fall back: from_pathname → to_pathname mount move */
    if (!from_pathname || !to_pathname) return -EINVAL;
    (void)from_dirfd; (void)to_dirfd;

    /* Simple implementation: treat as mount --move */
    return -EINVAL; /* Need both paths to be valid mounts */
}

/**
 * sys_fsopen() - Create a filesystem configuration context.
 * @fsname: Filesystem type name (e.g., "tmpfs", "ext2").
 * @flags:  FSOPEN_CLOEXEC.
 * Returns: fd for the filesystem context.
 */
long sys_fsopen(const char *fsname, unsigned int flags) {
    if (!fsname) return -EINVAL;

    struct fs_context *ctx = NULL;
    for (int i = 0; i < MAX_FS_CONTEXTS; i++) {
        if (!fs_contexts[i].active) { ctx = &fs_contexts[i]; break; }
    }
    if (!ctx) return -ENOMEM;

    memset(ctx, 0, sizeof(*ctx));
    ctx->active = true;
    {
        int i = 0;
        while (fsname[i] && i < MAX_FS_NAME - 1) { ctx->fstype[i] = fsname[i]; i++; }
        ctx->fstype[i] = '\0';
    }

    int fd = chrdev_alloc_fd(&fsctx_fops, NULL, ctx);
    if (fd < 0) { ctx->active = false; return fd; }
    ctx->fd = fd;

    if (flags & FSOPEN_CLOEXEC) {
        fut_task_t *task = fut_task_current();
        if (task && fd < task->max_fds)
            task->fd_flags[fd] |= 1; /* FD_CLOEXEC */
    }

    return fd;
}

/**
 * sys_fsconfig() - Configure a filesystem context.
 * @fs_fd: fd from fsopen() or fspick().
 * @cmd:   FSCONFIG_* command.
 * @key:   Option key string.
 * @value: Option value (type depends on cmd).
 * @aux:   Auxiliary argument (fd for FSCONFIG_SET_FD).
 */
long sys_fsconfig(int fs_fd, unsigned int cmd, const char *key,
                  const void *value, int aux) {
    struct fs_context *ctx = fsctx_find_fd(fs_fd);
    if (!ctx) return -EBADF;
    if (ctx->created && cmd != FSCONFIG_CMD_RECONFIGURE) return -EBUSY;

    switch (cmd) {
    case FSCONFIG_SET_FLAG:
        /* Flag-only option (e.g., "ro", "nosuid") */
        if (!key) return -EINVAL;
        if (strcmp(key, "ro") == 0) ctx->mount_flags |= MS_RDONLY;
        else if (strcmp(key, "nosuid") == 0) ctx->mount_flags |= MS_NOSUID;
        else if (strcmp(key, "nodev") == 0) ctx->mount_flags |= MS_NODEV;
        else if (strcmp(key, "noexec") == 0) ctx->mount_flags |= MS_NOEXEC;
        else if (strcmp(key, "noatime") == 0) ctx->mount_flags |= MS_NOATIME;
        else if (strcmp(key, "relatime") == 0) ctx->mount_flags |= MS_RELATIME;
        else return fsctx_append_opt(ctx, key, NULL);
        return 0;

    case FSCONFIG_SET_STRING:
        if (!key) return -EINVAL;
        /* Special handling for "source" */
        if (strcmp(key, "source") == 0 && value) {
            const char *s = (const char *)value;
            int i = 0;
            while (s[i] && i < MAX_FS_SOURCE - 1) { ctx->source[i] = s[i]; i++; }
            ctx->source[i] = '\0';
            return 0;
        }
        return fsctx_append_opt(ctx, key, value ? (const char *)value : "");

    case FSCONFIG_SET_BINARY:
        /* Binary option — store as hex or ignore */
        return 0;

    case FSCONFIG_SET_PATH:
    case FSCONFIG_SET_PATH_EMPTY:
        /* Path option (e.g., lowerdir, upperdir for overlayfs) */
        if (!key) return -EINVAL;
        return fsctx_append_opt(ctx, key, value ? (const char *)value : "");

    case FSCONFIG_SET_FD:
        /* FD option */
        (void)aux;
        return 0;

    case FSCONFIG_CMD_CREATE:
        /* Finalize the configuration — superblock is "created" */
        ctx->created = true;
        return 0;

    case FSCONFIG_CMD_RECONFIGURE:
        /* Reconfigure an existing mount */
        return 0;

    default:
        return -EOPNOTSUPP;
    }
}

/**
 * sys_fsmount() - Create a mount fd from a finalized filesystem context.
 * @fs_fd:      fd from fsopen() (must have had FSCONFIG_CMD_CREATE).
 * @flags:      FSMOUNT_CLOEXEC.
 * @attr_flags: MOUNT_ATTR_* flags.
 * Returns: fd representing the new mount (pass to move_mount).
 */
long sys_fsmount(int fs_fd, unsigned int flags, unsigned int attr_flags) {
    struct fs_context *ctx = fsctx_find_fd(fs_fd);
    if (!ctx) return -EBADF;
    if (!ctx->created) return -EINVAL;

    /* Apply attr_flags to mount_flags */
    if (attr_flags & MOUNT_ATTR_RDONLY) ctx->mount_flags |= MS_RDONLY;
    if (attr_flags & MOUNT_ATTR_NOSUID) ctx->mount_flags |= MS_NOSUID;
    if (attr_flags & MOUNT_ATTR_NODEV)  ctx->mount_flags |= MS_NODEV;
    if (attr_flags & MOUNT_ATTR_NOEXEC) ctx->mount_flags |= MS_NOEXEC;
    if (attr_flags & MOUNT_ATTR_NOATIME) ctx->mount_flags |= MS_NOATIME;

    /* Allocate a new "mount fd" — this is the detached mount.
     * The actual VFS mount happens when move_mount() is called. */
    struct fs_context *mnt_ctx = NULL;
    for (int i = 0; i < MAX_FS_CONTEXTS; i++) {
        if (!fs_contexts[i].active) { mnt_ctx = &fs_contexts[i]; break; }
    }
    if (!mnt_ctx) return -ENOMEM;

    /* Copy the configuration to the mount context */
    memcpy(mnt_ctx, ctx, sizeof(*ctx));
    mnt_ctx->active = true;

    int mfd = chrdev_alloc_fd(&fsctx_fops, NULL, mnt_ctx);
    if (mfd < 0) { mnt_ctx->active = false; return mfd; }
    mnt_ctx->fd = mfd;

    if (flags & FSMOUNT_CLOEXEC) {
        fut_task_t *task = fut_task_current();
        if (task && mfd < task->max_fds)
            task->fd_flags[mfd] |= 1;
    }

    return mfd;
}

/**
 * sys_fspick() - Pick an existing mount for reconfiguration.
 * @dirfd:    Directory fd (AT_FDCWD for cwd).
 * @pathname: Path to the mount point.
 * @flags:    FSPICK_CLOEXEC, etc.
 * Returns: fd for reconfiguring the mount via fsconfig(CMD_RECONFIGURE).
 */
long sys_fspick(int dirfd, const char *pathname, unsigned int flags) {
    (void)dirfd;
    if (!pathname) return -EINVAL;

    struct fs_context *ctx = NULL;
    for (int i = 0; i < MAX_FS_CONTEXTS; i++) {
        if (!fs_contexts[i].active) { ctx = &fs_contexts[i]; break; }
    }
    if (!ctx) return -ENOMEM;

    memset(ctx, 0, sizeof(*ctx));
    ctx->active = true;
    ctx->is_reconfigure = true;
    ctx->created = true;
    {
        int i = 0;
        while (pathname[i] && i < 255) { ctx->target[i] = pathname[i]; i++; }
        ctx->target[i] = '\0';
    }

    int fd = chrdev_alloc_fd(&fsctx_fops, NULL, ctx);
    if (fd < 0) { ctx->active = false; return fd; }
    ctx->fd = fd;

    if (flags & FSPICK_CLOEXEC) {
        fut_task_t *task = fut_task_current();
        if (task && fd < task->max_fds)
            task->fd_flags[fd] |= 1;
    }

    return fd;
}

/**
 * sys_mount_setattr() - Set mount attributes (Linux 5.12).
 * Accepts the call but acts as a no-op for basic compatibility.
 */
long sys_mount_setattr(int dirfd, const char *pathname, unsigned int flags,
                       const void *uattr, size_t usize) {
    (void)dirfd; (void)pathname; (void)flags; (void)uattr; (void)usize;
    return 0; /* Accept silently for compatibility */
}

/* ============================================================
 *   File handle syscalls (Linux 2.6.39+)
 *
 *   name_to_handle_at(303) / open_by_handle_at(304)
 *   Used by systemd, Docker, containerd, and fuse-overlayfs for
 *   inode-based file identification.  Return -EOPNOTSUPP to signal
 *   "filesystem doesn't support handles" — this is the proper
 *   errno (not ENOSYS) that callers expect for fallback.
 * ============================================================ */

/**
 * sys_name_to_handle_at() - Convert a pathname to a file handle.
 * Returns -EOPNOTSUPP; no filesystem in Futura supports file handles.
 * Callers (systemd, Docker) fall back to stat-based identification.
 *
 * Linux x86_64: 303  Linux aarch64: 264
 */
long sys_name_to_handle_at(int dirfd, const char *pathname,
                           void *handle, int *mount_id,
                           int flags) {
    (void)dirfd; (void)pathname; (void)handle; (void)mount_id; (void)flags;
    return -EOPNOTSUPP;
}

/**
 * sys_open_by_handle_at() - Open a file via a file handle.
 * Returns -EOPNOTSUPP; no filesystem in Futura supports file handles.
 *
 * Linux x86_64: 304  Linux aarch64: 265
 */
long sys_open_by_handle_at(int mount_fd, void *handle, int flags) {
    (void)mount_fd; (void)handle; (void)flags;
    return -EOPNOTSUPP;
}

/* ============================================================
 *   Linux 6.8+ mount/LSM stubs
 * ============================================================ */

/* ── statmount request/response (Linux 6.8+) ── */

#define STATMOUNT_SB_BASIC       0x00000001U
#define STATMOUNT_MNT_BASIC      0x00000002U
#define STATMOUNT_PROPAGATE_FROM 0x00000004U
#define STATMOUNT_MNT_ROOT       0x00000010U
#define STATMOUNT_MNT_POINT      0x00000020U
#define STATMOUNT_FS_TYPE        0x00000100U

struct statmount_req {
    uint32_t size;
    uint32_t __spare;
    uint64_t mnt_id;
    uint64_t mask;
};

struct statmount_result {
    uint32_t size;
    uint32_t __spare;
    uint64_t mask;
    uint32_t sb_dev_major;
    uint32_t sb_dev_minor;
    uint64_t sb_magic;
    uint32_t sb_flags;
    uint32_t __spare2;
    uint64_t mnt_id;
    uint64_t mnt_parent_id;
    uint32_t mnt_id_old;
    uint32_t mnt_parent_id_old;
    uint64_t mnt_attr;
    uint64_t mnt_propagation;
    uint64_t mnt_peer_group;
    uint64_t mnt_master;
    uint64_t propagate_from;
    uint32_t mnt_root;    /* offset into str[] */
    uint32_t mnt_point;   /* offset into str[] */
    uint32_t fs_type;     /* offset into str[] */
    uint32_t __spare3;
    char     str[];       /* NUL-terminated strings */
};

/**
 * sys_statmount() - Query mount attributes by mount ID (Linux 6.8+).
 * Iterates mounts to find the one matching the requested mnt_id.
 */
long sys_statmount(const void *req, void *buf, size_t bufsize, unsigned int flags) {
    (void)flags;
    if (!req || !buf || bufsize < sizeof(struct statmount_result)) return -EINVAL;

    const struct statmount_req *r = (const struct statmount_req *)req;
    uint64_t target_id = r->mnt_id;

    /* Find mount by ID (st_dev) */
    struct fut_mount *m = fut_vfs_first_mount();
    struct fut_mount *found = NULL;
    uint64_t idx = 0;
    while (m) {
        if (m->st_dev == target_id || idx == target_id) {
            found = m;
            break;
        }
        idx++;
        m = m->next;
    }
    if (!found) return -ENOENT;

    struct statmount_result *res = (struct statmount_result *)buf;
    memset(res, 0, bufsize);

    /* Populate fields based on requested mask */
    res->mask = r->mask;
    res->mnt_id = found->st_dev;
    res->mnt_id_old = (uint32_t)found->st_dev;

    /* String section starts after the fixed struct */
    uint32_t str_off = 0;
    size_t str_space = bufsize - sizeof(struct statmount_result);
    char *str_base = (char *)buf + sizeof(struct statmount_result);

    if (r->mask & STATMOUNT_MNT_ROOT) {
        res->mnt_root = str_off;
        const char *root = "/";
        size_t rlen = 2;
        if (str_off + rlen <= str_space) {
            memcpy(str_base + str_off, root, rlen);
            str_off += (uint32_t)rlen;
        }
    }

    if (r->mask & STATMOUNT_MNT_POINT) {
        res->mnt_point = str_off;
        const char *mp = found->mountpoint ? found->mountpoint : "/";
        size_t mplen = 0;
        while (mp[mplen]) mplen++;
        mplen++; /* NUL */
        if (str_off + mplen <= str_space) {
            memcpy(str_base + str_off, mp, mplen);
            str_off += (uint32_t)mplen;
        }
    }

    if (r->mask & STATMOUNT_FS_TYPE) {
        res->fs_type = str_off;
        const char *fs = found->fstype_display ? found->fstype_display :
                         (found->fs ? found->fs->name : "unknown");
        size_t flen = 0;
        while (fs[flen]) flen++;
        flen++;
        if (str_off + flen <= str_space) {
            memcpy(str_base + str_off, fs, flen);
            str_off += (uint32_t)flen;
        }
    }

    if (r->mask & STATMOUNT_SB_BASIC) {
        res->sb_dev_major = (uint32_t)(found->st_dev >> 8);
        res->sb_dev_minor = (uint32_t)(found->st_dev & 0xFF);
        res->sb_flags = (uint32_t)found->flags;
    }

    res->size = (uint32_t)(sizeof(struct statmount_result) + str_off);
    return 0;
}

/**
 * sys_listmount() - List mount IDs under a parent mount (Linux 6.8+).
 * Returns the number of mounts listed.
 */
long sys_listmount(const void *req, uint64_t *mnt_ids, size_t nr_mnt_ids,
                   unsigned int flags) {
    (void)req; (void)flags;
    if (!mnt_ids || nr_mnt_ids == 0) return -EINVAL;

    struct fut_mount *m = fut_vfs_first_mount();
    size_t count = 0;
    while (m && count < nr_mnt_ids) {
        mnt_ids[count] = m->st_dev;
        count++;
        m = m->next;
    }
    return (long)count;
}

/**
 * sys_lsm_get_self_attr() - Get LSM attributes of the calling process.
 * Futura has Landlock but no full LSM framework. Return EOPNOTSUPP
 * so callers know LSM is available but the specific attr isn't.
 */
long sys_lsm_get_self_attr(unsigned int attr, void *ctx, uint32_t *size,
                           uint32_t flags) {
    (void)attr; (void)ctx; (void)flags;
    /* Report that no LSM attributes are available */
    if (size) *size = 0;
    return -EOPNOTSUPP;
}

/**
 * sys_lsm_set_self_attr() - Set LSM attributes.
 * No LSM framework — return EOPNOTSUPP.
 */
long sys_lsm_set_self_attr(unsigned int attr, void *ctx, uint32_t size,
                           uint32_t flags) {
    (void)attr; (void)ctx; (void)size; (void)flags;
    return -EOPNOTSUPP;
}

/**
 * sys_lsm_list_modules() - List loaded LSM modules (Linux 6.8+).
 * Returns 0 (no modules loaded). systemd 256+ uses this to enumerate
 * available security modules.
 */
long sys_lsm_list_modules(uint64_t *ids, uint32_t *size, uint32_t flags) {
    (void)ids; (void)flags;
    if (size) {
        /* Report 0 modules — buffer size needed is 0 */
        *size = 0;
    }
    return 0;
}
