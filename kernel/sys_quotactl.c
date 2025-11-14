/* kernel/sys_quotactl.c - Disk quota control syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements quotactl for managing filesystem quotas.
 * Essential for multi-user systems with disk space limits.
 *
 * Phase 1 (Completed): Validation and stub implementation
 * Phase 2 (Completed): Enhanced validation, copy_from_user, command/type categorization
 * Phase 3 (Completed): Command and type categorization with detailed logging
 * Phase 4: Advanced features (grace periods, warnings)
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <stdint.h>
#include <stddef.h>

extern void fut_printf(const char *fmt, ...);
extern int fut_copy_from_user(void *to, const void *from, size_t size);

/* Quota commands (high-level operations) */
#define Q_SYNC       0x800001  /* Sync disk copy of quota */
#define Q_QUOTAON    0x800002  /* Turn quotas on */
#define Q_QUOTAOFF   0x800003  /* Turn quotas off */
#define Q_GETFMT     0x800004  /* Get quota format used */
#define Q_GETINFO    0x800005  /* Get information about quota files */
#define Q_SETINFO    0x800006  /* Set information about quota files */
#define Q_GETQUOTA   0x800007  /* Get quota for user */
#define Q_SETQUOTA   0x800008  /* Set quota for user */
#define Q_GETNEXTQUOTA 0x800009 /* Get next active quota */

/* Quota types */
#define USRQUOTA     0         /* User quota */
#define GRPQUOTA     1         /* Group quota */
#define PRJQUOTA     2         /* Project quota */

/* Quota formats */
#define QFMT_VFS_OLD 1         /* Old quota format */
#define QFMT_VFS_V0  2         /* Quota format v0 */
#define QFMT_VFS_V1  4         /* Quota format v1 */

/**
 * quotactl() - Manipulate disk quotas
 *
 * Performs quota operations on a filesystem. Allows querying, setting,
 * enabling, and disabling disk quotas for users and groups. Essential
 * for multi-user systems that need to limit disk space usage.
 *
 * @param cmd     Quota command and type (e.g., Q_QUOTAON, Q_GETQUOTA)
 * @param special Block device or mount point
 * @param id      User ID or group ID (for Q_GETQUOTA/Q_SETQUOTA)
 * @param addr    Command-specific data pointer
 *
 * Returns:
 *   - 0 on success
 *   - -EACCES if permission denied (requires CAP_SYS_ADMIN for most operations)
 *   - -EFAULT if special or addr points to invalid memory
 *   - -EINVAL if cmd is invalid
 *   - -ENOENT if quota file doesn't exist
 *   - -ENOSYS if quotas not supported on filesystem
 *   - -ESRCH if specified user has no quota
 *
 * Usage:
 *   struct dqblk dq;
 *
 *   // Get user quota
 *   quotactl(QCMD(Q_GETQUOTA, USRQUOTA), "/dev/sda1", 1000, (caddr_t)&dq);
 *   printf("User 1000 blocks: %lld/%lld\n", dq.dqb_curspace, dq.dqb_bsoftlimit);
 *
 *   // Set user quota
 *   dq.dqb_bsoftlimit = 10485760;  // 10GB soft limit
 *   dq.dqb_bhardlimit = 12582912;  // 12GB hard limit
 *   quotactl(QCMD(Q_SETQUOTA, USRQUOTA), "/dev/sda1", 1000, (caddr_t)&dq);
 *
 *   // Turn on user quotas
 *   quotactl(QCMD(Q_QUOTAON, USRQUOTA), "/dev/sda1", QFMT_VFS_V1, "aquota.user");
 *
 *   // Turn off group quotas
 *   quotactl(QCMD(Q_QUOTAOFF, GRPQUOTA), "/dev/sda1", 0, NULL);
 *
 * Command macro:
 *   #define QCMD(cmd, type) (((cmd) << 8) | ((type) & 0xFF))
 *
 * Quota commands:
 * - Q_SYNC: Write quota changes to disk
 * - Q_QUOTAON: Enable quota enforcement
 * - Q_QUOTAOFF: Disable quota enforcement
 * - Q_GETFMT: Query quota format version
 * - Q_GETINFO: Get quota file information (grace periods, etc.)
 * - Q_SETINFO: Set quota file information
 * - Q_GETQUOTA: Query user/group quota limits and usage
 * - Q_SETQUOTA: Set user/group quota limits
 * - Q_GETNEXTQUOTA: Iterate over quota entries
 *
 * Quota structure (simplified):
 * ```c
 * struct dqblk {
 *     uint64_t dqb_bhardlimit; // Hard limit on disk blocks
 *     uint64_t dqb_bsoftlimit; // Soft limit on disk blocks
 *     uint64_t dqb_curspace;   // Current space used
 *     uint64_t dqb_ihardlimit; // Hard limit on inodes
 *     uint64_t dqb_isoftlimit; // Soft limit on inodes
 *     uint64_t dqb_curinodes;  // Current inodes used
 *     uint64_t dqb_btime;      // Time limit for excessive disk use
 *     uint64_t dqb_itime;      // Time limit for excessive files
 *     uint32_t dqb_valid;      // Bit mask of valid fields
 * };
 * ```
 *
 * Quota types:
 * - USRQUOTA (0): Per-user quotas
 * - GRPQUOTA (1): Per-group quotas
 * - PRJQUOTA (2): Per-project quotas (XFS)
 *
 * Common use cases:
 * - System administration: Limit user disk space
 *   ```c
 *   // Set 5GB soft limit, 10GB hard limit for user 1000
 *   struct dqblk dq = {0};
 *   dq.dqb_bsoftlimit = 5 * 1024 * 1024 * 1024 / 1024; // blocks
 *   dq.dqb_bhardlimit = 10 * 1024 * 1024 * 1024 / 1024;
 *   dq.dqb_valid = QIF_LIMITS;
 *   quotactl(QCMD(Q_SETQUOTA, USRQUOTA), "/home", 1000, (caddr_t)&dq);
 *   ```
 *
 * - Quota tools: Report disk usage
 *   ```c
 *   // repquota - report all user quotas
 *   for (uid = 0; uid < MAX_UID; uid++) {
 *       if (quotactl(QCMD(Q_GETQUOTA, USRQUOTA), "/dev/sda1", uid, &dq) == 0) {
 *           printf("User %d: %lld/%lld blocks\n", uid, dq.dqb_curspace, dq.dqb_bsoftlimit);
 *       }
 *   }
 *   ```
 *
 * - Quota enforcement: Check before allowing writes
 *   ```c
 *   // File server checking quota before write
 *   struct dqblk dq;
 *   quotactl(QCMD(Q_GETQUOTA, USRQUOTA), "/data", user_id, &dq);
 *   if (dq.dqb_curspace + write_size > dq.dqb_bhardlimit) {
 *       return -EDQUOT;  // Disk quota exceeded
 *   }
 *   ```
 *
 * Soft vs hard limits:
 * - Soft limit: Can be exceeded temporarily (grace period)
 * - Hard limit: Absolute maximum (cannot be exceeded)
 * - Grace period: Time allowed to exceed soft limit
 * - After grace period expires, soft limit becomes hard limit
 *
 * Security considerations:
 * - Most operations require CAP_SYS_ADMIN capability
 * - Q_GETQUOTA may be allowed for users querying their own quota
 * - Quota files must be protected (root-owned, mode 600)
 * - Incorrect quotas can cause denial of service
 *
 * Filesystem support:
 * - ext4: Full quota support (user, group, project)
 * - XFS: Full quota support with project quotas
 * - btrfs: Limited quota support (subvolume quotas)
 * - Other filesystems may not support quotas
 *
 * Quota files:
 * - aquota.user: User quota file
 * - aquota.group: Group quota file
 * - Located at filesystem root
 * - Binary format (not human-readable)
 * - Created by quotacheck utility
 *
 * Grace periods:
 * - Default: 7 days for blocks, 7 days for inodes
 * - Can be customized with Q_SETINFO
 * - Enforced by filesystem at write time
 * - Users notified when approaching limits
 *
 * Quota utilities:
 * - quota: Display user/group quotas
 * - quotaon/quotaoff: Enable/disable quotas
 * - quotacheck: Scan filesystem and update quota files
 * - edquota: Edit user quotas
 * - repquota: Report all quotas for filesystem
 * - setquota: Set quotas from command line
 * - warnquota: Send email warnings to users over quota
 *
 * Typical quota setup:
 * ```bash
 * # Edit /etc/fstab to enable quotas
 * /dev/sda1 /home ext4 defaults,usrquota,grpquota 0 2
 *
 * # Remount with quota options
 * mount -o remount /home
 *
 * # Create quota files
 * quotacheck -cug /home
 *
 * # Turn on quotas
 * quotaon /home
 *
 * # Set quota for user
 * edquota -u username
 * ```
 *
 * Error conditions:
 * - EACCES: Permission denied (need CAP_SYS_ADMIN)
 * - EBUSY: Quota files in use
 * - EDQUOT: Disk quota exceeded (different context)
 * - EFAULT: Invalid addr pointer
 * - EINVAL: Invalid command
 * - ENOENT: Quota file doesn't exist
 * - ENOSYS: Filesystem doesn't support quotas
 * - ESRCH: User has no quota
 *
 * Performance considerations:
 * - Quota checks add overhead to write operations
 * - Quotas cached in memory (not checked on every write)
 * - Q_SYNC forces write to disk (slow)
 * - Large filesystems may have slow quota scans
 *
 * Quota enforcement:
 * - Checked at write time by filesystem
 * - Returns EDQUOT if quota exceeded
 * - Applies to: file writes, file creation, directory creation
 * - Does not apply to: metadata, already-allocated space
 *
 * Historical notes:
 * - Introduced in BSD Unix (4.2BSD, 1983)
 * - Linux implementation added in 1990s
 * - Multiple quota formats over time (v0, v1, v2)
 * - Still widely used on multi-user systems
 *
 * Phase 1: Validate parameters and return -ENOSYS
 * Phase 2: Implement basic quota query (Q_GETQUOTA)
 * Phase 3: Full quota management (set, enable, disable)
 */
long sys_quotactl(unsigned int cmd, const char *special, int id, void *addr) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    /* Phase 2: Validate special pointer (required) */
    if (!special) {
        fut_printf("[QUOTACTL] quotactl(cmd=0x%x, special=NULL, id=%d, addr=%p, pid=%d) -> EFAULT\n",
                   cmd, id, addr, task->pid);
        return -EFAULT;
    }

    /* Phase 2: Copy special from userspace to validate it */
    char special_buf[256];
    if (fut_copy_from_user(special_buf, special, sizeof(special_buf) - 1) != 0) {
        fut_printf("[QUOTACTL] quotactl(cmd=0x%x, special=?, id=%d, addr=%p, pid=%d) -> EFAULT "
                   "(special copy_from_user failed)\n",
                   cmd, id, addr, task->pid);
        return -EFAULT;
    }
    special_buf[sizeof(special_buf) - 1] = '\0';

    /* Phase 2: Validate special is not empty */
    if (special_buf[0] == '\0') {
        fut_printf("[QUOTACTL] quotactl(cmd=0x%x, special=\"\" [empty], id=%d, addr=%p, pid=%d) -> EINVAL\n",
                   cmd, id, addr, task->pid);
        return -EINVAL;
    }

    /* Extract quota type and command */
    unsigned int qtype = cmd & 0xFF;
    unsigned int qcmd = cmd & ~0xFF;  /* Full command with type bits masked */

    /* Categorize quota type */
    const char *type_desc;
    switch (qtype) {
        case USRQUOTA:
            type_desc = "user quota";
            break;
        case GRPQUOTA:
            type_desc = "group quota";
            break;
        case PRJQUOTA:
            type_desc = "project quota";
            break;
        default:
            type_desc = "unknown type";
            break;
    }

    /* Categorize command */
    const char *cmd_desc;
    switch (qcmd) {
        case Q_SYNC:
            cmd_desc = "Q_SYNC (sync quotas)";
            break;
        case Q_QUOTAON:
            cmd_desc = "Q_QUOTAON (enable)";
            break;
        case Q_QUOTAOFF:
            cmd_desc = "Q_QUOTAOFF (disable)";
            break;
        case Q_GETFMT:
            cmd_desc = "Q_GETFMT (get format)";
            break;
        case Q_GETINFO:
            cmd_desc = "Q_GETINFO (get info)";
            break;
        case Q_SETINFO:
            cmd_desc = "Q_SETINFO (set info)";
            break;
        case Q_GETQUOTA:
            cmd_desc = "Q_GETQUOTA (get quota)";
            break;
        case Q_SETQUOTA:
            cmd_desc = "Q_SETQUOTA (set quota)";
            break;
        case Q_GETNEXTQUOTA:
            cmd_desc = "Q_GETNEXTQUOTA (get next)";
            break;
        default:
            cmd_desc = "unknown command";
            break;
    }

    /* Phase 3: Enhanced logging with parameter categorization and buffer contents */
    if (qcmd == Q_GETQUOTA || qcmd == Q_SETQUOTA) {
        /* Commands that use id parameter */
        fut_printf("[QUOTACTL] quotactl(cmd=%s, type=%s, special='%s', id=%d, addr=%p, pid=%d) -> ENOSYS "
                   "(Phase 3: command and type categorization)\n",
                   cmd_desc, type_desc, special_buf, id, addr, task->pid);
    } else {
        /* Commands that don't use id parameter */
        fut_printf("[QUOTACTL] quotactl(cmd=%s, type=%s, special='%s', addr=%p, pid=%d) -> ENOSYS "
                   "(Phase 3: command and type categorization)\n",
                   cmd_desc, type_desc, special_buf, addr, task->pid);
    }

    return -ENOSYS;
}
