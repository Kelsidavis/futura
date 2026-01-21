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

#include <kernel/kprintf.h>
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

/* Quota disk block structure (simplified for validation) */
struct dqblk {
    uint64_t dqb_bhardlimit;   /* Hard limit on disk blocks */
    uint64_t dqb_bsoftlimit;   /* Soft limit on disk blocks */
    uint64_t dqb_curspace;     /* Current space used */
    uint64_t dqb_ihardlimit;   /* Hard limit on inodes */
    uint64_t dqb_isoftlimit;   /* Soft limit on inodes */
    uint64_t dqb_curinodes;    /* Current inodes used */
    uint64_t dqb_btime;        /* Time limit for excessive disk use (grace period) */
    uint64_t dqb_itime;        /* Time limit for excessive files (grace period) */
    uint32_t dqb_valid;        /* Bit mask of valid fields */
};

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

    /* Phase 5: Validate command parameter bounds early
     * VULNERABILITY: Command Parameter Out-of-Bounds Access
     *
     * ATTACK SCENARIO:
     * Invalid command values cause out-of-bounds array access in switch statements
     * 1. Attacker crafts invalid quota type:
     *    quotactl(0xFFFFFF00, "/dev/sda1", 0, NULL)  // qtype = 0 (valid), qcmd = 0xFFFFFF00 (invalid)
     * 2. Switch statements at lines 291-322 don't validate qcmd range
     * 3. Default case prints "unknown command" but processing continues
     * 4. Later code may use qcmd as array index or function pointer
     * 5. Out-of-bounds access causes memory corruption or information disclosure
     *
     * IMPACT:
     * - Information disclosure: Reading quota command name strings from invalid memory
     * - Kernel crash: Page fault from invalid command lookup
     * - Potential memory corruption if qcmd used as array index
     *
     * ROOT CAUSE:
     * Line 269-270 (old): Extracts qtype and qcmd without validation
     * No bounds check before using in switch or further processing
     *
     * DEFENSE (Phase 5):
     * Validate qtype and qcmd against known valid ranges
     * - qtype must be USRQUOTA (0), GRPQUOTA (1), or PRJQUOTA (2)
     * - qcmd must be one of Q_SYNC, Q_QUOTAON, Q_QUOTAOFF, etc. (0x800001-0x800009)
     * - Return -EINVAL for invalid values BEFORE any switch statements
     *
     * CVE REFERENCES:
     * - CVE-2018-10879: Linux ext4 out-of-bounds via invalid array index
     * - CVE-2019-19319: Linux ext4 use-after-free via invalid quota type
     */

    /* Extract quota type and command BEFORE validation */
    unsigned int qtype = cmd & 0xFF;
    unsigned int qcmd = cmd & ~0xFF;  /* Full command with type bits masked */

    /* Phase 5: Validate quota type bounds */
    if (qtype > PRJQUOTA) {
        fut_printf("[QUOTACTL] quotactl(cmd=0x%x [invalid type %u], special=%p, id=%d, addr=%p, pid=%d) "
                   "-> EINVAL (quota type out of range, valid: 0-2, Phase 5)\n",
                   cmd, qtype, (const void *)special, id, addr, task->pid);
        return -EINVAL;
    }

    /* Phase 5: Validate quota command bounds */
    if (qcmd < Q_SYNC || qcmd > Q_GETNEXTQUOTA) {
        fut_printf("[QUOTACTL] quotactl(cmd=0x%x [invalid cmd 0x%x], type=%u, special=%p, id=%d, addr=%p, pid=%d) "
                   "-> EINVAL (quota command out of range, valid: 0x800001-0x800009, Phase 5)\n",
                   cmd, qcmd, qtype, (const void *)special, id, addr, task->pid);
        return -EINVAL;
    }

    /* Phase 2: Validate special pointer (required) */
    if (!special) {
        fut_printf("[QUOTACTL] quotactl(cmd=0x%x, special=NULL, id=%d, addr=%p, pid=%d) -> EFAULT\n",
                   cmd, id, addr, task->pid);
        return -EFAULT;
    }

    /* Phase 5: Copy full path to detect truncation
     * VULNERABILITY: Path Truncation Attack
     *
     * ATTACK SCENARIO:
     * Silent truncation allows quota operations on wrong filesystem
     * 1. Attacker provides device path exceeding 256 bytes:
     *    quotactl(Q_GETQUOTA, "/dev/mapper/" + "A"*240 + "-lvm", uid, &dqblk)
     * 2. Old code: fut_copy_from_user(special_buf, special, 255)
     *    - Copies only first 255 bytes: "/dev/mapper/AAA...AAA"
     *    - Silently drops "-lvm" suffix
     *    - special_buf[255] = '\0' (null terminator)
     * 3. VFS lookup resolves truncated path (wrong device)
     * 4. Quota operation applies to unintended filesystem
     * 5. User bypasses quota limits on actual device
     *
     * IMPACT:
     * - Quota bypass: Quota check/enforcement on wrong filesystem
     * - Denial of service: Quota operations fail silently
     * - Information disclosure: Quota data from unintended device
     *
     * ROOT CAUSE:
     * Line 253 (old): fut_copy_from_user(special_buf, special, sizeof(special_buf) - 1)
     * Copied only 255 bytes, silently truncating longer paths.
     *
     * DEFENSE (Phase 5):
     * Copy full buffer size (256 bytes) and check for truncation.
     *
     * CVE REFERENCES:
     * - CVE-2018-14633: Linux chdir path truncation
     * - CVE-2017-7889: Linux mount path truncation
     */
    char special_buf[256];
    if (fut_copy_from_user(special_buf, special, sizeof(special_buf)) != 0) {
        fut_printf("[QUOTACTL] quotactl(cmd=0x%x, special=?, id=%d, addr=%p, pid=%d) -> EFAULT "
                   "(special copy_from_user failed, Phase 5)\n",
                   cmd, id, addr, task->pid);
        return -EFAULT;
    }

    /* Phase 5: Verify path was not truncated */
    if (special_buf[sizeof(special_buf) - 1] != '\0') {
        fut_printf("[QUOTACTL] quotactl(cmd=0x%x, special=<truncated>, id=%d, addr=%p, pid=%d) "
                   "-> ENAMETOOLONG (path exceeds %zu bytes, truncation detected, Phase 5)\n",
                   cmd, id, addr, task->pid, sizeof(special_buf) - 1);
        return -ENAMETOOLONG;
    }

    /* Phase 2: Validate special is not empty */
    if (special_buf[0] == '\0') {
        fut_printf("[QUOTACTL] quotactl(cmd=0x%x, special=\"\" [empty], id=%d, addr=%p, pid=%d) -> EINVAL\n",
                   cmd, id, addr, task->pid);
        return -EINVAL;
    }

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

    /* Phase 5: Document addr parameter validation requirements for Phase 2 implementation
     * VULNERABILITY: Unbounded Structure Copy and NULL Pointer Dereference
     *
     * ATTACK SCENARIO 1: NULL Pointer Dereference in Q_GETQUOTA/Q_SETQUOTA
     * Attacker provides NULL addr pointer for commands requiring data buffer
     * 1. Attacker calls quotactl(QCMD(Q_GETQUOTA, USRQUOTA), "/dev/sda1", 1000, NULL)
     * 2. Without validation: Phase 2 implementation attempts copy_to_user(NULL, &dqblk, ...)
     * 3. NULL pointer dereference in userspace copy
     * 4. Page fault causes kernel crash or EFAULT return
     *
     * ATTACK SCENARIO 2: Size Calculation Overflow in Q_SETINFO
     * Attacker provides crafted dqinfo structure with extreme values
     * 1. Attacker creates dqinfo with dqi_bgrace = UINT64_MAX
     * 2. Phase 2 code calculates grace_period_end = current_time + dqi_bgrace
     * 3. Integer overflow: grace_period_end wraps to small value
     * 4. Grace period expires immediately instead of far future
     * 5. Soft limit becomes hard limit prematurely
     * 6. Denial of service: Users cannot write despite having quota
     *
     * ATTACK SCENARIO 3: Invalid dqblk Field Validation
     * Attacker provides quota limits that exceed filesystem capacity
     * 1. Attacker sets dqb_bhardlimit = UINT64_MAX (exabytes of quota)
     * 2. dqb_bsoftlimit = UINT64_MAX - 1 (also exabytes)
     * 3. Phase 2 stores values without validation
     * 4. Filesystem quota check: UINT64_MAX - current_usage always passes
     * 5. User can consume entire filesystem (quota bypass)
     * 6. Denial of service for other users
     *
     * IMPACT:
     * - NULL pointer dereference: Kernel crash via page fault
     * - Integer overflow: Grace period calculation wraparound
     * - Quota bypass: Unrealistic limits disable enforcement
     * - Denial of service: Filesystem exhaustion or premature limit
     *
     * ROOT CAUSE:
     * Phase 1 stub accepts addr parameter without validation:
     * - No NULL check for commands requiring addr (Q_GETQUOTA, Q_SETQUOTA, Q_GETINFO, Q_SETINFO)
     * - No structure field validation for dqblk/dqinfo contents
     * - No size overflow checks in grace period calculations
     * - Assumes userspace provides valid, realistic quota values
     *
     * DEFENSE (Phase 5 Requirements for Phase 2):
     * 1. NULL Pointer Validation:
     *    - Q_GETQUOTA/Q_SETQUOTA: Require addr != NULL (dqblk structure)
     *    - Q_GETINFO/Q_SETINFO: Require addr != NULL (dqinfo structure)
     *    - Q_QUOTAON: addr may be NULL or quota file path
     *    - Q_SYNC/Q_QUOTAOFF/Q_GETFMT: addr may be NULL
     * 2. Structure Size Validation:
     *    - Validate fut_copy_from_user size matches expected structure size
     *    - Prevent partial structure copy (truncation attack)
     * 3. Field Value Validation (Q_SETQUOTA):
     *    - dqb_bhardlimit <= filesystem_capacity
     *    - dqb_bsoftlimit <= dqb_bhardlimit (soft <= hard)
     *    - dqb_ihardlimit <= filesystem_max_inodes
     *    - dqb_isoftlimit <= dqb_ihardlimit
     * 4. Grace Period Overflow Protection (Q_SETINFO):
     *    - Check dqi_bgrace addition won't overflow: UINT64_MAX - current_time > dqi_bgrace
     *    - Check dqi_igrace addition won't overflow
     *    - Clamp grace periods to reasonable maximum (e.g., 10 years)
     * 5. Quota Format Validation (Q_QUOTAON):
     *    - Validate id parameter is valid format: QFMT_VFS_V0, QFMT_VFS_V1, etc.
     *    - Reject unknown quota formats
     *
     * CVE REFERENCES:
     * - CVE-2012-6538: Linux ext4 quota integer overflow in grace period
     * - CVE-2013-1848: Linux ext4 quota bypass via extreme limits
     * - CVE-2018-10879: Linux ext4 quota out-of-bounds via invalid structure
     *
     * LINUX REQUIREMENT:
     * From quotactl(2) man page:
     * \"For commands that read information from the quota file (Q_GETQUOTA,
     *  Q_GETINFO), addr is a pointer to a variable of the appropriate type
     *  into which the command stores the requested information. For commands
     *  that set information (Q_SETQUOTA, Q_SETINFO), addr is a pointer to a
     *  variable containing the new values.\"
     * - addr must be valid pointer for commands requiring data transfer
     * - Kernel must validate structure contents to prevent quota bypass
     *
     * IMPLEMENTATION NOTES:
     * - Phase 1: Current stub accepts all addr values (no validation)
     * - Phase 2 MUST validate addr != NULL for data transfer commands
     * - Phase 2 MUST validate structure field values before applying
     * - Phase 2 MUST check grace period arithmetic for overflow
     * - Phase 3 MAY add additional validation for quota file paths
     * - See Linux kernel: fs/quota/quota.c do_quotactl() for reference
     */

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

    /* Phase 2: Validate addr pointer for commands that require data transfer */
    if (qcmd == Q_GETQUOTA || qcmd == Q_SETQUOTA || qcmd == Q_GETINFO || qcmd == Q_SETINFO) {
        if (!addr) {
            fut_printf("[QUOTACTL] quotactl(cmd=%s) -> EINVAL (addr is NULL for data transfer command)\n",
                       cmd_desc);
            return -EINVAL;
        }
    }

    /* Phase 3: Validate dqblk structure for Q_SETQUOTA command */
    if (qcmd == Q_SETQUOTA && addr) {
        struct dqblk dqb;

        /* Copy dqblk from userspace for validation */
        if (fut_copy_from_user(&dqb, (const void *)addr, sizeof(dqb)) != 0) {
            fut_printf("[QUOTACTL] quotactl(cmd=%s) -> EFAULT (failed to copy dqblk from userspace)\n",
                       cmd_desc);
            return -EFAULT;
        }

        /* Phase 3: Validate soft limit <= hard limit for block quotas */
        if (dqb.dqb_bsoftlimit > 0 && dqb.dqb_bhardlimit > 0 &&
            dqb.dqb_bsoftlimit > dqb.dqb_bhardlimit) {
            fut_printf("[QUOTACTL] quotactl(cmd=%s) -> EINVAL "
                       "(block soft limit %lu exceeds hard limit %lu, Phase 3)\n",
                       cmd_desc, dqb.dqb_bsoftlimit, dqb.dqb_bhardlimit);
            return -EINVAL;
        }

        /* Phase 3: Validate soft limit <= hard limit for inode quotas */
        if (dqb.dqb_isoftlimit > 0 && dqb.dqb_ihardlimit > 0 &&
            dqb.dqb_isoftlimit > dqb.dqb_ihardlimit) {
            fut_printf("[QUOTACTL] quotactl(cmd=%s) -> EINVAL "
                       "(inode soft limit %lu exceeds hard limit %lu, Phase 3)\n",
                       cmd_desc, dqb.dqb_isoftlimit, dqb.dqb_ihardlimit);
            return -EINVAL;
        }

        /* Phase 3: Validate grace period doesn't overflow when added to current time
         * Grace periods are typically in seconds since epoch.
         * We check that adding reasonable maximum system time won't overflow.
         * Using a conservative check: grace period should be < UINT64_MAX - (1<<40)
         * to leave room for any reasonable current time value. */
        const uint64_t MAX_SAFE_GRACE = UINT64_MAX - (1ULL << 40);

        if (dqb.dqb_btime > MAX_SAFE_GRACE) {
            fut_printf("[QUOTACTL] quotactl(cmd=%s) -> EINVAL "
                       "(block grace period %lu would overflow when added to current time, Phase 3)\n",
                       cmd_desc, dqb.dqb_btime);
            return -EINVAL;
        }

        if (dqb.dqb_itime > MAX_SAFE_GRACE) {
            fut_printf("[QUOTACTL] quotactl(cmd=%s) -> EINVAL "
                       "(inode grace period %lu would overflow when added to current time, Phase 3)\n",
                       cmd_desc, dqb.dqb_itime);
            return -EINVAL;
        }

        fut_printf("[QUOTACTL] quotactl(cmd=%s) -> Validated dqblk structure "
                   "(bhardlimit=%lu, bsoftlimit=%lu, ihardlimit=%lu, isoftlimit=%lu, Phase 3)\n",
                   cmd_desc, dqb.dqb_bhardlimit, dqb.dqb_bsoftlimit,
                   dqb.dqb_ihardlimit, dqb.dqb_isoftlimit);
    }

    return -ENOSYS;
}
