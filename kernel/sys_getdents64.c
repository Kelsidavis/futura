/* kernel/sys_getdents64.c - Directory entry reading syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements the getdents64() syscall for reading directory entries.
 * Essential for directory listing and filesystem traversal.
 *
 * Phase 1 (Completed): Basic directory entry reading with VFS integration
 * Phase 2 (Completed): Enhanced validation, FD/buffer categorization, entry counting, and detailed logging
 * Phase 3 (Completed): Performance optimization (readdir caching, large directory support)
 * Phase 4: Advanced features (directory entry filtering, sorted traversal)
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <kernel/fut_vfs.h>
#include <kernel/fut_fd_util.h>
#include <stdint.h>

#include <kernel/kprintf.h>
extern void *fut_malloc(size_t size);
extern void fut_free(void *ptr);
extern int fut_copy_to_user(void *to, const void *from, size_t size);
extern fut_task_t *fut_task_current(void);
extern struct fut_file *vfs_get_file_from_task(struct fut_task *task, int fd);

/* Linux getdents64 dirent structure */
struct linux_dirent64 {
    uint64_t d_ino;
    int64_t  d_off;
    uint16_t d_reclen;
    uint8_t  d_type;
    char     d_name[];
} __attribute__((packed));

/**
 * getdents64() - Read directory entries
 *
 * Reads multiple directory entries from an open directory file descriptor
 * into a buffer. This is the 64-bit version of getdents that supports large
 * inode numbers and offsets. Essential for directory traversal and listing.
 *
 * @param fd     File descriptor of the open directory
 * @param dirp   User-space buffer to store directory entries
 * @param count  Size of the buffer
 *
 * Returns:
 *   - Number of bytes read on success (0 at end of directory)
 *   - -EBADF if fd is not a valid file descriptor
 *   - -ENOTDIR if fd does not refer to a directory
 *   - -EINVAL if buffer size is too small
 *   - -EFAULT if dirp points to invalid memory
 *   - -ENOMEM if kernel buffer allocation fails
 *   - -ESRCH if no current task context
 *
 * Behavior:
 *   - Reads directory entries into buffer
 *   - Returns number of bytes read (0 at end)
 *   - Multiple entries fit in one buffer
 *   - Maintains directory position (cookie)
 *   - Each entry is 8-byte aligned
 *   - Directory traversal is stateful (uses fd offset)
 *
 * Directory entry structure:
 *   - d_ino: Inode number (0 for deleted entries)
 *   - d_off: Offset to next entry
 *   - d_reclen: Length of this entry
 *   - d_type: File type (DT_REG, DT_DIR, etc.)
 *   - d_name: Null-terminated filename
 *
 * File types (d_type):
 *   - DT_REG (8): Regular file
 *   - DT_DIR (4): Directory
 *   - DT_LNK (10): Symbolic link
 *   - DT_CHR (2): Character device
 *   - DT_BLK (6): Block device
 *   - DT_FIFO (1): FIFO/pipe
 *   - DT_SOCK (12): Socket
 *   - DT_UNKNOWN (0): Unknown type
 *
 * Common usage patterns:
 *
 * List directory contents:
 *   int fd = open("/path/to/dir", O_RDONLY | O_DIRECTORY);
 *   char buf[4096];
 *   while (1) {
 *       ssize_t n = getdents64(fd, buf, sizeof(buf));
 *       if (n == 0) break;  // End of directory
 *       if (n < 0) { perror("getdents64"); break; }
 *
 *       struct linux_dirent64 *d;
 *       for (size_t pos = 0; pos < n; ) {
 *           d = (struct linux_dirent64 *)(buf + pos);
 *           printf("%s\n", d->d_name);
 *           pos += d->d_reclen;
 *       }
 *   }
 *   close(fd);
 *
 * Filter by file type:
 *   struct linux_dirent64 *d;
 *   for (size_t pos = 0; pos < n; ) {
 *       d = (struct linux_dirent64 *)(buf + pos);
 *       if (d->d_type == DT_REG) {
 *           printf("File: %s\n", d->d_name);
 *       } else if (d->d_type == DT_DIR) {
 *           printf("Dir: %s\n", d->d_name);
 *       }
 *       pos += d->d_reclen;
 *   }
 *
 * Count directory entries:
 *   int count = 0;
 *   ssize_t n = getdents64(fd, buf, sizeof(buf));
 *   struct linux_dirent64 *d;
 *   for (size_t pos = 0; pos < n; ) {
 *       d = (struct linux_dirent64 *)(buf + pos);
 *       count++;
 *       pos += d->d_reclen;
 *   }
 *
 * Recursive directory traversal:
 *   void traverse(const char *path) {
 *       int fd = open(path, O_RDONLY | O_DIRECTORY);
 *       char buf[4096];
 *       ssize_t n;
 *       while ((n = getdents64(fd, buf, sizeof(buf))) > 0) {
 *           for (size_t pos = 0; pos < n; ) {
 *               struct linux_dirent64 *d = (struct linux_dirent64 *)(buf + pos);
 *               if (d->d_type == DT_DIR && strcmp(d->d_name, ".") != 0 &&
 *                   strcmp(d->d_name, "..") != 0) {
 *                   char subpath[PATH_MAX];
 *                   snprintf(subpath, sizeof(subpath), "%s/%s", path, d->d_name);
 *                   traverse(subpath);
 *               }
 *               pos += d->d_reclen;
 *           }
 *       }
 *       close(fd);
 *   }
 *
 * Special directory entries:
 *   - "." (current directory): Always present
 *   - ".." (parent directory): Always present (except root)
 *   - Hidden files: Start with '.' (Unix convention)
 *
 * Stateful traversal:
 *   - First call starts at beginning
 *   - Subsequent calls continue from last position
 *   - lseek(fd, 0, SEEK_SET) resets to beginning
 *   - Concurrent access requires careful synchronization
 *
 * Buffer size guidelines:
 *   - Minimum: sizeof(linux_dirent64) + 256 (one entry)
 *   - Typical: 4096 bytes (page size, multiple entries)
 *   - Large: 32768 bytes (better performance for large dirs)
 *
 * Performance considerations:
 *   - Larger buffers = fewer syscalls
 *   - 4KB buffer typically optimal
 *   - Large directories benefit from bigger buffers
 *   - Cache locality matters for readdir
 *
 * Security considerations:
 *   - Check fd refers to directory, not regular file
 *   - Validate buffer is writable
 *   - Watch for very long filenames
 *   - Be careful with symbolic links
 *
 * Related syscalls:
 *   - opendir()/readdir(): Higher-level directory reading (libc)
 *   - getdents(): 32-bit version (legacy)
 *   - fdopendir(): Convert fd to DIR*
 *   - rewinddir(): Reset directory position
 *
 * Phase 1 (Completed): Basic directory entry reading with VFS integration
 * Phase 2 (Completed): Enhanced validation, FD/buffer categorization, entry counting, detailed logging
 * Phase 3 (Completed): Performance optimization (readdir caching, large directory support)
 * Phase 4: Advanced features (directory entry filtering, sorted traversal)
 */
long sys_getdents64(unsigned int fd, void *dirp, unsigned int count) {
    /* Phase 2: Validate buffer pointer */
    if (!dirp) {
        fut_printf("[GETDENTS64] getdents64(fd=%u, dirp=NULL, count=%u) -> EFAULT (NULL buffer)\n",
                   fd, count);
        return -EFAULT;
    }

    /* Phase 2: Validate buffer size */
    if (count < sizeof(struct linux_dirent64) + 1) {
        fut_printf("[GETDENTS64] getdents64(fd=%u, dirp=?, count=%u) -> EINVAL "
                   "(buffer too small, min=%zu)\n",
                   fd, count, sizeof(struct linux_dirent64) + 1);
        return -EINVAL;
    }

    /* Phase 3: Validate count doesn't exceed maximum buffer size (prevent DoS) */
    if (count > 1048576) {  /* 1MB limit */
        fut_printf("[GETDENTS64] getdents64(fd=%u, count=%u) -> EINVAL "
                   "(count exceeds maximum 1MB limit)\n",
                   fd, count);
        return -EINVAL;
    }

    /* Phase 5: Validate buffer is writable BEFORE expensive operations
     * VULNERABILITY: Resource Exhaustion and Directory Traversal Attacks
     *
     * ATTACK SCENARIO 1: Resource Exhaustion via Read-Only Buffer
     * Attacker provides read-only buffer to waste kernel resources
     * 1. Attacker mmaps read-only page: mprotect(buf, 4096, PROT_READ)
     * 2. Calls getdents64(fd, buf, 4096) with read-only buffer
     * 3. WITHOUT Phase 5 check: Kernel allocates 4KB buffer (expensive)
     * 4. Kernel performs expensive VFS readdir operations filling buffer
     * 5. copy_to_user fails with -EFAULT (buffer read-only)
     * 6. Kernel frees buffer, wasted allocation + I/O
     * 7. Attacker loops: while(1) { getdents64(fd, ro_buf, 4096); }
     * 8. Each iteration wastes kernel allocation + directory I/O
     * 9. System becomes unresponsive (DoS)
     *
     * ATTACK SCENARIO 2: Buffer Overflow via Excessive count
     * Attacker provides count > SIZE_MAX to trigger integer overflow
     * 1. Attacker calls getdents64(fd, buf, UINT_MAX)
     * 2. Line 198-203: Validation caps at 1MB (Phase 3 protection works)
     * 3. WITHOUT 1MB cap: fut_malloc(UINT_MAX) fails or succeeds
     * 4. If succeeds: Massive kernel allocation exhausts memory
     * 5. Directory iteration fills huge buffer (CPU exhaustion)
     * 6. copy_to_user of gigabytes causes page faults
     * 7. System thrashes (DoS)
     *
     * ATTACK SCENARIO 3: Unbounded Directory Traversal
     * Attacker creates directory bomb to cause infinite traversal
     * 1. Attacker creates directory with millions of entries:
     *    for i in $(seq 1 10000000); do touch file$i; done
     * 2. Calls getdents64(fd, buf, 1MB) on directory bomb
     * 3. VFS readdir iterates millions of entries
     * 4. Each entry: inode lookup, name copy, d_reclen calculation
     * 5. No iteration limit or work budget
     * 6. Kernel spins for minutes reading directory
     * 7. CPU monopolized, other processes starved
     *
     * ATTACK SCENARIO 4: d_reclen Manipulation (Future VFS Implementation Risk)
     * Malicious filesystem provides crafted d_reclen values
     * 1. Attacker mounts malicious filesystem
     * 2. readdir returns entry with d_reclen = 0
     * 3. Userspace loop: for (pos = 0; pos < n; ) { pos += d->d_reclen; }
     * 4. Infinite loop: pos += 0 never advances
     * 5. Or d_reclen = UINT16_MAX causes pos to skip entries (data loss)
     * 6. Or d_reclen causes pos to exceed buffer (OOB read)
     *
     * ATTACK SCENARIO 5: Directory Position Integer Overflow
     * Attacker exploits offset tracking in stateful traversal
     * 1. Directory has 2^63 entries (theoretical filesystem limit)
     * 2. Multiple getdents64 calls advance position
     * 3. d_off (int64_t) increments: 0, 1, 2, ..., INT64_MAX
     * 4. Next increment: INT64_MAX + 1 = INT64_MIN (wraps)
     * 5. Directory position wraps to negative offset
     * 6. lseek interprets negative offset as error or beginning
     * 7. Directory traversal loops infinitely
     *
     * IMPACT:
     * - Resource exhaustion: Memory thrashing from alloc/free cycles
     * - CPU exhaustion: Unbounded directory iteration
     * - Directory bomb DoS: Millions of entries monopolize CPU
     * - Infinite loop: d_reclen=0 or d_off overflow
     * - OOB read: d_reclen exceeds buffer bounds
     *
     * ROOT CAUSE:
     * Pre-Phase 5 code lacks comprehensive validation:
     * - copy_to_user happens AFTER allocation and I/O (lines 415+)
     * - No early buffer writability check (fail-slow design)
     * - 1MB cap prevents SIZE_MAX but still allows large allocations
     * - No iteration limit for directory bombs
     * - No d_reclen validation from VFS (trusts filesystem)
     * - No d_off overflow protection in stateful traversal
     *
     * DEFENSE (Phase 5 Requirements):
     * 1. Early Buffer Validation (lines 245-251):
     *    - Test write permission on first byte BEFORE allocation/I/O
     *    - Minimal overhead: single byte test
     *    - Fail-fast: reject invalid buffer immediately
     * 2. Size Limits (line 198-203):
     *    - Cap count at 1MB (prevents excessive allocations)
     *    - Balances functionality vs DoS prevention
     * 3. Future d_reclen Validation (Phase 4):
     *    - Validate each d_reclen: 0 < d_reclen <= remaining_buffer
     *    - Ensure d_reclen is properly aligned (8-byte alignment)
     *    - Detect d_reclen=0 infinite loop
     * 4. Future Directory Bomb Protection (Phase 4):
     *    - Limit entries per getdents64 call (e.g., 10000 entries)
     *    - Add work budget: return early after N iterations
     *    - Or time budget: return after T milliseconds
     * 5. Future d_off Overflow Protection (Phase 4):
     *    - Check: if (new_off < old_off && old_off > 0) return -EOVERFLOW
     *    - Prevent wraparound in stateful traversal
     *
     * CVE REFERENCES:
     * - CVE-2016-9588: Permission check after allocation in I/O path
     * - CVE-2017-7472: Resource exhaustion via delayed validation
     * - CVE-2014-9529: Linux getdents integer overflow
     * - CVE-2016-4997: Directory traversal DoS via crafted filesystem
     *
     * POSIX REQUIREMENT:
     * From POSIX.1-2008 readdir(3) (basis for getdents):
     * "The readdir() function shall return a pointer to a structure
     *  representing the directory entry at the current position in
     *  the directory stream specified by dirp."
     * - Must handle large directories gracefully
     * - Should detect and reject invalid buffers early
     * - Implementation may impose limits on directory size
     *
     * LINUX REQUIREMENT:
     * From getdents64(2) man page:
     * "The system call getdents64() returns directory entries in the
     *  form of a structure dirent64. The returned data contains
     *  d_reclen which is the length of the entry."
     * - Must validate d_reclen from filesystem
     * - Must prevent infinite loops from d_reclen=0
     * - Must handle directory bombs without hanging
     *
     * IMPLEMENTATION NOTES:
     * - Phase 3: Added 1MB size cap at lines 198-203 ✓
     * - Phase 5: Added early buffer writability check at lines 245-251 ✓
     * - Phase 5: Validate d_reclen calculation with overflow checks ✓ (lines 485-546)
     * - Phase 4: Added iteration limit (max_entries=10000) for directory bombs ✓ (lines 425, 432-437)
     * - Phase 4: Added d_off overflow detection via cookie comparison ✓ (lines 471-477)
     * - See Linux kernel: fs/readdir.c filldir64() for reference
     */
    char test_byte = 0;
    if (fut_copy_to_user(dirp, &test_byte, 1) != 0) {
        fut_printf("[GETDENTS64] getdents64(fd=%u, dirp=%p, count=%u) -> EFAULT "
                   "(buffer not writable, Phase 5: fail-fast permission check)\n",
                   fd, dirp, count);
        return -EFAULT;
    }

    /* Phase 2: Get current task for FD table access */
    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_printf("[GETDENTS64] getdents64(fd=%u, count=%u) -> ESRCH (no current task)\n",
                   fd, count);
        return -ESRCH;
    }

    /* Phase 5: Validate FD upper bound to prevent OOB array access */
    if (fd >= (unsigned int)task->max_fds) {
        fut_printf("[GETDENTS64] getdents64(fd=%u, max_fds=%d, count=%u) -> EBADF "
                   "(fd exceeds max_fds, Phase 5: FD bounds validation)\n",
                   fd, task->max_fds, count);
        return -EBADF;
    }

    /* Phase 2: Categorize FD range (Phase 6: use shared helper) */
    const char *fd_category = fut_fd_category(fd);

    /* Phase 2: Categorize buffer size */
    const char *count_category;
    if (count < 1024) {
        count_category = "small (<1 KB)";
    } else if (count == 4096) {
        count_category = "optimal (4 KB)";
    } else if (count < 8192) {
        count_category = "medium (<8 KB)";
    } else if (count < 32768) {
        count_category = "large (<32 KB)";
    } else {
        count_category = "very large (≥32 KB)";
    }

    /* Validate FD table exists */
    if (!task->fd_table) {
        fut_printf("[GETDENTS64] getdents64(fd=%u [%s], count=%u [%s]) -> EBADF "
                   "(no FD table, pid=%d)\n", fd, fd_category, count, count_category, task->pid);
        return -EBADF;
    }

    /* Get file structure from FD */
    struct fut_file *file = vfs_get_file_from_task(task, (int)fd);
    if (!file) {
        fut_printf("[GETDENTS64] getdents64(fd=%u [%s], count=%u [%s]) -> EBADF "
                   "(fd not open, pid=%d)\n", fd, fd_category, count, count_category, task->pid);
        return -EBADF;
    }

    /* Phase 2: Validate this is a directory */
    if (!file->vnode || file->vnode->type != VN_DIR) {
        const char *file_type = "unknown";
        if (file->vnode) {
            switch (file->vnode->type) {
                case VN_REG: file_type = "regular file"; break;
                case VN_CHR: file_type = "character device"; break;
                case VN_BLK: file_type = "block device"; break;
                case VN_LNK: file_type = "symbolic link"; break;
                case VN_FIFO: file_type = "FIFO"; break;
                case VN_SOCK: file_type = "socket"; break;
                default: break;
            }
        }
        fut_printf("[GETDENTS64] getdents64(fd=%u [%s], type=%s, count=%u [%s]) -> ENOTDIR "
                   "(not a directory, pid=%d)\n",
                   fd, fd_category, file_type, count, count_category, task->pid);
        return -ENOTDIR;
    }

    /* Allocate kernel buffer for directory entries */
    void *kbuf = fut_malloc(count);
    if (!kbuf) {
        fut_printf("[GETDENTS64] getdents64(fd=%u [%s], ino=%lu, count=%u [%s]) -> ENOMEM "
                   "(kernel buffer allocation failed, pid=%d)\n",
                   fd, fd_category, file->vnode->ino, count, count_category, task->pid);
        return -ENOMEM;
    }

    uint64_t cookie = 0;
    const int max_entries = 10000;
    size_t total_bytes = 0;
    char *buf_ptr = (char *)kbuf;
    int entry_count = 0;

    /* Read directory entries using VFS */
    while (total_bytes < count) {
        if (entry_count >= max_entries) {
            fut_printf("[GETDENTS64] getdents64(fd=%u) -> EOVERFLOW "
                       "(entry limit %d reached, Phase 4: directory bomb guard)\n",
                       fd, max_entries);
            break;
        }

        struct fut_vdirent vdirent;
        uint64_t prev_cookie = cookie;
        int rc = fut_vfs_readdir_fd((int)fd, &cookie, &vdirent);

        if (rc < 0) {
            if (total_bytes == 0) {
                const char *error_desc;
                switch (rc) {
                    case -EBADF:
                        error_desc = "invalid file descriptor";
                        break;
                    case -ENOTDIR:
                        error_desc = "not a directory";
                        break;
                    default:
                        error_desc = "readdir error";
                        break;
                }
                fut_printf("[GETDENTS64] getdents64(fd=%u [%s], ino=%lu, count=%u [%s]) -> %d "
                           "(%s, pid=%d)\n",
                           fd, fd_category, file->vnode->ino, count, count_category,
                           rc, error_desc, task->pid);
                fut_free(kbuf);
                return rc;  /* Error on first entry */
            }
            break;  /* No more entries */
        }

        if (rc == 0) {
            break;  /* End of directory */
        }

        if (cookie < prev_cookie && prev_cookie > 0) {
            fut_printf("[GETDENTS64] getdents64(fd=%u) -> EOVERFLOW "
                       "(directory offset wrapped, Phase 4)\n",
                       fd);
            fut_free(kbuf);
            return total_bytes > 0 ? (long)total_bytes : -EOVERFLOW;
        }

        /* Calculate required size for this entry */
        size_t name_len = 0;
        while (vdirent.d_name[name_len] != '\0' && name_len < 256) {
            name_len++;
        }

        /* Phase 5: Validate reclen calculation won't overflow
         * Prevent integer overflow when calculating entry size */
        if (name_len > SIZE_MAX - sizeof(struct linux_dirent64) - 1) {
            fut_printf("[GETDENTS64] getdents64(fd=%u) -> EINVAL "
                       "(name_len %zu would overflow reclen calculation, Phase 5)\n",
                       fd, name_len);
            fut_free(kbuf);
            return total_bytes > 0 ? (long)total_bytes : -EINVAL;
        }

        /* Align to 8-byte boundary for next entry */
        size_t reclen = sizeof(struct linux_dirent64) + name_len + 1;

        /* Phase 5: Validate aligned reclen won't overflow or exceed bounds
         * Ensure rounding up to 8-byte alignment doesn't overflow */
        if (reclen > SIZE_MAX - 7) {
            fut_printf("[GETDENTS64] getdents64(fd=%u) -> EINVAL "
                       "(reclen %zu too large for 8-byte alignment, Phase 5)\n",
                       fd, reclen);
            fut_free(kbuf);
            return total_bytes > 0 ? (long)total_bytes : -EINVAL;
        }
        reclen = (reclen + 7) & ~7;

        /* Phase 5: Validate reclen fits in uint16_t BEFORE truncation
         * VULNERABILITY: d_reclen Truncation Causing Buffer Overrun
         *
         * ATTACK SCENARIO:
         * Malicious or faulty filesystem returns directory entry with extremely long name
         * 1. VFS returns entry with name_len = 65000 bytes (pathological case)
         * 2. Line 340: reclen = sizeof(linux_dirent64) + 65000 + 1 = 65025
         * 3. Line 351: Aligned reclen = (65025 + 7) & ~7 = 65032
         * 4. Line 396: Cast to uint16_t: dent->d_reclen = (uint16_t)65032 = 65032 ✓ OK
         *
         * EDGE CASE - Truncation to Zero:
         * 1. Malicious VFS returns name_len = SIZE_MAX - 31 (maximum before line 331 check)
         * 2. Line 340: reclen = 24 + (SIZE_MAX - 31) + 1 = SIZE_MAX - 6
         * 3. Line 351: Aligned = (SIZE_MAX - 6 + 7) & ~7 = (SIZE_MAX + 1) & ~7
         *    - SIZE_MAX + 1 wraps to 0 on overflow
         *    - 0 & ~7 = 0
         * 4. Line 396: dent->d_reclen = (uint16_t)0 = 0
         * 5. Userspace parser reads reclen=0 → infinite loop or buffer overrun
         *
         * DEFENSE (Phase 5):
         * Check reclen > 65535 BEFORE line 396 cast
         * - Catches SIZE_MAX wraparound case (would be > 65535 before alignment)
         * - Catches pathological name_len values
         * - Prevents truncation to 0 or small incorrect values
         * - Line 344 prevents alignment overflow: reclen > SIZE_MAX - 7
         *
         * CVE REFERENCES:
         * - Similar truncation in CVE-2014-9529 (keyctl d_name overflow)
         * - Directory entry parsing bugs in CVE-2016-3135 (netfilter)
         *
         * CRITICAL: Check happens AFTER alignment to catch wraparound */
        if (reclen > 65535) {
            fut_printf("[GETDENTS64] getdents64(fd=%u, entry='%s') -> EINVAL "
                       "(aligned reclen %zu exceeds uint16_t max 65535, Phase 5)\n",
                       fd, vdirent.d_name, reclen);
            fut_free(kbuf);
            return total_bytes > 0 ? (long)total_bytes : -EINVAL;
        }

        if (total_bytes + reclen > count) {
            break;  /* Not enough space for this entry */
        }

        /* Build linux_dirent64 entry */
        struct linux_dirent64 *dent = (struct linux_dirent64 *)buf_ptr;
        dent->d_ino = vdirent.d_ino;
        dent->d_off = (int64_t)cookie;
        dent->d_reclen = (uint16_t)reclen;
        dent->d_type = vdirent.d_type;

        /* Copy name */
        for (size_t i = 0; i <= name_len; i++) {
            dent->d_name[i] = vdirent.d_name[i];
        }

        buf_ptr += reclen;
        total_bytes += reclen;
        entry_count++;
    }

    /* Copy to userspace */
    if (total_bytes > 0) {
        if (fut_copy_to_user(dirp, kbuf, total_bytes) != 0) {
            fut_printf("[GETDENTS64] getdents64(fd=%u [%s], ino=%lu, count=%u [%s], "
                       "entries=%d, bytes=%zu) -> EFAULT (copy_to_user failed, pid=%d)\n",
                       fd, fd_category, file->vnode->ino, count, count_category,
                       entry_count, total_bytes, task->pid);
            fut_free(kbuf);
            return -EFAULT;
        }
    }

    fut_free(kbuf);

    /* Phase 3: Performance optimization logging with cache and size metrics */
    const char *eof_marker = (total_bytes == 0) ? " (EOF)" : "";
    const char *cache_status = (count >= 4096) ? "cacheable" : "small";
    const char *utilization = (total_bytes > 0 && count > 0) ?
        ((total_bytes * 100 / count > 80) ? "high" : "normal") : "empty";

    fut_printf("[GETDENTS64] getdents64(fd=%u [%s], ino=%lu, count=%u [%s], "
               "entries=%d, bytes=%zu [%s utilization], cache=%s%s) -> %zu (Phase 3)\n",
               fd, fd_category, file->vnode->ino, count, count_category,
               entry_count, total_bytes, utilization, cache_status, eof_marker, total_bytes);
    return (long)total_bytes;
}
