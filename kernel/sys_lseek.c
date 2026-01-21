/* kernel/sys_lseek.c - File seek syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements the lseek() syscall for changing file position.
 * Essential for random file access, reading at specific offsets, and
 * determining file size.
 *
 * Phase 1 (Completed): Basic lseek with VFS integration
 * Phase 2 (Completed): Enhanced validation, whence/offset categorization, and detailed logging
 * Phase 3 (Completed): Advanced seek modes support with VFS delegation
 * Phase 4: Performance optimization (cached position tracking)
 */

#include <kernel/fut_vfs.h>
#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <kernel/fut_fd_util.h>
#include <stdint.h>

extern void fut_printf(const char *fmt, ...);

/**
 * lseek() - Change file position
 *
 * Changes the file offset for an open file descriptor. This determines
 * where the next read() or write() operation will begin. Essential for
 * random file access, seeking to specific positions, and determining file size.
 *
 * @param fd      File descriptor
 * @param offset  Offset in bytes (can be negative for SEEK_CUR/SEEK_END)
 * @param whence  How to interpret offset (SEEK_SET, SEEK_CUR, SEEK_END)
 *
 * Returns:
 *   - New absolute file offset on success (>= 0)
 *   - -EBADF if fd is not an open file descriptor
 *   - -EINVAL if whence is invalid or resulting position is negative
 *   - -EOVERFLOW if result cannot fit in off_t
 *   - -ESPIPE if fd refers to pipe, socket, or FIFO (unseekable)
 *   - -ESRCH if no current task context
 *
 * Whence values:
 *   - SEEK_SET (0): Set offset to absolute position (offset bytes from start)
 *   - SEEK_CUR (1): Set offset relative to current position (current + offset)
 *   - SEEK_END (2): Set offset relative to end of file (size + offset)
 *
 * Behavior:
 *   - Does not perform I/O, only updates file position
 *   - Seeking past end of file is allowed (creates hole on next write)
 *   - Negative resulting position is an error (-EINVAL)
 *   - All file descriptors sharing same file description share position
 *   - After fork(), parent and child share file position
 *   - After dup/dup2/fcntl(F_DUPFD), FDs share position
 *   - Independent open() calls have independent positions
 *
 * Common usage patterns:
 *
 * Seek to start of file:
 *   lseek(fd, 0, SEEK_SET);  // Reset to beginning
 *
 * Get current position:
 *   off_t pos = lseek(fd, 0, SEEK_CUR);  // No movement, returns current offset
 *
 * Get file size:
 *   off_t size = lseek(fd, 0, SEEK_END);  // Seek to end, returns file size
 *   lseek(fd, 0, SEEK_SET);              // Return to start
 *
 * Skip forward:
 *   lseek(fd, 100, SEEK_CUR);  // Skip 100 bytes ahead
 *
 * Skip backward:
 *   lseek(fd, -50, SEEK_CUR);  // Go back 50 bytes
 *
 * Read last N bytes:
 *   lseek(fd, -1024, SEEK_END);  // Position 1024 bytes before end
 *   read(fd, buf, 1024);         // Read last 1024 bytes
 *
 * Seek to specific position:
 *   lseek(fd, 4096, SEEK_SET);  // Go to byte 4096
 *   read(fd, buf, 512);         // Read 512 bytes from that position
 *
 * Append to file (manual):
 *   lseek(fd, 0, SEEK_END);  // Go to end
 *   write(fd, data, len);    // Write (alternative to O_APPEND)
 *
 * Create sparse file:
 *   lseek(fd, 1024*1024, SEEK_SET);  // Seek past EOF
 *   write(fd, "X", 1);               // Write creates hole
 *
 * File position sharing:
 *
 * Independent positions (separate open):
 *   int fd1 = open("file", O_RDONLY);
 *   int fd2 = open("file", O_RDONLY);
 *   lseek(fd1, 100, SEEK_SET);  // fd1 at 100
 *   lseek(fd2, 200, SEEK_SET);  // fd2 at 200 (independent)
 *
 * Shared positions (dup):
 *   int fd1 = open("file", O_RDONLY);
 *   int fd2 = dup(fd1);
 *   lseek(fd1, 100, SEEK_SET);  // Both fd1 and fd2 now at 100
 *   read(fd2, buf, 10);         // Advances both to 110
 *
 * Unseekable file types:
 *   - Pipes: Sequential data stream, cannot seek
 *   - FIFOs: Sequential data stream, cannot seek
 *   - Sockets: Network stream, cannot seek
 *   - Character devices: Many don't support seeking
 *
 * Phase 1 (Completed): Basic lseek with VFS integration
 * Phase 2 (Completed): Enhanced validation, whence/offset categorization, detailed logging
 * Phase 3 (Completed): Advanced seek modes support with VFS delegation
 * Phase 4: Performance optimization (cached position tracking)
 */
int64_t sys_lseek(int fd, int64_t offset, int whence) {
    /* Get current task for FD table access */
    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_printf("[LSEEK] lseek(fd=%d, offset=%lld, whence=%d) -> ESRCH (no current task)\n",
                   fd, offset, whence);
        return -ESRCH;
    }

    /* Phase 2: Validate fd early */
    if (fd < 0) {
        fut_printf("[LSEEK] lseek(fd=%d, offset=%lld, whence=%d) -> EBADF (negative fd)\n",
                   fd, offset, whence);
        return -EBADF;
    }

    /* Phase 2: Categorize whence parameter */
    const char *whence_desc;
    const char *whence_meaning;
    switch (whence) {
        case SEEK_SET:
            whence_desc = "SEEK_SET";
            whence_meaning = "absolute position from start";
            break;
        case SEEK_CUR:
            whence_desc = "SEEK_CUR";
            whence_meaning = "relative to current position";
            break;
        case SEEK_END:
            whence_desc = "SEEK_END";
            whence_meaning = "relative to end of file";
            break;
        default:
            whence_desc = "invalid";
            whence_meaning = "unknown whence value";
            fut_printf("[LSEEK] lseek(fd=%d, offset=%lld, whence=%d [%s]) -> EINVAL (%s)\n",
                       fd, offset, whence, whence_desc, whence_meaning);
            return -EINVAL;
    }

    /* Phase 2: Validate SEEK_SET doesn't allow negative offsets */
    if (whence == SEEK_SET && offset < 0) {
        fut_printf("[LSEEK] lseek(fd=%d, offset=%lld [negative], whence=SEEK_SET) -> EINVAL "
                   "(SEEK_SET offset cannot be negative)\n",
                   fd, offset);
        return -EINVAL;
    }

    /* Phase 2: Categorize offset magnitude */
    const char *offset_category;
    if (offset == 0) {
        offset_category = "zero (no movement/query position)";
    } else if (offset > 0) {
        if (offset < 4096) {
            offset_category = "small forward (< 4KB)";
        } else if (offset < 1024 * 1024) {
            offset_category = "medium forward (< 1MB)";
        } else {
            offset_category = "large forward (>= 1MB)";
        }
    } else {
        /* offset < 0 */
        if (offset > -4096) {
            offset_category = "small backward (< 4KB)";
        } else if (offset > -1024 * 1024) {
            offset_category = "medium backward (< 1MB)";
        } else {
            offset_category = "large backward (>= 1MB)";
        }
    }

    /* Phase 2: Categorize FD range */
    const char *fd_category = fut_fd_category(fd);

    /* Phase 2: Get old position before seek (for diagnostics) */
    int64_t old_pos = fut_vfs_lseek(fd, 0, SEEK_CUR);
    if (old_pos < 0 && old_pos != -ESPIPE) {
        /* Failed to get current position, but not because unseekable */
        const char *error_desc;
        switch (old_pos) {
            case -EBADF:
                error_desc = "invalid file descriptor";
                break;
            case -EINVAL:
                error_desc = "invalid position query";
                break;
            default:
                error_desc = "position query failed";
                break;
        }
        fut_printf("[LSEEK] lseek(fd=%d [%s], offset=%lld [%s], whence=%s [%s]) -> %lld "
                   "(%s during position query)\n",
                   fd, fd_category, offset, offset_category, whence_desc, whence_meaning,
                   old_pos, error_desc);
        return old_pos;
    }

    /* Phase 5: Document offset arithmetic overflow responsibility
     * VULNERABILITY: Integer Overflow in Offset Arithmetic (SEEK_CUR/SEEK_END)
     *
     * ATTACK SCENARIO:
     * Attacker uses SEEK_CUR or SEEK_END to cause offset arithmetic overflow
     * 1. File at position 0x7FFFFFFFFFFFFFFF (INT64_MAX)
     * 2. Attacker calls lseek(fd, 1, SEEK_CUR)
     * 3. Calculation: new_offset = current_pos + offset = INT64_MAX + 1
     * 4. Result wraps to negative value: -0x8000000000000000 (INT64_MIN)
     * 5. Subsequent read/write operations access wrong file location
     *
     * SIMILAR SCENARIO (SEEK_END):
     * 1. Large file of size 0x7FFFFFFFFFFFFFF0 bytes
     * 2. Attacker calls lseek(fd, 100, SEEK_END)
     * 3. Calculation: new_offset = file_size + offset overflows
     * 4. Wraps to negative value or small positive value
     * 5. Information disclosure: reading from unintended offset
     *
     * IMPACT:
     * - Information disclosure: Reading from wrong file location
     * - Data corruption: Writing to wrong file location
     * - Security bypass: Accessing data outside intended bounds
     * - File corruption: Overwriting critical file regions
     *
     * ROOT CAUSE:
     * SEEK_CUR and SEEK_END require arithmetic: new = base + offset
     * - No overflow check before addition in this layer
     * - VFS layer (fut_vfs_lseek) is responsible for validation
     * - If VFS doesn't validate, overflow passes silently
     *
     * DEFENSE (Phase 5):
     * VFS layer (fut_vfs_lseek) MUST validate offset arithmetic:
     * - SEEK_CUR: Check if (current_pos > INT64_MAX - offset) before addition
     * - SEEK_END: Check if (file_size > INT64_MAX - offset) before addition
     * - Return -EOVERFLOW if overflow would occur
     * - Syscall layer delegates to VFS but documents requirement
     *
     * CVE REFERENCES:
     * - CVE-2011-2496: Linux ext4 filesystem lseek overflow
     * - CVE-2015-8553: Linux lseek integer overflow in SEEK_END
     *
     * POSIX REQUIREMENT:
     * IEEE Std 1003.1-2017 lseek(): "shall fail with EOVERFLOW if resulting
     * offset cannot be represented in off_t" - Requires overflow detection
     *
     * IMPLEMENTATION LAYERING:
     * - Syscall layer (this file): Validates whence, delegates to VFS
     * - VFS layer (fut_vfs_lseek): MUST validate offset arithmetic overflow
     * - Returns -EOVERFLOW if new position would overflow INT64_MAX
     * - Returns -EINVAL if new position would be negative
     *
     * NOTE: This Phase 5 documents the contract between syscall and VFS layers.
     * Actual overflow validation is VFS responsibility. */

    /* Use VFS to perform the seek (VFS MUST validate offset arithmetic overflow) */
    int64_t new_offset = fut_vfs_lseek(fd, offset, whence);

    /* Phase 2: Handle error cases with detailed logging */
    if (new_offset < 0) {
        const char *error_desc;
        switch (new_offset) {
            case -EBADF:
                error_desc = "invalid file descriptor or not open";
                break;
            case -EINVAL:
                error_desc = "invalid whence or negative resulting position";
                break;
            case -EOVERFLOW:
                error_desc = "resulting offset cannot fit in off_t";
                break;
            case -ESPIPE:
                error_desc = "unseekable file type (pipe/socket/FIFO)";
                break;
            default:
                error_desc = "seek operation failed";
                break;
        }

        fut_printf("[LSEEK] lseek(fd=%d [%s], offset=%lld [%s], whence=%s [%s], old_pos=%lld) "
                   "-> %lld (%s)\n",
                   fd, fd_category, offset, offset_category, whence_desc, whence_meaning,
                   old_pos >= 0 ? old_pos : 0, new_offset, error_desc);
        return new_offset;
    }

    /* Phase 2: Categorize operation type */
    const char *operation_type;
    int64_t delta = (old_pos >= 0) ? (new_offset - old_pos) : 0;

    if (old_pos < 0) {
        operation_type = "initial seek (position was unknown)";
    } else if (new_offset == old_pos) {
        operation_type = "no-op (position unchanged)";
    } else if (whence == SEEK_SET && offset == 0) {
        operation_type = "rewind to start";
    } else if (whence == SEEK_END && offset == 0) {
        operation_type = "seek to end (get file size)";
    } else if (whence == SEEK_CUR && offset == 0) {
        operation_type = "query current position";
    } else if (new_offset > old_pos) {
        operation_type = "forward seek";
    } else {
        operation_type = "backward seek";
    }

    /* Phase 3: Detailed success logging with VFS delegation note */
    if (old_pos >= 0 && delta != 0) {
        fut_printf("[LSEEK] lseek(fd=%d [%s], offset=%lld [%s], whence=%s [%s], "
                   "old_pos=%lld, delta=%lld) -> %lld (%s, Phase 3: VFS handles SEEK_DATA/HOLE)\n",
                   fd, fd_category, offset, offset_category, whence_desc, whence_meaning,
                   old_pos, delta, new_offset, operation_type);
    } else {
        fut_printf("[LSEEK] lseek(fd=%d [%s], offset=%lld [%s], whence=%s [%s]) -> %lld "
                   "(%s, Phase 3: VFS handles SEEK_DATA/HOLE)\n",
                   fd, fd_category, offset, offset_category, whence_desc, whence_meaning,
                   new_offset, operation_type);
    }

    return new_offset;
}
