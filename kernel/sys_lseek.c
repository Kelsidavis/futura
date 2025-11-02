/* kernel/sys_lseek.c - File seek syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements the lseek() syscall for changing file position.
 */

#include <kernel/fut_vfs.h>
#include <kernel/errno.h>
#include <stdint.h>

extern void fut_printf(const char *fmt, ...);

/**
 * lseek() - Change file position
 *
 * Changes the file offset for an open file descriptor according to the
 * whence parameter:
 *   - SEEK_SET (0): Set offset relative to start of file
 *   - SEEK_CUR (1): Set offset relative to current position
 *   - SEEK_END (2): Set offset relative to end of file
 *
 * @param fd      File descriptor
 * @param offset  Offset in bytes (can be negative for SEEK_CUR/SEEK_END)
 * @param whence  How to interpret offset (SEEK_SET, SEEK_CUR, SEEK_END)
 *
 * Returns:
 *   - New absolute file offset on success
 *   - -EBADF if fd is not an open file descriptor
 *   - -EINVAL if whence is invalid or result is negative
 *   - -EOVERFLOW if result cannot fit in off_t
 */
int64_t sys_lseek(int fd, int64_t offset, int whence) {
    /* Validate whence parameter */
    if (whence != SEEK_SET && whence != SEEK_CUR && whence != SEEK_END) {
        fut_printf("[LSEEK] lseek(%d, %lld, %d) -> EINVAL (invalid whence)\n", fd, offset, whence);
        return -EINVAL;
    }

    /* Use VFS to perform the seek */
    int64_t new_offset = fut_vfs_lseek(fd, offset, whence);

    if (new_offset < 0) {
        fut_printf("[LSEEK] lseek(%d, %lld, %d) -> error %lld\n", fd, offset, whence, new_offset);
        return new_offset;
    }

    fut_printf("[LSEEK] lseek(%d, %lld, %d) -> %lld\n", fd, offset, whence, new_offset);
    return new_offset;
}
