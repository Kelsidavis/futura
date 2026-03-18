/* kernel/sys_preadv2.c - preadv2() and pwritev2() syscalls (Linux 4.6+)
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * preadv2/pwritev2 extend preadv/pwritev with:
 *   - offset=-1 means "use/update current file position" (like readv/writev)
 *   - flags: RWF_HIPRI, RWF_DSYNC, RWF_SYNC, RWF_NOWAIT, RWF_APPEND
 *
 * Phase 1 (Completed):
 *   - offset=-1: delegate to readv/writev (current position semantics)
 *   - offset>=0: delegate to preadv/pwritev (explicit offset, no position update)
 *   - flags validation: reject unknown flags
 *   - RWF_HIPRI, RWF_DSYNC, RWF_SYNC: accepted (no-op; Futura has no I/O scheduling)
 *   - RWF_NOWAIT: accepted (no-op; ramfs I/O never blocks)
 *   - RWF_APPEND: writes from end-of-file; implemented for pwritev2
 */

#include <kernel/errno.h>
#include <kernel/fut_vfs.h>
#include <sys/uio.h>
#include <stdint.h>
#include <stddef.h>

/* RWF flags (from Linux uio.h) */
#define RWF_HIPRI   0x00000001
#define RWF_DSYNC   0x00000002
#define RWF_SYNC    0x00000004
#define RWF_NOWAIT  0x00000008
#define RWF_APPEND  0x00000010
#define RWF_VALID   (RWF_HIPRI | RWF_DSYNC | RWF_SYNC | RWF_NOWAIT | RWF_APPEND)

/**
 * sys_preadv2 - scatter-gather read with position and flags
 *
 * @param fd      File descriptor
 * @param iov     Array of iovec buffers
 * @param iovcnt  Number of iovec elements
 * @param offset  File offset, or -1 to use/update current position
 * @param flags   RWF_* flags
 * @return bytes read on success, -errno on error
 */
ssize_t sys_preadv2(int fd, const struct iovec *iov, int iovcnt,
                    int64_t offset, int flags) {
    if (flags & ~RWF_VALID)
        return -EINVAL;

    if (offset == -1) {
        /* Use current file position (same as readv) */
        extern ssize_t sys_readv(int fd, const struct iovec *iov, int iovcnt);
        return sys_readv(fd, iov, iovcnt);
    }

    /* Explicit offset: delegate to preadv (does not update file position) */
    extern ssize_t sys_preadv(int fd, const struct iovec *iov, int iovcnt,
                              int64_t offset);
    return sys_preadv(fd, iov, iovcnt, offset);
}

/**
 * sys_pwritev2 - scatter-gather write with position and flags
 *
 * @param fd      File descriptor
 * @param iov     Array of iovec buffers
 * @param iovcnt  Number of iovec elements
 * @param offset  File offset, or -1 to use/update current position
 * @param flags   RWF_* flags
 * @return bytes written on success, -errno on error
 */
ssize_t sys_pwritev2(int fd, const struct iovec *iov, int iovcnt,
                     int64_t offset, int flags) {
    if (flags & ~RWF_VALID)
        return -EINVAL;

    if (offset == -1) {
        if (flags & RWF_APPEND) {
            /* Seek to EOF before write */
            long end = fut_vfs_lseek(fd, 0, 2 /* SEEK_END */);
            if (end < 0)
                return end;
            offset = (int64_t)end;
            /* Fall through to pwritev with EOF offset */
            extern ssize_t sys_pwritev(int fd, const struct iovec *iov,
                                       int iovcnt, int64_t offset);
            return sys_pwritev(fd, iov, iovcnt, offset);
        }
        /* Use current file position (same as writev) */
        extern ssize_t sys_writev(int fd, const struct iovec *iov, int iovcnt);
        return sys_writev(fd, iov, iovcnt);
    }

    /* Explicit offset: delegate to pwritev */
    extern ssize_t sys_pwritev(int fd, const struct iovec *iov, int iovcnt,
                               int64_t offset);
    return sys_pwritev(fd, iov, iovcnt, offset);
}
