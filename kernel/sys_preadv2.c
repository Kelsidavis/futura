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

    /* Linux's kiocb_set_rw_flags rejects RWF_APPEND on the read path
     * with -EINVAL ("if (rw_type != WRITE) return -EINVAL").  RWF_APPEND
     * is meaningless for reads — the previous code silently accepted
     * it, masking a misuse pattern from libc preadv2 wrappers that
     * branch on EINVAL to fall back to plain preadv. */
    if (flags & RWF_APPEND)
        return -EINVAL;

    /* Linux's preadv2 treats offset == -1 as 'use current file position'
     * and rejects offset < -1 with -EINVAL (fs/read_write.c). The
     * previous Futura code passed any negative offset > -1 (e.g. -2)
     * straight through to sys_preadv, which only knew to reject offset
     * < 0 generally — collapsing the 'use current position' sentinel
     * with bogus negatives. Be explicit. */
    if (offset < -1)
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

    /* Same Linux contract as preadv2: offset == -1 means 'current pos',
     * offset < -1 is -EINVAL. */
    if (offset < -1)
        return -EINVAL;

    /* Linux's kiocb_set_rw_flags translates RWF_APPEND to IOCB_APPEND,
     * and the write path then OVERRIDES the user-supplied offset with
     * i_size — atomically appending regardless of whether the caller
     * passed offset=-1 or an explicit offset.  Futura's previous code
     * only honoured RWF_APPEND on the offset==-1 path, so
     * pwritev2(fd, iov, cnt, EXPLICIT, RWF_APPEND) wrote at the
     * caller-specified offset where Linux writes at EOF — silently
     * losing the atomic-append guarantee. */
    if (flags & RWF_APPEND) {
        extern struct fut_file *fut_vfs_get_file(int fd);
        struct fut_file *rwf_file = fut_vfs_get_file(fd);
        if (!rwf_file || !rwf_file->vnode)
            return -EBADF;

        fut_spinlock_acquire(&rwf_file->vnode->write_lock);
        int64_t append_off = (int64_t)rwf_file->vnode->size;
        extern ssize_t sys_pwritev(int fd, const struct iovec *iov,
                                   int iovcnt, int64_t offset);
        ssize_t result = sys_pwritev(fd, iov, iovcnt, append_off);
        fut_spinlock_release(&rwf_file->vnode->write_lock);
        return result;
    }

    if (offset == -1) {
        /* Use current file position (same as writev) */
        extern ssize_t sys_writev(int fd, const struct iovec *iov, int iovcnt);
        return sys_writev(fd, iov, iovcnt);
    }

    /* Explicit offset: delegate to pwritev */
    extern ssize_t sys_pwritev(int fd, const struct iovec *iov, int iovcnt,
                               int64_t offset);
    return sys_pwritev(fd, iov, iovcnt, offset);
}
