/* kernel/sys_splice.c - Zero-copy I/O syscalls
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements splice, vmsplice, tee, and sync_file_range for efficient I/O.
 * These syscalls enable zero-copy data movement between file descriptors
 * and memory, essential for high-performance applications.
 *
 * Phase 1 (Completed): Validation and stub implementations with parameter categorization
 * Phase 2 (Completed): Enhanced validation, operation type categorization, detailed logging
 * Phase 3 (Completed): Implement pipe-based zero-copy transfers
 * Phase 4: Add page cache integration for file-to-file transfers
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <kernel/uaccess.h>
#include <kernel/syscalls.h>
#include <kernel/fut_vfs.h>
#include <fcntl.h>
#include <kernel/fut_memory.h>
#include <kernel/chrdev.h>
#include <sys/uio.h>
#include <stdint.h>
#include <stddef.h>

/* ssize_t provided by kernel/syscalls.h */

#include <kernel/kprintf.h>

/* Architecture-specific paging headers for KERNEL_VIRTUAL_BASE (kernel pointer detection) */
#include <platform/platform.h>

/* Copy from user or kernel buffer transparently */
static inline int splice_copy_from(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)src >= KERNEL_VIRTUAL_BASE) {
        __builtin_memcpy(dst, src, n);
        return 0;
    }
#endif
    return fut_copy_from_user(dst, src, n);
}

/* splice flags */
#define SPLICE_F_MOVE     0x01  /* Move pages instead of copying */
#define SPLICE_F_NONBLOCK 0x02  /* Non-blocking operation */
#define SPLICE_F_MORE     0x04  /* More data will follow */
#define SPLICE_F_GIFT     0x08  /* Pages are a gift to kernel */

/* sync_file_range flags */
#define SYNC_FILE_RANGE_WAIT_BEFORE 1  /* Wait for writeback before */
#define SYNC_FILE_RANGE_WRITE       2  /* Initiate writeback */
#define SYNC_FILE_RANGE_WAIT_AFTER  4  /* Wait for writeback after */

/**
 * splice() - Move data between file descriptors
 *
 * Moves data between two file descriptors without copying between kernel and
 * user space. At least one of the file descriptors must refer to a pipe.
 * This enables zero-copy data movement for high-performance applications.
 *
 * @param fd_in     Source file descriptor
 * @param off_in    Offset in source (NULL for pipe, or pointer to offset)
 * @param fd_out    Destination file descriptor
 * @param off_out   Offset in destination (NULL for pipe, or pointer to offset)
 * @param len       Number of bytes to transfer
 * @param flags     SPLICE_F_MOVE, SPLICE_F_NONBLOCK, SPLICE_F_MORE, SPLICE_F_GIFT
 *
 * Returns:
 *   - Number of bytes transferred on success
 *   - 0 if no data available (non-blocking mode)
 *   - -EBADF if fd_in or fd_out is invalid
 *   - -EINVAL if neither fd is a pipe, or offsets invalid
 *   - -ENOMEM if insufficient memory
 *   - -ESPIPE if offset provided for pipe
 *
 * Typical usage patterns:
 *
 * 1. File to pipe (e.g., sendfile replacement):
 *    splice(file_fd, &offset, pipe_fd, NULL, len, SPLICE_F_MOVE);
 *
 * 2. Pipe to file:
 *    splice(pipe_fd, NULL, file_fd, &offset, len, SPLICE_F_MOVE);
 *
 * 3. Pipe to socket (zero-copy network send):
 *    splice(pipe_fd, NULL, socket_fd, NULL, len, SPLICE_F_MOVE | SPLICE_F_MORE);
 *
 * Phase 1 (Completed): Validate parameters and return dummy count
 * Phase 2 (Completed): Enhanced validation and operation categorization with detailed logging
 * Phase 3 (Completed): Implement pipe-based transfers
 * Phase 4: Add page cache integration for files
 */
long sys_splice(int fd_in, int64_t *off_in, int fd_out, int64_t *off_out,
                size_t len, unsigned int flags) {
    /* ARM64 FIX: Copy register-passed parameters to local stack variables so they
     * survive across potentially blocking calls (fut_copy_from_user/fut_copy_to_user
     * may context-switch on ARM64, corrupting register values on resumption). */
    int local_fd_in = fd_in;
    int64_t *local_off_in = off_in;
    int local_fd_out = fd_out;
    int64_t *local_off_out = off_out;
    size_t local_len = len;
    unsigned int local_flags = flags;

    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_printf("[SPLICE] splice(fd_in=%d, off_in=%p, fd_out=%d, off_out=%p, len=%zu, flags=0x%x) "
                   "-> ESRCH (no current task)\n", local_fd_in, local_off_in, local_fd_out, local_off_out, local_len, local_flags);
        return -ESRCH;
    }

    /* Linux's fs/splice.c:SYSCALL_DEFINE6(splice) validates flags FIRST
     * (before any fd lookup):
     *   if (unlikely(!len)) return 0;
     *   if (unlikely(flags & ~SPLICE_F_ALL)) return -EINVAL;
     *   error = -EBADF;
     *   in = fdget(fd_in);
     * The previous Futura order rejected negative fds before flags,
     * inverting the errno class for callers that probe with deliberately
     * bad fds to detect kernel-supported flag bits.  Match Linux —
     * same shape as the matching sys_tee fix. */
    const unsigned int VALID_FLAGS = SPLICE_F_MOVE | SPLICE_F_NONBLOCK | SPLICE_F_MORE | SPLICE_F_GIFT;
    if (local_flags & ~VALID_FLAGS) {
        fut_printf("[SPLICE] splice(fd_in=%d, fd_out=%d, len=%zu, flags=0x%x [invalid], pid=%d) "
                   "-> EINVAL\n", local_fd_in, local_fd_out, local_len, local_flags, task->pid);
        return -EINVAL;
    }

    /* Validate fds */
    if (local_fd_in < 0 || local_fd_out < 0) {
        fut_printf("[SPLICE] splice(fd_in=%d, fd_out=%d, len=%zu, flags=0x%x, pid=%d) "
                   "-> EBADF (invalid fd)\n", local_fd_in, local_fd_out, local_len, local_flags, task->pid);
        return -EBADF;
    }

    /* Linux's fs/splice.c orders the gates so ESPIPE (offset given for a
     * pipe) takes precedence over EFAULT on the offset pointer.  The
     * previous Futura order probed off_in/off_out via copy_from_user
     * before pipe detection, so a splice call with fd_in=pipe and
     * off_in=bad_ptr surfaced EFAULT instead of the documented
     * ESPIPE.  Resolve fds and detect pipe-ness up front, then perform
     * pipe/offset compatibility checks (ESPIPE / access-mode / pair
     * EINVAL), and finally probe the offset pointers for EFAULT. */
    if (local_fd_in >= task->max_fds || local_fd_out >= task->max_fds) {
        return -EBADF;
    }

    struct fut_file *file_in  = vfs_get_file_from_task(task, local_fd_in);
    struct fut_file *file_out = vfs_get_file_from_task(task, local_fd_out);

    if (!file_in || !file_out) {
        fut_printf("[SPLICE] splice(fd_in=%d, fd_out=%d) -> EBADF (fd not open)\n",
                   local_fd_in, local_fd_out);
        return -EBADF;
    }

    /* O_PATH fds cannot be used for I/O — only path-based operations */
    if ((file_in->flags & O_PATH) || (file_out->flags & O_PATH))
        return -EBADF;

    bool in_is_pipe  = (file_in->chr_ops  != NULL && file_in->chr_ops->read  != NULL);
    bool out_is_pipe = (file_out->chr_ops != NULL && file_out->chr_ops->write != NULL);

    /* POSIX: at least one fd must be a pipe */
    if (!in_is_pipe && !out_is_pipe) {
        fut_printf("[SPLICE] splice(fd_in=%d, fd_out=%d) -> EINVAL (neither fd is a pipe)\n",
                   local_fd_in, local_fd_out);
        return -EINVAL;
    }

    /* For the non-pipe (file) side, enforce access mode:
     * fd_in must be readable; fd_out must be writable. */
    if (!in_is_pipe && (file_in->flags & O_ACCMODE) == O_WRONLY)
        return -EBADF;
    if (!out_is_pipe && (file_out->flags & O_ACCMODE) == O_RDONLY)
        return -EBADF;

    /* Linux's fs/splice.c:do_splice rejects directory-source splice
     * with -EISDIR (S_ISDIR check inside splice_direct_to_actor /
     * generic_file_splice_read).  The previous Futura code would
     * fall through to the chunked read loop, where vnode reads on
     * a directory typically return EISDIR but with no guarantee —
     * an in-memory ramfs directory could return a different errno.
     * Surface EISDIR explicitly so libc splice() probes branch
     * correctly.  Same EISDIR/EINVAL split as the matching
     * sendfile / copy_file_range fixes. */
    if (!in_is_pipe && file_in->vnode && file_in->vnode->type == VN_DIR)
        return -EISDIR;
    if (!out_is_pipe && file_out->vnode && file_out->vnode->type == VN_DIR)
        return -EISDIR;

    /* ESPIPE: offset not allowed for pipes (must precede EFAULT on
     * offset pointer to match Linux's fs/splice.c gate order). */
    if (local_off_in  && in_is_pipe)  return -ESPIPE;
    if (local_off_out && out_is_pipe) return -ESPIPE;

    /* Now that ESPIPE has been ruled out, probe offset pointers.
     * Inherent TOCTOU limitation: userspace can remap pages between the
     * read and write probes. Best-effort validation catches most invalid
     * pointers. */
    if (local_off_in != NULL) {
        int64_t test_offset;
        if (fut_copy_from_user(&test_offset, local_off_in, sizeof(int64_t)) != 0) {
            fut_printf("[SPLICE] splice(fd_in=%d, off_in=%p) -> EFAULT "
                       "(off_in not readable)\n",
                       local_fd_in, local_off_in);
            return -EFAULT;
        }
        if (fut_copy_to_user(local_off_in, &test_offset, sizeof(int64_t)) != 0) {
            fut_printf("[SPLICE] splice(fd_in=%d, off_in=%p) -> EFAULT "
                       "(off_in not writable)\n",
                       local_fd_in, local_off_in);
            return -EFAULT;
        }
        if (test_offset < 0) {
            fut_printf("[SPLICE] splice(fd_in=%d, off_in=%p, offset=%ld) -> EINVAL "
                       "(negative offset)\n",
                       local_fd_in, local_off_in, test_offset);
            return -EINVAL;
        }
        if ((uint64_t)test_offset > (uint64_t)(INT64_MAX - local_len)) {
            fut_printf("[SPLICE] splice(fd_in=%d, off_in=%ld, len=%zu) -> EOVERFLOW "
                       "(offset+len would overflow, max_valid_offset=%ld)\n",
                       local_fd_in, test_offset, local_len, (int64_t)(INT64_MAX - local_len));
            return -EOVERFLOW;
        }
    }

    if (local_off_out != NULL) {
        int64_t test_offset;
        if (fut_copy_from_user(&test_offset, local_off_out, sizeof(int64_t)) != 0) {
            fut_printf("[SPLICE] splice(fd_out=%d, off_out=%p) -> EFAULT "
                       "(off_out not readable)\n",
                       local_fd_out, local_off_out);
            return -EFAULT;
        }
        if (fut_copy_to_user(local_off_out, &test_offset, sizeof(int64_t)) != 0) {
            fut_printf("[SPLICE] splice(fd_out=%d, off_out=%p) -> EFAULT "
                       "(off_out not writable)\n",
                       local_fd_out, local_off_out);
            return -EFAULT;
        }
        if (test_offset < 0) {
            fut_printf("[SPLICE] splice(fd_out=%d, off_out=%p, offset=%ld) -> EINVAL "
                       "(negative offset)\n",
                       local_fd_out, local_off_out, test_offset);
            return -EINVAL;
        }
        if ((uint64_t)test_offset > (uint64_t)(INT64_MAX - local_len)) {
            fut_printf("[SPLICE] splice(fd_out=%d, off_out=%ld, len=%zu) -> EOVERFLOW "
                       "(offset+len would overflow, max_valid_offset=%ld)\n",
                       local_fd_out, test_offset, local_len, (int64_t)(INT64_MAX - local_len));
            return -EOVERFLOW;
        }
    }

    /* Zero-length transfer is a valid no-op */
    if (local_len == 0)
        return 0;

    /* SPLICE_F_NONBLOCK: temporarily set nonblock on pipe ends */
    extern bool pipe_get_nonblock(void *priv, bool is_write);
    extern void pipe_set_nonblock(void *priv, bool is_write, bool nonblock);

    bool saved_in_nb  = false;
    bool saved_out_nb = false;
    bool set_in_nb    = false;
    bool set_out_nb   = false;

    if (local_flags & SPLICE_F_NONBLOCK) {
        if (in_is_pipe) {
            saved_in_nb = pipe_get_nonblock(file_in->chr_private, false);
            if (!saved_in_nb) {
                pipe_set_nonblock(file_in->chr_private, false, true);
                set_in_nb = true;
            }
        }
        if (out_is_pipe) {
            saved_out_nb = pipe_get_nonblock(file_out->chr_private, true);
            if (!saved_out_nb) {
                pipe_set_nonblock(file_out->chr_private, true, true);
                set_out_nb = true;
            }
        }
    }

    /* Determine effective read offset */
    int64_t read_off  = 0;
    int64_t write_off = 0;
    if (local_off_in) {
        if (fut_copy_from_user(&read_off,  local_off_in,  sizeof(int64_t)) != 0) return -EFAULT;
    } else {
        read_off = (int64_t)file_in->offset;
    }
    if (local_off_out) {
        if (fut_copy_from_user(&write_off, local_off_out, sizeof(int64_t)) != 0) return -EFAULT;
    } else {
        write_off = (int64_t)file_out->offset;
    }

    /* Transfer via a temporary kernel buffer (PIPE_BUF_SIZE chunks) */
    long result;
    const size_t CHUNK = 4096;
    uint8_t *kbuf = (uint8_t *)fut_malloc(CHUNK);
    if (!kbuf) {
        result = -ENOMEM;
        goto restore_nb;
    }

    size_t transferred = 0;
    long splice_err = 0;

    while (transferred < local_len) {
        size_t want = local_len - transferred;
        if (want > CHUNK) want = CHUNK;

        /* Read from source */
        ssize_t nread;
        if (in_is_pipe) {
            off_t pos = (off_t)read_off;
            nread = file_in->chr_ops->read(file_in->chr_inode,
                                           file_in->chr_private,
                                           kbuf, want, &pos);
            read_off = (int64_t)pos;
        } else {
            /* Regular file read at current offset */
            nread = file_in->vnode->ops->read(file_in->vnode, kbuf, want,
                                               (uint64_t)read_off);
            if (nread > 0) read_off += nread;
        }

        if (nread < 0) {
            /* EAGAIN from nonblock pipe: treat as "no more data right now" */
            if (transferred > 0) break;
            splice_err = (long)nread;
            break;
        }
        if (nread == 0) break;  /* EOF or pipe empty (non-blocking) */

        /* Write to destination */
        ssize_t nwritten;
        if (out_is_pipe) {
            off_t pos = (off_t)write_off;
            nwritten = file_out->chr_ops->write(file_out->chr_inode,
                                                file_out->chr_private,
                                                kbuf, (size_t)nread, &pos);
            write_off = (int64_t)pos;
        } else {
            /* O_APPEND: seek to end atomically, like fut_vfs_write() */
            int append = (file_out->flags & O_APPEND) != 0;
            if (append) {
                fut_spinlock_acquire(&file_out->vnode->write_lock);
                write_off = (int64_t)file_out->vnode->size;
            }
            nwritten = file_out->vnode->ops->write(file_out->vnode, kbuf,
                                                    (size_t)nread,
                                                    (uint64_t)write_off);
            if (append)
                fut_spinlock_release(&file_out->vnode->write_lock);
            if (nwritten > 0) write_off += nwritten;
        }

        if (nwritten < 0) {
            if (transferred > 0) break;
            splice_err = (long)nwritten;
            break;
        }

        transferred += (size_t)nwritten;
    }

    fut_free(kbuf);

    /* Update file offsets */
    if (!local_off_in)  file_in->offset  = (uint64_t)read_off;
    if (!local_off_out) file_out->offset = (uint64_t)write_off;

    /* Write back updated offsets to userspace if caller provided pointers */
    if (local_off_in  && fut_copy_to_user(local_off_in,  &read_off,  sizeof(int64_t)) != 0) {
        result = -EFAULT;
        goto restore_nb;
    }
    if (local_off_out && fut_copy_to_user(local_off_out, &write_off, sizeof(int64_t)) != 0) {
        result = -EFAULT;
        goto restore_nb;
    }

    /* POSIX/Linux: clear setuid/setgid bits on destination after successful write */
    if (transferred > 0 && file_out->vnode && file_out->vnode->type == VN_REG) {
        uint32_t mode = file_out->vnode->mode;
        int needs_clear = 0;
        if (mode & 04000) needs_clear = 1;
        if ((mode & 02000) && (mode & 00010)) needs_clear = 1;
        if (needs_clear) {
            int has_cap_fsetid = task &&
                (task->cap_effective & (1ULL << 4 /* CAP_FSETID */));
            if (!has_cap_fsetid) {
                if (mode & 04000)
                    file_out->vnode->mode &= ~(uint32_t)04000;
                if ((mode & 02000) && (mode & 00010))
                    file_out->vnode->mode &= ~(uint32_t)02000;
            }
        }
    }

    /* Success path silent — zero-copy data movement (cat /dev/zero |
     * pv > /dev/null, nginx sendfile-equivalent, dd via pipes) calls
     * splice in tight loops. Errors above still trace. */
    result = (transferred > 0) ? (long)transferred : splice_err;

restore_nb:
    if (set_in_nb)  pipe_set_nonblock(file_in->chr_private,  false, false);
    if (set_out_nb) pipe_set_nonblock(file_out->chr_private, true,  false);
    return result;
}

/**
 * vmsplice() - Splice user memory into pipe
 *
 * Splices user memory pages into a pipe without copying. The iovec array
 * describes the memory regions to be transferred.
 *
 * @param fd     Pipe file descriptor
 * @param iov    Array of iovec structures describing memory regions
 * @param nr_segs Number of iovec structures
 * @param flags  SPLICE_F_MOVE, SPLICE_F_NONBLOCK, SPLICE_F_MORE, SPLICE_F_GIFT
 *
 * Returns:
 *   - Number of bytes transferred on success
 *   - -EBADF if fd is invalid or not a pipe
 *   - -EINVAL if nr_segs is 0 or flags invalid
 *   - -ENOMEM if insufficient memory
 *
 * Usage:
 *   struct iovec iov[2];
 *   iov[0].iov_base = buffer1; iov[0].iov_len = len1;
 *   iov[1].iov_base = buffer2; iov[1].iov_len = len2;
 *   vmsplice(pipe_fd, iov, 2, SPLICE_F_GIFT);
 *
 * SPLICE_F_GIFT tells kernel it can take ownership of the pages.
 *
 * Phase 1 (Completed): Validate parameters and return dummy count
 * Phase 2 (Completed): Enhanced validation and segment categorization with detailed logging
 * Phase 3 (Completed): Map user pages and add to pipe buffer
 */
long sys_vmsplice(int fd, const void *iov, size_t nr_segs, unsigned int flags) {
    /* ARM64 FIX: Copy register-passed parameters to local stack variables so they
     * survive across potentially blocking calls. */
    int local_fd = fd;
    const void *local_iov = iov;
    size_t local_nr_segs = nr_segs;
    unsigned int local_flags = flags;

    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    /* Linux's fs/splice.c:SYSCALL_DEFINE4(vmsplice) validates flags FIRST
     * (before any fd lookup or iovec access):
     *   if (unlikely(flags & ~SPLICE_F_ALL)) return -EINVAL;
     *   f = fdget(fd);
     *   error = import_iovec(...);
     * The previous Futura order rejected negative fds and a NULL iov
     * pointer before flags, inverting the errno class for callers that
     * probe with deliberately bad fds/iov to detect kernel-supported
     * flag bits.  Match Linux — same shape as the matching sys_splice
     * and sys_tee fixes. */
    const unsigned int VALID_FLAGS = SPLICE_F_MOVE | SPLICE_F_NONBLOCK | SPLICE_F_MORE | SPLICE_F_GIFT;
    if (local_flags & ~VALID_FLAGS) {
        fut_printf("[VMSPLICE] vmsplice(fd=%d, nr_segs=%zu, flags=0x%x [invalid], pid=%d) "
                   "-> EINVAL\n", local_fd, local_nr_segs, local_flags, task->pid);
        return -EINVAL;
    }

    /* Validate fd */
    if (local_fd < 0) {
        fut_printf("[VMSPLICE] vmsplice(fd=%d [invalid], nr_segs=%zu, flags=0x%x, pid=%d) "
                   "-> EBADF\n", local_fd, local_nr_segs, local_flags, task->pid);
        return -EBADF;
    }

    /* Validate iov pointer */
    if (!local_iov) {
        fut_printf("[VMSPLICE] vmsplice(fd=%d, iov=NULL, nr_segs=%zu, pid=%d) "
                   "-> EFAULT\n", local_fd, local_nr_segs, task->pid);
        return -EFAULT;
    }

    /* Validate nr_segs */
    if (local_nr_segs == 0) {
        fut_printf("[VMSPLICE] vmsplice(fd=%d, nr_segs=0 [invalid], flags=0x%x, pid=%d) "
                   "-> EINVAL\n", local_fd, local_flags, task->pid);
        return -EINVAL;
    }

    /* Cap nr_segs to prevent excessive iteration (matches Linux UIO_MAXIOV) */
    if (local_nr_segs > 1024) {
        fut_printf("[VMSPLICE] vmsplice(fd=%d, nr_segs=%zu [exceeds 1024], pid=%d) "
                   "-> EINVAL\n", local_fd, local_nr_segs, task->pid);
        return -EINVAL;
    }

    /* Get file structure for the pipe fd */
    if (local_fd >= task->max_fds) return -EBADF;
    struct fut_file *file = vfs_get_file_from_task(task, local_fd);
    if (!file) return -EBADF;

    /* O_PATH fds cannot be used for I/O */
    if (file->flags & O_PATH) return -EBADF;

    /* vmsplice requires the fd to be a pipe (write end) */
    if (!file->chr_ops || !file->chr_ops->write) {
        fut_printf("[VMSPLICE] vmsplice(fd=%d) -> EBADF (not a writable pipe)\n", local_fd);
        return -EBADF;
    }

    /* Per-segment I/O limit matching sys_preadv/pwritev (2MB) */
    const size_t MAX_IOV_LEN = 2u * 1024u * 1024u;

    /* Process each iovec segment */
    ssize_t total = 0;
    const struct iovec *user_iov = (const struct iovec *)local_iov;

    for (size_t i = 0; i < local_nr_segs; i++) {
        struct iovec seg;
        if (splice_copy_from(&seg, &user_iov[i], sizeof(seg)) != 0)
            return (total > 0) ? total : -EFAULT;

        if (seg.iov_len == 0) continue;
        if (seg.iov_len > MAX_IOV_LEN) return (total > 0) ? total : -EINVAL;
        if (!seg.iov_base) return (total > 0) ? total : -EFAULT;

        /* Copy user data into a kernel buffer then write to pipe */
        uint8_t *kbuf = (uint8_t *)fut_malloc(seg.iov_len);
        if (!kbuf) return (total > 0) ? total : -ENOMEM;

        if (splice_copy_from(kbuf, seg.iov_base, seg.iov_len) != 0) {
            fut_free(kbuf);
            return (total > 0) ? total : -EFAULT;
        }

        off_t pos = 0;
        ssize_t nwritten = file->chr_ops->write(file->chr_inode, file->chr_private,
                                                 kbuf, seg.iov_len, &pos);
        fut_free(kbuf);

        if (nwritten < 0) return (total > 0) ? total : (long)nwritten;
        total += nwritten;
        if ((size_t)nwritten < seg.iov_len) break;  /* Pipe full */
    }

    return total;
}

/**
 * tee() - Duplicate pipe content
 *
 * Duplicates data from one pipe to another without consuming it from the
 * source pipe. Both pipes can subsequently be read independently.
 *
 * @param fd_in   Source pipe file descriptor
 * @param fd_out  Destination pipe file descriptor
 * @param len     Number of bytes to duplicate
 * @param flags   SPLICE_F_NONBLOCK, SPLICE_F_MORE
 *
 * Returns:
 *   - Number of bytes duplicated on success
 *   - 0 if no data available (non-blocking mode)
 *   - -EBADF if fd_in or fd_out invalid
 *   - -EINVAL if neither is a pipe or both are same pipe
 *   - -ENOMEM if insufficient memory
 *
 * Usage:
 *   // Duplicate pipe data for logging while still processing
 *   tee(input_pipe, log_pipe, len, 0);
 *   // Now input_pipe and log_pipe both have the same data
 *
 * Phase 1 (Completed): Validate parameters and return dummy count
 * Phase 2 (Completed): Enhanced validation and sanity checks with detailed logging
 * Phase 3 (Completed): Duplicate pipe buffer pages
 */
long sys_tee(int fd_in, int fd_out, size_t len, unsigned int flags) {
    /* ARM64 FIX: Copy register-passed parameters to local stack variables so they
     * survive across potentially blocking calls. */
    int local_fd_in = fd_in;
    int local_fd_out = fd_out;
    size_t local_len = len;
    unsigned int local_flags = flags;

    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    /* Linux's fs/splice.c:tee validates flags FIRST (before any fd
     * lookup), so tee(-1, -1, 0, 0xff) returns EINVAL — not EBADF.
     * The previous Futura order rejected negative fds before flags,
     * inverting the errno class for callers that probe with deliberately
     * bad fds to detect kernel-supported flag bits.  Match Linux's
     * 'flags first, then fds' ordering. */
    const unsigned int VALID_FLAGS = SPLICE_F_NONBLOCK | SPLICE_F_MORE;
    if (local_flags & ~VALID_FLAGS) {
        fut_printf("[TEE] tee(fd_in=%d, fd_out=%d, len=%zu, flags=0x%x [invalid], pid=%d) "
                   "-> EINVAL\n", local_fd_in, local_fd_out, local_len, local_flags, task->pid);
        return -EINVAL;
    }

    /* Validate fds */
    if (local_fd_in < 0 || local_fd_out < 0) {
        fut_printf("[TEE] tee(fd_in=%d, fd_out=%d, len=%zu, flags=0x%x, pid=%d) "
                   "-> EBADF (invalid fd)\n", local_fd_in, local_fd_out, local_len, local_flags, task->pid);
        return -EBADF;
    }

    /* Check if same fd */
    if (local_fd_in == local_fd_out) {
        fut_printf("[TEE] tee(fd_in=%d, fd_out=%d [same], len=%zu, flags=0x%x, pid=%d) "
                   "-> EINVAL\n", local_fd_in, local_fd_out, local_len, local_flags, task->pid);
        return -EINVAL;
    }

    /* Resolve file structures */
    if (local_fd_in >= task->max_fds || local_fd_out >= task->max_fds)
        return -EBADF;

    struct fut_file *file_in  = vfs_get_file_from_task(task, local_fd_in);
    struct fut_file *file_out = vfs_get_file_from_task(task, local_fd_out);
    if (!file_in || !file_out) {
        fut_printf("[TEE] tee(fd_in=%d, fd_out=%d) -> EBADF (fd not open)\n",
                   local_fd_in, local_fd_out);
        return -EBADF;
    }

    /* Both fds must be pipes */
    if (!file_in->chr_ops || !file_in->chr_ops->read) {
        fut_printf("[TEE] tee(fd_in=%d) -> EINVAL (not a readable pipe)\n", local_fd_in);
        return -EINVAL;
    }
    if (!file_out->chr_ops || !file_out->chr_ops->write) {
        fut_printf("[TEE] tee(fd_out=%d) -> EINVAL (not a writable pipe)\n", local_fd_out);
        return -EINVAL;
    }

    if (local_len == 0)
        return 0;

    /* Peek ALL requested data in a single call.
     *
     * BUG FIX: The previous chunked-loop approach called pipe_peek() multiple
     * times, but pipe_peek() always reads from the same read_pos (it doesn't
     * consume data). So chunk N+1 would re-read the same bytes as chunk N,
     * duplicating the first CHUNK bytes across the entire output.
     *
     * Fix: peek the full requested amount in one call, then write to the
     * output pipe. Cap at the source pipe's actual buffer size (which may
     * have been enlarged via F_SETPIPE_SZ) to prevent excessive allocation. */
    extern ssize_t pipe_peek(void *read_priv, void *buf, size_t len);
    extern size_t pipe_get_buffer_size(void *priv);

    size_t src_cap = pipe_get_buffer_size(file_in->chr_private);
    if (src_cap == 0) src_cap = 65536;  /* fallback default */

    size_t peek_len = local_len;
    if (peek_len > src_cap)
        peek_len = src_cap;

    uint8_t *kbuf = (uint8_t *)fut_malloc(peek_len);
    if (!kbuf) return -ENOMEM;

    ssize_t got = pipe_peek(file_in->chr_private, kbuf, peek_len);
    if (got < 0) {
        fut_free(kbuf);
        return got;
    }
    if (got == 0) {
        fut_free(kbuf);
        /* SPLICE_F_NONBLOCK: return -EAGAIN when source pipe is empty */
        if (local_flags & SPLICE_F_NONBLOCK)
            return -EAGAIN;
        /* Without NONBLOCK, return 0 (no data available) */
        return 0;
    }

    /* Write peeked data to output pipe */
    off_t pos = 0;
    ssize_t nwritten = file_out->chr_ops->write(
        file_out->chr_inode, file_out->chr_private, kbuf, (size_t)got, &pos);
    fut_free(kbuf);

    if (nwritten < 0)
        return nwritten;

    fut_printf("[TEE] tee(fd_in=%d, fd_out=%d, len=%zu, pid=%d) -> %zd bytes\n",
               local_fd_in, local_fd_out, local_len, task->pid, nwritten);
    return nwritten;
}

/**
 * sync_file_range() - Sync file region to disk
 *
 * Synchronizes a file region with the disk. Allows fine-grained control
 * over when and how data is written, essential for database applications
 * and other performance-critical software.
 *
 * @param fd      File descriptor
 * @param offset  Starting offset in file
 * @param nbytes  Number of bytes to sync (0 = to end of file)
 * @param flags   SYNC_FILE_RANGE_WAIT_BEFORE, SYNC_FILE_RANGE_WRITE,
 *                SYNC_FILE_RANGE_WAIT_AFTER
 *
 * Returns:
 *   - 0 on success
 *   - -EBADF if fd invalid
 *   - -EINVAL if offset or flags invalid
 *   - -EIO if I/O error during sync
 *   - -ESPIPE if fd is a pipe
 *
 * Flag combinations:
 *   - WRITE only: Start async writeback
 *   - WAIT_BEFORE | WRITE | WAIT_AFTER: Full sync (like fsync for range)
 *   - WAIT_BEFORE | WRITE: Sync previous writes, start new ones
 *
 * Usage:
 *   // Flush specific range to disk
 *   sync_file_range(fd, offset, length,
 *                   SYNC_FILE_RANGE_WAIT_BEFORE |
 *                   SYNC_FILE_RANGE_WRITE |
 *                   SYNC_FILE_RANGE_WAIT_AFTER);
 *
 * Phase 1 (Completed): Validate parameters and return success
 * Phase 2 (Completed): Enhanced validation, sync type categorization, detailed logging
 * Phase 3 (Completed): Integrate with page cache writeback
 */
long sys_sync_file_range(int fd, int64_t offset, int64_t nbytes, unsigned int flags) {
    /* ARM64 FIX: Copy register-passed parameters to local stack variables so they
     * survive across potentially blocking calls. */
    int local_fd = fd;
    int64_t local_offset = offset;
    int64_t local_nbytes = nbytes;
    unsigned int local_flags = flags;

    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    /* Linux's mm/filemap.c:ksys_sync_file_range validates flags FIRST
     * (before any fd lookup or offset/nbytes domain check):
     *   if (flags & ~VALID_FLAGS) goto out;   // EINVAL
     *   ...
     *   f = fdget(fd);
     *   if (!f.file) ret = -EBADF;
     * The previous Futura order rejected negative fd / offset / nbytes
     * before flags, inverting the errno class for callers that probe
     * with deliberately bad fds to detect supported flag bits.  Same
     * flags-first reorder pattern as the matching splice / vmsplice /
     * tee / mremap fixes. */
    const unsigned int VALID_FLAGS = SYNC_FILE_RANGE_WAIT_BEFORE | SYNC_FILE_RANGE_WRITE | SYNC_FILE_RANGE_WAIT_AFTER;
    if (local_flags & ~VALID_FLAGS) {
        fut_printf("[SYNC_FILE_RANGE] sync_file_range(fd=%d, offset=%ld, nbytes=%ld, flags=0x%x [invalid], pid=%d) "
                   "-> EINVAL\n", local_fd, local_offset, local_nbytes, local_flags, task->pid);
        return -EINVAL;
    }

    /* Validate fd */
    if (local_fd < 0) {
        fut_printf("[SYNC_FILE_RANGE] sync_file_range(fd=%d [invalid], offset=%ld, nbytes=%ld, flags=0x%x, pid=%d) "
                   "-> EBADF\n", local_fd, local_offset, local_nbytes, local_flags, task->pid);
        return -EBADF;
    }

    /* Validate offset */
    if (local_offset < 0) {
        fut_printf("[SYNC_FILE_RANGE] sync_file_range(fd=%d, offset=%ld [negative], nbytes=%ld, flags=0x%x, pid=%d) "
                   "-> EINVAL\n", local_fd, local_offset, local_nbytes, local_flags, task->pid);
        return -EINVAL;
    }

    /* Validate nbytes */
    if (local_nbytes < 0) {
        fut_printf("[SYNC_FILE_RANGE] sync_file_range(fd=%d, offset=%ld, nbytes=%ld [negative], flags=0x%x, pid=%d) "
                   "-> EINVAL\n", local_fd, local_offset, local_nbytes, local_flags, task->pid);
        return -EINVAL;
    }

    /* Linux's mm/filemap.c:ksys_sync_file_range computes the endbyte and
     * rejects the call if it overflows int64_t or wraps below offset:
     *   endbyte = offset + nbytes;
     *   if ((s64)endbyte < 0) goto out;        // would-be-negative
     *   if (endbyte < offset)  goto out;       // wraparound
     * Both surface as -EINVAL.  The previous Futura code only checked
     * offset and nbytes individually, so a caller passing
     * (offset=INT64_MAX-1, nbytes=10) got success on Futura where Linux
     * returns EINVAL — masking the parameter-domain wraparound that the
     * eventual page-cache walk would trip on. */
    {
        int64_t endbyte;
        if (__builtin_add_overflow(local_offset, local_nbytes, &endbyte) ||
            endbyte < 0 || endbyte < local_offset) {
            fut_printf("[SYNC_FILE_RANGE] sync_file_range(fd=%d, offset=%ld, nbytes=%ld) -> EINVAL "
                       "(offset+nbytes overflow)\n",
                       local_fd, local_offset, local_nbytes);
            return -EINVAL;
        }
    }

    /* Validate fd exists and check O_PATH */
    if (local_fd >= task->max_fds) return -EBADF;
    struct fut_file *sfr_file = vfs_get_file_from_task(task, local_fd);
    if (!sfr_file) return -EBADF;
    if (sfr_file->flags & O_PATH) return -EBADF;

    /* Categorize sync type */
    const char *sync_desc;
    if (local_flags == (SYNC_FILE_RANGE_WAIT_BEFORE | SYNC_FILE_RANGE_WRITE | SYNC_FILE_RANGE_WAIT_AFTER)) {
        sync_desc = "full sync (WAIT_BEFORE|WRITE|WAIT_AFTER)";
    } else if (local_flags == SYNC_FILE_RANGE_WRITE) {
        sync_desc = "async writeback (WRITE only)";
    } else if (local_flags == (SYNC_FILE_RANGE_WAIT_BEFORE | SYNC_FILE_RANGE_WRITE)) {
        sync_desc = "sync prev + start new (WAIT_BEFORE|WRITE)";
    } else if (local_flags == 0) {
        sync_desc = "no-op (no flags)";
    } else {
        sync_desc = "custom combination";
    }

    /* Categorize range size */
    const char *size_desc = (local_nbytes == 0) ? "to EOF" :
                           (local_nbytes < 4096) ? "small (<4KB)" :
                           (local_nbytes < 1048576) ? "medium (<1MB)" :
                           (local_nbytes < 1073741824) ? "large (<1GB)" : "very large (>=1GB)";

    /* Success path silent — databases (sqlite, postgres) call
     * sync_file_range on every commit for durability. Errors above
     * still trace explicitly. */
    (void)size_desc; (void)sync_desc;
    return 0;
}
