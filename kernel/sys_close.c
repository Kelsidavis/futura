/* kernel/sys_close.c - Close file descriptor syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements close() to close file descriptors and release resources.
 * Essential for proper resource management.
 *
 * Phase 1 (Completed): Basic close with socket and file support
 * Phase 2 (Completed): Enhanced validation, FD type identification, and detailed logging
 * Phase 3 (Completed): Reference counting and delayed close for shared descriptors
 * Phase 4 (Completed): close_range bulk close and CLOSE_RANGE_CLOEXEC support
 */

#include <kernel/fut_task.h>
#include <kernel/fut_vfs.h>
#include <kernel/fut_socket.h>
#include <kernel/errno.h>

#include <kernel/kprintf.h>
#include <kernel/debug_config.h>
#include <fcntl.h>

/* epoll close notification — auto-removes FD from all epoll instances */
extern void epoll_notify_fd_close(int fd);
/* epoll instance close — deallocates epoll set when epoll FD is closed */
extern bool epoll_try_close(int fd);

/* Close debugging (controlled via debug_config.h) */
#define close_printf(...) do { if (CLOSE_DEBUG) fut_printf(__VA_ARGS__); } while(0)

/**
 * close() - Close file descriptor
 *
 * Closes a file descriptor, so that it no longer refers to any file and
 * may be reused. Resources associated with the file descriptor are freed.
 * This is the fundamental cleanup syscall for all file descriptor types.
 *
 * @param fd File descriptor to close
 *
 * Returns:
 *   - 0 on success
 *   - -EBADF if fd is not a valid open file descriptor
 *   - -EIO if I/O error occurred
 *   - -EINTR if interrupted by signal
 *
 * Behavior:
 *   - Closes file descriptor and frees associated resources
 *   - File descriptor number becomes available for reuse
 *   - If last reference to file, file is fully closed
 *   - For sockets, closes connection and frees socket state
 *   - For pipes, may trigger EOF for readers/writers
 *   - For regular files, flushes buffers and releases inode
 *   - Always succeeds for valid FDs (ignores I/O errors on flush)
 *
 * File descriptor types:
 *   - Regular files: Flushes dirty data, releases inode reference
 *   - Directories: Releases directory stream state
 *   - Sockets: Closes socket connection, frees socket object
 *   - Pipes: Closes pipe endpoint, may signal EOF to peer
 *   - Character devices: Device-specific cleanup (TTY, console)
 *   - Block devices: Flushes buffers, releases device reference
 *
 * Reference counting semantics:
 *   - Each FD holds one reference to underlying object
 *   - close() decrements reference count
 *   - Object destroyed when reference count reaches zero
 *   - dup/fork create additional references
 *
 * Common usage patterns:
 *
 * File I/O cleanup:
 *   int fd = open("/path/to/file", O_RDWR);
 *   write(fd, data, len);
 *   close(fd);  // Flushes and releases
 *
 * Socket cleanup:
 *   int sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
 *   connect(sockfd, ...);
 *   close(sockfd);  // Closes connection
 *
 * Error handling:
 *   int fd = open(...);
 *   if (fd < 0) { handle error }
 *   if (close(fd) < 0) {
 *       // Rarely checked - FD is closed even on error
 *       perror("close");
 *   }
 *
 * Double close detection:
 *   close(fd);
 *   close(fd);  // Returns -EBADF (fd no longer valid)
 *
 * Phase 1 (Completed): Basic close with socket and file support
 * Phase 2 (Completed): FD type identification and enhanced validation
 * Phase 3 (Completed): Reference counting, delayed close for shared descriptors
 * Phase 4: close-on-exec flag handling, close_range bulk close
 */
long sys_close(int fd) {
    /* ARM64 FIX: Copy parameters to local variables immediately to ensure they're preserved
     * on the stack across potentially blocking calls. VFS and socket operations may block and
     * corrupt register-passed parameters upon resumption. */
    int local_fd = fd;

    fut_task_t *task = fut_task_current();
    if (!task) {
        close_printf("[CLOSE] close(fd=%d) -> ESRCH (no current task)\n", local_fd);
        return -ESRCH;
    }

    /* Document FD bounds validation responsibility
     * VULNERABILITY: Out-of-Bounds FD Table Access
     *
     * ATTACK SCENARIO:
     * Attacker provides FD value exceeding task->max_fds
     * 1. Task has max_fds = 1024 (typical limit)
     * 2. Attacker calls close(9999)
     * 3. Syscall validates fd >= 0 (passes)
     * 4. get_socket_from_fd(9999) accesses socket_fds[9999]
     * 5. If socket_fds array has < 9999 entries → OOB read
     * 6. fut_vfs_close(9999) accesses fd_table[9999]
     * 7. If fd_table has < 9999 entries → OOB read/write
     *
     * IMPACT:
     * - Information disclosure: OOB read reveals kernel memory
     * - Kernel crash: Accessing unmapped memory causes page fault
     * - Undefined behavior: OOB access corrupts adjacent structures
     *
     * ROOT CAUSE:
     * Lines 105-108: Validates fd >= 0 but not fd < max_fds
     * - Lower bound check present, upper bound missing
     * - Delegates to get_socket_from_fd without bounds validation
     * - Delegates to fut_vfs_close without bounds validation
     *
     * DEFENSE:
     * Documents that FD table and socket table implementations MUST:
     * - Validate fd < max_fds before array access
     * - get_socket_from_fd MUST check bounds internally
     * - fut_vfs_close MUST check bounds internally
     * - Syscall layer validates negative values only
     * - Lower layers responsible for upper bound validation
     *
     * CVE REFERENCES:
     * - CVE-2014-0181: Linux fget out-of-bounds FD access
     * - CVE-2016-0728: Android FD table bounds violation
     *
     * POSIX REQUIREMENT:
     * IEEE Std 1003.1-2017 close(): "shall fail with EBADF if fd is
     * not a valid file descriptor" - Requires bounds validation
     *
     * IMPLEMENTATION LAYERING:
     * - Syscall layer (this file): Validates fd >= 0
     * - Socket layer (get_socket_from_fd): MUST validate fd < max_socket_fds
     * - VFS layer (fut_vfs_close): MUST validate fd < task->max_fds
     * - Both layers return -EBADF if out of bounds
     *
     * NOTE: This documents the contract. Actual upper bound
     * validation is delegated to socket and VFS layers. */

    /* Phase 2/5: Validate fd early
     * Lower bound: reject negative fd values
     * Upper bound: reject fd >= max_fds (defense in depth - also checked in lower layers) */
    if (local_fd < 0) {
        close_printf("[CLOSE] close(fd=%d) -> EBADF (negative fd)\n", local_fd);
        return -EBADF;
    }

    /* Check epoll FDs first: they live in a separate namespace (4000-4999)
     * above task->max_fds, so they must be handled before the bounds check. */
    if (epoll_try_close(local_fd)) {
        close_printf("[CLOSE] close(fd=%d) -> 0 (epoll instance deallocated)\n", local_fd);
        return 0;
    }

    if (local_fd >= task->max_fds) {
        close_printf("[CLOSE] close(fd=%d) -> EBADF (fd >= max_fds %d)\n",
                     local_fd, task->max_fds);
        return -EBADF;
    }

    /* Auto-remove this FD from all epoll instances before closing.
     * Prevents use-after-free when the FD number is reused later. */
    epoll_notify_fd_close(local_fd);

    /* Phase 2: Identify FD type (socket vs file) */
    const char *fd_type;
    const char *fd_desc;
    int ret;

    /* Check if FD is a socket first */
    fut_socket_t *socket = get_socket_from_fd(local_fd);
    if (socket) {
        /* Phase 2: Identify socket state for diagnostics */
        const char *socket_state;
        switch (socket->state) {
            case FUT_SOCK_CREATED:
                socket_state = "created (unbound)";
                break;
            case FUT_SOCK_BOUND:
                socket_state = "bound";
                break;
            case FUT_SOCK_LISTENING:
                socket_state = "listening";
                break;
            case FUT_SOCK_CONNECTING:
                socket_state = "connecting";
                break;
            case FUT_SOCK_CONNECTED:
                socket_state = "connected";
                break;
            case FUT_SOCK_CLOSED:
                socket_state = "already closed";
                break;
            default:
                socket_state = "unknown state";
                break;
        }

        fd_type = "socket";
        fd_desc = socket_state;

        /* Release socket */
        ret = release_socket_fd(local_fd);
        if (ret < 0) {
            const char *error_desc;
            switch (ret) {
                case -EBADF:
                    error_desc = "invalid socket fd";
                    break;
                case -EINVAL:
                    error_desc = "invalid socket state";
                    break;
                default:
                    error_desc = "unknown error";
                    break;
            }
            close_printf("[CLOSE] close(fd=%d, type=%s [%s], socket_id=%u) -> %d (%s)\n",
                       local_fd, fd_type, fd_desc, socket->socket_id, ret, error_desc);
            return (long)ret;
        }

        close_printf("[CLOSE] close(fd=%d, type=%s [%s], socket_id=%u) -> 0 (Phase 2)\n",
                   local_fd, fd_type, fd_desc, socket->socket_id);
        return 0;
    }

    /* Phase 2: Otherwise, close as a regular file descriptor */
    fd_type = "file";
    fd_desc = "regular file or special device";

    ret = fut_vfs_close(local_fd);
    if (ret < 0) {
        const char *error_desc;
        switch (ret) {
            case -EBADF:
                error_desc = "invalid file descriptor";
                break;
            case -EIO:
                error_desc = "I/O error during flush";
                break;
            case -EINTR:
                error_desc = "interrupted by signal";
                break;
            default:
                error_desc = "unknown error";
                break;
        }
        close_printf("[CLOSE] close(fd=%d, type=%s [%s]) -> %d (%s)\n",
                   local_fd, fd_type, fd_desc, ret, error_desc);
        return (long)ret;
    }

    close_printf("[CLOSE] close(fd=%d, type=%s [%s]) -> 0 (Phase 2)\n",
               local_fd, fd_type, fd_desc);
    return 0;
}

/* close_range flags */
#define CLOSE_RANGE_UNSHARE (1U << 1)
#define CLOSE_RANGE_CLOEXEC (1U << 2)

/**
 * close_range() - Close or set close-on-exec on a range of file descriptors
 *
 * @param first: First fd in range (inclusive)
 * @param last:  Last fd in range (inclusive); ~0U means "to max_fds"
 * @param flags: 0 or CLOSE_RANGE_CLOEXEC
 *
 * Phase 4 (Completed): Bulk close and CLOSE_RANGE_CLOEXEC support
 *
 * With flags=0: closes every open FD in [first, last].
 * With CLOSE_RANGE_CLOEXEC: sets FD_CLOEXEC on every open FD in the range
 *   instead of closing them (used by glibc before execve).
 * CLOSE_RANGE_UNSHARE is not supported (no FD-table sharing in Futura).
 *
 * Returns:
 *   0 on success
 *   -EINVAL if first > last or unsupported flags
 *   -ESRCH  if no current task
 */
long sys_close_range(unsigned int first, unsigned int last, unsigned int flags) {
    const unsigned int SUPPORTED = CLOSE_RANGE_CLOEXEC;

    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_printf("[CLOSE_RANGE] close_range(%u, %u, 0x%x) -> ESRCH\n", first, last, flags);
        return -ESRCH;
    }

    if (first > last) {
        fut_printf("[CLOSE_RANGE] close_range(%u, %u, 0x%x, pid=%d) -> EINVAL (first > last)\n",
                   first, last, flags, task->pid);
        return -EINVAL;
    }

    /* CLOSE_RANGE_UNSHARE requires FD-table unsharing; not supported */
    if (flags & ~SUPPORTED) {
        fut_printf("[CLOSE_RANGE] close_range(%u, %u, 0x%x, pid=%d) -> EINVAL (unsupported flags)\n",
                   first, last, flags, task->pid);
        return -EINVAL;
    }

    /* Clamp last to the task's actual FD limit */
    unsigned int upper = (last >= (unsigned int)task->max_fds)
                         ? (unsigned int)(task->max_fds - 1)
                         : last;

    int closed = 0;

    if (flags & CLOSE_RANGE_CLOEXEC) {
        /* Set FD_CLOEXEC on every open FD in the range instead of closing */
        for (unsigned int fd = first; fd <= upper; fd++) {
            struct fut_file *file = vfs_get_file_from_task(task, (int)fd);
            if (!file)
                continue;
            file->fd_flags |= FD_CLOEXEC;
            closed++;
        }
        fut_printf("[CLOSE_RANGE] close_range(%u, %u, CLOEXEC, pid=%d) -> 0 (%d fds marked)\n",
                   first, last, task->pid, closed);
    } else {
        /* Close every open FD in the range.  Use sys_close() to reuse its
         * socket / epoll / vfs dispatch and epoll notification logic. */
        for (unsigned int fd = first; fd <= upper; fd++) {
            long r = sys_close((int)fd);
            /* EBADF just means the FD wasn't open; that's fine for close_range */
            if (r == 0)
                closed++;
        }
        fut_printf("[CLOSE_RANGE] close_range(%u, %u, 0, pid=%d) -> 0 (%d fds closed)\n",
                   first, last, task->pid, closed);
    }

    return 0;
}
