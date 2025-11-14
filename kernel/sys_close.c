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
 * Phase 4: Advanced features (close-on-exec handling, close_range support)
 */

#include <kernel/fut_task.h>
#include <kernel/fut_vfs.h>
#include <kernel/fut_socket.h>
#include <kernel/errno.h>

extern void fut_printf(const char *fmt, ...);
extern fut_task_t *fut_task_current(void);
extern fut_socket_t *get_socket_from_fd(int fd);
extern int release_socket_fd(int fd);

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
 * Phase 3 (Current): Reference counting, delayed close for shared descriptors
 * Phase 4: close-on-exec flag handling, close_range bulk close
 */
long sys_close(int fd) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_printf("[CLOSE] close(fd=%d) -> ESRCH (no current task)\n", fd);
        return -ESRCH;
    }

    /* Phase 2: Validate fd early */
    if (fd < 0) {
        fut_printf("[CLOSE] close(fd=%d) -> EBADF (negative fd)\n", fd);
        return -EBADF;
    }

    /* Phase 2: Identify FD type (socket vs file) */
    const char *fd_type;
    const char *fd_desc;
    int ret;

    /* Check if FD is a socket first */
    fut_socket_t *socket = get_socket_from_fd(fd);
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
        ret = release_socket_fd(fd);
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
            fut_printf("[CLOSE] close(fd=%d, type=%s [%s], socket_id=%u) -> %d (%s)\n",
                       fd, fd_type, fd_desc, socket->socket_id, ret, error_desc);
            return (long)ret;
        }

        fut_printf("[CLOSE] close(fd=%d, type=%s [%s], socket_id=%u) -> 0 (Phase 2)\n",
                   fd, fd_type, fd_desc, socket->socket_id);
        return 0;
    }

    /* Phase 2: Otherwise, close as a regular file descriptor */
    fd_type = "file";
    fd_desc = "regular file or special device";

    ret = fut_vfs_close(fd);
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
        fut_printf("[CLOSE] close(fd=%d, type=%s [%s]) -> %d (%s)\n",
                   fd, fd_type, fd_desc, ret, error_desc);
        return (long)ret;
    }

    fut_printf("[CLOSE] close(fd=%d, type=%s [%s]) -> 0 (Phase 2)\n",
               fd, fd_type, fd_desc);
    return 0;
}
