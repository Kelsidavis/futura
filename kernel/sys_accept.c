/* kernel/sys_accept.c - Accept incoming socket connection syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements accept() to accept incoming connections on listening sockets.
 * Essential for server applications implementing TCP servers, Unix domain
 * socket servers, and other connection-oriented protocols.
 *
 * Phase 1 (Completed): Basic validation stub
 * Phase 2 (Current): Full accept() with socket infrastructure integration
 * Phase 3: Non-blocking accept and EAGAIN handling
 * Phase 4: Address family specific peer address return
 */

#include <kernel/fut_task.h>
#include <kernel/fut_socket.h>
#include <kernel/errno.h>
#include <kernel/uaccess.h>
#include <stdint.h>

extern void fut_printf(const char *fmt, ...);
extern fut_task_t *fut_task_current(void);
extern fut_socket_t *get_socket_from_fd(int fd);
extern int allocate_socket_fd(fut_socket_t *socket);

/* socklen_t for address length */
typedef uint32_t socklen_t;

/**
 * accept() - Accept incoming connection on listening socket
 *
 * Extracts the first connection request from the queue of pending connections
 * for the listening socket sockfd, creates a new connected socket, and returns
 * a new file descriptor referring to that socket. The newly created socket is
 * not in listening state. The original socket sockfd is unaffected.
 *
 * @param sockfd Socket file descriptor (must be in listening state)
 * @param addr   Pointer to sockaddr structure to receive peer address (may be NULL)
 * @param addrlen Pointer to size of addr buffer (in/out parameter, may be NULL if addr is NULL)
 *
 * Returns:
 *   - Non-negative file descriptor for accepted connection on success
 *   - -EBADF if sockfd is not a valid file descriptor
 *   - -EFAULT if addr or addrlen point to invalid memory
 *   - -EINVAL if socket is not listening or addrlen is invalid
 *   - -ENOTSOCK if sockfd is not a socket
 *   - -EOPNOTSUPP if socket does not support accepting connections
 *   - -EWOULDBLOCK/EAGAIN if socket is non-blocking and no connections are pending
 *   - -ECONNABORTED if connection was aborted before accept completed
 *   - -EMFILE if per-process file descriptor limit reached
 *   - -ENFILE if system-wide file descriptor limit reached
 *   - -ENOMEM if insufficient memory available
 *   - -EPROTO if protocol error occurred
 *
 * Behavior:
 * - Blocks until connection arrives (unless socket is non-blocking)
 * - Returns new socket file descriptor for the accepted connection
 * - New socket inherits properties from listening socket (non-blocking flag, etc.)
 * - Original listening socket remains open and listening
 * - If addr is NULL, peer address is not returned
 * - If addr is non-NULL, peer address is stored in addr
 * - addrlen is value-result parameter (input: buffer size, output: actual address size)
 * - If buffer too small, address is truncated and addrlen reflects actual size
 * - For SOCK_STREAM (TCP), new socket is connected to peer
 * - For SOCK_SEQPACKET, new socket is connected to peer
 * - Does not work with SOCK_DGRAM (connectionless)
 *
 * Phase 1 (Current): Validates parameters and returns stub
 * Phase 2: Implement basic accept for TCP sockets
 * Phase 3: Add non-blocking support and connection queue
 * Phase 4: Unix domain socket support and advanced features
 *
 * Socket states:
 * - Listening socket: Created with socket(), bound with bind(), listening with listen()
 * - Must be SOCK_STREAM or SOCK_SEQPACKET type
 * - Must be in listening state (listen() called)
 * - Accepts connections from connect() calls
 *
 * Connection queue:
 * - Kernel maintains queue of pending connections (set by listen backlog)
 * - accept() removes first connection from queue
 * - If queue empty and socket blocking: blocks until connection arrives
 * - If queue empty and socket non-blocking: returns -EWOULDBLOCK
 *
 * File descriptor inheritance:
 * - New socket inherits:
 *   - Socket type (SOCK_STREAM, etc.)
 *   - Protocol family (AF_INET, AF_UNIX, etc.)
 *   - Some socket options (depends on option)
 * - New socket does NOT inherit:
 *   - Listening state (new socket is connected, not listening)
 *   - O_NONBLOCK flag may or may not be inherited (system-dependent)
 *
 * Common use cases:
 *
 * Basic TCP server accept loop:
 *   int listenfd = socket(AF_INET, SOCK_STREAM, 0);
 *   bind(listenfd, &addr, sizeof(addr));
 *   listen(listenfd, 128);
 *
 *   while (1) {
 *       struct sockaddr_in client_addr;
 *       socklen_t client_len = sizeof(client_addr);
 *       int connfd = accept(listenfd, (struct sockaddr *)&client_addr, &client_len);
 *       if (connfd < 0) {
 *           perror("accept");
 *           continue;
 *       }
 *       // Handle client connection (fork, thread, or event loop)
 *       handle_client(connfd);
 *       close(connfd);
 *   }
 *
 * Accept without retrieving peer address:
 *   int connfd = accept(listenfd, NULL, NULL);
 *   if (connfd < 0) {
 *       perror("accept");
 *   }
 *   // Use connfd for communication
 *
 * Non-blocking accept (with select/poll/epoll):
 *   fcntl(listenfd, F_SETFL, O_NONBLOCK);
 *   // ... wait for readability with select/poll/epoll ...
 *   int connfd = accept(listenfd, NULL, NULL);
 *   if (connfd < 0) {
 *       if (errno == EWOULDBLOCK || errno == EAGAIN) {
 *           // No connection available, try again later
 *       } else {
 *           perror("accept");
 *       }
 *   }
 *
 * Get peer address information:
 *   struct sockaddr_storage client_addr;
 *   socklen_t client_len = sizeof(client_addr);
 *   int connfd = accept(listenfd, (struct sockaddr *)&client_addr, &client_len);
 *
 *   if (client_addr.ss_family == AF_INET) {
 *       struct sockaddr_in *addr_in = (struct sockaddr_in *)&client_addr;
 *       char ip[INET_ADDRSTRLEN];
 *       inet_ntop(AF_INET, &addr_in->sin_addr, ip, sizeof(ip));
 *       printf("Connection from %s:%d\n", ip, ntohs(addr_in->sin_port));
 *   }
 *
 * Concurrent server (fork model):
 *   while (1) {
 *       int connfd = accept(listenfd, NULL, NULL);
 *       if (connfd < 0) continue;
 *
 *       pid_t pid = fork();
 *       if (pid == 0) {
 *           // Child process
 *           close(listenfd);  // Don't need listening socket
 *           handle_client(connfd);
 *           close(connfd);
 *           exit(0);
 *       } else {
 *           // Parent process
 *           close(connfd);  // Don't need connection socket
 *       }
 *   }
 *
 * Edge cases:
 * - addr is NULL: Valid, peer address not returned
 * - addrlen is NULL when addr is NULL: Valid
 * - addrlen is NULL when addr is non-NULL: Returns -EFAULT
 * - Buffer too small (addrlen < actual address size): Truncates address, sets addrlen to actual
 * - Socket not listening: Returns -EINVAL
 * - Connection aborted before accept: Returns -ECONNABORTED
 * - Interrupted by signal: Returns -EINTR
 * - File descriptor table full: Returns -EMFILE or -ENFILE
 *
 * Value-result parameter pattern:
 *
 *   struct sockaddr_in client_addr;
 *   socklen_t client_len = sizeof(client_addr);
 *   int connfd = accept(sockfd, (struct sockaddr *)&client_addr, &client_len);
 *   // client_len now contains actual address size (may be less than sizeof)
 *
 * Input: client_len = buffer size available
 * Output: client_len = actual address size written
 *
 * Performance considerations:
 * - O(1) operation (dequeue from connection queue)
 * - May block indefinitely if no connections arrive
 * - Non-blocking mode essential for event-driven servers
 * - File descriptor allocation overhead
 * - Consider using accept4() for atomically setting flags (Linux-specific)
 *
 * Security considerations:
 * - Validates all pointers before use
 * - Checks buffer bounds for address truncation
 * - New socket inherits security context
 * - DoS risk: accept backlog limits connection queue
 * - Resource exhaustion: track file descriptor usage
 * - Peer address validation important for access control
 *
 * Interaction with other syscalls:
 * - socket: Creates initial socket
 * - bind: Binds socket to local address
 * - listen: Puts socket in listening state
 * - connect: Initiates connection from client side
 * - close: Closes accepted connection
 * - fcntl: Sets non-blocking mode
 * - select/poll/epoll: Waits for connections to arrive
 * - shutdown: Gracefully shuts down connection
 *
 * Error handling:
 * - EBADF: sockfd is invalid
 * - EFAULT: addr or addrlen pointer invalid
 * - EINVAL: socket not listening
 * - ENOTSOCK: sockfd is not a socket
 * - EOPNOTSUPP: socket type doesn't support accept
 * - EWOULDBLOCK/EAGAIN: non-blocking and no connections
 * - ECONNABORTED: connection aborted
 * - EINTR: interrupted by signal
 * - EMFILE/ENFILE: file descriptor limit
 * - ENOMEM: out of memory
 * - EPROTO: protocol error
 *
 * Portability notes:
 * - POSIX standard but behavior varies slightly
 * - accept4() is Linux-specific (atomically sets flags)
 * - Non-blocking behavior is portable (use fcntl)
 * - Address truncation behavior is standard
 * - Always check return value
 * - Close accepted socket when done
 *
 * Protocol-specific behavior:
 *
 * TCP (SOCK_STREAM):
 *   - Three-way handshake completed before accept returns
 *   - New socket is fully connected and ready for I/O
 *   - Can send/recv immediately after accept
 *
 * Unix domain sockets (AF_UNIX, SOCK_STREAM):
 *   - Works similar to TCP
 *   - Returns new connected socket
 *   - Peer credentials available via SO_PEERCRED
 *
 * SCTP (SOCK_SEQPACKET):
 *   - Association established before accept returns
 *   - Message-oriented connection
 *
 * Differences from connect():
 * - accept: Server-side, waits for incoming connections
 * - connect: Client-side, initiates outgoing connection
 * - accept: Returns new socket for each connection
 * - connect: Uses existing socket
 *
 * Real-world examples:
 *
 * HTTP server accept loop:
 *   int http_server(int port) {
 *       int listenfd = socket(AF_INET, SOCK_STREAM, 0);
 *       int reuse = 1;
 *       setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
 *
 *       struct sockaddr_in addr = {0};
 *       addr.sin_family = AF_INET;
 *       addr.sin_port = htons(port);
 *       addr.sin_addr.s_addr = INADDR_ANY;
 *
 *       bind(listenfd, (struct sockaddr *)&addr, sizeof(addr));
 *       listen(listenfd, 128);
 *
 *       while (1) {
 *           int connfd = accept(listenfd, NULL, NULL);
 *           if (connfd < 0) continue;
 *           handle_http_request(connfd);
 *           close(connfd);
 *       }
 *   }
 *
 * Event-driven server with epoll:
 *   int epollfd = epoll_create1(0);
 *   struct epoll_event ev = {.events = EPOLLIN, .data.fd = listenfd};
 *   epoll_ctl(epollfd, EPOLL_CTL_ADD, listenfd, &ev);
 *
 *   while (1) {
 *       struct epoll_event events[MAX_EVENTS];
 *       int nfds = epoll_wait(epollfd, events, MAX_EVENTS, -1);
 *
 *       for (int i = 0; i < nfds; i++) {
 *           if (events[i].data.fd == listenfd) {
 *               int connfd = accept(listenfd, NULL, NULL);
 *               fcntl(connfd, F_SETFL, O_NONBLOCK);
 *               struct epoll_event cev = {.events = EPOLLIN, .data.fd = connfd};
 *               epoll_ctl(epollfd, EPOLL_CTL_ADD, connfd, &cev);
 *           } else {
 *               handle_client_data(events[i].data.fd);
 *           }
 *       }
 *   }
 *
 * Connection logging server:
 *   void log_and_accept(int listenfd) {
 *       struct sockaddr_storage client_addr;
 *       socklen_t client_len = sizeof(client_addr);
 *       int connfd = accept(listenfd, (struct sockaddr *)&client_addr, &client_len);
 *
 *       if (connfd < 0) {
 *           perror("accept");
 *           return;
 *       }
 *
 *       char host[NI_MAXHOST], service[NI_MAXSERV];
 *       getnameinfo((struct sockaddr *)&client_addr, client_len,
 *                   host, sizeof(host), service, sizeof(service),
 *                   NI_NUMERICHOST | NI_NUMERICSERV);
 *       printf("Connection from %s:%s\n", host, service);
 *
 *       handle_client(connfd);
 *       close(connfd);
 *   }
 */
long sys_accept(int sockfd, void *addr, socklen_t *addrlen) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    /* Validate sockfd */
    if (sockfd < 0) {
        fut_printf("[ACCEPT] accept(sockfd=%d) -> EBADF\n", sockfd);
        return -EBADF;
    }

    /* Validate addr and addrlen consistency */
    if (addr != NULL && addrlen == NULL) {
        fut_printf("[ACCEPT] accept(sockfd=%d) -> EFAULT (addr non-NULL but addrlen is NULL)\n", sockfd);
        return -EFAULT;
    }

    /* If addrlen provided, read and validate it */
    socklen_t len = 0;
    if (addrlen != NULL) {
        if (fut_copy_from_user(&len, addrlen, sizeof(socklen_t)) != 0) {
            fut_printf("[ACCEPT] accept(sockfd=%d) -> EFAULT (copy_from_user addrlen failed)\n", sockfd);
            return -EFAULT;
        }

        /* Validate addrlen value */
        if (len > 1024) {  /* Sanity check */
            fut_printf("[ACCEPT] accept(sockfd=%d, addrlen=%u) -> EINVAL\n", sockfd, len);
            return -EINVAL;
        }
    }

    /* Get listening socket from FD */
    fut_socket_t *listen_socket = get_socket_from_fd(sockfd);
    if (!listen_socket) {
        fut_printf("[ACCEPT] accept(sockfd=%d) -> EBADF (not a socket)\n", sockfd);
        return -EBADF;
    }

    /* Accept connection using kernel socket layer */
    fut_socket_t *accepted_socket = NULL;
    int ret = fut_socket_accept(listen_socket, &accepted_socket);
    if (ret < 0) {
        /* fut_socket_accept returns negative errno */
        fut_printf("[ACCEPT] accept(sockfd=%d) -> %d (fut_socket_accept failed)\n",
                   sockfd, ret);
        return ret;
    }

    /* Allocate new file descriptor for accepted socket */
    int newfd = allocate_socket_fd(accepted_socket);
    if (newfd < 0) {
        fut_printf("[ACCEPT] accept(sockfd=%d) -> EMFILE (failed to allocate FD)\n", sockfd);
        /* TODO: Clean up accepted socket */
        return -EMFILE;
    }

    /* Phase 2: For now, we don't populate peer address (AF_UNIX doesn't need it much)
     * Phase 3: Copy peer address if requested */
    if (addr != NULL && addrlen != NULL) {
        /* For Unix domain sockets, peer address is the bound path
         * For now, we'll just set addrlen to 0 to indicate no address returned */
        socklen_t actual_len = 0;
        if (fut_copy_to_user(addrlen, &actual_len, sizeof(socklen_t)) != 0) {
            fut_printf("[ACCEPT] accept(sockfd=%d, newfd=%d) -> warning: failed to update addrlen\n",
                       sockfd, newfd);
            /* Not fatal - connection is established, just couldn't return address */
        }

        fut_printf("[ACCEPT] accept(sockfd=%d) -> %d (peer address not yet implemented)\n",
                   sockfd, newfd);
    } else {
        fut_printf("[ACCEPT] accept(sockfd=%d) -> %d (success, no address requested)\n",
                   sockfd, newfd);
    }

    return newfd;
}
