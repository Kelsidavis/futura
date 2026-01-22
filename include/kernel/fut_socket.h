/* fut_socket.h - Futura OS Kernel Socket Object System
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Phase 3: Kernel-level socket object management for AF_UNIX SOCK_STREAM sockets.
 * Provides socket state machine, connection queueing, and blocking operations.
 */

#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <kernel/fut_sched.h>

/* Define ssize_t for freestanding environment */
#ifndef __ssize_t_defined
#define __ssize_t_defined 1
typedef int64_t ssize_t;
#endif

/* Define socklen_t for socket address lengths */
#ifndef __socklen_t_defined
#define __socklen_t_defined 1
typedef uint32_t socklen_t;
#endif

/* ============================================================
 *   Socket States
 * ============================================================ */

enum fut_socket_state {
    FUT_SOCK_CREATED = 0,       /* Newly created, unbound */
    FUT_SOCK_BOUND = 1,         /* Bound to path (not listening) */
    FUT_SOCK_LISTENING = 2,     /* Listening for connections */
    FUT_SOCK_CONNECTING = 3,    /* Connecting (pending) */
    FUT_SOCK_CONNECTED = 4,     /* Connected to peer */
    FUT_SOCK_CLOSED = 5,        /* Closed/invalid */
};

/* ============================================================
 *   Forward Declarations
 * ============================================================ */

struct fut_socket;
struct fut_socket_listener;
struct fut_socket_connection;
struct fut_vnode;

/* ============================================================
 *   Connection Queue Entry
 * ============================================================ */

/**
 * Pending connection in listener's accept queue.
 * Represents a connection attempt waiting to be accepted.
 */
typedef struct fut_socket_connection_entry {
    struct fut_socket *peer_socket;         /* Connected peer socket */
    uint32_t flags;                         /* Connection flags */
    uint64_t timestamp_ns;                  /* Connection time */
} fut_socket_connection_entry_t;

#define FUT_SOCKET_QUEUE_MAX 16  /* Maximum pending connections in backlog */

/* ============================================================
 *   Socket Listener State (for listening sockets)
 * ============================================================ */

/**
 * Listener state for sockets in LISTENING state.
 * Manages accept queue and backlog.
 */
typedef struct fut_socket_listener {
    fut_socket_connection_entry_t queue[FUT_SOCKET_QUEUE_MAX];  /* Accept queue */
    uint32_t queue_head;                    /* Queue head index */
    uint32_t queue_count;                   /* Number of pending connections */
    struct fut_waitq *accept_waitq;         /* Wait queue for accept() */
    int backlog;                            /* Maximum pending connections */
} fut_socket_listener_t;

/* ============================================================
 *   Socket Pair (for connected sockets)
 * ============================================================ */

/**
 * Socket pair for connected sockets.
 * Two sockets share a bidirectional connection with circular buffers.
 */
typedef struct fut_socket_pair {
    uint8_t *send_buf;                      /* Outgoing data buffer (4KB) */
    uint32_t send_head;                     /* Write position */
    uint32_t send_tail;                     /* Read position */
    uint32_t send_size;                     /* Buffer capacity */

    uint8_t *recv_buf;                      /* Incoming data buffer (4KB) */
    uint32_t recv_head;                     /* Write position */
    uint32_t recv_tail;                     /* Read position */
    uint32_t recv_size;                     /* Buffer capacity */

    struct fut_waitq *send_waitq;           /* Wait queue for send availability */
    struct fut_waitq *recv_waitq;           /* Wait queue for data availability */
    struct fut_socket *peer;                /* Connected peer socket */
    uint64_t refcount;                      /* Shared refcount */
    fut_spinlock_t lock;                    /* Spinlock for buffer synchronization */
} fut_socket_pair_t;

#define FUT_SOCKET_BUFSIZE 4096  /* Per-direction buffer size */

/* ============================================================
 *   Socket Object
 * ============================================================ */

/**
 * Kernel socket object (AF_UNIX SOCK_STREAM).
 * Manages socket state, connections, and I/O operations.
 *
 * Socket lifecycle:
 * 1. Created: socket() -> CREATED state
 * 2. Bound: bind() -> BOUND state
 * 3a. Listener: listen() -> LISTENING state, accept() returns CONNECTED sockets
 * 3b. Connected: connect() -> CONNECTED state, communicates via pair
 * 4. Closed: close() -> CLOSED state
 */
typedef struct fut_socket {
    /* Identity and state */
    enum fut_socket_state state;            /* Current socket state */
    uint32_t socket_id;                     /* Unique socket ID for debugging */

    /* Path binding (for all sockets) */
    char *bound_path;                       /* Path if bound (max 108 bytes) */
    struct fut_vnode *path_vnode;           /* VFS vnode for bound path */

    /* Listener state (if state == LISTENING) */
    fut_socket_listener_t *listener;        /* Listener queue, NULL if not listening */

    /* Connection state (if state == CONNECTED) */
    fut_socket_pair_t *pair;                /* Send/receive buffers (THIS socket sends, peer receives) */
    fut_socket_pair_t *pair_reverse;        /* Return direction (peer sends, THIS socket receives) */

    /* Socket options and flags */
    int flags;                              /* O_NONBLOCK, etc */
    int socket_type;                        /* SOCK_STREAM, etc (AF_UNIX only) */
    int address_family;                     /* AF_UNIX only */

    /* Shutdown state (Phase 4) */
    bool shutdown_rd;                       /* Read channel shut down (SHUT_RD) */
    bool shutdown_wr;                       /* Write channel shut down (SHUT_WR) */

    /* Server-side socket flag (set by accept) */
    bool is_accepted;                       /* TRUE if this socket was returned by accept() */

    /* Refcounting and lifecycle */
    uint64_t refcount;                      /* Reference count */
    struct fut_waitq *close_waitq;          /* Wait queue for close completion */
    struct fut_waitq *connect_waitq;        /* Wait queue for connect() completion */
} fut_socket_t;

/* ============================================================
 *   Socket System API
 * ============================================================ */

/**
 * Initialize socket subsystem.
 * Must be called during kernel initialization.
 */
void fut_socket_system_init(void);

/**
 * Create a new socket object.
 * Creates socket in CREATED state, unbound.
 *
 * @param family Address family (AF_UNIX)
 * @param type Socket type (SOCK_STREAM)
 * @return Socket object, or NULL on failure
 */
fut_socket_t *fut_socket_create(int family, int type);

/**
 * Bind socket to path.
 * Creates VFS inode for socket path, transitions to BOUND state.
 *
 * @param socket Socket to bind
 * @param path Path to bind to (max 108 bytes)
 * @return 0 on success, negative on error
 */
int fut_socket_bind(fut_socket_t *socket, const char *path);

/**
 * Mark socket as listening.
 * Allocates accept queue, transitions to LISTENING state.
 *
 * @param socket Socket to mark as listener
 * @param backlog Maximum pending connections
 * @return 0 on success, negative on error
 */
int fut_socket_listen(fut_socket_t *socket, int backlog);

/**
 * Accept pending connection on listening socket.
 * Blocks if no pending connections (unless O_NONBLOCK).
 *
 * @param listener Listening socket
 * @param out_socket Pointer to store accepted socket
 * @return 0 on success, -EAGAIN if no pending (non-blocking), negative on error
 */
int fut_socket_accept(fut_socket_t *listener, fut_socket_t **out_socket);

/**
 * Connect to listening socket.
 * Creates bidirectional connection, queues with listener.
 *
 * @param socket Socket to connect
 * @param target_path Path of listening socket
 * @return 0 on success (immediately for AF_UNIX), negative on error
 */
int fut_socket_connect(fut_socket_t *socket, const char *target_path);

/**
 * Send data on connected socket.
 * Blocks if send buffer full (unless O_NONBLOCK).
 *
 * @param socket Connected socket
 * @param buf Data to send
 * @param len Length of data
 * @return Number of bytes sent, -EAGAIN if would block, negative on error
 */
ssize_t fut_socket_send(fut_socket_t *socket, const void *buf, size_t len);

/**
 * Receive data from connected socket.
 * Blocks if no data available (unless O_NONBLOCK).
 *
 * @param socket Connected socket
 * @param buf Buffer for data
 * @param len Maximum bytes to receive
 * @return Number of bytes received, -EAGAIN if would block, 0 if closed, negative on error
 */
ssize_t fut_socket_recv(fut_socket_t *socket, void *buf, size_t len);

/**
 * Close socket and clean up resources.
 * Transitions to CLOSED state, frees buffers and listeners.
 *
 * @param socket Socket to close
 * @return 0 on success, negative on error
 */
int fut_socket_close(fut_socket_t *socket);

/**
 * Get reference to socket (increase refcount).
 *
 * @param socket Socket to reference
 */
void fut_socket_ref(fut_socket_t *socket);

/**
 * Release reference to socket (decrease refcount, may free).
 *
 * @param socket Socket to release
 */
void fut_socket_unref(fut_socket_t *socket);

/**
 * Find listening socket by bound path.
 * Used by connect() to locate target listener.
 *
 * @param path Path to search for
 * @return Socket if found and listening, NULL otherwise
 */
fut_socket_t *fut_socket_find_listener(const char *path);

/**
 * Check if socket is ready for I/O (for poll/select).
 *
 * @param socket Socket to check
 * @param events Requested events (POLLIN, POLLOUT, etc)
 * @return Bitmask of ready events
 */
int fut_socket_poll(fut_socket_t *socket, int events);

/* ============================================================
 *   File Descriptor / Socket Mapping (POSIX compatibility)
 * ============================================================ */

/**
 * Get socket structure from file descriptor.
 * Used by syscalls to translate FD to socket object.
 *
 * @param fd File descriptor
 * @return Socket pointer if fd is a socket, NULL otherwise
 */
fut_socket_t *get_socket_from_fd(int fd);

/**
 * Allocate a file descriptor for a socket.
 * Creates FD-to-socket mapping for POSIX syscall interface.
 *
 * @param socket Socket to allocate FD for
 * @return Non-negative FD on success, negative error code on failure
 */
int allocate_socket_fd(fut_socket_t *socket);

/**
 * Release a socket file descriptor.
 * Removes FD-to-socket mapping and cleans up resources.
 *
 * @param fd File descriptor to release
 * @return 0 on success, negative error code on failure
 */
int release_socket_fd(int fd);
