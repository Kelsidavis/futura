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
 *   Socket Address Families (Domains)
 * ============================================================ */

#ifndef AF_UNSPEC
#define AF_UNSPEC   0   /* Unspecified */
#endif
#ifndef AF_UNIX
#define AF_UNIX     1   /* Unix domain sockets (local IPC) */
#endif
#ifndef AF_LOCAL
#define AF_LOCAL    AF_UNIX  /* POSIX alias for AF_UNIX */
#endif
#ifndef AF_INET
#define AF_INET     2   /* IPv4 Internet protocols */
#endif
#ifndef AF_INET6
#define AF_INET6    10  /* IPv6 Internet protocols */
#endif
#ifndef AF_NETLINK
#define AF_NETLINK  16  /* Kernel user interface (netlink) */
#endif

/* IPv4 address constants */
#ifndef INADDR_ANY
#define INADDR_ANY       0x00000000U
#endif
#ifndef INADDR_LOOPBACK
#define INADDR_LOOPBACK  0x7f000001U  /* 127.0.0.1 in host byte order */
#endif

/* ============================================================
 *   Socket Types
 * ============================================================ */

#ifndef SOCK_STREAM
#define SOCK_STREAM     1   /* Connection-based byte streams */
#endif
#ifndef SOCK_DGRAM
#define SOCK_DGRAM      2   /* Connectionless datagrams */
#endif
#ifndef SOCK_RAW
#define SOCK_RAW        3   /* Raw network protocol access */
#endif
#ifndef SOCK_SEQPACKET
#define SOCK_SEQPACKET  5   /* Connection-based packets */
#endif

/* Socket type flags (OR'd with socket type) */
#ifndef SOCK_NONBLOCK
#define SOCK_NONBLOCK   0x800   /* Set O_NONBLOCK on new fd */
#endif
#ifndef SOCK_CLOEXEC
#define SOCK_CLOEXEC    0x80000 /* Set FD_CLOEXEC on new fd */
#endif

/* ============================================================
 *   Socket Option Levels
 * ============================================================ */

#ifndef SOL_SOCKET
#define SOL_SOCKET      1   /* Socket level options */
#endif
#ifndef IPPROTO_IP
#define IPPROTO_IP      0   /* IP protocol options */
#endif
#ifndef IPPROTO_TCP
#define IPPROTO_TCP     6   /* TCP protocol options */
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP     17  /* UDP protocol options */
#endif
#ifndef IPPROTO_IPV6
#define IPPROTO_IPV6    41  /* IPv6 protocol options */
#endif

/* ============================================================
 *   Common Socket Options (SOL_SOCKET level)
 * ============================================================ */

#ifndef SO_DEBUG
#define SO_DEBUG        1   /* Enable debugging */
#endif
#ifndef SO_REUSEADDR
#define SO_REUSEADDR    2   /* Allow address reuse */
#endif
#ifndef SO_TYPE
#define SO_TYPE         3   /* Get socket type */
#endif
#ifndef SO_ERROR
#define SO_ERROR        4   /* Get/clear error status */
#endif
#ifndef SO_DONTROUTE
#define SO_DONTROUTE    5   /* Bypass routing */
#endif
#ifndef SO_BROADCAST
#define SO_BROADCAST    6   /* Allow broadcast */
#endif
#ifndef SO_SNDBUF
#define SO_SNDBUF       7   /* Send buffer size */
#endif
#ifndef SO_RCVBUF
#define SO_RCVBUF       8   /* Receive buffer size */
#endif
#ifndef SO_KEEPALIVE
#define SO_KEEPALIVE    9   /* Keep connections alive */
#endif
#ifndef SO_OOBINLINE
#define SO_OOBINLINE    10  /* Leave OOB data inline */
#endif
#ifndef SO_LINGER
#define SO_LINGER       13  /* Linger on close */
#endif
#ifndef SO_REUSEPORT
#define SO_REUSEPORT    15  /* Allow port reuse */
#endif
#ifndef SO_RCVLOWAT
#define SO_RCVLOWAT     18  /* Receive low-water mark */
#endif
#ifndef SO_SNDLOWAT
#define SO_SNDLOWAT     19  /* Send low-water mark */
#endif
#ifndef SO_RCVTIMEO
#define SO_RCVTIMEO     20  /* Receive timeout */
#endif
#ifndef SO_SNDTIMEO
#define SO_SNDTIMEO     21  /* Send timeout */
#endif

/* ============================================================
 *   Message Flags (for send/recv)
 * ============================================================ */

#ifndef MSG_OOB
#define MSG_OOB         0x01    /* Out-of-band data */
#endif
#ifndef MSG_PEEK
#define MSG_PEEK        0x02    /* Peek at incoming message */
#endif
#ifndef MSG_DONTROUTE
#define MSG_DONTROUTE   0x04    /* Don't use routing */
#endif
#ifndef MSG_DONTWAIT
#define MSG_DONTWAIT    0x40    /* Non-blocking operation */
#endif
#ifndef MSG_WAITALL
#define MSG_WAITALL     0x100   /* Wait for full request */
#endif
#ifndef MSG_TRUNC
#define MSG_TRUNC       0x20    /* Data was truncated */
#endif
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL    0x4000  /* Don't raise SIGPIPE */
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
    /* Peer credentials captured at connect() time for SO_PEERCRED */
    uint32_t peer_pid;
    uint32_t peer_uid;
    uint32_t peer_gid;
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
    struct fut_waitq *epoll_notify;         /* Epoll wakeup on new connection */
} fut_socket_listener_t;

/* ============================================================
 *   Socket Pair (for connected sockets)
 * ============================================================ */

/**
 * Maximum number of in-flight file descriptors per socket pair direction.
 * Used for SCM_RIGHTS FD passing over Unix domain sockets.
 */
#define FUT_SOCKET_FD_QUEUE_MAX 16

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

    /* SCM_RIGHTS FD passing queue - stores file pointers in transit */
    struct fut_file *fd_queue[FUT_SOCKET_FD_QUEUE_MAX];
    uint32_t fd_queue_head;                 /* Dequeue position */
    uint32_t fd_queue_tail;                 /* Enqueue position */
    uint32_t fd_queue_count;                /* Number of FDs in queue */

    struct fut_waitq *epoll_notify;         /* Epoll wakeup on data arrival */
} fut_socket_pair_t;

#define FUT_SOCKET_BUFSIZE 4096  /* Per-direction buffer size */

/* ============================================================
 *   Datagram Queue (for SOCK_DGRAM sockets)
 * ============================================================ */

#define FUT_DGRAM_QUEUE_MAX 8    /* Max datagrams buffered */
#define FUT_DGRAM_DATA_MAX  1024 /* Max datagram payload */

/**
 * One datagram entry: sender address + data.
 */
typedef struct fut_dgram_entry {
    char     sender_path[108];  /* Sender's bound path (may start with '\0') */
    uint16_t sender_path_len;   /* Length including leading NUL for abstract */
    uint16_t data_len;          /* Payload length */
    uint8_t  data[FUT_DGRAM_DATA_MAX];
    /* AF_INET sender address (used when sender_path_len == 0 && sender_inet_port != 0) */
    uint32_t sender_inet_addr;  /* IPv4 address in network byte order */
    uint16_t sender_inet_port;  /* Port in network byte order */
} fut_dgram_entry_t;

/**
 * Per-socket datagram receive queue.
 * Allocated when a DGRAM socket is bound.
 */
typedef struct fut_dgram_queue {
    fut_dgram_entry_t msgs[FUT_DGRAM_QUEUE_MAX];
    uint32_t          head;       /* Dequeue index */
    uint32_t          count;      /* Number of messages */
    fut_spinlock_t    lock;
    struct fut_waitq *recv_waitq; /* Unblocks recvfrom() */
} fut_dgram_queue_t;

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
/* Magic value used to detect use-after-free on socket structs. */
#define FUT_SOCKET_MAGIC 0x534F434BU  /* "SOCK" */

typedef struct fut_socket {
    /* Identity and state */
    uint32_t magic;                         /* Must equal FUT_SOCKET_MAGIC while alive */
    enum fut_socket_state state;            /* Current socket state */
    uint32_t socket_id;                     /* Unique socket ID for debugging */

    /* Path binding (for all sockets) */
    char *bound_path;                       /* Path if bound (max 108 bytes) */
    uint16_t bound_path_len;               /* Length of bound_path (needed for abstract sockets) */
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
    uint32_t so_flags;                      /* Boolean SO_* options bitmask */
/* so_flags bits */
#define FUT_SO_F_REUSEADDR  (1u << 0)
#define FUT_SO_F_REUSEPORT  (1u << 1)
#define FUT_SO_F_KEEPALIVE  (1u << 2)
#define FUT_SO_F_BROADCAST  (1u << 3)
#define FUT_SO_F_OOBINLINE  (1u << 4)
#define FUT_SO_F_DONTROUTE  (1u << 5)
#define FUT_SO_F_DEBUG      (1u << 6)
#define FUT_SO_F_TIMESTAMP  (1u << 7)
#define FUT_SO_F_TIMESTAMPNS (1u << 8)

    /* Shutdown state (Phase 4) */
    bool shutdown_rd;                       /* Read channel shut down (SHUT_RD) */
    bool shutdown_wr;                       /* Write channel shut down (SHUT_WR) */

    /* Server-side socket flag (set by accept) */
    bool is_accepted;                       /* TRUE if this socket was returned by accept() */

    /* Credential passing (SO_PASSCRED) */
    bool passcred;                          /* Attach SCM_CREDENTIALS cmsg on every recvmsg */

    /* Framed recv truncation tracking (set by fut_socket_recv when a DGRAM/SEQPACKET
     * message is truncated to fit the caller's buffer; cleared before each recv).
     * Stores the full message length so MSG_TRUNC flag in recv/recvfrom can return
     * the actual datagram size per Linux semantics. 0 = not truncated. */
    uint32_t last_recv_full_msg_len;

    /* Datagram receive queue (SOCK_DGRAM only, allocated on bind) */
    fut_dgram_queue_t *dgram_queue;

    /* SOCK_DGRAM connected peer (set by connect(), cleared by connect(AF_UNSPEC)) */
    char dgram_peer_path[108];          /* Peer path (may start with '\0' for abstract) */
    uint16_t dgram_peer_path_len;       /* 0 = not connected */

    /* SO_RCVTIMEO / SO_SNDTIMEO: 0 = no timeout (block forever) */
    uint64_t rcvtimeo_ms;               /* Receive timeout in milliseconds */
    uint64_t sndtimeo_ms;               /* Send timeout in milliseconds */

    /* SO_LINGER: linger-on-close settings */
    int linger_onoff;                   /* l_onoff: 0=disabled (default) */
    int linger_secs;                    /* l_linger: delay in seconds */

    /* SO_SNDBUF / SO_RCVBUF: effective buffer sizes (stored doubled, like Linux) */
    uint32_t sndbuf;                    /* Send buffer size (default 2*FUT_SOCKET_BUFSIZE) */
    uint32_t rcvbuf;                    /* Receive buffer size (default 2*FUT_SOCKET_BUFSIZE) */

    /* SO_RCVLOWAT: receive low-water mark (default 1) */
    uint32_t rcvlowat;                  /* Min bytes before poll/select reports readable */

    /* IPPROTO_TCP options (stored for round-trip; enforcement is best-effort) */
    uint8_t  tcp_nodelay;      /* TCP_NODELAY (1) — disable Nagle */
    uint8_t  tcp_cork;         /* TCP_CORK (3) — cork output */
    uint32_t tcp_keepidle;     /* TCP_KEEPIDLE (4) — seconds */
    uint32_t tcp_keepintvl;    /* TCP_KEEPINTVL (5) — seconds */
    uint32_t tcp_keepcnt;      /* TCP_KEEPCNT (6) — count */
    uint32_t tcp_syncnt;       /* TCP_SYNCNT (7) — SYN retries */
    int32_t  tcp_linger2;      /* TCP_LINGER2 (8) — FIN_WAIT2 timeout */
    uint32_t tcp_defer_accept; /* TCP_DEFER_ACCEPT (9) — seconds */
    uint32_t tcp_maxseg;       /* TCP_MAXSEG (2) — segment size */
    uint8_t  tcp_quickack;     /* TCP_QUICKACK (12) — quick-ack mode */

    /* IPPROTO_IP options */
    uint8_t  ip_tos;           /* IP_TOS (1) */
    uint8_t  ip_ttl;           /* IP_TTL (2) — default 64 */
    uint8_t  ip_hdrincl;       /* IP_HDRINCL (3) */
    uint8_t  ip_recvtos;       /* IP_RECVTOS (13) */
    uint8_t  ip_recvttl;       /* IP_RECVTTL (12) */
    uint32_t ip_mtu_discover;  /* IP_MTU_DISCOVER (10) */

    /* IPPROTO_IPV6 options */
    uint8_t  ipv6_v6only;      /* IPV6_V6ONLY (26) */
    uint8_t  ipv6_tclass;      /* IPV6_TCLASS (67) */
    uint8_t  ipv6_recvtclass;  /* IPV6_RECVTCLASS (66) */

    /* AF_INET/AF_INET6 bound address (stored by bind(), returned by getsockname()) */
    uint32_t inet_addr;        /* IPv4 address (network byte order); 0 = unbound/any */
    uint16_t inet_port;        /* IPv4/IPv6 port (network byte order); 0 = unbound */
    uint8_t  inet6_addr[16];   /* IPv6 address (network byte order); all-zero = unbound */

    /* SO_PEERCRED: credentials of the connected peer (set at connect/accept time) */
    uint32_t peer_pid;
    uint32_t peer_uid;
    uint32_t peer_gid;

    /* AF_NETLINK pending response buffer (allocated on sendmsg, freed after recvmsg drains it) */
    uint8_t *nl_resp_buf;    /* heap-allocated response; NULL = nothing pending */
    uint32_t nl_resp_len;    /* total bytes in nl_resp_buf */
    uint32_t nl_resp_pos;    /* bytes already consumed by recvmsg */

    /* Pending error (SO_ERROR): set by async failures, read-and-cleared by getsockopt */
    int pending_error;

    /* AF_INET tcpip stack linkage (for external network I/O via tcpip.c) */
    void *inet_tcpip;   /* Points to tcpip_socket_t when connected to real network; NULL for loopback */

    /* Back-pointer to the VFS file struct for O_ASYNC/SIGIO delivery.
     * Set when the socket fd is allocated (socket(), accept(), socketpair()).
     * Checked by fut_socket_send() to deliver SIGIO to the peer. */
    struct fut_file *socket_file;

    /* Refcounting and lifecycle */
    uint64_t refcount;                      /* Reference count */
    struct fut_waitq *close_waitq;          /* Wait queue for close completion */
    struct fut_waitq *connect_waitq;        /* Wait queue for connect() completion */
    struct fut_waitq *connect_notify;       /* epoll/poll wait queue to wake when CONNECTING→CONNECTED */
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
 * For abstract sockets (path[0] == '\0'), path_len includes the leading NUL.
 *
 * @param socket   Socket to bind
 * @param path     Path to bind to (max 108 bytes; may start with '\0' for abstract)
 * @param path_len Length of path in bytes (strlen for filesystem, full len for abstract)
 * @return 0 on success, negative on error
 */
int fut_socket_bind(fut_socket_t *socket, const char *path, size_t path_len);

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
 * @param socket      Socket to connect
 * @param target_path Path of listening socket (may be abstract)
 * @param path_len    Length of target_path in bytes
 * @return 0 on success (immediately for AF_UNIX), negative on error
 */
int fut_socket_connect(fut_socket_t *socket, const char *target_path, size_t path_len);

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
 * Peek at data without consuming (MSG_PEEK).
 */
ssize_t fut_socket_recv_peek(fut_socket_t *socket, void *buf, size_t len);

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
int fut_socket_ref(fut_socket_t *socket);

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
 * @param path     Path to search for (may be abstract, starting with '\0')
 * @param path_len Length of path in bytes
 * @return Socket if found and listening, NULL otherwise
 */
fut_socket_t *fut_socket_find_listener(const char *path, size_t path_len);

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

/**
 * Find socket bound to the given path (any state including BOUND).
 * Used for SOCK_DGRAM delivery to unconnected sockets.
 * Returns the socket with an incremented refcount, or NULL.
 */
fut_socket_t *fut_socket_find_bound(const char *path, size_t path_len);

/**
 * Send datagram to socket bound at dest_path.
 * Routes directly to the destination socket's dgram_queue.
 * sender_path/sender_path_len identify the source (may be "", 0 for anonymous).
 *
 * @return Number of bytes sent, or negative error code.
 */
ssize_t fut_socket_sendto_dgram(const char *dest_path, size_t dest_path_len,
                                const char *sender_path, size_t sender_path_len,
                                const void *data, size_t data_len);

/**
 * Receive datagram from this socket's dgram_queue.
 * Blocks if empty (unless socket has O_NONBLOCK).
 * Fills sender_path_out[108] and *sender_path_len_out with source address.
 *
 * @return Number of data bytes returned, 0 if nothing, or negative error.
 */
ssize_t fut_socket_recvfrom_dgram(fut_socket_t *socket, void *buf, size_t len,
                                  char *sender_path_out, uint16_t *sender_path_len_out,
                                  size_t *actual_datagram_len_out);

ssize_t fut_socket_peek_dgram(fut_socket_t *socket, void *buf, size_t len,
                               char *sender_path_out, uint16_t *sender_path_len_out,
                               size_t *actual_datagram_len_out);

/* ============================================================
 *   AF_INET Socket Layer API (loopback + external)
 * ============================================================ */

/**
 * Find AF_INET listening socket by address and port.
 * Matches port exactly; addr matches if either side is INADDR_ANY or equal.
 * Returns socket with incremented refcount, or NULL.
 */
fut_socket_t *fut_socket_find_inet_listener(uint32_t addr, uint16_t port);

/**
 * Bind AF_INET socket to address:port.
 * Checks for port conflicts, allocates dgram_queue for SOCK_DGRAM.
 * addr/port in network byte order.
 */
int fut_socket_bind_inet(fut_socket_t *socket, uint32_t addr, uint16_t port);

/**
 * Connect AF_INET socket to listener by address:port (loopback path).
 * Queues connection with matching listener, returns immediately.
 * addr/port in network byte order.
 */
int fut_socket_connect_inet(fut_socket_t *socket, uint32_t addr, uint16_t port);

/**
 * Find AF_INET bound socket by address:port (any state: BOUND or LISTENING).
 * Used for UDP datagram delivery. Returns socket with incremented refcount.
 */
fut_socket_t *fut_socket_find_inet_bound(uint32_t addr, uint16_t port);

/**
 * Send datagram to AF_INET socket bound at dest addr:port.
 * Routes to the destination socket's dgram_queue.
 */
ssize_t fut_socket_sendto_inet_dgram(uint32_t dest_addr, uint16_t dest_port,
                                      uint32_t sender_addr, uint16_t sender_port,
                                      const void *data, size_t data_len);

/**
 * fut_socket_foreach - Iterate over all live (non-closed) sockets.
 *
 * Calls @cb once for each socket in the registry that is not NULL and not in
 * FUT_SOCK_CLOSED state.  @arg is passed through to each callback invocation.
 * The callback must not call fut_socket_foreach() recursively.
 */
void fut_socket_foreach(void (*cb)(const fut_socket_t *, void *), void *arg);
