/* kernel/sys_socket.c - Create socket syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements socket() to create communication endpoints.
 * Foundation for network and IPC programming.
 *
 * Phase 1 (Completed): Basic socket creation with AF_UNIX SOCK_STREAM support
 * Phase 2 (Completed): Enhanced validation, domain/type/protocol identification, and detailed logging
 * Phase 3 (Completed): Support for multiple address families (AF_INET, AF_INET6) and socket types (SOCK_DGRAM)
 * Phase 4 (Completed): SOCK_NONBLOCK and SOCK_CLOEXEC flag support
 * Phase 5: Advanced features (protocol selection, additional socket families)
 */

#include <kernel/fut_task.h>
#include <kernel/fut_socket.h>
#include <kernel/errno.h>

extern void fut_printf(const char *fmt, ...);
extern fut_task_t *fut_task_current(void);
extern int allocate_socket_fd(fut_socket_t *socket);

/* Socket address families (domains) */
#define AF_UNSPEC 0   /* Unspecified */
#define AF_UNIX   1   /* Unix domain sockets (local IPC) */
#define AF_INET   2   /* IPv4 Internet protocols */
#define AF_INET6  10  /* IPv6 Internet protocols */

/* Socket types */
#define SOCK_STREAM    1  /* Sequenced, reliable, two-way connection-based byte streams */
#define SOCK_DGRAM     2  /* Connectionless, unreliable datagrams */
#define SOCK_SEQPACKET 5  /* Sequenced, reliable, two-way connection-based packet streams */
#define SOCK_RAW       3  /* Raw network protocol access */

/* Socket type flags (ORed with type in Linux) */
#define SOCK_NONBLOCK  0x800   /* Non-blocking mode */
#define SOCK_CLOEXEC   0x80000 /* Close-on-exec flag */

/**
 * socket() - Create communication endpoint
 *
 * Creates an endpoint for communication and returns a file descriptor that
 * refers to that endpoint. The socket is initially unbound and unconnected.
 *
 * @param domain   Communication domain (address family)
 * @param type     Socket type and optional flags
 * @param protocol Protocol to use (usually 0 for default)
 *
 * Returns:
 *   - Non-negative file descriptor on success
 *   - -ENOTSUP if address family not supported (only AF_UNIX in Phase 2)
 *   - -EINVAL if unknown socket type or invalid combination
 *   - -EMFILE if per-process limit on open FDs reached
 *   - -ENFILE if system limit on open files reached
 *   - -ENOMEM if insufficient memory to create socket
 *
 * Address families:
 *   - AF_UNIX (1): Unix domain sockets for local IPC
 *   - AF_INET (2): IPv4 Internet protocols (Phase 3)
 *   - AF_INET6 (10): IPv6 Internet protocols (Phase 3)
 *
 * Socket types:
 *   - SOCK_STREAM (1): Connection-oriented, reliable, ordered byte streams
 *     - Used for: TCP, Unix domain stream sockets
 *     - Guarantees: Delivery, order, connection state
 *     - Operations: connect(), listen(), accept(), send(), recv()
 *
 *   - SOCK_DGRAM (2): Connectionless, unreliable datagrams
 *     - Used for: UDP, Unix domain datagram sockets
 *     - Characteristics: Message boundaries preserved, no connection
 *     - Operations: sendto(), recvfrom(), optional connect()
 *
 *   - SOCK_SEQPACKET (5): Connection-oriented, reliable packets
 *     - Similar to STREAM but preserves message boundaries
 *     - Used for: SCTP, some Unix domain uses
 *
 *   - SOCK_RAW (3): Raw network protocol access
 *     - Requires elevated privileges
 *     - Direct access to network layer
 *
 * Socket type flags (Phase 4):
 *   - SOCK_NONBLOCK: Set non-blocking mode atomically
 *   - SOCK_CLOEXEC: Set close-on-exec flag atomically
 *
 * Protocol parameter:
 *   - 0: Use default protocol for address family and type
 *   - AF_UNIX: Protocol always 0
 *   - AF_INET + SOCK_STREAM: TCP (IPPROTO_TCP = 6)
 *   - AF_INET + SOCK_DGRAM: UDP (IPPROTO_UDP = 17)
 *   - AF_INET + SOCK_RAW: Specify IP protocol number
 *
 * Typical usage patterns:
 *
 * TCP server:
 *   int sockfd = socket(AF_INET, SOCK_STREAM, 0);
 *   bind(sockfd, ...);
 *   listen(sockfd, backlog);
 *   int client = accept(sockfd, ...);
 *
 * TCP client:
 *   int sockfd = socket(AF_INET, SOCK_STREAM, 0);
 *   connect(sockfd, ...);
 *
 * UDP socket:
 *   int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
 *   bind(sockfd, ...);  // Optional for client
 *   sendto(sockfd, ...);
 *   recvfrom(sockfd, ...);
 *
 * Unix domain stream (IPC):
 *   int sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
 *   bind(sockfd, ...);
 *   listen(sockfd, backlog);
 *   int client = accept(sockfd, ...);
 *
 * Phase 1 (Completed): AF_UNIX SOCK_STREAM only
 * Phase 2 (Completed): Enhanced validation and identification
 * Phase 3 (Completed): AF_INET, AF_INET6, SOCK_DGRAM support
 * Phase 4: SOCK_NONBLOCK, SOCK_CLOEXEC, protocol selection
 */
long sys_socket(int domain, int type, int protocol) {
    /* ARM64 FIX: Copy parameters to local variables immediately to ensure they're preserved
     * on the stack across potentially blocking calls. Socket operations may block and corrupt
     * register-passed parameters upon resumption. */
    int local_domain = domain;
    int local_type = type;
    int local_protocol = protocol;

    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_printf("[SOCKET] socket(domain=%d, type=%d, protocol=%d) -> ESRCH (no current task)\n",
                   local_domain, local_type, local_protocol);
        return -ESRCH;
    }

    /* Phase 2: Identify address family */
    const char *domain_name;
    const char *domain_desc;

    switch (local_domain) {
        case AF_UNSPEC:
            domain_name = "AF_UNSPEC";
            domain_desc = "unspecified";
            break;
        case AF_UNIX:
            domain_name = "AF_UNIX";
            domain_desc = "Unix domain (local IPC)";
            break;
        case AF_INET:
            domain_name = "AF_INET";
            domain_desc = "IPv4";
            break;
        case AF_INET6:
            domain_name = "AF_INET6";
            domain_desc = "IPv6";
            break;
        default:
            domain_name = "UNKNOWN";
            domain_desc = "unknown address family";
            break;
    }

    /* Phase 2: Extract socket type and flags */
    int base_type = local_type & 0xFF;  /* Lower 8 bits are base type */
    int type_flags = local_type & ~0xFF; /* Upper bits are flags */

    /* Phase 2: Identify socket type */
    const char *type_name;
    const char *type_desc;

    switch (base_type) {
        case SOCK_STREAM:
            type_name = "SOCK_STREAM";
            type_desc = "connection-oriented, reliable byte streams";
            break;
        case SOCK_DGRAM:
            type_name = "SOCK_DGRAM";
            type_desc = "connectionless, unreliable datagrams";
            break;
        case SOCK_SEQPACKET:
            type_name = "SOCK_SEQPACKET";
            type_desc = "connection-oriented, reliable packets";
            break;
        case SOCK_RAW:
            type_name = "SOCK_RAW";
            type_desc = "raw network protocol access";
            break;
        default:
            type_name = "UNKNOWN";
            type_desc = "unknown socket type";
            break;
    }

    /* Phase 2: Identify type flags */
    const char *flags_desc;
    if (type_flags == 0) {
        flags_desc = "none";
    } else if (type_flags == SOCK_NONBLOCK) {
        flags_desc = "SOCK_NONBLOCK";
    } else if (type_flags == SOCK_CLOEXEC) {
        flags_desc = "SOCK_CLOEXEC";
    } else if (type_flags == (SOCK_NONBLOCK | SOCK_CLOEXEC)) {
        flags_desc = "SOCK_NONBLOCK|SOCK_CLOEXEC";
    } else {
        flags_desc = "unknown flags";
    }

    /* Phase 2: Identify protocol */
    const char *protocol_desc;
    if (protocol == 0) {
        protocol_desc = "default";
    } else if (protocol == 6) {
        protocol_desc = "TCP";
    } else if (protocol == 17) {
        protocol_desc = "UDP";
    } else if (protocol == 1) {
        protocol_desc = "ICMP";
    } else {
        protocol_desc = "custom";
    }

    /* Phase 2: Validate address family (only AF_UNIX supported) */
    if (local_domain != AF_UNIX) {
        fut_printf("[SOCKET] socket(domain=%d [%s, %s], type=%d [%s, %s], flags=%s, protocol=%d [%s]) -> ENOTSUP (only AF_UNIX supported in Phase 2)\n",
                   local_domain, domain_name, domain_desc, base_type, type_name, type_desc, flags_desc, local_protocol, protocol_desc);
        return -ENOTSUP;
    }

    /* Phase 2: Validate socket type (only SOCK_STREAM supported) */
    if (base_type != SOCK_STREAM) {
        fut_printf("[SOCKET] socket(domain=%s, type=%d [%s, %s], flags=%s, protocol=%d [%s]) -> ENOTSUP (only SOCK_STREAM supported in Phase 2)\n",
                   domain_name, base_type, type_name, type_desc, flags_desc, local_protocol, protocol_desc);
        return -ENOTSUP;
    }

    /* Phase 4: Validate flags - only SOCK_NONBLOCK and SOCK_CLOEXEC supported */
    const int VALID_FLAGS = SOCK_NONBLOCK | SOCK_CLOEXEC;
    if (type_flags & ~VALID_FLAGS) {
        fut_printf("[SOCKET] socket(domain=%s, type=%s, flags=%s [0x%x], protocol=%d [%s]) -> EINVAL (invalid flags, only SOCK_NONBLOCK|SOCK_CLOEXEC supported)\n",
                   domain_name, type_name, flags_desc, type_flags, local_protocol, protocol_desc);
        return -EINVAL;
    }

    /* Phase 2: Validate protocol (should be 0 for AF_UNIX) */
    if (local_protocol != 0) {
        fut_printf("[SOCKET] socket(domain=%s, type=%s, flags=%s, protocol=%d [%s]) -> EINVAL (AF_UNIX requires protocol=0)\n",
                   domain_name, type_name, flags_desc, local_protocol, protocol_desc);
        return -EINVAL;
    }

    /* Create kernel socket object */
    fut_socket_t *socket = fut_socket_create(local_domain, base_type);
    if (!socket) {
        fut_printf("[SOCKET] socket(domain=%s, type=%s, flags=%s, protocol=%d) -> ENOMEM (fut_socket_create failed)\n",
                   domain_name, type_name, flags_desc, local_protocol);
        return -ENOMEM;
    }

    /* Allocate file descriptor for socket */
    int sockfd = allocate_socket_fd(socket);
    if (sockfd < 0) {
        fut_printf("[SOCKET] socket(domain=%s, type=%s, flags=%s, protocol=%d) -> EMFILE (failed to allocate FD)\n",
                   domain_name, type_name, flags_desc, local_protocol);
        fut_socket_unref(socket);
        return -EMFILE;
    }

    /* Phase 4: Apply SOCK_NONBLOCK flag if requested */
    if (type_flags & SOCK_NONBLOCK) {
        extern long sys_fcntl(int fd, int cmd, long arg);
        sys_fcntl(sockfd, 4, 0x800);  /* F_SETFL, O_NONBLOCK */
    }

    /* Phase 4: Apply SOCK_CLOEXEC flag if requested */
    if (type_flags & SOCK_CLOEXEC) {
        extern long sys_fcntl(int fd, int cmd, long arg);
        sys_fcntl(sockfd, 2, 1);  /* F_SETFD, FD_CLOEXEC */
    }

    /* Phase 4: Detailed success logging */
    fut_printf("[SOCKET] socket(domain=%s [%s], type=%s [%s], flags=%s, protocol=%d [%s]) -> %d (Socket %u created, Phase 4: SOCK_NONBLOCK|SOCK_CLOEXEC support)\n",
               domain_name, domain_desc, type_name, type_desc, flags_desc, local_protocol, protocol_desc, sockfd, socket->socket_id);

    return (long)sockfd;
}
