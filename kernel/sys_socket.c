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
 * Advanced features (protocol selection, additional socket families)
 */

#include <kernel/fut_task.h>
#include <kernel/fut_socket.h>
#include <kernel/fut_vfs.h>
#include <kernel/fut_memory.h>
#include <kernel/syscalls.h>
#include <kernel/errno.h>
#include <fcntl.h>
#include <string.h>

#include <kernel/kprintf.h>
#include <kernel/debug_config.h>

/* Socket debugging (controlled via debug_config.h) */
#define socket_printf(...) do { if (SOCKET_DEBUG) fut_printf(__VA_ARGS__); } while(0)

/* Socket constants (AF_*, SOCK_*) provided by fut_socket.h */

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
        socket_printf("[SOCKET] socket(domain=%d, type=%d, protocol=%d) -> ESRCH (no current task)\n",
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
        case AF_NETLINK:
            domain_name = "AF_NETLINK";
            domain_desc = "kernel netlink interface";
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

    /* Linux's net/socket.c:__sys_socket extracts SOCK flags FIRST and
     * rejects unknown bits BEFORE calling sock_create:
     *
     *   flags = type & ~SOCK_TYPE_MASK;
     *   if (flags & ~(SOCK_CLOEXEC | SOCK_NONBLOCK))
     *       return -EINVAL;
     *   type &= SOCK_TYPE_MASK;
     *   retval = sock_create(family, type, protocol, &sock);
     *
     * That ordering matters for callers probing the SOCK_* flag space
     * with a deliberately bad family — Linux returns EINVAL (flags),
     * Futura previously returned EAFNOSUPPORT (family) because the
     * family check ran first.  Hoist the flag gate so the errno class
     * matches Linux for libc feature-detection probes.  Test 68
     * (socket(AF_PACKET=17, SOCK_STREAM, 0)) passes valid flags and
     * still returns EAFNOSUPPORT under the new order. */
    const int VALID_FLAGS = SOCK_NONBLOCK | SOCK_CLOEXEC;
    if (type_flags & ~VALID_FLAGS) {
        socket_printf("[SOCKET] socket(domain=%s, type=%s, flags=%s [0x%x], protocol=%d [%s]) -> EINVAL (invalid flags, only SOCK_NONBLOCK|SOCK_CLOEXEC supported)\n",
                   domain_name, type_name, flags_desc, type_flags, local_protocol, protocol_desc);
        return -EINVAL;
    }

    /* Validate address family: AF_UNIX (full), AF_INET/AF_INET6 (stub), AF_NETLINK (stub) */
    if (local_domain != AF_UNIX && local_domain != AF_INET &&
        local_domain != AF_INET6 && local_domain != AF_NETLINK) {
        return -EAFNOSUPPORT;
    }

    /* Linux's __sock_create rejects negative protocol numbers with
     * -EINVAL ('if (protocol < 0 || protocol >= IPPROTO_MAX) return
     * -EINVAL'). Futura previously accepted any int as protocol, so
     * a typo like socket(AF_INET, SOCK_STREAM, -1) silently created a
     * socket with protocol=-1 that the lower layer would later treat
     * as wildcard. Reject up front to match Linux's gate. */
    if (local_protocol < 0 || local_protocol >= 256 /* IPPROTO_MAX */) {
        socket_printf("[SOCKET] socket(domain=%d, type=%d, protocol=%d) -> EINVAL "
                      "(protocol out of range, expected [0, IPPROTO_MAX=256))\n",
                      local_domain, local_type, local_protocol);
        return -EINVAL;
    }

    /* Validate socket type. Linux's per-family create() handlers
     * (net/unix/af_unix.c, net/ipv4/af_inet.c, net/netlink/af_netlink.c)
     * return -ESOCKTNOSUPPORT for an unsupported sock->type within a
     * known address family — not -EOPNOTSUPP (a.k.a. ENOTSUP). The
     * distinction matters: libc's socket() probes (e.g. glibc's
     * sock_type-fallback path) branch on ESOCKTNOSUPPORT to retry with
     * a different SOCK_* number, but treat EOPNOTSUPP as a fatal
     * runtime error and abort. */
    if (local_domain == AF_UNIX) {
        /* AF_UNIX supports SOCK_STREAM, SOCK_DGRAM, and SOCK_SEQPACKET */
        if (base_type != SOCK_STREAM && base_type != SOCK_DGRAM && base_type != SOCK_SEQPACKET) {
            return -ESOCKTNOSUPPORT;
        }
    } else if (local_domain == AF_NETLINK) {
        /* AF_NETLINK uses SOCK_RAW or SOCK_DGRAM */
        if (base_type != SOCK_RAW && base_type != SOCK_DGRAM) {
            return -ESOCKTNOSUPPORT;
        }
    } else {
        /* AF_INET/AF_INET6 support SOCK_STREAM, SOCK_DGRAM, and SOCK_RAW */
        if (base_type != SOCK_STREAM && base_type != SOCK_DGRAM && base_type != SOCK_RAW) {
            return -ESOCKTNOSUPPORT;
        }
    }

    /* SOCK_RAW on AF_INET/AF_INET6 lets a process see/inject raw IP
     * packets — Linux gates this behind CAP_NET_RAW. AF_NETLINK
     * SOCK_RAW is the standard netlink mode (libnl, ip(8), and most
     * tools open netlink sockets this way) and is not privileged on
     * Linux. AF_UNIX/etc don't allow SOCK_RAW; if they ever do, the
     * IP-style cap gate would still apply incorrectly to them, so
     * keep the check tight to the IP families. */
    if (base_type == SOCK_RAW &&
        (local_domain == AF_INET || local_domain == AF_INET6) &&
        task->uid != 0 &&
        !(task->cap_effective & (1ULL << 13 /* CAP_NET_RAW */))) {
        return -EPERM;
    }

    /* Validate protocol: AF_UNIX requires 0 or PF_UNIX (==AF_UNIX==1).
     * Linux's net/unix/af_unix.c:unix_create returns -EPROTONOSUPPORT
     * (not -EINVAL) for any other protocol value: protocol-domain errors
     * use the dedicated EPROTONOSUPPORT errno, while EINVAL is reserved
     * for malformed parameters. Futura previously collapsed both into
     * EINVAL, which broke libc socket() wrappers that branch on
     * EPROTONOSUPPORT to retry with a different protocol number. */
    if (local_domain == AF_UNIX && local_protocol != 0 &&
        local_protocol != AF_UNIX /* PF_UNIX */) {
        socket_printf("[SOCKET] socket(domain=%s, type=%s, flags=%s, protocol=%d [%s]) -> "
                   "EPROTONOSUPPORT (AF_UNIX accepts protocol=0 or PF_UNIX)\n",
                   domain_name, type_name, flags_desc, local_protocol, protocol_desc);
        return -EPROTONOSUPPORT;
    }

    /* Create kernel socket object */
    fut_socket_t *socket = fut_socket_create(local_domain, base_type);
    if (!socket) {
        socket_printf("[SOCKET] socket(domain=%s, type=%s, flags=%s, protocol=%d) -> ENOMEM (fut_socket_create failed)\n",
                   domain_name, type_name, flags_desc, local_protocol);
        return -ENOMEM;
    }

    /* Store protocol number (used by SOCK_RAW to identify packet type) */
    socket->protocol = local_protocol;

    /* SOCK_RAW sockets need a dgram queue for receiving packets */
    if (base_type == SOCK_RAW && (local_domain == AF_INET || local_domain == AF_INET6)) {
        fut_dgram_queue_t *dq = (fut_dgram_queue_t *)fut_malloc(sizeof(fut_dgram_queue_t));
        if (dq) {
            memset(dq, 0, sizeof(*dq));
            dq->recv_waitq = (fut_waitq_t *)fut_malloc(sizeof(fut_waitq_t));
            if (dq->recv_waitq) {
                extern void fut_waitq_init(fut_waitq_t *);
                fut_waitq_init(dq->recv_waitq);
            }
            fut_spinlock_init(&dq->lock);
            socket->dgram_queue = dq;
        }
    }

    /* Allocate file descriptor for socket */
    int sockfd = allocate_socket_fd(socket);
    if (sockfd < 0) {
        socket_printf("[SOCKET] socket(domain=%s, type=%s, flags=%s, protocol=%d) -> EMFILE (failed to allocate FD)\n",
                   domain_name, type_name, flags_desc, local_protocol);
        fut_socket_unref(socket);
        return -EMFILE;
    }

    /* Store file back-pointer for O_ASYNC/SIGIO delivery */
    {
        fut_task_t *ftask = fut_task_current();
        if (ftask && sockfd < ftask->max_fds && ftask->fd_table)
            socket->socket_file = ftask->fd_table[sockfd];
    }

    /* Apply SOCK_NONBLOCK and SOCK_CLOEXEC directly on the FD structure
     * to avoid race windows between fd allocation and flag application.
     * (Using sys_fcntl would leave a gap where another thread could
     * observe the fd without the requested flags.) */
    if (type_flags & (SOCK_NONBLOCK | SOCK_CLOEXEC)) {
        fut_task_t *stask = fut_task_current();
        if (stask && sockfd < stask->max_fds) {
            if (type_flags & SOCK_NONBLOCK) {
                /* Guard fd_table non-NULL: in symmetry with the back-pointer
                 * write above (line 319) which already gates on it. The
                 * previous bare index would NULL-deref the kernel for any
                 * caller without a populated fd_table. */
                if (stask->fd_table) {
                    struct fut_file *sfile = stask->fd_table[sockfd];
                    if (sfile)
                        sfile->flags |= O_NONBLOCK;
                }
                /* Also set on the socket struct so socket_nonblock()
                 * returns true in fut_socket_recv/send. */
                socket->flags |= O_NONBLOCK;
            }
            if (type_flags & SOCK_CLOEXEC) {
                /* Guard fd_flags non-NULL: lazily allocated, may be NULL
                 * for early-init / kernel-thread callers (same NULL-guard
                 * fix already applied to socketpair / accept / userfaultfd
                 * / pidfd_open / perf_event_open / fanotify_init). */
                if (stask->fd_flags)
                    stask->fd_flags[sockfd] |= FD_CLOEXEC;
            }
        }
    }

    /* Phase 4: Detailed success logging */
    socket_printf("[SOCKET] socket(domain=%s [%s], type=%s [%s], flags=%s, protocol=%d [%s]) -> %d (Socket %u created, Phase 4: SOCK_NONBLOCK|SOCK_CLOEXEC support)\n",
               domain_name, domain_desc, type_name, type_desc, flags_desc, local_protocol, protocol_desc, sockfd, socket->socket_id);

    return (long)sockfd;
}
