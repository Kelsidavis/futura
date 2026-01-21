// SPDX-License-Identifier: MPL-2.0
/*
 * sys/socket.h - Socket interface definitions
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Provides socket types, address families, and related constants
 * for the BSD socket interface.
 */

#pragma once

#include <stdint.h>
#include <stddef.h>

/* In hosted environment with system headers available, use them */
#if __has_include_next(<sys/socket.h>)
#include_next <sys/socket.h>
#else

/* ============================================================
 *   Address Families (Protocol Families)
 * ============================================================ */

#ifndef AF_UNSPEC
#define AF_UNSPEC       0       /* Unspecified */
#endif
#ifndef AF_UNIX
#define AF_UNIX         1       /* Unix domain sockets */
#endif
#ifndef AF_LOCAL
#define AF_LOCAL        AF_UNIX /* POSIX alias for AF_UNIX */
#endif
#ifndef AF_INET
#define AF_INET         2       /* IPv4 Internet protocols */
#endif
#ifndef AF_INET6
#define AF_INET6        10      /* IPv6 Internet protocols */
#endif
#ifndef AF_NETLINK
#define AF_NETLINK      16      /* Kernel user interface device */
#endif
#ifndef AF_PACKET
#define AF_PACKET       17      /* Low level packet interface */
#endif

/* Protocol families (same as address families) */
#ifndef PF_UNSPEC
#define PF_UNSPEC       AF_UNSPEC
#endif
#ifndef PF_UNIX
#define PF_UNIX         AF_UNIX
#endif
#ifndef PF_LOCAL
#define PF_LOCAL        AF_LOCAL
#endif
#ifndef PF_INET
#define PF_INET         AF_INET
#endif
#ifndef PF_INET6
#define PF_INET6        AF_INET6
#endif

/* ============================================================
 *   Socket Types
 * ============================================================ */

#ifndef SOCK_STREAM
#define SOCK_STREAM     1       /* Sequenced, reliable, connection-based byte streams */
#endif
#ifndef SOCK_DGRAM
#define SOCK_DGRAM      2       /* Connectionless, unreliable datagrams */
#endif
#ifndef SOCK_RAW
#define SOCK_RAW        3       /* Raw protocol interface */
#endif
#ifndef SOCK_SEQPACKET
#define SOCK_SEQPACKET  5       /* Sequenced, reliable, connection-based, datagrams */
#endif

/* Socket type flags (can be OR'd with socket type) */
#ifndef SOCK_NONBLOCK
#define SOCK_NONBLOCK   0x800   /* Set O_NONBLOCK on the new fd */
#endif
#ifndef SOCK_CLOEXEC
#define SOCK_CLOEXEC    0x80000 /* Set FD_CLOEXEC on the new fd */
#endif

/* ============================================================
 *   Socket Options (for setsockopt/getsockopt)
 * ============================================================ */

/* Option levels */
#ifndef SOL_SOCKET
#define SOL_SOCKET      1       /* Socket level options */
#endif
#ifndef IPPROTO_TCP
#define IPPROTO_TCP     6       /* TCP protocol options */
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP     17      /* UDP protocol options */
#endif
#ifndef IPPROTO_IP
#define IPPROTO_IP      0       /* IP protocol options */
#endif
#ifndef IPPROTO_IPV6
#define IPPROTO_IPV6    41      /* IPv6 protocol options */
#endif

/* SOL_SOCKET option names */
#ifndef SO_DEBUG
#define SO_DEBUG        1       /* Enable debugging */
#endif
#ifndef SO_REUSEADDR
#define SO_REUSEADDR    2       /* Allow local address reuse */
#endif
#ifndef SO_TYPE
#define SO_TYPE         3       /* Get socket type */
#endif
#ifndef SO_ERROR
#define SO_ERROR        4       /* Get and clear error status */
#endif
#ifndef SO_DONTROUTE
#define SO_DONTROUTE    5       /* Bypass routing */
#endif
#ifndef SO_BROADCAST
#define SO_BROADCAST    6       /* Allow broadcast */
#endif
#ifndef SO_SNDBUF
#define SO_SNDBUF       7       /* Send buffer size */
#endif
#ifndef SO_RCVBUF
#define SO_RCVBUF       8       /* Receive buffer size */
#endif
#ifndef SO_KEEPALIVE
#define SO_KEEPALIVE    9       /* Keep connections alive */
#endif
#ifndef SO_OOBINLINE
#define SO_OOBINLINE    10      /* Leave OOB data inline */
#endif
#ifndef SO_LINGER
#define SO_LINGER       13      /* Linger on close */
#endif
#ifndef SO_RCVTIMEO
#define SO_RCVTIMEO     20      /* Receive timeout */
#endif
#ifndef SO_SNDTIMEO
#define SO_SNDTIMEO     21      /* Send timeout */
#endif
#ifndef SO_ACCEPTCONN
#define SO_ACCEPTCONN   30      /* Socket is accepting connections */
#endif
#ifndef SO_PEERCRED
#define SO_PEERCRED     17      /* Get peer credentials */
#endif

/* ============================================================
 *   Message Flags (for send/recv)
 * ============================================================ */

#ifndef MSG_OOB
#define MSG_OOB         0x01    /* Process out-of-band data */
#endif
#ifndef MSG_PEEK
#define MSG_PEEK        0x02    /* Peek at incoming message */
#endif
#ifndef MSG_DONTROUTE
#define MSG_DONTROUTE   0x04    /* Send without using routing tables */
#endif
#ifndef MSG_DONTWAIT
#define MSG_DONTWAIT    0x40    /* Nonblocking operation */
#endif
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL    0x4000  /* Don't generate SIGPIPE */
#endif
#ifndef MSG_TRUNC
#define MSG_TRUNC       0x20    /* Data was truncated */
#endif
#ifndef MSG_WAITALL
#define MSG_WAITALL     0x100   /* Wait for full request or error */
#endif

/* ============================================================
 *   Shutdown How Values
 * ============================================================ */

#ifndef SHUT_RD
#define SHUT_RD         0       /* Shutdown receive operations */
#endif
#ifndef SHUT_WR
#define SHUT_WR         1       /* Shutdown send operations */
#endif
#ifndef SHUT_RDWR
#define SHUT_RDWR       2       /* Shutdown both operations */
#endif

/* ============================================================
 *   Socket Address Structures
 * ============================================================ */

/* Generic socket address */
#ifndef _STRUCT_SOCKADDR
#define _STRUCT_SOCKADDR
struct sockaddr {
    uint16_t sa_family;         /* Address family */
    char     sa_data[14];       /* Address data */
};
#endif

/* Unix domain socket address */
#ifndef _STRUCT_SOCKADDR_UN
#define _STRUCT_SOCKADDR_UN
struct sockaddr_un {
    uint16_t sun_family;        /* AF_UNIX */
    char     sun_path[108];     /* Pathname */
};
#endif

/* IPv4 socket address */
#ifndef _STRUCT_SOCKADDR_IN
#define _STRUCT_SOCKADDR_IN
struct in_addr {
    uint32_t s_addr;            /* IPv4 address in network byte order */
};

struct sockaddr_in {
    uint16_t       sin_family;  /* AF_INET */
    uint16_t       sin_port;    /* Port number in network byte order */
    struct in_addr sin_addr;    /* IPv4 address */
    char           sin_zero[8]; /* Padding to match sockaddr size */
};
#endif

/* Socket address storage (large enough for any socket address) */
#ifndef _STRUCT_SOCKADDR_STORAGE
#define _STRUCT_SOCKADDR_STORAGE
struct sockaddr_storage {
    uint16_t ss_family;         /* Address family */
    char     __ss_pad[126];     /* Padding for alignment and size */
};
#endif

/* socklen_t type */
#ifndef socklen_t
typedef uint32_t socklen_t;
#endif

/* ============================================================
 *   Function Declarations
 * ============================================================ */

extern int socket(int domain, int type, int protocol);
extern int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
extern int listen(int sockfd, int backlog);
extern int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
extern int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
extern ssize_t send(int sockfd, const void *buf, size_t len, int flags);
extern ssize_t recv(int sockfd, void *buf, size_t len, int flags);
extern ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
                      const struct sockaddr *dest_addr, socklen_t addrlen);
extern ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
                        struct sockaddr *src_addr, socklen_t *addrlen);
extern int setsockopt(int sockfd, int level, int optname,
                      const void *optval, socklen_t optlen);
extern int getsockopt(int sockfd, int level, int optname,
                      void *optval, socklen_t *optlen);
extern int shutdown(int sockfd, int how);
extern int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
extern int getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
extern int socketpair(int domain, int type, int protocol, int sv[2]);

#endif /* !has_include_next */
