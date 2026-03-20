/* kernel/sys_netlink.c - AF_NETLINK (NETLINK_ROUTE) minimal stub
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Provides enough NETLINK_ROUTE support for getifaddrs() and similar
 * programs that enumerate network interfaces at startup.
 *
 * Supported operations:
 *   RTM_GETLINK   → RTM_NEWLINK for loopback (lo, index 1)
 *   RTM_GETADDR   → RTM_NEWADDR for 127.0.0.1/8 on lo
 *   RTM_GETROUTE  → RTM_NEWROUTE for loopback route (127.0.0.0/8 lo)
 *   RTM_GETNEIGH  → NLMSG_DONE (empty neighbor table)
 *   anything else → empty NLMSG_DONE
 *
 * Socket lifecycle:
 *   socket(AF_NETLINK, SOCK_RAW|SOCK_DGRAM, NETLINK_ROUTE) → fd
 *   bind(fd, &sockaddr_nl, sizeof)                          → 0 (no-op)
 *   sendmsg(fd, {RTM_GETLINK}, 0)                          → builds response
 *   recvmsg(fd, ...)                                        → drains response
 */

#include <kernel/fut_socket.h>
#include <kernel/fut_memory.h>
#include <kernel/errno.h>
#include <kernel/kprintf.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* ── Netlink constants ─────────────────────────────────────────────────── */

#define NLMSG_NOOP      1
#define NLMSG_ERROR     2
#define NLMSG_DONE      3
#define NLMSG_MIN_TYPE  0x10

#define NLM_F_MULTI     0x0002  /* multi-part message */
#define NLM_F_REQUEST   0x0001

#define RTM_NEWLINK     16
#define RTM_GETLINK     18
#define RTM_NEWADDR     20
#define RTM_GETADDR     22
#define RTM_NEWROUTE    24
#define RTM_GETROUTE    26
#define RTM_GETNEIGH    30

/* ARPHRD (hardware type) */
#define ARPHRD_ETHER    1
#define ARPHRD_LOOPBACK 772

/* Interface flags */
#define IFF_UP          0x1
#define IFF_LOOPBACK    0x8
#define IFF_RUNNING     0x40
#define IFF_LOWER_UP    0x10000

/* IFA address attributes */
#define IFA_ADDRESS     1
#define IFA_LOCAL       2
#define IFA_LABEL       3
#define IFA_FLAGS       8

/* IFA scope values */
#define RT_SCOPE_HOST   254

/* IFA flags */
#define IFA_F_PERMANENT 0x80

/* IFLA interface attributes */
#define IFLA_IFNAME     3
#define IFLA_MTU        4
#define IFLA_TXQLEN     13

/* Alignment (nlmsghdr and rtattr are 4-byte aligned) */
#define NL_ALIGN(n)  (((n) + 3u) & ~3u)

/* ── Wire-format structs (packed layout matching Linux ABI) ─────────────── */

typedef struct __attribute__((packed)) {
    uint32_t nlmsg_len;
    uint16_t nlmsg_type;
    uint16_t nlmsg_flags;
    uint32_t nlmsg_seq;
    uint32_t nlmsg_pid;
} nl_hdr_t;  /* 16 bytes */

typedef struct __attribute__((packed)) {
    uint8_t  ifi_family;
    uint8_t  __pad;
    uint16_t ifi_type;
    int32_t  ifi_index;
    uint32_t ifi_flags;
    uint32_t ifi_change;
} nl_ifinfomsg_t;  /* 16 bytes */

typedef struct __attribute__((packed)) {
    uint8_t  ifa_family;
    uint8_t  ifa_prefixlen;
    uint8_t  ifa_flags;
    uint8_t  ifa_scope;
    uint32_t ifa_index;
} nl_ifaddrmsg_t;  /* 8 bytes */

typedef struct __attribute__((packed)) {
    uint16_t rta_len;
    uint16_t rta_type;
} nl_rta_t;  /* 4 bytes */

typedef struct __attribute__((packed)) {
    uint8_t  rtm_family;    /* Address family */
    uint8_t  rtm_dst_len;   /* Destination prefix length */
    uint8_t  rtm_src_len;   /* Source prefix length */
    uint8_t  rtm_tos;       /* TOS filter */
    uint8_t  rtm_table;     /* Routing table ID */
    uint8_t  rtm_protocol;  /* Routing protocol */
    uint8_t  rtm_scope;     /* Routing scope */
    uint8_t  rtm_type;      /* Route type */
    uint32_t rtm_flags;     /* Route flags */
} nl_rtmsg_t;  /* 12 bytes */

/* rtmsg table / protocol / scope / type constants */
#define RT_TABLE_LOCAL   255
#define RTPROT_KERNEL    2
#define RT_SCOPE_LINK    253
#define RTN_LOCAL        2

/* Route rtattrs */
#define RTA_DST          1
#define RTA_OIF          4

/* ── Builder helpers ────────────────────────────────────────────────────── */

/* Append 'src' of 'n' bytes to buf[*pos], zero-pad to 4-byte boundary */
static void nl_append(uint8_t *buf, uint32_t *pos, const void *src, uint32_t n) {
    __builtin_memcpy(buf + *pos, src, n);
    uint32_t pad = NL_ALIGN(n) - n;
    if (pad > 0) __builtin_memset(buf + *pos + n, 0, pad);
    *pos += NL_ALIGN(n);
}

/* Write a uint32 rtattr */
static void nl_rta32(uint8_t *buf, uint32_t *pos, uint16_t type, uint32_t val) {
    nl_rta_t rta = { .rta_len = 8, .rta_type = type };
    nl_append(buf, pos, &rta, sizeof(rta));
    nl_append(buf, pos, &val, sizeof(val));
}

/* Write a variable-length rtattr (data already NL_ALIGN'd by caller) */
static void nl_rta_str(uint8_t *buf, uint32_t *pos, uint16_t type,
                       const char *str, uint16_t str_len) {
    uint16_t rta_len = (uint16_t)(sizeof(nl_rta_t) + str_len);
    nl_rta_t rta = { .rta_len = rta_len, .rta_type = type };
    uint32_t start = *pos;
    nl_append(buf, pos, &rta, sizeof(rta));
    /* Copy str + zero-pad to align */
    __builtin_memcpy(buf + start + sizeof(rta), str, str_len);
    uint32_t total = (uint32_t)(sizeof(rta) + str_len);
    uint32_t pad   = NL_ALIGN(total) - total;
    if (pad) __builtin_memset(buf + start + total, 0, pad);
    *pos = start + NL_ALIGN(total);
}

/* Write NLMSG_DONE with NLM_F_MULTI */
static void nl_done(uint8_t *buf, uint32_t *pos, uint32_t seq) {
    uint32_t done_errno = 0;
    uint32_t msg_len = (uint32_t)(sizeof(nl_hdr_t) + sizeof(done_errno));
    nl_hdr_t hdr = {
        .nlmsg_len   = msg_len,
        .nlmsg_type  = NLMSG_DONE,
        .nlmsg_flags = NLM_F_MULTI,
        .nlmsg_seq   = seq,
        .nlmsg_pid   = 0,
    };
    nl_append(buf, pos, &hdr, sizeof(hdr));
    nl_append(buf, pos, &done_errno, sizeof(done_errno));
}

/* ── RTM_GETLINK response ───────────────────────────────────────────────── */

static uint32_t nl_build_newlink(uint8_t *buf, uint32_t seq) {
    uint32_t pos = 0;

    /* Reserve space for the outer nlmsghdr; fill length at end */
    uint32_t msg_start = pos;
    nl_hdr_t hdr = {
        .nlmsg_len   = 0,   /* filled below */
        .nlmsg_type  = RTM_NEWLINK,
        .nlmsg_flags = NLM_F_MULTI,
        .nlmsg_seq   = seq,
        .nlmsg_pid   = 0,
    };
    nl_append(buf, &pos, &hdr, sizeof(hdr));

    /* ifinfomsg for lo */
    nl_ifinfomsg_t ifi = {
        .ifi_family = 0 /* AF_UNSPEC */,
        .__pad      = 0,
        .ifi_type   = ARPHRD_LOOPBACK,
        .ifi_index  = 1,
        .ifi_flags  = IFF_UP | IFF_LOOPBACK | IFF_RUNNING | IFF_LOWER_UP,
        .ifi_change = 0xFFFFFFFFu,
    };
    nl_append(buf, &pos, &ifi, sizeof(ifi));

    /* IFLA_IFNAME = "lo" */
    nl_rta_str(buf, &pos, IFLA_IFNAME, "lo", 3 /* "lo\0" */);

    /* IFLA_MTU = 65536 */
    nl_rta32(buf, &pos, IFLA_MTU, 65536);

    /* IFLA_TXQLEN = 1000 */
    nl_rta32(buf, &pos, IFLA_TXQLEN, 1000);

    /* Patch length in the header */
    uint32_t msg_len = pos - msg_start;
    __builtin_memcpy(buf + msg_start, &msg_len, sizeof(msg_len));

    /* NLMSG_DONE */
    nl_done(buf, &pos, seq);

    return pos;
}

/* ── RTM_GETADDR response ───────────────────────────────────────────────── */

static uint32_t nl_build_newaddr(uint8_t *buf, uint32_t seq) {
    uint32_t pos = 0;

    /* Outer nlmsghdr */
    uint32_t msg_start = pos;
    nl_hdr_t hdr = {
        .nlmsg_len   = 0,
        .nlmsg_type  = RTM_NEWADDR,
        .nlmsg_flags = NLM_F_MULTI,
        .nlmsg_seq   = seq,
        .nlmsg_pid   = 0,
    };
    nl_append(buf, &pos, &hdr, sizeof(hdr));

    /* ifaddrmsg: AF_INET, /8, permanent, scope=host, index=1 */
    nl_ifaddrmsg_t ifa = {
        .ifa_family    = 2 /* AF_INET */,
        .ifa_prefixlen = 8,
        .ifa_flags     = IFA_F_PERMANENT,
        .ifa_scope     = RT_SCOPE_HOST,
        .ifa_index     = 1,
    };
    nl_append(buf, &pos, &ifa, sizeof(ifa));

    /* IFA_LOCAL = 127.0.0.1 */
    uint32_t lo4 = 0x0100007fU; /* 127.0.0.1 in network byte order */
    nl_rta32(buf, &pos, IFA_LOCAL, lo4);

    /* IFA_ADDRESS = 127.0.0.1 */
    nl_rta32(buf, &pos, IFA_ADDRESS, lo4);

    /* IFA_LABEL = "lo" */
    nl_rta_str(buf, &pos, IFA_LABEL, "lo", 3);

    uint32_t msg_len = pos - msg_start;
    __builtin_memcpy(buf + msg_start, &msg_len, sizeof(msg_len));

    nl_done(buf, &pos, seq);

    return pos;
}

/* ── RTM_GETROUTE response ──────────────────────────────────────────────── */

/* Returns the loopback route: 127.0.0.0/8 via lo (scope link, type local) */
static uint32_t nl_build_newroute(uint8_t *buf, uint32_t seq) {
    uint32_t pos = 0;

    /* Outer nlmsghdr */
    uint32_t msg_start = pos;
    nl_hdr_t hdr = {
        .nlmsg_len   = 0,
        .nlmsg_type  = RTM_NEWROUTE,
        .nlmsg_flags = NLM_F_MULTI,
        .nlmsg_seq   = seq,
        .nlmsg_pid   = 0,
    };
    nl_append(buf, &pos, &hdr, sizeof(hdr));

    /* rtmsg: AF_INET, 127.0.0.0/8, table=LOCAL, proto=KERNEL, scope=LINK */
    nl_rtmsg_t rtm = {
        .rtm_family   = 2 /* AF_INET */,
        .rtm_dst_len  = 8,
        .rtm_src_len  = 0,
        .rtm_tos      = 0,
        .rtm_table    = RT_TABLE_LOCAL,
        .rtm_protocol = RTPROT_KERNEL,
        .rtm_scope    = RT_SCOPE_LINK,
        .rtm_type     = RTN_LOCAL,
        .rtm_flags    = 0,
    };
    nl_append(buf, &pos, &rtm, sizeof(rtm));

    /* RTA_DST = 127.0.0.0 */
    uint32_t dst = 0x0000007fU; /* 127.0.0.0 in network byte order */
    nl_rta32(buf, &pos, RTA_DST, dst);

    /* RTA_OIF = 1 (lo) */
    nl_rta32(buf, &pos, RTA_OIF, 1);

    /* Patch length in the header */
    uint32_t msg_len = pos - msg_start;
    __builtin_memcpy(buf + msg_start, &msg_len, sizeof(msg_len));

    nl_done(buf, &pos, seq);

    return pos;
}

/* ── Empty NLMSG_DONE (for unsupported request types) ──────────────────── */

static uint32_t nl_build_done_only(uint8_t *buf, uint32_t seq) {
    uint32_t pos = 0;
    nl_done(buf, &pos, seq);
    return pos;
}

/* ── Public interface ───────────────────────────────────────────────────── */

/**
 * netlink_handle_send - Process a sendmsg() on an AF_NETLINK socket.
 *
 * Reads the netlink request from the iovec, builds a canned response, and
 * stores it in socket->nl_resp_buf for the next recvmsg().
 *
 * @sock      Kernel socket (address_family == AF_NETLINK)
 * @iov_base  Pointer to first iov base (contains the nlmsghdr request)
 * @iov_len   Length of that iov
 * @total_len Total bytes across all iovecs (returned to caller)
 * @return    total_len on success, negative errno on error
 */
ssize_t netlink_handle_send(fut_socket_t *sock,
                            const void *iov_base, size_t iov_len,
                            ssize_t total_len) {
    /* Discard old pending response if any */
    if (sock->nl_resp_buf) {
        fut_free(sock->nl_resp_buf);
        sock->nl_resp_buf = NULL;
        sock->nl_resp_len = 0;
        sock->nl_resp_pos = 0;
    }

    if (!iov_base || iov_len < sizeof(nl_hdr_t)) {
        /* No valid header; generate empty DONE */
        uint8_t *buf = fut_malloc(32);
        if (!buf) return -ENOMEM;
        uint32_t len = nl_build_done_only(buf, 0);
        sock->nl_resp_buf = buf;
        sock->nl_resp_len = len;
        sock->nl_resp_pos = 0;
        return total_len;
    }

    /* Read the request nlmsghdr */
    nl_hdr_t req;
    __builtin_memcpy(&req, iov_base, sizeof(req));

    /* Allocate response buffer large enough for any single-interface response */
    uint8_t *buf = fut_malloc(256);
    if (!buf) return -ENOMEM;
    __builtin_memset(buf, 0, 256);

    uint32_t resp_len;
    switch (req.nlmsg_type) {
    case RTM_GETLINK:
        resp_len = nl_build_newlink(buf, req.nlmsg_seq);
        break;
    case RTM_GETADDR:
        resp_len = nl_build_newaddr(buf, req.nlmsg_seq);
        break;
    case RTM_GETROUTE:
        resp_len = nl_build_newroute(buf, req.nlmsg_seq);
        break;
    case RTM_GETNEIGH:
        /* Empty neighbor table — just NLMSG_DONE */
        resp_len = nl_build_done_only(buf, req.nlmsg_seq);
        break;
    default:
        resp_len = nl_build_done_only(buf, req.nlmsg_seq);
        break;
    }

    sock->nl_resp_buf = buf;
    sock->nl_resp_len = resp_len;
    sock->nl_resp_pos = 0;

    return total_len > 0 ? total_len : (ssize_t)iov_len;
}

/**
 * netlink_handle_recv - Process a recvmsg() on an AF_NETLINK socket.
 *
 * Copies pending response data into @out_buf (up to @out_len bytes).
 *
 * @sock     Kernel socket (address_family == AF_NETLINK)
 * @out_buf  Destination buffer
 * @out_len  Maximum bytes to copy
 * @return   Bytes copied, 0 if nothing pending, negative on error
 */
ssize_t netlink_handle_recv(fut_socket_t *sock, void *out_buf, size_t out_len) {
    if (!sock->nl_resp_buf || sock->nl_resp_pos >= sock->nl_resp_len)
        return 0;

    uint32_t available = sock->nl_resp_len - sock->nl_resp_pos;
    size_t to_copy = out_len < available ? out_len : (size_t)available;
    __builtin_memcpy(out_buf, sock->nl_resp_buf + sock->nl_resp_pos, to_copy);
    sock->nl_resp_pos += (uint32_t)to_copy;

    /* Free when fully consumed */
    if (sock->nl_resp_pos >= sock->nl_resp_len) {
        fut_free(sock->nl_resp_buf);
        sock->nl_resp_buf = NULL;
        sock->nl_resp_len = 0;
        sock->nl_resp_pos = 0;
    }

    return (ssize_t)to_copy;
}
