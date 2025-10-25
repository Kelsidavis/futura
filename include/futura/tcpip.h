// SPDX-License-Identifier: MPL-2.0
/*
 * tcpip.h - TCP/IP Protocol Stack for Futura OS
 *
 * This file defines structures and functions for a complete TCP/IP stack
 * including Ethernet, ARP, IP, ICMP, UDP, and TCP protocols.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Ethernet Layer (Link Layer)
 * ========================================================================= */

#define ETH_ADDR_LEN 6
#define ETH_HEADER_LEN 14
#define ETH_MIN_FRAME 64
#define ETH_MAX_FRAME 1518

typedef uint8_t eth_addr_t[ETH_ADDR_LEN];

/* EtherType values */
#define ETHERTYPE_IP    0x0800  /* IPv4 */
#define ETHERTYPE_ARP   0x0806  /* Address Resolution Protocol */
#define ETHERTYPE_IPV6  0x86DD  /* IPv6 (for future use) */

/* Ethernet frame header */
typedef struct __attribute__((packed)) {
    eth_addr_t dest;        /* Destination MAC address */
    eth_addr_t src;         /* Source MAC address */
    uint16_t type;          /* EtherType (in network byte order) */
} eth_header_t;

/* ============================================================================
 * ARP (Address Resolution Protocol)
 * ========================================================================= */

#define ARP_HARDWARE_ETHERNET 1
#define ARP_PROTOCOL_IP 0x0800

#define ARP_OP_REQUEST 1
#define ARP_OP_REPLY 2

#define ARP_CACHE_SIZE 256
#define ARP_CACHE_TIMEOUT_MS 300000  /* 5 minutes */

/* ARP packet */
typedef struct __attribute__((packed)) {
    uint16_t hardware_type;     /* Hardware type (Ethernet = 1) */
    uint16_t protocol_type;     /* Protocol type (IP = 0x0800) */
    uint8_t hardware_len;       /* Hardware address length (6 for Ethernet) */
    uint8_t protocol_len;       /* Protocol address length (4 for IPv4) */
    uint16_t operation;         /* Operation (request = 1, reply = 2) */
    eth_addr_t sender_mac;      /* Sender hardware address */
    uint32_t sender_ip;         /* Sender protocol address */
    eth_addr_t target_mac;      /* Target hardware address */
    uint32_t target_ip;         /* Target protocol address */
} arp_packet_t;

/* ============================================================================
 * IPv4 (Internet Protocol)
 * ========================================================================= */

#define IP_VERSION_4 4
#define IP_HEADER_MIN_LEN 20
#define IP_MAX_PACKET 65535

/* IP Protocol numbers */
#define IP_PROTO_ICMP 1
#define IP_PROTO_TCP 6
#define IP_PROTO_UDP 17

/* IPv4 header */
typedef struct __attribute__((packed)) {
    uint8_t version_ihl;        /* Version (4 bits) + IHL (4 bits) */
    uint8_t tos;                /* Type of Service */
    uint16_t total_length;      /* Total length of packet */
    uint16_t identification;    /* Identification for fragmentation */
    uint16_t flags_fragment;    /* Flags (3 bits) + Fragment offset (13 bits) */
    uint8_t ttl;                /* Time to Live */
    uint8_t protocol;           /* Protocol (TCP=6, UDP=17, ICMP=1) */
    uint16_t checksum;          /* Header checksum */
    uint32_t src_addr;          /* Source IP address */
    uint32_t dest_addr;         /* Destination IP address */
} ip_header_t;

/* IP flags */
#define IP_FLAG_DF 0x4000  /* Don't Fragment */
#define IP_FLAG_MF 0x2000  /* More Fragments */

/* ============================================================================
 * ICMP (Internet Control Message Protocol)
 * ========================================================================= */

#define ICMP_ECHO_REPLY 0
#define ICMP_DEST_UNREACHABLE 3
#define ICMP_ECHO_REQUEST 8
#define ICMP_TIME_EXCEEDED 11

/* ICMP header */
typedef struct __attribute__((packed)) {
    uint8_t type;               /* ICMP type */
    uint8_t code;               /* ICMP code */
    uint16_t checksum;          /* Checksum */
    uint16_t id;                /* Identifier (for echo) */
    uint16_t sequence;          /* Sequence number (for echo) */
} icmp_header_t;

/* ============================================================================
 * UDP (User Datagram Protocol)
 * ========================================================================= */

#define UDP_HEADER_LEN 8

/* UDP header */
typedef struct __attribute__((packed)) {
    uint16_t src_port;          /* Source port */
    uint16_t dest_port;         /* Destination port */
    uint16_t length;            /* Length of UDP header + data */
    uint16_t checksum;          /* Checksum (optional in IPv4) */
} udp_header_t;

/* ============================================================================
 * TCP (Transmission Control Protocol)
 * ========================================================================= */

#define TCP_HEADER_MIN_LEN 20
#define TCP_MAX_WINDOW 65535

/* TCP header */
typedef struct __attribute__((packed)) {
    uint16_t src_port;          /* Source port */
    uint16_t dest_port;         /* Destination port */
    uint32_t seq_num;           /* Sequence number */
    uint32_t ack_num;           /* Acknowledgment number */
    uint8_t data_offset_rsvd;   /* Data offset (4 bits) + Reserved (4 bits) */
    uint8_t flags;              /* TCP flags */
    uint16_t window;            /* Window size */
    uint16_t checksum;          /* Checksum */
    uint16_t urgent_ptr;        /* Urgent pointer */
} tcp_header_t;

/* TCP flags */
#define TCP_FLAG_FIN 0x01  /* Finish */
#define TCP_FLAG_SYN 0x02  /* Synchronize */
#define TCP_FLAG_RST 0x04  /* Reset */
#define TCP_FLAG_PSH 0x08  /* Push */
#define TCP_FLAG_ACK 0x10  /* Acknowledgment */
#define TCP_FLAG_URG 0x20  /* Urgent */

/* TCP states */
typedef enum {
    TCP_STATE_CLOSED = 0,
    TCP_STATE_LISTEN,
    TCP_STATE_SYN_SENT,
    TCP_STATE_SYN_RECEIVED,
    TCP_STATE_ESTABLISHED,
    TCP_STATE_FIN_WAIT_1,
    TCP_STATE_FIN_WAIT_2,
    TCP_STATE_CLOSE_WAIT,
    TCP_STATE_CLOSING,
    TCP_STATE_LAST_ACK,
    TCP_STATE_TIME_WAIT,
} tcp_state_t;

/* ============================================================================
 * Network Stack Configuration
 * ========================================================================= */

#define TCPIP_DEFAULT_IP    0x0A00020F  /* 10.0.2.15 (QEMU default guest) */
#define TCPIP_DEFAULT_MASK  0xFFFFFF00  /* 255.255.255.0 */
#define TCPIP_DEFAULT_GW    0x0A000202  /* 10.0.2.2 */

/* Maximum number of simultaneous connections */
#define TCPIP_MAX_SOCKETS 256
#define TCPIP_MAX_TCP_CONNECTIONS 128
#define TCPIP_MAX_UDP_SOCKETS 128

/* Buffer sizes */
#define TCPIP_TX_BUFFER_SIZE 4096
#define TCPIP_RX_BUFFER_SIZE 4096

/* Timeouts */
#define TCP_CONNECT_TIMEOUT_MS 30000  /* 30 seconds */
#define TCP_RETRANSMIT_TIMEOUT_MS 1000  /* 1 second */
#define TCP_MAX_RETRIES 5

/* ============================================================================
 * Socket API Types
 * ========================================================================= */

/* Socket types */
typedef enum {
    SOCK_TYPE_RAW = 0,
    SOCK_TYPE_UDP,
    SOCK_TYPE_TCP,
} socket_type_t;

/* Socket structure (opaque) */
typedef struct tcpip_socket tcpip_socket_t;

/* Socket address */
typedef struct {
    uint32_t ip;           /* IP address */
    uint16_t port;         /* Port number */
} sockaddr_in_t;

/* ============================================================================
 * Public API Functions
 * ========================================================================= */

/* Stack initialization */
int tcpip_init(void);
int tcpip_set_ip_address(uint32_t ip, uint32_t netmask, uint32_t gateway);
int tcpip_get_mac_address(eth_addr_t *mac);

/* Utility functions */
uint16_t tcpip_checksum(const void *data, size_t len);
uint32_t tcpip_parse_ip(const char *str);
void tcpip_format_ip(uint32_t ip, char *buf, size_t len);
void tcpip_format_mac(const eth_addr_t mac, char *buf, size_t len);

/* ARP functions */
int arp_resolve(uint32_t ip, eth_addr_t *mac);
int arp_add_static(uint32_t ip, const eth_addr_t mac);
void arp_clear_cache(void);

/* Socket API */
tcpip_socket_t *tcpip_socket(socket_type_t type);
int tcpip_bind(tcpip_socket_t *sock, uint16_t port);
int tcpip_listen(tcpip_socket_t *sock, int backlog);
tcpip_socket_t *tcpip_accept(tcpip_socket_t *sock);
int tcpip_connect(tcpip_socket_t *sock, uint32_t ip, uint16_t port);
int tcpip_send(tcpip_socket_t *sock, const void *data, size_t len);
int tcpip_recv(tcpip_socket_t *sock, void *buf, size_t len);
int tcpip_sendto(tcpip_socket_t *sock, const void *data, size_t len,
                 uint32_t dest_ip, uint16_t dest_port);
int tcpip_recvfrom(tcpip_socket_t *sock, void *buf, size_t len,
                   uint32_t *src_ip, uint16_t *src_port);
int tcpip_close(tcpip_socket_t *sock);

/* ICMP functions */
int icmp_ping(uint32_t dest_ip, uint16_t id, uint16_t seq, void *data, size_t len);

/* Network byte order conversion */
static inline uint16_t htons(uint16_t x) {
    return __builtin_bswap16(x);
}

static inline uint16_t ntohs(uint16_t x) {
    return __builtin_bswap16(x);
}

static inline uint32_t htonl(uint32_t x) {
    return __builtin_bswap32(x);
}

static inline uint32_t ntohl(uint32_t x) {
    return __builtin_bswap32(x);
}

#ifdef __cplusplus
}
#endif
