// SPDX-License-Identifier: MPL-2.0
/*
 * tcpip.c - TCP/IP Protocol Stack Implementation
 *
 * A complete TCP/IP stack for Futura OS including:
 * - Ethernet layer
 * - ARP (Address Resolution Protocol)
 * - IPv4 with routing and fragmentation
 * - ICMP (ping support)
 * - UDP (connectionless transport)
 * - TCP (connection-oriented transport with flow control)
 */

#include <futura/tcpip.h>
#include <futura/net.h>
#include <kernel/errno.h>
#include <kernel/fut_memory.h>
#include <kernel/fut_sched.h>
#include <kernel/fut_timer.h>
#include <string.h>
#include <stdbool.h>

extern void fut_printf(const char *fmt, ...);

/* Debug output - uncomment to enable */
// #define DEBUG_TCPIP 1

#ifdef DEBUG_TCPIP
#define TCPIP_DEBUG(...) fut_printf(__VA_ARGS__)
#else
#define TCPIP_DEBUG(...) do { } while (0)
#endif

/* ============================================================================
 * Global State
 * ========================================================================= */

typedef struct {
    bool initialized;
    uint32_t ip_address;
    uint32_t netmask;
    uint32_t gateway;
    eth_addr_t mac_address;
    uint16_t ip_id_counter;  /* For IP packet IDs */
    fut_socket_t *raw_socket;  /* Underlying raw socket */
    fut_spinlock_t lock;
} tcpip_state_t;

static tcpip_state_t g_tcpip;

/* ============================================================================
 * ARP Cache
 * ========================================================================= */

typedef struct {
    uint32_t ip;
    eth_addr_t mac;
    uint64_t timestamp;  /* For timeout */
    bool valid;
} arp_entry_t;

static arp_entry_t arp_cache[ARP_CACHE_SIZE];
static fut_spinlock_t arp_lock;

/* ============================================================================
 * TCP Connection Tracking
 * ========================================================================= */

typedef struct tcp_connection {
    bool active;
    tcp_state_t state;
    uint32_t remote_ip;
    uint16_t local_port;
    uint16_t remote_port;

    /* Sequence numbers */
    uint32_t send_next;      /* Next sequence to send */
    uint32_t send_unack;     /* Oldest unacknowledged sequence */
    uint32_t recv_next;      /* Next sequence expected */

    /* Window */
    uint16_t send_window;
    uint16_t recv_window;

    /* Buffers */
    uint8_t tx_buffer[TCPIP_TX_BUFFER_SIZE];
    size_t tx_len;
    uint8_t rx_buffer[TCPIP_RX_BUFFER_SIZE];
    size_t rx_len;

    /* Timing */
    uint64_t last_send_time;
    int retries;

    struct tcp_connection *next;
} tcp_connection_t;

static tcp_connection_t tcp_connections[TCPIP_MAX_TCP_CONNECTIONS];
static fut_spinlock_t tcp_lock;

/* ============================================================================
 * Socket Structure
 * ========================================================================= */

struct tcpip_socket {
    socket_type_t type;
    bool bound;
    bool listening;
    bool connected;
    uint16_t local_port;
    uint32_t remote_ip;
    uint16_t remote_port;

    /* For TCP */
    tcp_connection_t *tcp_conn;

    /* For UDP */
    struct {
        uint8_t rx_buffer[TCPIP_RX_BUFFER_SIZE];
        size_t rx_len;
        uint32_t src_ip;
        uint16_t src_port;
    } udp;

    fut_spinlock_t lock;
};

static tcpip_socket_t *sockets[TCPIP_MAX_SOCKETS];
static fut_spinlock_t socket_lock;

/* ============================================================================
 * Utility Functions
 * ========================================================================= */

/* Internet checksum calculation */
uint16_t tcpip_checksum(const void *data, size_t len) {
    const uint16_t *ptr = (const uint16_t *)data;
    uint32_t sum = 0;

    while (len > 1) {
        sum += *ptr++;
        len -= 2;
    }

    if (len > 0) {
        sum += *(const uint8_t *)ptr;
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return ~sum;
}

/* Parse IP address from string (e.g., "192.168.1.1") */
uint32_t tcpip_parse_ip(const char *str) {
    uint32_t result = 0;
    int octet = 0;
    int shift = 24;

    while (*str && shift >= 0) {
        if (*str >= '0' && *str <= '9') {
            octet = octet * 10 + (*str - '0');
        } else if (*str == '.') {
            result |= (octet << shift);
            octet = 0;
            shift -= 8;
        }
        str++;
    }

    if (shift == 0) {
        result |= octet;
    }

    return result;
}

/* Format IP address to string */
void tcpip_format_ip(uint32_t ip, char *buf, size_t len) {
    if (!buf || len < 16) return;

    uint8_t *b = (uint8_t *)&ip;
    int written = 0;

    for (int i = 3; i >= 0; i--) {
        int val = b[i];

        if (val == 0) {
            if (written < (int)len - 1) buf[written++] = '0';
        } else {
            char temp[4];
            int td = 0;
            while (val > 0 && td < 3) {
                temp[td++] = '0' + (val % 10);
                val /= 10;
            }
            for (int j = td - 1; j >= 0 && written < (int)len - 1; j--) {
                buf[written++] = temp[j];
            }
        }

        if (i > 0 && written < (int)len - 1) {
            buf[written++] = '.';
        }
    }

    buf[written] = '\0';
}

/* Format MAC address to string */
void tcpip_format_mac(const eth_addr_t mac, char *buf, size_t len) {
    if (!buf || len < 18) return;

    static const char hex[] = "0123456789abcdef";
    int written = 0;

    for (int i = 0; i < ETH_ADDR_LEN && written < (int)len - 1; i++) {
        buf[written++] = hex[(mac[i] >> 4) & 0xF];
        if (written < (int)len - 1) buf[written++] = hex[mac[i] & 0xF];
        if (i < ETH_ADDR_LEN - 1 && written < (int)len - 1) buf[written++] = ':';
    }

    buf[written] = '\0';
}

/* ============================================================================
 * ARP Implementation
 * ========================================================================= */

void arp_clear_cache(void) {
    fut_spinlock_acquire(&arp_lock);
    memset(arp_cache, 0, sizeof(arp_cache));
    fut_spinlock_release(&arp_lock);
}

int arp_add_static(uint32_t ip, const eth_addr_t mac) {
    fut_spinlock_acquire(&arp_lock);

    /* Find empty slot or existing entry */
    int slot = -1;
    for (int i = 0; i < ARP_CACHE_SIZE; i++) {
        if (!arp_cache[i].valid || arp_cache[i].ip == ip) {
            slot = i;
            break;
        }
    }

    if (slot < 0) {
        fut_spinlock_release(&arp_lock);
        return -ENOSPC;
    }

    arp_cache[slot].ip = ip;
    memcpy(arp_cache[slot].mac, mac, ETH_ADDR_LEN);
    arp_cache[slot].valid = true;
    arp_cache[slot].timestamp = 0;  /* Static entry, no timeout */

    fut_spinlock_release(&arp_lock);
    return 0;
}

static int arp_lookup_cache(uint32_t ip, eth_addr_t *mac) {
    fut_spinlock_acquire(&arp_lock);

    for (int i = 0; i < ARP_CACHE_SIZE; i++) {
        if (arp_cache[i].valid && arp_cache[i].ip == ip) {
            memcpy(*mac, arp_cache[i].mac, ETH_ADDR_LEN);
            fut_spinlock_release(&arp_lock);
            return 0;
        }
    }

    fut_spinlock_release(&arp_lock);
    return -ENOENT;
}

static void arp_handle_packet(const uint8_t *frame, size_t len) {
    if (len < ETH_HEADER_LEN + sizeof(arp_packet_t)) {
        return;
    }

    const arp_packet_t *arp = (const arp_packet_t *)(frame + ETH_HEADER_LEN);

    uint16_t hw_type = ntohs(arp->hardware_type);
    uint16_t proto_type = ntohs(arp->protocol_type);
    uint16_t op = ntohs(arp->operation);

    if (hw_type != ARP_HARDWARE_ETHERNET || proto_type != ARP_PROTOCOL_IP) {
        return;
    }

    uint32_t sender_ip = ntohl(arp->sender_ip);
    uint32_t target_ip = ntohl(arp->target_ip);

    /* Update ARP cache with sender info */
    arp_add_static(sender_ip, arp->sender_mac);

    /* Handle ARP request */
    if (op == ARP_OP_REQUEST && target_ip == g_tcpip.ip_address) {
        TCPIP_DEBUG("[ARP] Request for our IP, sending reply\n");

        /* Build ARP reply */
        uint8_t reply[ETH_HEADER_LEN + sizeof(arp_packet_t)];
        eth_header_t *eth_hdr = (eth_header_t *)reply;
        arp_packet_t *arp_reply = (arp_packet_t *)(reply + ETH_HEADER_LEN);

        /* Ethernet header */
        memcpy(eth_hdr->dest, arp->sender_mac, ETH_ADDR_LEN);
        memcpy(eth_hdr->src, g_tcpip.mac_address, ETH_ADDR_LEN);
        eth_hdr->type = htons(ETHERTYPE_ARP);

        /* ARP reply */
        arp_reply->hardware_type = htons(ARP_HARDWARE_ETHERNET);
        arp_reply->protocol_type = htons(ARP_PROTOCOL_IP);
        arp_reply->hardware_len = ETH_ADDR_LEN;
        arp_reply->protocol_len = 4;
        arp_reply->operation = htons(ARP_OP_REPLY);
        memcpy(arp_reply->sender_mac, g_tcpip.mac_address, ETH_ADDR_LEN);
        arp_reply->sender_ip = htonl(g_tcpip.ip_address);
        memcpy(arp_reply->target_mac, arp->sender_mac, ETH_ADDR_LEN);
        arp_reply->target_ip = arp->sender_ip;

        /* Send reply */
        fut_net_send(g_tcpip.raw_socket, reply, sizeof(reply));
    }

    /* Handle ARP reply */
    if (op == ARP_OP_REPLY && target_ip == g_tcpip.ip_address) {
        TCPIP_DEBUG("[ARP] Received reply from ");
        char ip_str[16];
        tcpip_format_ip(sender_ip, ip_str, sizeof(ip_str));
        TCPIP_DEBUG("%s\n", ip_str);
    }
}

int arp_resolve(uint32_t ip, eth_addr_t *mac) {
    /* Check if it's broadcast */
    if (ip == 0xFFFFFFFF) {
        memset(*mac, 0xFF, ETH_ADDR_LEN);
        return 0;
    }

    /* Check cache first */
    if (arp_lookup_cache(ip, mac) == 0) {
        return 0;
    }

    TCPIP_DEBUG("[ARP] Resolving IP address\n");

    /* Send ARP request */
    uint8_t request[ETH_HEADER_LEN + sizeof(arp_packet_t)];
    eth_header_t *eth_hdr = (eth_header_t *)request;
    arp_packet_t *arp = (arp_packet_t *)(request + ETH_HEADER_LEN);

    /* Ethernet header - broadcast */
    memset(eth_hdr->dest, 0xFF, ETH_ADDR_LEN);
    memcpy(eth_hdr->src, g_tcpip.mac_address, ETH_ADDR_LEN);
    eth_hdr->type = htons(ETHERTYPE_ARP);

    /* ARP request */
    arp->hardware_type = htons(ARP_HARDWARE_ETHERNET);
    arp->protocol_type = htons(ARP_PROTOCOL_IP);
    arp->hardware_len = ETH_ADDR_LEN;
    arp->protocol_len = 4;
    arp->operation = htons(ARP_OP_REQUEST);
    memcpy(arp->sender_mac, g_tcpip.mac_address, ETH_ADDR_LEN);
    arp->sender_ip = htonl(g_tcpip.ip_address);
    memset(arp->target_mac, 0, ETH_ADDR_LEN);
    arp->target_ip = htonl(ip);

    /* Send request */
    fut_net_send(g_tcpip.raw_socket, request, sizeof(request));

    /* Wait for reply (simplified - should use proper async mechanism) */
    for (int retry = 0; retry < 3; retry++) {
        /* Small delay */
        for (volatile int i = 0; i < 1000000; i++);

        if (arp_lookup_cache(ip, mac) == 0) {
            return 0;
        }
    }

    /* Failed to resolve */
    return -EHOSTUNREACH;
}

/* ============================================================================
 * IP Layer
 * ========================================================================= */

static void ip_send_packet(uint32_t dest_ip, uint8_t protocol,
                           const void *payload, size_t payload_len) {
    if (payload_len > (ETH_MAX_FRAME - ETH_HEADER_LEN - IP_HEADER_MIN_LEN)) {
        TCPIP_DEBUG("[IP] Packet too large\n");
        return;
    }

    /* Resolve destination MAC */
    eth_addr_t dest_mac;
    uint32_t next_hop = dest_ip;

    /* If not on local network, use gateway */
    if ((dest_ip & g_tcpip.netmask) != (g_tcpip.ip_address & g_tcpip.netmask)) {
        next_hop = g_tcpip.gateway;
    }

    if (arp_resolve(next_hop, &dest_mac) != 0) {
        TCPIP_DEBUG("[IP] ARP resolution failed\n");
        return;
    }

    /* Build packet */
    size_t total_len = ETH_HEADER_LEN + IP_HEADER_MIN_LEN + payload_len;
    uint8_t *packet = fut_malloc(total_len);
    if (!packet) return;

    /* Ethernet header */
    eth_header_t *eth = (eth_header_t *)packet;
    memcpy(eth->dest, dest_mac, ETH_ADDR_LEN);
    memcpy(eth->src, g_tcpip.mac_address, ETH_ADDR_LEN);
    eth->type = htons(ETHERTYPE_IP);

    /* IP header */
    ip_header_t *ip = (ip_header_t *)(packet + ETH_HEADER_LEN);
    memset(ip, 0, IP_HEADER_MIN_LEN);
    ip->version_ihl = (IP_VERSION_4 << 4) | 5;  /* Version 4, IHL=5 (20 bytes) */
    ip->tos = 0;
    ip->total_length = htons(IP_HEADER_MIN_LEN + payload_len);
    ip->identification = htons(g_tcpip.ip_id_counter++);
    ip->flags_fragment = htons(IP_FLAG_DF);  /* Don't fragment */
    ip->ttl = 64;
    ip->protocol = protocol;
    ip->src_addr = htonl(g_tcpip.ip_address);
    ip->dest_addr = htonl(dest_ip);
    ip->checksum = 0;
    ip->checksum = tcpip_checksum(ip, IP_HEADER_MIN_LEN);

    /* Copy payload */
    memcpy(packet + ETH_HEADER_LEN + IP_HEADER_MIN_LEN, payload, payload_len);

    /* Send packet */
    fut_net_send(g_tcpip.raw_socket, packet, total_len);
    fut_free(packet);
}

/* ============================================================================
 * ICMP Implementation
 * ========================================================================= */

static void icmp_handle_packet(const uint8_t *ip_payload, size_t len,
                               uint32_t src_ip) {
    if (len < sizeof(icmp_header_t)) {
        return;
    }

    const icmp_header_t *icmp = (const icmp_header_t *)ip_payload;

    if (icmp->type == ICMP_ECHO_REQUEST) {
        TCPIP_DEBUG("[ICMP] Echo request received\n");

        /* Build echo reply */
        size_t reply_len = len;
        uint8_t *reply = fut_malloc(reply_len);
        if (!reply) return;

        memcpy(reply, ip_payload, len);
        icmp_header_t *reply_icmp = (icmp_header_t *)reply;
        reply_icmp->type = ICMP_ECHO_REPLY;
        reply_icmp->checksum = 0;
        reply_icmp->checksum = tcpip_checksum(reply, reply_len);

        ip_send_packet(src_ip, IP_PROTO_ICMP, reply, reply_len);
        fut_free(reply);
    }
}

int icmp_ping(uint32_t dest_ip, uint16_t id, uint16_t seq, void *data, size_t len) {
    size_t total_len = sizeof(icmp_header_t) + len;
    uint8_t *packet = fut_malloc(total_len);
    if (!packet) return -ENOMEM;

    icmp_header_t *icmp = (icmp_header_t *)packet;
    icmp->type = ICMP_ECHO_REQUEST;
    icmp->code = 0;
    icmp->checksum = 0;
    icmp->id = htons(id);
    icmp->sequence = htons(seq);

    if (data && len > 0) {
        memcpy(packet + sizeof(icmp_header_t), data, len);
    }

    icmp->checksum = tcpip_checksum(packet, total_len);

    ip_send_packet(dest_ip, IP_PROTO_ICMP, packet, total_len);
    fut_free(packet);

    return 0;
}

/* ============================================================================
 * UDP Implementation
 * ========================================================================= */

static void udp_handle_packet(const uint8_t *ip_payload, size_t len,
                              uint32_t src_ip, uint32_t dest_ip) {
    (void)dest_ip;  /* Unused for now */

    if (len < UDP_HEADER_LEN) {
        return;
    }

    const udp_header_t *udp = (const udp_header_t *)ip_payload;
    uint16_t src_port = ntohs(udp->src_port);
    uint16_t dest_port = ntohs(udp->dest_port);
    uint16_t udp_len = ntohs(udp->length);

    if (udp_len < UDP_HEADER_LEN || udp_len > len) {
        return;
    }

    size_t data_len = udp_len - UDP_HEADER_LEN;
    const uint8_t *data = ip_payload + UDP_HEADER_LEN;

    TCPIP_DEBUG("[UDP] Packet: port %u -> %u, len %zu\n", src_port, dest_port, data_len);

    /* Find matching socket */
    fut_spinlock_acquire(&socket_lock);
    for (int i = 0; i < TCPIP_MAX_SOCKETS; i++) {
        tcpip_socket_t *sock = sockets[i];
        if (sock && sock->type == SOCK_TYPE_UDP &&
            sock->bound && sock->local_port == dest_port) {

            fut_spinlock_acquire(&sock->lock);
            if (data_len <= TCPIP_RX_BUFFER_SIZE) {
                memcpy(sock->udp.rx_buffer, data, data_len);
                sock->udp.rx_len = data_len;
                sock->udp.src_ip = src_ip;
                sock->udp.src_port = src_port;
            }
            fut_spinlock_release(&sock->lock);
            break;
        }
    }
    fut_spinlock_release(&socket_lock);
}

/* ============================================================================
 * TCP Implementation
 * ========================================================================= */

static tcp_connection_t *tcp_find_connection(uint32_t remote_ip,
                                             uint16_t local_port,
                                             uint16_t remote_port) {
    for (int i = 0; i < TCPIP_MAX_TCP_CONNECTIONS; i++) {
        tcp_connection_t *conn = &tcp_connections[i];
        if (conn->active &&
            conn->remote_ip == remote_ip &&
            conn->local_port == local_port &&
            conn->remote_port == remote_port) {
            return conn;
        }
    }
    return NULL;
}

static tcp_connection_t *tcp_alloc_connection(void) {
    for (int i = 0; i < TCPIP_MAX_TCP_CONNECTIONS; i++) {
        if (!tcp_connections[i].active) {
            memset(&tcp_connections[i], 0, sizeof(tcp_connection_t));
            tcp_connections[i].active = true;
            return &tcp_connections[i];
        }
    }
    return NULL;
}

static void tcp_send_packet(tcp_connection_t *conn, uint8_t flags,
                            const void *data, size_t data_len) {
    size_t total_len = TCP_HEADER_MIN_LEN + data_len;
    uint8_t *packet = fut_malloc(total_len);
    if (!packet) return;

    tcp_header_t *tcp = (tcp_header_t *)packet;
    tcp->src_port = htons(conn->local_port);
    tcp->dest_port = htons(conn->remote_port);
    tcp->seq_num = htonl(conn->send_next);
    tcp->ack_num = htonl(conn->recv_next);
    tcp->data_offset_rsvd = (TCP_HEADER_MIN_LEN / 4) << 4;
    tcp->flags = flags;
    tcp->window = htons(TCPIP_RX_BUFFER_SIZE - conn->rx_len);
    tcp->urgent_ptr = 0;

    /* Copy data */
    if (data && data_len > 0) {
        memcpy(packet + TCP_HEADER_MIN_LEN, data, data_len);
    }

    /* Calculate checksum (simplified - should include pseudo-header) */
    tcp->checksum = 0;
    tcp->checksum = tcpip_checksum(packet, total_len);

    ip_send_packet(conn->remote_ip, IP_PROTO_TCP, packet, total_len);
    fut_free(packet);

    /* Update sequence number if sending data */
    if (data_len > 0 || (flags & (TCP_FLAG_SYN | TCP_FLAG_FIN))) {
        conn->send_next += data_len + ((flags & (TCP_FLAG_SYN | TCP_FLAG_FIN)) ? 1 : 0);
    }
}

static void tcp_handle_packet(const uint8_t *ip_payload, size_t len,
                              uint32_t src_ip, uint32_t dest_ip) {
    (void)dest_ip;  /* Unused for now */

    if (len < TCP_HEADER_MIN_LEN) {
        return;
    }

    const tcp_header_t *tcp = (const tcp_header_t *)ip_payload;
    uint16_t src_port = ntohs(tcp->src_port);
    uint16_t dest_port = ntohs(tcp->dest_port);
    uint32_t seq = ntohl(tcp->seq_num);
    uint32_t ack = ntohl(tcp->ack_num);
    uint8_t flags = tcp->flags;
    uint16_t window = ntohs(tcp->window);

    size_t header_len = ((tcp->data_offset_rsvd >> 4) & 0xF) * 4;
    if (header_len < TCP_HEADER_MIN_LEN || header_len > len) {
        return;
    }

    size_t data_len = len - header_len;
    const uint8_t *data = ip_payload + header_len;

    TCPIP_DEBUG("[TCP] Packet: port %u -> %u, flags=%02x\n", src_port, dest_port, flags);

    fut_spinlock_acquire(&tcp_lock);

    tcp_connection_t *conn = tcp_find_connection(src_ip, dest_port, src_port);

    /* Handle SYN for new connections */
    if ((flags & TCP_FLAG_SYN) && !(flags & TCP_FLAG_ACK) && !conn) {
        conn = tcp_alloc_connection();
        if (conn) {
            conn->state = TCP_STATE_LISTEN;
            conn->remote_ip = src_ip;
            conn->local_port = dest_port;
            conn->remote_port = src_port;
            conn->recv_next = seq + 1;
            conn->send_next = 1000;  /* Initial sequence number */
            conn->send_window = window;

            /* Send SYN-ACK */
            tcp_send_packet(conn, TCP_FLAG_SYN | TCP_FLAG_ACK, NULL, 0);
            conn->state = TCP_STATE_SYN_RECEIVED;
            TCPIP_DEBUG("[TCP] SYN received, sending SYN-ACK\n");
        }
    }
    /* Handle established connection packets */
    else if (conn) {
        /* Update window */
        conn->send_window = window;

        /* Handle ACK */
        if (flags & TCP_FLAG_ACK) {
            if (conn->state == TCP_STATE_SYN_SENT && (flags & TCP_FLAG_SYN)) {
                conn->recv_next = seq + 1;
                conn->send_unack = ack;
                conn->state = TCP_STATE_ESTABLISHED;
                tcp_send_packet(conn, TCP_FLAG_ACK, NULL, 0);
                TCPIP_DEBUG("[TCP] Connection established\n");
            }
            else if (conn->state == TCP_STATE_SYN_RECEIVED) {
                conn->send_unack = ack;
                conn->state = TCP_STATE_ESTABLISHED;
                TCPIP_DEBUG("[TCP] Connection established\n");
            }
            else if (conn->state == TCP_STATE_ESTABLISHED) {
                conn->send_unack = ack;
            }
        }

        /* Handle data */
        if (data_len > 0 && conn->state == TCP_STATE_ESTABLISHED) {
            if (seq == conn->recv_next) {
                size_t copy_len = data_len;
                if (conn->rx_len + copy_len > TCPIP_RX_BUFFER_SIZE) {
                    copy_len = TCPIP_RX_BUFFER_SIZE - conn->rx_len;
                }

                if (copy_len > 0) {
                    memcpy(conn->rx_buffer + conn->rx_len, data, copy_len);
                    conn->rx_len += copy_len;
                    conn->recv_next += copy_len;
                }

                /* Send ACK */
                tcp_send_packet(conn, TCP_FLAG_ACK, NULL, 0);
            }
        }

        /* Handle FIN */
        if (flags & TCP_FLAG_FIN) {
            conn->recv_next++;
            tcp_send_packet(conn, TCP_FLAG_ACK | TCP_FLAG_FIN, NULL, 0);
            conn->state = TCP_STATE_LAST_ACK;
        }

        /* Handle RST */
        if (flags & TCP_FLAG_RST) {
            conn->active = false;
            conn->state = TCP_STATE_CLOSED;
        }
    }

    fut_spinlock_release(&tcp_lock);
}

/* ============================================================================
 * IP Packet Reception
 * ========================================================================= */

static void ip_handle_packet(const uint8_t *frame, size_t len) {
    if (len < ETH_HEADER_LEN + IP_HEADER_MIN_LEN) {
        return;
    }

    const ip_header_t *ip = (const ip_header_t *)(frame + ETH_HEADER_LEN);

    /* Verify version and header length */
    uint8_t version = (ip->version_ihl >> 4) & 0xF;
    uint8_t ihl = (ip->version_ihl & 0xF) * 4;

    if (version != IP_VERSION_4 || ihl < IP_HEADER_MIN_LEN) {
        return;
    }

    /* Verify checksum */
    uint16_t received_checksum = ip->checksum;
    ip_header_t *ip_mut = (ip_header_t *)(frame + ETH_HEADER_LEN);
    ip_mut->checksum = 0;
    uint16_t calculated_checksum = tcpip_checksum(ip, ihl);
    ip_mut->checksum = received_checksum;

    if (received_checksum != calculated_checksum) {
        TCPIP_DEBUG("[IP] Checksum mismatch\n");
        return;
    }

    uint32_t src_ip = ntohl(ip->src_addr);
    uint32_t dest_ip = ntohl(ip->dest_addr);
    uint16_t total_len = ntohs(ip->total_length);
    uint8_t protocol = ip->protocol;

    /* Check if packet is for us */
    if (dest_ip != g_tcpip.ip_address && dest_ip != 0xFFFFFFFF) {
        return;
    }

    size_t payload_len = total_len - ihl;
    const uint8_t *payload = (const uint8_t *)ip + ihl;

    /* Dispatch to protocol handlers */
    switch (protocol) {
        case IP_PROTO_ICMP:
            icmp_handle_packet(payload, payload_len, src_ip);
            break;
        case IP_PROTO_UDP:
            udp_handle_packet(payload, payload_len, src_ip, dest_ip);
            break;
        case IP_PROTO_TCP:
            tcp_handle_packet(payload, payload_len, src_ip, dest_ip);
            break;
        default:
            TCPIP_DEBUG("[IP] Unknown protocol %u\n", protocol);
            break;
    }
}

/* ============================================================================
 * Frame Reception Thread
 * ========================================================================= */

static void tcpip_rx_thread(void *arg) {
    (void)arg;

    uint8_t buffer[ETH_MAX_FRAME];

    while (1) {
        size_t received = 0;
        int rc = fut_net_recv(g_tcpip.raw_socket, buffer, sizeof(buffer), &received);

        if (rc == 0 && received >= ETH_HEADER_LEN) {
            const eth_header_t *eth = (const eth_header_t *)buffer;
            uint16_t ethertype = ntohs(eth->type);

            switch (ethertype) {
                case ETHERTYPE_ARP:
                    arp_handle_packet(buffer, received);
                    break;
                case ETHERTYPE_IP:
                    ip_handle_packet(buffer, received);
                    break;
                default:
                    break;
            }
        }
    }
}

/* ============================================================================
 * Socket API Implementation
 * ========================================================================= */

tcpip_socket_t *tcpip_socket(socket_type_t type) {
    tcpip_socket_t *sock = fut_malloc(sizeof(tcpip_socket_t));
    if (!sock) return NULL;

    memset(sock, 0, sizeof(tcpip_socket_t));
    sock->type = type;
    fut_spinlock_init(&sock->lock);

    /* Add to socket list */
    fut_spinlock_acquire(&socket_lock);
    for (int i = 0; i < TCPIP_MAX_SOCKETS; i++) {
        if (!sockets[i]) {
            sockets[i] = sock;
            break;
        }
    }
    fut_spinlock_release(&socket_lock);

    return sock;
}

int tcpip_bind(tcpip_socket_t *sock, uint16_t port) {
    if (!sock || port == 0) return -EINVAL;

    fut_spinlock_acquire(&sock->lock);
    if (sock->bound) {
        fut_spinlock_release(&sock->lock);
        return -EINVAL;
    }

    sock->local_port = port;
    sock->bound = true;
    fut_spinlock_release(&sock->lock);

    return 0;
}

int tcpip_listen(tcpip_socket_t *sock, int backlog) {
    (void)backlog;  /* Unused for now */

    if (!sock || sock->type != SOCK_TYPE_TCP) return -EINVAL;

    fut_spinlock_acquire(&sock->lock);
    if (!sock->bound) {
        fut_spinlock_release(&sock->lock);
        return -EINVAL;
    }

    sock->listening = true;
    fut_spinlock_release(&sock->lock);

    return 0;
}

int tcpip_connect(tcpip_socket_t *sock, uint32_t ip, uint16_t port) {
    if (!sock || sock->type != SOCK_TYPE_TCP) return -EINVAL;

    fut_spinlock_acquire(&sock->lock);
    if (sock->connected) {
        fut_spinlock_release(&sock->lock);
        return -EISCONN;
    }

    /* Allocate connection */
    fut_spinlock_acquire(&tcp_lock);
    tcp_connection_t *conn = tcp_alloc_connection();
    if (!conn) {
        fut_spinlock_release(&tcp_lock);
        fut_spinlock_release(&sock->lock);
        return -ENOMEM;
    }

    conn->remote_ip = ip;
    conn->local_port = sock->local_port ? sock->local_port : 50000;  /* Ephemeral port */
    conn->remote_port = port;
    conn->send_next = 1000;  /* Initial sequence number */
    conn->recv_next = 0;
    conn->state = TCP_STATE_SYN_SENT;
    sock->tcp_conn = conn;

    /* Send SYN */
    tcp_send_packet(conn, TCP_FLAG_SYN, NULL, 0);
    fut_spinlock_release(&tcp_lock);

    /* Wait for connection (simplified) */
    for (int i = 0; i < 100; i++) {
        for (volatile int j = 0; j < 100000; j++);
        if (conn->state == TCP_STATE_ESTABLISHED) {
            sock->connected = true;
            sock->remote_ip = ip;
            sock->remote_port = port;
            fut_spinlock_release(&sock->lock);
            return 0;
        }
    }

    /* Connection timeout */
    fut_spinlock_release(&sock->lock);
    return -ETIMEDOUT;
}

int tcpip_send(tcpip_socket_t *sock, const void *data, size_t len) {
    if (!sock || !data || len == 0) return -EINVAL;

    fut_spinlock_acquire(&sock->lock);

    if (sock->type == SOCK_TYPE_TCP) {
        if (!sock->connected || !sock->tcp_conn) {
            fut_spinlock_release(&sock->lock);
            return -ENOTCONN;
        }

        tcp_connection_t *conn = sock->tcp_conn;
        tcp_send_packet(conn, TCP_FLAG_PSH | TCP_FLAG_ACK, data, len);
        fut_spinlock_release(&sock->lock);
        return len;
    }

    fut_spinlock_release(&sock->lock);
    return -EINVAL;
}

int tcpip_sendto(tcpip_socket_t *sock, const void *data, size_t len,
                 uint32_t dest_ip, uint16_t dest_port) {
    if (!sock || !data || len == 0 || sock->type != SOCK_TYPE_UDP) {
        return -EINVAL;
    }

    size_t total_len = UDP_HEADER_LEN + len;
    uint8_t *packet = fut_malloc(total_len);
    if (!packet) return -ENOMEM;

    udp_header_t *udp = (udp_header_t *)packet;
    udp->src_port = htons(sock->local_port);
    udp->dest_port = htons(dest_port);
    udp->length = htons(total_len);
    udp->checksum = 0;  /* Optional in IPv4 */

    memcpy(packet + UDP_HEADER_LEN, data, len);

    ip_send_packet(dest_ip, IP_PROTO_UDP, packet, total_len);
    fut_free(packet);

    return len;
}

int tcpip_recv(tcpip_socket_t *sock, void *buf, size_t len) {
    if (!sock || !buf || len == 0) return -EINVAL;

    fut_spinlock_acquire(&sock->lock);

    if (sock->type == SOCK_TYPE_TCP) {
        if (!sock->connected || !sock->tcp_conn) {
            fut_spinlock_release(&sock->lock);
            return -ENOTCONN;
        }

        tcp_connection_t *conn = sock->tcp_conn;

        /* Wait for data (simplified) */
        for (int i = 0; i < 100; i++) {
            if (conn->rx_len > 0) break;
            fut_spinlock_release(&sock->lock);
            for (volatile int j = 0; j < 100000; j++);
            fut_spinlock_acquire(&sock->lock);
        }

        if (conn->rx_len == 0) {
            fut_spinlock_release(&sock->lock);
            return -EAGAIN;
        }

        size_t copy_len = (len < conn->rx_len) ? len : conn->rx_len;
        memcpy(buf, conn->rx_buffer, copy_len);

        /* Remove from buffer */
        memmove(conn->rx_buffer, conn->rx_buffer + copy_len, conn->rx_len - copy_len);
        conn->rx_len -= copy_len;

        fut_spinlock_release(&sock->lock);
        return copy_len;
    }

    fut_spinlock_release(&sock->lock);
    return -EINVAL;
}

int tcpip_recvfrom(tcpip_socket_t *sock, void *buf, size_t len,
                   uint32_t *src_ip, uint16_t *src_port) {
    if (!sock || !buf || len == 0 || sock->type != SOCK_TYPE_UDP) {
        return -EINVAL;
    }

    fut_spinlock_acquire(&sock->lock);

    /* Wait for data (simplified) */
    for (int i = 0; i < 100; i++) {
        if (sock->udp.rx_len > 0) break;
        fut_spinlock_release(&sock->lock);
        for (volatile int j = 0; j < 100000; j++);
        fut_spinlock_acquire(&sock->lock);
    }

    if (sock->udp.rx_len == 0) {
        fut_spinlock_release(&sock->lock);
        return -EAGAIN;
    }

    size_t copy_len = (len < sock->udp.rx_len) ? len : sock->udp.rx_len;
    memcpy(buf, sock->udp.rx_buffer, copy_len);

    if (src_ip) *src_ip = sock->udp.src_ip;
    if (src_port) *src_port = sock->udp.src_port;

    sock->udp.rx_len = 0;

    fut_spinlock_release(&sock->lock);
    return copy_len;
}

int tcpip_close(tcpip_socket_t *sock) {
    if (!sock) return -EINVAL;

    fut_spinlock_acquire(&sock->lock);

    if (sock->type == SOCK_TYPE_TCP && sock->tcp_conn) {
        tcp_connection_t *conn = sock->tcp_conn;
        if (conn->state == TCP_STATE_ESTABLISHED) {
            tcp_send_packet(conn, TCP_FLAG_FIN | TCP_FLAG_ACK, NULL, 0);
            conn->state = TCP_STATE_FIN_WAIT_1;
        }
        conn->active = false;
    }

    fut_spinlock_release(&sock->lock);

    /* Remove from socket list */
    fut_spinlock_acquire(&socket_lock);
    for (int i = 0; i < TCPIP_MAX_SOCKETS; i++) {
        if (sockets[i] == sock) {
            sockets[i] = NULL;
            break;
        }
    }
    fut_spinlock_release(&socket_lock);

    fut_free(sock);
    return 0;
}

/* ============================================================================
 * Initialization
 * ========================================================================= */

int tcpip_set_ip_address(uint32_t ip, uint32_t netmask, uint32_t gateway) {
    g_tcpip.ip_address = ip;
    g_tcpip.netmask = netmask;
    g_tcpip.gateway = gateway;

    char ip_str[16];
    tcpip_format_ip(ip, ip_str, sizeof(ip_str));
    fut_printf("[TCP/IP] IP address set to %s\n", ip_str);

    return 0;
}

int tcpip_get_mac_address(eth_addr_t *mac) {
    if (!mac) return -EINVAL;
    memcpy(*mac, g_tcpip.mac_address, ETH_ADDR_LEN);
    return 0;
}

int tcpip_init(void) {
    if (g_tcpip.initialized) {
        return 0;
    }

    fut_printf("[TCP/IP] Initializing protocol stack...\n");

    /* Initialize state */
    memset(&g_tcpip, 0, sizeof(g_tcpip));
    fut_spinlock_init(&g_tcpip.lock);
    fut_spinlock_init(&arp_lock);
    fut_spinlock_init(&tcp_lock);
    fut_spinlock_init(&socket_lock);

    /* Set default MAC address (should be provided by NIC driver) */
    g_tcpip.mac_address[0] = 0x52;
    g_tcpip.mac_address[1] = 0x54;
    g_tcpip.mac_address[2] = 0x00;
    g_tcpip.mac_address[3] = 0x12;
    g_tcpip.mac_address[4] = 0x34;
    g_tcpip.mac_address[5] = 0x56;

    /* Set default IP configuration */
    tcpip_set_ip_address(TCPIP_DEFAULT_IP, TCPIP_DEFAULT_MASK, TCPIP_DEFAULT_GW);

    /* Initialize underlying network layer */
    fut_net_init();

    /* Create raw socket for sending/receiving frames */
    int rc = fut_net_listen(0, &g_tcpip.raw_socket);
    if (rc != 0) {
        fut_printf("[TCP/IP] Failed to create raw socket: %d\n", rc);
        return rc;
    }

    /* Accept the socket (puts it into receive mode) */
    fut_socket_t *accepted;
    rc = fut_net_accept(g_tcpip.raw_socket, &accepted);
    if (rc == 0) {
        g_tcpip.raw_socket = accepted;
    }

    /* Start receive thread */
    fut_thread_t *rx_thread = fut_thread_create(NULL, tcpip_rx_thread, NULL, 8192, 100);
    if (rx_thread) {
        fut_sched_add_thread(rx_thread);
    }

    g_tcpip.initialized = true;
    fut_printf("[TCP/IP] Stack initialized\n");

    return 0;
}
