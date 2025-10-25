// SPDX-License-Identifier: MPL-2.0
/*
 * dns.c - Domain Name System (DNS) resolver implementation
 */

#include <futura/dns.h>
#include <futura/tcpip.h>
#include <kernel/fut_memory.h>
#include <kernel/fut_timer.h>
#include <kernel/errno.h>
#include <platform/platform.h>

/* String functions we need */
static size_t dns_strlen(const char *s) {
    size_t len = 0;
    while (s[len]) len++;
    return len;
}

static void dns_memcpy(void *dest, const void *src, size_t n) {
    uint8_t *d = dest;
    const uint8_t *s = src;
    while (n--) *d++ = *s++;
}

static void dns_memset(void *s, int c, size_t n) {
    uint8_t *p = s;
    while (n--) *p++ = (uint8_t)c;
}

static int dns_strcmp(const char *s1, const char *s2) {
    while (*s1 && (*s1 == *s2)) {
        s1++;
        s2++;
    }
    return *(unsigned char *)s1 - *(unsigned char *)s2;
}

static char *dns_strcpy(char *dest, const char *src) {
    char *ret = dest;
    while ((*dest++ = *src++));
    return ret;
}

/* Global DNS state */
static dns_state_t g_dns = {0};

/*
 * DNS Domain Name Encoding (RFC 1035 Section 4.1.4)
 * Converts "google.com" to "\x06google\x03com\x00"
 */
static size_t dns_encode_domain(const char *domain, uint8_t *buffer) {
    size_t pos = 0;
    size_t label_start = 0;
    size_t domain_len = dns_strlen(domain);

    for (size_t i = 0; i <= domain_len; i++) {
        if (domain[i] == '.' || domain[i] == '\0') {
            size_t label_len = i - label_start;
            if (label_len == 0) {
                continue;  /* Skip empty labels */
            }
            if (label_len > DNS_MAX_LABEL_LEN) {
                return 0;  /* Label too long */
            }

            buffer[pos++] = (uint8_t)label_len;
            dns_memcpy(&buffer[pos], &domain[label_start], label_len);
            pos += label_len;
            label_start = i + 1;
        }
    }

    buffer[pos++] = 0;  /* Null terminator */
    return pos;
}

/*
 * DNS Domain Name Decoding
 * Handles both regular labels and compression pointers
 */
static size_t dns_decode_domain(const uint8_t *packet, size_t packet_len,
                                size_t offset, char *domain, size_t domain_max) {
    size_t pos = offset;
    size_t domain_pos = 0;
    size_t jumps = 0;
    size_t ret_offset = 0;
    bool jumped = false;

    while (pos < packet_len && jumps < 20) {  /* Prevent infinite loops */
        uint8_t len = packet[pos];

        if (len == 0) {
            /* End of domain name */
            if (!jumped) {
                ret_offset = pos + 1;
            }
            break;
        }

        if ((len & 0xC0) == 0xC0) {
            /* Compression pointer (RFC 1035 Section 4.1.4) */
            if (pos + 1 >= packet_len) {
                return 0;  /* Invalid pointer */
            }

            uint16_t pointer = ((len & 0x3F) << 8) | packet[pos + 1];
            if (!jumped) {
                ret_offset = pos + 2;
                jumped = true;
            }
            pos = pointer;
            jumps++;
            continue;
        }

        /* Regular label */
        if (len > DNS_MAX_LABEL_LEN) {
            return 0;  /* Invalid label length */
        }

        pos++;
        if (pos + len > packet_len) {
            return 0;  /* Label extends past packet */
        }

        if (domain_pos > 0 && domain_pos < domain_max) {
            domain[domain_pos++] = '.';
        }

        for (size_t i = 0; i < len && domain_pos < domain_max - 1; i++) {
            domain[domain_pos++] = packet[pos++];
        }
    }

    domain[domain_pos] = '\0';
    return jumped ? ret_offset : pos;
}

/*
 * Build a DNS query packet
 */
static size_t dns_build_query(const char *domain, uint8_t *buffer, size_t buffer_len,
                              uint16_t query_id) {
    if (buffer_len < sizeof(dns_header_t) + DNS_MAX_DOMAIN_LEN + 4) {
        return 0;
    }

    /* Build DNS header */
    dns_header_t *header = (dns_header_t *)buffer;
    dns_memset(header, 0, sizeof(dns_header_t));

    header->id = htons(query_id);
    header->flags = htons(DNS_FLAG_RD);  /* Recursion desired */
    header->qdcount = htons(1);  /* One question */
    header->ancount = 0;
    header->nscount = 0;
    header->arcount = 0;

    /* Encode domain name */
    size_t name_len = dns_encode_domain(domain, buffer + sizeof(dns_header_t));
    if (name_len == 0) {
        return 0;
    }

    /* Add question suffix (type and class) */
    dns_question_suffix_t *qsuffix =
        (dns_question_suffix_t *)(buffer + sizeof(dns_header_t) + name_len);
    qsuffix->qtype = htons(DNS_TYPE_A);      /* IPv4 address */
    qsuffix->qclass = htons(DNS_CLASS_IN);   /* Internet */

    return sizeof(dns_header_t) + name_len + sizeof(dns_question_suffix_t);
}

/*
 * Parse a DNS response packet
 */
static int dns_parse_response(const uint8_t *packet, size_t packet_len,
                              uint16_t expected_id, uint32_t *ip) {
    if (packet_len < sizeof(dns_header_t)) {
        return -EINVAL;
    }

    dns_header_t *header = (dns_header_t *)packet;

    /* Verify this is a response to our query */
    if (ntohs(header->id) != expected_id) {
        return -EINVAL;
    }

    uint16_t flags = ntohs(header->flags);

    /* Check if this is a response */
    if ((flags & DNS_FLAG_QR) == 0) {
        return -EINVAL;  /* Not a response */
    }

    /* Check response code */
    uint16_t rcode = flags & DNS_RCODE_MASK;
    if (rcode == DNS_RCODE_NXDOMAIN) {
        return -ENOENT;  /* Domain doesn't exist */
    } else if (rcode != DNS_RCODE_NOERROR) {
        return -EIO;  /* Other DNS error */
    }

    uint16_t ancount = ntohs(header->ancount);
    if (ancount == 0) {
        return -ENOENT;  /* No answers */
    }

    /* Skip past questions */
    size_t offset = sizeof(dns_header_t);
    uint16_t qdcount = ntohs(header->qdcount);

    for (uint16_t i = 0; i < qdcount; i++) {
        char domain[DNS_MAX_DOMAIN_LEN + 1];
        offset = dns_decode_domain(packet, packet_len, offset, domain, sizeof(domain));
        if (offset == 0) {
            return -EINVAL;
        }
        offset += sizeof(dns_question_suffix_t);
        if (offset > packet_len) {
            return -EINVAL;
        }
    }

    /* Parse answer records */
    for (uint16_t i = 0; i < ancount; i++) {
        char domain[DNS_MAX_DOMAIN_LEN + 1];
        size_t name_end = dns_decode_domain(packet, packet_len, offset, domain, sizeof(domain));
        if (name_end == 0 || name_end + sizeof(dns_rr_suffix_t) > packet_len) {
            return -EINVAL;
        }

        dns_rr_suffix_t *rr = (dns_rr_suffix_t *)(packet + name_end);
        uint16_t type = ntohs(rr->type);
        uint16_t rdlength = ntohs(rr->rdlength);

        size_t rdata_offset = name_end + sizeof(dns_rr_suffix_t);
        if (rdata_offset + rdlength > packet_len) {
            return -EINVAL;
        }

        if (type == DNS_TYPE_A && rdlength == 4) {
            /* Found an IPv4 address! */
            const uint8_t *rdata = packet + rdata_offset;
            *ip = (rdata[0] << 24) | (rdata[1] << 16) | (rdata[2] << 8) | rdata[3];
            return 0;
        }

        /* Skip to next answer */
        offset = rdata_offset + rdlength;
    }

    return -ENOENT;  /* No A record found */
}

/*
 * DNS Cache Implementation
 */

void dns_cache_add(const char *domain, uint32_t ip, uint32_t ttl) {
    if (!domain || dns_strlen(domain) > DNS_MAX_DOMAIN_LEN) {
        return;
    }

    uint64_t now = fut_get_ticks();
    uint64_t expires = now + (ttl * 100);  /* Convert seconds to ticks (100Hz) */

    /* Find an empty slot or the oldest entry */
    int slot = -1;
    uint64_t oldest_time = UINT64_MAX;

    for (int i = 0; i < DNS_CACHE_SIZE; i++) {
        if (!g_dns.cache[i].valid || g_dns.cache[i].expires < now) {
            slot = i;
            break;
        }
        if (g_dns.cache[i].expires < oldest_time) {
            oldest_time = g_dns.cache[i].expires;
            slot = i;
        }
    }

    if (slot >= 0) {
        dns_strcpy(g_dns.cache[slot].domain, domain);
        g_dns.cache[slot].ip = ip;
        g_dns.cache[slot].expires = expires;
        g_dns.cache[slot].valid = true;
    }
}

int dns_cache_lookup(const char *domain, uint32_t *ip) {
    if (!domain || !ip) {
        return -EINVAL;
    }

    uint64_t now = fut_get_ticks();

    for (int i = 0; i < DNS_CACHE_SIZE; i++) {
        if (g_dns.cache[i].valid &&
            dns_strcmp(g_dns.cache[i].domain, domain) == 0) {

            if (g_dns.cache[i].expires > now) {
                *ip = g_dns.cache[i].ip;
                return 0;
            } else {
                /* Entry expired */
                g_dns.cache[i].valid = false;
                return -ENOENT;
            }
        }
    }

    return -ENOENT;
}

void dns_cache_clear(void) {
    dns_memset(&g_dns.cache, 0, sizeof(g_dns.cache));
}

void dns_format_ip(uint32_t ip, char *buf, size_t len) {
    if (!buf || len < 16) return;

    uint8_t b[4];
    b[0] = (ip >> 24) & 0xFF;
    b[1] = (ip >> 16) & 0xFF;
    b[2] = (ip >> 8) & 0xFF;
    b[3] = ip & 0xFF;

    /* Simple formatting without snprintf */
    size_t pos = 0;
    for (int i = 0; i < 4; i++) {
        int val = b[i];
        char tmp[4];
        int tmppos = 0;

        do {
            tmp[tmppos++] = '0' + (val % 10);
            val /= 10;
        } while (val > 0);

        while (tmppos > 0 && pos < len - 1) {
            buf[pos++] = tmp[--tmppos];
        }

        if (i < 3 && pos < len - 1) {
            buf[pos++] = '.';
        }
    }
    buf[pos] = '\0';
}

/*
 * Main DNS Resolver Function
 */

int dns_resolve(const char *domain, uint32_t *ip) {
    if (!g_dns.initialized) {
        return -EINVAL;
    }

    if (!domain || !ip) {
        return -EINVAL;
    }

    if (dns_strlen(domain) > DNS_MAX_DOMAIN_LEN) {
        return -ENAMETOOLONG;
    }

    /* Check cache first */
    if (dns_cache_lookup(domain, ip) == 0) {
        char ip_str[16];
        dns_format_ip(*ip, ip_str, sizeof(ip_str));
        fut_printf("[DNS] Cache hit: %s -> %s\n", domain, ip_str);
        return 0;
    }

    /* Build DNS query */
    uint8_t query_buffer[512];
    uint16_t query_id = g_dns.next_id++;

    size_t query_len = dns_build_query(domain, query_buffer, sizeof(query_buffer), query_id);
    if (query_len == 0) {
        return -EINVAL;
    }

    /* Create UDP socket if not already created */
    if (!g_dns.udp_socket) {
        g_dns.udp_socket = tcpip_socket(SOCK_TYPE_UDP);
        if (!g_dns.udp_socket) {
            return -ENOMEM;
        }
    }

    fut_printf("[DNS] Querying %s (ID %u)...\n", domain, query_id);

    /* Try primary DNS server first, then alternative if available */
    uint32_t dns_servers[2] = { g_dns.dns_server, g_dns.dns_server_alt };
    int num_servers = g_dns.dns_server_alt ? 2 : 1;

    for (int server = 0; server < num_servers; server++) {
        if (!dns_servers[server]) continue;

        for (int retry = 0; retry < DNS_MAX_RETRIES; retry++) {
            /* Connect to DNS server */
            int rc = tcpip_connect(g_dns.udp_socket, dns_servers[server], DNS_PORT);
            if (rc != 0) {
                continue;
            }

            /* Send query */
            rc = tcpip_send(g_dns.udp_socket, query_buffer, query_len);
            if (rc < 0) {
                continue;
            }

            /* Wait for response with timeout */
            uint8_t response_buffer[512];
            uint64_t start_time = fut_get_ticks();
            uint64_t timeout_ticks = (DNS_TIMEOUT_MS * 100) / 1000;  /* ms to ticks */

            while (fut_get_ticks() - start_time < timeout_ticks) {
                rc = tcpip_recv(g_dns.udp_socket, response_buffer, sizeof(response_buffer));
                if (rc > 0) {
                    /* Parse response */
                    rc = dns_parse_response(response_buffer, rc, query_id, ip);
                    if (rc == 0) {
                        /* Success! Add to cache */
                        dns_cache_add(domain, *ip, DNS_CACHE_TTL);

                        char ip_str[16];
                        dns_format_ip(*ip, ip_str, sizeof(ip_str));
                        fut_printf("[DNS] Resolved: %s -> %s\n", domain, ip_str);
                        return 0;
                    }
                }

                /* Small delay before checking again */
                for (volatile int i = 0; i < 100000; i++);
            }
        }
    }

    fut_printf("[DNS] Failed to resolve: %s\n", domain);
    return -ETIMEDOUT;
}

/*
 * DNS Initialization
 */

int dns_init(uint32_t primary_dns, uint32_t alt_dns) {
    if (g_dns.initialized) {
        return 0;  /* Already initialized */
    }

    dns_memset(&g_dns, 0, sizeof(g_dns));

    g_dns.dns_server = primary_dns;
    g_dns.dns_server_alt = alt_dns;
    g_dns.next_id = 1;
    g_dns.initialized = true;

    char primary_str[16];
    dns_format_ip(primary_dns, primary_str, sizeof(primary_str));

    if (alt_dns) {
        char alt_str[16];
        dns_format_ip(alt_dns, alt_str, sizeof(alt_str));
        fut_printf("[DNS] Initialized with servers: %s, %s\n", primary_str, alt_str);
    } else {
        fut_printf("[DNS] Initialized with server: %s\n", primary_str);
    }

    return 0;
}
