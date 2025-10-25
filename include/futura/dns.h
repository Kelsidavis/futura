// SPDX-License-Identifier: MPL-2.0
/*
 * dns.h - Domain Name System (DNS) resolver
 *
 * Provides DNS resolution capabilities for converting domain names to IP
 * addresses. Implements DNS query/response protocol over UDP port 53 with
 * caching support for performance.
 */

#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/*
 * DNS Protocol Constants
 */
#define DNS_PORT            53
#define DNS_MAX_DOMAIN_LEN  255
#define DNS_MAX_LABEL_LEN   63
#define DNS_CACHE_SIZE      128
#define DNS_CACHE_TTL       300     /* 5 minutes default TTL */
#define DNS_TIMEOUT_MS      5000    /* 5 second timeout */
#define DNS_MAX_RETRIES     3

/*
 * DNS Message Header (RFC 1035 Section 4.1.1)
 */
typedef struct __attribute__((packed)) {
    uint16_t id;           /* Query ID */
    uint16_t flags;        /* Flags and codes */
    uint16_t qdcount;      /* Number of questions */
    uint16_t ancount;      /* Number of answers */
    uint16_t nscount;      /* Number of authority records */
    uint16_t arcount;      /* Number of additional records */
} dns_header_t;

/*
 * DNS Header Flags
 */
#define DNS_FLAG_QR     0x8000  /* Query/Response (0=query, 1=response) */
#define DNS_FLAG_AA     0x0400  /* Authoritative Answer */
#define DNS_FLAG_TC     0x0200  /* Truncated */
#define DNS_FLAG_RD     0x0100  /* Recursion Desired */
#define DNS_FLAG_RA     0x0080  /* Recursion Available */

#define DNS_OPCODE_QUERY  0x0000  /* Standard query */
#define DNS_OPCODE_MASK   0x7800

#define DNS_RCODE_MASK    0x000F
#define DNS_RCODE_NOERROR 0x0000
#define DNS_RCODE_FORMERR 0x0001  /* Format error */
#define DNS_RCODE_SERVFAIL 0x0002 /* Server failure */
#define DNS_RCODE_NXDOMAIN 0x0003 /* Name error */
#define DNS_RCODE_NOTIMP  0x0004  /* Not implemented */
#define DNS_RCODE_REFUSED 0x0005  /* Refused */

/*
 * DNS Question Section (RFC 1035 Section 4.1.2)
 * Note: Variable-length encoded domain name followed by type and class
 */
typedef struct __attribute__((packed)) {
    /* Domain name is variable-length, encoded before this struct */
    uint16_t qtype;
    uint16_t qclass;
} dns_question_suffix_t;

/*
 * DNS Resource Record (RFC 1035 Section 4.1.3)
 */
typedef struct __attribute__((packed)) {
    /* Name is variable-length, encoded before this struct */
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t rdlength;
    /* rdata follows, variable length */
} dns_rr_suffix_t;

/*
 * DNS Record Types (RFC 1035)
 */
#define DNS_TYPE_A      1   /* IPv4 address */
#define DNS_TYPE_NS     2   /* Name server */
#define DNS_TYPE_CNAME  5   /* Canonical name */
#define DNS_TYPE_SOA    6   /* Start of authority */
#define DNS_TYPE_PTR    12  /* Pointer */
#define DNS_TYPE_MX     15  /* Mail exchange */
#define DNS_TYPE_TXT    16  /* Text */
#define DNS_TYPE_AAAA   28  /* IPv6 address */

/*
 * DNS Classes
 */
#define DNS_CLASS_IN    1   /* Internet */

/*
 * DNS Cache Entry
 */
typedef struct {
    char domain[DNS_MAX_DOMAIN_LEN + 1];
    uint32_t ip;
    uint64_t expires;    /* Timestamp when entry expires */
    bool valid;
} dns_cache_entry_t;

/*
 * DNS Resolver State
 */
typedef struct {
    bool initialized;
    uint32_t dns_server;      /* Primary DNS server IP */
    uint32_t dns_server_alt;  /* Alternative DNS server IP */
    uint16_t next_id;         /* Next query ID */
    dns_cache_entry_t cache[DNS_CACHE_SIZE];
    void *udp_socket;         /* UDP socket for queries */
} dns_state_t;

/*
 * DNS Resolver API
 */

/**
 * Initialize the DNS resolver
 * @param primary_dns Primary DNS server IP (e.g., 8.8.8.8)
 * @param alt_dns Alternative DNS server IP (optional, can be 0)
 * @return 0 on success, negative error code on failure
 */
int dns_init(uint32_t primary_dns, uint32_t alt_dns);

/**
 * Resolve a domain name to an IPv4 address
 * @param domain Domain name to resolve (e.g., "google.com")
 * @param ip Pointer to store the resolved IP address
 * @return 0 on success, negative error code on failure
 */
int dns_resolve(const char *domain, uint32_t *ip);

/**
 * Add an entry to the DNS cache
 * @param domain Domain name
 * @param ip IP address
 * @param ttl Time-to-live in seconds
 */
void dns_cache_add(const char *domain, uint32_t ip, uint32_t ttl);

/**
 * Look up a domain in the DNS cache
 * @param domain Domain name
 * @param ip Pointer to store IP if found
 * @return 0 if found, -ENOENT if not in cache or expired
 */
int dns_cache_lookup(const char *domain, uint32_t *ip);

/**
 * Clear all entries from the DNS cache
 */
void dns_cache_clear(void);

/**
 * Format an IP address as a string (for debugging)
 * @param ip IP address in host byte order
 * @param buf Buffer to store formatted string
 * @param len Buffer length
 */
void dns_format_ip(uint32_t ip, char *buf, size_t len);
