/* string.c - String Functions for Futura OS Userland
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Basic string manipulation functions (no libc dependency).
 */

#include <stddef.h>
#include <stdint.h>

/**
 * Calculate string length.
 */
size_t strlen(const char *s) {
    size_t len = 0;
    if (!s) return 0;
    while (s[len]) len++;
    return len;
}

/**
 * Copy string (safe version).
 */
char *strncpy(char *dest, const char *src, size_t n) {
    if (!dest || !src) return dest;

    size_t i;
    for (i = 0; i < n && src[i] != '\0'; i++) {
        dest[i] = src[i];
    }
    for (; i < n; i++) {
        dest[i] = '\0';
    }

    return dest;
}

/**
 * Copy string (unsafe version).
 */
char *strcpy(char *dest, const char *src) {
    if (!dest || !src) return dest;

    size_t i = 0;
    while (src[i] != '\0') {
        dest[i] = src[i];
        i++;
    }
    dest[i] = '\0';

    return dest;
}

/**
 * Compare strings.
 */
int strcmp(const char *s1, const char *s2) {
    if (!s1 || !s2) return 0;

    while (*s1 && *s2 && *s1 == *s2) {
        s1++;
        s2++;
    }

    return (unsigned char)*s1 - (unsigned char)*s2;
}

/**
 * Compare strings (limited length).
 */
int strncmp(const char *s1, const char *s2, size_t n) {
    if (!s1 || !s2 || n == 0) return 0;

    size_t i;
    for (i = 0; i < n && s1[i] && s2[i]; i++) {
        if (s1[i] != s2[i]) {
            return (unsigned char)s1[i] - (unsigned char)s2[i];
        }
    }

    if (i == n) return 0;
    return (unsigned char)s1[i] - (unsigned char)s2[i];
}

/**
 * Concatenate strings.
 */
char *strcat(char *dest, const char *src) {
    if (!dest || !src) return dest;

    char *ptr = dest + strlen(dest);
    while (*src != '\0') {
        *ptr++ = *src++;
    }
    *ptr = '\0';

    return dest;
}

/**
 * Find character in string.
 */
char *strchr(const char *s, int c) {
    if (!s) return NULL;

    while (*s != '\0') {
        if (*s == (char)c) {
            return (char *)s;
        }
        s++;
    }

    return (*s == (char)c) ? (char *)s : NULL;
}

/**
 * Copy memory.
 */
void *memcpy(void *dest, const void *src, size_t n) {
    if (!dest || !src) return dest;

    unsigned char *d = (unsigned char *)dest;
    const unsigned char *s = (const unsigned char *)src;

    for (size_t i = 0; i < n; i++) {
        d[i] = s[i];
    }

    return dest;
}

/**
 * Set memory to value.
 */
void *memset(void *s, int c, size_t n) {
    if (!s) return s;

    unsigned char *p = (unsigned char *)s;
    for (size_t i = 0; i < n; i++) {
        p[i] = (unsigned char)c;
    }

    return s;
}

/**
 * Compare memory.
 */
int memcmp(const void *s1, const void *s2, size_t n) {
    if (!s1 || !s2) return 0;

    const unsigned char *p1 = (const unsigned char *)s1;
    const unsigned char *p2 = (const unsigned char *)s2;

    for (size_t i = 0; i < n; i++) {
        if (p1[i] != p2[i]) {
            return p1[i] - p2[i];
        }
    }

    return 0;
}

/**
 * Move memory (handles overlapping regions).
 */
void *memmove(void *dest, const void *src, size_t n) {
    if (!dest || !src) return dest;

    unsigned char *d = (unsigned char *)dest;
    const unsigned char *s = (const unsigned char *)src;

    if (d < s) {
        /* Copy forward */
        for (size_t i = 0; i < n; i++) {
            d[i] = s[i];
        }
    } else {
        /* Copy backward */
        for (size_t i = n; i > 0; i--) {
            d[i - 1] = s[i - 1];
        }
    }

    return dest;
}
