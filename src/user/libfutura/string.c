/* string.c - String Functions for Futura OS Userland
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Basic string manipulation functions (no libc dependency).
 */

#include <stddef.h>
#include <stdint.h>


extern void *malloc(size_t);

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

char *strdup(const char *s) {
    if (!s) {
        return NULL;
    }

    size_t len = strlen(s) + 1;
    char *copy = malloc(len);
    if (!copy) {
        return NULL;
    }

    for (size_t i = 0; i < len; ++i) {
        copy[i] = s[i];
    }
    return copy;
}

char *strstr(const char *haystack, const char *needle) {
    if (!haystack || !needle) return NULL;
    if (*needle == '\0') return (char *)haystack;

    size_t needle_len = strlen(needle);
    for (const char *p = haystack; *p; ++p) {
        if (*p == *needle && strncmp(p, needle, needle_len) == 0) {
            return (char *)p;
        }
    }
    return NULL;
}

long strtol(const char *nptr, char **endptr, int base) {
    if (!nptr) {
        if (endptr) *endptr = (char *)nptr;
        return 0;
    }

    while (*nptr == ' ' || *nptr == '\t' || *nptr == '\n' ||
           *nptr == '\r' || *nptr == '\f' || *nptr == '\v') {
        ++nptr;
    }

    int sign = 1;
    if (*nptr == '+') {
        ++nptr;
    } else if (*nptr == '-') {
        sign = -1;
        ++nptr;
    }

    if (base == 0) {
        if (*nptr == '0') {
            if (nptr[1] == 'x' || nptr[1] == 'X') {
                base = 16;
                nptr += 2;
            } else {
                base = 8;
                ++nptr;
            }
        } else {
            base = 10;
        }
    } else if (base == 16 && *nptr == '0' && (nptr[1] == 'x' || nptr[1] == 'X')) {
        nptr += 2;
    }

    long result = 0;
    const char *start = nptr;
    while (*nptr) {
        int digit;
        if (*nptr >= '0' && *nptr <= '9') {
            digit = *nptr - '0';
        } else if (*nptr >= 'a' && *nptr <= 'z') {
            digit = *nptr - 'a' + 10;
        } else if (*nptr >= 'A' && *nptr <= 'Z') {
            digit = *nptr - 'A' + 10;
        } else {
            break;
        }
        if (digit >= base) {
            break;
        }
        result = result * base + digit;
        ++nptr;
    }

    if (endptr) {
        *endptr = (char *)(nptr != start ? nptr : (const char *)start);
    }
    return sign * result;
}

long __isoc23_strtol(const char *nptr, char **endptr, int base) {
    return strtol(nptr, endptr, base);
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

void *__memcpy_chk(void *dest, const void *src, size_t len, size_t destlen) {
    (void)destlen;
    return memcpy(dest, src, len);
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
