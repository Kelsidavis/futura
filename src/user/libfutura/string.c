/* string.c - String Functions for Futura OS Userland
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Basic string manipulation functions (no libc dependency).
 */

#include <stddef.h>
#include <stdint.h>
#include <limits.h>


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

/**
 * Bounded string length — never reads past maxlen bytes.
 */
size_t strnlen(const char *s, size_t maxlen) {
    if (!s) return 0;
    size_t len = 0;
    while (len < maxlen && s[len]) len++;
    return len;
}

/**
 * Find the last occurrence of c in s.  As with strchr, the terminating
 * NUL is considered part of the string, so strrchr(s, 0) returns a
 * pointer to it.
 */
char *strrchr(const char *s, int c) {
    if (!s) return NULL;

    const char *last = NULL;
    do {
        if (*s == (char)c) {
            last = s;
        }
    } while (*s++);

    return (char *)last;
}

/**
 * Append at most n bytes of src to dest, always NUL-terminating.
 */
char *strncat(char *dest, const char *src, size_t n) {
    if (!dest || !src) return dest;

    char *ptr = dest + strlen(dest);
    size_t i = 0;
    while (i < n && src[i] != '\0') {
        ptr[i] = src[i];
        i++;
    }
    ptr[i] = '\0';

    return dest;
}

static int lower_byte(unsigned char c) {
    return (c >= 'A' && c <= 'Z') ? c + ('a' - 'A') : c;
}

/**
 * Case-insensitive string comparison.
 */
int strcasecmp(const char *s1, const char *s2) {
    if (!s1 || !s2) return 0;

    while (*s1 && lower_byte((unsigned char)*s1) == lower_byte((unsigned char)*s2)) {
        s1++;
        s2++;
    }

    return lower_byte((unsigned char)*s1) - lower_byte((unsigned char)*s2);
}

/**
 * Case-insensitive comparison of at most n bytes.
 */
int strncasecmp(const char *s1, const char *s2, size_t n) {
    if (!s1 || !s2 || n == 0) return 0;

    size_t i;
    for (i = 0; i < n; i++) {
        int c1 = lower_byte((unsigned char)s1[i]);
        int c2 = lower_byte((unsigned char)s2[i]);
        if (c1 != c2) return c1 - c2;
        if (c1 == 0) break;
    }
    return 0;
}

/**
 * Duplicate at most n bytes of s into a freshly malloc'd, NUL-terminated
 * buffer.
 */
char *strndup(const char *s, size_t n) {
    if (!s) return NULL;

    size_t len = strnlen(s, n);
    char *copy = malloc(len + 1);
    if (!copy) return NULL;

    for (size_t i = 0; i < len; ++i) copy[i] = s[i];
    copy[len] = '\0';
    return copy;
}

static int in_delim(char c, const char *delim) {
    for (; *delim; ++delim) {
        if (*delim == c) return 1;
    }
    return 0;
}

/**
 * Reentrant tokenizer.  Splits str on any byte in delim, tracking state
 * through *saveptr so the non-reentrant strtok can share the logic.
 */
char *strtok_r(char *str, const char *delim, char **saveptr) {
    if (!delim || !saveptr) return NULL;

    char *s = str ? str : *saveptr;
    if (!s) return NULL;

    /* Skip leading delimiters */
    while (*s && in_delim(*s, delim)) s++;
    if (*s == '\0') {
        *saveptr = s;
        return NULL;
    }

    char *token = s;
    /* Advance to the next delimiter */
    while (*s && !in_delim(*s, delim)) s++;
    if (*s) {
        *s = '\0';
        *saveptr = s + 1;
    } else {
        *saveptr = s;
    }

    return token;
}

/**
 * Non-reentrant tokenizer (uses a hidden static cursor).
 */
char *strtok(char *str, const char *delim) {
    static char *saved;
    return strtok_r(str, delim, &saved);
}

/**
 * Scan the first n bytes of s for c.
 */
void *memchr(const void *s, int c, size_t n) {
    if (!s) return NULL;

    const unsigned char *p = (const unsigned char *)s;
    for (size_t i = 0; i < n; i++) {
        if (p[i] == (unsigned char)c) {
            return (void *)(p + i);
        }
    }
    return NULL;
}

long strtol(const char *nptr, char **endptr, int base) {
    /* Defensive check: reject NULL and corrupted pointers (addresses < 0x10000) */
    if (!nptr || (uintptr_t)nptr < 0x10000) {
        if (endptr) *endptr = (char *)nptr;
        return 0;
    }

    /* Skip whitespace with bounds check to prevent pointer corruption issues */
    int max_whitespace = 1024;  /* Sanity limit */
    while (max_whitespace-- > 0 && (*nptr == ' ' || *nptr == '\t' || *nptr == '\n' ||
           *nptr == '\r' || *nptr == '\f' || *nptr == '\v')) {
        ++nptr;
        /* Re-check pointer validity after each increment */
        if ((uintptr_t)nptr < 0x10000) {
            if (endptr) *endptr = (char *)nptr;
            return 0;
        }
    }

    int sign = 1;
    if (*nptr == '+') {
        ++nptr;
        if ((uintptr_t)nptr < 0x10000) {
            if (endptr) *endptr = (char *)nptr;
            return 0;
        }
    } else if (*nptr == '-') {
        sign = -1;
        ++nptr;
        if ((uintptr_t)nptr < 0x10000) {
            if (endptr) *endptr = (char *)nptr;
            return 0;
        }
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

    /* Use unsigned accumulator for overflow detection */
    unsigned long cutoff;
    int cutlim;
    if (sign == 1) {
        cutoff = (unsigned long)LONG_MAX / (unsigned long)base;
        cutlim = (int)((unsigned long)LONG_MAX % (unsigned long)base);
    } else {
        /* LONG_MIN magnitude as unsigned */
        cutoff = (unsigned long)-(LONG_MIN + 1) / (unsigned long)base;
        cutlim = (int)((unsigned long)-(LONG_MIN + 1) % (unsigned long)base);
        /* Adjust for the +1 used above to avoid UB */
        cutlim += 1;
        if (cutlim >= base) {
            cutoff += 1;
            cutlim -= base;
        }
    }

    unsigned long acc = 0;
    int overflow = 0;
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
        if (acc > cutoff || (acc == cutoff && digit > cutlim)) {
            overflow = 1;
        }
        acc = acc * (unsigned long)base + (unsigned long)digit;
        ++nptr;
    }

    if (endptr) {
        *endptr = (char *)(nptr != start ? nptr : (const char *)start);
    }

    if (overflow) {
        return (sign == 1) ? LONG_MAX : LONG_MIN;
    }
    return sign * (long)acc;
}

long __isoc23_strtol(const char *nptr, char **endptr, int base) {
    return strtol(nptr, endptr, base);
}

/* atoi/atol — thin wrappers around strtol(s, NULL, 10).  libwayland's
 * connection.c uses atoi() to parse @since version markers in protocol
 * messages. */
int atoi(const char *nptr) {
    return (int)strtol(nptr, (char **)0, 10);
}

long atol(const char *nptr) {
    return strtol(nptr, (char **)0, 10);
}

/* Shared unsigned parser for strtoul/strtoull.  Mirrors strtol's
 * defensive pointer checks and base handling, accumulating into an
 * unsigned long long and clamping to `limit` on overflow. */
static unsigned long long parse_unsigned(const char *nptr, char **endptr,
                                         int base, unsigned long long limit,
                                         int *negated) {
    if (negated) *negated = 0;
    if (!nptr || (uintptr_t)nptr < 0x10000) {
        if (endptr) *endptr = (char *)nptr;
        return 0;
    }

    int max_whitespace = 1024;
    while (max_whitespace-- > 0 && (*nptr == ' ' || *nptr == '\t' || *nptr == '\n' ||
           *nptr == '\r' || *nptr == '\f' || *nptr == '\v')) {
        ++nptr;
        if ((uintptr_t)nptr < 0x10000) {
            if (endptr) *endptr = (char *)nptr;
            return 0;
        }
    }

    /* C allows a sign on the unsigned conversions; a '-' negates modulo. */
    if (*nptr == '+') {
        ++nptr;
    } else if (*nptr == '-') {
        if (negated) *negated = 1;
        ++nptr;
    }
    if ((uintptr_t)nptr < 0x10000) {
        if (endptr) *endptr = (char *)nptr;
        return 0;
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

    unsigned long long cutoff = limit / (unsigned long long)base;
    int cutlim = (int)(limit % (unsigned long long)base);

    unsigned long long acc = 0;
    int overflow = 0;
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
        if (acc > cutoff || (acc == cutoff && digit > cutlim)) {
            overflow = 1;
        }
        acc = acc * (unsigned long long)base + (unsigned long long)digit;
        ++nptr;
    }

    if (endptr) {
        *endptr = (char *)(nptr != start ? nptr : (const char *)start);
    }

    if (overflow) {
        return limit;
    }
    return acc;
}

unsigned long strtoul(const char *nptr, char **endptr, int base) {
    int negated;
    unsigned long long v = parse_unsigned(nptr, endptr, base, ULONG_MAX, &negated);
    if (v == ULONG_MAX) return ULONG_MAX;
    return negated ? (unsigned long)(-(unsigned long)v) : (unsigned long)v;
}

unsigned long long strtoull(const char *nptr, char **endptr, int base) {
    int negated;
    unsigned long long v = parse_unsigned(nptr, endptr, base, ULLONG_MAX, &negated);
    if (v == ULLONG_MAX) return ULLONG_MAX;
    return negated ? (unsigned long long)(-v) : v;
}

long long strtoll(const char *nptr, char **endptr, int base) {
    /* Parse the magnitude against the full unsigned range, then apply the
     * sign and clamp into the signed range. */
    int negated;
    unsigned long long v = parse_unsigned(nptr, endptr, base, ULLONG_MAX, &negated);
    if (negated) {
        if (v >= (unsigned long long)LLONG_MAX + 1ull) return LLONG_MIN;
        return -(long long)v;
    }
    if (v > (unsigned long long)LLONG_MAX) return LLONG_MAX;
    return (long long)v;
}

/**
 * Copy memory.
 */
void * __attribute__((noinline,noclone))
memcpy(void *dest, const void *src, size_t n) {
    if (!dest || (uintptr_t)dest < 0x10000) return dest;
    if (!src || (uintptr_t)src < 0x10000) return dest;
    if (n == 0) return dest;

    void *ret = dest;
#if defined(__x86_64__) || defined(__i386__)
    __asm__ volatile (
        "cld\n\t"
        "rep movsb\n\t"
        : "+D"(dest), "+S"(src), "+c"(n)
        :
        : "memory"
    );
#else
    unsigned char *d = (unsigned char *)dest;
    const unsigned char *s = (const unsigned char *)src;
    for (size_t i = 0; i < n; i++)
        d[i] = s[i];
#endif
    return ret;
}

void *__memcpy_chk(void *dest, const void *src, size_t len, size_t destlen) {
    (void)destlen;
    return memcpy(dest, src, len);
}

/**
 * Set memory to value.
 */
void *memset(void *s, int c, size_t n) {
    /* Defensive check: reject NULL or suspiciously low pointer values */
    if (!s || (uintptr_t)s < 0x10000) return s;

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

/* bcmp(3) — byte compare, BSD-origin. libcore's slice-equality lowering
 * on aarch64 emits direct calls to bcmp (Location::eq, StrSearcher,
 * Big32x40 PartialEq), so freestanding Rust user binaries link against
 * this symbol even when their own code never compares slices. Returns
 * 0 iff the buffers are equal — sign of the result is unspecified. */
int bcmp(const void *s1, const void *s2, size_t n) {
    return memcmp(s1, s2, n);
}

/**
 * Move memory (handles overlapping regions).
 */
void *memmove(void *dest, const void *src, size_t n) {
    /* Defensive check: reject NULL or suspiciously low pointer values */
    if (!dest || !src || (uintptr_t)dest < 0x10000 || (uintptr_t)src < 0x10000)
        return dest;

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
