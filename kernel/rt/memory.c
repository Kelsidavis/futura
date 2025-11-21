// SPDX-License-Identifier: MPL-2.0
/*
 * Futura OS - Minimal freestanding memory primitives.
 *
 * Provide basic memcpy/memmove/memset/memcmp implementations for the kernel
 * so that no libc symbols are required during freestanding links.
 */

#include <stddef.h>

void *memcpy(void *dest, const void *src, size_t n)
{
    unsigned char *d = (unsigned char *)dest;
    const unsigned char *s = (const unsigned char *)src;

    for (size_t i = 0; i < n; ++i) {
        d[i] = s[i];
    }
    return dest;
}

void *memmove(void *dest, const void *src, size_t n)
{
    unsigned char *d = (unsigned char *)dest;
    const unsigned char *s = (const unsigned char *)src;

    if (d == s || n == 0) {
        return dest;
    }

    if (d < s) {
        for (size_t i = 0; i < n; ++i) {
            d[i] = s[i];
        }
    } else {
        for (size_t i = n; i != 0; --i) {
            d[i - 1] = s[i - 1];
        }
    }
    return dest;
}

void *memset(void *dest, int value, size_t n)
{
    unsigned char *d = (unsigned char *)dest;
    unsigned char v = (unsigned char)value;

    for (size_t i = 0; i < n; ++i) {
        d[i] = v;
    }
    return dest;
}

int memcmp(const void *lhs, const void *rhs, size_t n)
{
    const unsigned char *a = (const unsigned char *)lhs;
    const unsigned char *b = (const unsigned char *)rhs;

    for (size_t i = 0; i < n; ++i) {
        if (a[i] != b[i]) {
            return (int)a[i] - (int)b[i];
        }
    }
    return 0;
}

size_t strlen(const char *s)
{
    size_t len = 0;
    while (s[len] != '\0') {
        ++len;
    }
    return len;
}

int strcmp(const char *s1, const char *s2)
{
    while (*s1 != '\0' && *s1 == *s2) {
        s1++;
        s2++;
    }
    return (int)(unsigned char)*s1 - (int)(unsigned char)*s2;
}

int strncmp(const char *s1, const char *s2, size_t n)
{
    if (n == 0) {
        return 0;
    }
    while (n > 0 && *s1 != '\0' && *s1 == *s2) {
        s1++;
        s2++;
        n--;
    }
    if (n == 0) {
        return 0;
    }
    return (int)(unsigned char)*s1 - (int)(unsigned char)*s2;
}

char *strstr(const char *haystack, const char *needle)
{
    if (*needle == '\0') {
        return (char *)haystack;
    }

    for (const char *h = haystack; *h != '\0'; h++) {
        const char *h1 = h;
        const char *n1 = needle;

        while (*h1 != '\0' && *n1 != '\0' && *h1 == *n1) {
            h1++;
            n1++;
        }

        if (*n1 == '\0') {
            return (char *)h;
        }
    }

    return NULL;
}

char *strrchr(const char *s, int c)
{
    const char *last = NULL;
    char ch = (char)c;

    while (*s != '\0') {
        if (*s == ch) {
            last = s;
        }
        s++;
    }

    if (ch == '\0') {
        return (char *)s;
    }

    return (char *)last;
}

char *strdup(const char *s)
{
    /* Not implemented in kernel - requires dynamic allocation */
    (void)s;
    return NULL;
}
