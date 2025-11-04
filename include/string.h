// SPDX-License-Identifier: MPL-2.0
/*
 * Futura OS - Minimal freestanding string operations for kernel.
 *
 * Declares basic memory manipulation functions implemented in kernel/rt/memory.c
 */

#ifndef FUTURA_KERNEL_STRING_H
#define FUTURA_KERNEL_STRING_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

void *memcpy(void *dest, const void *src, size_t n);
void *memmove(void *dest, const void *src, size_t n);
void *memset(void *dest, int value, size_t n);
int memcmp(const void *lhs, const void *rhs, size_t n);

size_t strlen(const char *s);
int strcmp(const char *s1, const char *s2);
char *strstr(const char *haystack, const char *needle);

#ifdef __cplusplus
}
#endif

#endif /* FUTURA_KERNEL_STRING_H */
