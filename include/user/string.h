// SPDX-License-Identifier: MPL-2.0
//
// Minimal string helpers specific to Futura OS userland.

#pragma once

#include <stddef.h>

/* Memory routines — provided by libfutura/string.c. Standard <string.h>
 * prototypes so third-party userland (libffi, libwayland, …) builds
 * cleanly against the Futura include tree. */
void  *memcpy(void *dest, const void *src, size_t n);
void  *memmove(void *dest, const void *src, size_t n);
void  *memset(void *s, int c, size_t n);
int    memcmp(const void *s1, const void *s2, size_t n);
void  *memchr(const void *s, int c, size_t n);

/* C string routines */
size_t strlen(const char *s);
size_t strnlen(const char *s, size_t maxlen);
int    strcmp(const char *s1, const char *s2);
int    strncmp(const char *s1, const char *s2, size_t n);
int    strcasecmp(const char *s1, const char *s2);
int    strncasecmp(const char *s1, const char *s2, size_t n);
char  *strcpy(char *dest, const char *src);
char  *strncpy(char *dest, const char *src, size_t n);
char  *strcat(char *dest, const char *src);
char  *strncat(char *dest, const char *src, size_t n);
char  *strchr(const char *s, int c);
char  *strrchr(const char *s, int c);
char  *strstr(const char *haystack, const char *needle);
char  *strdup(const char *s);
char  *strndup(const char *s, size_t n);
char  *strtok(char *str, const char *delim);
char  *strtok_r(char *str, const char *delim, char **saveptr);

char *strerror(int errnum);
int strerror_r(int errnum, char *buf, size_t buflen);
int __xpg_strerror_r(int errnum, char *buf, size_t buflen);
char *__gnu_strerror_r(int errnum, char *buf, size_t buflen);
char *strerror_l(int errnum, void *locale);
