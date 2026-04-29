// SPDX-License-Identifier: MPL-2.0
// Minimal process environment support for Futura OS userland.

#pragma once

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

extern char **environ;

/* Heap — provided by libfutura/malloc.c. Declared here so third-party
 * userland code (libffi, libwayland, …) builds against the standard C
 * surface without needing to know about libfutura internals. */
void *malloc(size_t size);
void  free(void *ptr);
void *calloc(size_t nmemb, size_t size);
void *realloc(void *ptr, size_t size);
int   posix_memalign(void **memptr, size_t alignment, size_t size);

/* Process termination — exit() runs atexit handlers, _Exit() does not. */
__attribute__((noreturn)) void exit(int status);
__attribute__((noreturn)) void _Exit(int status);

/* String → number conversion */
long      strtol(const char *nptr, char **endptr, int base);
long long strtoll(const char *nptr, char **endptr, int base);
unsigned long      strtoul(const char *nptr, char **endptr, int base);
unsigned long long strtoull(const char *nptr, char **endptr, int base);
int       atoi(const char *nptr);

char *getenv(const char *name);
char *secure_getenv(const char *name);
char *__secure_getenv(const char *name);
int setenv(const char *name, const char *value, int overwrite);
int putenv(char *string);
int unsetenv(const char *name);
int clearenv(void);

__attribute__((noreturn)) void abort(void);

#ifdef __cplusplus
}
#endif
