// SPDX-License-Identifier: MPL-2.0
// Minimal process environment support for Futura OS userland.

#pragma once

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

extern char **environ;

char *getenv(const char *name);
char *secure_getenv(const char *name);
char *__secure_getenv(const char *name);
int setenv(const char *name, const char *value, int overwrite);
int putenv(char *string);
int unsetenv(const char *name);
int clearenv(void);

#ifdef __cplusplus
}
#endif
