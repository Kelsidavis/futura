// SPDX-License-Identifier: MPL-2.0
//
// Minimal string helpers specific to Futura OS userland.

#pragma once

#include <stddef.h>

char *strerror(int errnum);
int strerror_r(int errnum, char *buf, size_t buflen);
int __xpg_strerror_r(int errnum, char *buf, size_t buflen);
char *__gnu_strerror_r(int errnum, char *buf, size_t buflen);
char *strerror_l(int errnum, void *locale);
