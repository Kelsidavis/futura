// SPDX-License-Identifier: MPL-2.0

#pragma once

#include <stdarg.h>

typedef int (*fut_putc_fn)(void *ctx, char ch);

int fut_vprintf_fmt(fut_putc_fn putc_cb, void *ctx, const char *fmt, va_list ap);
