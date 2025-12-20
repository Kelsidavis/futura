// SPDX-License-Identifier: MPL-2.0

#include "printf_core.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

static int emit_char(fut_putc_fn cb, void *ctx, char ch, int *total) {
    if (cb(ctx, ch) < 0) {
        return -1;
    }
    (*total)++;
    return 0;
}

static int emit_string(fut_putc_fn cb, void *ctx, const char *str, int *total) {
    for (size_t i = 0; str[i]; ++i) {
        if (emit_char(cb, ctx, str[i], total) < 0) {
            return -1;
        }
    }
    return 0;
}

static int emit_unsigned(fut_putc_fn cb, void *ctx, uint64_t value, unsigned base,
                         bool upper, int *total) {
    char tmp[32];
    size_t pos = 0;
    const char *digits = upper ? "0123456789ABCDEF" : "0123456789abcdef";

    if (value == 0) {
        tmp[pos++] = '0';
    } else {
        while (value > 0 && pos < sizeof(tmp)) {
            tmp[pos++] = digits[value % base];
            value /= base;
        }
    }

    while (pos > 0) {
        if (emit_char(cb, ctx, tmp[--pos], total) < 0) {
            return -1;
        }
    }
    return 0;
}

static int emit_signed(fut_putc_fn cb, void *ctx, int64_t value, int *total) {
    if (value < 0) {
        if (emit_char(cb, ctx, '-', total) < 0) {
            return -1;
        }
        return emit_unsigned(cb, ctx, (uint64_t)(-value), 10, false, total);
    }
    return emit_unsigned(cb, ctx, (uint64_t)value, 10, false, total);
}

int fut_vprintf_fmt(fut_putc_fn cb, void *ctx, const char *fmt, va_list ap) {
    int total = 0;

    while (*fmt) {
        if (*fmt != '%') {
            if (emit_char(cb, ctx, *fmt++, &total) < 0) {
                return -1;
            }
            continue;
        }

        ++fmt; /* Skip '%' */

        /* Parse length modifier */
        bool is_long = false;
        bool is_longlong = false;
        bool is_size = false;
        while (*fmt == 'l' || *fmt == 'z') {
            if (*fmt == 'l') {
                if (is_long) {
                    is_longlong = true;
                }
                is_long = true;
            } else if (*fmt == 'z') {
                is_size = true;
            }
            fmt++;
        }

        char spec = *fmt ? *fmt++ : '\0';
        switch (spec) {
        case '%':
            if (emit_char(cb, ctx, '%', &total) < 0) {
                return -1;
            }
            break;
        case 'c': {
            char ch = (char)va_arg(ap, int);
            if (emit_char(cb, ctx, ch, &total) < 0) {
                return -1;
            }
            break;
        }
        case 's': {
            const char *str = va_arg(ap, const char *);
            if (!str) {
                str = "(null)";
            }
            if (emit_string(cb, ctx, str, &total) < 0) {
                return -1;
            }
            break;
        }
        case 'd':
        case 'i': {
            int64_t val;
            if (is_longlong) {
                val = va_arg(ap, long long);
            } else if (is_long || is_size) {
                val = va_arg(ap, long);
            } else {
                val = va_arg(ap, int);
            }
            if (emit_signed(cb, ctx, val, &total) < 0) {
                return -1;
            }
            break;
        }
        case 'u': {
            uint64_t val;
            if (is_longlong) {
                val = va_arg(ap, unsigned long long);
            } else if (is_long || is_size) {
                val = va_arg(ap, unsigned long);
            } else {
                val = va_arg(ap, unsigned int);
            }
            if (emit_unsigned(cb, ctx, (uint64_t)val, 10, false, &total) < 0) {
                return -1;
            }
            break;
        }
        case 'x': {
            uint64_t val;
            if (is_longlong) {
                val = va_arg(ap, unsigned long long);
            } else if (is_long || is_size) {
                val = va_arg(ap, unsigned long);
            } else {
                val = va_arg(ap, unsigned int);
            }
            if (emit_unsigned(cb, ctx, (uint64_t)val, 16, false, &total) < 0) {
                return -1;
            }
            break;
        }
        case 'X': {
            uint64_t val;
            if (is_longlong) {
                val = va_arg(ap, unsigned long long);
            } else if (is_long || is_size) {
                val = va_arg(ap, unsigned long);
            } else {
                val = va_arg(ap, unsigned int);
            }
            if (emit_unsigned(cb, ctx, (uint64_t)val, 16, true, &total) < 0) {
                return -1;
            }
            break;
        }
        case 'p': {
            uintptr_t val = (uintptr_t)va_arg(ap, void *);
            if (emit_string(cb, ctx, "0x", &total) < 0) {
                return -1;
            }
            if (emit_unsigned(cb, ctx, (uint64_t)val, 16, false, &total) < 0) {
                return -1;
            }
            break;
        }
        default:
            if (emit_char(cb, ctx, '%', &total) < 0 ||
                emit_char(cb, ctx, spec, &total) < 0) {
                return -1;
            }
            break;
        }
    }

    return total;
}
