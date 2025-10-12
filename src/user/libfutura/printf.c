// SPDX-License-Identifier: MPL-2.0

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include <user/sys.h>
#include <user/stdio.h>

static int sys_write_all(int fd, const char *buf, size_t len) {
    size_t total = 0;
    while (total < len) {
        long written = sys_write(fd, buf + total, (long)(len - total));
        if (written < 0) {
            return -1;
        }
        total += (size_t)written;
    }
    return (int)total;
}

static int emit_buffer(char *buf, size_t *used, int fd) {
    if (*used == 0) {
        return 0;
    }
    int rc = sys_write_all(fd, buf, *used);
    *used = 0;
    return rc;
}

static int emit_string(const char *str, int fd) {
    size_t len = 0;
    while (str[len]) {
        ++len;
    }
    return sys_write_all(fd, str, len);
}

static int emit_unsigned(uint64_t value, unsigned base, bool upper, int fd) {
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

    char out[32];
    size_t out_pos = 0;
    while (pos > 0) {
        out[out_pos++] = tmp[--pos];
    }
    return sys_write_all(fd, out, out_pos);
}

static int emit_signed(int64_t value, int fd) {
    if (value < 0) {
        char minus = '-';
        if (sys_write_all(fd, &minus, 1) < 0) {
            return -1;
        }
        int rc = emit_unsigned((uint64_t)(-value), 10, false, fd);
        return (rc < 0) ? -1 : rc + 1;
    }
    return emit_unsigned((uint64_t)value, 10, false, fd);
}

int vprintf(const char *fmt, va_list args) {
    char buffer[128];
    size_t used = 0;
    int total = 0;

    while (*fmt) {
        if (*fmt != '%') {
            if (used == sizeof(buffer)) {
                int rc = emit_buffer(buffer, &used, 1);
                if (rc < 0) {
                    return -1;
                }
                total += rc;
            }
            buffer[used++] = *fmt++;
            continue;
        }

        int flushed = emit_buffer(buffer, &used, 1);
        if (flushed < 0) {
            return -1;
        }
        total += flushed;

        ++fmt; /* skip '%' */
        char spec = *fmt++;
        switch (spec) {
        case '%': {
            char c = '%';
            if (sys_write_all(1, &c, 1) < 0) {
                return -1;
            }
            total += 1;
            break;
        }
        case 'c': {
            char c = (char)va_arg(args, int);
            if (sys_write_all(1, &c, 1) < 0) {
                return -1;
            }
            total += 1;
            break;
        }
        case 's': {
            const char *str = va_arg(args, const char *);
            if (!str) {
                str = "(null)";
            }
            int rc = emit_string(str, 1);
            if (rc < 0) {
                return -1;
            }
            total += rc;
            break;
        }
        case 'd':
        case 'i': {
            int64_t val = va_arg(args, int);
            int rc = emit_signed(val, 1);
            if (rc < 0) {
                return -1;
            }
            total += rc;
            break;
        }
        case 'u': {
            uint64_t val = va_arg(args, unsigned int);
            int rc = emit_unsigned(val, 10, false, 1);
            if (rc < 0) {
                return -1;
            }
            total += rc;
            break;
        }
        case 'x': {
            uint64_t val = va_arg(args, unsigned int);
            int rc = emit_unsigned(val, 16, false, 1);
            if (rc < 0) {
                return -1;
            }
            total += rc;
            break;
        }
        case 'p': {
            uint64_t val = (uint64_t)(uintptr_t)va_arg(args, void *);
            if (sys_write_all(1, "0x", 2) < 0) {
                return -1;
            }
            total += 2;
            int rc = emit_unsigned(val, 16, false, 1);
            if (rc < 0) {
                return -1;
            }
            total += rc;
            break;
        }
        default: {
            char percent = '%';
            char c = spec;
            if (sys_write_all(1, &percent, 1) < 0 || sys_write_all(1, &c, 1) < 0) {
                return -1;
            }
            total += 2;
            break;
        }
        }
    }

    if (used > 0) {
        int rc = emit_buffer(buffer, &used, 1);
        if (rc < 0) {
            return -1;
        }
        total += rc;
    }

    return total;
}

int printf(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    int rc = vprintf(fmt, args);
    va_end(args);
    return rc;
}
