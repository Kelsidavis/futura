// SPDX-License-Identifier: MPL-2.0

#include <stdarg.h>
#include <stddef.h>

#include <user/stdio.h>

#include "printf_core.h"

struct buf_sink {
    char *buf;
    size_t cap;
    size_t len;
    int error;
};

static int buffer_putc(void *ctx, char ch) {
    struct buf_sink *sink = (struct buf_sink *)ctx;
    if (sink->error) {
        return -1;
    }
    if (sink->cap > 0 && sink->len < sink->cap - 1) {
        sink->buf[sink->len] = ch;
    }
    sink->len++;
    return 0;
}

int vsnprintf(char *buf, size_t size, const char *fmt, va_list args) {
    struct buf_sink sink = {
        .buf = buf,
        .cap = size,
        .len = 0,
        .error = 0,
    };

    va_list copy;
    va_copy(copy, args);
    int result = fut_vprintf_fmt(buffer_putc, &sink, fmt, copy);
    va_end(copy);

    if (result < 0 || sink.error) {
        return -1;
    }

    if (sink.cap > 0) {
        size_t term = (sink.len < sink.cap) ? sink.len : (sink.cap - 1);
        sink.buf[term] = '\0';
    }
    return result;
}

int snprintf(char *buf, size_t size, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    int rc = vsnprintf(buf, size, fmt, args);
    va_end(args);
    return rc;
}

__attribute__((weak)) int __vsnprintf_chk(char *buf, size_t size, int flag, size_t obj_size,
                                          const char *fmt, va_list args) {
    (void)flag;
    (void)obj_size;
    return vsnprintf(buf, size, fmt, args);
}

__attribute__((weak)) int __snprintf_chk(char *buf, size_t size, int flag, size_t obj_size,
                                         const char *fmt, ...) {
    (void)flag;
    (void)obj_size;
    va_list args;
    va_start(args, fmt);
    int rc = vsnprintf(buf, size, fmt, args);
    va_end(args);
    return rc;
}
