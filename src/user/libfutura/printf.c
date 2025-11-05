// SPDX-License-Identifier: MPL-2.0

#include <stdarg.h>
#include <stddef.h>
/* stdlib.h not available in freestanding */
/* Forward declarations for malloc/free from malloc.c */
extern void *malloc(size_t size);
extern void free(void *ptr);
extern void *realloc(void *ptr, size_t size);
extern void *calloc(size_t nmemb, size_t size);

#include <string.h>

#include <user/sys.h>
#include <user/stdio.h>

#include "printf_core.h"

static struct fut_FILE stdout_obj = {
    .fd = 1,
    .kind = FUT_FILE_KIND_STD,
    .mem_buf = NULL,
    .mem_size = NULL,
    .mem_data = NULL,
    .mem_capacity = 0,
    .mem_length = 0,
};

static struct fut_FILE stderr_obj = {
    .fd = 2,
    .kind = FUT_FILE_KIND_STD,
    .mem_buf = NULL,
    .mem_size = NULL,
    .mem_data = NULL,
    .mem_capacity = 0,
    .mem_length = 0,
};

FILE *stdout = &stdout_obj;
FILE *stderr = &stderr_obj;

struct stream_sink {
    FILE *stream;
    char buf[128];
    size_t used;
    int error;
};

static int sys_write_all(int fd, const char *buf, size_t len) {
    size_t total = 0;
    while (total < len) {
        long written = sys_write(fd, buf + total, (long)(len - total));
        if (written < 0) {
            return -1;
        }
        total += (size_t)written;
    }
    return 0;
}

static int append_mem(FILE *stream, const char *data, size_t len) {
    if (stream->kind != FUT_FILE_KIND_MEM) {
        return 0;
    }

    if (len == 0) {
        if (stream->mem_buf) {
            *stream->mem_buf = stream->mem_data;
        }
        if (stream->mem_size) {
            *stream->mem_size = stream->mem_length;
        }
        return 0;
    }

    size_t needed = stream->mem_length + len + 1;
    if (needed > stream->mem_capacity) {
        size_t new_cap = stream->mem_capacity ? stream->mem_capacity : 64;
        while (new_cap < needed) {
            new_cap *= 2;
        }
        char *new_data = realloc(stream->mem_data, new_cap);
        if (!new_data) {
            return -1;
        }
        stream->mem_data = new_data;
        stream->mem_capacity = new_cap;
    }

    memcpy(stream->mem_data + stream->mem_length, data, len);
    stream->mem_length += len;
    stream->mem_data[stream->mem_length] = '\0';

    if (stream->mem_buf) {
        *stream->mem_buf = stream->mem_data;
    }
    if (stream->mem_size) {
        *stream->mem_size = stream->mem_length;
    }
    return 0;
}

static int stream_flush(struct stream_sink *sink) {
    if (sink->used == 0) {
        return 0;
    }

    if (sink->stream->kind == FUT_FILE_KIND_STD) {
        if (sys_write_all(sink->stream->fd, sink->buf, sink->used) < 0) {
            sink->error = 1;
            return -1;
        }
    } else if (sink->stream->kind == FUT_FILE_KIND_MEM) {
        if (append_mem(sink->stream, sink->buf, sink->used) < 0) {
            sink->error = 1;
            return -1;
        }
    }

    sink->used = 0;
    return 0;
}

static int stream_putc(void *ctx, char ch) {
    struct stream_sink *sink = (struct stream_sink *)ctx;
    if (sink->error) {
        return -1;
    }
    if (sink->used == sizeof(sink->buf)) {
        if (stream_flush(sink) < 0) {
            return -1;
        }
    }
    sink->buf[sink->used++] = ch;
    return 0;
}

static int fut_vfprintf_stream(FILE *stream, const char *fmt, va_list args) {
    struct stream_sink sink = {
        .stream = stream,
        .buf = {0},
        .used = 0,
        .error = 0,
    };

    va_list copy;
    va_copy(copy, args);
    int result = fut_vprintf_fmt(stream_putc, &sink, fmt, copy);
    va_end(copy);

    if (result < 0 || sink.error) {
        return -1;
    }
    if (stream_flush(&sink) < 0) {
        return -1;
    }
    if (stream->kind == FUT_FILE_KIND_MEM) {
        if (append_mem(stream, "", 0) < 0) {
            return -1;
        }
    }
    return result;
}

int vprintf(const char *fmt, va_list args) {
    return fut_vfprintf_stream(stdout, fmt, args);
}

int __vfprintf_chk(void *stream, int flag, const char *fmt, va_list args) {
    (void)flag;
    FILE *fp = stream ? (FILE *)stream : stdout;
    return vfprintf(fp, fmt, args);
}

int printf(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    int rc = vprintf(fmt, args);
    va_end(args);
    return rc;
}

int vfprintf(FILE *stream, const char *fmt, va_list args) {
    FILE *target = stream ? stream : stdout;
    return fut_vfprintf_stream(target, fmt, args);
}

int fprintf(FILE *stream, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    int rc = vfprintf(stream, fmt, args);
    va_end(args);
    return rc;
}

FILE *open_memstream(char **buf, size_t *size) {
    if (!buf || !size) {
        return NULL;
    }

    FILE *stream = malloc(sizeof(*stream));
    if (!stream) {
        return NULL;
    }

    stream->fd = -1;
    stream->kind = FUT_FILE_KIND_MEM;
    stream->mem_buf = buf;
    stream->mem_size = size;
    stream->mem_capacity = 1;
    stream->mem_length = 0;
    stream->mem_data = malloc(stream->mem_capacity);
    if (!stream->mem_data) {
        free(stream);
        return NULL;
    }
    stream->mem_data[0] = '\0';
    *buf = stream->mem_data;
    *size = 0;
    return stream;
}

int fflush(FILE *stream) {
    if (!stream) {
        return -1;
    }
    if (stream->kind == FUT_FILE_KIND_MEM) {
        return append_mem(stream, "", 0);
    }
    return 0;
}

int fclose(FILE *stream) {
    if (!stream) {
        return -1;
    }
    if (fflush(stream) < 0) {
        return -1;
    }
    if (stream->kind == FUT_FILE_KIND_MEM) {
        free(stream);
        return 0;
    }
    return 0;
}
