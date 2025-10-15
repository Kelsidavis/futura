// SPDX-License-Identifier: MPL-2.0

#pragma once

#include <stdarg.h>
#include <stddef.h>

typedef enum {
    FUT_FILE_KIND_STD = 0,
    FUT_FILE_KIND_MEM = 1,
} fut_file_kind;

typedef struct fut_FILE {
    int fd;
    fut_file_kind kind;
    char **mem_buf;
    size_t *mem_size;
    char *mem_data;
    size_t mem_capacity;
    size_t mem_length;
} FILE;

extern FILE *stdout;
extern FILE *stderr;

#ifndef EOF
#define EOF (-1)
#endif

int printf(const char *fmt, ...);
int vprintf(const char *fmt, va_list args);
int fprintf(FILE *stream, const char *fmt, ...);
int vfprintf(FILE *stream, const char *fmt, va_list args);
int __vfprintf_chk(void *stream, int flag, const char *fmt, va_list args);
int snprintf(char *buf, size_t size, const char *fmt, ...);
int vsnprintf(char *buf, size_t size, const char *fmt, va_list args);
FILE *open_memstream(char **buf, size_t *size);
int fflush(FILE *stream);
int fclose(FILE *stream);
int fputs(const char *s, FILE *stream);
int puts(const char *s);
size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream);
