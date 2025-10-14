// SPDX-License-Identifier: MPL-2.0
// Minimal fputs/puts implementation built on the printf core.

#include <errno.h>
#include <stddef.h>

#include <user/stdio.h>

int fputs(const char *s, FILE *stream) {
    if (!s) {
        errno = EINVAL;
        return EOF;
    }

    FILE *target = stream ? stream : stdout;
    int written = fprintf(target, "%s", s);
    return (written < 0) ? EOF : written;
}

int puts(const char *s) {
    if (!s) {
        errno = EINVAL;
        return EOF;
    }

    int written = fprintf(stdout, "%s\n", s);
    return (written < 0) ? EOF : written;
}

int __fputs_chk(const char *s, FILE *stream, size_t bsz) {
    (void)bsz;
    return fputs(s, stream);
}
