// SPDX-License-Identifier: MPL-2.0
// Minimal fwrite implementation backed by the POSIX write shim.

#include <errno.h>
#include <stddef.h>

#include <user/stdio.h>
#include <user/sys.h>

size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) {
    if (!ptr || !stream) {
        errno = EINVAL;
        return 0;
    }
    if (size == 0 || nmemb == 0) {
        return 0;
    }

    size_t total = size * nmemb;
    long wrote = sys_write(stream->fd, ptr, (long)total);
    if (wrote < 0) {
        return 0;
    }

    size_t elements = (size_t)wrote / size;
    return elements;
}

__attribute__((weak))
size_t __fwrite_chk(const void *ptr, size_t size, size_t nmemb, FILE *stream, size_t bsz) {
    (void)bsz;
    return fwrite(ptr, size, nmemb, stream);
}
