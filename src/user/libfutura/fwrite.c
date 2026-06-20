// SPDX-License-Identifier: MPL-2.0
// Minimal fwrite implementation backed by the POSIX write shim.

#include <errno.h>
#include <stddef.h>
#include <stdint.h>

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

    /* Guard against size * nmemb overflow */
    if (nmemb > SIZE_MAX / size) {
        errno = EOVERFLOW;
        return 0;
    }

    size_t total = size * nmemb;

    /* sys_write may satisfy only part of the request, so loop until the
     * whole buffer is written, an error occurs, or the write stalls
     * (zero bytes of progress).  Returning early on a single short write
     * would silently drop the unwritten remainder. */
    const char *buf = (const char *)ptr;
    size_t written = 0;
    while (written < total) {
        long wrote = sys_write(stream->fd, buf + written, (long)(total - written));
        if (wrote <= 0) {
            break;
        }
        written += (size_t)wrote;
    }

    /* Report only the count of fully-written elements, per C semantics. */
    return written / size;
}

__attribute__((weak))
size_t __fwrite_chk(const void *ptr, size_t size, size_t nmemb, FILE *stream, size_t bsz) {
    /* Validate buffer size if _FORTIFY_SOURCE provided one */
    if (bsz != (size_t)-1 && size != 0 && nmemb > bsz / size) {
        /* Buffer overflow detected */
        return 0;
    }
    return fwrite(ptr, size, nmemb, stream);
}
