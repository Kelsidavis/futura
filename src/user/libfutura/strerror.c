/* strerror.c - Minimal strerror implementation for Futura OS userland
 *
 * Provides freestanding strerror helpers compatible with the subset used
 * by vendored Wayland components.
 */

#include <errno.h>
#include <stddef.h>

#include <user/stdio.h>
#include <user/string.h>

typedef struct {
    int code;
    const char *msg;
} fut_err_map;

static const fut_err_map g_error_table[] = {
    { 0, "Success" },
    { EPERM, "Operation not permitted" },
    { ENOENT, "No such file or directory" },
    { ESRCH, "No such process" },
    { EINTR, "Interrupted system call" },
    { EIO, "I/O error" },
    { ENXIO, "No such device or address" },
    { E2BIG, "Argument list too long" },
#ifdef ENOEXEC
    { ENOEXEC, "Exec format error" },
#endif
    { EBADF, "Bad file descriptor" },
    { ECHILD, "No child processes" },
    { EAGAIN, "Resource temporarily unavailable" },
    { ENOMEM, "Cannot allocate memory" },
    { EACCES, "Permission denied" },
    { EFAULT, "Bad address" },
    { EBUSY, "Device or resource busy" },
    { EEXIST, "File exists" },
#ifdef EXDEV
    { EXDEV, "Invalid cross-device link" },
#endif
    { ENODEV, "No such device" },
    { ENOTDIR, "Not a directory" },
    { EISDIR, "Is a directory" },
    { EINVAL, "Invalid argument" },
    { ENFILE, "File table overflow" },
    { EMFILE, "Too many open files" },
    { ENOTTY, "Inappropriate ioctl for device" },
#ifdef EFBIG
    { EFBIG, "File too large" },
#endif
    { ENOSPC, "No space left on device" },
    { ESPIPE, "Illegal seek" },
    { EROFS, "Read-only file system" },
    { EPIPE, "Broken pipe" },
    { ENAMETOOLONG, "File name too long" },
#ifdef EOPNOTSUPP
    { EOPNOTSUPP, "Operation not supported" },
#endif
#ifdef ECONNRESET
    { ECONNRESET, "Connection reset by peer" },
#endif
#ifdef ENOBUFS
    { ENOBUFS, "No buffer space available" },
#endif
#ifdef EPROTONOSUPPORT
    { EPROTONOSUPPORT, "Protocol not supported" },
#endif
};

static const char *lookup_error(int errnum) {
    for (size_t i = 0; i < (sizeof g_error_table / sizeof g_error_table[0]); ++i) {
        if (g_error_table[i].code == errnum) {
            return g_error_table[i].msg;
        }
    }
    return NULL;
}

#define ERR_RING_SLOTS 4
#define ERR_RING_LEN   64

static char g_err_ring[ERR_RING_SLOTS][ERR_RING_LEN];
static size_t g_err_ring_index;

static void copy_message(char *dst, size_t cap, const char *src) {
    if (!dst || cap == 0) {
        return;
    }
    if (!src) {
        dst[0] = '\0';
        return;
    }
    size_t i = 0;
    while (src[i] && (i + 1) < cap) {
        dst[i] = src[i];
        ++i;
    }
    dst[i] = '\0';
}

char *strerror(int errnum) {
    char *slot = g_err_ring[g_err_ring_index];
    g_err_ring_index = (g_err_ring_index + 1U) % ERR_RING_SLOTS;

    const char *msg = lookup_error(errnum);
    if (msg) {
        copy_message(slot, ERR_RING_LEN, msg);
    } else {
        (void)snprintf(slot, ERR_RING_LEN, "Unknown error %d", errnum);
    }

    return slot;
}

int strerror_r(int errnum, char *buf, size_t buflen) {
    if (!buf || buflen == 0) {
        return EINVAL;
    }

    const char *msg = lookup_error(errnum);
    if (msg) {
        copy_message(buf, buflen, msg);
        return 0;
    }

    if (snprintf(buf, buflen, "Unknown error %d", errnum) < 0) {
        return EINVAL;
    }

    return 0;
}

int __xpg_strerror_r(int errnum, char *buf, size_t buflen) {
    return strerror_r(errnum, buf, buflen);
}

char *__gnu_strerror_r(int errnum, char *buf, size_t buflen) {
    int rc = strerror_r(errnum, buf, buflen);
    if (rc != 0) {
        errno = rc;
        return NULL;
    }
    return buf;
}

char *strerror_l(int errnum, void *locale) {
    (void)locale;
    return strerror(errnum);
}
