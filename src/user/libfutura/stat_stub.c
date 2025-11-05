// SPDX-License-Identifier: MPL-2.0

#include <errno.h>

int lstat64(const char *path, void *buf) {
    (void)path;
    (void)buf;
    errno = ENOENT;
    return -1;
}

/* lstat wrapper - aliases not supported on some toolchains */
int lstat(const char *path, void *buf) {
    return lstat64(path, buf);
}
