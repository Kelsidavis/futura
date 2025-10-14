// SPDX-License-Identifier: MPL-2.0

#include <errno.h>

int lstat64(const char *path, void *buf) {
    (void)path;
    (void)buf;
    errno = ENOENT;
    return -1;
}

int lstat(const char *path, void *buf) __attribute__((weak, alias("lstat64")));
