// SPDX-License-Identifier: MPL-2.0

#include <errno.h>
#include <string.h>

#include <sys/stat.h>

#include "fd.h"
#include "memory_map.h"

#define FUT_DEFAULT_MODE (S_IRUSR | S_IWUSR)
#define FUT_DEFAULT_BLKSIZE 4096ULL

__attribute__((unused))
static void fut_stat_reset(struct stat *st) {
    memset(st, 0, sizeof(*st));
    st->st_blksize = FUT_DEFAULT_BLKSIZE;
    st->st_nlink = 1;
    st->st_mode = S_IFREG | FUT_DEFAULT_MODE;
}

__attribute__((unused))
static void fut_stat_set_size(struct stat *st, size_t len) {
    st->st_size = (off_t)len;
    st->st_blocks = (blkcnt_t)((len + 511ULL) / 512ULL);
}

__attribute__((nonnull(2), leaf, nothrow))
int fstat(int fd, struct stat *st) {
    fut_stat_reset(st);
    st->st_ino = (ino_t)(unsigned int)fd;

    struct fut_fd_entry *entry = fut_fd_lookup(fd);
    if (entry) {
        switch (entry->kind) {
        case FUT_FD_UNIX_STREAM:
        case FUT_FD_UNIX_LISTENER:
            st->st_mode = S_IFSOCK | FUT_DEFAULT_MODE | S_IRGRP | S_IROTH;
            return 0;
        case FUT_FD_SIGNALFD:
            st->st_mode = S_IFCHR | FUT_DEFAULT_MODE;
            return 0;
        default:
            break;
        }
    }

    struct fut_maprec rec;
    if (fut_maprec_find_by_fd(fd, &rec) == 0) {
        fut_stat_set_size(st, rec.length);
        st->st_mode = S_IFREG | FUT_DEFAULT_MODE;
        return 0;
    }

    /* Unknown descriptor kind: report a tiny regular file */
    fut_stat_set_size(st, 0);
    return 0;
}

__attribute__((weak, alias("fstat"), nonnull(2), leaf, nothrow))
int fstat64(int fd, struct stat *st);

int __fxstat64(int ver, int fd, struct stat *st) {
    (void)ver;
    return fstat(fd, st);
}

int __fstat64_time64(int fd, struct stat *st) {
    return fstat(fd, st);
}
