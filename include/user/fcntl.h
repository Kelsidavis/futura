// SPDX-License-Identifier: MPL-2.0
#pragma once

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* open() flags — Linux-compatible bit layout, matches the kernel side. */
#define O_RDONLY       0x0000
#define O_WRONLY       0x0001
#define O_RDWR         0x0002
#define O_ACCMODE      0x0003

#define O_CREAT        0x0040
#define O_EXCL         0x0080
#define O_NOCTTY       0x0100
#define O_TRUNC        0x0200
#define O_APPEND       0x0400
#define O_NONBLOCK     0x0800
#define O_DSYNC        0x1000
#define O_DIRECT       0x4000
#define O_LARGEFILE    0x8000
#define O_DIRECTORY    0x10000
#define O_NOFOLLOW     0x20000
#define O_CLOEXEC      0x80000
#define O_PATH         0x200000
#define O_TMPFILE      (0x400000 | O_DIRECTORY)

#define AT_FDCWD                -100
#define AT_SYMLINK_NOFOLLOW     0x100
#define AT_REMOVEDIR            0x200
#define AT_SYMLINK_FOLLOW       0x400
#define AT_NO_AUTOMOUNT         0x800
#define AT_EMPTY_PATH           0x1000

/* fcntl() commands */
#define F_DUPFD         0
#define F_GETFD         1
#define F_SETFD         2
#define F_GETFL         3
#define F_SETFL         4
#define F_GETLK         5
#define F_SETLK         6
#define F_SETLKW        7
#define F_DUPFD_CLOEXEC 1030

/* fd flags */
#define FD_CLOEXEC      1

int open(const char *pathname, int flags, ...);
int openat(int dirfd, const char *pathname, int flags, ...);
int creat(const char *pathname, mode_t mode);
int fcntl(int fd, int cmd, ...);

#ifdef __cplusplus
}
#endif
