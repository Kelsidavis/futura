// SPDX-License-Identifier: MPL-2.0
#pragma once

#include <stddef.h>
#include <stdint.h>

/* Try to use system headers if they're available (in hosted or when glibc is used) */
#if __has_include(<time.h>)
#include <time.h>
#endif

#if __has_include_next(<sys/stat.h>)
/* System headers are available - use them */
#include_next <sys/stat.h>
#include_next <sys/types.h>
#else
/* Freestanding environment: define our own stat structure and types */
#include <user/time.h>

/* Define types if not already defined */
#ifndef dev_t
typedef uint64_t dev_t;
#endif
#ifndef ino_t
typedef uint64_t ino_t;
#endif
#ifndef mode_t
typedef uint32_t mode_t;
#endif
#ifndef nlink_t
typedef uint64_t nlink_t;
#endif
#ifndef blksize_t
typedef uint64_t blksize_t;
#endif
#ifndef blkcnt_t
typedef uint64_t blkcnt_t;
#endif
#ifndef off_t
typedef int64_t off_t;
#endif

struct stat {
    dev_t st_dev;
    ino_t st_ino;
    mode_t st_mode;
    nlink_t st_nlink;
    uint32_t st_uid;
    uint32_t st_gid;
    dev_t st_rdev;
    off_t st_size;
    blksize_t st_blksize;
    blkcnt_t st_blocks;
    struct timespec st_atim;
    struct timespec st_mtim;
    struct timespec st_ctim;
};

#endif /* !has_include_next */

/* File type macros - always define these */
#ifndef S_IFSOCK
#define S_IFSOCK 0140000
#endif
#ifndef S_IFREG
#define S_IFREG  0100000
#endif
#ifndef S_IFCHR
#define S_IFCHR  0020000
#endif

/* File permission macros - always define these */
#ifndef S_IRUSR
#define S_IRUSR 0400
#endif
#ifndef S_IWUSR
#define S_IWUSR 0200
#endif
#ifndef S_IRGRP
#define S_IRGRP 0040
#endif
#ifndef S_IROTH
#define S_IROTH 0004
#endif
