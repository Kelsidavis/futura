// SPDX-License-Identifier: MPL-2.0
#pragma once

#include <stddef.h>
#include <stdint.h>

#if defined(__STDC_HOSTED__) && __STDC_HOSTED__ == 1
#include_next <sys/stat.h>
#else
#include <user/time.h>

#ifndef FUT_DEV_T_DEFINED
#define FUT_DEV_T_DEFINED 1
typedef uint64_t dev_t;
#endif
#ifndef FUT_INO_T_DEFINED
#define FUT_INO_T_DEFINED 1
typedef uint64_t ino_t;
#endif
#ifndef FUT_MODE_T_DEFINED
#define FUT_MODE_T_DEFINED 1
typedef uint32_t mode_t;
#endif
#ifndef FUT_NLINK_T_DEFINED
#define FUT_NLINK_T_DEFINED 1
typedef uint64_t nlink_t;
#endif
#ifndef FUT_BLKSIZE_T_DEFINED
#define FUT_BLKSIZE_T_DEFINED 1
typedef uint64_t blksize_t;
#endif
#ifndef FUT_BLKCNT_T_DEFINED
#define FUT_BLKCNT_T_DEFINED 1
typedef uint64_t blkcnt_t;
#endif
#ifndef FUT_OFF_T_DEFINED
#define FUT_OFF_T_DEFINED 1
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

#ifndef S_IFSOCK
#define S_IFSOCK 0140000
#endif
#ifndef S_IFREG
#define S_IFREG  0100000
#endif
#ifndef S_IFCHR
#define S_IFCHR  0020000
#endif

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

#endif /* __STDC_HOSTED__ */
