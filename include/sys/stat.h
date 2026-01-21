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
#include <sys/types.h>

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

/* File type mask and constants */
#ifndef S_IFMT
#define S_IFMT   0170000  /* File type mask */
#endif
#ifndef S_IFSOCK
#define S_IFSOCK 0140000  /* Socket */
#endif
#ifndef S_IFLNK
#define S_IFLNK  0120000  /* Symbolic link */
#endif
#ifndef S_IFREG
#define S_IFREG  0100000  /* Regular file */
#endif
#ifndef S_IFBLK
#define S_IFBLK  0060000  /* Block device */
#endif
#ifndef S_IFDIR
#define S_IFDIR  0040000  /* Directory */
#endif
#ifndef S_IFCHR
#define S_IFCHR  0020000  /* Character device */
#endif
#ifndef S_IFIFO
#define S_IFIFO  0010000  /* FIFO (named pipe) */
#endif

/* File type test macros */
#ifndef S_ISREG
#define S_ISREG(m)  (((m) & S_IFMT) == S_IFREG)
#endif
#ifndef S_ISDIR
#define S_ISDIR(m)  (((m) & S_IFMT) == S_IFDIR)
#endif
#ifndef S_ISCHR
#define S_ISCHR(m)  (((m) & S_IFMT) == S_IFCHR)
#endif
#ifndef S_ISBLK
#define S_ISBLK(m)  (((m) & S_IFMT) == S_IFBLK)
#endif
#ifndef S_ISFIFO
#define S_ISFIFO(m) (((m) & S_IFMT) == S_IFIFO)
#endif
#ifndef S_ISLNK
#define S_ISLNK(m)  (((m) & S_IFMT) == S_IFLNK)
#endif
#ifndef S_ISSOCK
#define S_ISSOCK(m) (((m) & S_IFMT) == S_IFSOCK)
#endif

/* Special permission bits */
#ifndef S_ISUID
#define S_ISUID  04000    /* Set user ID on execution */
#endif
#ifndef S_ISGID
#define S_ISGID  02000    /* Set group ID on execution */
#endif
#ifndef S_ISVTX
#define S_ISVTX  01000    /* Sticky bit */
#endif

/* User (owner) permissions */
#ifndef S_IRWXU
#define S_IRWXU  0700     /* User rwx mask */
#endif
#ifndef S_IRUSR
#define S_IRUSR  0400     /* User read */
#endif
#ifndef S_IWUSR
#define S_IWUSR  0200     /* User write */
#endif
#ifndef S_IXUSR
#define S_IXUSR  0100     /* User execute */
#endif

/* Group permissions */
#ifndef S_IRWXG
#define S_IRWXG  0070     /* Group rwx mask */
#endif
#ifndef S_IRGRP
#define S_IRGRP  0040     /* Group read */
#endif
#ifndef S_IWGRP
#define S_IWGRP  0020     /* Group write */
#endif
#ifndef S_IXGRP
#define S_IXGRP  0010     /* Group execute */
#endif

/* Other (world) permissions */
#ifndef S_IRWXO
#define S_IRWXO  0007     /* Other rwx mask */
#endif
#ifndef S_IROTH
#define S_IROTH  0004     /* Other read */
#endif
#ifndef S_IWOTH
#define S_IWOTH  0002     /* Other write */
#endif
#ifndef S_IXOTH
#define S_IXOTH  0001     /* Other execute */
#endif
