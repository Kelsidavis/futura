// SPDX-License-Identifier: MPL-2.0
#pragma once

#include <stdint.h>

/* File control operations */

#ifndef mode_t
typedef uint32_t mode_t;
#endif

/* File access modes (O_RDONLY, O_WRONLY, O_RDWR are mutually exclusive) */
#define O_RDONLY    00000000
#define O_WRONLY    00000001
#define O_RDWR      00000002
#define O_ACCMODE   00000003

/* File creation and status flags */
#define O_CREAT     00000100    /* Create file if it doesn't exist */
#define O_EXCL      00000200    /* Exclusive use flag */
#define O_NOCTTY    00000400    /* Do not assign controlling terminal */
#define O_TRUNC     00001000    /* Truncate file to zero length */
#define O_APPEND    00002000    /* Append mode */
#define O_NONBLOCK  00004000    /* Non-blocking mode */
#define O_SYNC      00010000    /* Synchronous writes */
#define O_DIRECTORY 00200000    /* Must be a directory */
#define O_NOFOLLOW  00400000    /* Don't follow symbolic links */
#define O_CLOEXEC   02000000    /* Close on exec */

/* fcntl() commands */
#define F_DUPFD     0    /* Duplicate file descriptor */
#define F_GETFD     1    /* Get file descriptor flags */
#define F_SETFD     2    /* Set file descriptor flags */
#define F_GETFL     3    /* Get file status flags */
#define F_SETFL     4    /* Set file status flags */
#define F_GETLK     5    /* Get record locking information */
#define F_SETLK     6    /* Set record locking information */
#define F_SETLKW    7    /* Set record locking information; wait if blocked */
#define F_SETOWN    8    /* Set process or process group to receive SIGIO */
#define F_GETOWN    9    /* Get process or process group to receive SIGIO */

/* File descriptor flags */
#define FD_CLOEXEC  1    /* Close on exec */

/* fcntl() function */
extern int fcntl(int fd, int cmd, ...);
extern int open(const char *pathname, int flags, ...);
extern int creat(const char *pathname, mode_t mode);
