// SPDX-License-Identifier: MPL-2.0
/*
 * unistd.h - Standard symbolic constants and types
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Provides POSIX symbolic constants for system calls and
 * commonly used function declarations.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

/* Include system types */
#include <sys/types.h>

/* ============================================================
 *   Access Mode Constants (for access/faccessat)
 * ============================================================ */

#ifndef F_OK
#define F_OK    0   /* Test for existence */
#endif
#ifndef X_OK
#define X_OK    1   /* Test for execute permission */
#endif
#ifndef W_OK
#define W_OK    2   /* Test for write permission */
#endif
#ifndef R_OK
#define R_OK    4   /* Test for read permission */
#endif

/* ============================================================
 *   Standard File Descriptors
 * ============================================================ */

#ifndef STDIN_FILENO
#define STDIN_FILENO    0   /* Standard input */
#endif
#ifndef STDOUT_FILENO
#define STDOUT_FILENO   1   /* Standard output */
#endif
#ifndef STDERR_FILENO
#define STDERR_FILENO   2   /* Standard error */
#endif

/* ============================================================
 *   Seek Constants (for lseek)
 * ============================================================ */

#ifndef SEEK_SET
#define SEEK_SET    0   /* Seek from beginning of file */
#endif
#ifndef SEEK_CUR
#define SEEK_CUR    1   /* Seek from current position */
#endif
#ifndef SEEK_END
#define SEEK_END    2   /* Seek from end of file */
#endif
#ifndef SEEK_DATA
#define SEEK_DATA   3   /* Seek to next data */
#endif
#ifndef SEEK_HOLE
#define SEEK_HOLE   4   /* Seek to next hole */
#endif

/* ============================================================
 *   sysconf Constants (_SC_*)
 * ============================================================ */

#ifndef _SC_ARG_MAX
#define _SC_ARG_MAX             0   /* Maximum length of arguments */
#endif
#ifndef _SC_CHILD_MAX
#define _SC_CHILD_MAX           1   /* Maximum number of child processes */
#endif
#ifndef _SC_CLK_TCK
#define _SC_CLK_TCK             2   /* Clock ticks per second */
#endif
#ifndef _SC_NGROUPS_MAX
#define _SC_NGROUPS_MAX         3   /* Maximum supplementary groups */
#endif
#ifndef _SC_OPEN_MAX
#define _SC_OPEN_MAX            4   /* Maximum open files per process */
#endif
#ifndef _SC_STREAM_MAX
#define _SC_STREAM_MAX          5   /* Maximum open streams per process */
#endif
#ifndef _SC_TZNAME_MAX
#define _SC_TZNAME_MAX          6   /* Maximum timezone name length */
#endif
#ifndef _SC_JOB_CONTROL
#define _SC_JOB_CONTROL         7   /* Job control supported */
#endif
#ifndef _SC_SAVED_IDS
#define _SC_SAVED_IDS           8   /* Saved set-user/group-ID supported */
#endif
#ifndef _SC_VERSION
#define _SC_VERSION             29  /* POSIX version */
#endif
#ifndef _SC_PAGESIZE
#define _SC_PAGESIZE            30  /* Page size */
#endif
#ifndef _SC_PAGE_SIZE
#define _SC_PAGE_SIZE           _SC_PAGESIZE
#endif
#ifndef _SC_NPROCESSORS_CONF
#define _SC_NPROCESSORS_CONF    83  /* Number of configured processors */
#endif
#ifndef _SC_NPROCESSORS_ONLN
#define _SC_NPROCESSORS_ONLN    84  /* Number of online processors */
#endif
#ifndef _SC_PHYS_PAGES
#define _SC_PHYS_PAGES          85  /* Total physical memory pages */
#endif
#ifndef _SC_AVPHYS_PAGES
#define _SC_AVPHYS_PAGES        86  /* Available physical memory pages */
#endif

/* ============================================================
 *   pathconf Constants (_PC_*)
 * ============================================================ */

#ifndef _PC_LINK_MAX
#define _PC_LINK_MAX            0   /* Maximum file link count */
#endif
#ifndef _PC_MAX_CANON
#define _PC_MAX_CANON           1   /* Maximum bytes in terminal input */
#endif
#ifndef _PC_MAX_INPUT
#define _PC_MAX_INPUT           2   /* Maximum bytes in terminal input queue */
#endif
#ifndef _PC_NAME_MAX
#define _PC_NAME_MAX            3   /* Maximum filename length */
#endif
#ifndef _PC_PATH_MAX
#define _PC_PATH_MAX            4   /* Maximum pathname length */
#endif
#ifndef _PC_PIPE_BUF
#define _PC_PIPE_BUF            5   /* Maximum atomic pipe write */
#endif
#ifndef _PC_CHOWN_RESTRICTED
#define _PC_CHOWN_RESTRICTED    6   /* chown restricted */
#endif
#ifndef _PC_NO_TRUNC
#define _PC_NO_TRUNC            7   /* Truncation disabled */
#endif
#ifndef _PC_VDISABLE
#define _PC_VDISABLE            8   /* Terminal disable char */
#endif

/* ============================================================
 *   Lockf Constants
 * ============================================================ */

#ifndef F_ULOCK
#define F_ULOCK     0   /* Unlock locked sections */
#endif
#ifndef F_LOCK
#define F_LOCK      1   /* Lock a section for exclusive use */
#endif
#ifndef F_TLOCK
#define F_TLOCK     2   /* Test and lock (non-blocking) */
#endif
#ifndef F_TEST
#define F_TEST      3   /* Test if locked */
#endif

/* ============================================================
 *   NULL Constant
 * ============================================================ */

#ifndef NULL
#define NULL ((void *)0)
#endif

/* ============================================================
 *   Process/User Functions
 * ============================================================ */

extern pid_t fork(void);
extern pid_t vfork(void);
extern int execve(const char *pathname, char *const argv[], char *const envp[]);
extern int execv(const char *pathname, char *const argv[]);
extern int execvp(const char *file, char *const argv[]);
extern int execl(const char *pathname, const char *arg, ...);
extern int execlp(const char *file, const char *arg, ...);
extern int execle(const char *pathname, const char *arg, ...);
extern void _exit(int status);

extern pid_t getpid(void);
extern pid_t getppid(void);
extern pid_t getpgrp(void);
extern pid_t getpgid(pid_t pid);
extern int setpgid(pid_t pid, pid_t pgid);
extern pid_t setsid(void);
extern pid_t getsid(pid_t pid);

extern uid_t getuid(void);
extern uid_t geteuid(void);
extern gid_t getgid(void);
extern gid_t getegid(void);
extern int setuid(uid_t uid);
extern int seteuid(uid_t uid);
extern int setgid(gid_t gid);
extern int setegid(gid_t gid);
extern int setreuid(uid_t ruid, uid_t euid);
extern int setregid(gid_t rgid, gid_t egid);
extern int getgroups(int size, gid_t list[]);
extern int setgroups(size_t size, const gid_t *list);

/* ============================================================
 *   File Operations
 * ============================================================ */

extern int access(const char *pathname, int mode);
extern int faccessat(int dirfd, const char *pathname, int mode, int flags);
extern int close(int fd);
extern ssize_t read(int fd, void *buf, size_t count);
extern ssize_t write(int fd, const void *buf, size_t count);
extern ssize_t pread(int fd, void *buf, size_t count, off_t offset);
extern ssize_t pwrite(int fd, const void *buf, size_t count, off_t offset);
extern off_t lseek(int fd, off_t offset, int whence);
extern int dup(int oldfd);
extern int dup2(int oldfd, int newfd);
extern int dup3(int oldfd, int newfd, int flags);
extern int pipe(int pipefd[2]);
extern int pipe2(int pipefd[2], int flags);
extern int truncate(const char *path, off_t length);
extern int ftruncate(int fd, off_t length);
extern int fsync(int fd);
extern int fdatasync(int fd);
extern int syncfs(int fd);
extern void sync(void);

/* ============================================================
 *   Directory Operations
 * ============================================================ */

extern int chdir(const char *path);
extern int fchdir(int fd);
extern char *getcwd(char *buf, size_t size);
extern int chroot(const char *path);
extern int rmdir(const char *pathname);

/* ============================================================
 *   File/Link Operations
 * ============================================================ */

extern int link(const char *oldpath, const char *newpath);
extern int linkat(int olddirfd, const char *oldpath,
                  int newdirfd, const char *newpath, int flags);
extern int unlink(const char *pathname);
extern int unlinkat(int dirfd, const char *pathname, int flags);
extern int symlink(const char *target, const char *linkpath);
extern int symlinkat(const char *target, int newdirfd, const char *linkpath);
extern ssize_t readlink(const char *pathname, char *buf, size_t bufsiz);
extern ssize_t readlinkat(int dirfd, const char *pathname, char *buf, size_t bufsiz);

/* ============================================================
 *   File Ownership
 * ============================================================ */

extern int chown(const char *pathname, uid_t owner, gid_t group);
extern int fchown(int fd, uid_t owner, gid_t group);
extern int lchown(const char *pathname, uid_t owner, gid_t group);
extern int fchownat(int dirfd, const char *pathname,
                    uid_t owner, gid_t group, int flags);

/* ============================================================
 *   Hostname Functions
 * ============================================================ */

extern int gethostname(char *name, size_t len);
extern int sethostname(const char *name, size_t len);
extern int getdomainname(char *name, size_t len);
extern int setdomainname(const char *name, size_t len);

/* ============================================================
 *   Sleep/Pause Functions
 * ============================================================ */

extern unsigned int sleep(unsigned int seconds);
extern int usleep(useconds_t usec);
extern int pause(void);
extern unsigned int alarm(unsigned int seconds);

/* ============================================================
 *   Configuration Functions
 * ============================================================ */

extern long sysconf(int name);
extern long pathconf(const char *path, int name);
extern long fpathconf(int fd, int name);

/* ============================================================
 *   Miscellaneous Functions
 * ============================================================ */

extern int isatty(int fd);
extern char *ttyname(int fd);
extern int ttyname_r(int fd, char *buf, size_t buflen);
extern int lockf(int fd, int cmd, off_t len);
extern int nice(int inc);
extern int getopt(int argc, char * const argv[], const char *optstring);

/* getopt global variables */
extern char *optarg;
extern int optind;
extern int opterr;
extern int optopt;

