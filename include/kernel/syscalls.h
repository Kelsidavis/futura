// SPDX-License-Identifier: MPL-2.0
/*
 * syscalls.h - Kernel syscall prototypes (Phase 1 scaffolding)
 *
 * Provides the minimal declarations needed to exercise newly added
 * uaccess helpers via a simple echo syscall.  Future work will expand
 * this table as the userland ABI stabilises.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>
#include <shared/fut_timespec.h>
#include <shared/fut_timeval.h>

/* Forward declarations */
struct fut_stat;
struct pollfd;
struct rlimit;
struct rusage;
struct tms;
struct iovec;

#ifndef _SSIZE_T_DEFINED
#define _SSIZE_T_DEFINED
typedef long ssize_t;
#endif

#define SYS_access 21u
#define SYS_echo 42u
#define SYS_mmap 9u
#define SYS_munmap 11u
#define SYS_brk 12u
#define SYS_exit 60u
#define SYS_waitpid 61u
#define SYS_nanosleep 35u
#define SYS_getcwd 79u
#define SYS_chdir 80u
#define SYS_epoll_create 228u
#define SYS_epoll_ctl 229u
#define SYS_epoll_wait 230u
#define SYS_madvise 231u
#define SYS_getuid 102u
#define SYS_geteuid 107u
#define SYS_getgid 104u
#define SYS_getegid 108u
#define SYS_setuid 105u
#define SYS_seteuid 109u
#define SYS_rename 82u
#define SYS_chmod 90u
#define SYS_setgid 106u
#define SYS_setegid 110u
#define SYS_getpgrp 111u
#define SYS_setsid 112u
#define SYS_getppid 113u
#define SYS_getsid 124u
/* Note: SYS_setpgid/SYS_setpgrp would be 109 but conflicts with SYS_seteuid */
#define SYS_time_millis 400u

ssize_t sys_echo(const char *u_in, char *u_out, size_t n);
long sys_brk(uintptr_t new_break);
long sys_mmap(void *addr, size_t len, int prot, int flags, int fd, long offset);
long sys_munmap(void *addr, size_t len);
long sys_mprotect(void *addr, size_t len, int prot);
long sys_mremap(void *old_address, size_t old_size, size_t new_size, int flags, void *new_address);
long sys_msync(void *addr, size_t length, int flags);
long sys_mincore(void *addr, size_t length, unsigned char *vec);
long sys_exit(int status);
long sys_waitpid(int pid, int *u_status, int flags);
long sys_nanosleep(const fut_timespec_t *u_req, fut_timespec_t *u_rem);
long sys_getcwd(char *buf, size_t size);
long sys_chdir(const char *path);
long sys_dup(int oldfd);
long sys_dup2(int oldfd, int newfd);
long sys_poll(struct pollfd *fds, unsigned long nfds, int timeout);
long sys_epoll_create(int size);
long sys_epoll_ctl(int epfd, int op, int fd, void *event);
long sys_epoll_wait(int epfd, void *events, int maxevents, int timeout);
long sys_madvise(void *addr, size_t length, int advice);
long sys_getuid(void);
long sys_geteuid(void);
long sys_getgid(void);
long sys_getegid(void);
long sys_setuid(uint32_t uid);
long sys_seteuid(uint32_t euid);
long sys_setgid(uint32_t gid);
long sys_setegid(uint32_t egid);
long sys_getpid(void);
long sys_gettid(void);
long sys_getppid(void);
long sys_getpgrp(void);
long sys_getsid(uint64_t pid);
long sys_setsid(void);
long sys_getrlimit(int resource, struct rlimit *rlim);
long sys_setrlimit(int resource, const struct rlimit *rlim);
long sys_umask(uint32_t mask);
long sys_uname(void *buf);
long sys_rename(const char *oldpath, const char *newpath);
long sys_stat(const char *path, struct fut_stat *statbuf);
long sys_fstat(int fd, struct fut_stat *statbuf);
long sys_lstat(const char *path, struct fut_stat *statbuf);
long sys_chmod(const char *path, uint32_t mode);
long sys_fchmod(int fd, uint32_t mode);
long sys_chown(const char *path, uint32_t uid, uint32_t gid);
long sys_fchown(int fd, uint32_t uid, uint32_t gid);
long sys_truncate(const char *path, uint64_t length);
long sys_ftruncate(int fd, uint64_t length);
long sys_fcntl(int fd, int cmd, uint64_t arg);
long sys_flock(int fd, int operation);
long sys_fsync(int fd);
long sys_fdatasync(int fd);
long sys_access(const char *path, int mode);
long sys_mkdir(const char *path, uint32_t mode);
long sys_rmdir(const char *path);
long sys_unlink(const char *path);
long sys_link(const char *oldpath, const char *newpath);
long sys_symlink(const char *target, const char *linkpath);
long sys_readlink(const char *path, char *buf, size_t bufsiz);
long sys_getdents64(unsigned int fd, void *dirp, unsigned int count);
long sys_pread64(unsigned int fd, void *buf, size_t count, int64_t offset);
long sys_pwrite64(unsigned int fd, const void *buf, size_t count, int64_t offset);
ssize_t sys_readv(int fd, const struct iovec *iov, int iovcnt);
ssize_t sys_writev(int fd, const struct iovec *iov, int iovcnt);
int64_t sys_lseek(int fd, int64_t offset, int whence);
long sys_gettimeofday(fut_timeval_t *tv, void *tz);
long sys_time(uint64_t *tloc);
long sys_clock_gettime(int clock_id, fut_timespec_t *tp);
/* Note: sys_setpgrp and sys_setpgid are implemented but not exposed via syscall
   (syscall numbers conflict with seteuid from Priority #14) */
long sys_time_millis(void);
long sys_sched_yield(void);
long sys_getpriority(int which, int who);
long sys_setpriority(int which, int who, int prio);
long sys_alarm(unsigned int seconds);
long sys_pause(void);
long sys_getrusage(int who, struct rusage *usage);
long sys_times(struct tms *buf);
