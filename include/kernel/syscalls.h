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

#ifndef _SSIZE_T_DEFINED
#define _SSIZE_T_DEFINED
typedef long ssize_t;
#endif

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
#define SYS_time_millis 400u

ssize_t sys_echo(const char *u_in, char *u_out, size_t n);
long sys_brk(uintptr_t new_break);
long sys_mmap(void *addr, size_t len, int prot, int flags, int fd, long offset);
long sys_munmap(void *addr, size_t len);
long sys_exit(int status);
long sys_waitpid(int pid, int *u_status, int flags);
long sys_nanosleep(const fut_timespec_t *u_req, fut_timespec_t *u_rem);
long sys_getcwd(char *buf, size_t size);
long sys_chdir(const char *path);
long sys_dup2(int oldfd, int newfd);
long sys_epoll_create(int size);
long sys_epoll_ctl(int epfd, int op, int fd, void *event);
long sys_epoll_wait(int epfd, void *events, int maxevents, int timeout);
long sys_time_millis(void);
