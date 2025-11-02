// SPDX-License-Identifier: MPL-2.0

#pragma once

#include <stdint.h>
#include <shared/fut_timespec.h>
#include <user/sysnums.h>

static inline long sys_call0(long nr) {
    register long rax __asm__("rax") = nr;
    __asm__ volatile("int $0x80"
                     : "+a"(rax)
                     :
                     : "rcx", "r11", "memory");
    return rax;
}

static inline long sys_call1(long nr, long a1) {
    register long rax __asm__("rax") = nr;
    register long rdi __asm__("rdi") = a1;
    __asm__ volatile("int $0x80"
                     : "+a"(rax)
                     : "D"(rdi)
                     : "rcx", "r11", "memory");
    return rax;
}

static inline long sys_call2(long nr, long a1, long a2) {
    register long rax __asm__("rax") = nr;
    register long rdi __asm__("rdi") = a1;
    register long rsi __asm__("rsi") = a2;
    __asm__ volatile("int $0x80"
                     : "+a"(rax)
                     : "D"(rdi), "S"(rsi)
                     : "rcx", "r11", "memory");
    return rax;
}

static inline long sys_call3(long nr, long a1, long a2, long a3) {
    register long rax __asm__("rax") = nr;
    register long rdi __asm__("rdi") = a1;
    register long rsi __asm__("rsi") = a2;
    register long rdx __asm__("rdx") = a3;
    __asm__ volatile("int $0x80"
                     : "+a"(rax)
                     : "D"(rdi), "S"(rsi), "d"(rdx)
                     : "rcx", "r11", "memory");
    return rax;
}

static inline long sys_call4(long nr, long a1, long a2, long a3, long a4) {
    register long rax __asm__("rax") = nr;
    register long rdi __asm__("rdi") = a1;
    register long rsi __asm__("rsi") = a2;
    register long rdx __asm__("rdx") = a3;
    __asm__ volatile(
        "mov %[a4], %%r10\n"
        "int $0x80"
        : "+a"(rax)
        : "D"(rdi), "S"(rsi), "d"(rdx), [a4]"r"(a4)
        : "rcx", "r10", "r11", "memory");
    return rax;
}

static inline long sys_call6(long nr, long a1, long a2, long a3,
                             long a4, long a5, long a6) {
    register long rax __asm__("rax") = nr;
    register long rdi __asm__("rdi") = a1;
    register long rsi __asm__("rsi") = a2;
    register long rdx __asm__("rdx") = a3;
    __asm__ volatile(
        "mov %[a4], %%r10\n"
        "mov %[a5], %%r8\n"
        "mov %[a6], %%r9\n"
        "int $0x80"
        : "+a"(rax)
        : "D"(rdi), "S"(rsi), "d"(rdx),
          [a4]"r"(a4), [a5]"r"(a5), [a6]"r"(a6)
        : "rcx", "r8", "r9", "r10", "r11", "memory");
    return rax;
}

static inline long sys_exit(long code) {
    return sys_call1(SYS_exit, code);
}

static inline long sys_open(const char *path, long flags, long mode) {
    return sys_call3(SYS_open, (long)path, flags, mode);
}

static inline long sys_close(long fd) {
    return sys_call1(SYS_close, fd);
}

static inline long sys_unlink(const char *path) {
    return sys_call1(SYS_unlink, (long)path);
}

static inline long sys_ftruncate(int fd, long length) {
    return sys_call2(SYS_ftruncate, (long)fd, length);
}

static inline long sys_ioctl(long fd, long req, long arg) {
    return sys_call3(SYS_ioctl, fd, req, arg);
}

static inline long sys_mmap(void *addr, long len, long prot, long flags, long fd, long off) {
    return sys_call6(SYS_mmap, (long)addr, len, prot, flags, fd, off);
}

static inline long sys_munmap_call(void *addr, long len) {
    return sys_call2(SYS_munmap, (long)addr, len);
}

static inline long sys_brk_call(void *addr) {
    return sys_call1(SYS_brk, (long)addr);
}

static inline long sys_write(long fd, const void *buf, long len) {
    return sys_call3(SYS_write, fd, (long)buf, len);
}

static inline long sys_read(long fd, void *buf, long len) {
    return sys_call3(SYS_read, fd, (long)buf, len);
}

static inline long sys_echo_call(const char *in, char *out, long len) {
    return sys_call3(SYS_echo, (long)in, (long)out, len);
}

static inline long sys_time_millis_call(void) {
    return sys_call0(SYS_time_millis);
}

static inline long sys_nanosleep_call(const fut_timespec_t *req, fut_timespec_t *rem) {
    return sys_call2(SYS_nanosleep, (long)req, (long)rem);
}

static inline long sys_fork_call(void) {
    return sys_call0(SYS_fork);
}

static inline long sys_execve_call(const char *pathname, char *const *argv, char *const *envp) {
    return sys_call3(SYS_execve, (long)pathname, (long)argv, (long)envp);
}

static inline long sys_wait4_call(long pid, int *wstatus, long options, void *rusage) {
    return sys_call6(SYS_wait4, pid, (long)wstatus, options, (long)rusage, 0, 0);
}

static inline long sys_getcwd_call(char *buf, long size) {
    return sys_call2(SYS_getcwd, (long)buf, size);
}

static inline long sys_chdir_call(const char *path) {
    return sys_call1(SYS_chdir, (long)path);
}

/* epoll() syscall veneers */
static inline long sys_epoll_create_call(int size) {
    return sys_call1(SYS_epoll_create, (long)size);
}

static inline long sys_epoll_ctl_call(int epfd, int op, int fd, void *event) {
    return sys_call4(SYS_epoll_ctl, (long)epfd, (long)op, (long)fd, (long)event);
}

static inline long sys_epoll_wait_call(int epfd, void *events, int maxevents, int timeout) {
    return sys_call4(SYS_epoll_wait, (long)epfd, (long)events, (long)maxevents, (long)timeout);
}

/* madvise() syscall veneer */
static inline long sys_madvise_call(void *addr, size_t length, int advice) {
    return sys_call3(SYS_madvise, (long)addr, (long)length, (long)advice);
}
