// SPDX-License-Identifier: MPL-2.0
#pragma once

#include <stdint.h>

#if defined(__has_include)
#if __has_include(<signal.h>) && !defined(FUTURA_FORCE_MINIMAL_SIGNAL)
#include <signal.h>
#define FUTURA_HAVE_NATIVE_SIGNAL 1
#endif
#endif

#include <user/signal.h>

#ifndef SFD_CLOEXEC
#define SFD_CLOEXEC   0x080000
#endif
#ifndef SFD_NONBLOCK
#define SFD_NONBLOCK  0x0800
#endif

struct signalfd_siginfo {
    uint32_t ssi_signo;
    int32_t ssi_errno;
    int32_t ssi_code;
    uint32_t ssi_pid;
    uint32_t ssi_uid;
    int32_t ssi_fd;
    uint32_t ssi_tid;
    uint32_t ssi_band;
    uint32_t ssi_overrun;
    uint32_t ssi_trapno;
    int32_t ssi_status;
    int32_t ssi_int;
    uint64_t ssi_ptr;
    uint64_t ssi_utime;
    uint64_t ssi_stime;
    uint64_t ssi_addr;
    uint16_t ssi_addr_lsb;
    uint16_t __pad2;
    int32_t ssi_syscall;
    uint64_t ssi_call_addr;
    uint32_t ssi_arch;
    uint8_t __pad[28];
};

int signalfd(int fd, const sigset_t *mask, int flags);
