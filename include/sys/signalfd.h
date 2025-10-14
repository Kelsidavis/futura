// SPDX-License-Identifier: MPL-2.0
#pragma once

#include <stdint.h>

#include <user/signal.h>

#ifndef __sigset_t_defined
#define __sigset_t_defined 1
typedef unsigned long sigset_t;
#endif

#define SFD_CLOEXEC   0x0001
#define SFD_NONBLOCK  0x0002

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
