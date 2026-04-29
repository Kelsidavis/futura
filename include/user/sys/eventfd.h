// SPDX-License-Identifier: MPL-2.0
#pragma once

/* Suppress wayland_nofortify.h's stub eventfd: */
#ifndef _SYS_EVENTFD_H
#define _SYS_EVENTFD_H
#endif

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define EFD_SEMAPHORE  0x0001
#define EFD_NONBLOCK   0x0800
#define EFD_CLOEXEC    0x80000

typedef uint64_t eventfd_t;

int eventfd(unsigned int initval, int flags);
int eventfd_read(int fd, eventfd_t *value);
int eventfd_write(int fd, eventfd_t value);

#ifdef __cplusplus
}
#endif
