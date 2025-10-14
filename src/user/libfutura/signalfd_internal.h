// SPDX-License-Identifier: MPL-2.0
#pragma once

#include <stdint.h>
#include <user/futura_posix.h>
#include <sys/signalfd.h>

int __fut_signalfd_close(int fd);
int __fut_signalfd_is(int fd);
int __fut_signalfd_poll(int fd, uint32_t *events_out);
ssize_t __fut_signalfd_read(int fd, void *buf, size_t count);
int __fut_signalfd_update(int fd, const sigset_t *mask, int flags);
