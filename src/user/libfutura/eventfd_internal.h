// SPDX-License-Identifier: MPL-2.0
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <user/futura_posix.h>

int __fut_eventfd_is(int fd);
ssize_t __fut_eventfd_read(int fd, void *buf, size_t count);
ssize_t __fut_eventfd_write(int fd, const void *buf, size_t count);
int __fut_eventfd_close(int fd);
int __fut_eventfd_poll(int fd, uint32_t requested, uint32_t *ready_out);
int __fut_eventfd_set_flags(int fd, int flags);
int __fut_eventfd_retain(int fd);
