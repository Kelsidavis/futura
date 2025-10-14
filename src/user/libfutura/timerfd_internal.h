// SPDX-License-Identifier: MPL-2.0
#pragma once

#include <stddef.h>
#include <stdint.h>

#include <user/futura_posix.h>

int __fut_timerfd_close(int fd);
int __fut_timerfd_is_timer(int fd);
int __fut_timerfd_poll(int fd, uint32_t *events_out);
int __fut_timerfd_next_timeout_ms(void);
uint64_t __fut_timerfd_pending(int fd);
int __fut_timerfd_disarm(int fd);
ssize_t __fut_timerfd_read(int fd, void *buf, size_t count);

