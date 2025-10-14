// SPDX-License-Identifier: MPL-2.0
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <user/futura_posix.h>

enum fut_fd_kind;

int __fut_unix_socket_is(int fd);
int __fut_unix_socket_close(int fd);

ssize_t __fut_unix_socket_read(int fd, void *buf, size_t count);
ssize_t __fut_unix_socket_write(int fd, const void *buf, size_t count);

ssize_t __fut_unix_socket_sendmsg(int fd, const struct msghdr *msg, int flags);
ssize_t __fut_unix_socket_recvmsg(int fd, struct msghdr *msg, int flags);

int __fut_unix_socket_poll(int fd, uint32_t requested, uint32_t *ready_out);

void __fut_unix_socket_forget(int fd);
int __fut_unix_socket_retain(int fd);
int __fut_unix_socket_set_flags(int fd, int flags);
