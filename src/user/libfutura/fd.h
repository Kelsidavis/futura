// SPDX-License-Identifier: MPL-2.0
#pragma once

#include <stddef.h>
#include <stdbool.h>

enum fut_fd_kind {
    FUT_FD_NONE = 0,
    FUT_FD_UNIX_STREAM = 1,
    FUT_FD_UNIX_LISTENER = 2,
    FUT_FD_SIGNALFD = 3,
    FUT_FD_EVENTFD = 4,
};

struct fut_fd_entry {
    enum fut_fd_kind kind;
    void *payload;
    bool in_use;
    int flags;
    int cloexec;
};

int fut_fd_alloc(enum fut_fd_kind kind, void *payload);
int fut_fd_alloc_at_or_above(enum fut_fd_kind kind, void *payload, int min_fd,
                             int inherit_flags, int cloexec);
void fut_fd_update_payload(int fd, void *payload);
struct fut_fd_entry *fut_fd_lookup(int fd);
void fut_fd_release(int fd);

void fut_fd_path_register(int fd, const char *path);
int fut_fd_path_lookup(int fd, char *buf, size_t buf_len);
void fut_fd_path_forget(int fd);

int fd_dup(int fd, int min_new_fd, int cloexec);
int fd_get_flags(int fd, int *out_flags);
int fd_set_flags(int fd, int new_flags);
int fd_get_cloexec(int fd);
int fd_set_cloexec(int fd, int on);
