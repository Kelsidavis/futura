// SPDX-License-Identifier: MPL-2.0
#pragma once

#include <stddef.h>
#include <stdbool.h>

enum fut_fd_kind {
    FUT_FD_NONE = 0,
    FUT_FD_UNIX_STREAM = 1,
    FUT_FD_UNIX_LISTENER = 2,
};

struct fut_fd_entry {
    enum fut_fd_kind kind;
    void *payload;
    bool in_use;
};

int fut_fd_alloc(enum fut_fd_kind kind, void *payload);
void fut_fd_update_payload(int fd, void *payload);
struct fut_fd_entry *fut_fd_lookup(int fd);
void fut_fd_release(int fd);

void fut_fd_path_register(int fd, const char *path);
int fut_fd_path_lookup(int fd, char *buf, size_t buf_len);
void fut_fd_path_forget(int fd);
