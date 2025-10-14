// SPDX-License-Identifier: MPL-2.0

#include "fd.h"

#include <user/futura_posix.h>
#include <user/libfutura.h>

#define FUT_FD_TABLE_SIZE 256
#define FUT_FD_BASE       128

static struct fut_fd_entry fd_table[FUT_FD_TABLE_SIZE];
static int next_fd_hint = 0;

int fut_fd_alloc(enum fut_fd_kind kind, void *payload) {
    for (int attempt = 0; attempt < FUT_FD_TABLE_SIZE; ++attempt) {
        int idx = (next_fd_hint + attempt) % FUT_FD_TABLE_SIZE;
        if (!fd_table[idx].in_use) {
            fd_table[idx].in_use = true;
            fd_table[idx].kind = kind;
            fd_table[idx].payload = payload;
            next_fd_hint = (idx + 1) % FUT_FD_TABLE_SIZE;
            return FUT_FD_BASE + idx;
        }
    }
    return -1;
}

struct fut_fd_entry *fut_fd_lookup(int fd) {
    int idx = fd - FUT_FD_BASE;
    if (idx < 0 || idx >= FUT_FD_TABLE_SIZE) {
        return NULL;
    }
    if (!fd_table[idx].in_use) {
        return NULL;
    }
    return &fd_table[idx];
}

void fut_fd_update_payload(int fd, void *payload) {
    struct fut_fd_entry *entry = fut_fd_lookup(fd);
    if (!entry) {
        return;
    }
    entry->payload = payload;
}

void fut_fd_release(int fd) {
    int idx = fd - FUT_FD_BASE;
    if (idx < 0 || idx >= FUT_FD_TABLE_SIZE) {
        return;
    }
    fd_table[idx].in_use = false;
    fd_table[idx].payload = NULL;
    fd_table[idx].kind = FUT_FD_NONE;
    if (next_fd_hint == idx) {
        next_fd_hint = (idx + 1) % FUT_FD_TABLE_SIZE;
    }
}

struct fd_path_entry {
    bool in_use;
    int fd;
    char path[128];
};

#define FD_PATH_TABLE_SIZE 64

static struct fd_path_entry path_table[FD_PATH_TABLE_SIZE];

void fut_fd_path_register(int fd, const char *path) {
    if (!path) {
        return;
    }
    for (int i = 0; i < FD_PATH_TABLE_SIZE; ++i) {
        if (path_table[i].in_use && path_table[i].fd == fd) {
            size_t len = strlen(path);
            if (len >= sizeof(path_table[i].path)) {
                len = sizeof(path_table[i].path) - 1;
            }
            memcpy(path_table[i].path, path, len);
            path_table[i].path[len] = '\0';
            return;
        }
    }
    for (int i = 0; i < FD_PATH_TABLE_SIZE; ++i) {
        if (!path_table[i].in_use) {
            path_table[i].in_use = true;
            path_table[i].fd = fd;
            size_t len = strlen(path);
            if (len >= sizeof(path_table[i].path)) {
                len = sizeof(path_table[i].path) - 1;
            }
            memcpy(path_table[i].path, path, len);
            path_table[i].path[len] = '\0';
            return;
        }
    }
}

int fut_fd_path_lookup(int fd, char *buf, size_t buf_len) {
    if (!buf || buf_len == 0) {
        return -1;
    }
    for (int i = 0; i < FD_PATH_TABLE_SIZE; ++i) {
        if (path_table[i].in_use && path_table[i].fd == fd) {
            size_t len = strlen(path_table[i].path);
            if (len + 1 > buf_len) {
                len = buf_len - 1;
            }
            memcpy(buf, path_table[i].path, len);
            buf[len] = '\0';
            return 0;
        }
    }
    return -1;
}

void fut_fd_path_forget(int fd) {
    for (int i = 0; i < FD_PATH_TABLE_SIZE; ++i) {
        if (path_table[i].in_use && path_table[i].fd == fd) {
            path_table[i].in_use = false;
            path_table[i].fd = -1;
            path_table[i].path[0] = '\0';
            return;
        }
    }
}
