// SPDX-License-Identifier: MPL-2.0

#include "fd.h"

#include <errno.h>
#include <user/futura_posix.h>
#include <user/libfutura.h>
#include "eventfd_internal.h"

extern int __fut_unix_socket_retain(int fd);
extern int __fut_unix_socket_set_flags(int fd, int flags);

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
            fd_table[idx].flags = 0;
            fd_table[idx].cloexec = 0;
            next_fd_hint = (idx + 1) % FUT_FD_TABLE_SIZE;
            return FUT_FD_BASE + idx;
        }
    }
    return -1;
}

int fut_fd_alloc_at_or_above(enum fut_fd_kind kind, void *payload, int min_fd,
                             int inherit_flags, int cloexec) {
    if (min_fd < FUT_FD_BASE) {
        min_fd = FUT_FD_BASE;
    }
    int start_idx = min_fd - FUT_FD_BASE;
    if (start_idx < 0) {
        start_idx = 0;
    }
    if (start_idx >= FUT_FD_TABLE_SIZE) {
        return -1;
    }
    for (int idx = start_idx; idx < FUT_FD_TABLE_SIZE; ++idx) {
        if (!fd_table[idx].in_use) {
            fd_table[idx].in_use = true;
            fd_table[idx].kind = kind;
            fd_table[idx].payload = payload;
            fd_table[idx].flags = inherit_flags;
            fd_table[idx].cloexec = cloexec ? 1 : 0;
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
    fd_table[idx].flags = 0;
    fd_table[idx].cloexec = 0;
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

static int retain_entry_kind(int fd, struct fut_fd_entry *entry) {
    (void)entry;
    switch (entry->kind) {
    case FUT_FD_UNIX_STREAM:
    case FUT_FD_UNIX_LISTENER:
        return __fut_unix_socket_retain(fd);
    case FUT_FD_EVENTFD:
        return __fut_eventfd_retain(fd);
    default:
        return 0;
    }
}

int fd_dup(int fd, int min_new_fd, int cloexec) {
    struct fut_fd_entry *entry = fut_fd_lookup(fd);
    if (!entry) {
        errno = EBADF;
        return -1;
    }

    switch (entry->kind) {
    case FUT_FD_UNIX_STREAM:
    case FUT_FD_UNIX_LISTENER:
    case FUT_FD_EVENTFD:
        break;
    default:
        errno = EINVAL;
        return -1;
    }

    int desired_cloexec = cloexec ? 1 : entry->cloexec;
    int new_fd = fut_fd_alloc_at_or_above(entry->kind,
                                          entry->payload,
                                          min_new_fd,
                                          entry->flags,
                                          desired_cloexec);
    if (new_fd < 0) {
        errno = EMFILE;
        return -1;
    }

    if (retain_entry_kind(fd, entry) < 0) {
        fut_fd_release(new_fd);
        errno = EMFILE;
        return -1;
    }

    char path_buf[128];
    if (fut_fd_path_lookup(fd, path_buf, sizeof(path_buf)) == 0) {
        fut_fd_path_register(new_fd, path_buf);
    }

    return new_fd;
}

int fd_get_flags(int fd, int *out_flags) {
    struct fut_fd_entry *entry = fut_fd_lookup(fd);
    if (!entry) {
        return -1;
    }
    if (out_flags) {
        *out_flags = entry->flags;
    }
    return 0;
}

int fd_set_flags(int fd, int new_flags) {
    struct fut_fd_entry *entry = fut_fd_lookup(fd);
    if (!entry) {
        return -1;
    }
    entry->flags = new_flags;
    switch (entry->kind) {
    case FUT_FD_UNIX_STREAM:
    case FUT_FD_UNIX_LISTENER:
        __fut_unix_socket_set_flags(fd, new_flags);
        break;
    case FUT_FD_EVENTFD:
        __fut_eventfd_set_flags(fd, new_flags);
        break;
    default:
        break;
    }
    return 0;
}

int fd_get_cloexec(int fd) {
    struct fut_fd_entry *entry = fut_fd_lookup(fd);
    if (!entry) {
        return -1;
    }
    return entry->cloexec ? FD_CLOEXEC : 0;
}

int fd_set_cloexec(int fd, int on) {
    struct fut_fd_entry *entry = fut_fd_lookup(fd);
    if (!entry) {
        return -1;
    }
    entry->cloexec = on ? 1 : 0;
    return 0;
}
