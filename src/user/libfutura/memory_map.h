// SPDX-License-Identifier: MPL-2.0
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <user/futura_posix.h>

struct fut_maprec {
    void *addr;
    size_t length;
    int fd;
    off_t offset;
    int prot;
    int flags;
    char path[128];
};

int fut_maprec_insert(void *addr, size_t length, int fd, off_t offset,
                      int prot, int flags, const char *path);
int fut_maprec_find(void *addr, struct fut_maprec *out);
int fut_maprec_update(void *old_addr, void *new_addr, size_t new_len);
int fut_maprec_remove(void *addr);
int fut_maprec_find_by_fd(int fd, struct fut_maprec *out);
