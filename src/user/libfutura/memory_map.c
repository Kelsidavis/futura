// SPDX-License-Identifier: MPL-2.0

#include "memory_map.h"

#include <stdbool.h>
#include <user/libfutura.h>

#define FUT_MAPREC_MAX 128
#define FUT_PAGE_SIZE  4096UL

struct fut_maprec_slot {
    bool in_use;
    struct fut_maprec rec;
};

static struct fut_maprec_slot map_table[FUT_MAPREC_MAX];

static size_t page_round_up(size_t len) {
    if (len == 0) {
        return 0;
    }
    return (len + FUT_PAGE_SIZE - 1ULL) & ~(FUT_PAGE_SIZE - 1ULL);
}

static void copy_path(char *dst, const char *src, size_t dst_len) {
    if (!dst || dst_len == 0) {
        return;
    }
    if (!src) {
        dst[0] = '\0';
        return;
    }
    size_t copy = strlen(src);
    if (copy >= dst_len) {
        copy = dst_len - 1;
    }
    memcpy(dst, src, copy);
    dst[copy] = '\0';
}

int fut_maprec_insert(void *addr, size_t length, int fd, off_t offset,
                      int prot, int flags, const char *path) {
    if (!addr || length == 0) {
        return -1;
    }
    size_t len_aligned = page_round_up(length);
    if (len_aligned == 0) {
        return -1;
    }
    for (int i = 0; i < FUT_MAPREC_MAX; ++i) {
        if (!map_table[i].in_use) {
            map_table[i].in_use = true;
            map_table[i].rec.addr = addr;
            map_table[i].rec.length = len_aligned;
            map_table[i].rec.fd = fd;
            map_table[i].rec.offset = offset;
            map_table[i].rec.prot = prot;
            map_table[i].rec.flags = flags;
            copy_path(map_table[i].rec.path, path, sizeof(map_table[i].rec.path));
            return 0;
        }
    }
    return -1;
}

int fut_maprec_find(void *addr, struct fut_maprec *out) {
    if (!addr) {
        return -1;
    }
    for (int i = 0; i < FUT_MAPREC_MAX; ++i) {
        if (map_table[i].in_use && map_table[i].rec.addr == addr) {
            if (out) {
                *out = map_table[i].rec;
            }
            return 0;
        }
    }
    return -1;
}

int fut_maprec_update(void *old_addr, void *new_addr, size_t new_len) {
    if (!old_addr || !new_addr || new_len == 0) {
        return -1;
    }
    size_t len_aligned = page_round_up(new_len);
    for (int i = 0; i < FUT_MAPREC_MAX; ++i) {
        if (map_table[i].in_use && map_table[i].rec.addr == old_addr) {
            map_table[i].rec.addr = new_addr;
            map_table[i].rec.length = len_aligned;
            return 0;
        }
    }
    return -1;
}

int fut_maprec_remove(void *addr) {
    if (!addr) {
        return -1;
    }
    for (int i = 0; i < FUT_MAPREC_MAX; ++i) {
        if (map_table[i].in_use && map_table[i].rec.addr == addr) {
            map_table[i].in_use = false;
            map_table[i].rec.addr = NULL;
            map_table[i].rec.length = 0;
            map_table[i].rec.fd = -1;
            map_table[i].rec.path[0] = '\0';
            return 0;
        }
    }
    return -1;
}

int fut_maprec_find_by_fd(int fd, struct fut_maprec *out) {
    for (int i = 0; i < FUT_MAPREC_MAX; ++i) {
        if (map_table[i].in_use && map_table[i].rec.fd == fd) {
            if (out) {
                *out = map_table[i].rec;
            }
            return 0;
        }
    }
    return -1;
}
