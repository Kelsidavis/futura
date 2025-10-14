// SPDX-License-Identifier: MPL-2.0

#include <stdarg.h>
#include <errno.h>

#include <user/futura_posix.h>
#include <user/libfutura.h>
#include <user/sys.h>

#include "memory_map.h"

#define FUT_PAGE_SIZE 4096UL

static size_t page_round_up(size_t len) {
    if (len == 0) {
        return 0;
    }
    return (len + FUT_PAGE_SIZE - 1ULL) & ~(FUT_PAGE_SIZE - 1ULL);
}

void *mremap(void *old_addr, size_t old_size, size_t new_size, int flags, ...) {
    if (!old_addr || new_size == 0) {
        errno = EINVAL;
        return (void *)-1;
    }

    if (flags & MREMAP_FIXED) {
        va_list ap;
        va_start(ap, flags);
        (void)va_arg(ap, void *);
        va_end(ap);
        errno = EINVAL;
        return (void *)-1;
    }

    if ((new_size != old_size) && !(flags & MREMAP_MAYMOVE)) {
        errno = EINVAL;
        return (void *)-1;
    }

    struct fut_maprec rec;
    if (fut_maprec_find(old_addr, &rec) < 0) {
        errno = EINVAL;
        return (void *)-1;
    }

    size_t old_len = page_round_up(old_size ? old_size : rec.length);
    if (old_len == 0) {
        old_len = rec.length;
    }
    size_t new_len = page_round_up(new_size);
    if (new_len == 0) {
        errno = EINVAL;
        return (void *)-1;
    }

    if (new_len == old_len) {
        fut_maprec_update(old_addr, old_addr, new_len);
        return old_addr;
    }

    long map_ret = sys_mmap(NULL, (long)new_len, rec.prot, rec.flags, rec.fd, rec.offset);
    if (map_ret < 0) {
        errno = (int)-map_ret;
        return (void *)-1;
    }

    void *new_addr = (void *)map_ret;
    size_t copy_len = old_len < new_len ? old_len : new_len;
    if (copy_len > 0) {
        memcpy(new_addr, old_addr, copy_len);
    }

    long unmap_ret = sys_munmap_call(old_addr, (long)old_len);
    if (unmap_ret < 0) {
        sys_munmap_call(new_addr, (long)new_len);
        errno = (int)-unmap_ret;
        return (void *)-1;
    }

    if (fut_maprec_update(old_addr, new_addr, new_len) < 0) {
        fut_maprec_insert(new_addr, new_len, rec.fd, rec.offset, rec.prot, rec.flags, rec.path);
    }

    return new_addr;
}
