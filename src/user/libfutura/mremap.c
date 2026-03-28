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
    /* Overflow check: reject sizes that would wrap when rounding up */
    if (len > (size_t)-1 - (FUT_PAGE_SIZE - 1ULL)) {
        return 0;
    }
    return (len + FUT_PAGE_SIZE - 1ULL) & ~(FUT_PAGE_SIZE - 1ULL);
}

void *mremap(void *old_addr, size_t old_size, size_t new_size, int flags, ...) {
    if (!old_addr || new_size == 0) {
        errno = EINVAL;
        return (void *)-1;
    }

    /* Extract optional new_address for MREMAP_FIXED */
    void *new_address = NULL;
    if (flags & MREMAP_FIXED) {
        va_list ap;
        va_start(ap, flags);
        new_address = va_arg(ap, void *);
        va_end(ap);

        /* MREMAP_FIXED requires MREMAP_MAYMOVE per Linux semantics */
        if (!(flags & MREMAP_MAYMOVE)) {
            errno = EINVAL;
            return (void *)-1;
        }

        /* Delegate MREMAP_FIXED to kernel — it handles target unmapping,
         * mapping at exact address, data copy, and old region cleanup. */
        long ret = sys_call5(SYS_mremap, (long)old_addr, (long)old_size,
                             (long)new_size, (long)flags, (long)new_address);
        if (ret < 0) {
            errno = (int)-ret;
            return (void *)-1;
        }
        void *result = (void *)ret;
        if (fut_maprec_update(old_addr, result, page_round_up(new_size)) < 0) {
            struct fut_maprec rec;
            int prot = 3, mflags = 0x22; /* defaults: RW, PRIVATE|ANON */
            if (fut_maprec_find(old_addr, &rec) == 0) {
                prot = rec.prot;
                mflags = rec.flags;
            }
            fut_maprec_insert(result, page_round_up(new_size), -1, 0, prot, mflags, NULL);
        }
        return result;
    }

    /* Growing without MREMAP_MAYMOVE is only allowed in-place (kernel
     * returns ENOMEM if extension range is occupied).  Shrinking never
     * requires MREMAP_MAYMOVE. */
    if (new_size > old_size && !(flags & MREMAP_MAYMOVE)) {
        /* Still try: the kernel will succeed if the in-place range is free,
         * or return ENOMEM if not. */
        long ret = sys_call5(SYS_mremap, (long)old_addr, (long)old_size,
                             (long)new_size, (long)flags, 0);
        if (ret < 0) {
            errno = (int)-ret;
            return (void *)-1;
        }
        fut_maprec_update(old_addr, old_addr, page_round_up(new_size));
        return (void *)ret;
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

    /* Same-size remap: no-op */
    if (new_len == old_len) {
        fut_maprec_update(old_addr, old_addr, new_len);
        return old_addr;
    }

    /* Shrinking: unmap the tail pages in-place.
     * This is much faster than alloc+copy+unmap — no data movement needed.
     * Critical for realloc() shrink performance. */
    if (new_len < old_len) {
        uintptr_t tail_start = (uintptr_t)old_addr + new_len;
        size_t tail_len = old_len - new_len;
        long unmap_ret = sys_munmap_call((void *)tail_start, (long)tail_len);
        if (unmap_ret < 0) {
            errno = (int)-unmap_ret;
            return (void *)-1;
        }
        fut_maprec_update(old_addr, old_addr, new_len);
        return old_addr;
    }

    /* Growing with MREMAP_MAYMOVE: allocate new region, copy, unmap old.
     * The kernel's mremap tries in-place first, so delegate to it. */
    long map_ret = sys_mmap(NULL, (long)new_len, rec.prot, rec.flags, rec.fd, rec.offset);
    if (map_ret < 0) {
        errno = (int)-map_ret;
        return (void *)-1;
    }

    void *new_addr = (void *)map_ret;
    if (old_len > 0) {
        memcpy(new_addr, old_addr, old_len);
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
