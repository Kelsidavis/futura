// SPDX-License-Identifier: MPL-2.0
/*
 * uaccess.c - Safe user memory access helpers
 *
 * Provides minimal page-aware validation and copy routines so kernel code can
 * interact with user pointers without relying on hardware faults.  The checks
 * currently operate on the global kernel address space; future VM work will
 * extend this to per-process contexts.
 */

#include <kernel/uaccess.h>
#include <kernel/errno.h>

#include <arch/x86_64/paging.h>
#include <arch/x86_64/pmap.h>

#include <string.h>

uintptr_t g_user_lo = 0x0000000000400000ULL;
uintptr_t g_user_hi = USER_SPACE_END + 1ULL; /* exclusive upper bound */

static inline int __range_user_ok(uintptr_t u, size_t n) {
    if (n == 0) {
        return 1;
    }

    if (u < g_user_lo) {
        return 0;
    }

    uintptr_t max_len = g_user_hi > u ? (g_user_hi - u) : 0;
    if (n > max_len) {
        return 0;
    }

    return 1;
}

int fut_access_ok(const void *u_ptr, size_t len, int write) {
    uintptr_t u = (uintptr_t)u_ptr;

    if (!__range_user_ok(u, len)) {
        return -EFAULT;
    }

    if (len == 0) {
        return 0;
    }

    uintptr_t start = u & ~(uintptr_t)(PAGE_SIZE - 1ULL);
    uintptr_t end = (u + len - 1ULL) & ~(uintptr_t)(PAGE_SIZE - 1ULL);

    for (uintptr_t addr = start; addr <= end; addr += PAGE_SIZE) {
        uint64_t pte = 0;
        if (pmap_probe_pte(NULL, addr, &pte) != 0) {
            return -EFAULT;
        }

        if (!(pte & PTE_PRESENT) || !(pte & PTE_USER)) {
            return -EFAULT;
        }

        if (write && !(pte & PTE_WRITABLE)) {
            return -EFAULT;
        }
    }

    return 0;
}

static int __copy(void *dst, const void *src, size_t n, int to_user) {
    if (n == 0) {
        return 0;
    }

    int rc;
    if (to_user) {
        rc = fut_access_ok(dst, n, 1);
    } else {
        rc = fut_access_ok(src, n, 0);
    }

    if (rc != 0) {
        return rc;
    }

    memcpy(dst, src, n);
    return 0;
}

int fut_copy_from_user(void *k_dst, const void *u_src, size_t n) {
    return __copy(k_dst, u_src, n, 0);
}

int fut_copy_to_user(void *u_dst, const void *k_src, size_t n) {
    return __copy(u_dst, k_src, n, 1);
}
