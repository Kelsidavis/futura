/* kernel/sys_process_vm.c - process_vm_readv / process_vm_writev
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements cross-process memory access (Linux 3.2+).
 * In Futura's single-address-space kernel model all tasks share the same
 * virtual address space, so a direct memcpy suffices for the non-NULL PID
 * and self-PID cases.
 *
 * Phase 1 (Completed): Full implementation for same-address-space case.
 *   - Validates iov arrays and cumulative length limits (SSIZE_MAX).
 *   - Copies data between local and remote iov scatter-gather lists.
 *   - Returns total bytes transferred, or -errno on error.
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <kernel/kprintf.h>
#include <kernel/uaccess.h>
#include <stddef.h>
#include <stdint.h>
#include <limits.h>

#include <platform/platform.h>

#define IOV_MAX  1024   /* Linux UIO_MAXIOV */

struct pvm_iovec {
    void   *iov_base;
    size_t  iov_len;
};

static inline int pvm_copy_to_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)dst >= KERNEL_VIRTUAL_BASE) { __builtin_memcpy(dst, src, n); return 0; }
#endif
    return fut_copy_to_user(dst, src, n);
}

static inline int pvm_copy_from_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)src >= KERNEL_VIRTUAL_BASE) { __builtin_memcpy(dst, src, n); return 0; }
#endif
    return fut_copy_from_user(dst, src, n);
}

/**
 * process_vm_readv - Read from a remote process's address space.
 *
 * @param pid        Target process PID (0 = self)
 * @param lvec       Local iovec array (destination)
 * @param liovcnt    Number of local iovecs
 * @param rvec       Remote iovec array (source)
 * @param riovcnt    Number of remote iovecs
 * @param flags      Must be 0 (reserved)
 * @return Total bytes read, or -errno
 */
long sys_process_vm_readv(int pid, const struct pvm_iovec *lvec, unsigned long liovcnt,
                          const struct pvm_iovec *rvec, unsigned long riovcnt,
                          unsigned long flags)
{
    (void)pid;   /* all tasks share address space in Futura */

    if (flags != 0)
        return -EINVAL;
    if (liovcnt > IOV_MAX || riovcnt > IOV_MAX)
        return -EINVAL;
    if (!lvec || !rvec)
        return -EFAULT;

    /* Copy iovec arrays from user/kernel */
    struct pvm_iovec lv[IOV_MAX];
    struct pvm_iovec rv[IOV_MAX];

    if (pvm_copy_from_user(lv, lvec, liovcnt * sizeof(struct pvm_iovec)) != 0)
        return -EFAULT;
    if (pvm_copy_from_user(rv, rvec, riovcnt * sizeof(struct pvm_iovec)) != 0)
        return -EFAULT;

    /* Validate cumulative lengths */
    size_t ltotal = 0, rtotal = 0;
    for (unsigned long i = 0; i < liovcnt; i++) {
        if (lv[i].iov_len > (size_t)SSIZE_MAX - ltotal) return -EINVAL;
        ltotal += lv[i].iov_len;
    }
    for (unsigned long i = 0; i < riovcnt; i++) {
        if (rv[i].iov_len > (size_t)SSIZE_MAX - rtotal) return -EINVAL;
        rtotal += rv[i].iov_len;
    }

    /* Scatter-gather copy: remote → local */
    size_t done = 0;
    unsigned long li = 0, ri = 0;
    size_t loff = 0, roff = 0;

    while (li < liovcnt && ri < riovcnt) {
        size_t lrem = lv[li].iov_len - loff;
        size_t rrem = rv[ri].iov_len - roff;
        size_t chunk = lrem < rrem ? lrem : rrem;
        if (chunk == 0) {
            if (lrem == 0) { li++; loff = 0; }
            if (rrem == 0) { ri++; roff = 0; }
            continue;
        }

        const void *src = (const char *)rv[ri].iov_base + roff;
        void       *dst = (char *)lv[li].iov_base + loff;

        if (pvm_copy_to_user(dst, src, chunk) != 0)
            break;

        done += chunk;
        loff += chunk;
        roff += chunk;
        if (loff >= lv[li].iov_len) { li++; loff = 0; }
        if (roff >= rv[ri].iov_len) { ri++; roff = 0; }
    }

    return (long)done;
}

/**
 * process_vm_writev - Write to a remote process's address space.
 *
 * @param pid        Target process PID (0 = self)
 * @param lvec       Local iovec array (source)
 * @param liovcnt    Number of local iovecs
 * @param rvec       Remote iovec array (destination)
 * @param riovcnt    Number of remote iovecs
 * @param flags      Must be 0 (reserved)
 * @return Total bytes written, or -errno
 */
long sys_process_vm_writev(int pid, const struct pvm_iovec *lvec, unsigned long liovcnt,
                           const struct pvm_iovec *rvec, unsigned long riovcnt,
                           unsigned long flags)
{
    (void)pid;

    if (flags != 0)
        return -EINVAL;
    if (liovcnt > IOV_MAX || riovcnt > IOV_MAX)
        return -EINVAL;
    if (!lvec || !rvec)
        return -EFAULT;

    struct pvm_iovec lv[IOV_MAX];
    struct pvm_iovec rv[IOV_MAX];

    if (pvm_copy_from_user(lv, lvec, liovcnt * sizeof(struct pvm_iovec)) != 0)
        return -EFAULT;
    if (pvm_copy_from_user(rv, rvec, riovcnt * sizeof(struct pvm_iovec)) != 0)
        return -EFAULT;

    size_t ltotal = 0, rtotal = 0;
    for (unsigned long i = 0; i < liovcnt; i++) {
        if (lv[i].iov_len > (size_t)SSIZE_MAX - ltotal) return -EINVAL;
        ltotal += lv[i].iov_len;
    }
    for (unsigned long i = 0; i < riovcnt; i++) {
        if (rv[i].iov_len > (size_t)SSIZE_MAX - rtotal) return -EINVAL;
        rtotal += rv[i].iov_len;
    }

    /* Scatter-gather copy: local → remote */
    size_t done = 0;
    unsigned long li = 0, ri = 0;
    size_t loff = 0, roff = 0;

    while (li < liovcnt && ri < riovcnt) {
        size_t lrem = lv[li].iov_len - loff;
        size_t rrem = rv[ri].iov_len - roff;
        size_t chunk = lrem < rrem ? lrem : rrem;
        if (chunk == 0) {
            if (lrem == 0) { li++; loff = 0; }
            if (rrem == 0) { ri++; roff = 0; }
            continue;
        }

        const void *src = (const char *)lv[li].iov_base + loff;
        void       *dst = (char *)rv[ri].iov_base + roff;

        if (pvm_copy_to_user(dst, src, chunk) != 0)
            break;

        done += chunk;
        loff += chunk;
        roff += chunk;
        if (loff >= lv[li].iov_len) { li++; loff = 0; }
        if (roff >= rv[ri].iov_len) { ri++; roff = 0; }
    }

    return (long)done;
}
