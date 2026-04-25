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

/* CAP_SYS_PTRACE = 19 (Linux ABI) */
#define PVM_CAP_SYS_PTRACE 19

struct pvm_iovec {
    void   *iov_base;
    size_t  iov_len;
};

/* These helpers are used to read iovec arrays themselves (which may
 * come from a kernel-resident caller). The KERNEL_VIRTUAL_BASE bypass
 * here is safe because the iovec array pointer is the syscall arg, not
 * a user-controlled scatter-gather payload pointer. The remote/local
 * iov_base entries are validated separately to be userspace addresses
 * before any copy. */
static inline int pvm_copy_iov_from_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)src >= KERNEL_VIRTUAL_BASE) { __builtin_memcpy(dst, src, n); return 0; }
#endif
    return fut_copy_from_user(dst, src, n);
}

/* Reject any iov_base in the kernel half of the address space — without
 * this check, a user could ask the kernel to copy to or from kernel
 * memory using process_vm_readv/writev. */
static inline int pvm_iov_is_user(const struct pvm_iovec *iov) {
#ifdef KERNEL_VIRTUAL_BASE
    uintptr_t base = (uintptr_t)iov->iov_base;
    if (iov->iov_len == 0) return 1;
    if (base >= KERNEL_VIRTUAL_BASE) return 0;
    if (base + iov->iov_len < base) return 0;          /* wraparound */
    if (base + iov->iov_len > KERNEL_VIRTUAL_BASE) return 0;
#endif
    return 1;
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
    if (flags != 0)
        return -EINVAL;
    if (liovcnt > IOV_MAX || riovcnt > IOV_MAX)
        return -EINVAL;
    if (!lvec || !rvec)
        return -EFAULT;

    /* Permission: PTRACE_MODE_ATTACH_REALCREDS — same uid or CAP_SYS_PTRACE.
     * Without this, any process could read another process's memory by
     * invoking the syscall (Futura's single-AS implementation otherwise
     * trusts iov_base pointers without translating through a target mm). */
    fut_task_t *self = fut_task_current();
    if (self && pid != 0 && (uint64_t)pid != self->pid) {
        fut_task_t *target = fut_task_by_pid((uint64_t)pid);
        if (!target) return -ESRCH;
        if (self->uid != 0 && self->uid != target->uid &&
            !(self->cap_effective & (1ULL << PVM_CAP_SYS_PTRACE)))
            return -EPERM;
    }

    /* Copy iovec arrays from user/kernel. Heap-allocate sized to caller's
     * iovcnt; previous version put two IOV_MAX (16 KB each = 32 KB) arrays
     * on the kernel stack regardless of iovcnt — a stack-overflow primitive
     * triggerable from any caller permitted to call this syscall. */
    extern void *fut_malloc(uint64_t size);
    extern void  fut_free(void *p);
    struct pvm_iovec *lv = fut_malloc(liovcnt * sizeof(struct pvm_iovec));
    struct pvm_iovec *rv = fut_malloc(riovcnt * sizeof(struct pvm_iovec));
    if (!lv || !rv) {
        if (lv) fut_free(lv);
        if (rv) fut_free(rv);
        return -ENOMEM;
    }

    if (pvm_copy_iov_from_user(lv, lvec, liovcnt * sizeof(struct pvm_iovec)) != 0) {
        fut_free(lv); fut_free(rv);
        return -EFAULT;
    }
    if (pvm_copy_iov_from_user(rv, rvec, riovcnt * sizeof(struct pvm_iovec)) != 0) {
        fut_free(lv); fut_free(rv);
        return -EFAULT;
    }

    /* Validate cumulative lengths AND that every iov_base lives in
     * userspace, not the kernel half. Without this, a caller could
     * point iov_base at a kernel address and the copy helpers' built-in
     * KERNEL_VIRTUAL_BASE bypass would do a raw memcpy across the
     * boundary — read/write-anywhere primitive. */
    size_t ltotal = 0, rtotal = 0;
    for (unsigned long i = 0; i < liovcnt; i++) {
        if (lv[i].iov_len > (size_t)SSIZE_MAX - ltotal) { fut_free(lv); fut_free(rv); return -EINVAL; }
        if (!pvm_iov_is_user(&lv[i])) { fut_free(lv); fut_free(rv); return -EFAULT; }
        ltotal += lv[i].iov_len;
    }
    for (unsigned long i = 0; i < riovcnt; i++) {
        if (rv[i].iov_len > (size_t)SSIZE_MAX - rtotal) { fut_free(lv); fut_free(rv); return -EINVAL; }
        if (!pvm_iov_is_user(&rv[i])) { fut_free(lv); fut_free(rv); return -EFAULT; }
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

        /* Both src and dst are guaranteed userspace by pvm_iov_is_user.
         * Stage through a kernel bounce so we never bypass uaccess on
         * either end. */
        char bounce[256];
        size_t off = 0;
        while (off < chunk) {
            size_t step = chunk - off;
            if (step > sizeof(bounce)) step = sizeof(bounce);
            if (fut_copy_from_user(bounce, (const char *)src + off, step) != 0)
                goto read_done;
            if (fut_copy_to_user((char *)dst + off, bounce, step) != 0)
                goto read_done;
            off += step;
            done += step;
        }

        loff += chunk;
        roff += chunk;
        if (loff >= lv[li].iov_len) { li++; loff = 0; }
        if (roff >= rv[ri].iov_len) { ri++; roff = 0; }
    }
read_done:
    fut_free(lv); fut_free(rv);
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
    if (flags != 0)
        return -EINVAL;
    if (liovcnt > IOV_MAX || riovcnt > IOV_MAX)
        return -EINVAL;
    if (!lvec || !rvec)
        return -EFAULT;

    /* Same permission check as readv. */
    fut_task_t *self = fut_task_current();
    if (self && pid != 0 && (uint64_t)pid != self->pid) {
        fut_task_t *target = fut_task_by_pid((uint64_t)pid);
        if (!target) return -ESRCH;
        if (self->uid != 0 && self->uid != target->uid &&
            !(self->cap_effective & (1ULL << PVM_CAP_SYS_PTRACE)))
            return -EPERM;
    }

    /* Heap-allocate iovec staging — see sys_process_vm_readv for rationale. */
    extern void *fut_malloc(uint64_t size);
    extern void  fut_free(void *p);
    struct pvm_iovec *lv = fut_malloc(liovcnt * sizeof(struct pvm_iovec));
    struct pvm_iovec *rv = fut_malloc(riovcnt * sizeof(struct pvm_iovec));
    if (!lv || !rv) {
        if (lv) fut_free(lv);
        if (rv) fut_free(rv);
        return -ENOMEM;
    }

    if (pvm_copy_iov_from_user(lv, lvec, liovcnt * sizeof(struct pvm_iovec)) != 0) {
        fut_free(lv); fut_free(rv);
        return -EFAULT;
    }
    if (pvm_copy_iov_from_user(rv, rvec, riovcnt * sizeof(struct pvm_iovec)) != 0) {
        fut_free(lv); fut_free(rv);
        return -EFAULT;
    }

    size_t ltotal = 0, rtotal = 0;
    for (unsigned long i = 0; i < liovcnt; i++) {
        if (lv[i].iov_len > (size_t)SSIZE_MAX - ltotal) { fut_free(lv); fut_free(rv); return -EINVAL; }
        if (!pvm_iov_is_user(&lv[i])) { fut_free(lv); fut_free(rv); return -EFAULT; }
        ltotal += lv[i].iov_len;
    }
    for (unsigned long i = 0; i < riovcnt; i++) {
        if (rv[i].iov_len > (size_t)SSIZE_MAX - rtotal) { fut_free(lv); fut_free(rv); return -EINVAL; }
        if (!pvm_iov_is_user(&rv[i])) { fut_free(lv); fut_free(rv); return -EFAULT; }
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

        char bounce[256];
        size_t off = 0;
        while (off < chunk) {
            size_t step = chunk - off;
            if (step > sizeof(bounce)) step = sizeof(bounce);
            if (fut_copy_from_user(bounce, (const char *)src + off, step) != 0)
                goto write_done;
            if (fut_copy_to_user((char *)dst + off, bounce, step) != 0)
                goto write_done;
            off += step;
            done += step;
        }

        loff += chunk;
        roff += chunk;
        if (loff >= lv[li].iov_len) { li++; loff = 0; }
        if (roff >= rv[ri].iov_len) { ri++; roff = 0; }
    }
write_done:
    fut_free(lv); fut_free(rv);
    return (long)done;
}
