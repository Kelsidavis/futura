/* kernel/sys_arch_prctl.c - Architecture-specific process control (x86_64)
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements arch_prctl() for x86_64 TLS (Thread Local Storage) management.
 * Essential for libc/musl initialization and pthread support.
 */

#include <kernel/fut_task.h>
#include <kernel/fut_thread.h>
#include <kernel/uaccess.h>
#include <kernel/errno.h>
#include <stdint.h>

#include <platform/platform.h>

/* Helper: copy a 64-bit value to either a user or kernel pointer.
 * Kernel-pointer self-tests must NOT cause copy_to_user to be the only
 * gate; otherwise on its failure the original code wrote *uptr = val
 * directly, which let a user supply a kernel address and turn this
 * syscall into a write-anywhere primitive. */
static inline int aprctl_put_u64(uint64_t *uptr, uint64_t val) {
    if (!uptr) return -EFAULT;
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)uptr >= KERNEL_VIRTUAL_BASE) {
        *uptr = val;
        return 0;
    }
#endif
    if (fut_copy_to_user(uptr, &val, sizeof(val)) != 0)
        return -EFAULT;
    return 0;
}

#ifdef __x86_64__
#include <arch/x86_64/msr.h>
#define MSR_FS_BASE 0xC0000100
#define MSR_GS_BASE 0xC0000101
#endif

/* arch_prctl codes (x86_64 specific) */
#define ARCH_SET_GS  0x1001
#define ARCH_SET_FS  0x1002
#define ARCH_GET_FS  0x1003
#define ARCH_GET_GS  0x1004

/* CPU feature enumeration control (Linux 4.12+) */
#define ARCH_GET_CPUID  0x1011  /* Returns 1 if CPUID instruction is enabled */
#define ARCH_SET_CPUID  0x1012  /* Enable/disable CPUID instruction (arg=0/1) */

/* Extended CPU state component control (Linux 5.16+) */
#define ARCH_GET_XCOMP_SUPP        0x1021  /* Get supported xstate component mask */
#define ARCH_GET_XCOMP_PERM        0x1022  /* Get permitted xstate component mask */
#define ARCH_REQ_XCOMP_PERM        0x1023  /* Request permission to use xstate component */
#define ARCH_GET_XCOMP_GUEST_PERM  0x1024  /* Get guest xstate permission mask */
#define ARCH_REQ_XCOMP_GUEST_PERM  0x1025  /* Request guest xstate permission */

/* Supported xstate components (XFEATURE masks).
 * Futura emulates under QEMU with at minimum x87, SSE, AVX. */
#define XFEATURE_MASK_FP   (1ULL << 0)   /* x87 FPU */
#define XFEATURE_MASK_SSE  (1ULL << 1)   /* SSE/XMM */
#define XFEATURE_MASK_AVX  (1ULL << 2)   /* AVX/YMM */
#define XFEATURE_SUPP      (XFEATURE_MASK_FP | XFEATURE_MASK_SSE | XFEATURE_MASK_AVX)

/**
 * sys_arch_prctl - Set/get architecture-specific thread state
 *
 * @param code: ARCH_SET_FS, ARCH_GET_FS, ARCH_SET_GS, ARCH_GET_GS
 * @param addr: Address to set, or pointer to store result
 *
 * ARCH_SET_FS sets the FS segment base register used by libc for TLS.
 * Every thread needs its own FS base pointing to its TLS block.
 *
 * Returns:
 *   - 0 on success
 *   - -EINVAL for unknown code or non-canonical address
 *   - -EFAULT for invalid pointer (ARCH_GET_*)
 *   - -ESRCH if no thread context
 */
long sys_arch_prctl(int code, unsigned long addr) {
    fut_thread_t *thread = fut_thread_current();
    if (!thread) {
        return -ESRCH;
    }

    switch (code) {
    case ARCH_SET_FS:
        /* Reject non-canonical / kernel-half FS bases before touching the MSR.
         * On x86_64 with FSGSBASE enabled, wrmsr(MSR_FS_BASE, non_canonical)
         * raises #GP and aborts the syscall in kernel mode — an unprivileged
         * DoS primitive. Linux clamps to TASK_SIZE_MAX (~ (1<<47)-PAGE_SIZE);
         * we apply the same upper bound. ARM64's TPIDR_EL0 takes any 64-bit
         * value, but limiting it to user-space matches Linux's contract that
         * a TLS pointer must address user memory. */
        if (addr >= (1ULL << 47))
            return -EPERM;
#ifdef __x86_64__
        wrmsr(MSR_FS_BASE, addr);
#elif defined(__aarch64__)
        /* On ARM64, TPIDR_EL0 is the user-space TLS register (equivalent to FS_BASE).
         * Write it immediately so the current thread sees it; context switch will
         * save/restore it via fut_thread_t.fs_base (offset 864). */
        __asm__ volatile("msr tpidr_el0, %0" :: "r"(addr));
#endif
        thread->fs_base = addr;
        return 0;

    case ARCH_GET_FS: {
        return aprctl_put_u64((uint64_t *)addr, thread->fs_base);
    }

    case ARCH_SET_GS:
        /* Same canonical/user-space guard as ARCH_SET_FS: even though Futura
         * does not currently write MSR_GS_BASE here, a future SWAPGS path
         * would, and stashing a kernel-half value would let the eventual
         * wrmsr trap. Reject non-canonical values up-front. */
        if (addr >= (1ULL << 47))
            return -EPERM;
        if (thread)
            thread->gs_base = addr;
        return 0;

    case ARCH_GET_GS: {
        return aprctl_put_u64((uint64_t *)addr,
                              thread ? thread->gs_base : 0);
    }

    case ARCH_GET_CPUID:
        /* In Futura (emulated), CPUID is always available */
        return 1;

    case ARCH_SET_CPUID:
        /* Accept enable/disable request; CPUID always available in emulation */
        if (addr != 0 && addr != 1)
            return -EINVAL;
        return 0;

    case ARCH_GET_XCOMP_SUPP:
        return aprctl_put_u64((uint64_t *)addr, XFEATURE_SUPP);

    case ARCH_GET_XCOMP_PERM:
        /* Permitted == supported on Futura */
        return aprctl_put_u64((uint64_t *)addr, XFEATURE_SUPP);

    case ARCH_REQ_XCOMP_PERM: {
        /* Linux's xstate_request_perm() takes a feature INDEX (not a mask)
         * and rejects out-of-range indices with -EINVAL and unsupported
         * indices with -EOPNOTSUPP. The previous code returned 0 for any
         * value the caller passed, so a runtime probing for AMX
         * (XFEATURE_XTILE_DATA = 18, unsupported on Futura) believed the
         * request succeeded and would later trap when issuing AMX ops. */
        #define XFEATURE_MAX 19
        if (addr >= XFEATURE_MAX)
            return -EINVAL;
        if (!(XFEATURE_SUPP & (1ULL << addr)))
            return -EOPNOTSUPP;
        return 0;
    }

    case ARCH_GET_XCOMP_GUEST_PERM:
        /* No guest VM support — guest perm is 0 */
        return aprctl_put_u64((uint64_t *)addr, 0);

    case ARCH_REQ_XCOMP_GUEST_PERM:
        /* No guest VM support — return EINVAL per Linux behavior */
        return -EINVAL;

    default:
        return -EINVAL;
    }
}
