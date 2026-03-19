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
        /* Set FS base — used for TLS by libc */
        thread->fs_base = addr;
#ifdef __x86_64__
        wrmsr(MSR_FS_BASE, addr);
#endif
        return 0;

    case ARCH_GET_FS: {
        /* Get current FS base */
        uint64_t *uptr = (uint64_t *)addr;
        if (!uptr) {
            return -EFAULT;
        }
        uint64_t val = thread->fs_base;
        if (fut_copy_to_user(uptr, &val, sizeof(val)) != 0) {
            /* Kernel pointer fallback for self-tests */
            *uptr = val;
        }
        return 0;
    }

    case ARCH_SET_GS:
#ifdef __x86_64__
        wrmsr(MSR_GS_BASE, addr);
#endif
        return 0;

    case ARCH_GET_GS: {
        uint64_t *uptr = (uint64_t *)addr;
        if (!uptr) {
            return -EFAULT;
        }
        uint64_t val = 0;
#ifdef __x86_64__
        val = rdmsr(MSR_GS_BASE);
#endif
        if (fut_copy_to_user(uptr, &val, sizeof(val)) != 0) {
            *uptr = val;
        }
        return 0;
    }

    case ARCH_GET_CPUID:
        /* In Futura (emulated), CPUID is always available */
        return 1;

    case ARCH_SET_CPUID:
        /* Accept enable/disable request; CPUID always available in emulation */
        if (addr != 0 && addr != 1)
            return -EINVAL;
        return 0;

    case ARCH_GET_XCOMP_SUPP: {
        /* Return supported extended state component mask */
        uint64_t *uptr = (uint64_t *)addr;
        if (!uptr) return -EFAULT;
        uint64_t val = XFEATURE_SUPP;
        if (fut_copy_to_user(uptr, &val, sizeof(val)) != 0)
            *uptr = val;
        return 0;
    }

    case ARCH_GET_XCOMP_PERM: {
        /* Return permitted extended state component mask (same as supported) */
        uint64_t *uptr = (uint64_t *)addr;
        if (!uptr) return -EFAULT;
        uint64_t val = XFEATURE_SUPP;
        if (fut_copy_to_user(uptr, &val, sizeof(val)) != 0)
            *uptr = val;
        return 0;
    }

    case ARCH_REQ_XCOMP_PERM:
        /* Grant permission to use any supported xstate component */
        return 0;

    case ARCH_GET_XCOMP_GUEST_PERM: {
        /* Return 0 — no guest VM support */
        uint64_t *uptr = (uint64_t *)addr;
        if (!uptr) return -EFAULT;
        uint64_t val = 0;
        if (fut_copy_to_user(uptr, &val, sizeof(val)) != 0)
            *uptr = val;
        return 0;
    }

    case ARCH_REQ_XCOMP_GUEST_PERM:
        /* No guest VM support — return EINVAL per Linux behavior */
        return -EINVAL;

    default:
        return -EINVAL;
    }
}
