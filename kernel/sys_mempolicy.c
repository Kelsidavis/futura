/* kernel/sys_mempolicy.c - NUMA memory policy syscalls
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Futura runs on a single-node "NUMA" topology: all memory is on node 0.
 * mbind/get_mempolicy/set_mempolicy succeed as no-ops because every
 * allocation already satisfies the only policy that makes sense here.
 *
 * Linux x86_64 syscall numbers:  237 mbind, 238 set_mempolicy, 239 get_mempolicy
 * Linux aarch64 syscall numbers: 235 mbind, 236 get_mempolicy, 237 set_mempolicy
 *
 * MPOL_DEFAULT = 0: use the process's default policy (inherited; for us, node 0).
 */

#include <kernel/errno.h>
#include <kernel/uaccess.h>
#include <stdint.h>
#include <stddef.h>

#include <platform/platform.h>

/* Kernel-pointer bypass: same idiom as the other syscalls so kernel
 * self-tests can pass kernel addresses without triggering uaccess. */
static inline int mempol_copy_to_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)dst >= KERNEL_VIRTUAL_BASE) {
        __builtin_memcpy(dst, src, n);
        return 0;
    }
#endif
    return fut_copy_to_user(dst, src, n);
}

/* Memory policy modes (subset; Futura only supports MPOL_DEFAULT = 0) */
#define MPOL_DEFAULT     0
#define MPOL_PREFERRED   1
#define MPOL_BIND        2
#define MPOL_INTERLEAVE  3
#define MPOL_LOCAL       4
#define MPOL_MAX         5

/* mbind flags */
#define MPOL_MF_STRICT   (1 << 0)
#define MPOL_MF_MOVE     (1 << 1)
#define MPOL_MF_MOVE_ALL (1 << 2)

/* get_mempolicy flags */
#define MPOL_F_NODE      (1 << 0)
#define MPOL_F_ADDR      (1 << 1)
#define MPOL_F_MEMS_ALLOWED (1 << 2)

/**
 * sys_mbind() - Bind a memory range to a NUMA node set.
 *
 * Futura is single-node; any binding that includes node 0 succeeds silently.
 * MPOL_DEFAULT always succeeds.  Strict migrations (MPOL_MF_MOVE_ALL) on a
 * single node are a no-op.  Returns -EINVAL for unknown policy modes.
 */
long sys_mbind(unsigned long addr, unsigned long len, int mode,
               const unsigned long *nodemask, unsigned long maxnode,
               unsigned int flags) {
    (void)addr; (void)len; (void)nodemask; (void)maxnode; (void)flags;
    if (mode < 0 || mode >= MPOL_MAX)
        return -EINVAL;
    return 0;
}

/**
 * sys_set_mempolicy() - Set the calling thread's default NUMA policy.
 *
 * Single-node stub: MPOL_DEFAULT always accepted; other modes accepted
 * as long as they are valid policy codes (since there is only one node).
 */
long sys_set_mempolicy(int mode, const unsigned long *nodemask,
                       unsigned long maxnode) {
    (void)nodemask; (void)maxnode;
    if (mode < 0 || mode >= MPOL_MAX)
        return -EINVAL;
    return 0;
}

/**
 * sys_get_mempolicy() - Query the NUMA policy for an address or the thread.
 *
 * Always reports MPOL_DEFAULT (0) and node 0.  Honours MPOL_F_MEMS_ALLOWED:
 * returns a nodemask with bit 0 set (one node: node 0).
 */
long sys_get_mempolicy(int *mode_out, unsigned long *nodemask_out,
                       unsigned long maxnode, unsigned long addr,
                       unsigned int flags) {
    (void)addr;

    /* MPOL_F_NODE: report node number for addr (always 0 here). Otherwise
     * report the policy mode (always MPOL_DEFAULT). Either way the value
     * lives in mode_out. */
    int mode_val = (flags & MPOL_F_NODE) ? 0 : MPOL_DEFAULT;

    if (mode_out) {
        if (mempol_copy_to_user(mode_out, &mode_val, sizeof(mode_val)) != 0)
            return -EFAULT;
    }

    if (nodemask_out && maxnode > 0) {
        unsigned long words = (maxnode + (8 * sizeof(unsigned long) - 1))
                              / (8 * sizeof(unsigned long));
        /* Build the response in a small kernel buffer first; only commit
         * via copy_to_user. Bit 0 set (node 0 present), all other bits
         * clear. Cap at MEMPOL_NODEMASK_WORDS to bound stack usage and
         * reject absurd maxnode values. */
        enum { MEMPOL_NODEMASK_WORDS = 16 };  /* 1024 nodes max */
        if (words > MEMPOL_NODEMASK_WORDS)
            return -EINVAL;
        unsigned long buf[MEMPOL_NODEMASK_WORDS] = {0};
        buf[0] = 1UL;
        if (mempol_copy_to_user(nodemask_out, buf,
                                words * sizeof(unsigned long)) != 0)
            return -EFAULT;
    }

    return 0;
}
