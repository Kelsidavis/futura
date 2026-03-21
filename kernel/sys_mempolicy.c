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
#include <stdint.h>
#include <stddef.h>

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

    /* Write mode = MPOL_DEFAULT if caller wants it */
    if (mode_out)
        *mode_out = MPOL_DEFAULT;

    /* Write nodemask if caller provided a buffer */
    if (nodemask_out && maxnode > 0) {
        /* Set bit 0 only (node 0 is present) */
        nodemask_out[0] = 1UL;
        /* Zero any remaining words the caller allocated */
        unsigned long words = (maxnode + (8 * sizeof(unsigned long) - 1))
                              / (8 * sizeof(unsigned long));
        for (unsigned long i = 1; i < words; i++)
            nodemask_out[i] = 0;
    }

    if (flags & MPOL_F_NODE) {
        /* Caller wants node number for addr; return 0 (node 0) */
        if (mode_out)
            *mode_out = 0;
    }

    return 0;
}
