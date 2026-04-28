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
/* Linux's MPOL_MODE_FLAGS occupy the high bits of the mode argument
 * and are stripped before MPOL_MAX validation in kernel_mbind /
 * kernel_set_mempolicy. */
#define MPOL_F_STATIC_NODES    0x8000
#define MPOL_F_RELATIVE_NODES  0x4000
#define MPOL_MODE_FLAGS        (MPOL_F_STATIC_NODES | MPOL_F_RELATIVE_NODES)

static inline long mempol_validate_mode(int mode) {
    int mode_flags = mode & MPOL_MODE_FLAGS;
    int lmode = mode & ~MPOL_MODE_FLAGS;
    if (lmode < 0 || lmode >= MPOL_MAX)
        return -EINVAL;
    if ((mode_flags & MPOL_F_STATIC_NODES) &&
        (mode_flags & MPOL_F_RELATIVE_NODES))
        return -EINVAL;
    return 0;
}

/* Linux's get_nodes (mm/mempolicy.c) rejects an absurd maxnode up
 * front:
 *   if (maxnode > PAGE_SIZE * BITS_PER_BYTE)
 *       return -EINVAL;
 * The cap is 32768 on 4 KB-page architectures.  Without this check
 * an unprivileged caller can request a multi-megabyte nodemask
 * decode pass that Linux refuses outright; userspace probes that
 * detect 'kernel rejects huge maxnode' to discover the cap also
 * couldn't run on Futura.  Apply the same bound here. */
#define MEMPOL_MAXNODE_LIMIT (4096UL * 8UL)

long sys_mbind(unsigned long addr, unsigned long len, int mode,
               const unsigned long *nodemask, unsigned long maxnode,
               unsigned int flags) {
    (void)len; (void)nodemask;
    /* Linux's kernel_mbind validates 'addr' page-alignment up front:
     *   start = untagged_addr(start);
     *   if (start & ~PAGE_MASK) return -EINVAL;
     * (mm/mempolicy.c).  The previous Futura stub silently ignored
     * addr alignment, so a libnuma probe passing a deliberately
     * misaligned address to detect kernel-side validation got success
     * where Linux returns EINVAL — masking the parameter-domain
     * error class.  addr == 0 stays valid (page-aligned by definition,
     * preserving the test 1183 contract). */
    if (addr & ((uintptr_t)PAGE_SIZE - 1))
        return -EINVAL;
    /* Linux's kernel_mbind strips MPOL_MODE_FLAGS (MPOL_F_STATIC_NODES
     * | MPOL_F_RELATIVE_NODES, mask 0xC000) from mode before validating
     * against MPOL_MAX, and rejects the two mode_flags being set
     * together.  The previous code rejected any value with the high
     * bits set, so MPOL_DEFAULT|MPOL_F_STATIC_NODES (a documented
     * combination) returned EINVAL where Linux accepts it. */
    if (maxnode > MEMPOL_MAXNODE_LIMIT)
        return -EINVAL;
    /* Linux's kernel_mbind validates flags against MPOL_MF_VALID
     * (MPOL_MF_STRICT | MPOL_MF_MOVE | MPOL_MF_MOVE_ALL) and rejects
     * unknown bits with -EINVAL:
     *   if (flags & ~(unsigned int)MPOL_MF_VALID) return -EINVAL;
     * The previous Futura code silently ignored every flag bit, so a
     * caller probing for future MPOL_MF_* additions saw 'success'
     * regardless of the requested flag — masking the parameter-domain
     * error class libnuma's feature-detection code-paths expect. */
    const unsigned int MPOL_MF_VALID =
        MPOL_MF_STRICT | MPOL_MF_MOVE | MPOL_MF_MOVE_ALL;
    if (flags & ~MPOL_MF_VALID)
        return -EINVAL;
    return mempol_validate_mode(mode);
}

/**
 * sys_set_mempolicy() - Set the calling thread's default NUMA policy.
 *
 * Single-node stub: MPOL_DEFAULT always accepted; other modes accepted
 * as long as they are valid policy codes (since there is only one node).
 */
long sys_set_mempolicy(int mode, const unsigned long *nodemask,
                       unsigned long maxnode) {
    (void)nodemask;
    /* Mirror sys_mbind: strip MPOL_MODE_FLAGS before validating mode
     * against MPOL_MAX, matching Linux's kernel_set_mempolicy.  Same
     * MEMPOL_MAXNODE_LIMIT cap as mbind/get_mempolicy applies. */
    if (maxnode > MEMPOL_MAXNODE_LIMIT)
        return -EINVAL;
    return mempol_validate_mode(mode);
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

    /* Linux's do_get_mempolicy rejects unknown flag bits with -EINVAL
     * before doing any work, and forbids combining MPOL_F_MEMS_ALLOWED
     * with MPOL_F_NODE or MPOL_F_ADDR. The previous code silently
     * accepted any flag bits, so a caller passing garbage flags got
     * back a "MPOL_DEFAULT" answer that masked the malformed request —
     * libc / numactl test harnesses that probe for MPOL_F_* support
     * via expected -EINVAL replies treated Futura as supporting
     * arbitrary future bits. */
    if (flags & ~(unsigned int)(MPOL_F_NODE | MPOL_F_ADDR |
                                MPOL_F_MEMS_ALLOWED))
        return -EINVAL;
    if ((flags & MPOL_F_MEMS_ALLOWED) &&
        (flags & (MPOL_F_NODE | MPOL_F_ADDR)))
        return -EINVAL;

    /* Linux's do_get_mempolicy: when MPOL_F_ADDR is NOT set, both a
     * non-zero addr and the MPOL_F_NODE flag are rejected with -EINVAL:
     *
     *   } else if (addr || (flags & MPOL_F_NODE)) {
     *       return -EINVAL;
     *   }
     *
     * MPOL_F_NODE means "report which node the addr lives on", which is
     * only meaningful when MPOL_F_ADDR is also set to identify the addr.
     * Futura previously honoured MPOL_F_NODE alone (returning node 0)
     * and silently ignored a non-zero addr without MPOL_F_ADDR — masking
     * the malformed-flag-combination error class libnuma probes via
     * `get_mempolicy(&node, NULL, 0, NULL, MPOL_F_NODE)` expect. */
    if (!(flags & MPOL_F_MEMS_ALLOWED) && !(flags & MPOL_F_ADDR) &&
        (addr || (flags & MPOL_F_NODE)))
        return -EINVAL;

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
