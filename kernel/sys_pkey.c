/* kernel/sys_pkey.c - Memory Protection Keys syscalls (Linux 4.9+)
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements pkey_alloc(), pkey_free(), and pkey_mprotect().
 *
 * Memory Protection Keys (PKU/MPK) require hardware support (OSPKE/PKU
 * CPUID bit on x86_64). Futura does not model this hardware feature, so
 * pkey_alloc() returns ENOSPC (consistent with Linux on non-PKU CPUs).
 * pkey_mprotect() accepts pkey=-1 (no key) and delegates to sys_mprotect;
 * a non-negative pkey returns EINVAL since no keys are allocated.
 * pkey_free() returns EINVAL (no keys to free).
 *
 * Linux syscall numbers (x86_64):
 *   329 = pkey_mprotect
 *   330 = pkey_alloc
 *   331 = pkey_free
 */

#include <kernel/errno.h>
#include <stddef.h>
#include <stdint.h>

/* Only PKEY_ACCESS_MASK and PKEY_DISABLE_* flags are valid */
#define PKEY_ACCESS_MASK    0x3  /* PKEY_DISABLE_ACCESS | PKEY_DISABLE_WRITE */
#define PKEY_ALLOC_FLAGS    0    /* no flags defined yet in Linux */

/**
 * sys_pkey_alloc - Allocate a protection key
 *
 * @param flags        Must be 0 (no flags defined)
 * @param access_rights Initial access rights bitmask (PKEY_DISABLE_*)
 * @return allocated key (0..15) on success; -EINVAL for bad args;
 *         -ENOSPC when no hardware PKU support or all keys in use.
 *
 * Futura has no PKU hardware: always returns -ENOSPC, matching Linux
 * behavior on CPUs that lack the OSPKE CPUID bit.
 */
long sys_pkey_alloc(unsigned int flags, unsigned int access_rights) {
    if (flags != 0)
        return -EINVAL;
    if (access_rights & ~PKEY_ACCESS_MASK)
        return -EINVAL;
    /* No PKU hardware support: no keys available */
    return -ENOSPC;
}

/**
 * sys_pkey_free - Free a previously allocated protection key
 *
 * @param pkey  Key to free (must have been allocated with pkey_alloc)
 * @return 0 on success; -EINVAL if pkey out of range or not allocated.
 *
 * Since pkey_alloc always fails on Futura, no key can ever be valid.
 */
long sys_pkey_free(int pkey) {
    /* Valid pkey range on x86_64 is 0..15 */
    if (pkey < 0 || pkey > 15)
        return -EINVAL;
    /* No key was ever allocated */
    return -EINVAL;
}

/**
 * sys_pkey_mprotect - mprotect with a protection key association
 *
 * @param addr  Page-aligned address
 * @param len   Length of region
 * @param prot  PROT_* flags (same as mprotect)
 * @param pkey  Protection key to associate; -1 means "no key"
 * @return 0 on success; -EINVAL for invalid pkey; mprotect errors otherwise.
 *
 * pkey=-1 is equivalent to plain mprotect (removes any key association).
 * Any non-negative pkey returns EINVAL since no keys are allocated.
 */
long sys_pkey_mprotect(void *addr, size_t len, int prot, int pkey) {
    if (pkey < -1 || pkey > 15)
        return -EINVAL;
    if (pkey != -1)
        return -EINVAL;  /* No allocated keys on this system */

    /* Delegate to standard mprotect */
    extern long sys_mprotect(void *addr, size_t len, int prot);
    return sys_mprotect(addr, len, prot);
}
