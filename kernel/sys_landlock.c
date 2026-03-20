/* kernel/sys_landlock.c - Linux Landlock LSM and newer syscall stubs
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Stub implementations for Linux 5.10-6.10 syscalls not yet in Futura.
 * Each returns -ENOSYS (or 0 for no-op-safe ops) so callers fall back.
 *
 * Linux x86_64 syscall numbers:
 *   landlock_create_ruleset  444   (Linux 5.13)
 *   landlock_add_rule        445   (Linux 5.13)
 *   landlock_restrict_self   446   (Linux 5.13)
 *   memfd_secret             447   (Linux 5.14)
 *   futex_waitv              449   (Linux 5.16)
 *   process_madvise          440   (Linux 5.10) — remapped in Futura
 *   set_mempolicy_home_node  450   (Linux 5.17) — remapped in Futura
 *   cachestat                451   (Linux 6.5)  — remapped in Futura
 *   fchmodat2                452   (Linux 6.6)  — remapped in Futura
 *   mseal                    459   (Linux 6.10) — remapped in Futura
 */

#include <kernel/errno.h>
#include <stdint.h>
#include <stddef.h>

/**
 * sys_landlock_create_ruleset() - Create a new Landlock ruleset.
 * Returns -ENOSYS; callers fall back to a permissive sandbox model.
 */
long sys_landlock_create_ruleset(const void *attr, size_t size,
                                 uint32_t flags) {
    (void)attr; (void)size; (void)flags;
    return -ENOSYS;
}

/**
 * sys_landlock_add_rule() - Add a rule to a Landlock ruleset fd.
 * Returns -ENOSYS.
 */
long sys_landlock_add_rule(int ruleset_fd, unsigned int rule_type,
                           const void *rule_attr, uint32_t flags) {
    (void)ruleset_fd; (void)rule_type; (void)rule_attr; (void)flags;
    return -ENOSYS;
}

/**
 * sys_landlock_restrict_self() - Apply a Landlock ruleset to the caller.
 * Returns -ENOSYS.
 */
long sys_landlock_restrict_self(int ruleset_fd, uint32_t flags) {
    (void)ruleset_fd; (void)flags;
    return -ENOSYS;
}

/**
 * sys_memfd_secret() - Create a memory area excluded from core dumps.
 * Returns -ENOSYS; callers fall back to regular anonymous mappings.
 */
long sys_memfd_secret(unsigned int flags) {
    (void)flags;
    return -ENOSYS;
}

/**
 * sys_futex_waitv() - Wait on multiple futexes simultaneously (Wine/Proton).
 * Returns -ENOSYS; callers fall back to sequential futex waits.
 */
long sys_futex_waitv(const void *waiters, unsigned int nr_futexes,
                     unsigned int flags, const void *timeout,
                     int32_t clockid) {
    (void)waiters; (void)nr_futexes; (void)flags; (void)timeout; (void)clockid;
    return -ENOSYS;
}

/**
 * sys_process_madvise() - Apply madvise() hints to another process.
 * Returns -ENOSYS; callers (Android LMKD, systemd-oomd) fall back.
 */
long sys_process_madvise(int pidfd, const void *iovec, unsigned long vlen,
                         int advice, unsigned int flags) {
    (void)pidfd; (void)iovec; (void)vlen; (void)advice; (void)flags;
    return -ENOSYS;
}

/**
 * sys_set_mempolicy_home_node() - Set home node for NUMA memory policy.
 * Returns -ENOSYS; Futura has no NUMA topology.
 */
long sys_set_mempolicy_home_node(unsigned long start, unsigned long len,
                                 unsigned long home_node, unsigned long flags) {
    (void)start; (void)len; (void)home_node; (void)flags;
    return -ENOSYS;
}

/**
 * sys_cachestat() - Query page-cache status for a file range.
 * Returns -ENOSYS; Futura has no page cache.
 */
long sys_cachestat(unsigned int fd, const void *cachestat_range,
                   void *cachestat_buf, unsigned int flags) {
    (void)fd; (void)cachestat_range; (void)cachestat_buf; (void)flags;
    return -ENOSYS;
}

/**
 * sys_fchmodat2() - Change file permissions (Linux 6.6+, with flag support).
 * Delegates to sys_fchmodat; the main addition is AT_SYMLINK_NOFOLLOW which
 * already returns ENOTSUP from fchmodat (symlinks have no permissions).
 */
long sys_fchmodat2(int dirfd, const char *pathname, unsigned int mode,
                   unsigned int flags) {
    extern long sys_fchmodat(int dirfd, const char *pathname, uint32_t mode, int flags);
    return sys_fchmodat(dirfd, pathname, (uint32_t)mode, (int)flags);
}

/**
 * sys_mseal() - Seal a memory mapping against future changes.
 * Returns 0 (success, no-op); glibc 2.38+ uses this to seal its own segments
 * and ignores ENOSYS, but returning 0 is more accurate from the caller's view.
 */
long sys_mseal(void *addr, size_t len, unsigned long flags) {
    (void)addr; (void)len; (void)flags;
    return 0;
}

/**
 * sys_add_key() - Add a key to the Linux keyring.
 * Returns -ENOSYS; programs (ssh, PAM, OpenSSL) fall back to file-based creds.
 */
long sys_add_key(const char *type, const char *description,
                 const void *payload, size_t plen, int keyring) {
    (void)type; (void)description; (void)payload; (void)plen; (void)keyring;
    return -ENOSYS;
}

/**
 * sys_request_key() - Request a key from the kernel keyring.
 * Returns -ENOSYS.
 */
long sys_request_key(const char *type, const char *description,
                     const char *callout_info, int dest_keyring) {
    (void)type; (void)description; (void)callout_info; (void)dest_keyring;
    return -ENOSYS;
}

/**
 * sys_keyctl() - Operate on the Linux keyring.
 * Returns -ENOSYS; callers must handle absence of kernel keyring.
 */
long sys_keyctl(int operation, unsigned long arg2, unsigned long arg3,
                unsigned long arg4, unsigned long arg5) {
    (void)operation; (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return -ENOSYS;
}
