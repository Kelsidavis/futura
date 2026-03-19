/* kernel/sys_landlock.c - Linux Landlock LSM and related stubs
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Stub implementations for Linux 5.13-5.16 syscalls that are not yet
 * implemented in Futura.  Each returns -ENOSYS so callers can fall back
 * gracefully (e.g. container sandboxes skip landlock, Wine/Proton uses
 * alternative synchronisation paths).
 *
 * Syscall numbers (Linux x86_64 / ARM64):
 *   landlock_create_ruleset  444
 *   landlock_add_rule        445
 *   landlock_restrict_self   446
 *   memfd_secret             447
 *   futex_waitv              449   (Linux 5.16)
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
