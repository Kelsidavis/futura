/* libfutura/capability.c - User-space Capability Validation
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * User-space implementation of capability validation functions.
 * Provides the same API as kernel capability validation but without
 * requiring kernel-specific data structures.
 */

#include <kernel/fut_capability.h>
#include <errno.h>
#include <string.h>

/* ============================================================
 *   Path Scope Validation
 * ============================================================ */

/* Check if a path is within a scope restriction.
 * Returns 0 if path matches scope, -EACCES if not.
 */
static int check_path_scope(const char *path, uint32_t scopes) {
    if (!path) {
        return -EINVAL;
    }

    /* No scope restrictions */
    if (scopes == 0) {
        return 0;
    }

    /* Root-only scope */
    if (scopes & FUT_CAP_SCOPE_ROOT_ONLY) {
        if (path[0] != '/' || path[1] != '\0') {
            return -EACCES;
        }
    }

    /* Home-only scope (restricts to /home/, tilde, or /root) */
    if (scopes & FUT_CAP_SCOPE_HOME_ONLY) {
        if (strncmp(path, "/home/", 6) != 0 &&
            strcmp(path, "/root") != 0 &&
            path[0] != '~') {
            return -EACCES;
        }
    }

    /* /tmp-only scope */
    if (scopes & FUT_CAP_SCOPE_TMP_ONLY) {
        if (strncmp(path, "/tmp", 4) != 0) {
            return -EACCES;
        }
    }

    /* /sys-only scope */
    if (scopes & FUT_CAP_SCOPE_SYSTEM_ONLY) {
        if (strncmp(path, "/sys", 4) != 0) {
            return -EACCES;
        }
    }

    return 0;
}

/* ============================================================
 *   Capability Validation Implementations
 * ============================================================ */

int fut_capability_validate(uint64_t cap, uint32_t required) {
    /* Null capability is invalid */
    if (cap == 0) {
        return -EACCES;
    }

    /* Extract operation bits */
    uint32_t ops = cap & 0xFFFF;

    /* Check if required operation is present */
    if ((ops & required) == 0) {
        return -EACCES;
    }

    /* Extract scope flags and check for blocking restrictions */
    uint32_t scopes = FUT_CAP_GET_SCOPE(cap);
    if (scopes & FUT_CAP_SCOPE_TIME_LIMITED) {
        /* Time-based restrictions need additional check */
        if (fut_capability_check_expiry(cap) != 0) {
            return -ETIMEDOUT;  /* Use standard error code for expired capability */
        }
    }

    return 0;
}

int fut_capability_validate_path(uint64_t cap, const char *path) {
    /* Null capability cannot access any path */
    if (cap == 0) {
        return -EACCES;
    }

    /* Extract scope flags */
    uint32_t scopes = FUT_CAP_GET_SCOPE(cap);

    /* Check path against scope restrictions */
    return check_path_scope(path, scopes);
}

int fut_capability_validate_fd(uint64_t cap, int fd) {
    /* Null capability cannot access any FD */
    if (cap == 0) {
        return -EACCES;
    }

    /* Invalid FD */
    if (fd < 0) {
        return -EBADF;
    }

    /* User-space validation cannot check object types
     * as it doesn't have access to VFS structures.
     * Object type validation will be performed by the kernel
     * when the actual syscall is made.
     */

    return 0;
}

uint64_t fut_capability_create(uint32_t ops, uint32_t scopes, uint32_t objtypes) {
    uint64_t cap = 0;

    /* Pack operation bits (0-15) */
    cap |= (uint64_t)(ops & 0xFFFFULL);

    /* Pack scope bits (16-31) */
    cap |= (uint64_t)((scopes & 0xFFFFULL) << 16);

    /* Pack object type bits (32-47) */
    cap |= (uint64_t)((objtypes & 0xFFFFULL) << 32);

    /* Bits 48-63 reserved for future use */

    return cap;
}

int fut_capability_check_expiry(uint64_t cap) {
    /* Check if time-limited flag is set */
    uint32_t scopes = FUT_CAP_GET_SCOPE(cap);

    if (!(scopes & FUT_CAP_SCOPE_TIME_LIMITED)) {
        /* Not time-limited, always valid */
        return 0;
    }

    /* TODO: Implement time-based capability expiry checking.
     * This requires storing expiry timestamp somewhere accessible
     * from the capability value or from a capability table.
     * For now, all time-limited capabilities are considered valid.
     */

    return 0;
}

void fut_capability_init(void) {
    /* No-op in user space */
}

/* ============================================================
 *   Capability Check Helpers for FSD Handlers
 * ============================================================ */

/**
 * Helper for FSD handlers: check if write operation is allowed.
 * Validates both operation capability and read-only scope.
 *
 * @param cap        Capability from FIPC message
 * @return 0 if write allowed, -EACCES if read-only, -EINVAL if no capability
 */
int fut_cap_check_write(uint64_t cap) {
    /* Check write operation capability */
    if (fut_capability_validate(cap, FUT_CAP_WRITE_FILE) != 0) {
        return -EACCES;
    }

    /* Check for read-only scope restriction */
    uint32_t scopes = FUT_CAP_GET_SCOPE(cap);
    if (scopes & FUT_CAP_SCOPE_READ_ONLY) {
        return -EACCES;
    }

    return 0;
}

/**
 * Helper for FSD handlers: check if permission change is allowed.
 * Validates against privilege escalation and permission change restrictions.
 *
 * @param cap        Capability from FIPC message
 * @return 0 if allowed, -EACCES if restricted
 */
int fut_cap_check_permission_change(uint64_t cap) {
    uint32_t scopes = FUT_CAP_GET_SCOPE(cap);

    /* Prevent privilege escalation */
    if (scopes & FUT_CAP_SCOPE_NO_PRIVESC) {
        return -EACCES;
    }

    /* Prevent any permission changes */
    if (scopes & FUT_CAP_SCOPE_NO_PERMISSION_CHANGE) {
        return -EACCES;
    }

    return 0;
}
