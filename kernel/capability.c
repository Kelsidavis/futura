/* kernel/capability.c - Capability-based Access Control (C23)
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements capability validation engine for filesystem operations.
 * Enforces operation types, scope restrictions, and object type checks.
 */

#include <kernel/fut_capability.h>
#include <kernel/fut_vfs.h>
#include <kernel/errno.h>
#include <string.h>

extern void fut_printf(const char *fmt, ...);

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
 *   File Descriptor Validation
 * ============================================================ */

/* Get file type for a file descriptor.
 * Returns file type bits or 0 on error.
 */
static uint64_t get_fd_type(int fd) {
    extern struct fut_file *vfs_get_file(int fd);
    struct fut_file *f = vfs_get_file(fd);
    if (!f || !f->vnode) {
        return 0;
    }

    /* Determine file type from vnode type */
    switch (f->vnode->type) {
    case VN_REG:
        return FUT_CAP_OBJTYPE_REGULAR_FILE;
    case VN_DIR:
        return FUT_CAP_OBJTYPE_DIRECTORY;
    case VN_LNK:
        return FUT_CAP_OBJTYPE_SYMLINK;
    case VN_CHR:
        return FUT_CAP_OBJTYPE_CHRDEV;
    case VN_BLK:
        return FUT_CAP_OBJTYPE_BLKDEV;
    default:
        return 0;
    }
}

/* Check if FD matches object type restrictions.
 * Returns 0 if FD matches, -EACCES if not.
 */
static int check_fd_objtype(int fd, uint64_t required_types) {
    uint64_t fd_type = get_fd_type(fd);

    if (!fd_type) {
        return -EBADF;
    }

    /* No object type restrictions */
    if (required_types == FUT_CAP_OBJTYPE_ANY) {
        return 0;
    }

    /* Check if FD type matches any required type */
    if (!(fd_type & required_types)) {
        return -EACCES;
    }

    return 0;
}

/* ============================================================
 *   Permission Scope Validation
 * ============================================================ */

/* Permission checks are performed at operation level by calling functions */
static inline int check_permission_scopes_unused(uint64_t cap, uint32_t scopes) {
    (void)cap;
    (void)scopes;
    return 0;
}
#define check_permission_scopes(c, s) check_permission_scopes_unused(c, s)

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

    /* Extract object type restrictions (bits 32-47 as uint64_t) */
    uint64_t objtypes = ((cap >> 32) & 0xFFFFULL);

    /* Check FD against object type restrictions */
    if (objtypes != 0) {  /* 0 means no restriction */
        return check_fd_objtype(fd, objtypes);
    }

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
    fut_printf("[CAPABILITY] Capability subsystem initialized\n");
}

/* ============================================================
 *   Capability Check Helpers for FSD Handlers
 * ============================================================ */

/**
 * Helper for FSD handlers: validate operation capability.
 * Used by all FIPC message handlers for fast-path validation.
 *
 * @param cap        Capability from FIPC message
 * @param required   Required operation (FUT_CAP_*)
 * @return 0 on success, -EACCES on failure
 */
int fut_cap_check_operation(uint64_t cap, uint32_t required) {
    return fut_capability_validate(cap, required);
}

/**
 * Helper for FSD handlers: validate path access.
 * Used by path-based handlers (open, mkdir, unlink, etc).
 *
 * @param cap        Capability from FIPC message
 * @param path       Path to validate
 * @return 0 on success, -EACCES on failure
 */
int fut_cap_check_path(uint64_t cap, const char *path) {
    return fut_capability_validate_path(cap, path);
}

/**
 * Helper for FSD handlers: validate FD access.
 * Used by FD-based handlers (read, write, seek, etc).
 *
 * @param cap        Capability from FIPC message
 * @param fd         File descriptor to validate
 * @return 0 on success, -EACCES on failure
 */
int fut_cap_check_fd(uint64_t cap, int fd) {
    return fut_capability_validate_fd(cap, fd);
}

/**
 * Helper for FSD handlers: check if write operation is allowed.
 * Validates both operation capability and read-only scope.
 *
 * @param cap        Capability from FIPC message
 * @return 0 if write allowed, -EACCES if read-only, -EINVAL if no capability
 */
int fut_cap_check_write(uint64_t cap) {
    /* Check write operation capability */
    if (fut_cap_check_operation(cap, FUT_CAP_WRITE_FILE) != 0) {
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
