/* fut_capability.h - Futura OS Capability Model (C23)
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Capability-based access control for filesystem operations and IPC.
 * Capabilities are 64-bit values with structured bit layout:
 *
 * Bit Layout:
 *   Bits 0-15:   Operation type (FUT_CAP_*)
 *   Bits 16-31:  Scope/context flags
 *   Bits 32-47:  Object type restrictions
 *   Bits 48-63:  Reserved for future use
 */

#pragma once

#include <stdint.h>
#include <stdbool.h>

/* ============================================================
 *   Capability Operation Types (Bits 0-15)
 * ============================================================ */

/* Filesystem Operations */
#define FUT_CAP_OPEN_FILE       0x0001   /* Open/create files */
#define FUT_CAP_READ_FILE       0x0002   /* Read file contents */
#define FUT_CAP_WRITE_FILE      0x0004   /* Write file contents */
#define FUT_CAP_DELETE_FILE     0x0008   /* Delete/unlink files */
#define FUT_CAP_STAT_FILE       0x0010   /* Stat/query file metadata */
#define FUT_CAP_SEEK_FILE       0x0020   /* Seek within files */
#define FUT_CAP_FSYNC           0x0040   /* Sync file to disk */
#define FUT_CAP_CLOSE_FILE      0x0080   /* Close file descriptors */

/* Directory Operations */
#define FUT_CAP_CREATE_DIR      0x0100   /* Create directories */
#define FUT_CAP_DELETE_DIR      0x0200   /* Delete directories */
#define FUT_CAP_LIST_DIR        0x0400   /* Enumerate directory contents */

/* Permission Operations */
#define FUT_CAP_CHMOD_FILE      0x0800   /* Change file permissions */
#define FUT_CAP_CHOWN_FILE      0x1000   /* Change file ownership */

/* Client Management */
#define FUT_CAP_REGISTER        0x2000   /* Register as FSD client */
#define FUT_CAP_UNREGISTER      0x4000   /* Unregister from FSD */

/* Combined Operation Masks */
#define FUT_CAP_READ_OPS        (FUT_CAP_READ_FILE | FUT_CAP_STAT_FILE | FUT_CAP_LIST_DIR)
#define FUT_CAP_WRITE_OPS       (FUT_CAP_WRITE_FILE | FUT_CAP_DELETE_FILE | \
                                FUT_CAP_CHMOD_FILE | FUT_CAP_CHOWN_FILE)
#define FUT_CAP_ALL_FILE_OPS    (FUT_CAP_OPEN_FILE | FUT_CAP_READ_FILE | \
                                FUT_CAP_WRITE_FILE | FUT_CAP_DELETE_FILE | \
                                FUT_CAP_STAT_FILE | FUT_CAP_SEEK_FILE | \
                                FUT_CAP_FSYNC | FUT_CAP_CLOSE_FILE | \
                                FUT_CAP_CREATE_DIR | FUT_CAP_DELETE_DIR | \
                                FUT_CAP_LIST_DIR | FUT_CAP_CHMOD_FILE | \
                                FUT_CAP_CHOWN_FILE)

/* ============================================================
 *   Capability Scope Flags (Bits 16-31)
 * ============================================================ */

/* Path scope restrictions */
#define FUT_CAP_SCOPE_ROOT_ONLY       0x00010000  /* Restrict to root mount only */
#define FUT_CAP_SCOPE_HOME_ONLY       0x00020000  /* Restrict to user home dir */
#define FUT_CAP_SCOPE_TMP_ONLY        0x00040000  /* Restrict to /tmp only */
#define FUT_CAP_SCOPE_SYSTEM_ONLY     0x00080000  /* Restrict to /sys only */

/* Data access restrictions */
#define FUT_CAP_SCOPE_READ_ONLY       0x00100000  /* Read-only access */
#define FUT_CAP_SCOPE_EXECUTE_ONLY    0x00200000  /* Execute-only access */

/* Permission restrictions */
#define FUT_CAP_SCOPE_NO_PRIVESC      0x00400000  /* Prevent privilege escalation */
#define FUT_CAP_SCOPE_NO_PERMISSION_CHANGE 0x00800000  /* Prevent chmod/chown */

/* Timing restrictions */
#define FUT_CAP_SCOPE_TIME_LIMITED    0x01000000  /* Capability expires */

/* ============================================================
 *   Capability Object Type Restrictions (Bits 32-47)
 * ============================================================ */

#define FUT_CAP_OBJTYPE_ANY           0ULL  /* No restriction */
#define FUT_CAP_OBJTYPE_REGULAR_FILE  (1ULL << 32)  /* Regular files only */
#define FUT_CAP_OBJTYPE_DIRECTORY     (2ULL << 32)  /* Directories only */
#define FUT_CAP_OBJTYPE_SYMLINK       (4ULL << 32)  /* Symlinks only */
#define FUT_CAP_OBJTYPE_CHRDEV        (8ULL << 32)  /* Character devices only */
#define FUT_CAP_OBJTYPE_BLKDEV        (16ULL << 32)  /* Block devices only */

/* ============================================================
 *   Capability Expiry Time (Bits 48-63)
 * ============================================================ */

/**
 * Extract expiry time from capability (minutes since boot).
 * Returns 0 if not time-limited.
 * Max value: 65535 minutes (~45 days)
 */
#define FUT_CAP_GET_EXPIRY(cap) \
    (((cap) >> 48) & 0xFFFFULL)

/**
 * Set expiry time in capability (minutes since boot).
 * @param minutes Minutes until expiry (0-65535)
 */
#define FUT_CAP_SET_EXPIRY(cap, minutes) \
    (((cap) & 0x0000FFFFFFFFFFFFULL) | (((uint64_t)(minutes) & 0xFFFFULL) << 48))

/* ============================================================
 *   Capability Validation Macros
 * ============================================================ */

/**
 * Check if a capability has a specific operation right.
 * @param cap Capability to check
 * @param required Required operation type (FUT_CAP_*)
 * @return true if capability includes operation, false otherwise
 */
#define FUT_CAP_HAS_OP(cap, required) \
    (((cap) & 0xFFFF) & (required))

/**
 * Check if a capability has all required operations.
 * @param cap Capability to check
 * @param required Bitmask of required operations
 * @return true if capability includes all operations, false otherwise
 */
#define FUT_CAP_HAS_ALL_OPS(cap, required) \
    (((cap) & 0xFFFF & (required)) == (required))

/**
 * Check if a capability has any of multiple required operations.
 * @param cap Capability to check
 * @param required Bitmask of operations (any one satisfies)
 * @return true if capability includes any operation, false otherwise
 */
#define FUT_CAP_HAS_ANY_OPS(cap, required) \
    (((cap) & 0xFFFF & (required)) != 0)

/**
 * Extract capability scope flags.
 * @param cap Capability value
 * @return Scope flags (bits 16-31)
 */
#define FUT_CAP_GET_SCOPE(cap) \
    (((cap) >> 16) & 0xFFFF)

/**
 * Check if capability has a specific scope restriction.
 * @param cap Capability to check
 * @param scope Scope flag (FUT_CAP_SCOPE_*)
 * @return true if scope flag is set, false otherwise
 */
#define FUT_CAP_HAS_SCOPE(cap, scope) \
    ((FUT_CAP_GET_SCOPE(cap) & (scope)) == (scope))

/**
 * Extract object type restrictions.
 * @param cap Capability value
 * @return Object type mask (bits 32-47)
 */
#define FUT_CAP_GET_OBJTYPE(cap) \
    (((cap) >> 32) & 0xFFFFULL)

/* File mode compatibility definitions for kernel */
#define VN_INVALID_TYPE  0
#define VN_REG_TYPE      1
#define VN_DIR_TYPE      2
#define VN_CHR_TYPE      3
#define VN_BLK_TYPE      4
#define VN_FIFO_TYPE     5
#define VN_LNK_TYPE      6
#define VN_SOCK_TYPE     7

/**
 * Fail-fast capability validation macro for handlers.
 * @param cap Capability from message
 * @param required Required operation type
 * Usage: if (!FUT_CAP_VALIDATE_FAST(msg->capability, FUT_CAP_OPEN_FILE)) return -EACCES;
 */
#define FUT_CAP_VALIDATE_FAST(cap, required) \
    (FUT_CAP_HAS_OP((cap), (required)) != 0)

/* ============================================================
 *   Capability Validation API
 * ============================================================ */

/**
 * Validate if a capability grants a specific operation.
 *
 * Performs full validation including:
 * - Operation type check
 * - Scope restriction check
 * - Object type check
 * - Time-based restrictions (if any)
 *
 * @param cap        64-bit capability value
 * @param required   Required operation type (FUT_CAP_*)
 * @return 0 if capability is valid, negative error code on failure
 *         -EACCES if operation not permitted
 *         -ENOTSUP if scope restriction prevents operation
 */
int fut_capability_validate(uint64_t cap, uint32_t required);

/**
 * Validate if a capability grants access to a specific path.
 *
 * Checks scope restrictions (e.g., root-only, home-only) against path.
 *
 * @param cap        64-bit capability value
 * @param path       File path to validate against
 * @return 0 if path is accessible, -EACCES if restricted
 */
int fut_capability_validate_path(uint64_t cap, const char *path);

/**
 * Validate if a capability grants access to a file descriptor.
 *
 * Checks object type restrictions and operation permissions.
 *
 * @param cap        64-bit capability value
 * @param fd         File descriptor to validate
 * @return 0 if FD is accessible, -EACCES if restricted
 */
int fut_capability_validate_fd(uint64_t cap, int fd);

/**
 * Create a new capability with specified operations and scopes.
 *
 * Utility function for constructing capabilities programmatically.
 *
 * @param ops        Bitmask of operations (FUT_CAP_*)
 * @param scopes     Bitmask of scope flags (FUT_CAP_SCOPE_*)
 * @param objtypes   Bitmask of object types (FUT_CAP_OBJTYPE_*)
 * @return Constructed 64-bit capability value
 */
uint64_t fut_capability_create(uint32_t ops, uint32_t scopes, uint32_t objtypes);

/**
 * Create a time-limited capability that expires after specified duration.
 *
 * @param ops            Bitmask of operations (FUT_CAP_*)
 * @param scopes         Bitmask of scope flags (FUT_CAP_SCOPE_*)
 * @param objtypes       Bitmask of object types (FUT_CAP_OBJTYPE_*)
 * @param minutes_valid  Minutes until expiry (1-65535, max ~45 days)
 * @return Constructed 64-bit capability value with TIME_LIMITED scope and expiry set
 */
uint64_t fut_capability_create_timed(uint32_t ops, uint32_t scopes, uint32_t objtypes, uint32_t minutes_valid);

/**
 * Check if capability is expired (if time-limited).
 *
 * @param cap        64-bit capability value
 * @return 0 if valid, -EEXPIRE if expired
 */
int fut_capability_check_expiry(uint64_t cap);

/**
 * Initialize capability subsystem (called at kernel startup).
 */
void fut_capability_init(void);

/**
 * Check if capability allows write operations.
 *
 * Validates that the capability:
 * 1. Has write operation bits set
 * 2. Does not have READ_ONLY scope restriction
 *
 * @param cap        64-bit capability value
 * @return 0 if write allowed, -EACCES if read-only or no write permission
 */
int fut_cap_check_write(uint64_t cap);

/**
 * Check if capability allows permission changes (chmod/chown).
 *
 * Validates that the capability does not have NO_PERMISSION_CHANGE scope.
 *
 * @param cap        64-bit capability value
 * @return 0 if permission changes allowed, -EACCES if restricted
 */
int fut_cap_check_permission_change(uint64_t cap);

/* ============================================================
 *   Convenience Inline Helpers
 * ============================================================ */

/**
 * Check if capability is null/uninitialized.
 */
static inline bool fut_capability_is_null(uint64_t cap) {
    return cap == 0;
}

/**
 * Check if capability grants all filesystem operations.
 */
static inline bool fut_capability_is_superuser(uint64_t cap) {
    return FUT_CAP_HAS_ALL_OPS(cap, FUT_CAP_ALL_FILE_OPS) &&
           !FUT_CAP_HAS_SCOPE(cap, 0xFFFF);  /* No scope restrictions */
}

/**
 * Check if capability is read-only.
 */
static inline bool fut_capability_is_readonly(uint64_t cap) {
    return FUT_CAP_HAS_SCOPE(cap, FUT_CAP_SCOPE_READ_ONLY);
}
