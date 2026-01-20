/* fut_capability.h - Futura OS Capability System Interface
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * High-level capability syscall interface for capability-based security.
 * Provides file operations, handle transfer, and capability validation.
 *
 * This layer builds on top of fut_object.h to provide POSIX-compatible
 * capability syscalls needed for FSD integration (Phase 1).
 */

#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <kernel/fut_object.h>

/* Forward declarations */
struct fut_task;
struct stat;

/* ============================================================
 *   Capability Rights Helper Macros
 * ============================================================ */

/* Standard file rights combinations */
#define FUT_CAP_FILE_READ_ONLY      (FUT_RIGHT_READ | FUT_RIGHT_DESTROY)
#define FUT_CAP_FILE_WRITE_ONLY     (FUT_RIGHT_WRITE | FUT_RIGHT_DESTROY)
#define FUT_CAP_FILE_READ_WRITE     (FUT_RIGHT_READ | FUT_RIGHT_WRITE | FUT_RIGHT_DESTROY)
#define FUT_CAP_FILE_ALL            (FUT_RIGHT_READ | FUT_RIGHT_WRITE | FUT_RIGHT_ADMIN | FUT_RIGHT_DESTROY)

/* Directory rights combinations */
#define FUT_CAP_DIR_READ            (FUT_RIGHT_READ | FUT_RIGHT_DESTROY)
#define FUT_CAP_DIR_MODIFY          (FUT_RIGHT_WRITE | FUT_RIGHT_ADMIN | FUT_RIGHT_DESTROY)
#define FUT_CAP_DIR_ALL             (FUT_RIGHT_READ | FUT_RIGHT_WRITE | FUT_RIGHT_ADMIN | FUT_RIGHT_DESTROY)

/* Rights validation macros */
#define FUT_CAP_HAS_RIGHT(rights, required)     (((rights) & (required)) == (required))
#define FUT_CAP_CAN_READ(rights)                FUT_CAP_HAS_RIGHT(rights, FUT_RIGHT_READ)
#define FUT_CAP_CAN_WRITE(rights)               FUT_CAP_HAS_RIGHT(rights, FUT_RIGHT_WRITE)
#define FUT_CAP_CAN_ADMIN(rights)               FUT_CAP_HAS_RIGHT(rights, FUT_RIGHT_ADMIN)
#define FUT_CAP_CAN_SHARE(rights)               FUT_CAP_HAS_RIGHT(rights, FUT_RIGHT_SHARE)
#define FUT_CAP_CAN_DESTROY(rights)             FUT_CAP_HAS_RIGHT(rights, FUT_RIGHT_DESTROY)

/* Rights restriction (create subset of rights) */
#define FUT_CAP_RESTRICT(original, allowed)     ((original) & (allowed))

/* ============================================================
 *   Capability File Operations (Phase 1 Syscalls)
 * ============================================================ */

/**
 * Open a file and return a capability handle.
 *
 * Similar to open(2) but returns a capability handle instead of FD.
 * Rights are determined by flags (O_RDONLY, O_WRONLY, O_RDWR).
 *
 * @param path      File path
 * @param flags     Open flags (O_RDONLY, O_WRONLY, O_RDWR, O_CREAT, etc.)
 * @param mode      File creation mode (if O_CREAT specified)
 * @return Capability handle, or FUT_INVALID_HANDLE on error
 */
fut_handle_t fut_cap_open(const char *path, int flags, int mode);

/**
 * Read from a capability handle.
 *
 * Validates READ rights before allowing operation.
 *
 * @param handle    File capability handle
 * @param buffer    Buffer to read into
 * @param count     Number of bytes to read
 * @return Number of bytes read, or negative error code
 */
long fut_cap_read(fut_handle_t handle, void *buffer, size_t count);

/**
 * Write to a capability handle.
 *
 * Validates WRITE rights before allowing operation.
 *
 * @param handle    File capability handle
 * @param buffer    Buffer to write from
 * @param count     Number of bytes to write
 * @return Number of bytes written, or negative error code
 */
long fut_cap_write(fut_handle_t handle, const void *buffer, size_t count);

/**
 * Seek within a capability handle.
 *
 * @param handle    File capability handle
 * @param offset    Offset to seek to
 * @param whence    SEEK_SET, SEEK_CUR, or SEEK_END
 * @return New file position, or negative error code
 */
long fut_cap_lseek(fut_handle_t handle, int64_t offset, int whence);

/**
 * Sync a capability handle to storage.
 *
 * Validates WRITE rights before allowing operation.
 *
 * @param handle    File capability handle
 * @return 0 on success, or negative error code
 */
int fut_cap_fsync(fut_handle_t handle);

/**
 * Get file status from capability handle.
 *
 * Validates handle is valid (no specific rights required for metadata).
 *
 * @param handle    File capability handle
 * @param statbuf   Output buffer for file status
 * @return 0 on success, or negative error code
 */
int fut_cap_fstat(fut_handle_t handle, struct stat *statbuf);

/**
 * Close a capability handle.
 *
 * Validates DESTROY rights before allowing operation.
 * Decrements reference count and frees resources when reaching zero.
 *
 * @param handle    Capability handle to close
 * @return 0 on success, or negative error code
 */
int fut_cap_close(fut_handle_t handle);

/* ============================================================
 *   Directory Operations with Capabilities (Phase 1 Syscalls)
 * ============================================================ */

/**
 * Create directory relative to parent capability handle.
 *
 * Validates parent handle has WRITE|ADMIN rights.
 *
 * @param parent_handle  Parent directory capability handle
 * @param name          Name of new directory (not full path)
 * @param mode          Directory creation mode
 * @return 0 on success, or negative error code
 */
int fut_cap_mkdirat(fut_handle_t parent_handle, const char *name, int mode);

/**
 * Remove directory relative to parent capability handle.
 *
 * Validates parent handle has ADMIN rights.
 *
 * @param parent_handle  Parent directory capability handle
 * @param name          Name of directory to remove
 * @return 0 on success, or negative error code
 */
int fut_cap_rmdirat(fut_handle_t parent_handle, const char *name);

/**
 * Remove file relative to parent capability handle.
 *
 * Validates parent handle has ADMIN rights.
 *
 * @param parent_handle  Parent directory capability handle
 * @param name          Name of file to remove
 * @return 0 on success, or negative error code
 */
int fut_cap_unlinkat(fut_handle_t parent_handle, const char *name);

/**
 * Get file status relative to parent capability handle.
 *
 * Validates parent handle has READ rights.
 *
 * @param parent_handle  Parent directory capability handle
 * @param name          Name of file to stat
 * @param statbuf       Output buffer for file status
 * @return 0 on success, or negative error code
 */
int fut_cap_statat(fut_handle_t parent_handle, const char *name, struct stat *statbuf);

/* ============================================================
 *   Capability Handle Transfer (Phase 1 IPC Primitives)
 * ============================================================ */

/**
 * Send a capability handle to another process.
 *
 * Creates a new handle in the target process with specified rights.
 * Source handle rights can be restricted when sharing.
 *
 * @param target_pid    Target process PID
 * @param source_handle Source capability handle
 * @param shared_rights Rights to grant to target (must be subset of source)
 * @return New handle in target process, or FUT_INVALID_HANDLE on error
 */
fut_handle_t fut_cap_handle_send(uint64_t target_pid, fut_handle_t source_handle,
                                 fut_rights_t shared_rights);

/**
 * Receive a capability handle from another process.
 *
 * Blocks until a handle is received from the specified process.
 *
 * @param source_pid    Source process PID (0 = any process)
 * @param received_rights Output: rights of received handle
 * @return Received capability handle, or FUT_INVALID_HANDLE on error
 */
fut_handle_t fut_cap_handle_recv(uint64_t source_pid, fut_rights_t *received_rights);

/**
 * Duplicate a capability handle with optionally reduced rights.
 *
 * Creates a new handle to the same object with same or reduced rights.
 * Useful for creating restricted handles within the same process.
 *
 * @param source_handle Source capability handle
 * @param new_rights    Rights for new handle (must be subset of source)
 * @return New capability handle, or FUT_INVALID_HANDLE on error
 */
fut_handle_t fut_cap_handle_dup(fut_handle_t source_handle, fut_rights_t new_rights);

/* ============================================================
 *   Capability Validation Helpers
 * ============================================================ */

/**
 * Validate that a capability handle has required rights.
 *
 * @param handle        Capability handle to validate
 * @param required_rights Rights that must be present
 * @return true if handle has all required rights, false otherwise
 */
bool fut_cap_validate(fut_handle_t handle, fut_rights_t required_rights);

/**
 * Get the rights associated with a capability handle.
 *
 * @param handle    Capability handle
 * @return Rights bitfield, or FUT_RIGHT_NONE if invalid handle
 */
fut_rights_t fut_cap_get_rights(fut_handle_t handle);

/**
 * Convert open flags to capability rights.
 *
 * Helper to determine rights from POSIX open() flags.
 *
 * @param flags     Open flags (O_RDONLY, O_WRONLY, O_RDWR, etc.)
 * @return Appropriate capability rights
 */
fut_rights_t fut_cap_flags_to_rights(int flags);

/* ============================================================
 *   Capability System Initialization
 * ============================================================ */

/**
 * Initialize the capability system.
 *
 * Must be called during kernel initialization after fut_object_system_init().
 */
void fut_cap_system_init(void);

/**
 * Print capability system statistics (debug).
 *
 * @param task  Task to print stats for (NULL = system-wide stats)
 */
void fut_cap_print_stats(struct fut_task *task);

#endif /* FUT_CAPABILITY_H */
