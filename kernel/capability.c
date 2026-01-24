/* kernel/capability.c - Capability System Implementation
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements capability-based file operations and handle transfer.
 * Phase 1 implementation for FSD integration.
 */

#include <kernel/fut_capability.h>
#include <kernel/fut_object.h>
#include <kernel/fut_task.h>
#include <kernel/fut_vfs.h>
#include <kernel/fut_timer.h>
#include <kernel/errno.h>

#include <kernel/kprintf.h>

/* ============================================================
 *   Time-Based Expiry Support
 * ============================================================ */

/**
 * Get current time in minutes since boot.
 * Used for capability expiry checking.
 *
 * @return Minutes since system boot (0-65535 wraps)
 */
static uint16_t get_current_time_minutes(void) {
    uint64_t ticks_ms = fut_get_ticks();
    return (uint16_t)(ticks_ms / 60000);  /* ms -> minutes */
}

/**
 * Check if a capability has expired.
 *
 * @param cap Capability to check
 * @return 0 if valid (not expired or no time limit), -ETIMEDOUT if expired
 */
int fut_capability_check_expiry(uint64_t cap) {
    uint32_t scopes = FUT_CAP_GET_SCOPE(cap);

    /* Check if time-limited flag is set */
    if (!(scopes & FUT_CAP_SCOPE_TIME_LIMITED)) {
        /* Not time-limited, always valid */
        return 0;
    }

    uint16_t expiry = FUT_CAP_GET_EXPIRY(cap);
    if (expiry == 0) {
        /* Expiry of 0 means "never expires" for backward compatibility */
        return 0;
    }

    uint16_t current = get_current_time_minutes();

    /* Handle wraparound: if current time is significantly less than expiry,
     * it means we wrapped around the 16-bit counter (unlikely in practice
     * since 65535 minutes is ~45 days) */
    if (current > expiry) {
        /* Expired */
        return -ETIMEDOUT;
    }

    return 0;
}

/**
 * Create a time-limited capability.
 *
 * @param ops Operation flags (FUT_CAP_*)
 * @param scopes Scope flags (FUT_CAP_SCOPE_*)
 * @param objtypes Object type flags (FUT_CAP_OBJTYPE_*)
 * @param minutes_valid Duration in minutes (0 = never expires)
 * @return Constructed capability with TIME_LIMITED flag and expiry time
 */
uint64_t fut_capability_create_timed(uint32_t ops, uint32_t scopes,
                                     uint32_t objtypes, uint32_t minutes_valid) {
    /* Construct capability from components:
     * Bits 0-15: ops
     * Bits 16-31: scopes (with TIME_LIMITED flag added)
     * Bits 32-47: objtypes
     * Bits 48-63: expiry time */
    uint64_t cap = ((uint64_t)(ops & 0xFFFF)) |
                   ((uint64_t)((scopes | FUT_CAP_SCOPE_TIME_LIMITED) & 0xFFFF) << 16) |
                   ((uint64_t)(objtypes & 0xFFFF) << 32);

    if (minutes_valid > 0 && minutes_valid < 65536) {
        uint16_t current = get_current_time_minutes();
        uint16_t expiry = current + (uint16_t)minutes_valid;
        cap = FUT_CAP_SET_EXPIRY(cap, expiry);
    }

    return cap;
}

/* ============================================================
 *   System Initialization
 * ============================================================ */

void fut_cap_system_init(void) {
    fut_printf("[CAP] Capability system initialized\n");
    fut_printf("[CAP] Time-based expiry support enabled (resolution: 1 minute)\n");
}

/* ============================================================
 *   Rights Conversion Helpers
 * ============================================================ */

fut_rights_t fut_cap_flags_to_rights(int flags) {
    fut_rights_t rights = FUT_RIGHT_DESTROY;  /* Always allow close */

    /* Extract access mode from flags */
    int access_mode = flags & O_ACCMODE;

    switch (access_mode) {
        case O_RDONLY:
            rights |= FUT_RIGHT_READ;
            break;
        case O_WRONLY:
            rights |= FUT_RIGHT_WRITE;
            break;
        case O_RDWR:
            rights |= FUT_RIGHT_READ | FUT_RIGHT_WRITE;
            break;
    }

    /* O_CREAT, O_TRUNC, O_EXCL require ADMIN rights */
    if (flags & (O_CREAT | O_TRUNC | O_EXCL)) {
        rights |= FUT_RIGHT_ADMIN;
    }

    return rights;
}

fut_rights_t fut_cap_get_rights(fut_handle_t handle) {
    if (handle == FUT_INVALID_HANDLE) {
        return FUT_RIGHT_NONE;
    }

    /* Query object system for rights */
    fut_object_t *obj = fut_object_get(handle, FUT_RIGHT_NONE);
    if (!obj) {
        return FUT_RIGHT_NONE;
    }

    fut_rights_t rights = obj->rights;
    fut_object_put(obj);

    return rights;
}

bool fut_cap_validate(fut_handle_t handle, fut_rights_t required_rights) {
    return fut_object_has_rights(handle, required_rights);
}

/* ============================================================
 *   Capability File Operations (Phase 1 Syscalls)
 * ============================================================ */

fut_handle_t fut_cap_open(const char *path, int flags, int mode) {
    if (!path) {
        return FUT_INVALID_HANDLE;
    }

    /* Use VFS capability-aware open function */
    return fut_vfs_open_cap(path, flags, mode);
}

long fut_cap_read(fut_handle_t handle, void *buffer, size_t count) {
    if (handle == FUT_INVALID_HANDLE || !buffer) {
        return -EINVAL;
    }

    /* Use VFS capability-aware read function */
    return fut_vfs_read_cap(handle, buffer, count);
}

long fut_cap_write(fut_handle_t handle, const void *buffer, size_t count) {
    if (handle == FUT_INVALID_HANDLE || !buffer) {
        return -EINVAL;
    }

    /* Use VFS capability-aware write function */
    return fut_vfs_write_cap(handle, buffer, count);
}

long fut_cap_lseek(fut_handle_t handle, int64_t offset, int whence) {
    if (handle == FUT_INVALID_HANDLE) {
        return -EINVAL;
    }

    /* Use VFS capability-aware lseek function */
    return fut_vfs_lseek_cap(handle, offset, whence);
}

int fut_cap_fsync(fut_handle_t handle) {
    if (handle == FUT_INVALID_HANDLE) {
        return -EINVAL;
    }

    /* Use VFS capability-aware fsync function */
    return fut_vfs_fsync_cap(handle);
}

int fut_cap_fstat(fut_handle_t handle, struct stat *statbuf) {
    if (handle == FUT_INVALID_HANDLE || !statbuf) {
        return -EINVAL;
    }

    /* Use VFS capability-aware fstat function */
    return fut_vfs_fstat_cap(handle, (struct fut_stat *)statbuf);
}

int fut_cap_close(fut_handle_t handle) {
    if (handle == FUT_INVALID_HANDLE) {
        return -EINVAL;
    }

    /* Validate DESTROY rights */
    if (!fut_cap_validate(handle, FUT_RIGHT_DESTROY)) {
        fut_printf("[CAP] fut_cap_close: handle lacks DESTROY rights\n");
        return -EPERM;
    }

    /* Destroy the capability handle */
    int result = fut_object_destroy(handle);

    fut_printf("[CAP] fut_cap_close(handle=%llu) -> %d\n", handle, result);
    return result;
}

/* ============================================================
 *   Directory Operations with Capabilities (Phase 1 Syscalls)
 * ============================================================ */

int fut_cap_mkdirat(fut_handle_t parent_handle, const char *name, int mode) {
    if (parent_handle == FUT_INVALID_HANDLE || !name) {
        return -EINVAL;
    }

    /* Use VFS capability-aware mkdirat function */
    return fut_vfs_mkdirat_cap(parent_handle, name, mode);
}

int fut_cap_rmdirat(fut_handle_t parent_handle, const char *name) {
    if (parent_handle == FUT_INVALID_HANDLE || !name) {
        return -EINVAL;
    }

    /* Use VFS capability-aware rmdirat function */
    return fut_vfs_rmdirat_cap(parent_handle, name);
}

int fut_cap_unlinkat(fut_handle_t parent_handle, const char *name) {
    if (parent_handle == FUT_INVALID_HANDLE || !name) {
        return -EINVAL;
    }

    /* Use VFS capability-aware unlinkat function */
    return fut_vfs_unlinkat_cap(parent_handle, name);
}

int fut_cap_statat(fut_handle_t parent_handle, const char *name, struct stat *statbuf) {
    if (parent_handle == FUT_INVALID_HANDLE || !name || !statbuf) {
        return -EINVAL;
    }

    /* Use VFS capability-aware statat function */
    return fut_vfs_statat_cap(parent_handle, name, (struct fut_stat *)statbuf);
}

/* ============================================================
 *   Capability Handle Transfer (Phase 1 IPC Primitives)
 * ============================================================ */

fut_handle_t fut_cap_handle_send(uint64_t target_pid, fut_handle_t source_handle,
                                 fut_rights_t shared_rights) {
    if (target_pid == 0 || source_handle == FUT_INVALID_HANDLE) {
        return FUT_INVALID_HANDLE;
    }

    /* Validate source handle has rights to share */
    if (!fut_cap_validate(source_handle, FUT_RIGHT_SHARE)) {
        fut_printf("[CAP] fut_cap_handle_send: source handle lacks SHARE rights\n");
        return FUT_INVALID_HANDLE;
    }

    /* Share object with target process using reduced rights */
    fut_handle_t target_handle = fut_object_share(source_handle, target_pid, shared_rights);

    fut_printf("[CAP] fut_cap_handle_send(target_pid=%llu, source=%llu, rights=0x%llx) -> %llu\n",
               target_pid, source_handle, shared_rights, target_handle);

    return target_handle;
}

fut_handle_t fut_cap_handle_recv(uint64_t source_pid, fut_rights_t *received_rights) {
    (void)received_rights;  /* Unused until implementation complete */

    /* TODO: Implement blocking receive of capability handle
     * This requires adding a handle receive queue to fut_task structure
     * and integrating with the scheduler for blocking wait.
     *
     * Planned implementation:
     *   1. Check task's handle receive queue
     *   2. If empty, block on waitq until handle arrives
     *   3. Pop handle from queue and return
     */

    fut_printf("[CAP] fut_cap_handle_recv(source_pid=%llu) (STUB)\n", source_pid);
    return FUT_INVALID_HANDLE;  /* Stub: not yet implemented */
}

fut_handle_t fut_cap_handle_dup(fut_handle_t source_handle, fut_rights_t new_rights) {
    if (source_handle == FUT_INVALID_HANDLE) {
        return FUT_INVALID_HANDLE;
    }

    /* Get source object */
    fut_object_t *obj = fut_object_get(source_handle, FUT_RIGHT_NONE);
    if (!obj) {
        return FUT_INVALID_HANDLE;
    }

    /* Validate new rights are subset of original */
    if ((new_rights & obj->rights) != new_rights) {
        fut_printf("[CAP] fut_cap_handle_dup: new rights not subset of original\n");
        fut_object_put(obj);
        return FUT_INVALID_HANDLE;
    }

    /* Create new handle with restricted rights */
    fut_handle_t new_handle = fut_object_create(obj->type, new_rights, obj->data);

    fut_object_put(obj);

    fut_printf("[CAP] fut_cap_handle_dup(source=%llu, new_rights=0x%llx) -> %llu\n",
               source_handle, new_rights, new_handle);

    return new_handle;
}

/* ============================================================
 *   Debug and Statistics
 * ============================================================ */

void fut_cap_print_stats(struct fut_task *task) {
    if (task) {
        /* Per-task stats require object ownership tracking (not yet implemented) */
        fut_printf("[CAP] Capability stats for task PID %llu:\n", task->pid);
        fut_printf("      Per-task capability tracking not yet implemented.\n");
        fut_printf("      Use fut_cap_print_stats(NULL) for system-wide stats.\n");
    } else {
        /* System-wide capability statistics */
        fut_printf("[CAP] System-wide capability statistics:\n");

        fut_object_stats_t stats;
        fut_object_get_stats(&stats);

        fut_printf("      Total objects allocated: %llu / %llu\n",
                   stats.total_objects, stats.max_objects);
        fut_printf("      Total refcount: %llu\n", stats.total_refcount);
        fut_printf("      Objects by type:\n");

        const char *type_names[] = {
            "NONE", "FILE", "SOCKET", "THREAD", "TASK", "MEMORY",
            "CHANNEL", "EVENT", "DEVICE", "BLKDEV", "NETDEV"
        };

        for (int i = 0; i < 11; i++) {
            if (stats.objects_by_type[i] > 0) {
                fut_printf("        %-10s: %llu\n", type_names[i], stats.objects_by_type[i]);
            }
        }
    }
}
