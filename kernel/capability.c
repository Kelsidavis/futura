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
#include <kernel/errno.h>
#include <string.h>

extern void fut_printf(const char *fmt, ...);

/* ============================================================
 *   System Initialization
 * ============================================================ */

void fut_cap_system_init(void) {
    fut_printf("[CAP] Capability system initialized\n");
}

/* ============================================================
 *   Rights Conversion Helpers
 * ============================================================ */

fut_rights_t fut_cap_flags_to_rights(int flags) {
    fut_rights_t rights = FUT_RIGHT_DESTROY;  /* Always allow close */

    /* Extract access mode from flags */
    int access_mode = flags & 0x3;  /* O_RDONLY=0, O_WRONLY=1, O_RDWR=2 */

    switch (access_mode) {
        case 0:  /* O_RDONLY */
            rights |= FUT_RIGHT_READ;
            break;
        case 1:  /* O_WRONLY */
            rights |= FUT_RIGHT_WRITE;
            break;
        case 2:  /* O_RDWR */
            rights |= FUT_RIGHT_READ | FUT_RIGHT_WRITE;
            break;
    }

    /* O_CREAT, O_TRUNC, O_EXCL require ADMIN rights */
    if (flags & (0x0040 | 0x0200 | 0x0080)) {  /* O_CREAT | O_TRUNC | O_EXCL */
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

    /* Convert flags to capability rights */
    fut_rights_t rights = fut_cap_flags_to_rights(flags);

    /* TODO: Integrate with VFS to open file and create capability handle
     * This requires updating fut_vfs_open() to return capability handles
     * instead of integer file descriptors.
     *
     * Planned implementation:
     *   1. Call fut_vfs_open(path, flags, mode) -> returns file structure
     *   2. Create capability object: fut_object_create(FUT_OBJ_FILE, rights, file)
     *   3. Return capability handle
     */

    fut_printf("[CAP] fut_cap_open(\"%s\", flags=0x%x, mode=0%o) -> rights=0x%llx (STUB)\n",
               path, flags, mode, rights);

    return FUT_INVALID_HANDLE;  /* Stub: return invalid until VFS integration */
}

long fut_cap_read(fut_handle_t handle, void *buffer, size_t count) {
    if (handle == FUT_INVALID_HANDLE || !buffer) {
        return -EINVAL;
    }

    /* Validate READ rights */
    if (!fut_cap_validate(handle, FUT_RIGHT_READ)) {
        fut_printf("[CAP] fut_cap_read: handle lacks READ rights\n");
        return -EPERM;
    }

    /* Get object */
    fut_object_t *obj = fut_object_get(handle, FUT_RIGHT_READ);
    if (!obj) {
        return -EBADF;
    }

    /* TODO: Call VFS read operation with object data
     * struct fut_file *file = (struct fut_file *)obj->data;
     * long result = fut_vfs_read(file, buffer, count);
     */

    fut_object_put(obj);

    fut_printf("[CAP] fut_cap_read(handle=%llu, count=%zu) (STUB)\n", handle, count);
    return -ENOSYS;  /* Stub: not yet implemented */
}

long fut_cap_write(fut_handle_t handle, const void *buffer, size_t count) {
    if (handle == FUT_INVALID_HANDLE || !buffer) {
        return -EINVAL;
    }

    /* Validate WRITE rights */
    if (!fut_cap_validate(handle, FUT_RIGHT_WRITE)) {
        fut_printf("[CAP] fut_cap_write: handle lacks WRITE rights\n");
        return -EPERM;
    }

    /* Get object */
    fut_object_t *obj = fut_object_get(handle, FUT_RIGHT_WRITE);
    if (!obj) {
        return -EBADF;
    }

    /* TODO: Call VFS write operation with object data
     * struct fut_file *file = (struct fut_file *)obj->data;
     * long result = fut_vfs_write(file, buffer, count);
     */

    fut_object_put(obj);

    fut_printf("[CAP] fut_cap_write(handle=%llu, count=%zu) (STUB)\n", handle, count);
    return -ENOSYS;  /* Stub: not yet implemented */
}

long fut_cap_lseek(fut_handle_t handle, int64_t offset, int whence) {
    if (handle == FUT_INVALID_HANDLE) {
        return -EINVAL;
    }

    /* Validate handle is valid (no specific rights needed for seek) */
    fut_object_t *obj = fut_object_get(handle, FUT_RIGHT_NONE);
    if (!obj) {
        return -EBADF;
    }

    /* TODO: Call VFS lseek operation
     * struct fut_file *file = (struct fut_file *)obj->data;
     * long result = fut_vfs_lseek(file, offset, whence);
     */

    fut_object_put(obj);

    fut_printf("[CAP] fut_cap_lseek(handle=%llu, offset=%lld, whence=%d) (STUB)\n",
               handle, offset, whence);
    return -ENOSYS;  /* Stub: not yet implemented */
}

int fut_cap_fsync(fut_handle_t handle) {
    if (handle == FUT_INVALID_HANDLE) {
        return -EINVAL;
    }

    /* Validate WRITE rights (data must be writable to sync) */
    if (!fut_cap_validate(handle, FUT_RIGHT_WRITE)) {
        fut_printf("[CAP] fut_cap_fsync: handle lacks WRITE rights\n");
        return -EPERM;
    }

    /* Get object */
    fut_object_t *obj = fut_object_get(handle, FUT_RIGHT_WRITE);
    if (!obj) {
        return -EBADF;
    }

    /* TODO: Call VFS fsync operation
     * struct fut_file *file = (struct fut_file *)obj->data;
     * int result = fut_vfs_fsync(file);
     */

    fut_object_put(obj);

    fut_printf("[CAP] fut_cap_fsync(handle=%llu) (STUB)\n", handle);
    return -ENOSYS;  /* Stub: not yet implemented */
}

int fut_cap_fstat(fut_handle_t handle, struct stat *statbuf) {
    if (handle == FUT_INVALID_HANDLE || !statbuf) {
        return -EINVAL;
    }

    /* Validate handle is valid (no specific rights needed for metadata) */
    fut_object_t *obj = fut_object_get(handle, FUT_RIGHT_NONE);
    if (!obj) {
        return -EBADF;
    }

    /* TODO: Call VFS fstat operation
     * struct fut_file *file = (struct fut_file *)obj->data;
     * int result = fut_vfs_fstat(file, statbuf);
     */

    fut_object_put(obj);

    fut_printf("[CAP] fut_cap_fstat(handle=%llu) (STUB)\n", handle);
    return -ENOSYS;  /* Stub: not yet implemented */
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

    /* Validate parent has WRITE|ADMIN rights */
    if (!fut_cap_validate(parent_handle, FUT_RIGHT_WRITE | FUT_RIGHT_ADMIN)) {
        fut_printf("[CAP] fut_cap_mkdirat: parent handle lacks WRITE|ADMIN rights\n");
        return -EPERM;
    }

    /* TODO: Implement directory creation via VFS
     * Get parent directory from handle, create child directory
     */

    fut_printf("[CAP] fut_cap_mkdirat(parent=%llu, name=\"%s\", mode=0%o) (STUB)\n",
               parent_handle, name, mode);
    return -ENOSYS;  /* Stub: not yet implemented */
}

int fut_cap_rmdirat(fut_handle_t parent_handle, const char *name) {
    if (parent_handle == FUT_INVALID_HANDLE || !name) {
        return -EINVAL;
    }

    /* Validate parent has ADMIN rights */
    if (!fut_cap_validate(parent_handle, FUT_RIGHT_ADMIN)) {
        fut_printf("[CAP] fut_cap_rmdirat: parent handle lacks ADMIN rights\n");
        return -EPERM;
    }

    /* TODO: Implement directory removal via VFS */

    fut_printf("[CAP] fut_cap_rmdirat(parent=%llu, name=\"%s\") (STUB)\n",
               parent_handle, name);
    return -ENOSYS;  /* Stub: not yet implemented */
}

int fut_cap_unlinkat(fut_handle_t parent_handle, const char *name) {
    if (parent_handle == FUT_INVALID_HANDLE || !name) {
        return -EINVAL;
    }

    /* Validate parent has ADMIN rights */
    if (!fut_cap_validate(parent_handle, FUT_RIGHT_ADMIN)) {
        fut_printf("[CAP] fut_cap_unlinkat: parent handle lacks ADMIN rights\n");
        return -EPERM;
    }

    /* TODO: Implement file removal via VFS */

    fut_printf("[CAP] fut_cap_unlinkat(parent=%llu, name=\"%s\") (STUB)\n",
               parent_handle, name);
    return -ENOSYS;  /* Stub: not yet implemented */
}

int fut_cap_statat(fut_handle_t parent_handle, const char *name, struct stat *statbuf) {
    if (parent_handle == FUT_INVALID_HANDLE || !name || !statbuf) {
        return -EINVAL;
    }

    /* Validate parent has READ rights */
    if (!fut_cap_validate(parent_handle, FUT_RIGHT_READ)) {
        fut_printf("[CAP] fut_cap_statat: parent handle lacks READ rights\n");
        return -EPERM;
    }

    /* TODO: Implement stat operation via VFS */

    fut_printf("[CAP] fut_cap_statat(parent=%llu, name=\"%s\") (STUB)\n",
               parent_handle, name);
    return -ENOSYS;  /* Stub: not yet implemented */
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
