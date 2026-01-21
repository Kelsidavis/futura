/* fut_vfs_cap.c - Capability-aware VFS Operations
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * This file implements capability-aware VFS operations that integrate
 * with the Futura object system for capability-based access control.
 * These functions validate rights before performing file operations.
 */

#include <kernel/fut_vfs.h>
#include <kernel/fut_object.h>
#include <kernel/fut_capability.h>
#include <kernel/fut_memory.h>
#include <kernel/fut_task.h>
#include <kernel/chrdev.h>
#include <kernel/errno.h>
#include <stddef.h>
#include <stdbool.h>

extern void fut_printf(const char *fmt, ...);

/* ============================================================
 *   Helper Functions
 * ============================================================ */

/**
 * Convert open flags to capability rights.
 *
 * Maps O_RDONLY, O_WRONLY, O_RDWR flags to FUT_RIGHT_* bits.
 *
 * @param flags Open flags (O_RDONLY, O_WRONLY, O_RDWR, etc.)
 * @return Capability rights bitmask
 */
static fut_rights_t flags_to_rights(int flags) {
    fut_rights_t rights = FUT_RIGHT_DESTROY;  /* Always allow close */

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

    return rights;
}

/**
 * Validate that a handle has the required rights.
 *
 * @param handle Handle to validate
 * @param required Required rights bitmask
 * @return true if handle has all required rights, false otherwise
 */
static bool validate_rights(fut_handle_t handle, fut_rights_t required) {
    if (handle == FUT_INVALID_HANDLE) {
        return false;
    }
    return fut_object_has_rights(handle, required);
}

/* ============================================================
 *   Capability-aware File Operations
 * ============================================================ */

/**
 * Open a file with capability-based access control.
 *
 * @param path  File path to open
 * @param flags Open flags (O_RDONLY, O_WRONLY, O_RDWR, O_CREAT, etc.)
 * @param mode  File mode for creation
 * @return Capability handle on success, FUT_INVALID_HANDLE on failure
 */
fut_handle_t fut_vfs_open_cap(const char *path, int flags, int mode) {
    if (!path) {
        return FUT_INVALID_HANDLE;
    }

    /* Open file using existing VFS API */
    int fd = fut_vfs_open(path, flags, mode);
    if (fd < 0) {
        return FUT_INVALID_HANDLE;
    }

    /* Get the file structure */
    struct fut_file *file = fut_vfs_get_file(fd);
    if (!file) {
        fut_vfs_close(fd);
        return FUT_INVALID_HANDLE;
    }

    /* Convert flags to capability rights */
    fut_rights_t rights = flags_to_rights(flags);

    /* Create capability object wrapping the file structure */
    fut_handle_t handle = fut_object_create(FUT_OBJ_FILE, rights, file);
    if (handle == FUT_INVALID_HANDLE) {
        fut_vfs_close(fd);
        return FUT_INVALID_HANDLE;
    }

    /* Increment file refcount since object now holds a reference */
    file->refcount++;

    return handle;
}

/**
 * Read from a file using capability handle.
 *
 * @param handle Capability handle to file
 * @param buffer Buffer to read into
 * @param count  Number of bytes to read
 * @return Number of bytes read, or negative error code
 */
long fut_vfs_read_cap(fut_handle_t handle, void *buffer, size_t count) {
    /* Validate READ rights */
    if (!validate_rights(handle, FUT_RIGHT_READ)) {
        return -EPERM;
    }

    /* Get file object */
    fut_object_t *obj = fut_object_get(handle, FUT_RIGHT_READ);
    if (!obj || obj->type != FUT_OBJ_FILE) {
        if (obj) {
            fut_object_put(obj);
        }
        return -EBADF;
    }

    /* Get file structure from object */
    struct fut_file *file = (struct fut_file *)obj->data;
    if (!file) {
        fut_object_put(obj);
        return -EBADF;
    }

    /* Perform read operation directly on file structure */
    long result;

    if (file->chr_ops) {
        /* Character device path */
        if (!file->chr_ops->read) {
            fut_object_put(obj);
            return -EINVAL;
        }
        off_t pos = (off_t)file->offset;
        result = file->chr_ops->read(file->chr_inode, file->chr_private, buffer, count, &pos);
        if (result > 0) {
            file->offset = (uint64_t)pos;
        }
    } else if (file->vnode && file->vnode->ops && file->vnode->ops->read) {
        /* VFS vnode path */
        result = file->vnode->ops->read(file->vnode, buffer, count, file->offset);
        if (result > 0) {
            file->offset += result;
        }
    } else {
        result = -EINVAL;
    }

    /* Release object reference */
    fut_object_put(obj);

    return result;
}

/**
 * Write to a file using capability handle.
 *
 * @param handle Capability handle to file
 * @param buffer Buffer to write from
 * @param count  Number of bytes to write
 * @return Number of bytes written, or negative error code
 */
long fut_vfs_write_cap(fut_handle_t handle, const void *buffer, size_t count) {
    /* Validate WRITE rights */
    if (!validate_rights(handle, FUT_RIGHT_WRITE)) {
        return -EPERM;
    }

    /* Get file object */
    fut_object_t *obj = fut_object_get(handle, FUT_RIGHT_WRITE);
    if (!obj || obj->type != FUT_OBJ_FILE) {
        if (obj) {
            fut_object_put(obj);
        }
        return -EBADF;
    }

    /* Get file structure from object */
    struct fut_file *file = (struct fut_file *)obj->data;
    if (!file) {
        fut_object_put(obj);
        return -EBADF;
    }

    /* Perform write operation directly on file structure */
    long result;

    if (file->chr_ops) {
        /* Character device path */
        if (!file->chr_ops->write) {
            fut_object_put(obj);
            return -EINVAL;
        }
        off_t pos = (off_t)file->offset;
        result = file->chr_ops->write(file->chr_inode, file->chr_private, buffer, count, &pos);
        if (result > 0) {
            file->offset = (uint64_t)pos;
        }
    } else if (file->vnode && file->vnode->ops && file->vnode->ops->write) {
        /* VFS vnode path */
        result = file->vnode->ops->write(file->vnode, buffer, count, file->offset);
        if (result > 0) {
            file->offset += result;
        }
    } else {
        result = -EINVAL;
    }

    /* Release object reference */
    fut_object_put(obj);

    return result;
}

/**
 * Seek within a file using capability handle.
 *
 * @param handle Capability handle to file
 * @param offset Seek offset
 * @param whence Seek mode (SEEK_SET, SEEK_CUR, SEEK_END)
 * @return New file offset, or negative error code
 */
long fut_vfs_lseek_cap(fut_handle_t handle, int64_t offset, int whence) {
    /* No specific rights required for seek - just need valid handle */
    fut_object_t *obj = fut_object_get(handle, FUT_RIGHT_NONE);
    if (!obj || obj->type != FUT_OBJ_FILE) {
        if (obj) {
            fut_object_put(obj);
        }
        return -EBADF;
    }

    /* Get file structure from object */
    struct fut_file *file = (struct fut_file *)obj->data;
    if (!file) {
        fut_object_put(obj);
        return -EBADF;
    }

    /* Calculate new offset */
    int64_t new_offset;
    uint64_t file_size = 0;

    if (file->vnode) {
        file_size = file->vnode->size;
    }

    switch (whence) {
        case SEEK_SET:
            new_offset = offset;
            break;
        case SEEK_CUR:
            new_offset = (int64_t)file->offset + offset;
            break;
        case SEEK_END:
            new_offset = (int64_t)file_size + offset;
            break;
        default:
            fut_object_put(obj);
            return -EINVAL;
    }

    if (new_offset < 0) {
        fut_object_put(obj);
        return -EINVAL;
    }

    file->offset = (uint64_t)new_offset;

    fut_object_put(obj);

    return new_offset;
}

/**
 * Sync file data to storage using capability handle.
 *
 * @param handle Capability handle to file
 * @return 0 on success, negative error code on failure
 */
int fut_vfs_fsync_cap(fut_handle_t handle) {
    /* Requires WRITE rights for fsync */
    if (!validate_rights(handle, FUT_RIGHT_WRITE)) {
        return -EPERM;
    }

    fut_object_t *obj = fut_object_get(handle, FUT_RIGHT_WRITE);
    if (!obj || obj->type != FUT_OBJ_FILE) {
        if (obj) {
            fut_object_put(obj);
        }
        return -EBADF;
    }

    struct fut_file *file = (struct fut_file *)obj->data;
    if (!file || !file->vnode) {
        fut_object_put(obj);
        return -EBADF;
    }

    int result = 0;

    /* Call vnode sync operation if available */
    if (file->vnode->ops && file->vnode->ops->sync) {
        result = file->vnode->ops->sync(file->vnode);
    }

    fut_object_put(obj);

    return result;
}

/**
 * Get file statistics using capability handle.
 *
 * @param handle  Capability handle to file
 * @param statbuf Buffer to receive file statistics
 * @return 0 on success, negative error code on failure
 */
int fut_vfs_fstat_cap(fut_handle_t handle, struct fut_stat *statbuf) {
    if (!statbuf) {
        return -EINVAL;
    }

    /* No specific rights required for metadata query */
    fut_object_t *obj = fut_object_get(handle, FUT_RIGHT_NONE);
    if (!obj || obj->type != FUT_OBJ_FILE) {
        if (obj) {
            fut_object_put(obj);
        }
        return -EBADF;
    }

    struct fut_file *file = (struct fut_file *)obj->data;
    if (!file || !file->vnode) {
        fut_object_put(obj);
        return -EBADF;
    }

    int result = 0;

    /* Call vnode getattr operation if available */
    if (file->vnode->ops && file->vnode->ops->getattr) {
        result = file->vnode->ops->getattr(file->vnode, statbuf);
    } else {
        /* Fallback: populate from vnode fields */
        statbuf->st_dev = file->vnode->mount ? file->vnode->mount->st_dev : 0;
        statbuf->st_ino = file->vnode->ino;
        statbuf->st_mode = file->vnode->mode;
        statbuf->st_nlink = file->vnode->nlinks;
        statbuf->st_uid = file->vnode->uid;
        statbuf->st_gid = file->vnode->gid;
        statbuf->st_size = file->vnode->size;
        statbuf->st_blksize = 4096;
        statbuf->st_blocks = (file->vnode->size + 511) / 512;
        statbuf->st_atime = 0;
        statbuf->st_mtime = 0;
        statbuf->st_ctime = 0;
    }

    fut_object_put(obj);

    return result;
}

/**
 * Close a file using capability handle.
 *
 * @param handle Capability handle to close
 * @return 0 on success, negative error code on failure
 */
int fut_vfs_close_cap(fut_handle_t handle) {
    if (handle == FUT_INVALID_HANDLE) {
        return -EBADF;
    }

    /* DESTROY right is required to close */
    if (!validate_rights(handle, FUT_RIGHT_DESTROY)) {
        return -EPERM;
    }

    /* Get the object to access the file structure */
    fut_object_t *obj = fut_object_get(handle, FUT_RIGHT_DESTROY);
    if (!obj || obj->type != FUT_OBJ_FILE) {
        if (obj) {
            fut_object_put(obj);
        }
        return -EBADF;
    }

    struct fut_file *file = (struct fut_file *)obj->data;

    /* Decrement our reference to the file */
    if (file && file->refcount > 0) {
        file->refcount--;

        /* If this was the last reference, close the file properly */
        if (file->refcount == 0) {
            if (file->chr_ops && file->chr_ops->release) {
                file->chr_ops->release(file->chr_inode, file->chr_private);
            } else if (file->vnode) {
                if (file->vnode->ops && file->vnode->ops->close) {
                    file->vnode->ops->close(file->vnode);
                }
                fut_vnode_unref(file->vnode);
            }
            fut_free(file);
        }
    }

    /* Release object reference and destroy the handle */
    fut_object_put(obj);
    return fut_object_destroy(handle);
}

/* ============================================================
 *   Directory Operations (Capability-aware)
 * ============================================================ */

/**
 * Create a directory relative to a parent handle.
 *
 * @param parent_handle Capability handle to parent directory
 * @param name          Name of directory to create
 * @param mode          Directory permissions
 * @return 0 on success, negative error code on failure
 */
int fut_vfs_mkdirat_cap(fut_handle_t parent_handle, const char *name, int mode) {
    if (!name) {
        return -EINVAL;
    }

    /* Requires WRITE and ADMIN rights to create directories */
    if (!validate_rights(parent_handle, FUT_RIGHT_WRITE | FUT_RIGHT_ADMIN)) {
        return -EPERM;
    }

    fut_object_t *obj = fut_object_get(parent_handle, FUT_RIGHT_WRITE | FUT_RIGHT_ADMIN);
    if (!obj || obj->type != FUT_OBJ_FILE) {
        if (obj) {
            fut_object_put(obj);
        }
        return -EBADF;
    }

    struct fut_file *file = (struct fut_file *)obj->data;
    if (!file || !file->vnode) {
        fut_object_put(obj);
        return -EBADF;
    }

    /* Verify parent is a directory */
    if (file->vnode->type != VN_DIR) {
        fut_object_put(obj);
        return -ENOTDIR;
    }

    int result = -ENOSYS;

    if (file->vnode->ops && file->vnode->ops->mkdir) {
        result = file->vnode->ops->mkdir(file->vnode, name, (uint32_t)mode);
    }

    fut_object_put(obj);

    return result;
}

/**
 * Remove a directory relative to a parent handle.
 *
 * @param parent_handle Capability handle to parent directory
 * @param name          Name of directory to remove
 * @return 0 on success, negative error code on failure
 */
int fut_vfs_rmdirat_cap(fut_handle_t parent_handle, const char *name) {
    if (!name) {
        return -EINVAL;
    }

    /* Requires ADMIN rights to remove directories */
    if (!validate_rights(parent_handle, FUT_RIGHT_ADMIN)) {
        return -EPERM;
    }

    fut_object_t *obj = fut_object_get(parent_handle, FUT_RIGHT_ADMIN);
    if (!obj || obj->type != FUT_OBJ_FILE) {
        if (obj) {
            fut_object_put(obj);
        }
        return -EBADF;
    }

    struct fut_file *file = (struct fut_file *)obj->data;
    if (!file || !file->vnode) {
        fut_object_put(obj);
        return -EBADF;
    }

    /* Verify parent is a directory */
    if (file->vnode->type != VN_DIR) {
        fut_object_put(obj);
        return -ENOTDIR;
    }

    int result = -ENOSYS;

    if (file->vnode->ops && file->vnode->ops->rmdir) {
        result = file->vnode->ops->rmdir(file->vnode, name);
    }

    fut_object_put(obj);

    return result;
}

/**
 * Unlink (delete) a file relative to a parent handle.
 *
 * @param parent_handle Capability handle to parent directory
 * @param name          Name of file to unlink
 * @return 0 on success, negative error code on failure
 */
int fut_vfs_unlinkat_cap(fut_handle_t parent_handle, const char *name) {
    if (!name) {
        return -EINVAL;
    }

    /* Requires ADMIN rights to unlink files */
    if (!validate_rights(parent_handle, FUT_RIGHT_ADMIN)) {
        return -EPERM;
    }

    fut_object_t *obj = fut_object_get(parent_handle, FUT_RIGHT_ADMIN);
    if (!obj || obj->type != FUT_OBJ_FILE) {
        if (obj) {
            fut_object_put(obj);
        }
        return -EBADF;
    }

    struct fut_file *file = (struct fut_file *)obj->data;
    if (!file || !file->vnode) {
        fut_object_put(obj);
        return -EBADF;
    }

    /* Verify parent is a directory */
    if (file->vnode->type != VN_DIR) {
        fut_object_put(obj);
        return -ENOTDIR;
    }

    int result = -ENOSYS;

    if (file->vnode->ops && file->vnode->ops->unlink) {
        result = file->vnode->ops->unlink(file->vnode, name);
    }

    fut_object_put(obj);

    return result;
}

/**
 * Get file statistics relative to a parent handle.
 *
 * @param parent_handle Capability handle to parent directory
 * @param name          Name of file to stat
 * @param statbuf       Buffer to receive statistics
 * @return 0 on success, negative error code on failure
 */
int fut_vfs_statat_cap(fut_handle_t parent_handle, const char *name, struct fut_stat *statbuf) {
    if (!name || !statbuf) {
        return -EINVAL;
    }

    /* Requires READ rights to stat files */
    if (!validate_rights(parent_handle, FUT_RIGHT_READ)) {
        return -EPERM;
    }

    fut_object_t *obj = fut_object_get(parent_handle, FUT_RIGHT_READ);
    if (!obj || obj->type != FUT_OBJ_FILE) {
        if (obj) {
            fut_object_put(obj);
        }
        return -EBADF;
    }

    struct fut_file *file = (struct fut_file *)obj->data;
    if (!file || !file->vnode) {
        fut_object_put(obj);
        return -EBADF;
    }

    /* Verify parent is a directory */
    if (file->vnode->type != VN_DIR) {
        fut_object_put(obj);
        return -ENOTDIR;
    }

    int result = -ENOSYS;

    /* Lookup the target vnode */
    if (file->vnode->ops && file->vnode->ops->lookup) {
        struct fut_vnode *target = NULL;
        result = file->vnode->ops->lookup(file->vnode, name, &target);

        if (result == 0 && target) {
            /* Get attributes from target vnode */
            if (target->ops && target->ops->getattr) {
                result = target->ops->getattr(target, statbuf);
            } else {
                /* Fallback: populate from vnode fields */
                statbuf->st_dev = target->mount ? target->mount->st_dev : 0;
                statbuf->st_ino = target->ino;
                statbuf->st_mode = target->mode;
                statbuf->st_nlink = target->nlinks;
                statbuf->st_uid = target->uid;
                statbuf->st_gid = target->gid;
                statbuf->st_size = target->size;
                statbuf->st_blksize = 4096;
                statbuf->st_blocks = (target->size + 511) / 512;
                statbuf->st_atime = 0;
                statbuf->st_mtime = 0;
                statbuf->st_ctime = 0;
                result = 0;
            }

            /* Release target vnode reference */
            fut_vnode_unref(target);
        }
    }

    fut_object_put(obj);

    return result;
}

/* Note: Handle transfer operations (fut_cap_handle_dup, fut_cap_handle_send,
 * fut_cap_handle_recv, fut_cap_get_rights, fut_cap_validate) are implemented
 * in kernel/capability.c to avoid duplication.
 */
