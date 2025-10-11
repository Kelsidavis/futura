/* fut_vfs.c - Futura OS Virtual File System Implementation
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Core VFS implementation with filesystem registration and mount management.
 */

#include <kernel/fut_vfs.h>
#include <kernel/fut_memory.h>
#include <stddef.h>

/* ============================================================
 *   VFS State
 * ============================================================ */

#define MAX_FS_TYPES 16
#define MAX_MOUNTS 32
#define MAX_OPEN_FILES 256

static const struct fut_fs_type *registered_fs[MAX_FS_TYPES];
static int num_fs_types = 0;

static struct fut_mount *mount_list = NULL;
static struct fut_file *file_table[MAX_OPEN_FILES];

/* ============================================================
 *   VFS Initialization
 * ============================================================ */

void fut_vfs_init(void) {
    /* Initialize file table */
    for (int i = 0; i < MAX_OPEN_FILES; i++) {
        file_table[i] = NULL;
    }

    /* Initialize mount list */
    mount_list = NULL;
}

/* ============================================================
 *   Filesystem Registration
 * ============================================================ */

int fut_vfs_register_fs(const struct fut_fs_type *fs) {
    if (num_fs_types >= MAX_FS_TYPES) {
        return -ENOMEM;
    }

    registered_fs[num_fs_types++] = fs;
    return 0;
}

static const struct fut_fs_type *find_fs_type(const char *name) {
    for (int i = 0; i < num_fs_types; i++) {
        if (registered_fs[i] && registered_fs[i]->name) {
            /* Simple string comparison (should use strcmp) */
            const char *a = registered_fs[i]->name;
            const char *b = name;
            while (*a && *b && *a == *b) {
                a++;
                b++;
            }
            if (*a == *b) {
                return registered_fs[i];
            }
        }
    }
    return NULL;
}

/* ============================================================
 *   Mount Management
 * ============================================================ */

int fut_vfs_mount(const char *device, const char *mountpoint,
                  const char *fstype, int flags, void *data) {
    /* Find filesystem type */
    const struct fut_fs_type *fs = find_fs_type(fstype);
    if (!fs) {
        return -ENOENT;  /* Filesystem type not found */
    }

    /* Create mount structure */
    struct fut_mount *mount = NULL;
    int ret = fs->mount(device, flags, data, &mount);
    if (ret < 0) {
        return ret;
    }

    /* Set mount point info */
    mount->device = device;
    mount->mountpoint = mountpoint;
    mount->fs = fs;
    mount->flags = flags;

    /* Add to mount list */
    mount->next = mount_list;
    mount_list = mount;

    return 0;
}

int fut_vfs_unmount(const char *mountpoint) {
    struct fut_mount **prev = &mount_list;
    struct fut_mount *mount = mount_list;

    while (mount) {
        /* Simple string comparison */
        const char *a = mount->mountpoint;
        const char *b = mountpoint;
        while (*a && *b && *a == *b) {
            a++;
            b++;
        }

        if (*a == *b) {
            /* Found mount point */
            *prev = mount->next;

            /* Unmount filesystem */
            if (mount->fs && mount->fs->unmount) {
                mount->fs->unmount(mount);
            }

            /* Free mount structure */
            fut_free(mount);
            return 0;
        }

        prev = &mount->next;
        mount = mount->next;
    }

    return -ENOENT;
}

/* ============================================================
 *   File Descriptor Management
 * ============================================================ */

__attribute__((unused))
static int alloc_fd(struct fut_file *file) {
    for (int i = 0; i < MAX_OPEN_FILES; i++) {
        if (file_table[i] == NULL) {
            file_table[i] = file;
            return i;
        }
    }
    return -ENOMEM;
}

static struct fut_file *get_file(int fd) {
    if (fd < 0 || fd >= MAX_OPEN_FILES) {
        return NULL;
    }
    return file_table[fd];
}

static void free_fd(int fd) {
    if (fd >= 0 && fd < MAX_OPEN_FILES) {
        file_table[fd] = NULL;
    }
}

/* ============================================================
 *   File Operations
 * ============================================================ */

int fut_vfs_open(const char *path, int flags, int mode) {
    /* Phase 2: Stub implementation */
    /* Full implementation would:
     * 1. Parse path and find vnode
     * 2. Check permissions
     * 3. Create file structure
     * 4. Allocate file descriptor
     */
    (void)path;
    (void)flags;
    (void)mode;
    return -ENOENT;
}

ssize_t fut_vfs_read(int fd, void *buf, size_t size) {
    struct fut_file *file = get_file(fd);
    if (!file) {
        return -EBADF;
    }

    /* Call vnode read operation */
    if (!file->vnode || !file->vnode->ops || !file->vnode->ops->read) {
        return -EINVAL;
    }

    ssize_t ret = file->vnode->ops->read(file->vnode, buf, size, file->offset);
    if (ret > 0) {
        file->offset += ret;
    }

    return ret;
}

ssize_t fut_vfs_write(int fd, const void *buf, size_t size) {
    struct fut_file *file = get_file(fd);
    if (!file) {
        return -EBADF;
    }

    /* Call vnode write operation */
    if (!file->vnode || !file->vnode->ops || !file->vnode->ops->write) {
        return -EINVAL;
    }

    ssize_t ret = file->vnode->ops->write(file->vnode, buf, size, file->offset);
    if (ret > 0) {
        file->offset += ret;
    }

    return ret;
}

int fut_vfs_close(int fd) {
    struct fut_file *file = get_file(fd);
    if (!file) {
        return -EBADF;
    }

    /* Call vnode close operation */
    if (file->vnode && file->vnode->ops && file->vnode->ops->close) {
        file->vnode->ops->close(file->vnode);
    }

    /* Free file structure */
    free_fd(fd);
    fut_free(file);

    return 0;
}

int64_t fut_vfs_lseek(int fd, int64_t offset, int whence) {
    struct fut_file *file = get_file(fd);
    if (!file) {
        return -EBADF;
    }

    uint64_t new_offset = file->offset;

    switch (whence) {
    case SEEK_SET:
        new_offset = offset;
        break;
    case SEEK_CUR:
        new_offset = file->offset + offset;
        break;
    case SEEK_END:
        if (file->vnode) {
            new_offset = file->vnode->size + offset;
        }
        break;
    default:
        return -EINVAL;
    }

    file->offset = new_offset;
    return (int64_t)new_offset;
}

int fut_vfs_stat(const char *path, struct fut_stat *stat) {
    /* Phase 2: Stub implementation */
    /* Full implementation would:
     * 1. Parse path and find vnode
     * 2. Call vnode getattr operation
     * 3. Fill stat structure
     */
    (void)path;
    (void)stat;
    return -ENOENT;
}

/* ============================================================
 *   VNode Reference Counting
 * ============================================================ */

void fut_vnode_ref(struct fut_vnode *vnode) {
    if (vnode) {
        vnode->refcount++;
    }
}

void fut_vnode_unref(struct fut_vnode *vnode) {
    if (vnode && vnode->refcount > 0) {
        vnode->refcount--;
        if (vnode->refcount == 0) {
            /* Free vnode resources */
            fut_free(vnode);
        }
    }
}
