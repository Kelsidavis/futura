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
#define MAX_PATH_COMPONENTS 32

static const struct fut_fs_type *registered_fs[MAX_FS_TYPES];
static int num_fs_types = 0;

static struct fut_mount *mount_list = NULL;
static struct fut_file *file_table[MAX_OPEN_FILES];

/* Root vnode - set when root filesystem is mounted */
static struct fut_vnode *root_vnode = NULL;

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

    /* Initialize root vnode */
    root_vnode = NULL;
}

void fut_vfs_set_root(struct fut_vnode *vnode) {
    if (root_vnode) {
        fut_vnode_unref(root_vnode);
    }
    root_vnode = vnode;
    if (root_vnode) {
        fut_vnode_ref(root_vnode);
    }
}

struct fut_vnode *fut_vfs_get_root(void) {
    return root_vnode;
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

    /* If mounting at root, set root vnode */
    if (mountpoint && mountpoint[0] == '/' && mountpoint[1] == '\0') {
        fut_vfs_set_root(mount->root);
    }

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
 *   Path Resolution
 * ============================================================ */

/**
 * Simple string copy helper.
 */
static void str_copy(char *dest, const char *src, size_t max_len) {
    size_t i = 0;
    while (i < max_len - 1 && src[i]) {
        dest[i] = src[i];
        i++;
    }
    dest[i] = '\0';
}

/**
 * Parse path into components.
 *
 * @param path       Path to parse (e.g., "/foo/bar/baz")
 * @param components Array to store component pointers
 * @param max_comp   Maximum number of components
 * @return Number of components parsed
 */
static int parse_path(const char *path, char components[][64], int max_comp) {
    int count = 0;
    const char *start = path;

    /* Skip leading slashes */
    while (*start == '/') {
        start++;
    }

    while (*start && count < max_comp) {
        const char *end = start;

        /* Find next slash or end of string */
        while (*end && *end != '/') {
            end++;
        }

        /* Copy component */
        size_t len = end - start;
        if (len > 0 && len < 63) {
            str_copy(components[count], start, len + 1);
            count++;
        }

        /* Skip trailing slashes */
        while (*end == '/') {
            end++;
        }

        start = end;
    }

    return count;
}

/**
 * Lookup vnode by path.
 *
 * @param path   Path to lookup
 * @param vnode  Pointer to store result vnode
 * @return 0 on success, negative error code on failure
 */
static int lookup_vnode(const char *path, struct fut_vnode **vnode) {
    if (!path || !vnode) {
        return -EINVAL;
    }

    /* Handle root directory */
    if (path[0] == '/' && path[1] == '\0') {
        if (!root_vnode) {
            return -ENOENT;  /* Root not mounted */
        }
        *vnode = root_vnode;
        fut_vnode_ref(*vnode);
        return 0;
    }

    /* Parse path into components */
    char components[MAX_PATH_COMPONENTS][64];
    int num_components = parse_path(path, components, MAX_PATH_COMPONENTS);

    if (num_components == 0) {
        return -EINVAL;
    }

    /* Start from root */
    if (!root_vnode) {
        return -ENOENT;
    }

    struct fut_vnode *current = root_vnode;
    fut_vnode_ref(current);

    /* Walk path components */
    for (int i = 0; i < num_components; i++) {
        /* Check if current is a directory */
        if (current->type != VN_DIR) {
            fut_vnode_unref(current);
            return -ENOTDIR;
        }

        /* Lookup next component */
        if (!current->ops || !current->ops->lookup) {
            fut_vnode_unref(current);
            return -ENOENT;
        }

        struct fut_vnode *next = NULL;
        int ret = current->ops->lookup(current, components[i], &next);

        if (ret < 0) {
            fut_vnode_unref(current);
            return ret;
        }

        fut_vnode_unref(current);
        current = next;
    }

    *vnode = current;
    return 0;
}

/* ============================================================
 *   File Descriptor Management
 * ============================================================ */

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
    struct fut_vnode *vnode = NULL;
    int ret;

    /* Lookup vnode */
    ret = lookup_vnode(path, &vnode);
    if (ret < 0) {
        /* If O_CREAT is set and parent exists, create new file */
        if ((flags & O_CREAT) && ret == -ENOENT) {
            /* TODO: Parse parent directory and create file */
            /* For now, return error */
            return -ENOENT;
        }
        return ret;
    }

    /* Check if trying to open directory with write flags */
    if (vnode->type == VN_DIR && (flags & (O_WRONLY | O_RDWR))) {
        fut_vnode_unref(vnode);
        return -EISDIR;
    }

    /* Call vnode open operation */
    if (vnode->ops && vnode->ops->open) {
        ret = vnode->ops->open(vnode, flags);
        if (ret < 0) {
            fut_vnode_unref(vnode);
            return ret;
        }
    }

    /* Allocate file structure */
    struct fut_file *file = fut_malloc(sizeof(struct fut_file));
    if (!file) {
        fut_vnode_unref(vnode);
        return -ENOMEM;
    }

    file->vnode = vnode;
    file->offset = 0;
    file->flags = flags;
    file->refcount = 1;

    /* Allocate file descriptor */
    int fd = alloc_fd(file);
    if (fd < 0) {
        fut_free(file);
        fut_vnode_unref(vnode);
        return fd;
    }

    (void)mode;  /* TODO: Use mode for permission checks */
    return fd;
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
    if (!path || !stat) {
        return -EINVAL;
    }

    /* Lookup vnode */
    struct fut_vnode *vnode = NULL;
    int ret = lookup_vnode(path, &vnode);
    if (ret < 0) {
        return ret;
    }

    /* Call vnode getattr operation if available */
    if (vnode->ops && vnode->ops->getattr) {
        ret = vnode->ops->getattr(vnode, stat);
    } else {
        /* Fill basic stat info from vnode */
        stat->st_ino = vnode->ino;
        stat->st_mode = vnode->mode;
        stat->st_nlink = vnode->nlinks;
        stat->st_size = vnode->size;
        stat->st_dev = 0;    /* TODO: Device ID */
        stat->st_uid = 0;
        stat->st_gid = 0;
        stat->st_blksize = 4096;
        stat->st_blocks = (vnode->size + 4095) / 4096;
        stat->st_atime = 0;
        stat->st_mtime = 0;
        stat->st_ctime = 0;
        ret = 0;
    }

    fut_vnode_unref(vnode);
    return ret;
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
