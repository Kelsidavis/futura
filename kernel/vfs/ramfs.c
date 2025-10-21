/* ramfs.c - RAM Filesystem Implementation
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Simple in-memory filesystem for testing VFS layer.
 * Files and directories stored in dynamically allocated memory.
 */

#include <kernel/fut_vfs.h>
#include <kernel/fut_memory.h>
#include <stddef.h>
#include <string.h>

/* ============================================================
 *   RamFS Structures
 * ============================================================ */

/* Directory entry linking file names to vnodes */
struct ramfs_dirent {
    char name[64];                  /* File/directory name */
    struct fut_vnode *vnode;        /* Associated vnode */
    struct ramfs_dirent *next;      /* Next entry in directory */
};

/* Per-vnode filesystem data */
struct ramfs_node {
    union {
        /* For regular files: data buffer */
        struct {
            uint8_t *data;          /* File data */
            size_t capacity;        /* Allocated size */
        } file;

        /* For directories: list of entries */
        struct {
            struct ramfs_dirent *entries;
        } dir;
    };
};

#define RAMFS_ROOT_CANARY_BEFORE 0xFADC0DE0CAFEBABEULL
#define RAMFS_ROOT_CANARY_AFTER  0xDEADBEEFCAFED00DULL

struct ramfs_root_guard {
    uint64_t before;
    struct fut_vnode vnode;
    uint64_t after;
};

/* ============================================================
 *   String Utilities
 * ============================================================ */

static int str_cmp(const char *a, const char *b) {
    while (*a && *b && *a == *b) {
        a++;
        b++;
    }
    return *a - *b;
}

static void str_copy_safe(char *dest, const char *src, size_t max_len) {
    size_t i = 0;
    while (i < max_len - 1 && src[i]) {
        dest[i] = src[i];
        i++;
    }
    dest[i] = '\0';
}

/* ============================================================
 *   VNode Operations
 * ============================================================ */

static int ramfs_open(struct fut_vnode *vnode, int flags) {
    (void)vnode;
    (void)flags;
    /* Nothing to do for open */
    return 0;
}

static int ramfs_close(struct fut_vnode *vnode) {
    (void)vnode;
    /* Nothing to do for close */
    return 0;
}

static ssize_t ramfs_read(struct fut_vnode *vnode, void *buf, size_t size, uint64_t offset) {
    if (!vnode || !buf) {
        return -EINVAL;
    }

    if (vnode->type != VN_REG) {
        return -EINVAL;  /* Can only read regular files */
    }

    struct ramfs_node *node = (struct ramfs_node *)vnode->fs_data;
    if (!node) {
        return -EIO;
    }

    /* Check offset */
    if (offset >= vnode->size) {
        return 0;  /* EOF */
    }

    /* Calculate bytes to read */
    size_t remaining = vnode->size - offset;
    size_t to_read = (size < remaining) ? size : remaining;

    /* Copy data using memcpy for efficiency */
    memcpy(buf, node->file.data + offset, to_read);

    return (ssize_t)to_read;
}

static ssize_t ramfs_write(struct fut_vnode *vnode, const void *buf, size_t size, uint64_t offset) {
    if (!vnode || !buf) {
        return -EINVAL;
    }

    if (vnode->type != VN_REG) {
        return -EINVAL;  /* Can only write regular files */
    }

    struct ramfs_node *node = (struct ramfs_node *)vnode->fs_data;
    if (!node) {
        return -EIO;
    }

    /* Calculate required capacity */
    size_t required = offset + size;

    /* Expand buffer if needed */
    if (required > node->file.capacity) {
        /* Allocation strategy balancing performance and heap management:
         * - Small files: aggressive growth to minimize realloc overhead
         * - Large files (>64KB): conservative growth (25% overhead) to reduce fragmentation
         */
        size_t new_capacity;
        if (required < 65536) {
            /* For small files (<64KB), double capacity
             * This batches allocations efficiently for smaller files
             */
            new_capacity = required * 2;
        } else {
            /* For larger files (>=64KB), add 25% overhead instead of doubling
             * A 544KB file allocates 680KB instead of 1088KB,
             * significantly reducing heap fragmentation
             */
            new_capacity = required + (required / 4);
        }

        uint8_t *new_data = fut_malloc(new_capacity);
        if (!new_data) {
            return -ENOMEM;
        }

        /* Copy old data using memcpy for efficiency */
        if (node->file.data && vnode->size > 0) {
            memcpy(new_data, node->file.data, vnode->size);
            fut_free(node->file.data);
        }

        node->file.data = new_data;
        node->file.capacity = new_capacity;
    }

    /* Write data using memcpy for efficiency */
    memcpy(node->file.data + offset, buf, size);

    /* Update size */
    if (offset + size > vnode->size) {
        vnode->size = offset + size;
    }

    return (ssize_t)size;
}

static int ramfs_lookup(struct fut_vnode *dir, const char *name, struct fut_vnode **result) {
    if (!dir || !name || !result) {
        return -EINVAL;
    }

    if (dir->type != VN_DIR) {
        return -ENOTDIR;
    }

    struct ramfs_node *node = (struct ramfs_node *)dir->fs_data;
    if (!node) {
        return -EIO;
    }

    /* Search directory entries */
    struct ramfs_dirent *entry = node->dir.entries;
    while (entry) {
        if (str_cmp(entry->name, name) == 0) {
            *result = entry->vnode;
            fut_vnode_ref(*result);
            return 0;
        }
        entry = entry->next;
    }

    return -ENOENT;
}

static int ramfs_create(struct fut_vnode *dir, const char *name, uint32_t mode, struct fut_vnode **result) {
    if (!dir || !name || !result) {
        return -EINVAL;
    }

    if (dir->type != VN_DIR) {
        return -ENOTDIR;
    }

    struct ramfs_node *dir_node = (struct ramfs_node *)dir->fs_data;
    if (!dir_node) {
        return -EIO;
    }

    /* Check if file already exists */
    struct ramfs_dirent *entry = dir_node->dir.entries;
    while (entry) {
        if (str_cmp(entry->name, name) == 0) {
            return -EEXIST;
        }
        entry = entry->next;
    }

    /* Create new vnode */
    struct fut_vnode *vnode = fut_malloc(sizeof(struct fut_vnode));
    if (!vnode) {
        return -ENOMEM;
    }

    struct ramfs_node *node = fut_malloc(sizeof(struct ramfs_node));
    if (!node) {
        fut_free(vnode);
        return -ENOMEM;
    }

    /* Initialize vnode */
    vnode->type = VN_REG;
    vnode->ino = (uint64_t)vnode;  /* Use pointer as inode number */
    vnode->mode = mode;
    vnode->size = 0;
    vnode->nlinks = 1;
    vnode->mount = dir->mount;
    vnode->fs_data = node;
    vnode->refcount = 1;
    vnode->ops = dir->ops;  /* Same ops as parent */

    /* Initialize file data */
    node->file.data = NULL;
    node->file.capacity = 0;

    /* Create directory entry */
    struct ramfs_dirent *new_entry = fut_malloc(sizeof(struct ramfs_dirent));
    if (!new_entry) {
        fut_free(node);
        fut_free(vnode);
        return -ENOMEM;
    }

    str_copy_safe(new_entry->name, name, sizeof(new_entry->name));
    new_entry->vnode = vnode;
    new_entry->next = dir_node->dir.entries;
    dir_node->dir.entries = new_entry;

    /* Take reference for caller - must match reference-taking in lookup */
    fut_vnode_ref(vnode);
    *result = vnode;
    return 0;
}

static int ramfs_mkdir(struct fut_vnode *dir, const char *name, uint32_t mode) {
    if (!dir || !name) {
        return -EINVAL;
    }

    if (dir->type != VN_DIR) {
        return -ENOTDIR;
    }

    struct ramfs_node *dir_node = (struct ramfs_node *)dir->fs_data;
    if (!dir_node) {
        return -EIO;
    }

    /* Check if directory already exists */
    struct ramfs_dirent *entry = dir_node->dir.entries;
    while (entry) {
        if (str_cmp(entry->name, name) == 0) {
            return -EEXIST;
        }
        entry = entry->next;
    }

    /* Create new vnode */
    struct fut_vnode *vnode = fut_malloc(sizeof(struct fut_vnode));
    if (!vnode) {
        return -ENOMEM;
    }

    struct ramfs_node *node = fut_malloc(sizeof(struct ramfs_node));
    if (!node) {
        fut_free(vnode);
        return -ENOMEM;
    }

    /* Initialize vnode */
    vnode->type = VN_DIR;
    vnode->ino = (uint64_t)vnode;
    vnode->mode = mode;
    vnode->size = 0;
    vnode->nlinks = 2;  /* "." and parent reference */
    vnode->mount = dir->mount;
    vnode->fs_data = node;
    vnode->refcount = 1;
    vnode->ops = dir->ops;

    /* Initialize directory */
    node->dir.entries = NULL;

    /* Create directory entry */
    struct ramfs_dirent *new_entry = fut_malloc(sizeof(struct ramfs_dirent));
    if (!new_entry) {
        fut_free(node);
        fut_free(vnode);
        return -ENOMEM;
    }

    str_copy_safe(new_entry->name, name, sizeof(new_entry->name));
    new_entry->vnode = vnode;
    new_entry->next = dir_node->dir.entries;
    dir_node->dir.entries = new_entry;

    return 0;
}

static const struct fut_vnode_ops ramfs_vnode_ops = {
    .open = ramfs_open,
    .close = ramfs_close,
    .read = ramfs_read,
    .write = ramfs_write,
    .readdir = NULL,    /* TODO: Implement readdir */
    .lookup = ramfs_lookup,
    .create = ramfs_create,
    .unlink = NULL,      /* TODO: Implement unlink */
    .mkdir = ramfs_mkdir,
    .rmdir = NULL,       /* TODO: Implement rmdir */
    .getattr = NULL,     /* Use default from VFS */
    .setattr = NULL
};

/* ============================================================
 *   Filesystem Operations
 * ============================================================ */

static int ramfs_mount(const char *device, int flags, void *data, struct fut_mount **mount_out) {
    (void)device;
    (void)data;

    /* Create mount structure */
    struct fut_mount *mount = fut_malloc(sizeof(struct fut_mount));
    if (!mount) {
        return -ENOMEM;
    }

    /* Create root directory vnode */
    struct ramfs_root_guard *guard = fut_malloc(sizeof(struct ramfs_root_guard));
    if (!guard) {
        fut_free(mount);
        return -ENOMEM;
    }
    guard->before = RAMFS_ROOT_CANARY_BEFORE;
    guard->after = RAMFS_ROOT_CANARY_AFTER;

    struct fut_vnode *root = &guard->vnode;

    struct ramfs_node *root_node = fut_malloc(sizeof(struct ramfs_node));
    if (!root_node) {
        fut_free(guard);
        fut_free(mount);
        return -ENOMEM;
    }

    /* Initialize root vnode */
    root->type = VN_DIR;
    root->ino = 1;  /* Root always has inode 1 */
    root->mode = 0755;
    root->size = 0;
    root->nlinks = 2;
    root->mount = mount;
    root->fs_data = root_node;
    root->refcount = 1;
    root->ops = &ramfs_vnode_ops;

    fut_vfs_register_root_canary(&guard->before, &guard->after);

    /* Initialize root directory */
    root_node->dir.entries = NULL;

    /* Initialize mount */
    mount->device = NULL;
    mount->mountpoint = NULL;
    mount->fs = NULL;  /* Set by VFS */
    mount->root = root;
    mount->flags = flags;
    mount->fs_data = NULL;
    mount->next = NULL;

    *mount_out = mount;
    return 0;
}

static int ramfs_unmount(struct fut_mount *mount) {
    if (!mount || !mount->root) {
        return -EINVAL;
    }

    /* TODO: Free all vnodes and data */
    /* For now, just free the mount structure */
    (void)mount;

    return 0;
}

static const struct fut_fs_type ramfs_type = {
    .name = "ramfs",
    .mount = ramfs_mount,
    .unmount = ramfs_unmount
};

/* ============================================================
 *   RamFS Registration
 * ============================================================ */

void fut_ramfs_init(void) {
    fut_vfs_register_fs(&ramfs_type);
}
