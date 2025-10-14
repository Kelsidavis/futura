/* fut_vfs.c - Futura OS Virtual File System Implementation
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Core VFS implementation with filesystem registration and mount management.
 */

#include <kernel/fut_vfs.h>
#include <kernel/fut_memory.h>
#include <kernel/chrdev.h>
#include <kernel/devfs.h>
#include <kernel/errno.h>
#include <platform/platform.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

extern void fut_printf(const char *fmt, ...);

/* Uncomment for verbose VFS tracing */
#define DEBUG_VFS 1

#ifdef DEBUG_VFS
#define VFSDBG(...) fut_printf(__VA_ARGS__)
#else
#define VFSDBG(...) do { } while (0)
#endif

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
static struct fut_vnode *root_vnode_base = NULL;
static uint64_t *root_canary_before = NULL;
static uint64_t *root_canary_after = NULL;

#define ROOT_CANARY_BEFORE_VALUE 0xFADC0DE0CAFEBABEULL
#define ROOT_CANARY_AFTER_VALUE  0xDEADBEEFCAFED00DULL

void fut_vfs_register_root_canary(uint64_t *before, uint64_t *after) {
    root_canary_before = before;
    root_canary_after = after;
    fut_vfs_check_root_canary("register");
}

void fut_vfs_check_root_canary(const char *where) {
    if (root_canary_before && *root_canary_before != ROOT_CANARY_BEFORE_VALUE) {
        fut_printf("[VFS] root canary (before) smashed at %s\n", where);
        fut_platform_panic("root canary before corrupted");
    }
    if (root_canary_after && *root_canary_after != ROOT_CANARY_AFTER_VALUE) {
        fut_printf("[VFS] root canary (after) smashed at %s\n", where);
        fut_platform_panic("root canary after corrupted");
    }
    if (root_vnode && root_vnode->type == VN_INVALID) {
        fut_printf("[VFS] root vnode type invalid at %s\n", where);
        fut_platform_panic("root vnode corrupted");
    }
}

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
    root_vnode_base = NULL;
}

void fut_vfs_set_root(struct fut_vnode *vnode) {
    if (root_vnode_base) {
        fut_vnode_unref(root_vnode_base);
        root_vnode_base = NULL;
    }

    root_vnode = vnode;
    if (root_vnode) {
        fut_vnode_ref(root_vnode);
        root_vnode_base = root_vnode;
        VFSDBG("[vfs] root vnode set %p ref=%u\n",
               (void *)root_vnode,
               root_vnode ? root_vnode->refcount : 0);
    } else {
        VFSDBG("[vfs] root vnode cleared\n");
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

    bool is_root_mount = (mountpoint && mountpoint[0] == '/' && mountpoint[1] == '\0');

    if (mount->root && !is_root_mount) {
        fut_vnode_ref(mount->root);
    }

    /* Add to mount list */
    mount->next = mount_list;
    mount_list = mount;

    /* If mounting at root, set root vnode */
    if (is_root_mount) {
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

            bool is_root_mount = (mount->mountpoint && mount->mountpoint[0] == '/' && mount->mountpoint[1] == '\0');
            struct fut_vnode *root = mount->root;

            /* Unmount filesystem */
            if (mount->fs && mount->fs->unmount) {
                mount->fs->unmount(mount);
            }

            if (is_root_mount) {
                fut_vfs_set_root(NULL);
                if (root) {
                    fut_vnode_unref(root);
                }
            } else if (root) {
                fut_vnode_unref(root);
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

static int lookup_vnode(const char *path, struct fut_vnode **vnode);

int fut_vfs_lookup(const char *path, struct fut_vnode **out_vnode) {
    if (!out_vnode) {
        return -EINVAL;
    }
    *out_vnode = NULL;

    struct fut_vnode *vnode = NULL;
    int ret = lookup_vnode(path, &vnode);
    if (ret < 0) {
        return ret;
    }

    *out_vnode = vnode;
    return 0;
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

static bool str_equals(const char *a, const char *b) {
    while (*a && *b) {
        if (*a != *b) {
            return false;
        }
        ++a;
        ++b;
    }
    return *a == *b;
}

int fut_vfs_statfs(const char *mountpoint, struct fut_statfs *out) {
    if (!mountpoint || !out) {
        return -EINVAL;
    }

#ifndef ENOTSUP
#define ENOTSUP 95
#endif

    struct fut_mount *mount = mount_list;
    while (mount) {
        if (mount->mountpoint && str_equals(mount->mountpoint, mountpoint)) {
            break;
        }
        mount = mount->next;
    }

    if (!mount) {
        return -ENOENT;
    }

    if (!mount->fs || !mount->fs->statfs) {
        return -ENOTSUP;
    }

    return mount->fs->statfs(mount, out);
}

/**
 * Parse path into components.
 *
 * @param path       Path to parse (e.g., "/foo/bar/baz")
 * @param components Array to store component pointers
 * @param max_comp   Maximum number of components
 * @return Number of components parsed
 */
static int parse_path(const char *path,
                      char components[][FUT_VFS_NAME_MAX + 1],
                      int max_comp) {
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
        if (len > 0) {
            if (len > FUT_VFS_NAME_MAX) {
                return -ENAMETOOLONG;
            }
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

static struct fut_mount *find_mount_for_path(
    char components[][FUT_VFS_NAME_MAX + 1],
    int count) {
    if (count <= 0) {
        return NULL;
    }

    struct fut_mount *mount = mount_list;
    while (mount) {
        if (!mount->mountpoint || mount->mountpoint[0] != '/') {
            mount = mount->next;
            continue;
        }

        if (mount->mountpoint[1] == '\0') {
            /* Root mount handled separately via root_vnode */
            mount = mount->next;
            continue;
        }

        char mount_components[MAX_PATH_COMPONENTS][FUT_VFS_NAME_MAX + 1];
        int mount_count = parse_path(mount->mountpoint,
                                     mount_components,
                                     MAX_PATH_COMPONENTS);
        if (mount_count < 0 || mount_count != count) {
            mount = mount->next;
            continue;
        }

        bool match = true;
        for (int i = 0; i < count; ++i) {
            if (!str_equals(components[i], mount_components[i])) {
                match = false;
                break;
            }
        }

        if (match) {
            return mount;
        }

        mount = mount->next;
    }

    return NULL;
}

static void release_lookup_ref(struct fut_vnode *vnode) {
    if (!vnode) {
        return;
    }
    if (vnode == root_vnode_base) {
        return;
    }
    fut_vnode_unref(vnode);
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

    const char *orig_path = path;

    /* Parse path into components */
    char components[MAX_PATH_COMPONENTS][FUT_VFS_NAME_MAX + 1];
    int num_components = parse_path(path, components, MAX_PATH_COMPONENTS);

    if (num_components < 0) {
        return num_components;
    }

    if (num_components == 0) {
        return -EINVAL;
    }

    /* Start from root */
    if (!root_vnode) {
        return -ENOENT;
    }

    struct fut_vnode *current = root_vnode;
    fut_vnode_ref(current);
    VFSDBG("[vfs] lookup_vnode start current=%p ref=%u\n",
           (void *)current,
           current ? current->refcount : 0);
    VFSDBG("[vfs] root vnode type=%d\n", root_vnode ? (int)root_vnode->type : -1);
    VFSDBG("[vfs] lookup_vnode path=%s\n", path);

    /* Walk path components */
    unsigned int steps = 0;
    unsigned int max_steps = (unsigned int)(num_components * 2 + 4);

    for (int i = 0; i < num_components;) {
        if (++steps > max_steps) {
            VFSDBG("[vfs] ELOOP: exceeded step budget walking '%s'\n", path);
            release_lookup_ref(current);
            return -ELOOP;
        }

        const char *component = components[i];

        if (component[0] == '\0') {
            i++;
            continue;
        }

        if (component[0] == '.' && component[1] == '\0') {
            i++;
            continue;
        }

        if (component[0] == '.' && component[1] == '.' && component[2] == '\0') {
            /* Parent traversal not yet supported - stay within current vnode */
            VFSDBG("[vfs]  '..' component ignored (unsupported)\n");
            i++;
            continue;
        }

        struct fut_mount *mount = find_mount_for_path(components, i + 1);
        if (mount && mount->root) {
            VFSDBG("[vfs]  component %d matched mount %s root=%p\n", i, mount->mountpoint, (void *)mount->root);

            if (current != mount->root) {
                struct fut_vnode *prev = current;
                VFSDBG("[vfs]    switching from %p ref=%u to mount root\n", (void *)prev, prev ? prev->refcount : 0);
                current = mount->root;
                fut_vnode_ref(current);
                release_lookup_ref(prev);
                VFSDBG("[vfs]    prev released, new root ref=%u\n", current ? current->refcount : 0);
            }

            VFSDBG("[vfs]  after mount switch current=%p ref=%u (i=%d/%d)\n",
                   (void *)current,
                   current ? current->refcount : 0,
                   i,
                   num_components);

            if (i == num_components - 1) {
                *vnode = current;
                VFSDBG("[vfs] lookup_vnode done vnode=%p ino=%llu (mount root)\n",
                       (void *)current,
                       current ? (unsigned long long)current->ino : 0ULL);
                return 0;
            }

            i++;
            continue;
        }

        /* Check if current is a directory */
        if (current->type != VN_DIR) {
            VFSDBG("[vfs]  ENOTDIR while resolving %s: component '%s' current=%p type=%d\n",
                   orig_path,
                   component,
                   (void *)current,
                   current ? (int)current->type : -1);
            release_lookup_ref(current);
            return -ENOTDIR;
        }

        /* Lookup next component */
        if (!current->ops || !current->ops->lookup) {
            release_lookup_ref(current);
            return -ENOENT;
        }

        struct fut_vnode *next = NULL;
        VFSDBG("[vfs]  lookup component %s on vnode %p\n", component, (void *)current);
        int ret = current->ops->lookup(current, component, &next);

        if (ret < 0) {
            release_lookup_ref(current);
            VFSDBG("[vfs]  component lookup failed ret=%d\n", ret);
            return ret;
        }

        VFSDBG("[vfs]  -> lookup('%s') = %p (ino=%llu)\n",
               component,
               (void *)next,
               next ? (unsigned long long)next->ino : 0ULL);

        release_lookup_ref(current);
        current = next;
        i++;
    }

    *vnode = current;
    VFSDBG("[vfs] lookup_vnode done vnode=%p ino=%llu\n",
           (void *)current,
           current ? (unsigned long long)current->ino : 0ULL);
    return 0;
}

static int lookup_parent_and_name(const char *path,
                                  struct fut_vnode **parent_out,
                                  char name_out[FUT_VFS_NAME_MAX + 1]) {
    if (!path || !parent_out || !name_out) {
        return -EINVAL;
    }

    char components[MAX_PATH_COMPONENTS][FUT_VFS_NAME_MAX + 1];
    int num_components = parse_path(path, components, MAX_PATH_COMPONENTS);
    if (num_components < 0) {
        return num_components;
    }

    if (num_components == 0) {
        return -EINVAL;
    }

    if (!root_vnode) {
        return -ENOENT;
    }

    struct fut_vnode *current = root_vnode;
    fut_vnode_ref(current);

    for (int i = 0; i < num_components - 1; i++) {
        struct fut_mount *mount = find_mount_for_path(components, i + 1);
        if (mount && mount->root) {
            release_lookup_ref(current);
            current = mount->root;
            fut_vnode_ref(current);
            continue;
        }

        if (current->type != VN_DIR || !current->ops || !current->ops->lookup) {
            release_lookup_ref(current);
            return -ENOTDIR;
        }

        struct fut_vnode *next = NULL;
        int ret = current->ops->lookup(current, components[i], &next);
        if (ret < 0) {
            release_lookup_ref(current);
            return ret;
        }

        release_lookup_ref(current);
        current = next;
    }

    if (current->type != VN_DIR) {
        release_lookup_ref(current);
        return -ENOTDIR;
    }

    str_copy(name_out, components[num_components - 1], FUT_VFS_NAME_MAX + 1);
    *parent_out = current;
    return 0;
}

int fut_vfs_readdir(const char *path, uint64_t *cookie, struct fut_vdirent *dirent) {
    if (!path || !cookie || !dirent) {
        return -EINVAL;
    }

    struct fut_vnode *dir = NULL;
    int ret = lookup_vnode(path, &dir);
    if (ret < 0) {
        return ret;
    }

    if (dir->type != VN_DIR) {
        release_lookup_ref(dir);
        return -ENOTDIR;
    }

    if (!dir->ops || !dir->ops->readdir) {
        release_lookup_ref(dir);
        return -ENOSYS;
    }

    ret = dir->ops->readdir(dir, cookie, dirent);
    release_lookup_ref(dir);
    return ret;
}

int fut_vfs_unlink(const char *path) {
    struct fut_vnode *parent = NULL;
    char leaf[FUT_VFS_NAME_MAX + 1];

    int ret = lookup_parent_and_name(path, &parent, leaf);
    if (ret < 0) {
        return ret;
    }

    if (!parent->ops || !parent->ops->unlink) {
        release_lookup_ref(parent);
        return -ENOSYS;
    }

    ret = parent->ops->unlink(parent, leaf);
    release_lookup_ref(parent);
    return ret;
}

int fut_vfs_rmdir(const char *path) {
    struct fut_vnode *parent = NULL;
    char leaf[FUT_VFS_NAME_MAX + 1];

    int ret = lookup_parent_and_name(path, &parent, leaf);
    if (ret < 0) {
        return ret;
    }

    if (!parent->ops || !parent->ops->rmdir) {
        release_lookup_ref(parent);
        return -ENOSYS;
    }

    ret = parent->ops->rmdir(parent, leaf);
    release_lookup_ref(parent);
    return ret;
}

int fut_vfs_mkdir(const char *path, uint32_t mode) {
    struct fut_vnode *parent = NULL;
    char leaf[FUT_VFS_NAME_MAX + 1];

    int ret = lookup_parent_and_name(path, &parent, leaf);
    if (ret < 0) {
        return ret;
    }

    if (!parent->ops || !parent->ops->mkdir) {
        release_lookup_ref(parent);
        return -ENOSYS;
    }

    ret = parent->ops->mkdir(parent, leaf, mode);
    release_lookup_ref(parent);
    return ret;
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

static int try_open_chrdev(const char *path, int flags) {
    unsigned major = 0;
    unsigned minor = 0;
    if (devfs_lookup_chr(path, &major, &minor) != 0) {
        return -ENOENT;
    }

    void *inode = NULL;
    const struct fut_file_ops *ops = chrdev_lookup(major, minor, &inode);
    if (!ops) {
        return -ENODEV;
    }

    struct fut_file *file = fut_malloc(sizeof(struct fut_file));
    if (!file) {
        return -ENOMEM;
    }

    file->vnode = NULL;
    file->offset = 0;
    file->flags = flags;
    file->refcount = 1;
    file->chr_ops = ops;
    file->chr_inode = inode;
    file->chr_private = NULL;

    if (ops->open) {
        int rc = ops->open(inode, flags, &file->chr_private);
        if (rc < 0) {
            fut_free(file);
            return rc;
        }
    }

    int fd = alloc_fd(file);
    if (fd < 0) {
        if (ops->release) {
            ops->release(inode, file->chr_private);
        }
        fut_free(file);
        return fd;
    }

    return fd;
}

/* ============================================================
 *   File Operations
 * ============================================================ */

int fut_vfs_open(const char *path, int flags, int mode) {
    struct fut_vnode *vnode = NULL;
    int ret;
    bool created = false;

    int chr_fd = try_open_chrdev(path, flags);
    if (chr_fd != -ENOENT) {
        return chr_fd;
    }

    /* Lookup vnode */
    ret = lookup_vnode(path, &vnode);
    if (ret < 0) {
        /* If O_CREAT is set and parent exists, create new file */
        if ((flags & O_CREAT) && ret == -ENOENT) {
            struct fut_vnode *parent = NULL;
            char leaf[FUT_VFS_NAME_MAX + 1];

            int lookup_ret = lookup_parent_and_name(path, &parent, leaf);
            if (lookup_ret < 0) {
                return lookup_ret;
            }

            if (!parent->ops || !parent->ops->create) {
                release_lookup_ref(parent);
                return -ENOSYS;
            }

            struct fut_vnode *new_node = NULL;
            int create_ret = parent->ops->create(parent, leaf, (uint32_t)mode, &new_node);
            release_lookup_ref(parent);
            if (create_ret < 0) {
                return create_ret;
            }

            vnode = new_node;
            created = true;
        } else {
            return ret;
        }
    } else {
        if ((flags & O_CREAT) && (flags & O_EXCL)) {
            release_lookup_ref(vnode);
            return -EEXIST;
        }
    }

    /* Check if trying to open directory with write flags */
    if (vnode->type == VN_DIR && (flags & (O_WRONLY | O_RDWR))) {
        release_lookup_ref(vnode);
        return -EISDIR;
    }

    /* Call vnode open operation */
    if (vnode->ops && vnode->ops->open) {
        ret = vnode->ops->open(vnode, flags);
        if (ret < 0) {
            release_lookup_ref(vnode);
            return ret;
        }
    }

    /* Allocate file structure */
    struct fut_file *file = fut_malloc(sizeof(struct fut_file));
    if (!file) {
        release_lookup_ref(vnode);
        return -ENOMEM;
    }

    file->vnode = vnode;
    if ((flags & O_APPEND) && !created) {
        file->offset = vnode->size;
    } else {
        file->offset = 0;
    }
    file->flags = flags;
    file->refcount = 1;
    file->chr_ops = NULL;
    file->chr_inode = NULL;
    file->chr_private = NULL;

    /* Allocate file descriptor */
    int fd = alloc_fd(file);
    if (fd < 0) {
        fut_free(file);
        release_lookup_ref(vnode);
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

    if (file->chr_ops) {
        if (!file->chr_ops->read) {
            return -EINVAL;
        }
        off_t pos = (off_t)file->offset;
        ssize_t ret = file->chr_ops->read(file->chr_inode, file->chr_private, buf, size, &pos);
        if (ret > 0) {
            file->offset = (uint64_t)pos;
        }
        return ret;
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

    if (file->chr_ops) {
        if (!file->chr_ops->write) {
            return -EINVAL;
        }
        off_t pos = (off_t)file->offset;
        ssize_t ret = file->chr_ops->write(file->chr_inode, file->chr_private, buf, size, &pos);
        if (ret > 0) {
            file->offset = (uint64_t)pos;
        }
        return ret;
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

    if (file->chr_ops) {
        if (file->chr_ops->release) {
            file->chr_ops->release(file->chr_inode, file->chr_private);
        }
        free_fd(fd);
        fut_free(file);
        return 0;
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

    if (file->chr_ops) {
        return -ESPIPE;
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

    release_lookup_ref(vnode);
    return ret;
}

int fut_vfs_ioctl(int fd, unsigned long req, unsigned long arg) {
    struct fut_file *file = get_file(fd);
    if (!file) {
        return -EBADF;
    }

    if (file->chr_ops && file->chr_ops->ioctl) {
        return file->chr_ops->ioctl(file->chr_inode, file->chr_private, req, arg);
    }

    return -ENOTTY;
}

void *fut_vfs_mmap(int fd, void *addr, size_t len, int prot, int flags, off_t off) {
    struct fut_file *file = get_file(fd);
    if (!file) {
        return (void *)(intptr_t)(-EBADF);
    }

    if (file->chr_ops && file->chr_ops->mmap) {
        return file->chr_ops->mmap(file->chr_inode, file->chr_private, addr, len, off, prot, flags);
    }

    return (void *)(intptr_t)(-ENOTTY);
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
