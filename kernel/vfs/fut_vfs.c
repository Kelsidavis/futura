/* fut_vfs.c - Futura OS Virtual File System Implementation
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Core VFS implementation with filesystem registration and mount management.
 */

#include <kernel/fut_vfs.h>
#include <kernel/fut_memory.h>
#include <kernel/fut_mm.h>
#include <kernel/fut_task.h>
#include <kernel/fut_timer.h>
#include <kernel/chrdev.h>
#include <kernel/devfs.h>
#include <kernel/errno.h>
#include <platform/platform.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/stat.h>

#include <kernel/kprintf.h>

/* Permission checking functions (vfs_check_*_perm) provided by fut_vfs.h */

/* Forward declarations for sync functions */
int fut_vfs_sync_all(void);
int fut_vfs_sync_fs(struct fut_mount *mount);

/* Uncomment for verbose VFS tracing */
#define DEBUG_VFS 0
#define DEBUG_READ 0

#if DEBUG_VFS
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
/* Reduced to 4 to prevent stack overflow. Since fut_vfs_open() calls both
 * lookup_vnode() AND lookup_parent_and_name(), and each allocates
 * components[MAX_PATH_COMPONENTS][256], we need: 4 * 256 = 1KB per function.
 * Total stack usage: 2KB instead of 4KB. Most paths have 2-3 components anyway. */
#define MAX_PATH_COMPONENTS 4

static const struct fut_fs_type *registered_fs[MAX_FS_TYPES];
static int num_fs_types = 0;

static struct fut_mount *mount_list = NULL;

/* Debug counter for ARM64 - non-allocating trace */
volatile int vfs_debug_stage = 0;
static uint64_t next_device_id = 1;  /* Counter for generating unique device IDs */
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
 *   Per-Task File Descriptor Management
 * ============================================================ */

/**
 * Allocate an FD in a task's FD table.
 *
 * @param task  Task whose FD table to allocate from
 * @param file  File structure to allocate
 * @return FD number on success, negative error code on failure
 */
static int alloc_fd_for_task(fut_task_t *task, struct fut_file *file) {
    if (!task || !task->fd_table || !file) {
        return -EINVAL;
    }

    /* Find first available FD */
    for (int i = 0; i < task->max_fds; i++) {
        if (task->fd_table[i] == NULL) {
            task->fd_table[i] = file;
            return i;
        }
    }

    /* FD table is full - could expand here in future */
    return -EMFILE;  /* Too many open files */
}

/**
 * Get file from task's FD table.
 *
 * @param task  Task whose FD table to query
 * @param fd    File descriptor number
 * @return File structure, or NULL if invalid/not open
 */
static struct fut_file *get_file_from_task(fut_task_t *task, int fd) {
    if (!task || !task->fd_table || fd < 0 || fd >= task->max_fds) {
        return NULL;
    }
    return task->fd_table[fd];
}

/**
 * Close an FD in task's FD table (release file).
 *
 * @param task  Task whose FD to close
 * @param fd    File descriptor to close
 */
static void close_fd_in_task(fut_task_t *task, int fd) {
    if (!task || !task->fd_table || fd < 0 || fd >= task->max_fds) {
        return;
    }

    struct fut_file *file = task->fd_table[fd];
    if (file == NULL) {
        return;
    }

    /* Decrement refcount - VFS layer manages actual cleanup */
    if (file->refcount > 0) {
        file->refcount--;
    }

    task->fd_table[fd] = NULL;
}

/**
 * Free an FD entry without closing (used internally).
 *
 * @param task  Task whose FD to free
 * @param fd    File descriptor to free
 */
static __attribute__((unused)) void free_fd_in_task(fut_task_t *task, int fd) {
    if (!task || !task->fd_table || fd < 0 || fd >= task->max_fds) {
        return;
    }
    task->fd_table[fd] = NULL;
}

/**
 * Allocate a specific FD in task's table (for dup2).
 *
 * @param task      Task whose FD table to use
 * @param target_fd Target FD number
 * @param file      File to allocate
 * @return target_fd on success, negative error code on failure
 */
static int alloc_specific_fd_for_task(fut_task_t *task, int target_fd, struct fut_file *file) {
    if (!task || !task->fd_table || !file) {
        return -EINVAL;
    }

    if (target_fd < 0 || target_fd >= task->max_fds) {
        return -EBADF;
    }

    /* Close existing file if any */
    if (task->fd_table[target_fd] != NULL) {
        close_fd_in_task(task, target_fd);
    }

    task->fd_table[target_fd] = file;
    return target_fd;
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
                  const char *fstype, int flags, void *data, fut_handle_t block_device_handle) {
    vfs_debug_stage = 200;  /* Entry to mount */

    /* Find filesystem type */
    const struct fut_fs_type *fs = find_fs_type(fstype);
    if (!fs) {
        return -ENOENT;  /* Filesystem type not found */
    }
    vfs_debug_stage = 201;  /* Found FS type */

    /* Create mount structure */
    struct fut_mount *mount = NULL;
    vfs_debug_stage = 202;  /* Before fs->mount() */
    int ret = fs->mount(device, flags, data, block_device_handle, &mount);
    vfs_debug_stage = 203;  /* After fs->mount() */
    if (ret < 0) {
        return ret;
    }

    /* Set mount point info */
    mount->device = device;
    mount->mountpoint = mountpoint;
    mount->fs = fs;
    mount->flags = flags;
    mount->st_dev = next_device_id++;  /* Assign unique device ID */
    mount->block_device_handle = block_device_handle;  /* Store capability handle */

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

    /* Allocate scratch buffer on heap to avoid stack overflow */
    char (*mount_components)[FUT_VFS_NAME_MAX + 1] = fut_malloc(MAX_PATH_COMPONENTS * (FUT_VFS_NAME_MAX + 1));
    if (!mount_components) {
        return NULL;  /* OOM - no mount */
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
            fut_free(mount_components);
            return mount;
        }

        mount = mount->next;
    }

    fut_free(mount_components);
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
        /* Note: Root vnode is never freed, so we don't take/release references to it */
        return 0;
    }

#if DEBUG_VFS
    const char *orig_path = path;
#endif

    /* Use heap allocation to avoid stack overflow - each component array is 1KB */
    size_t alloc_size = MAX_PATH_COMPONENTS * (FUT_VFS_NAME_MAX + 1);
    char (*components)[FUT_VFS_NAME_MAX + 1] = fut_malloc(alloc_size);
    VFSDBG("[vfs-heap] lookup_vnode malloc(%llu) = %p\n",
           (unsigned long long)alloc_size, (void*)components);
    if (!components) {
        return -ENOMEM;
    }

    int num_components = parse_path(path, components, MAX_PATH_COMPONENTS);
    if (num_components < 0) {
        VFSDBG("[vfs-heap] lookup_vnode freeing %p (parse_path failed)\n", (void*)components);
        fut_free(components);
        return num_components;
    }

    if (num_components == 0) {
        VFSDBG("[vfs-heap] lookup_vnode freeing %p (num==0)\n", (void*)components);
        fut_free(components);
        return -EINVAL;
    }

    /* Start from root */
    if (!root_vnode) {
        VFSDBG("[vfs-heap] lookup_vnode freeing %p (no root)\n", (void*)components);
        fut_free(components);
        return -ENOENT;
    }

    struct fut_vnode *current = root_vnode;
    /* Note: We do not take a reference to root_vnode; it's always valid */
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
            fut_free(components);
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
                /* Only take reference if mount->root is not the root vnode */
                if (current != root_vnode_base) {
                    fut_vnode_ref(current);
                }
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
                fut_free(components);
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
            fut_free(components);
            return -ENOTDIR;
        }

        /* Lookup next component */
        if (!current->ops || !current->ops->lookup) {
            release_lookup_ref(current);
            fut_free(components);
            return -ENOENT;
        }

        struct fut_vnode *next = NULL;
        VFSDBG("[vfs]  lookup component %s on vnode %p\n", component, (void *)current);
        int ret = current->ops->lookup(current, component, &next);

        if (ret < 0) {
            VFSDBG("[vfs]  component lookup failed ret=%d\n", ret);
            VFSDBG("[vfs]  about to release_lookup_ref(%p)\n", (void*)current);
            release_lookup_ref(current);
            VFSDBG("[vfs]  released OK, about to free components=%p\n", (void*)components);
            fut_free(components);
            VFSDBG("[vfs]  freed OK, returning %d\n", ret);
            return ret;
        }

        /* Handle case where lookup succeeded but vnode was not found */
        if (next == NULL) {
            release_lookup_ref(current);
            VFSDBG("[vfs]  -> lookup('%s') = NULL (not found)\n", component);
            fut_free(components);
            return -ENOENT;
        }

        VFSDBG("[vfs]  -> lookup('%s') = %p (ino=%llu type=%d)\n",
               component,
               (void *)next,
               next ? (unsigned long long)next->ino : 0ULL,
               next ? (int)next->type : -1);

        /* Follow symlinks during path resolution (unless it's the final component and we want lstat semantics) */
        if (next->type == VN_LNK) {
            /* Check if there's a readlink operation */
            if (next->ops && next->ops->readlink) {
                char link_target[256];
                int link_ret = next->ops->readlink(next, link_target, sizeof(link_target) - 1);
                if (link_ret > 0) {
                    link_target[link_ret] = '\0';
                    VFSDBG("[vfs]  symlink '%s' -> '%s'\n", component, link_target);

                    /* Release the symlink vnode */
                    release_lookup_ref(next);

                    /* Recursively resolve the symlink target */
                    int symlink_ret = lookup_vnode(link_target, &next);
                    if (symlink_ret < 0) {
                        release_lookup_ref(current);
                        fut_free(components);
                        VFSDBG("[vfs] ELOOP: failed to resolve symlink target '%s' ret=%d\n", link_target, symlink_ret);
                        return symlink_ret;
                    }

                    if (!next) {
                        release_lookup_ref(current);
                        fut_free(components);
                        VFSDBG("[vfs] ELOOP: symlink target '%s' resolved to NULL\n", link_target);
                        return -ENOENT;
                    }

                    VFSDBG("[vfs]  resolved symlink to vnode=%p ino=%llu\n",
                           (void *)next, next ? (unsigned long long)next->ino : 0ULL);
                } else if (link_ret < 0) {
                    /* readlink failed */
                    release_lookup_ref(current);
                    release_lookup_ref(next);
                    fut_free(components);
                    VFSDBG("[vfs] ELOOP: readlink failed ret=%d\n", link_ret);
                    return link_ret;
                }
            } else {
                /* No readlink operation - treat symlink as broken */
                release_lookup_ref(current);
                release_lookup_ref(next);
                fut_free(components);
                VFSDBG("[vfs] ELOOP: symlink has no readlink operation\n");
                return -ELOOP;
            }
        }

        release_lookup_ref(current);
        current = next;
        i++;
    }

    *vnode = current;
    VFSDBG("[vfs] lookup_vnode done vnode=%p ino=%llu\n",
           (void *)current,
           current ? (unsigned long long)current->ino : 0ULL);
    VFSDBG("[vfs-heap] lookup_vnode freeing %p\n", (void*)components);
    fut_free(components);
    VFSDBG("[vfs-heap] lookup_vnode freed %p OK\n", (void*)components);
    return 0;
}

static int lookup_parent_and_name(const char *path,
                                  struct fut_vnode **parent_out,
                                  char name_out[FUT_VFS_NAME_MAX + 1]) {
    vfs_debug_stage = 1;  /* Entry */
    if (!path || !parent_out || !name_out) {
        return -EINVAL;
    }

    vfs_debug_stage = 2;  /* Before malloc */
    /* Use heap allocation to avoid stack overflow */
    char (*components)[FUT_VFS_NAME_MAX + 1] = fut_malloc(MAX_PATH_COMPONENTS * (FUT_VFS_NAME_MAX + 1));
    vfs_debug_stage = 3;  /* After malloc */
    if (!components) {
        return -ENOMEM;
    }

    vfs_debug_stage = 4;  /* Before parse_path */
    int num_components = parse_path(path, components, MAX_PATH_COMPONENTS);
    vfs_debug_stage = 5;  /* After parse_path */
    if (num_components < 0) {
        fut_free(components);
        return num_components;
    }

    vfs_debug_stage = 6;  /* After num_components check */
    if (num_components == 0) {
        fut_free(components);
        return -EINVAL;
    }

    vfs_debug_stage = 7;  /* Before root_vnode check */
    if (!root_vnode) {
        fut_free(components);
        return -ENOENT;
    }

    vfs_debug_stage = 8;  /* Before loop */
    struct fut_vnode *current = root_vnode;
    /* Note: Do NOT take reference to root_vnode; it is never freed */

    for (int i = 0; i < num_components - 1; i++) {
        vfs_debug_stage = 10 + i;  /* Loop iteration marker */
        struct fut_mount *mount = find_mount_for_path(components, i + 1);
        vfs_debug_stage = 20 + i;  /* After find_mount */
        if (mount && mount->root) {
            /* Release previous vnode only if it wasn't root */
            if (current != root_vnode_base) {
                release_lookup_ref(current);
            }
            current = mount->root;
            /* Do NOT take reference to mount->root if it's root_vnode */
            if (current != root_vnode_base) {
                fut_vnode_ref(current);
            }
            continue;
        }

        if (current->type != VN_DIR || !current->ops || !current->ops->lookup) {
            release_lookup_ref(current);
            fut_free(components);
            return -ENOTDIR;
        }

        struct fut_vnode *next = NULL;
        int ret = current->ops->lookup(current, components[i], &next);
        if (ret < 0) {
            if (current != root_vnode_base) {
                release_lookup_ref(current);
            }
            fut_free(components);
            return ret;
        }

        /* Handle case where lookup succeeded but vnode was not found */
        if (next == NULL) {
            if (current != root_vnode_base) {
                release_lookup_ref(current);
            }
            fut_free(components);
            return -ENOENT;
        }

        if (current != root_vnode_base) {
            release_lookup_ref(current);
        }
        current = next;
    }

    vfs_debug_stage = 30;  /* After loop */
    if (current == NULL || current->type != VN_DIR) {
        if (current != root_vnode_base) {
            release_lookup_ref(current);
        }
        fut_free(components);
        return -ENOTDIR;
    }

    vfs_debug_stage = 31;  /* Before str_copy */
    str_copy(name_out, components[num_components - 1], FUT_VFS_NAME_MAX + 1);
    vfs_debug_stage = 32;  /* Before free */
    *parent_out = current;
    /* Return current with reference held - only release if not root */
    fut_free(components);
    vfs_debug_stage = 33;  /* Success */
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
    vfs_debug_stage = 100;  /* Entry to mkdir */
    struct fut_vnode *parent = NULL;
    char leaf[FUT_VFS_NAME_MAX + 1];

    vfs_debug_stage = 101;  /* Before lookup_parent_and_name */
    int ret = lookup_parent_and_name(path, &parent, leaf);
    vfs_debug_stage = 102;  /* After lookup_parent_and_name */
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
    if (fd < 0) {
        return NULL;
    }

    /* Prefer the current task's FD table so user FDs stay isolated. */
    fut_task_t *task = fut_task_current();
    if (task) {
        struct fut_file *file = get_file_from_task(task, fd);
        if (file) {
            return file;
        }
    }

    if (fd >= MAX_OPEN_FILES) {
        return NULL;
    }
    return file_table[fd];
}

static void free_fd(int fd) {
    if (fd >= 0 && fd < MAX_OPEN_FILES) {
        file_table[fd] = NULL;
    }
}

/* Exported versions for dup2() syscall */
struct fut_file *vfs_get_file(int fd) {
    return get_file(fd);
}

void vfs_free_fd(int fd) {
    free_fd(fd);
}

/* Public API for getting file from FD (for testing) */
struct fut_file *fut_vfs_get_file(int fd) {
    return get_file(fd);
}

int fut_vfs_readdir_fd(int fd, uint64_t *cookie, struct fut_vdirent *dirent) {
    if (!cookie || !dirent) {
        return -EINVAL;
    }

    struct fut_file *file = vfs_get_file(fd);
    if (!file) {
        return -EBADF;
    }

    struct fut_vnode *dir = file->vnode;
    if (!dir) {
        return -EBADF;
    }

    if (dir->type != VN_DIR) {
        return -ENOTDIR;
    }

    if (!dir->ops || !dir->ops->readdir) {
        return -ENOSYS;
    }

    /* Use the file descriptor's offset as the starting cookie */
    uint64_t pos = file->offset;

    /* Call the vnode's readdir operation */
    int ret = dir->ops->readdir(dir, &pos, dirent);

    /* Update the file descriptor's offset for next read */
    if (ret > 0) {
        file->offset = pos;
    }

    /* Return the updated cookie to caller */
    *cookie = pos;

    return ret;
}

void vfs_file_ref(struct fut_file *file) {
    if (file) {
        file->refcount++;
    }
}

int vfs_alloc_specific_fd(int target_fd, struct fut_file *file) {
    if (target_fd < 0 || target_fd >= MAX_OPEN_FILES) {
        return -EBADF;
    }

    /* Close existing file if any */
    if (file_table[target_fd] != NULL) {
        /* Should have been closed by caller, but be safe */
        return -EBUSY;
    }

    file_table[target_fd] = file;
    return target_fd;
}

/* ============================================================
 *   Per-Task FD Management (Public API)
 * ============================================================ */

/**
 * Get file from a task's FD table.
 * Public wrapper for per-task FD access.
 */
struct fut_file *vfs_get_file_from_task(struct fut_task *task, int fd) {
    return get_file_from_task((fut_task_t *)task, fd);
}

/**
 * Allocate a specific FD in a task's FD table (for dup2).
 * Public wrapper for per-task FD allocation.
 */
int vfs_alloc_specific_fd_for_task(struct fut_task *task, int target_fd, struct fut_file *file) {
    return alloc_specific_fd_for_task((fut_task_t *)task, target_fd, file);
}

/**
 * Close an FD in a task's FD table.
 * Public wrapper for per-task FD closing.
 */
void vfs_close_fd_in_task(struct fut_task *task, int fd) {
    close_fd_in_task((fut_task_t *)task, fd);
}

static int try_open_chrdev(const char *path, int flags) {
    unsigned major = 0;
    unsigned minor = 0;
    int devfs_ret = devfs_lookup_chr(path, &major, &minor);
    if (devfs_ret != 0) {
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
    file->owner_pid = 0;

    if (ops->open) {
        int rc = ops->open(inode, flags, &file->chr_private);
        if (rc < 0) {
            fut_free(file);
            return rc;
        }
    }

    /* Use per-task FD table instead of global file_table */
    fut_task_t *task = fut_task_current();
    int fd;
    if (task && task->fd_table) {
        fd = alloc_fd_for_task(task, file);
    } else {
        /* Fallback to global table if no task context */
        fd = alloc_fd(file);
    }

    if (fd < 0) {
        if (ops->release) {
            ops->release(inode, file->chr_private);
        }
        fut_free(file);
        return fd;
    }

    if (task) {
        fut_printf("[CHR-OPEN] path=%p pid=%llu fd=%d\n",
                   (const void *)path,
                   task ? task->pid : 0,
                   fd);
    } else {
        fut_printf("[CHR-OPEN] path=%p pid=0 fd=%d (no task context)\n",
                   (const void *)path,
                   fd);
    }

    return fd;
}

/**
 * Allocate a file descriptor for a character device or pipe.
 * Used by sys_pipe() to create pipe file descriptors.
 *
 * @param ops   File operations for this device
 * @param inode Device inode (can be NULL for pipes)
 * @param priv  Private data pointer (e.g., pipe buffer)
 * @return File descriptor on success, negative error code on failure
 */
int chrdev_alloc_fd(const struct fut_file_ops *ops, void *inode, void *priv) {
    if (!ops) {
        return -EINVAL;
    }

    struct fut_file *file = fut_malloc(sizeof(struct fut_file));
    if (!file) {
        return -ENOMEM;
    }

    file->vnode = NULL;
    file->offset = 0;
    file->flags = O_RDWR;
    file->refcount = 1;
    file->chr_ops = ops;
    file->chr_inode = inode;
    file->chr_private = priv;
    file->fd_flags = 0;  /* No close-on-exec for device files by default */
    file->owner_pid = 0;

    /* Get current task for per-task FD allocation */
    fut_task_t *task = fut_task_current();

    int fd;
    if (task && task->fd_table) {
        /* Allocate FD in current task's FD table */
        fd = alloc_fd_for_task(task, file);
    } else {
        /* Fallback to global allocation (shouldn't happen in normal operation) */
        fd = alloc_fd(file);
    }

    if (fd < 0) {
        fut_free(file);
        return fd;
    }

    return fd;
}

/* ============================================================
 *   Permission Checking
 * ============================================================ */

/* POSIX file mode permission bits (S_I*) and file type macros (S_IS*)
 * are provided by sys/stat.h */

/**
 * Check if a file operation is allowed based on file mode (POSIX permissions).
 * Implements standard Unix permission checking: owner, group, other.
 * Currently assumes all files are owned by root (uid 0, gid 0).
 *
 * @param vnode VNode to check
 * @param task Task (process) requesting access (NULL = current task)
 * @param check_write True to check write permission, false for read
 * @return 0 if allowed, -EACCES if denied
 */
static int check_file_permission(struct fut_vnode *vnode, fut_task_t *task, bool check_write) {
    if (!vnode) {
        return -EINVAL;
    }

    uint32_t mode = vnode->mode;

    /* Get task credentials if not provided */
    if (!task) {
        task = fut_task_current();
    }

    uint32_t task_uid = task ? task->uid : 0;
    uint32_t task_gid = task ? task->gid : 0;

    /* For now, assume all files are owned by root (uid 0, gid 0) */
    uint32_t file_uid = 0;
    uint32_t file_gid = 0;
    uint32_t perm_bits = 0;

    /* Determine which permission bits to check: owner, group, or other */
    if (task_uid == file_uid) {
        /* Process is the file owner - check owner permissions */
        perm_bits = (mode >> 6) & 7;  /* Owner: bits 6-8 */
    } else if (task_gid == file_gid) {
        /* Process is in the file's group - check group permissions */
        perm_bits = (mode >> 3) & 7;  /* Group: bits 3-5 */
    } else {
        /* Process is neither owner nor in group - check other permissions */
        perm_bits = mode & 7;          /* Other: bits 0-2 */
    }

    /* Check for the required permission bit */
    if (check_write) {
        /* Check write permission (bit 1 = 0o002 for other, etc.) */
        if (!(perm_bits & 2)) {
            fut_printf("[VFS-PERM] Write denied: pid=%llu uid=%u mode=0%o\n",
                      task ? task->pid : 0, task_uid, mode);
            return -EACCES;
        }
    } else {
        /* Check read permission (bit 2 = 0o004 for other, etc.) */
        if (!(perm_bits & 4)) {
            fut_printf("[VFS-PERM] Read denied: pid=%llu uid=%u mode=0%o\n",
                      task ? task->pid : 0, task_uid, mode);
            return -EACCES;
        }
    }

    return 0;
}

/* ============================================================
 *   File Operations
 * ============================================================ */

int fut_vfs_open(const char *path, int flags, int mode) {
    struct fut_vnode *vnode = NULL;
    int ret;
    bool created = false;

    /* Get current task for per-task FD table */
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    int chr_fd = try_open_chrdev(path, flags);
    if (chr_fd != -ENOENT) {
        return chr_fd;
    }

    /* Lookup vnode */
    ret = lookup_vnode(path, &vnode);
    if (ret < 0) {
        /* If O_CREAT is set and parent exists, create new file */
        if ((flags & O_CREAT) && (ret == -ENOENT || ret == -2)) {
            VFSDBG("[vfs-open] O_CREAT path triggered for %s\n", path);
            struct fut_vnode *parent = NULL;
            /* Allocate leaf buffer on heap to avoid stack overflow */
            char *leaf = fut_malloc(FUT_VFS_NAME_MAX + 1);
            if (!leaf) {
                return -ENOMEM;
            }

            VFSDBG("[vfs-open] calling lookup_parent_and_name\n");
            int lookup_ret = lookup_parent_and_name(path, &parent, leaf);
            VFSDBG("[vfs-open] lookup_parent_and_name returned %d\n", lookup_ret);
            if (lookup_ret < 0) {
                fut_free(leaf);
                return lookup_ret;
            }

            VFSDBG("[vfs-open] parent=%p leaf='%s'\n", (void*)parent, leaf);
            if (!parent->ops || !parent->ops->create) {
                VFSDBG("[vfs-open] parent has no create op\n");
                release_lookup_ref(parent);
                fut_free(leaf);
                return -ENOSYS;
            }

            VFSDBG("[vfs-open] calling parent->ops->create\n");
            struct fut_vnode *new_node = NULL;
            int create_ret = parent->ops->create(parent, leaf, (uint32_t)mode, &new_node);
            VFSDBG("[vfs-open] create returned %d new_node=%p\n", create_ret, (void*)new_node);
            VFSDBG("[vfs-open] about to release_lookup_ref(parent=%p)\n", (void*)parent);
            release_lookup_ref(parent);
            fut_free(leaf);  /* Done with leaf buffer */
            VFSDBG("[vfs-open] released parent OK\n");
            if (create_ret < 0) {
                VFSDBG("[vfs-open] create failed, returning %d\n", create_ret);
                return create_ret;
            }
            VFSDBG("[vfs-open] create succeeded, continuing\n");

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
    VFSDBG("[vfs-open] checking vnode type, vnode=%p\n", (void*)vnode);
    VFSDBG("[vfs-open] about to read vnode->type at %p\n", (void*)&vnode->type);
    int vtype = vnode->type;
    VFSDBG("[vfs-open] vnode->type=%d flags=%d\n", vtype, flags);
    if (vtype == VN_DIR && (flags & (O_WRONLY | O_RDWR))) {
        VFSDBG("[vfs-open] trying to open dir with write flags, returning EISDIR\n");
        release_lookup_ref(vnode);
        return -EISDIR;
    }

    /* Permission checks based on access mode (unless we just created the file) */
    if (!created) {
        int access_mode = flags & O_ACCMODE;

        /* Check read permission for O_RDONLY and O_RDWR */
        if (access_mode == O_RDONLY || access_mode == O_RDWR) {
            ret = vfs_check_read_perm(vnode);
            if (ret < 0) {
                VFSDBG("[vfs-open] read permission denied\n");
                release_lookup_ref(vnode);
                return -EACCES;
            }
        }

        /* Check write permission for O_WRONLY and O_RDWR */
        if (access_mode == O_WRONLY || access_mode == O_RDWR) {
            ret = vfs_check_write_perm(vnode);
            if (ret < 0) {
                VFSDBG("[vfs-open] write permission denied\n");
                release_lookup_ref(vnode);
                return -EACCES;
            }
        }
    }

    /* Call vnode open operation */
    VFSDBG("[vfs-open] checking if vnode has open op\n");
    if (vnode->ops && vnode->ops->open) {
        VFSDBG("[vfs-open] calling vnode->ops->open\n");
        ret = vnode->ops->open(vnode, flags);
        VFSDBG("[vfs-open] vnode->ops->open returned %d\n", ret);
        if (ret < 0) {
            release_lookup_ref(vnode);
            return ret;
        }
    }
    VFSDBG("[vfs-open] past vnode open check\n");

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
    file->owner_pid = 0;

    /* Check permissions for write access */
    if ((flags & (O_WRONLY | O_RDWR)) && !created) {
        /* For existing files, check if write is allowed */
        int perm_ret = check_file_permission(vnode, NULL, true);
        if (perm_ret < 0) {
            fut_printf("[VFS-OPEN] Write permission denied for '%s' (mode=0%o)\n", path, vnode->mode);
            fut_free(file);
            release_lookup_ref(vnode);
            return perm_ret;
        }
    }

    /* Allocate file descriptor in task's FD table */
    int fd = alloc_fd_for_task(task, file);
    if (fd < 0) {
        fut_free(file);
        release_lookup_ref(vnode);
        fut_printf("[VFS-OPEN] alloc_fd_for_task failed, returning %d\n", fd);
        return fd;
    }

    /* Store mode for newly created files */
    if (created) {
        vnode->mode = mode & 0777;  /* Use provided mode, mask to permission bits only */
    }

#if DEBUG_VFS
    fut_printf("[VFS-OPEN] SUCCESS: opened '%s' as fd=%d (mode=0%o)\n", path, fd, vnode->mode);
#endif
    return fd;
}

ssize_t fut_vfs_read(int fd, void *buf, size_t size) {
#if DEBUG_READ
    fut_printf("[vfs-read] fd=%d buf=%p size=%zu\n", fd, buf, size);
#endif
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    struct fut_file *file = get_file_from_task(task, fd);
    if (!file) {
#if DEBUG_READ
        fut_printf("[vfs-read] EBADF: no file for fd=%d\n", fd);
#endif
        return -EBADF;
    }

    if (file->chr_ops) {
#if DEBUG_READ
        fut_printf("[vfs-read] chr_ops path, read=%p\n", (void*)(uintptr_t)file->chr_ops->read);
#endif
        if (!file->chr_ops->read) {
#if DEBUG_READ
            fut_printf("[vfs-read] EINVAL: no chr_ops->read\n");
#endif
            return -EINVAL;
        }
        off_t pos = (off_t)file->offset;
        ssize_t ret = file->chr_ops->read(file->chr_inode, file->chr_private, buf, size, &pos);
#if DEBUG_READ
        fut_printf("[vfs-read] chr_ops->read returned %zd\n", ret);
#endif
        if (ret > 0) {
            file->offset = (uint64_t)pos;
        }
        return ret;
    }

    /* Call vnode read operation */
    if (!file->vnode || !file->vnode->ops || !file->vnode->ops->read) {
        return -EINVAL;
    }

    /* Check read permission */
    int perm_ret = check_file_permission(file->vnode, NULL, false);
    if (perm_ret < 0) {
        VFSDBG("[vfs-read] Read permission denied (mode=0%o)\n", file->vnode->mode);
        return perm_ret;
    }

    ssize_t ret = file->vnode->ops->read(file->vnode, buf, size, file->offset);
    if (ret > 0) {
        file->offset += ret;
    }

    return ret;
}

ssize_t fut_vfs_write(int fd, const void *buf, size_t size) {
    VFSDBG("[vfs-write] enter fd=%d size=%llu\n", fd, (unsigned long long)size);
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    struct fut_file *file = get_file_from_task(task, fd);
    VFSDBG("[vfs-write] get_file_from_task returned %p\n", (void*)file);
    if (!file) {
        return -EBADF;
    }

    if (file->chr_ops) {
        VFSDBG("[vfs-write] chr_ops path\n");
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
    VFSDBG("[vfs-write] vnode path, checking ops\n");
    if (!file->vnode || !file->vnode->ops || !file->vnode->ops->write) {
        VFSDBG("[vfs-write] invalid vnode/ops/write\n");
        return -EINVAL;
    }

    /* Check write permission */
    int perm_ret = check_file_permission(file->vnode, NULL, true);
    if (perm_ret < 0) {
        VFSDBG("[vfs-write] Write permission denied (mode=0%o)\n", file->vnode->mode);
        return perm_ret;
    }

    VFSDBG("[vfs-write] calling vnode->ops->write\n");
    ssize_t ret = file->vnode->ops->write(file->vnode, buf, size, file->offset);
    VFSDBG("[vfs-write] vnode->ops->write returned %lld\n", (long long)ret);
    if (ret > 0) {
        file->offset += ret;
    }

    VFSDBG("[vfs-write] returning %lld\n", (long long)ret);
    return ret;
}

int fut_vfs_close(int fd) {
    VFSDBG("[vfs-close] close fd=%d\n", fd);
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    struct fut_file *file = get_file_from_task(task, fd);
    VFSDBG("[vfs-close] get_file_from_task returned file=%p\n", (void*)file);
    if (!file) {
        return -EBADF;
    }

    if (file->chr_ops) {
        VFSDBG("[vfs-close] chr_ops path\n");
        if (file->chr_ops->release) {
            file->chr_ops->release(file->chr_inode, file->chr_private);
        }
        close_fd_in_task(task, fd);
        return 0;
    }

    VFSDBG("[vfs-close] vnode path, file->vnode=%p\n", (void*)file->vnode);
    /* Call vnode close operation */
    if (file->vnode && file->vnode->ops && file->vnode->ops->close) {
        VFSDBG("[vfs-close] calling vnode->ops->close\n");
        file->vnode->ops->close(file->vnode);
        VFSDBG("[vfs-close] vnode->ops->close returned\n");
    }

    /* Release vnode reference - CRITICAL! */
    if (file->vnode) {
        VFSDBG("[vfs-close] calling fut_vnode_unref(vnode=%p)\n", (void*)file->vnode);
        fut_vnode_unref(file->vnode);
        VFSDBG("[vfs-close] fut_vnode_unref returned\n");
    }

    /* Free file structure */
    VFSDBG("[vfs-close] calling close_fd_in_task\n");
    close_fd_in_task(task, fd);
    /* File is now removed from task's FD table, refcount handled by close_fd_in_task */
    VFSDBG("[vfs-close] fut_free returned\n");

    return 0;
}

int64_t fut_vfs_lseek(int fd, int64_t offset, int whence) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    struct fut_file *file = get_file_from_task(task, fd);
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
        stat->st_dev = vnode->mount ? vnode->mount->st_dev : 0;
        stat->st_uid = 0;
        stat->st_gid = 0;
        stat->st_blksize = 4096;
        stat->st_blocks = (vnode->size + 4095) / 4096;

        /* Set timestamps - atime is current time (file access time),
         * mtime and ctime would ideally come from filesystem metadata.
         * Using current time as default for basic compliance. */
        uint64_t now_ns = fut_get_time_ns();
        stat->st_atime = now_ns;  /* Access time (now) */
        stat->st_mtime = now_ns;  /* Modification time (default) */
        stat->st_ctime = now_ns;  /* Change time (default) */
        ret = 0;
    }

    release_lookup_ref(vnode);
    return ret;
}

/**
 * Get file statistics without following final symlink (lstat semantics).
 * Like fut_vfs_stat() but does NOT follow the final symlink - returns
 * information about the symlink itself instead of its target.
 */
int fut_vfs_lstat(const char *path, struct fut_stat *stat) {
    if (!path || !stat) {
        return -EINVAL;
    }

    /* Handle root directory - lstat of "/" is same as stat of "/" */
    if (path[0] == '/' && path[1] == '\0') {
        return fut_vfs_stat(path, stat);
    }

    /* Get parent directory and final component name */
    struct fut_vnode *parent = NULL;
    char name[FUT_VFS_NAME_MAX + 1];
    int ret = lookup_parent_and_name(path, &parent, name);
    if (ret < 0) {
        return ret;
    }

    /* Lookup the final component in the parent directory */
    struct fut_vnode *vnode = NULL;
    if (!parent->ops || !parent->ops->lookup) {
        release_lookup_ref(parent);
        return -ENOENT;
    }

    ret = parent->ops->lookup(parent, name, &vnode);
    release_lookup_ref(parent);
    if (ret < 0) {
        return ret;
    }

    if (!vnode) {
        return -ENOENT;
    }

    /* Get stats from vnode - do NOT follow it if it's a symlink */
    if (vnode->ops && vnode->ops->getattr) {
        ret = vnode->ops->getattr(vnode, stat);
    } else {
        /* Fill basic stat info from vnode */
        stat->st_ino = vnode->ino;
        stat->st_mode = vnode->mode;
        stat->st_nlink = vnode->nlinks;
        stat->st_size = vnode->size;
        stat->st_dev = vnode->mount ? vnode->mount->st_dev : 0;
        stat->st_uid = 0;
        stat->st_gid = 0;
        stat->st_blksize = 4096;
        stat->st_blocks = (vnode->size + 4095) / 4096;

        /* Set timestamps */
        uint64_t now_ns = fut_get_time_ns();
        stat->st_atime = now_ns / 1000000000;
        stat->st_atime_nsec = now_ns % 1000000000;
        stat->st_mtime = now_ns / 1000000000;
        stat->st_mtime_nsec = now_ns % 1000000000;
        stat->st_ctime = now_ns / 1000000000;
        stat->st_ctime_nsec = now_ns % 1000000000;
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
    fut_task_t *task = fut_task_current();
    if (!task) {
        return (void *)(intptr_t)(-EPERM);
    }

    struct fut_file *file = get_file_from_task(task, fd);
    if (!file) {
        fut_printf("[VFS-MMAP] fd=%d not found in task pid=%llu fd_table (max_fds=%d)\n",
                   fd,
                   task ? task->pid : 0,
                   task ? task->max_fds : 0);
        return (void *)(intptr_t)(-EBADF);
    }

    /* Character devices may have custom mmap implementations */
    if (file->chr_ops && file->chr_ops->mmap) {
        return file->chr_ops->mmap(file->chr_inode, file->chr_private, addr, len, off, prot, flags);
    }

    /* Regular files: use generic file-backed mmap */
    if (file->vnode) {
        fut_mm_t *mm = fut_mm_current();
        if (!mm) {
            return (void *)(intptr_t)(-ENOMEM);
        }

        return fut_mm_map_file(mm, file->vnode, (uintptr_t)addr, len, prot, flags, (uint64_t)off);
    }

    return (void *)(intptr_t)(-ENODEV);
}

/* ============================================================
 *   VNode Reference Counting
 * ============================================================ */

void fut_vnode_ref(struct fut_vnode *vnode) {
    if (!vnode) {
        return;
    }

    /* Safety check: prevent overflow (refcount should never exceed a reasonable limit) */
    if (vnode->refcount >= 10000) {
        fut_printf("[VNODE-ERROR] refcount overflow: vnode=%p ino=%llu refcount=%u\n",
                   (void*)vnode, vnode->ino, vnode->refcount);
        return;
    }

    vnode->refcount++;
    VFSDBG("[vnode-ref] vnode=%p ino=%llu refcount now %u\n",
           (void*)vnode, vnode->ino, vnode->refcount);
}

void fut_vnode_unref(struct fut_vnode *vnode) {
    if (!vnode) {
        return;
    }

    /* Safety check: prevent underflow */
    if (vnode->refcount == 0) {
        fut_printf("[VNODE-ERROR] refcount underflow: vnode=%p ino=%llu type=%d\n",
                   (void*)vnode, vnode->ino, vnode->type);
        return;
    }

    vnode->refcount--;
    VFSDBG("[vnode-unref] vnode=%p ino=%llu refcount now %u\n",
           (void*)vnode, vnode->ino, vnode->refcount);

    /* Free vnode when refcount reaches 0 */
    if (vnode->refcount == 0) {
        VFSDBG("[vnode-unref] freeing vnode ino=%llu type=%d\n", vnode->ino, vnode->type);

        /* Clean up parent reference and basename */
        if (vnode->parent) {
            fut_vnode_unref(vnode->parent);
            vnode->parent = NULL;
        }
        if (vnode->name) {
            fut_free(vnode->name);
            vnode->name = NULL;
        }

        /* Free filesystem-specific data if any */
        if (vnode->fs_data) {
            /* Filesystems should clean up their own fs_data */
            /* For now, just warn if there's orphaned data */
            VFSDBG("[vnode-unref] warning: vnode has fs_data=%p, filesystem must clean up\n",
                   vnode->fs_data);
        }

        fut_free(vnode);
    }
}

/* ============================================================
 *   Sync Operations (Phase 2)
 * ============================================================ */

/**
 * Synchronize a specific filesystem to storage.
 * Calls the sync operation on the filesystem's root vnode.
 *
 * @param mount Mount point to sync
 * @return 0 on success, negative error on failure
 */
int fut_vfs_sync_fs(struct fut_mount *mount) {
    if (!mount || !mount->root) {
        return -EINVAL;
    }

    /* Call sync operation if available */
    if (mount->root->ops && mount->root->ops->sync) {
        int ret = mount->root->ops->sync(mount->root);
        if (ret < 0) {
            fut_printf("[VFS-SYNC] Failed to sync filesystem at %s: %d\n",
                       mount->mountpoint ? mount->mountpoint : "(root)", ret);
            return ret;
        }
        fut_printf("[VFS-SYNC] Synced filesystem at %s\n",
                   mount->mountpoint ? mount->mountpoint : "(root)");
        return 0;
    }

    /* No sync operation - assume in-memory filesystem (no-op) */
    fut_printf("[VFS-SYNC] Filesystem at %s has no sync operation (in-memory?)\n",
               mount->mountpoint ? mount->mountpoint : "(root)");
    return 0;
}

/**
 * Synchronize all mounted filesystems to storage.
 * Iterates through mount list and syncs each filesystem.
 *
 * @return 0 on success, negative error on failure (first error encountered)
 */
int fut_vfs_sync_all(void) {
    int first_error = 0;
    int synced = 0;

    struct fut_mount *mount = mount_list;
    while (mount) {
        int ret = fut_vfs_sync_fs(mount);
        if (ret < 0 && first_error == 0) {
            first_error = ret;  /* Record first error */
        }
        if (ret == 0) {
            synced++;
        }
        mount = mount->next;
    }

    if (synced == 0) {
        fut_printf("[VFS-SYNC] No filesystems to sync (empty mount list)\n");
    } else {
        fut_printf("[VFS-SYNC] Synced %d filesystem(s)\n", synced);
    }

    return first_error;
}
