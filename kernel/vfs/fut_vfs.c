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
#include <kernel/userns.h>
#include <kernel/chrdev.h>
#include <kernel/devfs.h>
#include <kernel/errno.h>
#include <platform/platform.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>

#include <kernel/kprintf.h>
#include <kernel/fut_socket.h>
#include <sys/mman.h>

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
/* Heap-allocated per lookup call (fut_malloc), so depth can be generous.
 * 16 * 256 = 4KB per allocation; supports paths like /proc/self/task/<tid>/status
 * which have 5 components, plus room for deeply-nested filesystem paths. */
#define MAX_PATH_COMPONENTS 16

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

    /* Enforce RLIMIT_NOFILE soft limit (resource index 7) */
    uint64_t nofile_limit = task->rlimits[7].rlim_cur;
    int max = task->max_fds;
    if (nofile_limit > 0 && nofile_limit < (uint64_t)max) {
        max = (int)nofile_limit;
    }

    /* Find first available FD within limit */
    for (int i = 0; i < max; i++) {
        if (task->fd_table[i] == NULL) {
            task->fd_table[i] = file;
            if (task->fd_flags) task->fd_flags[i] = 0;
            return i;
        }
    }

    /* FD table is full — try to grow it if RLIMIT_NOFILE allows more */
    if (nofile_limit == 0 || (uint64_t)max < nofile_limit) {
        int old_max  = task->max_fds;
        int new_size = old_max * 2;
        if (nofile_limit > 0 && (uint64_t)new_size > nofile_limit)
            new_size = (int)nofile_limit;
        if (new_size > (1 << 20)) new_size = (1 << 20);  /* Hard cap: 1M FDs */
        if (new_size <= old_max) return -EMFILE;

        /* Allocate larger tables.  Deliberately do NOT free the old tables:
         * they may be static (ARM64 early-boot) memory, not PMM heap. */
        struct fut_file **new_table =
            fut_malloc((size_t)new_size * sizeof(struct fut_file *));
        if (!new_table) return -EMFILE;

        int *new_flags = fut_malloc((size_t)new_size * sizeof(int));
        if (!new_flags) { fut_free(new_table); return -EMFILE; }

        /* Copy existing entries, zero the new extension */
        __builtin_memcpy(new_table, task->fd_table,
                         (size_t)old_max * sizeof(struct fut_file *));
        __builtin_memset(new_table + old_max, 0,
                         (size_t)(new_size - old_max) * sizeof(struct fut_file *));

        if (task->fd_flags) {
            __builtin_memcpy(new_flags, task->fd_flags,
                             (size_t)old_max * sizeof(int));
        }
        __builtin_memset(new_flags + old_max, 0,
                         (size_t)(new_size - old_max) * sizeof(int));

        task->fd_table = new_table;
        task->fd_flags = new_flags;
        task->max_fds  = new_size;

        /* First free slot is the first extended entry */
        task->fd_table[old_max] = file;
        task->fd_flags[old_max] = 0;
        return old_max;
    }

    /* RLIMIT_NOFILE reached */
    return -EMFILE;
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

    /* Dispatch inotify IN_CLOSE_WRITE or IN_CLOSE_NOWRITE before releasing the file */
    if (file->vnode && file->vnode->name[0]) {
        extern void inotify_dispatch_event(const char *, uint32_t, const char *, uint32_t);
        char close_dir[256];
        const char *vname = file->vnode->name;
        /* Build parent directory path using fut_vnode_build_path (consistent with
         * all other inotify dispatch sites in ramfs/VFS) */
        struct fut_vnode *pv = file->vnode->parent;
        if (pv) {
            if (!fut_vnode_build_path(pv, close_dir, sizeof(close_dir))) {
                close_dir[0] = '/'; close_dir[1] = '\0';
            }
        } else {
            close_dir[0] = '/'; close_dir[1] = '\0';
        }
        uint32_t close_mask = (file->flags & O_WRONLY || file->flags & O_RDWR)
            ? 0x00000008 /* IN_CLOSE_WRITE */
            : 0x00000010 /* IN_CLOSE_NOWRITE */;
        inotify_dispatch_event(close_dir, close_mask, vname, 0);

        /* Dispatch fanotify FAN_CLOSE_WRITE on close of writable files */
        if (close_mask == 0x00000008) {
            extern void fanotify_notify(const char *, uint64_t, int32_t);
            char fpath[512]; int fp = 0;
            for (int i = 0; close_dir[i] && fp < 500; i++) fpath[fp++] = close_dir[i];
            if (fp > 1) fpath[fp++] = '/';
            for (int i = 0; vname[i] && fp < 510; i++) fpath[fp++] = vname[i];
            fpath[fp] = '\0';
            fut_task_t *ft = fut_task_current();
            fanotify_notify(fpath, 0x00000008 /* FAN_CLOSE_WRITE */, ft ? (int32_t)ft->pid : 0);
        }
    }

    task->fd_table[fd] = NULL;
    if (task->fd_flags) task->fd_flags[fd] = 0;

    /* Notify epoll instances that this fd is closing */
    extern void epoll_notify_fd_close(int fd);
    epoll_notify_fd_close(fd);

    /* Clear socket tracking table to prevent stale entries */
    release_socket_fd(fd);

    /* Atomically decrement refcount and clean up on last reference */
    uint32_t remaining = __atomic_sub_fetch(&file->refcount, 1, __ATOMIC_ACQ_REL);
    if (remaining > 0) {
        return;
    }

    if (file->chr_ops) {
        if (file->chr_ops->release) {
            file->chr_ops->release(file->chr_inode, file->chr_private);
        }
    } else if (file->vnode) {
        if (file->vnode->ops && file->vnode->ops->close) {
            file->vnode->ops->close(file->vnode);
        }
        fut_vnode_unref(file->vnode);
    }

    if (file->path) {
        fut_free(file->path);
    }
    fut_free(file);
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
    if (task->fd_flags) task->fd_flags[target_fd] = 0;
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
    /* Initialize dentry cache */
    vfs_dcache_init();
}

void fut_vfs_set_root(struct fut_vnode *vnode) {
    struct fut_vnode *old_root = root_vnode_base;
    /* Detach old root first so fut_vnode_unref() does not treat it as pinned. */
    root_vnode = NULL;
    root_vnode_base = NULL;
    if (old_root) {
        fut_vnode_unref(old_root);
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
    mount->expire_marked = false;
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

/**
 * fut_vfs_bind_mount - Create a bind mount.
 *
 * A bind mount makes a directory subtree visible at a second location.
 * Both paths share the same underlying vnode tree; changes at either
 * location are immediately visible at the other.
 *
 * Allocates a new mount entry with root pointing to the source directory
 * vnode (ref already held).  The target path string is heap-duplicated so
 * the caller may free its copy.
 *
 * @param source  Absolute path of the source directory.
 * @param target  Heap-allocated absolute path of the new mount point
 *                (ownership transferred to the mount entry; caller must
 *                NOT free it after a successful return).
 * @return 0 on success, negative errno on failure.
 */
int fut_vfs_bind_mount(const char *source, char *target) {
    if (!source || !target)
        return -EINVAL;

    /* Look up source vnode — must be a directory */
    struct fut_vnode *src_vnode = NULL;
    int ret = fut_vfs_lookup(source, &src_vnode);
    if (ret < 0)
        return ret;
    if (!src_vnode) {
        return -ENOENT;
    }
    if (src_vnode->type != VN_DIR) {
        fut_vnode_unref(src_vnode);
        return -ENOTDIR;
    }

    /* Allocate bind mount entry */
    struct fut_mount *mount = fut_malloc(sizeof(struct fut_mount));
    if (!mount) {
        fut_vnode_unref(src_vnode);
        return -ENOMEM;
    }

    mount->device         = source;   /* informational only */
    mount->mountpoint     = target;   /* heap-dup from caller */
    mount->fs             = NULL;     /* no filesystem driver */
    mount->root           = src_vnode; /* ref held by lookup */
    mount->flags          = 4096;    /* MS_BIND */
    mount->expire_marked  = false;
    mount->fs_data        = NULL;
    mount->st_dev         = next_device_id++;
    mount->block_device_handle = ((fut_handle_t)0); /* FUT_INVALID_HANDLE */

    /* Prepend to mount list */
    mount->next = mount_list;
    mount_list  = mount;

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

/**
 * fut_vfs_move_mount - Atomically move a mount to a new location (MS_MOVE).
 *
 * @param source  Current mountpoint path of the mount to move.
 * @param target  Heap-allocated path string for the new mountpoint.
 *                Ownership transferred on success; caller must NOT free it.
 * @return 0 on success, -ENOENT if source not found, -ENOTDIR if target not a dir,
 *         -EINVAL if source or target is NULL/empty.
 */
int fut_vfs_move_mount(const char *source, char *target) {
    if (!source || !target || source[0] == '\0' || target[0] == '\0')
        return -EINVAL;

    /* Verify target directory exists */
    struct fut_vnode *target_vnode = NULL;
    int ret = fut_vfs_lookup(target, &target_vnode);
    if (ret < 0)
        return ret;
    if (target_vnode->type != VN_DIR) {
        fut_vnode_unref(target_vnode);
        return -ENOTDIR;
    }
    fut_vnode_unref(target_vnode);

    /* Find mount with source as its mountpoint */
    struct fut_mount *mount = mount_list;
    while (mount) {
        const char *a = mount->mountpoint;
        const char *b = source;
        while (*a && *b && *a == *b) { a++; b++; }
        if (*a == '\0' && *b == '\0') {
            /* Found — update mountpoint in-place */
            mount->mountpoint = target;
            return 0;
        }
        mount = mount->next;
    }

    return -ENOENT;
}

int fut_vfs_remount(const char *mountpoint, int flags) {
    if (!mountpoint) {
        return -EINVAL;
    }

    struct fut_mount *mount = mount_list;
    while (mount) {
        const char *a = mount->mountpoint;
        const char *b = mountpoint;
        while (a && *a && *b && *a == *b) {
            a++;
            b++;
        }

        if (a && *a == *b) {
            mount->flags = flags;
            mount->expire_marked = false;
            return 0;
        }
        mount = mount->next;
    }

    return -ENOENT;
}

int fut_vfs_expire_mount(const char *mountpoint) {
    if (!mountpoint) {
        return -EINVAL;
    }

    struct fut_mount *mount = mount_list;
    while (mount) {
        const char *a = mount->mountpoint;
        const char *b = mountpoint;
        while (a && *a && *b && *a == *b) {
            a++;
            b++;
        }

        if (a && *a == *b) {
            if (!mount->expire_marked) {
                mount->expire_marked = true;
                return -EAGAIN;
            }
            return fut_vfs_unmount(mountpoint);
        }
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
 * Resolve a potentially relative path to absolute using the current task's cwd.
 * Returns either the original path pointer (if already absolute) or abs_buf
 * filled with the resolved path.  abs_buf must be FUT_VFS_PATH_BUFFER_SIZE bytes.
 */
static const char *resolve_path_to_abs(const char *path, char *abs_buf) {
    if (!path || path[0] == '/') {
        return path;
    }
    fut_task_t *task = fut_task_current();
    const char *cwd = (task && task->cwd_cache && task->cwd_cache[0]) ? task->cwd_cache : "/";
    size_t cwd_len = 0;
    while (cwd[cwd_len]) cwd_len++;
    size_t path_len = 0;
    while (path[path_len]) path_len++;
    bool has_trail = (cwd_len > 0 && cwd[cwd_len - 1] == '/');
    size_t total = cwd_len + (has_trail ? 0 : 1) + path_len;
    if (total >= FUT_VFS_PATH_BUFFER_SIZE) {
        return path; /* Too long — caller will get ENAMETOOLONG later */
    }
    size_t i = 0;
    for (size_t j = 0; j < cwd_len; j++) abs_buf[i++] = cwd[j];
    if (!has_trail) abs_buf[i++] = '/';
    for (size_t j = 0; j < path_len; j++) abs_buf[i++] = path[j];
    abs_buf[i] = '\0';
    return abs_buf;
}

/**
 * Lookup vnode by path.
 *
 * @param path   Path to lookup (absolute or relative to cwd)
 * @param vnode  Pointer to store result vnode
 * @return 0 on success, negative error code on failure
 */
static int lookup_vnode(const char *path, struct fut_vnode **vnode) {
    if (!path || !vnode) {
        return -EINVAL;
    }

    /* Resolve relative paths against current task's cwd */
    char abs_buf[FUT_VFS_PATH_BUFFER_SIZE];
    path = resolve_path_to_abs(path, abs_buf);

    /* Determine effective root: use chroot jail vnode if task has one set */
    fut_task_t *task_for_root = fut_task_current();
    struct fut_vnode *effective_root = root_vnode;
    if (task_for_root && task_for_root->chroot_vnode) {
        effective_root = task_for_root->chroot_vnode;
    }

    /* Handle root directory */
    if (path[0] == '/' && path[1] == '\0') {
        if (!effective_root) {
            return -ENOENT;  /* Root not mounted */
        }
        *vnode = effective_root;
        /* The global root vnode is immortal — no refcount needed.
         * A chroot vnode must be refcounted so the caller can unref it. */
        if (effective_root != root_vnode_base) {
            fut_vnode_ref(effective_root);
        }
        return 0;
    }

    /* Dentry cache fast path (non-chroot only) */
    if (effective_root == root_vnode) {
        struct fut_vnode *cached = vfs_dcache_lookup(path);
        if (cached) {
            *vnode = cached;
            return 0;
        }
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

    /* Start from effective root (global root or chroot jail) */
    if (!effective_root) {
        VFSDBG("[vfs-heap] lookup_vnode freeing %p (no root)\n", (void*)components);
        fut_free(components);
        return -ENOENT;
    }

    struct fut_vnode *current = effective_root;

    /* Defensive check: root vnode must always be VN_DIR.  If the type field
     * is corrupted (e.g. by a heap allocator bug writing into adjacent memory),
     * reset it and log a critical warning rather than returning a spurious
     * ENOTDIR to callers.  The canaries around the ramfs_root_guard structure
     * would have caught a full overflow; this handles a narrower corruption of
     * just the type field. */
    if (current == root_vnode_base && current && current->type != VN_DIR) {
        fut_printf("[VFS] CRITICAL: root vnode type corrupted (was %d, expected %d=%s). "
                   "Resetting. vnode=%p\n",
                   (int)current->type, (int)VN_DIR, "VN_DIR", (void *)current);
        current->type = VN_DIR;
    }

    /* The global root_vnode_base is never refcounted during traversal (it's immortal).
     * A chroot vnode IS refcounted so that release_lookup_ref works correctly. */
    if (current != root_vnode_base) {
        fut_vnode_ref(current);
    }
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
            /* Parent directory traversal via vnode->parent link */
            if (current->parent && current != effective_root) {
                struct fut_vnode *parent = current->parent;
                /* Ref parent before releasing current */
                if (parent != root_vnode_base)
                    fut_vnode_ref(parent);
                release_lookup_ref(current);
                current = parent;
            }
            /* At root or no parent: stay at current (can't go above root) */
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
                if (effective_root == root_vnode)
                    vfs_dcache_insert(path, current);
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
            /* RESOLVE_NO_SYMLINKS: reject any symlink traversal (openat2) */
            {
                extern fut_task_t *fut_task_current(void);
                fut_task_t *_t = fut_task_current();
                if (_t && _t->vfs_no_symlinks) {
                    release_lookup_ref(current);
                    release_lookup_ref(next);
                    fut_free(components);
                    return -ELOOP;
                }
            }
            /* Check if there's a readlink operation */
            if (next->ops && next->ops->readlink) {
                char link_target[256];
                int link_ret = next->ops->readlink(next, link_target, sizeof(link_target) - 1);
                if (link_ret > 0) {
                    link_target[link_ret] = '\0';
                    VFSDBG("[vfs]  symlink '%s' -> '%s'\n", component, link_target);

                    /* For relative symlinks, prepend the containing directory's
                     * absolute path.  Without this, lookup_vnode("../foo") would
                     * start from root and resolve incorrectly: a link at /a/b/link
                     * pointing to "../foo" must resolve to /a/foo, not /foo. */
                    char abs_target[512];
                    const char *resolve_path = link_target;
                    if (link_target[0] != '/') {
                        char dir_path[256];
                        char *dir = fut_vnode_build_path(current, dir_path, sizeof(dir_path));
                        if (dir) {
                            size_t dlen = strlen(dir);
                            size_t tlen = (size_t)link_ret;
                            if (dlen + 1 + tlen < sizeof(abs_target)) {
                                __builtin_memcpy(abs_target, dir, dlen);
                                abs_target[dlen] = '/';
                                __builtin_memcpy(abs_target + dlen + 1, link_target, tlen + 1);
                                resolve_path = abs_target;
                            }
                        }
                    }

                    /* Release the symlink vnode */
                    release_lookup_ref(next);

                    /* Recursively resolve the symlink target */
                    int symlink_ret = lookup_vnode(resolve_path, &next);
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
    if (effective_root == root_vnode)
        vfs_dcache_insert(path, current);
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

    /* Resolve relative paths against current task's cwd */
    char abs_buf[FUT_VFS_PATH_BUFFER_SIZE];
    path = resolve_path_to_abs(path, abs_buf);

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

    /* Defensive check: same root-type guard as in lookup_vnode */
    if (current == root_vnode_base && current && current->type != VN_DIR) {
        fut_printf("[VFS] CRITICAL: root vnode type corrupted in lookup_parent_and_name "
                   "(was %d). Resetting. vnode=%p\n",
                   (int)current->type, (void *)current);
        current->type = VN_DIR;
    }

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

        /* Follow symlinks in intermediate path components */
        if (next->type == VN_LNK) {
            /* RESOLVE_NO_SYMLINKS check */
            {
                extern fut_task_t *fut_task_current(void);
                fut_task_t *_t = fut_task_current();
                if (_t && _t->vfs_no_symlinks) {
                    release_lookup_ref(next);
                    if (current != root_vnode_base) release_lookup_ref(current);
                    fut_free(components);
                    return -ELOOP;
                }
            }
            if (next->ops && next->ops->readlink) {
                char link_target[256];
                int link_ret = next->ops->readlink(next, link_target, sizeof(link_target) - 1);
                if (link_ret > 0) {
                    link_target[link_ret] = '\0';

                    /* For relative symlinks, prepend the containing directory's path */
                    char abs_target[512];
                    const char *resolve_path = link_target;
                    if (link_target[0] != '/') {
                        char dir_path[256];
                        char *dir = fut_vnode_build_path(current, dir_path, sizeof(dir_path));
                        if (dir) {
                            size_t dlen = strlen(dir);
                            size_t tlen = (size_t)link_ret;
                            if (dlen + 1 + tlen < sizeof(abs_target)) {
                                __builtin_memcpy(abs_target, dir, dlen);
                                abs_target[dlen] = '/';
                                __builtin_memcpy(abs_target + dlen + 1, link_target, tlen + 1);
                                resolve_path = abs_target;
                            }
                        }
                    }

                    release_lookup_ref(next);
                    struct fut_vnode *sym_resolved = NULL;
                    int sym_ret = lookup_vnode(resolve_path, &sym_resolved);
                    if (sym_ret < 0 || !sym_resolved) {
                        if (current != root_vnode_base) release_lookup_ref(current);
                        fut_free(components);
                        return sym_ret < 0 ? sym_ret : -ENOENT;
                    }
                    next = sym_resolved;
                } else {
                    release_lookup_ref(next);
                    if (current != root_vnode_base) release_lookup_ref(current);
                    fut_free(components);
                    return link_ret < 0 ? link_ret : -ENOENT;
                }
            } else {
                release_lookup_ref(next);
                if (current != root_vnode_base) release_lookup_ref(current);
                fut_free(components);
                return -ELOOP;
            }
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

int fut_vfs_lookup_nofollow(const char *path, struct fut_vnode **out_vnode) {
    if (!out_vnode) {
        return -EINVAL;
    }
    *out_vnode = NULL;

    /* Root is never a symlink; just use the regular lookup */
    if (path && path[0] == '/' && path[1] == '\0') {
        return fut_vfs_lookup(path, out_vnode);
    }

    struct fut_vnode *parent = NULL;
    char name[FUT_VFS_NAME_MAX + 1];
    int ret = lookup_parent_and_name(path, &parent, name);
    if (ret < 0) {
        return ret;
    }

    if (!parent->ops || !parent->ops->lookup) {
        release_lookup_ref(parent);
        return -ENOENT;
    }

    struct fut_vnode *vnode = NULL;
    ret = parent->ops->lookup(parent, name, &vnode);
    release_lookup_ref(parent);
    if (ret < 0) {
        return ret;
    }
    if (!vnode) {
        return -ENOENT;
    }

    *out_vnode = vnode;
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

    /* Sticky bit enforcement: in a directory with 01000 (sticky bit),
     * only the file owner, directory owner, or CAP_FOWNER can unlink. */
    if (parent->mode & 01000) {
        fut_task_t *task = fut_task_current();
        uint32_t caller_uid = task ? task->uid : 0;
        int has_cap_fowner = task &&
            (task->cap_effective & (1ULL << 3 /* CAP_FOWNER */));
        if (caller_uid != 0 && !has_cap_fowner && caller_uid != parent->uid) {
            /* Need to check if caller owns the target file */
            struct fut_vnode *target = NULL;
            int lret = fut_vfs_lookup(path, &target);
            if (lret == 0 && target) {
                if (caller_uid != target->uid) {
                    release_lookup_ref(target);
                    release_lookup_ref(parent);
                    return -EACCES;
                }
                release_lookup_ref(target);
            }
        }
    }

    ret = parent->ops->unlink(parent, leaf);
    if (ret == 0) vfs_dcache_invalidate_path(path);
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

    /* Sticky bit enforcement: same check as unlink */
    if (parent->mode & 01000) {
        fut_task_t *task = fut_task_current();
        uint32_t caller_uid = task ? task->uid : 0;
        int has_cap_fowner = task &&
            (task->cap_effective & (1ULL << 3 /* CAP_FOWNER */));
        if (caller_uid != 0 && !has_cap_fowner && caller_uid != parent->uid) {
            struct fut_vnode *target = NULL;
            int lret = fut_vfs_lookup(path, &target);
            if (lret == 0 && target) {
                if (caller_uid != target->uid) {
                    release_lookup_ref(target);
                    release_lookup_ref(parent);
                    return -EACCES;
                }
                release_lookup_ref(target);
            }
        }
    }

    ret = parent->ops->rmdir(parent, leaf);
    if (ret == 0) vfs_dcache_invalidate_path(path);
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

    /* POSIX: Apply umask to directory creation mode */
    uint32_t dir_mode = mode;
    {
        fut_task_t *mk_task = fut_task_current();
        if (mk_task)
            dir_mode &= ~(uint32_t)(mk_task->umask & 0777);
    }
    ret = parent->ops->mkdir(parent, leaf, dir_mode);
    release_lookup_ref(parent);
    return ret;
}

/**
 * fut_vfs_create_file() - Create a regular file without opening it
 *
 * Creates a regular file in the VFS without allocating a file descriptor.
 * Used by sys_mknodat to create files without fd table side effects.
 *
 * @param path  Absolute path for the new file
 * @param mode  File permission bits (will be masked with umask)
 * @return 0 on success, negative error code on failure
 */
int fut_vfs_create_file(const char *path, uint32_t mode) {
    struct fut_vnode *parent = NULL;
    char *leaf = fut_malloc(FUT_VFS_NAME_MAX + 1);
    if (!leaf) {
        return -ENOMEM;
    }

    int ret = lookup_parent_and_name(path, &parent, leaf);
    if (ret < 0) {
        fut_free(leaf);
        return ret;
    }

    if (!parent->ops || !parent->ops->create) {
        release_lookup_ref(parent);
        fut_free(leaf);
        return -ENOSYS;
    }

    /* POSIX: Apply umask to creation mode */
    uint32_t eff_mode = mode;
    {
        fut_task_t *cf_task = fut_task_current();
        if (cf_task)
            eff_mode &= ~(uint32_t)(cf_task->umask & 0777);
    }
    struct fut_vnode *new_node = NULL;
    int create_ret = parent->ops->create(parent, leaf, eff_mode, &new_node);
    release_lookup_ref(parent);
    fut_free(leaf);

    if (create_ret < 0) {
        return create_ret;
    }

    /* Release the caller's reference - the directory entry holds its own reference */
    if (new_node) {
        fut_vnode_unref(new_node);
    }

    return 0;
}

/**
 * fut_vfs_mknod() - Create a special filesystem node
 *
 * Creates a filesystem node of the specified type (FIFO, socket, regular file)
 * without opening it. The full mode including S_IFMT type bits is passed to
 * the filesystem create operation.
 *
 * @param path  Absolute path for the new node
 * @param mode  Full mode including file type bits (S_IFIFO|perms, S_IFSOCK|perms, etc.)
 * @return 0 on success, negative error code on failure
 */
int fut_vfs_mknod(const char *path, uint32_t mode) {
    struct fut_vnode *parent = NULL;
    char *leaf = fut_malloc(FUT_VFS_NAME_MAX + 1);
    if (!leaf) {
        return -ENOMEM;
    }

    int ret = lookup_parent_and_name(path, &parent, leaf);
    if (ret < 0) {
        fut_free(leaf);
        return ret;
    }

    if (!parent->ops || !parent->ops->create) {
        release_lookup_ref(parent);
        fut_free(leaf);
        return -ENOSYS;
    }

    /* POSIX: Apply umask to permission bits (preserve S_IFMT type bits) */
    uint32_t mknod_mode = mode & 0777;
    {
        fut_task_t *mn_task = fut_task_current();
        if (mn_task)
            mknod_mode &= ~(uint32_t)(mn_task->umask & 0777);
    }
    struct fut_vnode *new_node = NULL;
    int create_ret = parent->ops->create(parent, leaf, mknod_mode, &new_node);
    release_lookup_ref(parent);
    fut_free(leaf);

    if (create_ret < 0) {
        return create_ret;
    }

    /* Fix up the vnode type based on S_IFMT bits in mode.
     * ramfs_create always creates VN_REG; we patch the type here for special nodes. */
    if (new_node) {
        uint32_t file_type = mode & S_IFMT;
        if (file_type == S_IFIFO) {
            new_node->type = VN_FIFO;
        } else if (file_type == S_IFSOCK) {
            new_node->type = VN_SOCK;
        }
        /* Release the caller's reference - the directory entry holds its own reference */
        fut_vnode_unref(new_node);
    }

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
    return -ENFILE;  /* system-wide file table full (not per-process EMFILE) */
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

    /* Update the file descriptor's offset for next read.
     * readdir returns 0 (FuturaFS) or 1 (ramfs) on success, negative on error/end. */
    if (ret >= 0) {
        file->offset = pos;
    }

    /* Return the updated cookie to caller */
    *cookie = pos;

    return ret;
}

void vfs_file_ref(struct fut_file *file) {
    if (file) {
        __atomic_add_fetch(&file->refcount, 1, __ATOMIC_ACQ_REL);
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
 * Allocate lowest available FD in a task's FD table.
 * Public wrapper for per-task FD allocation (used by SCM_RIGHTS).
 */
int vfs_alloc_fd_for_task(struct fut_task *task, struct fut_file *file) {
    return alloc_fd_for_task((fut_task_t *)task, file);
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
    /* Dynamic PTY slave: /dev/pts/<n> — not pre-registered in devfs */
    if (path[0] == '/' && path[1] == 'd' && path[2] == 'e' && path[3] == 'v' &&
        path[4] == '/' && path[5] == 'p' && path[6] == 't' && path[7] == 's' &&
        path[8] == '/' && path[9] >= '0' && path[9] <= '9') {
        int idx = 0;
        for (const char *p = path + 9; *p >= '0' && *p <= '9'; p++)
            idx = idx * 10 + (*p - '0');
        extern int pty_open_slave(int index);
        int slave_fd = pty_open_slave(idx);
        /* Propagate O_CLOEXEC to the allocated fd */
        if (slave_fd >= 0 && (flags & 02000000 /* O_CLOEXEC */)) {
            fut_task_t *pts_task = fut_task_current();
            if (pts_task && pts_task->fd_flags)
                pts_task->fd_flags[slave_fd] |= 1; /* FD_CLOEXEC */
        }
        return slave_fd;
    }

    /* /dev/tty: open the calling process's controlling terminal.
     * Linux: major 5, minor 0 — resolves to the process's ctty.
     * If the process has a PTY controlling terminal (tty_nr = MKDEV(136,N)),
     * redirect to /dev/pts/N. Otherwise fall through to console device. */
    if (path[0] == '/' && path[1] == 'd' && path[2] == 'e' && path[3] == 'v' &&
        path[4] == '/' && path[5] == 't' && path[6] == 't' && path[7] == 'y' &&
        path[8] == '\0') {
        fut_task_t *tty_task = fut_task_current();
        if (tty_task && tty_task->tty_nr != 0) {
            uint32_t tty_major = (tty_task->tty_nr >> 8) & 0xFF;
            uint32_t tty_minor = tty_task->tty_nr & 0xFF;
            if (tty_major == 136) {
                extern int pty_open_slave(int index);
                int tty_fd = pty_open_slave((int)tty_minor);
                if (tty_fd >= 0 && (flags & 02000000)) {
                    if (tty_task->fd_flags)
                        tty_task->fd_flags[tty_fd] |= 1;
                }
                return tty_fd;
            }
        }
        /* Fall through: no PTY ctty, use console device */
    }

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
    file->owner_type = 0;
    file->async_sig = 0;
    file->fd_flags = 0;
    file->seals = 0;
    /* Store device path so /proc/self/fd/<n> readlink shows the correct name */
    {
        size_t plen = 0;
        while (path[plen]) plen++;
        char *pcopy = fut_malloc(plen + 1);
        if (pcopy) {
            for (size_t pi = 0; pi <= plen; pi++) pcopy[pi] = path[pi];
        }
        file->path = pcopy;
    }

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

    /* O_CLOEXEC: set FD_CLOEXEC on the per-fd flags for chrdev fds */
    if (fd >= 0 && (flags & 02000000 /* O_CLOEXEC */) && task && task->fd_flags) {
        task->fd_flags[fd] |= 1;  /* FD_CLOEXEC */
    }

    if (fd < 0) {
        if (ops->release) {
            ops->release(inode, file->chr_private);
        }
        fut_free(file);
        return fd;
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
    file->flags = O_RDWR | FUT_F_UNSEEKABLE;
    file->refcount = 1;
    file->chr_ops = ops;
    file->chr_inode = inode;
    file->chr_private = priv;
    file->fd_flags = 0;  /* No close-on-exec for device files by default */
    file->owner_pid = 0;
    file->owner_type = 0;
    file->async_sig = 0;
    file->seals = 0;
    file->path = NULL;

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

    uint32_t task_uid = task ? userns_ns_to_host_uid(task->user_ns, task->uid) : 0;
    uint32_t task_gid = task ? userns_ns_to_host_gid(task->user_ns, task->gid) : 0;

    /* Root or CAP_DAC_OVERRIDE bypasses all file permission checks */
    if (task_uid == 0 || (task && (task->cap_effective & (1ULL << 1 /* CAP_DAC_OVERRIDE */)))) {
        return 0;
    }

    /* SECURITY: Explicitly deny access to mode 000 files for non-root.
     * While the bit checks below would also reject, this is defense-in-depth. */
    if ((mode & 0777) == 0) {
        return -EACCES;
    }

    /* Get actual file ownership from vnode */
    uint32_t file_uid = vnode->uid;
    uint32_t file_gid = vnode->gid;
    uint32_t perm_bits = 0;

    /* Determine which permission bits to check: owner, group, or other */
    if (task_uid == file_uid) {
        /* Process is the file owner - check owner permissions */
        perm_bits = (mode >> 6) & 7;  /* Owner: bits 6-8 */
    } else if (task_gid == file_gid) {
        /* Process primary GID matches - check group permissions */
        perm_bits = (mode >> 3) & 7;  /* Group: bits 3-5 */
    } else {
        /* Check supplementary groups */
        int in_group = 0;
        if (task) {
            for (int i = 0; i < task->ngroups; i++) {
                if (userns_ns_to_host_gid(task->user_ns, task->groups[i]) == file_gid) {
                    in_group = 1;
                    break;
                }
            }
        }
        if (in_group) {
            perm_bits = (mode >> 3) & 7;  /* Group: bits 3-5 */
        } else {
            /* Process is neither owner nor in any matching group */
            perm_bits = mode & 7;          /* Other: bits 0-2 */
        }
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

    /* Lookup vnode. O_NOFOLLOW: don't follow final symlink component. */
    if (flags & O_NOFOLLOW) {
        ret = fut_vfs_lookup_nofollow(path, &vnode);
    } else {
        ret = lookup_vnode(path, &vnode);
    }
    if (ret == -ENOENT && !(flags & O_NOFOLLOW)) {
        /* VFS lookup failed — the path might be a symlink pointing to a chrdev.
         * Try looking up the symlink itself and following it to a chrdev. */
        struct fut_vnode *link_vnode = NULL;
        if (fut_vfs_lookup_nofollow(path, &link_vnode) == 0 &&
            link_vnode && link_vnode->type == VN_LNK &&
            link_vnode->ops && link_vnode->ops->readlink) {
            char link_target[256];
            int link_len = link_vnode->ops->readlink(link_vnode, link_target, sizeof(link_target) - 1);
            release_lookup_ref(link_vnode);
            if (link_len > 0) {
                link_target[link_len] = '\0';
                int chr_fd2 = try_open_chrdev(link_target, flags);
                if (chr_fd2 != -ENOENT)
                    return chr_fd2;
            }
        } else if (link_vnode) {
            release_lookup_ref(link_vnode);
        }
    }
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

            VFSDBG("[vfs-open] parent=%p leaf='%s'\n", (void*)parent, leaf);
            struct fut_vnode *new_node = NULL;
            /* POSIX: Apply umask to creation mode.
             * mode 0666 with umask 022 → effective 0644. */
            uint32_t effective_mode = (uint32_t)mode;
            {
                fut_task_t *cr_task = fut_task_current();
                if (cr_task)
                    effective_mode &= ~(uint32_t)(cr_task->umask & 0777);
            }
            int create_ret = parent->ops->create(parent, leaf, effective_mode, &new_node);
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

    /* O_NOFOLLOW: reject if final component is a symbolic link */
    if ((flags & O_NOFOLLOW) && vnode->type == VN_LNK) {
        release_lookup_ref(vnode);
        return -ELOOP;
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

    /* O_DIRECTORY: fail with ENOTDIR if path is not a directory */
    if ((flags & O_DIRECTORY) && vtype != VN_DIR) {
        release_lookup_ref(vnode);
        return -ENOTDIR;
    }

    /* Permission checks based on access mode (unless we just created the file).
     * O_PATH skips all content-access permission checks: the caller only needs
     * execute permission on the path components, not on the file itself. */
    if (!created && !(flags & O_PATH)) {
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
    file->owner_type = 0;
    file->async_sig = 0;
    file->fd_flags = 0;
    file->seals = 0;

    /* VN_FIFO: wire the file struct to a per-vnode FIFO pipe buffer.
     * chr_inode = fut_fifo_state *, chr_private = fut_fifo_state *
     * The FIFO fops dispatch to pipe_read/write via the fut_fifo_state wrapper
     * and do NOT free the buffer on close (it is owned by the vnode). */
    if (vtype == VN_FIFO) {
        extern void *fut_fifo_state_create(void);
        extern void fut_fifo_open_read(void *fs);
        extern void fut_fifo_open_write(void *fs);
        extern struct fut_file_ops fifo_read_fops;
        extern struct fut_file_ops fifo_write_fops;
        extern struct fut_file_ops fifo_rdwr_fops;
        /* Accessors avoid exposing the private ramfs_node layout */
        extern void *ramfs_get_fifo_pipe(struct fut_vnode *vn);
        extern void  ramfs_set_fifo_pipe(struct fut_vnode *vn, void *pipe);
        extern int   fut_fifo_has_readers(void *fsp);

        void *fifo_pipe = ramfs_get_fifo_pipe(vnode);
        if (!fifo_pipe) {
            fifo_pipe = fut_fifo_state_create();
            if (!fifo_pipe) {
                fut_free(file);
                release_lookup_ref(vnode);
                return -ENOMEM;
            }
            ramfs_set_fifo_pipe(vnode, fifo_pipe);
        }
        int fifo_acc = flags & O_ACCMODE;
        /* O_WRONLY|O_NONBLOCK with no readers: ENXIO (Linux open(2) semantics) */
        if (fifo_acc == O_WRONLY && (flags & O_NONBLOCK) && !fut_fifo_has_readers(fifo_pipe)) {
            fut_free(file);
            release_lookup_ref(vnode);
            return -ENXIO;
        }
        if (fifo_acc == O_RDONLY || fifo_acc == O_RDWR)
            fut_fifo_open_read(fifo_pipe);
        if (fifo_acc == O_WRONLY || fifo_acc == O_RDWR)
            fut_fifo_open_write(fifo_pipe);

        file->chr_inode   = fifo_pipe;
        file->chr_private = fifo_pipe;
        if (fifo_acc == O_WRONLY)
            file->chr_ops = &fifo_write_fops;
        else if (fifo_acc == O_RDONLY)
            file->chr_ops = &fifo_read_fops;
        else
            file->chr_ops = &fifo_rdwr_fops;
    }

    /* Resolve and store absolute path for dirfd-relative *at syscall resolution */
    {
        char abs_path_buf[FUT_VFS_PATH_BUFFER_SIZE];
        const char *abs_path = resolve_path_to_abs(path, abs_path_buf);
        size_t abs_len = strlen(abs_path);
        file->path = fut_malloc(abs_len + 1);
        if (file->path) {
            memcpy(file->path, abs_path, abs_len + 1);
        }
        /* If malloc fails, path remains NULL; dirfd resolution will fall back gracefully */
    }

    /* Check permissions for write access — O_PATH bypasses content access */
    if ((flags & (O_WRONLY | O_RDWR)) && !created && !(flags & O_PATH)) {
        /* For existing files, check if write is allowed */
        int perm_ret = check_file_permission(vnode, NULL, true);
        if (perm_ret < 0) {
            fut_printf("[VFS-OPEN] Write permission denied for '%s' (mode=0%o)\n", path, vnode->mode);
            if (file->path) { fut_free(file->path); }
            fut_free(file);
            release_lookup_ref(vnode);
            return perm_ret;
        }
    }

    /* O_TRUNC: truncate existing regular files to zero length (no-op with O_PATH) */
    if ((flags & O_TRUNC) && !(flags & O_PATH) && !created && vnode->type == VN_REG) {
        if (vnode->ops && vnode->ops->truncate) {
            int trunc_ret = vnode->ops->truncate(vnode, 0);
            if (trunc_ret < 0) {
                VFSDBG("[VFS-OPEN] O_TRUNC failed for '%s': %d\n", path, trunc_ret);
                if (file->path) { fut_free(file->path); }
                fut_free(file);
                release_lookup_ref(vnode);
                return trunc_ret;
            }
            file->offset = 0;  /* Reset offset after truncation */

            /* POSIX/Linux: clear S_ISUID and S_ISGID bits on O_TRUNC */
            uint32_t mode = vnode->mode;
            int needs_clear = 0;
            if (mode & 04000)  /* S_ISUID */
                needs_clear = 1;
            if ((mode & 02000) && (mode & 00010))  /* S_ISGID + S_IXGRP */
                needs_clear = 1;
            if (needs_clear) {
                int has_cap_fsetid = task &&
                    (task->cap_effective & (1ULL << 4 /* CAP_FSETID */));
                if (!has_cap_fsetid) {
                    if (mode & 04000)
                        vnode->mode &= ~(uint32_t)04000;
                    if ((mode & 02000) && (mode & 00010))
                        vnode->mode &= ~(uint32_t)02000;
                }
            }
        }
    }

    /* Allocate file descriptor in task's FD table */
    int fd = alloc_fd_for_task(task, file);
    if (fd < 0) {
        if (file->path) { fut_free(file->path); }
        fut_free(file);
        release_lookup_ref(vnode);
        fut_printf("[VFS-OPEN] alloc_fd_for_task failed, returning %d\n", fd);
        return fd;
    }

    /* Note: mode for newly created files is set by the filesystem's create
     * operation via vfs_init_vnode_ownership(), which applies umask. No
     * additional mode setting needed here. */

    /* Handle O_CLOEXEC — set FD_CLOEXEC on the per-fd flags */
    if ((flags & 02000000 /* O_CLOEXEC */) && task->fd_flags) {
        task->fd_flags[fd] |= 1;  /* FD_CLOEXEC */
    }

    /* Dispatch IN_OPEN inotify event */
    if (vnode->parent && vnode->name) {
        char dir_path[256];
        if (fut_vnode_build_path(vnode->parent, dir_path, sizeof(dir_path)))
            inotify_dispatch_event(dir_path, 0x00000020 /* IN_OPEN */, vnode->name, 0);
    }

    /* Dispatch fanotify FAN_OPEN event for filesystem-wide monitoring */
    {
        extern void fanotify_notify(const char *, uint64_t, int32_t);
        extern fut_task_t *fut_task_current(void);
        fut_task_t *fan_task = fut_task_current();
        fanotify_notify(path, 0x00000020 /* FAN_OPEN */, fan_task ? (int32_t)fan_task->pid : 0);
    }

#if DEBUG_VFS
    fut_printf("[VFS-OPEN] SUCCESS: opened '%s' as fd=%d (mode=0%o)\n", path, fd, vnode->mode);
#endif
    return fd;
}

/**
 * fut_vfs_open_at - Open a file relative to a directory FD.
 *
 * Implements the *at syscall convention: if path is absolute or dirfd is
 * AT_FDCWD, this is identical to fut_vfs_open(). If path is relative and
 * dirfd is a valid directory FD, resolves path relative to that directory
 * using the stored fut_file.path of the dirfd.
 */
int fut_vfs_open_at(fut_task_t *task, int dirfd, const char *path, int flags, int mode) {
    if (!path) {
        return -EINVAL;
    }

    /* Absolute path or AT_FDCWD: delegate directly */
    if (path[0] == '/' || dirfd == AT_FDCWD) {
        return fut_vfs_open(path, flags, mode);
    }

    /* Relative path with real dirfd: resolve relative to the dirfd's path */
    if (!task || !task->fd_table || dirfd < 0 || dirfd >= task->max_fds) {
        return -EBADF;
    }

    struct fut_file *dir_file = get_file_from_task(task, dirfd);
    if (!dir_file) {
        return -EBADF;
    }

    if (!dir_file->vnode || dir_file->vnode->type != VN_DIR) {
        return -ENOTDIR;
    }

    /* We need the directory's path to combine with the relative path.
     * Use the stored file->path if available. */
    if (!dir_file->path) {
        /* No path stored - fall back to treating relative path as CWD-relative */
        return fut_vfs_open(path, flags, mode);
    }

    /* Combine dir_path + "/" + rel_path into an absolute path */
    char combined[FUT_VFS_PATH_BUFFER_SIZE];
    size_t dir_len = strlen(dir_file->path);
    size_t rel_len = strlen(path);
    bool has_trail = (dir_len > 0 && dir_file->path[dir_len - 1] == '/');
    size_t total = dir_len + (has_trail ? 0 : 1) + rel_len;
    if (total >= FUT_VFS_PATH_BUFFER_SIZE) {
        return -ENAMETOOLONG;
    }
    size_t i = 0;
    for (size_t j = 0; j < dir_len; j++) combined[i++] = dir_file->path[j];
    if (!has_trail) combined[i++] = '/';
    for (size_t j = 0; j < rel_len; j++) combined[i++] = path[j];
    combined[i] = '\0';

    return fut_vfs_open(combined, flags, mode);
}

int fut_vfs_resolve_at(fut_task_t *task, int dirfd, const char *path, char *out, size_t out_size) {
    if (!path || !out || out_size == 0) {
        return -EINVAL;
    }

    /* Absolute path or AT_FDCWD: copy unchanged */
    if (path[0] == '/' || dirfd == AT_FDCWD) {
        size_t len = strlen(path);
        if (len >= out_size) {
            return -ENAMETOOLONG;
        }
        memcpy(out, path, len + 1);
        return 0;
    }

    /* Relative path with real dirfd */
    if (!task || !task->fd_table || dirfd < 0 || dirfd >= task->max_fds) {
        return -EBADF;
    }

    struct fut_file *dir_file = get_file_from_task(task, dirfd);
    if (!dir_file) {
        return -EBADF;
    }

    if (!dir_file->vnode || dir_file->vnode->type != VN_DIR) {
        return -ENOTDIR;
    }

    if (!dir_file->path) {
        /* No path stored - copy relative path as-is (best-effort) */
        size_t len = strlen(path);
        if (len >= out_size) {
            return -ENAMETOOLONG;
        }
        memcpy(out, path, len + 1);
        return 0;
    }

    /* Combine dir_path + "/" + rel_path */
    size_t dir_len = strlen(dir_file->path);
    size_t rel_len = strlen(path);
    bool has_trail = (dir_len > 0 && dir_file->path[dir_len - 1] == '/');
    size_t total = dir_len + (has_trail ? 0 : 1) + rel_len;
    if (total >= out_size) {
        return -ENAMETOOLONG;
    }
    size_t i = 0;
    for (size_t j = 0; j < dir_len; j++) out[i++] = dir_file->path[j];
    if (!has_trail) out[i++] = '/';
    for (size_t j = 0; j < rel_len; j++) out[i++] = path[j];
    out[i] = '\0';
    return 0;
}

ssize_t fut_vfs_read(int fd, void *buf, size_t size) {
    /* POSIX: read with count=0 returns 0 */
    if (size == 0) return 0;
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

    /* O_PATH fds cannot be used for I/O — only path-based operations */
    if (file->flags & O_PATH) {
        return -EBADF;
    }

    /* Check that fd was opened for reading */
    int access_mode = file->flags & O_ACCMODE;
    if (access_mode == O_WRONLY) {
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
            extern void iocg_account_read(uint64_t);
            iocg_account_read((uint64_t)ret);
        }
        return ret;
    }

    /* Directories cannot be read with read() — use getdents64 */
    if (file->vnode && file->vnode->type == VN_DIR) {
        return -EISDIR;
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
        extern void iocg_account_read(uint64_t);
        iocg_account_read((uint64_t)ret);

        /* Update access time unless O_NOATIME is set.
         * O_NOATIME suppresses atime updates on read, commonly used by
         * backup tools, databases, and mail servers to avoid write amplification. */
        if (!(file->flags & O_NOATIME)) {
            extern void ramfs_touch_atime(struct fut_vnode *vnode);
            ramfs_touch_atime(file->vnode);
        }

        /* Dispatch IN_ACCESS so watchers know the file was read */
        if (file->vnode->parent && file->vnode->name) {
            char dir_path[256];
            if (fut_vnode_build_path(file->vnode->parent, dir_path, sizeof(dir_path))) {
                inotify_dispatch_event(dir_path, 0x00000001 /* IN_ACCESS */, file->vnode->name, 0);
                /* fanotify FAN_ACCESS */
                extern void fanotify_notify(const char *, uint64_t, int32_t);
                char fpath[512];
                int fp = 0;
                for (int i = 0; dir_path[i] && fp < 500; i++) fpath[fp++] = dir_path[i];
                if (fp > 1) fpath[fp++] = '/';
                for (int i = 0; file->vnode->name[i] && fp < 510; i++) fpath[fp++] = file->vnode->name[i];
                fpath[fp] = '\0';
                fut_task_t *ft = fut_task_current();
                fanotify_notify(fpath, 0x00000001 /* FAN_ACCESS */, ft ? (int32_t)ft->pid : 0);
            }
        }
    }

    /* Update I/O accounting counters for /proc/<pid>/io */
    if (ret > 0 && task) {
        task->io_rchar += (uint64_t)ret;
        task->io_syscr++;
    }

    return ret;
}

ssize_t fut_vfs_write(int fd, const void *buf, size_t size) {
    /* POSIX: write with count=0 returns 0 */
    if (size == 0) return 0;
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

    /* O_PATH fds cannot be used for I/O */
    if (file->flags & O_PATH) {
        return -EBADF;
    }

    /* Check that fd was opened for writing */
    int access_mode = file->flags & O_ACCMODE;
    if (access_mode == O_RDONLY) {
        return -EBADF;
    }

    /* Enforce file seals: F_SEAL_WRITE and F_SEAL_FUTURE_WRITE prevent writes.
     * F_SEAL_WRITE (0x0008): prevents all writes (and adding MAP_SHARED+PROT_WRITE).
     * F_SEAL_FUTURE_WRITE (0x0010): prevents future write()/writev() calls but
     *   allows existing shared writable mappings to continue writing via mmap. */
    if (file->seals & (0x0008 /* F_SEAL_WRITE */ | 0x0010 /* F_SEAL_FUTURE_WRITE */)) {
        return -EPERM;
    }

    if (file->chr_ops) {
        VFSDBG("[vfs-write] chr_ops path\n");
        if (!file->chr_ops->write) {
            return -EINVAL;
        }
        /* Enforce F_SEAL_GROW on chr_ops (memfd) files: if the write would extend
         * past the current file size, reject with EPERM. */
        if (file->seals & 0x0004 /* F_SEAL_GROW */) {
            extern long fut_memfd_get_size(struct fut_file *file);
            long cur = fut_memfd_get_size(file);
            if (cur >= 0 && file->offset + size > (size_t)cur)
                return -EPERM;
        }
        off_t pos = (off_t)file->offset;
        ssize_t ret = file->chr_ops->write(file->chr_inode, file->chr_private, buf, size, &pos);
        if (ret > 0) {
            file->offset = (uint64_t)pos;
            extern void iocg_account_write(uint64_t);
            iocg_account_write((uint64_t)ret);
        }
        /* POSIX: deliver SIGPIPE on broken pipe/socket write.
         * MSG_NOSIGNAL sets suppress_sigpipe to skip SIGPIPE delivery. */
        if (ret == -EPIPE) {
            fut_task_t *wr_task = fut_task_current();
            if (wr_task && !wr_task->suppress_sigpipe)
                fut_signal_send(wr_task, 13 /* SIGPIPE */);
        }
        return ret;
    }

    /* Directories cannot be written with write() */
    if (file->vnode && file->vnode->type == VN_DIR) {
        return -EISDIR;
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

    /* Enforce F_SEAL_GROW: reject writes that would extend the file */
    if ((file->seals & 0x0004 /* F_SEAL_GROW */) &&
        file->offset + size > file->vnode->size) {
        return -EPERM;
    }

    /* O_APPEND: acquire per-vnode write lock to make seek-to-end + write
     * atomic with respect to other O_APPEND writers (POSIX requirement). */
    int is_append = (file->flags & O_APPEND) != 0;
    if (is_append) {
        fut_spinlock_acquire(&file->vnode->write_lock);
        file->offset = file->vnode->size;
    }

    /* Enforce RLIMIT_FSIZE: limit maximum file size (resource index 1).
     * If the write would extend the file beyond the limit, cap the size
     * or return EFBIG. On Linux, SIGXFSZ is also sent. */
    {
        fut_task_t *wr_task = fut_task_current();
        if (wr_task) {
            uint64_t fsize_limit = wr_task->rlimits[1].rlim_cur;
            if (fsize_limit != (uint64_t)-1 && fsize_limit > 0) {
                uint64_t write_end = file->offset + size;
                if (write_end > fsize_limit) {
                    if (file->offset >= fsize_limit) {
                        /* Send SIGXFSZ (signal 25) per POSIX */
                        extern int fut_signal_send(struct fut_task *t, int sig);
                        fut_signal_send(wr_task, 25 /* SIGXFSZ */);
                        if (is_append)
                            fut_spinlock_release(&file->vnode->write_lock);
                        return -27;  /* EFBIG */
                    }
                    /* Truncate write to fit within limit */
                    size = (size_t)(fsize_limit - file->offset);
                }
            }
        }
    }

    VFSDBG("[vfs-write] calling vnode->ops->write\n");
    ssize_t ret = file->vnode->ops->write(file->vnode, buf, size, file->offset);
    VFSDBG("[vfs-write] vnode->ops->write returned %lld\n", (long long)ret);
    if (ret > 0) {
        file->offset += ret;
        extern void iocg_account_write(uint64_t);
        iocg_account_write((uint64_t)ret);

        /* POSIX/Linux: clear set-user-ID and set-group-ID bits on write.
         * After a successful write to a regular file, the kernel must:
         *   - Clear S_ISUID (04000) unconditionally
         *   - Clear S_ISGID (02000) only if S_IXGRP (00010) is also set
         *     (S_ISGID without S_IXGRP means mandatory locking, not setgid)
         * Exception: processes with CAP_FSETID (bit 4) retain these bits.
         * This prevents privilege escalation via writing to setuid binaries. */
        if (file->vnode->type == VN_REG) {
            uint32_t mode = file->vnode->mode;
            int needs_clear = 0;
            if (mode & 04000)  /* S_ISUID */
                needs_clear = 1;
            if ((mode & 02000) && (mode & 00010))  /* S_ISGID + S_IXGRP */
                needs_clear = 1;
            if (needs_clear) {
                fut_task_t *suid_task = fut_task_current();
                int has_cap_fsetid = suid_task &&
                    (suid_task->cap_effective & (1ULL << 4 /* CAP_FSETID */));
                if (!has_cap_fsetid) {
                    if (mode & 04000)
                        file->vnode->mode &= ~(uint32_t)04000;
                    if ((mode & 02000) && (mode & 00010))
                        file->vnode->mode &= ~(uint32_t)02000;
                }
            }
        }

        /* Dispatch IN_MODIFY so inotify watchers see writes */
        if (file->vnode->parent && file->vnode->name) {
            char dir_path[256];
            if (fut_vnode_build_path(file->vnode->parent, dir_path, sizeof(dir_path))) {
                inotify_dispatch_event(dir_path, 0x00000002 /* IN_MODIFY */, file->vnode->name, 0);
                /* fanotify FAN_MODIFY */
                extern void fanotify_notify(const char *, uint64_t, int32_t);
                char fpath[512]; int fp = 0;
                for (int i = 0; dir_path[i] && fp < 500; i++) fpath[fp++] = dir_path[i];
                if (fp > 1) fpath[fp++] = '/';
                for (int i = 0; file->vnode->name[i] && fp < 510; i++) fpath[fp++] = file->vnode->name[i];
                fpath[fp] = '\0';
                fut_task_t *ft = fut_task_current();
                fanotify_notify(fpath, 0x00000002 /* FAN_MODIFY */, ft ? (int32_t)ft->pid : 0);
            }
        }
    }

    if (is_append)
        fut_spinlock_release(&file->vnode->write_lock);

    /* Update I/O accounting counters for /proc/<pid>/io */
    if (ret > 0) {
        fut_task_t *io_task = fut_task_current();
        if (io_task) {
            io_task->io_wchar += (uint64_t)ret;
            io_task->io_syscw++;
        }
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

    /* Remove FD from task table first, then handle refcount.
     * This prevents other threads from accessing the FD during cleanup. */
    if (task->fd_table && fd >= 0 && fd < task->max_fds) {
        task->fd_table[fd] = NULL;
    }

    /* Clear socket tracking table so stale socket pointers don't pollute
     * poll/select for FDs reused by non-socket files (e.g. /dev/null). */
    release_socket_fd(fd);

    /* Atomically decrement refcount. Only perform resource cleanup (vnode release,
     * chr_ops release, file struct free) on the LAST reference.
     * Without this guard, dup'd FDs would double-close vnodes and
     * cause use-after-free when the second FD is closed.
     * Uses atomic decrement to prevent races when two threads close
     * dup'd FDs concurrently — avoids both resource leaks and double-frees. */
    uint32_t old_ref = __atomic_sub_fetch(&file->refcount, 1, __ATOMIC_ACQ_REL);
    if (old_ref > 0) {
        VFSDBG("[vfs-close] refcount decremented to %u, skipping cleanup\n", old_ref);
        return 0;
    }

    if (file->chr_ops) {
        VFSDBG("[vfs-close] chr_ops path\n");
        if (file->chr_ops->release) {
            file->chr_ops->release(file->chr_inode, file->chr_private);
        }
        if (file->path) { fut_free(file->path); }
        fut_free(file);
        return 0;
    }

    /* Dispatch IN_CLOSE_WRITE or IN_CLOSE_NOWRITE inotify event */
    if (file->vnode && file->vnode->parent && file->vnode->name) {
        int writable = file->flags & (01 /* O_WRONLY */ | 02 /* O_RDWR */);
        uint32_t mask = writable ? 0x00000008 /* IN_CLOSE_WRITE */
                                 : 0x00000010 /* IN_CLOSE_NOWRITE */;
        char dir_path[256];
        if (fut_vnode_build_path(file->vnode->parent, dir_path, sizeof(dir_path)))
            inotify_dispatch_event(dir_path, mask, file->vnode->name, 0);
    }

    VFSDBG("[vfs-close] vnode path, file->vnode=%p\n", (void*)file->vnode);
    /* Call vnode close operation */
    if (file->vnode && file->vnode->ops && file->vnode->ops->close) {
        VFSDBG("[vfs-close] calling vnode->ops->close\n");
        file->vnode->ops->close(file->vnode);
        VFSDBG("[vfs-close] vnode->ops->close returned\n");
    }

    /* Release vnode reference */
    if (file->vnode) {
        VFSDBG("[vfs-close] calling fut_vnode_unref(vnode=%p)\n", (void*)file->vnode);
        fut_vnode_unref(file->vnode);
        VFSDBG("[vfs-close] fut_vnode_unref returned\n");
    }

    /* Free file structure */
    VFSDBG("[vfs-close] freeing file struct %p\n", (void*)file);
    if (file->path) {
        fut_free(file->path);
    }
    fut_free(file);

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

    /* Non-seekable chr_ops files return ESPIPE per POSIX.
     * Pipes use O_RDONLY/O_WRONLY (set by pipe()/pipe2()).
     * Sockets, eventfd, timerfd, signalfd, pidfd, and mqueue use
     * FUT_F_UNSEEKABLE (set by chrdev_alloc_fd()).
     * Device files opened by path (try_open_chrdev) and memfd are seekable.
     * Named FIFOs have both chr_ops and vnode (VN_FIFO) — also ESPIPE. */
    if ((file->chr_ops && !file->vnode &&
         ((file->flags & O_ACCMODE) != O_RDWR ||
          (file->flags & FUT_F_UNSEEKABLE))) ||
        (file->vnode && file->vnode->type == VN_FIFO))
        return -ESPIPE;

    uint64_t new_offset = file->offset;

    /* SEEK_DATA (3) and SEEK_HOLE (4): sparse file navigation.
     * Futura's ramfs is dense (no holes); implement dense-file fallback per spec. */
#ifndef SEEK_DATA
#define SEEK_DATA 3
#endif
#ifndef SEEK_HOLE
#define SEEK_HOLE 4
#endif

    switch (whence) {
    case SEEK_SET:
        if (offset < 0)
            return -EINVAL;
        new_offset = (uint64_t)offset;
        break;
    case SEEK_CUR:
        new_offset = file->offset + (uint64_t)offset;
        break;
    case SEEK_END:
        if (file->vnode) {
            new_offset = file->vnode->size + (uint64_t)offset;
        }
        break;
    case SEEK_DATA:
        /* Dense file: every byte in [0, size) is data.
         * ENXIO if offset >= file_size; otherwise position = offset. */
        if (offset < 0)
            return -EINVAL;
        if (!file->vnode || (uint64_t)offset >= file->vnode->size)
            return -ENXIO;
        file->offset = (uint64_t)offset;
        return offset;
    case SEEK_HOLE:
        /* Dense file: only hole is the implicit one at EOF (== file_size).
         * ENXIO if offset > file_size; otherwise position = file_size. */
        if (offset < 0)
            return -EINVAL;
        if (!file->vnode || (uint64_t)offset > file->vnode->size)
            return -ENXIO;
        file->offset = file->vnode->size;
        return (int64_t)file->vnode->size;
    default:
        return -EINVAL;
    }

    /* Validate resulting offset is representable in off_t.
     * Catches: SEEK_CUR/SEEK_END arithmetic underflow (negative result wraps
     * to large uint64_t) and overflow past INT64_MAX.
     * POSIX: EOVERFLOW when resulting offset cannot be represented in off_t. */
    if (new_offset > (uint64_t)INT64_MAX) {
        return -EOVERFLOW;
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
        stat->st_mode = vnode_type_to_stat_mode(vnode->type) | (vnode->mode & 07777);
        stat->st_nlink = vnode->nlinks;
        stat->st_size = vnode->size;
        stat->st_dev = vnode->mount ? vnode->mount->st_dev : 0;
        stat->st_uid = vnode->uid;
        stat->st_gid = vnode->gid;
        stat->st_blksize = 4096;
        stat->st_blocks = (vnode->size + 511) / 512;  /* 512-byte units per POSIX */

        /* Set timestamps using tick-based time to avoid calibration deadlock.
         * fut_get_ticks() returns ticks at 100 Hz (10ms each).
         * st_atime/mtime/ctime are seconds, st_*_nsec is the sub-second part. */
        extern uint64_t fut_get_ticks(void);
        uint64_t now_ticks = fut_get_ticks();
        uint64_t now_ns = now_ticks * 10000000ULL;  /* ticks → ns */
        stat->st_atime = now_ns / 1000000000ULL;
        stat->st_atime_nsec = now_ns % 1000000000ULL;
        stat->st_mtime = now_ns / 1000000000ULL;
        stat->st_mtime_nsec = now_ns % 1000000000ULL;
        stat->st_ctime = now_ns / 1000000000ULL;
        stat->st_ctime_nsec = now_ns % 1000000000ULL;
        ret = 0;
    }

    if (ret == 0) {
        fut_task_t *cur = fut_task_current();
        struct user_namespace *ns = cur ? cur->user_ns : NULL;
        stat->st_uid = userns_host_to_ns_uid(ns, stat->st_uid);
        stat->st_gid = userns_host_to_ns_gid(ns, stat->st_gid);
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
        stat->st_mode = vnode_type_to_stat_mode(vnode->type) | (vnode->mode & 07777);
        stat->st_nlink = vnode->nlinks;
        stat->st_size = vnode->size;
        stat->st_dev = vnode->mount ? vnode->mount->st_dev : 0;
        stat->st_uid = vnode->uid;
        stat->st_gid = vnode->gid;
        stat->st_blksize = 4096;
        stat->st_blocks = (vnode->size + 511) / 512;  /* 512-byte units per POSIX */

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

    if (ret == 0) {
        fut_task_t *cur = fut_task_current();
        struct user_namespace *ns = cur ? cur->user_ns : NULL;
        stat->st_uid = userns_host_to_ns_uid(ns, stat->st_uid);
        stat->st_gid = userns_host_to_ns_gid(ns, stat->st_gid);
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

    /* POSIX: MAP_SHARED + PROT_WRITE on a read-only fd must fail with EACCES.
     * Also reject if fd is not open for reading at all. */
    {
        int acc = file->flags & O_ACCMODE;
        if (acc == O_WRONLY) {
            /* Cannot read-map a write-only fd */
            return (void *)(intptr_t)(-EACCES);
        }
        if ((prot & PROT_WRITE) && (flags & MAP_SHARED) && acc == O_RDONLY) {
            return (void *)(intptr_t)(-EACCES);
        }
    }

    /* Enforce file seals on mmap.
     * F_SEAL_WRITE (0x0008): reject any shared writable mapping.
     * F_SEAL_FUTURE_WRITE (0x0010): reject new PROT_WRITE mappings
     *   (existing mappings may keep writing, but new ones are denied).
     * F_SEAL_SEAL (0x0001): does not affect mmap directly. */
    if (file->seals) {
        if ((file->seals & 0x0008 /* F_SEAL_WRITE */) && (prot & PROT_WRITE))
            return (void *)(intptr_t)(-EPERM);
        if ((file->seals & 0x0010 /* F_SEAL_FUTURE_WRITE */) &&
            (prot & PROT_WRITE) && (flags & MAP_SHARED))
            return (void *)(intptr_t)(-EPERM);
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

    __atomic_add_fetch(&vnode->refcount, 1, __ATOMIC_ACQ_REL);
    VFSDBG("[vnode-ref] vnode=%p ino=%llu refcount now %u\n",
           (void*)vnode, vnode->ino, vnode->refcount);
}

void fut_vnode_unref(struct fut_vnode *vnode) {
    if (!vnode) {
        return;
    }

    /* Keep active global root vnode pinned while mounted. */
    if (vnode == root_vnode_base) {
        return;
    }

    /* Safety check: prevent underflow */
    if (vnode->refcount == 0) {
        fut_printf("[VNODE-ERROR] refcount underflow: vnode=%p ino=%llu type=%d\n",
                   (void*)vnode, vnode->ino, vnode->type);
        return;
    }

    uint32_t remaining = __atomic_sub_fetch(&vnode->refcount, 1, __ATOMIC_ACQ_REL);
    VFSDBG("[vnode-unref] vnode=%p ino=%llu refcount now %u\n",
           (void*)vnode, vnode->ino, remaining);

    /* Free vnode when refcount reaches 0 */
    if (remaining == 0) {
        VFSDBG("[vnode-unref] freeing vnode ino=%llu type=%d\n", vnode->ino, vnode->type);

        /* Invalidate dentry cache entries before freeing */
        fut_dcache_invalidate_vnode(vnode);
        vnode->type = VN_INVALID;

        /* vnode->parent is a weak traversal pointer only — no refcount is held
         * on the parent.  Calling fut_vnode_unref(vnode->parent) here would
         * spuriously decrement the parent's refcount because no matching
         * fut_vnode_ref was called when the child was created. */
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

/**
 * fut_vnode_build_path - Build absolute path string by walking parent vnode chain
 *
 * Walks vnode->parent links and vnode->name to reconstruct the full absolute path.
 * Writes at most buf_size bytes into buf. Returns buf on success, NULL if truncated.
 */
char *fut_vnode_build_path(struct fut_vnode *vnode, char *buf, size_t buf_size) {
    if (!vnode || !buf || buf_size == 0) return NULL;

    /* Walk parents to determine depth and collect name pointers */
#define VNODE_MAX_DEPTH 32
    const char *parts[VNODE_MAX_DEPTH];
    int depth = 0;
    struct fut_vnode *v = vnode;
    while (v && v->name && v->parent && v->parent != v && depth < VNODE_MAX_DEPTH) {
        parts[depth++] = v->name;
        v = v->parent;
    }

    /* Build path by reversing the parts */
    size_t pos = 0;
    if (pos < buf_size - 1) buf[pos++] = '/';
    for (int i = depth - 1; i >= 0; i--) {
        const char *part = parts[i];
        size_t plen = strlen(part);
        if (pos + plen + 1 >= buf_size) { buf[0] = '\0'; return NULL; }
        for (size_t j = 0; j < plen; j++) buf[pos++] = part[j];
        if (i > 0 && pos < buf_size - 1) buf[pos++] = '/';
    }
    buf[pos] = '\0';
    return buf;
#undef VNODE_MAX_DEPTH
}

/**
 * fut_vfs_chdir() - Change the current working directory (kernel-level, no copy_from_user)
 */
int fut_vfs_chdir(const char *path) {
    if (!path) {
        return -EINVAL;
    }

    struct fut_vnode *vnode = NULL;
    int ret = fut_vfs_lookup(path, &vnode);
    if (ret < 0) {
        return ret;
    }
    if (!vnode) {
        return -ENOENT;
    }
    if (vnode->type != VN_DIR) {
        fut_vnode_unref(vnode);
        return -ENOTDIR;
    }

    fut_task_t *task = fut_task_current();
    if (task) {
        task->current_dir_ino = vnode->ino;
        /* Build canonical path from vnode parent chain (normalizes '..' etc.) */
        char *built = fut_vnode_build_path(vnode, task->cwd_cache_buf, 256);
        if (!built || task->cwd_cache_buf[0] == '\0') {
            /* Fallback: copy raw path */
            size_t len = 0;
            while (path[len] && len < 255) {
                task->cwd_cache_buf[len] = path[len];
                len++;
            }
            task->cwd_cache_buf[len] = '\0';
        }
        task->cwd_cache = task->cwd_cache_buf;
    }

    fut_vnode_unref(vnode);
    return 0;
}

/**
 * fut_vfs_symlink() - Create a symbolic link (kernel-level, no copy_from_user)
 */
int fut_vfs_symlink(const char *target, const char *linkpath) {
    if (!target || !linkpath) {
        return -EINVAL;
    }

    struct fut_vnode *parent = NULL;
    char leaf[FUT_VFS_NAME_MAX + 1];

    int ret = lookup_parent_and_name(linkpath, &parent, leaf);
    if (ret < 0) {
        return ret;
    }

    if (!parent->ops || !parent->ops->symlink) {
        release_lookup_ref(parent);
        return -ENOSYS;
    }

    ret = parent->ops->symlink(parent, leaf, target);
    if (ret == 0) vfs_dcache_invalidate_path(linkpath);
    release_lookup_ref(parent);
    return ret;
}

/**
 * fut_vfs_readlink() - Read a symbolic link target (kernel-level, no copy_from_user)
 */
ssize_t fut_vfs_readlink(const char *path, char *buf, size_t bufsiz) {
    if (!path || !buf || bufsiz == 0) {
        return -EINVAL;
    }

    /* Split path into parent directory and leaf name.
     * Use lookup_vnode() for the parent so intermediate symlinks are followed
     * (e.g. /proc/self/cwd: "self" is a symlink and must be resolved first). */
    char abs_buf[FUT_VFS_PATH_BUFFER_SIZE];
    path = resolve_path_to_abs(path, abs_buf);

    /* Find last '/' to split parent/leaf */
    int slash = -1;
    for (int i = 0; path[i]; i++) {
        if (path[i] == '/') slash = i;
    }

    char leaf[FUT_VFS_NAME_MAX + 1];
    struct fut_vnode *parent = NULL;
    int ret;

    if (slash <= 0) {
        /* No slash or only root slash: parent is root, leaf is path (or "") */
        if (slash == 0) {
            /* path is "/<name>" */
            size_t nl = 0;
            while (path[1 + nl] && nl < FUT_VFS_NAME_MAX) { leaf[nl] = path[1 + nl]; nl++; }
            leaf[nl] = '\0';
        } else {
            /* relative path with no slash — use cwd */
            size_t nl = 0;
            while (path[nl] && nl < FUT_VFS_NAME_MAX) { leaf[nl] = path[nl]; nl++; }
            leaf[nl] = '\0';
        }
        parent = root_vnode;
        /* root_vnode is never freed; no need to ref */
        if (!parent) return -ENOENT;
    } else {
        /* Build parent path string */
        char parent_path[FUT_VFS_PATH_BUFFER_SIZE];
        if (slash == 0) {
            parent_path[0] = '/'; parent_path[1] = '\0';
        } else {
            size_t pi = 0;
            while (pi < (size_t)slash && pi < sizeof(parent_path) - 1)
                { parent_path[pi] = path[pi]; pi++; }
            parent_path[pi] = '\0';
        }
        /* Copy leaf */
        size_t nl = 0;
        const char *lp = path + slash + 1;
        while (*lp && nl < FUT_VFS_NAME_MAX) { leaf[nl++] = *lp++; }
        leaf[nl] = '\0';

        /* Resolve parent, following intermediate symlinks */
        ret = lookup_vnode(parent_path, &parent);
        if (ret < 0) return ret;
        if (!parent) return -ENOENT;
    }

    if (!parent->ops || !parent->ops->lookup) {
        if (parent != root_vnode) release_lookup_ref(parent);
        return -ENOENT;
    }

    struct fut_vnode *vnode = NULL;
    ret = parent->ops->lookup(parent, leaf, &vnode);
    if (parent != root_vnode) release_lookup_ref(parent);
    if (ret < 0) return ret;
    if (!vnode) return -ENOENT;

    if (vnode->type != VN_LNK) {
        fut_vnode_unref(vnode);
        return -EINVAL;
    }

    if (!vnode->ops || !vnode->ops->readlink) {
        fut_vnode_unref(vnode);
        return -ENOSYS;
    }

    ssize_t len = vnode->ops->readlink(vnode, buf, bufsiz);
    fut_vnode_unref(vnode);
    return len;
}

/**
 * fut_vfs_link() - Create a hard link (kernel-level, no copy_from_user)
 */
int fut_vfs_link(const char *oldpath, const char *newpath) {
    if (!oldpath || !newpath) {
        return -EINVAL;
    }

    struct fut_vnode *old_vnode = NULL;
    int ret = fut_vfs_lookup(oldpath, &old_vnode);
    if (ret < 0) {
        return ret;
    }
    if (!old_vnode) {
        return -ENOENT;
    }

    if (!old_vnode->ops || !old_vnode->ops->link) {
        fut_vnode_unref(old_vnode);
        return -ENOSYS;
    }

    ret = old_vnode->ops->link(old_vnode, oldpath, newpath);
    if (ret == 0) vfs_dcache_invalidate_path(newpath);
    fut_vnode_unref(old_vnode);
    return ret;
}

/**
 * fut_vfs_rename() - Rename/move a file (kernel-level, no copy_from_user)
 *
 * Delegates to the parent directory vnode's rename operation.
 * Used by kernel selftests where paths are kernel-space strings.
 */
int fut_vfs_rename(const char *oldpath, const char *newpath) {
    if (!oldpath || !newpath || oldpath[0] == '\0' || newpath[0] == '\0')
        return -EINVAL;

    /* POSIX: rename(path, path) is a no-op */
    if (strcmp(oldpath, newpath) == 0)
        return 0;

    /* Find last slash to split parent dir / filename */
    size_t old_len = strlen(oldpath);
    size_t new_len = strlen(newpath);

    int old_slash = -1, new_slash = -1;
    for (size_t i = 0; i < old_len; i++)
        if (oldpath[i] == '/') old_slash = (int)i;
    for (size_t i = 0; i < new_len; i++)
        if (newpath[i] == '/') new_slash = (int)i;

    /* Build parent paths and leaf names */
    char old_parent_buf[256], new_parent_buf[256];
    const char *old_name, *new_name;

    if (old_slash < 0) {
        old_parent_buf[0] = '.'; old_parent_buf[1] = '\0';
        old_name = oldpath;
    } else if (old_slash == 0) {
        old_parent_buf[0] = '/'; old_parent_buf[1] = '\0';
        old_name = oldpath + 1;
    } else {
        size_t plen = (size_t)old_slash < 255 ? (size_t)old_slash : 255;
        memcpy(old_parent_buf, oldpath, plen);
        old_parent_buf[plen] = '\0';
        old_name = oldpath + old_slash + 1;
    }

    if (new_slash < 0) {
        new_parent_buf[0] = '.'; new_parent_buf[1] = '\0';
        new_name = newpath;
    } else if (new_slash == 0) {
        new_parent_buf[0] = '/'; new_parent_buf[1] = '\0';
        new_name = newpath + 1;
    } else {
        size_t plen = (size_t)new_slash < 255 ? (size_t)new_slash : 255;
        memcpy(new_parent_buf, newpath, plen);
        new_parent_buf[plen] = '\0';
        new_name = newpath + new_slash + 1;
    }

    if (old_name[0] == '\0' || new_name[0] == '\0')
        return -EINVAL;

    /* Look up old parent directory */
    struct fut_vnode *old_parent = NULL;
    int ret = fut_vfs_lookup(old_parent_buf, &old_parent);
    if (ret < 0 || !old_parent)
        return ret < 0 ? ret : -ENOENT;

    if (!old_parent->ops || !old_parent->ops->rename) {
        fut_vnode_unref(old_parent);
        return -ENOSYS;
    }

    /* Sticky bit enforcement on source directory */
    if (old_parent->mode & 01000) {
        fut_task_t *task = fut_task_current();
        uint32_t caller_uid = task ? task->uid : 0;
        int has_cap_fowner = task &&
            (task->cap_effective & (1ULL << 3 /* CAP_FOWNER */));
        if (caller_uid != 0 && !has_cap_fowner && caller_uid != old_parent->uid) {
            struct fut_vnode *src = NULL;
            int lret = fut_vfs_lookup(oldpath, &src);
            if (lret == 0 && src) {
                if (caller_uid != src->uid) {
                    release_lookup_ref(src);
                    fut_vnode_unref(old_parent);
                    return -EACCES;
                }
                release_lookup_ref(src);
            }
        }
    }

    /* Same parent: simple rename */
    if (strcmp(old_parent_buf, new_parent_buf) == 0) {
        ret = old_parent->ops->rename(old_parent, old_name, new_name);
        if (ret == 0) { vfs_dcache_invalidate_path(oldpath); vfs_dcache_invalidate_path(newpath); }
        fut_vnode_unref(old_parent);
        return ret;
    }

    /* Cross-directory rename: lookup new parent too */
    struct fut_vnode *new_parent = NULL;
    ret = fut_vfs_lookup(new_parent_buf, &new_parent);
    if (ret < 0 || !new_parent) {
        fut_vnode_unref(old_parent);
        return ret < 0 ? ret : -ENOENT;
    }

    if (!new_parent->ops || !new_parent->ops->rename) {
        fut_vnode_unref(old_parent);
        fut_vnode_unref(new_parent);
        return -ENOSYS;
    }

    /* Use new parent's rename with full paths for cross-directory move */
    ret = new_parent->ops->rename(old_parent, old_name, new_name);
    if (ret == 0) { vfs_dcache_invalidate_path(oldpath); vfs_dcache_invalidate_path(newpath); }
    fut_vnode_unref(old_parent);
    fut_vnode_unref(new_parent);
    return ret;
}


/* Iterate the mount list — used by procfs to generate /proc/mounts */
struct fut_mount *fut_vfs_first_mount(void) { return mount_list; }

struct fut_mount *fut_vfs_find_mount(const char *mountpoint) {
    if (!mountpoint) return NULL;
    for (struct fut_mount *m = mount_list; m; m = m->next) {
        if (m->mountpoint) {
            const char *a = m->mountpoint, *b = mountpoint;
            while (*a && *b && *a == *b) { a++; b++; }
            if (*a == '\0' && *b == '\0') return m;
        }
    }
    return NULL;
}
