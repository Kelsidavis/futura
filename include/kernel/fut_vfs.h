/* fut_vfs.h - Futura OS Virtual File System
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Modular VFS layer supporting multiple filesystem backends.
 */

#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "fut_object.h"
#include "fut_waitq.h"

#define FUT_VFS_NAME_MAX 255

/* Maximum path buffer size for kernel syscall buffers.
 * Intentionally smaller than PATH_MAX (4096) to:
 * - Conserve kernel stack space (syscalls use stack-allocated buffers)
 * - Limit copy size from userspace for DoS protection
 * - Cover typical practical path lengths
 */
#define FUT_VFS_PATH_BUFFER_SIZE 256

/* Freestanding environment: define ssize_t */
#ifndef __ssize_t_defined
#define __ssize_t_defined 1
typedef long ssize_t;
#endif

#ifndef __off_t_defined
#define __off_t_defined 1
typedef long off_t;
#endif

/* Forward declarations */
struct fut_vnode;
struct fut_mount;
struct fut_file;
struct fut_vfs_ops;
struct fut_stat;
struct fut_file_ops;
struct fut_task;

/* ============================================================
 *   File Types
 * ============================================================ */

enum fut_vnode_type {
    VN_INVALID = 0,
    VN_REG,        /* Regular file */
    VN_DIR,        /* Directory */
    VN_CHR,        /* Character device */
    VN_BLK,        /* Block device */
    VN_FIFO,       /* Named pipe */
    VN_LNK,        /* Symbolic link */
    VN_SOCK        /* Socket */
};

/** Convert vnode type enum to S_IF* file type bits for stat st_mode */
static inline uint32_t vnode_type_to_stat_mode(enum fut_vnode_type type) {
    switch (type) {
        case VN_REG:  return 0100000;  /* S_IFREG */
        case VN_DIR:  return 0040000;  /* S_IFDIR */
        case VN_CHR:  return 0020000;  /* S_IFCHR */
        case VN_BLK:  return 0060000;  /* S_IFBLK */
        case VN_FIFO: return 0010000;  /* S_IFIFO */
        case VN_LNK:  return 0120000;  /* S_IFLNK */
        case VN_SOCK: return 0140000;  /* S_IFSOCK */
        default:      return 0;
    }
}

/* ============================================================
 *   VNode (Virtual Node) - Represents a file/directory
 * ============================================================ */

struct fut_vnode {
    enum fut_vnode_type type;       /* File type */
    uint64_t ino;                   /* Inode number */
    uint32_t mode;                  /* File mode/permissions */
    uint32_t uid;                   /* File owner UID */
    uint32_t gid;                   /* File owner GID */
    uint64_t size;                  /* File size in bytes */
    uint32_t nlinks;                /* Number of hard links */

    struct fut_mount *mount;        /* Mount point this vnode belongs to */
    void *fs_data;                  /* Filesystem-specific data */

    uint32_t refcount;              /* Reference count */
    struct fut_vnode *parent;       /* Parent directory vnode (for path reconstruction) */
    char *name;                     /* Filename/basename in parent directory (for getcwd) */

    /* Phase 3: Advisory file locking state */
    uint32_t lock_type;             /* 0=none, 1=shared, 2=exclusive */
    uint32_t lock_count;            /* Number of shared locks, or 1 for exclusive */
    uint32_t lock_owner_pid;        /* PID of exclusive lock owner (0 if shared/none) */
    fut_waitq_t lock_waitq;         /* Waitq for processes blocked on lock acquisition */

    /* Per-vnode write lock for O_APPEND atomicity */
    fut_spinlock_t write_lock;

    /* Operations for this vnode */
    const struct fut_vnode_ops *ops;
};

/* Directory entry types returned by readdir() */
enum fut_vdir_type {
    FUT_VDIR_TYPE_UNKNOWN = 0,
    FUT_VDIR_TYPE_REG     = 1,
    FUT_VDIR_TYPE_DIR     = 2,
    FUT_VDIR_TYPE_CHAR    = 3,
    FUT_VDIR_TYPE_BLOCK   = 4,
    FUT_VDIR_TYPE_FIFO    = 5,
    FUT_VDIR_TYPE_SOCKET  = 6,
    FUT_VDIR_TYPE_SYMLINK = 7
};

/* Directory entry returned by filesystem backends */
struct fut_vdirent {
    uint64_t d_ino;
    uint64_t d_off;
    uint16_t d_reclen;
    uint8_t d_type;
    char d_name[FUT_VFS_NAME_MAX + 1];
};

/* ============================================================
 *   VNode Operations
 * ============================================================ */

struct fut_vnode_ops {
    /**
     * Open a vnode (called when file is opened).
     *
     * @param vnode VNode to open
     * @param flags Open flags
     * @return 0 on success, negative error code on failure
     */
    int (*open)(struct fut_vnode *vnode, int flags);

    /**
     * Close a vnode (called when file is closed).
     *
     * @param vnode VNode to close
     * @return 0 on success, negative error code on failure
     */
    int (*close)(struct fut_vnode *vnode);

    /**
     * Read from a vnode.
     *
     * @param vnode  VNode to read from
     * @param buf    Buffer to read into
     * @param size   Number of bytes to read
     * @param offset File offset
     * @return Number of bytes read, or negative error code
     */
    ssize_t (*read)(struct fut_vnode *vnode, void *buf, size_t size, uint64_t offset);

    /**
     * Write to a vnode.
     *
     * @param vnode  VNode to write to
     * @param buf    Buffer to write from
     * @param size   Number of bytes to write
     * @param offset File offset
     * @return Number of bytes written, or negative error code
     */
    ssize_t (*write)(struct fut_vnode *vnode, const void *buf, size_t size, uint64_t offset);

    /**
     * Read a directory entry.
     *
     * @param dir     Directory vnode
     * @param cookie  Iterator cookie (updated on success)
     * @param dirent  Directory entry to populate
     * @return 0 on success, negative error code on failure or end of directory
     */
    int (*readdir)(struct fut_vnode *dir, uint64_t *cookie, struct fut_vdirent *dirent);

    /**
     * Lookup a child vnode in a directory.
     *
     * @param dir    Directory vnode
     * @param name   Name to lookup
     * @param result Pointer to store result vnode
     * @return 0 on success, negative error code on failure
     */
    int (*lookup)(struct fut_vnode *dir, const char *name, struct fut_vnode **result);

    /**
     * Create a new file in a directory.
     *
     * @param dir    Directory vnode
     * @param name   Name of new file
     * @param mode   File mode/permissions
     * @param result Pointer to store new vnode
     * @return 0 on success, negative error code on failure
     */
    int (*create)(struct fut_vnode *dir, const char *name, uint32_t mode, struct fut_vnode **result);

    /**
     * Remove a file from a directory.
     *
     * @param dir  Directory vnode
     * @param name Name of file to remove
     * @return 0 on success, negative error code on failure
     */
    int (*unlink)(struct fut_vnode *dir, const char *name);

    /**
     * Create a directory.
     *
     * @param dir  Parent directory vnode
     * @param name Name of new directory
     * @param mode Directory mode/permissions
     * @return 0 on success, negative error code on failure
     */
    int (*mkdir)(struct fut_vnode *dir, const char *name, uint32_t mode);

    /**
     * Remove a directory.
     *
     * @param dir  Parent directory vnode
     * @param name Name of directory to remove
     * @return 0 on success, negative error code on failure
     */
    int (*rmdir)(struct fut_vnode *dir, const char *name);

    /**
     * Get file attributes.
     *
     * @param vnode VNode to query
     * @param stat  Pointer to stat structure to fill
     * @return 0 on success, negative error code on failure
     */
    int (*getattr)(struct fut_vnode *vnode, struct fut_stat *stat);

    /**
     * Set file attributes.
     *
     * @param vnode VNode to modify
     * @param stat  New attributes
     * @return 0 on success, negative error code on failure
     */
    int (*setattr)(struct fut_vnode *vnode, const struct fut_stat *stat);

    /**
     * Synchronize file data and metadata to storage (Phase 3).
     *
     * Flushes all modified in-core data and metadata for the vnode to the
     * underlying storage device. Does not return until the storage device
     * reports that the transfer has completed.
     *
     * @param vnode VNode to synchronize
     * @return 0 on success, negative error code on failure
     *         -EIO: I/O error during sync
     *         -EROFS: read-only filesystem
     *         -EINVAL: vnode doesn't support syncing (e.g., pipes, sockets)
     */
    int (*sync)(struct fut_vnode *vnode);

    /**
     * Synchronize file data (but not all metadata) to storage (Phase 3).
     *
     * Similar to sync(), but only flushes file data and critical metadata
     * (such as file size) required for data retrieval. Access time and other
     * non-critical metadata may not be flushed, providing better performance
     * for applications that only require data durability.
     *
     * @param vnode VNode to synchronize
     * @return 0 on success, negative error code on failure
     *         -EIO: I/O error during sync
     *         -EROFS: read-only filesystem
     *         -EINVAL: vnode doesn't support syncing (e.g., pipes, sockets)
     */
    int (*datasync)(struct fut_vnode *vnode);

    /**
     * Truncate file to specified size (Phase 3).
     *
     * Changes the size of the file. If the new size is smaller than the current
     * size, the extra data is discarded and backing storage is deallocated.
     * If the new size is larger, the file is extended and new area is zero-filled.
     *
     * @param vnode  VNode to truncate
     * @param length New file size in bytes
     * @return 0 on success, negative error code on failure
     *         -EINVAL: invalid length (e.g., negative) or not a regular file
     *         -EFBIG: length exceeds maximum file size
     *         -ENOSPC: insufficient space for extension
     *         -EROFS: read-only filesystem
     *         -EIO: I/O error during operation
     */
    int (*truncate)(struct fut_vnode *vnode, uint64_t length);

    /**
     * Create a hard link to a vnode (called by link() syscall).
     *
     * Creates a new directory entry pointing to an existing vnode, incrementing
     * its link count. Hard links allow multiple names to reference the same file.
     *
     * @param vnode   VNode to create link to
     * @param oldpath Path to existing file
     * @param newpath Path where hard link should be created
     * @return 0 on success, negative error code on failure
     *         -EEXIST: newpath already exists
     *         -EISDIR: vnode is a directory (cannot hard link directories)
     *         -ENOTDIR: newpath parent is not a directory
     *         -ENOSPC: insufficient space for new directory entry
     *         -EMLINK: too many hard links to file
     *         -EROFS: read-only filesystem
     *         -EACCES: permission denied
     */
    int (*link)(struct fut_vnode *vnode, const char *oldpath, const char *newpath);

    /**
     * Create a symbolic link (called by symlink() syscall).
     *
     * Creates a new symbolic link vnode with the given target path string.
     * The target is stored as-is (not resolved) allowing dangling symlinks.
     *
     * @param parent   Parent directory vnode
     * @param linkpath Name of symlink to create
     * @param target   Target path the symlink points to
     * @return 0 on success, negative error code on failure
     *         -EEXIST: linkpath already exists
     *         -ENOTDIR: linkpath parent is not a directory
     *         -ENOSPC: insufficient space for new entry or symlink data
     *         -EROFS: read-only filesystem
     *         -EACCES: permission denied
     */
    int (*symlink)(struct fut_vnode *parent, const char *linkpath, const char *target);

    /**
     * Read symbolic link target path (called by readlink() syscall).
     *
     * Returns the target path string stored in a symbolic link vnode.
     * Does NOT follow the symlink or resolve relative paths.
     *
     * @param vnode VNode of symbolic link to read
     * @param buf   Buffer to store target path
     * @param size  Maximum number of bytes to read
     * @return Number of bytes read (not including null terminator),
     *         or negative error code on failure
     *         -EINVAL: vnode is not a symbolic link
     *         -EFAULT: buf is inaccessible
     */
    ssize_t (*readlink)(struct fut_vnode *vnode, char *buf, size_t size);

    /**
     * Rename or move a file/directory (called by rename() syscall).
     *
     * Atomically renames oldname to newname within the directory.
     * If newname already exists, it is atomically replaced.
     * Does NOT support cross-directory moves; for that use separate
     * unlink/create operations or implement cross-parent move support.
     *
     * @param parent  Parent directory vnode containing both old and new names
     * @param oldname Name of existing file/directory to rename
     * @param newname New name for the file/directory
     * @return 0 on success, negative error code on failure
     *         -ENOENT: oldname does not exist
     *         -EEXIST: newname exists and is directory but oldname is not
     *         -EISDIR: newname is directory but oldname is not
     *         -ENOTDIR: newname parent is not a directory
     *         -ENOTEMPTY: newname is non-empty directory
     *         -EROFS: read-only filesystem
     *         -EACCES: permission denied
     */
    int (*rename)(struct fut_vnode *parent, const char *oldname, const char *newname);

    /**
     * Set extended attribute on a vnode.
     *
     * @param vnode  Target vnode
     * @param name   Attribute name (e.g. "user.comment")
     * @param value  Attribute value bytes
     * @param size   Length of value in bytes
     * @param flags  0, XATTR_CREATE, or XATTR_REPLACE
     * @return 0 on success, negative error code on failure
     *         -EEXIST: XATTR_CREATE and attribute already exists
     *         -ENODATA: XATTR_REPLACE and attribute doesn't exist
     *         -ENOSPC: no space for new attribute
     *         -ERANGE: name or value too large
     */
    int (*setxattr)(struct fut_vnode *vnode, const char *name,
                    const void *value, size_t size, int flags);

    /**
     * Get extended attribute from a vnode.
     *
     * @param vnode  Target vnode
     * @param name   Attribute name
     * @param value  Buffer for attribute value (NULL to query size)
     * @param size   Size of value buffer (0 to query size)
     * @return Attribute size on success, negative error code on failure
     *         -ENODATA: attribute not found
     *         -ERANGE: buffer too small
     */
    ssize_t (*getxattr)(struct fut_vnode *vnode, const char *name,
                        void *value, size_t size);

    /**
     * List extended attribute names on a vnode.
     *
     * @param vnode  Target vnode
     * @param list   Buffer for null-separated name list (NULL to query size)
     * @param size   Size of list buffer (0 to query size)
     * @return Total byte length of name list on success, negative error code on failure
     *         -ERANGE: buffer too small
     */
    ssize_t (*listxattr)(struct fut_vnode *vnode, char *list, size_t size);

    /**
     * Remove an extended attribute from a vnode.
     *
     * @param vnode  Target vnode
     * @param name   Attribute name to remove
     * @return 0 on success, negative error code on failure
     *         -ENODATA: attribute not found
     */
    int (*removexattr)(struct fut_vnode *vnode, const char *name);
};

/* ============================================================
 *   Filesystem Type
 * ============================================================ */

/* Forward declaration for Futura-specific statfs (defined later) */
struct fut_statfs;

/* Linux-compatible filesystem statistics structure (for syscalls) */
struct fut_linux_statfs {
    uint64_t f_type;      /* Filesystem type */
    uint64_t f_bsize;     /* Optimal transfer block size */
    uint64_t f_blocks;    /* Total data blocks in filesystem */
    uint64_t f_bfree;     /* Free blocks in filesystem */
    uint64_t f_bavail;    /* Free blocks available to unprivileged user */
    uint64_t f_files;     /* Total file nodes in filesystem */
    uint64_t f_ffree;     /* Free file nodes in filesystem */
    uint64_t f_fsid[2];   /* Filesystem ID */
    uint64_t f_namelen;   /* Maximum length of filenames */
    uint64_t f_frsize;    /* Fragment size */
    uint64_t f_flags;     /* Mount flags of filesystem */
    uint64_t f_spare[4];  /* Padding for future use */
};

/* Linux-compatible system information structure (for syscalls) */
struct fut_linux_sysinfo {
    uint64_t uptime;      /* Seconds since boot */
    uint64_t loads[3];    /* 1, 5, and 15 minute load averages */
    uint64_t totalram;    /* Total usable main memory size */
    uint64_t freeram;     /* Available memory size */
    uint64_t sharedram;   /* Amount of shared memory */
    uint64_t bufferram;   /* Memory used by buffers */
    uint64_t totalswap;   /* Total swap space size */
    uint64_t freeswap;    /* Swap space still available */
    uint16_t procs;       /* Number of current processes */
    uint16_t pad;         /* Padding */
    uint64_t totalhigh;   /* Total high memory size */
    uint64_t freehigh;    /* Available high memory size */
    uint32_t mem_unit;    /* Memory unit size in bytes */
    char _f[8];           /* Padding to 64 bytes */
};

struct fut_fs_type {
    const char *name;               /* Filesystem name (e.g., "futura_fs") */

    /**
     * Mount a filesystem.
     *
     * @param device  Device path (or NULL for pseudo-filesystems)
     * @param flags   Mount flags
     * @param data    Filesystem-specific mount data
     * @param block_device_handle Capability handle for block device (FUT_INVALID_HANDLE if none)
     * @param mount   Pointer to store mount structure
     * @return 0 on success, negative error code on failure
     */
    int (*mount)(const char *device, int flags, void *data, fut_handle_t block_device_handle, struct fut_mount **mount);

    /**
     * Unmount a filesystem.
     *
     * @param mount Mount to unmount
     * @return 0 on success, negative error code on failure
     */
    int (*unmount)(struct fut_mount *mount);

    /**
     * Query filesystem statistics.
     *
     * @param mount Mount instance
     * @param out   Receives stats
     * @return 0 on success, negative error code on failure
     */
    int (*statfs)(struct fut_mount *mount, struct fut_statfs *out);
};

/* ============================================================
 *   Mount Point
 * ============================================================ */

struct fut_mount {
    const char *device;             /* Device path */
    const char *mountpoint;         /* Mount point path */
    const struct fut_fs_type *fs;   /* Filesystem type */
    struct fut_vnode *root;         /* Root vnode of mounted filesystem */
    int flags;                      /* Mount flags */
    bool expire_marked;             /* MNT_EXPIRE first-pass marker */
    void *fs_data;                  /* Filesystem-specific data */
    uint64_t st_dev;                /* Device ID for stat() */

    /* Capability-based block device access */
    fut_handle_t block_device_handle; /* Block device capability handle (FUT_INVALID_HANDLE if none) */

    struct fut_mount *next;         /* Next in mount list */
};

/* ============================================================
 *   File Descriptor
 * ============================================================ */

struct fut_file {
    struct fut_vnode *vnode;        /* Associated vnode */
    uint64_t offset;                /* Current file offset */
    int flags;                      /* Open flags */
    uint32_t refcount;              /* Reference count */
    const struct fut_file_ops *chr_ops; /* Character device operations */
    void *chr_inode;                /* Driver-provided inode pointer */
    void *chr_private;              /* Driver private state */
    int fd_flags;                   /* FD-specific flags (e.g., FD_CLOEXEC) */
    int owner_pid;                  /* Owner PID for async I/O signals (F_SETOWN/F_GETOWN) */
    int async_sig;                  /* Signal for async I/O (F_SETSIG/F_GETSIG; 0 = SIGIO) */
    uint32_t seals;                 /* File sealing flags (F_SEAL_*) */
    char *path;                     /* Absolute path (heap-allocated); used by *at syscalls for dirfd resolution */
};

/* ============================================================
 *   VNode Operation Validation Macros
 *
 *   These macros provide consistent validation of vnode operation
 *   chains, reducing code duplication in syscall implementations.
 * ============================================================ */

/** Check if file has a valid vnode with read capability */
#define FUT_FILE_CAN_READ(file) \
    ((file) && (file)->vnode && (file)->vnode->ops && (file)->vnode->ops->read)

/** Check if file has a valid vnode with write capability */
#define FUT_FILE_CAN_WRITE(file) \
    ((file) && (file)->vnode && (file)->vnode->ops && (file)->vnode->ops->write)

/** Check if file has a valid vnode with readdir capability (directories) */
#define FUT_FILE_CAN_READDIR(file) \
    ((file) && (file)->vnode && (file)->vnode->ops && (file)->vnode->ops->readdir)

/** Check if file has a valid vnode with fsync capability */
#define FUT_FILE_CAN_FSYNC(file) \
    ((file) && (file)->vnode && (file)->vnode->ops && (file)->vnode->ops->fsync)

/** Check if file has a valid vnode with any operations */
#define FUT_FILE_HAS_VNODE_OPS(file) \
    ((file) && (file)->vnode && (file)->vnode->ops)

/** Check if file is a regular file */
#define FUT_FILE_IS_REG(file) \
    ((file) && (file)->vnode && (file)->vnode->type == VN_REG)

/** Check if file is a directory */
#define FUT_FILE_IS_DIR(file) \
    ((file) && (file)->vnode && (file)->vnode->type == VN_DIR)

/** Check if file is a character device */
#define FUT_FILE_IS_CHR(file) \
    ((file) && (file)->vnode && (file)->vnode->type == VN_CHR)

/* ============================================================
 *   File Statistics
 * ============================================================ */

struct fut_stat {
    uint64_t st_dev;                /* Device ID */
    uint64_t st_ino;                /* Inode number */
    uint32_t st_mode;               /* File mode */
    uint32_t st_nlink;              /* Number of hard links */
    uint32_t st_uid;                /* User ID */
    uint32_t st_gid;                /* Group ID */
    uint64_t st_size;               /* File size */
    uint64_t st_blksize;            /* Block size */
    uint64_t st_blocks;             /* Number of blocks */
    uint64_t st_atime;              /* Access time (seconds since epoch) */
    uint32_t st_atime_nsec;         /* Access time nanoseconds */
    uint32_t _pad_atime;            /* Padding for alignment */
    uint64_t st_mtime;              /* Modification time (seconds since epoch) */
    uint32_t st_mtime_nsec;         /* Modification time nanoseconds */
    uint32_t _pad_mtime;            /* Padding for alignment */
    uint64_t st_ctime;              /* Status change time (seconds since epoch) */
    uint32_t st_ctime_nsec;         /* Status change time nanoseconds */
    uint32_t _pad_ctime;            /* Padding for alignment */
};

/* Filesystem feature flags returned by statfs */
#define FUT_STATFS_FEAT_LOG_STRUCTURED   (1ull << 0)
#define FUT_STATFS_FEAT_TOMBSTONES       (1ull << 1)
#define FUT_STATFS_FEAT_DIR_COMPACTION   (1ull << 2)

struct fut_statfs {
    uint64_t block_size;        /* Fundamental block size */
    uint64_t blocks_total;      /* Total data blocks */
    uint64_t blocks_free;       /* Free data blocks */
    uint64_t inodes_total;      /* Total inodes */
    uint64_t inodes_free;       /* Free inode count */
    uint64_t dir_tombstones;    /* Directory tombstone entries */
    uint64_t features;          /* FUT_STATFS_FEAT_* bitmask */
};

/* ============================================================
 *   VFS API
 * ============================================================ */

/**
 * Initialize VFS subsystem.
 */
void fut_vfs_init(void);

/**
 * Set root vnode (called when root filesystem is mounted).
 *
 * @param vnode Root vnode
 */
void fut_vfs_set_root(struct fut_vnode *vnode);

/**
 * Get root vnode (for testing and direct access).
 *
 * @return Root vnode or NULL if not mounted
 */
struct fut_vnode *fut_vfs_get_root(void);
void fut_vfs_register_root_canary(uint64_t *before, uint64_t *after);
void fut_vfs_check_root_canary(const char *where);

/**
 * Increment vnode reference count.
 *
 * @param vnode VNode to reference
 */
void fut_vnode_ref(struct fut_vnode *vnode);

/**
 * Decrement vnode reference count and free if zero.
 *
 * @param vnode VNode to unreference
 */
void fut_vnode_unref(struct fut_vnode *vnode);

/**
 * Register a filesystem type.
 *
 * @param fs Filesystem type to register
 * @return 0 on success, negative error code on failure
 */
int fut_vfs_register_fs(const struct fut_fs_type *fs);

/**
 * Mount a filesystem.
 *
 * @param device     Device path
 * @param mountpoint Mount point path
 * @param fstype     Filesystem type name
 * @param flags      Mount flags
 * @param data       Filesystem-specific data
 * @param block_device_handle  Capability handle for block device (FUT_INVALID_HANDLE if none)
 * @return 0 on success, negative error code on failure
 */
int fut_vfs_mount(const char *device, const char *mountpoint,
                  const char *fstype, int flags, void *data, fut_handle_t block_device_handle);

/**
 * Create a bind mount.
 *
 * Makes the directory at @source visible at @target.  The @target string
 * must be heap-allocated; ownership is transferred on success.
 *
 * @param source  Absolute path of source directory.
 * @param target  Heap-allocated absolute path of target mount point.
 * @return 0 on success, negative errno on failure.
 */
int fut_vfs_bind_mount(const char *source, char *target);
int fut_vfs_move_mount(const char *source, char *target);

/**
 * Unmount a filesystem.
 *
 * @param mountpoint Mount point path
 * @return 0 on success, negative error code on failure
 */
int fut_vfs_unmount(const char *mountpoint);

/**
 * Remount a filesystem and update its mount flags.
 *
 * @param mountpoint Mount point path
 * @param flags      New persistent mount flags (without MS_REMOUNT bit)
 * @return 0 on success, negative error code on failure
 */
int fut_vfs_remount(const char *mountpoint, int flags);

/**
 * Mark a mount as expirable, or unmount it on a second expire request.
 *
 * Behavior matches Linux umount2(MNT_EXPIRE):
 * - First call marks mount and returns -EAGAIN
 * - Second call unmounts (or returns unmount error)
 *
 * @param mountpoint Mount point path
 * @return -EAGAIN on first mark, 0 on unmount, negative error otherwise
 */
int fut_vfs_expire_mount(const char *mountpoint);

/**
 * Query filesystem statistics for a mounted filesystem.
 *
 * @param mountpoint Mount point path (e.g. "/mnt")
 * @param out        Receives filesystem statistics
 * @return 0 on success, negative error code otherwise
 */
int fut_vfs_statfs(const char *mountpoint, struct fut_statfs *out);

/**
 * Lookup a vnode by path and return it with an extra reference.
 *
 * @param path      Path to resolve
 * @param out_vnode Receives referenced vnode on success
 * @return 0 on success, negative error code on failure
 */
int fut_vfs_lookup(const char *path, struct fut_vnode **out_vnode);

/**
 * Look up a path without following the final symlink component (lstat semantics).
 * Intermediate symlinks in the path are still resolved.
 *
 * @param path      File path
 * @param out_vnode Output: resolved vnode (caller must call fut_vnode_unref)
 * @return 0 on success, negative error code on failure
 */
int fut_vfs_lookup_nofollow(const char *path, struct fut_vnode **out_vnode);

/**
 * Open a file.
 *
 * @param path  File path
 * @param flags Open flags
 * @param mode  File mode (for creation)
 * @return File descriptor, or negative error code
 */
int fut_vfs_open(const char *path, int flags, int mode);

/**
 * Open a file relative to a directory file descriptor (for *at syscalls).
 *
 * If path is absolute or dirfd is AT_FDCWD, behaves identically to fut_vfs_open.
 * If path is relative and dirfd is a valid directory FD, resolves path relative
 * to that directory using the stored fut_file.path of the dirfd.
 *
 * @param task   Current task (for fd table lookup)
 * @param dirfd  Directory file descriptor or AT_FDCWD
 * @param path   Path to open (absolute or relative)
 * @param flags  Open flags (O_RDONLY, O_WRONLY, O_CREAT, etc.)
 * @param mode   File mode for newly created files
 * @return File descriptor, or negative error code
 */
int fut_vfs_open_at(struct fut_task *task, int dirfd, const char *path, int flags, int mode);

/**
 * Resolve a dirfd-relative path to an absolute path.
 *
 * Combines the stored absolute path of the directory referred to by dirfd
 * with a relative path component to produce an absolute path. If path is
 * already absolute or dirfd is AT_FDCWD, the path is copied unchanged.
 *
 * @param task     Current task (needed for fd_table access)
 * @param dirfd    Directory fd, or AT_FDCWD for CWD-relative
 * @param path     Relative (or absolute) path component
 * @param out      Output buffer for the resolved absolute path
 * @param out_size Size of the output buffer
 * @return 0 on success, negative errno on failure
 */
int fut_vfs_resolve_at(struct fut_task *task, int dirfd, const char *path,
                       char *out, size_t out_size);

/**
 * Read from a file.
 *
 * @param fd   File descriptor
 * @param buf  Buffer to read into
 * @param size Number of bytes to read
 * @return Number of bytes read, or negative error code
 */
ssize_t fut_vfs_read(int fd, void *buf, size_t size);

/**
 * Write to a file.
 *
 * @param fd   File descriptor
 * @param buf  Buffer to write from
 * @param size Number of bytes to write
 * @return Number of bytes written, or negative error code
 */
ssize_t fut_vfs_write(int fd, const void *buf, size_t size);

/**
 * Read a directory entry.
 *
 * @param path   Directory path
 * @param cookie Iterator cookie (offset)
 * @param dirent Directory entry to populate
 * @return 0 on success, -ENOENT when no more entries, negative error code otherwise
 */
int fut_vfs_readdir(const char *path, uint64_t *cookie, struct fut_vdirent *dirent);

/**
 * Read next directory entry from an open directory file descriptor
 * @param fd File descriptor of open directory
 * @param cookie Iterator cookie (offset)
 * @param dirent Directory entry to populate
 * @return 0 on success, -ENOENT when no more entries, negative error code otherwise
 */
int fut_vfs_readdir_fd(int fd, uint64_t *cookie, struct fut_vdirent *dirent);

/**
 * Close a file.
 *
 * @param fd File descriptor
 * @return 0 on success, negative error code on failure
 */
int fut_vfs_close(int fd);

/**
 * Get file structure from file descriptor (for testing).
 *
 * @param fd File descriptor
 * @return File structure pointer, or NULL if invalid
 */
struct fut_file *fut_vfs_get_file(int fd);

/**
 * Return the head of the global mount list (for procfs /proc/mounts).
 * Callers must not modify the list; it is read-only.
 */
struct fut_mount *fut_vfs_first_mount(void);

/**
 * Get file structure from file descriptor (exported for syscalls).
 *
 * @param fd File descriptor
 * @return File structure pointer, or NULL if invalid
 */
struct fut_file *vfs_get_file(int fd);

/**
 * Free a file descriptor slot (exported for syscalls).
 *
 * @param fd File descriptor to free
 */
void vfs_free_fd(int fd);

/**
 * Seek within a file.
 *
 * @param fd     File descriptor
 * @param offset Offset to seek to
 * @param whence Seek mode (SEEK_SET, SEEK_CUR, SEEK_END)
 * @return New file offset, or negative error code
 */
int64_t fut_vfs_lseek(int fd, int64_t offset, int whence);

/**
 * Get file statistics.
 *
 * @param path File path
 * @param stat Pointer to stat structure
 * @return 0 on success, negative error code on failure
 */
int fut_vfs_stat(const char *path, struct fut_stat *stat);

/**
 * Get file statistics without following final symlink.
 * Like stat() but for lstat() - returns information about the symlink itself,
 * not what it points to.
 *
 * @param path File path
 * @param stat Pointer to stat structure
 * @return 0 on success, negative error code on failure
 */
int fut_vfs_lstat(const char *path, struct fut_stat *stat);

int fut_vfs_ioctl(int fd, unsigned long req, unsigned long arg);
void *fut_vfs_mmap(int fd, void *addr, size_t len, int prot, int flags, off_t off);

/**
 * Remove a file.
 *
 * @param path Path to file
 * @return 0 on success or negative error code on failure
 */
int fut_vfs_unlink(const char *path);

/**
 * Remove a directory.
 *
 * @param path Path to directory
 * @return 0 on success or negative error code on failure
 */
int fut_vfs_rmdir(const char *path);

/**
 * Create a directory.
 *
 * @param path Path to new directory
 * @param mode Permission bits for directory
 * @return 0 on success or negative error code on failure
 */
int fut_vfs_mkdir(const char *path, uint32_t mode);
int fut_vfs_create_file(const char *path, uint32_t mode);
int fut_vfs_mknod(const char *path, uint32_t mode);
int fut_vfs_chdir(const char *path);
int fut_vfs_symlink(const char *target, const char *linkpath);
ssize_t fut_vfs_readlink(const char *path, char *buf, size_t bufsiz);
int fut_vfs_link(const char *oldpath, const char *newpath);
int fut_vfs_rename(const char *oldpath, const char *newpath);

/**
 * Sync all cached data for a specific filesystem.
 *
 * @param mount Mount point to sync
 * @return 0 on success or negative error code on failure
 */
int fut_vfs_sync_fs(struct fut_mount *mount);

/**
 * Sync all cached data for all mounted filesystems.
 *
 * @return 0 on success or negative error code on failure
 */
int fut_vfs_sync_all(void);

/**
 * Build an absolute path string for a vnode by walking parent links.
 * Writes at most buf_size bytes into buf, including the null terminator.
 * Returns a pointer to buf on success, or NULL if the path was truncated.
 */
char *fut_vnode_build_path(struct fut_vnode *vnode, char *buf, size_t buf_size);

/**
 * inotify_dispatch_event - Deliver a VFS filesystem event to inotify watchers.
 * Called by the VFS when files are created, deleted, or modified.
 *
 * @param dir_path  Absolute path of the directory where the event occurred
 * @param mask      inotify event mask (IN_CREATE, IN_DELETE, IN_MODIFY, etc.)
 * @param filename  Basename of the affected file (may be NULL for self-events)
 * @param cookie    Rename cookie linking IN_MOVED_FROM/IN_MOVED_TO pairs (0 for non-rename)
 */
void inotify_dispatch_event(const char *dir_path, uint32_t mask, const char *filename,
                            uint32_t cookie);
uint32_t inotify_next_rename_cookie(void);

/* Per-task FD management (for multi-process isolation) */
struct fut_file *vfs_get_file_from_task(struct fut_task *task, int fd);
int vfs_alloc_fd_for_task(struct fut_task *task, struct fut_file *file);
int vfs_alloc_specific_fd_for_task(struct fut_task *task, int target_fd, struct fut_file *file);
void vfs_close_fd_in_task(struct fut_task *task, int fd);

/* File reference counting */
void vfs_file_ref(struct fut_file *file);

/* Permission checking */
int vfs_check_read_perm(struct fut_vnode *vnode);
int vfs_check_write_perm(struct fut_vnode *vnode);
int vfs_check_exec_perm(struct fut_vnode *vnode);
int vfs_check_modify_perm(struct fut_vnode *vnode);

/* Seek modes */
#define SEEK_SET    0
#define SEEK_CUR    1
#define SEEK_END    2

/* Open flags */
#define O_RDONLY    0x0000
#ifndef O_WRONLY
#define O_WRONLY    0x0001
#endif
#ifndef O_RDWR
#define O_RDWR      0x0002
#endif
#ifndef O_ACCMODE
#define O_ACCMODE   0x0003  /* Mask for access mode (O_RDONLY, O_WRONLY, O_RDWR) */
#endif
#ifndef O_CREAT
#define O_CREAT     0x0040
#endif
#ifndef O_EXCL
#define O_EXCL      0x0080
#endif
#ifndef O_TRUNC
#define O_TRUNC     0x0200
#endif
#ifndef O_APPEND
#define O_APPEND    0x0400
#endif
#ifndef O_NONBLOCK
#define O_NONBLOCK  0x0800
#endif
#ifndef O_CLOEXEC
#define O_CLOEXEC   0x80000  /* Close on exec */
#endif

/* Internal kernel-only flag stored in fut_file.flags.
 * Set by chrdev_alloc_fd() on programmatically-created chr_ops files
 * (sockets, eventfd, timerfd, signalfd, pidfd, mqueue) to mark them
 * as non-seekable.  Cleared by memfd after allocation. */
#define FUT_F_UNSEEKABLE 0x40000000
/* Set by memfd_create(MFD_ALLOW_SEALING) to permit F_ADD_SEALS/F_GET_SEALS.
 * Without this flag, F_ADD_SEALS returns -EPERM (Linux semantics). */
#define FUT_F_SEALING    0x20000000

/* Error codes */
#define ENOENT      2       /* No such file or directory */
#define EIO         5       /* I/O error */
#define EBADF       9       /* Bad file descriptor */
#define ENOMEM      12      /* Out of memory */
#define EACCES      13      /* Permission denied */
#define EEXIST      17      /* File exists */
#define ENOTDIR     20      /* Not a directory */
#define EISDIR      21      /* Is a directory */
#define EINVAL      22      /* Invalid argument */
#define ENFILE      23      /* File table overflow */
#define EMFILE      24      /* Too many open files */
#define ENOSPC      28      /* No space left on device */
#define EROFS       30      /* Read-only filesystem */
#define ENAMETOOLONG 36     /* File name too long */
#define ENOSYS      38      /* Function not implemented */
#define ENOTEMPTY   39      /* Directory not empty */
#define EPERM       1       /* Operation not permitted */
#define ELOOP       40      /* Too many symbolic links encountered */

/* ============================================================
 *   Capability-aware VFS Operations (Phase 1)
 * ============================================================ */

/**
 * Open a file with capability-based access control.
 *
 * @param path  File path to open
 * @param flags Open flags (O_RDONLY, O_WRONLY, O_RDWR, O_CREAT, etc.)
 * @param mode  File mode for creation
 * @return Capability handle on success, FUT_INVALID_HANDLE on failure
 */
fut_handle_t fut_vfs_open_cap(const char *path, int flags, int mode);

/**
 * Read from a file using capability handle.
 *
 * @param handle Capability handle to file
 * @param buffer Buffer to read into
 * @param count  Number of bytes to read
 * @return Number of bytes read, or negative error code
 */
long fut_vfs_read_cap(fut_handle_t handle, void *buffer, size_t count);

/**
 * Write to a file using capability handle.
 *
 * @param handle Capability handle to file
 * @param buffer Buffer to write from
 * @param count  Number of bytes to write
 * @return Number of bytes written, or negative error code
 */
long fut_vfs_write_cap(fut_handle_t handle, const void *buffer, size_t count);

/**
 * Seek within a file using capability handle.
 *
 * @param handle Capability handle to file
 * @param offset Seek offset
 * @param whence Seek mode (SEEK_SET, SEEK_CUR, SEEK_END)
 * @return New file offset, or negative error code
 */
long fut_vfs_lseek_cap(fut_handle_t handle, int64_t offset, int whence);

/**
 * Sync file data to storage using capability handle.
 *
 * @param handle Capability handle to file
 * @return 0 on success, negative error code on failure
 */
int fut_vfs_fsync_cap(fut_handle_t handle);

/**
 * Get file statistics using capability handle.
 *
 * @param handle  Capability handle to file
 * @param statbuf Buffer to receive file statistics
 * @return 0 on success, negative error code on failure
 */
int fut_vfs_fstat_cap(fut_handle_t handle, struct fut_stat *statbuf);

/**
 * Close a file using capability handle.
 *
 * @param handle Capability handle to close
 * @return 0 on success, negative error code on failure
 */
int fut_vfs_close_cap(fut_handle_t handle);

/* ============================================================
 *   Capability-aware Directory Operations
 * ============================================================ */

/**
 * Create a directory relative to a parent handle.
 *
 * @param parent_handle Capability handle to parent directory
 * @param name          Name of directory to create
 * @param mode          Directory permissions
 * @return 0 on success, negative error code on failure
 */
int fut_vfs_mkdirat_cap(fut_handle_t parent_handle, const char *name, int mode);

/**
 * Remove a directory relative to a parent handle.
 *
 * @param parent_handle Capability handle to parent directory
 * @param name          Name of directory to remove
 * @return 0 on success, negative error code on failure
 */
int fut_vfs_rmdirat_cap(fut_handle_t parent_handle, const char *name);

/**
 * Unlink (delete) a file relative to a parent handle.
 *
 * @param parent_handle Capability handle to parent directory
 * @param name          Name of file to unlink
 * @return 0 on success, negative error code on failure
 */
int fut_vfs_unlinkat_cap(fut_handle_t parent_handle, const char *name);

/**
 * Get file statistics relative to a parent handle.
 *
 * @param parent_handle Capability handle to parent directory
 * @param name          Name of file to stat
 * @param statbuf       Buffer to receive statistics
 * @return 0 on success, negative error code on failure
 */
int fut_vfs_statat_cap(fut_handle_t parent_handle, const char *name, struct fut_stat *statbuf);

/* ============================================================
 *   Handle Transfer Operations
 * ============================================================ */

/**
 * Duplicate a handle with reduced rights.
 *
 * @param handle     Source handle to duplicate
 * @param new_rights Rights to grant to new handle (must be subset of original)
 * @return New handle on success, FUT_INVALID_HANDLE on failure
 */
fut_handle_t fut_cap_handle_dup(fut_handle_t handle, fut_rights_t new_rights);

/**
 * Send a handle to another process.
 *
 * @param target_pid Process ID to send handle to
 * @param handle     Handle to send
 * @param rights     Rights to grant to receiver
 * @return New handle in target process, or FUT_INVALID_HANDLE on failure
 */
fut_handle_t fut_cap_handle_send(uint64_t target_pid, fut_handle_t handle, fut_rights_t rights);

/**
 * Receive a handle from another process.
 *
 * @param source_pid Process ID to receive from
 * @param rights_out Receives the rights of the received handle
 * @return Received handle, or FUT_INVALID_HANDLE on failure
 */
fut_handle_t fut_cap_handle_recv(uint64_t source_pid, fut_rights_t *rights_out);

/**
 * Get the rights associated with a handle.
 *
 * @param handle Handle to query
 * @return Rights bitmask, or FUT_RIGHT_NONE if invalid handle
 */
fut_rights_t fut_cap_get_rights(fut_handle_t handle);

/**
 * Validate that a handle has specific rights.
 *
 * @param handle   Handle to validate
 * @param required Required rights bitmask
 * @return true if handle has all required rights, false otherwise
 */
bool fut_cap_validate(fut_handle_t handle, fut_rights_t required);
