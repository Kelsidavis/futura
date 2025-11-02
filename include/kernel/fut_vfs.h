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

#define FUT_VFS_NAME_MAX 255

/* Freestanding environment: define ssize_t */
#ifndef _SSIZE_T_DEFINED
#define _SSIZE_T_DEFINED
typedef long ssize_t;
#endif

#ifndef _OFF_T_DEFINED
#define _OFF_T_DEFINED
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

/* ============================================================
 *   VNode (Virtual Node) - Represents a file/directory
 * ============================================================ */

struct fut_vnode {
    enum fut_vnode_type type;       /* File type */
    uint64_t ino;                   /* Inode number */
    uint32_t mode;                  /* File mode/permissions */
    uint64_t size;                  /* File size in bytes */
    uint32_t nlinks;                /* Number of hard links */

    struct fut_mount *mount;        /* Mount point this vnode belongs to */
    void *fs_data;                  /* Filesystem-specific data */

    uint32_t refcount;              /* Reference count */
    struct fut_vnode *parent;       /* Parent directory vnode (for path reconstruction) */
    char *name;                     /* Filename/basename in parent directory (for getcwd) */

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
};

/* ============================================================
 *   Filesystem Type
 * ============================================================ */

struct fut_statfs;

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
};

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
    uint64_t st_atime;              /* Access time */
    uint64_t st_mtime;              /* Modification time */
    uint64_t st_ctime;              /* Status change time */
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
 * Unmount a filesystem.
 *
 * @param mountpoint Mount point path
 * @return 0 on success, negative error code on failure
 */
int fut_vfs_unmount(const char *mountpoint);

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
 * Open a file.
 *
 * @param path  File path
 * @param flags Open flags
 * @param mode  File mode (for creation)
 * @return File descriptor, or negative error code
 */
int fut_vfs_open(const char *path, int flags, int mode);

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

/* Per-task FD management (for multi-process isolation) */
struct fut_file *vfs_get_file_from_task(struct fut_task *task, int fd);
int vfs_alloc_specific_fd_for_task(struct fut_task *task, int target_fd, struct fut_file *file);
void vfs_close_fd_in_task(struct fut_task *task, int fd);

/* Seek modes */
#define SEEK_SET    0
#define SEEK_CUR    1
#define SEEK_END    2

/* Open flags */
#define O_RDONLY    0x0000
#define O_WRONLY    0x0001
#define O_RDWR      0x0002
#define O_CREAT     0x0040
#define O_EXCL      0x0080
#define O_TRUNC     0x0200
#define O_APPEND    0x0400
#define O_NONBLOCK  0x0800

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
