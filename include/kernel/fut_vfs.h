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

/* Freestanding environment: define ssize_t */
#ifndef _SSIZE_T_DEFINED
#define _SSIZE_T_DEFINED
typedef long ssize_t;
#endif

/* Forward declarations */
struct fut_vnode;
struct fut_mount;
struct fut_file;
struct fut_vfs_ops;
struct fut_stat;

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

    /* Operations for this vnode */
    const struct fut_vnode_ops *ops;
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

struct fut_fs_type {
    const char *name;               /* Filesystem name (e.g., "futura_fs") */

    /**
     * Mount a filesystem.
     *
     * @param device  Device path (or NULL for pseudo-filesystems)
     * @param flags   Mount flags
     * @param data    Filesystem-specific mount data
     * @param mount   Pointer to store mount structure
     * @return 0 on success, negative error code on failure
     */
    int (*mount)(const char *device, int flags, void *data, struct fut_mount **mount);

    /**
     * Unmount a filesystem.
     *
     * @param mount Mount to unmount
     * @return 0 on success, negative error code on failure
     */
    int (*unmount)(struct fut_mount *mount);
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
 * @return 0 on success, negative error code on failure
 */
int fut_vfs_mount(const char *device, const char *mountpoint,
                  const char *fstype, int flags, void *data);

/**
 * Unmount a filesystem.
 *
 * @param mountpoint Mount point path
 * @return 0 on success, negative error code on failure
 */
int fut_vfs_unmount(const char *mountpoint);

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
 * Close a file.
 *
 * @param fd File descriptor
 * @return 0 on success, negative error code on failure
 */
int fut_vfs_close(int fd);

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
#define ENOSPC      28      /* No space left on device */
#define EROFS       30      /* Read-only filesystem */
