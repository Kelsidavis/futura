/* fut_futurafs.h - FuturaFS Filesystem
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Native filesystem for Futura OS built on block device layer.
 * Simple Unix-like design with inodes, directories, and data blocks.
 */

#pragma once

#include <kernel/fut_vfs.h>
#include <kernel/fut_blockdev.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* ============================================================
 *   FuturaFS Constants
 * ============================================================ */

#define FUTURAFS_MAGIC          0x46555455  /* "FUTU" */
#define FUTURAFS_VERSION        1
#define FUTURAFS_BLOCK_SIZE     4096
#define FUTURAFS_NAME_MAX       255
#define FUTURAFS_INODE_SIZE     128
#define FUTURAFS_ROOT_INO       1

/* Direct block pointers in inode */
#define FUTURAFS_DIRECT_BLOCKS  12
#define FUTURAFS_INDIRECT_BLOCK 1

/* ============================================================
 *   On-Disk Structures
 * ============================================================ */

/**
 * FuturaFS Superblock (Block 0)
 *
 * Layout:
 * - Block 0: Superblock
 * - Block 1-N: Inode table
 * - Block N+1: Inode bitmap
 * - Block N+2: Data block bitmap
 * - Block N+3+: Data blocks
 */
struct futurafs_superblock {
    uint32_t magic;              /* Magic number (FUTURAFS_MAGIC) */
    uint32_t version;            /* Filesystem version */
    uint32_t block_size;         /* Block size in bytes */
    uint64_t total_blocks;       /* Total blocks in filesystem */
    uint64_t total_inodes;       /* Total number of inodes */
    uint64_t free_blocks;        /* Number of free data blocks */
    uint64_t free_inodes;        /* Number of free inodes */

    uint64_t inode_table_block;  /* First block of inode table */
    uint64_t inode_bitmap_block; /* Block containing inode bitmap */
    uint64_t data_bitmap_block;  /* Block containing data bitmap */
    uint64_t data_blocks_start;  /* First data block */

    uint64_t mount_time;         /* Last mount time */
    uint64_t write_time;         /* Last write time */
    uint32_t mount_count;        /* Number of mounts since fsck */
    uint32_t max_mount_count;    /* Max mounts before fsck */

    uint8_t  uuid[16];           /* Filesystem UUID */
    char     label[64];          /* Volume label */

    uint8_t  reserved[3776];     /* Pad to 4096 bytes */
} __attribute__((packed));

/**
 * FuturaFS Inode
 *
 * Represents a file or directory in the filesystem.
 */
struct futurafs_inode {
    uint32_t mode;               /* File mode and type */
    uint32_t uid;                /* Owner user ID */
    uint32_t gid;                /* Owner group ID */
    uint32_t nlinks;             /* Number of hard links */

    uint64_t size;               /* File size in bytes */
    uint64_t blocks;             /* Number of blocks allocated */

    uint64_t atime;              /* Access time */
    uint64_t mtime;              /* Modification time */
    uint64_t ctime;              /* Change time */

    uint64_t direct[FUTURAFS_DIRECT_BLOCKS];   /* Direct block pointers */
    uint64_t indirect;           /* Single indirect block pointer */

    uint8_t  reserved[24];       /* Pad to 128 bytes */
} __attribute__((packed));

/**
 * FuturaFS Directory Entry
 *
 * Stored within directory data blocks.
 */
struct futurafs_dirent {
    uint64_t ino;                /* Inode number (0 = unused) */
    uint16_t rec_len;            /* Length of this entry */
    uint8_t  name_len;           /* Length of name */
    uint8_t  file_type;          /* File type */
    char     name[FUTURAFS_NAME_MAX + 1]; /* Filename */
} __attribute__((packed));

/* Directory entry file types */
#define FUTURAFS_FT_UNKNOWN    0
#define FUTURAFS_FT_REG_FILE   1
#define FUTURAFS_FT_DIR        2
#define FUTURAFS_FT_CHRDEV     3
#define FUTURAFS_FT_BLKDEV     4
#define FUTURAFS_FT_FIFO       5
#define FUTURAFS_FT_SOCK       6
#define FUTURAFS_FT_SYMLINK    7

/* ============================================================
 *   In-Memory Structures
 * ============================================================ */

/**
 * FuturaFS mount information
 */
struct futurafs_mount {
    struct fut_blockdev *dev;           /* Block device */
    struct futurafs_superblock *sb;     /* Superblock */

    uint8_t *inode_bitmap;              /* Inode allocation bitmap */
    uint8_t *data_bitmap;               /* Data block allocation bitmap */

    uint32_t inodes_per_block;          /* Inodes per block */
    bool dirty;                         /* Filesystem needs sync */
};

/**
 * FuturaFS inode information
 */
struct futurafs_inode_info {
    struct futurafs_inode disk_inode;   /* On-disk inode */
    uint64_t ino;                       /* Inode number */
    struct futurafs_mount *mount;       /* Mount point */
    bool dirty;                         /* Inode needs sync */
};

/* ============================================================
 *   FuturaFS API
 * ============================================================ */

/**
 * Initialize FuturaFS driver.
 */
void fut_futurafs_init(void);

/**
 * Format a block device with FuturaFS.
 *
 * @param dev        Block device to format
 * @param label      Volume label (optional, can be NULL)
 * @param inode_ratio Bytes per inode (0 = auto)
 * @return 0 on success, negative error code on failure
 */
int fut_futurafs_format(struct fut_blockdev *dev, const char *label, uint32_t inode_ratio);

/**
 * Mount a FuturaFS filesystem.
 *
 * @param device     Device path
 * @param flags      Mount flags
 * @param data       Mount options
 * @param mount_out  Pointer to store mount info
 * @return 0 on success, negative error code on failure
 */
int fut_futurafs_mount(const char *device, int flags, void *data, struct fut_mount **mount_out);

/**
 * Unmount a FuturaFS filesystem.
 *
 * @param mount Mount point
 * @return 0 on success, negative error code on failure
 */
int fut_futurafs_unmount(struct fut_mount *mount);

/**
 * Sync filesystem to disk.
 *
 * @param mount Mount point
 * @return 0 on success, negative error code on failure
 */
int fut_futurafs_sync(struct fut_mount *mount);

/* Error codes */
#define FUTURAFS_EINVAL   -22    /* Invalid argument */
#define FUTURAFS_EIO      -5     /* I/O error */
#define FUTURAFS_ENOSPC   -28    /* No space left */
#define FUTURAFS_ENOENT   -2     /* No such file */
#define FUTURAFS_EEXIST   -17    /* File exists */
#define FUTURAFS_ENOTDIR  -20    /* Not a directory */
#define FUTURAFS_EISDIR   -21    /* Is a directory */
#define FUTURAFS_ENOTEMPTY -39   /* Directory not empty */
