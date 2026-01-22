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

/* Formatting defaults */
#define FUTURAFS_DEFAULT_INODE_RATIO  16384  /* One inode per 16KB of storage */
#define FUTURAFS_MIN_INODES           16     /* Minimum number of inodes */

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
    uint64_t double_indirect;    /* Double indirect block pointer */
    uint64_t triple_indirect;    /* Triple indirect block pointer */

    uint8_t  reserved[8];        /* Pad to 128 bytes */
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
    /* Capability-based block device access */
    fut_handle_t block_device_handle;   /* Block device capability handle */

    /* Legacy block device pointer (for sync I/O during transition) */
    struct fut_blockdev *dev;           /* Block device (deprecated) */

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

/* ============================================================
 *   FuturaFS Async API (Phase 3)
 * ============================================================ */

/**
 * Filesystem operation completion callback.
 *
 * @param result  Operation result (0 on success, negative error code on failure)
 * @param ctx     User context pointer passed to async function
 */
typedef void (*futurafs_completion_t)(int result, void *ctx);

/**
 * Generic async operation context.
 * Specific operations extend this with operation-specific fields.
 */
struct futurafs_async_ctx {
    /* Completion callback */
    futurafs_completion_t callback;
    void *callback_ctx;

    /* Operation state */
    struct futurafs_mount *mount;
    int result;
};

/**
 * Superblock read async context.
 */
struct futurafs_sb_read_ctx {
    struct futurafs_async_ctx base;
    struct futurafs_superblock *sb;
    uint8_t block_buffer[FUTURAFS_BLOCK_SIZE];
};

/**
 * Superblock write async context.
 */
struct futurafs_sb_write_ctx {
    struct futurafs_async_ctx base;
    const struct futurafs_superblock *sb;
};

/**
 * Inode read async context.
 */
struct futurafs_inode_read_ctx {
    struct futurafs_async_ctx base;
    uint64_t ino;
    struct futurafs_inode *inode;
    uint8_t block_buffer[FUTURAFS_BLOCK_SIZE];
};

/**
 * Inode write async context.
 */
struct futurafs_inode_write_ctx {
    struct futurafs_async_ctx base;
    uint64_t ino;
    const struct futurafs_inode *inode;
    uint8_t block_buffer[FUTURAFS_BLOCK_SIZE];
};

/**
 * Data block read async context.
 */
struct futurafs_block_read_ctx {
    struct futurafs_async_ctx base;
    uint64_t block_num;
    void *buffer;
};

/**
 * Data block write async context.
 */
struct futurafs_block_write_ctx {
    struct futurafs_async_ctx base;
    uint64_t block_num;
    const void *buffer;
};

/**
 * Read superblock asynchronously.
 *
 * @param mount      Mount information
 * @param sb         Superblock buffer to read into
 * @param callback   Completion callback
 * @param ctx        User context pointer
 * @return 0 on successful submission, negative error code on failure
 */
int futurafs_read_superblock_async(struct futurafs_mount *mount,
                                   struct futurafs_superblock *sb,
                                   futurafs_completion_t callback,
                                   void *ctx);

/**
 * Write superblock asynchronously.
 *
 * @param mount      Mount information
 * @param sb         Superblock to write
 * @param callback   Completion callback
 * @param ctx        User context pointer
 * @return 0 on successful submission, negative error code on failure
 */
int futurafs_write_superblock_async(struct futurafs_mount *mount,
                                    const struct futurafs_superblock *sb,
                                    futurafs_completion_t callback,
                                    void *ctx);

/**
 * Read inode asynchronously.
 *
 * @param mount      Mount information
 * @param ino        Inode number
 * @param inode      Inode buffer to read into
 * @param callback   Completion callback
 * @param ctx        User context pointer
 * @return 0 on successful submission, negative error code on failure
 */
int futurafs_read_inode_async(struct futurafs_mount *mount,
                              uint64_t ino,
                              struct futurafs_inode *inode,
                              futurafs_completion_t callback,
                              void *ctx);

/**
 * Write inode asynchronously.
 *
 * @param mount      Mount information
 * @param ino        Inode number
 * @param inode      Inode to write
 * @param callback   Completion callback
 * @param ctx        User context pointer
 * @return 0 on successful submission, negative error code on failure
 */
int futurafs_write_inode_async(struct futurafs_mount *mount,
                               uint64_t ino,
                               const struct futurafs_inode *inode,
                               futurafs_completion_t callback,
                               void *ctx);

/**
 * Read data block asynchronously.
 *
 * @param mount      Mount information
 * @param block_num  Block number to read
 * @param buffer     Buffer to read into (must be FUTURAFS_BLOCK_SIZE bytes)
 * @param callback   Completion callback
 * @param ctx        User context pointer
 * @return 0 on successful submission, negative error code on failure
 */
int futurafs_read_block_async(struct futurafs_mount *mount,
                              uint64_t block_num,
                              void *buffer,
                              futurafs_completion_t callback,
                              void *ctx);

/**
 * Write data block asynchronously.
 *
 * @param mount      Mount information
 * @param block_num  Block number to write
 * @param buffer     Buffer to write from (must be FUTURAFS_BLOCK_SIZE bytes)
 * @param callback   Completion callback
 * @param ctx        User context pointer
 * @return 0 on successful submission, negative error code on failure
 */
int futurafs_write_block_async(struct futurafs_mount *mount,
                               uint64_t block_num,
                               const void *buffer,
                               futurafs_completion_t callback,
                               void *ctx);

/* ============================================================
 *   Phase 3b: Composite Async Operations
 * ============================================================ */

/**
 * Directory lookup async context.
 * State machine for searching directory blocks until entry found.
 */
struct futurafs_dir_lookup_ctx {
    struct futurafs_async_ctx base;

    /* Search parameters */
    struct futurafs_inode_info *dir_info;
    const char *name;
    size_t name_len;

    /* Output parameters */
    uint64_t *block_out;
    size_t *offset_out;
    struct futurafs_dirent *entry_out;

    /* State machine */
    int current_block_index;  /* Which direct block we're searching */
    uint8_t block_buffer[FUTURAFS_BLOCK_SIZE];
};

/**
 * Look up directory entry by name asynchronously.
 *
 * Searches directory blocks sequentially until finding entry with matching name.
 * Demonstrates callback loop pattern for multi-block operations.
 *
 * @param dir_info   Directory inode information
 * @param name       Name to search for
 * @param name_len   Length of name
 * @param block_out  Output: block number containing entry (optional)
 * @param offset_out Output: offset within block (optional)
 * @param entry_out  Output: directory entry (optional)
 * @param callback   Completion callback (result 0 on success, FUTURAFS_ENOENT if not found)
 * @param ctx        User context pointer
 * @return 0 on successful submission, negative error code on failure
 */
int futurafs_dir_lookup_entry_async(struct futurafs_inode_info *dir_info,
                                    const char *name,
                                    size_t name_len,
                                    uint64_t *block_out,
                                    size_t *offset_out,
                                    struct futurafs_dirent *entry_out,
                                    futurafs_completion_t callback,
                                    void *ctx);

/**
 * Directory add entry async context.
 * State machine for adding directory entry with conditional block allocation.
 */
enum futurafs_dir_add_state {
    DIR_ADD_SEARCHING,      /* Searching for free slot */
    DIR_ADD_ALLOCATING,     /* Allocating new block */
    DIR_ADD_WRITING,        /* Writing entry to block */
    DIR_ADD_COMPLETE        /* Operation complete */
};

struct futurafs_dir_add_ctx {
    struct futurafs_async_ctx base;

    /* Entry parameters */
    struct futurafs_inode_info *dir_info;
    struct fut_vnode *dir_vnode;
    const char *name;
    size_t name_len;
    uint64_t ino;
    uint8_t file_type;

    /* State machine */
    enum futurafs_dir_add_state state;
    int current_block_index;
    uint8_t block_buffer[FUTURAFS_BLOCK_SIZE];

    /* Slot tracking */
    bool found_slot;
    uint64_t slot_block;
    size_t slot_offset;
    int slot_index;

    /* Block allocation tracking */
    int new_block_index;
    bool allocated_block;
    uint64_t allocated_block_num;
};

/**
 * Add directory entry asynchronously.
 *
 * Demonstrates read-modify-write pattern with conditional block allocation.
 * Searches for free slot, allocates block if needed, writes entry.
 *
 * @param dir_vnode  Directory vnode
 * @param dir_info   Directory inode information
 * @param name       Entry name
 * @param name_len   Length of name
 * @param ino        Inode number for entry
 * @param file_type  File type
 * @param callback   Completion callback (result 0 on success, error code on failure)
 * @param ctx        User context pointer
 * @return 0 on successful submission, negative error code on failure
 */
int futurafs_dir_add_entry_async(struct fut_vnode *dir_vnode,
                                 struct futurafs_inode_info *dir_info,
                                 const char *name,
                                 size_t name_len,
                                 uint64_t ino,
                                 uint8_t file_type,
                                 futurafs_completion_t callback,
                                 void *ctx);

/**
 * File read async context.
 * State machine for multi-block file reads with offset handling.
 */
struct futurafs_file_read_ctx {
    struct futurafs_async_ctx base;

    /* Read parameters */
    struct futurafs_inode_info *inode_info;
    void *user_buffer;          /* User buffer to read into */
    size_t total_size;          /* Total bytes to read */
    uint64_t file_offset;       /* Starting offset in file */

    /* Progress tracking */
    size_t bytes_read;          /* Bytes read so far */
    uint8_t block_buffer[FUTURAFS_BLOCK_SIZE];
};

/**
 * File write async context.
 * State machine for multi-block file writes with read-modify-write pattern.
 */
enum futurafs_file_write_state {
    FILE_WRITE_READING,     /* Reading block for read-modify-write */
    FILE_WRITE_WRITING,     /* Writing modified block */
    FILE_WRITE_SYNCING,     /* Syncing inode to disk */
    FILE_WRITE_COMPLETE     /* Operation complete */
};

struct futurafs_file_write_ctx {
    struct futurafs_async_ctx base;

    /* Write parameters */
    struct futurafs_inode_info *inode_info;
    const void *user_buffer;    /* User buffer to write from */
    size_t total_size;          /* Total bytes to write */
    uint64_t file_offset;       /* Starting offset in file */

    /* Progress tracking */
    size_t bytes_written;       /* Bytes written so far */
    enum futurafs_file_write_state state;
    uint8_t block_buffer[FUTURAFS_BLOCK_SIZE];

    /* Block allocation tracking */
    uint64_t current_block_num;
    bool allocated_block;
    bool need_read;             /* Need to read block first for partial write */
};

/**
 * Read from file asynchronously.
 *
 * Reads data from file at specified offset into buffer.
 * Demonstrates multi-block sequential reads with sparse block handling.
 *
 * @param inode_info Inode information for file
 * @param buffer     Buffer to read into
 * @param size       Number of bytes to read
 * @param offset     File offset to read from
 * @param callback   Completion callback (result = bytes read, or negative error)
 * @param ctx        User context pointer
 * @return 0 on successful submission, negative error code on failure
 */
int futurafs_file_read_async(struct futurafs_inode_info *inode_info,
                              void *buffer,
                              size_t size,
                              uint64_t offset,
                              futurafs_completion_t callback,
                              void *ctx);

/**
 * Write to file asynchronously.
 *
 * Writes data to file at specified offset from buffer.
 * Demonstrates read-modify-write pattern with conditional block allocation.
 *
 * @param inode_info Inode information for file
 * @param buffer     Buffer to write from
 * @param size       Number of bytes to write
 * @param offset     File offset to write to
 * @param callback   Completion callback (result = bytes written, or negative error)
 * @param ctx        User context pointer
 * @return 0 on successful submission, negative error code on failure
 */
int futurafs_file_write_async(struct futurafs_inode_info *inode_info,
                               const void *buffer,
                               size_t size,
                               uint64_t offset,
                               futurafs_completion_t callback,
                               void *ctx);

/* Error codes */
#define FUTURAFS_EINVAL   -22    /* Invalid argument */
#define FUTURAFS_EIO      -5     /* I/O error */
#define FUTURAFS_ENOSPC   -28    /* No space left */
#define FUTURAFS_ENOENT   -2     /* No such file */
#define FUTURAFS_EEXIST   -17    /* File exists */
#define FUTURAFS_ENOTDIR  -20    /* Not a directory */
#define FUTURAFS_EISDIR   -21    /* Is a directory */
#define FUTURAFS_ENOTEMPTY -39   /* Directory not empty */
#define FUTURAFS_ENOMEM   -12    /* Out of memory */
