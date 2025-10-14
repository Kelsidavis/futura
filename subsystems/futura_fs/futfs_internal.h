// SPDX-License-Identifier: MPL-2.0
/*
 * futfs_internal.h - Internal structures shared within FuturaFS subsystem
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <futura/blkdev.h>

#include "futfs.h"

#define FUTFS_LABEL_MAX        64u
#define FUTFS_DEFAULT_SEG_SECT 16u

typedef struct futfs_extent_disk {
    uint32_t offset; /* Offset from start of segment */
    uint32_t length;
} futfs_extent_disk_t;

typedef struct futfs_inode_disk_fixed {
    uint64_t ino;
    uint32_t type;
    uint32_t rights;
    uint64_t size;
    uint32_t dirent_count;
    uint32_t extent_count;
} futfs_inode_disk_fixed_t;

typedef struct futfs_dirent_disk {
    uint64_t ino;
    uint16_t name_len;
    uint16_t reserved;
    char name[];
} futfs_dirent_disk_t;

typedef struct futfs_segment_header_disk {
    uint64_t id;
    uint32_t checksum;
    uint32_t inode_count;
    uint64_t next_lba;
} futfs_segment_header_disk_t;

typedef struct futfs_superblock_disk {
    char magic[8];
    uint32_t version;
    uint32_t block_size;
    uint32_t segment_sectors;
    uint32_t inode_count;
    uint64_t latest_segment_lba;
    uint64_t next_free_lba;
    uint64_t root_ino;
    uint64_t next_inode;
    char label[FUTFS_LABEL_MAX];
    uint8_t reserved[512 - 8 - (6 * sizeof(uint32_t)) - (4 * sizeof(uint64_t)) - FUTFS_LABEL_MAX];
} futfs_superblock_disk_t;

struct futfs_inode_mem {
    uint64_t ino;
    uint32_t type;
    uint32_t rights;
    uint64_t size;
    uint8_t *data;
    size_t capacity;
};

struct futfs_fs {
    bool mounted;
    fut_handle_t dev_handle;
    fut_blkdev_t *dev;
    uint32_t block_size;
    uint32_t segment_sectors;
    uint64_t next_free_lba;
    uint64_t next_segment_id;
    uint64_t next_inode;
    uint32_t version;
    char label[FUTFS_LABEL_MAX];

    struct futfs_inode_mem *inodes;
    size_t inode_count;
    size_t inode_capacity;

    bool dirty;
};

extern struct futfs_fs g_fs;

size_t futfs_align8(size_t value);
struct futfs_inode_mem *futfs_find_inode(uint64_t ino);
fut_status_t futfs_resolve_dir(const char *path, struct futfs_inode_mem **dir_out);
fut_status_t futfs_dir_resolve_latest(const struct futfs_inode_mem *dir,
                                      const char *name,
                                      size_t name_len,
                                      size_t *offset_out,
                                      const futfs_dirent_disk_t **entry_out);
bool futfs_dir_is_empty(const struct futfs_inode_mem *dir);

fut_status_t futfs_gc_compact_dir(struct futfs_inode_mem *dir,
                                  struct futfs_gc_stats *stats,
                                  bool crash_before_commit);
uint64_t futfs_gc_count_tombstones(const struct futfs_inode_mem *dir);
void futfs_gc_set_crash_injection(bool enable);
bool futfs_gc_crash_enabled(void);
