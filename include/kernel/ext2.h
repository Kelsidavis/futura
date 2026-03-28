/* kernel/ext2.h - ext2 filesystem on-disk structures
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 */

#ifndef KERNEL_EXT2_H
#define KERNEL_EXT2_H

#include <stdint.h>

#define EXT2_SUPER_MAGIC    0xEF53
#define EXT2_ROOT_INO       2
#define EXT2_SUPER_OFFSET   1024    /* Superblock is at byte offset 1024 */

/* Inode file type (from i_mode) */
#define EXT2_S_IFREG    0x8000
#define EXT2_S_IFDIR    0x4000
#define EXT2_S_IFLNK    0xA000

/* Directory entry file_type field */
#define EXT2_FT_UNKNOWN  0
#define EXT2_FT_REG_FILE 1
#define EXT2_FT_DIR      2
#define EXT2_FT_CHRDEV   3
#define EXT2_FT_BLKDEV   4
#define EXT2_FT_FIFO     5
#define EXT2_FT_SOCK     6
#define EXT2_FT_SYMLINK  7

/* Feature compat flags */
#define EXT3_FEATURE_COMPAT_HAS_JOURNAL  0x0004

/* Feature incompat flags */
#define EXT2_FEATURE_INCOMPAT_FILETYPE   0x0002
#define EXT4_FEATURE_INCOMPAT_EXTENTS    0x0040
#define EXT4_FEATURE_INCOMPAT_64BIT      0x0080
#define EXT4_FEATURE_INCOMPAT_FLEX_BG    0x0200

/* Feature ro_compat flags */
#define EXT2_FEATURE_RO_COMPAT_SPARSE_SUPER  0x0001
#define EXT2_FEATURE_RO_COMPAT_LARGE_FILE    0x0002
#define EXT4_FEATURE_RO_COMPAT_HUGE_FILE     0x0008
#define EXT4_FEATURE_RO_COMPAT_DIR_NLINK     0x0020
#define EXT4_FEATURE_RO_COMPAT_EXTRA_ISIZE   0x0040

/* Incompat features we cannot handle (require write support or extent trees) */
#define EXT2_INCOMPAT_UNSUPPORTED ( \
    EXT4_FEATURE_INCOMPAT_EXTENTS | \
    EXT4_FEATURE_INCOMPAT_64BIT   )

/* Maximum log_block_size: 6 means 64KB blocks (1024 << 6) */
#define EXT2_MAX_LOG_BLOCK_SIZE  6

/* On-disk superblock (at byte offset 1024) */
struct ext2_super_block {
    uint32_t s_inodes_count;
    uint32_t s_blocks_count;
    uint32_t s_r_blocks_count;
    uint32_t s_free_blocks_count;
    uint32_t s_free_inodes_count;
    uint32_t s_first_data_block;
    uint32_t s_log_block_size;      /* block_size = 1024 << this */
    uint32_t s_log_frag_size;
    uint32_t s_blocks_per_group;
    uint32_t s_frags_per_group;
    uint32_t s_inodes_per_group;
    uint32_t s_mtime;
    uint32_t s_wtime;
    uint16_t s_mnt_count;
    uint16_t s_max_mnt_count;
    uint16_t s_magic;               /* Must be EXT2_SUPER_MAGIC */
    uint16_t s_state;
    uint16_t s_errors;
    uint16_t s_minor_rev_level;
    uint32_t s_lastcheck;
    uint32_t s_checkinterval;
    uint32_t s_creator_os;
    uint32_t s_rev_level;
    uint16_t s_def_resuid;
    uint16_t s_def_resgid;
    /* Rev 1 fields */
    uint32_t s_first_ino;
    uint16_t s_inode_size;
    uint16_t s_block_group_nr;
    uint32_t s_feature_compat;
    uint32_t s_feature_incompat;
    uint32_t s_feature_ro_compat;
    uint8_t  s_uuid[16];
    char     s_volume_name[16];
    char     s_last_mounted[64];
    uint32_t s_algo_bitmap;
    /* Padding to 1024 bytes total (204 bytes of fields above) */
    uint8_t  _pad[1024 - 204];
};

/* Block group descriptor (32 bytes) */
struct ext2_group_desc {
    uint32_t bg_block_bitmap;
    uint32_t bg_inode_bitmap;
    uint32_t bg_inode_table;
    uint16_t bg_free_blocks_count;
    uint16_t bg_free_inodes_count;
    uint16_t bg_used_dirs_count;
    uint16_t bg_pad;
    uint8_t  bg_reserved[12];
};

/* On-disk inode (128 bytes for rev 0) */
struct ext2_inode {
    uint16_t i_mode;
    uint16_t i_uid;
    uint32_t i_size;
    uint32_t i_atime;
    uint32_t i_ctime;
    uint32_t i_mtime;
    uint32_t i_dtime;
    uint16_t i_gid;
    uint16_t i_links_count;
    uint32_t i_blocks;          /* 512-byte sector count */
    uint32_t i_flags;
    uint32_t i_osd1;
    uint32_t i_block[15];       /* 0-11=direct, 12=indirect, 13=double, 14=triple */
    uint32_t i_generation;
    uint32_t i_file_acl;
    uint32_t i_dir_acl;         /* i_size_high for regular files in rev 1 */
    uint32_t i_faddr;
    uint8_t  i_osd2[12];
};

/* Directory entry (variable length) */
struct ext2_dir_entry {
    uint32_t inode;
    uint16_t rec_len;
    uint8_t  name_len;
    uint8_t  file_type;         /* Only if INCOMPAT_FILETYPE */
    char     name[];            /* Variable length */
};

/* In-memory ext2 mount state */
struct ext2_mount_info {
    struct fut_blockdev *dev;
    uint32_t block_size;
    uint32_t inodes_per_group;
    uint32_t blocks_per_group;
    uint32_t inode_size;
    uint32_t group_count;
    uint32_t inodes_count;
    uint32_t blocks_count;
    uint32_t free_blocks;
    uint32_t free_inodes;
    uint32_t first_data_block;
    uint32_t feature_compat;
    uint32_t feature_incompat;
    uint32_t feature_ro_compat;
    struct ext2_group_desc *group_descs;
};

/* ext2 filesystem registration */
void ext2_init(void);

#endif /* KERNEL_EXT2_H */
