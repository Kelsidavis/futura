/* kernel/fat.h - FAT filesystem on-disk structures
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Supports FAT12, FAT16, and FAT32 (read-only).
 */

#ifndef KERNEL_FAT_H
#define KERNEL_FAT_H

#include <stdint.h>

/* FAT Boot Sector (BPB - BIOS Parameter Block) */
struct fat_bpb {
    uint8_t  jmp[3];
    char     oem_name[8];
    uint16_t bytes_per_sector;
    uint8_t  sectors_per_cluster;
    uint16_t reserved_sectors;
    uint8_t  num_fats;
    uint16_t root_entry_count;     /* 0 for FAT32 */
    uint16_t total_sectors_16;
    uint8_t  media_type;
    uint16_t fat_size_16;          /* 0 for FAT32 */
    uint16_t sectors_per_track;
    uint16_t num_heads;
    uint32_t hidden_sectors;
    uint32_t total_sectors_32;
    /* FAT32 extended BPB */
    uint32_t fat_size_32;
    uint16_t ext_flags;
    uint16_t fs_version;
    uint32_t root_cluster;         /* FAT32: first cluster of root dir */
    uint16_t fs_info;
    uint16_t backup_boot;
    uint8_t  reserved[12];
    uint8_t  drive_number;
    uint8_t  reserved1;
    uint8_t  boot_sig;
    uint32_t volume_id;
    char     volume_label[11];
    char     fs_type[8];
} __attribute__((packed));

/* FAT directory entry (32 bytes) */
struct fat_dir_entry {
    char     name[11];             /* 8.3 format: "FILENAME EXT" */
    uint8_t  attr;
    uint8_t  nt_reserved;
    uint8_t  create_time_tenths;
    uint16_t create_time;
    uint16_t create_date;
    uint16_t access_date;
    uint16_t first_cluster_hi;     /* High 16 bits (FAT32 only) */
    uint16_t modify_time;
    uint16_t modify_date;
    uint16_t first_cluster_lo;     /* Low 16 bits */
    uint32_t file_size;
} __attribute__((packed));

/* Long filename entry */
struct fat_lfn_entry {
    uint8_t  order;
    uint16_t name1[5];
    uint8_t  attr;                 /* Always 0x0F */
    uint8_t  type;
    uint8_t  checksum;
    uint16_t name2[6];
    uint16_t first_cluster;        /* Always 0 */
    uint16_t name3[2];
} __attribute__((packed));

/* Attributes */
#define FAT_ATTR_READ_ONLY  0x01
#define FAT_ATTR_HIDDEN     0x02
#define FAT_ATTR_SYSTEM     0x04
#define FAT_ATTR_VOLUME_ID  0x08
#define FAT_ATTR_DIRECTORY  0x10
#define FAT_ATTR_ARCHIVE    0x20
#define FAT_ATTR_LFN        0x0F

/* FAT type detection */
#define FAT_TYPE_12  12
#define FAT_TYPE_16  16
#define FAT_TYPE_32  32

/* Cluster chain end markers */
#define FAT12_EOC   0x0FF8
#define FAT16_EOC   0xFFF8
#define FAT32_EOC   0x0FFFFFF8

/* LFN constants */
#define FAT_LFN_MAX          255   /* Maximum long filename characters */
#define FAT_LFN_CHARS_PER    13    /* UCS-2 chars per LFN entry (5+6+2) */
#define FAT_LFN_ORDER_LAST   0x40  /* Bit set in order byte of last LFN entry */
#define FAT_LFN_ORDER_MASK   0x3F  /* Mask to extract sequence number */

/* BPB validation limits */
#define FAT_BPB_SECTOR_MIN   512
#define FAT_BPB_SECTOR_MAX   4096
#define FAT_BPB_SPC_MAX      128   /* Max sectors per cluster */

/* In-memory FAT mount state */
struct fat_mount_info {
    struct fut_blockdev *dev;
    uint8_t  fat_type;             /* FAT_TYPE_12/16/32 */
    uint32_t bytes_per_sector;
    uint32_t sectors_per_cluster;
    uint32_t cluster_size;         /* bytes_per_sector * sectors_per_cluster */
    uint32_t reserved_sectors;
    uint32_t num_fats;
    uint32_t fat_size;             /* Sectors per FAT */
    uint32_t root_dir_sectors;     /* FAT12/16: root directory sectors */
    uint32_t first_data_sector;
    uint32_t data_sectors;
    uint32_t total_clusters;
    uint32_t root_cluster;         /* FAT32: root directory cluster */
    uint32_t root_entry_count;     /* FAT12/16: entries in root dir */
    uint32_t total_sectors;
    uint32_t first_root_dir_sector; /* FAT12/16: sector of root dir */
};

void fat_init(void);

#endif /* KERNEL_FAT_H */
