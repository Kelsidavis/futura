/* kernel/exfat.h - exFAT filesystem on-disk structures
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * exFAT (Extended File Allocation Table) for large USB drives and SDXC cards.
 */

#ifndef KERNEL_EXFAT_H
#define KERNEL_EXFAT_H

#include <stdint.h>

/* exFAT Boot Sector */
struct exfat_boot_sector {
    uint8_t  jmp[3];
    char     oem_name[8];           /* Must be "EXFAT   " */
    uint8_t  zeros[53];             /* Must be zero */
    uint64_t partition_offset;
    uint64_t volume_length;         /* Total sectors */
    uint32_t fat_offset;            /* FAT start sector */
    uint32_t fat_length;            /* FAT size in sectors */
    uint32_t cluster_heap_offset;   /* First cluster sector */
    uint32_t cluster_count;
    uint32_t root_dir_cluster;      /* First cluster of root dir */
    uint32_t volume_serial;
    uint16_t fs_revision;
    uint16_t volume_flags;
    uint8_t  bytes_per_sector_shift;  /* log2(bytes_per_sector) */
    uint8_t  sectors_per_cluster_shift; /* log2(sectors_per_cluster) */
    uint8_t  num_fats;
    uint8_t  drive_select;
    uint8_t  percent_in_use;
    uint8_t  reserved[7];
    uint8_t  boot_code[390];
    uint16_t boot_signature;        /* 0xAA55 */
} __attribute__((packed));

/* Directory entry types */
#define EXFAT_ENTRY_EOD         0x00  /* End of directory */
#define EXFAT_ENTRY_ALLOC_BITMAP 0x81
#define EXFAT_ENTRY_UPCASE_TABLE 0x82
#define EXFAT_ENTRY_VOLUME_LABEL 0x83
#define EXFAT_ENTRY_FILE        0x85
#define EXFAT_ENTRY_STREAM_EXT  0xC0
#define EXFAT_ENTRY_FILE_NAME   0xC1

/* File attributes */
#define EXFAT_ATTR_READONLY  0x01
#define EXFAT_ATTR_HIDDEN    0x02
#define EXFAT_ATTR_SYSTEM    0x04
#define EXFAT_ATTR_DIRECTORY 0x10
#define EXFAT_ATTR_ARCHIVE   0x20

/* Generic directory entry (32 bytes) */
struct exfat_dir_entry {
    uint8_t  type;
    uint8_t  data[31];
} __attribute__((packed));

/* File directory entry (type 0x85) */
struct exfat_file_entry {
    uint8_t  type;                  /* 0x85 */
    uint8_t  secondary_count;
    uint16_t set_checksum;
    uint16_t file_attributes;
    uint16_t reserved1;
    uint32_t create_timestamp;
    uint32_t modify_timestamp;
    uint32_t access_timestamp;
    uint8_t  create_10ms;
    uint8_t  modify_10ms;
    uint8_t  create_utc_offset;
    uint8_t  modify_utc_offset;
    uint8_t  access_utc_offset;
    uint8_t  reserved2[7];
} __attribute__((packed));

/* Stream extension entry (type 0xC0) */
struct exfat_stream_entry {
    uint8_t  type;                  /* 0xC0 */
    uint8_t  flags;                 /* bit 0: allocation possible, bit 1: no FAT chain */
    uint8_t  reserved1;
    uint8_t  name_length;           /* Length of filename in chars */
    uint16_t name_hash;
    uint16_t reserved2;
    uint64_t valid_data_length;
    uint32_t reserved3;
    uint32_t first_cluster;
    uint64_t data_length;
} __attribute__((packed));

/* Filename extension entry (type 0xC1) */
struct exfat_name_entry {
    uint8_t  type;                  /* 0xC1 */
    uint8_t  flags;
    uint16_t name[15];              /* UTF-16LE, up to 15 chars per entry */
} __attribute__((packed));

/* In-memory exFAT mount state */
struct exfat_mount_info {
    struct fut_blockdev *dev;
    uint32_t bytes_per_sector;
    uint32_t sectors_per_cluster;
    uint32_t cluster_size;
    uint32_t fat_offset;            /* FAT start sector */
    uint32_t cluster_heap_offset;   /* Data start sector */
    uint32_t cluster_count;
    uint32_t root_cluster;
    uint64_t volume_length;
};

void exfat_init(void);

#endif /* KERNEL_EXFAT_H */
