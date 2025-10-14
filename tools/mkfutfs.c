// SPDX-License-Identifier: MPL-2.0
/*
 * mkfutfs.c - FuturaFS image formatter
 */

#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define FUTFS_LABEL_MAX        64u
#define FUTFS_DEFAULT_BLOCK    512u
#define FUTFS_DEFAULT_SEG_SECT 16u

static size_t align8(size_t value) {
    return (value + 7u) & ~((size_t)7u);
}

typedef struct futfs_extent_disk {
    uint32_t offset;
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

typedef struct futfs_segment_header_disk {
    uint64_t id;
    uint32_t checksum;
    uint32_t inode_count;
    uint64_t next_lba;
} futfs_segment_header_disk_t;

typedef struct futfs_superblock_disk {
    char magic[8];
    uint32_t version;
    uint32_t block_size_legacy;
    uint32_t segment_sectors;
    uint32_t inode_count;
    uint64_t latest_segment_lba;
    uint64_t next_free_lba;
    uint64_t root_ino;
    uint64_t next_inode;
    char label[FUTFS_LABEL_MAX];
    uint32_t version_minor;
    uint32_t reserved0;
    uint64_t features;
    uint64_t block_size;
    uint64_t blocks_total;
    uint64_t blocks_used;
    uint64_t inodes_total;
    uint64_t inodes_used;
    uint64_t dir_tombstones;
    uint8_t reserved[512 - 8 - (8 * sizeof(uint32_t)) - (11 * sizeof(uint64_t)) - FUTFS_LABEL_MAX];
} futfs_superblock_disk_t;

#define FUTFS_SUPER_VERSION_MAJOR 1u
#define FUTFS_SUPER_VERSION_MINOR 1u

#define FUTFS_FEATURE_LOG_STRUCTURED  (1ull << 0)
#define FUTFS_FEATURE_TOMBSTONES      (1ull << 1)
#define FUTFS_FEATURE_DIR_COMPACTION  (1ull << 2)

#define FUTFS_RIGHT_READ   (1u << 0)
#define FUTFS_RIGHT_WRITE  (1u << 1)
#define FUTFS_RIGHT_ADMIN  (1u << 2)
#define FUTFS_INODE_REG    1u
#define FUTFS_INODE_DIR    2u

static uint32_t checksum32(const uint8_t *data, size_t len) {
    uint32_t sum = 0;
    for (size_t i = 0; i < len; ++i) {
        sum += data[i];
    }
    return sum;
}

static void usage(const char *prog) {
    fprintf(stderr,
            "Usage: %s <image> [--segments N] [--segment-sectors N] [--block-size N] [--inodes N] [--label TEXT]\n",
            prog);
}

int main(int argc, char **argv) {
    const char *path = NULL;
    uint32_t segments = 128;
    uint32_t segment_sectors = FUTFS_DEFAULT_SEG_SECT;
    uint32_t block_size = FUTFS_DEFAULT_BLOCK;
    uint64_t inode_hint = 0;
    char label[FUTFS_LABEL_MAX] = "FuturaFS";

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--segments") == 0 && i + 1 < argc) {
            segments = (uint32_t)strtoul(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--segment-sectors") == 0 && i + 1 < argc) {
            segment_sectors = (uint32_t)strtoul(argv[++i], NULL, 10);
            if (segment_sectors == 0) {
                segment_sectors = FUTFS_DEFAULT_SEG_SECT;
            }
        } else if (strcmp(argv[i], "--block-size") == 0 && i + 1 < argc) {
            block_size = (uint32_t)strtoul(argv[++i], NULL, 10);
            if (block_size == 0) {
                block_size = FUTFS_DEFAULT_BLOCK;
            }
        } else if (strcmp(argv[i], "--inodes") == 0 && i + 1 < argc) {
            inode_hint = strtoull(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--label") == 0 && i + 1 < argc) {
            strncpy(label, argv[++i], sizeof(label) - 1);
            label[sizeof(label) - 1] = '\0';
        } else if (!path) {
            path = argv[i];
        } else {
            usage(argv[0]);
            return 1;
        }
    }

    if (!path) {
        usage(argv[0]);
        return 1;
    }

    if (segments == 0) {
        fprintf(stderr, "mkfutfs: --segments must be > 0\n");
        return 1;
    }

    int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    uint64_t total_sectors = 1u + (uint64_t)segments * segment_sectors;
    uint64_t total_bytes = total_sectors * block_size;
    if (ftruncate(fd, (off_t)total_bytes) != 0) {
        perror("ftruncate");
        close(fd);
        return 1;
    }

    futfs_superblock_disk_t super;
    memset(&super, 0, sizeof(super));
    memcpy(super.magic, "FUTFSv0", 7);
    super.version = FUTFS_SUPER_VERSION_MAJOR;
    super.block_size_legacy = block_size;
    super.segment_sectors = segment_sectors;
    super.inode_count = 1;
    super.latest_segment_lba = 1;
    super.next_free_lba = 1 + segment_sectors;
    super.root_ino = 1;
    super.next_inode = 2;
    size_t label_len = strlen(label);
    if (label_len >= sizeof(super.label)) {
        label_len = sizeof(super.label) - 1;
    }
    memcpy(super.label, label, label_len);
    super.version_minor = FUTFS_SUPER_VERSION_MINOR;
    super.features = FUTFS_FEATURE_LOG_STRUCTURED |
                     FUTFS_FEATURE_TOMBSTONES |
                     FUTFS_FEATURE_DIR_COMPACTION;
    super.block_size = block_size;
    super.blocks_total = (uint64_t)segments * segment_sectors;
    super.blocks_used = 0;
    super.inodes_total = inode_hint ? inode_hint : 1;
    if (super.inodes_total < 1) {
        super.inodes_total = 1;
    }
    super.inodes_used = 1;
    super.dir_tombstones = 0;

    if (pwrite(fd, &super, sizeof(super), 0) != (ssize_t)sizeof(super)) {
        perror("pwrite superblock");
        close(fd);
        return 1;
    }

    size_t seg_bytes = (size_t)segment_sectors * block_size;
    uint8_t *segment = calloc(1, seg_bytes);
    if (!segment) {
        perror("calloc segment");
        close(fd);
        return 1;
    }

    futfs_segment_header_disk_t *header = (futfs_segment_header_disk_t *)segment;
    header->id = 1;
    header->inode_count = 1;
    header->next_lba = super.next_free_lba;

    uint8_t *cursor = segment + sizeof(*header);
    futfs_inode_disk_fixed_t root_fixed = {
        .ino = 1,
        .type = FUTFS_INODE_DIR,
        .rights = FUTFS_RIGHT_READ | FUTFS_RIGHT_WRITE | FUTFS_RIGHT_ADMIN,
        .size = 0,
        .dirent_count = 0,
        .extent_count = 0,
    };
    memcpy(cursor, &root_fixed, sizeof(root_fixed));
    cursor += sizeof(root_fixed);
    cursor = segment + align8(cursor - segment);

    header->checksum = checksum32(segment + sizeof(*header), seg_bytes - sizeof(*header));

    ssize_t written = pwrite(fd, segment, seg_bytes, (off_t)block_size);
    free(segment);
    if (written != (ssize_t)seg_bytes) {
        perror("pwrite segment");
        close(fd);
        return 1;
    }

    close(fd);
    printf("mkfutfs: %s block=%u sectors=%u segments=%u inodes_total=%llu label=%s\n",
           path,
           block_size,
           segment_sectors,
           segments,
           (unsigned long long)super.inodes_total,
           super.label);
    return 0;
}
