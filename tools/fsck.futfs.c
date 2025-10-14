// SPDX-License-Identifier: MPL-2.0
/*
 * fsck.futfs.c - Offline consistency checker for FuturaFS images
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
#define FUTFS_NAME_MAX         64u
#define FUTFS_DEFAULT_SEG_SECT 16u

#define FUTFS_SUPER_VERSION_MAJOR 1u
#define FUTFS_SUPER_VERSION_MINOR 1u

#define FUTFS_FEATURE_LOG_STRUCTURED  (1ull << 0)
#define FUTFS_FEATURE_TOMBSTONES      (1ull << 1)
#define FUTFS_FEATURE_DIR_COMPACTION  (1ull << 2)

#define FUTFS_INODE_REG 1u
#define FUTFS_INODE_DIR 2u

struct futfs_extent_disk {
    uint32_t offset;
    uint32_t length;
} __attribute__((packed));

struct futfs_inode_disk_fixed {
    uint64_t ino;
    uint32_t type;
    uint32_t rights;
    uint64_t size;
    uint32_t dirent_count;
    uint32_t extent_count;
} __attribute__((packed));

struct futfs_dirent_disk {
    uint64_t ino;
    uint16_t name_len;
    uint16_t reserved;
    char name[];
} __attribute__((packed));

struct futfs_segment_header_disk {
    uint64_t id;
    uint32_t checksum;
    uint32_t inode_count;
    uint64_t next_lba;
} __attribute__((packed));

struct futfs_superblock_disk {
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
} __attribute__((packed));

static size_t align8(size_t value) {
    return (value + 7u) & ~((size_t)7u);
}

struct options {
    const char *device;
    bool dry_run;
    bool repair;
    bool verbose;
    bool gc;
};

struct dir_entry_info {
    char name[FUTFS_NAME_MAX + 1];
    uint16_t name_len;
    uint64_t ino;
    bool tombstone;
    bool malformed;
    size_t order;
};

struct dir_info {
    struct dir_entry_info *entries;
    size_t entry_count;
    size_t tombstones;
    bool malformed;
    bool needs_rewrite;
    uint8_t *rewrite_data;
    size_t rewrite_size;
};

struct inode_info {
    struct futfs_inode_disk_fixed fixed;
    uint8_t *data;
    size_t data_len;
    bool is_dir;
    bool modified;
    struct dir_info dir;
};

struct fsck_report {
    size_t inode_count;
    size_t dir_count;
    size_t dirent_errors;
    size_t extent_errors;
    size_t unreachable_inodes;
    size_t repaired_dirs;
    uint64_t tombstones;
    uint64_t blocks_used;
};

static void usage(const char *prog) {
    fprintf(stderr,
            "Usage: %s --device <image> [--dry-run] [--repair] [--verbose] [--gc]\n",
            prog);
}

static bool parse_args(int argc, char **argv, struct options *opts) {
    memset(opts, 0, sizeof(*opts));
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--device") == 0 && i + 1 < argc) {
            opts->device = argv[++i];
        } else if (strcmp(argv[i], "--dry-run") == 0) {
            opts->dry_run = true;
        } else if (strcmp(argv[i], "--repair") == 0) {
            opts->repair = true;
        } else if (strcmp(argv[i], "--verbose") == 0) {
            opts->verbose = true;
        } else if (strcmp(argv[i], "--gc") == 0) {
            opts->gc = true;
        } else {
            return false;
        }
    }
    if (!opts->device) {
        return false;
    }
    return true;
}

static ssize_t read_exact(int fd, void *buf, size_t len, off_t offset) {
    ssize_t rd = pread(fd, buf, len, offset);
    return rd;
}

static ssize_t write_exact(int fd, const void *buf, size_t len, off_t offset) {
    ssize_t wr = pwrite(fd, buf, len, offset);
    return wr;
}

static uint32_t checksum32(const uint8_t *data, size_t len) {
    uint32_t sum = 0;
    for (size_t i = 0; i < len; ++i) {
        sum += data[i];
    }
    return sum;
}

static bool is_dot_entry(const struct dir_entry_info *e) {
    if (!e) {
        return false;
    }
    if (e->name_len == 1 && e->name[0] == '.') {
        return true;
    }
    if (e->name_len == 2 && e->name[0] == '.' && e->name[1] == '.') {
        return true;
    }
    return false;
}

static void dir_info_free(struct dir_info *dir) {
    if (!dir) {
        return;
    }
    free(dir->entries);
    dir->entries = NULL;
    dir->entry_count = 0;
    if (dir->rewrite_data) {
        free(dir->rewrite_data);
        dir->rewrite_data = NULL;
    }
    dir->rewrite_size = 0;
}

static void inode_info_cleanup(struct inode_info *inos, size_t count) {
    if (!inos) {
        return;
    }
    for (size_t i = 0; i < count; ++i) {
        dir_info_free(&inos[i].dir);
    }
    free(inos);
}

static uint64_t blocks_for_size(uint64_t size, uint64_t block_size) {
    if (size == 0 || block_size == 0) {
        return 0;
    }
    return (size + block_size - 1u) / block_size;
}

static int compare_range(const void *lhs, const void *rhs) {
    const uint64_t *a = lhs;
    const uint64_t *b = rhs;
    if (a[0] < b[0]) {
        return -1;
    }
    if (a[0] > b[0]) {
        return 1;
    }
    return 0;
}

static int fsck_main(struct options *opts) {
    int fd = open(opts->device, opts->repair ? O_RDWR : O_RDONLY);
    if (fd < 0) {
        perror("open");
        return 2;
    }

    struct stat st;
    if (fstat(fd, &st) != 0) {
        perror("fstat");
        close(fd);
        return 2;
    }

    struct futfs_superblock_disk super;
    ssize_t rd = read_exact(fd, &super, sizeof(super), 0);
    if (rd != (ssize_t)sizeof(super)) {
        fprintf(stderr, "fsck.futfs: failed to read superblock\n");
        close(fd);
        return 2;
    }

    int status = 0;

    if (memcmp(super.magic, "FUTFSv0", 7) != 0) {
        fprintf(stderr, "fsck.futfs: invalid magic\n");
        close(fd);
        return 2;
    }

    uint64_t block_size = super.block_size ? super.block_size : super.block_size_legacy;
    if (block_size == 0) {
        block_size = 512;
    }

    uint32_t seg_sectors = super.segment_sectors ? super.segment_sectors : FUTFS_DEFAULT_SEG_SECT;
    uint64_t seg_bytes = block_size * (uint64_t)seg_sectors;
    if (seg_bytes == 0) {
        fprintf(stderr, "fsck.futfs: bad segment geometry\n");
        close(fd);
        return 2;
    }

    uint64_t device_blocks = block_size ? ((uint64_t)st.st_size / block_size) : 0;
    uint64_t data_blocks_total = super.blocks_total ? super.blocks_total
                                                    : (device_blocks > 1 ? device_blocks - 1 : device_blocks);

    uint64_t segment_lba = super.latest_segment_lba ? super.latest_segment_lba : 1;
    uint64_t segment_offset = segment_lba * block_size;
    if (segment_offset + seg_bytes > (uint64_t)st.st_size) {
        fprintf(stderr, "fsck.futfs: segment exceeds image size\n");
        close(fd);
        return 2;
    }

    uint8_t *segment = calloc(1, seg_bytes);
    if (!segment) {
        perror("calloc segment");
        close(fd);
        return 2;
    }

    rd = read_exact(fd, segment, seg_bytes, (off_t)segment_offset);
    if (rd != (ssize_t)seg_bytes) {
        fprintf(stderr, "fsck.futfs: failed to read segment\n");
        free(segment);
        close(fd);
        return 2;
    }

    const struct futfs_segment_header_disk *header = (const struct futfs_segment_header_disk *)segment;
    if (header->inode_count != super.inode_count) {
        fprintf(stderr, "fsck.futfs: inode count mismatch (segment=%u super=%u)\n",
                header->inode_count, super.inode_count);
        status = 1;
    }

    uint32_t header_checksum = checksum32(segment + sizeof(*header), seg_bytes - sizeof(*header));
    if (header_checksum != header->checksum) {
        fprintf(stderr, "fsck.futfs: checksum mismatch (expected %u got %u)\n",
                header_checksum, header->checksum);
        status = 1;
    }

    size_t inode_capacity = header->inode_count;
    if (inode_capacity == 0) {
        inode_capacity = 1;
    }
    struct inode_info *inodes = calloc(inode_capacity, sizeof(*inodes));
    if (!inodes) {
        perror("calloc inodes");
        free(segment);
        close(fd);
        return 2;
    }

    const uint8_t *cursor = segment + sizeof(*header);
    const uint8_t *segment_end = segment + seg_bytes;

    struct fsck_report report = {0};
    size_t actual_inodes = 0;
    bool extent_overlap_error = false;

    uint64_t (*ranges)[2] = calloc(header->inode_count ? header->inode_count : 1, sizeof(uint64_t[2]));
    size_t range_count = 0;

    for (uint32_t i = 0; i < header->inode_count; ++i) {
        if (cursor + sizeof(struct futfs_inode_disk_fixed) > segment_end) {
            fprintf(stderr, "fsck.futfs: truncated inode table\n");
            status = 1;
            break;
        }
        struct inode_info *info = &inodes[i];
        memcpy(&info->fixed, cursor, sizeof(info->fixed));
        cursor += sizeof(info->fixed);

        if (info->fixed.extent_count > 1) {
            fprintf(stderr, "fsck.futfs: inode %llu has unexpected extent count %u\n",
                    (unsigned long long)info->fixed.ino,
                    info->fixed.extent_count);
            status = 1;
        }

        struct futfs_extent_disk extent = {0};
        if (info->fixed.extent_count > 0) {
            if (cursor + sizeof(extent) > segment_end) {
                fprintf(stderr, "fsck.futfs: extent truncated for inode %llu\n",
                        (unsigned long long)info->fixed.ino);
                status = 1;
                break;
            }
            memcpy(&extent, cursor, sizeof(extent));
            cursor += sizeof(extent);
        }

        size_t consumed = cursor - segment;
        cursor = segment + align8(consumed);

        info->is_dir = (info->fixed.type == FUTFS_INODE_DIR);

        if (info->fixed.extent_count > 0) {
            if ((uint64_t)extent.offset + extent.length > seg_bytes) {
                fprintf(stderr, "fsck.futfs: extent out of range for inode %llu\n",
                        (unsigned long long)info->fixed.ino);
                status = 1;
                continue;
            }
            info->data = segment + extent.offset;
            info->data_len = extent.length;
            if (info->data_len != info->fixed.size) {
                fprintf(stderr, "fsck.futfs: inode %llu size mismatch (fixed=%llu extent=%u)\n",
                        (unsigned long long)info->fixed.ino,
                        (unsigned long long)info->fixed.size,
                        extent.length);
                status = 1;
            }
            if (ranges && range_count < header->inode_count) {
                ranges[range_count][0] = extent.offset;
                ranges[range_count][1] = extent.offset + extent.length;
                range_count++;
            }
        }

        if (info->is_dir && info->data && info->data_len > 0) {
            size_t offset = 0;
            size_t order = 0;
            struct dir_info *dir = &info->dir;
            while (offset + sizeof(struct futfs_dirent_disk) <= info->data_len) {
                const struct futfs_dirent_disk *dent =
                    (const struct futfs_dirent_disk *)(info->data + offset);
                size_t entry_bytes = sizeof(struct futfs_dirent_disk) + dent->name_len;
                size_t padded = align8(entry_bytes);
                if (offset + padded > info->data_len) {
                    dir->malformed = true;
                    report.dirent_errors++;
                    break;
                }

                struct dir_entry_info entry;
                memset(&entry, 0, sizeof(entry));
                entry.name_len = dent->name_len;
                if (entry.name_len > FUTFS_NAME_MAX) {
                    entry.name_len = FUTFS_NAME_MAX;
                    entry.malformed = true;
                }
                memcpy(entry.name, dent->name, entry.name_len);
                entry.name[entry.name_len] = '\0';
                entry.ino = dent->ino;
                entry.tombstone = (dent->ino == 0);
                entry.order = order++;
                if (entry.name_len == 0 && !entry.tombstone) {
                    entry.malformed = true;
                }
                if (entry.malformed) {
                    dir->malformed = true;
                    report.dirent_errors++;
                }

                struct dir_entry_info *new_entries = realloc(dir->entries, (dir->entry_count + 1) * sizeof(*dir->entries));
                if (!new_entries) {
                    perror("realloc dir entries");
                    inode_info_cleanup(inodes, inode_capacity);
                    free(segment);
                    close(fd);
                    return 2;
                }
                dir->entries = new_entries;
                dir->entries[dir->entry_count++] = entry;
                if (entry.tombstone) {
                    dir->tombstones++;
                }

                offset += padded;
            }
        }

        actual_inodes++;
        if (info->is_dir) {
            report.dir_count++;
        }
    }

    if (ranges && range_count > 1) {
        qsort(ranges, range_count, sizeof(uint64_t[2]), compare_range);
        for (size_t i = 1; i < range_count; ++i) {
            if (ranges[i][0] < ranges[i - 1][1]) {
                extent_overlap_error = true;
                break;
            }
        }
    }

    if (extent_overlap_error) {
        fprintf(stderr, "fsck.futfs: overlapping extents detected\n");
        report.extent_errors++;
        status = 1;
    }

    free(ranges);

    uint64_t max_ino = super.next_inode ? super.next_inode - 1 : actual_inodes;
    bool *reachable = calloc(max_ino + 1, sizeof(bool));
    if (!reachable) {
        perror("calloc reachable");
        inode_info_cleanup(inodes, inode_capacity);
        free(segment);
        close(fd);
        return 2;
    }
    if (max_ino >= 1) {
        reachable[1] = true; /* root */
    }

    bool repaired_any = false;
    for (size_t i = 0; i < actual_inodes; ++i) {
        struct inode_info *info = &inodes[i];
        if (!info->is_dir || !info->data) {
            continue;
        }
        struct dir_info *dir = &info->dir;
        for (size_t j = 0; j < dir->entry_count; ++j) {
            struct dir_entry_info *entry = &dir->entries[j];
            if (entry->tombstone || entry->malformed || is_dot_entry(entry)) {
                continue;
            }
            if (entry->ino <= max_ino) {
                reachable[entry->ino] = true;
            }
        }
    }

    for (size_t i = 0; i < actual_inodes; ++i) {
        uint64_t ino = inodes[i].fixed.ino;
        if (ino == 0 || ino > max_ino) {
            continue;
        }
        if (!reachable[ino]) {
            report.unreachable_inodes++;
            status = 1;
            if (opts->verbose) {
                fprintf(stderr, "fsck.futfs: unreachable inode %llu\n",
                        (unsigned long long)ino);
            }
        }
    }

    free(reachable);

    uint64_t highwater = super.next_inode ? super.next_inode - 1 : actual_inodes;
    if (highwater < actual_inodes) {
        highwater = actual_inodes;
    }

    /* Decide whether to rewrite directories (malformed or GC request) */
    for (size_t i = 0; i < actual_inodes; ++i) {
        struct inode_info *info = &inodes[i];
        if (!info->is_dir || !info->data) {
            continue;
        }
        struct dir_info *dir = &info->dir;
        if (dir->entry_count == 0) {
            continue;
        }
        bool rewrite = dir->malformed;
        size_t live_entries = 0;
        for (size_t j = 0; j < dir->entry_count; ++j) {
            struct dir_entry_info *entry = &dir->entries[j];
            if (!entry->tombstone && !entry->malformed) {
                live_entries++;
            }
        }
        if (!rewrite && opts->gc) {
            if (dir->tombstones > live_entries) {
                rewrite = true;
            }
        }

        if (!rewrite) {
            continue;
        }

        /* Build latest mapping */
        for (size_t j = 0; j < dir->entry_count; ++j) {
            struct dir_entry_info *entry = &dir->entries[j];
            if (entry->tombstone) {
                continue;
            }
            if (entry->name_len == 0) {
                entry->malformed = true;
            }
        }

        /* Reconstruct directory stream */
        uint8_t *new_stream = NULL;
        size_t new_size = 0;
        for (size_t j = 0; j < dir->entry_count; ++j) {
            struct dir_entry_info *entry = &dir->entries[j];
            bool latest = true;
            for (size_t k = j + 1; k < dir->entry_count; ++k) {
                struct dir_entry_info *future = &dir->entries[k];
                if (future->name_len == entry->name_len &&
                    memcmp(future->name, entry->name, entry->name_len) == 0) {
                    latest = false;
                    break;
                }
            }
            if (!latest) {
                continue;
            }
            if (entry->tombstone || entry->malformed || is_dot_entry(entry)) {
                continue;
            }
            size_t rec_len = sizeof(struct futfs_dirent_disk) + entry->name_len;
            size_t padded = align8(rec_len);
            uint8_t *resized = realloc(new_stream, new_size + padded);
            if (!resized) {
                perror("realloc compact dir");
                free(new_stream);
                inode_info_cleanup(inodes, inode_capacity);
                free(segment);
                close(fd);
                return 2;
            }
            new_stream = resized;
            struct futfs_dirent_disk *disk = (struct futfs_dirent_disk *)(new_stream + new_size);
            disk->ino = entry->ino;
            disk->name_len = entry->name_len;
            disk->reserved = 0;
            memcpy(disk->name, entry->name, entry->name_len);
            size_t pad = padded - rec_len;
            if (pad > 0) {
                memset((uint8_t *)disk + rec_len, 0, pad);
            }
            new_size += padded;
        }

        if (new_stream) {
            dir->rewrite_data = new_stream;
            dir->rewrite_size = new_size;
            info->data = new_stream;
            info->data_len = new_size;
            info->fixed.size = new_size;
            info->modified = true;
            dir->needs_rewrite = true;
            report.repaired_dirs++;
            repaired_any = true;
        }
    }

    /* Aggregate statistics */
    for (size_t i = 0; i < actual_inodes; ++i) {
        struct inode_info *info = &inodes[i];
        report.blocks_used += blocks_for_size(info->data_len, block_size);
        if (info->is_dir) {
            report.tombstones += info->dir.tombstones;
        }
    }

    bool wrote_segment = false;

    if (opts->repair) {
        bool any_changes = false;
        for (size_t i = 0; i < actual_inodes; ++i) {
            if (inodes[i].modified) {
                any_changes = true;
                break;
            }
        }
        if (any_changes && !opts->dry_run) {
            size_t seg_bytes_sz = seg_bytes;
            uint8_t *out_segment = calloc(1, seg_bytes_sz);
            if (!out_segment) {
                perror("calloc out_segment");
                inode_info_cleanup(inodes, inode_capacity);
                free(segment);
                close(fd);
                return 2;
            }

            struct futfs_segment_header_disk *out_header = (struct futfs_segment_header_disk *)out_segment;
            out_header->id = header->id + 1;
            out_header->inode_count = header->inode_count;
            out_header->next_lba = super.next_free_lba;

            size_t meta_cursor = sizeof(*out_header);
            size_t data_cursor = meta_cursor;
            struct futfs_extent_disk extent = {0};

            for (size_t i = 0; i < actual_inodes; ++i) {
                struct inode_info *info = &inodes[i];
                data_cursor = align8(data_cursor);
                extent.offset = (uint32_t)data_cursor;
                extent.length = (uint32_t)info->data_len;

                struct futfs_inode_disk_fixed fixed = info->fixed;
                fixed.size = info->data_len;
                fixed.extent_count = (info->data_len > 0) ? 1 : 0;

                if (meta_cursor + sizeof(fixed) > seg_bytes_sz) {
                    fprintf(stderr, "fsck.futfs: insufficient segment space during repair\n");
                    free(out_segment);
                    inode_info_cleanup(inodes, inode_capacity);
                    free(segment);
                    close(fd);
                    return 2;
                }
                memcpy(out_segment + meta_cursor, &fixed, sizeof(fixed));
                meta_cursor += sizeof(fixed);

                if (fixed.extent_count > 0) {
                    if (meta_cursor + sizeof(extent) > seg_bytes_sz) {
                        fprintf(stderr, "fsck.futfs: insufficient segment space writing extent\n");
                        free(out_segment);
                        inode_info_cleanup(inodes, inode_capacity);
                        free(segment);
                        close(fd);
                        return 2;
                    }
                    memcpy(out_segment + meta_cursor, &extent, sizeof(extent));
                    meta_cursor += sizeof(extent);
                }

                meta_cursor = align8(meta_cursor);

                if (info->data_len > 0) {
                    if (extent.offset + extent.length > seg_bytes_sz) {
                        fprintf(stderr, "fsck.futfs: extent overflow while rewriting\n");
                        free(out_segment);
                        inode_info_cleanup(inodes, inode_capacity);
                        free(segment);
                        close(fd);
                        return 2;
                    }
                    memcpy(out_segment + extent.offset, info->data, info->data_len);
                    data_cursor = extent.offset + extent.length;
                }
            }

            out_header->checksum = checksum32(out_segment + sizeof(*out_header), seg_bytes_sz - sizeof(*out_header));

            if (write_exact(fd, out_segment, seg_bytes_sz, (off_t)segment_offset) != (ssize_t)seg_bytes_sz) {
                perror("pwrite segment");
                free(out_segment);
                inode_info_cleanup(inodes, inode_capacity);
                free(segment);
                close(fd);
                return 2;
            }
            wrote_segment = true;
            free(out_segment);
        }

        /* Update superblock */
        struct futfs_superblock_disk new_super = super;
        if (wrote_segment && !opts->dry_run) {
            new_super.version = super.version + 1;
            new_super.latest_segment_lba = segment_lba;
        }
        new_super.version_minor = FUTFS_SUPER_VERSION_MINOR;
        new_super.features = FUTFS_FEATURE_LOG_STRUCTURED |
                             FUTFS_FEATURE_TOMBSTONES |
                             FUTFS_FEATURE_DIR_COMPACTION;
        new_super.block_size = block_size;
        new_super.block_size_legacy = block_size;
        new_super.blocks_total = data_blocks_total;
        new_super.blocks_used = report.blocks_used;
        new_super.inodes_total = highwater;
        new_super.inodes_used = actual_inodes;
        new_super.inode_count = actual_inodes;
        new_super.dir_tombstones = report.tombstones;

        if (!opts->dry_run) {
            if (write_exact(fd, &new_super, sizeof(new_super), 0) != (ssize_t)sizeof(new_super)) {
                perror("pwrite superblock");
                inode_info_cleanup(inodes, inode_capacity);
                free(segment);
                close(fd);
                return 2;
            }
        }
        super = new_super;
        if (!opts->dry_run && (repaired_any || status == 0) &&
            !extent_overlap_error && report.unreachable_inodes == 0) {
            status = 0;
        }
    }

    printf("fsck.futfs: inodes=%zu dirs=%zu unreachable=%zu dirent_errors=%zu extents=%zu tombstones=%llu\n",
           actual_inodes,
           report.dir_count,
           report.unreachable_inodes,
           report.dirent_errors,
           report.extent_errors,
           (unsigned long long)report.tombstones);

    inode_info_cleanup(inodes, inode_capacity);
    free(segment);
    close(fd);
    return status;
}

int main(int argc, char **argv) {
    struct options opts;
    if (!parse_args(argc, argv, &opts)) {
        usage(argv[0]);
        return 2;
    }
    return fsck_main(&opts);
}
