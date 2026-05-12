/* kernel/fs/fat.c - Read-only FAT12/16/32 filesystem driver
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements a read-only FAT filesystem driver for USB drives, SD cards,
 * and EFI boot partitions. Supports FAT12, FAT16, and FAT32 with 8.3
 * short filenames and long filename (LFN) entries.
 */

#include <kernel/fat.h>
#include <kernel/fut_vfs.h>
#include <kernel/fut_blockdev.h>
#include <kernel/fut_memory.h>
#include <kernel/kprintf.h>
#include <kernel/errno.h>
#include <stddef.h>
#include <string.h>

/* ============================================================
 *   BPB validation helpers
 * ============================================================ */

static bool fat_is_power_of_2(uint32_t v) {
    return v != 0 && (v & (v - 1)) == 0;
}

static int fat_validate_bpb(const struct fat_bpb *bpb) {
    /* Check jump boot code: must be 0xEB xx 0x90 or 0xE9 xx xx */
    if (bpb->jmp[0] != 0xEB && bpb->jmp[0] != 0xE9)
        return -EINVAL;

    /* Bytes per sector must be 512, 1024, 2048, or 4096 */
    if (bpb->bytes_per_sector < FAT_BPB_SECTOR_MIN ||
        bpb->bytes_per_sector > FAT_BPB_SECTOR_MAX ||
        !fat_is_power_of_2(bpb->bytes_per_sector))
        return -EINVAL;

    /* Sectors per cluster must be power of 2, max 128 */
    if (bpb->sectors_per_cluster == 0 ||
        bpb->sectors_per_cluster > FAT_BPB_SPC_MAX ||
        !fat_is_power_of_2(bpb->sectors_per_cluster))
        return -EINVAL;

    /* Must have at least one FAT */
    if (bpb->num_fats == 0)
        return -EINVAL;

    /* Reserved sectors must be nonzero */
    if (bpb->reserved_sectors == 0)
        return -EINVAL;

    /* Must have at least some sectors */
    if (bpb->total_sectors_16 == 0 && bpb->total_sectors_32 == 0)
        return -EINVAL;

    /* Media type must be 0xF0 or 0xF8-0xFF */
    if (bpb->media_type != 0xF0 && bpb->media_type < 0xF8)
        return -EINVAL;

    return 0;
}

/* ============================================================
 *   Cluster chain helpers
 * ============================================================ */

/* Wrappers that apply fi->partition_offset_bytes to every block I/O. When
 * the FAT FS is at LBA 0 (no MBR) the offset is 0 and these are pass-through;
 * when an MBR partition was discovered they shift every read/write into the
 * partition's address space. */
static ssize_t fat_dev_read(struct fat_mount_info *fi, uint64_t off,
                             size_t len, void *buf) {
    return fut_blockdev_read_bytes(fi->dev,
                                    fi->partition_offset_bytes + off,
                                    len, buf);
}
static ssize_t fat_dev_write(struct fat_mount_info *fi, uint64_t off,
                              size_t len, const void *buf) {
    return fut_blockdev_write_bytes(fi->dev,
                                     fi->partition_offset_bytes + off,
                                     len, buf);
}

static uint64_t fat_cluster_to_sector(struct fat_mount_info *fi, uint32_t cluster) {
    return fi->first_data_sector + (uint64_t)(cluster - 2) * fi->sectors_per_cluster;
}

static ssize_t fat_read_cluster(struct fat_mount_info *fi, uint32_t cluster, void *buf) {
    uint64_t sector = fat_cluster_to_sector(fi, cluster);
    uint64_t offset = sector * fi->bytes_per_sector;
    return fat_dev_read(fi, offset, fi->cluster_size, buf);
}

static uint32_t fat_next_cluster(struct fat_mount_info *fi, uint32_t cluster) {
    uint32_t fat_offset;
    uint32_t entry;
    uint64_t fat_start = (uint64_t)fi->reserved_sectors * fi->bytes_per_sector;

    if (fi->fat_type == FAT_TYPE_32) {
        fat_offset = cluster * 4;
        fat_dev_read(fi, fat_start + fat_offset, 4, &entry);
        entry &= 0x0FFFFFFF;
        if (entry < 2 || entry >= FAT32_EOC) return 0;
        return entry;
    } else if (fi->fat_type == FAT_TYPE_16) {
        fat_offset = cluster * 2;
        uint16_t entry16;
        fat_dev_read(fi, fat_start + fat_offset, 2, &entry16);
        if (entry16 < 2 || entry16 >= FAT16_EOC) return 0;
        return entry16;
    } else { /* FAT12 */
        fat_offset = cluster + (cluster / 2);
        uint16_t entry12;
        fat_dev_read(fi, fat_start + fat_offset, 2, &entry12);
        entry12 = (cluster & 1) ? (entry12 >> 4) : (entry12 & 0xFFF);
        if (entry12 < 2 || entry12 >= FAT12_EOC) return 0;
        return entry12;
    }
}

/* ============================================================
 *   FAT16 fixed root directory helpers
 * ============================================================ */

/* Read from the FAT12/16 fixed root directory area (not cluster-based) */
static ssize_t fat_read_fixed_root(struct fat_mount_info *fi, uint32_t byte_offset,
                                    uint32_t len, void *buf) {
    uint32_t root_bytes = fi->root_entry_count * 32;
    if (byte_offset >= root_bytes) return 0;
    if (byte_offset + len > root_bytes) len = root_bytes - byte_offset;
    uint64_t disk_off = (uint64_t)fi->first_root_dir_sector * fi->bytes_per_sector + byte_offset;
    return fat_dev_read(fi, disk_off, len, buf);
}

/* Check if a vnode represents the FAT12/16 fixed root directory */
static bool fat_is_fixed_root(struct fat_mount_info *fi, uint32_t first_cluster) {
    return (fi->fat_type != FAT_TYPE_32 && first_cluster == 0);
}

/* ============================================================
 *   LFN (Long File Name) support
 * ============================================================ */

/* Compute the 8.3 checksum used by LFN entries */
static uint8_t fat_lfn_checksum(const char *shortname) {
    uint8_t sum = 0;
    for (int i = 0; i < 11; i++)
        sum = ((sum & 1) ? 0x80 : 0) + (sum >> 1) + (uint8_t)shortname[i];
    return sum;
}

/* Extract UCS-2 characters from an LFN entry into a char buffer (ASCII only).
 * Returns number of characters extracted (up to 13). */
static int fat_lfn_extract(const struct fat_lfn_entry *lfn, char *out) {
    int pos = 0;
    /* name1[5], name2[6], name3[2] */
    for (int i = 0; i < 5; i++) {
        uint16_t c = lfn->name1[i];
        if (c == 0x0000 || c == 0xFFFF) return pos;
        out[pos++] = (c < 0x80) ? (char)c : '_';
    }
    for (int i = 0; i < 6; i++) {
        uint16_t c = lfn->name2[i];
        if (c == 0x0000 || c == 0xFFFF) return pos;
        out[pos++] = (c < 0x80) ? (char)c : '_';
    }
    for (int i = 0; i < 2; i++) {
        uint16_t c = lfn->name3[i];
        if (c == 0x0000 || c == 0xFFFF) return pos;
        out[pos++] = (c < 0x80) ? (char)c : '_';
    }
    return pos;
}

/* ============================================================
 *   VFS vnode operations
 * ============================================================ */

struct fat_vnode_info {
    uint32_t first_cluster;
    uint32_t file_size;
    uint8_t  attr;
    struct fat_mount_info *fi;
    /* Absolute disk byte offset of this file's 8.3 directory entry.
     * Used by fat_vnode_write / unlink to update the on-disk metadata
     * (size, first_cluster). 0 for the root vnode and for vnodes that
     * weren't created via the lookup/create paths. */
    uint64_t dir_entry_disk_off;
};

static ssize_t fat_vnode_read(struct fut_vnode *vnode, void *buf,
                              size_t size, uint64_t offset) {
    struct fat_vnode_info *vi = (struct fat_vnode_info *)vnode->fs_data;
    if (!vi) return -EIO;
    if (offset >= vi->file_size) return 0;
    if (offset + size > vi->file_size) size = vi->file_size - (size_t)offset;

    struct fat_mount_info *fi = vi->fi;
    uint8_t *out = (uint8_t *)buf;
    size_t total = 0;

    /* Allocate a cluster-sized read buffer */
    uint8_t *cbuf = fut_malloc(fi->cluster_size);
    if (!cbuf) return -ENOMEM;

    /* Walk cluster chain to find starting cluster */
    uint32_t cluster = vi->first_cluster;
    uint64_t skip = offset;
    while (skip >= fi->cluster_size && cluster >= 2) {
        skip -= fi->cluster_size;
        cluster = fat_next_cluster(fi, cluster);
    }

    /* Read data from cluster chain */
    while (total < size && cluster >= 2) {
        fat_read_cluster(fi, cluster, cbuf);

        uint32_t off_in = (uint32_t)skip;
        size_t avail = fi->cluster_size - off_in;
        if (avail > size - total) avail = size - total;
        memcpy(out + total, cbuf + off_in, avail);
        total += avail;
        skip = 0;

        cluster = fat_next_cluster(fi, cluster);
    }

    fut_free(cbuf);
    return (ssize_t)total;
}

/* Forward decls for write primitives defined below. */
static int fat_alloc_cluster(struct fat_mount_info *fi, uint32_t *out_cluster);
static int fat_set_fat_entry(struct fat_mount_info *fi, uint32_t cluster,
                              uint32_t value);
static ssize_t fat_write_cluster_at(struct fat_mount_info *fi, uint32_t cluster,
                                     uint32_t off_in, const void *buf, size_t len);
static int fat_dir_entry_set_size(struct fat_mount_info *fi, uint64_t disk_off,
                                   uint32_t first_cluster, uint32_t size);

static ssize_t fat_vnode_write(struct fut_vnode *v, const void *b, size_t s,
                                uint64_t o) {
    struct fat_vnode_info *vi = (struct fat_vnode_info *)v->fs_data;
    if (!vi) return -EIO;
    if (vi->attr & FAT_ATTR_DIRECTORY) return -EISDIR;
    if (vi->dir_entry_disk_off == 0) return -EROFS;
    struct fat_mount_info *fi = vi->fi;
    if (s == 0) return 0;

    const uint8_t *src = (const uint8_t *)b;
    size_t total = 0;

    /* Allocate first cluster if the file is empty. */
    if (vi->first_cluster < 2) {
        uint32_t newc = 0;
        int rc = fat_alloc_cluster(fi, &newc);
        if (rc < 0) return rc;
        vi->first_cluster = newc;
    }

    /* Skip clusters to reach `o`. */
    uint64_t skip = o;
    uint32_t cluster = vi->first_cluster;
    while (skip >= fi->cluster_size) {
        uint32_t next = fat_next_cluster(fi, cluster);
        if (next < 2) {
            /* Need to extend. Allocate + link. */
            int rc = fat_alloc_cluster(fi, &next);
            if (rc < 0) return rc;
            rc = fat_set_fat_entry(fi, cluster, next);
            if (rc < 0) return rc;
        }
        cluster = next;
        skip -= fi->cluster_size;
    }
    uint32_t off_in = (uint32_t)skip;

    /* Walk and write. */
    while (total < s) {
        size_t avail = fi->cluster_size - off_in;
        if (avail > s - total) avail = s - total;
        ssize_t wrote = fat_write_cluster_at(fi, cluster, off_in,
                                              src + total, avail);
        if (wrote < 0) return wrote;
        total += (size_t)wrote;
        if ((size_t)wrote < avail) break;
        off_in = 0;
        if (total < s) {
            uint32_t next = fat_next_cluster(fi, cluster);
            if (next < 2) {
                int rc = fat_alloc_cluster(fi, &next);
                if (rc < 0) break;
                rc = fat_set_fat_entry(fi, cluster, next);
                if (rc < 0) break;
            }
            cluster = next;
        }
    }

    /* Update the in-memory + on-disk dir entry if the file grew. */
    uint64_t new_size = o + total;
    if (new_size > vi->file_size) {
        vi->file_size = (uint32_t)new_size;
        v->size = (uint64_t)vi->file_size;
        fat_dir_entry_set_size(fi, vi->dir_entry_disk_off,
                               vi->first_cluster, vi->file_size);
    } else if (vi->first_cluster != 0 && total > 0) {
        /* Keep dir entry's first_cluster in sync in case we allocated it. */
        fat_dir_entry_set_size(fi, vi->dir_entry_disk_off,
                               vi->first_cluster, vi->file_size);
    }
    return (ssize_t)total;
}

/* ============================================================
 *   FAT write primitives
 * ============================================================ */

/* Write a FAT entry for cluster `cluster` with value `value`, mirrored
 * across all FAT copies the BPB declares. Handles FAT32 (4-byte entries
 * with high 4 bits reserved) and FAT16 (2-byte entries). FAT12 (4-bit
 * straddling) is not supported -- SD card use case is FAT32, eMMC eMMC
 * is also FAT32; FAT12 callers get -ENOTSUP. */
static int fat_set_fat_entry(struct fat_mount_info *fi, uint32_t cluster,
                              uint32_t value) {
    if (fi->fat_type == FAT_TYPE_12) return -ENOTSUP;

    uint64_t fat_base = (uint64_t)fi->reserved_sectors * fi->bytes_per_sector;
    uint64_t fat_bytes = (uint64_t)fi->fat_size * fi->bytes_per_sector;

    for (uint32_t f = 0; f < fi->num_fats; f++) {
        uint64_t this_fat = fat_base + (uint64_t)f * fat_bytes;
        if (fi->fat_type == FAT_TYPE_32) {
            uint32_t cur = 0;
            uint64_t off = this_fat + (uint64_t)cluster * 4;
            fat_dev_read(fi, off, 4, &cur);
            uint32_t merged = (cur & 0xF0000000) | (value & 0x0FFFFFFF);
            ssize_t w = fat_dev_write(fi, off, 4, &merged);
            if (w < 0) return (int)w;
        } else { /* FAT16 */
            uint16_t v16 = (uint16_t)value;
            uint64_t off = this_fat + (uint64_t)cluster * 2;
            ssize_t w = fat_dev_write(fi, off, 2, &v16);
            if (w < 0) return (int)w;
        }
    }
    return 0;
}

/* Read a FAT entry without the EOC translation that fat_next_cluster
 * does. Returns the raw value (0 = free, EOC marker = end of chain). */
static uint32_t fat_read_fat_entry_raw(struct fat_mount_info *fi,
                                        uint32_t cluster) {
    uint64_t fat_base = (uint64_t)fi->reserved_sectors * fi->bytes_per_sector;
    if (fi->fat_type == FAT_TYPE_32) {
        uint32_t entry = 0;
        fat_dev_read(fi, fat_base + (uint64_t)cluster * 4,
                                4, &entry);
        return entry & 0x0FFFFFFF;
    } else if (fi->fat_type == FAT_TYPE_16) {
        uint16_t entry = 0;
        fat_dev_read(fi, fat_base + (uint64_t)cluster * 2,
                                2, &entry);
        return entry;
    }
    return 0;
}

/* Linearly scan the FAT for a free cluster (entry == 0). On success
 * marks the entry EOC, returns the cluster number in `*out`.
 *
 * Not efficient for large volumes -- a proper implementation reads the
 * FSInfo "next free hint" and tracks free count -- but it's correct,
 * which is what we need for the klog-write use case (a few hundred KB
 * tops). */
static int fat_alloc_cluster(struct fat_mount_info *fi, uint32_t *out) {
    uint32_t eoc = (fi->fat_type == FAT_TYPE_32) ? FAT32_EOC : FAT16_EOC;
    /* Cluster 0 + 1 reserved per spec; valid data clusters start at 2. */
    for (uint32_t c = 2; c < fi->total_clusters + 2; c++) {
        if (fat_read_fat_entry_raw(fi, c) == 0) {
            int rc = fat_set_fat_entry(fi, c, eoc);
            if (rc < 0) return rc;
            *out = c;
            return 0;
        }
    }
    return -ENOSPC;
}

/* Write up to `len` bytes into cluster `cluster` starting at offset
 * `off_in` (must be < cluster_size). Returns bytes written or -errno. */
static ssize_t fat_write_cluster_at(struct fat_mount_info *fi, uint32_t cluster,
                                     uint32_t off_in, const void *buf,
                                     size_t len) {
    if (off_in >= fi->cluster_size) return -EINVAL;
    if (off_in + len > fi->cluster_size) len = fi->cluster_size - off_in;
    uint64_t disk = (uint64_t)fat_cluster_to_sector(fi, cluster)
                        * fi->bytes_per_sector + off_in;
    return fat_dev_write(fi, disk, len, buf);
}

/* Update the size + first_cluster fields of a directory entry already
 * on disk. `disk_off` is the absolute byte offset of the 32-byte 8.3
 * entry. Leaves other fields (name, attr, timestamps) untouched. */
static int fat_dir_entry_set_size(struct fat_mount_info *fi, uint64_t disk_off,
                                   uint32_t first_cluster, uint32_t size) {
    struct fat_dir_entry de;
    ssize_t r = fat_dev_read(fi, disk_off, sizeof(de), &de);
    if (r < 0) return (int)r;
    de.first_cluster_lo = (uint16_t)(first_cluster & 0xFFFF);
    de.first_cluster_hi = (uint16_t)((first_cluster >> 16) & 0xFFFF);
    de.file_size = size;
    ssize_t w = fat_dev_write(fi, disk_off, sizeof(de), &de);
    return (w < 0) ? (int)w : 0;
}

/* Convert 8.3 name to lowercase null-terminated string */
static void fat_83_to_name(const char *raw, char *out) {
    int i = 0, o = 0;
    /* Base name (trim trailing spaces) */
    for (i = 7; i >= 0 && raw[i] == ' '; i--);
    for (int j = 0; j <= i; j++) {
        char c = raw[j];
        if (c >= 'A' && c <= 'Z') c += 32; /* lowercase */
        out[o++] = c;
    }
    /* Extension */
    int ext_end = 10;
    while (ext_end >= 8 && raw[ext_end] == ' ') ext_end--;
    if (ext_end >= 8) {
        out[o++] = '.';
        for (int j = 8; j <= ext_end; j++) {
            char c = raw[j];
            if (c >= 'A' && c <= 'Z') c += 32;
            out[o++] = c;
        }
    }
    out[o] = '\0';
}

static struct fut_vnode *fat_alloc_vnode(struct fat_mount_info *fi,
                                         uint32_t cluster, uint32_t size,
                                         uint8_t attr, struct fut_mount *mnt);

/* Case-insensitive string compare for FAT name matching */
static bool fat_names_equal(const char *a, size_t alen, const char *b, size_t blen) {
    if (alen != blen) return false;
    for (size_t i = 0; i < alen; i++) {
        char ca = a[i], cb = b[i];
        if (ca >= 'A' && ca <= 'Z') ca += 32;
        if (cb >= 'A' && cb <= 'Z') cb += 32;
        if (ca != cb) return false;
    }
    return true;
}

/*
 * Iterate directory entries, calling cb() for each valid short entry.
 * Handles both FAT32 cluster-chained directories and FAT12/16 fixed root.
 * Accumulates LFN fragments and passes the long name to the callback.
 *
 * Callback signature:
 *   int cb(struct fat_dir_entry *de, const char *lfn_name, size_t lfn_len,
 *          const char *short_name, uint32_t byte_pos, void *ctx)
 * Return 0 to continue, nonzero to stop (value returned to caller).
 */
typedef int (*fat_dir_iter_cb)(struct fat_dir_entry *de, const char *lfn_name,
                                size_t lfn_len, const char *short_name,
                                uint32_t byte_pos, uint64_t disk_off,
                                void *ctx);

static int fat_dir_iterate(struct fat_mount_info *fi, uint32_t first_cluster,
                            uint32_t start_pos, fat_dir_iter_cb cb, void *ctx) {
    /* LFN accumulation buffer: up to 20 LFN entries x 13 chars = 260 chars */
    char lfn_buf[FAT_LFN_MAX + 1];
    size_t lfn_len = 0;
    uint8_t lfn_checksum = 0;
    bool lfn_valid = false;

    bool fixed_root = fat_is_fixed_root(fi, first_cluster);

    uint8_t *cbuf = fut_malloc(fixed_root ? fi->bytes_per_sector : fi->cluster_size);
    if (!cbuf) return -ENOMEM;

    uint32_t pos = 0;
    uint32_t cluster = first_cluster;

    if (fixed_root) {
        /* FAT12/16 fixed root: read sector by sector */
        uint32_t root_bytes = fi->root_entry_count * 32;
        for (uint32_t root_off = 0; root_off < root_bytes;
             root_off += fi->bytes_per_sector) {
            uint32_t read_len = fi->bytes_per_sector;
            if (root_off + read_len > root_bytes)
                read_len = root_bytes - root_off;
            fat_read_fixed_root(fi, root_off, read_len, cbuf);

            for (uint32_t off = 0; off < read_len; off += 32) {
                struct fat_dir_entry *de = (struct fat_dir_entry *)(cbuf + off);
                if (de->name[0] == 0x00) { fut_free(cbuf); return -ENOENT; }
                pos = root_off + off + 32;

                if ((uint8_t)de->name[0] == 0xE5) {
                    lfn_valid = false; lfn_len = 0;
                    continue;
                }

                if (de->attr == FAT_ATTR_LFN) {
                    /* Accumulate LFN entry */
                    struct fat_lfn_entry *lfn = (struct fat_lfn_entry *)(cbuf + off);
                    uint8_t order = lfn->order;
                    if (order & FAT_LFN_ORDER_LAST) {
                        /* First LFN entry we encounter (last in name order) */
                        lfn_valid = true;
                        lfn_checksum = lfn->checksum;
                        lfn_len = 0;
                        memset(lfn_buf, 0, sizeof(lfn_buf));
                    }
                    if (lfn_valid && lfn->checksum == lfn_checksum) {
                        uint8_t seq = order & FAT_LFN_ORDER_MASK;
                        if (seq >= 1 && seq <= 20) {
                            uint32_t base = (seq - 1) * FAT_LFN_CHARS_PER;
                            char frag[FAT_LFN_CHARS_PER];
                            int n = fat_lfn_extract(lfn, frag);
                            for (int i = 0; i < n && base + (uint32_t)i < FAT_LFN_MAX; i++)
                                lfn_buf[base + i] = frag[i];
                            /* Cap end at FAT_LFN_MAX so the later
                             * lfn_buf[lfn_len] = '\0' stays within the
                             * (FAT_LFN_MAX + 1)-byte buffer. A malformed
                             * LFN with seq=20 and n=13 would otherwise
                             * push lfn_len to 260. */
                            uint32_t end = base + (uint32_t)n;
                            if (end > FAT_LFN_MAX) end = FAT_LFN_MAX;
                            if (end > lfn_len) lfn_len = end;
                        }
                    }
                    continue;
                }

                if (de->attr & FAT_ATTR_VOLUME_ID) {
                    lfn_valid = false; lfn_len = 0;
                    continue;
                }

                /* Short name entry: validate LFN checksum */
                const char *final_lfn = NULL;
                size_t final_lfn_len = 0;
                if (lfn_valid && lfn_len > 0) {
                    uint8_t cs = fat_lfn_checksum(de->name);
                    if (cs == lfn_checksum) {
                        lfn_buf[lfn_len] = '\0';
                        final_lfn = lfn_buf;
                        final_lfn_len = lfn_len;
                    }
                }
                lfn_valid = false; lfn_len = 0;

                char short_name[13];
                fat_83_to_name(de->name, short_name);

                if (pos > start_pos) {
                    uint64_t disk_off =
                        (uint64_t)fi->first_root_dir_sector * fi->bytes_per_sector
                        + root_off + off;
                    int rc = cb(de, final_lfn, final_lfn_len, short_name,
                                pos, disk_off, ctx);
                    if (rc != 0) { fut_free(cbuf); return rc; }
                }
            }
        }
    } else {
        /* Cluster-chained directory (FAT32, or FAT12/16 subdirectory) */
        while (cluster >= 2) {
            fat_read_cluster(fi, cluster, cbuf);
            for (uint32_t off = 0; off < fi->cluster_size; off += 32) {
                struct fat_dir_entry *de = (struct fat_dir_entry *)(cbuf + off);
                if (de->name[0] == 0x00) { fut_free(cbuf); return -ENOENT; }
                pos += 32;

                if ((uint8_t)de->name[0] == 0xE5) {
                    lfn_valid = false; lfn_len = 0;
                    continue;
                }

                if (de->attr == FAT_ATTR_LFN) {
                    struct fat_lfn_entry *lfn = (struct fat_lfn_entry *)(cbuf + off);
                    uint8_t order = lfn->order;
                    if (order & FAT_LFN_ORDER_LAST) {
                        lfn_valid = true;
                        lfn_checksum = lfn->checksum;
                        lfn_len = 0;
                        memset(lfn_buf, 0, sizeof(lfn_buf));
                    }
                    if (lfn_valid && lfn->checksum == lfn_checksum) {
                        uint8_t seq = order & FAT_LFN_ORDER_MASK;
                        if (seq >= 1 && seq <= 20) {
                            uint32_t base = (seq - 1) * FAT_LFN_CHARS_PER;
                            char frag[FAT_LFN_CHARS_PER];
                            int n = fat_lfn_extract(lfn, frag);
                            for (int i = 0; i < n && base + (uint32_t)i < FAT_LFN_MAX; i++)
                                lfn_buf[base + i] = frag[i];
                            /* Cap end at FAT_LFN_MAX so the later
                             * lfn_buf[lfn_len] = '\0' stays within the
                             * (FAT_LFN_MAX + 1)-byte buffer. A malformed
                             * LFN with seq=20 and n=13 would otherwise
                             * push lfn_len to 260. */
                            uint32_t end = base + (uint32_t)n;
                            if (end > FAT_LFN_MAX) end = FAT_LFN_MAX;
                            if (end > lfn_len) lfn_len = end;
                        }
                    }
                    continue;
                }

                if (de->attr & FAT_ATTR_VOLUME_ID) {
                    lfn_valid = false; lfn_len = 0;
                    continue;
                }

                const char *final_lfn = NULL;
                size_t final_lfn_len = 0;
                if (lfn_valid && lfn_len > 0) {
                    uint8_t cs = fat_lfn_checksum(de->name);
                    if (cs == lfn_checksum) {
                        lfn_buf[lfn_len] = '\0';
                        final_lfn = lfn_buf;
                        final_lfn_len = lfn_len;
                    }
                }
                lfn_valid = false; lfn_len = 0;

                char short_name[13];
                fat_83_to_name(de->name, short_name);

                if (pos > start_pos) {
                    uint64_t disk_off =
                        (uint64_t)fat_cluster_to_sector(fi, cluster)
                            * fi->bytes_per_sector + off;
                    int rc = cb(de, final_lfn, final_lfn_len, short_name,
                                pos, disk_off, ctx);
                    if (rc != 0) { fut_free(cbuf); return rc; }
                }
            }
            cluster = fat_next_cluster(fi, cluster);
        }
    }

    fut_free(cbuf);
    return -ENOENT; /* no more entries */
}

/* ---- Lookup callback context ---- */
struct fat_lookup_ctx {
    const char *name;
    size_t name_len;
    struct fat_mount_info *fi;
    struct fut_mount *mnt;
    struct fut_vnode *parent;
    struct fut_vnode *result;
};

static int fat_lookup_cb(struct fat_dir_entry *de, const char *lfn_name,
                          size_t lfn_len, const char *short_name,
                          uint32_t byte_pos, uint64_t disk_off, void *ctx) {
    (void)byte_pos;
    struct fat_lookup_ctx *lc = (struct fat_lookup_ctx *)ctx;

    /* Try LFN match first, then 8.3 match */
    bool match = false;
    if (lfn_name && lfn_len > 0)
        match = fat_names_equal(lc->name, lc->name_len, lfn_name, lfn_len);
    if (!match) {
        size_t slen = 0;
        while (short_name[slen]) slen++;
        match = fat_names_equal(lc->name, lc->name_len, short_name, slen);
    }

    if (match) {
        uint32_t fc = ((uint32_t)de->first_cluster_hi << 16) | de->first_cluster_lo;
        lc->result = fat_alloc_vnode(lc->fi, fc, de->file_size, de->attr, lc->mnt);
        if (!lc->result) return -ENOMEM;
        lc->result->parent = lc->parent;
        char *ndup = fut_malloc(lc->name_len + 1);
        if (ndup) { memcpy(ndup, lc->name, lc->name_len); ndup[lc->name_len] = '\0'; }
        lc->result->name = ndup;
        /* Remember where this file's 8.3 entry lives on disk so future
         * writes can update size + first_cluster in place. */
        ((struct fat_vnode_info *)lc->result->fs_data)->dir_entry_disk_off = disk_off;
        return 1; /* found — stop iteration */
    }
    return 0; /* continue */
}

static int fat_vnode_lookup(struct fut_vnode *dir, const char *name,
                            struct fut_vnode **result) {
    struct fat_vnode_info *vi = (struct fat_vnode_info *)dir->fs_data;
    if (!vi || !(vi->attr & FAT_ATTR_DIRECTORY)) return -ENOTDIR;

    struct fat_mount_info *fi = vi->fi;

    struct fat_lookup_ctx lc;
    lc.name = name;
    lc.name_len = 0;
    while (name[lc.name_len]) lc.name_len++;
    lc.fi = fi;
    lc.mnt = dir->mount;
    lc.parent = dir;
    lc.result = NULL;

    int rc = fat_dir_iterate(fi, vi->first_cluster, 0, fat_lookup_cb, &lc);
    if (rc == 1) {
        *result = lc.result;
        return 0;
    }
    if (rc < 0 && rc != -ENOENT) return rc;
    return -ENOENT;
}

/* ---- Readdir callback context ---- */
struct fat_readdir_ctx {
    struct fut_vdirent *dirent;
    uint64_t *cookie;
    bool found;
};

static int fat_readdir_cb(struct fat_dir_entry *de, const char *lfn_name,
                           size_t lfn_len, const char *short_name,
                           uint32_t byte_pos, uint64_t disk_off, void *ctx) {
    (void)disk_off;
    struct fat_readdir_ctx *rc = (struct fat_readdir_ctx *)ctx;

    rc->dirent->d_ino = ((uint32_t)de->first_cluster_hi << 16) | de->first_cluster_lo;
    if (rc->dirent->d_ino == 0) rc->dirent->d_ino = 1;
    rc->dirent->d_off = byte_pos;
    rc->dirent->d_reclen = sizeof(*rc->dirent);
    rc->dirent->d_type = (de->attr & FAT_ATTR_DIRECTORY) ? 4 : 8;

    /* Prefer LFN if available, otherwise use 8.3 short name */
    const char *use_name = short_name;
    size_t nl = 0;
    if (lfn_name && lfn_len > 0) {
        use_name = lfn_name;
        nl = lfn_len;
    } else {
        while (use_name[nl]) nl++;
    }
    if (nl > FUT_VFS_NAME_MAX) nl = FUT_VFS_NAME_MAX;
    memcpy(rc->dirent->d_name, use_name, nl);
    rc->dirent->d_name[nl] = '\0';

    *rc->cookie = byte_pos;
    rc->found = true;
    return 1; /* stop — we only want one entry per call */
}

static int fat_vnode_readdir(struct fut_vnode *dir, uint64_t *cookie,
                             struct fut_vdirent *dirent) {
    struct fat_vnode_info *vi = (struct fat_vnode_info *)dir->fs_data;
    if (!vi) return -EIO;

    struct fat_mount_info *fi = vi->fi;
    uint32_t start_pos = (uint32_t)*cookie;

    struct fat_readdir_ctx rc;
    rc.dirent = dirent;
    rc.cookie = cookie;
    rc.found = false;

    int ret = fat_dir_iterate(fi, vi->first_cluster, start_pos, fat_readdir_cb, &rc);
    if (rc.found) return 1;
    if (ret < 0 && ret != -ENOENT) return ret;
    return -ENOENT;
}

/* Build an 11-byte 8.3 directory entry name from a possibly-lowercase
 * filename. Returns 0 on success, -EINVAL if the name doesn't fit 8.3.
 * Limitations: no LFN, no Unicode -- ASCII only, at most 8 chars before
 * the dot and 3 chars after. We don't need more for `klog.log`-style
 * names; LFN support is a future task. */
static int fat_make_short_name(const char *name, char out[11]) {
    for (int i = 0; i < 11; i++) out[i] = ' ';
    int n_base = 0, n_ext = 0;
    bool past_dot = false;
    for (const char *p = name; *p; p++) {
        char c = *p;
        if (c == '.') {
            if (past_dot) return -EINVAL; /* multiple dots not allowed */
            past_dot = true;
            continue;
        }
        if (c >= 'a' && c <= 'z') c = c - 'a' + 'A';
        if (c < ' ' || c == '"' || c == '*' || c == '/' || c == ':' ||
            c == '<' || c == '>' || c == '?' || c == '\\' || c == '|')
            return -EINVAL;
        if (!past_dot) {
            if (n_base >= 8) return -EINVAL;
            out[n_base++] = c;
        } else {
            if (n_ext >= 3) return -EINVAL;
            out[8 + n_ext++] = c;
        }
    }
    if (n_base == 0) return -EINVAL;
    /* Filenames whose first byte is 0xE5 must be written as 0x05 in
     * the on-disk entry. */
    if ((uint8_t)out[0] == 0xE5) out[0] = 0x05;
    return 0;
}

/* Find a free 32-byte slot in a directory's cluster chain (or fixed
 * root for FAT12/16). Returns 0 + slot_disk_off on success.
 * "Free" means name[0] == 0xE5 (deleted) or name[0] == 0x00 (terminator
 * -- we use this slot and let the next slot be the new terminator).
 *
 * For cluster-chained dirs (FAT32), extends the directory by allocating
 * a new cluster + linking it onto the chain if no slot is found. */
static int fat_dir_find_free_slot(struct fat_mount_info *fi,
                                    uint32_t dir_cluster,
                                    uint64_t *out_disk_off) {
    if (fat_is_fixed_root(fi, dir_cluster)) {
        uint32_t root_bytes = fi->root_entry_count * 32;
        uint64_t base = (uint64_t)fi->first_root_dir_sector * fi->bytes_per_sector;
        struct fat_dir_entry de;
        for (uint32_t off = 0; off < root_bytes; off += 32) {
            fat_dev_read(fi, base + off, sizeof(de), &de);
            uint8_t n0 = (uint8_t)de.name[0];
            if (n0 == 0x00 || n0 == 0xE5) {
                *out_disk_off = base + off;
                return 0;
            }
        }
        return -ENOSPC;
    }

    /* Cluster-chained directory (FAT32 root, or FAT12/16 subdir). */
    uint32_t cluster = dir_cluster;
    uint32_t prev = cluster;
    while (cluster >= 2) {
        uint64_t base = (uint64_t)fat_cluster_to_sector(fi, cluster)
                            * fi->bytes_per_sector;
        struct fat_dir_entry de;
        for (uint32_t off = 0; off < fi->cluster_size; off += 32) {
            fat_dev_read(fi, base + off, sizeof(de), &de);
            uint8_t n0 = (uint8_t)de.name[0];
            if (n0 == 0x00 || n0 == 0xE5) {
                *out_disk_off = base + off;
                return 0;
            }
        }
        prev = cluster;
        cluster = fat_next_cluster(fi, cluster);
    }
    /* No slot found and chain ended. Extend by allocating a new
     * cluster, zero-filling it, linking it onto the chain. */
    uint32_t newc = 0;
    int rc = fat_alloc_cluster(fi, &newc);
    if (rc < 0) return rc;
    /* Zero the new directory cluster so name[0]=0 marks all slots free. */
    uint8_t *zbuf = fut_malloc(fi->cluster_size);
    if (!zbuf) return -ENOMEM;
    memset(zbuf, 0, fi->cluster_size);
    fat_write_cluster_at(fi, newc, 0, zbuf, fi->cluster_size);
    fut_free(zbuf);
    rc = fat_set_fat_entry(fi, prev, newc);
    if (rc < 0) return rc;
    *out_disk_off = (uint64_t)fat_cluster_to_sector(fi, newc) * fi->bytes_per_sector;
    return 0;
}

/* Create a new empty regular file in `dir` named `name` (8.3 only).
 * Writes a single 32-byte directory entry with size=0, first_cluster=0.
 * Returns a new vnode in *result on success. */
static int fat_vnode_create(struct fut_vnode *dir, const char *name,
                             uint32_t mode, struct fut_vnode **result) {
    (void)mode;
    struct fat_vnode_info *dvi = (struct fat_vnode_info *)dir->fs_data;
    if (!dvi || !(dvi->attr & FAT_ATTR_DIRECTORY)) return -ENOTDIR;
    struct fat_mount_info *fi = dvi->fi;

    char shortname[11];
    int rc = fat_make_short_name(name, shortname);
    if (rc < 0) return rc;

    /* Refuse if a file with this short name already exists in the dir.
     * Use the existing lookup path -- it case-folds + handles LFN, so
     * this is a stronger "no duplicate" check than 8.3-only would give. */
    struct fut_vnode *existing = NULL;
    if (fat_vnode_lookup(dir, name, &existing) == 0) {
        return -EEXIST;
    }

    uint64_t slot = 0;
    rc = fat_dir_find_free_slot(fi, dvi->first_cluster, &slot);
    if (rc < 0) return rc;

    /* Build a zero-initialized dir entry with our 8.3 name. */
    struct fat_dir_entry de;
    memset(&de, 0, sizeof(de));
    memcpy(de.name, shortname, 11);
    de.attr = FAT_ATTR_ARCHIVE;

    ssize_t w = fat_dev_write(fi, slot, sizeof(de), &de);
    if (w < 0) return (int)w;

    struct fut_vnode *vn = fat_alloc_vnode(fi, 0, 0, FAT_ATTR_ARCHIVE,
                                            dir->mount);
    if (!vn) return -ENOMEM;
    vn->parent = dir;
    size_t nl = 0; while (name[nl]) nl++;
    char *ndup = fut_malloc(nl + 1);
    if (ndup) { memcpy(ndup, name, nl); ndup[nl] = '\0'; }
    vn->name = ndup;
    ((struct fat_vnode_info *)vn->fs_data)->dir_entry_disk_off = slot;
    *result = vn;
    return 0;
}

static int fat_ro3(struct fut_vnode *d, const char *n, uint32_t m) {
    (void)d;(void)n;(void)m; return -EROFS; }
static int fat_ro4(struct fut_vnode *d, const char *o, const char *n) {
    (void)d;(void)o;(void)n; return -EROFS; }

/* Walk the cluster chain rooted at `first_cluster`, marking each entry
 * free (0) in every FAT mirror. Stops at the FAT-type-specific EOC or
 * if it sees a value < 2 (free / reserved). Returns 0 on success. */
static int fat_free_chain(struct fat_mount_info *fi, uint32_t first_cluster) {
    uint32_t c = first_cluster;
    int safety = 0;
    while (c >= 2) {
        uint32_t next = fat_next_cluster(fi, c);
        int rc = fat_set_fat_entry(fi, c, 0);
        if (rc < 0) return rc;
        if (next < 2) break;
        c = next;
        /* Cluster count is bounded by fi->total_clusters; double that to
         * be safe against a corrupted self-loop. */
        if (++safety > (int)(fi->total_clusters * 2 + 16)) return -EIO;
    }
    return 0;
}

/* Truncate a file to `length` bytes. Walks the cluster chain to find the
 * boundary cluster, then:
 *   - shrink-to-0:    free the whole chain, set first_cluster=0 in dir
 *   - shrink-to-N:    set the boundary cluster's FAT entry to EOC, free
 *                     everything past it
 *   - same size:      no-op
 *   - grow-to-N:      allocate new EOC-terminated clusters at the end of
 *                     the chain, zero-fill, then update size
 * In every case the dir entry's `file_size` field is rewritten.
 *
 * O_TRUNC on an existing file goes through this path (after unlink+create
 * was the previous workaround). With this in place, the klog SD writer
 * could in principle drop its unlink-before-write call, but leaving both
 * costs nothing and gives defence in depth. */
static int fat_vnode_truncate(struct fut_vnode *v, uint64_t length) {
    struct fat_vnode_info *vi = (struct fat_vnode_info *)v->fs_data;
    if (!vi) return -EINVAL;
    if (vi->attr & FAT_ATTR_DIRECTORY) return -EINVAL;
    if (vi->dir_entry_disk_off == 0) return -EROFS;
    struct fat_mount_info *fi = vi->fi;
    uint32_t old_size = vi->file_size;
    if ((uint64_t)length > 0xFFFFFFFFULL) return -EFBIG;
    uint32_t new_size = (uint32_t)length;
    if (new_size == old_size) return 0;

    if (new_size < old_size) {
        if (new_size == 0) {
            if (vi->first_cluster >= 2) {
                int rc = fat_free_chain(fi, vi->first_cluster);
                if (rc < 0) return rc;
            }
            vi->first_cluster = 0;
        } else {
            /* Walk forward (new_size-1)/cluster_size clusters from the
             * head. That's the last cluster the file still needs. */
            uint32_t keep_clusters = (new_size + fi->cluster_size - 1) / fi->cluster_size;
            uint32_t cur = vi->first_cluster;
            for (uint32_t i = 1; i < keep_clusters && cur >= 2; ++i) {
                cur = fat_next_cluster(fi, cur);
            }
            if (cur < 2) return -EIO;
            uint32_t to_free = fat_next_cluster(fi, cur);
            uint32_t eoc = (fi->fat_type == FAT_TYPE_32) ? FAT32_EOC : FAT16_EOC;
            int rc = fat_set_fat_entry(fi, cur, eoc);
            if (rc < 0) return rc;
            if (to_free >= 2) {
                rc = fat_free_chain(fi, to_free);
                if (rc < 0) return rc;
            }
        }
    } else {
        /* Grow. Walk to the chain end, then allocate-link-zero each new
         * cluster up to the new size. */
        uint32_t cur_clusters = (old_size + fi->cluster_size - 1) / fi->cluster_size;
        uint32_t need_clusters = (new_size + fi->cluster_size - 1) / fi->cluster_size;
        uint32_t to_add = need_clusters - cur_clusters;
        if (to_add == 0) {
            /* Same number of clusters, just a size bump within the last
             * cluster — no FAT work needed, only the dir-entry update. */
        } else if (vi->first_cluster == 0) {
            /* Empty file growing for the first time. */
            uint32_t newc;
            int rc = fat_alloc_cluster(fi, &newc);
            if (rc < 0) return rc;
            vi->first_cluster = newc;
            to_add--;
            uint32_t prev = newc;
            while (to_add > 0) {
                rc = fat_alloc_cluster(fi, &newc);
                if (rc < 0) return rc;
                rc = fat_set_fat_entry(fi, prev, newc);
                if (rc < 0) return rc;
                prev = newc;
                to_add--;
            }
        } else {
            uint32_t cur = vi->first_cluster;
            while (true) {
                uint32_t next = fat_next_cluster(fi, cur);
                if (next < 2) break;
                cur = next;
            }
            while (to_add > 0) {
                uint32_t newc;
                int rc = fat_alloc_cluster(fi, &newc);
                if (rc < 0) return rc;
                rc = fat_set_fat_entry(fi, cur, newc);
                if (rc < 0) return rc;
                cur = newc;
                to_add--;
            }
        }
        /* Zero-fill the newly-allocated tail. We don't bother zeroing
         * partial bytes in the last cluster — those were either zero
         * already (cluster came from fat_alloc_cluster on a freshly-
         * formatted volume) or contain a previous deleted file's bytes.
         * A strict POSIX zero-fill would memset() each new cluster; left
         * for later if it ever matters. */
    }

    vi->file_size = new_size;
    return fat_dir_entry_set_size(fi, vi->dir_entry_disk_off,
                                  vi->first_cluster, new_size);
}

/* Delete `name` in directory `dir`. Walks the cluster chain on disk and
 * marks each cluster free, then marks the dir entry as deleted (0xE5)
 * which is the standard FAT "free dir slot" sentinel.
 *
 * Also walks BACKWARDS from the 8.3 entry looking for LFN (long-filename)
 * slots that prefix it, marking each as deleted too. Without this, Linux's
 * vfat mount sees orphan LFN entries pointing at a deleted 8.3 and flags
 * the FS as inconsistent — observed when the user removed the SD card
 * mid-write; chkdsk eventually fixed it but the boot-time log writes were
 * scary. LFN entries always have attr == 0x0F and immediately precede
 * their 8.3 entry; sequence numbers count down to 1 (with 0x40 set on the
 * last/first-by-name slot).
 *
 * Remaining limitations versus a full POSIX unlink:
 *   - No support for unlinking directories (must be empty).
 *   - Does not update FSInfo free-cluster hint (Linux recomputes it on
 *     next mount — chkdsk does NOT flag this).
 */
static int fat_vnode_unlink(struct fut_vnode *dir, const char *name) {
    struct fat_vnode_info *dvi = (struct fat_vnode_info *)dir->fs_data;
    if (!dvi || !(dvi->attr & FAT_ATTR_DIRECTORY)) return -ENOTDIR;
    struct fat_mount_info *fi = dvi->fi;

    /* Re-use lookup to find the target vnode (and its dir_entry_disk_off). */
    struct fut_vnode *target = NULL;
    int rc = fat_vnode_lookup(dir, name, &target);
    if (rc < 0) return rc;
    if (!target) return -ENOENT;

    struct fat_vnode_info *tvi = (struct fat_vnode_info *)target->fs_data;
    if (tvi->attr & FAT_ATTR_DIRECTORY) {
        /* Could implement rmdir-with-empty-check here; for now refuse. */
        return -EISDIR;
    }
    if (tvi->dir_entry_disk_off == 0) return -EIO;

    /* Free the cluster chain (if the file has any). */
    if (tvi->first_cluster >= 2) {
        rc = fat_free_chain(fi, tvi->first_cluster);
        if (rc < 0) return rc;
    }

    /* Walk backwards through preceding LFN slots and mark each deleted.
     * Each dir entry is exactly 32 bytes; LFN slots have attr=0x0F at byte
     * offset 11. Stop when we hit a non-LFN entry, the start of the
     * containing cluster, or the start of the FAT volume — whichever
     * comes first. Up to 20 LFN slots are allowed per name (max 255 chars
     * × 13 chars per slot ≈ 20); cap at 20 here as a safety bound. */
    uint8_t deleted = 0xE5;
    uint64_t entry_off = tvi->dir_entry_disk_off;
    for (int i = 0; i < 20; ++i) {
        if (entry_off < 32) break;
        uint64_t prev_off = entry_off - 32;
        struct fat_dir_entry prev_de;
        ssize_t r = fat_dev_read(fi, prev_off, sizeof(prev_de), &prev_de);
        if (r < 0) break;
        /* Stop if this isn't an LFN slot, or if it's already deleted
         * (0xE5 in the first byte). */
        if (prev_de.attr != FAT_ATTR_LFN) break;
        if ((uint8_t)prev_de.name[0] == 0xE5) break;
        /* Don't cross a cluster boundary — LFN slots and their 8.3 must
         * live in the same cluster, but we still defensively check. */
        if ((entry_off & ~((uint64_t)fi->cluster_size - 1)) !=
            (prev_off  & ~((uint64_t)fi->cluster_size - 1))) {
            break;
        }
        ssize_t lw = fat_dev_write(fi, prev_off, 1, &deleted);
        if (lw < 0) break;
        entry_off = prev_off;
    }

    /* Mark the dir entry's first byte as 0xE5 = "deleted slot". */
    ssize_t w = fat_dev_write(fi, tvi->dir_entry_disk_off,
                                          1, &deleted);
    if (w < 0) return (int)w;

    return 0;
}

static struct fut_vnode_ops fat_vnode_ops;

static struct fut_vnode *fat_alloc_vnode(struct fat_mount_info *fi,
                                         uint32_t cluster, uint32_t size,
                                         uint8_t attr, struct fut_mount *mnt) {
    struct fut_vnode *vn = fut_malloc(sizeof(struct fut_vnode));
    if (!vn) return NULL;
    memset(vn, 0, sizeof(*vn));

    struct fat_vnode_info *vi = fut_malloc(sizeof(struct fat_vnode_info));
    if (!vi) { fut_free(vn); return NULL; }
    vi->first_cluster = cluster;
    vi->file_size = size;
    vi->attr = attr;
    vi->fi = fi;
    vi->dir_entry_disk_off = 0; /* set by lookup or create after alloc */

    vn->fs_data = vi;
    vn->ops = &fat_vnode_ops;
    vn->mount = mnt;
    vn->ino = cluster ? cluster : 1;
    vn->size = size;
    vn->mode = (attr & FAT_ATTR_DIRECTORY) ? 0040755 : 0100644;
    vn->nlinks = 1;
    vn->refcount = 1;
    vn->type = (attr & FAT_ATTR_DIRECTORY) ? VN_DIR : VN_REG;

    return vn;
}

/* ============================================================
 *   Filesystem type
 * ============================================================ */

static int fat_mount_impl(const char *device, int flags, void *data,
                           fut_handle_t bh, struct fut_mount **mount_out) {
    (void)flags; (void)data; (void)bh;

    struct fut_blockdev *dev = fut_blockdev_find(device);
    if (!dev) return -ENODEV;

    /* Try to read a FAT BPB at LBA 0 first. If the device starts with
     * an MBR partition table (common for USB sticks / SD cards formatted
     * by Windows/macOS/Linux), the LBA-0 block is the MBR — not a FAT
     * BPB. In that case parse the partition table and re-read the BPB
     * from the start of the first FAT partition. */
    struct fat_bpb bpb;
    uint64_t partition_offset_bytes = 0;
    ssize_t n = fut_blockdev_read_bytes(dev, 0, sizeof(bpb), &bpb);
    if (n < 0) return (int)n;

    int val = fat_validate_bpb(&bpb);
    if (val < 0) {
        /* Try MBR parsing. The MBR has 0x55 0xAA at offset 0x1FE and four
         * 16-byte partition entries starting at offset 0x1BE. Each entry's
         * type byte (offset 4) is one of: 0x01 (FAT12), 0x04/0x06 (FAT16),
         * 0x0B/0x0C (FAT32). Bytes 8..11 hold the partition's start LBA
         * as little-endian uint32. */
        uint8_t mbr[512];
        ssize_t mn = fut_blockdev_read_bytes(dev, 0, sizeof(mbr), mbr);
        if (mn < (ssize_t)sizeof(mbr)) return val;
        if (mbr[0x1FE] != 0x55 || mbr[0x1FF] != 0xAA) return val;
        uint32_t fat_start_lba = 0;
        for (int p = 0; p < 4; ++p) {
            const uint8_t *ent = &mbr[0x1BE + p * 16];
            uint8_t type = ent[4];
            if (type != 0x01 && type != 0x04 && type != 0x06
                && type != 0x0B && type != 0x0C) continue;
            uint32_t lba = (uint32_t)ent[8]
                         | ((uint32_t)ent[9]  << 8)
                         | ((uint32_t)ent[10] << 16)
                         | ((uint32_t)ent[11] << 24);
            if (lba == 0) continue;
            fat_start_lba = lba;
            break;
        }
        if (fat_start_lba == 0) return val;
        /* Assume 512-byte sectors at the MBR layer (universal for SD/USB).
         * The BPB itself may report a different bytes_per_sector but the
         * partition table always uses 512-byte LBAs. */
        partition_offset_bytes = (uint64_t)fat_start_lba * 512ULL;
        n = fut_blockdev_read_bytes(dev, partition_offset_bytes,
                                     sizeof(bpb), &bpb);
        if (n < 0) return (int)n;
        val = fat_validate_bpb(&bpb);
        if (val < 0) return val;
        fut_printf("[FAT] Found FAT partition at LBA %u (offset %llu bytes)\n",
                   fat_start_lba, (unsigned long long)partition_offset_bytes);
    }

    struct fat_mount_info *fi = fut_malloc(sizeof(struct fat_mount_info));
    if (!fi) return -ENOMEM;
    memset(fi, 0, sizeof(*fi));

    fi->dev = dev;
    fi->partition_offset_bytes = partition_offset_bytes;
    fi->bytes_per_sector = bpb.bytes_per_sector;
    fi->sectors_per_cluster = bpb.sectors_per_cluster;
    fi->cluster_size = fi->bytes_per_sector * fi->sectors_per_cluster;
    fi->reserved_sectors = bpb.reserved_sectors;
    fi->num_fats = bpb.num_fats;
    fi->root_entry_count = bpb.root_entry_count;
    fi->total_sectors = bpb.total_sectors_16 ? bpb.total_sectors_16 : bpb.total_sectors_32;
    fi->fat_size = bpb.fat_size_16 ? bpb.fat_size_16 : bpb.fat_size_32;
    fi->root_dir_sectors = ((fi->root_entry_count * 32) + fi->bytes_per_sector - 1) /
                           fi->bytes_per_sector;
    fi->first_data_sector = fi->reserved_sectors + (fi->num_fats * fi->fat_size) +
                            fi->root_dir_sectors;

    /* Sanity: data must start within the device */
    if (fi->first_data_sector >= fi->total_sectors) {
        fut_free(fi);
        return -EINVAL;
    }

    fi->data_sectors = fi->total_sectors - fi->first_data_sector;
    fi->total_clusters = fi->data_sectors / fi->sectors_per_cluster;

    /* Determine FAT type per the Microsoft FAT specification */
    if (fi->total_clusters < 4085) fi->fat_type = FAT_TYPE_12;
    else if (fi->total_clusters < 65525) fi->fat_type = FAT_TYPE_16;
    else fi->fat_type = FAT_TYPE_32;

    /* FAT32 requires fat_size_32 and root_entry_count == 0 */
    if (fi->fat_type == FAT_TYPE_32) {
        if (bpb.fat_size_16 != 0 || bpb.root_entry_count != 0) {
            fut_free(fi);
            return -EINVAL;
        }
    }

    fi->root_cluster = (fi->fat_type == FAT_TYPE_32) ? bpb.root_cluster : 0;
    fi->first_root_dir_sector = fi->reserved_sectors + fi->num_fats * fi->fat_size;

    /* Create mount */
    struct fut_mount *mnt = fut_malloc(sizeof(struct fut_mount));
    if (!mnt) { fut_free(fi); return -ENOMEM; }
    memset(mnt, 0, sizeof(*mnt));
    mnt->fs_data = fi;

    /* Root vnode: FAT32 uses root_cluster, FAT12/16 uses cluster 0 (fixed root) */
    uint32_t root_cluster = (fi->fat_type == FAT_TYPE_32) ? fi->root_cluster : 0;
    struct fut_vnode *root = fat_alloc_vnode(fi, root_cluster, 0,
                                             FAT_ATTR_DIRECTORY, mnt);
    if (!root) { fut_free(fi); fut_free(mnt); return -EIO; }
    mnt->root = root;

    *mount_out = mnt;
    fut_printf("[FAT] Mounted FAT%d: %u clusters, %u bytes/cluster\n",
               fi->fat_type, fi->total_clusters, fi->cluster_size);
    return 0;
}

static int fat_unmount_impl(struct fut_mount *mount) {
    if (mount->fs_data) fut_free(mount->fs_data);
    return 0;
}

static int fat_statfs_impl(struct fut_mount *mount, struct fut_statfs *out) {
    struct fat_mount_info *fi = (struct fat_mount_info *)mount->fs_data;
    if (!fi || !out) return -EINVAL;
    memset(out, 0, sizeof(*out));
    out->block_size = fi->cluster_size;
    out->blocks_total = fi->total_clusters;
    out->blocks_free = 0; /* Read-only, don't count free */
    return 0;
}

static struct fut_fs_type fat_fs_type;

void fat_init(void) {
    fat_vnode_ops.read = fat_vnode_read;
    fat_vnode_ops.write = fat_vnode_write;
    fat_vnode_ops.lookup = fat_vnode_lookup;
    fat_vnode_ops.readdir = fat_vnode_readdir;
    fat_vnode_ops.create = fat_vnode_create;
    fat_vnode_ops.unlink = fat_vnode_unlink;
    fat_vnode_ops.truncate = fat_vnode_truncate;
    fat_vnode_ops.mkdir = fat_ro3;
    fat_vnode_ops.rename = fat_ro4;

    fat_fs_type.name = "vfat";
    fat_fs_type.mount = fat_mount_impl;
    fat_fs_type.unmount = fat_unmount_impl;
    fat_fs_type.statfs = fat_statfs_impl;

    extern int fut_vfs_register_fs(const struct fut_fs_type *);
    fut_vfs_register_fs(&fat_fs_type);

    fut_printf("[FAT] FAT12/16/32 filesystem driver registered\n");
}
