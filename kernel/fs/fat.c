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

static uint64_t fat_cluster_to_sector(struct fat_mount_info *fi, uint32_t cluster) {
    return fi->first_data_sector + (uint64_t)(cluster - 2) * fi->sectors_per_cluster;
}

static ssize_t fat_read_cluster(struct fat_mount_info *fi, uint32_t cluster, void *buf) {
    uint64_t sector = fat_cluster_to_sector(fi, cluster);
    uint64_t offset = sector * fi->bytes_per_sector;
    return fut_blockdev_read_bytes(fi->dev, offset, fi->cluster_size, buf);
}

static uint32_t fat_next_cluster(struct fat_mount_info *fi, uint32_t cluster) {
    uint32_t fat_offset;
    uint32_t entry;
    uint64_t fat_start = (uint64_t)fi->reserved_sectors * fi->bytes_per_sector;

    if (fi->fat_type == FAT_TYPE_32) {
        fat_offset = cluster * 4;
        fut_blockdev_read_bytes(fi->dev, fat_start + fat_offset, 4, &entry);
        entry &= 0x0FFFFFFF;
        if (entry < 2 || entry >= FAT32_EOC) return 0;
        return entry;
    } else if (fi->fat_type == FAT_TYPE_16) {
        fat_offset = cluster * 2;
        uint16_t entry16;
        fut_blockdev_read_bytes(fi->dev, fat_start + fat_offset, 2, &entry16);
        if (entry16 < 2 || entry16 >= FAT16_EOC) return 0;
        return entry16;
    } else { /* FAT12 */
        fat_offset = cluster + (cluster / 2);
        uint16_t entry12;
        fut_blockdev_read_bytes(fi->dev, fat_start + fat_offset, 2, &entry12);
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
    return fut_blockdev_read_bytes(fi->dev, disk_off, len, buf);
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

static ssize_t fat_vnode_write(struct fut_vnode *v, const void *b, size_t s, uint64_t o) {
    (void)v; (void)b; (void)s; (void)o; return -EROFS;
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
                                uint32_t byte_pos, void *ctx);

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
                    int rc = cb(de, final_lfn, final_lfn_len, short_name, pos, ctx);
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
                    int rc = cb(de, final_lfn, final_lfn_len, short_name, pos, ctx);
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
                          uint32_t byte_pos, void *ctx) {
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
                           uint32_t byte_pos, void *ctx) {
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

static int fat_ro(struct fut_vnode *d, const char *n, uint32_t m, struct fut_vnode **r) {
    (void)d;(void)n;(void)m;(void)r; return -EROFS; }
static int fat_ro2(struct fut_vnode *d, const char *n) {
    (void)d;(void)n; return -EROFS; }
static int fat_ro3(struct fut_vnode *d, const char *n, uint32_t m) {
    (void)d;(void)n;(void)m; return -EROFS; }
static int fat_ro4(struct fut_vnode *d, const char *o, const char *n) {
    (void)d;(void)o;(void)n; return -EROFS; }

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

    /* Read BPB */
    struct fat_bpb bpb;
    ssize_t n = fut_blockdev_read_bytes(dev, 0, sizeof(bpb), &bpb);
    if (n < 0) return (int)n;

    /* Comprehensive BPB validation */
    int val = fat_validate_bpb(&bpb);
    if (val < 0) return val;

    struct fat_mount_info *fi = fut_malloc(sizeof(struct fat_mount_info));
    if (!fi) return -ENOMEM;
    memset(fi, 0, sizeof(*fi));

    fi->dev = dev;
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
    fat_vnode_ops.create = fat_ro;
    fat_vnode_ops.unlink = fat_ro2;
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
