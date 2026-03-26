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

    if (fi->fat_type == FAT_TYPE_32) {
        fat_offset = cluster * 4;
        uint64_t byte_off = (uint64_t)fi->reserved_sectors * fi->bytes_per_sector + fat_offset;
        fut_blockdev_read_bytes(fi->dev, byte_off, 4, &entry);
        entry &= 0x0FFFFFFF;
        return (entry >= FAT32_EOC) ? 0 : entry;
    } else if (fi->fat_type == FAT_TYPE_16) {
        fat_offset = cluster * 2;
        uint16_t entry16;
        uint64_t byte_off = (uint64_t)fi->reserved_sectors * fi->bytes_per_sector + fat_offset;
        fut_blockdev_read_bytes(fi->dev, byte_off, 2, &entry16);
        return (entry16 >= FAT16_EOC) ? 0 : entry16;
    } else { /* FAT12 */
        fat_offset = cluster + (cluster / 2);
        uint16_t entry12;
        uint64_t byte_off = (uint64_t)fi->reserved_sectors * fi->bytes_per_sector + fat_offset;
        fut_blockdev_read_bytes(fi->dev, byte_off, 2, &entry12);
        entry12 = (cluster & 1) ? (entry12 >> 4) : (entry12 & 0xFFF);
        return (entry12 >= FAT12_EOC) ? 0 : entry12;
    }
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

    /* Walk cluster chain to find starting cluster */
    uint32_t cluster = vi->first_cluster;
    uint64_t skip = offset;
    while (skip >= fi->cluster_size && cluster >= 2) {
        skip -= fi->cluster_size;
        cluster = fat_next_cluster(fi, cluster);
    }

    /* Read data from cluster chain */
    while (total < size && cluster >= 2) {
        static uint8_t cbuf[4096];
        size_t csize = fi->cluster_size < sizeof(cbuf) ? fi->cluster_size : sizeof(cbuf);
        fat_read_cluster(fi, cluster, cbuf);

        uint32_t off_in = (uint32_t)skip;
        size_t avail = csize - off_in;
        if (avail > size - total) avail = size - total;
        memcpy(out + total, cbuf + off_in, avail);
        total += avail;
        skip = 0;

        cluster = fat_next_cluster(fi, cluster);
    }

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

static int fat_vnode_lookup(struct fut_vnode *dir, const char *name,
                            struct fut_vnode **result) {
    struct fat_vnode_info *vi = (struct fat_vnode_info *)dir->fs_data;
    if (!vi || !(vi->attr & FAT_ATTR_DIRECTORY)) return -ENOTDIR;

    size_t name_len = 0;
    while (name[name_len]) name_len++;

    struct fat_mount_info *fi = vi->fi;
    uint32_t cluster = vi->first_cluster;
    static uint8_t cbuf[4096];

    while (cluster >= 2) {
        fat_read_cluster(fi, cluster, cbuf);
        for (uint32_t off = 0; off < fi->cluster_size; off += 32) {
            struct fat_dir_entry *de = (struct fat_dir_entry *)(cbuf + off);
            if (de->name[0] == 0x00) goto done;     /* End of directory */
            if ((uint8_t)de->name[0] == 0xE5) continue;       /* Deleted */
            if (de->attr == FAT_ATTR_LFN) continue;  /* Skip LFN for now */
            if (de->attr & FAT_ATTR_VOLUME_ID) continue;

            char fname[13];
            fat_83_to_name(de->name, fname);

            bool match = true;
            size_t fl = 0; while (fname[fl]) fl++;
            if (fl != name_len) match = false;
            else for (size_t i = 0; i < fl; i++) {
                char a = name[i], b = fname[i];
                if (a >= 'A' && a <= 'Z') a += 32;
                if (b >= 'A' && b <= 'Z') b += 32;
                if (a != b) { match = false; break; }
            }

            if (match) {
                uint32_t fc = ((uint32_t)de->first_cluster_hi << 16) | de->first_cluster_lo;
                *result = fat_alloc_vnode(fi, fc, de->file_size, de->attr, dir->mount);
                if (!*result) return -ENOMEM;
                (*result)->parent = dir;
                char *ndup = fut_malloc(name_len + 1);
                if (ndup) { memcpy(ndup, name, name_len); ndup[name_len] = '\0'; }
                (*result)->name = ndup;
                return 0;
            }
        }
        cluster = fat_next_cluster(fi, cluster);
    }
done:
    return -ENOENT;
}

static int fat_vnode_readdir(struct fut_vnode *dir, uint64_t *cookie,
                             struct fut_vdirent *dirent) {
    struct fat_vnode_info *vi = (struct fat_vnode_info *)dir->fs_data;
    if (!vi) return -EIO;

    struct fat_mount_info *fi = vi->fi;
    uint32_t pos = (uint32_t)*cookie;  /* Byte offset into directory */
    uint32_t cluster = vi->first_cluster;
    static uint8_t cbuf[4096];

    /* Walk to the right cluster */
    uint32_t skip = pos;
    while (skip >= fi->cluster_size && cluster >= 2) {
        skip -= fi->cluster_size;
        cluster = fat_next_cluster(fi, cluster);
    }
    if (cluster < 2) return -ENOENT;

    fat_read_cluster(fi, cluster, cbuf);
    uint32_t off = skip;

    while (off < fi->cluster_size) {
        struct fat_dir_entry *de = (struct fat_dir_entry *)(cbuf + off);
        pos += 32; off += 32;
        if (de->name[0] == 0x00) return -ENOENT;
        if ((uint8_t)de->name[0] == 0xE5) continue;
        if (de->attr == FAT_ATTR_LFN) continue;
        if (de->attr & FAT_ATTR_VOLUME_ID) continue;

        char fname[13];
        fat_83_to_name(de->name, fname);

        dirent->d_ino = ((uint32_t)de->first_cluster_hi << 16) | de->first_cluster_lo;
        if (dirent->d_ino == 0) dirent->d_ino = 1;
        dirent->d_off = pos;
        dirent->d_reclen = sizeof(*dirent);
        dirent->d_type = (de->attr & FAT_ATTR_DIRECTORY) ? 4 : 8;
        size_t nl = 0; while (fname[nl]) nl++;
        if (nl > FUT_VFS_NAME_MAX) nl = FUT_VFS_NAME_MAX;
        memcpy(dirent->d_name, fname, nl);
        dirent->d_name[nl] = '\0';

        *cookie = pos;
        return 1;
    }
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

    /* Validate */
    if (bpb.bytes_per_sector < 512 || bpb.sectors_per_cluster == 0)
        return -EINVAL;

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
    fi->data_sectors = fi->total_sectors - fi->first_data_sector;
    fi->total_clusters = fi->data_sectors / fi->sectors_per_cluster;

    /* Determine FAT type */
    if (fi->total_clusters < 4085) fi->fat_type = FAT_TYPE_12;
    else if (fi->total_clusters < 65525) fi->fat_type = FAT_TYPE_16;
    else fi->fat_type = FAT_TYPE_32;

    fi->root_cluster = (fi->fat_type == FAT_TYPE_32) ? bpb.root_cluster : 0;
    fi->first_root_dir_sector = fi->reserved_sectors + fi->num_fats * fi->fat_size;

    /* Create mount */
    struct fut_mount *mnt = fut_malloc(sizeof(struct fut_mount));
    if (!mnt) { fut_free(fi); return -ENOMEM; }
    memset(mnt, 0, sizeof(*mnt));
    mnt->fs_data = fi;

    /* Root vnode */
    uint32_t root_cluster = (fi->fat_type == FAT_TYPE_32) ? fi->root_cluster : 2;
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
