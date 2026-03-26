/* kernel/fs/exfat.c - Read-only exFAT filesystem driver
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements read-only exFAT for SDXC cards and large USB drives (>32GB).
 * exFAT uses 32-byte directory entries with file/stream/name entry sets,
 * UTF-16LE filenames, and a simpler FAT chain than FAT32.
 */

#include <kernel/exfat.h>
#include <kernel/fut_vfs.h>
#include <kernel/fut_blockdev.h>
#include <kernel/fut_memory.h>
#include <kernel/kprintf.h>
#include <kernel/errno.h>
#include <stddef.h>
#include <string.h>

/* ============================================================
 *   Cluster I/O
 * ============================================================ */

static uint64_t exfat_cluster_offset(struct exfat_mount_info *ei, uint32_t cluster) {
    return ((uint64_t)ei->cluster_heap_offset + (uint64_t)(cluster - 2) * ei->sectors_per_cluster)
           * ei->bytes_per_sector;
}

static ssize_t exfat_read_cluster(struct exfat_mount_info *ei, uint32_t cluster, void *buf) {
    return fut_blockdev_read_bytes(ei->dev, exfat_cluster_offset(ei, cluster),
                                   ei->cluster_size, buf);
}

static uint32_t exfat_next_cluster(struct exfat_mount_info *ei, uint32_t cluster) {
    uint64_t fat_off = (uint64_t)ei->fat_offset * ei->bytes_per_sector +
                       (uint64_t)cluster * 4;
    uint32_t entry;
    fut_blockdev_read_bytes(ei->dev, fat_off, 4, &entry);
    return (entry >= 0xFFFFFFF8) ? 0 : entry;
}

/* Convert UTF-16LE to ASCII (lossy) */
static int exfat_utf16_to_ascii(const uint16_t *src, int chars, char *dst, int max) {
    int o = 0;
    for (int i = 0; i < chars && o < max - 1; i++) {
        uint16_t c = src[i];
        if (c == 0) break;
        dst[o++] = (c < 128) ? (char)c : '?';
    }
    dst[o] = '\0';
    return o;
}

/* ============================================================
 *   VFS operations
 * ============================================================ */

struct exfat_vnode_info {
    uint32_t first_cluster;
    uint64_t file_size;
    uint16_t attributes;
    struct exfat_mount_info *ei;
};

static ssize_t exfat_vnode_read(struct fut_vnode *vn, void *buf, size_t size, uint64_t offset) {
    struct exfat_vnode_info *vi = (struct exfat_vnode_info *)vn->fs_data;
    if (!vi) return -EIO;
    if (offset >= vi->file_size) return 0;
    if (offset + size > vi->file_size) size = (size_t)(vi->file_size - offset);

    struct exfat_mount_info *ei = vi->ei;
    uint8_t *out = (uint8_t *)buf;
    size_t total = 0;
    uint32_t cluster = vi->first_cluster;
    uint64_t skip = offset;

    while (skip >= ei->cluster_size && cluster >= 2) {
        skip -= ei->cluster_size;
        cluster = exfat_next_cluster(ei, cluster);
    }

    while (total < size && cluster >= 2) {
        static uint8_t cbuf[4096];
        size_t cs = ei->cluster_size < sizeof(cbuf) ? ei->cluster_size : sizeof(cbuf);
        exfat_read_cluster(ei, cluster, cbuf);
        uint32_t off_in = (uint32_t)skip;
        size_t avail = cs - off_in;
        if (avail > size - total) avail = size - total;
        memcpy(out + total, cbuf + off_in, avail);
        total += avail;
        skip = 0;
        cluster = exfat_next_cluster(ei, cluster);
    }
    return (ssize_t)total;
}

static ssize_t exfat_vnode_write(struct fut_vnode *v, const void *b, size_t s, uint64_t o) {
    (void)v;(void)b;(void)s;(void)o; return -EROFS;
}

static struct fut_vnode *exfat_alloc_vnode(struct exfat_mount_info *ei,
                                           uint32_t cluster, uint64_t size,
                                           uint16_t attr, struct fut_mount *mnt);

static int exfat_vnode_lookup(struct fut_vnode *dir, const char *name,
                              struct fut_vnode **result) {
    struct exfat_vnode_info *vi = (struct exfat_vnode_info *)dir->fs_data;
    if (!vi || !(vi->attributes & EXFAT_ATTR_DIRECTORY)) return -ENOTDIR;

    size_t name_len = 0;
    while (name[name_len]) name_len++;

    struct exfat_mount_info *ei = vi->ei;
    uint32_t cluster = vi->first_cluster;
    static uint8_t cbuf[4096];

    /* State for parsing file entry sets */
    uint16_t pending_attr = 0;
    uint32_t pending_cluster = 0;
    uint64_t pending_size = 0;
    int pending_name_len = 0;
    char pending_name[256] = {0};
    int pending_name_pos = 0;
    int pending_secondary = 0;
    int pending_seen = 0;

    while (cluster >= 2) {
        exfat_read_cluster(ei, cluster, cbuf);
        for (uint32_t off = 0; off < ei->cluster_size; off += 32) {
            uint8_t type = cbuf[off];
            if (type == EXFAT_ENTRY_EOD) goto done;

            if (type == EXFAT_ENTRY_FILE) {
                struct exfat_file_entry *fe = (struct exfat_file_entry *)(cbuf + off);
                pending_attr = fe->file_attributes;
                pending_secondary = fe->secondary_count;
                pending_seen = 0;
                pending_name_pos = 0;
                pending_name[0] = '\0';
            } else if (type == EXFAT_ENTRY_STREAM_EXT) {
                struct exfat_stream_entry *se = (struct exfat_stream_entry *)(cbuf + off);
                pending_cluster = se->first_cluster;
                pending_size = se->data_length;
                pending_name_len = se->name_length;
                pending_seen++;
            } else if (type == EXFAT_ENTRY_FILE_NAME) {
                struct exfat_name_entry *ne = (struct exfat_name_entry *)(cbuf + off);
                int chars = pending_name_len - pending_name_pos;
                if (chars > 15) chars = 15;
                pending_name_pos += exfat_utf16_to_ascii((const uint16_t *)((const uint8_t *)ne + 2), chars,
                    pending_name + pending_name_pos, 256 - pending_name_pos);
                pending_seen++;

                /* Check if entry set is complete */
                if (pending_seen >= pending_secondary) {
                    /* Compare name (case-insensitive) */
                    size_t pl = 0; while (pending_name[pl]) pl++;
                    if (pl == name_len) {
                        bool match = true;
                        for (size_t i = 0; i < pl; i++) {
                            char a = name[i], b = pending_name[i];
                            if (a >= 'A' && a <= 'Z') a += 32;
                            if (b >= 'A' && b <= 'Z') b += 32;
                            if (a != b) { match = false; break; }
                        }
                        if (match) {
                            *result = exfat_alloc_vnode(ei, pending_cluster,
                                                        pending_size, pending_attr, dir->mount);
                            if (!*result) return -ENOMEM;
                            (*result)->parent = dir;
                            char *ndup = fut_malloc(name_len + 1);
                            if (ndup) { memcpy(ndup, name, name_len); ndup[name_len] = '\0'; }
                            (*result)->name = ndup;
                            return 0;
                        }
                    }
                }
            }
        }
        cluster = exfat_next_cluster(ei, cluster);
    }
done:
    return -ENOENT;
}

static int exfat_vnode_readdir(struct fut_vnode *dir, uint64_t *cookie,
                               struct fut_vdirent *dirent) {
    struct exfat_vnode_info *vi = (struct exfat_vnode_info *)dir->fs_data;
    if (!vi) return -EIO;

    struct exfat_mount_info *ei = vi->ei;
    uint32_t pos = (uint32_t)*cookie;
    uint32_t cluster = vi->first_cluster;
    static uint8_t cbuf[4096];
    uint32_t skip = pos;

    while (skip >= ei->cluster_size && cluster >= 2) {
        skip -= ei->cluster_size;
        cluster = exfat_next_cluster(ei, cluster);
    }
    if (cluster < 2) return -ENOENT;

    /* State */
    uint16_t attr = 0;
    uint32_t fc = 0;
    uint64_t fsz __attribute__((unused)) = 0;
    int nlen = 0;
    char fname[256] = {0};
    int fpos = 0;
    int secondary = 0, seen = 0;

    exfat_read_cluster(ei, cluster, cbuf);
    uint32_t off = skip;

    while (off < ei->cluster_size) {
        uint8_t type = cbuf[off];
        pos += 32; off += 32;
        if (type == EXFAT_ENTRY_EOD) return -ENOENT;

        if (type == EXFAT_ENTRY_FILE) {
            struct exfat_file_entry *fe = (struct exfat_file_entry *)(cbuf + off - 32);
            attr = fe->file_attributes;
            secondary = fe->secondary_count;
            seen = 0; fpos = 0; fname[0] = '\0';
        } else if (type == EXFAT_ENTRY_STREAM_EXT) {
            struct exfat_stream_entry *se = (struct exfat_stream_entry *)(cbuf + off - 32);
            fc = se->first_cluster;
            fsz = se->data_length;
            nlen = se->name_length;
            seen++;
        } else if (type == EXFAT_ENTRY_FILE_NAME) {
            struct exfat_name_entry *ne = (struct exfat_name_entry *)(cbuf + off - 32);
            int chars = nlen - fpos;
            if (chars > 15) chars = 15;
            fpos += exfat_utf16_to_ascii((const uint16_t *)((const uint8_t *)ne + 2), chars, fname + fpos, 256 - fpos);
            seen++;

            if (seen >= secondary && fname[0]) {
                dirent->d_ino = fc ? fc : 1;
                dirent->d_off = pos;
                dirent->d_reclen = sizeof(*dirent);
                dirent->d_type = (attr & EXFAT_ATTR_DIRECTORY) ? 4 : 8;
                size_t nl = 0; while (fname[nl]) nl++;
                if (nl > FUT_VFS_NAME_MAX) nl = FUT_VFS_NAME_MAX;
                memcpy(dirent->d_name, fname, nl);
                dirent->d_name[nl] = '\0';
                *cookie = pos;
                return 1;
            }
        }
    }
    return -ENOENT;
}

static int exfat_ro1(struct fut_vnode *d, const char *n, uint32_t m, struct fut_vnode **r)
    { (void)d;(void)n;(void)m;(void)r; return -EROFS; }
static int exfat_ro2(struct fut_vnode *d, const char *n)
    { (void)d;(void)n; return -EROFS; }
static int exfat_ro3(struct fut_vnode *d, const char *n, uint32_t m)
    { (void)d;(void)n;(void)m; return -EROFS; }
static int exfat_ro4(struct fut_vnode *d, const char *o, const char *n)
    { (void)d;(void)o;(void)n; return -EROFS; }

static struct fut_vnode_ops exfat_vnode_ops;

static struct fut_vnode *exfat_alloc_vnode(struct exfat_mount_info *ei,
                                           uint32_t cluster, uint64_t size,
                                           uint16_t attr, struct fut_mount *mnt) {
    struct fut_vnode *vn = fut_malloc(sizeof(struct fut_vnode));
    if (!vn) return NULL;
    memset(vn, 0, sizeof(*vn));
    struct exfat_vnode_info *vi = fut_malloc(sizeof(struct exfat_vnode_info));
    if (!vi) { fut_free(vn); return NULL; }
    vi->first_cluster = cluster;
    vi->file_size = size;
    vi->attributes = attr;
    vi->ei = ei;
    vn->fs_data = vi;
    vn->ops = &exfat_vnode_ops;
    vn->mount = mnt;
    vn->ino = cluster ? cluster : 1;
    vn->size = size;
    vn->mode = (attr & EXFAT_ATTR_DIRECTORY) ? 0040755 : 0100644;
    vn->nlinks = 1;
    vn->refcount = 1;
    vn->type = (attr & EXFAT_ATTR_DIRECTORY) ? VN_DIR : VN_REG;
    return vn;
}

/* ============================================================
 *   Filesystem type
 * ============================================================ */

static int exfat_mount_impl(const char *device, int flags, void *data,
                             fut_handle_t bh, struct fut_mount **mount_out) {
    (void)flags; (void)data; (void)bh;
    struct fut_blockdev *dev = fut_blockdev_find(device);
    if (!dev) return -ENODEV;

    struct exfat_boot_sector bs;
    ssize_t n = fut_blockdev_read_bytes(dev, 0, sizeof(bs), &bs);
    if (n < 0) return (int)n;

    /* Validate OEM name */
    if (bs.oem_name[0] != 'E' || bs.oem_name[1] != 'X' ||
        bs.oem_name[2] != 'F' || bs.oem_name[3] != 'A' ||
        bs.oem_name[4] != 'T')
        return -EINVAL;

    struct exfat_mount_info *ei = fut_malloc(sizeof(struct exfat_mount_info));
    if (!ei) return -ENOMEM;
    memset(ei, 0, sizeof(*ei));

    ei->dev = dev;
    ei->bytes_per_sector = 1u << bs.bytes_per_sector_shift;
    ei->sectors_per_cluster = 1u << bs.sectors_per_cluster_shift;
    ei->cluster_size = ei->bytes_per_sector * ei->sectors_per_cluster;
    ei->fat_offset = bs.fat_offset;
    ei->cluster_heap_offset = bs.cluster_heap_offset;
    ei->cluster_count = bs.cluster_count;
    ei->root_cluster = bs.root_dir_cluster;
    ei->volume_length = bs.volume_length;

    struct fut_mount *mnt = fut_malloc(sizeof(struct fut_mount));
    if (!mnt) { fut_free(ei); return -ENOMEM; }
    memset(mnt, 0, sizeof(*mnt));
    mnt->fs_data = ei;

    struct fut_vnode *root = exfat_alloc_vnode(ei, ei->root_cluster, 0,
                                               EXFAT_ATTR_DIRECTORY, mnt);
    if (!root) { fut_free(ei); fut_free(mnt); return -EIO; }
    mnt->root = root;

    *mount_out = mnt;
    fut_printf("[EXFAT] Mounted: %u clusters, %u bytes/cluster\n",
               ei->cluster_count, ei->cluster_size);
    return 0;
}

static int exfat_unmount_impl(struct fut_mount *m) {
    if (m->fs_data) fut_free(m->fs_data);
    return 0;
}

static int exfat_statfs_impl(struct fut_mount *m, struct fut_statfs *out) {
    struct exfat_mount_info *ei = (struct exfat_mount_info *)m->fs_data;
    if (!ei || !out) return -EINVAL;
    memset(out, 0, sizeof(*out));
    out->block_size = ei->cluster_size;
    out->blocks_total = ei->cluster_count;
    return 0;
}

static struct fut_fs_type exfat_fs_type;

void exfat_init(void) {
    exfat_vnode_ops.read = exfat_vnode_read;
    exfat_vnode_ops.write = exfat_vnode_write;
    exfat_vnode_ops.lookup = exfat_vnode_lookup;
    exfat_vnode_ops.readdir = exfat_vnode_readdir;
    exfat_vnode_ops.create = exfat_ro1;
    exfat_vnode_ops.unlink = exfat_ro2;
    exfat_vnode_ops.mkdir = exfat_ro3;
    exfat_vnode_ops.rename = exfat_ro4;

    exfat_fs_type.name = "exfat";
    exfat_fs_type.mount = exfat_mount_impl;
    exfat_fs_type.unmount = exfat_unmount_impl;
    exfat_fs_type.statfs = exfat_statfs_impl;

    extern int fut_vfs_register_fs(const struct fut_fs_type *);
    fut_vfs_register_fs(&exfat_fs_type);

    fut_printf("[EXFAT] exFAT filesystem driver registered\n");
}
