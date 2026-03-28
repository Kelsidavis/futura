/* kernel/fs/ext2.c - Read-only ext2 filesystem driver
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements a read-only ext2 filesystem driver that can mount real Linux
 * disk images. Supports: directory listing, file reading, stat, symlinks,
 * and indirect block resolution. No write support (returns EROFS).
 *
 * Usage:
 *   mount("/dev/loop0", "/mnt", "ext2", MS_RDONLY, NULL)
 */

#include <kernel/ext2.h>
#include <kernel/fut_vfs.h>
#include <kernel/fut_blockdev.h>
#include <kernel/fut_memory.h>
#include <kernel/kprintf.h>
#include <kernel/errno.h>
#include <stddef.h>
#include <string.h>

/* ============================================================
 *   Block I/O helpers
 * ============================================================ */

static ssize_t ext2_read_bytes(struct ext2_mount_info *mi, uint64_t offset,
                               size_t size, void *buf) {
    return fut_blockdev_read_bytes(mi->dev, offset, size, buf);
}

/* ============================================================
 *   Inode reading
 * ============================================================ */

static int ext2_read_inode(struct ext2_mount_info *mi, uint32_t ino,
                           struct ext2_inode *out) {
    if (ino == 0 || ino > mi->inodes_count) return -EINVAL;

    uint32_t group = (ino - 1) / mi->inodes_per_group;
    uint32_t local = (ino - 1) % mi->inodes_per_group;

    if (group >= mi->group_count) return -EINVAL;

    uint32_t inode_table = mi->group_descs[group].bg_inode_table;
    uint64_t byte_offset = (uint64_t)inode_table * mi->block_size +
                           (uint64_t)local * mi->inode_size;

    ssize_t n = ext2_read_bytes(mi, byte_offset, sizeof(struct ext2_inode), out);
    return n < 0 ? (int)n : 0;
}

/* ============================================================
 *   Block mapping (direct + indirect)
 * ============================================================ */

static uint32_t ext2_block_for_offset(struct ext2_mount_info *mi,
                                       struct ext2_inode *inode,
                                       uint64_t file_offset) {
    uint32_t block_index = (uint32_t)(file_offset / mi->block_size);
    uint32_t ptrs_per_block = mi->block_size / 4;

    /* Direct blocks (0-11) */
    if (block_index < 12)
        return inode->i_block[block_index];

    block_index -= 12;

    /* Single indirect (12) */
    if (block_index < ptrs_per_block) {
        uint32_t indirect_block = inode->i_block[12];
        if (indirect_block == 0) return 0;
        uint32_t ptr;
        ext2_read_bytes(mi, (uint64_t)indirect_block * mi->block_size +
                        (uint64_t)block_index * 4, 4, &ptr);
        return ptr;
    }

    block_index -= ptrs_per_block;

    /* Double indirect (13) */
    if (block_index < ptrs_per_block * ptrs_per_block) {
        uint32_t dind_block = inode->i_block[13];
        if (dind_block == 0) return 0;
        uint32_t first = block_index / ptrs_per_block;
        uint32_t second = block_index % ptrs_per_block;
        uint32_t ind_block;
        ext2_read_bytes(mi, (uint64_t)dind_block * mi->block_size +
                        (uint64_t)first * 4, 4, &ind_block);
        if (ind_block == 0) return 0;
        uint32_t ptr;
        ext2_read_bytes(mi, (uint64_t)ind_block * mi->block_size +
                        (uint64_t)second * 4, 4, &ptr);
        return ptr;
    }

    block_index -= ptrs_per_block * ptrs_per_block;

    /* Triple indirect (14) */
    uint64_t tind_capacity = (uint64_t)ptrs_per_block * ptrs_per_block * ptrs_per_block;
    if (block_index < tind_capacity) {
        uint32_t tind_block = inode->i_block[14];
        if (tind_block == 0) return 0;
        uint32_t first  = (uint32_t)(block_index / ((uint64_t)ptrs_per_block * ptrs_per_block));
        uint32_t rem    = (uint32_t)(block_index % ((uint64_t)ptrs_per_block * ptrs_per_block));
        uint32_t second = rem / ptrs_per_block;
        uint32_t third  = rem % ptrs_per_block;
        uint32_t dind;
        ext2_read_bytes(mi, (uint64_t)tind_block * mi->block_size +
                        (uint64_t)first * 4, 4, &dind);
        if (dind == 0) return 0;
        uint32_t ind;
        ext2_read_bytes(mi, (uint64_t)dind * mi->block_size +
                        (uint64_t)second * 4, 4, &ind);
        if (ind == 0) return 0;
        uint32_t ptr;
        ext2_read_bytes(mi, (uint64_t)ind * mi->block_size +
                        (uint64_t)third * 4, 4, &ptr);
        return ptr;
    }

    return 0; /* Block index exceeds maximum ext2 file size */
}

/* ============================================================
 *   VFS vnode operations
 * ============================================================ */

/* Per-vnode private data */
struct ext2_vnode_info {
    uint32_t ino;
    struct ext2_inode inode;
    struct ext2_mount_info *mi;
};

static ssize_t ext2_vnode_read(struct fut_vnode *vnode, void *buf,
                               size_t size, uint64_t offset) {
    struct ext2_vnode_info *vi = (struct ext2_vnode_info *)vnode->fs_data;
    if (!vi) return -EIO;

    uint32_t file_size = vi->inode.i_size;
    if (offset >= file_size) return 0;
    if (offset + size > file_size) size = file_size - (size_t)offset;

    size_t total = 0;
    uint8_t *out = (uint8_t *)buf;

    while (total < size) {
        uint32_t blk = ext2_block_for_offset(vi->mi, &vi->inode, offset + total);
        if (blk == 0) {
            /* Sparse block — fill with zeros */
            size_t chunk = vi->mi->block_size - ((offset + total) % vi->mi->block_size);
            if (chunk > size - total) chunk = size - total;
            memset(out + total, 0, chunk);
            total += chunk;
            continue;
        }

        uint64_t blk_off = (uint64_t)blk * vi->mi->block_size;
        uint32_t off_in_block = (uint32_t)((offset + total) % vi->mi->block_size);
        size_t chunk = vi->mi->block_size - off_in_block;
        if (chunk > size - total) chunk = size - total;

        ssize_t n = ext2_read_bytes(vi->mi, blk_off + off_in_block, chunk, out + total);
        if (n < 0) return n;
        total += (size_t)n;
    }

    return (ssize_t)total;
}

static ssize_t ext2_vnode_write(struct fut_vnode *vnode, const void *buf,
                                size_t size, uint64_t offset) {
    (void)vnode; (void)buf; (void)size; (void)offset;
    return -EROFS;  /* Read-only filesystem */
}

static struct fut_vnode *ext2_alloc_vnode(struct ext2_mount_info *mi,
                                          uint32_t ino, struct fut_mount *mnt);

static int ext2_vnode_lookup(struct fut_vnode *dir, const char *name,
                             struct fut_vnode **result) {
    struct ext2_vnode_info *vi = (struct ext2_vnode_info *)dir->fs_data;
    if (!vi || (vi->inode.i_mode & 0xF000) != EXT2_S_IFDIR) return -ENOTDIR;

    size_t name_len = 0;
    while (name[name_len]) name_len++;

    /* Scan directory entries */
    uint32_t dir_size = vi->inode.i_size;
    uint32_t pos = 0;
    static uint8_t dirbuf[4096];

    while (pos < dir_size) {
        uint32_t blk = ext2_block_for_offset(vi->mi, &vi->inode, pos);
        if (blk == 0) break;

        ext2_read_bytes(vi->mi, (uint64_t)blk * vi->mi->block_size,
                        vi->mi->block_size < sizeof(dirbuf) ? vi->mi->block_size : sizeof(dirbuf),
                        dirbuf);

        uint32_t blk_pos = 0;
        while (blk_pos < vi->mi->block_size && pos + blk_pos < dir_size) {
            struct ext2_dir_entry *de = (struct ext2_dir_entry *)(dirbuf + blk_pos);
            if (de->rec_len == 0) break;

            if (de->inode != 0 && de->name_len == name_len) {
                bool match = true;
                for (size_t i = 0; i < name_len; i++) {
                    if (de->name[i] != name[i]) { match = false; break; }
                }
                if (match) {
                    *result = ext2_alloc_vnode(vi->mi, de->inode, dir->mount);
                    if (!*result) return -ENOMEM;
                    (*result)->parent = dir;
                    /* Store name for path reconstruction */
                    char *ndup = fut_malloc(name_len + 1);
                    if (ndup) { memcpy(ndup, name, name_len); ndup[name_len] = '\0'; }
                    (*result)->name = ndup;
                    return 0;
                }
            }
            blk_pos += de->rec_len;
        }
        pos += vi->mi->block_size;
    }

    return -ENOENT;
}

static int ext2_vnode_readdir(struct fut_vnode *dir, uint64_t *cookie,
                              struct fut_vdirent *dirent) {
    struct ext2_vnode_info *vi = (struct ext2_vnode_info *)dir->fs_data;
    if (!vi) return -EIO;

    uint32_t dir_size = vi->inode.i_size;
    uint32_t pos = (uint32_t)*cookie;
    static uint8_t dirbuf[4096];

    while (pos < dir_size) {
        uint32_t blk = ext2_block_for_offset(vi->mi, &vi->inode, pos);
        if (blk == 0) { pos += vi->mi->block_size; continue; }

        uint32_t off_in_block = pos % vi->mi->block_size;
        ext2_read_bytes(vi->mi, (uint64_t)blk * vi->mi->block_size,
                        vi->mi->block_size < sizeof(dirbuf) ? vi->mi->block_size : sizeof(dirbuf),
                        dirbuf);

        struct ext2_dir_entry *de = (struct ext2_dir_entry *)(dirbuf + off_in_block);
        if (de->rec_len == 0) return -ENOENT;

        pos += de->rec_len;

        if (de->inode == 0) continue;  /* Deleted entry */

        dirent->d_ino = de->inode;
        dirent->d_off = pos;
        dirent->d_reclen = sizeof(*dirent);
        /* Map ext2 file_type to DT_* constants */
        switch (de->file_type) {
        case EXT2_FT_REG_FILE: dirent->d_type = 8;  break; /* DT_REG  */
        case EXT2_FT_DIR:      dirent->d_type = 4;  break; /* DT_DIR  */
        case EXT2_FT_CHRDEV:   dirent->d_type = 2;  break; /* DT_CHR  */
        case EXT2_FT_BLKDEV:   dirent->d_type = 6;  break; /* DT_BLK  */
        case EXT2_FT_FIFO:     dirent->d_type = 1;  break; /* DT_FIFO */
        case EXT2_FT_SOCK:     dirent->d_type = 12; break; /* DT_SOCK */
        case EXT2_FT_SYMLINK:  dirent->d_type = 10; break; /* DT_LNK  */
        default:               dirent->d_type = 0;  break; /* DT_UNKNOWN */
        }

        size_t nlen = de->name_len;
        if (nlen > FUT_VFS_NAME_MAX) nlen = FUT_VFS_NAME_MAX;
        memcpy(dirent->d_name, de->name, nlen);
        dirent->d_name[nlen] = '\0';

        *cookie = pos;
        return 1;
    }

    return -ENOENT;
}

static ssize_t ext2_vnode_readlink(struct fut_vnode *vnode, char *buf, size_t bufsz) {
    struct ext2_vnode_info *vi = (struct ext2_vnode_info *)vnode->fs_data;
    if (!vi) return -EIO;
    if ((vi->inode.i_mode & 0xF000) != EXT2_S_IFLNK) return -EINVAL;

    uint32_t link_size = vi->inode.i_size;
    if (link_size > bufsz) link_size = (uint32_t)bufsz;

    /* Short symlinks (< 60 bytes) are stored inline in i_block[] */
    if (vi->inode.i_size < 60 && vi->inode.i_blocks == 0) {
        memcpy(buf, (const char *)vi->inode.i_block, link_size);
        return (int)link_size;
    }

    /* Long symlinks are in data blocks */
    ssize_t n = ext2_vnode_read(vnode, buf, link_size, 0);
    return n < 0 ? (int)n : (int)n;
}

static int ext2_vnode_getattr(struct fut_vnode *vnode, struct fut_stat *stat) {
    struct ext2_vnode_info *vi = (struct ext2_vnode_info *)vnode->fs_data;
    if (!vi || !stat) return -EINVAL;
    memset(stat, 0, sizeof(*stat));
    stat->st_ino = vi->ino;
    stat->st_mode = vi->inode.i_mode;
    stat->st_nlink = vi->inode.i_links_count;
    stat->st_uid = vi->inode.i_uid;
    stat->st_gid = vi->inode.i_gid;
    stat->st_size = vi->inode.i_size;
    stat->st_blocks = vi->inode.i_blocks;
    stat->st_blksize = vi->mi->block_size;
    stat->st_atime = vi->inode.i_atime;
    stat->st_mtime = vi->inode.i_mtime;
    stat->st_ctime = vi->inode.i_ctime;
    return 0;
}

/* Read-only: reject all write operations */
static int ext2_vnode_create(struct fut_vnode *d, const char *n, uint32_t m, struct fut_vnode **r) {
    (void)d; (void)n; (void)m; (void)r; return -EROFS; }
static int ext2_vnode_unlink(struct fut_vnode *d, const char *n) {
    (void)d; (void)n; return -EROFS; }
static int ext2_vnode_mkdir(struct fut_vnode *d, const char *n, uint32_t m) {
    (void)d; (void)n; (void)m; return -EROFS; }
static int ext2_vnode_rename(struct fut_vnode *d, const char *o, const char *n) {
    (void)d; (void)o; (void)n; return -EROFS; }

static struct fut_vnode_ops ext2_vnode_ops;

static struct fut_vnode *ext2_alloc_vnode(struct ext2_mount_info *mi,
                                          uint32_t ino, struct fut_mount *mnt) {
    struct ext2_inode disk_inode;
    if (ext2_read_inode(mi, ino, &disk_inode) < 0) return NULL;

    struct fut_vnode *vnode = fut_malloc(sizeof(struct fut_vnode));
    if (!vnode) return NULL;
    memset(vnode, 0, sizeof(struct fut_vnode));

    struct ext2_vnode_info *vi = fut_malloc(sizeof(struct ext2_vnode_info));
    if (!vi) { fut_free(vnode); return NULL; }
    vi->ino = ino;
    vi->inode = disk_inode;
    vi->mi = mi;

    vnode->fs_data = vi;
    vnode->ops = &ext2_vnode_ops;
    vnode->mount = mnt;
    vnode->ino = ino;
    vnode->mode = disk_inode.i_mode;
    vnode->uid = disk_inode.i_uid;
    vnode->gid = disk_inode.i_gid;
    vnode->size = disk_inode.i_size;
    vnode->nlinks = disk_inode.i_links_count;
    vnode->refcount = 1;

    uint16_t ftype = disk_inode.i_mode & 0xF000;
    if (ftype == EXT2_S_IFDIR) vnode->type = VN_DIR;
    else if (ftype == EXT2_S_IFLNK) vnode->type = VN_LNK;
    else vnode->type = VN_REG;

    return vnode;
}

/* ============================================================
 *   Filesystem type (mount/unmount/statfs)
 * ============================================================ */

static int ext2_mount_impl(const char *device, int flags, void *data,
                            fut_handle_t block_device_handle,
                            struct fut_mount **mount_out) {
    (void)flags; (void)data; (void)block_device_handle;

    struct fut_blockdev *dev = fut_blockdev_find(device);
    if (!dev) return -ENODEV;

    /* Read superblock at byte offset 1024 */
    struct ext2_super_block sb;
    ssize_t n = fut_blockdev_read_bytes(dev, EXT2_SUPER_OFFSET, sizeof(sb), &sb);
    if (n < 0) return (int)n;

    if (sb.s_magic != EXT2_SUPER_MAGIC) {
        fut_printf("[EXT2] Bad magic: 0x%x (expected 0xEF53)\n", sb.s_magic);
        return -EINVAL;
    }

    /* Validate block size (log must be 0-6, i.e. 1KB-64KB) */
    if (sb.s_log_block_size > EXT2_MAX_LOG_BLOCK_SIZE) {
        fut_printf("[EXT2] Invalid log_block_size: %u (max %u)\n",
                   sb.s_log_block_size, EXT2_MAX_LOG_BLOCK_SIZE);
        return -EINVAL;
    }

    uint32_t block_size = 1024u << sb.s_log_block_size;

    /* Reject zero blocks_per_group (would cause division by zero) */
    if (sb.s_blocks_per_group == 0 || sb.s_inodes_per_group == 0) {
        fut_printf("[EXT2] Invalid: blocks_per_group=%u inodes_per_group=%u\n",
                   sb.s_blocks_per_group, sb.s_inodes_per_group);
        return -EINVAL;
    }

    /* Reject incompat features we cannot handle (extents, 64-bit) */
    uint32_t unsupported = sb.s_feature_incompat & EXT2_INCOMPAT_UNSUPPORTED;
    if (unsupported) {
        fut_printf("[EXT2] Unsupported incompat features: 0x%x (need ext4 driver)\n",
                   unsupported);
        return -EINVAL;
    }

    /* ext3 with has_journal is fine for read-only (we just ignore the journal) */
    if (sb.s_feature_compat & EXT3_FEATURE_COMPAT_HAS_JOURNAL) {
        fut_printf("[EXT2] ext3 journal detected (ignored for read-only mount)\n");
    }

    uint32_t group_count = (sb.s_blocks_count + sb.s_blocks_per_group - 1) /
                           sb.s_blocks_per_group;

    /* Allocate mount info */
    struct ext2_mount_info *mi = fut_malloc(sizeof(struct ext2_mount_info));
    if (!mi) return -ENOMEM;
    memset(mi, 0, sizeof(*mi));

    mi->dev = dev;
    mi->block_size = block_size;
    mi->inodes_per_group = sb.s_inodes_per_group;
    mi->blocks_per_group = sb.s_blocks_per_group;
    mi->inode_size = (sb.s_rev_level >= 1) ? sb.s_inode_size : 128;
    mi->group_count = group_count;
    mi->inodes_count = sb.s_inodes_count;
    mi->blocks_count = sb.s_blocks_count;
    mi->free_blocks = sb.s_free_blocks_count;
    mi->free_inodes = sb.s_free_inodes_count;
    mi->first_data_block = sb.s_first_data_block;
    mi->feature_compat = sb.s_feature_compat;
    mi->feature_incompat = sb.s_feature_incompat;
    mi->feature_ro_compat = sb.s_feature_ro_compat;

    /* Read block group descriptor table */
    uint32_t bgd_block = (block_size == 1024) ? 2 : 1;
    size_t bgd_size = group_count * sizeof(struct ext2_group_desc);
    mi->group_descs = fut_malloc(bgd_size);
    if (!mi->group_descs) { fut_free(mi); return -ENOMEM; }

    n = ext2_read_bytes(mi, (uint64_t)bgd_block * block_size, bgd_size, mi->group_descs);
    if (n < 0) { fut_free(mi->group_descs); fut_free(mi); return (int)n; }

    /* Create mount and root vnode */
    struct fut_mount *mnt = fut_malloc(sizeof(struct fut_mount));
    if (!mnt) { fut_free(mi->group_descs); fut_free(mi); return -ENOMEM; }
    memset(mnt, 0, sizeof(*mnt));
    mnt->fs_data = mi;

    struct fut_vnode *root = ext2_alloc_vnode(mi, EXT2_ROOT_INO, mnt);
    if (!root) {
        fut_free(mi->group_descs); fut_free(mi); fut_free(mnt);
        return -EIO;
    }
    mnt->root = root;

    *mount_out = mnt;

    const char *fstype = (mi->feature_compat & EXT3_FEATURE_COMPAT_HAS_JOURNAL)
                         ? "ext3" : "ext2";
    fut_printf("[EXT2] Mounted %s: %u blocks, %u inodes, bs=%u, %u groups\n",
               fstype, mi->blocks_count, mi->inodes_count, mi->block_size,
               mi->group_count);
    return 0;
}

static int ext2_unmount_impl(struct fut_mount *mount) {
    struct ext2_mount_info *mi = (struct ext2_mount_info *)mount->fs_data;
    if (mi) {
        if (mi->group_descs) fut_free(mi->group_descs);
        fut_free(mi);
    }
    return 0;
}

static int ext2_statfs_impl(struct fut_mount *mount, struct fut_statfs *out) {
    struct ext2_mount_info *mi = (struct ext2_mount_info *)mount->fs_data;
    if (!mi || !out) return -EINVAL;
    memset(out, 0, sizeof(*out));
    out->block_size = mi->block_size;
    out->blocks_total = mi->blocks_count;
    out->blocks_free = mi->free_blocks;
    out->inodes_total = mi->inodes_count;
    out->inodes_free = mi->free_inodes;
    return 0;
}

/* ============================================================
 *   Registration
 * ============================================================ */

static struct fut_fs_type ext2_fs_type;
static struct fut_fs_type ext3_fs_type;

void ext2_init(void) {
    /* Initialize vnode ops at runtime (ARM64 relocation safety) */
    ext2_vnode_ops.read = ext2_vnode_read;
    ext2_vnode_ops.write = ext2_vnode_write;
    ext2_vnode_ops.lookup = ext2_vnode_lookup;
    ext2_vnode_ops.readdir = ext2_vnode_readdir;
    ext2_vnode_ops.readlink = ext2_vnode_readlink;
    ext2_vnode_ops.create = ext2_vnode_create;
    ext2_vnode_ops.unlink = ext2_vnode_unlink;
    ext2_vnode_ops.mkdir = ext2_vnode_mkdir;
    ext2_vnode_ops.rename = ext2_vnode_rename;
    ext2_vnode_ops.getattr = ext2_vnode_getattr;

    ext2_fs_type.name = "ext2";
    ext2_fs_type.mount = ext2_mount_impl;
    ext2_fs_type.unmount = ext2_unmount_impl;
    ext2_fs_type.statfs = ext2_statfs_impl;

    /* Register ext3 as alias (same driver, journal is ignored for read-only) */
    ext3_fs_type.name = "ext3";
    ext3_fs_type.mount = ext2_mount_impl;
    ext3_fs_type.unmount = ext2_unmount_impl;
    ext3_fs_type.statfs = ext2_statfs_impl;

    extern int fut_vfs_register_fs(const struct fut_fs_type *);
    fut_vfs_register_fs(&ext2_fs_type);
    fut_vfs_register_fs(&ext3_fs_type);

    fut_printf("[EXT2] ext2/ext3 filesystem driver registered\n");
}
