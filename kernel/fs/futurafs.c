/* futurafs.c - FuturaFS Filesystem Implementation
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Native filesystem for Futura OS.
 */

#include <kernel/fut_futurafs.h>
#include <kernel/fut_memory.h>
#include <kernel/fut_vfs.h>
#include <kernel/fut_blockdev.h>

/* ============================================================
 *   Helper Functions
 * ============================================================ */

/**
 * Read superblock from device.
 */
static int futurafs_read_superblock(struct fut_blockdev *dev, struct futurafs_superblock *sb) {
    int ret = fut_blockdev_read(dev, 0, 1, sb);
    if (ret < 0) {
        return FUTURAFS_EIO;
    }

    /* Validate magic number */
    if (sb->magic != FUTURAFS_MAGIC) {
        return FUTURAFS_EINVAL;
    }

    /* Validate version */
    if (sb->version != FUTURAFS_VERSION) {
        return FUTURAFS_EINVAL;
    }

    return 0;
}

/**
 * Write superblock to device.
 */
static int futurafs_write_superblock(struct fut_blockdev *dev, struct futurafs_superblock *sb) {
    return fut_blockdev_write(dev, 0, 1, sb) < 0 ? FUTURAFS_EIO : 0;
}

/**
 * Read inode from disk.
 */
static int futurafs_read_inode(struct futurafs_mount *mount, uint64_t ino,
                               struct futurafs_inode *inode) {
    if (ino == 0 || ino > mount->sb->total_inodes) {
        return FUTURAFS_EINVAL;
    }

    /* Calculate block and offset */
    uint64_t inode_index = ino - 1;
    uint64_t block_num = mount->sb->inode_table_block + (inode_index / mount->inodes_per_block);
    uint64_t block_offset = (inode_index % mount->inodes_per_block) * FUTURAFS_INODE_SIZE;

    /* Read block containing inode */
    uint8_t block_buf[FUTURAFS_BLOCK_SIZE];
    int ret = fut_blockdev_read(mount->dev, block_num, 1, block_buf);
    if (ret < 0) {
        return FUTURAFS_EIO;
    }

    /* Copy inode data */
    uint8_t *inode_ptr = block_buf + block_offset;
    for (size_t i = 0; i < sizeof(struct futurafs_inode); i++) {
        ((uint8_t *)inode)[i] = inode_ptr[i];
    }

    return 0;
}

/**
 * Write inode to disk.
 */
static int futurafs_write_inode(struct futurafs_mount *mount, uint64_t ino,
                                struct futurafs_inode *inode) {
    if (ino == 0 || ino > mount->sb->total_inodes) {
        return FUTURAFS_EINVAL;
    }

    /* Calculate block and offset */
    uint64_t inode_index = ino - 1;
    uint64_t block_num = mount->sb->inode_table_block + (inode_index / mount->inodes_per_block);
    uint64_t block_offset = (inode_index % mount->inodes_per_block) * FUTURAFS_INODE_SIZE;

    /* Read block */
    uint8_t block_buf[FUTURAFS_BLOCK_SIZE];
    int ret = fut_blockdev_read(mount->dev, block_num, 1, block_buf);
    if (ret < 0) {
        return FUTURAFS_EIO;
    }

    /* Update inode data */
    uint8_t *inode_ptr = block_buf + block_offset;
    for (size_t i = 0; i < sizeof(struct futurafs_inode); i++) {
        inode_ptr[i] = ((uint8_t *)inode)[i];
    }

    /* Write block back */
    ret = fut_blockdev_write(mount->dev, block_num, 1, block_buf);
    if (ret < 0) {
        return FUTURAFS_EIO;
    }

    return 0;
}

/**
 * Allocate a new inode.
 */
__attribute__((unused))
static int futurafs_alloc_inode(struct futurafs_mount *mount, uint64_t *ino_out) {
    if (mount->sb->free_inodes == 0) {
        return FUTURAFS_ENOSPC;
    }

    /* Search bitmap for free inode */
    for (uint64_t i = 0; i < mount->sb->total_inodes; i++) {
        uint64_t byte_index = i / 8;
        uint64_t bit_index = i % 8;

        if ((mount->inode_bitmap[byte_index] & (1 << bit_index)) == 0) {
            /* Found free inode */
            mount->inode_bitmap[byte_index] |= (1 << bit_index);
            mount->sb->free_inodes--;
            mount->dirty = true;

            *ino_out = i + 1;  /* Inode numbers start at 1 */
            return 0;
        }
    }

    return FUTURAFS_ENOSPC;
}

/**
 * Free an inode.
 */
__attribute__((unused))
static int futurafs_free_inode(struct futurafs_mount *mount, uint64_t ino) {
    if (ino == 0 || ino > mount->sb->total_inodes) {
        return FUTURAFS_EINVAL;
    }

    uint64_t inode_index = ino - 1;
    uint64_t byte_index = inode_index / 8;
    uint64_t bit_index = inode_index % 8;

    mount->inode_bitmap[byte_index] &= ~(1 << bit_index);
    mount->sb->free_inodes++;
    mount->dirty = true;

    return 0;
}

/**
 * Allocate a data block.
 */
static int futurafs_alloc_block(struct futurafs_mount *mount, uint64_t *block_out) {
    if (mount->sb->free_blocks == 0) {
        return FUTURAFS_ENOSPC;
    }

    uint64_t total_data_blocks = mount->sb->total_blocks - mount->sb->data_blocks_start;

    /* Search bitmap for free block */
    for (uint64_t i = 0; i < total_data_blocks; i++) {
        uint64_t byte_index = i / 8;
        uint64_t bit_index = i % 8;

        if ((mount->data_bitmap[byte_index] & (1 << bit_index)) == 0) {
            /* Found free block */
            mount->data_bitmap[byte_index] |= (1 << bit_index);
            mount->sb->free_blocks--;
            mount->dirty = true;

            *block_out = mount->sb->data_blocks_start + i;
            return 0;
        }
    }

    return FUTURAFS_ENOSPC;
}

/**
 * Free a data block.
 */
__attribute__((unused))
static int futurafs_free_block(struct futurafs_mount *mount, uint64_t block_num) {
    if (block_num < mount->sb->data_blocks_start || block_num >= mount->sb->total_blocks) {
        return FUTURAFS_EINVAL;
    }

    uint64_t block_index = block_num - mount->sb->data_blocks_start;
    uint64_t byte_index = block_index / 8;
    uint64_t bit_index = block_index % 8;

    mount->data_bitmap[byte_index] &= ~(1 << bit_index);
    mount->sb->free_blocks++;
    mount->dirty = true;

    return 0;
}

/* ============================================================
 *   VNode Operations
 * ============================================================ */

static ssize_t futurafs_vnode_read(struct fut_vnode *vnode, void *buf, size_t size, uint64_t offset) {
    struct futurafs_inode_info *inode_info = (struct futurafs_inode_info *)vnode->fs_data;
    struct futurafs_inode *disk_inode = &inode_info->disk_inode;

    if (offset >= disk_inode->size) {
        return 0;  /* EOF */
    }

    /* Limit read to file size */
    if (offset + size > disk_inode->size) {
        size = disk_inode->size - offset;
    }

    size_t bytes_read = 0;
    uint8_t block_buf[FUTURAFS_BLOCK_SIZE];

    while (bytes_read < size) {
        uint64_t file_block = (offset + bytes_read) / FUTURAFS_BLOCK_SIZE;
        uint64_t block_offset = (offset + bytes_read) % FUTURAFS_BLOCK_SIZE;
        size_t to_read = FUTURAFS_BLOCK_SIZE - block_offset;
        if (to_read > size - bytes_read) {
            to_read = size - bytes_read;
        }

        /* Get block number */
        uint64_t block_num;
        if (file_block < FUTURAFS_DIRECT_BLOCKS) {
            block_num = disk_inode->direct[file_block];
        } else {
            /* TODO: Implement indirect blocks */
            return bytes_read;
        }

        if (block_num == 0) {
            /* Sparse block - return zeros */
            uint8_t *dest = (uint8_t *)buf + bytes_read;
            for (size_t i = 0; i < to_read; i++) {
                dest[i] = 0;
            }
        } else {
            /* Read block */
            int ret = fut_blockdev_read(inode_info->mount->dev, block_num, 1, block_buf);
            if (ret < 0) {
                return bytes_read > 0 ? (int)bytes_read : FUTURAFS_EIO;
            }

            /* Copy data */
            uint8_t *dest = (uint8_t *)buf + bytes_read;
            for (size_t i = 0; i < to_read; i++) {
                dest[i] = block_buf[block_offset + i];
            }
        }

        bytes_read += to_read;
    }

    return (int)bytes_read;
}

static ssize_t futurafs_vnode_write(struct fut_vnode *vnode, const void *buf, size_t size, uint64_t offset) {
    struct futurafs_inode_info *inode_info = (struct futurafs_inode_info *)vnode->fs_data;
    struct futurafs_inode *disk_inode = &inode_info->disk_inode;

    size_t bytes_written = 0;
    uint8_t block_buf[FUTURAFS_BLOCK_SIZE];

    while (bytes_written < size) {
        uint64_t file_block = (offset + bytes_written) / FUTURAFS_BLOCK_SIZE;
        uint64_t block_offset = (offset + bytes_written) % FUTURAFS_BLOCK_SIZE;
        size_t to_write = FUTURAFS_BLOCK_SIZE - block_offset;
        if (to_write > size - bytes_written) {
            to_write = size - bytes_written;
        }

        /* Get or allocate block */
        uint64_t block_num;
        if (file_block < FUTURAFS_DIRECT_BLOCKS) {
            block_num = disk_inode->direct[file_block];
            if (block_num == 0) {
                /* Allocate new block */
                int ret = futurafs_alloc_block(inode_info->mount, &block_num);
                if (ret < 0) {
                    return bytes_written > 0 ? (int)bytes_written : ret;
                }
                disk_inode->direct[file_block] = block_num;
                disk_inode->blocks++;
                inode_info->dirty = true;
            }
        } else {
            /* TODO: Implement indirect blocks */
            return bytes_written > 0 ? (int)bytes_written : FUTURAFS_ENOSPC;
        }

        /* Read block if partial write */
        if (block_offset != 0 || to_write != FUTURAFS_BLOCK_SIZE) {
            int ret = fut_blockdev_read(inode_info->mount->dev, block_num, 1, block_buf);
            if (ret < 0) {
                return bytes_written > 0 ? (int)bytes_written : FUTURAFS_EIO;
            }
        }

        /* Update block data */
        const uint8_t *src = (const uint8_t *)buf + bytes_written;
        for (size_t i = 0; i < to_write; i++) {
            block_buf[block_offset + i] = src[i];
        }

        /* Write block */
        int ret = fut_blockdev_write(inode_info->mount->dev, block_num, 1, block_buf);
        if (ret < 0) {
            return bytes_written > 0 ? (int)bytes_written : FUTURAFS_EIO;
        }

        bytes_written += to_write;
    }

    /* Update file size if needed */
    if (offset + bytes_written > disk_inode->size) {
        disk_inode->size = offset + bytes_written;
        inode_info->dirty = true;
    }

    /* Sync inode to disk */
    if (inode_info->dirty) {
        futurafs_write_inode(inode_info->mount, inode_info->ino, disk_inode);
        inode_info->dirty = false;
    }

    return (int)bytes_written;
}

static int futurafs_vnode_lookup(struct fut_vnode *dir, const char *name, struct fut_vnode **result) {
    /* TODO: Implement directory lookup */
    (void)dir;
    (void)name;
    (void)result;
    return FUTURAFS_ENOENT;
}

static int futurafs_vnode_create(struct fut_vnode *dir, const char *name, uint32_t mode,
                                 struct fut_vnode **result) {
    /* TODO: Implement file creation */
    (void)dir;
    (void)name;
    (void)mode;
    (void)result;
    return FUTURAFS_ENOSPC;
}

static int futurafs_vnode_mkdir(struct fut_vnode *dir, const char *name, uint32_t mode) {
    /* TODO: Implement directory creation */
    (void)dir;
    (void)name;
    (void)mode;
    return FUTURAFS_ENOSPC;
}

static const struct fut_vnode_ops futurafs_vnode_ops = {
    .open = NULL,
    .close = NULL,
    .read = futurafs_vnode_read,
    .write = futurafs_vnode_write,
    .lookup = futurafs_vnode_lookup,
    .create = futurafs_vnode_create,
    .unlink = NULL,
    .mkdir = futurafs_vnode_mkdir,
    .rmdir = NULL,
    .getattr = NULL,
    .setattr = NULL,
};

/* ============================================================
 *   Filesystem Operations
 * ============================================================ */

static int futurafs_mount_impl(const char *device, int flags, void *data, struct fut_mount **mount_out) {
    (void)flags;
    (void)data;

    /* Find block device */
    struct fut_blockdev *dev = fut_blockdev_find(device);
    if (!dev) {
        return FUTURAFS_ENOENT;
    }

    /* Allocate mount structure */
    struct futurafs_mount *fs_mount = fut_malloc(sizeof(struct futurafs_mount));
    if (!fs_mount) {
        return FUTURAFS_EIO;
    }

    /* Allocate superblock */
    fs_mount->sb = fut_malloc(sizeof(struct futurafs_superblock));
    if (!fs_mount->sb) {
        fut_free(fs_mount);
        return FUTURAFS_EIO;
    }

    /* Read superblock */
    int ret = futurafs_read_superblock(dev, fs_mount->sb);
    if (ret < 0) {
        fut_free(fs_mount->sb);
        fut_free(fs_mount);
        return ret;
    }

    fs_mount->dev = dev;
    fs_mount->inodes_per_block = FUTURAFS_BLOCK_SIZE / FUTURAFS_INODE_SIZE;
    fs_mount->dirty = false;

    /* Allocate and read inode bitmap */
    size_t inode_bitmap_size = (fs_mount->sb->total_inodes + 7) / 8;
    fs_mount->inode_bitmap = fut_malloc(inode_bitmap_size);
    if (!fs_mount->inode_bitmap) {
        fut_free(fs_mount->sb);
        fut_free(fs_mount);
        return FUTURAFS_EIO;
    }

    ret = fut_blockdev_read_bytes(dev, fs_mount->sb->inode_bitmap_block * FUTURAFS_BLOCK_SIZE,
                                   inode_bitmap_size, fs_mount->inode_bitmap);
    if (ret < 0) {
        fut_free(fs_mount->inode_bitmap);
        fut_free(fs_mount->sb);
        fut_free(fs_mount);
        return FUTURAFS_EIO;
    }

    /* Allocate and read data bitmap */
    size_t data_bitmap_size = ((fs_mount->sb->total_blocks - fs_mount->sb->data_blocks_start) + 7) / 8;
    fs_mount->data_bitmap = fut_malloc(data_bitmap_size);
    if (!fs_mount->data_bitmap) {
        fut_free(fs_mount->inode_bitmap);
        fut_free(fs_mount->sb);
        fut_free(fs_mount);
        return FUTURAFS_EIO;
    }

    ret = fut_blockdev_read_bytes(dev, fs_mount->sb->data_bitmap_block * FUTURAFS_BLOCK_SIZE,
                                   data_bitmap_size, fs_mount->data_bitmap);
    if (ret < 0) {
        fut_free(fs_mount->data_bitmap);
        fut_free(fs_mount->inode_bitmap);
        fut_free(fs_mount->sb);
        fut_free(fs_mount);
        return FUTURAFS_EIO;
    }

    /* Create VFS mount structure */
    struct fut_mount *vfs_mount = fut_malloc(sizeof(struct fut_mount));
    if (!vfs_mount) {
        fut_free(fs_mount->data_bitmap);
        fut_free(fs_mount->inode_bitmap);
        fut_free(fs_mount->sb);
        fut_free(fs_mount);
        return FUTURAFS_EIO;
    }

    vfs_mount->device = device;
    vfs_mount->mountpoint = "/";
    vfs_mount->fs = NULL;  /* Will be set by VFS */
    vfs_mount->fs_data = fs_mount;
    vfs_mount->flags = flags;
    vfs_mount->next = NULL;

    /* Create root vnode */
    struct fut_vnode *root_vnode = fut_malloc(sizeof(struct fut_vnode));
    if (!root_vnode) {
        fut_free(vfs_mount);
        fut_free(fs_mount->data_bitmap);
        fut_free(fs_mount->inode_bitmap);
        fut_free(fs_mount->sb);
        fut_free(fs_mount);
        return FUTURAFS_EIO;
    }

    /* Read root inode */
    struct futurafs_inode_info *root_info = fut_malloc(sizeof(struct futurafs_inode_info));
    if (!root_info) {
        fut_free(root_vnode);
        fut_free(vfs_mount);
        fut_free(fs_mount->data_bitmap);
        fut_free(fs_mount->inode_bitmap);
        fut_free(fs_mount->sb);
        fut_free(fs_mount);
        return FUTURAFS_EIO;
    }

    ret = futurafs_read_inode(fs_mount, FUTURAFS_ROOT_INO, &root_info->disk_inode);
    if (ret < 0) {
        fut_free(root_info);
        fut_free(root_vnode);
        fut_free(vfs_mount);
        fut_free(fs_mount->data_bitmap);
        fut_free(fs_mount->inode_bitmap);
        fut_free(fs_mount->sb);
        fut_free(fs_mount);
        return ret;
    }

    root_info->ino = FUTURAFS_ROOT_INO;
    root_info->mount = fs_mount;
    root_info->dirty = false;

    root_vnode->type = VN_DIR;
    root_vnode->ino = FUTURAFS_ROOT_INO;
    root_vnode->mode = root_info->disk_inode.mode;
    root_vnode->size = root_info->disk_inode.size;
    root_vnode->nlinks = root_info->disk_inode.nlinks;
    root_vnode->mount = vfs_mount;
    root_vnode->fs_data = root_info;
    root_vnode->refcount = 1;
    root_vnode->ops = &futurafs_vnode_ops;

    vfs_mount->root = root_vnode;

    *mount_out = vfs_mount;
    return 0;
}

static int futurafs_unmount_impl(struct fut_mount *mount) {
    struct futurafs_mount *fs_mount = (struct futurafs_mount *)mount->fs_data;

    /* Sync if dirty */
    if (fs_mount->dirty) {
        futurafs_write_superblock(fs_mount->dev, fs_mount->sb);
    }

    /* Free resources */
    if (fs_mount->data_bitmap) {
        fut_free(fs_mount->data_bitmap);
    }
    if (fs_mount->inode_bitmap) {
        fut_free(fs_mount->inode_bitmap);
    }
    if (fs_mount->sb) {
        fut_free(fs_mount->sb);
    }
    fut_free(fs_mount);

    return 0;
}

static const struct fut_fs_type futurafs_type = {
    .name = "futurafs",
    .mount = futurafs_mount_impl,
    .unmount = futurafs_unmount_impl,
};

/* ============================================================
 *   Public API
 * ============================================================ */

void fut_futurafs_init(void) {
    fut_vfs_register_fs(&futurafs_type);
}

int fut_futurafs_format(struct fut_blockdev *dev, const char *label, uint32_t inode_ratio) {
    if (!dev) {
        return FUTURAFS_EINVAL;
    }

    /* Use default inode ratio if not specified */
    if (inode_ratio == 0) {
        inode_ratio = 16384;  /* One inode per 16KB */
    }

    /* Calculate filesystem layout */
    uint64_t total_blocks = dev->num_blocks;
    uint64_t total_inodes = (dev->capacity / inode_ratio);
    if (total_inodes < 16) {
        total_inodes = 16;  /* Minimum inodes */
    }

    uint64_t inode_table_blocks = (total_inodes * FUTURAFS_INODE_SIZE + FUTURAFS_BLOCK_SIZE - 1) / FUTURAFS_BLOCK_SIZE;
    uint64_t inode_bitmap_block = 1 + inode_table_blocks;
    uint64_t data_bitmap_block = inode_bitmap_block + 1;
    uint64_t data_blocks_start = data_bitmap_block + 1;

    /* Create superblock */
    struct futurafs_superblock sb = {0};
    sb.magic = FUTURAFS_MAGIC;
    sb.version = FUTURAFS_VERSION;
    sb.block_size = FUTURAFS_BLOCK_SIZE;
    sb.total_blocks = total_blocks;
    sb.total_inodes = total_inodes;
    sb.free_blocks = total_blocks - data_blocks_start;
    sb.free_inodes = total_inodes - 1;  /* Root inode is allocated */

    sb.inode_table_block = 1;
    sb.inode_bitmap_block = inode_bitmap_block;
    sb.data_bitmap_block = data_bitmap_block;
    sb.data_blocks_start = data_blocks_start;

    sb.mount_time = 0;
    sb.write_time = 0;
    sb.mount_count = 0;
    sb.max_mount_count = 20;

    /* Set label */
    if (label) {
        size_t i = 0;
        while (i < 63 && label[i]) {
            sb.label[i] = label[i];
            i++;
        }
        sb.label[i] = '\0';
    }

    /* Write superblock */
    int ret = futurafs_write_superblock(dev, &sb);
    if (ret < 0) {
        return ret;
    }

    /* Initialize inode table (all zeros) */
    uint8_t zero_block[FUTURAFS_BLOCK_SIZE] = {0};
    for (uint64_t i = 0; i < inode_table_blocks; i++) {
        ret = fut_blockdev_write(dev, 1 + i, 1, zero_block);
        if (ret < 0) {
            return FUTURAFS_EIO;
        }
    }

    /* Create root inode */
    struct futurafs_inode root_inode = {0};
    root_inode.mode = 0755 | 0040000;  /* S_IFDIR | 0755 */
    root_inode.uid = 0;
    root_inode.gid = 0;
    root_inode.nlinks = 2;  /* . and .. */
    root_inode.size = 0;
    root_inode.blocks = 0;

    /* Write root inode */
    ret = fut_blockdev_write_bytes(dev, (sb.inode_table_block * FUTURAFS_BLOCK_SIZE),
                                    sizeof(struct futurafs_inode), &root_inode);
    if (ret < 0) {
        return FUTURAFS_EIO;
    }

    /* Initialize inode bitmap (mark root inode as allocated) */
    size_t inode_bitmap_size = (total_inodes + 7) / 8;
    uint8_t *inode_bitmap = fut_malloc(inode_bitmap_size);
    if (!inode_bitmap) {
        return FUTURAFS_EIO;
    }

    for (size_t i = 0; i < inode_bitmap_size; i++) {
        inode_bitmap[i] = 0;
    }
    inode_bitmap[0] = 0x01;  /* Mark root inode as allocated */

    ret = fut_blockdev_write_bytes(dev, inode_bitmap_block * FUTURAFS_BLOCK_SIZE,
                                    inode_bitmap_size, inode_bitmap);
    fut_free(inode_bitmap);
    if (ret < 0) {
        return FUTURAFS_EIO;
    }

    /* Initialize data bitmap (all free) */
    size_t data_bitmap_size = ((total_blocks - data_blocks_start) + 7) / 8;
    uint8_t *data_bitmap = fut_malloc(data_bitmap_size);
    if (!data_bitmap) {
        return FUTURAFS_EIO;
    }

    for (size_t i = 0; i < data_bitmap_size; i++) {
        data_bitmap[i] = 0;
    }

    ret = fut_blockdev_write_bytes(dev, data_bitmap_block * FUTURAFS_BLOCK_SIZE,
                                    data_bitmap_size, data_bitmap);
    fut_free(data_bitmap);
    if (ret < 0) {
        return FUTURAFS_EIO;
    }

    return 0;
}
