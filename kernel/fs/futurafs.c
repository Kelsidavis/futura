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
#include <kernel/fut_timer.h>
#include <kernel/errno.h>

/* FuturaFS vnode operations - initialized at runtime to avoid ARM64 relocation issues */
static struct fut_vnode_ops futurafs_vnode_ops;

/* ============================================================
 *   I/O Transition Wrappers (Dual-Mode Support)
 * ============================================================ */

/**
 * Dual-mode block read wrapper.
 * Uses capability-based I/O if handle is available, otherwise falls back to legacy.
 */
static inline int futurafs_blk_read(struct futurafs_mount *mnt,
                                    uint64_t block_num, uint64_t num_blocks, void *buffer) {
    if (mnt->block_device_handle != FUT_INVALID_HANDLE) {
        /* Use capability-based async I/O with blocking wait */
        return fut_blk_read_sync(mnt->block_device_handle, block_num, num_blocks, buffer);
    } else {
        /* Fall back to legacy sync I/O */
        return fut_blockdev_read(mnt->dev, block_num, num_blocks, buffer);
    }
}

/**
 * Dual-mode block write wrapper.
 * Uses capability-based I/O if handle is available, otherwise falls back to legacy.
 */
static inline int futurafs_blk_write(struct futurafs_mount *mnt,
                                     uint64_t block_num, uint64_t num_blocks, const void *buffer) {
    if (mnt->block_device_handle != FUT_INVALID_HANDLE) {
        /* Use capability-based async I/O with blocking wait */
        return fut_blk_write_sync(mnt->block_device_handle, block_num, num_blocks, buffer);
    } else {
        /* Fall back to legacy sync I/O */
        return fut_blockdev_write(mnt->dev, block_num, num_blocks, buffer);
    }
}

/**
 * Dual-mode byte-level read wrapper.
 * Uses capability-based I/O if handle is available, otherwise falls back to legacy.
 */
static inline ssize_t futurafs_blk_read_bytes(struct futurafs_mount *mnt,
                                               uint64_t offset, size_t size, void *buffer) {
    if (mnt->block_device_handle != FUT_INVALID_HANDLE) {
        /* Use capability-based byte-level I/O */
        if (!buffer || size == 0) {
            return FUTURAFS_EINVAL;
        }

        /* Get device properties from mount */
        uint32_t block_size = mnt->dev->block_size;
        uint64_t capacity = mnt->dev->capacity;

        /* Check bounds */
        if (offset > UINT64_MAX - (uint64_t)size || offset + size > capacity) {
            return FUTURAFS_EINVAL;
        }

        uint64_t start_block = offset / block_size;
        uint64_t end_block = (offset + size + block_size - 1) / block_size;
        uint64_t num_blocks = end_block - start_block;

        /* Allocate temporary buffer for aligned I/O */
        void *temp_buffer = fut_malloc(num_blocks * block_size);
        if (!temp_buffer) {
            return -12;  /* ENOMEM */
        }

        /* Read blocks using capability-based API */
        int ret = fut_blk_read_sync(mnt->block_device_handle, start_block, num_blocks, temp_buffer);
        if (ret < 0) {
            fut_free(temp_buffer);
            return ret;
        }

        /* Copy relevant portion to output buffer */
        uint64_t offset_in_block = offset % block_size;
        uint8_t *src = (uint8_t *)temp_buffer + offset_in_block;
        uint8_t *dst = (uint8_t *)buffer;
        for (size_t i = 0; i < size; i++) {
            dst[i] = src[i];
        }

        fut_free(temp_buffer);
        return (ssize_t)size;
    } else {
        /* Fall back to legacy sync I/O */
        return fut_blockdev_read_bytes(mnt->dev, offset, size, buffer);
    }
}

/**
 * Dual-mode byte-level write wrapper.
 * Uses capability-based I/O if handle is available, otherwise falls back to legacy.
 */
static inline ssize_t futurafs_blk_write_bytes(struct futurafs_mount *mnt,
                                                uint64_t offset, size_t size, const void *buffer) {
    if (mnt->block_device_handle != FUT_INVALID_HANDLE) {
        /* Use capability-based byte-level I/O */
        if (!buffer || size == 0) {
            return FUTURAFS_EINVAL;
        }

        /* Get device properties from mount */
        uint32_t block_size = mnt->dev->block_size;
        uint64_t capacity = mnt->dev->capacity;
        bool read_only = mnt->dev->read_only;

        /* Check read-only */
        if (read_only) {
            return BLOCKDEV_EROFS;
        }

        /* Check bounds */
        if (offset > UINT64_MAX - (uint64_t)size || offset + size > capacity) {
            return FUTURAFS_EINVAL;
        }

        uint64_t start_block = offset / block_size;
        uint64_t end_block = (offset + size + block_size - 1) / block_size;
        uint64_t num_blocks = end_block - start_block;

        /* Allocate temporary buffer for aligned I/O */
        void *temp_buffer = fut_malloc(num_blocks * block_size);
        if (!temp_buffer) {
            return -12;  /* ENOMEM */
        }

        /* Read-modify-write: read existing blocks first */
        int ret = fut_blk_read_sync(mnt->block_device_handle, start_block, num_blocks, temp_buffer);
        if (ret < 0) {
            fut_free(temp_buffer);
            return ret;
        }

        /* Modify relevant portion */
        uint64_t offset_in_block = offset % block_size;
        uint8_t *dst = (uint8_t *)temp_buffer + offset_in_block;
        const uint8_t *src = (const uint8_t *)buffer;
        for (size_t i = 0; i < size; i++) {
            dst[i] = src[i];
        }

        /* Write blocks back using capability-based API */
        ret = fut_blk_write_sync(mnt->block_device_handle, start_block, num_blocks, temp_buffer);
        if (ret < 0) {
            fut_free(temp_buffer);
            return ret;
        }

        fut_free(temp_buffer);
        return (ssize_t)size;
    } else {
        /* Fall back to legacy sync I/O */
        return fut_blockdev_write_bytes(mnt->dev, offset, size, buffer);
    }
}

/* ============================================================
 *   Forward Declarations
 * ============================================================ */

static int futurafs_alloc_block(struct futurafs_mount *mount, uint64_t *block_out);
static int futurafs_free_block(struct futurafs_mount *mount, uint64_t block_num);

/* ============================================================
 *   Helper Functions
 * ============================================================ */

/**
 * Read superblock from device.
 */
static int futurafs_read_superblock(struct futurafs_mount *mount, struct futurafs_superblock *sb) {
    extern void fut_printf(const char *, ...);

    int ret = futurafs_blk_read(mount, 0, 1, sb);
    if (ret < 0) {
        fut_printf("[FUTURAFS] blockdev_read failed: %d\n", ret);
        return FUTURAFS_EIO;
    }

    /* Validate magic number */
    fut_printf("[FUTURAFS] magic=0x%x (expected 0x%x)\n", sb->magic, FUTURAFS_MAGIC);
    if (sb->magic != FUTURAFS_MAGIC) {
        return FUTURAFS_EINVAL;
    }

    /* Validate version */
    if (sb->version != FUTURAFS_VERSION) {
        fut_printf("[FUTURAFS] version=%u (expected %u)\n", sb->version, FUTURAFS_VERSION);
        return FUTURAFS_EINVAL;
    }

    return 0;
}

/**
 * Write superblock to device.
 */
static int futurafs_write_superblock(struct futurafs_mount *mount, struct futurafs_superblock *sb) {
    return futurafs_blk_write(mount, 0, 1, sb) < 0 ? FUTURAFS_EIO : 0;
}

/* ============================================================
 *   Async Operations (Phase 3)
 * ============================================================ */

/**
 * Superblock read completion callback.
 * Called when async superblock read completes.
 */
static void futurafs_sb_read_callback(int result, void *ctx) {
    extern void fut_printf(const char *, ...);
    struct futurafs_sb_read_ctx *sb_ctx = (struct futurafs_sb_read_ctx *)ctx;

    if (result >= 0) {
        /* Copy superblock from block buffer to output */
        for (size_t i = 0; i < sizeof(struct futurafs_superblock); i++) {
            ((uint8_t *)sb_ctx->sb)[i] = sb_ctx->block_buffer[i];
        }

        /* Validate magic number */
        fut_printf("[FUTURAFS] Async: magic=0x%x (expected 0x%x)\n",
                   sb_ctx->sb->magic, FUTURAFS_MAGIC);
        if (sb_ctx->sb->magic != FUTURAFS_MAGIC) {
            result = FUTURAFS_EINVAL;
        }
        /* Validate version */
        else if (sb_ctx->sb->version != FUTURAFS_VERSION) {
            fut_printf("[FUTURAFS] Async: version=%u (expected %u)\n",
                       sb_ctx->sb->version, FUTURAFS_VERSION);
            result = FUTURAFS_EINVAL;
        }
    }

    /* Call user callback */
    sb_ctx->base.callback(result, sb_ctx->base.callback_ctx);

    /* Free context */
    fut_free(sb_ctx);
}

/**
 * Read superblock asynchronously.
 */
int futurafs_read_superblock_async(struct futurafs_mount *mount,
                                   struct futurafs_superblock *sb,
                                   futurafs_completion_t callback,
                                   void *ctx) {
    /* Allocate async context */
    struct futurafs_sb_read_ctx *sb_ctx = fut_malloc(sizeof(*sb_ctx));
    if (!sb_ctx) {
        return -12;  /* ENOMEM */
    }

    /* Initialize context */
    sb_ctx->base.callback = callback;
    sb_ctx->base.callback_ctx = ctx;
    sb_ctx->base.mount = mount;
    sb_ctx->sb = sb;

    /* Submit async block read */
    int ret = fut_blk_read_async(mount->block_device_handle, 0, 1,
                                 sb_ctx->block_buffer,
                                 futurafs_sb_read_callback, sb_ctx);
    if (ret < 0) {
        fut_free(sb_ctx);
        return ret;
    }

    return 0;
}

/**
 * Superblock write completion callback.
 * Called when async superblock write completes.
 */
static void futurafs_sb_write_callback(int result, void *ctx) {
    struct futurafs_sb_write_ctx *sb_ctx = (struct futurafs_sb_write_ctx *)ctx;

    /* Convert block I/O error to filesystem error */
    if (result < 0) {
        result = FUTURAFS_EIO;
    }

    /* Call user callback */
    sb_ctx->base.callback(result, sb_ctx->base.callback_ctx);

    /* Free context */
    fut_free(sb_ctx);
}

/**
 * Write superblock asynchronously.
 */
int futurafs_write_superblock_async(struct futurafs_mount *mount,
                                    const struct futurafs_superblock *sb,
                                    futurafs_completion_t callback,
                                    void *ctx) {
    /* Allocate async context */
    struct futurafs_sb_write_ctx *sb_ctx = fut_malloc(sizeof(*sb_ctx));
    if (!sb_ctx) {
        return -12;  /* ENOMEM */
    }

    /* Initialize context */
    sb_ctx->base.callback = callback;
    sb_ctx->base.callback_ctx = ctx;
    sb_ctx->base.mount = mount;
    sb_ctx->sb = sb;

    /* Submit async block write */
    int ret = fut_blk_write_async(mount->block_device_handle, 0, 1,
                                  (const void *)sb,
                                  futurafs_sb_write_callback, sb_ctx);
    if (ret < 0) {
        fut_free(sb_ctx);
        return ret;
    }

    return 0;
}

/**
 * Inode read completion callback.
 * Called when async inode read completes.
 */
static void futurafs_inode_read_callback(int result, void *ctx) {
    struct futurafs_inode_read_ctx *inode_ctx = (struct futurafs_inode_read_ctx *)ctx;

    if (result >= 0) {
        /* Extract inode from block buffer */
        uint64_t inode_index = inode_ctx->ino - 1;
        uint64_t block_offset = (inode_index % inode_ctx->base.mount->inodes_per_block)
                                * FUTURAFS_INODE_SIZE;
        uint8_t *inode_ptr = inode_ctx->block_buffer + block_offset;

        /* Copy inode data */
        for (size_t i = 0; i < sizeof(struct futurafs_inode); i++) {
            ((uint8_t *)inode_ctx->inode)[i] = inode_ptr[i];
        }
    }

    /* Call user callback */
    inode_ctx->base.callback(result >= 0 ? 0 : FUTURAFS_EIO, inode_ctx->base.callback_ctx);

    /* Free context */
    fut_free(inode_ctx);
}

/**
 * Read inode asynchronously.
 */
int futurafs_read_inode_async(struct futurafs_mount *mount,
                              uint64_t ino,
                              struct futurafs_inode *inode,
                              futurafs_completion_t callback,
                              void *ctx) {
    /* Validate inode number */
    if (ino == 0 || ino > mount->sb->total_inodes) {
        return FUTURAFS_EINVAL;
    }

    /* Allocate async context */
    struct futurafs_inode_read_ctx *inode_ctx = fut_malloc(sizeof(*inode_ctx));
    if (!inode_ctx) {
        return -12;  /* ENOMEM */
    }

    /* Initialize context */
    inode_ctx->base.callback = callback;
    inode_ctx->base.callback_ctx = ctx;
    inode_ctx->base.mount = mount;
    inode_ctx->ino = ino;
    inode_ctx->inode = inode;

    /* Calculate block number */
    uint64_t inode_index = ino - 1;
    uint64_t block_num = mount->sb->inode_table_block + (inode_index / mount->inodes_per_block);

    /* Check if we have a valid handle; if not, use synchronous blockdev read as fallback */
    if (mount->block_device_handle == FUT_INVALID_HANDLE) {
        /* Fallback: use synchronous blockdev API and call callback directly */
        int ret = fut_blockdev_read(mount->dev, block_num, 1, inode_ctx->block_buffer);
        if (ret < 0) {
            fut_free(inode_ctx);
            return ret;
        }

        /* Call the completion callback directly since we're using synchronous I/O */
        futurafs_inode_read_callback(0, inode_ctx);
        return 0;
    }

    /* Submit async block read with valid handle */
    int ret = fut_blk_read_async(mount->block_device_handle, block_num, 1,
                                 inode_ctx->block_buffer,
                                 futurafs_inode_read_callback, inode_ctx);
    if (ret < 0) {
        fut_free(inode_ctx);
        return ret;
    }

    return 0;
}

/**
 * Inode write second stage callback (after write completes).
 * Called when the modified block has been written back to disk.
 */
static void futurafs_inode_write_stage2_callback(int result, void *ctx) {
    struct futurafs_inode_write_ctx *inode_ctx = (struct futurafs_inode_write_ctx *)ctx;

    /* Convert block I/O error to filesystem error */
    if (result < 0) {
        result = FUTURAFS_EIO;
    }

    /* Call user callback */
    inode_ctx->base.callback(result, inode_ctx->base.callback_ctx);

    /* Free context */
    fut_free(inode_ctx);
}

/**
 * Inode write first stage callback (after read completes).
 * Called when the block containing the inode has been read.
 * Now we modify it and write it back.
 */
static void futurafs_inode_write_stage1_callback(int result, void *ctx) {
    struct futurafs_inode_write_ctx *inode_ctx = (struct futurafs_inode_write_ctx *)ctx;

    if (result < 0) {
        /* Read failed, propagate error */
        inode_ctx->base.callback(FUTURAFS_EIO, inode_ctx->base.callback_ctx);
        fut_free(inode_ctx);
        return;
    }

    /* Modify inode in block buffer */
    uint64_t inode_index = inode_ctx->ino - 1;
    uint64_t block_offset = (inode_index % inode_ctx->base.mount->inodes_per_block)
                            * FUTURAFS_INODE_SIZE;
    uint8_t *inode_ptr = inode_ctx->block_buffer + block_offset;

    /* Copy inode data into block */
    for (size_t i = 0; i < sizeof(struct futurafs_inode); i++) {
        inode_ptr[i] = ((const uint8_t *)inode_ctx->inode)[i];
    }

    /* Calculate block number again for write */
    uint64_t block_num = inode_ctx->base.mount->sb->inode_table_block +
                         (inode_index / inode_ctx->base.mount->inodes_per_block);

    /* Submit async block write (stage 2) */
    int ret = fut_blk_write_async(inode_ctx->base.mount->block_device_handle,
                                  block_num, 1, inode_ctx->block_buffer,
                                  futurafs_inode_write_stage2_callback, inode_ctx);
    if (ret < 0) {
        /* Write submission failed */
        inode_ctx->base.callback(ret, inode_ctx->base.callback_ctx);
        fut_free(inode_ctx);
    }
}

/**
 * Write inode asynchronously.
 * This uses a read-modify-write pattern with callback chaining.
 */
int futurafs_write_inode_async(struct futurafs_mount *mount,
                               uint64_t ino,
                               const struct futurafs_inode *inode,
                               futurafs_completion_t callback,
                               void *ctx) {
    /* Validate inode number */
    if (ino == 0 || ino > mount->sb->total_inodes) {
        return FUTURAFS_EINVAL;
    }

    /* Allocate async context */
    struct futurafs_inode_write_ctx *inode_ctx = fut_malloc(sizeof(*inode_ctx));
    if (!inode_ctx) {
        return -12;  /* ENOMEM */
    }

    /* Initialize context */
    inode_ctx->base.callback = callback;
    inode_ctx->base.callback_ctx = ctx;
    inode_ctx->base.mount = mount;
    inode_ctx->ino = ino;
    inode_ctx->inode = inode;

    /* Calculate block number */
    uint64_t inode_index = ino - 1;
    uint64_t block_num = mount->sb->inode_table_block + (inode_index / mount->inodes_per_block);

    /* Check if we have a valid handle; if not, use synchronous blockdev API as fallback */
    if (mount->block_device_handle == FUT_INVALID_HANDLE) {
        /* Fallback: use synchronous blockdev API and call callbacks directly */
        int ret = fut_blockdev_read(mount->dev, block_num, 1, inode_ctx->block_buffer);
        if (ret < 0) {
            fut_free(inode_ctx);
            return ret;
        }

        /* Call the stage 1 callback directly since we're using synchronous I/O */
        futurafs_inode_write_stage1_callback(0, inode_ctx);
        return 0;
    }

    /* Submit async block read (stage 1) - will chain to write in callback */
    int ret = fut_blk_read_async(mount->block_device_handle, block_num, 1,
                                 inode_ctx->block_buffer,
                                 futurafs_inode_write_stage1_callback, inode_ctx);
    if (ret < 0) {
        fut_free(inode_ctx);
        return ret;
    }

    return 0;
}

/**
 * Data block read completion callback.
 * Called when async data block read completes.
 */
static void futurafs_block_read_callback(int result, void *ctx) {
    struct futurafs_block_read_ctx *block_ctx = (struct futurafs_block_read_ctx *)ctx;

    /* Convert block I/O error to filesystem error */
    if (result < 0) {
        result = FUTURAFS_EIO;
    }

    /* Call user callback */
    block_ctx->base.callback(result, block_ctx->base.callback_ctx);

    /* Free context */
    fut_free(block_ctx);
}

/**
 * Read data block asynchronously.
 * Reads a single data block from the filesystem.
 */
int futurafs_read_block_async(struct futurafs_mount *mount,
                              uint64_t block_num,
                              void *buffer,
                              futurafs_completion_t callback,
                              void *ctx) {
    /* Validate block number */
    if (block_num >= mount->sb->total_blocks) {
        return FUTURAFS_EINVAL;
    }

    /* Allocate async context */
    struct futurafs_block_read_ctx *block_ctx = fut_malloc(sizeof(*block_ctx));
    if (!block_ctx) {
        return -12;  /* ENOMEM */
    }

    /* Initialize context */
    block_ctx->base.callback = callback;
    block_ctx->base.callback_ctx = ctx;
    block_ctx->base.mount = mount;
    block_ctx->block_num = block_num;
    block_ctx->buffer = buffer;

    /* Submit async block read */
    int ret = fut_blk_read_async(mount->block_device_handle, block_num, 1,
                                 buffer, futurafs_block_read_callback, block_ctx);
    if (ret < 0) {
        fut_free(block_ctx);
        return ret;
    }

    return 0;
}

/**
 * Data block write completion callback.
 * Called when async data block write completes.
 */
static void futurafs_block_write_callback(int result, void *ctx) {
    struct futurafs_block_write_ctx *block_ctx = (struct futurafs_block_write_ctx *)ctx;

    /* Convert block I/O error to filesystem error */
    if (result < 0) {
        result = FUTURAFS_EIO;
    }

    /* Call user callback */
    block_ctx->base.callback(result, block_ctx->base.callback_ctx);

    /* Free context */
    fut_free(block_ctx);
}

/**
 * Write data block asynchronously.
 * Writes a single data block to the filesystem.
 */
int futurafs_write_block_async(struct futurafs_mount *mount,
                               uint64_t block_num,
                               const void *buffer,
                               futurafs_completion_t callback,
                               void *ctx) {
    /* Validate block number */
    if (block_num >= mount->sb->total_blocks) {
        return FUTURAFS_EINVAL;
    }

    /* Allocate async context */
    struct futurafs_block_write_ctx *block_ctx = fut_malloc(sizeof(*block_ctx));
    if (!block_ctx) {
        return -12;  /* ENOMEM */
    }

    /* Initialize context */
    block_ctx->base.callback = callback;
    block_ctx->base.callback_ctx = ctx;
    block_ctx->base.mount = mount;
    block_ctx->block_num = block_num;
    block_ctx->buffer = buffer;

    /* Submit async block write */
    int ret = fut_blk_write_async(mount->block_device_handle, block_num, 1,
                                  buffer, futurafs_block_write_callback, block_ctx);
    if (ret < 0) {
        fut_free(block_ctx);
        return ret;
    }

    return 0;
}

/* ============================================================
 *   Phase 3b: Composite Async Operations
 * ============================================================ */

/**
 * Callback for async directory lookup - processes one directory block.
 * Implements callback loop pattern: searches current block, then chains to next block if needed.
 */
static void futurafs_dir_lookup_callback(int result, void *ctx) {
    struct futurafs_dir_lookup_ctx *lookup_ctx = ctx;

    /* Check for I/O error */
    if (result < 0) {
        lookup_ctx->base.callback(FUTURAFS_EIO, lookup_ctx->base.callback_ctx);
        fut_free(lookup_ctx);
        return;
    }

    /* Search current block for matching entry */
    for (size_t offset = 0; offset < FUTURAFS_BLOCK_SIZE;
         offset += sizeof(struct futurafs_dirent)) {
        struct futurafs_dirent *dent =
            (struct futurafs_dirent *)(lookup_ctx->block_buffer + offset);

        /* Skip unused entries */
        if (dent->ino == 0) {
            continue;
        }

        /* Check if name matches */
        if (dent->name_len == lookup_ctx->name_len) {
            bool match = true;
            for (size_t i = 0; i < lookup_ctx->name_len; i++) {
                if (dent->name[i] != lookup_ctx->name[i]) {
                    match = false;
                    break;
                }
            }

            if (match) {
                /* Found matching entry - fill output parameters */
                if (lookup_ctx->entry_out) {
                    *lookup_ctx->entry_out = *dent;
                }
                if (lookup_ctx->block_out) {
                    *lookup_ctx->block_out =
                        lookup_ctx->dir_info->disk_inode.direct[lookup_ctx->current_block_index];
                }
                if (lookup_ctx->offset_out) {
                    *lookup_ctx->offset_out = offset;
                }

                /* Complete successfully */
                lookup_ctx->base.callback(0, lookup_ctx->base.callback_ctx);
                fut_free(lookup_ctx);
                return;
            }
        }
    }

    /* Entry not found in this block - try next block (callback loop) */
    lookup_ctx->current_block_index++;

    /* Check if we've exhausted all direct blocks */
    if (lookup_ctx->current_block_index >= FUTURAFS_DIRECT_BLOCKS) {
        /* Not found in any block */
        lookup_ctx->base.callback(FUTURAFS_ENOENT, lookup_ctx->base.callback_ctx);
        fut_free(lookup_ctx);
        return;
    }

    /* Get next block number */
    uint64_t next_block = lookup_ctx->dir_info->disk_inode.direct[lookup_ctx->current_block_index];

    /* Skip empty blocks */
    if (next_block == 0) {
        /* Re-invoke callback to try next block */
        futurafs_dir_lookup_callback(0, lookup_ctx);
        return;
    }

    /* Submit async read for next block - callback chains back to this function */
    int ret = futurafs_read_block_async(lookup_ctx->base.mount, next_block,
                                       lookup_ctx->block_buffer,
                                       futurafs_dir_lookup_callback, lookup_ctx);
    if (ret < 0) {
        lookup_ctx->base.callback(ret, lookup_ctx->base.callback_ctx);
        fut_free(lookup_ctx);
    }
}

/**
 * Look up directory entry by name asynchronously.
 * Demonstrates callback loop pattern for multi-block searches.
 */
int futurafs_dir_lookup_entry_async(struct futurafs_inode_info *dir_info,
                                    const char *name,
                                    size_t name_len,
                                    uint64_t *block_out,
                                    size_t *offset_out,
                                    struct futurafs_dirent *entry_out,
                                    futurafs_completion_t callback,
                                    void *ctx) {
    /* Allocate context for state machine */
    struct futurafs_dir_lookup_ctx *lookup_ctx =
        fut_malloc(sizeof(struct futurafs_dir_lookup_ctx));
    if (!lookup_ctx) {
        return FUTURAFS_EINVAL;
    }

    /* Initialize context */
    lookup_ctx->base.callback = callback;
    lookup_ctx->base.callback_ctx = ctx;
    lookup_ctx->base.mount = dir_info->mount;
    lookup_ctx->dir_info = dir_info;
    lookup_ctx->name = name;
    lookup_ctx->name_len = name_len;
    lookup_ctx->block_out = block_out;
    lookup_ctx->offset_out = offset_out;
    lookup_ctx->entry_out = entry_out;
    lookup_ctx->current_block_index = 0;

    /* Find first non-empty block */
    uint64_t first_block = 0;
    int first_block_index = -1;
    for (int i = 0; i < FUTURAFS_DIRECT_BLOCKS; i++) {
        if (dir_info->disk_inode.direct[i] != 0) {
            first_block = dir_info->disk_inode.direct[i];
            first_block_index = i;
            break;
        }
    }

    /* If no blocks allocated, directory is empty */
    if (first_block_index == -1) {
        fut_free(lookup_ctx);
        callback(FUTURAFS_ENOENT, ctx);
        return 0;
    }

    lookup_ctx->current_block_index = first_block_index;

    /* Submit async read for first block */
    int ret = futurafs_read_block_async(dir_info->mount, first_block,
                                       lookup_ctx->block_buffer,
                                       futurafs_dir_lookup_callback, lookup_ctx);
    if (ret < 0) {
        fut_free(lookup_ctx);
        return ret;
    }

    return 0;
}

/**
 * Callback for async directory add entry - implements state machine.
 * States: SEARCHING -> ALLOCATING (if needed) -> WRITING -> COMPLETE
 */
static void futurafs_dir_add_callback(int result, void *ctx) {
    struct futurafs_dir_add_ctx *add_ctx = ctx;

    /* Handle I/O errors */
    if (result < 0 && add_ctx->state != DIR_ADD_ALLOCATING) {
        /* Rollback any allocated blocks */
        if (add_ctx->allocated_block) {
            futurafs_free_block(add_ctx->base.mount, add_ctx->allocated_block_num);
        }
        add_ctx->base.callback(FUTURAFS_EIO, add_ctx->base.callback_ctx);
        fut_free(add_ctx);
        return;
    }

    switch (add_ctx->state) {
    case DIR_ADD_SEARCHING: {
        /* Search current block for free slot */
        for (size_t offset = 0; offset < FUTURAFS_BLOCK_SIZE;
             offset += sizeof(struct futurafs_dirent)) {
            struct futurafs_dirent *dent =
                (struct futurafs_dirent *)(add_ctx->block_buffer + offset);

            /* Check for duplicate name */
            if (dent->ino != 0 && dent->name_len == add_ctx->name_len) {
                bool match = true;
                for (size_t i = 0; i < add_ctx->name_len; i++) {
                    if (dent->name[i] != add_ctx->name[i]) {
                        match = false;
                        break;
                    }
                }
                if (match) {
                    /* Entry already exists */
                    add_ctx->base.callback(FUTURAFS_EEXIST, add_ctx->base.callback_ctx);
                    fut_free(add_ctx);
                    return;
                }
            }

            /* Found free slot */
            if (dent->ino == 0 && !add_ctx->found_slot) {
                add_ctx->found_slot = true;
                add_ctx->slot_block = add_ctx->dir_info->disk_inode.direct[add_ctx->current_block_index];
                add_ctx->slot_offset = offset;
                add_ctx->slot_index = add_ctx->current_block_index;
                /* Continue searching for duplicates */
            }
        }

        /* Move to next block */
        add_ctx->current_block_index++;

        /* Check if we've exhausted all direct blocks */
        if (add_ctx->current_block_index >= FUTURAFS_DIRECT_BLOCKS) {
            /* Done searching - check if we found a slot */
            if (add_ctx->found_slot) {
                /* Read the block containing the free slot */
                add_ctx->state = DIR_ADD_WRITING;
                int ret = futurafs_read_block_async(add_ctx->base.mount, add_ctx->slot_block,
                                                    add_ctx->block_buffer,
                                                    futurafs_dir_add_callback, add_ctx);
                if (ret < 0) {
                    add_ctx->base.callback(ret, add_ctx->base.callback_ctx);
                    fut_free(add_ctx);
                }
                return;
            } else if (add_ctx->new_block_index != -1) {
                /* Need to allocate new block */
                add_ctx->state = DIR_ADD_ALLOCATING;
                uint64_t new_block;
                int ret = futurafs_alloc_block(add_ctx->base.mount, &new_block);
                if (ret < 0) {
                    add_ctx->base.callback(FUTURAFS_ENOSPC, add_ctx->base.callback_ctx);
                    fut_free(add_ctx);
                    return;
                }
                add_ctx->allocated_block = true;
                add_ctx->allocated_block_num = new_block;

                /* Update directory inode with new block */
                add_ctx->dir_info->disk_inode.direct[add_ctx->new_block_index] = new_block;
                add_ctx->dir_info->dirty = true;

                /* Clear new block and prepare for write */
                for (size_t i = 0; i < FUTURAFS_BLOCK_SIZE; i++) {
                    add_ctx->block_buffer[i] = 0;
                }
                add_ctx->slot_block = new_block;
                add_ctx->slot_offset = 0;
                add_ctx->slot_index = add_ctx->new_block_index;
                add_ctx->state = DIR_ADD_WRITING;

                /* Fall through to writing */
                futurafs_dir_add_callback(0, add_ctx);
                return;
            } else {
                /* No free slots and no room for new blocks */
                add_ctx->base.callback(FUTURAFS_ENOSPC, add_ctx->base.callback_ctx);
                fut_free(add_ctx);
                return;
            }
        }

        /* Get next block number */
        uint64_t next_block = add_ctx->dir_info->disk_inode.direct[add_ctx->current_block_index];

        /* Track first empty slot for potential allocation */
        if (next_block == 0 && add_ctx->new_block_index == -1) {
            add_ctx->new_block_index = add_ctx->current_block_index;
        }

        /* Skip unallocated blocks */
        if (next_block == 0) {
            futurafs_dir_add_callback(0, add_ctx);
            return;
        }

        /* Submit async read for next block */
        int ret = futurafs_read_block_async(add_ctx->base.mount, next_block,
                                           add_ctx->block_buffer,
                                           futurafs_dir_add_callback, add_ctx);
        if (ret < 0) {
            add_ctx->base.callback(ret, add_ctx->base.callback_ctx);
            fut_free(add_ctx);
        }
        break;
    }

    case DIR_ADD_ALLOCATING:
        /* Allocation happens synchronously in SEARCHING state */
        /* This state is mainly for tracking purposes */
        add_ctx->state = DIR_ADD_WRITING;
        futurafs_dir_add_callback(0, add_ctx);
        break;

    case DIR_ADD_WRITING: {
        /* Fill in directory entry */
        struct futurafs_dirent *dent =
            (struct futurafs_dirent *)(add_ctx->block_buffer + add_ctx->slot_offset);

        dent->ino = add_ctx->ino;
        dent->rec_len = sizeof(struct futurafs_dirent);
        dent->name_len = add_ctx->name_len;
        dent->file_type = add_ctx->file_type;
        for (size_t i = 0; i < add_ctx->name_len; i++) {
            dent->name[i] = add_ctx->name[i];
        }
        dent->name[add_ctx->name_len] = '\0';

        /* Write block back - completion callback will handle success */
        add_ctx->state = DIR_ADD_COMPLETE;
        int ret = futurafs_write_block_async(add_ctx->base.mount, add_ctx->slot_block,
                                             add_ctx->block_buffer,
                                             futurafs_dir_add_callback, add_ctx);
        if (ret < 0) {
            /* Rollback */
            if (add_ctx->allocated_block) {
                futurafs_free_block(add_ctx->base.mount, add_ctx->allocated_block_num);
                add_ctx->dir_info->disk_inode.direct[add_ctx->slot_index] = 0;
            }
            add_ctx->base.callback(ret, add_ctx->base.callback_ctx);
            fut_free(add_ctx);
        }
        break;
    }

    case DIR_ADD_COMPLETE:
        /* Write completed successfully - update directory metadata */
        add_ctx->dir_info->disk_inode.nlinks++;
        add_ctx->dir_info->disk_inode.mtime = fut_get_time_ns();
        add_ctx->dir_info->disk_inode.ctime = fut_get_time_ns();
        add_ctx->dir_info->dirty = true;

        /* Mark directory vnode as modified */
        if (add_ctx->dir_vnode) {
            add_ctx->dir_vnode->size = add_ctx->dir_info->disk_inode.size;
        }

        /* Complete successfully */
        add_ctx->base.callback(0, add_ctx->base.callback_ctx);
        fut_free(add_ctx);
        break;
    }
}

/**
 * Add directory entry asynchronously.
 * Demonstrates read-modify-write pattern with conditional block allocation.
 */
int futurafs_dir_add_entry_async(struct fut_vnode *dir_vnode,
                                 struct futurafs_inode_info *dir_info,
                                 const char *name,
                                 size_t name_len,
                                 uint64_t ino,
                                 uint8_t file_type,
                                 futurafs_completion_t callback,
                                 void *ctx) {
    /* Validate parameters */
    if (!dir_info || !name || name_len == 0 || name_len > FUTURAFS_NAME_MAX || ino == 0) {
        return FUTURAFS_EINVAL;
    }

    /* Allocate context for state machine */
    struct futurafs_dir_add_ctx *add_ctx =
        fut_malloc(sizeof(struct futurafs_dir_add_ctx));
    if (!add_ctx) {
        return FUTURAFS_EINVAL;
    }

    /* Initialize context */
    add_ctx->base.callback = callback;
    add_ctx->base.callback_ctx = ctx;
    add_ctx->base.mount = dir_info->mount;
    add_ctx->dir_info = dir_info;
    add_ctx->dir_vnode = dir_vnode;
    add_ctx->name = name;
    add_ctx->name_len = name_len;
    add_ctx->ino = ino;
    add_ctx->file_type = file_type;
    add_ctx->state = DIR_ADD_SEARCHING;
    add_ctx->current_block_index = 0;
    add_ctx->found_slot = false;
    add_ctx->slot_block = 0;
    add_ctx->slot_offset = 0;
    add_ctx->slot_index = -1;
    add_ctx->new_block_index = -1;
    add_ctx->allocated_block = false;
    add_ctx->allocated_block_num = 0;

    /* Find first allocated block */
    uint64_t first_block = 0;
    int first_block_index = -1;
    for (int i = 0; i < FUTURAFS_DIRECT_BLOCKS; i++) {
        if (dir_info->disk_inode.direct[i] != 0) {
            first_block = dir_info->disk_inode.direct[i];
            first_block_index = i;
            break;
        } else if (add_ctx->new_block_index == -1) {
            /* Track first empty slot for potential allocation */
            add_ctx->new_block_index = i;
        }
    }

    /* If no blocks allocated, allocate first block */
    if (first_block_index == -1) {
        if (add_ctx->new_block_index == -1) {
            /* No room for new blocks */
            fut_free(add_ctx);
            callback(FUTURAFS_ENOSPC, ctx);
            return 0;
        }

        uint64_t new_block;
        int ret = futurafs_alloc_block(dir_info->mount, &new_block);
        if (ret < 0) {
            fut_free(add_ctx);
            callback(FUTURAFS_ENOSPC, ctx);
            return 0;
        }

        /* Update directory inode */
        dir_info->disk_inode.direct[add_ctx->new_block_index] = new_block;
        dir_info->dirty = true;

        add_ctx->allocated_block = true;
        add_ctx->allocated_block_num = new_block;
        add_ctx->slot_block = new_block;
        add_ctx->slot_offset = 0;
        add_ctx->slot_index = add_ctx->new_block_index;

        /* Clear block buffer */
        for (size_t i = 0; i < FUTURAFS_BLOCK_SIZE; i++) {
            add_ctx->block_buffer[i] = 0;
        }

        /* Skip to writing state */
        add_ctx->state = DIR_ADD_WRITING;
        futurafs_dir_add_callback(0, add_ctx);
        return 0;
    }

    add_ctx->current_block_index = first_block_index;

    /* Submit async read for first block to begin search */
    int ret = futurafs_read_block_async(dir_info->mount, first_block,
                                       add_ctx->block_buffer,
                                       futurafs_dir_add_callback, add_ctx);
    if (ret < 0) {
        fut_free(add_ctx);
        return ret;
    }

    return 0;
}

/* ============================================================
 *   Phase 3b: File I/O Async Operations
 * ============================================================ */

/**
 * File read callback - implements callback loop for sequential block reads.
 */
static void futurafs_file_read_callback(int result, void *ctx) {
    struct futurafs_file_read_ctx *read_ctx = (struct futurafs_file_read_ctx *)ctx;

    /* Check for I/O error */
    if (result < 0) {
        read_ctx->base.callback(read_ctx->bytes_read > 0 ? (int)read_ctx->bytes_read : FUTURAFS_EIO,
                               read_ctx->base.callback_ctx);
        fut_free(read_ctx);
        return;
    }

    /* Calculate current position and how much to copy */
    uint64_t current_offset = read_ctx->file_offset + read_ctx->bytes_read;
    uint64_t block_offset = current_offset % FUTURAFS_BLOCK_SIZE;
    size_t remaining = read_ctx->total_size - read_ctx->bytes_read;
    size_t to_copy = FUTURAFS_BLOCK_SIZE - block_offset;
    if (to_copy > remaining) {
        to_copy = remaining;
    }

    /* Copy data from block buffer to user buffer */
    uint8_t *dest = (uint8_t *)read_ctx->user_buffer + read_ctx->bytes_read;
    for (size_t i = 0; i < to_copy; i++) {
        dest[i] = read_ctx->block_buffer[block_offset + i];
    }

    read_ctx->bytes_read += to_copy;

    /* Check if done */
    if (read_ctx->bytes_read >= read_ctx->total_size) {
        /* Success - all bytes read */
        read_ctx->base.callback((int)read_ctx->bytes_read, read_ctx->base.callback_ctx);
        fut_free(read_ctx);
        return;
    }

    /* More blocks to read - continue callback loop */
    uint64_t next_offset = read_ctx->file_offset + read_ctx->bytes_read;
    uint64_t file_block = next_offset / FUTURAFS_BLOCK_SIZE;

    /* Get next block number with support for direct, single, double, and triple indirect */
    uint64_t block_num;
    if (file_block < FUTURAFS_DIRECT_BLOCKS) {
        block_num = read_ctx->inode_info->disk_inode.direct[file_block];
    } else {
        /* Indirect blocks required */
        uint64_t indirect_index = file_block - FUTURAFS_DIRECT_BLOCKS;
        uint64_t max_indirect_entries = FUTURAFS_BLOCK_SIZE / sizeof(uint64_t);

        bool use_double_indirect = (indirect_index >= max_indirect_entries);
        uint64_t indirect_block_num = 0;

        if (use_double_indirect) {
            /* Double or triple indirect blocks: beyond single indirect capacity */
            uint64_t double_indirect_index = indirect_index - max_indirect_entries;
            uint64_t indirect_within_double = double_indirect_index / max_indirect_entries;
            uint64_t entry_in_indirect = double_indirect_index % max_indirect_entries;

            if (indirect_within_double >= max_indirect_entries) {
                /* Triple indirect blocks: beyond double indirect capacity */
                uint64_t triple_indirect_index = indirect_within_double - max_indirect_entries;
                uint64_t triple_level_1 = triple_indirect_index / (max_indirect_entries * max_indirect_entries);
                uint64_t triple_level_2 = (triple_indirect_index / max_indirect_entries) % max_indirect_entries;
                uint64_t triple_level_3 = triple_indirect_index % max_indirect_entries;

                if (triple_level_1 >= max_indirect_entries) {
                    /* File too large or sparse */
                    read_ctx->base.callback((int)read_ctx->bytes_read, read_ctx->base.callback_ctx);
                    fut_free(read_ctx);
                    return;
                }

                /* Read triple-indirect block to find double-indirect block pointer */
                if (read_ctx->inode_info->disk_inode.triple_indirect == 0) {
                    /* Sparse file */
                    read_ctx->base.callback((int)read_ctx->bytes_read, read_ctx->base.callback_ctx);
                    fut_free(read_ctx);
                    return;
                }

                int read_ret = fut_blockdev_read(read_ctx->base.mount->dev,
                                                read_ctx->inode_info->disk_inode.triple_indirect,
                                                1, read_ctx->block_buffer);
                if (read_ret < 0) {
                    read_ctx->base.callback(read_ctx->bytes_read > 0 ? (int)read_ctx->bytes_read : read_ret,
                                          read_ctx->base.callback_ctx);
                    fut_free(read_ctx);
                    return;
                }

                /* Get double-indirect block pointer from triple-indirect table */
                uint64_t *triple_indirect_table = (uint64_t *)read_ctx->block_buffer;
                uint64_t double_indirect_block_num = triple_indirect_table[triple_level_1];
                if (double_indirect_block_num == 0) {
                    /* Sparse file */
                    read_ctx->base.callback((int)read_ctx->bytes_read, read_ctx->base.callback_ctx);
                    fut_free(read_ctx);
                    return;
                }

                /* Read double-indirect block to find indirect block pointer */
                read_ret = fut_blockdev_read(read_ctx->base.mount->dev,
                                            double_indirect_block_num,
                                            1, read_ctx->block_buffer);
                if (read_ret < 0) {
                    read_ctx->base.callback(read_ctx->bytes_read > 0 ? (int)read_ctx->bytes_read : read_ret,
                                          read_ctx->base.callback_ctx);
                    fut_free(read_ctx);
                    return;
                }

                /* Get indirect block pointer from double-indirect table */
                uint64_t *double_indirect_table = (uint64_t *)read_ctx->block_buffer;
                indirect_block_num = double_indirect_table[triple_level_2];
                if (indirect_block_num == 0) {
                    /* Sparse file */
                    read_ctx->base.callback((int)read_ctx->bytes_read, read_ctx->base.callback_ctx);
                    fut_free(read_ctx);
                    return;
                }

                /* Read indirect block to get the data block pointer */
                read_ret = fut_blockdev_read(read_ctx->base.mount->dev,
                                            indirect_block_num, 1,
                                            read_ctx->block_buffer);
                if (read_ret < 0) {
                    read_ctx->base.callback(read_ctx->bytes_read > 0 ? (int)read_ctx->bytes_read : read_ret,
                                          read_ctx->base.callback_ctx);
                    fut_free(read_ctx);
                    return;
                }

                /* Get data block pointer from indirect table */
                uint64_t *indirect_table = (uint64_t *)read_ctx->block_buffer;
                block_num = indirect_table[triple_level_3];
            } else {
                /* Double indirect blocks (but not triple) */
                if (read_ctx->inode_info->disk_inode.double_indirect == 0) {
                    /* Sparse file */
                    read_ctx->base.callback((int)read_ctx->bytes_read, read_ctx->base.callback_ctx);
                    fut_free(read_ctx);
                    return;
                }

                /* Read double-indirect block to find indirect block pointer */
                int read_ret = fut_blockdev_read(read_ctx->base.mount->dev,
                                                read_ctx->inode_info->disk_inode.double_indirect,
                                                1, read_ctx->block_buffer);
                if (read_ret < 0) {
                    read_ctx->base.callback(read_ctx->bytes_read > 0 ? (int)read_ctx->bytes_read : read_ret,
                                          read_ctx->base.callback_ctx);
                    fut_free(read_ctx);
                    return;
                }

                /* Get indirect block pointer from double-indirect table */
                uint64_t *double_indirect_table = (uint64_t *)read_ctx->block_buffer;
                indirect_block_num = double_indirect_table[indirect_within_double];
                if (indirect_block_num == 0) {
                    /* Sparse file */
                    read_ctx->base.callback((int)read_ctx->bytes_read, read_ctx->base.callback_ctx);
                    fut_free(read_ctx);
                    return;
                }

                /* Read indirect block to get the data block pointer */
                read_ret = fut_blockdev_read(read_ctx->base.mount->dev,
                                            indirect_block_num, 1,
                                            read_ctx->block_buffer);
                if (read_ret < 0) {
                    read_ctx->base.callback(read_ctx->bytes_read > 0 ? (int)read_ctx->bytes_read : read_ret,
                                          read_ctx->base.callback_ctx);
                    fut_free(read_ctx);
                    return;
                }

                /* Get data block pointer from indirect table */
                uint64_t *indirect_table = (uint64_t *)read_ctx->block_buffer;
                block_num = indirect_table[entry_in_indirect];
            }
        } else {
            /* Single indirect block handling */
            if (read_ctx->inode_info->disk_inode.indirect == 0) {
                /* No indirect block - sparse file */
                read_ctx->base.callback((int)read_ctx->bytes_read, read_ctx->base.callback_ctx);
                fut_free(read_ctx);
                return;
            }

            /* Read the indirect block synchronously */
            int read_ret = fut_blockdev_read(read_ctx->base.mount->dev,
                                            read_ctx->inode_info->disk_inode.indirect,
                                            1, read_ctx->block_buffer);
            if (read_ret < 0) {
                read_ctx->base.callback(read_ctx->bytes_read > 0 ? (int)read_ctx->bytes_read : read_ret,
                                       read_ctx->base.callback_ctx);
                fut_free(read_ctx);
                return;
            }

            /* Extract block pointer from indirect block */
            uint64_t *indirect_table = (uint64_t *)read_ctx->block_buffer;
            block_num = indirect_table[indirect_index];
        }
    }

    /* Handle sparse block (block_num == 0) */
    if (block_num == 0) {
        /* Fill with zeros without I/O */
        size_t next_block_offset = next_offset % FUTURAFS_BLOCK_SIZE;
        size_t next_remaining = read_ctx->total_size - read_ctx->bytes_read;
        size_t next_to_copy = FUTURAFS_BLOCK_SIZE - next_block_offset;
        if (next_to_copy > next_remaining) {
            next_to_copy = next_remaining;
        }

        uint8_t *next_dest = (uint8_t *)read_ctx->user_buffer + read_ctx->bytes_read;
        for (size_t i = 0; i < next_to_copy; i++) {
            next_dest[i] = 0;
        }

        read_ctx->bytes_read += next_to_copy;

        /* Check if done after filling sparse block */
        if (read_ctx->bytes_read >= read_ctx->total_size) {
            read_ctx->base.callback((int)read_ctx->bytes_read, read_ctx->base.callback_ctx);
            fut_free(read_ctx);
            return;
        }

        /* Continue to next block recursively */
        futurafs_file_read_callback(0, read_ctx);
        return;
    }

    /* Read next block asynchronously */
    int ret = futurafs_read_block_async(read_ctx->base.mount, block_num,
                                       read_ctx->block_buffer,
                                       futurafs_file_read_callback, read_ctx);
    if (ret < 0) {
        read_ctx->base.callback(read_ctx->bytes_read > 0 ? (int)read_ctx->bytes_read : ret,
                               read_ctx->base.callback_ctx);
        fut_free(read_ctx);
    }
}

/**
 * Read from file asynchronously.
 */
int futurafs_file_read_async(struct futurafs_inode_info *inode_info,
                              void *buffer,
                              size_t size,
                              uint64_t offset,
                              futurafs_completion_t callback,
                              void *ctx) {
    /* EOF check */
    if (offset >= inode_info->disk_inode.size) {
        callback(0, ctx);  /* Return 0 bytes read */
        return 0;
    }

    /* Limit read to file size */
    if (offset + size > inode_info->disk_inode.size) {
        size = inode_info->disk_inode.size - offset;
    }

    /* Allocate context */
    struct futurafs_file_read_ctx *read_ctx = fut_malloc(sizeof(*read_ctx));
    if (!read_ctx) {
        return FUTURAFS_EIO;
    }

    /* Initialize context */
    read_ctx->base.callback = callback;
    read_ctx->base.callback_ctx = ctx;
    read_ctx->base.mount = inode_info->mount;
    read_ctx->inode_info = inode_info;
    read_ctx->user_buffer = buffer;
    read_ctx->total_size = size;
    read_ctx->file_offset = offset;
    read_ctx->bytes_read = 0;

    /* Calculate first block to read */
    uint64_t file_block = offset / FUTURAFS_BLOCK_SIZE;

    /* Get first block number */
    uint64_t block_num;
    if (file_block < FUTURAFS_DIRECT_BLOCKS) {
        block_num = inode_info->disk_inode.direct[file_block];
    } else {
        /* Indirect blocks: read indirect block and extract pointer */
        if (inode_info->disk_inode.indirect == 0) {
            /* No indirect block - sparse file */
            fut_free(read_ctx);
            callback(0, ctx);
            return 0;
        }

        /* Read the indirect block synchronously */
        int sync_result = fut_blockdev_read(inode_info->mount->dev,
                                           inode_info->disk_inode.indirect,
                                           1, read_ctx->block_buffer);
        if (sync_result < 0) {
            fut_free(read_ctx);
            callback(sync_result, ctx);
            return sync_result;
        }

        /* Extract block pointer from indirect block */
        uint64_t indirect_index = file_block - FUTURAFS_DIRECT_BLOCKS;
        if (indirect_index >= (FUTURAFS_BLOCK_SIZE / sizeof(uint64_t))) {
            /* Out of range - sparse file */
            fut_free(read_ctx);
            callback(0, ctx);
            return 0;
        }

        uint64_t *indirect_table = (uint64_t *)read_ctx->block_buffer;
        block_num = indirect_table[indirect_index];
    }

    /* Handle sparse block at start */
    if (block_num == 0) {
        /* Fill with zeros and continue */
        futurafs_file_read_callback(0, read_ctx);
        return 0;
    }

    /* Submit first block read to begin operation */
    int ret = futurafs_read_block_async(inode_info->mount, block_num,
                                       read_ctx->block_buffer,
                                       futurafs_file_read_callback, read_ctx);
    if (ret < 0) {
        fut_free(read_ctx);
        return ret;
    }

    return 0;
}

/**
 * File write callback - implements state machine for read-modify-write pattern.
 */
static void futurafs_file_write_callback(int result, void *ctx) {
    struct futurafs_file_write_ctx *write_ctx = (struct futurafs_file_write_ctx *)ctx;

    /* Check for I/O error */
    if (result < 0) {
        write_ctx->base.callback(write_ctx->bytes_written > 0 ? (int)write_ctx->bytes_written : FUTURAFS_EIO,
                                write_ctx->base.callback_ctx);
        fut_free(write_ctx);
        return;
    }

    switch (write_ctx->state) {
        case FILE_WRITE_READING: {
            /* Read completed for read-modify-write - now modify and write */
            uint64_t current_offset = write_ctx->file_offset + write_ctx->bytes_written;
            uint64_t block_offset = current_offset % FUTURAFS_BLOCK_SIZE;
            size_t remaining = write_ctx->total_size - write_ctx->bytes_written;
            size_t to_write = FUTURAFS_BLOCK_SIZE - block_offset;
            if (to_write > remaining) {
                to_write = remaining;
            }

            /* Modify block data */
            const uint8_t *src = (const uint8_t *)write_ctx->user_buffer + write_ctx->bytes_written;
            for (size_t i = 0; i < to_write; i++) {
                write_ctx->block_buffer[block_offset + i] = src[i];
            }

            /* Write modified block */
            write_ctx->state = FILE_WRITE_WRITING;
            int ret = futurafs_write_block_async(write_ctx->base.mount, write_ctx->current_block_num,
                                                 write_ctx->block_buffer,
                                                 futurafs_file_write_callback, write_ctx);
            if (ret < 0) {
                write_ctx->base.callback(write_ctx->bytes_written > 0 ? (int)write_ctx->bytes_written : ret,
                                        write_ctx->base.callback_ctx);
                fut_free(write_ctx);
            }
            break;
        }

        case FILE_WRITE_WRITING: {
            /* Write completed - update progress */
            uint64_t current_offset = write_ctx->file_offset + write_ctx->bytes_written;
            uint64_t block_offset = current_offset % FUTURAFS_BLOCK_SIZE;
            size_t remaining = write_ctx->total_size - write_ctx->bytes_written;
            size_t to_write = FUTURAFS_BLOCK_SIZE - block_offset;
            if (to_write > remaining) {
                to_write = remaining;
            }

            write_ctx->bytes_written += to_write;

            /* Check if done writing all blocks */
            if (write_ctx->bytes_written >= write_ctx->total_size) {
                /* Update file size if needed */
                uint64_t new_size = write_ctx->file_offset + write_ctx->bytes_written;
                if (new_size > write_ctx->inode_info->disk_inode.size) {
                    write_ctx->inode_info->disk_inode.size = new_size;
                    write_ctx->inode_info->dirty = true;
                }

                /* Sync inode if dirty */
                if (write_ctx->inode_info->dirty) {
                    write_ctx->state = FILE_WRITE_SYNCING;
                    int ret = futurafs_write_inode_async(write_ctx->base.mount,
                                                         write_ctx->inode_info->ino,
                                                         &write_ctx->inode_info->disk_inode,
                                                         futurafs_file_write_callback, write_ctx);
                    if (ret < 0) {
                        write_ctx->base.callback((int)write_ctx->bytes_written, write_ctx->base.callback_ctx);
                        fut_free(write_ctx);
                    }
                } else {
                    /* Done */
                    write_ctx->base.callback((int)write_ctx->bytes_written, write_ctx->base.callback_ctx);
                    fut_free(write_ctx);
                }
                return;
            }

            /* More blocks to write - prepare next block */
            uint64_t next_offset = write_ctx->file_offset + write_ctx->bytes_written;
            uint64_t file_block = next_offset / FUTURAFS_BLOCK_SIZE;
            uint64_t next_block_offset = next_offset % FUTURAFS_BLOCK_SIZE;
            size_t next_remaining = write_ctx->total_size - write_ctx->bytes_written;
            size_t next_to_write = FUTURAFS_BLOCK_SIZE - next_block_offset;
            if (next_to_write > next_remaining) {
                next_to_write = next_remaining;
            }

            /* Get or allocate next block */
            uint64_t block_num;
            if (file_block < FUTURAFS_DIRECT_BLOCKS) {
                block_num = write_ctx->inode_info->disk_inode.direct[file_block];
                if (block_num == 0) {
                    /* Allocate new block */
                    int ret = futurafs_alloc_block(write_ctx->base.mount, &block_num);
                    if (ret < 0) {
                        write_ctx->base.callback((int)write_ctx->bytes_written, write_ctx->base.callback_ctx);
                        fut_free(write_ctx);
                        return;
                    }
                    write_ctx->inode_info->disk_inode.direct[file_block] = block_num;
                    write_ctx->inode_info->disk_inode.blocks++;
                    write_ctx->inode_info->dirty = true;
                    write_ctx->allocated_block = true;
                }
            } else {
                /* Indirect blocks: file_block >= FUTURAFS_DIRECT_BLOCKS */
                uint64_t indirect_index = file_block - FUTURAFS_DIRECT_BLOCKS;
                uint64_t max_indirect_entries = FUTURAFS_BLOCK_SIZE / sizeof(uint64_t);

                bool use_double_indirect = (indirect_index >= max_indirect_entries);
                uint64_t indirect_block_num = 0;
                uint64_t data_block_num = 0;

                if (use_double_indirect) {
                    /* Double indirect blocks: beyond single indirect capacity
                     * File block layout:
                     * 0-11: direct blocks
                     * 12-(12+512): single indirect
                     * (12+512)+: double indirect (each entry points to 512-entry indirect block)
                     */
                    uint64_t double_indirect_index = indirect_index - max_indirect_entries;
                    uint64_t indirect_within_double = double_indirect_index / max_indirect_entries;
                    uint64_t entry_in_indirect = double_indirect_index % max_indirect_entries;

                    if (indirect_within_double >= max_indirect_entries) {
                        /* Triple indirect blocks: beyond double indirect capacity
                         * File block layout:
                         * 0-11: direct
                         * 12-(12+512): single indirect
                         * (12+512)-(12+512*512): double indirect
                         * (12+512*512)+: triple indirect
                         */
                        uint64_t triple_indirect_index = indirect_within_double - max_indirect_entries;
                        uint64_t triple_level_1 = triple_indirect_index / (max_indirect_entries * max_indirect_entries);
                        uint64_t triple_level_2 = (triple_indirect_index / max_indirect_entries) % max_indirect_entries;
                        uint64_t triple_level_3 = triple_indirect_index % max_indirect_entries;

                        if (triple_level_1 >= max_indirect_entries) {
                            /* File too large - would need 4-level indirection */
                            write_ctx->base.callback((int)write_ctx->bytes_written, write_ctx->base.callback_ctx);
                            fut_free(write_ctx);
                            return;
                        }

                        /* Allocate triple-indirect block if needed */
                        if (write_ctx->inode_info->disk_inode.triple_indirect == 0) {
                            uint64_t triple_indirect_block = 0;
                            int ret = futurafs_alloc_block(write_ctx->base.mount, &triple_indirect_block);
                            if (ret < 0) {
                                write_ctx->base.callback((int)write_ctx->bytes_written, write_ctx->base.callback_ctx);
                                fut_free(write_ctx);
                                return;
                            }
                            write_ctx->inode_info->disk_inode.triple_indirect = triple_indirect_block;
                            write_ctx->inode_info->dirty = true;

                            /* Zero out the triple-indirect block */
                            for (size_t i = 0; i < FUTURAFS_BLOCK_SIZE; i++) {
                                write_ctx->block_buffer[i] = 0;
                            }

                            /* Write zeroed triple-indirect block */
                            int write_ret = futurafs_blk_write(write_ctx->base.mount,
                                                              write_ctx->inode_info->disk_inode.triple_indirect, 1,
                                                              write_ctx->block_buffer);
                            if (write_ret < 0) {
                                write_ctx->base.callback((int)write_ctx->bytes_written, write_ctx->base.callback_ctx);
                                fut_free(write_ctx);
                                return;
                            }
                        }

                        /* Read triple-indirect block to find double-indirect block pointer */
                        int read_ret = futurafs_blk_read(write_ctx->base.mount,
                                                         write_ctx->inode_info->disk_inode.triple_indirect, 1,
                                                         write_ctx->block_buffer);
                        if (read_ret < 0) {
                            write_ctx->base.callback((int)write_ctx->bytes_written, write_ctx->base.callback_ctx);
                            fut_free(write_ctx);
                            return;
                        }

                        /* Get double-indirect block pointer from triple-indirect table */
                        uint64_t *triple_indirect_table = (uint64_t *)write_ctx->block_buffer;
                        uint64_t double_indirect_block_num = triple_indirect_table[triple_level_1];

                        /* Allocate double-indirect block if needed */
                        if (double_indirect_block_num == 0) {
                            int ret = futurafs_alloc_block(write_ctx->base.mount, &double_indirect_block_num);
                            if (ret < 0) {
                                write_ctx->base.callback((int)write_ctx->bytes_written, write_ctx->base.callback_ctx);
                                fut_free(write_ctx);
                                return;
                            }

                            /* Update triple-indirect table and write it back */
                            triple_indirect_table[triple_level_1] = double_indirect_block_num;
                            int write_ret = futurafs_blk_write(write_ctx->base.mount,
                                                              write_ctx->inode_info->disk_inode.triple_indirect, 1,
                                                              write_ctx->block_buffer);
                            if (write_ret < 0) {
                                write_ctx->base.callback((int)write_ctx->bytes_written, write_ctx->base.callback_ctx);
                                fut_free(write_ctx);
                                return;
                            }

                            write_ctx->inode_info->disk_inode.blocks++;
                            write_ctx->inode_info->dirty = true;

                            /* Zero out the new double-indirect block */
                            for (size_t i = 0; i < FUTURAFS_BLOCK_SIZE; i++) {
                                write_ctx->block_buffer[i] = 0;
                            }

                            /* Write zeroed double-indirect block */
                            int write_ret2 = futurafs_blk_write(write_ctx->base.mount,
                                                               double_indirect_block_num, 1,
                                                               write_ctx->block_buffer);
                            if (write_ret2 < 0) {
                                write_ctx->base.callback((int)write_ctx->bytes_written, write_ctx->base.callback_ctx);
                                fut_free(write_ctx);
                                return;
                            }
                        }

                        /* Read double-indirect block to find indirect block pointer */
                        read_ret = futurafs_blk_read(write_ctx->base.mount,
                                                    double_indirect_block_num, 1,
                                                    write_ctx->block_buffer);
                        if (read_ret < 0) {
                            write_ctx->base.callback((int)write_ctx->bytes_written, write_ctx->base.callback_ctx);
                            fut_free(write_ctx);
                            return;
                        }

                        /* Get indirect block pointer from double-indirect table */
                        uint64_t *double_indirect_table = (uint64_t *)write_ctx->block_buffer;
                        uint64_t indirect_block_num = double_indirect_table[triple_level_2];

                        /* Allocate indirect block if needed */
                        if (indirect_block_num == 0) {
                            int ret = futurafs_alloc_block(write_ctx->base.mount, &indirect_block_num);
                            if (ret < 0) {
                                write_ctx->base.callback((int)write_ctx->bytes_written, write_ctx->base.callback_ctx);
                                fut_free(write_ctx);
                                return;
                            }

                            /* Update double-indirect table and write it back */
                            double_indirect_table[triple_level_2] = indirect_block_num;
                            int write_ret = futurafs_blk_write(write_ctx->base.mount,
                                                              double_indirect_block_num, 1,
                                                              write_ctx->block_buffer);
                            if (write_ret < 0) {
                                write_ctx->base.callback((int)write_ctx->bytes_written, write_ctx->base.callback_ctx);
                                fut_free(write_ctx);
                                return;
                            }

                            write_ctx->inode_info->disk_inode.blocks++;
                            write_ctx->inode_info->dirty = true;

                            /* Zero out the new indirect block */
                            for (size_t i = 0; i < FUTURAFS_BLOCK_SIZE; i++) {
                                write_ctx->block_buffer[i] = 0;
                            }

                            /* Write zeroed indirect block */
                            int write_ret2 = futurafs_blk_write(write_ctx->base.mount,
                                                               indirect_block_num, 1,
                                                               write_ctx->block_buffer);
                            if (write_ret2 < 0) {
                                write_ctx->base.callback((int)write_ctx->bytes_written, write_ctx->base.callback_ctx);
                                fut_free(write_ctx);
                                return;
                            }
                        }

                        /* Read indirect block to get the data block pointer */
                        read_ret = futurafs_blk_read(write_ctx->base.mount,
                                                    indirect_block_num, 1,
                                                    write_ctx->block_buffer);
                        if (read_ret < 0) {
                            write_ctx->base.callback((int)write_ctx->bytes_written, write_ctx->base.callback_ctx);
                            fut_free(write_ctx);
                            return;
                        }

                        /* Get data block pointer from indirect table */
                        uint64_t *indirect_table = (uint64_t *)write_ctx->block_buffer;
                        block_num = indirect_table[triple_level_3];

                        /* Allocate data block if needed */
                        if (block_num == 0) {
                            int ret = futurafs_alloc_block(write_ctx->base.mount, &block_num);
                            if (ret < 0) {
                                write_ctx->base.callback((int)write_ctx->bytes_written, write_ctx->base.callback_ctx);
                                fut_free(write_ctx);
                                return;
                            }

                            /* Update indirect table and write it back */
                            indirect_table[triple_level_3] = block_num;
                            int write_ret = futurafs_blk_write(write_ctx->base.mount,
                                                              indirect_block_num, 1,
                                                              write_ctx->block_buffer);
                            if (write_ret < 0) {
                                write_ctx->base.callback((int)write_ctx->bytes_written, write_ctx->base.callback_ctx);
                                fut_free(write_ctx);
                                return;
                            }

                            write_ctx->inode_info->disk_inode.blocks++;
                            write_ctx->inode_info->dirty = true;
                        }

                        /* Use block_num from triple-indirect logic */
                    }

                    /* Allocate double-indirect block if needed */
                    if (write_ctx->inode_info->disk_inode.double_indirect == 0) {
                        uint64_t double_indirect_block = 0;
                        int ret = futurafs_alloc_block(write_ctx->base.mount, &double_indirect_block);
                        if (ret < 0) {
                            write_ctx->base.callback((int)write_ctx->bytes_written, write_ctx->base.callback_ctx);
                            fut_free(write_ctx);
                            return;
                        }
                        write_ctx->inode_info->disk_inode.double_indirect = double_indirect_block;
                        write_ctx->inode_info->dirty = true;

                        /* Zero out the double-indirect block */
                        for (size_t i = 0; i < FUTURAFS_BLOCK_SIZE; i++) {
                            write_ctx->block_buffer[i] = 0;
                        }

                        /* Write zeroed double-indirect block */
                        int write_ret = futurafs_blk_write(write_ctx->base.mount,
                                                          write_ctx->inode_info->disk_inode.double_indirect, 1,
                                                          write_ctx->block_buffer);
                        if (write_ret < 0) {
                            write_ctx->base.callback((int)write_ctx->bytes_written, write_ctx->base.callback_ctx);
                            fut_free(write_ctx);
                            return;
                        }
                    }

                    /* Read double-indirect block to find indirect block pointer */
                    int read_ret = futurafs_blk_read(write_ctx->base.mount,
                                                     write_ctx->inode_info->disk_inode.double_indirect, 1,
                                                     write_ctx->block_buffer);
                    if (read_ret < 0) {
                        write_ctx->base.callback((int)write_ctx->bytes_written, write_ctx->base.callback_ctx);
                        fut_free(write_ctx);
                        return;
                    }

                    /* Get indirect block pointer from double-indirect table */
                    uint64_t *double_indirect_table = (uint64_t *)write_ctx->block_buffer;
                    indirect_block_num = double_indirect_table[indirect_within_double];

                    /* Allocate indirect block if needed */
                    if (indirect_block_num == 0) {
                        int ret = futurafs_alloc_block(write_ctx->base.mount, &indirect_block_num);
                        if (ret < 0) {
                            write_ctx->base.callback((int)write_ctx->bytes_written, write_ctx->base.callback_ctx);
                            fut_free(write_ctx);
                            return;
                        }

                        /* Update double-indirect table and write it back */
                        double_indirect_table[indirect_within_double] = indirect_block_num;
                        int write_ret = futurafs_blk_write(write_ctx->base.mount,
                                                          write_ctx->inode_info->disk_inode.double_indirect, 1,
                                                          write_ctx->block_buffer);
                        if (write_ret < 0) {
                            write_ctx->base.callback((int)write_ctx->bytes_written, write_ctx->base.callback_ctx);
                            fut_free(write_ctx);
                            return;
                        }

                        write_ctx->inode_info->disk_inode.blocks++;
                        write_ctx->inode_info->dirty = true;

                        /* Zero out the new indirect block */
                        for (size_t i = 0; i < FUTURAFS_BLOCK_SIZE; i++) {
                            write_ctx->block_buffer[i] = 0;
                        }

                        /* Write zeroed indirect block */
                        int write_ret2 = futurafs_blk_write(write_ctx->base.mount,
                                                           indirect_block_num, 1,
                                                           write_ctx->block_buffer);
                        if (write_ret2 < 0) {
                            write_ctx->base.callback((int)write_ctx->bytes_written, write_ctx->base.callback_ctx);
                            fut_free(write_ctx);
                            return;
                        }
                    }

                    /* Read indirect block to check/update data block pointers */
                    read_ret = futurafs_blk_read(write_ctx->base.mount,
                                               indirect_block_num, 1,
                                               write_ctx->block_buffer);
                    if (read_ret < 0) {
                        write_ctx->base.callback((int)write_ctx->bytes_written, write_ctx->base.callback_ctx);
                        fut_free(write_ctx);
                        return;
                    }

                    /* Get data block pointer from indirect table */
                    uint64_t *indirect_table = (uint64_t *)write_ctx->block_buffer;
                    data_block_num = indirect_table[entry_in_indirect];

                    /* Allocate data block if needed */
                    if (data_block_num == 0) {
                        int ret = futurafs_alloc_block(write_ctx->base.mount, &data_block_num);
                        if (ret < 0) {
                            write_ctx->base.callback((int)write_ctx->bytes_written, write_ctx->base.callback_ctx);
                            fut_free(write_ctx);
                            return;
                        }

                        /* Update indirect table and write it back */
                        indirect_table[entry_in_indirect] = data_block_num;
                        int write_ret = futurafs_blk_write(write_ctx->base.mount,
                                                          indirect_block_num, 1,
                                                          write_ctx->block_buffer);
                        if (write_ret < 0) {
                            write_ctx->base.callback((int)write_ctx->bytes_written, write_ctx->base.callback_ctx);
                            fut_free(write_ctx);
                            return;
                        }

                        write_ctx->inode_info->disk_inode.blocks++;
                        write_ctx->inode_info->dirty = true;
                    }

                    block_num = data_block_num;
                }

                /* Allocate indirect block if needed */
                if (write_ctx->inode_info->disk_inode.indirect == 0) {
                    uint64_t indirect_block = 0;
                    int ret = futurafs_alloc_block(write_ctx->base.mount, &indirect_block);
                    if (ret < 0) {
                        write_ctx->base.callback((int)write_ctx->bytes_written, write_ctx->base.callback_ctx);
                        fut_free(write_ctx);
                        return;
                    }
                    write_ctx->inode_info->disk_inode.indirect = indirect_block;
                    write_ctx->inode_info->dirty = true;

                    /* Zero out the indirect block */
                    for (size_t i = 0; i < FUTURAFS_BLOCK_SIZE; i++) {
                        write_ctx->block_buffer[i] = 0;
                    }

                    /* Write zeroed indirect block */
                    int write_ret = futurafs_blk_write(write_ctx->base.mount,
                                                      write_ctx->inode_info->disk_inode.indirect, 1,
                                                      write_ctx->block_buffer);
                    if (write_ret < 0) {
                        write_ctx->base.callback((int)write_ctx->bytes_written, write_ctx->base.callback_ctx);
                        fut_free(write_ctx);
                        return;
                    }
                }

                /* Read indirect block to check/update pointers */
                int read_ret = futurafs_blk_read(write_ctx->base.mount,
                                                 write_ctx->inode_info->disk_inode.indirect, 1,
                                                 write_ctx->block_buffer);
                if (read_ret < 0) {
                    write_ctx->base.callback((int)write_ctx->bytes_written, write_ctx->base.callback_ctx);
                    fut_free(write_ctx);
                    return;
                }

                /* Get block pointer from indirect table */
                uint64_t *indirect_table = (uint64_t *)write_ctx->block_buffer;
                block_num = indirect_table[indirect_index];

                /* Allocate data block if needed */
                if (block_num == 0) {
                    int ret = futurafs_alloc_block(write_ctx->base.mount, &block_num);
                    if (ret < 0) {
                        write_ctx->base.callback((int)write_ctx->bytes_written, write_ctx->base.callback_ctx);
                        fut_free(write_ctx);
                        return;
                    }

                    /* Update indirect table and write it back */
                    indirect_table[indirect_index] = block_num;
                    int write_ret = futurafs_blk_write(write_ctx->base.mount,
                                                      write_ctx->inode_info->disk_inode.indirect, 1,
                                                      write_ctx->block_buffer);
                    if (write_ret < 0) {
                        write_ctx->base.callback((int)write_ctx->bytes_written, write_ctx->base.callback_ctx);
                        fut_free(write_ctx);
                        return;
                    }

                    write_ctx->inode_info->disk_inode.blocks++;
                    write_ctx->inode_info->dirty = true;
                    write_ctx->allocated_block = true;
                }
            }

            write_ctx->current_block_num = block_num;

            /* Check if we need read-modify-write (partial block) */
            bool need_read = (next_block_offset != 0 || next_to_write != FUTURAFS_BLOCK_SIZE);
            if (need_read) {
                /* Read block first */
                write_ctx->state = FILE_WRITE_READING;
                int ret = futurafs_read_block_async(write_ctx->base.mount, block_num,
                                                    write_ctx->block_buffer,
                                                    futurafs_file_write_callback, write_ctx);
                if (ret < 0) {
                    write_ctx->base.callback(write_ctx->bytes_written > 0 ? (int)write_ctx->bytes_written : ret,
                                            write_ctx->base.callback_ctx);
                    fut_free(write_ctx);
                }
            } else {
                /* Full block write - no need to read first */
                const uint8_t *src = (const uint8_t *)write_ctx->user_buffer + write_ctx->bytes_written;
                for (size_t i = 0; i < FUTURAFS_BLOCK_SIZE; i++) {
                    write_ctx->block_buffer[i] = src[i];
                }

                write_ctx->state = FILE_WRITE_WRITING;
                int ret = futurafs_write_block_async(write_ctx->base.mount, block_num,
                                                     write_ctx->block_buffer,
                                                     futurafs_file_write_callback, write_ctx);
                if (ret < 0) {
                    write_ctx->base.callback(write_ctx->bytes_written > 0 ? (int)write_ctx->bytes_written : ret,
                                            write_ctx->base.callback_ctx);
                    fut_free(write_ctx);
                }
            }
            break;
        }

        case FILE_WRITE_SYNCING: {
            /* Inode sync completed */
            write_ctx->inode_info->dirty = false;
            write_ctx->state = FILE_WRITE_COMPLETE;
            write_ctx->base.callback((int)write_ctx->bytes_written, write_ctx->base.callback_ctx);
            fut_free(write_ctx);
            break;
        }

        case FILE_WRITE_COMPLETE:
            /* Should not reach here */
            break;
    }
}

/**
 * Write to file asynchronously.
 */
int futurafs_file_write_async(struct futurafs_inode_info *inode_info,
                               const void *buffer,
                               size_t size,
                               uint64_t offset,
                               futurafs_completion_t callback,
                               void *ctx) {
    /* Allocate context */
    struct futurafs_file_write_ctx *write_ctx = fut_malloc(sizeof(*write_ctx));
    if (!write_ctx) {
        return FUTURAFS_EIO;
    }

    /* Initialize context */
    write_ctx->base.callback = callback;
    write_ctx->base.callback_ctx = ctx;
    write_ctx->base.mount = inode_info->mount;
    write_ctx->inode_info = inode_info;
    write_ctx->user_buffer = buffer;
    write_ctx->total_size = size;
    write_ctx->file_offset = offset;
    write_ctx->bytes_written = 0;
    write_ctx->state = FILE_WRITE_WRITING;
    write_ctx->allocated_block = false;

    /* Calculate first block to write */
    uint64_t file_block = offset / FUTURAFS_BLOCK_SIZE;
    uint64_t block_offset = offset % FUTURAFS_BLOCK_SIZE;
    size_t to_write = FUTURAFS_BLOCK_SIZE - block_offset;
    if (to_write > size) {
        to_write = size;
    }

    /* Get or allocate first block */
    uint64_t block_num;
    if (file_block < FUTURAFS_DIRECT_BLOCKS) {
        block_num = inode_info->disk_inode.direct[file_block];
        if (block_num == 0) {
            /* Allocate new block */
            int ret = futurafs_alloc_block(inode_info->mount, &block_num);
            if (ret < 0) {
                fut_free(write_ctx);
                return ret;
            }
            inode_info->disk_inode.direct[file_block] = block_num;
            inode_info->disk_inode.blocks++;
            inode_info->dirty = true;
            write_ctx->allocated_block = true;
        }
    } else {
        /* Indirect blocks: file_block >= FUTURAFS_DIRECT_BLOCKS */
        uint64_t indirect_index = file_block - FUTURAFS_DIRECT_BLOCKS;
        uint64_t max_indirect_entries = FUTURAFS_BLOCK_SIZE / sizeof(uint64_t);

        bool use_double_indirect = (indirect_index >= max_indirect_entries);
        uint64_t indirect_block_num = 0;

        if (use_double_indirect) {
            /* Double indirect blocks: beyond single indirect capacity */
            uint64_t double_indirect_index = indirect_index - max_indirect_entries;
            uint64_t indirect_within_double = double_indirect_index / max_indirect_entries;
            uint64_t entry_in_indirect = double_indirect_index % max_indirect_entries;

            if (indirect_within_double >= max_indirect_entries) {
                /* Triple indirect blocks: beyond double indirect capacity
                 * File block layout:
                 * 0-11: direct
                 * 12-(12+512): single indirect
                 * (12+512)-(12+512*512): double indirect
                 * (12+512*512)+: triple indirect
                 */
                uint64_t triple_indirect_index = indirect_within_double - max_indirect_entries;
                uint64_t triple_level_1 = triple_indirect_index / (max_indirect_entries * max_indirect_entries);
                uint64_t triple_level_2 = (triple_indirect_index / max_indirect_entries) % max_indirect_entries;
                uint64_t triple_level_3 = triple_indirect_index % max_indirect_entries;

                if (triple_level_1 >= max_indirect_entries) {
                    /* File too large - would need 4-level indirection */
                    fut_free(write_ctx);
                    return FUTURAFS_ENOSPC;
                }

                /* Allocate triple-indirect block if needed */
                if (inode_info->disk_inode.triple_indirect == 0) {
                    uint64_t triple_indirect_block = 0;
                    int ret = futurafs_alloc_block(inode_info->mount, &triple_indirect_block);
                    if (ret < 0) {
                        fut_free(write_ctx);
                        return ret;
                    }
                    inode_info->disk_inode.triple_indirect = triple_indirect_block;
                    inode_info->dirty = true;

                    /* Zero out the triple-indirect block */
                    for (size_t i = 0; i < FUTURAFS_BLOCK_SIZE; i++) {
                        write_ctx->block_buffer[i] = 0;
                    }

                    /* Write zeroed triple-indirect block */
                    int write_ret = futurafs_blk_write(inode_info->mount,
                                                      inode_info->disk_inode.triple_indirect, 1,
                                                      write_ctx->block_buffer);
                    if (write_ret < 0) {
                        fut_free(write_ctx);
                        return write_ret;
                    }
                }

                /* Read triple-indirect block to find double-indirect block pointer */
                int read_ret = futurafs_blk_read(inode_info->mount,
                                                 inode_info->disk_inode.triple_indirect, 1,
                                                 write_ctx->block_buffer);
                if (read_ret < 0) {
                    fut_free(write_ctx);
                    return read_ret;
                }

                /* Get double-indirect block pointer from triple-indirect table */
                uint64_t *triple_indirect_table = (uint64_t *)write_ctx->block_buffer;
                uint64_t double_indirect_block_num = triple_indirect_table[triple_level_1];

                /* Allocate double-indirect block if needed */
                if (double_indirect_block_num == 0) {
                    int ret = futurafs_alloc_block(inode_info->mount, &double_indirect_block_num);
                    if (ret < 0) {
                        fut_free(write_ctx);
                        return ret;
                    }

                    /* Update triple-indirect table and write it back */
                    triple_indirect_table[triple_level_1] = double_indirect_block_num;
                    int write_ret = futurafs_blk_write(inode_info->mount,
                                                      inode_info->disk_inode.triple_indirect, 1,
                                                      write_ctx->block_buffer);
                    if (write_ret < 0) {
                        fut_free(write_ctx);
                        return write_ret;
                    }

                    inode_info->disk_inode.blocks++;
                    inode_info->dirty = true;

                    /* Zero out the new double-indirect block */
                    for (size_t i = 0; i < FUTURAFS_BLOCK_SIZE; i++) {
                        write_ctx->block_buffer[i] = 0;
                    }

                    /* Write zeroed double-indirect block */
                    int write_ret2 = futurafs_blk_write(inode_info->mount,
                                                       double_indirect_block_num, 1,
                                                       write_ctx->block_buffer);
                    if (write_ret2 < 0) {
                        fut_free(write_ctx);
                        return write_ret2;
                    }
                }

                /* Read double-indirect block to find indirect block pointer */
                read_ret = futurafs_blk_read(inode_info->mount,
                                             double_indirect_block_num, 1,
                                             write_ctx->block_buffer);
                if (read_ret < 0) {
                    fut_free(write_ctx);
                    return read_ret;
                }

                /* Get indirect block pointer from double-indirect table */
                uint64_t *double_indirect_table = (uint64_t *)write_ctx->block_buffer;
                uint64_t indirect_block_num = double_indirect_table[triple_level_2];

                /* Allocate indirect block if needed */
                if (indirect_block_num == 0) {
                    int ret = futurafs_alloc_block(inode_info->mount, &indirect_block_num);
                    if (ret < 0) {
                        fut_free(write_ctx);
                        return ret;
                    }

                    /* Update double-indirect table and write it back */
                    double_indirect_table[triple_level_2] = indirect_block_num;
                    int write_ret = futurafs_blk_write(inode_info->mount,
                                                      double_indirect_block_num, 1,
                                                      write_ctx->block_buffer);
                    if (write_ret < 0) {
                        fut_free(write_ctx);
                        return write_ret;
                    }

                    inode_info->disk_inode.blocks++;
                    inode_info->dirty = true;

                    /* Zero out the new indirect block */
                    for (size_t i = 0; i < FUTURAFS_BLOCK_SIZE; i++) {
                        write_ctx->block_buffer[i] = 0;
                    }

                    /* Write zeroed indirect block */
                    int write_ret2 = futurafs_blk_write(inode_info->mount,
                                                       indirect_block_num, 1,
                                                       write_ctx->block_buffer);
                    if (write_ret2 < 0) {
                        fut_free(write_ctx);
                        return write_ret2;
                    }
                }

                /* Read indirect block to get the data block pointer */
                read_ret = futurafs_blk_read(inode_info->mount,
                                             indirect_block_num, 1,
                                             write_ctx->block_buffer);
                if (read_ret < 0) {
                    fut_free(write_ctx);
                    return read_ret;
                }

                /* Get data block pointer from indirect table */
                uint64_t *indirect_table = (uint64_t *)write_ctx->block_buffer;
                block_num = indirect_table[triple_level_3];

                /* Allocate data block if needed */
                if (block_num == 0) {
                    int ret = futurafs_alloc_block(inode_info->mount, &block_num);
                    if (ret < 0) {
                        fut_free(write_ctx);
                        return ret;
                    }

                    /* Update indirect table and write it back */
                    indirect_table[triple_level_3] = block_num;
                    int write_ret = futurafs_blk_write(inode_info->mount,
                                                      indirect_block_num, 1,
                                                      write_ctx->block_buffer);
                    if (write_ret < 0) {
                        fut_free(write_ctx);
                        return write_ret;
                    }

                    inode_info->disk_inode.blocks++;
                    inode_info->dirty = true;
                }

                /* Use block_num from triple-indirect logic */
            }

            /* Check if double-indirect block exists */
            if (inode_info->disk_inode.double_indirect == 0) {
                /* Need to allocate double-indirect block */
                uint64_t double_indirect_block = 0;
                int ret = futurafs_alloc_block(inode_info->mount, &double_indirect_block);
                if (ret < 0) {
                    fut_free(write_ctx);
                    return ret;
                }
                inode_info->disk_inode.double_indirect = double_indirect_block;
                inode_info->dirty = true;

                /* Zero out the double-indirect block */
                for (size_t i = 0; i < FUTURAFS_BLOCK_SIZE; i++) {
                    write_ctx->block_buffer[i] = 0;
                }

                /* Write zeroed double-indirect block */
                int write_ret = futurafs_blk_write(inode_info->mount,
                                                  inode_info->disk_inode.double_indirect, 1,
                                                  write_ctx->block_buffer);
                if (write_ret < 0) {
                    fut_free(write_ctx);
                    return write_ret;
                }
            }

            /* Read double-indirect block to find indirect block pointer */
            int read_ret = futurafs_blk_read(inode_info->mount,
                                            inode_info->disk_inode.double_indirect, 1,
                                            write_ctx->block_buffer);
            if (read_ret < 0) {
                fut_free(write_ctx);
                return read_ret;
            }

            /* Get indirect block pointer from double-indirect table */
            uint64_t *double_indirect_table = (uint64_t *)write_ctx->block_buffer;
            indirect_block_num = double_indirect_table[indirect_within_double];

            /* Allocate indirect block if needed */
            if (indirect_block_num == 0) {
                int ret = futurafs_alloc_block(inode_info->mount, &indirect_block_num);
                if (ret < 0) {
                    fut_free(write_ctx);
                    return ret;
                }

                /* Update double-indirect table and write it back */
                double_indirect_table[indirect_within_double] = indirect_block_num;
                int write_ret = futurafs_blk_write(inode_info->mount,
                                                  inode_info->disk_inode.double_indirect, 1,
                                                  write_ctx->block_buffer);
                if (write_ret < 0) {
                    fut_free(write_ctx);
                    return write_ret;
                }

                inode_info->disk_inode.blocks++;
                inode_info->dirty = true;

                /* Zero out the new indirect block */
                for (size_t i = 0; i < FUTURAFS_BLOCK_SIZE; i++) {
                    write_ctx->block_buffer[i] = 0;
                }

                /* Write zeroed indirect block */
                int write_ret2 = futurafs_blk_write(inode_info->mount,
                                                   indirect_block_num, 1,
                                                   write_ctx->block_buffer);
                if (write_ret2 < 0) {
                    fut_free(write_ctx);
                    return write_ret2;
                }
            }

            /* Read indirect block to get the data block pointer */
            read_ret = futurafs_blk_read(inode_info->mount,
                                        indirect_block_num, 1,
                                        write_ctx->block_buffer);
            if (read_ret < 0) {
                fut_free(write_ctx);
                return read_ret;
            }

            /* Update indirect_index for the subsequent logic to use correct offset */
            indirect_index = entry_in_indirect;
        } else {
            /* Single indirect block handling */

        /* Check if indirect block exists */
        if (inode_info->disk_inode.indirect == 0) {
            /* Need to allocate indirect block */
            uint64_t indirect_block = 0;
            int ret = futurafs_alloc_block(inode_info->mount, &indirect_block);
            if (ret < 0) {
                fut_free(write_ctx);
                return ret;
            }
            inode_info->disk_inode.indirect = indirect_block;
            inode_info->dirty = true;

            /* Zero out the indirect block */
            for (size_t i = 0; i < FUTURAFS_BLOCK_SIZE; i++) {
                write_ctx->block_buffer[i] = 0;
            }

            /* Write zeroed indirect block */
            int write_ret = futurafs_blk_write(inode_info->mount,
                                              inode_info->disk_inode.indirect, 1,
                                              write_ctx->block_buffer);
            if (write_ret < 0) {
                fut_free(write_ctx);
                return write_ret;
            }
        }

        /* Read indirect block to check/update pointers */
        int read_ret = futurafs_blk_read(inode_info->mount,
                                         inode_info->disk_inode.indirect, 1,
                                         write_ctx->block_buffer);
        if (read_ret < 0) {
            fut_free(write_ctx);
            return read_ret;
        }

        /* Get block pointer from indirect table */
        uint64_t *indirect_table = (uint64_t *)write_ctx->block_buffer;
        block_num = indirect_table[indirect_index];

        /* Allocate data block if needed */
        if (block_num == 0) {
            int ret = futurafs_alloc_block(inode_info->mount, &block_num);
            if (ret < 0) {
                fut_free(write_ctx);
                return ret;
            }

            /* Update indirect table and write it back */
            indirect_table[indirect_index] = block_num;
            int write_ret = futurafs_blk_write(inode_info->mount,
                                              inode_info->disk_inode.indirect, 1,
                                              write_ctx->block_buffer);
            if (write_ret < 0) {
                fut_free(write_ctx);
                return write_ret;
            }

            inode_info->disk_inode.blocks++;
            inode_info->dirty = true;
            write_ctx->allocated_block = true;
        }
        }  /* End of single-indirect else block */
    }

    write_ctx->current_block_num = block_num;

    /* Check if we need read-modify-write (partial block) */
    bool need_read = (block_offset != 0 || to_write != FUTURAFS_BLOCK_SIZE);
    if (need_read) {
        /* Read block first for read-modify-write */
        write_ctx->state = FILE_WRITE_READING;
        int ret = futurafs_read_block_async(inode_info->mount, block_num,
                                           write_ctx->block_buffer,
                                           futurafs_file_write_callback, write_ctx);
        if (ret < 0) {
            fut_free(write_ctx);
            return ret;
        }
    } else {
        /* Full block write - prepare data and write directly */
        const uint8_t *src = (const uint8_t *)buffer;
        for (size_t i = 0; i < FUTURAFS_BLOCK_SIZE; i++) {
            write_ctx->block_buffer[i] = src[i];
        }

        write_ctx->state = FILE_WRITE_WRITING;
        int ret = futurafs_write_block_async(inode_info->mount, block_num,
                                             write_ctx->block_buffer,
                                             futurafs_file_write_callback, write_ctx);
        if (ret < 0) {
            fut_free(write_ctx);
            return ret;
        }
    }

    return 0;
}

/* ============================================================
 *   Phase 3c: Synchronous Wrappers for VFS Integration
 * ============================================================ */

/**
 * Synchronous completion context.
 * Used for blocking wrappers that poll until async operation completes.
 */
struct futurafs_sync_ctx {
    volatile bool completed;
    int result;
};

/**
 * Synchronous completion callback.
 * Sets completion flag and stores result for blocking wrapper.
 */
static void futurafs_sync_completion(int result, void *ctx) {
    struct futurafs_sync_ctx *sync_ctx = (struct futurafs_sync_ctx *)ctx;
    sync_ctx->result = result;
    sync_ctx->completed = true;
}

/**
 * Synchronous file read wrapper (blocks until async operation completes).
 * Transition helper for converting VFS operations to use async I/O.
 *
 * @param inode_info Inode information structure
 * @param buffer     Buffer to read into
 * @param size       Number of bytes to read
 * @param offset     File offset to read from
 * @return Number of bytes read on success, negative error code on failure
 */
static ssize_t futurafs_file_read_sync(struct futurafs_inode_info *inode_info,
                                        void *buffer,
                                        size_t size,
                                        uint64_t offset) {
    struct futurafs_sync_ctx sync_ctx = {
        .completed = false,
        .result = 0
    };

    /* Submit async read operation */
    int ret = futurafs_file_read_async(inode_info, buffer, size, offset,
                                       futurafs_sync_completion, &sync_ctx);
    if (ret < 0) {
        return ret;
    }

    /* Busy-wait until async operation completes */
    while (!sync_ctx.completed) {
        /* In a real implementation, this would yield to scheduler */
        #ifdef __x86_64__
        __asm__ volatile("pause" ::: "memory");
#elif defined(__aarch64__)
        __asm__ volatile("yield" ::: "memory");
#endif
    }

    return sync_ctx.result;
}

/**
 * Synchronous file write wrapper (blocks until async operation completes).
 * Transition helper for converting VFS operations to use async I/O.
 *
 * @param inode_info Inode information structure
 * @param buffer     Buffer to write from
 * @param size       Number of bytes to write
 * @param offset     File offset to write to
 * @return Number of bytes written on success, negative error code on failure
 */
static ssize_t futurafs_file_write_sync(struct futurafs_inode_info *inode_info,
                                         const void *buffer,
                                         size_t size,
                                         uint64_t offset) {
    struct futurafs_sync_ctx sync_ctx = {
        .completed = false,
        .result = 0
    };

    /* Submit async write operation */
    int ret = futurafs_file_write_async(inode_info, buffer, size, offset,
                                        futurafs_sync_completion, &sync_ctx);
    if (ret < 0) {
        return ret;
    }

    /* Busy-wait until async operation completes */
    while (!sync_ctx.completed) {
        /* In a real implementation, this would yield to scheduler */
        #ifdef __x86_64__
        __asm__ volatile("pause" ::: "memory");
#elif defined(__aarch64__)
        __asm__ volatile("yield" ::: "memory");
#endif
    }

    return sync_ctx.result;
}

/* ============================================================
 *   Legacy Synchronous I/O Functions
 * ============================================================ */

/**
 * Read inode from disk (synchronous wrapper over async operation).
 * Routes all inode reads through the async I/O path.
 */
static int futurafs_read_inode(struct futurafs_mount *mount, uint64_t ino,
                               struct futurafs_inode *inode) {
    struct futurafs_sync_ctx sync_ctx = {
        .completed = false,
        .result = 0
    };

    /* Submit async read operation */
    int ret = futurafs_read_inode_async(mount, ino, inode,
                                       futurafs_sync_completion, &sync_ctx);
    if (ret < 0) {
        return ret;
    }

    /* Busy-wait until async operation completes */
    while (!sync_ctx.completed) {
        #ifdef __x86_64__
        __asm__ volatile("pause" ::: "memory");
#elif defined(__aarch64__)
        __asm__ volatile("yield" ::: "memory");
#endif
    }

    return sync_ctx.result;
}

/**
 * Write inode to disk (synchronous wrapper over async operation).
 * Routes all inode writes through the async I/O path.
 */
static int futurafs_write_inode(struct futurafs_mount *mount, uint64_t ino,
                                struct futurafs_inode *inode) {
    struct futurafs_sync_ctx sync_ctx = {
        .completed = false,
        .result = 0
    };

    /* Submit async write operation */
    int ret = futurafs_write_inode_async(mount, ino, inode,
                                        futurafs_sync_completion, &sync_ctx);
    if (ret < 0) {
        return ret;
    }

    /* Busy-wait until async operation completes */
    while (!sync_ctx.completed) {
        #ifdef __x86_64__
        __asm__ volatile("pause" ::: "memory");
#elif defined(__aarch64__)
        __asm__ volatile("yield" ::: "memory");
#endif
    }

    return sync_ctx.result;
}

/**
 * Allocate a new inode.
 */
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

#define FUTURAFS_S_IFMT   0170000
#define FUTURAFS_S_IFIFO  0010000
#define FUTURAFS_S_IFCHR  0020000
#define FUTURAFS_S_IFDIR  0040000
#define FUTURAFS_S_IFBLK  0060000
#define FUTURAFS_S_IFREG  0100000
#define FUTURAFS_S_IFLNK  0120000
#define FUTURAFS_S_IFSOCK 0140000

static enum fut_vnode_type futurafs_mode_to_vtype(uint32_t mode) {
    switch (mode & FUTURAFS_S_IFMT) {
        case FUTURAFS_S_IFDIR:  return VN_DIR;
        case FUTURAFS_S_IFCHR:  return VN_CHR;
        case FUTURAFS_S_IFBLK:  return VN_BLK;
        case FUTURAFS_S_IFIFO:  return VN_FIFO;
        case FUTURAFS_S_IFSOCK: return VN_SOCK;
        case FUTURAFS_S_IFLNK:  return VN_LNK;
        default:                return VN_REG;
    }
}

static uint8_t futurafs_mode_to_filetype(uint32_t mode) {
    switch (mode & FUTURAFS_S_IFMT) {
        case FUTURAFS_S_IFDIR:  return FUTURAFS_FT_DIR;
        case FUTURAFS_S_IFCHR:  return FUTURAFS_FT_CHRDEV;
        case FUTURAFS_S_IFBLK:  return FUTURAFS_FT_BLKDEV;
        case FUTURAFS_S_IFIFO:  return FUTURAFS_FT_FIFO;
        case FUTURAFS_S_IFSOCK: return FUTURAFS_FT_SOCK;
        case FUTURAFS_S_IFLNK:  return FUTURAFS_FT_SYMLINK;
        default:                return FUTURAFS_FT_REG_FILE;
    }
}

static size_t futurafs_strnlen(const char *name, size_t max) {
    size_t len = 0;
    while (len < max && name[len]) {
        len++;
    }
    return len;
}

static bool futurafs_name_equals(const struct futurafs_dirent *dent, const char *name, size_t name_len) {
    if (dent->name_len != name_len) {
        return false;
    }
    for (size_t i = 0; i < name_len; ++i) {
        if ((uint8_t)dent->name[i] != (uint8_t)name[i]) {
            return false;
        }
    }
    return true;
}

static int futurafs_sync_metadata(struct futurafs_mount *mount) {
    if (!mount->dirty) {
        return 0;
    }

    size_t inode_bitmap_size = (mount->sb->total_inodes + 7) / 8;
    ssize_t written = futurafs_blk_write_bytes(mount,
                                               mount->sb->inode_bitmap_block * FUTURAFS_BLOCK_SIZE,
                                               inode_bitmap_size,
                                               mount->inode_bitmap);
    if (written < 0) {
        return FUTURAFS_EIO;
    }

    size_t data_bitmap_size = ((mount->sb->total_blocks - mount->sb->data_blocks_start) + 7) / 8;
    written = futurafs_blk_write_bytes(mount,
                                       mount->sb->data_bitmap_block * FUTURAFS_BLOCK_SIZE,
                                       data_bitmap_size,
                                       mount->data_bitmap);
    if (written < 0) {
        return FUTURAFS_EIO;
    }

    int ret = futurafs_write_superblock(mount, mount->sb);
    if (ret < 0) {
        return ret;
    }

    mount->dirty = false;
    return 0;
}

static int futurafs_create_vnode(struct fut_mount *vfs_mount,
                                 struct futurafs_mount *fs_mount,
                                 uint64_t ino,
                                 struct fut_vnode **out) {
    struct futurafs_inode_info *info = fut_malloc(sizeof(struct futurafs_inode_info));
    if (!info) {
        return FUTURAFS_EIO;
    }

    int ret = futurafs_read_inode(fs_mount, ino, &info->disk_inode);
    if (ret < 0) {
        fut_free(info);
        return ret;
    }

    struct fut_vnode *vnode = fut_malloc(sizeof(struct fut_vnode));
    if (!vnode) {
        fut_free(info);
        return FUTURAFS_EIO;
    }

    info->ino = ino;
    info->mount = fs_mount;
    info->dirty = false;

    vnode->type = futurafs_mode_to_vtype(info->disk_inode.mode);
    vnode->ino = ino;
    vnode->mode = info->disk_inode.mode;
    vnode->size = info->disk_inode.size;
    vnode->nlinks = info->disk_inode.nlinks;
    vnode->mount = vfs_mount;
    vnode->fs_data = info;
    vnode->refcount = 1;
    vnode->ops = &futurafs_vnode_ops;

    *out = vnode;
    return 0;
}

static int futurafs_dir_add_entry(struct fut_vnode *dir,
                                  struct futurafs_inode_info *dir_info,
                                  const char *name,
                                  size_t name_len,
                                  uint64_t ino,
                                  uint8_t file_type) {
    struct futurafs_mount *mount = dir_info->mount;
    uint8_t slot_buf[FUTURAFS_BLOCK_SIZE];
    bool slot_buf_valid = false;
    uint64_t slot_block = 0;
    size_t slot_offset = 0;
    int slot_index = -1;
    int new_block_index = -1;

    uint8_t block_buf[FUTURAFS_BLOCK_SIZE];

    for (int i = 0; i < FUTURAFS_DIRECT_BLOCKS; ++i) {
        uint64_t block_num = dir_info->disk_inode.direct[i];
        if (block_num == 0) {
            if (new_block_index == -1) {
                new_block_index = i;
            }
            continue;
        }

        if (futurafs_blk_read(mount, block_num, 1, block_buf) < 0) {
            return FUTURAFS_EIO;
        }

        for (size_t offset = 0; offset < FUTURAFS_BLOCK_SIZE; offset += sizeof(struct futurafs_dirent)) {
            struct futurafs_dirent *dent = (struct futurafs_dirent *)(block_buf + offset);
            if (dent->ino != 0) {
                if (futurafs_name_equals(dent, name, name_len)) {
                    return FUTURAFS_EEXIST;
                }
            } else if (slot_index == -1) {
                slot_index = i;
                slot_block = block_num;
                slot_offset = offset;
                slot_buf_valid = true;
                for (size_t j = 0; j < FUTURAFS_BLOCK_SIZE; ++j) {
                    slot_buf[j] = block_buf[j];
                }
            }
        }
    }

    bool allocated_block = false;
    if (!slot_buf_valid) {
        if (new_block_index == -1) {
            return FUTURAFS_ENOSPC;
        }

        uint64_t new_block;
        int ret = futurafs_alloc_block(mount, &new_block);
        if (ret < 0) {
            return ret;
        }
        allocated_block = true;

        for (size_t i = 0; i < FUTURAFS_BLOCK_SIZE; ++i) {
            slot_buf[i] = 0;
        }
        slot_buf_valid = true;
        slot_block = new_block;
        slot_offset = 0;
        slot_index = new_block_index;

        dir_info->disk_inode.direct[new_block_index] = new_block;
        dir_info->disk_inode.blocks++;
    }

    struct futurafs_dirent *dent = (struct futurafs_dirent *)(slot_buf + slot_offset);
    dent->ino = ino;
    dent->rec_len = sizeof(struct futurafs_dirent);
    dent->name_len = (uint8_t)name_len;
    dent->file_type = file_type;
    for (size_t i = 0; i < name_len; ++i) {
        dent->name[i] = name[i];
    }
    dent->name[name_len] = '\0';

    if (futurafs_blk_write(mount, slot_block, 1, slot_buf) < 0) {
        dent->ino = 0;
        if (allocated_block) {
            dir_info->disk_inode.direct[slot_index] = 0;
            dir_info->disk_inode.blocks--;
            futurafs_free_block(mount, slot_block);
        }
        return FUTURAFS_EIO;
    }

    dir_info->dirty = true;
    dir_info->disk_inode.size = dir_info->disk_inode.blocks * FUTURAFS_BLOCK_SIZE;
    dir->size = dir_info->disk_inode.size;

    return 0;
}

static int futurafs_dir_lookup_entry(struct futurafs_inode_info *dir_info,
                                     const char *name,
                                     size_t name_len,
                                     uint64_t *block_out,
                                     size_t *offset_out,
                                     struct futurafs_dirent *entry_out,
                                     uint8_t *block_buf_out) {
    struct futurafs_mount *mount = dir_info->mount;
    uint8_t block_buf[FUTURAFS_BLOCK_SIZE];

    for (int i = 0; i < FUTURAFS_DIRECT_BLOCKS; ++i) {
        uint64_t block_num = dir_info->disk_inode.direct[i];
        if (block_num == 0) {
            continue;
        }

        if (futurafs_blk_read(mount, block_num, 1, block_buf) < 0) {
            return FUTURAFS_EIO;
        }

        for (size_t offset = 0; offset < FUTURAFS_BLOCK_SIZE;
             offset += sizeof(struct futurafs_dirent)) {
            struct futurafs_dirent *dent =
                (struct futurafs_dirent *)(block_buf + offset);
            if (dent->ino == 0) {
                continue;
            }

            if (!futurafs_name_equals(dent, name, name_len)) {
                continue;
            }

            if (entry_out) {
                *entry_out = *dent;
            }
            if (block_out) {
                *block_out = block_num;
            }
            if (offset_out) {
                *offset_out = offset;
            }
            if (block_buf_out) {
                for (size_t j = 0; j < FUTURAFS_BLOCK_SIZE; ++j) {
                    block_buf_out[j] = block_buf[j];
                }
            }

            return 0;
        }
    }

    return FUTURAFS_ENOENT;
}

static int futurafs_dir_remove_entry(struct futurafs_inode_info *dir_info,
                                     uint64_t block_num,
                                     size_t offset,
                                     uint8_t *block_buf) {
    struct futurafs_mount *mount = dir_info->mount;
    struct futurafs_dirent *dent = (struct futurafs_dirent *)(block_buf + offset);

    for (size_t i = 0; i < sizeof(struct futurafs_dirent); ++i) {
        ((uint8_t *)dent)[i] = 0;
    }

    if (futurafs_blk_write(mount, block_num, 1, block_buf) < 0) {
        return FUTURAFS_EIO;
    }

    bool block_empty = true;
    for (size_t i = 0; i < FUTURAFS_BLOCK_SIZE; ++i) {
        if (block_buf[i] != 0) {
            block_empty = false;
            break;
        }
    }

    if (block_empty) {
        for (int i = 0; i < FUTURAFS_DIRECT_BLOCKS; ++i) {
            if (dir_info->disk_inode.direct[i] == block_num) {
                dir_info->disk_inode.direct[i] = 0;
                if (dir_info->disk_inode.blocks > 0) {
                    dir_info->disk_inode.blocks--;
                }
                int ret = futurafs_free_block(mount, block_num);
                if (ret < 0) {
                    return ret;
                }
                dir_info->dirty = true;
                break;
            }
        }
    }

    return 0;
}

static uint8_t futurafs_filetype_to_vdir_type(uint8_t file_type) {
    switch (file_type) {
        case FUTURAFS_FT_DIR:
            return FUT_VDIR_TYPE_DIR;
        case FUTURAFS_FT_CHRDEV:
            return FUT_VDIR_TYPE_CHAR;
        case FUTURAFS_FT_BLKDEV:
            return FUT_VDIR_TYPE_BLOCK;
        case FUTURAFS_FT_FIFO:
            return FUT_VDIR_TYPE_FIFO;
        case FUTURAFS_FT_SOCK:
            return FUT_VDIR_TYPE_SOCKET;
        case FUTURAFS_FT_SYMLINK:
            return FUT_VDIR_TYPE_SYMLINK;
        default:
            return FUT_VDIR_TYPE_REG;
    }
}

static int futurafs_inode_release_blocks(struct futurafs_mount *mount,
                                         struct futurafs_inode *inode) {
    for (int i = 0; i < FUTURAFS_DIRECT_BLOCKS; ++i) {
        uint64_t block_num = inode->direct[i];
        if (block_num == 0) {
            continue;
        }

        int ret = futurafs_free_block(mount, block_num);
        if (ret < 0) {
            return ret;
        }
        inode->direct[i] = 0;
    }

    if (inode->indirect != 0) {
        return FUTURAFS_EIO;
    }

    inode->blocks = 0;
    inode->size = 0;
    return 0;
}

static int futurafs_dir_is_empty(struct futurafs_mount *mount,
                                 const struct futurafs_inode *inode,
                                 bool *is_empty) {
    if (!is_empty) {
        return FUTURAFS_EINVAL;
    }

    if (inode->blocks == 0) {
        *is_empty = true;
        return 0;
    }

    uint8_t block_buf[FUTURAFS_BLOCK_SIZE];

    for (int i = 0; i < FUTURAFS_DIRECT_BLOCKS; ++i) {
        uint64_t block_num = inode->direct[i];
        if (block_num == 0) {
            continue;
        }

        if (futurafs_blk_read(mount, block_num, 1, block_buf) < 0) {
            return FUTURAFS_EIO;
        }

        for (size_t offset = 0; offset < FUTURAFS_BLOCK_SIZE;
             offset += sizeof(struct futurafs_dirent)) {
            struct futurafs_dirent *dent =
                (struct futurafs_dirent *)(block_buf + offset);
            if (dent->ino == 0) {
                continue;
            }

            if (dent->name_len == 1 && dent->name[0] == '.') {
                continue;
            }
            if (dent->name_len == 2 &&
                dent->name[0] == '.' && dent->name[1] == '.') {
                continue;
            }

            *is_empty = false;
            return 0;
        }
    }

    *is_empty = true;
    return 0;
}

/* ============================================================
 *   VNode Operations
 * ============================================================ */

static ssize_t futurafs_vnode_read(struct fut_vnode *vnode, void *buf, size_t size, uint64_t offset) {
    struct futurafs_inode_info *inode_info = (struct futurafs_inode_info *)vnode->fs_data;

    /* Use async I/O path via synchronous wrapper */
    return futurafs_file_read_sync(inode_info, buf, size, offset);
}

static ssize_t futurafs_vnode_write(struct fut_vnode *vnode, const void *buf, size_t size, uint64_t offset) {
    struct futurafs_inode_info *inode_info = (struct futurafs_inode_info *)vnode->fs_data;

    /* Use async I/O path via synchronous wrapper */
    return futurafs_file_write_sync(inode_info, buf, size, offset);
}

static int futurafs_vnode_readdir(struct fut_vnode *dir,
                                  uint64_t *cookie,
                                  struct fut_vdirent *dirent) {
    if (!dir || !cookie || !dirent) {
        return FUTURAFS_EINVAL;
    }

    if (dir->type != VN_DIR) {
        return FUTURAFS_ENOTDIR;
    }

    struct futurafs_inode_info *dir_info = (struct futurafs_inode_info *)dir->fs_data;
    struct futurafs_mount *mount = dir_info->mount;

    uint64_t offset = *cookie;
    size_t entry_size = sizeof(struct futurafs_dirent);
    uint64_t max_size = dir_info->disk_inode.blocks * FUTURAFS_BLOCK_SIZE;

    if (dir_info->disk_inode.blocks == 0) {
        *cookie = 0;
        return FUTURAFS_ENOENT;
    }

    if (offset >= max_size) {
        *cookie = max_size;
        return FUTURAFS_ENOENT;
    }

    while (offset < (uint64_t)FUTURAFS_DIRECT_BLOCKS * FUTURAFS_BLOCK_SIZE) {
        uint64_t block_index = offset / FUTURAFS_BLOCK_SIZE;
        if (block_index >= dir_info->disk_inode.blocks ||
            block_index >= FUTURAFS_DIRECT_BLOCKS) {
            break;
        }

        uint64_t block_num = dir_info->disk_inode.direct[block_index];
        size_t block_offset = offset % FUTURAFS_BLOCK_SIZE;

        if (block_num == 0) {
            offset = (block_index + 1) * FUTURAFS_BLOCK_SIZE;
            *cookie = offset;
            continue;
        }

        uint8_t block_buf[FUTURAFS_BLOCK_SIZE];
        if (futurafs_blk_read(mount, block_num, 1, block_buf) < 0) {
            return FUTURAFS_EIO;
        }

        if (block_offset % entry_size != 0) {
            block_offset = (block_offset / entry_size) * entry_size;
        }

        while (block_offset < FUTURAFS_BLOCK_SIZE) {
            struct futurafs_dirent *dent =
                (struct futurafs_dirent *)(block_buf + block_offset);
            offset = block_index * FUTURAFS_BLOCK_SIZE + block_offset + entry_size;

            if (dent->ino != 0) {
                dirent->d_ino = dent->ino;
                dirent->d_off = offset;
                dirent->d_reclen = (uint16_t)entry_size;
                dirent->d_type = futurafs_filetype_to_vdir_type(dent->file_type);

                size_t name_len = dent->name_len;
                if (name_len > FUT_VFS_NAME_MAX) {
                    name_len = FUT_VFS_NAME_MAX;
                }
                for (size_t i = 0; i < name_len; ++i) {
                    dirent->d_name[i] = dent->name[i];
                }
                dirent->d_name[name_len] = '\0';

                *cookie = offset;
                return 0;
            }

            block_offset += entry_size;
        }

        offset = (block_index + 1) * FUTURAFS_BLOCK_SIZE;
        *cookie = offset;
    }

    *cookie = max_size;
    return FUTURAFS_ENOENT;
}

static int futurafs_vnode_lookup(struct fut_vnode *dir, const char *name, struct fut_vnode **result) {
    if (!dir || !result) {
        return FUTURAFS_EINVAL;
    }

    if (dir->type != VN_DIR) {
        return FUTURAFS_ENOTDIR;
    }

    size_t name_len = futurafs_strnlen(name, FUTURAFS_NAME_MAX);
    if (name_len == 0 || name_len > FUTURAFS_NAME_MAX) {
        return FUTURAFS_EINVAL;
    }

    struct futurafs_inode_info *dir_info = (struct futurafs_inode_info *)dir->fs_data;
    struct futurafs_mount *mount = dir_info->mount;
    uint8_t block_buf[FUTURAFS_BLOCK_SIZE];

    for (int i = 0; i < FUTURAFS_DIRECT_BLOCKS; ++i) {
        uint64_t block_num = dir_info->disk_inode.direct[i];
        if (block_num == 0) {
            continue;
        }

        if (futurafs_blk_read(mount, block_num, 1, block_buf) < 0) {
            return FUTURAFS_EIO;
        }

        for (size_t offset = 0; offset < FUTURAFS_BLOCK_SIZE; offset += sizeof(struct futurafs_dirent)) {
            struct futurafs_dirent *dent = (struct futurafs_dirent *)(block_buf + offset);
            if (dent->ino == 0) {
                continue;
            }

            if (futurafs_name_equals(dent, name, name_len)) {
                return futurafs_create_vnode(dir->mount, mount, dent->ino, result);
            }
        }
    }

    *result = NULL;
    return FUTURAFS_ENOENT;
}

static int futurafs_vnode_create(struct fut_vnode *dir, const char *name, uint32_t mode,
                                 struct fut_vnode **result) {
    if (!dir || !result) {
        return FUTURAFS_EINVAL;
    }

    if (dir->type != VN_DIR) {
        return FUTURAFS_ENOTDIR;
    }

    size_t name_len = futurafs_strnlen(name, FUTURAFS_NAME_MAX);
    if (name_len == 0 || name_len > FUTURAFS_NAME_MAX) {
        return FUTURAFS_EINVAL;
    }

    struct futurafs_inode_info *dir_info = (struct futurafs_inode_info *)dir->fs_data;
    struct futurafs_mount *mount = dir_info->mount;

    uint64_t new_ino;
    int ret = futurafs_alloc_inode(mount, &new_ino);
    if (ret < 0) {
        return ret;
    }

    struct futurafs_inode inode = {0};
    inode.mode = mode ? mode : FUTURAFS_S_IFREG | 0644;
    if ((inode.mode & FUTURAFS_S_IFMT) == 0) {
        inode.mode |= FUTURAFS_S_IFREG;
    }
    inode.uid = 0;
    inode.gid = 0;
    inode.nlinks = 1;
    inode.size = 0;
    inode.blocks = 0;

    ret = futurafs_write_inode(mount, new_ino, &inode);
    if (ret < 0) {
        futurafs_free_inode(mount, new_ino);
        futurafs_sync_metadata(mount);
        return ret;
    }

    ret = futurafs_dir_add_entry(dir, dir_info, name, name_len, new_ino,
                                 futurafs_mode_to_filetype(inode.mode));
    if (ret < 0) {
        futurafs_free_inode(mount, new_ino);
        futurafs_sync_metadata(mount);
        return ret;
    }

    dir->size = dir_info->disk_inode.size;
    if (futurafs_write_inode(mount, dir_info->ino, &dir_info->disk_inode) < 0) {
        futurafs_sync_metadata(mount);
        return FUTURAFS_EIO;
    }
    dir_info->dirty = false;

    ret = futurafs_sync_metadata(mount);
    if (ret < 0) {
        return ret;
    }

    return futurafs_create_vnode(dir->mount, mount, new_ino, result);
}

static int futurafs_vnode_mkdir(struct fut_vnode *dir, const char *name, uint32_t mode) {
    fut_printf("[futurafs] mkdir enter dir=%llu name=%s\n",
               dir ? (unsigned long long)dir->ino : 0,
               name ? name : "<null>");
    if (!dir) {
        return FUTURAFS_EINVAL;
    }

    if (dir->type != VN_DIR) {
        return FUTURAFS_ENOTDIR;
    }

    size_t name_len = futurafs_strnlen(name, FUTURAFS_NAME_MAX);
    if (name_len == 0 || name_len > FUTURAFS_NAME_MAX) {
        return FUTURAFS_EINVAL;
    }

    struct futurafs_inode_info *dir_info = (struct futurafs_inode_info *)dir->fs_data;
    struct futurafs_mount *mount = dir_info->mount;

    uint64_t new_ino;
    int ret = futurafs_alloc_inode(mount, &new_ino);
    if (ret < 0) {
        return ret;
    }

    uint64_t new_block;
    ret = futurafs_alloc_block(mount, &new_block);
    if (ret < 0) {
        futurafs_free_inode(mount, new_ino);
        return ret;
    }

    uint8_t block_buf[FUTURAFS_BLOCK_SIZE];
    for (size_t i = 0; i < FUTURAFS_BLOCK_SIZE; ++i) {
        block_buf[i] = 0;
    }

    struct futurafs_dirent *dot = (struct futurafs_dirent *)block_buf;
    dot->ino = new_ino;
    dot->rec_len = sizeof(struct futurafs_dirent);
    dot->name_len = 1;
    dot->file_type = FUTURAFS_FT_DIR;
    dot->name[0] = '.';
    dot->name[1] = '\0';

    struct futurafs_dirent *dotdot = (struct futurafs_dirent *)(block_buf + sizeof(struct futurafs_dirent));
    dotdot->ino = dir->ino;
    dotdot->rec_len = sizeof(struct futurafs_dirent);
    dotdot->name_len = 2;
    dotdot->file_type = FUTURAFS_FT_DIR;
    dotdot->name[0] = '.';
    dotdot->name[1] = '.';
    dotdot->name[2] = '\0';

    if (futurafs_blk_write(mount, new_block, 1, block_buf) < 0) {
        futurafs_free_block(mount, new_block);
        futurafs_free_inode(mount, new_ino);
        futurafs_sync_metadata(mount);
        return FUTURAFS_EIO;
    }

    struct futurafs_inode inode = {0};
    inode.mode = mode ? mode : (FUTURAFS_S_IFDIR | 0755);
    if ((inode.mode & FUTURAFS_S_IFMT) == 0) {
        inode.mode |= FUTURAFS_S_IFDIR;
    }
    inode.uid = 0;
    inode.gid = 0;
    inode.nlinks = 2;  /* '.' and '..' */
    inode.size = 2 * sizeof(struct futurafs_dirent);
    inode.blocks = 1;
    inode.direct[0] = new_block;

    ret = futurafs_write_inode(mount, new_ino, &inode);
    if (ret < 0) {
        futurafs_free_block(mount, new_block);
        futurafs_free_inode(mount, new_ino);
        futurafs_sync_metadata(mount);
        return ret;
    }

    ret = futurafs_dir_add_entry(dir, dir_info, name, name_len, new_ino, FUTURAFS_FT_DIR);
    if (ret < 0) {
        futurafs_free_block(mount, new_block);
        futurafs_free_inode(mount, new_ino);
        futurafs_sync_metadata(mount);
        return ret;
    }

    dir_info->disk_inode.nlinks++;
    dir->nlinks = dir_info->disk_inode.nlinks;
    if (futurafs_write_inode(mount, dir_info->ino, &dir_info->disk_inode) < 0) {
        futurafs_sync_metadata(mount);
        return FUTURAFS_EIO;
    }
    dir_info->dirty = false;

    ret = futurafs_sync_metadata(mount);
    if (ret < 0) {
        return ret;
    }

    fut_printf("[futurafs] mkdir exit new_ino=%llu\n", (unsigned long long)new_ino);
    return 0;
}

static int futurafs_vnode_unlink(struct fut_vnode *dir, const char *name) {
    if (!dir || !name) {
        return FUTURAFS_EINVAL;
    }

    if (dir->type != VN_DIR) {
        return FUTURAFS_ENOTDIR;
    }

    size_t name_len = futurafs_strnlen(name, FUTURAFS_NAME_MAX);
    if (name_len == 0 || name_len > FUTURAFS_NAME_MAX) {
        return FUTURAFS_EINVAL;
    }

    struct futurafs_inode_info *dir_info = (struct futurafs_inode_info *)dir->fs_data;
    struct futurafs_mount *mount = dir_info->mount;

    uint8_t block_buf[FUTURAFS_BLOCK_SIZE];
    struct futurafs_dirent entry = {0};
    uint64_t block_num = 0;
    size_t block_offset = 0;

    int ret = futurafs_dir_lookup_entry(dir_info, name, name_len, &block_num,
                                        &block_offset, &entry, block_buf);
    if (ret < 0) {
        return ret;
    }

    if (entry.file_type == FUTURAFS_FT_DIR) {
        return FUTURAFS_EISDIR;
    }

    struct futurafs_inode target_inode = {0};
    ret = futurafs_read_inode(mount, entry.ino, &target_inode);
    if (ret < 0) {
        return ret;
    }

    if (target_inode.indirect != 0) {
        return FUTURAFS_EIO;
    }
    if (target_inode.nlinks == 0) {
        return FUTURAFS_EIO;
    }

    ret = futurafs_dir_remove_entry(dir_info, block_num, block_offset, block_buf);
    if (ret < 0) {
        return ret;
    }

    dir_info->disk_inode.size = dir_info->disk_inode.blocks * FUTURAFS_BLOCK_SIZE;
    dir->size = dir_info->disk_inode.size;

    if (dir_info->dirty) {
        if (futurafs_write_inode(mount, dir_info->ino, &dir_info->disk_inode) < 0) {
            dir_info->dirty = true;
            return FUTURAFS_EIO;
        }
        dir_info->dirty = false;
    }

    if (target_inode.nlinks > 0) {
        target_inode.nlinks--;
    }

    if (target_inode.nlinks == 0) {
        ret = futurafs_inode_release_blocks(mount, &target_inode);
        if (ret < 0) {
            return ret;
        }

        for (size_t i = 0; i < sizeof(struct futurafs_inode); ++i) {
            ((uint8_t *)&target_inode)[i] = 0;
        }

        ret = futurafs_write_inode(mount, entry.ino, &target_inode);
        if (ret < 0) {
            return ret;
        }

        ret = futurafs_free_inode(mount, entry.ino);
        if (ret < 0) {
            return ret;
        }
    } else {
        ret = futurafs_write_inode(mount, entry.ino, &target_inode);
        if (ret < 0) {
            return ret;
        }
    }

    ret = futurafs_sync_metadata(mount);
    if (ret < 0) {
        return ret;
    }

    return 0;
}

static int futurafs_vnode_rmdir(struct fut_vnode *dir, const char *name) {
    if (!dir || !name) {
        return FUTURAFS_EINVAL;
    }

    if (dir->type != VN_DIR) {
        return FUTURAFS_ENOTDIR;
    }

    size_t name_len = futurafs_strnlen(name, FUTURAFS_NAME_MAX);
    if (name_len == 0 || name_len > FUTURAFS_NAME_MAX) {
        return FUTURAFS_EINVAL;
    }

    if ((name_len == 1 && name[0] == '.') ||
        (name_len == 2 && name[0] == '.' && name[1] == '.')) {
        return FUTURAFS_EINVAL;
    }

    struct futurafs_inode_info *dir_info = (struct futurafs_inode_info *)dir->fs_data;
    struct futurafs_mount *mount = dir_info->mount;

    uint8_t block_buf[FUTURAFS_BLOCK_SIZE];
    struct futurafs_dirent entry = {0};
    uint64_t block_num = 0;
    size_t block_offset = 0;

    int ret = futurafs_dir_lookup_entry(dir_info, name, name_len, &block_num,
                                        &block_offset, &entry, block_buf);
    if (ret < 0) {
        return ret;
    }

    if (entry.file_type != FUTURAFS_FT_DIR) {
        return FUTURAFS_ENOTDIR;
    }

    struct futurafs_inode child_inode = {0};
    ret = futurafs_read_inode(mount, entry.ino, &child_inode);
    if (ret < 0) {
        return ret;
    }

    if (child_inode.indirect != 0) {
        return FUTURAFS_EIO;
    }

    bool empty = false;
    ret = futurafs_dir_is_empty(mount, &child_inode, &empty);
    if (ret < 0) {
        return ret;
    }
    if (!empty) {
        return FUTURAFS_ENOTEMPTY;
    }

    ret = futurafs_dir_remove_entry(dir_info, block_num, block_offset, block_buf);
    if (ret < 0) {
        return ret;
    }

    if (dir_info->disk_inode.nlinks > 0) {
        dir_info->disk_inode.nlinks--;
    }
    dir->nlinks = dir_info->disk_inode.nlinks;
    dir_info->disk_inode.size = dir_info->disk_inode.blocks * FUTURAFS_BLOCK_SIZE;
    dir->size = dir_info->disk_inode.size;
    dir_info->dirty = true;

    ret = futurafs_inode_release_blocks(mount, &child_inode);
    if (ret < 0) {
        return ret;
    }

    for (size_t i = 0; i < sizeof(struct futurafs_inode); ++i) {
        ((uint8_t *)&child_inode)[i] = 0;
    }

    ret = futurafs_write_inode(mount, entry.ino, &child_inode);
    if (ret < 0) {
        return ret;
    }

    ret = futurafs_free_inode(mount, entry.ino);
    if (ret < 0) {
        return ret;
    }

    if (futurafs_write_inode(mount, dir_info->ino, &dir_info->disk_inode) < 0) {
        return FUTURAFS_EIO;
    }
    dir_info->dirty = false;

    ret = futurafs_sync_metadata(mount);
    if (ret < 0) {
        return ret;
    }

    return 0;
}

/* Initialize FuturaFS vnode operations at runtime */
static void futurafs_init_vnode_ops(void) {
    futurafs_vnode_ops.open = NULL;
    futurafs_vnode_ops.close = NULL;
    futurafs_vnode_ops.read = futurafs_vnode_read;
    futurafs_vnode_ops.write = futurafs_vnode_write;
    futurafs_vnode_ops.readdir = futurafs_vnode_readdir;
    futurafs_vnode_ops.lookup = futurafs_vnode_lookup;
    futurafs_vnode_ops.create = futurafs_vnode_create;
    futurafs_vnode_ops.unlink = futurafs_vnode_unlink;
    futurafs_vnode_ops.mkdir = futurafs_vnode_mkdir;
    futurafs_vnode_ops.rmdir = futurafs_vnode_rmdir;
    futurafs_vnode_ops.getattr = NULL;
    futurafs_vnode_ops.setattr = NULL;
}

/* ============================================================
 *   Filesystem Operations
 * ============================================================ */

static int futurafs_mount_impl(const char *device, int flags, void *data, fut_handle_t block_device_handle, struct fut_mount **mount_out) {
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

    /* Store capability handle and legacy block device pointer */
    fs_mount->block_device_handle = block_device_handle;
    fs_mount->dev = dev;

    /* Read superblock */
    int ret = futurafs_read_superblock(fs_mount, fs_mount->sb);
    if (ret < 0) {
        fut_free(fs_mount->sb);
        fut_free(fs_mount);
        return ret;
    }
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

    ret = futurafs_blk_read_bytes(fs_mount, fs_mount->sb->inode_bitmap_block * FUTURAFS_BLOCK_SIZE,
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

    ret = futurafs_blk_read_bytes(fs_mount, fs_mount->sb->data_bitmap_block * FUTURAFS_BLOCK_SIZE,
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
        futurafs_write_superblock(fs_mount, fs_mount->sb);
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

static int futurafs_statfs_impl(struct fut_mount *mount, struct fut_statfs *out) {
    if (!mount || !out) {
        return -EINVAL;
    }

    struct futurafs_mount *fs_mount = (struct futurafs_mount *)mount->fs_data;
    if (!fs_mount || !fs_mount->sb) {
        return -EIO;
    }

    out->block_size = FUTURAFS_BLOCK_SIZE;
    out->blocks_total = fs_mount->sb->total_blocks;
    out->blocks_free = fs_mount->sb->free_blocks;
    out->inodes_total = fs_mount->sb->total_inodes;
    out->inodes_free = fs_mount->sb->free_inodes;
    out->dir_tombstones = 0;
    out->features = 0;

    return 0;
}

static const struct fut_fs_type futurafs_type = {
    .name = "futurafs",
    .mount = futurafs_mount_impl,
    .unmount = futurafs_unmount_impl,
    .statfs = futurafs_statfs_impl,
};

/* ============================================================
 *   Public API
 * ============================================================ */

void fut_futurafs_init(void) {
    /* Initialize vnode operations at runtime */
    futurafs_init_vnode_ops();

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
    int ret = fut_blockdev_write(dev, 0, 1, &sb);
    if (ret < 0) {
        return FUTURAFS_EIO;
    }
    fut_printf("[FUTURAFS-FMT] Superblock written\n");

    /* Initialize inode table (all zeros) */
    uint8_t zero_block[FUTURAFS_BLOCK_SIZE] = {0};
    for (uint64_t i = 0; i < inode_table_blocks; i++) {
        ret = fut_blockdev_write(dev, 1 + i, 1, zero_block);
        if (ret < 0) {
            return FUTURAFS_EIO;
        }
    }
    fut_printf("[FUTURAFS-FMT] Inode table zeroed (%llu blocks)\n",
               (unsigned long long)inode_table_blocks);

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
    fut_printf("[FUTURAFS-FMT] Root inode written\n");

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
    fut_printf("[FUTURAFS-FMT] Inode bitmap initialized (%zu bytes)\n", inode_bitmap_size);

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
    fut_printf("[FUTURAFS-FMT] Data bitmap initialized (%zu bytes)\n", data_bitmap_size);

    return 0;
}
