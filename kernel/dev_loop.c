/* kernel/dev_loop.c - Loop block device (/dev/loop*)
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements loop devices that present a regular file as a block device.
 * This enables mounting filesystem images (FuturaFS, ext2, etc.) without
 * physical storage, and is essential for containers and testing.
 *
 * Usage:
 *   1. Create a filesystem image file
 *   2. Associate it with a loop device via LOOP_SET_FD ioctl
 *   3. Mount the loop device: mount("/dev/loop0", "/mnt", "futurafs", 0, NULL)
 *
 * Supports up to 8 loop devices (/dev/loop0 through /dev/loop7).
 */

#include <kernel/fut_vfs.h>
#include <kernel/fut_blockdev.h>
#include <kernel/chrdev.h>
#include <kernel/fut_memory.h>
#include <kernel/kprintf.h>
#include <kernel/errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* Loop device ioctls (Linux compatible) */
#define LOOP_SET_FD         0x4C00
#define LOOP_CLR_FD         0x4C01
#define LOOP_GET_STATUS64   0x4C05

#define LOOP_MAX            8
#define LOOP_BLOCK_SIZE     512

struct loop_device {
    bool        active;         /* Device is configured */
    int         backing_fd;     /* FD of the backing file (kernel-internal) */
    uint64_t    file_size;      /* Size of the backing file in bytes */
    uint64_t    offset;         /* Offset into backing file */
    struct fut_blockdev *blkdev; /* Registered block device */
    char        name[16];       /* "loop0", "loop1", etc. */
};

static struct loop_device g_loops[LOOP_MAX];

/* Block device read operation: translate to file read */
static int loop_blk_read(struct fut_blockdev *dev, uint64_t block_num,
                         uint64_t num_blocks, void *buffer) {
    /* Find the loop device from private_data */
    struct loop_device *loop = (struct loop_device *)dev->private_data;
    if (!loop || !loop->active || loop->backing_fd < 0)
        return -EIO;

    uint64_t offset = loop->offset + block_num * LOOP_BLOCK_SIZE;
    uint64_t size = num_blocks * LOOP_BLOCK_SIZE;

    /* Bounds check */
    if (offset + size > loop->file_size)
        return -EIO;

    /* Read from backing file using pread64 */
    extern long sys_pread64(unsigned int fd, void *buf, size_t count, int64_t off);
    long n = sys_pread64((unsigned int)loop->backing_fd, buffer, (size_t)size, (int64_t)offset);
    if (n < 0) return (int)n;
    if ((uint64_t)n < size) {
        memset((uint8_t *)buffer + n, 0, (size_t)(size - (uint64_t)n));
    }
    return 0;
}

/* Block device write operation: translate to file write */
static int loop_blk_write(struct fut_blockdev *dev, uint64_t block_num,
                          uint64_t num_blocks, const void *buffer) {
    struct loop_device *loop = (struct loop_device *)dev->private_data;
    if (!loop || !loop->active || loop->backing_fd < 0)
        return -EIO;

    uint64_t offset = loop->offset + block_num * LOOP_BLOCK_SIZE;
    uint64_t size = num_blocks * LOOP_BLOCK_SIZE;

    if (offset + size > loop->file_size)
        return -EIO;

    extern long sys_pwrite64(unsigned int fd, const void *buf, size_t count, int64_t off);
    long n = sys_pwrite64((unsigned int)loop->backing_fd, buffer, (size_t)size, (int64_t)offset);
    return (n < 0) ? (int)n : 0;
}

static struct fut_blockdev_ops loop_blk_ops = {
    .read  = loop_blk_read,
    .write = loop_blk_write,
    .flush = NULL,
};

/**
 * loop_set_fd - Associate a file with a loop device
 *
 * @param loop_idx  Loop device index (0-7)
 * @param fd        File descriptor of the backing file
 * @return 0 on success, negative error code on failure
 */
int loop_set_fd(int loop_idx, int fd) {
    if (loop_idx < 0 || loop_idx >= LOOP_MAX)
        return -EINVAL;

    struct loop_device *loop = &g_loops[loop_idx];
    if (loop->active)
        return -EBUSY;

    /* Get the file size via fstat */
    extern long sys_fstat(int fd, void *statbuf);
    struct { uint64_t dev; uint64_t ino; uint32_t mode; uint32_t nlink;
             uint32_t uid; uint32_t gid; uint64_t rdev; uint64_t size;
             uint64_t blksize; uint64_t blocks;
             uint64_t atime; uint64_t atime_nsec;
             uint64_t mtime; uint64_t mtime_nsec;
             uint64_t ctime; uint64_t ctime_nsec; } st;
    memset(&st, 0, sizeof(st));
    long sr = sys_fstat(fd, &st);
    if (sr < 0) return (int)sr;
    if (st.size == 0) return -EINVAL;

    /* Allocate block device structure */
    struct fut_blockdev *blkdev = fut_malloc(sizeof(struct fut_blockdev));
    if (!blkdev) return -ENOMEM;

    memset(blkdev, 0, sizeof(*blkdev));
    memset(loop, 0, sizeof(*loop));

    /* Build name */
    loop->name[0] = 'l'; loop->name[1] = 'o'; loop->name[2] = 'o';
    loop->name[3] = 'p'; loop->name[4] = (char)('0' + loop_idx);
    loop->name[5] = '\0';

    loop->active = true;
    loop->backing_fd = fd;
    loop->file_size = st.size;
    loop->offset = 0;
    loop->blkdev = blkdev;

    /* Configure block device */
    memcpy(blkdev->name, loop->name, 6);
    blkdev->type = BLOCKDEV_ATA;  /* Generic disk */
    blkdev->block_size = LOOP_BLOCK_SIZE;
    blkdev->num_blocks = loop->file_size / LOOP_BLOCK_SIZE;
    blkdev->capacity = loop->file_size;
    blkdev->read_only = false;
    blkdev->ops = &loop_blk_ops;
    blkdev->private_data = loop;

    int ret = fut_blockdev_register(blkdev);
    if (ret < 0) {
        fut_free(blkdev);
        memset(loop, 0, sizeof(*loop));
        return ret;
    }

    fut_printf("[LOOP] %s: attached to fd=%d (%llu bytes, %llu blocks)\n",
               loop->name, fd,
               (unsigned long long)loop->file_size,
               (unsigned long long)blkdev->num_blocks);
    return 0;
}

/**
 * loop_clr_fd - Detach a file from a loop device
 */
int loop_clr_fd(int loop_idx) {
    if (loop_idx < 0 || loop_idx >= LOOP_MAX)
        return -EINVAL;

    struct loop_device *loop = &g_loops[loop_idx];
    if (!loop->active)
        return -ENXIO;

    if (loop->blkdev) {
        fut_blockdev_unregister(loop->blkdev);
        fut_free(loop->blkdev);
    }

    fut_printf("[LOOP] %s: detached\n", loop->name);
    memset(loop, 0, sizeof(*loop));
    return 0;
}

/**
 * loop_get_info - Get information about a loop device
 */
int loop_is_active(int loop_idx) {
    if (loop_idx < 0 || loop_idx >= LOOP_MAX)
        return 0;
    return g_loops[loop_idx].active ? 1 : 0;
}

/* Character device file operations for /dev/loopN */
static ssize_t loop_chr_read(void *inode, void *priv, void *buf, size_t n, off_t *pos) {
    (void)inode; (void)priv; (void)buf; (void)n; (void)pos;
    return 0;  /* Block I/O goes through blockdev layer, not chr read */
}

static ssize_t loop_chr_write(void *inode, void *priv, const void *buf, size_t n, off_t *pos) {
    (void)inode; (void)priv; (void)buf; (void)n; (void)pos;
    return 0;
}

/* Loop chr_ops needs to be initialized at runtime (ARM64 relocation) */
static struct fut_file_ops loop_chr_ops;
static bool loop_ops_init = false;

/**
 * Initialize loop device subsystem
 */
void loop_init(void) {
    memset(g_loops, 0, sizeof(g_loops));

    /* Initialize file operations at runtime */
    if (!loop_ops_init) {
        loop_chr_ops.read = loop_chr_read;
        loop_chr_ops.write = loop_chr_write;
        loop_ops_init = true;
    }

    /* Register character devices and create /dev/loop0 through /dev/loop7 */
    extern int chrdev_register(unsigned, unsigned, const struct fut_file_ops *,
                               const char *, void *);
    extern int devfs_create_chr(const char *, unsigned, unsigned);
    for (int i = 0; i < LOOP_MAX; i++) {
        char name[8] = "loop0";
        name[4] = (char)('0' + i);
        chrdev_register(7, (unsigned)i, &loop_chr_ops, name, NULL);
        char path[16] = "/dev/loop0";
        path[9] = (char)('0' + i);
        devfs_create_chr(path, 7, (unsigned)i);
    }

    fut_printf("[LOOP] Loop device subsystem initialized (%d devices)\n", LOOP_MAX);
}
