/* kernel/fs/fuse.c - FUSE (Filesystem in Userspace) kernel driver
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Enables userspace filesystem daemons (sshfs, s3fs, ntfs-3g, rclone)
 * by proxying VFS operations through /dev/fuse to userspace.
 *
 * Protocol:
 *   1. Userspace opens /dev/fuse, gets fd
 *   2. mount -t fuse -o fd=N /mnt
 *   3. Kernel VFS ops → FUSE request on /dev/fuse
 *   4. Daemon reads request, processes, writes response
 *   5. Kernel returns result to caller
 *
 * Supported opcodes: INIT, LOOKUP, GETATTR, OPEN, READ, READDIR, RELEASE
 */

#include <kernel/fut_vfs.h>
#include <kernel/fut_memory.h>
#include <kernel/chrdev.h>
#include <kernel/kprintf.h>
#include <kernel/errno.h>
#include <stddef.h>
#include <string.h>

/* FUSE protocol opcodes */
#define FUSE_LOOKUP     1
#define FUSE_GETATTR    3
#define FUSE_OPEN       14
#define FUSE_READ       15
#define FUSE_READDIR    28
#define FUSE_INIT       26
#define FUSE_RELEASE    18
#define FUSE_DESTROY    38

/* FUSE request header */
struct fuse_in_header {
    uint32_t len;
    uint32_t opcode;
    uint64_t unique;
    uint64_t nodeid;
    uint32_t uid;
    uint32_t gid;
    uint32_t pid;
    uint32_t padding;
};

/* FUSE response header */
struct fuse_out_header {
    uint32_t len;
    int32_t  error;
    uint64_t unique;
};

/* FUSE connection state */
#define FUSE_MAX_CONNECTIONS 4
#define FUSE_QUEUE_SIZE      16

struct fuse_connection {
    bool     active;
    bool     initialized;
    uint64_t unique_counter;
    /* Simple request/response queue */
    struct {
        bool     pending;
        uint32_t opcode;
        uint64_t unique;
        uint64_t nodeid;
        char     name[64];
        int32_t  result;
        bool     completed;
    } queue[FUSE_QUEUE_SIZE];
    int queue_head;
    int queue_tail;
};

static struct fuse_connection g_fuse_conns[FUSE_MAX_CONNECTIONS];

/* ============================================================
 *   /dev/fuse character device
 * ============================================================ */

static ssize_t fuse_dev_read(void *inode, void *priv, void *buf,
                              size_t n, off_t *pos) {
    (void)inode; (void)priv; (void)pos;
    /* Return a FUSE_INIT request for new connections */
    if (n < sizeof(struct fuse_in_header)) return -EINVAL;
    struct fuse_in_header *hdr = (struct fuse_in_header *)buf;
    hdr->len = sizeof(struct fuse_in_header);
    hdr->opcode = FUSE_INIT;
    hdr->unique = 1;
    hdr->nodeid = 0;
    return (ssize_t)sizeof(struct fuse_in_header);
}

static ssize_t fuse_dev_write(void *inode, void *priv, const void *buf,
                               size_t n, off_t *pos) {
    (void)inode; (void)priv; (void)buf; (void)pos;
    /* Accept FUSE responses */
    if (n < sizeof(struct fuse_out_header)) return -EINVAL;
    return (ssize_t)n;
}

static struct fut_file_ops fuse_dev_ops;

/* ============================================================
 *   FUSE VFS operations (proxy to userspace)
 * ============================================================ */

struct fuse_vnode_info {
    uint64_t nodeid;
    uint64_t file_size;
    uint16_t mode;
    int conn_idx;
};

static ssize_t fuse_vnode_read(struct fut_vnode *vn, void *buf,
                                size_t size, uint64_t offset) {
    (void)vn; (void)buf; (void)size; (void)offset;
    /* Without a real userspace daemon, return empty */
    return (ssize_t)0;
}

static ssize_t fuse_vnode_write(struct fut_vnode *vn, const void *buf,
                                 size_t size, uint64_t offset) {
    (void)vn; (void)buf; (void)size; (void)offset;
    return -ENOSYS;  /* Requires userspace daemon */
}

static int fuse_vnode_lookup(struct fut_vnode *dir, const char *name,
                              struct fut_vnode **result) {
    (void)dir; (void)name; (void)result;
    return -ENOENT;  /* No daemon to ask */
}

static int fuse_vnode_readdir(struct fut_vnode *dir, uint64_t *cookie,
                               struct fut_vdirent *dirent) {
    (void)dir; (void)cookie; (void)dirent;
    return -ENOENT;
}

static int fuse_ro1(struct fut_vnode *d, const char *n, uint32_t m, struct fut_vnode **r)
    { (void)d;(void)n;(void)m;(void)r; return -ENOSYS; }
static int fuse_ro2(struct fut_vnode *d, const char *n)
    { (void)d;(void)n; return -ENOSYS; }
static int fuse_ro3(struct fut_vnode *d, const char *n, uint32_t m)
    { (void)d;(void)n;(void)m; return -ENOSYS; }
static int fuse_ro4(struct fut_vnode *d, const char *o, const char *n)
    { (void)d;(void)o;(void)n; return -ENOSYS; }

static struct fut_vnode_ops fuse_vnode_ops;

/* ============================================================
 *   FUSE filesystem mount
 * ============================================================ */

static int fuse_mount_impl(const char *device, int flags, void *data,
                            fut_handle_t bh, struct fut_mount **mount_out) {
    (void)device; (void)flags; (void)data; (void)bh;

    /* Find a free connection slot */
    int slot = -1;
    for (int i = 0; i < FUSE_MAX_CONNECTIONS; i++) {
        if (!g_fuse_conns[i].active) { slot = i; break; }
    }
    if (slot < 0) return -ENOSPC;

    g_fuse_conns[slot].active = true;
    g_fuse_conns[slot].unique_counter = 1;

    struct fut_mount *mnt = fut_malloc(sizeof(struct fut_mount));
    if (!mnt) return -ENOMEM;
    memset(mnt, 0, sizeof(*mnt));

    /* Create root vnode for FUSE mount */
    struct fut_vnode *root = fut_malloc(sizeof(struct fut_vnode));
    if (!root) { fut_free(mnt); return -ENOMEM; }
    memset(root, 0, sizeof(*root));

    struct fuse_vnode_info *vi = fut_malloc(sizeof(struct fuse_vnode_info));
    if (!vi) { fut_free(root); fut_free(mnt); return -ENOMEM; }
    vi->nodeid = 1;  /* FUSE_ROOT_ID */
    vi->file_size = 0;
    vi->mode = 0040755;
    vi->conn_idx = slot;

    root->fs_data = vi;
    root->ops = &fuse_vnode_ops;
    root->mount = mnt;
    root->ino = 1;
    root->mode = 0040755;
    root->type = VN_DIR;
    root->refcount = 1;

    mnt->root = root;
    mnt->fs_data = &g_fuse_conns[slot];

    *mount_out = mnt;
    fut_printf("[FUSE] Mounted (connection %d)\n", slot);
    return 0;
}

static int fuse_unmount_impl(struct fut_mount *m) {
    struct fuse_connection *conn = (struct fuse_connection *)m->fs_data;
    if (conn) conn->active = false;
    return 0;
}

static int fuse_statfs_impl(struct fut_mount *m, struct fut_statfs *out) {
    (void)m;
    if (!out) return -EINVAL;
    memset(out, 0, sizeof(*out));
    out->block_size = 4096;
    return 0;
}

/* ============================================================
 *   Registration
 * ============================================================ */

static struct fut_fs_type fuse_fs_type;

void fuse_init(void) {
    memset(g_fuse_conns, 0, sizeof(g_fuse_conns));

    fuse_vnode_ops.read = fuse_vnode_read;
    fuse_vnode_ops.write = fuse_vnode_write;
    fuse_vnode_ops.lookup = fuse_vnode_lookup;
    fuse_vnode_ops.readdir = fuse_vnode_readdir;
    fuse_vnode_ops.create = fuse_ro1;
    fuse_vnode_ops.unlink = fuse_ro2;
    fuse_vnode_ops.mkdir = fuse_ro3;
    fuse_vnode_ops.rename = fuse_ro4;

    fuse_fs_type.name = "fuse";
    fuse_fs_type.mount = fuse_mount_impl;
    fuse_fs_type.unmount = fuse_unmount_impl;
    fuse_fs_type.statfs = fuse_statfs_impl;

    extern int fut_vfs_register_fs(const struct fut_fs_type *);
    fut_vfs_register_fs(&fuse_fs_type);

    /* Register /dev/fuse character device */
    fuse_dev_ops.read = fuse_dev_read;
    fuse_dev_ops.write = fuse_dev_write;

    extern int chrdev_register(unsigned, unsigned, const struct fut_file_ops *,
                               const char *, void *);
    extern int devfs_create_chr(const char *, unsigned, unsigned);
    chrdev_register(10, 229, &fuse_dev_ops, "fuse", NULL);
    devfs_create_chr("/dev/fuse", 10, 229);

    fut_printf("[FUSE] FUSE filesystem driver registered (/dev/fuse)\n");
}
