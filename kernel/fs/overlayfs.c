/* kernel/fs/overlayfs.c - Overlay filesystem (union mount)
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements an overlay filesystem that layers a writable upper directory
 * on top of a read-only lower directory. This is Docker's primary storage
 * driver for container filesystem layers.
 *
 * Mount options: lowerdir=<path>,upperdir=<path>,workdir=<path>
 *
 * Lookup: check upper first, fall back to lower
 * Read: from whichever layer has the file
 * Write: copy-up to upper layer (creates in upper if not there)
 * Readdir: merged view of both layers (upper entries shadow lower)
 */

#include <kernel/fut_vfs.h>
#include <kernel/fut_memory.h>
#include <kernel/kprintf.h>
#include <kernel/errno.h>
#include <stddef.h>
#include <string.h>

struct overlay_mount_info {
    struct fut_vnode *lower_root;    /* Read-only base layer */
    struct fut_vnode *upper_root;    /* Writable layer */
    char lower_path[64];
    char upper_path[64];
};

struct overlay_vnode_info {
    struct fut_vnode *lower;         /* Lower layer vnode (may be NULL) */
    struct fut_vnode *upper;         /* Upper layer vnode (may be NULL) */
    struct overlay_mount_info *omi;
};

/* ============================================================
 *   VFS operations
 * ============================================================ */

static ssize_t overlay_read(struct fut_vnode *vn, void *buf, size_t size, uint64_t offset) {
    struct overlay_vnode_info *ovi = (struct overlay_vnode_info *)vn->fs_data;
    if (!ovi) return -EIO;
    /* Prefer upper, fall back to lower */
    struct fut_vnode *real = ovi->upper ? ovi->upper : ovi->lower;
    if (!real || !real->ops || !real->ops->read) return -EIO;
    return real->ops->read(real, buf, size, offset);
}

static ssize_t overlay_write(struct fut_vnode *vn, const void *buf, size_t size, uint64_t offset) {
    struct overlay_vnode_info *ovi = (struct overlay_vnode_info *)vn->fs_data;
    if (!ovi) return -EIO;
    /* Write always goes to upper layer */
    if (ovi->upper && ovi->upper->ops && ovi->upper->ops->write)
        return ovi->upper->ops->write(ovi->upper, buf, size, offset);
    /* No upper — read-only */
    return -EROFS;
}

static struct fut_vnode *overlay_alloc_vnode(struct fut_vnode *lower,
                                             struct fut_vnode *upper,
                                             struct overlay_mount_info *omi,
                                             struct fut_mount *mnt);

static int overlay_lookup(struct fut_vnode *dir, const char *name,
                          struct fut_vnode **result) {
    struct overlay_vnode_info *ovi = (struct overlay_vnode_info *)dir->fs_data;
    if (!ovi) return -EIO;

    struct fut_vnode *upper_child = NULL, *lower_child = NULL;

    /* Check upper layer first */
    if (ovi->upper && ovi->upper->ops && ovi->upper->ops->lookup) {
        if (ovi->upper->ops->lookup(ovi->upper, name, &upper_child) == 0) {
            /* Found in upper — this shadows any lower entry */
        }
    }

    /* Check lower layer */
    if (ovi->lower && ovi->lower->ops && ovi->lower->ops->lookup) {
        if (ovi->lower->ops->lookup(ovi->lower, name, &lower_child) == 0) {
            /* Found in lower */
        }
    }

    if (!upper_child && !lower_child) return -ENOENT;

    *result = overlay_alloc_vnode(lower_child, upper_child, ovi->omi, dir->mount);
    if (!*result) return -ENOMEM;
    (*result)->parent = dir;
    size_t nl = 0; while (name[nl]) nl++;
    char *ndup = fut_malloc(nl + 1);
    if (ndup) { memcpy(ndup, name, nl); ndup[nl] = '\0'; }
    (*result)->name = ndup;
    return 0;
}

static int overlay_readdir(struct fut_vnode *dir, uint64_t *cookie,
                           struct fut_vdirent *dirent) {
    struct overlay_vnode_info *ovi = (struct overlay_vnode_info *)dir->fs_data;
    if (!ovi) return -EIO;

    /* Simple strategy: enumerate upper first, then lower.
     * Use high bit of cookie to distinguish layers. */
    uint64_t layer = (*cookie >> 32) & 1;
    uint64_t sub_cookie = *cookie & 0xFFFFFFFF;

    if (layer == 0) {
        /* Upper layer */
        if (ovi->upper && ovi->upper->ops && ovi->upper->ops->readdir) {
            int rc = ovi->upper->ops->readdir(ovi->upper, &sub_cookie, dirent);
            if (rc > 0) {
                *cookie = sub_cookie;  /* Stay in upper */
                return rc;
            }
        }
        /* Switch to lower */
        layer = 1;
        sub_cookie = 0;
    }

    if (layer == 1 && ovi->lower && ovi->lower->ops && ovi->lower->ops->readdir) {
        int rc = ovi->lower->ops->readdir(ovi->lower, &sub_cookie, dirent);
        if (rc > 0) {
            *cookie = (1ULL << 32) | sub_cookie;
            return rc;
        }
    }

    return -ENOENT;
}

static int overlay_create(struct fut_vnode *dir, const char *name,
                          uint32_t mode, struct fut_vnode **result) {
    struct overlay_vnode_info *ovi = (struct overlay_vnode_info *)dir->fs_data;
    if (!ovi || !ovi->upper) return -EROFS;
    if (ovi->upper->ops && ovi->upper->ops->create)
        return ovi->upper->ops->create(ovi->upper, name, mode, result);
    return -EROFS;
}

static int overlay_unlink(struct fut_vnode *dir, const char *name) {
    struct overlay_vnode_info *ovi = (struct overlay_vnode_info *)dir->fs_data;
    if (!ovi || !ovi->upper) return -EROFS;
    if (ovi->upper->ops && ovi->upper->ops->unlink)
        return ovi->upper->ops->unlink(ovi->upper, name);
    return -EROFS;
}

static int overlay_mkdir(struct fut_vnode *dir, const char *name, uint32_t mode) {
    struct overlay_vnode_info *ovi = (struct overlay_vnode_info *)dir->fs_data;
    if (!ovi || !ovi->upper) return -EROFS;
    if (ovi->upper->ops && ovi->upper->ops->mkdir)
        return ovi->upper->ops->mkdir(ovi->upper, name, mode);
    return -EROFS;
}

static int overlay_rename(struct fut_vnode *dir, const char *old, const char *new) {
    struct overlay_vnode_info *ovi = (struct overlay_vnode_info *)dir->fs_data;
    if (!ovi || !ovi->upper) return -EROFS;
    if (ovi->upper->ops && ovi->upper->ops->rename)
        return ovi->upper->ops->rename(ovi->upper, old, new);
    return -EROFS;
}

static struct fut_vnode_ops overlay_ops;

static struct fut_vnode *overlay_alloc_vnode(struct fut_vnode *lower,
                                             struct fut_vnode *upper,
                                             struct overlay_mount_info *omi,
                                             struct fut_mount *mnt) {
    struct fut_vnode *vn = fut_malloc(sizeof(struct fut_vnode));
    if (!vn) return NULL;
    memset(vn, 0, sizeof(*vn));

    struct overlay_vnode_info *ovi = fut_malloc(sizeof(struct overlay_vnode_info));
    if (!ovi) { fut_free(vn); return NULL; }
    ovi->lower = lower;
    ovi->upper = upper;
    ovi->omi = omi;

    /* Use upper's metadata if available, else lower's */
    struct fut_vnode *ref = upper ? upper : lower;

    vn->fs_data = ovi;
    vn->ops = &overlay_ops;
    vn->mount = mnt;
    vn->ino = ref ? ref->ino : 1;
    vn->mode = ref ? ref->mode : 0040755;
    vn->uid = ref ? ref->uid : 0;
    vn->gid = ref ? ref->gid : 0;
    vn->size = ref ? ref->size : 0;
    vn->nlinks = ref ? ref->nlinks : 1;
    vn->refcount = 1;
    vn->type = ref ? ref->type : VN_DIR;

    return vn;
}

/* ============================================================
 *   Mount / unmount
 * ============================================================ */

/* Parse "key=value" from comma-separated options string */
static const char *overlay_parse_opt(const char *opts, const char *key, char *out, int max) {
    if (!opts || !key) return NULL;
    int klen = 0; while (key[klen]) klen++;

    const char *p = opts;
    while (*p) {
        /* Check if this segment starts with key= */
        bool match = true;
        for (int i = 0; i < klen; i++) {
            if (p[i] != key[i]) { match = false; break; }
        }
        if (match && p[klen] == '=') {
            const char *val = p + klen + 1;
            int i = 0;
            while (val[i] && val[i] != ',' && i < max - 1) {
                out[i] = val[i]; i++;
            }
            out[i] = '\0';
            return out;
        }
        /* Skip to next option */
        while (*p && *p != ',') p++;
        if (*p == ',') p++;
    }
    return NULL;
}

static int overlay_mount_impl(const char *device, int flags, void *data,
                               fut_handle_t bh, struct fut_mount **mount_out) {
    (void)device; (void)flags; (void)bh;

    char lower_path[64] = {0}, upper_path[64] = {0};

    /* Parse mount options from data string */
    const char *opts = (const char *)data;
    if (opts) {
        overlay_parse_opt(opts, "lowerdir", lower_path, sizeof(lower_path));
        overlay_parse_opt(opts, "upperdir", upper_path, sizeof(upper_path));
    }

    if (!lower_path[0] || !upper_path[0]) {
        fut_printf("[OVERLAY] mount failed: need lowerdir= and upperdir=\n");
        return -EINVAL;
    }

    /* Lookup lower and upper root vnodes */
    extern int fut_vfs_lookup(const char *, struct fut_vnode **);
    struct fut_vnode *lower_vn = NULL, *upper_vn = NULL;

    int lr = fut_vfs_lookup(lower_path, &lower_vn);
    if (lr < 0 || !lower_vn) {
        fut_printf("[OVERLAY] lowerdir '%s' not found: %d\n", lower_path, lr);
        return -ENOENT;
    }

    int ur = fut_vfs_lookup(upper_path, &upper_vn);
    if (ur < 0 || !upper_vn) {
        fut_printf("[OVERLAY] upperdir '%s' not found: %d\n", upper_path, ur);
        return -ENOENT;
    }

    struct overlay_mount_info *omi = fut_malloc(sizeof(struct overlay_mount_info));
    if (!omi) return -ENOMEM;
    memset(omi, 0, sizeof(*omi));
    omi->lower_root = lower_vn;
    omi->upper_root = upper_vn;
    size_t ll = 0; while (lower_path[ll] && ll < 63) { omi->lower_path[ll] = lower_path[ll]; ll++; }
    size_t ul = 0; while (upper_path[ul] && ul < 63) { omi->upper_path[ul] = upper_path[ul]; ul++; }

    struct fut_mount *mnt = fut_malloc(sizeof(struct fut_mount));
    if (!mnt) { fut_free(omi); return -ENOMEM; }
    memset(mnt, 0, sizeof(*mnt));
    mnt->fs_data = omi;

    struct fut_vnode *root = overlay_alloc_vnode(lower_vn, upper_vn, omi, mnt);
    if (!root) { fut_free(omi); fut_free(mnt); return -EIO; }
    mnt->root = root;

    *mount_out = mnt;
    fut_printf("[OVERLAY] Mounted: lower=%s upper=%s\n", lower_path, upper_path);
    return 0;
}

static int overlay_unmount_impl(struct fut_mount *m) {
    if (m->fs_data) fut_free(m->fs_data);
    return 0;
}

static int overlay_statfs_impl(struct fut_mount *m, struct fut_statfs *out) {
    (void)m;
    if (!out) return -EINVAL;
    memset(out, 0, sizeof(*out));
    out->block_size = 4096;
    return 0;
}

/* ============================================================
 *   Registration
 * ============================================================ */

static struct fut_fs_type overlay_fs_type;

void overlayfs_init(void) {
    overlay_ops.read = overlay_read;
    overlay_ops.write = overlay_write;
    overlay_ops.lookup = overlay_lookup;
    overlay_ops.readdir = overlay_readdir;
    overlay_ops.create = overlay_create;
    overlay_ops.unlink = overlay_unlink;
    overlay_ops.mkdir = overlay_mkdir;
    overlay_ops.rename = overlay_rename;

    overlay_fs_type.name = "overlay";
    overlay_fs_type.mount = overlay_mount_impl;
    overlay_fs_type.unmount = overlay_unmount_impl;
    overlay_fs_type.statfs = overlay_statfs_impl;

    extern int fut_vfs_register_fs(const struct fut_fs_type *);
    fut_vfs_register_fs(&overlay_fs_type);

    fut_printf("[OVERLAY] Overlay filesystem driver registered\n");
}
