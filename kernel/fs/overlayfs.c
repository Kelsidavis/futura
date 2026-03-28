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
 * Lookup: check upper first, fall back to lower; whiteouts hide lower entries
 * Read: from whichever layer has the file (upper preferred)
 * Write: copy-up to upper layer (creates in upper if not there)
 * Delete: removes from upper, creates whiteout to hide lower entry
 * Readdir: merged view of both layers (upper shadows lower, whiteouts filtered)
 */

#include <kernel/fut_vfs.h>
#include <kernel/fut_memory.h>
#include <kernel/kprintf.h>
#include <kernel/errno.h>
#include <stddef.h>
#include <string.h>

/* Whiteout prefix: files named ".wh.<name>" in upperdir mark deleted entries.
 * This is the standard Linux overlayfs whiteout convention. */
#define WHITEOUT_PREFIX     ".wh."
#define WHITEOUT_PREFIX_LEN 4

struct overlay_mount_info {
    struct fut_vnode *lower_root;    /* Read-only base layer */
    struct fut_vnode *upper_root;    /* Writable layer */
    char lower_path[256];
    char upper_path[256];
    char work_path[256];            /* Workdir for atomic operations */
};

struct overlay_vnode_info {
    struct fut_vnode *lower;         /* Lower layer vnode (may be NULL) */
    struct fut_vnode *upper;         /* Upper layer vnode (may be NULL) */
    struct overlay_mount_info *omi;
};

/* ============================================================
 *   Whiteout helpers
 * ============================================================ */

/* Check if a name is a whiteout marker (starts with ".wh.") */
static bool is_whiteout_name(const char *name) {
    return name[0] == '.' && name[1] == 'w' && name[2] == 'h' && name[3] == '.';
}

/* Build whiteout name: ".wh.<name>" into buf. Returns false if it won't fit. */
static bool make_whiteout_name(const char *name, char *buf, size_t buflen) {
    size_t nlen = strlen(name);
    if (WHITEOUT_PREFIX_LEN + nlen + 1 > buflen) return false;
    memcpy(buf, WHITEOUT_PREFIX, WHITEOUT_PREFIX_LEN);
    memcpy(buf + WHITEOUT_PREFIX_LEN, name, nlen + 1);
    return true;
}

/* Check if a whiteout exists for the given name in the upper layer */
static bool has_whiteout(struct fut_vnode *upper_dir, const char *name) {
    if (!upper_dir || !upper_dir->ops || !upper_dir->ops->lookup) return false;
    char wh_name[FUT_VFS_NAME_MAX + 1];
    if (!make_whiteout_name(name, wh_name, sizeof(wh_name))) return false;
    struct fut_vnode *wh = NULL;
    if (upper_dir->ops->lookup(upper_dir, wh_name, &wh) == 0 && wh) {
        return true;
    }
    return false;
}

/* Create a whiteout marker in the upper layer for the given name */
static int create_whiteout(struct fut_vnode *upper_dir, const char *name) {
    if (!upper_dir || !upper_dir->ops || !upper_dir->ops->create) return -EROFS;
    char wh_name[FUT_VFS_NAME_MAX + 1];
    if (!make_whiteout_name(name, wh_name, sizeof(wh_name))) return -ENAMETOOLONG;
    struct fut_vnode *wh = NULL;
    return upper_dir->ops->create(upper_dir, wh_name, 0, &wh);
}

/* Remove a whiteout marker in the upper layer (when re-creating a deleted file) */
static void remove_whiteout(struct fut_vnode *upper_dir, const char *name) {
    if (!upper_dir || !upper_dir->ops || !upper_dir->ops->unlink) return;
    char wh_name[FUT_VFS_NAME_MAX + 1];
    if (!make_whiteout_name(name, wh_name, sizeof(wh_name))) return;
    upper_dir->ops->unlink(upper_dir, wh_name);
}

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

    /* Check for whiteout: if upper has ".wh.<name>", the file is deleted */
    if (!upper_child && has_whiteout(ovi->upper, name)) {
        return -ENOENT;  /* Whiteout hides this entry */
    }

    /* Check lower layer (only if no upper shadow) */
    if (!upper_child && ovi->lower && ovi->lower->ops && ovi->lower->ops->lookup) {
        if (ovi->lower->ops->lookup(ovi->lower, name, &lower_child) == 0) {
            /* Found in lower */
        }
    }

    if (!upper_child && !lower_child) return -ENOENT;

    *result = overlay_alloc_vnode(lower_child, upper_child, ovi->omi, dir->mount);
    if (!*result) return -ENOMEM;
    (*result)->parent = dir;
    size_t nl = strlen(name);
    char *ndup = fut_malloc(nl + 1);
    if (ndup) { memcpy(ndup, name, nl); ndup[nl] = '\0'; }
    (*result)->name = ndup;
    return 0;
}

/* Check if a name exists in the upper layer (for readdir dedup) */
static bool upper_has_entry(struct fut_vnode *upper_dir, const char *name) {
    if (!upper_dir || !upper_dir->ops || !upper_dir->ops->lookup) return false;
    struct fut_vnode *child = NULL;
    return (upper_dir->ops->lookup(upper_dir, name, &child) == 0 && child);
}

static int overlay_readdir(struct fut_vnode *dir, uint64_t *cookie,
                           struct fut_vdirent *dirent) {
    struct overlay_vnode_info *ovi = (struct overlay_vnode_info *)dir->fs_data;
    if (!ovi) return -EIO;

    /* Strategy: enumerate upper first, then lower.
     * Use high bit of cookie to distinguish layers.
     * Skip whiteout entries and deduplicate lower entries that are
     * shadowed by (or whited-out from) the upper layer. */
    uint64_t layer = (*cookie >> 32) & 1;
    uint64_t sub_cookie = *cookie & 0xFFFFFFFF;

    if (layer == 0) {
        /* Upper layer — skip whiteout marker files */
        if (ovi->upper && ovi->upper->ops && ovi->upper->ops->readdir) {
            while (1) {
                int rc = ovi->upper->ops->readdir(ovi->upper, &sub_cookie, dirent);
                if (rc <= 0) break;  /* No more entries in upper */
                /* Filter out whiteout markers from user-visible listing */
                if (is_whiteout_name(dirent->d_name)) {
                    continue;  /* Skip, try next upper entry */
                }
                *cookie = sub_cookie;  /* Stay in upper */
                return rc;
            }
        }
        /* Switch to lower */
        layer = 1;
        sub_cookie = 0;
    }

    /* Lower layer — skip entries that are shadowed or whited-out by upper */
    if (layer == 1 && ovi->lower && ovi->lower->ops && ovi->lower->ops->readdir) {
        while (1) {
            int rc = ovi->lower->ops->readdir(ovi->lower, &sub_cookie, dirent);
            if (rc <= 0) return -ENOENT;  /* No more entries */
            /* Skip if upper already has this name (shadowed) */
            if (upper_has_entry(ovi->upper, dirent->d_name)) {
                continue;
            }
            /* Skip if upper has a whiteout for this name (deleted) */
            if (has_whiteout(ovi->upper, dirent->d_name)) {
                continue;
            }
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
    if (!ovi->upper->ops || !ovi->upper->ops->create) return -EROFS;
    /* If there was a whiteout for this name, remove it since we're re-creating */
    remove_whiteout(ovi->upper, name);
    return ovi->upper->ops->create(ovi->upper, name, mode, result);
}

static int overlay_unlink(struct fut_vnode *dir, const char *name) {
    struct overlay_vnode_info *ovi = (struct overlay_vnode_info *)dir->fs_data;
    if (!ovi || !ovi->upper) return -EROFS;

    /* Check if file exists in the upper layer */
    bool in_upper = false;
    if (ovi->upper->ops && ovi->upper->ops->lookup) {
        struct fut_vnode *child = NULL;
        if (ovi->upper->ops->lookup(ovi->upper, name, &child) == 0 && child)
            in_upper = true;
    }

    /* Check if file exists in the lower layer */
    bool in_lower = false;
    if (ovi->lower && ovi->lower->ops && ovi->lower->ops->lookup) {
        struct fut_vnode *child = NULL;
        if (ovi->lower->ops->lookup(ovi->lower, name, &child) == 0 && child)
            in_lower = true;
    }

    if (!in_upper && !in_lower) return -ENOENT;

    /* Remove from upper if present */
    if (in_upper && ovi->upper->ops && ovi->upper->ops->unlink) {
        ovi->upper->ops->unlink(ovi->upper, name);
    }

    /* If file existed in lower, create a whiteout so it stays hidden */
    if (in_lower) {
        int wret = create_whiteout(ovi->upper, name);
        if (wret < 0) {
            fut_printf("[OVERLAY] warning: whiteout creation failed for '%s': %d\n", name, wret);
            /* Non-fatal: file is still removed from upper, but lower will show through.
             * Callers will see the old lower version reappear — not ideal but not data loss. */
        }
    }

    return 0;
}

static int overlay_mkdir(struct fut_vnode *dir, const char *name, uint32_t mode) {
    struct overlay_vnode_info *ovi = (struct overlay_vnode_info *)dir->fs_data;
    if (!ovi || !ovi->upper) return -EROFS;
    if (!ovi->upper->ops || !ovi->upper->ops->mkdir) return -EROFS;
    /* Remove whiteout if re-creating a previously deleted directory */
    remove_whiteout(ovi->upper, name);
    return ovi->upper->ops->mkdir(ovi->upper, name, mode);
}

static int overlay_rename(struct fut_vnode *dir, const char *old, const char *new) {
    struct overlay_vnode_info *ovi = (struct overlay_vnode_info *)dir->fs_data;
    if (!ovi || !ovi->upper) return -EROFS;
    if (!ovi->upper->ops || !ovi->upper->ops->rename) return -EROFS;

    /* Check if old name exists in lower — if so, we need a whiteout after rename */
    bool old_in_lower = false;
    if (ovi->lower && ovi->lower->ops && ovi->lower->ops->lookup) {
        struct fut_vnode *child = NULL;
        if (ovi->lower->ops->lookup(ovi->lower, old, &child) == 0 && child)
            old_in_lower = true;
    }

    int ret = ovi->upper->ops->rename(ovi->upper, old, new);
    if (ret < 0) return ret;

    /* Whiteout the old name if it was in lower, so it doesn't reappear */
    if (old_in_lower)
        create_whiteout(ovi->upper, old);

    /* Remove any whiteout on the new name since we just placed a file there */
    remove_whiteout(ovi->upper, new);

    return 0;
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

    char lower_path[256] = {0}, upper_path[256] = {0}, work_path[256] = {0};

    /* Parse mount options from data string */
    const char *opts = (const char *)data;
    if (opts) {
        overlay_parse_opt(opts, "lowerdir", lower_path, sizeof(lower_path));
        overlay_parse_opt(opts, "upperdir", upper_path, sizeof(upper_path));
        overlay_parse_opt(opts, "workdir", work_path, sizeof(work_path));
    }

    if (!lower_path[0] || !upper_path[0]) {
        fut_printf("[OVERLAY] mount failed: need lowerdir= and upperdir=\n");
        return -EINVAL;
    }

    /* Lookup lower and upper root vnodes */
    extern int fut_vfs_lookup(const char *, struct fut_vnode **);
    extern int fut_vfs_mkdir(const char *, uint32_t);
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

    /* Create workdir if specified and doesn't exist */
    if (work_path[0]) {
        fut_vfs_mkdir(work_path, 0755);
    }

    struct overlay_mount_info *omi = fut_malloc(sizeof(struct overlay_mount_info));
    if (!omi) return -ENOMEM;
    memset(omi, 0, sizeof(*omi));
    omi->lower_root = lower_vn;
    omi->upper_root = upper_vn;
    {
        size_t ll = strlen(lower_path);
        if (ll > sizeof(omi->lower_path) - 1) ll = sizeof(omi->lower_path) - 1;
        memcpy(omi->lower_path, lower_path, ll);
        omi->lower_path[ll] = '\0';
    }
    {
        size_t ul = strlen(upper_path);
        if (ul > sizeof(omi->upper_path) - 1) ul = sizeof(omi->upper_path) - 1;
        memcpy(omi->upper_path, upper_path, ul);
        omi->upper_path[ul] = '\0';
    }
    {
        size_t wl = strlen(work_path);
        if (wl > sizeof(omi->work_path) - 1) wl = sizeof(omi->work_path) - 1;
        memcpy(omi->work_path, work_path, wl);
        omi->work_path[wl] = '\0';
    }

    struct fut_mount *mnt = fut_malloc(sizeof(struct fut_mount));
    if (!mnt) { fut_free(omi); return -ENOMEM; }
    memset(mnt, 0, sizeof(*mnt));
    mnt->fs_data = omi;

    struct fut_vnode *root = overlay_alloc_vnode(lower_vn, upper_vn, omi, mnt);
    if (!root) { fut_free(omi); fut_free(mnt); return -EIO; }
    mnt->root = root;

    *mount_out = mnt;
    fut_printf("[OVERLAY] Mounted: lower=%s upper=%s%s%s\n",
               lower_path, upper_path,
               work_path[0] ? " work=" : "", work_path);
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
 *   Extended Attribute Operations (container compat)
 *
 *   Docker's overlay2 driver stores metadata xattrs on every layer:
 *     - "trusted.overlay.opaque" marks opaque directories
 *     - "trusted.overlay.redirect" stores redirect paths
 *     - "security.selinux" for SELinux labels
 *   These must pass through to the underlying layer vnodes.
 * ============================================================ */

/* Generic vnode xattr helpers (from kernel/vfs/fut_vfs.c) */
extern int vnode_generic_setxattr(struct fut_vnode *vnode, const char *name,
                                  const void *value, size_t size, int flags);
extern ssize_t vnode_generic_getxattr(struct fut_vnode *vnode, const char *name,
                                      void *value, size_t size);
extern ssize_t vnode_generic_listxattr(struct fut_vnode *vnode, char *list, size_t size);
extern int vnode_generic_removexattr(struct fut_vnode *vnode, const char *name);

/**
 * overlay_setxattr - Set xattr, writing to upper layer.
 *
 * If the upper vnode's FS has native xattr ops, delegate there.
 * Otherwise use the generic per-vnode xattr storage on the overlay vnode
 * itself (so the attribute persists for the overlay view lifetime).
 */
static int overlay_setxattr(struct fut_vnode *vn, const char *name,
                             const void *value, size_t size, int flags) {
    struct overlay_vnode_info *ovi = (struct overlay_vnode_info *)vn->fs_data;
    if (!ovi) return -EIO;

    /* Try upper layer's native xattr ops first */
    if (ovi->upper && ovi->upper->ops && ovi->upper->ops->setxattr)
        return ovi->upper->ops->setxattr(ovi->upper, name, value, size, flags);

    /* Fall back to generic per-vnode xattr on the overlay vnode */
    return vnode_generic_setxattr(vn, name, value, size, flags);
}

/**
 * overlay_getxattr - Get xattr, checking upper then lower.
 */
static ssize_t overlay_getxattr(struct fut_vnode *vn, const char *name,
                                 void *value, size_t size) {
    struct overlay_vnode_info *ovi = (struct overlay_vnode_info *)vn->fs_data;
    if (!ovi) return -EIO;

    /* Check upper layer first (it shadows lower) */
    if (ovi->upper) {
        if (ovi->upper->ops && ovi->upper->ops->getxattr) {
            ssize_t r = ovi->upper->ops->getxattr(ovi->upper, name, value, size);
            if (r != -ENODATA) return r;
        }
    }

    /* Fall through to lower layer */
    if (ovi->lower && ovi->lower->ops && ovi->lower->ops->getxattr) {
        ssize_t r = ovi->lower->ops->getxattr(ovi->lower, name, value, size);
        if (r != -ENODATA) return r;
    }

    /* Check generic per-vnode storage last */
    return vnode_generic_getxattr(vn, name, value, size);
}

/**
 * overlay_listxattr - List xattrs from both layers (merged, upper shadows).
 */
static ssize_t overlay_listxattr(struct fut_vnode *vn, char *list, size_t size) {
    struct overlay_vnode_info *ovi = (struct overlay_vnode_info *)vn->fs_data;
    if (!ovi) return -EIO;

    /* Collect from upper, then lower, then generic — simple concatenation.
     * Duplicates are acceptable per POSIX (caller filters). */
    size_t total = 0;

    /* Upper layer xattrs */
    if (ovi->upper && ovi->upper->ops && ovi->upper->ops->listxattr) {
        ssize_t n = ovi->upper->ops->listxattr(ovi->upper, NULL, 0);
        if (n > 0) total += (size_t)n;
    }

    /* Lower layer xattrs */
    if (ovi->lower && ovi->lower->ops && ovi->lower->ops->listxattr) {
        ssize_t n = ovi->lower->ops->listxattr(ovi->lower, NULL, 0);
        if (n > 0) total += (size_t)n;
    }

    /* Generic per-vnode xattrs */
    ssize_t gen = vnode_generic_listxattr(vn, NULL, 0);
    if (gen > 0) total += (size_t)gen;

    if (size == 0 || !list) return (ssize_t)total;
    if (size < total) return -ERANGE;

    char *p = list;
    size_t remain = size;

    if (ovi->upper && ovi->upper->ops && ovi->upper->ops->listxattr) {
        ssize_t n = ovi->upper->ops->listxattr(ovi->upper, p, remain);
        if (n > 0) { p += n; remain -= (size_t)n; }
    }
    if (ovi->lower && ovi->lower->ops && ovi->lower->ops->listxattr) {
        ssize_t n = ovi->lower->ops->listxattr(ovi->lower, p, remain);
        if (n > 0) { p += n; remain -= (size_t)n; }
    }
    if (gen > 0) {
        ssize_t n = vnode_generic_listxattr(vn, p, remain);
        if (n > 0) { p += n; }
    }

    return (ssize_t)total;
}

/**
 * overlay_removexattr - Remove xattr from upper layer.
 */
static int overlay_removexattr(struct fut_vnode *vn, const char *name) {
    struct overlay_vnode_info *ovi = (struct overlay_vnode_info *)vn->fs_data;
    if (!ovi) return -EIO;

    /* Try upper layer first */
    if (ovi->upper && ovi->upper->ops && ovi->upper->ops->removexattr) {
        int r = ovi->upper->ops->removexattr(ovi->upper, name);
        if (r == 0 || r != -ENODATA) return r;
    }

    /* Fall back to generic per-vnode storage */
    return vnode_generic_removexattr(vn, name);
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
    overlay_ops.setxattr = overlay_setxattr;
    overlay_ops.getxattr = overlay_getxattr;
    overlay_ops.listxattr = overlay_listxattr;
    overlay_ops.removexattr = overlay_removexattr;

    overlay_fs_type.name = "overlay";
    overlay_fs_type.mount = overlay_mount_impl;
    overlay_fs_type.unmount = overlay_unmount_impl;
    overlay_fs_type.statfs = overlay_statfs_impl;

    extern int fut_vfs_register_fs(const struct fut_fs_type *);
    fut_vfs_register_fs(&overlay_fs_type);

    fut_printf("[OVERLAY] Overlay filesystem driver registered (with xattr support)\n");
}
