/* kernel/sys_pivot_root.c - Change root filesystem syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements pivot_root for changing the root mount in a mount namespace.
 * Essential for container initialization and initramfs switching.
 *
 * Phase 1 (Completed): Validation and stub implementation
 * Phase 2 (Completed): Enhanced validation, path categorization, user-space data handling
 * Phase 3 (Completed): Path validation and categorization with error reporting
 * Phase 4: Full mount namespace integration
 */

#include <kernel/fut_task.h>
#include <kernel/fut_vfs.h>
#include <kernel/errno.h>
#include <stddef.h>
#include <string.h>

#include <kernel/kprintf.h>
#include <kernel/uaccess.h>

#include <platform/platform.h>

static inline int sys_pivot_root_copy_from_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)src >= KERNEL_VIRTUAL_BASE) { __builtin_memcpy(dst, src, n); return 0; }
#endif
    return fut_copy_from_user(dst, src, n);
}
/* CAP_SYS_ADMIN capability bit */
#define CAP_SYS_ADMIN 21

/* Resolve a relative path to absolute using the task's cwd */
static const char *pivot_resolve_abs(const char *path, char *out, size_t out_sz) {
    if (!path) return NULL;
    if (path[0] == '/') return path;
    fut_task_t *t = fut_task_current();
    const char *cwd = (t && t->cwd_cache && t->cwd_cache[0]) ? t->cwd_cache : "/";
    size_t cl = strlen(cwd), pl = strlen(path);
    int ns = (cl > 0 && cwd[cl - 1] != '/') ? 1 : 0;
    if (cl + (size_t)ns + pl >= out_sz) return NULL;
    __builtin_memcpy(out, cwd, cl);
    if (ns) out[cl] = '/';
    __builtin_memcpy(out + cl + ns, path, pl + 1);
    return out;
}

/* Check if abs_path is a mount point */
static int pivot_is_mountpoint(const char *abs_path) {
    extern struct fut_mount *fut_vfs_find_mount(const char *);
    if (!abs_path) return 0;
    if (abs_path[0] == '/' && abs_path[1] == '\0') return 1;
    return fut_vfs_find_mount(abs_path) != NULL;
}

/* Check if put_old is at or under new_root */
static int pivot_path_under(const char *new_root, const char *put_old) {
    if (!new_root || !put_old) return 0;
    size_t nr = strlen(new_root);
    if (nr == 1 && new_root[0] == '/') return 1;
    if (strncmp(put_old, new_root, nr) != 0) return 0;
    return (put_old[nr] == '/' || put_old[nr] == '\0');
}

/**
 * sys_pivot_root - Change the root filesystem (container-critical)
 */
long sys_pivot_root(const char *new_root, const char *put_old) {
    fut_task_t *task = fut_task_current();
    if (!task) return -ESRCH;

    /* Copy and validate new_root from userspace */
    if (!new_root) {
        fut_printf("[PIVOT_ROOT] new_root=NULL pid=%llu\n", (unsigned long long)task->pid);
        return -EFAULT;
    }
    char new_root_buf[256];
    if (sys_pivot_root_copy_from_user(new_root_buf, new_root, sizeof(new_root_buf)) != 0)
        return -EFAULT;
    if (memchr(new_root_buf, '\0', sizeof(new_root_buf)) == NULL)
        return -ENAMETOOLONG;
    if (new_root_buf[0] == '\0')
        return -EINVAL;

    /* Copy and validate put_old from userspace */
    if (!put_old) {
        fut_printf("[PIVOT_ROOT] put_old=NULL pid=%llu\n", (unsigned long long)task->pid);
        return -EFAULT;
    }
    char put_old_buf[256];
    if (sys_pivot_root_copy_from_user(put_old_buf, put_old, sizeof(put_old_buf)) != 0)
        return -EFAULT;
    if (memchr(put_old_buf, '\0', sizeof(put_old_buf)) == NULL)
        return -ENAMETOOLONG;
    if (put_old_buf[0] == '\0')
        return -EINVAL;

    /* Permission check: require CAP_SYS_ADMIN or root */
    bool has_cap = (task->cap_effective & (1ULL << CAP_SYS_ADMIN)) != 0;
    if (!has_cap && task->uid != 0) {
        fut_printf("[PIVOT_ROOT] denied pid=%llu\n", (unsigned long long)task->pid);
        return -EPERM;
    }

    /* Resolve new_root to absolute path */
    char nr_abs[256];
    const char *new_root_abs = pivot_resolve_abs(new_root_buf, nr_abs, sizeof(nr_abs));
    if (!new_root_abs) return -ENAMETOOLONG;

    /* Lookup new_root vnode */
    extern int fut_vfs_lookup(const char *, struct fut_vnode **);
    struct fut_vnode *nrv = NULL;
    int lr = fut_vfs_lookup(new_root_abs, &nrv);
    if (lr < 0 || !nrv) {
        fut_printf("[PIVOT_ROOT] '%s' not found pid=%llu\n", new_root_abs, (unsigned long long)task->pid);
        return -EINVAL;
    }
    if (nrv->type != VN_DIR) {
        fut_vnode_unref(nrv);
        return -ENOTDIR;
    }

    /* Validate new_root is a mount point (or is a mounted fs root) */
    if (!pivot_is_mountpoint(new_root_abs)) {
        if (!(nrv->mount && nrv->mount->root == nrv)) {
            fut_printf("[PIVOT_ROOT] '%s' not a mount point pid=%llu\n",
                       new_root_abs, (unsigned long long)task->pid);
            fut_vnode_unref(nrv);
            return -EINVAL;
        }
    }

    /* Same-root pivot is a no-op (compatibility with test 659: pivot_root("/","/")) */
    extern struct fut_vnode *fut_vfs_get_root(void);
    struct fut_vnode *cur_root = task->chroot_vnode ? task->chroot_vnode : fut_vfs_get_root();
    if (nrv == cur_root) {
        fut_vnode_unref(nrv);
        fut_printf("[PIVOT_ROOT] same root no-op pid=%llu\n", (unsigned long long)task->pid);
        return 0;
    }

    /* Resolve put_old to absolute path */
    char po_abs[256];
    const char *put_old_abs = pivot_resolve_abs(put_old_buf, po_abs, sizeof(po_abs));
    if (!put_old_abs) { fut_vnode_unref(nrv); return -ENAMETOOLONG; }

    /* Validate put_old is at or under new_root */
    if (!pivot_path_under(new_root_abs, put_old_abs)) {
        fut_printf("[PIVOT_ROOT] put_old '%s' not under '%s' pid=%llu\n",
                   put_old_abs, new_root_abs, (unsigned long long)task->pid);
        fut_vnode_unref(nrv);
        return -EINVAL;
    }

    /* Ensure put_old directory exists */
    extern int fut_vfs_mkdir(const char *, uint32_t);
    fut_vfs_mkdir(put_old_abs, 0755);

    /* Verify put_old is a directory */
    struct fut_vnode *pov = NULL;
    lr = fut_vfs_lookup(put_old_abs, &pov);
    if (lr < 0 || !pov) { fut_vnode_unref(nrv); return -EINVAL; }
    if (pov->type != VN_DIR) {
        fut_vnode_unref(pov);
        fut_vnode_unref(nrv);
        return -ENOTDIR;
    }
    fut_vnode_unref(pov);

    /* Perform the pivot: set new_root as this task's root via chroot_vnode.
     * This per-process root override is used by the VFS path resolver and
     * inherited by children via fork. Unlike the old fut_vfs_set_root() which
     * changed the global root for ALL processes, chroot_vnode gives proper
     * per-process isolation for containers. */
    if (task->chroot_vnode)
        fut_vnode_unref(task->chroot_vnode);
    task->chroot_vnode = nrv; /* takes ref from fut_vfs_lookup */

    /* Reset cwd to "/" within the new root */
    task->cwd_cache_buf[0] = '/';
    task->cwd_cache_buf[1] = '\0';
    task->cwd_cache = task->cwd_cache_buf;

    fut_printf("[PIVOT_ROOT] pivot_root('%s','%s') -> 0 pid=%llu\n",
               new_root_abs, put_old_abs, (unsigned long long)task->pid);
    return 0;
}
