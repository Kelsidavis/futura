// SPDX-License-Identifier: MPL-2.0

#include <kernel/errno.h>
#include <kernel/fut_task.h>
#include <kernel/fut_thread.h>
#include <kernel/fut_vfs.h>

/**
 * Change the current working directory.
 * @param path The path to the new working directory
 * @return 0 on success, -errno on error
 */
long sys_chdir(const char *path) {
    if (!path) {
        return -EINVAL;
    }

    /* Get the current task */
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -EPERM;
    }

    /* Look up the path */
    struct fut_vnode *vnode = NULL;
    int ret = fut_vfs_lookup(path, &vnode);
    if (ret < 0) {
        return ret;
    }

    /* Verify it's a directory */
    if (vnode->type != VN_DIR) {
        fut_vnode_unref(vnode);
        return -ENOTDIR;
    }

    /* Update the task's current working directory */
    task->current_dir_ino = vnode->ino;

    /* Release the vnode reference */
    fut_vnode_unref(vnode);

    return 0;
}
