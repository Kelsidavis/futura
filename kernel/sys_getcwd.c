// SPDX-License-Identifier: MPL-2.0

#include <kernel/errno.h>
#include <kernel/fut_task.h>
#include <kernel/fut_thread.h>
#include <kernel/fut_vfs.h>
#include <kernel/fut_memory.h>
#include <string.h>

extern void fut_printf(const char *fmt, ...);

/**
 * Get the current working directory.
 * Reconstructs the full path by walking up the parent chain.
 * @param buf Buffer to store the path
 * @param size Size of the buffer
 * @return Pointer to buf on success, or error code (negative) on failure
 */
long sys_getcwd(char *buf, size_t size) {
    extern struct fut_vnode *fut_vfs_get_inode(uint64_t ino);

    /* Get the current task */
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -EPERM;
    }

    if (!buf) {
        return -EINVAL;
    }

    if (size < 2) {
        return -ERANGE;
    }

    /* Get the current working directory inode from task */
    struct fut_vnode *cwd = fut_vfs_get_inode(task->current_dir_ino);
    if (!cwd) {
        /* No CWD found, default to root */
        buf[0] = '/';
        buf[1] = '\0';
        return (long)(uintptr_t)buf;
    }

    /* Special case: if CWD is root, just return "/" */
    if (cwd->ino == 1 || !cwd->parent) {
        buf[0] = '/';
        buf[1] = '\0';
        return (long)(uintptr_t)buf;
    }

    /* Walk up the parent chain to reconstruct the path */
    /* First, collect components from CWD up to root */
    struct fut_vnode **path_components = NULL;
    int num_components = 0;
    struct fut_vnode *current = cwd;

    /* Count components needed */
    while (current && current->parent) {
        num_components++;
        current = current->parent;
    }

    /* Allocate temporary array to hold path components */
    path_components = (struct fut_vnode **)fut_malloc(sizeof(struct fut_vnode *) * num_components);
    if (!path_components && num_components > 0) {
        return -ENOMEM;
    }

    /* Collect components */
    current = cwd;
    int idx = num_components - 1;
    while (current && current->parent && idx >= 0) {
        path_components[idx--] = current;
        current = current->parent;
    }

    /* Build the path string */
    size_t pos = 0;
    buf[pos++] = '/';

    /* Add each component to the path */
    for (int i = 0; i < num_components; i++) {
        struct fut_vnode *vnode = path_components[i];

        if (!vnode || !vnode->name) {
            continue;
        }

        /* Get length of component name */
        size_t name_len = 0;
        const char *p = vnode->name;
        while (*p) {
            name_len++;
            p++;
        }

        /* Check if adding this component would overflow buffer */
        if (pos + name_len + 1 >= size) {
            /* Path too long for buffer */
            if (path_components) {
                fut_free(path_components);
            }
            return -ERANGE;
        }

        /* Add component and slash */
        for (size_t j = 0; j < name_len; j++) {
            buf[pos++] = vnode->name[j];
        }

        /* Add slash after each component except the last */
        if (i < num_components - 1) {
            buf[pos++] = '/';
        }
    }

    /* Null-terminate the path */
    buf[pos] = '\0';

    /* Clean up */
    if (path_components) {
        fut_free(path_components);
    }

    return (long)(uintptr_t)buf;
}
