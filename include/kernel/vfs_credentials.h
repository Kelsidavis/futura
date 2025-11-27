/* include/kernel/vfs_credentials.h - VFS Credential Management API
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * VFS credential context and permission checking interface.
 */

#pragma once

#include <stdint.h>

struct fut_vnode;

/* ============================================================
 *   Credential Context Access
 * ============================================================ */

/**
 * Get the current process's effective UID.
 */
uint32_t vfs_get_current_uid(void);

/**
 * Get the current process's effective GID.
 */
uint32_t vfs_get_current_gid(void);

/**
 * Get the current process's file creation mask.
 */
uint32_t vfs_get_current_umask(void);

/* ============================================================
 *   Permission Checking
 * ============================================================ */

/**
 * Check if current process has write permission on a vnode.
 * Implements standard Unix rwx permission bits (0777).
 */
int vfs_check_write_perm(struct fut_vnode *vnode);

/**
 * Check if current process has read permission on a vnode.
 * Implements standard Unix rwx permission bits (0777).
 */
int vfs_check_read_perm(struct fut_vnode *vnode);

/**
 * Check if current process has execute/search permission on a vnode.
 * For directories, this means search permission (can traverse).
 */
int vfs_check_exec_perm(struct fut_vnode *vnode);

/**
 * Check if current process can modify a vnode's attributes.
 * Only owner or root can change permissions/ownership.
 */
int vfs_check_modify_perm(struct fut_vnode *vnode);

/* ============================================================
 *   VNode Initialization
 * ============================================================ */

/**
 * Calculate effective permissions after umask is applied.
 * Used when creating new files/directories.
 */
uint32_t vfs_apply_umask(uint32_t mode);

/**
 * Initialize a newly created vnode with proper ownership.
 * Sets uid/gid/mode based on parent directory and current process.
 */
void vfs_init_vnode_ownership(struct fut_vnode *vnode,
                               struct fut_vnode *parent,
                               uint32_t requested_mode);
