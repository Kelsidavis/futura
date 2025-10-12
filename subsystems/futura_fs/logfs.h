// SPDX-License-Identifier: MPL-2.0
/*
 * logfs.h - Minimal log-structured filesystem skeleton for Futura OS
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct futfs_context futfs_t;
typedef struct futfs_handle futfs_handle_t;

enum futfs_rights {
    FUTFS_RIGHT_READ  = 1u << 0,
    FUTFS_RIGHT_WRITE = 1u << 1,
    FUTFS_RIGHT_ADMIN = 1u << 2,
};

/* Formatting / mounting */
int futfs_format_path(const char *path, size_t initial_size_bytes, uint32_t block_size);
int futfs_mount_path(const char *path, futfs_t **out_fs);
void futfs_unmount(futfs_t *fs);

/* Capability-oriented inode handles */
int futfs_create(futfs_t *fs,
                 uint64_t parent_ino,
                 const char *name,
                 uint32_t policy_rights,
                 uint32_t requested_rights,
                 futfs_handle_t **out_handle);
int futfs_open(futfs_t *fs,
               uint64_t ino,
               uint32_t requested_rights,
               futfs_handle_t **out_handle);
void futfs_handle_close(futfs_handle_t *handle);
uint64_t futfs_handle_ino(const futfs_handle_t *handle);
uint32_t futfs_handle_rights(const futfs_handle_t *handle);

/* File primitives */
int futfs_write(futfs_handle_t *handle, const void *data, size_t len);
int futfs_read_all(futfs_handle_t *handle, uint8_t **out_data, size_t *out_len);
int futfs_rename(futfs_handle_t *handle, uint64_t new_parent_ino, const char *new_name);

/* Convenience helpers */
uint64_t futfs_root_ino(const futfs_t *fs);

#ifdef __cplusplus
}
#endif

