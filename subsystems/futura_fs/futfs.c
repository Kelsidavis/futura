// SPDX-License-Identifier: MPL-2.0
/*
 * futfs.c - FuturaFS v0 snapshot log implementation
 */

#include "futfs.h"
#include "futfs_internal.h"

#include <kernel/errno.h>
#include <kernel/fut_memory.h>
#include <kernel/fut_object.h>
#include <kernel/fut_thread.h>
#include <kernel/boot_args.h>

#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#ifndef ENOTSUP
#define ENOTSUP 95
#endif

#ifndef ENOTEMPTY
#define ENOTEMPTY 39
#endif

#ifndef EISDIR
#define EISDIR 21
#endif

struct futfs_handle {
    struct futfs_inode_mem *inode;
    uint32_t rights;
    size_t offset;
};
struct futfs_fs g_fs = {0};

static void futfs_mark_dirty(void) {
    g_fs.dirty = true;
    g_fs.super_dirty = true;
}

static uint64_t futfs_blocks_for_size(uint64_t size) {
    uint64_t blk = g_fs.block_size ? (uint64_t)g_fs.block_size : 512;
    if (size == 0) {
        return 0;
    }
    return (size + blk - 1u) / blk;
}

static uint64_t futfs_total_blocks_used(void) {
    uint64_t total = 0;
    for (size_t i = 0; i < g_fs.inode_count; ++i) {
        total += futfs_blocks_for_size(g_fs.inodes[i].size);
    }
    return total;
}

static uint64_t futfs_total_dir_tombstones(void) {
    uint64_t total = 0;
    for (size_t i = 0; i < g_fs.inode_count; ++i) {
        if (g_fs.inodes[i].type == FUTFS_INODE_DIR) {
            total += futfs_gc_count_tombstones(&g_fs.inodes[i]);
        }
    }
    return total;
}

static uint64_t futfs_highwater_inodes(void) {
    return (g_fs.next_inode > 0) ? g_fs.next_inode - 1u : 0u;
}

/* -------------------------------------------------------------------------- */
/* Utility helpers                                                            */
/* -------------------------------------------------------------------------- */

size_t futfs_align8(size_t value) {
    return (value + 7u) & ~((size_t)7u);
}

static size_t futfs_strlen(const char *str) {
    if (!str) {
        return 0;
    }
    size_t len = 0;
    while (str[len] != '\0') {
        ++len;
    }
    return len;
}

static void *futfs_zalloc(size_t bytes) {
    void *ptr = fut_malloc(bytes);
    if (ptr) {
        memset(ptr, 0, bytes);
    }
    return ptr;
}

static void futfs_sleep_poll(void) {
    fut_thread_sleep(1);
}

struct futfs_inode_mem *futfs_find_inode(uint64_t ino) {
    for (size_t i = 0; i < g_fs.inode_count; ++i) {
        if (g_fs.inodes[i].ino == ino) {
            return &g_fs.inodes[i];
        }
    }
    return NULL;
}

static struct futfs_inode_mem *futfs_create_inode_slot(uint64_t ino) {
    if (g_fs.inode_count == g_fs.inode_capacity) {
        size_t new_cap = g_fs.inode_capacity ? g_fs.inode_capacity * 2u : 8u;
        struct futfs_inode_mem *resized =
            fut_realloc(g_fs.inodes, new_cap * sizeof(*resized));
        if (!resized) {
            return NULL;
        }
        g_fs.inodes = resized;
        g_fs.inode_capacity = new_cap;
    }
    struct futfs_inode_mem *slot = &g_fs.inodes[g_fs.inode_count++];
    memset(slot, 0, sizeof(*slot));
    slot->ino = ino;
    return slot;
}

static void futfs_free_inode_data(struct futfs_inode_mem *inode) {
    if (inode->data) {
        fut_free(inode->data);
        inode->data = NULL;
        inode->capacity = 0;
        inode->size = 0;
    }
}

static void futfs_reset_inodes(void) {
    if (!g_fs.inodes) {
        g_fs.inode_count = 0;
        g_fs.inode_capacity = 0;
        return;
    }
    for (size_t i = 0; i < g_fs.inode_count; ++i) {
        futfs_free_inode_data(&g_fs.inodes[i]);
    }
    fut_free(g_fs.inodes);
    g_fs.inodes = NULL;
    g_fs.inode_count = 0;
    g_fs.inode_capacity = 0;
}

static uint32_t futfs_checksum32(const uint8_t *data, size_t len) {
    uint32_t sum = 0;
    for (size_t i = 0; i < len; ++i) {
        sum += data[i];
    }
    return sum;
}

/* -------------------------------------------------------------------------- */
/* Directory utilities                                                        */
/* -------------------------------------------------------------------------- */

static fut_status_t futfs_dir_append(struct futfs_inode_mem *dir,
                                     const char *name,
                                     uint64_t ino) {
    size_t name_len = futfs_strlen(name);
    if (name_len == 0 || name_len > FUTFS_NAME_MAX) {
        return -EINVAL;
    }
    size_t entry_bytes = sizeof(futfs_dirent_disk_t) + name_len;
    size_t padded = futfs_align8(entry_bytes);
    size_t new_size = dir->size + padded;
    if (new_size > dir->capacity) {
        size_t new_cap = dir->capacity ? dir->capacity * 2u : 64u;
        while (new_cap < new_size) {
            new_cap *= 2u;
        }
        uint8_t *resized = fut_realloc(dir->data, new_cap);
        if (!resized) {
            return -ENOMEM;
        }
        dir->data = resized;
        dir->capacity = new_cap;
    }
    futfs_dirent_disk_t *entry = (futfs_dirent_disk_t *)(dir->data + dir->size);
    entry->ino = ino;
    entry->name_len = (uint16_t)name_len;
    entry->reserved = 0;
    memcpy(entry->name, name, name_len);
    memset((uint8_t *)entry + entry_bytes, 0, padded - entry_bytes);
    dir->size += padded;
    return 0;
}

fut_status_t futfs_dir_resolve_latest(const struct futfs_inode_mem *dir,
                                             const char *name,
                                             size_t name_len,
                                             size_t *offset_out,
                                             const futfs_dirent_disk_t **entry_out) {
    if (!dir || !dir->data || dir->size == 0 ||
        !name || name_len == 0 || name_len > FUTFS_NAME_MAX) {
        return -ENOENT;
    }

    const futfs_dirent_disk_t *candidate = NULL;
    size_t candidate_offset = 0;

    size_t offset = 0;
    while (offset + sizeof(futfs_dirent_disk_t) <= dir->size) {
        const futfs_dirent_disk_t *entry =
            (const futfs_dirent_disk_t *)(dir->data + offset);
        size_t entry_bytes = sizeof(futfs_dirent_disk_t) + entry->name_len;
        size_t padded = futfs_align8(entry_bytes);
        if (offset + padded > dir->size) {
            return -EINVAL;
        }

        if (entry->name_len == name_len &&
            memcmp(entry->name, name, name_len) == 0) {
            if (entry->ino == 0) {
                candidate = NULL;
            } else {
                candidate = entry;
                candidate_offset = offset;
            }
        }

        offset += padded;
    }

    if (!candidate) {
        return -ENOENT;
    }

    if (offset_out) {
        *offset_out = candidate_offset;
    }
    if (entry_out) {
        *entry_out = candidate;
    }
    return 0;
}

static uint64_t futfs_dir_lookup(const struct futfs_inode_mem *dir,
                                 const char *name) {
    size_t name_len = futfs_strlen(name);
    const futfs_dirent_disk_t *entry = NULL;
    if (futfs_dir_resolve_latest(dir, name, name_len, NULL, &entry) == 0 && entry) {
        return entry->ino;
    }
    return 0;
}

static size_t futfs_dir_count_entries(const struct futfs_inode_mem *dir) {
    if (!dir || !dir->data || dir->size == 0) {
        return 0;
    }

    size_t count = 0;
    size_t offset = 0;

    while (offset + sizeof(futfs_dirent_disk_t) <= dir->size) {
        const futfs_dirent_disk_t *entry =
            (const futfs_dirent_disk_t *)(dir->data + offset);
        size_t entry_bytes = sizeof(futfs_dirent_disk_t) + entry->name_len;
        size_t padded = futfs_align8(entry_bytes);
        if (offset + padded > dir->size) {
            break;
        }

        if (entry->ino != 0 && entry->name_len != 0) {
            const futfs_dirent_disk_t *latest = NULL;
            if (futfs_dir_resolve_latest(dir, entry->name, entry->name_len,
                                         NULL, &latest) == 0 &&
                latest == entry) {
                bool is_dot = (entry->name_len == 1 && entry->name[0] == '.');
                bool is_dotdot = (entry->name_len == 2 &&
                                  entry->name[0] == '.' &&
                                  entry->name[1] == '.');
                if (!is_dot && !is_dotdot) {
                    count++;
                }
            }
        }

        offset += padded;
    }

    return count;
}

bool futfs_dir_is_empty(const struct futfs_inode_mem *dir) {
    return futfs_dir_count_entries(dir) == 0;
}

static struct futfs_inode_mem *futfs_root_dir(void) {
    return futfs_find_inode(1);
}

/* -------------------------------------------------------------------------- */
/* Path parsing utilities for nested directory support                       */
/* -------------------------------------------------------------------------- */

#define FUTFS_MAX_PATH_COMPONENTS 64

/**
 * Parse a path like "/a/b/c" into individual components.
 * @param path Input path (must start with '/')
 * @param components Output array of component strings
 * @param max_components Maximum number of components to extract
 * @return Number of components extracted, or negative error code
 */
static int futfs_parse_path(const char *path,
                             char components[][FUTFS_NAME_MAX + 1],
                             int max_components) {
    if (!path || path[0] != '/') {
        return -EINVAL;
    }

    int count = 0;
    const char *start = path;

    /* Skip leading slashes */
    while (*start == '/') {
        start++;
    }

    while (*start && count < max_components) {
        const char *end = start;

        /* Find next slash or end of string */
        while (*end && *end != '/') {
            end++;
        }

        /* Copy component */
        size_t len = end - start;
        if (len > 0) {
            if (len > FUTFS_NAME_MAX) {
                return -ENAMETOOLONG;
            }
            memcpy(components[count], start, len);
            components[count][len] = '\0';
            count++;
        }

        /* Skip trailing slashes */
        while (*end == '/') {
            end++;
        }

        start = end;
    }

    if (*start) {
        /* Path has more components than we can handle */
        return -ENAMETOOLONG;
    }

    return count;
}

/**
 * Walk a path to find the parent directory.
 * For path "/a/b/c", returns directory for "/a/b".
 * For path "/a", returns the root directory.
 * @param path Input path
 * @param dir_out Output parent directory inode
 * @return Status code (0 on success)
 */
static fut_status_t futfs_walk_path_to_parent(const char *path,
                                              struct futfs_inode_mem **dir_out) {
    if (!path || path[0] != '/' || !dir_out) {
        return -EINVAL;
    }

    struct futfs_inode_mem *root = futfs_root_dir();
    if (!root || root->type != FUTFS_INODE_DIR) {
        return -EIO;
    }

    /* Parse path into components */
    char (*components)[FUTFS_NAME_MAX + 1] = fut_malloc(FUTFS_MAX_PATH_COMPONENTS * (FUTFS_NAME_MAX + 1));
    if (!components) {
        return -ENOMEM;
    }

    int comp_count = futfs_parse_path(path, components, FUTFS_MAX_PATH_COMPONENTS);
    if (comp_count < 0) {
        fut_free(components);
        return comp_count;
    }

    if (comp_count <= 1) {
        /* Path is "/" or has single component - parent is root */
        *dir_out = root;
        fut_free(components);
        return 0;
    }

    /* Walk to parent directory (all components except last) */
    struct futfs_inode_mem *current = root;
    for (int i = 0; i < comp_count - 1; i++) {
        uint64_t ino = futfs_dir_lookup(current, components[i]);
        if (ino == 0) {
            fut_free(components);
            return -ENOENT;
        }
        struct futfs_inode_mem *next = futfs_find_inode(ino);
        if (!next || next->type != FUTFS_INODE_DIR) {
            fut_free(components);
            return -ENOTDIR;
        }
        current = next;
    }

    *dir_out = current;
    fut_free(components);
    return 0;
}

/**
 * Walk a path to find a directory, handling nested paths like "/a/b/c".
 * @param path Input path
 * @param dir_out Output directory inode for the final component
 * @return Status code (0 on success, -ENOENT if not found, -ENOTDIR if intermediate component isn't a dir)
 */
static fut_status_t futfs_walk_path_to_dir(const char *path,
                                           struct futfs_inode_mem **dir_out) {
    if (!path || path[0] != '/' || !dir_out) {
        return -EINVAL;
    }

    struct futfs_inode_mem *root = futfs_root_dir();
    if (!root || root->type != FUTFS_INODE_DIR) {
        return -EIO;
    }

    /* Parse path into components */
    char (*components)[FUTFS_NAME_MAX + 1] = fut_malloc(FUTFS_MAX_PATH_COMPONENTS * (FUTFS_NAME_MAX + 1));
    if (!components) {
        return -ENOMEM;
    }

    int comp_count = futfs_parse_path(path, components, FUTFS_MAX_PATH_COMPONENTS);
    if (comp_count < 0) {
        fut_free(components);
        return comp_count;
    }

    if (comp_count == 0) {
        /* Path is "/" - return root */
        *dir_out = root;
        fut_free(components);
        return 0;
    }

    /* Walk all components */
    struct futfs_inode_mem *current = root;
    for (int i = 0; i < comp_count; i++) {
        uint64_t ino = futfs_dir_lookup(current, components[i]);
        if (ino == 0) {
            fut_free(components);
            return -ENOENT;
        }
        struct futfs_inode_mem *next = futfs_find_inode(ino);
        if (!next || next->type != FUTFS_INODE_DIR) {
            fut_free(components);
            return -ENOTDIR;
        }
        current = next;
    }

    *dir_out = current;
    fut_free(components);
    return 0;
}

fut_status_t futfs_resolve_dir(const char *path,
                                      struct futfs_inode_mem **dir_out) {
    if (!g_fs.mounted || !path || !dir_out) {
        return -EINVAL;
    }

    if (path[0] != '/') {
        return -EINVAL;
    }

    /* Handle root directory */
    const char *name = path + 1;
    if (*name == '\0') {
        struct futfs_inode_mem *root = futfs_root_dir();
        if (!root || root->type != FUTFS_INODE_DIR) {
            return -EIO;
        }
        *dir_out = root;
        return 0;
    }

    /* For any other path, use the path walker which handles nested paths */
    return futfs_walk_path_to_dir(path, dir_out);
}

static fut_status_t futfs_resolve_parent(const char *path,
                                         struct futfs_inode_mem **parent_out,
                                         const char **name_out) {
    if (!g_fs.mounted || !path || !parent_out || !name_out) {
        return -EINVAL;
    }
    if (path[0] != '/') {
        return -EINVAL;
    }

    /* Find the last '/' to separate parent path from basename */
    const char *last_slash = NULL;
    const char *p = path;
    while (*p) {
        if (*p == '/') {
            last_slash = p;
        }
        p++;
    }

    /* If no '/' found (shouldn't happen since path starts with '/'), it's invalid */
    if (!last_slash || last_slash == path) {
        /* This means path is "/" or has no intermediate slashes - extract basename simply */
        last_slash = path;
    }

    const char *basename = last_slash + 1;
    if (*basename == '\0') {
        /* Path ends with '/' - invalid for operations like mkdir/create */
        return -EINVAL;
    }

    /* Check basename length */
    size_t name_len = futfs_strlen(basename);
    if (name_len == 0 || name_len > FUTFS_NAME_MAX) {
        return -ENAMETOOLONG;
    }

    /* Find parent directory by walking the path up to (but not including) the basename */
    fut_status_t rc = futfs_walk_path_to_parent(path, parent_out);
    if (rc != 0) {
        return rc;
    }

    *name_out = basename;
    return 0;
}

static void futfs_remove_inode(struct futfs_inode_mem *inode) {
    if (!inode || !g_fs.inodes || g_fs.inode_count == 0) {
        return;
    }
    size_t idx = (size_t)(inode - g_fs.inodes);
    if (idx >= g_fs.inode_count) {
        return;
    }

    futfs_free_inode_data(&g_fs.inodes[idx]);

    if (idx + 1u < g_fs.inode_count) {
        memmove(&g_fs.inodes[idx],
                &g_fs.inodes[idx + 1u],
                (g_fs.inode_count - idx - 1u) * sizeof(g_fs.inodes[0]));
    }
    g_fs.inode_count--;
}

/* -------------------------------------------------------------------------- */
/* Block IO helpers                                                           */
/* -------------------------------------------------------------------------- */

struct futfs_bio {
    fut_bio_t bio;
    volatile bool done;
    fut_status_t status;
};

static void futfs_bio_complete(fut_bio_t *bio, int status, size_t bytes) {
    (void)bytes;
    struct futfs_bio *req =
        (struct futfs_bio *)((uint8_t *)bio - offsetof(struct futfs_bio, bio));
    req->status = status;
    req->done = true;
}

static fut_status_t futfs_transfer(uint64_t lba,
                                   size_t nsectors,
                                   void *buffer,
                                   bool write) {
    struct futfs_bio req;
    memset(&req, 0, sizeof(req));
    req.bio.lba = lba;
    req.bio.nsectors = nsectors;
    req.bio.buf = buffer;
    req.bio.write = write;
    req.bio.on_complete = futfs_bio_complete;

    fut_status_t rc = fut_blk_submit(g_fs.dev_handle, &req.bio);
    if (rc != 0) {
        return rc;
    }

    while (!req.done) {
        futfs_sleep_poll();
    }
    return req.status;
}

static fut_status_t futfs_read_blocks(uint64_t lba, void *buffer, size_t bytes) {
    size_t nsectors = (bytes + g_fs.block_size - 1u) / g_fs.block_size;
    return futfs_transfer(lba, nsectors, buffer, false);
}

static fut_status_t futfs_write_blocks(uint64_t lba, const void *buffer, size_t bytes) {
    size_t nsectors = (bytes + g_fs.block_size - 1u) / g_fs.block_size;
    return futfs_transfer(lba, nsectors, (void *)buffer, true);
}

static fut_rights_t futfs_rights_to_object(uint32_t rights) {
    fut_rights_t obj = FUT_RIGHT_DESTROY;
    if (rights & FUTFS_RIGHT_READ) {
        obj |= FUT_RIGHT_READ;
    }
    if (rights & FUTFS_RIGHT_WRITE) {
        obj |= FUT_RIGHT_WRITE;
    }
    if (rights & FUTFS_RIGHT_ADMIN) {
        obj |= FUT_RIGHT_ADMIN;
    }
    return obj;
}

static struct futfs_handle *futfs_get_handle(fut_handle_t cap,
                                             uint32_t required,
                                             fut_object_t **out_obj) {
    fut_rights_t needed = FUT_RIGHT_DESTROY;
    if (required & FUTFS_RIGHT_READ) {
        needed |= FUT_RIGHT_READ;
    }
    if (required & FUTFS_RIGHT_WRITE) {
        needed |= FUT_RIGHT_WRITE;
    }
    if (required & FUTFS_RIGHT_ADMIN) {
        needed |= FUT_RIGHT_ADMIN;
    }
    fut_object_t *obj = fut_object_get(cap, needed);
    if (!obj) {
        return NULL;
    }
    struct futfs_handle *handle = (struct futfs_handle *)obj->data;
    if (!handle) {
        fut_object_put(obj);
        return NULL;
    }
    if ((handle->rights & required) != required) {
        fut_object_put(obj);
        return NULL;
    }
    if (out_obj) {
        *out_obj = obj;
    }
    return handle;
}

/* -------------------------------------------------------------------------- */
/* Serialization / deserialization                                            */
/* -------------------------------------------------------------------------- */

static fut_status_t futfs_load_segment(uint64_t lba) {
    size_t seg_bytes = g_fs.segment_sectors * g_fs.block_size;
    uint8_t *buffer = fut_malloc(seg_bytes);
    if (!buffer) {
        return -ENOMEM;
    }

    fut_status_t rc = futfs_read_blocks(lba, buffer, seg_bytes);
    if (rc != 0) {
        fut_free(buffer);
        return rc;
    }

    futfs_segment_header_disk_t header;
    memcpy(&header, buffer, sizeof(header));
    uint32_t checksum = futfs_checksum32(buffer + sizeof(header),
                                         seg_bytes - sizeof(header));
    if (header.checksum != checksum) {
        fut_free(buffer);
        return -EIO;
    }

    uint8_t *cursor = buffer + sizeof(header);
    uint64_t highest_ino = 0;

    futfs_reset_inodes();

    for (uint32_t i = 0; i < header.inode_count; ++i) {
        if ((size_t)(cursor - buffer) + sizeof(futfs_inode_disk_fixed_t) > seg_bytes) {
            fut_free(buffer);
            return -EIO;
        }

        futfs_inode_disk_fixed_t fixed;
        memcpy(&fixed, cursor, sizeof(fixed));
        cursor += sizeof(fixed);

        if ((size_t)(cursor - buffer) +
                fixed.extent_count * sizeof(futfs_extent_disk_t) >
            seg_bytes) {
            fut_free(buffer);
            return -EIO;
        }

        const futfs_extent_disk_t *extents =
            (const futfs_extent_disk_t *)cursor;
        cursor += fixed.extent_count * sizeof(futfs_extent_disk_t);
        cursor = buffer + futfs_align8((size_t)(cursor - buffer));

        struct futfs_inode_mem *inode = futfs_create_inode_slot(fixed.ino);
        if (!inode) {
            fut_free(buffer);
            return -ENOMEM;
        }
        inode->type = fixed.type;
        inode->rights = fixed.rights;
        inode->size = fixed.size;
        inode->capacity = fixed.size;

        futfs_free_inode_data(inode);

        if (fixed.extent_count > 0 && fixed.size > 0) {
            const futfs_extent_disk_t *ext = &extents[0];
            if (ext->offset + ext->length > seg_bytes) {
                fut_free(buffer);
                return -EIO;
            }
            inode->data = fut_malloc(ext->length);
            if (!inode->data) {
                fut_free(buffer);
                return -ENOMEM;
            }
            memcpy(inode->data, buffer + ext->offset, ext->length);
            inode->size = ext->length;
            inode->capacity = ext->length;
        }

        if (inode->ino > highest_ino) {
            highest_ino = inode->ino;
        }
    }

    if (!futfs_find_inode(1)) {
        struct futfs_inode_mem *root = futfs_create_inode_slot(1);
        if (!root) {
            fut_free(buffer);
            return -ENOMEM;
        }
        root->type = FUTFS_INODE_DIR;
        root->rights = FUTFS_RIGHT_READ | FUTFS_RIGHT_WRITE | FUTFS_RIGHT_ADMIN;
    }

    g_fs.next_inode = highest_ino + 1;
    g_fs.next_segment_id = header.id + 1;

    fut_free(buffer);
    return 0;
}

struct futfs_inode_emit {
    struct futfs_inode_mem *inode;
    uint32_t extent_count;
    uint32_t dirent_count;
    uint32_t data_offset;
    uint32_t data_length;
};

static fut_status_t futfs_flush(void) {
    if (!g_fs.dirty && !g_fs.super_dirty) {
        return 0;
    }

    fut_status_t rc = 0;
    bool segment_written = false;
    uint64_t original_next_free = g_fs.next_free_lba;
    uint64_t original_version = g_fs.version;
    uint32_t block_size = g_fs.block_size ? g_fs.block_size : 512;

    if (g_fs.dirty) {
        if (g_fs.inode_count == 0) {
            return -EINVAL;
        }

        size_t seg_bytes = g_fs.segment_sectors * block_size;
        uint8_t *segment = futfs_zalloc(seg_bytes);
        if (!segment) {
            return -ENOMEM;
        }

        struct futfs_inode_emit *emit =
            futfs_zalloc(g_fs.inode_count * sizeof(*emit));
        if (!emit) {
            fut_free(segment);
            return -ENOMEM;
        }

        size_t cursor = sizeof(futfs_segment_header_disk_t);
        for (size_t i = 0; i < g_fs.inode_count; ++i) {
            emit[i].inode = &g_fs.inodes[i];
            emit[i].extent_count = g_fs.inodes[i].size > 0 ? 1u : 0u;
            emit[i].dirent_count =
                (g_fs.inodes[i].type == FUTFS_INODE_DIR)
                    ? futfs_dir_count_entries(&g_fs.inodes[i])
                    : 0u;
            cursor += sizeof(futfs_inode_disk_fixed_t) +
                      emit[i].extent_count * sizeof(futfs_extent_disk_t);
            cursor = futfs_align8(cursor);
        }

        size_t data_cursor = cursor;
        for (size_t i = 0; i < g_fs.inode_count; ++i) {
            struct futfs_inode_mem *inode = emit[i].inode;
            if (inode->size > 0) {
                data_cursor = futfs_align8(data_cursor);
                emit[i].data_offset = (uint32_t)data_cursor;
                emit[i].data_length = (uint32_t)inode->size;
                data_cursor += inode->size;
            }
        }

        if (data_cursor > seg_bytes) {
            fut_free(emit);
            fut_free(segment);
            return -ENOSPC;
        }

        futfs_segment_header_disk_t *header =
            (futfs_segment_header_disk_t *)segment;
        header->id = g_fs.next_segment_id++;
        header->inode_count = (uint32_t)g_fs.inode_count;
        header->next_lba = g_fs.next_free_lba;

        uint8_t *meta_cursor = segment + sizeof(*header);
        for (size_t i = 0; i < g_fs.inode_count; ++i) {
            futfs_inode_disk_fixed_t fixed = {
                .ino = emit[i].inode->ino,
                .type = emit[i].inode->type,
                .rights = emit[i].inode->rights,
                .size = emit[i].inode->size,
                .dirent_count = emit[i].dirent_count,
                .extent_count = emit[i].extent_count,
            };
            memcpy(meta_cursor, &fixed, sizeof(fixed));
            meta_cursor += sizeof(fixed);

            if (emit[i].extent_count > 0) {
                futfs_extent_disk_t ext = {
                    .offset = emit[i].data_offset,
                    .length = emit[i].data_length,
                };
                memcpy(meta_cursor, &ext, sizeof(ext));
                meta_cursor += sizeof(ext);
            }

            size_t consumed = meta_cursor - segment;
            meta_cursor = segment + futfs_align8(consumed);
        }

        for (size_t i = 0; i < g_fs.inode_count; ++i) {
            if (emit[i].data_length > 0) {
                memcpy(segment + emit[i].data_offset,
                       emit[i].inode->data,
                       emit[i].data_length);
            }
        }

        header->checksum = futfs_checksum32(segment + sizeof(*header),
                                            seg_bytes - sizeof(*header));

        rc = futfs_write_blocks(g_fs.next_free_lba, segment, seg_bytes);
        if (rc != 0) {
            fut_free(emit);
            fut_free(segment);
            g_fs.next_segment_id--;
            return rc;
        }

        g_fs.next_free_lba += g_fs.segment_sectors;
        g_fs.version++;
        segment_written = true;

        fut_free(emit);
        fut_free(segment);
    }

    uint64_t device_blocks = g_fs.dev ? fut_blk_block_count(g_fs.dev) : 0;
    uint64_t data_blocks_total =
        device_blocks > 1 ? device_blocks - 1 : device_blocks;
    uint64_t blocks_used = futfs_total_blocks_used();
    uint64_t inodes_total = futfs_highwater_inodes();
    uint64_t tombstones = futfs_total_dir_tombstones();

    futfs_superblock_disk_t super;
    memset(&super, 0, sizeof(super));
    memcpy(super.magic, "FUTFSv0", 7);
    super.version = g_fs.version ? g_fs.version : FUTFS_SUPER_VERSION_MAJOR;
    super.block_size_legacy = block_size;
    super.segment_sectors = g_fs.segment_sectors;
    super.inode_count = (uint32_t)g_fs.inode_count;
    if (g_fs.next_free_lba >= g_fs.segment_sectors) {
        super.latest_segment_lba = g_fs.next_free_lba - g_fs.segment_sectors;
    } else {
        super.latest_segment_lba = 1;
    }
    super.next_free_lba = g_fs.next_free_lba;
    super.root_ino = 1;
    super.next_inode = g_fs.next_inode;
    memcpy(super.label, g_fs.label, sizeof(super.label));
    super.version_minor = FUTFS_SUPER_VERSION_MINOR;
    super.features = FUTFS_FEATURE_LOG_STRUCTURED |
                     FUTFS_FEATURE_TOMBSTONES |
                     FUTFS_FEATURE_DIR_COMPACTION;
    super.block_size = block_size;
    super.blocks_total = data_blocks_total;
    super.blocks_used = blocks_used;
    super.inodes_total = inodes_total;
    super.inodes_used = g_fs.inode_count;
    super.dir_tombstones = tombstones;

    uint8_t *sb_buf = futfs_zalloc(block_size);
    if (!sb_buf) {
        rc = -ENOMEM;
        goto done;
    }
    memcpy(sb_buf, &super, sizeof(super));
    rc = futfs_write_blocks(0, sb_buf, block_size);
    fut_free(sb_buf);
    if (rc != 0) {
        goto done;
    }

    (void)fut_blk_flush(g_fs.dev_handle);
    g_fs.dirty = false;
    g_fs.super_dirty = false;

done:
    if (rc != 0 && segment_written) {
        g_fs.next_free_lba = original_next_free;
        g_fs.version = original_version;
    }
    return rc;
}

/* -------------------------------------------------------------------------- */
/* Public API                                                                 */
/* -------------------------------------------------------------------------- */

fut_status_t futfs_mount(fut_handle_t dev) {
    if (g_fs.mounted) {
        return -EBUSY;
    }

    fut_blkdev_t *blk = NULL;
    fut_status_t rc = fut_blk_open(dev, &blk);
    if (rc != 0) {
        return rc;
    }

    g_fs.dev_handle = dev;
    g_fs.dev = blk;
    g_fs.block_size = fut_blk_block_size(blk);
    if (g_fs.block_size == 0) {
        g_fs.block_size = 512;
    }

    uint8_t *sb_buf = futfs_zalloc(g_fs.block_size);
    if (!sb_buf) {
        return -ENOMEM;
    }

    rc = futfs_read_blocks(0, sb_buf, g_fs.block_size);
    if (rc != 0) {
        fut_free(sb_buf);
        return rc;
    }

    futfs_superblock_disk_t super;
    memcpy(&super, sb_buf, sizeof(super));
    fut_free(sb_buf);

    if (memcmp(super.magic, "FUTFSv0", 7) != 0) {
        return -EINVAL;
    }

    if (super.block_size_legacy != g_fs.block_size) {
        return -EINVAL;
    }

    bool compat_upgrade = false;
    if (super.version_minor < FUTFS_SUPER_VERSION_MINOR) {
        compat_upgrade = true;
    }

    if (super.features == 0) {
        super.features = FUTFS_FEATURE_LOG_STRUCTURED |
                         FUTFS_FEATURE_TOMBSTONES |
                         FUTFS_FEATURE_DIR_COMPACTION;
        compat_upgrade = true;
    }

    if (super.block_size == 0) {
        super.block_size = g_fs.block_size;
        compat_upgrade = true;
    }

    if (super.blocks_total == 0) {
        uint64_t device_blocks = g_fs.dev ? fut_blk_block_count(g_fs.dev) : 0;
        super.blocks_total =
            device_blocks > 1 ? device_blocks - 1 : device_blocks;
        compat_upgrade = true;
    }

    if (super.inodes_total == 0) {
        super.inodes_total = super.next_inode > 0 ? super.next_inode - 1 : 0;
        compat_upgrade = true;
    }

    if (super.inodes_used == 0) {
        super.inodes_used = super.inode_count;
        compat_upgrade = true;
    }

    g_fs.segment_sectors =
        super.segment_sectors ? super.segment_sectors : FUTFS_DEFAULT_SEG_SECT;
    g_fs.next_free_lba = super.next_free_lba
                             ? super.next_free_lba
                             : (uint64_t)g_fs.segment_sectors + 1u;
    g_fs.version = super.version ? super.version : FUTFS_SUPER_VERSION_MAJOR;
    g_fs.next_inode = super.next_inode ? super.next_inode : 2;
    memcpy(g_fs.label, super.label, sizeof(g_fs.label));

    rc = futfs_load_segment(
        super.latest_segment_lba ? super.latest_segment_lba : 1);
    if (rc != 0) {
        fut_blk_close(dev);
        g_fs.dev_handle = FUT_INVALID_HANDLE;
        g_fs.dev = NULL;
        futfs_reset_inodes();
        return rc;
    }

    uint64_t computed_blocks = futfs_total_blocks_used();
    uint64_t computed_tombstones = futfs_total_dir_tombstones();
    uint64_t computed_highwater = futfs_highwater_inodes();

    if (super.blocks_used != computed_blocks) {
        compat_upgrade = true;
    }
    if (super.dir_tombstones != computed_tombstones) {
        compat_upgrade = true;
    }
    if (super.inodes_total != computed_highwater) {
        compat_upgrade = true;
    }
    if (super.inodes_used != g_fs.inode_count) {
        compat_upgrade = true;
    }

    g_fs.mounted = true;
    g_fs.dirty = false;
    g_fs.super_dirty = compat_upgrade;

    if (fut_boot_arg_flag("futurafs.test_crash_compact")) {
        futfs_set_crash_compaction(true);
    } else {
        futfs_set_crash_compaction(false);
    }
    return 0;
}

fut_status_t futfs_unmount(void) {
    if (!g_fs.mounted) {
        return -EINVAL;
    }
    fut_status_t rc = futfs_flush();
    fut_blk_close(g_fs.dev_handle);
    g_fs.dev_handle = FUT_INVALID_HANDLE;
    g_fs.dev = NULL;
    g_fs.mounted = false;
    g_fs.dirty = false;
    g_fs.super_dirty = false;
    g_fs.block_size = 0;
    g_fs.segment_sectors = 0;
    g_fs.next_free_lba = 0;
    g_fs.next_segment_id = 0;
    g_fs.next_inode = 0;
    g_fs.version = 0;
    futfs_reset_inodes();
    memset(g_fs.label, 0, sizeof(g_fs.label));
    return rc;
}

fut_status_t futfs_create(const char *path, fut_handle_t *out) {
    if (!g_fs.mounted || !path || path[0] != '/' || !out) {
        return -EINVAL;
    }

    const char *name = path + 1;
    size_t name_len = futfs_strlen(name);
    if (name_len == 0) {
        return -EINVAL;
    }
    if (name_len > FUTFS_NAME_MAX) {
        return -ENAMETOOLONG;
    }

    struct futfs_inode_mem *root = futfs_find_inode(1);
    if (!root || root->type != FUTFS_INODE_DIR) {
        return -EIO;
    }

    if (futfs_dir_lookup(root, name) != 0) {
        return -EEXIST;
    }

    struct futfs_inode_mem *inode = futfs_create_inode_slot(g_fs.next_inode);
    if (!inode) {
        return -ENOMEM;
    }

    inode->type = FUTFS_INODE_REG;
    inode->rights = FUTFS_RIGHT_READ | FUTFS_RIGHT_WRITE | FUTFS_RIGHT_ADMIN;
    inode->size = 0;
    inode->capacity = 0;
    inode->data = NULL;

    fut_status_t rc = futfs_dir_append(root, name, inode->ino);
    if (rc != 0) {
        return rc;
    }

    g_fs.next_inode++;
    futfs_mark_dirty();

    struct futfs_handle *handle = fut_malloc(sizeof(*handle));
    if (!handle) {
        return -ENOMEM;
    }
    handle->inode = inode;
    handle->rights = inode->rights;
    handle->offset = 0;

    fut_rights_t obj_rights = futfs_rights_to_object(handle->rights);
    fut_handle_t cap = fut_object_create(FUT_OBJ_FILE, obj_rights, handle);
    if (cap == FUT_INVALID_HANDLE) {
        fut_free(handle);
        return -ENOMEM;
    }

    *out = cap;
    return 0;
}

fut_status_t futfs_read(fut_handle_t cap, void *buf, size_t len, size_t *out) {
    if (!buf) {
        return -EINVAL;
    }
    fut_object_t *obj = NULL;
    struct futfs_handle *handle = futfs_get_handle(cap, FUTFS_RIGHT_READ, &obj);
    if (!handle) {
        return -EPERM;
    }
    struct futfs_inode_mem *inode = handle->inode;
    if (!inode) {
        fut_object_put(obj);
        return -EIO;
    }
    size_t remaining = (handle->offset < inode->size)
                           ? inode->size - handle->offset
                           : 0;
    size_t to_copy = remaining < len ? remaining : len;
    if (to_copy > 0) {
        memcpy(buf, inode->data + handle->offset, to_copy);
        handle->offset += to_copy;
    }
    if (out) {
        *out = to_copy;
    }
    fut_object_put(obj);
    return 0;
}

fut_status_t futfs_write(fut_handle_t cap, const void *buf, size_t len) {
    if (!buf) {
        return -EINVAL;
    }
    fut_object_t *obj = NULL;
    struct futfs_handle *handle = futfs_get_handle(cap, FUTFS_RIGHT_WRITE, &obj);
    if (!handle) {
        return -EPERM;
    }
    struct futfs_inode_mem *inode = handle->inode;
    if (!inode || inode->type != FUTFS_INODE_REG) {
        fut_object_put(obj);
        return -EIO;
    }

    if (len > inode->capacity) {
        size_t new_cap = inode->capacity ? inode->capacity : 128u;
        while (new_cap < len) {
            new_cap *= 2u;
        }
        uint8_t *resized = fut_realloc(inode->data, new_cap);
        if (!resized) {
            fut_object_put(obj);
            return -ENOMEM;
        }
        inode->data = resized;
        inode->capacity = new_cap;
    }

    memcpy(inode->data, buf, len);
    inode->size = len;
    handle->offset = len;
    futfs_mark_dirty();
    fut_object_put(obj);
    return 0;
}

fut_status_t futfs_sync(fut_handle_t cap) {
    fut_object_t *obj = NULL;
    struct futfs_handle *handle = futfs_get_handle(cap, FUTFS_RIGHT_ADMIN, &obj);
    if (!handle) {
        return -EPERM;
    }
    handle->offset = 0;
    fut_object_put(obj);
    return futfs_flush();
}

fut_status_t futfs_stat(fut_handle_t cap, struct fut_stat *st) {
    if (!st) {
        return -EINVAL;
    }
    fut_object_t *obj = NULL;
    struct futfs_handle *handle = futfs_get_handle(cap, 0, &obj);
    if (!handle) {
        return -EPERM;
    }
    struct futfs_inode_mem *inode = handle->inode;
    if (!inode) {
        fut_object_put(obj);
        return -EIO;
    }
    memset(st, 0, sizeof(*st));
    st->st_ino = inode->ino;
    st->st_size = inode->size;
    st->st_blksize = g_fs.block_size;
    st->st_blocks = (inode->size + g_fs.block_size - 1u) / g_fs.block_size;
    st->st_mode = (inode->type == FUTFS_INODE_DIR) ? VN_DIR : VN_REG;
    fut_object_put(obj);
    return 0;
}

fut_status_t futfs_close(fut_handle_t cap) {
    fut_object_t *obj = fut_object_get(cap, FUT_RIGHT_DESTROY);
    if (!obj) {
        return -EPERM;
    }
    struct futfs_handle *handle = (struct futfs_handle *)obj->data;
    obj->data = NULL;
    fut_object_put(obj);
    fut_status_t rc = fut_object_destroy(cap);
    if (handle) {
        fut_free(handle);
    }
    return rc;
}

fut_status_t futfs_mkdir(const char *path) {
    struct futfs_inode_mem *parent = NULL;
    const char *name = NULL;
    fut_status_t rc = futfs_resolve_parent(path, &parent, &name);
    if (rc != 0) {
        return rc;
    }

    if (futfs_dir_lookup(parent, name) != 0) {
        return -EEXIST;
    }

    struct futfs_inode_mem *inode = futfs_create_inode_slot(g_fs.next_inode);
    if (!inode) {
        return -ENOMEM;
    }

    inode->type = FUTFS_INODE_DIR;
    inode->rights = FUTFS_RIGHT_READ | FUTFS_RIGHT_WRITE | FUTFS_RIGHT_ADMIN;
    inode->size = 0;
    inode->capacity = 0;
    inode->data = NULL;

    rc = futfs_dir_append(parent, name, inode->ino);
    if (rc != 0) {
        g_fs.inode_count--;
        return rc;
    }

    g_fs.next_inode++;
    futfs_mark_dirty();
    return 0;
}

fut_status_t futfs_readdir(const char *path, size_t *cookie, futfs_dirent_t *out) {
    if (!cookie || !out) {
        return -EINVAL;
    }

    struct futfs_inode_mem *dir = NULL;
    fut_status_t rc = futfs_resolve_dir(path, &dir);
    if (rc != 0) {
        return rc;
    }

    if (!dir->data || dir->size == 0 || *cookie >= dir->size) {
        *cookie = dir ? dir->size : 0;
        return 0;
    }

    size_t offset = *cookie;

    while (offset + sizeof(futfs_dirent_disk_t) <= dir->size) {
        const futfs_dirent_disk_t *entry =
            (const futfs_dirent_disk_t *)(dir->data + offset);
        size_t entry_bytes = sizeof(futfs_dirent_disk_t) + entry->name_len;
        size_t padded = futfs_align8(entry_bytes);
        if (offset + padded > dir->size) {
            return -EINVAL;
        }

        size_t next_offset = offset + padded;

        if (entry->ino != 0 && entry->name_len != 0) {
            const futfs_dirent_disk_t *latest = NULL;
            if (futfs_dir_resolve_latest(dir, entry->name, entry->name_len,
                                         NULL, &latest) == 0 &&
                latest == entry) {
                bool is_dot = (entry->name_len == 1 && entry->name[0] == '.');
                bool is_dotdot = (entry->name_len == 2 &&
                                  entry->name[0] == '.' &&
                                  entry->name[1] == '.');
                if (!is_dot && !is_dotdot) {
                    struct futfs_inode_mem *child = futfs_find_inode(entry->ino);

                    memset(out, 0, sizeof(*out));
                    out->ino = entry->ino;
                    out->type = child ? child->type : 0;

                    size_t copy = entry->name_len < FUTFS_NAME_MAX
                                      ? entry->name_len
                                      : FUTFS_NAME_MAX;
                    memcpy(out->name, entry->name, copy);
                    out->name[copy] = '\0';

                    *cookie = next_offset;
                    return 1;
                }
            }
        }

        offset = next_offset;
    }

    *cookie = dir->size;
    return 0;
}

fut_status_t futfs_unlink(const char *path) {
    struct futfs_inode_mem *parent = NULL;
    const char *name = NULL;
    fut_status_t rc = futfs_resolve_parent(path, &parent, &name);
    if (rc != 0) {
        return rc;
    }

    size_t name_len = futfs_strlen(name);
    const futfs_dirent_disk_t *entry = NULL;
    rc = futfs_dir_resolve_latest(parent, name, name_len, NULL, &entry);
    if (rc != 0 || !entry || entry->ino == 0) {
        return -ENOENT;
    }

    struct futfs_inode_mem *target = futfs_find_inode(entry->ino);
    if (!target) {
        return -EIO;
    }
    if (target->type != FUTFS_INODE_REG) {
        return -EISDIR;
    }

    rc = futfs_dir_append(parent, name, 0);
    if (rc != 0) {
        return rc;
    }

    futfs_remove_inode(target);
    futfs_mark_dirty();
    return 0;
}

fut_status_t futfs_statfs(struct fut_statfs *out) {
    if (!g_fs.mounted || !out) {
        return -EINVAL;
    }

    memset(out, 0, sizeof(*out));

    uint64_t block_size = g_fs.block_size;
    if (block_size == 0 && g_fs.dev) {
        block_size = fut_blk_block_size(g_fs.dev);
    }
    if (block_size == 0) {
        block_size = 512;
    }

    uint64_t total_blocks = g_fs.dev ? fut_blk_block_count(g_fs.dev) : 0;
    uint64_t data_blocks_total =
        total_blocks > 1 ? total_blocks - 1 : total_blocks;
    uint64_t blocks_used = futfs_total_blocks_used();
    uint64_t blocks_free =
        (data_blocks_total > blocks_used) ? (data_blocks_total - blocks_used) : 0;

    uint64_t max_inode = futfs_highwater_inodes();
    uint64_t active_inodes = g_fs.inode_count;
    uint64_t reclaimed =
        (max_inode > active_inodes) ? (max_inode - active_inodes) : 0;
    uint64_t tombstones = futfs_total_dir_tombstones();

    out->block_size = block_size;
    out->blocks_total = data_blocks_total;
    out->blocks_free = blocks_free;
    out->inodes_total = max_inode;
    out->inodes_free = reclaimed;
    out->dir_tombstones = tombstones;
    out->features = FUT_STATFS_FEAT_LOG_STRUCTURED |
                    FUT_STATFS_FEAT_TOMBSTONES |
                    FUT_STATFS_FEAT_DIR_COMPACTION;

    return 0;
}

fut_status_t futfs_compact_dir(const char *path, struct futfs_gc_stats *stats) {
    if (!path) {
        return -EINVAL;
    }
    struct futfs_inode_mem *dir = NULL;
    fut_status_t rc = futfs_resolve_dir(path, &dir);
    if (rc != 0) {
        return rc;
    }

    struct futfs_gc_stats local_stats;
    struct futfs_gc_stats *out = stats ? stats : &local_stats;
    memset(out, 0, sizeof(*out));

    rc = futfs_gc_compact_dir(dir, out, futfs_gc_crash_enabled());
    if (rc == 0 && (out->bytes_after != out->bytes_before ||
                    out->tombstones_after != out->tombstones_before)) {
        futfs_mark_dirty();
    }
    return rc;
}

void futfs_set_crash_compaction(bool enable) {
    futfs_gc_set_crash_injection(enable);
}

fut_status_t futfs_rmdir(const char *path) {
    struct futfs_inode_mem *parent = NULL;
    const char *name = NULL;
    fut_status_t rc = futfs_resolve_parent(path, &parent, &name);
    if (rc != 0) {
        return rc;
    }

    size_t name_len = futfs_strlen(name);
    const futfs_dirent_disk_t *entry = NULL;
    rc = futfs_dir_resolve_latest(parent, name, name_len, NULL, &entry);
    if (rc != 0 || !entry || entry->ino == 0) {
        return -ENOENT;
    }

    struct futfs_inode_mem *target = futfs_find_inode(entry->ino);
    if (!target) {
        return -EIO;
    }
    if (target->type != FUTFS_INODE_DIR) {
        return -ENOTDIR;
    }
    if (!futfs_dir_is_empty(target)) {
        return -ENOTEMPTY;
    }

    rc = futfs_dir_append(parent, name, 0);
    if (rc != 0) {
        return rc;
    }

    futfs_remove_inode(target);
    futfs_mark_dirty();
    return 0;
}
