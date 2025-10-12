// SPDX-License-Identifier: MPL-2.0
/*
 * logfs.c - Minimal log-structured filesystem skeleton
 */

#define _XOPEN_SOURCE 700

#include "logfs.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define FUTFS_SUPER_MAGIC "FUTFSLG"
#define FUTFS_VERSION     1u
#define FUTFS_SEG_MAGIC   0x46545347u /* 'FTSG' */

#define FUTFS_DEFAULT_BLOCK 4096u
#define FUTFS_MAX_NAME      63u
#define FUTFS_ROOT_INO      1ull

enum futfs_record_type {
    FUTFS_REC_CREATE = 1,
    FUTFS_REC_WRITE  = 2,
    FUTFS_REC_RENAME = 3,
};

struct futfs_superblock_disk {
    char magic[8];
    uint32_t version;
    uint32_t block_size;
    uint64_t log_begin;
    uint64_t log_tail;
    uint64_t next_ino;
    uint64_t root_ino;
    uint8_t reserved[400];
};

struct futfs_segment_header {
    uint32_t magic;
    uint16_t type;
    uint16_t reserved;
    uint32_t payload_len;
    uint64_t seqno;
};

struct futfs_rec_create_disk {
    uint64_t ino;
    uint64_t parent;
    uint32_t policy_rights;
    uint16_t name_len;
    uint16_t reserved;
    char name[];
};

struct futfs_rec_write_disk {
    uint64_t ino;
    uint64_t offset;
    uint32_t length;
    uint32_t reserved;
    uint8_t data[];
};

struct futfs_rec_rename_disk {
    uint64_t ino;
    uint64_t parent;
    uint16_t name_len;
    uint16_t reserved;
    char name[];
};

struct futfs_extent {
    uint64_t file_offset;
    uint32_t length;
    uint64_t log_data_offset;
};

struct futfs_inode_entry {
    uint64_t ino;
    uint64_t parent;
    uint32_t policy_rights;
    char name[FUTFS_MAX_NAME + 1];
    uint64_t size;
    struct futfs_extent *extents;
    size_t extent_count;
    size_t extent_capacity;
};

struct futfs_handle {
    futfs_t *fs;
    uint64_t ino;
    uint32_t rights;
};

struct futfs_context {
    int fd;
    char *path;
    struct futfs_superblock_disk super;
    uint64_t seqno;
    uint64_t log_tail;
    uint32_t block_size;
    uint64_t next_ino;
    struct futfs_inode_entry *inodes;
    size_t inode_count;
    size_t inode_capacity;
};

static size_t futfs_align8(size_t value) {
    return (value + 7u) & ~((size_t)7u);
}

static int futfs_pwrite_all(int fd, const void *buf, size_t len, off_t offset) {
    const uint8_t *cursor = (const uint8_t *)buf;
    size_t written = 0;
    while (written < len) {
        ssize_t rc = pwrite(fd, cursor + written, len - written, offset + (off_t)written);
        if (rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -errno;
        }
        written += (size_t)rc;
    }
    return 0;
}

static int futfs_pread_all(int fd, void *buf, size_t len, off_t offset) {
    uint8_t *cursor = (uint8_t *)buf;
    size_t read_bytes = 0;
    while (read_bytes < len) {
        ssize_t rc = pread(fd, cursor + read_bytes, len - read_bytes, offset + (off_t)read_bytes);
        if (rc == 0) {
            return -EIO;
        }
        if (rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -errno;
        }
        read_bytes += (size_t)rc;
    }
    return 0;
}

static int futfs_sync_super(futfs_t *fs) {
    return futfs_pwrite_all(fs->fd, &fs->super, sizeof(fs->super), 0);
}

static struct futfs_inode_entry *futfs_lookup_inode(futfs_t *fs, uint64_t ino) {
    for (size_t i = 0; i < fs->inode_count; ++i) {
        if (fs->inodes[i].ino == ino) {
            return &fs->inodes[i];
        }
    }
    return NULL;
}

static int futfs_reserve_inode_slot(futfs_t *fs, struct futfs_inode_entry **out_entry) {
    if (fs->inode_count == fs->inode_capacity) {
        size_t new_cap = fs->inode_capacity ? fs->inode_capacity * 2 : 8;
        struct futfs_inode_entry *resized = realloc(fs->inodes, new_cap * sizeof(*resized));
        if (!resized) {
            return -ENOMEM;
        }
        fs->inodes = resized;
        fs->inode_capacity = new_cap;
    }
    struct futfs_inode_entry *entry = &fs->inodes[fs->inode_count++];
    memset(entry, 0, sizeof(*entry));
    *out_entry = entry;
    return 0;
}

static int futfs_append_record(futfs_t *fs,
                               uint16_t type,
                               const void *payload,
                               uint32_t payload_len,
                               uint64_t *record_offset_out) {
    struct futfs_segment_header hdr = {
        .magic = FUTFS_SEG_MAGIC,
        .type = type,
        .reserved = 0,
        .payload_len = payload_len,
        .seqno = fs->seqno++,
    };

    uint64_t record_offset = fs->log_tail;
    size_t aligned_payload = futfs_align8(payload_len);
    size_t total_len = sizeof(hdr) + aligned_payload;

    int rc = futfs_pwrite_all(fs->fd, &hdr, sizeof(hdr), (off_t)fs->log_tail);
    if (rc != 0) {
        return rc;
    }
    rc = futfs_pwrite_all(fs->fd, payload, payload_len, (off_t)(fs->log_tail + sizeof(hdr)));
    if (rc != 0) {
        return rc;
    }
    if (aligned_payload != payload_len) {
        uint8_t padding[8] = {0};
        rc = futfs_pwrite_all(fs->fd,
                              padding,
                              aligned_payload - payload_len,
                              (off_t)(fs->log_tail + sizeof(hdr) + payload_len));
        if (rc != 0) {
            return rc;
        }
    }

    fs->log_tail += total_len;
    fs->super.log_tail = fs->log_tail;
    if (fsync(fs->fd) != 0) {
        return -errno;
    }
    rc = futfs_sync_super(fs);
    if (rc != 0) {
        return rc;
    }
    if (fsync(fs->fd) != 0) {
        return -errno;
    }

    if (record_offset_out) {
        *record_offset_out = record_offset;
    }
    return 0;
}

static int futfs_process_create(futfs_t *fs,
                                const struct futfs_rec_create_disk *rec) {
    struct futfs_inode_entry *existing = futfs_lookup_inode(fs, rec->ino);
    if (!existing) {
        struct futfs_inode_entry *entry = NULL;
        int rc = futfs_reserve_inode_slot(fs, &entry);
        if (rc != 0) {
            return rc;
        }
        entry->ino = rec->ino;
        existing = entry;
    }

    existing->parent = rec->parent;
    existing->policy_rights = rec->policy_rights;
    existing->size = 0;
    existing->extent_count = 0;
    if (existing->extents) {
        free(existing->extents);
        existing->extents = NULL;
        existing->extent_capacity = 0;
    }

    size_t name_len = rec->name_len > FUTFS_MAX_NAME ? FUTFS_MAX_NAME : rec->name_len;
    memcpy(existing->name, rec->name, name_len);
    existing->name[name_len] = '\0';

    if (rec->ino >= fs->next_ino) {
        fs->next_ino = rec->ino + 1;
        fs->super.next_ino = fs->next_ino;
    }
    return 0;
}

static int futfs_add_extent(struct futfs_inode_entry *entry,
                            uint64_t file_offset,
                            uint32_t length,
                            uint64_t log_data_offset) {
    if (entry->extent_count == entry->extent_capacity) {
        size_t new_cap = entry->extent_capacity ? entry->extent_capacity * 2 : 4;
        struct futfs_extent *resized = realloc(entry->extents, new_cap * sizeof(*resized));
        if (!resized) {
            return -ENOMEM;
        }
        entry->extents = resized;
        entry->extent_capacity = new_cap;
    }
    struct futfs_extent *ext = &entry->extents[entry->extent_count++];
    ext->file_offset = file_offset;
    ext->length = length;
    ext->log_data_offset = log_data_offset;
    return 0;
}

static int futfs_process_write(futfs_t *fs,
                               uint64_t record_offset,
                               const struct futfs_rec_write_disk *rec) {
    struct futfs_inode_entry *entry = futfs_lookup_inode(fs, rec->ino);
    if (!entry) {
        return -ENOENT;
    }
    uint64_t data_offset = record_offset + sizeof(struct futfs_segment_header)
                         + sizeof(struct futfs_rec_write_disk);
    int rc = futfs_add_extent(entry, rec->offset, rec->length, data_offset);
    if (rc != 0) {
        return rc;
    }
    uint64_t end = rec->offset + rec->length;
    if (end > entry->size) {
        entry->size = end;
    }
    return 0;
}

static int futfs_process_rename(futfs_t *fs, const struct futfs_rec_rename_disk *rec) {
    struct futfs_inode_entry *entry = futfs_lookup_inode(fs, rec->ino);
    if (!entry) {
        return -ENOENT;
    }
    entry->parent = rec->parent;
    size_t name_len = rec->name_len > FUTFS_MAX_NAME ? FUTFS_MAX_NAME : rec->name_len;
    memcpy(entry->name, rec->name, name_len);
    entry->name[name_len] = '\0';
    return 0;
}

static int futfs_scan_log(futfs_t *fs) {
    struct stat st;
    if (fstat(fs->fd, &st) != 0) {
        return -errno;
    }
    if (st.st_size < 0) {
        return -EIO;
    }
    uint64_t file_size = (uint64_t)st.st_size;
    uint64_t offset = fs->super.log_begin;
    uint64_t last_seq = 0;

    while (offset + sizeof(struct futfs_segment_header) <= file_size) {
        struct futfs_segment_header hdr;
        int rc = futfs_pread_all(fs->fd, &hdr, sizeof(hdr), (off_t)offset);
        if (rc != 0) {
            return rc;
        }
        if (hdr.magic != FUTFS_SEG_MAGIC) {
            break;
        }
        if (hdr.payload_len == 0) {
            break;
        }
        size_t aligned = futfs_align8(hdr.payload_len);
        if (offset + sizeof(hdr) + aligned > file_size) {
            break;
        }

        uint8_t *payload = malloc(hdr.payload_len);
        if (!payload) {
            return -ENOMEM;
        }
        rc = futfs_pread_all(fs->fd, payload, hdr.payload_len, (off_t)(offset + sizeof(hdr)));
        if (rc != 0) {
            free(payload);
            return rc;
        }

        switch (hdr.type) {
        case FUTFS_REC_CREATE:
            rc = futfs_process_create(fs, (const struct futfs_rec_create_disk *)payload);
            break;
        case FUTFS_REC_WRITE:
            rc = futfs_process_write(fs,
                                     offset,
                                     (const struct futfs_rec_write_disk *)payload);
            break;
        case FUTFS_REC_RENAME:
            rc = futfs_process_rename(fs, (const struct futfs_rec_rename_disk *)payload);
            break;
        default:
            rc = -EINVAL;
            break;
        }
        free(payload);
        if (rc != 0) {
            return rc;
        }

        last_seq = hdr.seqno;
        offset += sizeof(hdr) + aligned;
    }

    fs->log_tail = offset;
    fs->seqno = last_seq + 1;
    return 0;
}

static int futfs_format_internal(int fd,
                                 struct futfs_superblock_disk *super,
                                 uint64_t *seqno) {
    int rc = futfs_pwrite_all(fd, super, sizeof(*super), 0);
    if (rc != 0) {
        return rc;
    }
    fsync(fd);

    const char root_name[] = "/";
    struct futfs_rec_create_disk root_rec = {
        .ino = FUTFS_ROOT_INO,
        .parent = 0,
        .policy_rights = FUTFS_RIGHT_READ | FUTFS_RIGHT_WRITE | FUTFS_RIGHT_ADMIN,
        .name_len = (uint16_t)(sizeof(root_name) - 1),
        .reserved = 0,
    };

    size_t payload_len = sizeof(root_rec) + root_rec.name_len;
    uint8_t *payload = malloc(payload_len);
    if (!payload) {
        return -ENOMEM;
    }
    memcpy(payload, &root_rec, sizeof(root_rec));
    memcpy(payload + sizeof(root_rec), root_name, root_rec.name_len);

    struct futfs_segment_header hdr = {
        .magic = FUTFS_SEG_MAGIC,
        .type = FUTFS_REC_CREATE,
        .reserved = 0,
        .payload_len = payload_len,
        .seqno = (*seqno)++,
    };

    int rc_write = futfs_pwrite_all(fd, &hdr, sizeof(hdr), (off_t)super->log_begin);
    if (rc_write == 0) {
        rc_write = futfs_pwrite_all(fd,
                                    payload,
                                    payload_len,
                                    (off_t)(super->log_begin + sizeof(hdr)));
    }
    free(payload);
    if (rc_write != 0) {
        return rc_write;
    }

    size_t aligned = futfs_align8(payload_len);
    if (aligned != payload_len) {
        uint8_t padding[8] = {0};
        rc_write = futfs_pwrite_all(fd,
                                    padding,
                                    aligned - payload_len,
                                    (off_t)(super->log_begin + sizeof(hdr) + payload_len));
        if (rc_write != 0) {
            return rc_write;
        }
    }

    super->log_tail = super->log_begin + sizeof(hdr) + aligned;
    super->next_ino = FUTFS_ROOT_INO + 1;
    super->root_ino = FUTFS_ROOT_INO;
    rc_write = futfs_pwrite_all(fd, super, sizeof(*super), 0);
    if (rc_write != 0) {
        return rc_write;
    }
    fsync(fd);
    return 0;
}

int futfs_format_path(const char *path, size_t initial_size_bytes, uint32_t block_size) {
    if (block_size == 0) {
        block_size = FUTFS_DEFAULT_BLOCK;
    }

    int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        return -errno;
    }

    if (initial_size_bytes > 0) {
        if (ftruncate(fd, (off_t)initial_size_bytes) != 0) {
            int err = -errno;
            close(fd);
            return err;
        }
    }

    struct futfs_superblock_disk super = {0};
    memcpy(super.magic, FUTFS_SUPER_MAGIC, sizeof(super.magic));
    super.version = FUTFS_VERSION;
    super.block_size = block_size;
    super.log_begin = block_size;
    super.log_tail = super.log_begin;
    super.next_ino = FUTFS_ROOT_INO + 1;
    super.root_ino = FUTFS_ROOT_INO;

    uint64_t seqno = 1;
    int rc = futfs_format_internal(fd, &super, &seqno);
    int saved = errno;
    close(fd);
    errno = saved;
    return rc;
}

int futfs_mount_path(const char *path, futfs_t **out_fs) {
    if (!path || !out_fs) {
        return -EINVAL;
    }

    int fd = open(path, O_RDWR);
    if (fd < 0) {
        return -errno;
    }

    struct futfs_superblock_disk super = {0};
    int rc = futfs_pread_all(fd, &super, sizeof(super), 0);
    if (rc != 0) {
        int saved = errno;
        close(fd);
        errno = saved;
        return rc;
    }

    if (memcmp(super.magic, FUTFS_SUPER_MAGIC, sizeof(super.magic)) != 0) {
        close(fd);
        return -EINVAL;
    }

    futfs_t *fs = calloc(1, sizeof(*fs));
    if (!fs) {
        close(fd);
        return -ENOMEM;
    }

    fs->fd = fd;
    fs->path = strdup(path);
    if (!fs->path) {
        int err = -ENOMEM;
        futfs_unmount(fs);
        return err;
    }
    fs->super = super;
    fs->block_size = super.block_size ? super.block_size : FUTFS_DEFAULT_BLOCK;
    fs->log_tail = super.log_tail;
    fs->next_ino = super.next_ino ? super.next_ino : (FUTFS_ROOT_INO + 1);
    fs->seqno = 1;

    rc = futfs_scan_log(fs);
    if (rc != 0) {
        futfs_unmount(fs);
        return rc;
    }

    *out_fs = fs;
    return 0;
}

void futfs_unmount(futfs_t *fs) {
    if (!fs) {
        return;
    }
    if (fs->inodes) {
        for (size_t i = 0; i < fs->inode_count; ++i) {
            free(fs->inodes[i].extents);
        }
        free(fs->inodes);
    }
    if (fs->fd >= 0) {
        fsync(fs->fd);
        close(fs->fd);
    }
    free(fs->path);
    free(fs);
}

uint64_t futfs_root_ino(const futfs_t *fs) {
    (void)fs;
    return FUTFS_ROOT_INO;
}

static int futfs_validate_parent(futfs_t *fs, uint64_t parent) {
    if (parent == 0) {
        parent = FUTFS_ROOT_INO;
    }
    struct futfs_inode_entry *p = futfs_lookup_inode(fs, parent);
    return p ? 0 : -ENOENT;
}

int futfs_create(futfs_t *fs,
                 uint64_t parent_ino,
                 const char *name,
                 uint32_t policy_rights,
                 uint32_t requested_rights,
                 futfs_handle_t **out_handle) {
    if (!fs || !name || !out_handle) {
        return -EINVAL;
    }
    size_t name_len = strlen(name);
    if (name_len == 0 || name_len > FUTFS_MAX_NAME) {
        return -EINVAL;
    }
    if (requested_rights & ~policy_rights) {
        return -EACCES;
    }

    if (parent_ino == 0) {
        parent_ino = FUTFS_ROOT_INO;
    }
    int rc = futfs_validate_parent(fs, parent_ino);
    if (rc != 0) {
        return rc;
    }

    uint64_t ino = fs->next_ino++;
    fs->super.next_ino = fs->next_ino;
    futfs_sync_super(fs);

    size_t payload_len = sizeof(struct futfs_rec_create_disk) + name_len;
    uint8_t *payload = malloc(payload_len);
    if (!payload) {
        return -ENOMEM;
    }
    struct futfs_rec_create_disk *rec = (struct futfs_rec_create_disk *)payload;
    rec->ino = ino;
    rec->parent = parent_ino;
    rec->policy_rights = policy_rights;
    rec->name_len = (uint16_t)name_len;
    rec->reserved = 0;
    memcpy(rec->name, name, name_len);

    rc = futfs_append_record(fs, FUTFS_REC_CREATE, payload, payload_len, NULL);
    free(payload);
    if (rc != 0) {
        return rc;
    }

    struct futfs_inode_entry *entry = NULL;
    rc = futfs_reserve_inode_slot(fs, &entry);
    if (rc != 0) {
        return rc;
    }
    entry->ino = ino;
    entry->parent = parent_ino;
    entry->policy_rights = policy_rights;
    entry->size = 0;
    entry->extents = NULL;
    entry->extent_count = 0;
    entry->extent_capacity = 0;
    size_t copy_len = name_len > FUTFS_MAX_NAME ? FUTFS_MAX_NAME : name_len;
    memcpy(entry->name, name, copy_len);
    entry->name[copy_len] = '\0';

    futfs_handle_t *handle = calloc(1, sizeof(*handle));
    if (!handle) {
        return -ENOMEM;
    }
    handle->fs = fs;
    handle->ino = ino;
    handle->rights = requested_rights;
    *out_handle = handle;
    return 0;
}

int futfs_open(futfs_t *fs,
               uint64_t ino,
               uint32_t requested_rights,
               futfs_handle_t **out_handle) {
    if (!fs || !out_handle) {
        return -EINVAL;
    }
    struct futfs_inode_entry *entry = futfs_lookup_inode(fs, ino);
    if (!entry) {
        return -ENOENT;
    }
    if ((requested_rights & entry->policy_rights) != requested_rights) {
        return -EACCES;
    }
    futfs_handle_t *handle = calloc(1, sizeof(*handle));
    if (!handle) {
        return -ENOMEM;
    }
    handle->fs = fs;
    handle->ino = ino;
    handle->rights = requested_rights;
    *out_handle = handle;
    return 0;
}

void futfs_handle_close(futfs_handle_t *handle) {
    free(handle);
}

uint64_t futfs_handle_ino(const futfs_handle_t *handle) {
    return handle ? handle->ino : 0;
}

uint32_t futfs_handle_rights(const futfs_handle_t *handle) {
    return handle ? handle->rights : 0;
}

int futfs_write(futfs_handle_t *handle, const void *data, size_t len) {
    if (!handle || !data || len == 0) {
        return -EINVAL;
    }
    if ((handle->rights & FUTFS_RIGHT_WRITE) == 0) {
        return -EACCES;
    }
    futfs_t *fs = handle->fs;
    struct futfs_inode_entry *entry = futfs_lookup_inode(fs, handle->ino);
    if (!entry) {
        return -ENOENT;
    }
    if (len > UINT32_MAX) {
        return -EFBIG;
    }

    uint64_t offset = entry->size;

    size_t payload_len = sizeof(struct futfs_rec_write_disk) + len;
    uint8_t *payload = malloc(payload_len);
    if (!payload) {
        return -ENOMEM;
    }
    struct futfs_rec_write_disk *rec = (struct futfs_rec_write_disk *)payload;
    rec->ino = entry->ino;
    rec->offset = offset;
    rec->length = (uint32_t)len;
    rec->reserved = 0;
    memcpy(rec->data, data, len);

    uint64_t record_offset = 0;
    int rc = futfs_append_record(fs, FUTFS_REC_WRITE, payload, payload_len, &record_offset);
    free(payload);
    if (rc != 0) {
        return rc;
    }

    uint64_t data_offset = record_offset + sizeof(struct futfs_segment_header)
                         + sizeof(struct futfs_rec_write_disk);
    rc = futfs_add_extent(entry, offset, (uint32_t)len, data_offset);
    if (rc != 0) {
        return rc;
    }
    entry->size += len;
    return 0;
}

int futfs_read_all(futfs_handle_t *handle, uint8_t **out_data, size_t *out_len) {
    if (!handle || !out_data || !out_len) {
        return -EINVAL;
    }
    if ((handle->rights & FUTFS_RIGHT_READ) == 0) {
        return -EACCES;
    }
    futfs_t *fs = handle->fs;
    struct futfs_inode_entry *entry = futfs_lookup_inode(fs, handle->ino);
    if (!entry) {
        return -ENOENT;
    }
    uint8_t *buffer = NULL;
    if (entry->size > 0) {
        buffer = malloc(entry->size);
        if (!buffer) {
            return -ENOMEM;
        }
        for (size_t i = 0; i < entry->extent_count; ++i) {
            struct futfs_extent *ext = &entry->extents[i];
            int rc = futfs_pread_all(fs->fd,
                                     buffer + ext->file_offset,
                                     ext->length,
                                     (off_t)ext->log_data_offset);
            if (rc != 0) {
                free(buffer);
                return rc;
            }
        }
    }
    *out_data = buffer;
    *out_len = entry->size;
    return 0;
}

int futfs_rename(futfs_handle_t *handle, uint64_t new_parent_ino, const char *new_name) {
    if (!handle || !new_name) {
        return -EINVAL;
    }
    if ((handle->rights & FUTFS_RIGHT_ADMIN) == 0) {
        return -EACCES;
    }
    futfs_t *fs = handle->fs;
    struct futfs_inode_entry *entry = futfs_lookup_inode(fs, handle->ino);
    if (!entry) {
        return -ENOENT;
    }
    if (new_parent_ino == 0) {
        new_parent_ino = FUTFS_ROOT_INO;
    }
    int rc = futfs_validate_parent(fs, new_parent_ino);
    if (rc != 0) {
        return rc;
    }
    size_t name_len = strlen(new_name);
    if (name_len == 0 || name_len > FUTFS_MAX_NAME) {
        return -EINVAL;
    }

    size_t payload_len = sizeof(struct futfs_rec_rename_disk) + name_len;
    uint8_t *payload = malloc(payload_len);
    if (!payload) {
        return -ENOMEM;
    }
    struct futfs_rec_rename_disk *rec = (struct futfs_rec_rename_disk *)payload;
    rec->ino = entry->ino;
    rec->parent = new_parent_ino;
    rec->name_len = (uint16_t)name_len;
    rec->reserved = 0;
    memcpy(rec->name, new_name, name_len);

    rc = futfs_append_record(fs, FUTFS_REC_RENAME, payload, payload_len, NULL);
    free(payload);
    if (rc != 0) {
        return rc;
    }

    entry->parent = new_parent_ino;
    size_t copy_len = name_len > FUTFS_MAX_NAME ? FUTFS_MAX_NAME : name_len;
    memcpy(entry->name, new_name, copy_len);
    entry->name[copy_len] = '\0';
    return 0;
}
