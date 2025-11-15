// SPDX-License-Identifier: MPL-2.0
/*
 * futfs_gc.c - Directory compaction and tombstone accounting for FuturaFS
 */

#include "futfs_internal.h"

#include <kernel/fut_memory.h>
#include <platform/platform.h>
#include <string.h>

static bool g_futfs_crash_compaction = false;

void futfs_gc_set_crash_injection(bool enable) {
    g_futfs_crash_compaction = enable;
}

bool futfs_gc_crash_enabled(void) {
    return g_futfs_crash_compaction;
}

uint64_t futfs_gc_count_tombstones(const struct futfs_inode_mem *dir) {
    if (!dir || !dir->data || dir->size == 0) {
        return 0;
    }

    uint64_t tombstones = 0;
    size_t offset = 0;

    while (offset + sizeof(futfs_dirent_disk_t) <= dir->size) {
        const futfs_dirent_disk_t *entry =
            (const futfs_dirent_disk_t *)(dir->data + offset);
        size_t entry_bytes = sizeof(futfs_dirent_disk_t) + entry->name_len;
        size_t padded = futfs_align8(entry_bytes);
        if (offset + padded > dir->size) {
            break;
        }

        if (entry->ino == 0 && entry->name_len != 0) {
            tombstones++;
        }

        offset += padded;
    }

    return tombstones;
}

struct futfs_gc_entry {
    char name[FUTFS_NAME_MAX + 1];
    uint16_t name_len;
    uint64_t ino;
    size_t order;
    bool seen;
};

static struct futfs_gc_entry *gc_entry_find(struct futfs_gc_entry *entries,
                                            size_t count,
                                            const futfs_dirent_disk_t *disk) {
    for (size_t i = 0; i < count; ++i) {
        if (entries[i].name_len == disk->name_len &&
            memcmp(entries[i].name, disk->name, disk->name_len) == 0) {
            return &entries[i];
        }
    }
    return NULL;
}

static void gc_entry_sort(struct futfs_gc_entry *entries, size_t count) {
    if (count < 2) {
        return;
    }
    for (size_t i = 1; i < count; ++i) {
        struct futfs_gc_entry key = entries[i];
        size_t j = i;
        while (j > 0 && entries[j - 1].order > key.order) {
            entries[j] = entries[j - 1];
            --j;
        }
        entries[j] = key;
    }
}

fut_status_t futfs_gc_compact_dir(struct futfs_inode_mem *dir,
                                  struct futfs_gc_stats *stats,
                                  bool crash_before_commit) {
    if (stats) {
        memset(stats, 0, sizeof(*stats));
    }

    if (!dir) {
        return -EINVAL;
    }

    if (!dir->data || dir->size == 0) {
        return 0;
    }

    uint64_t tombstones_before = futfs_gc_count_tombstones(dir);
    if (stats) {
        stats->tombstones_before = tombstones_before;
        stats->bytes_before = dir->size;
    }

    size_t capacity = 8;
    size_t count = 0;
    struct futfs_gc_entry *entries =
        fut_malloc(sizeof(struct futfs_gc_entry) * capacity);
    if (!entries) {
        return -ENOMEM;
    }
    memset(entries, 0, sizeof(struct futfs_gc_entry) * capacity);

    size_t offset = 0;
    size_t order = 0;

    while (offset + sizeof(futfs_dirent_disk_t) <= dir->size) {
        const futfs_dirent_disk_t *entry =
            (const futfs_dirent_disk_t *)(dir->data + offset);
        size_t entry_bytes = sizeof(futfs_dirent_disk_t) + entry->name_len;
        size_t padded = futfs_align8(entry_bytes);
        if (offset + padded > dir->size) {
            break;
        }

        if (entry->name_len > 0 && entry->name_len <= FUTFS_NAME_MAX) {
            struct futfs_gc_entry *slot = gc_entry_find(entries, count, entry);
            if (!slot) {
                if (count == capacity) {
                    size_t new_cap = capacity * 2u;
                    struct futfs_gc_entry *resized =
                        fut_realloc(entries, new_cap * sizeof(*entries));
                    if (!resized) {
                        fut_free(entries);
                        return -ENOMEM;
                    }
                    entries = resized;
                    memset(entries + capacity, 0,
                           (new_cap - capacity) * sizeof(*entries));
                    capacity = new_cap;
                }
                slot = &entries[count++];
                memcpy(slot->name, entry->name, entry->name_len);
                slot->name[entry->name_len] = '\0';
                slot->name_len = entry->name_len;
                slot->order = order++;
                slot->seen = true;
            }
            slot->ino = entry->ino;
            slot->seen = true;
        }

        offset += padded;
    }

    /* Sort entries by first-seen order to keep traversal deterministic. */
    gc_entry_sort(entries, count);

    /* Calculate size required for compacted stream */
    size_t new_bytes = 0;
    size_t live_entries = 0;
    for (size_t i = 0; i < count; ++i) {
        const struct futfs_gc_entry *e = &entries[i];
        if (!e->seen || e->ino == 0 || e->name_len == 0) {
            continue;
        }

        if ((e->name_len == 1 && e->name[0] == '.') ||
            (e->name_len == 2 && e->name[0] == '.' && e->name[1] == '.')) {
            continue;
        }

        size_t entry_bytes = sizeof(futfs_dirent_disk_t) + e->name_len;
        new_bytes += futfs_align8(entry_bytes);
        live_entries++;
    }

    uint8_t *new_stream = NULL;
    if (new_bytes > 0) {
        new_stream = fut_malloc(new_bytes);
        if (!new_stream) {
            fut_free(entries);
            return -ENOMEM;
        }
        memset(new_stream, 0, new_bytes);
    }

    size_t write_offset = 0;
    for (size_t i = 0; i < count; ++i) {
        const struct futfs_gc_entry *e = &entries[i];
        if (!e->seen || e->ino == 0 || e->name_len == 0) {
            continue;
        }
        if ((e->name_len == 1 && e->name[0] == '.') ||
            (e->name_len == 2 && e->name[0] == '.' && e->name[1] == '.')) {
            continue;
        }
        futfs_dirent_disk_t *disk =
            (futfs_dirent_disk_t *)(new_stream + write_offset);
        disk->ino = e->ino;
        disk->name_len = e->name_len;
        disk->reserved = 0;
        memcpy(disk->name, e->name, e->name_len);

        size_t entry_bytes = sizeof(futfs_dirent_disk_t) + e->name_len;
        size_t padded = futfs_align8(entry_bytes);
        if (padded > entry_bytes) {
            memset((uint8_t *)disk + entry_bytes, 0, padded - entry_bytes);
        }
        write_offset += padded;
    }

    if (g_futfs_crash_compaction && crash_before_commit) {
        fut_platform_panic("[futfs] crash injection: compaction before commit");
    }

    uint8_t *old_data = dir->data;

    if (new_bytes == 0) {
        dir->data = NULL;
        dir->size = 0;
        dir->capacity = 0;
        if (new_stream) {
            fut_free(new_stream);
        }
    } else {
        dir->data = new_stream;
        dir->size = new_bytes;
        dir->capacity = new_bytes;
    }

    if (old_data) {
        fut_free(old_data);
    }

    g_fs.dirty = true;

    if (stats) {
        stats->bytes_after = dir->size;
        stats->tombstones_after = futfs_gc_count_tombstones(dir);
    }

    fut_free(entries);
    return 0;
}
