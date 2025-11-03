/* ramfs.c - RAM Filesystem Implementation
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Simple in-memory filesystem for testing VFS layer.
 * Files and directories stored in dynamically allocated memory.
 */

#include <kernel/fut_vfs.h>
#include <kernel/fut_memory.h>
#include <kernel/fut_timer.h>
#include <kernel/fut_lock.h>
#include <stddef.h>
#include <string.h>

/* ============================================================
 *   RamFS Structures
 * ============================================================ */

/* Directory entry linking file names to vnodes */
struct ramfs_dirent {
    char name[64];                  /* File/directory name */
    struct fut_vnode *vnode;        /* Associated vnode */
    struct ramfs_dirent *next;      /* Next entry in directory */
};

/* Per-vnode filesystem data */
struct ramfs_node {
    uint64_t magic_guard_before;    /* Guard value to detect overflow into structure */
    uint32_t open_count;            /* Reference count: number of open file descriptors */
    union {
        /* For regular files: data buffer */
        struct {
            uint8_t *data;          /* File data */
            size_t capacity;        /* Allocated size */
        } file;

        /* For directories: list of entries */
        struct {
            struct ramfs_dirent *entries;
        } dir;
    };
    uint64_t magic_guard_after;     /* Guard value to detect overflow after structure */
};

#define RAMFS_NODE_MAGIC 0xDEADC0DEDEADBEEFULL

#define RAMFS_ROOT_CANARY_BEFORE 0xFADC0DE0CAFEBABEULL
#define RAMFS_ROOT_CANARY_AFTER  0xDEADBEEFCAFED00DULL

struct ramfs_root_guard {
    uint64_t before;
    struct fut_vnode vnode;
    uint64_t after;
};

/* ============================================================
 *   String Utilities
 * ============================================================ */

static int str_cmp(const char *a, const char *b) {
    while (*a && *b && *a == *b) {
        a++;
        b++;
    }
    return *a - *b;
}

/* Log complete state of a ramfs_node for debugging */
static void log_ramfs_node_state(const char *context, struct ramfs_node *node, struct fut_vnode *vnode) {
    extern void fut_printf(const char *, ...);

    if (!node) {
        fut_printf("[RAMFS-STATE] %s: node is NULL\n", context);
        return;
    }

    fut_printf("[RAMFS-STATE] %s:\n", context);
    fut_printf("[RAMFS-STATE]   node=%p guard_before=0x%llx guard_after=0x%llx\n",
               (void*)node, (unsigned long long)node->magic_guard_before,
               (unsigned long long)node->magic_guard_after);

    if (vnode && vnode->type == VN_REG) {
        fut_printf("[RAMFS-STATE]   file.data=%p file.capacity=%llu\n",
                   (void*)node->file.data, (unsigned long long)node->file.capacity);
    }
}

/* Validate that ramfs_node guards haven't been corrupted */
static int validate_ramfs_node(struct ramfs_node *node) {
    extern void fut_printf(const char *, ...);

    if (!node) {
        return 0;  /* NULL is OK, caller checks this */
    }

    if (node->magic_guard_before != RAMFS_NODE_MAGIC) {
        fut_printf("[RAMFS-GUARD] ERROR: guard_before corrupted! Expected 0x%llx, got 0x%llx\n",
                   (unsigned long long)RAMFS_NODE_MAGIC, (unsigned long long)node->magic_guard_before);
        return -1;
    }

    if (node->magic_guard_after != RAMFS_NODE_MAGIC) {
        fut_printf("[RAMFS-GUARD] ERROR: guard_after corrupted! Expected 0x%llx, got 0x%llx\n",
                   (unsigned long long)RAMFS_NODE_MAGIC, (unsigned long long)node->magic_guard_after);
        return -1;
    }

    return 0;
}

static void str_copy_safe(char *dest, const char *src, size_t max_len) {
    size_t i = 0;
    while (i < max_len - 1 && src[i]) {
        dest[i] = src[i];
        i++;
    }
    dest[i] = '\0';
}

/* ============================================================
 *   VNode Operations
 * ============================================================ */

static int ramfs_open(struct fut_vnode *vnode, int flags) {
    (void)flags;

    if (!vnode) {
        return -EINVAL;
    }

    struct ramfs_node *node = (struct ramfs_node *)vnode->fs_data;
    if (!node) {
        return -EIO;
    }

    /* Increment open reference count */
    node->open_count++;
    return 0;
}

static int ramfs_close(struct fut_vnode *vnode) {
    extern void fut_printf(const char *, ...);

    if (!vnode) {
        return 0;
    }

    struct ramfs_node *node = (struct ramfs_node *)vnode->fs_data;
    if (!node) {
        return 0;
    }

    /* Decrement open reference count for tracking */
    if (node->open_count > 0) {
        node->open_count--;
    }

    /* RAMFS file buffers are NEVER freed after open.
     * This is intentional - RAMFS is a boot-time filesystem for staging binaries.
     * File data persists for the lifetime of the system.
     * Reasons:
     * 1. Files can be opened and closed multiple times (write, then read for exec)
     * 2. Each open/close pair is independent and shouldn't affect other accesses
     * 3. RAMFS files are typically small (binaries, configs)
     * 4. Keeping them persistent simplifies lifecycle management
     *
     * The open_count tracking is maintained for diagnostics only.
     */
    return 0;
}

static ssize_t ramfs_read(struct fut_vnode *vnode, void *buf, size_t size, uint64_t offset) {
    extern void fut_printf(const char *, ...);

    if (!vnode || !buf) {
        return -EINVAL;
    }

    if (vnode->type != VN_REG) {
        return -EINVAL;  /* Can only read regular files */
    }

    struct ramfs_node *node = (struct ramfs_node *)vnode->fs_data;
    if (!node) {
        return -EIO;
    }

    /* Log complete state at start of read */
    if (offset == 0) {
        log_ramfs_node_state("ramfs_read START (offset=0)", node, vnode);
    }

    /* Debug: log read operation for wayland binary */
    if (offset == 0 && size >= 64) {
        fut_printf("[RAMFS-READ] Reading from start: vnode=%p vnode->size=%llu\n",
                   (void*)vnode, (unsigned long long)vnode->size);
        fut_printf("[RAMFS-READ] vnode->fs_data=%p node->file.data=%p node->file.capacity=%llu\n",
                   (void*)vnode->fs_data, (void*)node->file.data, (unsigned long long)node->file.capacity);
    }

    /* Check offset - ensure it doesn't exceed file size */
    if (offset >= vnode->size) {
        fut_printf("[RAMFS-READ] EOF: offset=%llu >= size=%llu\n",
                   (unsigned long long)offset, (unsigned long long)vnode->size);
        return 0;  /* EOF */
    }

    /* Calculate bytes to read - safe since offset < vnode->size */
    uint64_t remaining = vnode->size - offset;
    /* Cap to SIZE_MAX to avoid overflow in pointer arithmetic */
    size_t to_read = (size < remaining) ? size : (size_t)remaining;

    /* Manual copy to avoid SSE/AVX instructions in memcpy */
    uint8_t *dest = (uint8_t *)buf;
    const uint8_t *src = node->file.data + (size_t)offset;

    /* Debug: check first bytes for ELF magic */
    if (offset == 0 && to_read >= 4) {
        uint32_t *magic = (uint32_t *)src;
        fut_printf("[RAMFS-READ] First 4 bytes at %p: 0x%08x\n", (void*)src, *magic);
    }

    for (size_t i = 0; i < to_read; i++) {
        dest[i] = src[i];
    }

    return (ssize_t)to_read;
}

static ssize_t ramfs_write(struct fut_vnode *vnode, const void *buf, size_t size, uint64_t offset) {
    extern void fut_printf(const char *, ...);

    if (!vnode || !buf) {
        return -EINVAL;
    }

    if (vnode->type != VN_REG) {
        return -EINVAL;  /* Can only write regular files */
    }

    struct ramfs_node *node = (struct ramfs_node *)vnode->fs_data;
    if (!node) {
        return -EIO;
    }

    /* Validate guards before writing - corruption detection */
    if (validate_ramfs_node(node) != 0) {
        fut_printf("[RAMFS-WRITE] ABORTING: node guards corrupted before write!\n");
        return -EIO;
    }

    /* Check for integer overflow: offset + size */
    if (offset > SIZE_MAX - size) {
        return -ENOSPC;  /* File would be too large */
    }

    /* Calculate required capacity */
    size_t required = offset + size;

    /* Expand buffer if needed */
    if (required > node->file.capacity) {
        extern void fut_printf(const char *, ...);

        /* Allocation strategy optimized for buddy allocator efficiency:
         * Allocate in power-of-2 aligned chunks to minimize fragmentation.
         * The buddy allocator works best with sizes close to order boundaries.
         */
        size_t new_capacity;

        /* Round up to next power-of-2 to align with buddy allocator orders
         * This prevents fragmenting buddy blocks and enables better coalescing
         * CRITICAL: Check for overflow to prevent allocating buffer smaller than required
         */
        size_t power_of_2 = 1;
        while (power_of_2 < required && power_of_2 <= (SIZE_MAX / 2)) {
            power_of_2 <<= 1;
        }

        /* If power_of_2 overflowed or would overflow, use required directly with safety margin */
        if (power_of_2 < required || power_of_2 > (SIZE_MAX / 2)) {
            /* For very large files, allocate with 10% overhead to avoid repeated reallocations */
            if (required > (SIZE_MAX / 11)) {
                /* File too large - this should not happen in practice */
                return -ENOSPC;
            }
            new_capacity = required + (required / 10);
        } else if (power_of_2 > (1024 * 1024)) {
            /* For files larger than 1MB, use conservative 10% overhead instead */
            new_capacity = required + (required / 10);
        } else {
            new_capacity = power_of_2;
        }

        fut_printf("[RAMFS-REALLOC] Reallocating: required=%llu power_of_2=%llu new_capacity=%llu\n",
                   (unsigned long long)required, (unsigned long long)power_of_2, (unsigned long long)new_capacity);
        fut_printf("[RAMFS-REALLOC] Old buffer: data=%p capacity=%llu vnode->size=%llu\n",
                   (void*)node->file.data, (unsigned long long)node->file.capacity, (unsigned long long)vnode->size);

        uint8_t *new_data = fut_malloc(new_capacity);
        if (!new_data) {
            fut_printf("[RAMFS-REALLOC] FAILED to allocate %llu bytes\n", (unsigned long long)new_capacity);
            return -ENOMEM;
        }

        fut_printf("[RAMFS-REALLOC] New buffer allocated: %p\n", (void*)new_data);

        /* Copy old data - use 8-byte chunks to avoid SIMD instruction issues */
        if (node->file.data && vnode->size > 0) {
            size_t copy_size = vnode->size;
            fut_printf("[RAMFS-REALLOC] Copying %llu bytes from %p to %p\n",
                       (unsigned long long)copy_size, (void*)node->file.data, (void*)new_data);

            /* Copy in 8-byte chunks for efficiency without SIMD issues */
            uint64_t *src64 = (uint64_t *)node->file.data;
            uint64_t *dst64 = (uint64_t *)new_data;
            size_t qwords = copy_size / 8;
            for (size_t i = 0; i < qwords; i++) {
                dst64[i] = src64[i];
            }

            /* Copy remaining bytes (0-7) */
            uint8_t *src8 = (uint8_t *)(node->file.data + (qwords * 8));
            uint8_t *dst8 = (uint8_t *)(new_data + (qwords * 8));
            size_t remainder = copy_size % 8;
            for (size_t i = 0; i < remainder; i++) {
                dst8[i] = src8[i];
            }

            /* Verify first few bytes were copied correctly */
            if (copy_size >= 4) {
                uint32_t *old_magic = (uint32_t *)node->file.data;
                uint32_t *new_magic = (uint32_t *)new_data;
                fut_printf("[RAMFS-REALLOC] Verify copy: old[0]=0x%08x new[0]=0x%08x\n", *old_magic, *new_magic);
            }

            /* CRITICAL: Validate new_data before freeing old buffer
             * because coalescing in buddy_free might corrupt adjacent memory */
            uint8_t *old_data_ptr = node->file.data;

            /* Verify new buffer is valid before freeing old */
            if (!new_data || (uintptr_t)new_data < 0xFFFFFFFF80000000ULL) {
                fut_printf("[RAMFS-REALLOC] CRITICAL: New buffer allocation is invalid! %p\n", (void*)new_data);
                return -EIO;
            }

            fut_printf("[RAMFS-REALLOC] About to free old buffer: %p\n", (void*)old_data_ptr);
            fut_free(old_data_ptr);
            fut_printf("[RAMFS-REALLOC] Old buffer freed: %p\n", (void*)old_data_ptr);
        }

        node->file.data = new_data;
        node->file.capacity = new_capacity;

        /* Validate node structure after assignment */
        if (validate_ramfs_node(node) != 0) {
            fut_printf("[RAMFS-REALLOC] CRITICAL: Node corrupted after reallocation!\n");
            return -EIO;
        }

        fut_printf("[RAMFS-REALLOC] Reallocation complete: node->file.data=%p capacity=%llu\n",
                   (void*)node->file.data, (unsigned long long)node->file.capacity);
    }

    /* Write data - use manual copy to avoid SIMD instructions */
    extern void fut_printf(const char *, ...);

    const uint8_t *src = (const uint8_t *)buf;

    /* CRITICAL: Bounds check before writing
     * Prevent buffer overflows that could corrupt kernel memory */
    if ((size_t)offset + size > node->file.capacity) {
        fut_printf("[RAMFS-WRITE] ERROR: Write would exceed buffer! offset=%llu size=%llu capacity=%llu\n",
                   (unsigned long long)offset, (unsigned long long)size,
                   (unsigned long long)node->file.capacity);
        fut_printf("[RAMFS-WRITE] This should have been caught by reallocation logic!\n");
        fut_printf("[RAMFS-WRITE] vnode->size=%llu node->file.data=%p node=%p\n",
                   (unsigned long long)vnode->size, (void*)node->file.data, (void*)node);
        return -ENOSPC;  /* Should never happen - reallocation should have caught this */
    }

    /* Log write operation for offset 0 (first writes) or offsets > 500KB */
    if ((offset == 0 && size >= 4000) || offset > 500000) {
        fut_printf("[RAMFS-WRITE] Write: offset=%llu size=%llu buf=%p data=%p capacity=%llu\n",
                   (unsigned long long)offset, (unsigned long long)size, buf,
                   (void*)node->file.data, (unsigned long long)node->file.capacity);
        /* Check first 4 bytes being written */
        if (size >= 4) {
            uint32_t *magic = (uint32_t *)src;
            fut_printf("[RAMFS-WRITE] First 4 bytes from buf: 0x%08x\n", *magic);
        }
    }

    /* Detailed logging for every write */
    if (size == 4096 && offset == 0) {
        fut_printf("[RAMFS-WRITE-DETAIL] First 4096-byte write to offset %llu\n", (unsigned long long)offset);
        fut_printf("[RAMFS-WRITE-DETAIL] src=%p dst=%p node->file.data=%p\n",
                   buf, (void*)(node->file.data + offset), (void*)node->file.data);
        fut_printf("[RAMFS-WRITE-DETAIL] About to write first 4 bytes: %02x %02x %02x %02x\n",
                   src[0], src[1], src[2], src[3]);
    }

    for (size_t i = 0; i < size; i++) {
        node->file.data[(size_t)offset + i] = src[i];
    }

    /* Verify the first write */
    if (size == 4096 && offset == 0) {
        fut_printf("[RAMFS-WRITE-DETAIL] After write, first 4 bytes at %p: %02x %02x %02x %02x\n",
                   (void*)node->file.data,
                   node->file.data[0], node->file.data[1], node->file.data[2], node->file.data[3]);
    }

    if ((offset == 0 && size >= 4000) || offset > 500000) {
        /* Verify write succeeded by reading back first bytes */
        if (size >= 4) {
            uint32_t *written_magic = (uint32_t *)(node->file.data + offset);
            fut_printf("[RAMFS-WRITE] Write completed: wrote to %p first bytes: 0x%08x\n",
                       (void*)(node->file.data + offset), *written_magic);
        }
    }

    /* Update size - we already checked for overflow above */
    if (offset + size > vnode->size) {
        vnode->size = offset + size;
    }

    /* Validate guards after writing - catch overflow corruption immediately */
    if (validate_ramfs_node(node) != 0) {
        fut_printf("[RAMFS-WRITE] CRITICAL: write operation corrupted node guards!\n");
        fut_printf("[RAMFS-WRITE] This indicates a buffer overflow - wrote %llu bytes at offset %llu\n",
                   (unsigned long long)size, (unsigned long long)offset);
        fut_printf("[RAMFS-WRITE] File capacity: %llu, would write to end at: %llu\n",
                   (unsigned long long)node->file.capacity, (unsigned long long)(offset + size));
        return -EIO;
    }

    /* Log complete state at end of write for large writes */
    if (size > 10000 || offset > 200000) {
        log_ramfs_node_state("ramfs_write END (large write)", node, vnode);
    }

    return (ssize_t)size;
}

static int ramfs_lookup(struct fut_vnode *dir, const char *name, struct fut_vnode **result) {
    extern void fut_printf(const char *, ...);

    if (!dir || !name || !result) {
        return -EINVAL;
    }

    if (dir->type != VN_DIR) {
        return -ENOTDIR;
    }

    struct ramfs_node *node = (struct ramfs_node *)dir->fs_data;
    if (!node) {
        return -EIO;
    }

    /* Search directory entries with corruption detection */
    struct ramfs_dirent *entry = node->dir.entries;
    int safety_counter = 0;

    while (entry) {
        /* Detect circular or corrupted lists (max 100 entries per directory) */
        if (++safety_counter > 100) {
            fut_printf("[ramfs] ERROR: Directory entry list corruption detected (loop?)\n");
            return -EIO;
        }

        /* Validate entry pointer is in valid kernel memory range */
        if ((uintptr_t)entry < 0xFFFFFFFF80000000ULL) {
            fut_printf("[ramfs] ERROR: Invalid entry pointer %p\n", (void*)entry);
            return -EIO;
        }

        /* Validate vnode pointer before comparing name */
        if (!entry->vnode || (uintptr_t)entry->vnode < 0xFFFFFFFF80000000ULL) {
            fut_printf("[ramfs] ERROR: Invalid vnode pointer %p in entry '%s'\n",
                      (void*)entry->vnode, entry->name);
            return -EIO;
        }

        if (str_cmp(entry->name, name) == 0) {
            fut_printf("[RAMFS-LOOKUP] Found '%s': vnode=%p fs_data=%p\n",
                      name, (void*)entry->vnode, (void*)entry->vnode->fs_data);

            /* Log full state of found node */
            struct ramfs_node *found_node = (struct ramfs_node *)entry->vnode->fs_data;
            if (found_node && entry->vnode->type == VN_REG) {
                log_ramfs_node_state("ramfs_lookup FOUND file", found_node, entry->vnode);
            }

            *result = entry->vnode;
            fut_vnode_ref(*result);
            return 0;
        }
        entry = entry->next;
    }

    return -ENOENT;
}

static int ramfs_create(struct fut_vnode *dir, const char *name, uint32_t mode, struct fut_vnode **result) {
    extern void fut_printf(const char *, ...);

    fut_printf("[RAMFS-CREATE-ENTRY] dir=%p name=%s mode=0%o result=%p\n", (void*)dir, name ? name : "(null)", mode, (void*)result);

    if (!dir || !name || !result) {
        fut_printf("[RAMFS-CREATE] FAILED: Invalid params - dir=%p name=%p result=%p\n", (void*)dir, (void*)name, (void*)result);
        return -EINVAL;
    }

    if (dir->type != VN_DIR) {
        fut_printf("[RAMFS-CREATE] FAILED: dir->type=%d is not VN_DIR\n", dir->type);
        return -ENOTDIR;
    }

    struct ramfs_node *dir_node = (struct ramfs_node *)dir->fs_data;
    if (!dir_node) {
        fut_printf("[RAMFS-CREATE] FAILED: dir->fs_data is NULL\n");
        return -EIO;
    }

    /* Check if file already exists */
    struct ramfs_dirent *entry = dir_node->dir.entries;
    while (entry) {
        if (str_cmp(entry->name, name) == 0) {
            fut_printf("[RAMFS-CREATE] File '%s' already exists at vnode=%p fs_data=%p\n",
                      name, (void*)entry->vnode, (void*)entry->vnode->fs_data);
            return -EEXIST;
        }
        entry = entry->next;
    }

    /* Create new vnode */
    struct fut_vnode *vnode = fut_malloc(sizeof(struct fut_vnode));
    if (!vnode) {
        return -ENOMEM;
    }

    struct ramfs_node *node = fut_malloc(sizeof(struct ramfs_node));
    if (!node) {
        fut_free(vnode);
        return -ENOMEM;
    }

    fut_printf("[RAMFS-CREATE] Creating file '%s': new vnode=%p new node=%p\n",
              name, (void*)vnode, (void*)node);

    /* Initialize vnode */
    vnode->type = VN_REG;
    vnode->ino = (uint64_t)vnode;  /* Use pointer as inode number */
    vnode->mode = mode;
    vnode->size = 0;
    vnode->nlinks = 1;
    vnode->mount = dir->mount;
    vnode->fs_data = node;
    vnode->refcount = 1;
    vnode->ops = dir->ops;  /* Same ops as parent */

    /* Phase 3: Initialize advisory file locking state */
    fut_vnode_lock_init(vnode);

    fut_printf("[RAMFS-CREATE] Set vnode->fs_data=%p for '%s'\n", (void*)node, name);

    /* Initialize guard values to detect buffer overflows */
    node->magic_guard_before = RAMFS_NODE_MAGIC;
    node->magic_guard_after = RAMFS_NODE_MAGIC;

    /* Initialize open reference count */
    node->open_count = 0;

    /* Initialize file data */
    node->file.data = NULL;
    node->file.capacity = 0;

    /* Create directory entry */
    struct ramfs_dirent *new_entry = fut_malloc(sizeof(struct ramfs_dirent));
    if (!new_entry) {
        fut_free(node);
        fut_free(vnode);
        return -ENOMEM;
    }

    str_copy_safe(new_entry->name, name, sizeof(new_entry->name));
    new_entry->vnode = vnode;
    new_entry->next = dir_node->dir.entries;
    dir_node->dir.entries = new_entry;

    /* Take reference for caller - must match reference-taking in lookup */
    fut_vnode_ref(vnode);
    *result = vnode;
    return 0;
}

static int ramfs_mkdir(struct fut_vnode *dir, const char *name, uint32_t mode) {
    if (!dir || !name) {
        return -EINVAL;
    }

    if (dir->type != VN_DIR) {
        return -ENOTDIR;
    }

    struct ramfs_node *dir_node = (struct ramfs_node *)dir->fs_data;
    if (!dir_node) {
        return -EIO;
    }

    /* Check if directory already exists */
    struct ramfs_dirent *entry = dir_node->dir.entries;
    while (entry) {
        if (str_cmp(entry->name, name) == 0) {
            return -EEXIST;
        }
        entry = entry->next;
    }

    /* Create new vnode */
    struct fut_vnode *vnode = fut_malloc(sizeof(struct fut_vnode));
    if (!vnode) {
        return -ENOMEM;
    }

    struct ramfs_node *node = fut_malloc(sizeof(struct ramfs_node));
    if (!node) {
        fut_free(vnode);
        return -ENOMEM;
    }

    /* Initialize vnode */
    vnode->type = VN_DIR;
    vnode->ino = (uint64_t)vnode;
    vnode->mode = mode;
    vnode->size = 0;
    vnode->nlinks = 2;  /* "." and parent reference */
    vnode->mount = dir->mount;
    vnode->fs_data = node;
    vnode->refcount = 1;
    vnode->ops = dir->ops;

    /* Phase 3: Initialize advisory file locking state */
    fut_vnode_lock_init(vnode);

    /* Initialize guard values to detect buffer overflows */
    node->magic_guard_before = RAMFS_NODE_MAGIC;
    node->magic_guard_after = RAMFS_NODE_MAGIC;

    /* Initialize open reference count */
    node->open_count = 0;

    /* Initialize directory */
    node->dir.entries = NULL;

    /* Create directory entry */
    struct ramfs_dirent *new_entry = fut_malloc(sizeof(struct ramfs_dirent));
    if (!new_entry) {
        fut_free(node);
        fut_free(vnode);
        return -ENOMEM;
    }

    str_copy_safe(new_entry->name, name, sizeof(new_entry->name));
    new_entry->vnode = vnode;
    new_entry->next = dir_node->dir.entries;
    dir_node->dir.entries = new_entry;

    return 0;
}

/**
 * ramfs_unlink - Remove a file from a directory
 * @dir: Parent directory vnode
 * @name: Name of file to remove
 *
 * Returns: 0 on success, negative error code on failure
 */
static int ramfs_unlink(struct fut_vnode *dir, const char *name) {
    extern void fut_printf(const char *, ...);

    if (!dir || !name) {
        return -EINVAL;
    }

    if (dir->type != VN_DIR) {
        return -ENOTDIR;
    }

    struct ramfs_node *dir_node = (struct ramfs_node *)dir->fs_data;
    if (!dir_node) {
        return -EIO;
    }

    /* Find the entry in the directory */
    struct ramfs_dirent *entry = dir_node->dir.entries;
    struct ramfs_dirent *prev = NULL;

    while (entry) {
        if (str_cmp(entry->name, name) == 0) {
            /* Found the entry */
            struct fut_vnode *vnode = entry->vnode;

            /* Can only unlink regular files */
            if (vnode->type != VN_REG) {
                return -EISDIR;
            }

            /* Check if file is still open */
            struct ramfs_node *node = (struct ramfs_node *)vnode->fs_data;
            if (node && node->open_count > 0) {
                fut_printf("[RAMFS-UNLINK] Warning: unlinking open file (open_count=%u)\n",
                          node->open_count);
            }

            /* Remove entry from linked list */
            if (prev) {
                prev->next = entry->next;
            } else {
                dir_node->dir.entries = entry->next;
            }

            /* Free file data if it exists */
            if (node && node->file.data) {
                fut_free(node->file.data);
            }

            /* Free the ramfs_node */
            if (node) {
                fut_free(node);
            }

            /* Free the vnode */
            fut_free(vnode);

            /* Free the directory entry */
            fut_free(entry);

            return 0;
        }

        prev = entry;
        entry = entry->next;
    }

    /* File not found */
    return -ENOENT;
}

/**
 * ramfs_rmdir - Remove an empty directory
 * @dir: Parent directory vnode
 * @name: Name of directory to remove
 *
 * Returns: 0 on success, negative error code on failure
 */
static int ramfs_rmdir(struct fut_vnode *dir, const char *name) {
    if (!dir || !name) {
        return -EINVAL;
    }

    if (dir->type != VN_DIR) {
        return -ENOTDIR;
    }

    struct ramfs_node *dir_node = (struct ramfs_node *)dir->fs_data;
    if (!dir_node) {
        return -EIO;
    }

    /* Find the entry in the directory */
    struct ramfs_dirent *entry = dir_node->dir.entries;
    struct ramfs_dirent *prev = NULL;

    while (entry) {
        if (str_cmp(entry->name, name) == 0) {
            /* Found the entry */
            struct fut_vnode *vnode = entry->vnode;

            /* Can only remove directories */
            if (vnode->type != VN_DIR) {
                return -ENOTDIR;
            }

            /* Check if directory is empty */
            struct ramfs_node *node = (struct ramfs_node *)vnode->fs_data;
            if (!node) {
                return -EIO;
            }

            if (node->dir.entries != NULL) {
                return -ENOTEMPTY;
            }

            /* Remove entry from linked list */
            if (prev) {
                prev->next = entry->next;
            } else {
                dir_node->dir.entries = entry->next;
            }

            /* Free the ramfs_node */
            fut_free(node);

            /* Free the vnode */
            fut_free(vnode);

            /* Free the directory entry */
            fut_free(entry);

            return 0;
        }

        prev = entry;
        entry = entry->next;
    }

    /* Directory not found */
    return -ENOENT;
}

/**
 * ramfs_readdir - Read directory entries
 * @dir: Directory vnode
 * @cookie: Position in directory (entry index)
 * @dirent: Output directory entry
 *
 * Returns: 1 if entry found, 0 if end of directory, negative error code on failure
 */
static int ramfs_readdir(struct fut_vnode *dir, uint64_t *cookie, struct fut_vdirent *dirent) {
    extern void fut_printf(const char *, ...);

    if (!dir || !cookie || !dirent) {
        return -EINVAL;
    }

    if (dir->type != VN_DIR) {
        return -ENOTDIR;
    }

    struct ramfs_node *node = (struct ramfs_node *)dir->fs_data;
    if (!node) {
        return -EIO;
    }

    /* Iterate to the entry at position *cookie */
    struct ramfs_dirent *entry = node->dir.entries;
    uint64_t index = 0;

    while (entry && index < *cookie) {
        entry = entry->next;
        index++;
    }

    /* No more entries */
    if (!entry) {
        return 0;
    }

    /* Fill in the dirent structure */
    dirent->d_ino = entry->vnode->ino;
    dirent->d_off = *cookie + 1;
    dirent->d_reclen = sizeof(struct fut_vdirent);

    /* Set d_type based on vnode type */
    switch (entry->vnode->type) {
        case VN_REG:
            dirent->d_type = FUT_VDIR_TYPE_REG;
            break;
        case VN_DIR:
            dirent->d_type = FUT_VDIR_TYPE_DIR;
            break;
        case VN_CHR:
            dirent->d_type = FUT_VDIR_TYPE_CHAR;
            break;
        case VN_BLK:
            dirent->d_type = FUT_VDIR_TYPE_BLOCK;
            break;
        case VN_FIFO:
            dirent->d_type = FUT_VDIR_TYPE_FIFO;
            break;
        case VN_SOCK:
            dirent->d_type = FUT_VDIR_TYPE_SOCKET;
            break;
        case VN_LNK:
            dirent->d_type = FUT_VDIR_TYPE_SYMLINK;
            break;
        default:
            dirent->d_type = FUT_VDIR_TYPE_UNKNOWN;
            break;
    }

    /* Copy the name */
    size_t name_len = 0;
    while (entry->name[name_len] && name_len < FUT_VFS_NAME_MAX) {
        dirent->d_name[name_len] = entry->name[name_len];
        name_len++;
    }
    dirent->d_name[name_len] = '\0';

    /* Update cookie to next entry */
    *cookie = *cookie + 1;

    return 1;  /* Entry found */
}

/**
 * Get file attributes (stat information).
 */
static int ramfs_getattr(struct fut_vnode *vnode, struct fut_stat *stat) {
    if (!vnode || !stat) {
        return -EINVAL;
    }

    struct ramfs_node *node = (struct ramfs_node *)vnode->fs_data;
    if (!node) {
        return -EIO;
    }

    /* Fill in stat structure */
    stat->st_dev = 1;               /* Device ID for ramfs */
    stat->st_ino = vnode->ino;      /* Inode number */
    stat->st_mode = vnode->mode;    /* File mode and permissions */
    stat->st_nlink = vnode->nlinks; /* Number of hard links */
    stat->st_uid = 0;               /* User ID (root) */
    stat->st_gid = 0;               /* Group ID (root) */

    /* Calculate file size based on type */
    if (vnode->type == VN_REG) {
        stat->st_size = node->file.capacity;  /* File size */
    } else if (vnode->type == VN_DIR) {
        stat->st_size = 0;  /* Directories don't have size */
    } else {
        stat->st_size = 0;
    }

    stat->st_blksize = 4096;        /* Filesystem block size */
    stat->st_blocks = (stat->st_size + 511) / 512;  /* Number of 512-byte blocks */

    /* Timestamps - using current time as default since ramfs is in-memory */
    uint64_t now_ns = fut_get_time_ns();
    stat->st_atime = now_ns;        /* Access time (current) */
    stat->st_mtime = now_ns;        /* Modification time (current) */
    stat->st_ctime = now_ns;        /* Change time (current) */

    return 0;
}

/**
 * ramfs_sync() - Sync file to storage (no-op for RamFS)
 *
 * Phase 3: RamFS is entirely in-memory, so there's no storage to sync to.
 * This is a no-op that always succeeds. However, we implement it for API
 * completeness and to allow fsync() to work on RamFS files.
 *
 * @param vnode VNode to sync
 * @return 0 (success - no actual sync needed)
 */
static int ramfs_sync(struct fut_vnode *vnode) {
    (void)vnode;  /* Unused - no actual sync needed for in-memory filesystem */

    /* Phase 3: RamFS is already in memory, so sync is a no-op.
     * All data is immediately visible to all processes. */
    return 0;
}

/**
 * ramfs_truncate() - Truncate file to specified size (Phase 3)
 *
 * Shrinking: Updates vnode size, data beyond new size becomes inaccessible
 * Extending: Reallocates buffer if needed, zeros new area, updates size
 *
 * @param vnode  VNode to truncate (must be regular file)
 * @param length New file size in bytes
 * @return 0 on success, negative error code on failure
 */
static int ramfs_truncate(struct fut_vnode *vnode, uint64_t length) {
    if (!vnode) {
        return -EINVAL;
    }

    /* Only regular files can be truncated */
    if (vnode->type != VN_REG) {
        return -EINVAL;
    }

    struct ramfs_node *node = (struct ramfs_node *)vnode->fs_data;
    if (!node) {
        return -EINVAL;
    }

    uint64_t old_size = vnode->size;

    /* Case 1: Shrinking file or no change */
    if (length <= old_size) {
        /* Just update the size - keep allocated memory for future growth */
        vnode->size = length;
        return 0;
    }

    /* Case 2: Extending file - need to ensure capacity and zero-fill */
    size_t new_capacity = (size_t)length;

    /* Reallocate buffer if current capacity is insufficient */
    if (new_capacity > node->file.capacity) {
        /* Round up to nearest 4KB for efficiency */
        size_t rounded_capacity = (new_capacity + 4095) & ~4095;

        uint8_t *new_data = fut_malloc(rounded_capacity);
        if (!new_data) {
            return -ENOMEM;
        }

        /* Copy existing data */
        if (node->file.data && old_size > 0) {
            for (uint64_t i = 0; i < old_size; i++) {
                new_data[i] = node->file.data[i];
            }
        }

        /* Zero-fill the extended region */
        for (uint64_t i = old_size; i < length; i++) {
            new_data[i] = 0;
        }

        /* Free old buffer and install new one */
        if (node->file.data) {
            fut_free(node->file.data);
        }
        node->file.data = new_data;
        node->file.capacity = rounded_capacity;
    } else {
        /* Sufficient capacity exists - just zero-fill extended region */
        if (node->file.data) {
            for (uint64_t i = old_size; i < length; i++) {
                node->file.data[i] = 0;
            }
        }
    }

    /* Update file size */
    vnode->size = length;

    return 0;
}

static const struct fut_vnode_ops ramfs_vnode_ops = {
    .open = ramfs_open,
    .close = ramfs_close,
    .read = ramfs_read,
    .write = ramfs_write,
    .readdir = ramfs_readdir,
    .lookup = ramfs_lookup,
    .create = ramfs_create,
    .unlink = ramfs_unlink,
    .mkdir = ramfs_mkdir,
    .rmdir = ramfs_rmdir,
    .getattr = ramfs_getattr,
    .setattr = NULL,
    .sync = ramfs_sync,
    .truncate = ramfs_truncate
};

/* ============================================================
 *   Filesystem Operations
 * ============================================================ */

static int ramfs_mount(const char *device, int flags, void *data, fut_handle_t block_device_handle, struct fut_mount **mount_out) {
    (void)device;
    (void)data;
    (void)block_device_handle;  /* ramfs doesn't use block devices */

    /* Create mount structure */
    struct fut_mount *mount = fut_malloc(sizeof(struct fut_mount));
    if (!mount) {
        return -ENOMEM;
    }

    /* Create root directory vnode */
    struct ramfs_root_guard *guard = fut_malloc(sizeof(struct ramfs_root_guard));
    if (!guard) {
        fut_free(mount);
        return -ENOMEM;
    }
    guard->before = RAMFS_ROOT_CANARY_BEFORE;
    guard->after = RAMFS_ROOT_CANARY_AFTER;

    struct fut_vnode *root = &guard->vnode;

    struct ramfs_node *root_node = fut_malloc(sizeof(struct ramfs_node));
    if (!root_node) {
        fut_free(guard);
        fut_free(mount);
        return -ENOMEM;
    }

    /* Initialize root vnode */
    root->type = VN_DIR;
    root->ino = 1;  /* Root always has inode 1 */
    root->mode = 0755;
    root->size = 0;
    root->nlinks = 2;
    root->mount = mount;
    root->fs_data = root_node;
    root->refcount = 1;
    root->ops = &ramfs_vnode_ops;

    fut_vfs_register_root_canary(&guard->before, &guard->after);

    /* Initialize guard values to detect buffer overflows */
    root_node->magic_guard_before = RAMFS_NODE_MAGIC;
    root_node->magic_guard_after = RAMFS_NODE_MAGIC;

    /* Initialize root directory */
    root_node->dir.entries = NULL;

    /* Initialize mount */
    mount->device = NULL;
    mount->mountpoint = NULL;
    mount->fs = NULL;  /* Set by VFS */
    mount->root = root;
    mount->flags = flags;
    mount->fs_data = NULL;
    mount->next = NULL;

    *mount_out = mount;
    return 0;
}

/* Forward declaration for cleanup function */
static void ramfs_cleanup_vnode(struct fut_vnode *vnode);

/**
 * Recursively free all vnodes in a directory.
 * Traverses the directory tree and unreferences all vnodes,
 * which triggers their cleanup via vnode refcounting.
 */
static void ramfs_free_directory_recursive(struct fut_vnode *dir_vnode) {
    if (!dir_vnode || dir_vnode->type != VN_DIR) {
        return;
    }

    struct ramfs_node *dir_node = (struct ramfs_node *)dir_vnode->fs_data;
    if (!dir_node) {
        return;
    }

    /* Iterate through directory entries */
    struct ramfs_dirent *entry = dir_node->dir.entries;
    while (entry) {
        struct ramfs_dirent *next_entry = entry->next;

        if (entry->vnode) {
            /* Recursively free subdirectories */
            if (entry->vnode->type == VN_DIR) {
                ramfs_free_directory_recursive(entry->vnode);
            }

            /* Clean up vnode filesystem data */
            ramfs_cleanup_vnode(entry->vnode);

            /* Unref the vnode */
            fut_vnode_unref(entry->vnode);
        }

        /* Free the directory entry */
        fut_free(entry);
        entry = next_entry;
    }

    /* Clear the directory entries list */
    dir_node->dir.entries = NULL;
}

/**
 * Clean up ramfs_node fs_data when vnode is freed.
 * Called when a vnode is destroyed (refcount reaches 0).
 */
static void ramfs_cleanup_vnode(struct fut_vnode *vnode) {
    if (!vnode || !vnode->fs_data) {
        return;
    }

    struct ramfs_node *node = (struct ramfs_node *)vnode->fs_data;

    /* Validate magic guards */
    if (node->magic_guard_before != RAMFS_NODE_MAGIC ||
        node->magic_guard_after != RAMFS_NODE_MAGIC) {
        return;  /* Invalid node, skip cleanup */
    }

    /* Free file data if present */
    if (vnode->type == VN_REG && node->file.data) {
        fut_free(node->file.data);
        node->file.data = NULL;
        node->file.capacity = 0;
    }

    /* Free the ramfs_node structure itself */
    fut_free(node);
    vnode->fs_data = NULL;
}

static void ramfs_free_vnode(struct fut_vnode *vnode) {
    if (!vnode) {
        return;
    }

    /* Clean up filesystem-specific data */
    ramfs_cleanup_vnode(vnode);

    /* Free the vnode structure itself */
    fut_free(vnode);
}

static int ramfs_unmount(struct fut_mount *mount) {
    if (!mount || !mount->root) {
        return -EINVAL;
    }

    struct fut_vnode *root = mount->root;

    /* Recursively free all vnodes and data in the directory tree
     * Note: We manually free vnodes here rather than using fut_vnode_unref()
     * because the normal unref path keeps directory vnodes alive permanently.
     * During unmount, we explicitly want to free everything.
     */
    struct ramfs_node *root_node = (struct ramfs_node *)root->fs_data;
    if (root_node) {
        /* Iterate through root directory entries */
        struct ramfs_dirent *entry = root_node->dir.entries;
        while (entry) {
            struct ramfs_dirent *next_entry = entry->next;

            if (entry->vnode) {
                /* Recursively free subdirectories */
                if (entry->vnode->type == VN_DIR) {
                    ramfs_free_directory_recursive(entry->vnode);
                }

                /* Free the vnode */
                ramfs_free_vnode(entry->vnode);
            }

            /* Free the directory entry */
            fut_free(entry);
            entry = next_entry;
        }

        /* Clear the directory entries list */
        root_node->dir.entries = NULL;
    }

    /* Free the root vnode itself */
    ramfs_free_vnode(root);

    return 0;
}

static const struct fut_fs_type ramfs_type = {
    .name = "ramfs",
    .mount = ramfs_mount,
    .unmount = ramfs_unmount
};

/* ============================================================
 *   RamFS Registration
 * ============================================================ */

void fut_ramfs_init(void) {
    fut_vfs_register_fs(&ramfs_type);
}
