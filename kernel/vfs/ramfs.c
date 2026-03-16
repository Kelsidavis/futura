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
#include <kernel/vfs_credentials.h>
#include <kernel/slab_allocator.h>
#include <kernel/kprintf.h>
#include <kernel/errno.h>
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

/* Extended attribute entry (name-value pair stored on a vnode) */
struct ramfs_xattr {
    char *name;                     /* Attribute name (heap-allocated) */
    void *value;                    /* Attribute value bytes (heap-allocated) */
    size_t size;                    /* Length of value in bytes */
    struct ramfs_xattr *next;       /* Next entry in per-vnode list */
};

/* Per-vnode filesystem data */
struct ramfs_node {
    uint64_t magic_guard_before;    /* Guard value to detect overflow into structure */
    uint32_t open_count;            /* Reference count: number of open file descriptors */
    /* Timestamps in milliseconds since boot (from fut_get_ticks()) */
    uint64_t atime_ms;              /* Last access time */
    uint64_t mtime_ms;              /* Last modification time */
    uint64_t ctime_ms;              /* Last status change time */
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

        /* For symbolic links: target path */
        struct {
            char *target;           /* Target path string (not resolved) */
        } link;
    };
    struct ramfs_xattr *xattrs;     /* Extended attributes list (NULL if none) */
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

#ifdef DEBUG_RAMFS
/* Log complete state of a ramfs_node for debugging */
static void log_ramfs_node_state(const char *context, struct ramfs_node *node, struct fut_vnode *vnode) {

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
#endif

/* Validate that ramfs_node guards haven't been corrupted */
static int validate_ramfs_node(struct ramfs_node *node) {

    if (!node) {
        return 0;  /* NULL is OK, caller checks this */
    }

    if (node->magic_guard_before != RAMFS_NODE_MAGIC) {
        fut_printf("[RAMFS-GUARD] ERROR: guard_before corrupted! Expected 0x%llx, got 0x%llx\n",
                   (unsigned long long)RAMFS_NODE_MAGIC, (unsigned long long)node->magic_guard_before);
        return -EIO;  /* Memory corruption detected */
    }

    if (node->magic_guard_after != RAMFS_NODE_MAGIC) {
        fut_printf("[RAMFS-GUARD] ERROR: guard_after corrupted! Expected 0x%llx, got 0x%llx\n",
                   (unsigned long long)RAMFS_NODE_MAGIC, (unsigned long long)node->magic_guard_after);
        return -EIO;  /* Memory corruption detected */
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

#ifdef DEBUG_RAMFS
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
#endif

    /* Check offset - ensure it doesn't exceed file size */
    if (offset >= vnode->size) {
#ifdef DEBUG_RAMFS
        fut_printf("[RAMFS-READ] EOF: offset=%llu >= size=%llu\n",
                   (unsigned long long)offset, (unsigned long long)vnode->size);
#endif
        return 0;  /* EOF */
    }

    /* Defensive check: file data must exist if size > 0 */
    if (!node->file.data) {
        return 0;  /* Treat as empty file */
    }

    /* Calculate bytes to read - safe since offset < vnode->size */
    uint64_t remaining = vnode->size - offset;
    /* Cap to SIZE_MAX to avoid overflow in pointer arithmetic */
    size_t to_read = (size < remaining) ? size : (size_t)remaining;

    /* Manual copy to avoid SSE/AVX instructions in memcpy */
    uint8_t *dest = (uint8_t *)buf;

#ifdef DEBUG_RAMFS
    /* DEBUG: Print file.data pointer value BEFORE using it */
    if (offset == 0 && to_read >= 4) {
        fut_printf("[RAMFS-READ-DEBUG] node=%p node->file.data=%p offset=%llu\n",
                   node, (void*)node->file.data, (unsigned long long)offset);
    }
#endif

    const uint8_t *src = node->file.data + (size_t)offset;

#ifdef DEBUG_RAMFS
    /* Debug: check first bytes for ELF magic */
    if (offset == 0 && to_read >= 4) {
        uint32_t *magic = (uint32_t *)src;
        fut_printf("[RAMFS-READ] src=%p (after adding offset) First 4 bytes: 0x%08x\n", (void*)src, *magic);
    }
#endif

    for (size_t i = 0; i < to_read; i++) {
        dest[i] = src[i];
    }

    /* Update access time on successful read */
    node->atime_ms = fut_get_ticks();

    return (ssize_t)to_read;
}

static ssize_t ramfs_write(struct fut_vnode *vnode, const void *buf, size_t size, uint64_t offset) {

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

#ifdef DEBUG_RAMFS
        fut_printf("[RAMFS-REALLOC] Reallocating: required=%llu power_of_2=%llu new_capacity=%llu\n",
                   (unsigned long long)required, (unsigned long long)power_of_2, (unsigned long long)new_capacity);
        fut_printf("[RAMFS-REALLOC] Old buffer: data=%p capacity=%llu vnode->size=%llu\n",
                   (void*)node->file.data, (unsigned long long)node->file.capacity, (unsigned long long)vnode->size);
#endif

        uint8_t *new_data = fut_malloc(new_capacity);
        if (!new_data) {
            fut_printf("[RAMFS-REALLOC] FAILED to allocate %llu bytes\n", (unsigned long long)new_capacity);
            return -ENOMEM;
        }

#ifdef DEBUG_RAMFS
        fut_printf("[RAMFS-REALLOC] required=%llu old_capacity=%llu -> new_capacity=%llu old=%p new=%p\n",
                   (unsigned long long)required,
                   (unsigned long long)node->file.capacity,
                   (unsigned long long)new_capacity,
                   (void*)node->file.data,
                   (void*)new_data);
#endif

#ifdef DEBUG_RAMFS
        fut_printf("[RAMFS-REALLOC] New buffer allocated: %p\n", (void*)new_data);
#endif

        /* Copy old data - use 8-byte chunks to avoid SIMD instruction issues */
        if (node->file.data && vnode->size > 0) {
            size_t copy_size = vnode->size;
#ifdef DEBUG_RAMFS
            fut_printf("[RAMFS-REALLOC] Copying %llu bytes from %p to %p\n",
                       (unsigned long long)copy_size, (void*)node->file.data, (void*)new_data);
#endif

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
#ifdef DEBUG_RAMFS
                fut_printf("[RAMFS-REALLOC] Verify copy: old[0]=0x%08x new[0]=0x%08x\n", *old_magic, *new_magic);
#else
                (void)old_magic;
                (void)new_magic;
#endif
            }

            /* CRITICAL: Validate new_data before freeing old buffer
             * because coalescing in buddy_free might corrupt adjacent memory */
            uint8_t *old_data_ptr = node->file.data;

            /* Verify new buffer is valid before freeing old */
#if defined(__x86_64__)
            if (!new_data || (uintptr_t)new_data < 0xFFFFFFFF80000000ULL) {
                fut_printf("[RAMFS-REALLOC] CRITICAL: New buffer allocation is invalid! %p\n", (void*)new_data);
                return -EIO;
            }
#elif defined(__aarch64__)
            if (!new_data || (uintptr_t)new_data < 0x40000000ULL) {
                fut_printf("[RAMFS-REALLOC] CRITICAL: New buffer allocation is invalid! %p\n", (void*)new_data);
                return -EIO;
            }
#else
            if (!new_data) {
                fut_printf("[RAMFS-REALLOC] CRITICAL: New buffer allocation is NULL!\n");
                return -EIO;
            }
#endif

#ifdef DEBUG_RAMFS
            fut_printf("[RAMFS-REALLOC] About to free old buffer: %p\n", (void*)old_data_ptr);
#endif
            fut_free(old_data_ptr);
#ifdef DEBUG_RAMFS
            fut_printf("[RAMFS-REALLOC] Old buffer freed: %p\n", (void*)old_data_ptr);
#endif
        }

        node->file.data = new_data;
        node->file.capacity = new_capacity;

        /* Validate node structure after assignment */
        if (validate_ramfs_node(node) != 0) {
            fut_printf("[RAMFS-REALLOC] CRITICAL: Node corrupted after reallocation!\n");
            return -EIO;
        }

#ifdef DEBUG_RAMFS
        slab_debug_validate_all("ramfs_realloc");
#endif

#ifdef DEBUG_RAMFS
        fut_printf("[RAMFS-REALLOC] Reallocation complete: node->file.data=%p capacity=%llu\n",
                   (void*)node->file.data, (unsigned long long)node->file.capacity);
#endif
    }

    /* Write data - use manual copy to avoid SIMD instructions */

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

#ifdef DEBUG_RAMFS
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
#endif

    for (size_t i = 0; i < size; i++) {
        node->file.data[(size_t)offset + i] = src[i];
    }

#ifdef DEBUG_RAMFS
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
#endif

    /* Update size - we already checked for overflow above */
    if (offset + size > vnode->size) {
        vnode->size = offset + size;
    }

    /* Update modification and status change timestamps */
    node->mtime_ms = fut_get_ticks();
    node->ctime_ms = node->mtime_ms;

    /* Validate guards after writing - catch overflow corruption immediately */
    if (validate_ramfs_node(node) != 0) {
        fut_printf("[RAMFS-WRITE] CRITICAL: write operation corrupted node guards!\n");
        fut_printf("[RAMFS-WRITE] This indicates a buffer overflow - wrote %llu bytes at offset %llu\n",
                   (unsigned long long)size, (unsigned long long)offset);
        fut_printf("[RAMFS-WRITE] File capacity: %llu, would write to end at: %llu\n",
                   (unsigned long long)node->file.capacity, (unsigned long long)(offset + size));
        return -EIO;
    }

#ifdef DEBUG_RAMFS
    /* Log complete state at end of write for large writes */
    if (size > 10000 || offset > 200000) {
        log_ramfs_node_state("ramfs_write END (large write)", node, vnode);
    }
#endif

    /* Phase 4: Dispatch IN_MODIFY inotify event to watchers on the file's parent */
    if (size > 0 && vnode->parent) {
        char dir_path[256];
        if (fut_vnode_build_path(vnode->parent, dir_path, sizeof(dir_path))) {
            inotify_dispatch_event(dir_path, 0x00000002 /* IN_MODIFY */,
                                   vnode->name ? vnode->name : "");
        }
    }

    return (ssize_t)size;
}

static int ramfs_lookup(struct fut_vnode *dir, const char *name, struct fut_vnode **result) {

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
        /* Note: On x86-64, kernel is at 0xFFFFFFFF80000000+, but on ARM64 it's at 0x40000000+ */
#if defined(__x86_64__)
        if ((uintptr_t)entry < 0xFFFFFFFF80000000ULL) {
            fut_printf("[ramfs] ERROR: Invalid entry pointer %p\n", (void*)entry);
            return -EIO;
        }
#elif defined(__aarch64__)
        if ((uintptr_t)entry < 0x40000000ULL) {
            fut_printf("[ramfs] ERROR: Invalid entry pointer %p\n", (void*)entry);
            return -EIO;
        }
#endif

        /* Validate vnode pointer before comparing name.
         * Skip entries with invalid vnodes rather than failing the entire lookup.
         * This provides resilience against transient corruption from preemption
         * during concurrent directory operations on a single-lock filesystem. */
#if defined(__x86_64__)
        if (!entry->vnode || (uintptr_t)entry->vnode < 0xFFFFFFFF80000000ULL) {
            fut_printf("[ramfs] WARNING: Skipping entry with invalid vnode %p (name='%s')\n",
                      (void*)entry->vnode, entry->name);
            entry = entry->next;
            continue;
        }
#elif defined(__aarch64__)
        if (!entry->vnode || (uintptr_t)entry->vnode < 0x40000000ULL) {
            fut_printf("[ramfs] WARNING: Skipping entry with invalid vnode %p (name='%s')\n",
                      (void*)entry->vnode, entry->name);
            entry = entry->next;
            continue;
        }
#endif

        if (str_cmp(entry->name, name) == 0) {
#ifdef DEBUG_RAMFS
            fut_printf("[RAMFS-LOOKUP] Found '%s': vnode=%p fs_data=%p\n",
                      name, (void*)entry->vnode, (void*)entry->vnode->fs_data);

            /* Log full state of found node */
            struct ramfs_node *found_node = (struct ramfs_node *)entry->vnode->fs_data;
            if (found_node && entry->vnode->type == VN_REG) {
                log_ramfs_node_state("ramfs_lookup FOUND file", found_node, entry->vnode);
            }
#endif

            *result = entry->vnode;
            fut_vnode_ref(*result);
            return 0;
        }
        entry = entry->next;
    }

    return -ENOENT;
}

static int ramfs_create(struct fut_vnode *dir, const char *name, uint32_t mode, struct fut_vnode **result) {

#ifdef DEBUG_RAMFS
    fut_printf("[RAMFS-CREATE-ENTRY] dir=%p name=%s mode=0%o result=%p\n", (void*)dir, name ? name : "(null)", mode, (void*)result);
#endif

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

#ifdef DEBUG_RAMFS
    fut_printf("[RAMFS-CREATE] Creating file '%s': new vnode=%p new node=%p\n",
              name, (void*)vnode, (void*)node);
#endif

    /* Initialize vnode */
    vnode->type = VN_REG;
    vnode->ino = (uint64_t)vnode;  /* Use pointer as inode number */
    vnode->mode = 0;  /* Will be set by vfs_init_vnode_ownership */
    vnode->size = 0;
    vnode->nlinks = 1;
    vnode->mount = dir->mount;
    vnode->fs_data = node;
    vnode->refcount = 1;
    vnode->ops = dir->ops;  /* Same ops as parent */
    vnode->uid = 0;  /* Will be set by vfs_init_vnode_ownership */
    vnode->gid = 0;  /* Will be set by vfs_init_vnode_ownership */
    vnode->parent = NULL;
    vnode->name = NULL;

    /* Initialize vnode ownership based on creating process and parent directory */
    vfs_init_vnode_ownership(vnode, dir, mode);

    /* Phase 3: Initialize advisory file locking state */
    fut_vnode_lock_init(vnode);

#ifdef DEBUG_RAMFS
    fut_printf("[RAMFS-CREATE] Set vnode->fs_data=%p for '%s'\n", (void*)node, name);
#endif

    /* Initialize guard values to detect buffer overflows */
    node->magic_guard_before = RAMFS_NODE_MAGIC;
    node->magic_guard_after = RAMFS_NODE_MAGIC;

    /* Initialize open reference count */
    node->open_count = 0;

    /* Initialize timestamps to current time */
    node->atime_ms = fut_get_ticks();
    node->mtime_ms = node->atime_ms;
    node->ctime_ms = node->atime_ms;

    /* Initialize extended attributes list */
    node->xattrs = NULL;

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

    /* Update parent directory mtime and ctime (new entry added) */
    uint64_t now = fut_get_ticks();
    dir_node->mtime_ms = now;
    dir_node->ctime_ms = now;

    /* Take reference for caller - must match reference-taking in lookup */
    fut_vnode_ref(vnode);
    *result = vnode;

    /* Phase 4: Dispatch IN_CREATE inotify event to watchers on the parent directory */
    {
        char dir_path[256];
        if (fut_vnode_build_path(dir, dir_path, sizeof(dir_path))) {
            inotify_dispatch_event(dir_path, 0x00000100 /* IN_CREATE */, name);
        }
    }

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
    vnode->mode = 0;  /* Will be set by vfs_init_vnode_ownership */
    vnode->size = 0;
    vnode->nlinks = 2;  /* "." and parent reference */
    vnode->mount = dir->mount;
    vnode->fs_data = node;
    vnode->refcount = 1;
    vnode->ops = dir->ops;
    vnode->uid = 0;  /* Will be set by vfs_init_vnode_ownership */
    vnode->gid = 0;  /* Will be set by vfs_init_vnode_ownership */
    vnode->parent = NULL;
    vnode->name = NULL;

    /* Initialize vnode ownership based on creating process and parent directory */
    vfs_init_vnode_ownership(vnode, dir, mode);

    /* Phase 3: Initialize advisory file locking state */
    fut_vnode_lock_init(vnode);

    /* Initialize guard values to detect buffer overflows */
    node->magic_guard_before = RAMFS_NODE_MAGIC;
    node->magic_guard_after = RAMFS_NODE_MAGIC;

    /* Initialize open reference count */
    node->open_count = 0;

    /* Initialize timestamps to current time */
    node->atime_ms = fut_get_ticks();
    node->mtime_ms = node->atime_ms;
    node->ctime_ms = node->atime_ms;

    /* Initialize extended attributes list */
    node->xattrs = NULL;

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

    fut_printf("[ramfs-mkdir] dir=%p fs_data=%p &entries=%p entries=%p added '%s'\n",
               (void*)dir, (void*)dir->fs_data, (void*)&dir_node->dir.entries,
               (void*)dir_node->dir.entries, name);

    /* Update parent directory mtime and ctime (new subdirectory added) */
    uint64_t dir_now = fut_get_ticks();
    dir_node->mtime_ms = dir_now;
    dir_node->ctime_ms = dir_now;

    /* Phase 4: Dispatch IN_CREATE|IN_ISDIR inotify event */
    {
        char dir_path[256];
        if (fut_vnode_build_path(dir, dir_path, sizeof(dir_path))) {
            inotify_dispatch_event(dir_path, 0x00000100 | 0x40000000 /* IN_CREATE|IN_ISDIR */, name);
        }
    }

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

            /* Can unlink regular files, symlinks, FIFOs, and sockets, but not directories */
            if (vnode->type == VN_DIR) {
                return -EISDIR;  /* Must use rmdir for directories */
            }
            if (vnode->type != VN_REG && vnode->type != VN_LNK &&
                vnode->type != VN_FIFO && vnode->type != VN_SOCK) {
                return -EACCES;  /* Cannot unlink device nodes */
            }

            /* Check if file is still open */
            struct ramfs_node *node = (struct ramfs_node *)vnode->fs_data;
            if (node && node->open_count > 0) {
                fut_printf("[RAMFS-UNLINK] Warning: unlinking open file (open_count=%u)\n",
                          node->open_count);
            }

            /* Decrement link count */
            if (vnode->nlinks > 0) {
                vnode->nlinks--;
            }

            /* Remove entry from linked list */
            if (prev) {
                prev->next = entry->next;
            } else {
                dir_node->dir.entries = entry->next;
            }

            /* Free the directory entry (always - this is the name being removed) */
            fut_free(entry);

            /* Only free data and vnode when all hard links are gone */
            if (vnode->nlinks == 0) {
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
            }

            /* Update parent directory mtime and ctime (entry removed) */
            uint64_t unlink_now = fut_get_ticks();
            dir_node->mtime_ms = unlink_now;
            dir_node->ctime_ms = unlink_now;

            /* Phase 4: Dispatch IN_DELETE inotify event */
            {
                char dir_path[256];
                if (fut_vnode_build_path(dir, dir_path, sizeof(dir_path))) {
                    inotify_dispatch_event(dir_path, 0x00000200 /* IN_DELETE */, name);
                }
            }

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

            /* Update parent directory mtime and ctime (subdirectory removed) */
            uint64_t rmdir_now = fut_get_ticks();
            dir_node->mtime_ms = rmdir_now;
            dir_node->ctime_ms = rmdir_now;

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
    stat->st_uid = vnode->uid;      /* User ID */
    stat->st_gid = vnode->gid;      /* Group ID */

    /* Use vnode->size which tracks the logical file size
     * (node->file.capacity is the allocated buffer size, which may be larger) */
    stat->st_size = vnode->size;

    stat->st_blksize = 4096;        /* Filesystem block size */
    stat->st_blocks = (stat->st_size + 511) / 512;  /* Number of 512-byte blocks */

    /* Timestamps - stored in ramfs_node as milliseconds since boot.
     * Using tick-based time to avoid TSC calibration deadlock. */
    uint64_t atime_ns = node->atime_ms * 1000000ULL;
    uint64_t mtime_ns = node->mtime_ms * 1000000ULL;
    uint64_t ctime_ns = node->ctime_ms * 1000000ULL;
    stat->st_atime = atime_ns / 1000000000;
    stat->st_atime_nsec = (uint32_t)(atime_ns % 1000000000);
    stat->st_mtime = mtime_ns / 1000000000;
    stat->st_mtime_nsec = (uint32_t)(mtime_ns % 1000000000);
    stat->st_ctime = ctime_ns / 1000000000;
    stat->st_ctime_nsec = (uint32_t)(ctime_ns % 1000000000);

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

static int ramfs_datasync(struct fut_vnode *vnode) {
    (void)vnode;  /* Unused - no actual sync needed for in-memory filesystem */

    /* Phase 3: RamFS is already in memory, so datasync is a no-op.
     * All data is immediately visible to all processes. Same as sync(). */
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

/**
 * Helper: Copy a string with size bounds to prevent overflow
 */
static void str_cpy_bounded(char *dst, const char *src, size_t dst_size) {
    if (!dst || !src || dst_size == 0) {
        return;
    }

    size_t i = 0;
    while (src[i] != '\0' && i < dst_size - 1) {
        dst[i] = src[i];
        i++;
    }
    dst[i] = '\0';
}

/**
 * Helper: Extract directory path and basename from a full path
 * Returns the basename (last component), and fills dirname_out with the parent directory path.
 * Returns NULL if path is invalid.
 */
static const char *path_extract_basename(const char *path, char *dirname_out, size_t dirname_size) {
    if (!path || !dirname_out) {
        return NULL;
    }

    size_t path_len = strnlen(path, 256);

    /* Find the last '/' */
    int last_slash = -1;
    for (size_t i = 0; i < path_len; i++) {
        if (path[i] == '/') {
            last_slash = (int)i;
        }
    }

    /* No directory component (relative path without /) */
    if (last_slash == -1) {
        /* dirname is current directory */
        if (dirname_size > 1) {
            dirname_out[0] = '.';
            dirname_out[1] = '\0';
        }
        return path;
    }

    /* Path is just "/" */
    if (last_slash == 0 && path[1] == '\0') {
        dirname_out[0] = '/';
        dirname_out[1] = '\0';
        return path + 1;
    }

    /* Copy dirname up to (but not including) the slash */
    if (last_slash + 1 > (int)dirname_size) {
        return NULL;  /* dirname too long */
    }
    for (int i = 0; i < last_slash; i++) {
        dirname_out[i] = path[i];
    }
    dirname_out[last_slash] = '\0';

    /* Return pointer to basename (after the slash) */
    return path + last_slash + 1;
}

/**
 * ramfs_rename - Atomically rename/move a file or directory
 * @old_vnode: Vnode of the file/directory to rename (unused, kept for compatibility)
 * @oldpath: Full path to existing file/directory
 * @newpath: Full path for the new location/name
 *
 * Renames a file or directory from oldpath to newpath. If newpath exists, it is
 * atomically replaced (or must be an empty directory).
 *
 * Returns: 0 on success, negative error code on failure
 */
/* Forward declaration - defined later after all helper functions */
static struct fut_vnode_ops ramfs_vnode_ops;

/**
 * ramfs_link() - Create a hard link to an existing file
 *
 * @old_vnode: Vnode of existing file (source)
 * @oldpath: Path to existing file
 * @newpath: Path where hard link should be created
 *
 * Creates a new directory entry in the parent of newpath that points to
 * the same inode as oldpath. Both paths then refer to the same file data.
 * The link count (nlinks) is incremented.
 *
 * Returns: 0 on success, negative error code on failure
 */
static int ramfs_link(struct fut_vnode *old_vnode, const char *oldpath, const char *newpath) {

    (void)oldpath;  /* Not needed for in-memory link */

    if (!old_vnode || !newpath) {
        return -EINVAL;
    }

    /* Cannot create hard link to directory (prevents cycles) */
    if (old_vnode->type == VN_DIR) {
        return -EISDIR;
    }

    /* Extract directory and basename from newpath */
    char new_dirname[256];
    const char *new_basename = path_extract_basename(newpath, new_dirname, sizeof(new_dirname));
    if (!new_basename) {
        return -EINVAL;
    }

    /* Look up the parent directory for newpath */
    struct fut_vnode *new_parent = NULL;
    int ret = fut_vfs_lookup(new_dirname, &new_parent);
    if (ret < 0) {
        fut_printf("[RAMFS-LINK] Failed to lookup new parent '%s': %d\n", new_dirname, ret);
        return ret;
    }

    /* Parent must be a directory */
    if (new_parent->type != VN_DIR) {
        return -ENOTDIR;
    }

    struct ramfs_node *new_parent_node = (struct ramfs_node *)new_parent->fs_data;
    if (!new_parent_node) {
        return -EIO;
    }

    /* Check if newpath already exists */
    struct ramfs_dirent *existing = new_parent_node->dir.entries;
    while (existing) {
        if (str_cmp(existing->name, new_basename) == 0) {
            return -EEXIST;  /* Entry already exists */
        }
        existing = existing->next;
    }

    /* Create new directory entry pointing to old_vnode */
    struct ramfs_dirent *new_entry = fut_malloc(sizeof(struct ramfs_dirent));
    if (!new_entry) {
        return -ENOMEM;
    }

    /* Copy the basename into the entry */
    str_cpy_bounded(new_entry->name, new_basename, sizeof(new_entry->name));

    /* Point to the same vnode */
    new_entry->vnode = old_vnode;
    new_entry->next = new_parent_node->dir.entries;
    new_parent_node->dir.entries = new_entry;

    /* Increment link count on the vnode */
    old_vnode->nlinks++;

    return 0;
}

/**
 * ramfs_symlink() - Create a symbolic link
 *
 * @parent: Parent directory vnode
 * @linkpath: Name of symlink to create
 * @target: Target path the symlink points to
 *
 * Creates a new symbolic link vnode with the given target path string.
 * The target is stored as-is (not resolved) allowing dangling symlinks.
 *
 * Returns: 0 on success, negative error code on failure
 */
static int ramfs_symlink(struct fut_vnode *parent, const char *linkpath, const char *target) {

    if (!parent || !linkpath || !target) {
        return -EINVAL;
    }

    /* Parent must be a directory */
    if (parent->type != VN_DIR) {
        return -ENOTDIR;
    }

    struct ramfs_node *parent_node = (struct ramfs_node *)parent->fs_data;
    if (!parent_node) {
        return -EIO;
    }

    /* Check if linkpath already exists */
    struct ramfs_dirent *existing = parent_node->dir.entries;
    while (existing) {
        if (str_cmp(existing->name, linkpath) == 0) {
            return -EEXIST;  /* Entry already exists */
        }
        existing = existing->next;
    }

    /* Calculate target length */
    size_t target_len = strnlen(target, 4096);

    if (target_len == 0) {
        return -EINVAL;  /* Empty target not allowed */
    }

    /* Allocate and initialize new symlink vnode */
    struct fut_vnode *link_vnode = fut_malloc(sizeof(struct fut_vnode));
    if (!link_vnode) {
        return -ENOMEM;
    }

    struct ramfs_node *link_node = fut_malloc(sizeof(struct ramfs_node));
    if (!link_node) {
        fut_free(link_vnode);
        return -ENOMEM;
    }

    /* Allocate target string buffer */
    char *target_buf = fut_malloc(target_len + 1);
    if (!target_buf) {
        fut_free(link_node);
        fut_free(link_vnode);
        return -ENOMEM;
    }

    /* Copy target string */
    for (size_t i = 0; i <= target_len; i++) {
        target_buf[i] = target[i];
    }

    /* Initialize link_node */
    link_node->magic_guard_before = RAMFS_NODE_MAGIC;
    link_node->open_count = 0;
    link_node->atime_ms = fut_get_ticks();
    link_node->mtime_ms = link_node->atime_ms;
    link_node->ctime_ms = link_node->atime_ms;
    link_node->xattrs = NULL;
    link_node->link.target = target_buf;
    link_node->magic_guard_after = RAMFS_NODE_MAGIC;

    /* Initialize link_vnode */
    link_vnode->type = VN_LNK;
    link_vnode->ino = 0;  /* Will be set by VFS layer if needed */
    link_vnode->mode = 0;  /* Will be set by vfs_init_vnode_ownership */
    link_vnode->size = target_len;  /* Size is length of target string */
    link_vnode->nlinks = 1;
    link_vnode->mount = parent->mount;
    link_vnode->fs_data = link_node;
    link_vnode->refcount = 1;
    link_vnode->uid = 0;  /* Will be set by vfs_init_vnode_ownership */
    link_vnode->gid = 0;  /* Will be set by vfs_init_vnode_ownership */
    link_vnode->parent = NULL;
    link_vnode->name = NULL;
    link_vnode->ops = &ramfs_vnode_ops;
    vfs_init_vnode_ownership(link_vnode, parent, 0777);
    /* Initialize lock fields to prevent garbage from uninitialized memory */
    fut_vnode_lock_init(link_vnode);

    /* Create directory entry */
    struct ramfs_dirent *new_entry = fut_malloc(sizeof(struct ramfs_dirent));
    if (!new_entry) {
        fut_free(target_buf);
        fut_free(link_node);
        fut_free(link_vnode);
        return -ENOMEM;
    }

    str_cpy_bounded(new_entry->name, linkpath, sizeof(new_entry->name));
    new_entry->vnode = link_vnode;
    new_entry->next = parent_node->dir.entries;
    parent_node->dir.entries = new_entry;

    return 0;
}

/**
 * ramfs_readlink() - Read symbolic link target
 *
 * @vnode: Vnode of symbolic link to read
 * @buf: Buffer to store target path
 * @size: Maximum number of bytes to read
 *
 * Returns the target path string stored in a symbolic link vnode.
 * Does NOT follow the symlink or resolve relative paths.
 *
 * Returns: Number of bytes read (not including null terminator),
 *          or negative error code on failure
 */
static ssize_t ramfs_readlink(struct fut_vnode *vnode, char *buf, size_t size) {

    if (!vnode || !buf || size == 0) {
        return -EINVAL;
    }

    /* Only symbolic links can be read with readlink */
    if (vnode->type != VN_LNK) {
        return -EINVAL;
    }

    struct ramfs_node *node = (struct ramfs_node *)vnode->fs_data;
    if (!node || !node->link.target) {
        return -EIO;
    }

    /* Calculate target length */
    size_t target_len = strnlen(node->link.target, 4096);

    /* Copy target to buffer, limiting to size */
    size_t bytes_to_copy = (target_len < size) ? target_len : size;
    for (size_t i = 0; i < bytes_to_copy; i++) {
        buf[i] = node->link.target[i];
    }

    return (ssize_t)bytes_to_copy;
}

/**
 * ramfs_rename() - Rename or replace a file/directory within a directory
 * @parent: Parent directory vnode
 * @oldname: Current name of the file/directory
 * @newname: New name for the file/directory
 *
 * Atomically renames oldname to newname. If newname exists, it is replaced.
 * Both names must be in the same parent directory.
 *
 * Returns: 0 on success, negative error code on failure
 */
static int ramfs_rename(struct fut_vnode *parent, const char *oldname, const char *newname) {

    if (!parent || !oldname || !newname) {
        return -EINVAL;
    }

    if (parent->type != VN_DIR) {
        return -ENOTDIR;
    }

    struct ramfs_node *parent_node = (struct ramfs_node *)parent->fs_data;
    if (!parent_node) {
        return -EIO;
    }

    /* Find oldname entry */
    struct ramfs_dirent *old_entry = parent_node->dir.entries;

    while (old_entry) {
        if (str_cmp(old_entry->name, oldname) == 0) {
            break;
        }
        old_entry = old_entry->next;
    }

    if (!old_entry) {
        return -ENOENT;
    }

    struct fut_vnode *old_vnode = old_entry->vnode;

    /* Find and remove newname entry if it exists */
    struct ramfs_dirent *new_entry = parent_node->dir.entries;
    struct ramfs_dirent *new_prev = NULL;

    while (new_entry) {
        if (str_cmp(new_entry->name, newname) == 0) {
            /* Found existing newname - need to replace it */
            struct fut_vnode *new_vnode = new_entry->vnode;

            /* Can't replace directory with non-directory */
            if (new_vnode->type == VN_DIR && old_vnode->type != VN_DIR) {
                return -EISDIR;
            }

            /* Can't replace non-directory with directory */
            if (new_vnode->type != VN_DIR && old_vnode->type == VN_DIR) {
                return -ENOTDIR;
            }

            /* Check if new is non-empty directory */
            if (new_vnode->type == VN_DIR) {
                struct ramfs_node *new_node = (struct ramfs_node *)new_vnode->fs_data;
                if (new_node && new_node->dir.entries) {
                    return -ENOTEMPTY;
                }
            }

            /* Decrement link count for the displaced entry */
            if (new_vnode->nlinks > 0) {
                new_vnode->nlinks--;
            }

            /* Remove new_entry from linked list */
            if (new_prev) {
                new_prev->next = new_entry->next;
            } else {
                parent_node->dir.entries = new_entry->next;
            }
            fut_free(new_entry);

            /* Only free data when all hard links to displaced file are gone */
            if (new_vnode->nlinks == 0) {
                struct ramfs_node *new_node = (struct ramfs_node *)new_vnode->fs_data;
                if (new_node && new_node->file.data) {
                    fut_free(new_node->file.data);
                }
                if (new_node) {
                    fut_free(new_node);
                }
                fut_free(new_vnode);
            }
            break;
        }
        new_prev = new_entry;
        new_entry = new_entry->next;
    }

    /* Now rename oldname to newname by updating the entry name */
    size_t newname_len = strnlen(newname, FUT_VFS_NAME_MAX);

    if (newname_len >= FUT_VFS_NAME_MAX) {
        return -ENAMETOOLONG;
    }

    /* Copy new name into the old entry */
    for (size_t i = 0; i <= newname_len; i++) {
        old_entry->name[i] = newname[i];
    }

    return 0;
}

/**
 * ramfs_setattr() - Change file attributes (permissions, mode, timestamps, ownership)
 *
 * Sets attributes on a vnode including:
 * - Permissions (mode bits and special bits)
 * - Access time (atime) and modification time (mtime)
 * - Ownership (uid, gid)
 * Uses sentinel value (time_t)-1 to indicate "don't change this field"
 *
 * Called by chmod(), chown(), utimensat() syscalls through VFS layer.
 */
static int ramfs_setattr(struct fut_vnode *vnode, const struct fut_stat *stat) {
    if (!vnode || !stat) {
        return -EINVAL;
    }

    struct ramfs_node *node = (struct ramfs_node *)vnode->fs_data;
    if (!node) {
        return -EIO;
    }

    /* Update mode: preserve only permission and special bits (not file type) */
    if (stat->st_mode != 0) {
        vnode->mode = stat->st_mode & 07777;
    }

    /* Update uid/gid: sentinel (uint32_t)-1 means "don't change" */
    if (stat->st_uid != (uint32_t)-1) {
        vnode->uid = stat->st_uid;
    }
    if (stat->st_gid != (uint32_t)-1) {
        vnode->gid = stat->st_gid;
    }

    /* Update timestamps: sentinel (uint64_t)-1 means "don't change" */
    if (stat->st_atime != (uint64_t)-1) {
        /* Convert seconds+nanoseconds to milliseconds for internal storage */
        node->atime_ms = stat->st_atime * 1000ULL + stat->st_atime_nsec / 1000000ULL;
    }
    if (stat->st_mtime != (uint64_t)-1) {
        node->mtime_ms = stat->st_mtime * 1000ULL + stat->st_mtime_nsec / 1000000ULL;
        node->ctime_ms = fut_get_ticks();  /* ctime always updates on metadata change */
    }

    return 0;
}

/* ============================================================
 *   Extended Attribute Operations
 * ============================================================ */

/* Flag constants mirroring userspace XATTR_CREATE / XATTR_REPLACE */
#define RAMFS_XATTR_CREATE  0x1
#define RAMFS_XATTR_REPLACE 0x2

static int ramfs_setxattr(struct fut_vnode *vnode, const char *name,
                          const void *value, size_t size, int flags) {
    struct ramfs_node *node = (struct ramfs_node *)vnode->fs_data;
    if (!node) return -EIO;

    /* Search for an existing entry with this name */
    struct ramfs_xattr *cur = node->xattrs;
    while (cur) {
        if (strcmp(cur->name, name) == 0) break;
        cur = cur->next;
    }

    if (cur) {
        /* Attribute already exists */
        if (flags & RAMFS_XATTR_CREATE) return -EEXIST;
        /* Replace value in-place */
        void *new_val = fut_malloc(size);
        if (!new_val && size > 0) return -ENOMEM;
        fut_free(cur->value);
        cur->value = new_val;
        if (size > 0) memcpy(cur->value, value, size);
        cur->size = size;
    } else {
        /* Attribute does not exist */
        if (flags & RAMFS_XATTR_REPLACE) return -ENODATA;
        /* Allocate new entry */
        struct ramfs_xattr *entry = fut_malloc(sizeof(struct ramfs_xattr));
        if (!entry) return -ENOMEM;
        size_t name_len = strlen(name) + 1;
        entry->name = fut_malloc(name_len);
        if (!entry->name) { fut_free(entry); return -ENOMEM; }
        memcpy(entry->name, name, name_len);
        entry->value = (size > 0) ? fut_malloc(size) : NULL;
        if (size > 0 && !entry->value) {
            fut_free(entry->name);
            fut_free(entry);
            return -ENOMEM;
        }
        if (size > 0) memcpy(entry->value, value, size);
        entry->size = size;
        entry->next = node->xattrs;
        node->xattrs = entry;
    }

    /* Update ctime on metadata change */
    node->ctime_ms = fut_get_ticks();
    return 0;
}

static ssize_t ramfs_getxattr(struct fut_vnode *vnode, const char *name,
                              void *value, size_t size) {
    struct ramfs_node *node = (struct ramfs_node *)vnode->fs_data;
    if (!node) return -EIO;

    for (struct ramfs_xattr *cur = node->xattrs; cur; cur = cur->next) {
        if (strcmp(cur->name, name) != 0) continue;
        /* Found: size=0 is a query for the required length */
        if (size == 0) return (ssize_t)cur->size;
        if (size < cur->size) return -ERANGE;
        if (cur->size > 0) memcpy(value, cur->value, cur->size);
        return (ssize_t)cur->size;
    }
    return -ENODATA;
}

static ssize_t ramfs_listxattr(struct fut_vnode *vnode, char *list, size_t size) {
    struct ramfs_node *node = (struct ramfs_node *)vnode->fs_data;
    if (!node) return -EIO;

    /* Calculate total bytes needed: each name followed by a NUL byte */
    size_t total = 0;
    for (struct ramfs_xattr *cur = node->xattrs; cur; cur = cur->next) {
        total += strlen(cur->name) + 1;
    }

    if (size == 0) return (ssize_t)total;
    if (size < total) return -ERANGE;

    char *p = list;
    for (struct ramfs_xattr *cur = node->xattrs; cur; cur = cur->next) {
        size_t n = strlen(cur->name) + 1;
        memcpy(p, cur->name, n);
        p += n;
    }
    return (ssize_t)total;
}

static int ramfs_removexattr(struct fut_vnode *vnode, const char *name) {
    struct ramfs_node *node = (struct ramfs_node *)vnode->fs_data;
    if (!node) return -EIO;

    struct ramfs_xattr *prev = NULL;
    struct ramfs_xattr *cur = node->xattrs;
    while (cur) {
        if (strcmp(cur->name, name) == 0) {
            if (prev) prev->next = cur->next;
            else node->xattrs = cur->next;
            fut_free(cur->name);
            if (cur->value) fut_free(cur->value);
            fut_free(cur);
            node->ctime_ms = fut_get_ticks();
            return 0;
        }
        prev = cur;
        cur = cur->next;
    }
    return -ENODATA;
}

/* Vnode operations structure - initialized at runtime to avoid relocation issues on ARM64 */
static struct fut_vnode_ops ramfs_vnode_ops;

/* Initialize ramfs vnode operations */
static void ramfs_init_vnode_ops(void) {
    ramfs_vnode_ops.open = ramfs_open;
    ramfs_vnode_ops.close = ramfs_close;
    ramfs_vnode_ops.read = ramfs_read;
    ramfs_vnode_ops.write = ramfs_write;
    ramfs_vnode_ops.readdir = ramfs_readdir;
    ramfs_vnode_ops.lookup = ramfs_lookup;
    ramfs_vnode_ops.create = ramfs_create;
    ramfs_vnode_ops.unlink = ramfs_unlink;
    ramfs_vnode_ops.mkdir = ramfs_mkdir;
    ramfs_vnode_ops.rmdir = ramfs_rmdir;
    ramfs_vnode_ops.getattr = ramfs_getattr;
    ramfs_vnode_ops.setattr = ramfs_setattr;
    ramfs_vnode_ops.sync = ramfs_sync;
    ramfs_vnode_ops.datasync = ramfs_datasync;
    ramfs_vnode_ops.truncate = ramfs_truncate;
    ramfs_vnode_ops.link = ramfs_link;
    ramfs_vnode_ops.symlink = ramfs_symlink;
    ramfs_vnode_ops.readlink = ramfs_readlink;
    ramfs_vnode_ops.rename = ramfs_rename;
    ramfs_vnode_ops.setxattr = ramfs_setxattr;
    ramfs_vnode_ops.getxattr = ramfs_getxattr;
    ramfs_vnode_ops.listxattr = ramfs_listxattr;
    ramfs_vnode_ops.removexattr = ramfs_removexattr;
}

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
    root->mode = 0;  /* Will be set by vfs_init_vnode_ownership */
    root->size = 0;
    root->nlinks = 2;
    root->mount = mount;
    root->fs_data = root_node;
    root->refcount = 1;
    root->uid = 0;
    root->gid = 0;
    root->parent = NULL;
    root->name = NULL;
    root->ops = &ramfs_vnode_ops;
    vfs_init_vnode_ownership(root, NULL, 0755);
    fut_vnode_lock_init(root);

    fut_vfs_register_root_canary(&guard->before, &guard->after);

    /* Initialize guard values to detect buffer overflows */
    root_node->magic_guard_before = RAMFS_NODE_MAGIC;
    root_node->open_count = 0;
    root_node->atime_ms = fut_get_ticks();
    root_node->mtime_ms = root_node->atime_ms;
    root_node->ctime_ms = root_node->atime_ms;
    root_node->xattrs = NULL;
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

/* Static ramfs type structure - initialized at runtime to avoid relocation issues */
static struct fut_fs_type ramfs_type;

/* ============================================================
 *   RamFS Registration
 * ============================================================ */

void fut_ramfs_init(void) {
    /* Initialize vnode operations first */
    ramfs_init_vnode_ops();

    /* Initialize the ramfs type structure at runtime */
    ramfs_type.name = "ramfs";
    ramfs_type.mount = ramfs_mount;
    ramfs_type.unmount = ramfs_unmount;

    fut_vfs_register_fs(&ramfs_type);
}
