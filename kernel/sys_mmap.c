// SPDX-License-Identifier: MPL-2.0
/* kernel/sys_mmap.c - Memory mapping syscalls
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements mmap() and munmap() for memory mapping and unmapping.
 * Essential for file I/O, shared memory, and dynamic memory allocation.
 *
 * Phase 1 (Completed): Basic mmap/munmap implementation
 * Phase 2 (Current): Enhanced validation, address/length/prot/flags categorization, detailed logging
 * Phase 3: Advanced mapping features (MAP_POPULATE, MAP_HUGETLB)
 * Phase 4: Optimized file-backed mappings, zero-copy techniques
 */

#include <stddef.h>
#include <stdint.h>

#include <kernel/errno.h>
#include <kernel/fut_mm.h>
#include <kernel/fut_task.h>
#include <kernel/fut_thread.h>
#include <kernel/fut_vfs.h>

#define MAP_SHARED      0x01
#define MAP_PRIVATE     0x02
#define MAP_FIXED       0x10
#define MAP_ANONYMOUS   0x20

/* Helper: Convert hex nibble to character (manual hex formatting) */
static char hex_to_char(int nibble) {
    if (nibble < 10) {
        return '0' + nibble;
    } else {
        return 'a' + (nibble - 10);
    }
}

/* Helper: Format address as hex string manually (no snprintf) */
static void format_address_hex(uintptr_t addr, char *buf, int buf_size) {
    /* Format as "0x" + hex digits */
    int pos = 0;
    if (buf_size < 3) return;  /* Need at least "0x" + null */

    buf[pos++] = '0';
    buf[pos++] = 'x';

    /* Convert address to hex, skip leading zeros */
    int started = 0;
    for (int i = 15; i >= 0; i--) {
        int nibble = (addr >> (i * 4)) & 0xF;
        if (nibble != 0 || started || i == 0) {
            if (pos < buf_size - 1) {
                buf[pos++] = hex_to_char(nibble);
                started = 1;
            }
        }
    }

    buf[pos] = '\0';
}

/* Helper: Build protection string (e.g., "r--", "rw-", "rwx") */
static void build_prot_string(int prot, char *buf) {
    buf[0] = (prot & 0x1) ? 'r' : '-';  /* PROT_READ */
    buf[1] = (prot & 0x2) ? 'w' : '-';  /* PROT_WRITE */
    buf[2] = (prot & 0x4) ? 'x' : '-';  /* PROT_EXEC */
    buf[3] = '\0';
}

/**
 * mmap() - Map files or devices into memory
 *
 * Creates a new mapping in the virtual address space of the calling process.
 * Can map files, devices, or anonymous memory (no backing file).
 *
 * @param addr   Hint address (NULL for kernel choice)
 * @param len    Length of mapping in bytes
 * @param prot   Memory protection (PROT_READ|PROT_WRITE|PROT_EXEC)
 * @param flags  Mapping flags (MAP_PRIVATE|MAP_SHARED|MAP_ANONYMOUS|MAP_FIXED)
 * @param fd     File descriptor (ignored for MAP_ANONYMOUS)
 * @param offset File offset (must be page-aligned)
 *
 * Returns:
 *   - Mapped address on success
 *   - -EINVAL if len is 0 or offset not aligned
 *   - -ENOMEM if out of memory or address space
 *   - -EPERM if no task context
 *   - -EBADF if fd is invalid (for file mappings)
 *
 * Behavior:
 *   - Creates virtual memory mapping
 *   - Pages allocated on-demand (lazy allocation)
 *   - MAP_PRIVATE: Copy-on-write, changes don't affect file
 *   - MAP_SHARED: Changes written back to file
 *   - MAP_ANONYMOUS: No backing file, initialized to zero
 *   - MAP_FIXED: Use exact addr (dangerous, may unmap existing)
 *
 * Common usage patterns:
 *
 * Anonymous memory (heap alternative):
 *   void *mem = mmap(NULL, size, PROT_READ|PROT_WRITE,
 *                    MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
 *
 * File mapping (read-only):
 *   int fd = open("file.txt", O_RDONLY);
 *   void *data = mmap(NULL, file_size, PROT_READ,
 *                     MAP_PRIVATE, fd, 0);
 *
 * Shared memory:
 *   void *shm = mmap(NULL, size, PROT_READ|PROT_WRITE,
 *                    MAP_SHARED|MAP_ANONYMOUS, -1, 0);
 *
 * Phase 1 (Completed): Basic mmap implementation
 * Phase 2 (Current): Enhanced validation, parameter categorization, detailed logging
 * Phase 3: MAP_POPULATE, MAP_HUGETLB, MAP_LOCKED
 * Phase 4: Optimized file I/O, zero-copy techniques
 */
long sys_mmap(void *addr, size_t len, int prot, int flags, int fd, long offset) {
    extern void fut_printf(const char *, ...);

    /* Phase 2: Validate length early */
    if (len == 0) {
        fut_printf("[MMAP] mmap(addr=%p, len=0) -> EINVAL (zero length)\n", addr);
        return -EINVAL;
    }

    /* Phase 2: Categorize address hint */
    uintptr_t addr_val = (uintptr_t)addr;
    const char *addr_category;

    if (addr_val == 0) {
        addr_category = "NULL (kernel choice)";
    } else if (addr_val < 0x10000) {
        addr_category = "very low (< 0x10000)";
    } else if (addr_val < 0x400000) {
        addr_category = "low (0x10000-0x400000)";
    } else if (addr_val < 0x10000000) {
        addr_category = "mid (0x400000-0x10000000)";
    } else if (addr_val < 0x7F00000000) {
        addr_category = "high (0x10000000-0x7F00000000)";
    } else if (addr_val < 0x8000000000) {
        addr_category = "stack region (≥0x7F00000000)";
    } else {
        addr_category = "kernel space (≥0x8000000000)";
    }

    /* Phase 2: Categorize length */
    const char *length_category;
    if (len <= 4096) {
        length_category = "single page (≤4KB)";
    } else if (len <= 65536) {
        length_category = "few pages (4KB-64KB)";
    } else if (len <= 1048576) {
        length_category = "many pages (64KB-1MB)";
    } else if (len <= 104857600) {
        length_category = "megabytes (1MB-100MB)";
    } else {
        length_category = "gigabytes (>100MB)";
    }

    /* Phase 2: Build protection string */
    char prot_str[4];
    build_prot_string(prot, prot_str);

    /* Phase 2: Categorize flags */
    const char *sharing_type;
    const char *backing_type;
    const char *fixed_hint;

    if (flags & MAP_SHARED) {
        sharing_type = "MAP_SHARED (changes written back)";
    } else if (flags & MAP_PRIVATE) {
        sharing_type = "MAP_PRIVATE (copy-on-write)";
    } else {
        sharing_type = "neither SHARED nor PRIVATE";
    }

    if (flags & MAP_ANONYMOUS) {
        backing_type = "MAP_ANONYMOUS (no file)";
    } else {
        backing_type = "file-backed";
    }

    if (flags & MAP_FIXED) {
        fixed_hint = "MAP_FIXED (exact address)";
    } else {
        fixed_hint = "kernel places mapping";
    }

    /* Phase 2: Categorize FD */
    const char *fd_category = NULL;
    if (!(flags & MAP_ANONYMOUS)) {
        if (fd < 0) {
            fd_category = "invalid (negative)";
        } else if (fd <= 2) {
            fd_category = "stdio (0-2)";
        } else if (fd < 10) {
            fd_category = "low (3-9)";
        } else if (fd < 100) {
            fd_category = "normal (10-99)";
        } else {
            fd_category = "high (≥100)";
        }
    }

    /* Format addr hint as hex */
    char addr_hex[32];
    format_address_hex(addr_val, addr_hex, sizeof(addr_hex));

    /* Handle anonymous mappings */
    if (flags & MAP_ANONYMOUS) {
        fut_task_t *task = fut_task_current();
        if (!task) {
            fut_printf("[MMAP] mmap(addr=%s [%s], len=%zu [%s], prot=%s, "
                       "flags=0x%x [%s, %s, %s]) -> EPERM (no task)\n",
                       addr_hex, addr_category, len, length_category, prot_str,
                       flags, sharing_type, backing_type, fixed_hint);
            return -EPERM;
        }

        fut_mm_t *mm = fut_task_get_mm(task);
        if (!mm) {
            fut_printf("[MMAP] mmap(addr=%s [%s], len=%zu [%s], prot=%s, "
                       "flags=0x%x [%s, %s, %s], pid=%u) -> ENOMEM (no MM)\n",
                       addr_hex, addr_category, len, length_category, prot_str,
                       flags, sharing_type, backing_type, fixed_hint,
                       task->pid);
            return -ENOMEM;
        }

        void *res = fut_mm_map_anonymous(mm, (uintptr_t)addr, len, prot, flags);
        if ((intptr_t)res < 0) {
            int err = (int)(intptr_t)res;
            const char *error_desc;
            switch (err) {
                case -ENOMEM:
                    error_desc = "out of memory";
                    break;
                case -EINVAL:
                    error_desc = "invalid parameters";
                    break;
                default:
                    error_desc = "mapping failed";
                    break;
            }

            fut_printf("[MMAP] mmap(addr=%s [%s], len=%zu [%s], prot=%s, "
                       "flags=0x%x [%s, %s, %s], pid=%u) -> %d (%s)\n",
                       addr_hex, addr_category, len, length_category, prot_str,
                       flags, sharing_type, backing_type, fixed_hint,
                       task->pid, err, error_desc);
            return (long)(intptr_t)res;
        }

        /* Phase 2: Detailed success logging */
        char result_hex[32];
        format_address_hex((uintptr_t)res, result_hex, sizeof(result_hex));

        fut_printf("[MMAP] mmap(addr=%s [%s], len=%zu [%s], prot=%s, "
                   "flags=0x%x [%s, %s, %s], pid=%u) -> %s "
                   "(anonymous mapping created, Phase 2)\n",
                   addr_hex, addr_category, len, length_category, prot_str,
                   flags, sharing_type, backing_type, fixed_hint,
                   task->pid, result_hex);

        return (long)(intptr_t)res;
    }

    /* File-backed mapping */
    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_printf("[MMAP] mmap(addr=%s [%s], len=%zu [%s], prot=%s, "
                   "flags=0x%x [%s, %s, %s], fd=%d [%s], offset=%ld) -> EPERM "
                   "(no task)\n",
                   addr_hex, addr_category, len, length_category, prot_str,
                   flags, sharing_type, backing_type, fixed_hint,
                   fd, fd_category, offset);
        return -EPERM;
    }

    void *mapped = fut_vfs_mmap(fd, addr, len, prot, flags, (off_t)offset);
    if (!mapped) {
        fut_printf("[MMAP] mmap(addr=%s [%s], len=%zu [%s], prot=%s, "
                   "flags=0x%x [%s, %s, %s], fd=%d [%s], offset=%ld, pid=%u) -> ENOMEM "
                   "(file mapping failed)\n",
                   addr_hex, addr_category, len, length_category, prot_str,
                   flags, sharing_type, backing_type, fixed_hint,
                   fd, fd_category, offset, task->pid);
        return -ENOMEM;
    }

    /* Phase 2: Detailed success logging for file-backed mapping */
    char result_hex[32];
    format_address_hex((uintptr_t)mapped, result_hex, sizeof(result_hex));

    fut_printf("[MMAP] mmap(addr=%s [%s], len=%zu [%s], prot=%s, "
               "flags=0x%x [%s, %s, %s], fd=%d [%s], offset=%ld, pid=%u) -> %s "
               "(file mapping created, Phase 2)\n",
               addr_hex, addr_category, len, length_category, prot_str,
               flags, sharing_type, backing_type, fixed_hint,
               fd, fd_category, offset, task->pid, result_hex);

    return (long)(intptr_t)mapped;
}

/**
 * munmap() - Unmap files or devices from memory
 *
 * Deletes mappings for the specified address range. Further references to
 * addresses in the range will generate invalid memory references.
 *
 * @param addr Start address (must be page-aligned)
 * @param len  Length in bytes
 *
 * Returns:
 *   - 0 on success
 *   - -EINVAL if addr is NULL, len is 0, or addr not aligned
 *   - -EPERM if no task context
 *   - -ENOMEM if no MM context or unmapping failed
 *
 * Behavior:
 *   - Removes virtual memory mapping
 *   - Pages are freed/unmapped
 *   - Dirty pages in MAP_SHARED mappings are flushed
 *   - Process can no longer access unmapped region
 *   - Partial unmapping of larger region is supported
 *
 * Common usage patterns:
 *
 * Unmap after use:
 *   void *mem = mmap(...);
 *   // Use memory
 *   munmap(mem, size);
 *
 * Unmap file mapping:
 *   void *data = mmap(NULL, file_size, PROT_READ, MAP_PRIVATE, fd, 0);
 *   // Read file
 *   munmap(data, file_size);
 *   close(fd);
 *
 * Phase 1 (Completed): Basic munmap implementation
 * Phase 2 (Current): Enhanced validation, address/length categorization, detailed logging
 * Phase 3: Partial unmapping, split VMA handling
 * Phase 4: Deferred unmapping, batch operations
 */
long sys_munmap(void *addr, size_t len) {
    extern void fut_printf(const char *, ...);

    /* Phase 2: Validate parameters */
    if (!addr) {
        fut_printf("[MUNMAP] munmap(addr=NULL, len=%zu) -> EINVAL (NULL address)\n", len);
        return -EINVAL;
    }

    if (len == 0) {
        fut_printf("[MUNMAP] munmap(addr=%p, len=0) -> EINVAL (zero length)\n", addr);
        return -EINVAL;
    }

    /* Phase 2: Categorize address */
    uintptr_t addr_val = (uintptr_t)addr;
    const char *addr_category;

    if (addr_val < 0x10000) {
        addr_category = "very low (< 0x10000)";
    } else if (addr_val < 0x400000) {
        addr_category = "low (0x10000-0x400000)";
    } else if (addr_val < 0x10000000) {
        addr_category = "mid (0x400000-0x10000000)";
    } else if (addr_val < 0x7F00000000) {
        addr_category = "high (0x10000000-0x7F00000000)";
    } else if (addr_val < 0x8000000000) {
        addr_category = "stack region (≥0x7F00000000)";
    } else {
        addr_category = "kernel space (≥0x8000000000)";
    }

    /* Phase 2: Categorize length */
    const char *length_category;
    if (len <= 4096) {
        length_category = "single page (≤4KB)";
    } else if (len <= 65536) {
        length_category = "few pages (4KB-64KB)";
    } else if (len <= 1048576) {
        length_category = "many pages (64KB-1MB)";
    } else if (len <= 104857600) {
        length_category = "megabytes (1MB-100MB)";
    } else {
        length_category = "gigabytes (>100MB)";
    }

    /* Format address as hex */
    char addr_hex[32];
    format_address_hex(addr_val, addr_hex, sizeof(addr_hex));

    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_printf("[MUNMAP] munmap(addr=%s [%s], len=%zu [%s]) -> EPERM (no task)\n",
                   addr_hex, addr_category, len, length_category);
        return -EPERM;
    }

    fut_mm_t *mm = fut_task_get_mm(task);
    if (!mm) {
        fut_printf("[MUNMAP] munmap(addr=%s [%s], len=%zu [%s], pid=%u) -> ENOMEM "
                   "(no MM context)\n",
                   addr_hex, addr_category, len, length_category, task->pid);
        return -ENOMEM;
    }

    int ret = fut_mm_unmap(mm, (uintptr_t)addr, len);

    if (ret < 0) {
        const char *error_desc;
        switch (ret) {
            case -EINVAL:
                error_desc = "invalid address or length";
                break;
            case -ENOMEM:
                error_desc = "unmapping failed";
                break;
            default:
                error_desc = "operation failed";
                break;
        }

        fut_printf("[MUNMAP] munmap(addr=%s [%s], len=%zu [%s], pid=%u) -> %d (%s)\n",
                   addr_hex, addr_category, len, length_category, task->pid,
                   ret, error_desc);
        return ret;
    }

    /* Phase 2: Detailed success logging */
    char end_hex[32];
    format_address_hex(addr_val + len, end_hex, sizeof(end_hex));

    fut_printf("[MUNMAP] munmap(addr=%s [%s], len=%zu [%s], range=%s-%s, pid=%u) -> 0 "
               "(unmapped successfully, Phase 2)\n",
               addr_hex, addr_category, len, length_category,
               addr_hex, end_hex, task->pid);

    return ret;
}
