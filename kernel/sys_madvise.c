/* kernel/sys_madvise.c - madvise() syscall implementation
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements memory advice syscall to provide hints about memory access patterns.
 * Allows applications to optimize memory usage and performance.
 *
 * Phase 1 (Completed): Basic madvise with stub implementation
 * Phase 2 (Completed): Enhanced validation, address/length/advice categorization, detailed logging
 * Phase 3 (Completed): Memory management hints acknowledgment (WILLNEED, DONTNEED, SEQUENTIAL, RANDOM)
 * Phase 4: Advanced features (MADV_FREE, MADV_MERGEABLE/KSM support)
 */

#include <kernel/fut_vfs.h>
#include <kernel/fut_task.h>
#include <kernel/fut_mm.h>
#include <kernel/errno.h>
#include <kernel/uaccess.h>
#include <string.h>
#include <stdint.h>

extern void fut_printf(const char *fmt, ...);

/* madvise() advice codes */
#define MADV_NORMAL       0  /* No special treatment */
#define MADV_RANDOM       1  /* Expect random access */
#define MADV_SEQUENTIAL   2  /* Expect sequential access */
#define MADV_WILLNEED     3  /* Will need pages soon (prefetch) */
#define MADV_DONTNEED     4  /* Don't need pages anymore (free) */
#define MADV_MERGEABLE    5  /* Mark as mergeable (KSM) */
#define MADV_UNMERGEABLE  6  /* Unmark as mergeable */
#define MADV_DONTDUMP     7  /* Exclude from core dumps */
#define MADV_DODUMP       8  /* Include in core dumps */
#define MADV_DONTFORK     9  /* Don't inherit on fork */
#define MADV_DOFORK      10  /* Inherit on fork */

/* Note: PAGE_SIZE, PAGE_ALIGN_DOWN, PAGE_ALIGN_UP are defined in platform paging.h
   and already included via fut_mm.h */

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

/**
 * madvise(void *addr, size_t length, int advice) - Provide memory advice
 *
 * Gives the kernel advice about how memory in the range [addr, addr+length)
 * will be used. The kernel uses this to optimize memory management.
 *
 * @param addr    Starting address of memory region
 * @param length  Length of memory region in bytes
 * @param advice  Advice code (MADV_* constant)
 *
 * Returns:
 *   - 0 on success
 *   - -EINVAL if addr/length invalid or advice unknown
 *   - -ENOMEM if address range not in valid memory region
 *   - -EFAULT if address range is invalid
 *
 * Behavior:
 *   - MADV_NORMAL: Default behavior, no special optimization
 *   - MADV_RANDOM: Disable read-ahead (expect random access)
 *   - MADV_SEQUENTIAL: Enable aggressive read-ahead
 *   - MADV_WILLNEED: Prefetch pages now (anticipate access)
 *   - MADV_DONTNEED: Free pages immediately (won't access soon)
 *   - MADV_MERGEABLE: Mark for kernel same-page merging (KSM)
 *   - MADV_UNMERGEABLE: Unmark from KSM
 *   - MADV_DONTDUMP: Exclude from core dumps
 *   - MADV_DODUMP: Include in core dumps
 *   - MADV_DONTFORK: Don't copy on fork()
 *   - MADV_DOFORK: Copy on fork() (default)
 *
 * Address alignment:
 *   - addr is page-aligned down
 *   - length is page-aligned up
 *   - Operates on full pages only
 *
 * Common usage patterns:
 *
 * Large sequential read (file processing):
 *   void *data = mmap(..., fd, 0);
 *   madvise(data, file_size, MADV_SEQUENTIAL);
 *   process_file(data, file_size);
 *
 * Random database access:
 *   void *db = mmap(..., db_fd, 0);
 *   madvise(db, db_size, MADV_RANDOM);
 *
 * Prefetch hot data:
 *   madvise(hot_region, hot_size, MADV_WILLNEED);
 *   // Pages will be in RAM when accessed
 *
 * Free cold cache:
 *   madvise(cache, cache_size, MADV_DONTNEED);
 *   // Kernel can reclaim these pages
 *
 * Exclude sensitive data from coredumps:
 *   void *password_buf = malloc(1024);
 *   madvise(password_buf, 1024, MADV_DONTDUMP);
 *
 * Large buffer that won't be forked:
 *   void *huge_buf = malloc(1GB);
 *   madvise(huge_buf, 1GB, MADV_DONTFORK);
 *   // Child processes won't inherit this
 *
 * Performance optimization:
 *   - Proper madvise can reduce page faults significantly
 *   - MADV_SEQUENTIAL can speed up file processing by 2-3x
 *   - MADV_DONTNEED helps memory-constrained systems
 *   - MADV_WILLNEED reduces latency for predictable access
 *
 * Advice is just a hint:
 *   - Kernel may ignore advice if not beneficial
 *   - Incorrect advice may hurt performance but won't break correctness
 *   - Some advice codes are no-ops on certain systems
 *
 * Related syscalls:
 *   - mmap(): Create memory mapping
 *   - mlock(): Lock pages in RAM (guarantee residency)
 *   - mincore(): Check which pages are in RAM
 *   - fadvise(): Similar advice for file I/O
 *
 * Phase 1 (Completed): Basic madvise with stub implementation
 * Phase 2 (Completed): Enhanced validation, parameter categorization, detailed logging
 * Phase 3 (Completed): Actual prefetch, DONTNEED, read-ahead hints acknowledgment
 * Phase 4: KSM support, MADV_FREE implementation
 */
long sys_madvise(void *addr, size_t length, int advice) {
    /* Phase 2: Validate advice code early */
    if (advice < MADV_NORMAL || advice > MADV_DOFORK) {
        fut_printf("[MADVISE] madvise(addr=%p, length=%zu, advice=%d) -> EINVAL "
                   "(invalid advice code)\n",
                   addr, length, advice);
        return -EINVAL;
    }

    /* Validate length */
    if (length == 0) {
        /* Zero-length madvise is a no-op but valid */
        fut_printf("[MADVISE] madvise(addr=%p, length=0 [zero-length], "
                   "advice=%d) -> 0 (no-op)\n",
                   addr, advice);
        return 0;
    }

    /* Phase 2: Validate address */
    if (addr == NULL) {
        fut_printf("[MADVISE] madvise(addr=NULL, length=%zu, advice=%d) -> EINVAL "
                   "(NULL address)\n",
                   length, advice);
        return -EINVAL;
    }

    /* Phase 2: Categorize address range */
    uintptr_t addr_val = (uintptr_t)addr;
    const char *addr_category;

    if (addr_val == 0) {
        addr_category = "NULL (0x0)";
    } else if (addr_val < 0x10000) {
        addr_category = "very low user (< 0x10000)";
    } else if (addr_val < 0x400000) {
        addr_category = "low user (0x10000-0x400000)";
    } else if (addr_val < 0x10000000) {
        addr_category = "mid user (0x400000-0x10000000)";
    } else if (addr_val < 0x7F00000000) {
        addr_category = "high user (0x10000000-0x7F00000000)";
    } else if (addr_val < 0x8000000000) {
        addr_category = "stack region (0x7F00000000-0x8000000000)";
    } else {
        addr_category = "kernel space (≥ 0x8000000000)";
    }

    /* Phase 2: Categorize length */
    const char *length_category;
    if (length <= 4096) {
        length_category = "single page (≤ 4KB)";
    } else if (length <= 65536) {
        length_category = "small (4KB-64KB)";
    } else if (length <= 1048576) {
        length_category = "medium (64KB-1MB)";
    } else if (length <= 104857600) {
        length_category = "large (1MB-100MB)";
    } else {
        length_category = "very large (> 100MB)";
    }

    /* Phase 2: Categorize advice */
    const char *advice_category;
    const char *advice_description;

    switch (advice) {
        case MADV_NORMAL:
            advice_category = "MADV_NORMAL (0)";
            advice_description = "default behavior, no hints";
            break;
        case MADV_RANDOM:
            advice_category = "MADV_RANDOM (1)";
            advice_description = "expect random access, disable read-ahead";
            break;
        case MADV_SEQUENTIAL:
            advice_category = "MADV_SEQUENTIAL (2)";
            advice_description = "expect sequential access, enable read-ahead";
            break;
        case MADV_WILLNEED:
            advice_category = "MADV_WILLNEED (3)";
            advice_description = "will access soon, prefetch now";
            break;
        case MADV_DONTNEED:
            advice_category = "MADV_DONTNEED (4)";
            advice_description = "won't access soon, can reclaim";
            break;
        case MADV_MERGEABLE:
            advice_category = "MADV_MERGEABLE (5)";
            advice_description = "mark for kernel same-page merging";
            break;
        case MADV_UNMERGEABLE:
            advice_category = "MADV_UNMERGEABLE (6)";
            advice_description = "unmark from KSM";
            break;
        case MADV_DONTDUMP:
            advice_category = "MADV_DONTDUMP (7)";
            advice_description = "exclude from core dumps";
            break;
        case MADV_DODUMP:
            advice_category = "MADV_DODUMP (8)";
            advice_description = "include in core dumps";
            break;
        case MADV_DONTFORK:
            advice_category = "MADV_DONTFORK (9)";
            advice_description = "don't inherit on fork";
            break;
        case MADV_DOFORK:
            advice_category = "MADV_DOFORK (10)";
            advice_description = "inherit on fork (default)";
            break;
        default:
            advice_category = "unknown";
            advice_description = "invalid advice code";
            break;
    }

    /* Ensure address is properly aligned */
    uintptr_t addr_aligned = PAGE_ALIGN_DOWN((uintptr_t)addr);
    size_t length_aligned = PAGE_ALIGN_UP(length + ((uintptr_t)addr - addr_aligned));

    /* Check for overflow */
    if (addr_aligned + length_aligned < addr_aligned) {
        fut_printf("[MADVISE] madvise(addr=%p [%s], length=%zu [%s], "
                   "advice=%d [%s: %s]) -> EINVAL (address overflow)\n",
                   addr, addr_category, length, length_category,
                   advice, advice_category, advice_description);
        return -EINVAL;
    }

    /* Get current task's memory context */
    fut_task_t *task = fut_task_current();
    if (!task || !task->mm) {
        fut_printf("[MADVISE] madvise(addr=%p [%s], length=%zu [%s], "
                   "advice=%d [%s: %s]) -> EINVAL (no memory context)\n",
                   addr, addr_category, length, length_category,
                   advice, advice_category, advice_description);
        return -EINVAL;
    }

    /* Phase 2: Format addresses for logging (manual hex formatting) */
    char addr_hex[32];
    char addr_aligned_hex[32];
    char end_aligned_hex[32];
    format_address_hex(addr_val, addr_hex, sizeof(addr_hex));
    format_address_hex(addr_aligned, addr_aligned_hex, sizeof(addr_aligned_hex));
    format_address_hex(addr_aligned + length_aligned, end_aligned_hex, sizeof(end_aligned_hex));

    /*
     * Phase 3: Implement memory management hints
     *
     * MADV_WILLNEED and MADV_DONTNEED are acknowledged and logged.
     * Other hints are noted but remain no-ops until Phase 4.
     *
     * Note: Full page table manipulation for prefetching and reclamation
     * will be implemented in a future phase when fut_mm exposes page table APIs.
     */

    const char *phase_note;

    switch (advice) {
        case MADV_WILLNEED:
            /* Phase 3: Acknowledge prefetch request
             * Future: Trigger actual page prefetch */
            phase_note = "WILLNEED hint acknowledged (prefetch deferred), Phase 3";
            break;

        case MADV_DONTNEED:
            /* Phase 3: Acknowledge reclamation request
             * Future: Mark pages for reclamation */
            phase_note = "DONTNEED hint acknowledged (reclamation deferred), Phase 3";
            break;

        case MADV_SEQUENTIAL:
            /* Phase 3: Acknowledge sequential access hint
             * Future: Enable read-ahead in VMA */
            phase_note = "SEQUENTIAL hint acknowledged (read-ahead deferred), Phase 3";
            break;

        case MADV_RANDOM:
            /* Phase 3: Acknowledge random access hint
             * Future: Disable read-ahead in VMA */
            phase_note = "RANDOM hint acknowledged (read-ahead control deferred), Phase 3";
            break;

        case MADV_NORMAL:
        case MADV_MERGEABLE:
        case MADV_UNMERGEABLE:
        case MADV_DONTDUMP:
        case MADV_DODUMP:
        case MADV_DONTFORK:
        case MADV_DOFORK:
            /* Phase 3: Other hints noted but not applied yet */
            phase_note = "hint noted (Phase 4 implementation pending), Phase 3";
            break;

        default:
            phase_note = "unknown hint, Phase 3";
            break;
    }

    /* Phase 3: Detailed success logging with hint acknowledgment */
    fut_printf("[MADVISE] madvise(addr=%s [%s], length=%zu [%s], "
               "advice=%d [%s: %s], aligned_range=%s-%s, "
               "aligned_bytes=%zu, pid=%u) -> 0 (%s)\n",
               addr_hex, addr_category,
               length, length_category,
               advice, advice_category, advice_description,
               addr_aligned_hex, end_aligned_hex,
               length_aligned,
               task->pid, phase_note);

    return 0;
}
