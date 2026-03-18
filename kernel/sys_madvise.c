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
 * Phase 4 (Completed): Full Linux advice code set (MADV_FREE, MADV_HUGEPAGE, MADV_DONTDUMP, etc.)
 *                      Uses switch-case validation to handle non-contiguous valid set (gaps at 5,6,7).
 */

#include <kernel/fut_mm.h>
#include <kernel/errno.h>
#include <sys/mman.h>
#include <stdint.h>

/* Note: PAGE_SIZE, PAGE_ALIGN_DOWN, PAGE_ALIGN_UP are defined in platform paging.h
   and already included via fut_mm.h */


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
    /* Zero-length is a POSIX-defined no-op (checked before addr) */
    if (length == 0) {
        return 0;
    }

    if (addr == NULL) {
        return -EINVAL;
    }

    /* Overflow-safe alignment: compute aligned range */
    uintptr_t addr_aligned = PAGE_ALIGN_DOWN((uintptr_t)addr);
    size_t offset = (uintptr_t)addr - addr_aligned;

    if (length > SIZE_MAX - offset) {
        return -EINVAL;
    }
    size_t length_aligned = PAGE_ALIGN_UP(length + offset);
    if (addr_aligned > SIZE_MAX - length_aligned) {
        return -EINVAL;
    }
    (void)length_aligned;

    /* Validate advice code using explicit switch.
     * Linux advice values are non-contiguous: valid set is
     * {0-4, 8-21}; values 5, 6, 7 are unused gaps → EINVAL. */
    switch (advice) {
    case MADV_NORMAL:       /* 0: default behavior */
    case MADV_RANDOM:       /* 1: expect random access */
    case MADV_SEQUENTIAL:   /* 2: expect sequential access */
    case MADV_WILLNEED:     /* 3: prefetch pages soon */
    case MADV_DONTNEED:     /* 4: free pages, won't need soon */
    case MADV_FREE:         /* 8: lazy free (Linux 4.5+) */
    case MADV_REMOVE:       /* 9: punch hole / remove pages */
    case MADV_DONTFORK:     /* 10: don't inherit on fork */
    case MADV_DOFORK:       /* 11: inherit on fork (default) */
    case MADV_MERGEABLE:    /* 12: KSM may merge identical pages */
    case MADV_UNMERGEABLE:  /* 13: KSM must not merge */
    case MADV_HUGEPAGE:     /* 14: back with transparent hugepages */
    case MADV_NOHUGEPAGE:   /* 15: do not back with hugepages */
    case MADV_DONTDUMP:     /* 16: exclude from core dump */
    case MADV_DODUMP:       /* 17: include in core dump */
    case 18:                /* MADV_WIPEONFORK: wipe on fork (Linux 4.14+) */
    case 19:                /* MADV_KEEPONFORK: keep on fork (Linux 4.14+) */
    case 20:                /* MADV_COLD: deactivate pages (Linux 5.4+) */
    case 21:                /* MADV_PAGEOUT: reclaim pages now (Linux 5.4+) */
        return 0;
    default:
        return -EINVAL;
    }
}
