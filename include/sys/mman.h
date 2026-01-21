// SPDX-License-Identifier: MPL-2.0
/*
 * sys/mman.h - Memory management declarations
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Provides constants for mmap, mprotect, msync, madvise, mlock,
 * and related memory management functions.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

/* ============================================================
 *   Memory Protection Flags (for mmap/mprotect)
 * ============================================================ */

#ifndef PROT_NONE
#define PROT_NONE   0x0     /* Page cannot be accessed */
#endif
#ifndef PROT_READ
#define PROT_READ   0x1     /* Page can be read */
#endif
#ifndef PROT_WRITE
#define PROT_WRITE  0x2     /* Page can be written */
#endif
#ifndef PROT_EXEC
#define PROT_EXEC   0x4     /* Page can be executed */
#endif

/* ============================================================
 *   Mapping Type Flags (for mmap)
 * ============================================================ */

#ifndef MAP_SHARED
#define MAP_SHARED      0x01    /* Share changes */
#endif
#ifndef MAP_PRIVATE
#define MAP_PRIVATE     0x02    /* Changes are private (copy-on-write) */
#endif
#ifndef MAP_FIXED
#define MAP_FIXED       0x10    /* Interpret addr exactly */
#endif
#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS   0x20    /* Don't use a file */
#endif
#ifndef MAP_ANON
#define MAP_ANON        MAP_ANONYMOUS   /* BSD alias */
#endif

/* Additional mapping flags */
#ifndef MAP_NORESERVE
#define MAP_NORESERVE   0x4000  /* Don't reserve swap space for this mapping */
#endif
#ifndef MAP_GROWSDOWN
#define MAP_GROWSDOWN   0x0100  /* Stack-like segment */
#endif
#ifndef MAP_DENYWRITE
#define MAP_DENYWRITE   0x0800  /* ETXTBSY */
#endif
#ifndef MAP_LOCKED
#define MAP_LOCKED      0x2000  /* Lock pages into memory */
#endif
#ifndef MAP_POPULATE
#define MAP_POPULATE    0x8000  /* Populate (prefault) page tables */
#endif
#ifndef MAP_NONBLOCK
#define MAP_NONBLOCK    0x10000 /* Don't block on IO */
#endif
#ifndef MAP_STACK
#define MAP_STACK       0x20000 /* Give out an address that is best suited for stack */
#endif
#ifndef MAP_HUGETLB
#define MAP_HUGETLB     0x40000 /* Create huge page mapping */
#endif

/* Return value for mmap on failure */
#ifndef MAP_FAILED
#define MAP_FAILED      ((void *)-1)
#endif

/* ============================================================
 *   Remap Flags (for mremap)
 * ============================================================ */

#ifndef MREMAP_MAYMOVE
#define MREMAP_MAYMOVE      1   /* Allow moving to new virtual address */
#endif
#ifndef MREMAP_FIXED
#define MREMAP_FIXED        2   /* Place mapping at exact address (requires MREMAP_MAYMOVE) */
#endif
#ifndef MREMAP_DONTUNMAP
#define MREMAP_DONTUNMAP    4   /* Don't unmap old mapping (Linux 5.7+) */
#endif

/* ============================================================
 *   Synchronization Flags (for msync)
 * ============================================================ */

#ifndef MS_ASYNC
#define MS_ASYNC        1   /* Schedule sync but return immediately */
#endif
#ifndef MS_INVALIDATE
#define MS_INVALIDATE   2   /* Invalidate cached data */
#endif
#ifndef MS_SYNC
#define MS_SYNC         4   /* Wait for sync to complete */
#endif

/* ============================================================
 *   Memory Advice Flags (for madvise)
 * ============================================================ */

#ifndef MADV_NORMAL
#define MADV_NORMAL         0   /* No special treatment */
#endif
#ifndef MADV_RANDOM
#define MADV_RANDOM         1   /* Expect random access */
#endif
#ifndef MADV_SEQUENTIAL
#define MADV_SEQUENTIAL     2   /* Expect sequential access */
#endif
#ifndef MADV_WILLNEED
#define MADV_WILLNEED       3   /* Will need pages soon (prefetch) */
#endif
#ifndef MADV_DONTNEED
#define MADV_DONTNEED       4   /* Don't need pages anymore (free) */
#endif
#ifndef MADV_FREE
#define MADV_FREE           8   /* Free pages only when memory pressure */
#endif
#ifndef MADV_REMOVE
#define MADV_REMOVE         9   /* Remove these pages and resources */
#endif
#ifndef MADV_DONTFORK
#define MADV_DONTFORK       10  /* Don't inherit across fork */
#endif
#ifndef MADV_DOFORK
#define MADV_DOFORK         11  /* Inherit across fork (default) */
#endif
#ifndef MADV_MERGEABLE
#define MADV_MERGEABLE      12  /* KSM may merge identical pages */
#endif
#ifndef MADV_UNMERGEABLE
#define MADV_UNMERGEABLE    13  /* KSM may not merge identical pages */
#endif
#ifndef MADV_HUGEPAGE
#define MADV_HUGEPAGE       14  /* Worth backing with hugepages */
#endif
#ifndef MADV_NOHUGEPAGE
#define MADV_NOHUGEPAGE     15  /* Not worth backing with hugepages */
#endif
#ifndef MADV_DONTDUMP
#define MADV_DONTDUMP       16  /* Exclude from core dump */
#endif
#ifndef MADV_DODUMP
#define MADV_DODUMP         17  /* Include in core dump (default) */
#endif

/* ============================================================
 *   Memory Lock Flags (for mlockall)
 * ============================================================ */

#ifndef MCL_CURRENT
#define MCL_CURRENT     1   /* Lock currently mapped pages */
#endif
#ifndef MCL_FUTURE
#define MCL_FUTURE      2   /* Lock future mappings */
#endif
#ifndef MCL_ONFAULT
#define MCL_ONFAULT     4   /* Lock pages only when they are faulted in */
#endif

/* ============================================================
 *   Function Declarations
 * ============================================================ */

extern void *mmap(void *addr, size_t length, int prot, int flags,
                  int fd, long offset);
extern int munmap(void *addr, size_t length);
extern int mprotect(void *addr, size_t len, int prot);
extern int msync(void *addr, size_t length, int flags);
extern int madvise(void *addr, size_t length, int advice);
extern int mlock(const void *addr, size_t len);
extern int munlock(const void *addr, size_t len);
extern int mlockall(int flags);
extern int munlockall(void);
extern void *mremap(void *old_address, size_t old_size,
                    size_t new_size, int flags, ...);
extern int mincore(void *addr, size_t length, unsigned char *vec);

