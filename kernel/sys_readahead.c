/* kernel/sys_readahead.c - Read-ahead hint syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements readahead() to prefetch file data into the page cache,
 * populating shared page cache entries so subsequent mmap faults and
 * reads hit cached pages instead of triggering on-demand I/O.
 *
 * Linux syscall number: 187 (x86_64), 213 (ARM64)
 */

#include <kernel/fut_task.h>
#include <kernel/fut_vfs.h>
#include <kernel/fut_memory.h>
#include <kernel/errno.h>
#include <kernel/kprintf.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>

#ifdef __x86_64__
#include <platform/x86_64/memory/pmap.h>
#elif defined(__aarch64__)
#include <platform/arm64/memory/pmap.h>
#endif

/* Page cache operations from page_fault.c */
extern void shared_page_insert(struct fut_vnode *vnode, uint64_t offset, phys_addr_t phys);
extern phys_addr_t shared_page_lookup(struct fut_vnode *vnode, uint64_t offset);

/* PMM allocation */
extern void *fut_pmm_alloc_page(void);
extern void  fut_pmm_free_page(void *page);

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

/**
 * readahead() - Initiate read-ahead on a file
 *
 * @param fd      File descriptor to read ahead
 * @param offset  Starting offset for read-ahead
 * @param count   Number of bytes to read ahead
 *
 * Returns 0 on success, negative errno on failure.
 *
 * Reads the specified range of the file into the shared page cache.
 * Subsequent page faults or reads on this region will find pages already
 * present, avoiding synchronous I/O on the fault path.
 */
long sys_readahead(int fd, int64_t offset, size_t count) {
    if (fd < 0)
        return -EBADF;

    if (offset < 0)
        return -EINVAL;

    struct fut_file *file = fut_vfs_get_file(fd);
    if (!file)
        return -EBADF;

    /* O_PATH fds cannot be used for I/O — only path-based operations */
    if (file->flags & O_PATH)
        return -EBADF;

    /* readahead requires the fd to be readable */
    if ((file->flags & O_ACCMODE) == O_WRONLY)
        return -EBADF;

    /* Linux's ksys_readahead rejects everything that is not a regular
     * file with -EINVAL (man readahead(2): 'fd does not refer to a file
     * type to which readahead() can be applied').  Directories, block
     * and character devices, FIFOs, sockets, and symlinks all fall
     * outside the readahead contract — their page caches don't honour
     * a 'prefetch into shared mapping' hint.  The previous code only
     * rejected FIFO/SOCK and silently returned 0 for everything else,
     * so a caller probing readahead() on a directory got 'success'
     * without any pages actually being prefetched. */
    if (!file->vnode || file->vnode->type != VN_REG)
        return -EINVAL;

    /* Need a vnode with read capability to prefetch pages */
    struct fut_vnode *vnode = file->vnode;
    if (!vnode || !vnode->ops || !vnode->ops->read)
        return 0;  /* No file backing — hint accepted as no-op */

    /* Clamp count to 2 MB to prevent excessive prefetch from a single call */
    if (count > (2u * 1024u * 1024u))
        count = 2u * 1024u * 1024u;

    /* Zero count is a valid no-op */
    if (count == 0)
        return 0;

    /* Prefetch page-aligned range into shared page cache */
    uint64_t start = (uint64_t)offset & ~((uint64_t)PAGE_SIZE - 1);
    uint64_t end   = ((uint64_t)offset + count + PAGE_SIZE - 1) & ~((uint64_t)PAGE_SIZE - 1);

    /* Don't read past end of file */
    if (end > vnode->size)
        end = (vnode->size + PAGE_SIZE - 1) & ~((uint64_t)PAGE_SIZE - 1);

    for (uint64_t page_off = start; page_off < end; page_off += PAGE_SIZE) {
        /* Skip if already cached */
        if (shared_page_lookup(vnode, page_off) != 0)
            continue;

        /* Allocate a physical page */
        void *page = fut_pmm_alloc_page();
        if (!page)
            break;  /* Out of memory — stop prefetching, not an error */

        memset(page, 0, PAGE_SIZE);

        /* Read file contents into the page */
        ssize_t bytes_read = vnode->ops->read(vnode, page, PAGE_SIZE, page_off);
        if (bytes_read <= 0) {
            fut_pmm_free_page(page);
            break;  /* EOF or error — stop prefetching */
        }

        /* Insert into shared page cache so demand-paging finds it */
        phys_addr_t phys = pmap_virt_to_phys((uintptr_t)page);
        shared_page_insert(vnode, page_off, phys);
    }

    return 0;
}
