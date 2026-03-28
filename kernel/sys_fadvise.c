/* kernel/sys_fadvise.c - File access pattern advisory
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements fadvise64() to allow applications to hint about their
 * intended file access patterns, enabling I/O optimization.
 *
 * Supported advisories:
 *   POSIX_FADV_SEQUENTIAL: Set VMA_SEQ_READ on file-backed VMAs
 *   POSIX_FADV_RANDOM:     Set VMA_RAND_READ on file-backed VMAs
 *   POSIX_FADV_WILLNEED:   Trigger readahead into page cache
 *   POSIX_FADV_DONTNEED:   Evict pages from the shared page cache
 *   POSIX_FADV_NORMAL:     Clear access-pattern flags
 *   POSIX_FADV_NOREUSE:    Accepted (no-op, valid per POSIX)
 */

#include <kernel/fut_task.h>
#include <kernel/fut_vfs.h>
#include <kernel/fut_mm.h>
#include <kernel/fut_memory.h>
#include <kernel/errno.h>
#include <kernel/kprintf.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>

/* POSIX_FADV_* constants (Linux ABI) */
#define POSIX_FADV_NORMAL     0  /* No special treatment */
#define POSIX_FADV_RANDOM     1  /* Expect random access */
#define POSIX_FADV_SEQUENTIAL 2  /* Expect sequential access */
#define POSIX_FADV_WILLNEED   3  /* Will need this data soon */
#define POSIX_FADV_DONTNEED   4  /* Don't need this data anymore */
#define POSIX_FADV_NOREUSE    5  /* Data will be accessed once */

/* Page cache operations from page_fault.c */
extern void shared_page_insert(struct fut_vnode *vnode, uint64_t offset, phys_addr_t phys);
extern phys_addr_t shared_page_lookup(struct fut_vnode *vnode, uint64_t offset);
extern void shared_page_evict(struct fut_vnode *vnode, uint64_t offset);

/* PMM allocation */
extern void *fut_pmm_alloc_page(void);
extern void  fut_pmm_free_page(void *page);

/* Physical address conversion */
extern phys_addr_t pmap_virt_to_phys(uintptr_t vaddr);

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

/**
 * Apply access-pattern VMA flags to all VMAs that map a given vnode.
 * POSIX_FADV_SEQUENTIAL sets VMA_SEQ_READ, POSIX_FADV_RANDOM sets
 * VMA_RAND_READ, and POSIX_FADV_NORMAL clears both.
 */
static void fadvise_set_vma_flags(struct fut_vnode *vnode, int advice) {
    fut_mm_t *mm = fut_mm_current();
    if (!mm)
        return;

    fut_spinlock_acquire(&mm->mm_lock);
    struct fut_vma *vma = mm->vma_list;
    while (vma) {
        if (vma->vnode == vnode) {
            switch (advice) {
            case POSIX_FADV_SEQUENTIAL:
                vma->flags &= ~VMA_RAND_READ;
                vma->flags |= VMA_SEQ_READ;
                break;
            case POSIX_FADV_RANDOM:
                vma->flags &= ~VMA_SEQ_READ;
                vma->flags |= VMA_RAND_READ;
                break;
            case POSIX_FADV_NORMAL:
                vma->flags &= ~(VMA_SEQ_READ | VMA_RAND_READ);
                break;
            default:
                break;
            }
        }
        vma = vma->next;
    }
    fut_spinlock_release(&mm->mm_lock);
}

/**
 * Prefetch a range of a file into the shared page cache.
 * Used by POSIX_FADV_WILLNEED.  Delegates to the same page cache
 * infrastructure that readahead() uses.
 */
static void fadvise_willneed(struct fut_vnode *vnode, uint64_t start, uint64_t end) {
    if (!vnode->ops || !vnode->ops->read)
        return;

    /* Clamp to file size */
    if (end > vnode->size)
        end = (vnode->size + PAGE_SIZE - 1) & ~((uint64_t)PAGE_SIZE - 1);

    /* Cap prefetch to 2 MB per call */
    if (end - start > 2u * 1024u * 1024u)
        end = start + 2u * 1024u * 1024u;

    for (uint64_t off = start; off < end; off += PAGE_SIZE) {
        if (shared_page_lookup(vnode, off) != 0)
            continue;

        void *page = fut_pmm_alloc_page();
        if (!page)
            break;

        memset(page, 0, PAGE_SIZE);
        ssize_t n = vnode->ops->read(vnode, page, PAGE_SIZE, off);
        if (n <= 0) {
            fut_pmm_free_page(page);
            break;
        }

        phys_addr_t phys = pmap_virt_to_phys((uintptr_t)page);
        shared_page_insert(vnode, off, phys);
    }
}

/**
 * Evict pages from the shared page cache for a file range.
 * Used by POSIX_FADV_DONTNEED to release memory that the application
 * declares it no longer needs.
 */
static void fadvise_dontneed(struct fut_vnode *vnode, uint64_t start, uint64_t end) {
    for (uint64_t off = start; off < end; off += PAGE_SIZE) {
        shared_page_evict(vnode, off);
    }
}

/**
 * sys_fadvise64 - Provide file access advisory
 *
 * @param fd:     File descriptor
 * @param offset: Starting offset of advisory region
 * @param len:    Length of advisory region (0 = to end of file)
 * @param advice: Advisory hint (POSIX_FADV_*)
 *
 * Unlike most syscalls, fadvise64 returns error codes directly
 * (not negated) per POSIX. However Linux returns negative errno,
 * and we follow Linux convention for consistency.
 *
 * Returns:
 *   - 0 on success (advisory accepted)
 *   - -EBADF if fd is invalid
 *   - -EINVAL if advice is unknown
 *   - -ESPIPE if fd refers to a pipe or socket
 */
long sys_fadvise64(int fd, int64_t offset, int64_t len, int advice) {
    /* Validate advice parameter */
    if (advice < POSIX_FADV_NORMAL || advice > POSIX_FADV_NOREUSE) {
        return -EINVAL;
    }

    /* Validate offset and length */
    if (offset < 0 || len < 0) {
        return -EINVAL;
    }

    /* Validate fd */
    if (fd < 0) {
        return -EBADF;
    }

    struct fut_file *file = fut_vfs_get_file(fd);
    if (!file) {
        return -EBADF;
    }

    /* O_PATH fds cannot be used for I/O — only path-based operations */
    if (file->flags & O_PATH)
        return -EBADF;

    /* Pipes and sockets are not seekable — fadvise doesn't apply */
    if (file->vnode && (file->vnode->type == VN_FIFO || file->vnode->type == VN_SOCK)) {
        return -ESPIPE;
    }

    struct fut_vnode *vnode = file->vnode;

    /* Compute page-aligned range.  len == 0 means "to end of file". */
    uint64_t start = (uint64_t)offset & ~((uint64_t)PAGE_SIZE - 1);
    uint64_t end;
    if (len == 0 && vnode) {
        end = (vnode->size + PAGE_SIZE - 1) & ~((uint64_t)PAGE_SIZE - 1);
    } else {
        end = ((uint64_t)offset + (uint64_t)len + PAGE_SIZE - 1) & ~((uint64_t)PAGE_SIZE - 1);
    }

    switch (advice) {
    case POSIX_FADV_SEQUENTIAL:
    case POSIX_FADV_RANDOM:
    case POSIX_FADV_NORMAL:
        /* Set or clear VMA access-pattern flags on all VMAs backed by this vnode */
        if (vnode)
            fadvise_set_vma_flags(vnode, advice);
        break;

    case POSIX_FADV_WILLNEED:
        /* Prefetch the specified range into the shared page cache */
        if (vnode)
            fadvise_willneed(vnode, start, end);
        break;

    case POSIX_FADV_DONTNEED:
        /* Evict the specified range from the shared page cache */
        if (vnode)
            fadvise_dontneed(vnode, start, end);
        break;

    case POSIX_FADV_NOREUSE:
        /* Accepted but no special action — valid per POSIX */
        break;
    }

    return 0;
}
