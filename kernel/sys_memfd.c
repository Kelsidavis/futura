/* kernel/sys_memfd.c - memfd_create() syscall implementation
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Creates an anonymous file in memory (no directory entry), accessible
 * only via the returned file descriptor. Used by Wayland compositors,
 * shared memory IPC, and programs needing temporary file-like objects.
 */

#include <kernel/fut_task.h>
#include <kernel/fut_memory.h>
#include <kernel/fut_mm.h>
#include <kernel/chrdev.h>
#include <kernel/fut_vfs.h>
#include <kernel/errno.h>
#include <kernel/kprintf.h>
#include <kernel/uaccess.h>
#include <fcntl.h>
#ifdef __x86_64__
#include <platform/x86_64/memory/paging.h>
#elif defined(__aarch64__)
#include <platform/arm64/memory/paging.h>
#endif
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* memfd_create flags */
#define MFD_CLOEXEC         0x0001U
#define MFD_ALLOW_SEALING   0x0002U
#define MFD_HUGETLB         0x0004U  /* Accepted as no-op (no huge page support) */
#define MFD_NOEXEC_SEAL     0x0008U  /* Linux 6.3+: implies SEAL_EXEC */
#define MFD_EXEC            0x0010U  /* Linux 6.3+: allow exec */

/* Maximum name length (Linux uses 249) */
#define MEMFD_NAME_MAX 249

/* memfd private data: dynamic buffer */
struct memfd {
    char    name[MEMFD_NAME_MAX + 1];
    uint8_t *data;
    size_t  size;      /* current file size (as set by ftruncate) */
    size_t  capacity;  /* allocated buffer capacity */
    unsigned int flags;
};

#define MEMFD_INIT_CAP 4096

static ssize_t memfd_read(void *inode, void *priv, void *buf, size_t n, off_t *pos) {
    (void)inode;
    struct memfd *mf = (struct memfd *)priv;
    if (!mf || !pos)
        return -EINVAL;

    off_t offset = *pos;
    if (offset < 0 || (size_t)offset >= mf->size)
        return 0;  /* EOF */

    size_t avail = mf->size - (size_t)offset;
    if (n > avail)
        n = avail;

    memcpy(buf, mf->data + offset, n);
    *pos += (off_t)n;
    return (ssize_t)n;
}

static ssize_t memfd_write(void *inode, void *priv, const void *buf, size_t n, off_t *pos) {
    (void)inode;
    struct memfd *mf = (struct memfd *)priv;
    if (!mf || !pos)
        return -EINVAL;

    off_t offset = *pos;
    if (offset < 0)
        return -EINVAL;

    size_t end = (size_t)offset + n;

    /* Grow buffer if needed */
    if (end > mf->capacity) {
        size_t new_cap = mf->capacity;
        while (new_cap < end)
            new_cap = new_cap ? new_cap * 2 : MEMFD_INIT_CAP;

        uint8_t *new_data = fut_malloc(new_cap);
        if (!new_data)
            return -ENOMEM;

        if (mf->data) {
            memcpy(new_data, mf->data, mf->size);
            fut_free(mf->data);
        }
        /* Zero-fill gap between old size and new capacity */
        if (new_cap > mf->size)
            memset(new_data + mf->size, 0, new_cap - mf->size);

        mf->data = new_data;
        mf->capacity = new_cap;
    }

    memcpy(mf->data + offset, buf, n);
    *pos += (off_t)n;

    if (end > mf->size)
        mf->size = end;

    return (ssize_t)n;
}

static int memfd_release(void *inode, void *priv) {
    (void)inode;
    struct memfd *mf = (struct memfd *)priv;
    if (mf) {
        if (mf->data)
            fut_free(mf->data);
        fut_free(mf);
    }
    return 0;
}

/* Private ioctls for ftruncate and seal-check support (used by sys_ftruncate) */
#define MEMFD_IOC_TRUNCATE 0xFE10
#define MEMFD_IOC_GETSIZE  0xFE11

static int memfd_ioctl(void *inode, void *priv, unsigned long req, unsigned long arg) {
    (void)inode;
    struct memfd *mf = (struct memfd *)priv;
    if (!mf)
        return -EINVAL;

    if (req == MEMFD_IOC_GETSIZE) {
        /* Returns current size in arg (as size_t*) */
        if (arg) *(size_t *)arg = mf->size;
        return (int)mf->size;
    }

    if (req == MEMFD_IOC_TRUNCATE) {
        size_t new_size = (size_t)arg;
        if (new_size > mf->capacity) {
            /* Grow */
            size_t new_cap = mf->capacity;
            while (new_cap < new_size)
                new_cap = new_cap ? new_cap * 2 : MEMFD_INIT_CAP;
            uint8_t *new_data = fut_malloc(new_cap);
            if (!new_data)
                return -ENOMEM;
            if (mf->data) {
                memcpy(new_data, mf->data, mf->size);
                fut_free(mf->data);
            }
            if (new_cap > mf->size)
                memset(new_data + mf->size, 0, new_cap - mf->size);
            mf->data = new_data;
            mf->capacity = new_cap;
        } else if (new_size < mf->size && mf->data) {
            /* Shrink: zero out truncated region */
            memset(mf->data + new_size, 0, mf->size - new_size);
        }
        mf->size = new_size;
        return 0;
    }

    return -EINVAL;
}

/* Exported helper for seal checking: returns current memfd size, or -EINVAL if not a memfd */
long fut_memfd_get_size(struct fut_file *file) {
    if (!file || !file->chr_ops || !file->chr_ops->ioctl)
        return -EINVAL;
    return (long)file->chr_ops->ioctl(file->chr_inode, file->chr_private,
                                      MEMFD_IOC_GETSIZE, 0);
}

static void *memfd_mmap(void *inode, void *priv, void *u_addr,
                        size_t len, off_t off, int prot, int flags) {
    (void)inode;
    struct memfd *mf = (struct memfd *)priv;
    if (!mf)
        return (void *)(intptr_t)(-EINVAL);
    if (off < 0 || (size_t)off > mf->size)
        return (void *)(intptr_t)(-EINVAL);

    fut_mm_t *mm = fut_mm_current();
    if (!mm)
        return (void *)(intptr_t)(-ENOMEM);

    /* Allocate anonymous pages for the mapping */
    void *vaddr = fut_mm_map_anonymous(mm, (uintptr_t)u_addr, len, prot, flags);
    if ((intptr_t)vaddr < 0)
        return vaddr;

    /* Copy existing content into the mapping */
    size_t avail = (mf->size > (size_t)off) ? (mf->size - (size_t)off) : 0;
    if (avail > len)
        avail = len;
    if (avail > 0 && mf->data) {
        /* fut_copy_to_user handles SMAP; ignore errors (mapping still valid) */
        fut_copy_to_user(vaddr, mf->data + (size_t)off, avail);
    }

    return vaddr;
}

/* Runtime-initialized for ARM64 relocation safety */
static struct fut_file_ops memfd_fops;

/**
 * memfd_create - Create an anonymous file in memory
 *
 * @param uname  Name for debugging (shown in /proc/PID/fd/N symlinks)
 * @param flags  MFD_CLOEXEC | MFD_ALLOW_SEALING | MFD_HUGETLB | MFD_NOEXEC_SEAL | MFD_EXEC
 *
 * Returns file descriptor on success, negative error on failure.
 */
long sys_memfd_create(const char *uname, unsigned int flags) {
    /* Runtime init file ops (ARM64 relocation safety) */
    if (!memfd_fops.read) {
        memfd_fops.read = memfd_read;
        memfd_fops.write = memfd_write;
        memfd_fops.release = memfd_release;
        memfd_fops.ioctl = memfd_ioctl;
        memfd_fops.mmap = memfd_mmap;
    }
    /* Accept all standard Linux memfd flags; MFD_HUGETLB and MFD_EXEC/MFD_NOEXEC_SEAL
     * are silently accepted (no huge page support; exec sealing is recorded).
     * Linux also encodes huge page size in bits 26-31 alongside MFD_HUGETLB. */
    unsigned int known = MFD_CLOEXEC | MFD_ALLOW_SEALING | MFD_HUGETLB |
                         MFD_NOEXEC_SEAL | MFD_EXEC;
    /* MFD_HUGETLB can include huge page size in upper bits (MAP_HUGE_MASK) */
    if (flags & MFD_HUGETLB)
        known |= (0x3fU << 26);  /* Accept MAP_HUGE_2MB etc. size encoding */
    if (flags & ~known)
        return -EINVAL;
    /* MFD_NOEXEC_SEAL and MFD_EXEC are mutually exclusive */
    if ((flags & MFD_NOEXEC_SEAL) && (flags & MFD_EXEC))
        return -EINVAL;

    /* Allocate memfd state */
    struct memfd *mf = fut_malloc(sizeof(struct memfd));
    if (!mf)
        return -ENOMEM;

    memset(mf, 0, sizeof(*mf));
    mf->flags = flags;

    /* Copy name (best-effort, kernel pointer or user pointer) */
    if (uname) {
#ifdef KERNEL_VIRTUAL_BASE
        /* For kernel self-tests: direct copy */
        if ((uintptr_t)uname >= KERNEL_VIRTUAL_BASE) {
            size_t len = strlen(uname);
            if (len > MEMFD_NAME_MAX) len = MEMFD_NAME_MAX;
            memcpy(mf->name, uname, len);
            mf->name[len] = '\0';
        } else
#endif
        {
            if (fut_copy_from_user(mf->name, uname, MEMFD_NAME_MAX) != 0) {
                /* Name copy failed - use default */
                memcpy(mf->name, "memfd", 6);
            }
            mf->name[MEMFD_NAME_MAX] = '\0';
        }
    } else {
        memcpy(mf->name, "memfd", 6);
    }

    /* Allocate fd */
    int fd = chrdev_alloc_fd(&memfd_fops, NULL, mf);
    if (fd < 0) {
        fut_free(mf);
        return fd;
    }

    /* memfd is seekable: clear the FUT_F_UNSEEKABLE flag set by chrdev_alloc_fd */
    {
        fut_task_t *mf_task = fut_task_current();
        if (mf_task && mf_task->fd_table && fd < mf_task->max_fds && mf_task->fd_table[fd])
            mf_task->fd_table[fd]->flags &= ~FUT_F_UNSEEKABLE;
    }

    /* Set FD_CLOEXEC if requested (per-FD flag) */
    if (flags & MFD_CLOEXEC) {
        fut_task_t *task = fut_task_current();
        if (task && task->fd_flags && fd < task->max_fds)
            task->fd_flags[fd] |= FD_CLOEXEC;
    }

    /* MFD_NOEXEC_SEAL implies MFD_ALLOW_SEALING and sets F_SEAL_EXEC (0x0020) */
    unsigned int effective_flags = flags;
    if (flags & MFD_NOEXEC_SEAL)
        effective_flags |= MFD_ALLOW_SEALING;

    /* Mark file as sealing-capable when MFD_ALLOW_SEALING is set.
     * F_ADD_SEALS checks this flag and returns EPERM if absent. */
    if (effective_flags & MFD_ALLOW_SEALING) {
        fut_task_t *task = fut_task_current();
        if (task && task->fd_table && fd < task->max_fds && task->fd_table[fd]) {
            task->fd_table[fd]->flags |= FUT_F_SEALING;
            /* MFD_NOEXEC_SEAL: apply F_SEAL_EXEC immediately */
            if (flags & MFD_NOEXEC_SEAL)
                task->fd_table[fd]->seals |= 0x0020;  /* F_SEAL_EXEC */
        }
    }

    return fd;
}
