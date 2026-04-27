/* kernel/sys_shm.c - SysV shared memory implementation
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements shmget(), shmat(), shmdt(), shmctl() for SysV IPC.
 * Supports up to SHMMNI segments, each up to SHMMAX bytes.
 *
 * Phase 3 (Completed): shmget/shmat/shmdt/shmctl with IPC_RMID/IPC_STAT/
 *                      IPC_SET. shmat returns a kernel-side pointer suitable
 *                      for kernel-selftest usage (same address space).
 *                      Deferred-free on IPC_RMID when nattach > 0.
 */

#include <kernel/fut_task.h>
#include <kernel/fut_memory.h>
#include <kernel/errno.h>
#include <kernel/kprintf.h>
#include <kernel/uaccess.h>
#include <stdint.h>
#include <stddef.h>

#include <platform/platform.h>

/* ============================================================
 *   IPC Constants
 * ============================================================ */

#define IPC_PRIVATE  0L
#define IPC_CREAT    0x0200
#define IPC_EXCL     0x0400
#define IPC_RMID     0
#define IPC_SET      1
#define IPC_STAT     2

/* shmat flags */
#define SHM_RDONLY   0x1000   /* attach read-only */
#define SHM_RND      0x2000   /* round shmaddr to SHMLBA */

/* limits */
#define SHMMNI    32                      /* max shared memory segments */
#define SHMMAX    (64UL * 1024UL * 1024UL) /* max segment size: 64 MB */
#define SHMLBA    4096                    /* segment low boundary address */
#define SHMATTACH_MAX 256                 /* max concurrent attachments */

/* ============================================================
 *   Data Structures
 * ============================================================ */

struct shm_seg {
    int          used;
    long         key;
    int          id;
    size_t       size;
    unsigned int mode;
    int          nattach;  /* current attachment count */
    int          pending_rmid;  /* IPC_RMID called, free when nattach hits 0 */
    void        *data;     /* kernel memory buffer (zero-initialized) */
};

/* Per-attachment record to support shmdt */
struct shm_attach {
    int   used;
    void *addr;   /* virtual address returned by shmat */
    int   shmid;
};

/* ============================================================
 *   Globals
 * ============================================================ */

static struct shm_seg   shmtable[SHMMNI];
static struct shm_attach shm_attachments[SHMATTACH_MAX];
static int shm_next_id = 1;

/* ============================================================
 *   Kernel-pointer bypass helpers
 * ============================================================ */

static inline int shm_copy_to_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)dst >= KERNEL_VIRTUAL_BASE) {
        __builtin_memcpy(dst, src, n);
        return 0;
    }
#endif
    return fut_copy_to_user(dst, src, n);
}

static inline int shm_copy_from_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)src >= KERNEL_VIRTUAL_BASE) {
        __builtin_memcpy(dst, src, n);
        return 0;
    }
#endif
    return fut_copy_from_user(dst, src, n);
}

/* ============================================================
 *   Internal helpers
 * ============================================================ */

static struct shm_seg *shmtable_find_by_id(int id) {
    for (int i = 0; i < SHMMNI; i++) {
        if (shmtable[i].used && shmtable[i].id == id)
            return &shmtable[i];
    }
    return NULL;
}

static struct shm_seg *shmtable_find_by_key(long key) {
    for (int i = 0; i < SHMMNI; i++) {
        if (shmtable[i].used && shmtable[i].key == key)
            return &shmtable[i];
    }
    return NULL;
}

/* Record a new attachment */
static int shm_record_attach(void *addr, int shmid) {
    for (int i = 0; i < SHMATTACH_MAX; i++) {
        if (!shm_attachments[i].used) {
            shm_attachments[i].used  = 1;
            shm_attachments[i].addr  = addr;
            shm_attachments[i].shmid = shmid;
            return 0;
        }
    }
    return -ENOMEM;
}

/* Remove attachment by address, return shmid or -1 */
static int shm_remove_attach(const void *addr) {
    for (int i = 0; i < SHMATTACH_MAX; i++) {
        if (shm_attachments[i].used &&
            shm_attachments[i].addr == addr) {
            int id = shm_attachments[i].shmid;
            shm_attachments[i].used = 0;
            return id;
        }
    }
    return -1;
}

/* ============================================================
 *   shmget(2) - get/create a shared memory segment
 * ============================================================ */

/**
 * shmget - Get or create a SysV shared memory segment.
 *
 * @param key     IPC key (IPC_PRIVATE = always create new)
 * @param size    Segment size in bytes (> 0 for new, 0 for existing)
 * @param shmflg  IPC_CREAT, IPC_EXCL, permissions
 * @return segment ID on success, -errno on error
 */
long sys_shmget(long key, size_t size, int shmflg) {
    if (key != IPC_PRIVATE) {
        struct shm_seg *s = shmtable_find_by_key(key);
        if (s) {
            if ((shmflg & IPC_CREAT) && (shmflg & IPC_EXCL))
                return -EEXIST;
            /* size check: requesting segment must be <= existing */
            if (size > 0 && size > s->size)
                return -EINVAL;
            return s->id;
        }
        if (!(shmflg & IPC_CREAT))
            return -ENOENT;
    }

    /* Validate size for new segment */
    if (size == 0 || size > SHMMAX)
        return -EINVAL;

    /* Round up to page boundary */
    size_t alloc_size = (size + (SHMLBA - 1)) & ~(size_t)(SHMLBA - 1);

    /* Find free slot */
    for (int i = 0; i < SHMMNI; i++) {
        if (!shmtable[i].used) {
            void *data = fut_malloc(alloc_size);
            if (!data)
                return -ENOMEM;
            __builtin_memset(data, 0, alloc_size);

            shmtable[i].used         = 1;
            shmtable[i].key          = key;
            shmtable[i].id           = shm_next_id++;
            shmtable[i].size         = alloc_size;
            shmtable[i].mode         = (unsigned int)(shmflg & 0777);
            shmtable[i].nattach      = 0;
            shmtable[i].pending_rmid = 0;
            shmtable[i].data         = data;
            return shmtable[i].id;
        }
    }
    return -ENOSPC;
}

/* ============================================================
 *   shmat(2) - attach shared memory segment
 * ============================================================ */

/**
 * shmat - Attach a shared memory segment to the calling process.
 *
 * For kernel-selftest usage, returns the kernel buffer pointer directly.
 * shmaddr is ignored (NULL preferred); SHM_RND silently accepted.
 *
 * @param shmid    Shared memory segment ID
 * @param shmaddr  Desired attachment address (NULL = kernel chooses)
 * @param shmflg   SHM_RDONLY, SHM_RND
 * @return Virtual address of attached segment, or error (negative)
 */
long sys_shmat(int shmid, const void *shmaddr, int shmflg) {
    (void)shmaddr;  /* kernel-selftest: ignored, return kernel pointer */
    (void)shmflg;

    struct shm_seg *s = shmtable_find_by_id(shmid);
    if (!s)
        return -EINVAL;
    /* Linux's do_shmat allows new attachments to a segment marked for
     * deferred removal (SHM_DEST/IPC_RMID set while shm_nattch > 0):
     * ipc_set_key_private() removes the key from public lookup but
     * keeps the id resolvable, and the segment is destroyed only when
     * the final detach drops shm_nattch to 0.  The previous EINVAL
     * gate broke libc/glibc shmat callers that obtain the id by other
     * means (fdpass, parent inheritance) after IPC_RMID — they expect
     * the same zombie-attach behavior the rest of POSIX/Linux gives
     * them.  Allow attach; shm_nattch keeps the data alive until the
     * final detach. */

    int r = shm_record_attach(s->data, shmid);
    if (r < 0)
        return r;

    s->nattach++;
    return (long)(uintptr_t)s->data;
}

/* ============================================================
 *   shmdt(2) - detach shared memory segment
 * ============================================================ */

/**
 * shmdt - Detach a shared memory segment from the calling process.
 *
 * @param shmaddr  Address returned by shmat
 * @return 0 on success, -errno on error
 */
long sys_shmdt(const void *shmaddr) {
    if (!shmaddr)
        return -EINVAL;

    int shmid = shm_remove_attach(shmaddr);
    if (shmid < 0)
        return -EINVAL;

    struct shm_seg *s = shmtable_find_by_id(shmid);
    if (!s)
        return 0;  /* Already removed by IPC_RMID */

    if (s->nattach > 0)
        s->nattach--;

    /* Deferred free: if IPC_RMID was called and no more attachments */
    if (s->pending_rmid && s->nattach == 0) {
        fut_free(s->data);
        s->used = 0;
        s->data = NULL;
    }

    return 0;
}

/* ============================================================
 *   struct shmid_ds for IPC_STAT (simplified)
 * ============================================================ */

struct shm_ipc_perm {
    int           key;
    unsigned int  uid, gid, cuid, cgid;
    unsigned int  mode;
    unsigned short seq, pad;
};

struct shmid_ds {
    struct shm_ipc_perm shm_perm;
    size_t              shm_segsz;    /* segment size */
    unsigned long       shm_atime;    /* last attach time */
    unsigned long       shm_dtime;    /* last detach time */
    unsigned long       shm_ctime;    /* last change time */
    int                 shm_cpid;     /* pid of creator */
    int                 shm_lpid;     /* pid of last operator */
    unsigned long       shm_nattch;   /* current # of attached processes */
};

/* ============================================================
 *   shmctl(2) - control shared memory segment
 * ============================================================ */

/**
 * shmctl - Perform control operation on a shared memory segment.
 *
 * @param shmid  Shared memory segment ID
 * @param cmd    IPC_RMID, IPC_STAT, IPC_SET
 * @param buf    Pointer to struct shmid_ds (for IPC_STAT/IPC_SET)
 * @return 0 on success, -errno on error
 */
long sys_shmctl(int shmid, int cmd, void *buf) {
    if (cmd == IPC_RMID) {
        struct shm_seg *s = shmtable_find_by_id(shmid);
        if (!s)
            return -EINVAL;
        if (s->nattach == 0) {
            /* No attachments: free immediately */
            fut_free(s->data);
            s->used = 0;
            s->data = NULL;
        } else {
            /* Deferred: free when last detach happens */
            s->pending_rmid = 1;
        }
        return 0;
    }

    struct shm_seg *s = shmtable_find_by_id(shmid);
    if (!s)
        return -EINVAL;

    switch (cmd) {
    case IPC_STAT: {
        if (!buf)
            return -EFAULT;
        struct shmid_ds ds;
        __builtin_memset(&ds, 0, sizeof(ds));
        ds.shm_perm.key  = (int)s->key;
        ds.shm_perm.mode = s->mode;
        ds.shm_segsz     = s->size;
        ds.shm_nattch    = (unsigned long)s->nattach;
        if (shm_copy_to_user(buf, &ds, sizeof(ds)) != 0)
            return -EFAULT;
        return 0;
    }

    case IPC_SET: {
        if (!buf)
            return -EFAULT;
        struct shmid_ds ds;
        if (shm_copy_from_user(&ds, buf, sizeof(ds)) != 0)
            return -EFAULT;
        s->mode = ds.shm_perm.mode & 0777;
        return 0;
    }

    default:
        return -EINVAL;
    }
}
