/* kernel/sys_getdents.c - Legacy getdents(78) and misc stubs
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * getdents(78): Legacy directory-entry syscall using the old linux_dirent
 * structure (32-bit inode, 32-bit offset).  Modern glibc uses getdents64(217)
 * but some statically-linked tools and older programs still emit syscall 78.
 * Implemented by calling sys_getdents64 and converting each entry.
 *
 * swapon(167) / swapoff(168): Swap management — requires privileged memory
 * management infrastructure not present in Futura; return EPERM/ENOSYS.
 *
 * iopl(172) / ioperm(173): x86 I/O privilege level / port bitmap — no user
 * I/O port access policy yet; return EPERM so callers know they're not root.
 */

#include <kernel/errno.h>
#include <kernel/fut_memory.h>
#include <kernel/uaccess.h>
#ifdef __x86_64__
#include <platform/x86_64/memory/paging.h>
#elif defined(__aarch64__)
#include <platform/arm64/memory/paging.h>
#endif
#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* ---- getdents(78) ------------------------------------------------------ */

/* Old linux_dirent (non-64) layout as seen by 64-bit Linux x86_64 ABI.
 * d_ino / d_off are unsigned long (8 bytes on x86_64) but callers that
 * request getdents (not getdents64) typically expect the old API.
 * Linux x86_64 getdents(2) uses:
 *   unsigned long  d_ino
 *   unsigned long  d_off
 *   unsigned short d_reclen
 *   char           d_name[]   (null-terminated, d_type byte before null)
 */
struct linux_dirent {
    unsigned long  d_ino;
    unsigned long  d_off;
    unsigned short d_reclen;
    char           d_name[];   /* variable length; d_type at d_name[namelen] */
};

/* linux_dirent64 — must match definition in sys_getdents64.c */
struct linux_dirent64 {
    uint64_t d_ino;
    int64_t  d_off;
    uint16_t d_reclen;
    uint8_t  d_type;
    char     d_name[];
} __attribute__((packed));

extern long sys_getdents64(unsigned int fd, void *dirp, unsigned int count);

/**
 * sys_getdents() - Read directory entries (legacy non-64 syscall 78).
 * @fd:    Open directory file descriptor.
 * @dirp:  User buffer for linux_dirent array.
 * @count: Buffer size in bytes.
 *
 * Calls sys_getdents64 internally, then converts each linux_dirent64 entry
 * to the old linux_dirent format.  Returns bytes written to @dirp, or < 0
 * on error.
 */
long sys_getdents(unsigned int fd, void *dirp, unsigned int count) {
    if (!dirp)
        return -EFAULT;
    if (count < 32)
        return -EINVAL;

    /* Allocate a temp buffer for getdents64 results. */
    void *buf64 = fut_malloc(count);
    if (!buf64)
        return -ENOMEM;

    long n64 = sys_getdents64(fd, buf64, count);
    if (n64 <= 0) {
        fut_free(buf64);
        return n64;
    }

    /* Allocate output buffer — old entries can be slightly larger due to
     * the trailing d_type byte embedded in the name array. */
    char *out = fut_malloc(count);
    if (!out) {
        fut_free(buf64);
        return -ENOMEM;
    }

    char *p64 = (char *)buf64;
    char *p64_end = p64 + n64;
    char *pout = out;
    char *pout_end = out + count;

    while (p64 < p64_end) {
        struct linux_dirent64 *d64 = (struct linux_dirent64 *)p64;

        size_t namelen = strlen(d64->d_name);
        /* old linux_dirent record: header(18) + name + '\0' + d_type,
         * rounded up to sizeof(long) alignment. */
        size_t raw = offsetof(struct linux_dirent, d_name) + namelen + 2;
        size_t reclen = (raw + sizeof(long) - 1) & ~(sizeof(long) - 1);

        if (pout + reclen > pout_end) {
            /* Not enough space — stop here (caller will call again). */
            break;
        }

        struct linux_dirent *d = (struct linux_dirent *)pout;
        d->d_ino    = (unsigned long)d64->d_ino;
        d->d_off    = (unsigned long)(unsigned long long)d64->d_off;
        d->d_reclen = (unsigned short)reclen;
        memcpy(d->d_name, d64->d_name, namelen + 1);  /* name + '\0' */
        /* d_type stored as last byte before padding */
        d->d_name[namelen + 1] = (char)d64->d_type;

        pout += reclen;
        p64  += d64->d_reclen;
    }

    long written = (long)(pout - out);
    int  err     = 0;

    if (written > 0) {
#ifdef KERNEL_VIRTUAL_BASE
        if ((uintptr_t)dirp >= KERNEL_VIRTUAL_BASE) {
            __builtin_memcpy(dirp, out, (size_t)written);
        } else
#endif
        err = fut_copy_to_user(dirp, out, (size_t)written);
    }

    fut_free(out);
    fut_free(buf64);

    return err ? -EFAULT : written;
}

/* ---- swapon(167) / swapoff(168) ---------------------------------------- */

/**
 * sys_swapon() - Enable a swap device/file.
 * Returns -EPERM: no swap subsystem; privileged operation.
 */
long sys_swapon(const char *path, int swapflags) {
    (void)path; (void)swapflags;
    return -EPERM;
}

/**
 * sys_swapoff() - Disable a swap device/file.
 * Returns -EPERM: no swap subsystem; privileged operation.
 */
long sys_swapoff(const char *path) {
    (void)path;
    return -EPERM;
}

/* ---- iopl(172) / ioperm(173) ------------------------------------------- */

/**
 * sys_iopl() - Change I/O privilege level (x86 only).
 * Returns -EPERM: I/O port access policy not implemented.
 */
long sys_iopl(unsigned int level) {
    (void)level;
    return -EPERM;
}

/**
 * sys_ioperm() - Set I/O port permissions.
 * Returns -EPERM: I/O port access policy not implemented.
 */
long sys_ioperm(unsigned long from, unsigned long num, int turn_on) {
    (void)from; (void)num; (void)turn_on;
    return -EPERM;
}
