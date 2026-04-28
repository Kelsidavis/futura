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
#include <kernel/fut_task.h>
#include <kernel/kprintf.h>
#include <kernel/uaccess.h>
#include <platform/platform.h>
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
 *
 * Since Futura runs entirely in RAM, no actual swapping occurs.
 * We track the swap entry so /proc/swaps and free(1) report correctly.
 * Requires CAP_SYS_ADMIN (uid 0).
 */

/* Simple swap tracking (max 4 swap areas) */
#define MAX_SWAP_AREAS 4
static struct {
    int active;
    char path[128];
    int priority;
} g_swap_areas[MAX_SWAP_AREAS];
static int g_swap_count = 0;

/* Stage a user-supplied path into a kernel buffer. The previous code
 * dereferenced path[i] / path[j] directly: a kernel-half pointer turned
 * the loop into a kernel-memory read primitive, and an unmapped user
 * pointer page-faulted the kernel. Use the standard uaccess helper with
 * the KERNEL_VIRTUAL_BASE bypass for in-kernel test callers. */
static int swap_copy_path(char *dst, const char *src, size_t n) {
    extern int fut_copy_from_user(void *dst, const void *src, size_t n);
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)src >= KERNEL_VIRTUAL_BASE) {
        for (size_t i = 0; i < n; i++) {
            dst[i] = src[i];
            if (!src[i]) return 0;
        }
        dst[n - 1] = '\0';
        return 0;
    }
#endif
    if (fut_copy_from_user(dst, src, n) != 0)
        return -1;
    dst[n - 1] = '\0';
    return 0;
}

long sys_swapon(const char *path, int swapflags) {
    /* Note: Futura test 2107 asserts EINVAL for NULL path, not Linux's
     * EFAULT. Keep the existing test contract green for CI. */
    if (!path) return -EINVAL;

    /* Linux's sys_swapon validates swap_flags against SWAP_FLAGS_VALID
     * (SWAP_FLAG_PREFER | SWAP_FLAG_PRIO_MASK | SWAP_FLAG_DISCARD |
     *  SWAP_FLAG_DISCARD_ONCE | SWAP_FLAG_DISCARD_PAGES, mask 0x7FFFF)
     * and rejects unknown bits with -EINVAL.  The previous Futura code
     * silently accepted any swap_flags value and only extracted the
     * priority bits, so a caller probing for SWAP_FLAG_DISCARD support
     * couldn't tell 'kernel doesn't honour it' from 'kernel accepted
     * but ignored', and userspace had no way to detect future
     * SWAP_FLAG_* extensions. */
    const int SWAP_FLAGS_VALID =
        0x7FFF  | /* SWAP_FLAG_PRIO_MASK */
        0x8000  | /* SWAP_FLAG_PREFER */
        0x10000 | /* SWAP_FLAG_DISCARD */
        0x20000 | /* SWAP_FLAG_DISCARD_ONCE */
        0x40000;  /* SWAP_FLAG_DISCARD_PAGES */
    if (swapflags & ~SWAP_FLAGS_VALID)
        return -EINVAL;

    /* Permission check: Linux gates swapon on CAP_SYS_ADMIN, not just
     * effective-uid 0. The previous check rejected non-root callers
     * holding CAP_SYS_ADMIN — the standard way to delegate swap
     * administration without granting full root — and forced operators
     * to run swapon binaries as raw root. Match Linux: allow either
     * uid==0 or CAP_SYS_ADMIN. */
    extern fut_task_t *fut_task_current(void);
    fut_task_t *task = fut_task_current();
    if (task && task->uid != 0 &&
        !(task->cap_effective & (1ULL << 21 /* CAP_SYS_ADMIN */)))
        return -EPERM;

    /* Stage the path into a kernel buffer before any further use. */
    char kpath[128];
    if (swap_copy_path(kpath, path, sizeof(kpath)) != 0)
        return -EFAULT;

    /* Empty pathname is ENOENT per Linux's swapon(2) — getname()
     * returns -ENOENT for an empty string and the call never reaches
     * the device-lookup path.  The previous Futura code silently
     * accepted "" and proceeded to register an unnamed swap area,
     * masking the caller's misuse. */
    if (kpath[0] == '\0')
        return -ENOENT;

    /* Check for duplicate using strcmp semantics (length must match too:
     * the previous loop terminated as soon as either side hit NUL, so
     * 'foo' would match a registered 'foobar' and incorrectly EBUSY). */
    for (int i = 0; i < g_swap_count; i++) {
        if (!g_swap_areas[i].active) continue;
        int match = 1;
        int j = 0;
        for (; j < (int)sizeof(kpath); j++) {
            if (kpath[j] != g_swap_areas[i].path[j]) { match = 0; break; }
            if (kpath[j] == '\0') break;
        }
        if (match) return -EBUSY;
    }

    if (g_swap_count >= MAX_SWAP_AREAS) return -ENOMEM;

    /* Register swap area */
    int slot = g_swap_count++;
    g_swap_areas[slot].active = 1;
    g_swap_areas[slot].priority = swapflags & 0x7FFF; /* SWAP_FLAG_PRIO_MASK */
    int pl = 0;
    while (kpath[pl] && pl < 127) { g_swap_areas[slot].path[pl] = kpath[pl]; pl++; }
    g_swap_areas[slot].path[pl] = '\0';

    extern void fut_printf(const char *, ...);
    fut_printf("[SWAP] swapon('%s', priority=%d) — accepted (no actual swapping)\n",
               g_swap_areas[slot].path, g_swap_areas[slot].priority);
    return 0;
}

/**
 * sys_swapoff() - Disable a swap device/file.
 */
long sys_swapoff(const char *path) {
    /* Match sys_swapon: keep EINVAL contract for NULL path. */
    if (!path) return -EINVAL;

    /* Same CAP_SYS_ADMIN gate as swapon (see comment there). */
    extern fut_task_t *fut_task_current(void);
    fut_task_t *task = fut_task_current();
    if (task && task->uid != 0 &&
        !(task->cap_effective & (1ULL << 21 /* CAP_SYS_ADMIN */)))
        return -EPERM;

    char kpath[128];
    if (swap_copy_path(kpath, path, sizeof(kpath)) != 0)
        return -EFAULT;

    /* Empty pathname is ENOENT per Linux's swapoff(2) — matches the
     * sister sys_swapon empty-path check.  Without this gate the
     * scan below would silently report 'not found' (-EINVAL) for an
     * empty string, which is the wrong errno class. */
    if (kpath[0] == '\0')
        return -ENOENT;

    for (int i = 0; i < g_swap_count; i++) {
        if (!g_swap_areas[i].active) continue;
        int match = 1;
        int j = 0;
        for (; j < (int)sizeof(kpath); j++) {
            if (kpath[j] != g_swap_areas[i].path[j]) { match = 0; break; }
            if (kpath[j] == '\0') break;
        }
        if (match) {
            g_swap_areas[i].active = 0;
            extern void fut_printf(const char *, ...);
            fut_printf("[SWAP] swapoff('%s')\n", g_swap_areas[i].path);
            return 0;
        }
    }
    return -EINVAL; /* Not found */
}

/* Generate /proc/swaps content */
int swap_gen_proc_swaps(char *buf, int cap) {
    int pos = 0;
    const char *hdr = "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n";
    while (*hdr && pos < cap - 1) buf[pos++] = *hdr++;
    for (int i = 0; i < g_swap_count && pos < cap - 80; i++) {
        if (!g_swap_areas[i].active) continue;
        /* path */
        for (int j = 0; g_swap_areas[i].path[j] && pos < cap - 60; j++)
            buf[pos++] = g_swap_areas[i].path[j];
        /* pad to column */
        while (pos % 32 != 0 && pos < cap - 40) buf[pos++] = ' ';
        const char *tp = "file\t\t0\t\t0\t\t";
        while (*tp && pos < cap - 20) buf[pos++] = *tp++;
        /* priority */
        int p = g_swap_areas[i].priority;
        char nbuf[8]; int np = 0;
        if (p < 0) { buf[pos++] = '-'; p = -p; }
        if (p == 0) nbuf[np++] = '0';
        else { char r[8]; int rp = 0;
            while (p > 0) { r[rp++] = '0' + (p % 10); p /= 10; }
            while (rp > 0) nbuf[np++] = r[--rp]; }
        for (int j = 0; j < np; j++) buf[pos++] = nbuf[j];
        buf[pos++] = '\n';
    }
    buf[pos] = '\0';
    return pos;
}

/* ---- iopl(172) / ioperm(173) ------------------------------------------- */

/**
 * sys_iopl() - Change I/O privilege level (x86 only).
 * Linux validates level <= 3 first (EINVAL), then checks CAP_SYS_RAWIO
 * (EPERM). Futura collapsed both into a blanket EPERM, masking the
 * range error class — userspace iopl(99) wrappers couldn't distinguish
 * "bad parameter" from "insufficient privilege".
 */
long sys_iopl(unsigned int level) {
    if (level > 3)
        return -EINVAL;
    return -EPERM;
}

/**
 * sys_ioperm() - Set I/O port permissions.
 * Linux's ioperm validates the [from, from+num) range against
 * IO_BITMAP_BITS (65536) before checking CAP_SYS_RAWIO:
 *   if ((from + num <= from) || (from + num > IO_BITMAP_BITS))
 *       return -EINVAL;
 *   if (turn_on && !capable(CAP_SYS_RAWIO))
 *       return -EPERM;
 * The previous Futura code blanket-returned -EPERM, masking the
 * range error class — userspace ioperm wrappers couldn't tell
 * 'bad parameters' (EINVAL) from 'insufficient privilege' (EPERM).
 * Same EINVAL-before-EPERM ordering as the matching sys_iopl fix.
 */
long sys_ioperm(unsigned long from, unsigned long num, int turn_on) {
    (void)turn_on;
    if (from + num <= from)
        return -EINVAL;
    if (from + num > 65536 /* IO_BITMAP_BITS */)
        return -EINVAL;
    return -EPERM;
}
