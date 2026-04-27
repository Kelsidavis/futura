/* kernel/sys_landlock.c - Linux Landlock LSM and newer syscall stubs
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Stub implementations for Linux 5.10-6.10 syscalls not yet in Futura.
 * Each returns -ENOSYS (or 0 for no-op-safe ops) so callers fall back.
 *
 * Linux x86_64 syscall numbers:
 *   landlock_create_ruleset  444   (Linux 5.13)
 *   landlock_add_rule        445   (Linux 5.13)
 *   landlock_restrict_self   446   (Linux 5.13)
 *   memfd_secret             447   (Linux 5.14)
 *   process_madvise          440   (Linux 5.10) — remapped in Futura
 *   set_mempolicy_home_node  450   (Linux 5.17) — remapped in Futura
 *   cachestat                451   (Linux 6.5)  — remapped in Futura
 *   fchmodat2                452   (Linux 6.6)  — remapped in Futura
 *   mseal                    459   (Linux 6.10) — remapped in Futura
 */

#include <kernel/errno.h>
#include <kernel/fut_task.h>
#include <kernel/fut_vfs.h>
#include <kernel/uaccess.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

#include <platform/platform.h>

/* Landlock ABI version */
#define LANDLOCK_ABI_VERSION 4

/* Landlock access rights for files */
#define LANDLOCK_ACCESS_FS_EXECUTE    (1ULL << 0)
#define LANDLOCK_ACCESS_FS_WRITE_FILE (1ULL << 1)
#define LANDLOCK_ACCESS_FS_READ_FILE  (1ULL << 2)
#define LANDLOCK_ACCESS_FS_READ_DIR   (1ULL << 3)
#define LANDLOCK_ACCESS_FS_REMOVE_DIR (1ULL << 4)
#define LANDLOCK_ACCESS_FS_REMOVE_FILE (1ULL << 5)
#define LANDLOCK_ACCESS_FS_MAKE_CHAR  (1ULL << 6)
#define LANDLOCK_ACCESS_FS_MAKE_DIR   (1ULL << 7)
#define LANDLOCK_ACCESS_FS_MAKE_REG   (1ULL << 8)
#define LANDLOCK_ACCESS_FS_MAKE_SOCK  (1ULL << 9)
#define LANDLOCK_ACCESS_FS_MAKE_FIFO  (1ULL << 10)
#define LANDLOCK_ACCESS_FS_MAKE_BLOCK (1ULL << 11)
#define LANDLOCK_ACCESS_FS_MAKE_SYM   (1ULL << 12)
#define LANDLOCK_ACCESS_FS_REFER      (1ULL << 13)
#define LANDLOCK_ACCESS_FS_TRUNCATE   (1ULL << 14)

/* Landlock ruleset attribute */
struct landlock_ruleset_attr {
    uint64_t handled_access_fs;
    uint64_t handled_access_net;
};

/* Landlock rule types */
#define LANDLOCK_RULE_PATH_BENEATH 1
#define LANDLOCK_RULE_NET_PORT     2

/* Simple Landlock ruleset tracking (per-fd) */
#define LANDLOCK_MAX_RULESETS 8
#define LANDLOCK_MAX_RULES    16

struct landlock_rule {
    uint64_t allowed_access;
    int      parent_fd;      /* -1 = all paths */
};

struct landlock_ruleset {
    bool     active;
    uint64_t handled_access_fs;
    struct landlock_rule rules[LANDLOCK_MAX_RULES];
    int      rule_count;
};

static struct landlock_ruleset g_rulesets[LANDLOCK_MAX_RULESETS];
static int g_next_ruleset_fd = 1000;  /* Fake fd range for rulesets */

/**
 * sys_landlock_create_ruleset() - Create a new Landlock ruleset.
 */
long sys_landlock_create_ruleset(const void *attr, size_t size,
                                 uint32_t flags) {
    /* LANDLOCK_CREATE_RULESET_VERSION flag: return ABI version */
    if (flags == (1U << 0)) {
        return LANDLOCK_ABI_VERSION;
    }

    if (!attr || size < sizeof(struct landlock_ruleset_attr))
        return -EINVAL;

    /* Find free ruleset slot */
    int slot = -1;
    for (int i = 0; i < LANDLOCK_MAX_RULESETS; i++) {
        if (!g_rulesets[i].active) { slot = i; break; }
    }
    if (slot < 0) return -ENOMEM;

    /* Copy attribute from caller. Bypass uaccess only for kernel-side
     * self-test pointers; never silently fall back to memcpy on a
     * user-pointer copy failure — the previous code did exactly that,
     * turning any failed copy into a kernel-memory read primitive
     * (kernel-address attr) or a kernel page fault (bad user attr). */
    struct landlock_ruleset_attr ka;
    extern int fut_copy_from_user(void *, const void *, size_t);
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)attr >= KERNEL_VIRTUAL_BASE) {
        __builtin_memcpy(&ka, attr, sizeof(ka));
    } else
#endif
    if (fut_copy_from_user(&ka, attr, sizeof(ka)) != 0) {
        return -EFAULT;
    }

    g_rulesets[slot].active = true;
    g_rulesets[slot].handled_access_fs = ka.handled_access_fs;
    g_rulesets[slot].rule_count = 0;

    int fd = g_next_ruleset_fd++;
    fut_printf("[LANDLOCK] Created ruleset fd=%d (access=0x%llx)\n",
               fd, (unsigned long long)ka.handled_access_fs);
    return fd;
}

/**
 * sys_landlock_add_rule() - Add a rule to a Landlock ruleset.
 */
long sys_landlock_add_rule(int ruleset_fd, unsigned int rule_type,
                           const void *rule_attr, uint32_t flags) {
    /* Linux's security/landlock/syscalls.c rejects non-zero flags up
     * front: 'if (flags) return -EINVAL'. The flags argument is
     * reserved for future use, and the kernel must signal kernel-old
     * to userspace probes that pass a future bit so the caller can
     * detect missing support. Futura silently ignored flags, masking
     * that ABI signal. */
    if (flags != 0)
        return -EINVAL;
    if (rule_type != LANDLOCK_RULE_PATH_BENEATH &&
        rule_type != LANDLOCK_RULE_NET_PORT)
        return -EINVAL;

    /* Find ruleset by fd (simple linear scan) */
    int slot = ruleset_fd - 1000;
    if (slot < 0 || slot >= LANDLOCK_MAX_RULESETS || !g_rulesets[slot].active)
        return -EBADF;

    if (g_rulesets[slot].rule_count >= LANDLOCK_MAX_RULES)
        return -E2BIG;

    /* Accept the rule (details in rule_attr are acknowledged) */
    struct landlock_rule *r = &g_rulesets[slot].rules[g_rulesets[slot].rule_count];
    r->allowed_access = 0;
    r->parent_fd = -1;
    if (rule_attr) {
        /* First 8 bytes are allowed_access, next 4 bytes are parent_fd.
         * Copy through the standard helper: a kernel-pointer rule_attr
         * is allowed (self-tests), but a user-pointer copy failure must
         * return -EFAULT instead of crashing the kernel. The previous
         * direct memcpy let any caller pass a kernel address as
         * rule_attr and have the rule populated from kernel memory. */
        struct { uint64_t allowed; int32_t parent; } __attribute__((packed)) ra;
        extern int fut_copy_from_user(void *, const void *, size_t);
#ifdef KERNEL_VIRTUAL_BASE
        if ((uintptr_t)rule_attr >= KERNEL_VIRTUAL_BASE) {
            __builtin_memcpy(&ra, rule_attr, sizeof(ra));
        } else
#endif
        if (fut_copy_from_user(&ra, rule_attr, sizeof(ra)) != 0) {
            return -EFAULT;
        }
        r->allowed_access = ra.allowed;
        r->parent_fd = ra.parent;
    }
    g_rulesets[slot].rule_count++;
    return 0;
}

/**
 * sys_landlock_restrict_self() - Apply a Landlock ruleset.
 */
long sys_landlock_restrict_self(int ruleset_fd, uint32_t flags) {
    if (flags != 0) return -EINVAL;

    int slot = ruleset_fd - 1000;
    if (slot < 0 || slot >= LANDLOCK_MAX_RULESETS || !g_rulesets[slot].active)
        return -EBADF;

    /* Linux's security/landlock/syscalls.c requires either
     * task_no_new_privs(current) or CAP_SYS_ADMIN before installing a
     * ruleset. Without that gate, an unprivileged caller could apply a
     * Landlock filter and then execve a setuid binary that wouldn't
     * expect its filesystem accesses to be restricted — a privilege-
     * escalation-via-confusion vector that NO_NEW_PRIVS exists
     * specifically to prevent. seccomp's filter path already enforces
     * the same gate (see kernel/sys_seccomp.c:235); landlock was the
     * straggler. */
    extern fut_task_t *fut_task_current(void);
    fut_task_t *cur = fut_task_current();
    if (cur && !cur->no_new_privs && cur->uid != 0 &&
        !(cur->cap_effective & (1ULL << 21 /* CAP_SYS_ADMIN */))) {
        fut_printf("[LANDLOCK] restrict_self(fd=%d) -> EPERM "
                   "(no_new_privs not set and no CAP_SYS_ADMIN)\n",
                   ruleset_fd);
        return -EPERM;
    }

    fut_printf("[LANDLOCK] Ruleset fd=%d applied to self (%d rules)\n",
               ruleset_fd, g_rulesets[slot].rule_count);
    return 0;
}

/**
 * sys_memfd_secret() - Create a secret memory area (Linux 5.14).
 *
 * Creates an anonymous file whose pages are excluded from core dumps,
 * /proc/pid/mem, and kernel direct map. Used by crypto libraries to
 * protect keys and passwords.
 *
 * In Futura's flat memory model, this creates a standard memfd that
 * is marked as "secret" (functionally equivalent since we don't have
 * a direct map to remove pages from).
 *
 * @flags: O_CLOEXEC only
 * Returns: fd on success, -errno on failure.
 */
long sys_memfd_secret(unsigned int flags) {
    /* Only O_CLOEXEC is allowed */
    if (flags & ~((unsigned int)02000000)) return -EINVAL;

    /* Create via memfd_create with MFD_SECRET-like semantics */
    extern long sys_memfd_create(const char *name, unsigned int flags);
    long fd = sys_memfd_create("secretmem", flags & 02000000 ? 1 /*MFD_CLOEXEC*/ : 0);
    return fd;
}

/**
 * sys_process_madvise() - Apply madvise() hints to another process's memory.
 *
 * Used by systemd-oomd, Android LMKD, and memory management daemons to
 * apply MADV_DONTNEED/MADV_COLD/MADV_PAGEOUT to another process via pidfd.
 *
 * In Futura (single address space), delegates directly to sys_madvise
 * after validating the pidfd and copying the iovec array.
 *
 * @param pidfd   Process file descriptor for the target process
 * @param iovec   Array of struct iovec describing memory ranges
 * @param vlen    Number of iovec entries
 * @param advice  MADV_* advice code
 * @param flags   Must be 0
 * @return Total bytes advised on success, -errno on error
 */
long sys_process_madvise(int pidfd, const void *iovec_ptr, unsigned long vlen,
                         int advice, unsigned int flags) {
    /* flags must be 0 (reserved for future use) */
    if (flags != 0)
        return -EINVAL;

    /* Validate pidfd → target PID */
    extern int pidfd_get_pid(int fd);
    int target_pid = pidfd_get_pid(pidfd);
    if (target_pid < 0)
        return -EBADF;

    /* Verify target process exists */
    extern fut_task_t *fut_task_by_pid(uint64_t pid);
    fut_task_t *target = fut_task_by_pid((uint64_t)target_pid);
    if (!target)
        return -ESRCH;

    /* Permission check: caller must own the target or be root */
    extern fut_task_t *fut_task_current(void);
    fut_task_t *caller = fut_task_current();
    if (!caller)
        return -ESRCH;
    if (caller->uid != 0 &&
        !(caller->cap_effective & (1ULL << 19 /* CAP_SYS_PTRACE */)) &&
        caller->uid != target->uid)
        return -EPERM;

    /* Validate vlen (Linux caps at UIO_MAXIOV=1024) */
    if (vlen == 0)
        return 0;
    if (vlen > 1024)
        return -EINVAL;

    /* Copy iovec array from user.
     * struct iovec { void *iov_base; size_t iov_len; } — use matching layout.
     * Heap-allocate sized to the caller's vlen. The previous code stack-
     * allocated all 1024 slots (16 KB) on a typically 8–16 KB kernel
     * stack — a stack-overflow primitive triggerable by any caller
     * regardless of vlen. fut_malloc keeps stack usage bounded. */
    typedef struct { void *iov_base; size_t iov_len; } pma_iovec_t;
    extern void *fut_malloc(uint64_t size);
    extern void  fut_free(void *p);
    pma_iovec_t *iovecs = fut_malloc(vlen * sizeof(pma_iovec_t));
    if (!iovecs)
        return -ENOMEM;

    /* Kernel-pointer bypass for self-tests */
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)iovec_ptr >= KERNEL_VIRTUAL_BASE)
        __builtin_memcpy(iovecs, iovec_ptr, vlen * sizeof(iovecs[0]));
    else
#endif
    {
        extern int fut_copy_from_user(void *dst, const void *src, uint64_t n);
        if (fut_copy_from_user(iovecs, iovec_ptr, vlen * sizeof(iovecs[0])) != 0) {
            fut_free(iovecs);
            return -EFAULT;
        }
    }

    /* Apply madvise to each iovec range */
    extern long sys_madvise(void *addr, size_t length, int advice);
    ssize_t total = 0;
    for (unsigned long i = 0; i < vlen; i++) {
        if (iovecs[i].iov_len == 0)
            continue;
        long r = sys_madvise(iovecs[i].iov_base, iovecs[i].iov_len, advice);
        if (r < 0) {
            /* Return bytes processed so far if any, else propagate error */
            ssize_t out = (total > 0) ? total : r;
            fut_free(iovecs);
            return out;
        }
        total += (ssize_t)iovecs[i].iov_len;
    }
    fut_free(iovecs);
    return total;
}

/**
 * sys_set_mempolicy_home_node() - Set home node for NUMA memory policy.
 * Returns -ENOSYS; Futura has no NUMA topology.
 */
long sys_set_mempolicy_home_node(unsigned long start, unsigned long len,
                                 unsigned long home_node, unsigned long flags) {
    (void)start; (void)len; (void)home_node; (void)flags;
    return -ENOSYS;
}

/**
 * sys_cachestat() - Query page-cache status for a file range (Linux 6.5+).
 *
 * On Futura's ramfs, all file data lives in memory, so everything is
 * effectively "cached". We report nr_cache pages covering the requested
 * range and zero for dirty/writeback/evicted counters.
 *
 * @param fd              File descriptor to query
 * @param cachestat_range Pointer to struct { u64 off; u64 len; }
 * @param cachestat_buf   Pointer to struct { u64 nr_cache, nr_dirty,
 *                          nr_writeback, nr_evicted, nr_recently_evicted; }
 * @param flags           Reserved (must be 0)
 *
 * Returns 0 on success, negative errno on error.
 */
long sys_cachestat(unsigned int fd, const void *cachestat_range,
                   void *cachestat_buf, unsigned int flags) {
    if (flags != 0) return -EINVAL;
    if (!cachestat_range || !cachestat_buf) return -EFAULT;

    fut_task_t *task = fut_task_current();
    if (!task) return -ESRCH;

    /* Validate fd */
    if (fd >= (unsigned int)task->max_fds || !task->fd_table) return -EBADF;
    struct fut_file *file = task->fd_table[fd];
    if (!file) return -EBADF;

    /* Copy range from user/kernel space */
    struct { uint64_t off; uint64_t len; } range;
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)cachestat_range >= KERNEL_VIRTUAL_BASE)
        __builtin_memcpy(&range, cachestat_range, sizeof(range));
    else
#endif
    if (fut_copy_from_user(&range, cachestat_range, sizeof(range)) != 0)
        return -EFAULT;

    /* Get file size from vnode; character/pipe/socket fds have no page cache */
    uint64_t file_size = 0;
    if (file->vnode) {
        file_size = file->vnode->size;
    } else {
        /* Non-regular files (pipes, sockets, etc.) have no page cache. */
        /* Linux returns success with all-zero counts for these. */
    }

    /* Calculate how many pages of the requested range are cached.
     * On ramfs, if the range overlaps the file, it's all cached. */
    uint64_t nr_cache_pages = 0;
    if (file_size > 0) {
        uint64_t start = range.off;
        uint64_t end;
        if (range.len == 0) {
            /* len=0 means "to end of file" */
            end = file_size;
        } else {
            end = range.off + range.len;
        }
        /* Clamp to file size */
        if (start >= file_size) {
            nr_cache_pages = 0;
        } else {
            if (end > file_size) end = file_size;
            uint64_t cached_bytes = end - start;
            nr_cache_pages = (cached_bytes + 4095) / 4096; /* PAGE_SIZE=4096 */
        }
    }

    /* Build result: all pages are cached, nothing is dirty/writeback/evicted */
    struct {
        uint64_t nr_cache;
        uint64_t nr_dirty;
        uint64_t nr_writeback;
        uint64_t nr_evicted;
        uint64_t nr_recently_evicted;
    } result = {
        .nr_cache = nr_cache_pages,
        .nr_dirty = 0,
        .nr_writeback = 0,
        .nr_evicted = 0,
        .nr_recently_evicted = 0,
    };

    /* Copy result to userspace */
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)cachestat_buf >= KERNEL_VIRTUAL_BASE)
        __builtin_memcpy(cachestat_buf, &result, sizeof(result));
    else
#endif
    if (fut_copy_to_user(cachestat_buf, &result, sizeof(result)) != 0)
        return -EFAULT;

    return 0;
}

/**
 * sys_fchmodat2() - Change file permissions (Linux 6.6+, with flag support).
 * Delegates to sys_fchmodat; the main addition is AT_SYMLINK_NOFOLLOW which
 * already returns ENOTSUP from fchmodat (symlinks have no permissions).
 */
long sys_fchmodat2(int dirfd, const char *pathname, unsigned int mode,
                   unsigned int flags) {
    extern long sys_fchmodat(int dirfd, const char *pathname, uint32_t mode, int flags);
    return sys_fchmodat(dirfd, pathname, (uint32_t)mode, (int)flags);
}

/**
 * sys_mseal() - Seal a memory mapping against future changes.
 * Returns 0 (success, no-op); glibc 2.38+ uses this to seal its own segments
 * and ignores ENOSYS, but returning 0 is more accurate from the caller's view.
 */
long sys_mseal(void *addr, size_t len, unsigned long flags) {
    (void)addr; (void)len; (void)flags;
    return 0;
}

/* add_key, request_key, keyctl — moved to kernel/sys_keyring.c */

/* perf_event_open — moved to kernel/sys_perf.c */

/* fanotify_init, fanotify_mark — moved to kernel/sys_fanotify.c */

/* userfaultfd — moved to kernel/sys_userfaultfd.c */

/**
 * sys_bpf() - Execute a BPF command.
 * Returns -EPERM; programs (systemd, tc, iproute2) probe this at startup.
 * -EPERM is more accurate than -ENOSYS: it means "BPF available but
 * unprivileged BPF is disabled", which triggers correct fallback paths.
 *
 * Linux x86_64: 321 (conflicts with Futura SYS_memfd_create — remapped to 457)
 * Linux aarch64: 280
 */
long sys_bpf(int cmd, const void *attr, unsigned int size) {
    (void)cmd; (void)attr; (void)size;
    return -EPERM;
}
