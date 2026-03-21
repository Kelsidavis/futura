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

#ifdef __x86_64__
#include <platform/x86_64/memory/paging.h>
#elif defined(__aarch64__)
#include <platform/arm64/memory/paging.h>
#endif

/**
 * sys_landlock_create_ruleset() - Create a new Landlock ruleset.
 * Returns -ENOSYS; callers fall back to a permissive sandbox model.
 */
long sys_landlock_create_ruleset(const void *attr, size_t size,
                                 uint32_t flags) {
    (void)attr; (void)size; (void)flags;
    return -ENOSYS;
}

/**
 * sys_landlock_add_rule() - Add a rule to a Landlock ruleset fd.
 * Returns -ENOSYS.
 */
long sys_landlock_add_rule(int ruleset_fd, unsigned int rule_type,
                           const void *rule_attr, uint32_t flags) {
    (void)ruleset_fd; (void)rule_type; (void)rule_attr; (void)flags;
    return -ENOSYS;
}

/**
 * sys_landlock_restrict_self() - Apply a Landlock ruleset to the caller.
 * Returns -ENOSYS.
 */
long sys_landlock_restrict_self(int ruleset_fd, uint32_t flags) {
    (void)ruleset_fd; (void)flags;
    return -ENOSYS;
}

/**
 * sys_memfd_secret() - Create a memory area excluded from core dumps.
 * Returns -ENOSYS; callers fall back to regular anonymous mappings.
 */
long sys_memfd_secret(unsigned int flags) {
    (void)flags;
    return -ENOSYS;
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
    if (caller->uid != 0 && caller->uid != target->uid)
        return -EPERM;

    /* Validate vlen (Linux caps at UIO_MAXIOV=1024) */
    if (vlen == 0)
        return 0;
    if (vlen > 1024)
        return -EINVAL;

    /* Copy iovec array from user.
     * struct iovec { void *iov_base; size_t iov_len; } — use matching layout. */
    struct { void *iov_base; size_t iov_len; } iovecs[1024];

    /* Kernel-pointer bypass for self-tests */
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)iovec_ptr >= KERNEL_VIRTUAL_BASE)
        __builtin_memcpy(iovecs, iovec_ptr, vlen * sizeof(iovecs[0]));
    else
#endif
    {
        extern int fut_copy_from_user(void *dst, const void *src, uint64_t n);
        if (fut_copy_from_user(iovecs, iovec_ptr, vlen * sizeof(iovecs[0])) != 0)
            return -EFAULT;
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
            return (total > 0) ? total : r;
        }
        total += (ssize_t)iovecs[i].iov_len;
    }
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

/**
 * sys_add_key() - Add a key to the Linux keyring.
 * Returns -ENOSYS; programs (ssh, PAM, OpenSSL) fall back to file-based creds.
 */
long sys_add_key(const char *type, const char *description,
                 const void *payload, size_t plen, int keyring) {
    (void)type; (void)description; (void)payload; (void)plen; (void)keyring;
    return -ENOSYS;
}

/**
 * sys_request_key() - Request a key from the kernel keyring.
 * Returns -ENOSYS.
 */
long sys_request_key(const char *type, const char *description,
                     const char *callout_info, int dest_keyring) {
    (void)type; (void)description; (void)callout_info; (void)dest_keyring;
    return -ENOSYS;
}

/**
 * sys_keyctl() - Operate on the Linux keyring.
 * Returns -ENOSYS; callers must handle absence of kernel keyring.
 */
long sys_keyctl(int operation, unsigned long arg2, unsigned long arg3,
                unsigned long arg4, unsigned long arg5) {
    (void)operation; (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return -ENOSYS;
}

/**
 * sys_perf_event_open() - Open a performance monitoring file descriptor.
 * Returns -ENOSYS; callers (perf, BPF programs) fall back to /proc/stat.
 *
 * Linux x86_64: 298  Linux aarch64: 241
 */
long sys_perf_event_open(const void *attr, int pid, int cpu,
                         int group_fd, unsigned long flags) {
    (void)attr; (void)pid; (void)cpu; (void)group_fd; (void)flags;
    return -ENOSYS;
}

/**
 * sys_fanotify_init() - Create a fanotify group.
 * Returns -ENOSYS; callers (systemd, antivirus) fall back to inotify.
 *
 * Linux x86_64: 300  Linux aarch64: 262
 */
long sys_fanotify_init(unsigned int flags, unsigned int event_f_flags) {
    (void)flags; (void)event_f_flags;
    return -ENOSYS;
}

/**
 * sys_fanotify_mark() - Add/remove/modify a fanotify mark.
 * Returns -ENOSYS.
 *
 * Linux x86_64: 301  Linux aarch64: 263
 */
long sys_fanotify_mark(int fanotify_fd, unsigned int flags,
                       unsigned long mask, int dirfd, const char *pathname) {
    (void)fanotify_fd; (void)flags; (void)mask; (void)dirfd; (void)pathname;
    return -ENOSYS;
}

/**
 * sys_userfaultfd() - Create a userfaultfd file descriptor.
 * Returns -ENOSYS; callers (CRIU, live migration tools) require kernel support.
 *
 * Linux x86_64: 323  Linux aarch64: 282
 */
long sys_userfaultfd(int flags) {
    (void)flags;
    return -ENOSYS;
}

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
