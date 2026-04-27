/* kernel/sys_uname.c - uname() syscall implementation
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements system information syscall for querying OS details.
 * Essential for compatibility checks, version detection, and system identification.
 *
 * Phase 1 (Completed): Basic uname with static system info
 * Phase 2 (Completed): Enhanced validation, field categorization, detailed logging
 * Phase 3 (Completed): Dynamic hostname and domain name via sethostname/setdomainname
 * Phase 4: Extended system info, capabilities reporting
 */

#include <kernel/errno.h>
#include <kernel/fut_task.h>
#include <kernel/uaccess.h>
#include <sys/utsname.h>
#include <stdint.h>
#include <string.h>

#include <kernel/kprintf.h>

#include <platform/platform.h>

static inline int uname_copy_to_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)dst >= KERNEL_VIRTUAL_BASE) { __builtin_memcpy(dst, src, n); return 0; }
#endif
    return fut_copy_to_user(dst, src, n);
}
static inline int uname_copy_from_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)src >= KERNEL_VIRTUAL_BASE) { __builtin_memcpy(dst, src, n); return 0; }
#endif
    return fut_copy_from_user(dst, src, n);
}
static inline int uname_access_ok(const void *ptr, size_t n, int write) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)ptr >= KERNEL_VIRTUAL_BASE) return 0;
#endif
    return fut_access_ok(ptr, n, write);
}

/* Mutable hostname and domainname — writable by sethostname/setdomainname */
#define HOSTNAME_MAX  65
#define DOMAINNAME_MAX 65

char g_hostname[HOSTNAME_MAX]   = "futura";
char g_domainname[DOMAINNAME_MAX] = "(none)";

/**
 * uname() syscall - Get system information.
 *
 * Fills a utsname structure with system identification strings.
 * Returns information about the OS name, version, hostname, and architecture.
 *
 * @param buf Pointer to utsname structure to fill
 *
 * Returns:
 *   - 0 on success
 *   - -EFAULT if buf points to invalid memory
 *
 * Behavior:
 *   - Fills utsname structure with system information
 *   - Always succeeds if buf is valid
 *   - Information is read-only for unprivileged processes
 *   - Nodename can be changed with sethostname() (root only)
 *
 * Fields populated:
 *   - sysname: "Futura" (operating system name)
 *   - nodename: "futura" (hostname, can be changed with sethostname)
 *   - release: "0.1.0" (OS release version)
 *   - version: Build date and time (#1 SMP <date> <time>)
 *   - machine: "x86_64" or "aarch64" (hardware architecture)
 *
 * Common usage patterns:
 *
 * Check OS name:
 *   struct utsname info;
 *   if (uname(&info) == 0) {
 *       printf("OS: %s\n", info.sysname);
 *   }
 *
 * Version check:
 *   struct utsname info;
 *   uname(&info);
 *   printf("%s %s %s\n", info.sysname, info.release, info.machine);
 *   // Output: Futura 0.1.0 x86_64
 *
 * Architecture detection:
 *   struct utsname info;
 *   uname(&info);
 *   if (strcmp(info.machine, "x86_64") == 0) {
 *       // x86-64 specific code
 *   } else if (strcmp(info.machine, "aarch64") == 0) {
 *       // ARM64 specific code
 *   }
 *
 * Hostname retrieval:
 *   struct utsname info;
 *   uname(&info);
 *   printf("Hostname: %s\n", info.nodename);
 *
 * Shell uname command implementation:
 *   struct utsname info;
 *   uname(&info);
 *
 *   // uname -s (sysname)
 *   printf("%s\n", info.sysname);
 *
 *   // uname -n (nodename)
 *   printf("%s\n", info.nodename);
 *
 *   // uname -r (release)
 *   printf("%s\n", info.release);
 *
 *   // uname -m (machine)
 *   printf("%s\n", info.machine);
 *
 *   // uname -a (all)
 *   printf("%s %s %s %s %s\n", info.sysname, info.nodename,
 *          info.release, info.version, info.machine);
 *
 * Comparison with other info syscalls:
 *   - uname(): Basic system identification
 *   - sysinfo(): Resource usage (RAM, uptime, load)
 *   - sysctl(): Kernel parameters and tunables
 *   - /proc/version: Detailed kernel build info
 *
 * Related syscalls:
 *   - sethostname(): Set system hostname (root only)
 *   - setdomainname(): Set NIS domain name (root only)
 *   - gethostname(): Get hostname (simpler than uname)
 *
 * Phase 1 (Completed): Basic uname with static system info
 * Phase 2 (Completed): Enhanced validation, field categorization, detailed logging
 * Phase 3 (Completed): Dynamic hostname and domain name via sethostname/setdomainname
 * Phase 4: Extended system info, kernel capabilities
 */
long sys_uname(struct utsname *buf) {
    /* Phase 2: Validate user pointer */
    if (!buf) {
        fut_printf("[UNAME] uname(buf=NULL) -> EFAULT (NULL buffer pointer)\n");
        return -EFAULT;
    }

    /* Validate buf write permission early (kernel writes system info)
     * VULNERABILITY: Invalid Output Buffer Pointer
     * ATTACK: Attacker provides unmapped or read-only buffer
     * IMPACT: Kernel page fault when writing system info
     * DEFENSE: Check write permission before processing */
    if (uname_access_ok(buf, sizeof(struct utsname), 1) != 0) {
        fut_printf("[UNAME] uname(buf=%p) -> EFAULT (buffer not writable for %zu bytes)\n",
                   (void*)buf, sizeof(struct utsname));
        return -EFAULT;
    }

    /* Build the utsname structure in kernel space */
    struct utsname info;
    memset(&info, 0, sizeof(info));

    /* Operating system name — report "Linux" for POSIX/Linux compatibility.
     * Many userspace programs check uname().sysname == "Linux" to detect the
     * OS. Futura targets Linux ABI (PER_LINUX personality by default). */
    memcpy(info.sysname, "Linux", 6);  /* 5 chars + null */

    /* Network node hostname (writable via sethostname) */
    size_t hn_len = 0;
    while (g_hostname[hn_len] && hn_len < sizeof(info.nodename) - 1) hn_len++;
    memcpy(info.nodename, g_hostname, hn_len);
    info.nodename[hn_len] = '\0';

    /* Operating system release — report a realistic Linux version */
    memcpy(info.release, "6.8.0-futura", 13);  /* 12 chars + null */

    /* Operating system version (build date/time) */
    {
        const char *ver = "#1 SMP " __DATE__ " " __TIME__;
        size_t len = 0;
        while (ver[len] && len < sizeof(info.version) - 1) len++;
        memcpy(info.version, ver, len);
        info.version[len] = '\0';
    }

    /* Hardware identifier (architecture) */
#if defined(__x86_64__)
    memcpy(info.machine, "x86_64", 7);  /* 6 chars + null */
    const char *arch_desc = "x86-64";
#elif defined(__aarch64__)
    memcpy(info.machine, "aarch64", 8);  /* 7 chars + null */
    const char *arch_desc = "ARM64";
#else
    memcpy(info.machine, "unknown", 8);  /* 7 chars + null */
    const char *arch_desc = "unknown";
#endif

    /* NIS domain name (writable via setdomainname). Previously this
     * field was left zero-filled by the memset above, so callers
     * always saw an empty domainname even after a successful
     * setdomainname() — uname() now reports the stored value. */
    {
        size_t dn_len = 0;
        while (g_domainname[dn_len] && dn_len < sizeof(info.domainname) - 1)
            dn_len++;
        memcpy(info.domainname, g_domainname, dn_len);
        info.domainname[dn_len] = '\0';
    }

    /* Copy to userspace */
    if (uname_copy_to_user(buf, &info, sizeof(info)) != 0) {
        fut_printf("[UNAME] uname(buf=%p) -> EFAULT "
                   "(copy_to_user failed)\n", (void*)buf);
        return -EFAULT;
    }

    (void)arch_desc;
    return 0;
}

/**
 * sethostname() - Set the system hostname
 *
 * @param name:   New hostname string (not necessarily NUL-terminated)
 * @param len:    Length of hostname (must be <= 64)
 *
 * Requires CAP_SYS_ADMIN or uid=0.
 *
 * Phase 3 (Completed): Dynamic hostname stored in g_hostname
 *
 * Returns:
 *   0 on success
 *   -EINVAL if len is out of range
 *   -EFAULT if name is invalid
 *   -EPERM  if caller lacks privilege
 *   -ESRCH  if no current task
 */
long sys_sethostname(const char *name, size_t len) {
    fut_task_t *task = fut_task_current();
    if (!task) return -ESRCH;

    /* Privilege check */
    bool is_root = (task->uid == 0);
    bool has_cap = (task->cap_effective & (1ULL << 21)) != 0; /* CAP_SYS_ADMIN = 21 */
    if (!is_root && !has_cap) {
        fut_printf("[SETHOSTNAME] sethostname(len=%zu, pid=%d) -> EPERM\n", len, task->pid);
        return -EPERM;
    }

    /* Linux's sethostname only rejects len > __NEW_UTS_LEN (64); a zero
     * length is a valid clear operation that empties uts->nodename. The
     * previous code rejected len=0 with EINVAL, breaking
     * `hostnamectl --transient=""` and any program that wants to revert
     * the hostname to a blank state without first sethostname()'ing a
     * one-byte placeholder. */
    if (len > (HOSTNAME_MAX - 1)) {
        fut_printf("[SETHOSTNAME] sethostname(len=%zu, pid=%d) -> EINVAL\n", len, task->pid);
        return -EINVAL;
    }

    char buf[HOSTNAME_MAX];
    if (len > 0 && uname_copy_from_user(buf, name, len) != 0) {
        fut_printf("[SETHOSTNAME] sethostname(len=%zu, pid=%d) -> EFAULT\n", len, task->pid);
        return -EFAULT;
    }
    buf[len] = '\0';

    memcpy(g_hostname, buf, len + 1);

    fut_printf("[SETHOSTNAME] sethostname(\"%s\", pid=%d) -> 0\n", g_hostname, task->pid);
    return 0;
}

/**
 * setdomainname() - Set the NIS domain name
 *
 * @param name:   New domain name string (not necessarily NUL-terminated)
 * @param len:    Length of domain name (must be <= 64)
 *
 * Requires CAP_SYS_ADMIN or uid=0.
 *
 * Phase 3 (Completed): Dynamic domain name stored in g_domainname
 *
 * Returns:
 *   0 on success
 *   -EINVAL if len is out of range
 *   -EFAULT if name is invalid
 *   -EPERM  if caller lacks privilege
 *   -ESRCH  if no current task
 */
long sys_setdomainname(const char *name, size_t len) {
    fut_task_t *task = fut_task_current();
    if (!task) return -ESRCH;

    bool is_root = (task->uid == 0);
    bool has_cap = (task->cap_effective & (1ULL << 21)) != 0;
    if (!is_root && !has_cap) {
        fut_printf("[SETDOMAINNAME] setdomainname(len=%zu, pid=%d) -> EPERM\n", len, task->pid);
        return -EPERM;
    }

    if (len > (DOMAINNAME_MAX - 1)) {
        fut_printf("[SETDOMAINNAME] setdomainname(len=%zu, pid=%d) -> EINVAL\n", len, task->pid);
        return -EINVAL;
    }

    /* Linux's setdomainname stores the user-supplied bytes verbatim
     * (zero-padding the rest of utsname.domainname). A len=0 call
     * therefore leaves an empty domainname — not the literal string
     * "(none)". The previous code substituted "(none)" so any later
     * uname() reported a fake domainname that no Linux kernel would
     * produce, and a subsequent gethostname-style probe would think
     * the system had a configured NIS domain when it did not. Mirror
     * sys_sethostname's clear-on-empty behaviour. */
    char buf[DOMAINNAME_MAX];
    if (len > 0 && uname_copy_from_user(buf, name, len) != 0) {
        fut_printf("[SETDOMAINNAME] setdomainname(len=%zu, pid=%d) -> EFAULT\n", len, task->pid);
        return -EFAULT;
    }
    buf[len] = '\0';

    memcpy(g_domainname, buf, len + 1);

    fut_printf("[SETDOMAINNAME] setdomainname(\"%s\", pid=%d) -> 0\n", g_domainname, task->pid);
    return 0;
}
