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
 * Phase 3: Dynamic hostname and domain name support with sethostname
 * Phase 4: Extended system info, capabilities reporting
 */

#include <kernel/errno.h>
#include <kernel/uaccess.h>
#include <sys/utsname.h>
#include <stdint.h>
#include <string.h>

#include <kernel/kprintf.h>

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
 * Phase 3: Dynamic hostname/domainname with sethostname support
 * Phase 4: Extended system info, kernel capabilities
 */
long sys_uname(struct utsname *buf) {
    /* Phase 2: Validate user pointer */
    if (!buf) {
        fut_printf("[UNAME] uname(buf=NULL) -> EFAULT (NULL buffer pointer)\n");
        return -EFAULT;
    }

    /* Phase 5: Validate buf write permission early (kernel writes system info)
     * VULNERABILITY: Invalid Output Buffer Pointer
     * ATTACK: Attacker provides unmapped or read-only buffer
     * IMPACT: Kernel page fault when writing system info
     * DEFENSE: Check write permission before processing */
    extern int fut_access_ok(const void *u_ptr, size_t size, int write);
    if (fut_access_ok(buf, sizeof(struct utsname), 1) != 0) {
        fut_printf("[UNAME] uname(buf=%p) -> EFAULT (buffer not writable for %zu bytes, Phase 5)\n",
                   (void*)buf, sizeof(struct utsname));
        return -EFAULT;
    }

    /* Build the utsname structure in kernel space */
    struct utsname info;
    memset(&info, 0, sizeof(info));

    /* Operating system name */
    memcpy(info.sysname, "Futura", 7);  /* 6 chars + null */

    /* Network node hostname (can be changed with sethostname) */
    memcpy(info.nodename, "futura", 7);  /* 6 chars + null */

    /* Operating system release */
    memcpy(info.release, "0.1.0", 6);  /* 5 chars + null */

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

    /* Copy to userspace */
    if (fut_copy_to_user(buf, &info, sizeof(info)) != 0) {
        fut_printf("[UNAME] uname(buf=%p) -> EFAULT "
                   "(copy_to_user failed)\n", (void*)buf);
        return -EFAULT;
    }

    /* Phase 2: Detailed success logging with all fields */
    fut_printf("[UNAME] uname(sysname=\"%s\", nodename=\"%s\", release=\"%s\", "
               "version=\"%s\", machine=\"%s\" [%s]) -> 0 (Phase 3: System information with field validation)\n",
               info.sysname, info.nodename, info.release,
               info.version, info.machine, arch_desc);

    return 0;
}
