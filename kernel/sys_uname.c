/* kernel/sys_uname.c - uname() syscall implementation
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements system information syscall.
 */

#include <kernel/errno.h>
#include <kernel/uaccess.h>
#include <stdint.h>
#include <string.h>

extern void fut_printf(const char *fmt, ...);
extern int fut_copy_to_user(void *to, const void *from, size_t size);

/* utsname structure - system information */
struct utsname {
    char sysname[65];    /* Operating system name */
    char nodename[65];   /* Network node hostname */
    char release[65];    /* Operating system release */
    char version[65];    /* Operating system version */
    char machine[65];    /* Hardware identifier */
};

/**
 * uname() syscall - Get system information.
 *
 * @param buf Pointer to utsname structure to fill
 *
 * Returns:
 *   - 0 on success
 *   - -errno on error
 *
 * Behavior:
 *   - Fills the provided utsname structure with system information
 *   - Returns -EFAULT if buf points to invalid memory
 *   - Always succeeds if buf is valid
 *
 * Fields populated:
 *   - sysname: "Futura" (operating system name)
 *   - nodename: "futura" (hostname, can be changed with sethostname)
 *   - release: "0.1.0" (OS release version)
 *   - version: Build date and time
 *   - machine: "x86_64" or "aarch64" (hardware architecture)
 */
long sys_uname(struct utsname *buf) {
    if (!buf) {
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
#elif defined(__aarch64__)
    memcpy(info.machine, "aarch64", 8);  /* 7 chars + null */
#else
    memcpy(info.machine, "unknown", 8);  /* 7 chars + null */
#endif

    /* Copy to userspace */
    if (fut_copy_to_user(buf, &info, sizeof(info)) != 0) {
        return -EFAULT;
    }

    fut_printf("[UNAME] Returned system info: %s %s %s\n",
               info.sysname, info.release, info.machine);

    return 0;
}
