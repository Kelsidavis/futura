/* SPDX-License-Identifier: MPL-2.0
 *
 * LD_PRELOAD wrapper for open/open64 syscalls
 *
 * This wrapper intercepts open() and open64() calls and routes them through
 * int 0x80 syscalls instead of the default x86_64 SYSCALL instruction.
 *
 * This solves the QEMU x86_64 SYSCALL emulation limitation that prevents
 * Wayland socket creation from working.
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <stdarg.h>
#include <errno.h>

/* open() syscall number on x86_64 */
#define SYS_OPEN 2

/* Wrapper for open64() - called by modern glibc when opening files */
int open64(const char *pathname, int flags, ...)
{
    va_list ap;
    mode_t mode = 0;

    /* Extract mode parameter if needed */
    if (flags & (O_CREAT | O_TMPFILE)) {
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }

    /* Make direct int 0x80 syscall to bypass QEMU SYSCALL limitation
     * Register setup for x86_64 int 0x80:
     *   RAX = syscall number (2 for open)
     *   RBX = first argument (pathname)
     *   RCX = second argument (flags)
     *   RDX = third argument (mode)
     */
    long result;
    __asm__ volatile("int $0x80"
        : "=a"(result)
        : "a"(SYS_OPEN), "b"(pathname), "c"(flags), "d"(mode)
        : "cc", "memory");

    if (result < 0) {
        errno = -result;
        return -1;
    }

    return (int)result;
}

/* Wrapper for open() - compatibility for code that calls open() directly */
int open(const char *pathname, int flags, ...)
{
    va_list ap;
    mode_t mode = 0;

    /* Extract mode parameter if needed */
    if (flags & (O_CREAT | O_TMPFILE)) {
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }

    /* Make direct int 0x80 syscall */
    long result;
    __asm__ volatile("int $0x80"
        : "=a"(result)
        : "a"(SYS_OPEN), "b"(pathname), "c"(flags), "d"(mode)
        : "cc", "memory");

    if (result < 0) {
        errno = -result;
        return -1;
    }

    return (int)result;
}
