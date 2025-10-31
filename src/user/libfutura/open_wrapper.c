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

    /* Make direct int 0x80 syscall using i386 ABI convention
     * On x86_64, int 0x80 uses 32-bit registers:
     *   EAX = syscall number
     *   EBX = arg1
     *   ECX = arg2
     *   EDX = arg3
     *   ESI = arg4
     *   EDI = arg5
     *   EBP = arg6
     */
    long result;
    __asm__ volatile(
        "movl %1, %%eax\n\t"      /* EAX = SYS_OPEN */
        "movq %2, %%rbx\n\t"      /* RBX = pathname */
        "movl %3, %%ecx\n\t"      /* ECX = flags */
        "movl %4, %%edx\n\t"      /* EDX = mode */
        "int $0x80\n\t"
        "movl %%eax, %0\n\t"      /* result = EAX */
        : "=r"(result)
        : "i"(SYS_OPEN), "r"(pathname), "r"(flags), "r"(mode)
        : "%eax", "%ebx", "%ecx", "%edx", "cc", "memory");

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

    /* Make direct int 0x80 syscall - same as open64() */
    long result;
    __asm__ volatile(
        "movl %1, %%eax\n\t"      /* EAX = SYS_OPEN */
        "movq %2, %%rbx\n\t"      /* RBX = pathname */
        "movl %3, %%ecx\n\t"      /* ECX = flags */
        "movl %4, %%edx\n\t"      /* EDX = mode */
        "int $0x80\n\t"
        "movl %%eax, %0\n\t"      /* result = EAX */
        : "=r"(result)
        : "i"(SYS_OPEN), "r"(pathname), "r"(flags), "r"(mode)
        : "%eax", "%ebx", "%ecx", "%edx", "cc", "memory");

    if (result < 0) {
        errno = -result;
        return -1;
    }

    return (int)result;
}
