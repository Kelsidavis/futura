/* SPDX-License-Identifier: MPL-2.0
 *
 * LD_PRELOAD wrapper for open/open64 syscalls
 *
 * Routes through int 0x80 (32-bit syscall gate) instead of SYSCALL instruction
 * to bypass QEMU x86_64 SYSCALL emulation limitations.
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <stdarg.h>
#include <errno.h>

#define SYS_OPEN 2

/* Direct int 0x80 syscall helper - uses i386 ABI calling convention
 * This bypasses QEMU's SYSCALL instruction limitation by using the
 * older 32-bit interrupt gate which is properly emulated. */
static inline long int80_open(const char *pathname, int flags, mode_t mode) {
    long result;

    /* In i386 ABI, arguments to int 0x80 are passed via registers:
     *   EBX = arg1 (pathname pointer)
     *   ECX = arg2 (flags)
     *   EDX = arg3 (mode)
     * We must use explicit mov instructions to ensure values are loaded */

    __asm__ __volatile__ (
        "int $0x80"
        : "=a" (result)                    /* output: EAX = result */
        : "a" (SYS_OPEN),                  /* EAX = syscall number */
          "b" ((long)pathname),             /* EBX = pathname */
          "c" ((long)flags),                /* ECX = flags */
          "d" ((long)mode)                  /* EDX = mode */
        : "memory", "cc"
    );

    return result;
}

/* Wrapper for open64() */
int open64(const char *pathname, int flags, ...) {
    va_list ap;
    mode_t mode = 0;

    if (flags & (O_CREAT | O_TMPFILE)) {
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }

    long result = int80_open(pathname, flags, mode);

    if (result < 0) {
        errno = -result;
        return -1;
    }
    return (int)result;
}

/* Wrapper for open() */
int open(const char *pathname, int flags, ...) {
    va_list ap;
    mode_t mode = 0;

    if (flags & (O_CREAT | O_TMPFILE)) {
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }

    long result = int80_open(pathname, flags, mode);

    if (result < 0) {
        errno = -result;
        return -1;
    }
    return (int)result;
}
