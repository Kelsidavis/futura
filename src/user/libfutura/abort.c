// SPDX-License-Identifier: MPL-2.0

#include <stddef.h>
#include <string.h>

#include <user/stdlib.h>
#include <user/sys.h>

static void write_stderr(const char *msg) {
    if (!msg) {
        return;
    }
    size_t len = strlen(msg);
    if (len == 0) {
        return;
    }
    (void)sys_write(2, msg, (long)len);
}

__attribute__((noreturn)) void abort(void) {
    write_stderr("abort(): fatal termination\n");
    sys_exit(134);
    __builtin_unreachable();
}

__attribute__((noreturn)) void __stack_chk_fail(void) {
    write_stderr("__stack_chk_fail: stack canary violation\n");
    sys_exit(134);
    __builtin_unreachable();
}

#if defined(__GNUC__) && !defined(__APPLE__)
__asm__(".symver abort,abort@GLIBC_2.2.5");
__asm__(".symver __stack_chk_fail,__stack_chk_fail@GLIBC_2.4");
#endif
